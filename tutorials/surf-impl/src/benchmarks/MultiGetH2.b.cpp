/*
  MultiGetH2 benchmark: HTTP/2 multiplexed Surf-PSK resumption.

  The resumed round
  fetches EVERY queued asset as parallel HTTP/2 streams over one TLS
  connection, so a page costs 1 full + 1 resumed handshake rather than 1 + N.

  `--round full` performs the full handshake, GETs `--path`, parses the HTML,
  and writes to the handoff directory: the session ticket, the prover's PSK
  share, the verifier's PSK share, and the asset list. `--round resumed` reads
  them back and fetches the whole list over a single PSK-resumption handshake.

  SURF TRUE mode and HTTP/2:
  In TRUE mode no record can be opened while it arrives: the prover holds k_c
  but not k_v, so SSL_read yields nothing until true_surf_release. nghttp2's
  normal drive loop is interactive (read SETTINGS, ack, emit WINDOW_UPDATEs
  as DATA arrives) and none of that is possible against a stream the client
  cannot decrypt. TRUE mode therefore runs the session in two halves:

    1. Send-only. The connection preface, our SETTINGS, a connection-level
       WINDOW_UPDATE and every HEADERS frame are generated up front and written
       as one TLS record. Flow control is pre-opened (SETTINGS_INITIAL_WINDOW_SIZE
       plus the WINDOW_UPDATE) so the origin never blocks waiting for a
       WINDOW_UPDATE we cannot send. A GOAWAY follows immediately, which is what
       makes the origin close once the requested streams finish (HTTP/2 has no
       "Connection: close", so without it the drain would never see a FIN).
    2. Offline parse. After the drain and true_surf_release, the decrypted
       payload is fed to the same nghttp2 session via nghttp2_session_mem_recv.

  Masked mode keeps the ordinary interactive loop, since records open inline.

  Usage (origin only for the local case; verifier and prover once per round):
    ./MultiGetH2Bench --is_server   --ip 127.0.0.1 -p 8443
    SURF_TRUE=1 ./MultiGetH2Bench --is_verifier --ip 127.0.0.1 -v 8444 \
        --round full --handoff /tmp/h2_x
    SURF_TRUE=1 ./MultiGetH2Bench --host example.com -v 8444 \
        --round full --handoff /tmp/h2_x
    (then one verifier and one prover with --round resumed, new -v)
*/

#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <gumbo.h>
#include <nghttp2/nghttp2.h>

#include "../nodes/Events.hpp"
#include "../nodes/Server.hpp"
#include "../ssl/Messaging.hpp"
#include "../ssl/Roundhandoff.hpp"
#include "../ssl/TestUtil.hpp"
#include "../ssl/ThreePartyHandshake.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>

enum class Round { Full, Resumed };

static double g_origin_rtt_ms = -1.0;

// Which SURF mode this process is running, for the summary.
static const char *g_surf_mode = "masked";

// Response bodies served by --is_server.
static const char HTML_BODY[] =
    "<!doctype html><title>Surf MultiGet test site</title>"
    "<img src=\"/img/logo.png\">"
    "<script src=\"/js/app.js\"></script>";
static_assert(sizeof(HTML_BODY) - 1 == 112, "HTML body must be 112 bytes");

static const char ASSET_BODY[] = "data";

// The origin must decrypt a ticket minted by a previous round's process.
// SSL_CTX_new generates a fresh ticket key per process, so without a fixed key
// every resumed round silently falls back to a full handshake
static const uint8_t kTicketKey[48] = {
    0x53, 0x55, 0x52, 0x46, 0x68, 0x32, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74,
    0x6b, 0x65, 0x79, 0x32, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

// Flow control, pre-opened so TRUE mode never needs a mid-stream WINDOW_UPDATE.
// 2^31-1 is the protocol maximum for both.
static constexpr uint32_t kBigWindow = 0x7fffffffu;

static std::string assets_file(const std::string &dir) {
  return dir + "/assets.txt";
}

static bool write_assets(const std::string &dir,
                         const std::vector<std::string> &assets) {
  std::ofstream f(assets_file(dir), std::ios::trunc);
  if (!f) return false;
  for (const auto &a : assets) f << a << "\n";
  f.flush();
  return f.good();
}

static std::vector<std::string> read_assets(const std::string &dir) {
  std::vector<std::string> out;
  std::ifstream f(assets_file(dir));
  std::string line;
  while (std::getline(f, line)) {
    if (!line.empty()) out.push_back(line);
  }
  return out;
}

// Helpers
static std::string resolve_hostname(const std::string &host) {
  struct addrinfo hints = {}, *results = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  int ret = getaddrinfo(host.c_str(), nullptr, &hints, &results);
  if (ret != 0 || !results) {
    std::cerr << "[DNS] Failed to resolve '" << host
              << "': " << gai_strerror(ret) << std::endl;
    return {};
  }
  char ip_buf[INET_ADDRSTRLEN] = {};
  auto *addr = reinterpret_cast<struct sockaddr_in *>(results->ai_addr);
  inet_ntop(AF_INET, &addr->sin_addr, ip_buf, sizeof(ip_buf));
  freeaddrinfo(results);
  return std::string(ip_buf);
}

static double ms_since(const std::chrono::steady_clock::time_point start) {
  using namespace std::chrono;
  return duration_cast<duration<double, std::milli>>(steady_clock::now() - start)
      .count();
}

static double measure_rtt_ms(const std::string &ip, uint16_t port,
                             int samples = 3) {
  std::vector<double> rtts;
  for (int i = 0; i < samples; ++i) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) continue;
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
      ::close(fd);
      continue;
    }
    const auto t0 = std::chrono::steady_clock::now();
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = ::connect(fd, reinterpret_cast<struct sockaddr *>(&addr),
                       sizeof(addr));
    if (rc < 0 && errno == EINPROGRESS) {
      struct pollfd pfd;
      pfd.fd = fd;
      pfd.events = POLLOUT;
      pfd.revents = 0;
      if (::poll(&pfd, 1, 3000) == 1) {
        int err = 0;
        socklen_t len = sizeof(err);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        rc = err ? -1 : 0;
      } else {
        rc = -1;
      }
    }
    const double ms = ms_since(t0);
    ::close(fd);
    if (rc == 0) rtts.push_back(ms);
  }

  if (rtts.empty()) return -1.0;
  std::sort(rtts.begin(), rtts.end());

  return rtts[rtts.size() / 2];
}

static void wire_bytes(SSL *ssl, uint64_t *sent, uint64_t *received) {
  *sent = ssl ? BIO_number_written(SSL_get_wbio(ssl)) : 0;
  *received = ssl ? BIO_number_read(SSL_get_rbio(ssl)) : 0;
}

static constexpr std::size_t kAesEncIters = 4;
static constexpr std::size_t kMaxRequestBytes =
    16 * EmpWrapperAG2PCConstants::AES_ENC_N * kAesEncIters - 1;

template <bool debug = false>
static bool read_handshake(TLSSocket &sock) {
  bssl::Array<uint8_t> arr;
  arr.Init(1);
  if (sock.read(arr.data(), static_cast<int>(arr.size())) != 1) return false;
  CBS cbs;
  CBS_init(&cbs, arr.data(), arr.size());
  uint8_t out;
  return CBS_get_u8(&cbs, &out) &&
         (out == static_cast<uint8_t>(Messaging::MessageHeaders::DONE_HS));
}

static bool set_callbacks(TLSSocket &socket) {
  socket.set_make_circuits();
  return socket.set_handshake_callback() && socket.set_keyshare_callback() &&
         socket.set_derive_shared_secret_callback() &&
         socket.set_derive_handshake_keys_callback() &&
         socket.set_commit_to_server_certificate_callback() &&
         socket.set_combine_handshake_secret_shares_callback() &&
         socket.set_derive_psk_keys_callback() &&
         socket.set_derive_resumption_keys_callback() &&
         socket.set_derive_traffic_keys_callback() &&
         socket.set_derive_gcm_shares_callback() &&
         socket.set_derive_binder_callback() &&
         socket.set_surf_encrypt_callback() &&
         socket.set_surf_decrypt_callback();
}

static void dump_err_queue(const char *tag) {
  const char *file = nullptr;
  int line = 0;
  const char *data = nullptr;
  int flags = 0;
  uint32_t err;
  while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    std::cerr << "[" << tag << "] " << buf << " at " << (file ? file : "?")
              << ":" << line;
    if (data && (flags & ERR_FLAG_STRING)) std::cerr << " data=" << data;
    std::cerr << "\n";
  }
}

// ALPN ("h2")
static const uint8_t kAlpnH2[] = {2, 'h', '2'};

static int alpn_select_h2(SSL *, const uint8_t **out, uint8_t *outlen,
                          const uint8_t *in, unsigned inlen, void *) {
  if (SSL_select_next_proto(const_cast<uint8_t **>(out), outlen, kAlpnH2,
                            sizeof(kAlpnH2), in,
                            inlen) == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

static bool require_alpn_h2(SSL *ssl, const char *tag) {
  const uint8_t *p = nullptr;
  unsigned len = 0;
  SSL_get0_alpn_selected(ssl, &p, &len);
  const std::string s(reinterpret_cast<const char *>(p), len);
  std::cerr << "[" << tag << "] ALPN selected: '" << s << "'\n";
  return len == 2 && s == "h2";
}

// Session ticket capture
static SSL_SESSION *g_ticket_session = nullptr;

static int new_session_cb(SSL * /*ssl*/, SSL_SESSION *session) {
  // The SURF PSK is derived only for the FIRST NewSessionTicket's nonce:
  // derive_psk_keys consumes the psk circuits on its first invocation and
  // no-ops thereafter. Resuming with a later ticket would pair the first
  // ticket's PSK with a session the origin keys differently, so the binder
  // fails and the origin aborts with decrypt_error.
  if (g_ticket_session != nullptr) {
    return 0;  // decline ownership; BoringSSL frees it
  }
  g_ticket_session = session;
  return 1;
}

// Gumbo HTML asset extraction
static std::string resolve_asset_path(const std::string &val,
                                      const std::string &host) {
  if (val.empty() || val[0] == '#') return "";

  const auto lower = [](std::string s) {
    for (auto &c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
  };

  std::string authority_and_path;
  if (val.rfind("//", 0) == 0) {
    authority_and_path = val.substr(2);
  } else if (const auto s = val.find("://"); s != std::string::npos) {
    authority_and_path = val.substr(s + 3);
  } else if (const auto c = val.find(':');
             c != std::string::npos && c < val.find('/')) {
    return "";  // mailto:, javascript:, tel:, data:
  }

  if (!authority_and_path.empty() || val.rfind("//", 0) == 0) {
    const auto slash = authority_and_path.find('/');
    std::string h = (slash == std::string::npos)
                        ? authority_and_path
                        : authority_and_path.substr(0, slash);
    if (const auto at = h.find('@'); at != std::string::npos)
      h = h.substr(at + 1);
    if (const auto colon = h.find(':'); colon != std::string::npos)
      h = h.substr(0, colon);
    if (lower(h) != lower(host)) return "";
    return (slash == std::string::npos) ? "/"
                                        : authority_and_path.substr(slash);
  }

  if (val[0] == '/') return val;
  if (val.rfind("./", 0) == 0) return val.substr(1);

  return "/" + val;
}

static void collect_assets(GumboNode *node, const std::string &host,
                           std::vector<std::string> &out) {
  if (!node || node->type != GUMBO_NODE_ELEMENT) return;
  const GumboTag tag = node->v.element.tag;
  for (const char *attr_name : {"src", "href"}) {
    if (std::strcmp(attr_name, "href") == 0 &&
        (tag == GUMBO_TAG_A || tag == GUMBO_TAG_AREA))
      continue;
    GumboAttribute *a =
        gumbo_get_attribute(&node->v.element.attributes, attr_name);
    if (!a) continue;
    std::string path = resolve_asset_path(a->value, host);
    if (!path.empty()) out.push_back(std::move(path));
  }
  const GumboVector *ch = &node->v.element.children;
  for (unsigned i = 0; i < ch->length; ++i)
    collect_assets(static_cast<GumboNode *>(ch->data[i]), host, out);
}

static std::vector<std::string> parse_assets(const std::string &html,
                                             const std::string &host) {
  GumboOutput *output = gumbo_parse(html.c_str());
  if (!output) return {};
  std::vector<std::string> urls;
  collect_assets(output->root, host, urls);
  gumbo_destroy_output(&kGumboDefaultOptions, output);

  std::vector<std::string> deduped;
  std::unordered_set<std::string> seen;
  for (auto &u : urls)
    if (seen.insert(u).second) deduped.push_back(std::move(u));
  return deduped;
}

// nghttp2 plumbing
static void set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void wait_io(int fd, bool want_read, bool want_write) {
  struct pollfd pfd{};
  pfd.fd = fd;
  pfd.events = (want_read ? POLLIN : 0) | (want_write ? POLLOUT : 0);
  if (pfd.events == 0) return;
  poll(&pfd, 1, -1);
}

static ssize_t ssl_send(SSL *ssl, const uint8_t *data, size_t len) {
  const size_t chunk = std::min<size_t>(len, 16 * 1024);
  int n = SSL_write(ssl, data, static_cast<int>(chunk));
  if (n > 0) return n;
  int e = SSL_get_error(ssl, n);
  if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ)
    return NGHTTP2_ERR_WOULDBLOCK;
  return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static ssize_t ssl_recv(SSL *ssl, uint8_t *buf, size_t len) {
  int n = SSL_read(ssl, buf, static_cast<int>(len));
  if (n > 0) return n;
  int e = SSL_get_error(ssl, n);
  if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
    return NGHTTP2_ERR_WOULDBLOCK;
  std::cerr << "[Prover] ssl_recv ended: SSL_get_error=" << e
            << (e == SSL_ERROR_ZERO_RETURN ? " (ZERO_RETURN/clean-close)"
                : e == SSL_ERROR_SYSCALL   ? " (SYSCALL/transport-EOF)"
                : e == SSL_ERROR_SSL       ? " (SSL/protocol)"
                                           : " (other)")
            << " errno=" << errno << "\n";
  return NGHTTP2_ERR_EOF;
}

// Server side
struct ServerStreamCtx {
  std::string path;
  const char *body = nullptr;
  size_t body_len = 0;
  size_t sent = 0;
};

struct ServerCtx {
  SSL *ssl;
  std::unordered_map<int32_t, ServerStreamCtx> streams;
};

static ssize_t server_data_provider(nghttp2_session *, int32_t stream_id,
                                    uint8_t *buf, size_t length,
                                    uint32_t *data_flags,
                                    nghttp2_data_source *, void *user_data) {
  auto *sc = static_cast<ServerCtx *>(user_data);
  auto it = sc->streams.find(stream_id);
  if (it == sc->streams.end()) return NGHTTP2_ERR_CALLBACK_FAILURE;
  auto &st = it->second;
  size_t remaining = st.body_len - st.sent;
  size_t n = std::min(length, remaining);
  std::memcpy(buf, st.body + st.sent, n);
  st.sent += n;
  if (st.sent == st.body_len) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  return static_cast<ssize_t>(n);
}

static int server_on_header(nghttp2_session *, const nghttp2_frame *frame,
                            const uint8_t *name, size_t namelen,
                            const uint8_t *value, size_t valuelen, uint8_t,
                            void *user_data) {
  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    return 0;
  auto *sc = static_cast<ServerCtx *>(user_data);
  if (namelen == 5 && std::memcmp(name, ":path", 5) == 0) {
    sc->streams[frame->hd.stream_id].path =
        std::string(reinterpret_cast<const char *>(value), valuelen);
  }
  return 0;
}

static int server_on_frame_recv(nghttp2_session *session,
                                const nghttp2_frame *frame, void *user_data) {
  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST ||
      !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
    return 0;

  auto *sc = static_cast<ServerCtx *>(user_data);
  auto &st = sc->streams[frame->hd.stream_id];
  const bool is_root = (st.path == "/");
  st.body = is_root ? HTML_BODY : ASSET_BODY;
  st.body_len = is_root ? sizeof(HTML_BODY) - 1 : sizeof(ASSET_BODY) - 1;
  st.sent = 0;

  const std::string clen = std::to_string(st.body_len);
  const char *ctype = is_root ? "text/html" : "application/octet-stream";
  nghttp2_nv hdrs[] = {
      {(uint8_t *)":status", (uint8_t *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
      {(uint8_t *)"content-type", (uint8_t *)ctype, 12, std::strlen(ctype),
       NGHTTP2_NV_FLAG_NONE},
      {(uint8_t *)"content-length", (uint8_t *)clen.c_str(), 14, clen.size(),
       NGHTTP2_NV_FLAG_NONE},
  };
  nghttp2_data_provider dp{};
  dp.read_callback = server_data_provider;
  int rv = nghttp2_submit_response(session, frame->hd.stream_id, hdrs,
                                   sizeof(hdrs) / sizeof(hdrs[0]), &dp);
  if (rv != 0) {
    std::cerr << "[Server] submit_response failed: " << nghttp2_strerror(rv)
              << "\n";
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static ssize_t server_send_cb(nghttp2_session *, const uint8_t *data,
                              size_t len, int, void *ud) {
  return ssl_send(static_cast<ServerCtx *>(ud)->ssl, data, len);
}
static ssize_t server_recv_cb(nghttp2_session *, uint8_t *buf, size_t len, int,
                              void *ud) {
  return ssl_recv(static_cast<ServerCtx *>(ud)->ssl, buf, len);
}

static bool serve_h2(SSL *ssl) {
  set_nonblock(SSL_get_fd(ssl));
  ServerCtx ctx{ssl, {}};

  nghttp2_session_callbacks *cbs = nullptr;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback(cbs, server_send_cb);
  nghttp2_session_callbacks_set_recv_callback(cbs, server_recv_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
                                                       server_on_frame_recv);
  nghttp2_session_callbacks_set_on_header_callback(cbs, server_on_header);

  nghttp2_session *sess = nullptr;
  nghttp2_session_server_new(&sess, cbs, &ctx);
  nghttp2_session_callbacks_del(cbs);

  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  nghttp2_submit_settings(sess, NGHTTP2_FLAG_NONE, iv, 1);

  bool ok = true;
  const int fd = SSL_get_fd(ssl);
  while (nghttp2_session_want_read(sess) || nghttp2_session_want_write(sess)) {
    int rv = nghttp2_session_send(sess);
    if (rv != 0) {
      std::cerr << "[Server] session_send: " << nghttp2_strerror(rv) << "\n";
      ok = false;
      break;
    }
    rv = nghttp2_session_recv(sess);
    if (rv == NGHTTP2_ERR_EOF) break;
    if (rv != 0) {
      std::cerr << "[Server] session_recv: " << nghttp2_strerror(rv) << "\n";
      ok = false;
      break;
    }
    wait_io(fd, nghttp2_session_want_read(sess),
            nghttp2_session_want_write(sess));
  }
  nghttp2_session_del(sess);
  return ok;
}

// Client side
struct ClientStreamCtx {
  std::string path;
  std::string body;
  bool closed = false;
};

struct ClientCtx {
  SSL *ssl = nullptr;
  std::unordered_map<int32_t, ClientStreamCtx> streams;
  size_t pending = 0;
  bool buffer_output = false;
  std::string outbuf;
};

static ssize_t client_send(nghttp2_session *, const uint8_t *data, size_t len,
                           int, void *ud) {
  auto *cc = static_cast<ClientCtx *>(ud);
  if (cc->buffer_output) {
    cc->outbuf.append(reinterpret_cast<const char *>(data), len);
    return static_cast<ssize_t>(len);
  }
  return ssl_send(cc->ssl, data, len);
}

static ssize_t client_recv(nghttp2_session *, uint8_t *buf, size_t len, int,
                           void *ud) {
  return ssl_recv(static_cast<ClientCtx *>(ud)->ssl, buf, len);
}

static int client_on_data_chunk(nghttp2_session *, uint8_t, int32_t stream_id,
                                const uint8_t *data, size_t len, void *ud) {
  auto *cc = static_cast<ClientCtx *>(ud);
  cc->streams[stream_id].body.append(reinterpret_cast<const char *>(data), len);
  return 0;
}

static int client_on_stream_close(nghttp2_session *, int32_t stream_id,
                                  uint32_t, void *ud) {
  auto *cc = static_cast<ClientCtx *>(ud);
  auto it = cc->streams.find(stream_id);
  if (it != cc->streams.end() && !it->second.closed) {
    it->second.closed = true;
    if (cc->pending > 0) cc->pending--;
  }
  return 0;
}

static int client_on_header(nghttp2_session *, const nghttp2_frame *frame,
                            const uint8_t *name, size_t namelen,
                            const uint8_t *value, size_t valuelen, uint8_t,
                            void *) {
  if (frame->hd.type != NGHTTP2_HEADERS) return 0;
  std::cerr << "[Prover] stream " << frame->hd.stream_id << " header "
            << std::string(reinterpret_cast<const char *>(name), namelen)
            << ": "
            << std::string(reinterpret_cast<const char *>(value), valuelen)
            << "\n";
  return 0;
}

static nghttp2_session *make_client_session(ClientCtx *cc) {
  nghttp2_session_callbacks *cbs = nullptr;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback(cbs, client_send);
  nghttp2_session_callbacks_set_recv_callback(cbs, client_recv);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      cbs, client_on_data_chunk);
  nghttp2_session_callbacks_set_on_stream_close_callback(
      cbs, client_on_stream_close);
  nghttp2_session_callbacks_set_on_header_callback(cbs, client_on_header);
  nghttp2_session *sess = nullptr;
  nghttp2_session_client_new(&sess, cbs, cc);
  nghttp2_session_callbacks_del(cbs);
  return sess;
}

static bool submit_requests(nghttp2_session *sess, ClientCtx &cc,
                            const std::string &authority,
                            const std::vector<std::string> &paths,
                            std::vector<int32_t> *sids) {
  nghttp2_settings_entry iv[2] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
      // Pre-open the per-stream receive window. In TRUE mode we cannot emit
      // WINDOW_UPDATEs during the transfer, so the whole allowance must be
      // announced before the first byte of DATA.
      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, kBigWindow}};
  if (nghttp2_submit_settings(sess, NGHTTP2_FLAG_NONE, iv, 2) != 0) {
    return false;
  }
  // Same for the connection-level window, which SETTINGS cannot raise.
  if (nghttp2_submit_window_update(sess, NGHTTP2_FLAG_NONE, 0,
                                   kBigWindow - 65535) != 0) {
    return false;
  }

  sids->reserve(paths.size());
  for (const auto &p : paths) {
    nghttp2_nv hdrs[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)authority.c_str(), 10,
         authority.size(), NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)p.c_str(), 5, p.size(),
         NGHTTP2_NV_FLAG_NONE},
    };
    int32_t sid = nghttp2_submit_request(
        sess, nullptr, hdrs, sizeof(hdrs) / sizeof(hdrs[0]), nullptr, nullptr);
    if (sid < 0) {
      std::cerr << "[Prover] submit_request failed: " << nghttp2_strerror(sid)
                << "\n";
      return false;
    }
    cc.streams[sid].path = p;
    sids->push_back(sid);
  }
  return true;
}

static void collect_bodies(ClientCtx &cc, const std::vector<int32_t> &sids,
                           std::vector<std::string> *out) {
  out->clear();
  out->reserve(sids.size());
  for (int32_t sid : sids) out->push_back(cc.streams[sid].body);
}

// Masked mode: ordinary interactive drive loop.
static bool h2_client_run_masked(SSL *ssl, const std::string &authority,
                                 const std::vector<std::string> &paths,
                                 std::vector<std::string> *bodies_out) {
  set_nonblock(SSL_get_fd(ssl));
  ClientCtx cc;
  cc.ssl = ssl;
  cc.pending = paths.size();

  nghttp2_session *sess = make_client_session(&cc);
  std::vector<int32_t> sids;
  if (!submit_requests(sess, cc, authority, paths, &sids)) {
    nghttp2_session_del(sess);
    return false;
  }

  bool ok = true;
  const int fd = SSL_get_fd(ssl);
  while (cc.pending > 0 &&
         (nghttp2_session_want_read(sess) ||
          nghttp2_session_want_write(sess))) {
    int rv = nghttp2_session_send(sess);
    if (rv != 0) {
      std::cerr << "[Prover] session_send: " << nghttp2_strerror(rv) << "\n";
      ok = false;
      break;
    }
    rv = nghttp2_session_recv(sess);
    if (rv == NGHTTP2_ERR_EOF) {
      ok = false;
      break;
    }
    if (rv != 0) {
      std::cerr << "[Prover] session_recv: " << nghttp2_strerror(rv) << "\n";
      ok = false;
      break;
    }
    if (cc.pending == 0) break;
    wait_io(fd, nghttp2_session_want_read(sess),
            nghttp2_session_want_write(sess));
  }

  collect_bodies(cc, sids, bodies_out);
  nghttp2_submit_goaway(sess, NGHTTP2_FLAG_NONE,
                        nghttp2_session_get_last_proc_stream_id(sess),
                        NGHTTP2_NO_ERROR, nullptr, 0);
  nghttp2_session_send(sess);
  nghttp2_session_del(sess);
  return ok;
}

// TRUE mode: send everything as one record, drain to FIN, release, then feed
// the decrypted payload back into the same session.
static bool h2_client_run_true(SSL *ssl, const std::string &authority,
                               const std::vector<std::string> &paths,
                               int read_timeout_ms,
                               std::vector<std::string> *bodies_out) {
  ClientCtx cc;
  cc.ssl = ssl;
  cc.pending = paths.size();
  cc.buffer_output = true;

  nghttp2_session *sess = make_client_session(&cc);
  std::vector<int32_t> sids;
  if (!submit_requests(sess, cc, authority, paths, &sids)) {
    nghttp2_session_del(sess);
    return false;
  }

  // GOAWAY up front: HTTP/2 has no "Connection: close", so this is what makes
  // the origin close once the requested streams finish. Without it the drain
  // below would block until the read timeout.
  //nghttp2_submit_goaway(sess, NGHTTP2_FLAG_NONE,
  //                      0,
  //                      NGHTTP2_NO_ERROR, nullptr, 0);

  // Serialise everything into cc.outbuf without touching the socket.
  while (nghttp2_session_want_write(sess)) {
    const int rv = nghttp2_session_send(sess);
    if (rv != 0) {
      std::cerr << "[Prover] session_send (buffering): "
                << nghttp2_strerror(rv) << "\n";
      nghttp2_session_del(sess);
      return false;
    }
  }

  if (cc.outbuf.size() > kMaxRequestBytes) {
    std::cerr << "[Prover] H2 request burst is " << cc.outbuf.size()
              << " bytes; the 2PC encryption circuit is provisioned for "
              << kMaxRequestBytes
              << ". Fetch fewer assets per round or raise aes_enc_iters on "
                 "both parties.\n";
    nghttp2_session_del(sess);
    return false;
  }

  // One SSL_write, therefore one encrypt_request, therefore one TLS record.
  const int w = SSL_write(ssl, cc.outbuf.data(),
                          static_cast<int>(cc.outbuf.size()));
  if (w <= 0 || static_cast<size_t>(w) != cc.outbuf.size()) {
    std::cerr << "[Prover] failed to write the H2 request burst (" << w
              << " of " << cc.outbuf.size() << ")\n";
    nghttp2_session_del(sess);
    return false;
  }
  std::cerr << "[Prover] wrote H2 burst: " << cc.outbuf.size() << " bytes, "
            << paths.size() << " stream(s) in one record\n";

  // Two-phase termination. The GOAWAY is what makes LiteSpeed finish up,
  // flush its NewSessionTickets and close -- but in the same record as the
  // HEADERS it arrives before the request is served and the origin tears down
  // with an empty response. We cannot detect when the response has landed
  // (nothing is readable until KEY_RELEASE), so we wait a fixed interval
  // instead: comfortably more than one RTT plus transfer, then send GOAWAY as
  // a second record and drain to the close it triggers.
  {
    const int fd = SSL_get_fd(ssl);
    const int settle_ms = 2000;
    bool sent_goaway = false;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(settle_ms);
    char sink[4096];
    for (;;) {
      const int n = SSL_read(ssl, sink, sizeof(sink));
      if (n > 0) continue;
      const int e = SSL_get_error(ssl, n);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
        std::cerr << "[Prover] drain ended n=" << n << " ssl_err=" << e
                  << " errno=" << errno << "\n";
        break;
      }
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now())
                            .count();
      if (left <= 0) {
        if (!sent_goaway) {
          // Second record: one more encrypt_request, and the origin's cue to
          // finish. Last-stream-id names the last PEER-initiated stream; a
          // client has none, so 0.
          nghttp2_submit_goaway(sess, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR,
                                nullptr, 0);
          cc.outbuf.clear();
          while (nghttp2_session_want_write(sess)) {
            if (nghttp2_session_send(sess) != 0) break;
          }
          if (!cc.outbuf.empty()) {
            SSL_write(ssl, cc.outbuf.data(),
                      static_cast<int>(cc.outbuf.size()));
            std::cerr << "[Prover] sent GOAWAY (" << cc.outbuf.size()
                      << " bytes) after " << settle_ms << " ms\n";
          }
          sent_goaway = true;
          deadline = std::chrono::steady_clock::now() +
                     std::chrono::milliseconds(read_timeout_ms);
          continue;
        }
        std::cerr << "[Prover] drain timed out after " << read_timeout_ms
                  << " ms with no close from the origin\n";
        break;
      }
      struct pollfd pfd{};
      pfd.fd = fd;
      pfd.events = (e == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
      if (::poll(&pfd, 1, static_cast<int>(left)) < 0 && errno != EINTR) {
        break;
      }
    }
  }


  bssl::Array<uint8_t> plaintext;
  if (!ThreePartyHandshake::true_surf_release(ssl, plaintext, false)) {
    std::cerr << "[Prover] true_surf_release failed\n";
    nghttp2_session_del(sess);
    return false;
  }
  std::cerr << "[Prover] TRUE release: " << ssl->surf_records.size()
            << " records, payload=" << plaintext.size() << " bytes\n";

  // Offline parse against the SAME session: stream ids and the HPACK dynamic
  // table carry over from the requests above. Output generated here (window
  // updates, settings acks) has nowhere to go and is discarded by the buffer.
  const ssize_t consumed = nghttp2_session_mem_recv(
      sess, reinterpret_cast<const uint8_t *>(plaintext.data()),
      plaintext.size());
  if (consumed < 0) {
    std::cerr << "[Prover] mem_recv failed: "
              << nghttp2_strerror(static_cast<int>(consumed)) << "\n";
    nghttp2_session_del(sess);
    return false;
  }
  if (static_cast<size_t>(consumed) != plaintext.size()) {
    std::cerr << "[Prover] mem_recv consumed " << consumed << " of "
              << plaintext.size() << " bytes\n";
  }

  collect_bodies(cc, sids, bodies_out);
  const size_t open = cc.pending;
  nghttp2_session_del(sess);
  if (open != 0) {
    std::cerr << "[Prover] " << open << " stream(s) never closed; the origin "
                 "did not finish them before closing\n";
    return false;
  }
  return true;
}

static bool h2_client_run(SSL *ssl, const std::string &authority,
                          const std::vector<std::string> &paths,
                          int read_timeout_ms,
                          std::vector<std::string> *bodies_out) {
  return ssl->surf_true_mode
             ? h2_client_run_true(ssl, authority, paths, read_timeout_ms,
                                  bodies_out)
             : h2_client_run_masked(ssl, authority, paths, bodies_out);
}

// Prover: one 3P-HS carrying N multiplexed GETs
struct GetResult {
  bool ok = false;
  bool new_session = false;
  std::vector<std::string> bodies;
};

static GetResult do_multiplexed_get(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                                    const std::string &server_ip,
                                    uint16_t server_port,
                                    const std::string &verifier_ip,
                                    uint16_t verifier_port,
                                    const std::string &authority,
                                    const std::vector<std::string> &paths,
                                    bool test_server,
                                    int read_timeout_ms,
                                    SSL_SESSION **inout_session) {
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  const bool is_resumption = (*inout_session != nullptr);

  Prover prover{TLSSocket(pv_ctx, false), TLSSocket(ps_ctx, false)};
  prover.connection_to_server.set_ip_v4();
  prover.connection_to_verifier.set_ip_v4();

  const auto connect_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_verifier.connect_to(verifier_ip, verifier_port) ||
      !read_handshake(prover.connection_to_verifier)) {
    std::cerr << "[Prover] Connecting to verifier failed" << std::endl;
    return {};
  }
  const double verifier_connect_ms = ms_since(connect_start);

  {
    const uint8_t mode = static_cast<uint8_t>(
        is_resumption ? Messaging::MessageHeaders::RUN_RESUMED
                      : Messaging::MessageHeaders::RUN_FULL);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &mode, 1) !=
        1) {
      std::cerr << "[Prover] failed to send run-type tag to verifier\n";
      return {};
    }
  }

  if (!prover.connection_to_server.set_verifier_connection(
          prover.connection_to_verifier.get_ssl_object())) {
    std::cerr << "[Prover] set_verifier_connection failed" << std::endl;
    return {};
  }
  if (!set_callbacks(prover.connection_to_server)) {
    std::cerr << "[Prover] set_callbacks failed" << std::endl;
    return {};
  }

  if (is_resumption) {
    SSL_set_session(prover.connection_to_server.get_ssl_object(),
                    *inout_session);
    SSL_SESSION_free(*inout_session);
    *inout_session = nullptr;
  }

  if (!authority.empty() &&
      authority.find_first_not_of("0123456789.") != std::string::npos) {
    SSL_set_tlsext_host_name(prover.connection_to_server.get_ssl_object(),
                             authority.c_str());
  }

  // Offline phase before the origin connection, so the origin socket does not
  // idle through the MPC.
  const auto preprocess_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.preprocess_circuits()) {
    std::cerr << "[Prover] preprocess_circuits failed" << std::endl;
    return {};
  }
  const double preprocess_ms = ms_since(preprocess_start);

  const auto origin_connect_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.connect_to(server_ip, server_port)) {
    SSL *ps_err = prover.connection_to_server.get_ssl_object();
    std::cerr << "[Prover] connect !ok in_init=" << SSL_in_init(ps_err)
              << " state=" << SSL_state_string_long(ps_err) << "\n";
    dump_err_queue("Prover connect");
    return {};
  }
  const double origin_connect_ms = ms_since(origin_connect_start);
  const double total_connect_ms = ms_since(connect_start);

  SSL *ps = prover.connection_to_server.get_ssl_object();
  if (!require_alpn_h2(ps, "Prover")) {
    std::cerr << "[Prover] ALPN did not negotiate h2\n";
    return {};
  }

  const bool reused = SSL_session_reused(ps) == 1;
  std::cerr << "[Prover] session_reused=" << reused << " streams="
            << paths.size() << std::endl;
  if (is_resumption && !reused) {
    std::cerr << "[Prover] resumed round did not resume: the origin rejected "
                 "the ticket (fixed ticket key set on --is_server?)\n";
    return {};
  }

  // The TRUE-mode drain runs to the peer's FIN. An origin that ignores our
  // GOAWAY would otherwise hang the round, so bound the read.
  if (read_timeout_ms > 0) {
    struct timeval tv;
    tv.tv_sec = read_timeout_ms / 1000;
    tv.tv_usec = (read_timeout_ms % 1000) * 1000;
    ::setsockopt(SSL_get_fd(ps), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  uint64_t verifier_bytes_sent = 0, verifier_bytes_recv = 0;
  wire_bytes(prover.connection_to_verifier.get_ssl_object(),
             &verifier_bytes_sent, &verifier_bytes_recv);

  const auto report = [&](const std::size_t response_bytes) {
    std::cerr << "[Prover] SUMMARY"
              << " round=" << (is_resumption ? "resumed" : "full")
              << " mode=" << g_surf_mode << " host=" << authority
              << " streams=" << paths.size()
              << " verifier_connect_ms=" << verifier_connect_ms
              << " preprocess_ms=" << preprocess_ms
              << " origin_connect_ms=" << origin_connect_ms
              << " total_connect_ms=" << total_connect_ms
              << " mpc_bytes_sent=" << verifier_bytes_sent
              << " mpc_bytes_recv=" << verifier_bytes_recv
              << " response_bytes=" << response_bytes
              << " empty_response=" << (response_bytes == 0 ? 1 : 0)
              << std::endl;
  };

  // Only the test Server writes the 1-byte DONE_HS marker over the TLS
  // session, and only on a full handshake. Reading it on any other path would
  // eat a byte of the H2 connection preface.
  if (test_server && !is_resumption &&
      !read_handshake(prover.connection_to_server)) {
    std::cerr << "[Prover] failed to read server DONE_HS marker\n";
    report(0);
    return {};
  }

  GetResult result;
  if (!h2_client_run(ps, authority, paths, read_timeout_ms,  &result.bodies)) {
    std::cerr << "[Prover] H2 multiplexed GETs failed\n";
    report(0);
    return {};
  }

  std::size_t total = 0;
  for (const auto &b : result.bodies) total += b.size();
  report(total);
  result.ok = true;

  const bool psk_derived = ps->psk_circuit == nullptr;
  if (!psk_derived) {
    const uint8_t skip =
        static_cast<uint8_t>(Messaging::MessageHeaders::PSK_SKIP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &skip, 1) !=
        1) {
      std::cerr << "[Prover] failed to send PSK_SKIP to verifier\n";
      return {};
    }
    std::cerr << "[Prover] no NewSessionTicket this round; sent PSK_SKIP\n";
  } else if (!g_ticket_session) {
    std::cerr << "[Prover] PSK derived but no session captured\n";
  } else {
    *inout_session = g_ticket_session;
    g_ticket_session = nullptr;
    result.new_session = true;
  }

  {
    std::vector<SurfBlockMap::RecordDims> recs;
    for (const auto &r : ps->surf_records) {
      recs.push_back({r.seq, static_cast<uint32_t>(r.ciphertext.size())});
    }
    std::cerr << "[Prover] attested surf_records=" << ps->surf_records.size()
              << " nblocks=" << SurfBlockMap::total_blocks(recs) << "\n";
    const uint8_t stop = static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &stop, 1) !=
        1) {
      std::cerr << "[Prover] failed to send STOP to verifier\n";
      return {};
    }
  }

  SSL_shutdown(ps);
  return result;
}

// Rounds
static int prover_full_round(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                             const std::string &server_ip,
                             uint16_t server_port,
                             const std::string &verifier_ip,
                             uint16_t verifier_port,
                             const std::string &authority,
                             const std::string &path,
                             const std::string &handoff_dir,
                             std::size_t max_assets, bool test_server,
                             int read_timeout_ms) {
  SSL_SESSION *session = nullptr;

  std::cerr << "[Prover] Initial GET " << authority << path << std::endl;
  GetResult r0 = do_multiplexed_get(pv_ctx, ps_ctx, server_ip, server_port,
                                    verifier_ip, verifier_port, authority,
                                    {path}, test_server, read_timeout_ms,
                                    &session);
  if (!r0.ok || r0.bodies.size() != 1) {
    std::cerr << "[Prover] Initial GET failed" << std::endl;
    if (session) SSL_SESSION_free(session);
    return 1;
  }
  std::cerr << "[Prover] Initial body: " << r0.bodies[0].size() << " bytes\n";

  // H2 delivers the body without HTTP/1.1 framing, so the body is the body.
  std::vector<std::string> assets = parse_assets(r0.bodies[0], authority);
  std::cerr << "[Prover] Found " << assets.size() << " asset(s)" << std::endl;
  if (assets.size() > max_assets) {
    std::cerr << "[Prover] Truncating to first " << max_assets << " asset(s)\n";
    assets.resize(max_assets);
  }

  if (!write_assets(handoff_dir, assets)) {
    std::cerr << "[Prover] failed to write the asset list to " << handoff_dir
              << std::endl;
    if (session) SSL_SESSION_free(session);
    return 1;
  }

  if (!session) {
    std::cerr << "[Prover] no NewSessionTicket captured; cannot hand off\n";
    return 1;
  }
  const bool saved = RoundHandoff::save_prover(handoff_dir, session,
                                               session->surf_psk_share);
  SSL_SESSION_free(session);
  if (!saved) {
    std::cerr << "[Prover] failed to write handoff" << std::endl;
    return 1;
  }
  std::cerr << "[Prover] wrote handoff and " << assets.size()
            << " queued asset(s) to " << handoff_dir << std::endl;
  return 0;
}

static int prover_resumed_round(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                                const std::string &server_ip,
                                uint16_t server_port,
                                const std::string &verifier_ip,
                                uint16_t verifier_port,
                                const std::string &authority,
                                const std::string &handoff_dir,
                                bool test_server, int read_timeout_ms) {
  const std::vector<std::string> assets = read_assets(handoff_dir);
  if (assets.empty()) {
    std::cerr << "[Prover] no asset list in " << handoff_dir
              << "; run --round full first (or the page had no same-origin "
                 "assets)\n";
    return 2;
  }

  RoundHandoff::Share psk_share{};
  SSL_SESSION *session =
      RoundHandoff::load_prover(handoff_dir, ps_ctx, psk_share);
  if (!session) {
    std::cerr << "[Prover] cannot load handoff from " << handoff_dir << "\n";
    return 1;
  }
  std::cerr << "[Prover] loaded session and PSK share; fetching "
            << assets.size() << " asset(s) as parallel streams\n";

  GetResult r = do_multiplexed_get(pv_ctx, ps_ctx, server_ip, server_port,
                                   verifier_ip, verifier_port, authority,
                                   assets, test_server, read_timeout_ms,
                                   &session);
  if (!r.ok) {
    std::cerr << "[Prover] multiplexed GETs failed" << std::endl;
    if (session) SSL_SESSION_free(session);
    return 1;
  }
  for (std::size_t i = 0; i < assets.size() && i < r.bodies.size(); ++i) {
    std::cerr << "[Prover] " << assets[i] << ": " << r.bodies[i].size()
              << " bytes\n";
  }

  if (r.new_session && session) {
    if (!RoundHandoff::save_prover(handoff_dir, session,
                                   session->surf_psk_share)) {
      std::cerr << "[Prover] failed to refresh handoff" << std::endl;
      SSL_SESSION_free(session);
      return 1;
    }
    std::cerr << "[Prover] refreshed handoff with the new ticket\n";
  }
  if (session) SSL_SESSION_free(session);
  return 0;
}

int main(int argc, char *argv[]) {
  std::cerr.setf(std::ios::unitbuf);
  bool is_server = false;
  bool is_verifier = false;
  std::string server_ip = "127.0.0.1";
  std::string verifier_ip = "127.0.0.1";
  std::string host;
  std::string path = "/";
  std::string handoff_dir = "/tmp/surf_multigeth2_handoff";
  Round round = Round::Full;
  int accept_timeout_ms = 5000;
  int read_timeout_ms = 30000;
  std::size_t max_assets = 2;
  uint16_t server_port{}, verifier_port{};

  const char *const short_opts = "abs:i:p:v:h:r:t:R:d:m:T:";
  const option long_opts[] = {
      {"is_server",         no_argument,       nullptr, 'a'},
      {"is_verifier",       no_argument,       nullptr, 'b'},
      {"server_ip",         required_argument, nullptr, 's'},
      {"ip",                required_argument, nullptr, 's'},
      {"verifier_ip",       required_argument, nullptr, 'i'},
      {"server_port",       required_argument, nullptr, 'p'},
      {"verifier_port",     required_argument, nullptr, 'v'},
      {"host",              required_argument, nullptr, 'h'},
      {"path",              required_argument, nullptr, 'r'},
      {"round",             required_argument, nullptr, 'R'},
      {"handoff",           required_argument, nullptr, 'd'},
      {"max_assets",        required_argument, nullptr, 'm'},
      {"accept_timeout_ms", required_argument, nullptr, 't'},
      {"read_timeout_ms",   required_argument, nullptr, 'T'},
      {nullptr, 0, nullptr, 0}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) break;
    switch (opt) {
    case 'a': is_server = true; break;
    case 'b': is_verifier = true; break;
    case 's': server_ip = optarg; break;
    case 'i': verifier_ip = optarg; break;
    case 'p': server_port = static_cast<uint16_t>(std::stoi(optarg)); break;
    case 'v': verifier_port = static_cast<uint16_t>(std::stoi(optarg)); break;
    case 'h': host = optarg; break;
    case 'r': path = optarg; break;
    case 'd': handoff_dir = optarg; break;
    case 'm': max_assets = static_cast<std::size_t>(std::stoul(optarg)); break;
    case 't': accept_timeout_ms = std::stoi(optarg); break;
    case 'T': read_timeout_ms = std::stoi(optarg); break;
    case 'R': {
      const std::string arg(optarg);
      if (arg == "full") {
        round = Round::Full;
      } else if (arg == "resumed") {
        round = Round::Resumed;
      } else {
        std::cerr << "--round must be 'full' or 'resumed'\n";
        return 2;
      }
      break;
    }
    default: break;
    }
  }

  const char *const round_name = (round == Round::Full) ? "full" : "resumed";
  {
    const char *const env = ::getenv("SURF_TRUE");
    g_surf_mode = (env && env[0] == '1') ? "true" : "masked";
  }

  // Origin mode (local only). One long-lived process serves every round.
  if (is_server) {
    auto server_ctx = (server_ip == "127.0.0.1")
                          ? CreateContextWithTestCertificate(TLS_method())
                          : CreateContextWOTestCertificate(TLS_method());
    SSL_CTX_set_alpn_select_cb(server_ctx.get(), alpn_select_h2, nullptr);

    Server server(std::move(server_ctx), server_ip, false, /*backlog=*/64,
                  server_port);
    if (!SSL_CTX_set_tlsext_ticket_keys(server.get_ctx(), kTicketKey,
                                        sizeof(kTicketKey))) {
      std::cerr << "[Server] failed to fix the origin ticket key\n";
      return 1;
    }
    server.set_accept_timeout(accept_timeout_ms);
    server.get_portnumber(&server_port);
    std::cerr << "[Server] port=" << server_port << std::endl;

    while (server.accept()) {
      if (!server.do_handshake()) {
        std::cerr << "[Server] do_handshake failed; skipping connection\n";
        continue;
      }
      const bool resumed = SSL_session_reused(server.get_ssl()) == 1;
      std::cerr << "[Server] handshake done, resumed=" << resumed << "\n";
      require_alpn_h2(server.get_ssl(), "Server");
      if (!resumed && !server.write_handshake_done()) {
        std::cerr << "[Server] write_handshake_done failed; skipping\n";
        continue;
      }
      if (!serve_h2(server.get_ssl())) {
        std::cerr << "[Server] serve_h2 ended with error\n";
      }
      // Close cleanly: the TRUE-mode prover terminates its drain on the FIN,
      // and true_surf_release requires the stream to end in a close_notify.
      SSL_shutdown(server.get_ssl());
    }
    std::cerr << "[Server] Done (accept timed out or error)\n";
    return 0;
  }

  // Verifier mode: exactly one MPC session, then exit.
  if (is_verifier) {
    Server verifier(CreateContextWithTestCertificate(TLS_method()), verifier_ip,
                    false, /*backlog=*/64, verifier_port);
    verifier.set_attestation();
    verifier.set_accept_timeout(accept_timeout_ms);
    verifier.get_portnumber(&verifier_port);
    std::cerr << "[Verifier] port=" << verifier_port << " round=" << round_name
              << " mode=" << g_surf_mode << std::endl;

    const auto kind = verifier.accept_and_read_mode(true);
    if (kind == Server::SessionKind::Idle) {
      std::cerr << "[Verifier] no prover connected within " << accept_timeout_ms
                << " ms" << std::endl;
      return 1;
    }
    const bool prover_resumed = (kind == Server::SessionKind::Resumed);
    if (prover_resumed != (round == Round::Resumed)) {
      std::cerr << "[Verifier] WARNING: --round " << round_name
                << " but the prover declared "
                << (prover_resumed ? "resumed" : "full")
                << "; following the prover" << std::endl;
    }

    if (prover_resumed) {
      RoundHandoff::Share share{};
      if (!RoundHandoff::load_share(
              RoundHandoff::verifier_share_path(handoff_dir), share)) {
        std::cerr << "[Verifier] cannot load verifier PSK share from "
                  << handoff_dir << std::endl;
        return 1;
      }
      verifier.set_psk_share(share);
    }

    const auto start = std::chrono::steady_clock::now();
    const bool worked =
        prover_resumed
            ? verifier.run_resumption(Server::ServerState::DONE, true, true,
                                      /*already_accepted=*/true)
            : verifier.run(Server::ServerState::DONE, true, true,
                           /*already_accepted=*/true);
    if (!worked) {
      std::cerr << "[Verifier] run failed" << std::endl;
      return 1;
    }
    std::cerr << "[Verifier] SUMMARY round="
              << (prover_resumed ? "resumed" : "full")
              << " mode=" << g_surf_mode << " total_ms=" << ms_since(start)
              << std::endl;

    if (!RoundHandoff::save_share(
            RoundHandoff::verifier_share_path(handoff_dir),
            verifier.get_psk_share())) {
      std::cerr << "[Verifier] failed to save verifier PSK share" << std::endl;
      return 1;
    }
    std::cerr << "[Verifier] Done" << std::endl;
    return 0;
  }

  // Prover mode: one round per process.
  std::error_code ec;
  std::filesystem::create_directories(handoff_dir, ec);
  if (ec) {
    std::cerr << "[Prover] cannot create handoff dir " << handoff_dir << ": "
              << ec.message() << std::endl;
    return 1;
  }

  std::string authority = host.empty() ? server_ip : host;

  if (!host.empty()) {
    std::string resolved = resolve_hostname(host);
    if (resolved.empty()) {
      std::cerr << "[Prover] Could not resolve hostname: " << host << std::endl;
      return 1;
    }
    server_ip = resolved;
    std::cerr << "[Prover] Resolved " << host << " -> " << server_ip << "\n";
    if (server_port == 0) server_port = 443;
    g_origin_rtt_ms = measure_rtt_ms(server_ip, server_port);
  }
  std::cerr << "[Prover] round=" << round_name << " mode=" << g_surf_mode
            << " RTT origin=" << g_origin_rtt_ms << "ms" << std::endl;

  // Whether the origin is our own --is_server, which writes the 1-byte DONE_HS
  // marker over the TLS session. Keyed off the resolved address, since callers
  // may reach it via --host 127.0.0.1; getting this wrong leaves DONE_HS
  // unread and corrupts the H2 connection preface.
  const bool test_server = (server_ip == "127.0.0.1");

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = (server_ip == "127.0.0.1")
                    ? CreateContextWithTestCertificate(TLS_method())
                    : CreateContextWOTestCertificate(TLS_method());
  SSL_CTX_set_alpn_protos(ps_ctx.get(), kAlpnH2, sizeof(kAlpnH2));
  SSL_CTX_set_session_cache_mode(
      ps_ctx.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(ps_ctx.get(), new_session_cb);

  const int rc =
      (round == Round::Full)
          ? prover_full_round(pv_ctx.get(), ps_ctx.get(), server_ip,
                              server_port, verifier_ip, verifier_port,
                              authority, path, handoff_dir, max_assets,
                              test_server, read_timeout_ms)
          : prover_resumed_round(pv_ctx.get(), ps_ctx.get(), server_ip,
                                 server_port, verifier_ip, verifier_port,
                                 authority, handoff_dir, test_server,
                                 read_timeout_ms);

  if (g_ticket_session) {
    SSL_SESSION_free(g_ticket_session);
    g_ticket_session = nullptr;
  }
  std::cerr << "[Prover] round=" << round_name << " rc=" << rc << std::endl;
  return rc;
}
