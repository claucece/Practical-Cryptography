/*
  MultiGet benchmark: the prover does one full 3P-HS for the initial GET, then
  fetches every discovered asset over a Surf-PSK *resumed* handshake.

  Rounds run one per process, as in E2E.b.cpp. `--round full` performs the full
  handshake, parses the HTML, and writes to the handoff directory: the session
  ticket, the prover's PSK share, the verifier's PSK share, the discovered
  asset list, and a cursor. `--round resumed` reads them back, fetches the
  asset at the cursor over a PSK-resumption handshake, advances the cursor, and
  re-saves the ticket if the origin issued a fresh one.

  Splitting the rounds means each round's online phases are free of the
  first-touch page faults a second round in the same process pays on
  re-allocated preprocessing material.

  Usage (origin and verifier in their own terminals, prover once per round):
    ./MultiGetBench --is_server   --ip 127.0.0.1
    SURF_TRUE=1 ./MultiGetBench --is_verifier --ip 127.0.0.1 --round full
    SURF_TRUE=1 ./MultiGetBench --ip 127.0.0.1 -p <sp> -v <vp> --round full
    (then one verifier and one prover per asset, with --round resumed)
*/

#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <gumbo.h>
#include <csignal>

#include "../nodes/Events.hpp"
#include "../nodes/Server.hpp"
#include "../ssl/Messaging.hpp"
#include "../ssl/Roundhandoff.hpp"
#include "../ssl/TestUtil.hpp"
#include "../ssl/ThreePartyHandshake.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
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

// Which SURF mode this process is running, for the stderr summary. Read once in
// main; the record layer reads the same variable independently via getenv.
static const char *g_surf_mode = "masked";

// Canned responses served by --is_server. GET / returns a minimal but
// well-formed HTML page referencing exactly two root-absolute resources (an
// image and a script); the asset parser extracts /img/logo.png and /js/app.js.
// The HTML body is exactly 112 bytes (keep Content-Length in sync if edited).
static const char HTML_RESPONSE[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
    "Content-Length: 112\r\nConnection: close\r\n\r\n"
    "<!doctype html><title>Surf MultiGet test site</title>"
    "<img src=\"/img/logo.png\">"
    "<script src=\"/js/app.js\"></script>";

static const char ASSET_RESPONSE[] =
    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
    "Content-Length: 4\r\nConnection: close\r\n\r\ndata";

// The origin must decrypt a ticket minted by a previous round's process.
// SSL_CTX_new generates a fresh ticket key per process, so without a fixed key
// every resumed round silently falls back to a full handshake -- and the PSK
// material on disk would then be paired with a session the origin rejected.
// This also disables BoringSSL's automatic 48-hour key rotation, which is fine
// for a benchmark and would not be for a deployment.
static const uint8_t kTicketKey[48] = {
    0x53, 0x55, 0x52, 0x46, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x67, 0x65, 0x74,
    0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d};

// RoundHandoff owns the session ticket and the two PSK shares. The asset queue
// is this benchmark's own state: the full round discovers it, and each resumed
// round consumes one entry.
//
//   <dir>/            ... RoundHandoff's files (ticket, prover + verifier share)
//   <dir>/assets.txt  ... one origin-absolute path per line, in discovery order
//   <dir>/cursor      ... index of the next asset to fetch
static std::string assets_file(const std::string &dir) {
  return dir + "/assets.txt";
}

static std::string cursor_file(const std::string &dir) {
  return dir + "/cursor";
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

static bool write_cursor(const std::string &dir, std::size_t n) {
  std::ofstream f(cursor_file(dir), std::ios::trunc);
  if (!f) return false;
  f << n << "\n";
  f.flush();
  return f.good();
}

static std::size_t read_cursor(const std::string &dir) {
  std::ifstream f(cursor_file(dir));
  std::size_t n = 0;
  if (!(f >> n)) return 0;
  return n;
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

static std::string build_http_request(const std::string &host,
                                      const std::string &path) {
  return "GET " + path + " HTTP/1.1\r\n"
         "Host: " + host + "\r\n"
         "User-Agent: Surf/1.0\r\n"
         "Connection: close\r\n\r\n";
}

// SURF encrypts the request through aes_enc_circuit, which is provisioned for
// AES_ENC_N blocks per execution and aes_enc_iters executions. Past that,
// encrypt_request returns a bare false and the failure surfaces as an opaque
// SSL_write error; check here so the message names the real cause. Raising the
// ceiling means raising aes_enc_iters on BOTH parties, since the circuit set is
// built in lock-step.
static constexpr std::size_t kAesEncIters = 4;
static constexpr std::size_t kMaxRequestBytes =
    16 * EmpWrapperAG2PCConstants::AES_ENC_N * kAesEncIters - 1;

static bool request_fits(const std::string &req) {
  // +1: RFC 8446 5.2 appends the inner content type to the plaintext.
  return req.size() + 1 <= kMaxRequestBytes + 1;
}

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

static void clienthello_msg_cb(int write_p, int /*version*/, int content_type,
                               const void *buf, size_t len, SSL * /*ssl*/,
                               void * /*arg*/) {
  // Only outgoing handshake records whose first byte is ClientHello (type 1).
  if (write_p != 1 || content_type != SSL3_RT_HANDSHAKE || len == 0) return;
  const auto *p = static_cast<const uint8_t *>(buf);
  if (p[0] != SSL3_MT_CLIENT_HELLO) return;
}

static void dump_err_queue(const char* tag) {
  const char* file = nullptr;
  int line = 0;
  const char* data = nullptr;
  int flags = 0;

  uint32_t err;
  while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    std::cerr << "[" << tag << "] " << buf
              << " lib=" << (ERR_lib_error_string(err) ? ERR_lib_error_string(err) : "?")
              << " reason=" << (ERR_reason_error_string(err) ? ERR_reason_error_string(err) : "?")
              << " at " << (file ? file : "?") << ":" << line;

    if (data && (flags & ERR_FLAG_STRING)) {
      std::cerr << " data=" << data;
    }
    std::cerr << "\n";
  }
}

// Session ticket capture (Surf-PSK resumption)
static SSL_SESSION *g_ticket_session = nullptr;

static int new_session_cb(SSL * /*ssl*/, SSL_SESSION *session) {
  // SURF: the PSK is derived (in MPC) only for the FIRST NewSessionTicket's
  // nonce — see derive_psk_keys in ThreePartyHandshake.cpp, which consumes the
  // single psk_circuit on its first invocation and no-ops thereafter. Real
  // servers (e.g. cutler.pl) send multiple tickets; we MUST resume with the
  // first one so the client's PSK binder matches the server's PSK.
  if (g_ticket_session != nullptr) {
    return 0;  // not the first ticket: decline ownership, BoringSSL frees it
  }
  g_ticket_session = session;
  return 1;  // take ownership; caller frees
}

// Timing helpers
static double ms_since(const std::chrono::steady_clock::time_point start) {
  using namespace std::chrono;
  return duration_cast<duration<double, std::milli>>(steady_clock::now() - start)
      .count();
}

// One completed TCP handshake is one RTT.
// Returns the median of `samples`, or -1 if every attempt failed.
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
        rc = -1;  // timed out, or poll failed
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

// Raw TLS-wire bytes exchanged over `ssl` so fa
static void wire_bytes(SSL *ssl, uint64_t *sent, uint64_t *received) {
  *sent = ssl ? BIO_number_written(SSL_get_wbio(ssl)) : 0;
  *received = ssl ? BIO_number_read(SSL_get_rbio(ssl)) : 0;
}

// Gumbo HTML asset extraction

// Resolves an asset reference `val` (an element's src/href value) into the
// origin-absolute request path to GET, or returns "" to skip it. The benchmark
// 3PHs against a *single* origin (`host`), so "all assets" means every asset
// hosted on that origin; cross-host and non-fetchable references are dropped:
//   - fragments (#...) and non-navigable schemes (mailto:/javascript:/tel:/data:)
//   - absolute URLs (scheme://host/... or protocol-relative //host/...) whose
//     host differs from `host`
// Absolute URLs on `host` keep their path; relative refs resolve against the
// document root "/": "/x" stays "/x", "./x" -> "/x", bare "x" -> "/x".
static std::string resolve_asset_path(const std::string &val,
                                      const std::string &host) {
  if (val.empty() || val[0] == '#') return "";

  const auto lower = [](std::string s) {
    for (auto &c : s) c = static_cast<char>(std::tolower((unsigned char)c));
    return s;
  };

  // Absolute forms: protocol-relative "//host/..." or "scheme://host/...".
  std::string authority_and_path;
  if (val.rfind("//", 0) == 0) {
    authority_and_path = val.substr(2);
  } else if (const auto s = val.find("://"); s != std::string::npos) {
    authority_and_path = val.substr(s + 3);
  } else if (const auto c = val.find(':');
             c != std::string::npos && c < val.find('/')) {
    // A scheme with no authority (mailto:, javascript:, tel:, data:) — nothing
    // fetchable over the origin connection.
    return "";
  }

  if (!authority_and_path.empty() || val.rfind("//", 0) == 0) {
    const auto slash = authority_and_path.find('/');
    std::string h = (slash == std::string::npos) ? authority_and_path
                                                  : authority_and_path.substr(0, slash);
    if (const auto at = h.find('@'); at != std::string::npos) h = h.substr(at + 1);
    if (const auto colon = h.find(':'); colon != std::string::npos)
      h = h.substr(0, colon);
    if (lower(h) != lower(host)) return "";  // different origin: unfetchable here
    return (slash == std::string::npos) ? "/" : authority_and_path.substr(slash);
  }

  // Relative references, resolved against the document root "/".
  if (val[0] == '/') return val;                       // origin-absolute path
  if (val.rfind("./", 0) == 0) return val.substr(1);   // "./x" -> "/x"
  return "/" + val;                                    // bare "x" -> "/x"
}

static void collect_assets(GumboNode *node, const std::string &host,
                           std::vector<std::string> &out) {
  if (!node || node->type != GUMBO_NODE_ELEMENT) return;
  const GumboTag tag = node->v.element.tag;
  for (const char *attr_name : {"src", "href"}) {
    // Skip hyperlinks: <a href> and <area href> are navigation, not assets.
    if (std::strcmp(attr_name, "href") == 0 &&
        (tag == GUMBO_TAG_A || tag == GUMBO_TAG_AREA)) {
      continue;
    }
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

// Extracts every same-origin asset path referenced by `html`, de-duplicated
// while preserving first-seen order. `host` is the origin we 3PH against.
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

// HTTP response utilities
static std::string extract_body(const std::string &resp) {
  const auto pos = resp.find("\r\n\r\n");
  return (pos == std::string::npos) ? "" : resp.substr(pos + 4);
}

static bool is_html_response(const std::string &resp) {
  const auto pos = resp.find("\r\n\r\n");
  return pos != std::string::npos &&
         resp.substr(0, pos).find("text/html") != std::string::npos;
}

// Core prover helper: one 3P-HS + HTTP GET
struct GetResult {
  bool ok = false;
  // The origin issued a NewSessionTicket whose PSK we derived, and it has been
  // installed in *inout_session. When false the handoff on disk is unchanged
  // and still describes the session we just used.
  bool new_session = false;
  std::string response;
};

static GetResult do_single_get(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                               const std::string &server_ip,
                               uint16_t server_port,
                               const std::string &verifier_ip,
                               uint16_t verifier_port,
                               const std::string &http_host,
                               const std::string &path,
                               SSL_SESSION **inout_session) {
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  const bool is_resumption = (*inout_session != nullptr);

  // Fail before any MPC if the request cannot fit the encryption circuit: the
  // preprocessing is ~14 s and ~900 MiB, and burning it to hit a bare false in
  // encrypt_request tells you nothing.
  const std::string req = build_http_request(http_host, path);
  if (!request_fits(req)) {
    std::cerr << "[Prover] request is " << req.size() << " bytes; the 2PC "
                 "encryption circuit is provisioned for " << kMaxRequestBytes
              << ". Shorten the Host/path or raise aes_enc_iters on both "
                 "parties.\n";
    return {};
  }

  Prover prover{TLSSocket(pv_ctx, false), TLSSocket(ps_ctx, false)};
  prover.connection_to_server.set_ip_v4();
  prover.connection_to_verifier.set_ip_v4();

  // 1) Connect to verifier and wait for DONE_HS marker.
  const auto connect_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_verifier.connect_to(verifier_ip, verifier_port) ||
      !read_handshake(prover.connection_to_verifier)) {
    std::cerr << "[Prover] Connecting to verifier failed" << std::endl;
    return {};
  }
  const double verifier_connect_ms = ms_since(connect_start);

  // 1.5) Declare this MPC session's run-type to the verifier (the first byte
  // after DONE_HS, before any preprocessing). The verifier dispatches run() vs
  // run_resumption() off this tag, so it never has to guess full-vs-resumed from
  // an accept() timeout between back-to-back provers.
  {
    const uint8_t mode = static_cast<uint8_t>(
        is_resumption ? Messaging::MessageHeaders::RUN_RESUMED
                      : Messaging::MessageHeaders::RUN_FULL);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &mode, 1) !=
        1) {
      std::cerr << "[Prover] failed to send run-type tag to verifier"
                << std::endl;
      return {};
    }
  }

  // 2) Link verifier into server connection.
  if (!prover.connection_to_server.set_verifier_connection(
          prover.connection_to_verifier.get_ssl_object())) {
    std::cerr << "[Prover] set_verifier_connection failed" << std::endl;
    return {};
  }

  // 3) Install 3PH callbacks.
  if (!set_callbacks(prover.connection_to_server)) {
    std::cerr << "[Prover] set_callbacks failed" << std::endl;
    return {};
  }

  // 4) Resumption path: install the session loaded from the handoff before
  // SSL_connect. SSL_set_session takes its own reference, so we drop ours here
  // and let the caller's pointer be repopulated only if a fresh ticket arrives.
  if (is_resumption) {
    SSL_set_session(prover.connection_to_server.get_ssl_object(),
                    *inout_session);
    SSL_SESSION_free(*inout_session);
    *inout_session = nullptr;
  }

  // SNI: required by virtual-hosted servers (e.g. Cloudflare). Skip if the
  // host string is an IP literal — RFC 6066 forbids IPs in SNI.
  if (!http_host.empty() &&
      http_host.find_first_not_of("0123456789.") != std::string::npos) {
    SSL_set_tlsext_host_name(prover.connection_to_server.get_ssl_object(),
                             http_host.c_str());
  }

  // 4.5) Offline phase: run the slow circuit preprocessing BEFORE opening the
  // origin connection. Otherwise the origin socket sits idle through the MPC and
  // a remote (WAN) verifier's round-trips exceed the origin's idle timeout.
  // Timed separately: this is the offline MPC, not the online origin handshake.
  //
  // Rounds are one per process, so nothing is amortised here: each resumed
  // fetch pays the full preprocessing again. That is the honest cost of
  // adaptive fetching and it is what this benchmark is for.
  const auto preprocess_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.preprocess_circuits()) {
    std::cerr << "[Prover] preprocess_circuits failed" << std::endl;
    return {};
  }
  const double preprocess_ms = ms_since(preprocess_start);

  // 5) Connect to server — triggers SSL_connect and all 3PH callbacks. Timed
  // from here so origin_connect_ms is the online handshake only (no preproc).
  const auto origin_connect_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.connect_to(server_ip, server_port)) {
    SSL *ps_err = prover.connection_to_server.get_ssl_object();
    std::cerr << "[Prover] connect !ok"
            << " in_init=" << SSL_in_init(ps_err)
            << " state=" << SSL_state_string_long(ps_err)
            << " session_reused=" << SSL_session_reused(ps_err) << "\n";
    dump_err_queue("Prover connect");
    int sslerr = SSL_get_error(ps_err, -1);
    std::cerr << "[Prover] connect_to server failed; SSL_get_error=" << sslerr
              << std::endl;
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
      char buf[256];
      ERR_error_string_n(e, buf, sizeof(buf));
      std::cerr << "[Prover] SSL err: " << buf << std::endl;
    }
    return {};
  }

  const double origin_connect_ms = ms_since(origin_connect_start);
  const double total_connect_ms = ms_since(connect_start);

  SSL *ps = prover.connection_to_server.get_ssl_object();
  const bool reused = SSL_session_reused(ps) == 1;
  std::cerr << "[Prover] session_reused=" << reused << " path=" << path
            << std::endl;

  // A resumed round that silently fell back to a full handshake is not the
  // measurement we asked for, and it invalidates the PSK material we are about
  // to re-save. Fail loudly rather than reporting a mislabelled round.
  if (is_resumption && !reused) {
    std::cerr << "[Prover] resumed round did not resume: the origin rejected "
                 "the ticket (fixed ticket key set on --is_server?)\n";
    return {};
  }

  // Capture the MPC byte counts now (right after the handshake) so they reflect
  // the 3PH traffic with the verifier, not the later GET.
  uint64_t verifier_bytes_sent = 0, verifier_bytes_recv = 0;
  wire_bytes(prover.connection_to_verifier.get_ssl_object(),
             &verifier_bytes_sent, &verifier_bytes_recv);

  // One summary line per connection, in the style of E2E.b.cpp's stderr
  // reporting. The verifier's TIMINGS / DATA blocks carry the per-phase
  // breakdown; this is the prover's view. An empty response is the signature of
  // the origin's TLS handshake timeout firing mid-3PH, so it is called out.
  const auto report = [&](const std::size_t response_bytes) {
    std::cerr << "[Prover] SUMMARY"
              << " round=" << (is_resumption ? "resumed" : "full")
              << " mode=" << g_surf_mode
              << " host=" << http_host
              << " path=" << path
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

  // 6) Send HTTP GET.
  int ret_code = 0;
  if (!prover.connection_to_server.write(
          reinterpret_cast<const uint8_t *>(req.data()), req.size(),
          &ret_code)) {
    std::cerr << "[Prover] write failed, ret_code=" << ret_code << std::endl;
    report(0);
    return {};
  }

  // 7) Read full response. In TRUE mode every record is captured sealed and
  // read() yields nothing, so this drains until the close_notify record turns
  // up; the payload comes out of true_surf_release below.
  std::string response;
  char buf[4096];
  for (;;) {
    int n = prover.connection_to_server.read(buf, static_cast<int>(sizeof(buf)));
    if (n <= 0) {
      int ssl_err = SSL_get_error(ps, n);
      std::cerr << "[Prover] read n=" << n << " ssl_err=" << ssl_err
                << " errno=" << errno << std::endl;
      if (!ps->surf_true_mode) {
        dump_err_queue("Prover/SSL_read");
      }
      break;
    }
    response.append(buf, static_cast<size_t>(n));
  }

  // 7.5) SURF TRUE mode: the whole attestation runs here -- commit to k_c,
  // submit every captured record's tag, take k_v, decrypt. This must precede
  // the PSK phase below: the NewSessionTicket arrived sealed, so
  // derive_psk_keys only fires inside true_surf_release, when the decrypted
  // ticket is fed back to the handshake layer. Testing psk_circuit before that
  // would report no PSK and send PSK_SKIP for a circuit we are about to run.
  if (ps->surf_true_mode) {
    bssl::Array<uint8_t> plaintext;
    if (!ThreePartyHandshake::true_surf_release(ps, plaintext)) {
      std::cerr << "[Prover] true_surf_release failed\n";
      report(0);
      return {};
    }
    response.assign(reinterpret_cast<const char *>(plaintext.data()),
                    plaintext.size());
    std::cerr << "[Prover] TRUE release: " << ps->surf_records.size()
              << " records, payload=" << plaintext.size() << " bytes\n";
  }

  report(response.size());

  GetResult result;
  result.ok = true;
  result.response = std::move(response);

  // 8) PSK reveal / splice. The verifier walks the PSK phase on EVERY run
  //    (run_resumption's state list includes DERIVE_PSK), and derive_psk blocks
  //    reading a header. The prover only sends DERIVE_PSK (and the verifier only
  //    sends the 16-byte reveal back) when derive_psk_keys fired while
  //    processing a NewSessionTicket -- which consumes psk_circuit (sets it
  //    null). An external origin can send no NST on a given connection
  //    (cutler.pl issues a ticket on the first resumption but not later ones),
  //    so a non-null psk_circuit here means no PSK was derived and no DERIVE_PSK
  //    was sent. Tell the verifier to skip the whole PSK phase via PSK_SKIP,
  //    else it blocks forever on the DERIVE_PSK header while we block on a reveal
  //    that never comes -> deadlock at "Deriving psk".
  const bool psk_derived = ps->psk_circuit == nullptr;
  if (!psk_derived) {
    const uint8_t skip =
        static_cast<uint8_t>(Messaging::MessageHeaders::PSK_SKIP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &skip, 1) !=
        1) {
      std::cerr << "[Prover] failed to send PSK_SKIP to verifier" << std::endl;
      return {};
    }
    std::cerr << "[Prover] no NewSessionTicket this round; sent PSK_SKIP. "
                 "The handoff on disk is left as-is and the next resumed "
                 "round will replay the same ticket.\n";
  } else if (!g_ticket_session) {
    std::cerr << "[Prover] PSK derived but no session captured; resumption "
                 "material not refreshed" << std::endl;
  } else {
    *inout_session = g_ticket_session;
    g_ticket_session = nullptr;
    result.new_session = true;
  }

  // 9) SURF: release the verifier from attest(). In masked mode every captured
  // record was already verified and its keystream derived inline from
  // tls_open_record as the record arrived (Algorithm 2); in TRUE mode step 7.5
  // did the whole batch. Either way there is no work left here, only the
  // terminator. Must come after the PSK phase above, since the verifier reaches
  // SHUTDOWN (and therefore attest()) only after PSK_DONE.
  {
    std::vector<SurfBlockMap::RecordDims> recs;
    for (const auto &r : ps->surf_records) {
      recs.push_back({r.seq, static_cast<uint32_t>(r.ciphertext.size())});
    }
    std::cerr << "[Prover] attested surf_records=" << ps->surf_records.size()
              << " nblocks=" << SurfBlockMap::total_blocks(recs) << "\n";

    const uint8_t stop =
        static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &stop, 1) !=
        1) {
      std::cerr << "[Prover] failed to send STOP to verifier" << std::endl;
      return {};
    }
  }

  SSL_shutdown(ps);
  return result;
}

// Prover rounds
static int prover_full_round(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                             const std::string &server_ip,
                             uint16_t server_port,
                             const std::string &verifier_ip,
                             uint16_t verifier_port,
                             const std::string &http_host,
                             const std::string &path,
                             const std::string &handoff_dir,
                             std::size_t max_assets) {
  SSL_SESSION *session = nullptr;

  std::cerr << "[Prover] Initial GET " << http_host << path << std::endl;
  GetResult r0 =
      do_single_get(pv_ctx, ps_ctx, server_ip, server_port, verifier_ip,
                    verifier_port, http_host, path, &session);
  if (!r0.ok) {
    std::cerr << "[Prover] Initial GET failed" << std::endl;
    return 1;
  }
  std::cerr << "[Prover] Initial response: " << r0.response.size() << " bytes"
            << std::endl;

  std::vector<std::string> assets;
  if (is_html_response(r0.response)) {
    assets = parse_assets(extract_body(r0.response), http_host);
  }
  std::cerr << "[Prover] Found " << assets.size() << " asset(s)" << std::endl;

  if (assets.size() > max_assets) {
    std::cerr << "[Prover] Truncating to first " << max_assets << " asset(s)"
              << std::endl;
    assets.resize(max_assets);
  }

  // The asset queue must be on disk before we report success: the resumed
  // rounds are separate processes with no other way to learn what to fetch.
  if (!write_assets(handoff_dir, assets) || !write_cursor(handoff_dir, 0)) {
    std::cerr << "[Prover] failed to write the asset queue to " << handoff_dir
              << std::endl;
    if (session) SSL_SESSION_free(session);
    return 1;
  }

  if (!session) {
    std::cerr << "[Prover] no NewSessionTicket captured; cannot hand off"
              << std::endl;
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
                                const std::string &http_host,
                                const std::string &handoff_dir) {
  const std::vector<std::string> assets = read_assets(handoff_dir);
  if (assets.empty()) {
    std::cerr << "[Prover] no asset queue in " << handoff_dir
              << "; run --round full first" << std::endl;
    return 1;
  }
  const std::size_t cursor = read_cursor(handoff_dir);
  if (cursor >= assets.size()) {
    std::cerr << "[Prover] asset queue exhausted (" << cursor << "/"
              << assets.size() << "); nothing to fetch" << std::endl;
    return 2;  // distinct from failure: the driver stops on this
  }
  const std::string &path = assets[cursor];

  RoundHandoff::Share psk_share{};
  SSL_SESSION *session =
      RoundHandoff::load_prover(handoff_dir, ps_ctx, psk_share);
  if (!session) {
    std::cerr << "[Prover] cannot load handoff from " << handoff_dir
              << std::endl;
    return 1;
  }
  // Reattaching surf_psk_share to the loaded session is enough: the prover's
  // ssl->psk_share is lifted off the session in do_read_server_hello, and
  // derive_binder reads the session field directly.
  std::cerr << "[Prover] loaded session and PSK share from " << handoff_dir
            << "; asset " << (cursor + 1) << "/" << assets.size() << " "
            << path << std::endl;

  GetResult r = do_single_get(pv_ctx, ps_ctx, server_ip, server_port,
                              verifier_ip, verifier_port, http_host, path,
                              &session);
  if (!r.ok) {
    std::cerr << "[Prover] Failed on asset " << path << std::endl;
    if (session) SSL_SESSION_free(session);
    return 1;
  }
  std::cerr << "[Prover] " << path << ": " << r.response.size() << " bytes"
            << std::endl;

  // Advance the cursor only on success, so a failed round can be retried
  // against the same asset.
  if (!write_cursor(handoff_dir, cursor + 1)) {
    std::cerr << "[Prover] failed to advance the asset cursor" << std::endl;
    if (session) SSL_SESSION_free(session);
    return 1;
  }

  if (r.new_session && session) {
    // A fresh ticket: overwrite the handoff so the next round resumes off this
    // connection rather than replaying a spent one.
    if (!RoundHandoff::save_prover(handoff_dir, session,
                                   session->surf_psk_share)) {
      std::cerr << "[Prover] failed to refresh handoff" << std::endl;
      SSL_SESSION_free(session);
      return 1;
    }
    std::cerr << "[Prover] refreshed handoff with the new ticket" << std::endl;
  }
  if (session) SSL_SESSION_free(session);
  return 0;
}

// main
int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);

  bool is_server = false;
  bool is_verifier = false;
  std::string server_ip = "127.0.0.1";
  std::string verifier_ip = "127.0.0.1";
  std::string host;
  std::string path = "/";
  std::string handoff_dir = "/tmp/surf_multiget_handoff";
  Round round = Round::Full;
  int accept_timeout_ms = 5000;
  // Cap the number of assets queued, to keep benchmark runtime bounded.
  std::size_t max_assets = 2;

  uint16_t server_port{}, verifier_port{};

  const char *const short_opts = "abs:i:p:v:h:r:t:R:d:m:";
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
      {nullptr, 0, nullptr, 0}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) break;
    switch (opt) {
    case 'a': is_server   = true; break;
    case 'b': is_verifier = true; break;
    case 's': server_ip   = optarg; break;
    case 'i': verifier_ip = optarg; break;
    case 'p': server_port   = static_cast<uint16_t>(std::stoi(optarg)); break;
    case 'v': verifier_port = static_cast<uint16_t>(std::stoi(optarg)); break;
    case 'h': host         = optarg; break;
    case 'r': path         = optarg; break;
    case 'd': handoff_dir  = optarg; break;
    case 'm': max_assets   = static_cast<std::size_t>(std::stoul(optarg)); break;
    case 't': accept_timeout_ms = std::stoi(optarg); break;
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

  // Server mode: loop, handle one HTTP connection per iteration, exit on
  // accept timeout. One long-lived origin serves every round.
  if (is_server) {
    auto server_ctx = (server_ip == "127.0.0.1")
                          ? CreateContextWithTestCertificate(TLS_method())
                          : CreateContextWOTestCertificate(TLS_method());

    Server server(std::move(server_ctx), server_ip, false, /*backlog=*/64,
              server_port);

    if (!SSL_CTX_set_tlsext_ticket_keys(server.get_ctx(), kTicketKey,
                                        sizeof(kTicketKey))) {
      std::cerr << "[Server] failed to fix the origin ticket key" << std::endl;
      return 1;
    }
    server.set_accept_timeout(accept_timeout_ms);
    server.get_portnumber(&server_port);
    std::cerr << "[Server] port=" << server_port << std::endl;

    // First connection is the full handshake (write_handshake_done required);
    // every subsequent connection is a Surf-PSK resumption
    while (server.accept()) {
      if (!server.do_handshake()) {
        std::cerr << "[Server] do_handshake failed; skipping connection"
                  << std::endl;
        continue;
      }
      const bool resumed = SSL_session_reused(server.get_ssl()) == 1;
      std::cerr << "[Server] handshake done, resumed=" << resumed << std::endl;
      if (!resumed && !server.write_handshake_done()) {
        std::cerr << "[Server] write_handshake_done failed; skipping connection"
                  << std::endl;
        continue;
      }

      char req_buf[4096] = {};
      int n = SSL_read(server.get_ssl(), req_buf, sizeof(req_buf) - 1);
      if (n <= 0) {
        std::cerr << "[Server] SSL_read failed: "
                  << SSL_get_error(server.get_ssl(), n) << std::endl;
        continue;
      }
      req_buf[n] = '\0';
      std::cerr << "[Server] Received request (" << n << " bytes)" << std::endl;

      // Dispatch based on path: GET / → HTML, anything else → asset.
      const bool is_asset = (std::strstr(req_buf, "GET / ") == nullptr);
      const char *resp = is_asset ? ASSET_RESPONSE : HTML_RESPONSE;
      SSL_write(server.get_ssl(), resp, static_cast<int>(std::strlen(resp)));

      SSL_shutdown(server.get_ssl());
    }
    std::cerr << "[Server] Done (accept timed out or error)" << std::endl;
    return 0;
  }

  // Verifier mode: serve exactly one MPC session, then exit. Rounds are one
  // per process on both sides, so the verifier's PSK share crosses the round
  // boundary on disk: the full round derives it, every resumed round consumes
  // it in do_ks / do_psk_binder and re-saves whatever it ends up holding.
  //
  // run()/run_resumption() print the TIMINGS / DATA / rounds blocks to stderr
  // when their `print` argument is true; that output is what aggregate_e2e.py
  // parses, so this mode writes no file of its own.
  if (is_verifier) {
    Server verifier(CreateContextWithTestCertificate(TLS_method()), verifier_ip,
                false, /*backlog=*/64, verifier_port);
    // SURF: walk attest() at SHUTDOWN. Without this the verifier never drains
    // the prover's GCM_VERIFY / KS_DERIVE (masked) or KEY_COMMIT / GCM_VERIFY /
    // KEY_RELEASE (TRUE) traffic and both sides deadlock.
    verifier.set_attestation();
    verifier.set_accept_timeout(accept_timeout_ms);
    verifier.get_portnumber(&verifier_port);
    std::cerr << "[Verifier] port=" << verifier_port << " round=" << round_name
              << " mode=" << g_surf_mode << std::endl;

    // The connection self-declares its run-type via the prover's tag, which
    // accept_and_read_mode() reads; we dispatch off it rather than off --round,
    // so a mismatch between the two processes shows up as a warning instead of
    // a hang. SessionKind::Idle means no prover connected in the window.
    const auto kind = verifier.accept_and_read_mode(true);
    if (kind == Server::SessionKind::Idle) {
      std::cerr << "[Verifier] no prover connected within "
                << accept_timeout_ms << " ms" << std::endl;
      return 1;
    }
    const bool prover_resumed = (kind == Server::SessionKind::Resumed);
    if (prover_resumed != (round == Round::Resumed)) {
      std::cerr << "[Verifier] WARNING: --round " << round_name
                << " but the prover declared "
                << (prover_resumed ? "resumed" : "full")
                << "; following the prover" << std::endl;
    }

    // The verifier's share must be in hand before do_ks and do_psk_binder,
    // both of which run inside run_resumption below.
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
              << " mode=" << g_surf_mode
              << " total_ms=" << ms_since(start) << std::endl;

    // Save unconditionally: on a PSK_SKIP round the share is unchanged and
    // rewriting it is a no-op, and on any other round the next resumed round
    // needs whatever we now hold.
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

  std::string http_host = host.empty() ? server_ip : host;

  if (!host.empty()) {
    std::string resolved = resolve_hostname(host);
    if (resolved.empty()) {
      std::cerr << "[Prover] Could not resolve hostname: " << host << std::endl;
      return 1;
    }
    server_ip = resolved;
    std::cerr << "[Prover] Resolved " << host << " -> " << server_ip
              << std::endl;
    if (server_port == 0) server_port = 443;
  }

  if (!host.empty()) {
    g_origin_rtt_ms = measure_rtt_ms(server_ip, server_port ? server_port : 443);
  }
  std::cerr << "[Prover] round=" << round_name << " mode=" << g_surf_mode
            << " RTT origin=" << g_origin_rtt_ms << "ms" << std::endl;

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = (server_ip == "127.0.0.1")
                    ? CreateContextWithTestCertificate(TLS_method())
                    : CreateContextWOTestCertificate(TLS_method());

  // Capture the NewSessionTicket; ownership moves to do_single_get, which hands
  // it back for the handoff write.
  SSL_CTX_set_session_cache_mode(
      ps_ctx.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(ps_ctx.get(), new_session_cb);

  // Hex-dump every outgoing ClientHello (full + resumed) so the bytes ruliweb
  // rejects with illegal_parameter can be decoded offline.
  SSL_CTX_set_msg_callback(ps_ctx.get(), clienthello_msg_cb);

  const int rc =
      (round == Round::Full)
          ? prover_full_round(pv_ctx.get(), ps_ctx.get(), server_ip,
                              server_port, verifier_ip, verifier_port,
                              http_host, path, handoff_dir, max_assets)
          : prover_resumed_round(pv_ctx.get(), ps_ctx.get(), server_ip,
                                 server_port, verifier_ip, verifier_port,
                                 http_host, handoff_dir);

  if (g_ticket_session) {
    SSL_SESSION_free(g_ticket_session);
    g_ticket_session = nullptr;
  }

  std::cerr << "[Prover] round=" << round_name << " rc=" << rc << std::endl;
  return rc;
}
