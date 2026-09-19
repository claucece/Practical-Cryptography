/*
  SURF browser proxy, true mode.

  A plain-HTTP listener on localhost. Browser talks to it in the clear: each
  browser request is relayed over its own SURF/TLS connection to the origin,
  with the prover <-> verifier MPC running underneath, and the origin's
  response bytes are handed back to the browser verbatim.

  Usage:
    SURF_TRUE=1 ./SurfProxy --is_verifier --ip 127.0.0.1 -v 8444
    SURF_TRUE=1 ./SurfProxy --host example.com -v 8444 -b 8080 --open

  Or drive both with run_proxy.sh.
*/

#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "../nodes/Events.hpp"
#include "../nodes/Server.hpp"
#include "../ssl/Messaging.hpp"
#include "../ssl/TestUtil.hpp"
#include "../ssl/ThreePartyHandshake.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <openssl/err.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

struct Fetched {
  std::string path;
  std::size_t bytes = 0;
  std::size_t records = 0;
  std::size_t blocks = 0;
  double preprocess_ms = 0;
  double total_ms = 0;
  bool resumed = false;
  bool ok = false;
};

static std::vector<Fetched> g_log;
static std::string g_origin_host;
static std::string g_started_at;
static bool g_staged = false;  // set once stage mode has actually edited a page

static SSL_SESSION *g_ticket_session = nullptr;

static int new_session_cb(SSL * /*ssl*/, SSL_SESSION *session) {
  if (g_ticket_session != nullptr) {
    return 0;
  }
  g_ticket_session = session;
  return 1;
}

static std::string to_lower(std::string s) {
  for (auto &c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

static std::string trim(const std::string &s) {
  const auto b = s.find_first_not_of(" \t");
  if (b == std::string::npos) {
    return {};
  }
  const auto e = s.find_last_not_of(" \t");
  return s.substr(b, e - b + 1);
}

static std::string html_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
    case '&': out += "&amp;"; break;
    case '<': out += "&lt;"; break;
    case '>': out += "&gt;"; break;
    case '"': out += "&quot;"; break;
    default:  out += c;
    }
  }
  return out;
}

static double ms_since(const std::chrono::steady_clock::time_point start) {
  using namespace std::chrono;
  return duration_cast<duration<double, std::milli>>(steady_clock::now() -
                                                     start)
      .count();
}

static void dump_err_queue(const char *tag) {
  uint32_t err;
  while ((err = ERR_get_error()) != 0) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    std::cerr << "[" << tag << "] " << buf << "\n";
  }
}

static std::string resolve_hostname(const std::string &host) {
  struct addrinfo hints = {}, *results = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  const int ret = getaddrinfo(host.c_str(), nullptr, &hints, &results);
  if (ret != 0 || !results) {
    std::cerr << "[DNS] cannot resolve '" << host << "': " << gai_strerror(ret)
              << "\n";
    return {};
  }
  char ip_buf[INET_ADDRSTRLEN] = {};
  auto *addr = reinterpret_cast<struct sockaddr_in *>(results->ai_addr);
  inet_ntop(AF_INET, &addr->sin_addr, ip_buf, sizeof(ip_buf));
  freeaddrinfo(results);
  return std::string(ip_buf);
}

// HTTP parsing on the browser side
static std::string request_method(const std::string &req) {
  const auto sp = req.find(' ');
  return (sp == std::string::npos) ? std::string{} : req.substr(0, sp);
}

static std::string request_path(const std::string &req) {
  const auto sp1 = req.find(' ');
  if (sp1 == std::string::npos) {
    return {};
  }
  const auto sp2 = req.find(' ', sp1 + 1);
  if (sp2 == std::string::npos) {
    return {};
  }
  return req.substr(sp1 + 1, sp2 - sp1 - 1);
}

static std::string header_value(const std::string &msg,
                                const std::string &name) {
  const auto end = msg.find("\r\n\r\n");
  const std::string hdrs =
      msg.substr(0, (end == std::string::npos) ? msg.size() : end);
  const std::string lowered = to_lower(hdrs);
  const std::string key = "\r\n" + to_lower(name) + ":";

  auto p = lowered.find(key);
  if (p == std::string::npos) {
    return {};
  }
  p += key.size();
  auto e = lowered.find("\r\n", p);
  if (e == std::string::npos) {
    e = hdrs.size();
  }
  return trim(hdrs.substr(p, e - p));
}

static void remove_header(std::string &resp, const std::string &name) {
  const auto he = resp.find("\r\n\r\n");
  std::string low =
      to_lower(resp.substr(0, he == std::string::npos ? resp.size() : he));
  const std::string key = "\r\n" + to_lower(name) + ":";
  for (;;) {
    const auto p = low.find(key);
    if (p == std::string::npos) break;
    auto e = low.find("\r\n", p + 2);
    if (e == std::string::npos) e = low.size();
    resp.erase(p, e - p);
    low.erase(p, e - p);
  }
}

static void strip_origin_bound_headers(std::string &resp) {
  for (const char *h : {"strict-transport-security", "alt-svc",
                        "clear-site-data", "public-key-pins",
                        "public-key-pins-report-only"}) {
    remove_header(resp, h);
  }
  // An origin CSP carrying upgrade-insecure-requests does the same thing to
  // subresources, so drop the origin's policy and rely on the one injected here.
  const std::string csp = to_lower(header_value(resp, "content-security-policy"));
  if (csp.find("upgrade-insecure-requests") != std::string::npos) {
    remove_header(resp, "content-security-policy");
  }
  // Every response should cost a real SURF round; a cached one silently doesn't.
  remove_header(resp, "cache-control");
  remove_header(resp, "expires");
  remove_header(resp, "etag");
  remove_header(resp, "last-modified");
  const auto eol = resp.find("\r\n");
  if (eol != std::string::npos) {
    resp.insert(eol + 2, "Cache-Control: no-store\r\n");
  }
}

static bool read_http_request(int fd, std::string &out) {
  char buf[4096];
  for (;;) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      return false;
    }
    out.append(buf, static_cast<size_t>(n));
    if (out.find("\r\n\r\n") != std::string::npos) {
      return true;
    }
    if (out.size() > (1u << 20)) {
      return false;
    }
  }
}

static bool send_all(int fd, const std::string &data) {
  std::size_t sent = 0;
  while (sent < data.size()) {
    const ssize_t n =
        ::send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
    if (n <= 0) {
      if (n < 0 && errno == EINTR) {
        continue;
      }
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

static void send_simple(int fd, const char *status, const char *ctype,
                        const std::string &body) {
  const std::string r = std::string("HTTP/1.1 ") + status +
                        "\r\nContent-Type: " + ctype +
                        "\r\nContent-Length: " + std::to_string(body.size()) +
                        "\r\nCache-Control: no-store"
                        "\r\nConnection: close\r\n\r\n" +
                        body;
  send_all(fd, r);
}

// Building the origin request
static constexpr std::size_t kAesEncIters = 4;
static constexpr std::size_t kMaxRequestBytes =
    16 * EmpWrapperAG2PCConstants::AES_ENC_N * kAesEncIters - 1;

static std::string build_origin_request(const std::string &method,
                                        const std::string &path,
                                        const std::string &host,
                                        const std::string &browser_req,
                                        bool allow_encoding) {
  std::ostringstream r;
  r << method << " " << path << " HTTP/1.1\r\n"
    << "Host: " << host << "\r\n";

  for (const char *name : {"accept", "accept-encoding", "accept-language"}) {
    if (!allow_encoding && std::strcmp(name, "accept-encoding") == 0) {
      continue;
    }
    const std::string v = header_value(browser_req, name);
    if (!v.empty()) {
      r << name << ": " << v << "\r\n";
    }
  }

  // A real UA string: bare "Surf/1.0" collects 403s from CDNs and WAFs.
  r << "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\n";

  r << "Connection: close\r\n\r\n";

  std::string out = r.str();
  if (out.size() > kMaxRequestBytes) {
    // Drop the forwarded headers and retry minimally rather than fail.
    std::ostringstream m;
    m << method << " " << path << " HTTP/1.1\r\n"
      << "Host: " << host << "\r\n"
      << "User-Agent: Mozilla/5.0 (compatible; Surf/1.0)\r\n"
      << "Connection: close\r\n\r\n";
    out = m.str();
  }
  return out;
}

static void inject_csp(std::string &response) {
  const auto eol = response.find("\r\n");
  if (eol == std::string::npos) {
    return;
  }
  response.insert(eol + 2,
                  "Content-Security-Policy: default-src 'self' 'unsafe-inline' "
                  "'unsafe-eval' data: blob:\r\n");
}

// Request prioritisation
// Chrome opens several connections at once and dispatches a page's
// subresources near-simultaneously, so the order they land in the accept queue
// is really the order their TCP connects happened to complete.
static int request_priority(const std::string &req, const std::string &path) {
  const std::string dest = to_lower(header_value(req, "sec-fetch-dest"));
  if (dest == "document") return 0;
  if (dest == "style")    return 1;
  if (dest == "script")   return 2;
  if (dest == "font")     return 3;
  if (dest == "image")    return 4;

  const std::string p = to_lower(path);
  const auto ends = [&p](const char *s) {
    const std::string suf(s);
    return p.size() >= suf.size() &&
           p.compare(p.size() - suf.size(), suf.size(), suf) == 0;
  };
  if (ends(".css")) return 1;
  if (ends(".js") || ends(".mjs")) return 2;
  if (ends(".woff2") || ends(".woff") || ends(".ttf") || ends(".otf")) return 3;
  if (ends(".png") || ends(".jpg") || ends(".jpeg") || ends(".gif") ||
      ends(".webp") || ends(".avif") || ends(".svg") || ends(".ico"))
    return 4;
  return 5;
}

static bool is_document_request(const std::string &req) {
  return to_lower(header_value(req, "sec-fetch-dest")) == "document";
}

static std::size_t unblock_stylesheets(std::string &html) {
  const std::string low = to_lower(html);
  std::string out;
  out.reserve(html.size() + 256);

  std::size_t i = 0, n = 0;
  for (;;) {
    const auto s = low.find("<link", i);
    if (s == std::string::npos) {
      out.append(html, i, std::string::npos);
      break;
    }
    const auto e = html.find('>', s);
    if (e == std::string::npos) {
      out.append(html, i, std::string::npos);
      break;
    }

    out.append(html, i, s - i);
    std::string tag = html.substr(s, e - s + 1);
    const std::string ltag = low.substr(s, e - s + 1);

    // Leave anything that already carries a media query alone; guessing at how
    // to compose with it is how this kind of rewriting goes wrong.
    if (ltag.find("stylesheet") != std::string::npos &&
        ltag.find("media=") == std::string::npos) {
      std::size_t at = tag.size() - 1;
      if (at > 0 && tag[at - 1] == '/') {
        --at;
      }
      tag.insert(at, " media=\"print\" onload=\"this.media='all'\"");
      ++n;
    }

    out += tag;
    i = e + 1;
  }

  html.swap(out);
  return n;
}

static void set_content_length(std::string &headers, std::size_t len) {
  const std::string low = to_lower(headers);
  const auto p = low.find("\r\ncontent-length:");
  if (p == std::string::npos) {
    headers += "\r\nContent-Length: " + std::to_string(len);
    return;
  }
  auto e = headers.find("\r\n", p + 2);
  if (e == std::string::npos) {
    e = headers.size();
  }
  headers.replace(p + 2, e - (p + 2), "Content-Length: " + std::to_string(len));
}

static std::size_t stage_html_response(std::string &resp) {
  const auto he = resp.find("\r\n\r\n");
  if (he == std::string::npos) {
    return 0;
  }
  if (to_lower(header_value(resp, "content-type")).find("text/html") ==
      std::string::npos) {
    return 0;
  }
  // Compressed or chunked bodies would have to be decoded first; stage mode
  // asks the origin for identity encoding on documents, so this is a guard
  // against origins that ignore that rather than a case to handle.
  if (!header_value(resp, "content-encoding").empty() ||
      !header_value(resp, "transfer-encoding").empty()) {
    std::cerr << "[Proxy] stage mode: document is encoded; leaving it alone\n";
    return 0;
  }

  std::string headers = resp.substr(0, he);
  std::string body = resp.substr(he + 4);

  const std::size_t n = unblock_stylesheets(body);
  if (n == 0) {
    return 0;
  }

  set_content_length(headers, body.size());
  resp = headers + "\r\n\r\n" + body;
  return n;
}

// One SURF connection: handshake, one GET, release, close
template <bool debug = false> static bool read_handshake(TLSSocket &sock) {
  bssl::Array<uint8_t> arr;
  arr.Init(1);
  if (sock.read(arr.data(), static_cast<int>(arr.size())) != 1) {
    return false;
  }
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

struct RoundResult {
  bool ok = false;
  bool resumed = false;
  std::string response;
  std::size_t records = 0;
  std::size_t blocks = 0;
  double preprocess_ms = 0;
  double origin_ms = 0;
};

static RoundResult surf_fetch(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                              const std::string &server_ip,
                              uint16_t server_port,
                              const std::string &verifier_ip,
                              uint16_t verifier_port, const std::string &host,
                              const std::string &request,
                              SSL_SESSION **inout_session) {
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  RoundResult out;
  out.resumed = (*inout_session != nullptr);
  const bool is_resumption = out.resumed;

  // A ticket from a previous round must not leak into this one's capture.
  if (g_ticket_session) {
    SSL_SESSION_free(g_ticket_session);
    g_ticket_session = nullptr;
  }

  if (request.size() > kMaxRequestBytes) {
    std::cerr << "[Proxy] request is " << request.size()
              << " bytes; the 2PC encryption circuit is provisioned for "
              << kMaxRequestBytes << "\n";
    return out;
  }

  Prover prover{TLSSocket(pv_ctx, false), TLSSocket(ps_ctx, false)};
  prover.connection_to_server.set_ip_v4();
  prover.connection_to_verifier.set_ip_v4();

  if (!prover.connection_to_verifier.connect_to(verifier_ip, verifier_port)) {
    std::cerr << "[Proxy] TCP connect to the verifier failed\n";
    return out;
  }
  if (!read_handshake(prover.connection_to_verifier)) {
    std::cerr << "[Proxy] no DONE_HS from the verifier; it may have exited "
                 "(check its log)\n";
    dump_err_queue("Proxy/verifier-hs");
    return out;
  }

  {
    const uint8_t mode = static_cast<uint8_t>(
        is_resumption ? Messaging::MessageHeaders::RUN_RESUMED
                      : Messaging::MessageHeaders::RUN_FULL);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &mode, 1) !=
        1) {
      std::cerr << "[Proxy] failed to send the run-type tag\n";
      return out;
    }
  }

  if (!prover.connection_to_server.set_verifier_connection(
          prover.connection_to_verifier.get_ssl_object()) ||
      !set_callbacks(prover.connection_to_server)) {
    std::cerr << "[Proxy] wiring the origin connection failed\n";
    return out;
  }

  if (is_resumption) {
    SSL_set_session(prover.connection_to_server.get_ssl_object(),
                    *inout_session);
    SSL_SESSION_free(*inout_session);
    *inout_session = nullptr;
  }

  if (!host.empty() &&
      host.find_first_not_of("0123456789.") != std::string::npos) {
    SSL_set_tlsext_host_name(prover.connection_to_server.get_ssl_object(),
                             host.c_str());
  }

  const auto preprocess_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.preprocess_circuits()) {
    std::cerr << "[Proxy] preprocess_circuits failed\n";
    return out;
  }
  out.preprocess_ms = ms_since(preprocess_start);

  const auto origin_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.connect_to(server_ip, server_port)) {
    std::cerr << "[Proxy] connecting to the origin failed\n";
    dump_err_queue("Proxy/origin-connect");
    return out;
  }
  out.origin_ms = ms_since(origin_start);

  SSL *ps = prover.connection_to_server.get_ssl_object();

  if (!ps->surf_true_mode) {
    std::cerr << "[Proxy] the connection is not in true mode; this binary "
                 "only supports SURF_TRUE=1\n";
    return out;
  }
  if (is_resumption && SSL_session_reused(ps) != 1) {
    std::cerr << "[Proxy] the origin rejected the ticket; the round did not "
                 "resume\n";
    return out;
  }

  if (!prover.connection_to_server.write(
          reinterpret_cast<const uint8_t *>(request.data()), request.size(),
          nullptr)) {
    std::cerr << "[Proxy] request write failed\n";
    return out;
  }

  // In true mode these bytes are not the plaintext; the loop runs only to
  // drive the connection to its close, which is what makes release possible.
  {
    char buf[4096];
    for (;;) {
      const int n =
          prover.connection_to_server.read(buf, static_cast<int>(sizeof(buf)));
      if (n <= 0) {
        break;
      }
    }
  }

  {
    bssl::Array<uint8_t> plaintext;
    if (!ThreePartyHandshake::true_surf_release(ps, plaintext, true)) {
      std::cerr << "[Proxy] attestation failed: the response could not be "
                   "shown to be complete\n";
      return out;
    }
    out.response.assign(reinterpret_cast<const char *>(plaintext.data()),
                        plaintext.size());
  }

  out.records = ps->surf_records.size();
  {
    std::vector<SurfBlockMap::RecordDims> recs;
    recs.reserve(out.records);
    for (const auto &r : ps->surf_records) {
      recs.push_back({r.seq, static_cast<uint32_t>(r.ciphertext.size())});
    }
    out.blocks = SurfBlockMap::total_blocks(recs);
  }

  // A non-null psk_circuit means no NewSessionTicket arrived, so the verifier
  // has to be told to skip the PSK phase or both sides block forever.
  if (ps->psk_circuit != nullptr) {
    const uint8_t skip =
        static_cast<uint8_t>(Messaging::MessageHeaders::PSK_SKIP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &skip, 1) !=
        1) {
      return out;
    }
  } else if (g_ticket_session) {
    *inout_session = g_ticket_session;
    g_ticket_session = nullptr;
  }

  {
    const uint8_t stop = static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &stop, 1) !=
        1) {
      return out;
    }
  }

  SSL_shutdown(ps);
  out.ok = true;
  return out;
}

// The /__surf provenance page
static std::string status_page(bool busy, const std::string &current) {
  std::size_t bytes = 0, records = 0, blocks = 0;
  double preprocess = 0;
  for (const auto &f : g_log) {
    bytes += f.bytes;
    records += f.records;
    blocks += f.blocks;
    preprocess += f.preprocess_ms;
  }

  std::ostringstream p;
  p << "<!doctype html><html><head><meta charset=\"utf-8\">"
       "<title>SURF provenance</title>";
  if (busy) {
    p << "<meta http-equiv=\"refresh\" content=\"3\">";
  }
  p << "<style>"
       "body{font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;"
       "background:#0b1020;color:#d7e0ff;margin:0;padding:24px;}"
       "h1{font-size:15px;color:#8fa7ff;margin:0 0 4px;}"
       "table{border-collapse:collapse;margin-top:16px;width:100%;}"
       "th{text-align:left;color:#8fa7ff;font-weight:600;padding:4px 16px 4px 0;"
       "border-bottom:1px solid #1b2340;}"
       "td{padding:4px 16px 4px 0;border-bottom:1px solid #141a30;}"
       ".n{text-align:right;}.bad{color:#ff8a8a;}.dim{color:#7c8db5;}"
       "</style></head><body>";

  p << "<h1>" << (busy ? "Fetching over SURF&hellip;" : "Fetched over SURF")
    << "</h1>"
    << "<div>origin <b>" << html_escape(g_origin_host)
    << "</b> &middot; session started " << html_escape(g_started_at)
    << " &middot; mode <b>true</b></div>"
    << "<div class=\"dim\">one SURF connection per request; the first is a "
       "full handshake, the rest resume</div>";

  if (busy && !current.empty()) {
    p << "<div style=\"margin-top:10px;\">now: <b>" << html_escape(current)
      << "</b> <span class=\"dim\">(~15s of circuit preprocessing)</span>"
         "</div>";
  }

  p << "<div style=\"margin-top:12px;\">" << g_log.size() << " request(s) "
    << "&middot; " << bytes << " bytes &middot; " << records
    << " TLS records attested &middot; " << blocks << " 2PC blocks &middot; "
    << static_cast<long>(preprocess / 1000) << "s preprocessing</div>";

  p << "<table><tr><th>#</th><th>path</th><th>hs</th><th class=\"n\">bytes"
       "</th><th class=\"n\">records</th><th class=\"n\">blocks</th>"
       "<th class=\"n\">preprocess</th><th class=\"n\">total</th></tr>";
  int i = 0;
  for (const auto &f : g_log) {
    p << "<tr><td>" << ++i << "</td><td" << (f.ok ? ">" : " class=\"bad\">")
      << html_escape(f.path) << (f.ok ? "" : " (failed)") << "</td>"
      << "<td class=\"dim\">" << (f.resumed ? "resumed" : "full") << "</td>"
      << "<td class=\"n\">" << f.bytes << "</td>"
      << "<td class=\"n\">" << f.records << "</td>"
      << "<td class=\"n\">" << f.blocks << "</td>"
      << "<td class=\"n\">" << static_cast<long>(f.preprocess_ms) << " ms</td>"
      << "<td class=\"n\">" << static_cast<long>(f.total_ms) << " ms</td></tr>";
  }
  p << "</table>";
  p << "<p class=\"dim\">These bytes were served by the named origin over a "
       "SURF-attested session. That is the whole claim: it is not a signature "
       "and verifies nothing on its own.</p>";
  if (g_staged) {
    p << "<p class=\"bad\">Stage mode is on: stylesheet links in the HTML were "
         "rewritten to be non-render-blocking, so the document delivered to "
         "the browser is not byte-identical to the attested one. The counts "
         "above are for the unedited bytes.</p>";
  }
  p << "<p><a href=\"/__done\" style=\"color:#8fa7ff;\">end the session</a>"
       "</p></body></html>";
  return p.str();
}

// The browser-facing listener
struct ProxyConfig {
  std::string server_ip;
  uint16_t server_port = 443;
  std::string verifier_ip;
  uint16_t verifier_port = 0;
  std::string host;
  uint16_t listen_port = 8080;
  bool fetch_favicon = false;
  bool csp = true;
  bool stage = false;
};

static void serve_to_browser(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                             const ProxyConfig &cfg) {
  const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (lfd < 0) {
    std::cerr << "[Proxy] socket() failed: " << std::strerror(errno) << "\n";
    return;
  }

  int one = 1;
  ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(cfg.listen_port);

  if (::bind(lfd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
      ::listen(lfd, 16) != 0) {
    std::cerr << "[Proxy] bind/listen on " << cfg.listen_port
              << " failed: " << std::strerror(errno) << "\n";
    ::close(lfd);
    return;
  }

  std::cerr << "\n[Proxy] ==> http://127.0.0.1:" << cfg.listen_port << "/\n"
            << "[Proxy] ==> http://127.0.0.1:" << cfg.listen_port
            << "/__surf for provenance\n"
            << "[Proxy] ==> http://127.0.0.1:" << cfg.listen_port
            << "/__done to finish\n\n";

  SSL_SESSION *session = nullptr;

  struct Pending {
    int fd = -1;
    std::string req;
    std::string method;
    std::string path;
    int priority = 5;
  };
  std::vector<Pending> queue;

  // Accept one connection and read its request. Chrome speculatively opens
  // connections and sends nothing on them, so a socket that stays quiet is
  // dropped rather than waited on.
  const auto take = [](int listener, int timeout_ms) -> Pending {
    Pending p;
    const int cfd = ::accept(listener, nullptr, nullptr);
    if (cfd < 0) {
      return p;
    }
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (!read_http_request(cfd, p.req)) {
      ::close(cfd);
      return p;
    }
    p.fd = cfd;
    p.method = request_method(p.req);
    p.path = request_path(p.req);
    p.priority = request_priority(p.req, p.path);
    return p;
  };

  const auto pending_on_listener = [](int listener) {
    pollfd pf{listener, POLLIN, 0};
    return ::poll(&pf, 1, 0) > 0 && (pf.revents & POLLIN) != 0;
  };

  // Serial by necessity: each request costs a whole SURF connection against a
  // single verifier, so concurrency would only interleave the MPC. But the
  // queue is drained and sorted before each pick, so during the ~15 s spent on
  // one resource the browser's next batch accumulates and gets served in
  // browser-priority order rather than TCP-arrival order.
  for (;;) {
    if (queue.empty()) {
      Pending p = take(lfd, 2000);
      if (p.fd < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
          continue;
        }
        if (!pending_on_listener(lfd) && errno != 0 && queue.empty()) {
          // A genuine accept() failure, not a quiet speculative socket.
          if (errno == EBADF || errno == EINVAL) {
            break;
          }
        }
        continue;
      }
      queue.push_back(std::move(p));
    }

    while (pending_on_listener(lfd) && queue.size() < 32) {
      Pending p = take(lfd, 300);
      if (p.fd >= 0) {
        queue.push_back(std::move(p));
      }
    }

    std::stable_sort(queue.begin(), queue.end(),
                     [](const Pending &a, const Pending &b) {
                       return a.priority < b.priority;
                     });

    Pending item = std::move(queue.front());
    queue.erase(queue.begin());

    const int cfd = item.fd;
    const std::string &req = item.req;
    const std::string &method = item.method;
    const std::string &path = item.path;

    std::cerr << "[Proxy] browser -> " << method << " " << path << " (prio "
              << item.priority << ", " << queue.size() << " queued)\n";

    if (path == "/__done") {
      send_simple(cfd, "200 OK", "text/html",
                  "<!doctype html><meta charset=\"utf-8\">"
                  "<body style=\"font:14px sans-serif;padding:40px;\">"
                  "SURF session closed. The proxy has stopped.</body>");
      ::close(cfd);
      break;
    }

    if (path == "/__surf") {
      send_simple(cfd, "200 OK", "text/html", status_page(false, ""));
      ::close(cfd);
      continue;
    }

    if (path == "/favicon.ico" && !cfg.fetch_favicon) {
      // 15 s and a whole SURF connection for an icon nobody asked for.
      send_simple(cfd, "404 Not Found", "text/plain", "");
      ::close(cfd);
      continue;
    }

    if (method != "GET") {
      send_simple(cfd, "405 Method Not Allowed", "text/plain",
                  "this proxy issues GETs only\n");
      ::close(cfd);
      continue;
    }

    // In stage mode the document has to come back uncompressed, since the
    // stylesheet links are rewritten in the body. Subresources are unaffected
    // and still get whatever encoding the browser asked for.
    const bool is_doc = is_document_request(req);
    const std::string origin_req = build_origin_request(
        method, path, cfg.host, req, !(cfg.stage && is_doc));

    const auto started = std::chrono::steady_clock::now();
    RoundResult r =
        surf_fetch(pv_ctx, ps_ctx, cfg.server_ip, cfg.server_port,
                   cfg.verifier_ip, cfg.verifier_port, cfg.host, origin_req,
                   &session);

    Fetched entry;
    entry.path = path;
    entry.resumed = r.resumed;
    entry.ok = r.ok;
    entry.preprocess_ms = r.preprocess_ms;
    entry.total_ms = ms_since(started);

    if (!r.ok) {
      g_log.push_back(entry);
      std::cerr << "[Proxy] " << path << " failed after "
                << static_cast<long>(entry.total_ms) << " ms\n";
      send_simple(cfd, "502 Bad Gateway", "text/plain",
                  "the SURF fetch failed; see the prover log\n");
      ::close(cfd);
      // A failed round may have consumed the ticket. Fall back to a full
      // handshake next time rather than resuming against a dead session.
      if (session) {
        SSL_SESSION_free(session);
        session = nullptr;
      }
      continue;
    }

    entry.bytes = r.response.size();
    entry.records = r.records;
    entry.blocks = r.blocks;
    g_log.push_back(entry);

    std::cerr << "[Proxy] " << path << ": " << r.response.size() << " bytes, "
              << r.records << " records, " << r.blocks << " blocks "
              << "(preprocess " << static_cast<long>(r.preprocess_ms)
              << " ms, origin " << static_cast<long>(r.origin_ms) << " ms, "
              << (r.resumed ? "resumed" : "full") << ")\n";

    if (cfg.stage) {
      const std::size_t n = stage_html_response(r.response);
      if (n > 0) {
        g_staged = true;
        std::cerr << "[Proxy] stage mode: unblocked " << n
                  << " stylesheet(s) in " << path << "\n";
      }
    }
    strip_origin_bound_headers(r.response);

    if (cfg.csp) {
      inject_csp(r.response);
    }
    send_all(cfd, r.response);
    ::close(cfd);
  }

  for (auto &p : queue) {
    if (p.fd >= 0) {
      ::close(p.fd);
    }
  }
  if (session) {
    SSL_SESSION_free(session);
  }
  ::close(lfd);
  std::cerr << "[Proxy] listener closed after " << g_log.size()
            << " request(s)\n";
}

static void open_in_browser(const std::string &url) {
#if defined(__APPLE__)
  const std::string cmd = "open '" + url + "'";
#else
  const std::string cmd = "xdg-open '" + url + "' >/dev/null 2>&1";
#endif
  if (std::system(cmd.c_str()) != 0) {
    std::cerr << "[Proxy] could not open a browser; go to " << url << "\n";
  }
}

// Verifier
static int run_verifier(const std::string &ip, uint16_t port,
                        int accept_timeout_ms) {
  Server verifier(CreateContextWithTestCertificate(TLS_method()), ip, false,
                  /*backlog=*/64, port);
  verifier.set_attestation();
  verifier.set_accept_timeout(accept_timeout_ms);
  verifier.get_portnumber(&port);
  std::cerr << "[Verifier] port=" << port << " mode=true\n";

  for (int round = 0;; ++round) {
    const auto kind = verifier.accept_and_read_mode(true);
    if (kind == Server::SessionKind::Idle) {
      std::cerr << "[Verifier] no prover connected within the timeout; "
                   "exiting after " << round << " round(s)\n";
      return 0;
    }

    const bool resumed = (kind == Server::SessionKind::Resumed);
    std::cerr << "[Verifier] round " << round << " ("
              << (resumed ? "resumed" : "full") << ")\n";

    const bool worked =
        resumed ? verifier.run_resumption(Server::ServerState::DONE, false,
                                          true, /*already_accepted=*/true)
                : verifier.run(Server::ServerState::DONE, false, true,
                               /*already_accepted=*/true);
    if (!worked) {
      std::cerr << "[Verifier] round " << round << " failed\n";
      return 1;
    }
  }
}

int main(int argc, char *argv[]) {
  std::cerr.setf(std::ios::unitbuf);

  bool is_verifier = false;
  bool open_browser = false;
  ProxyConfig cfg;
  cfg.verifier_ip = "127.0.0.1";
  cfg.server_ip = "127.0.0.1";
  int accept_timeout_ms = 600000;
  uint16_t server_port_opt = 0;

  enum { OPT_OPEN = 1000, OPT_FAVICON, OPT_NO_CSP, OPT_STAGE };
  const char *const short_opts = "cs:i:p:v:h:t:b:";
  const option long_opts[] = {
      {"is_verifier", no_argument, nullptr, 'c'},
      {"ip", required_argument, nullptr, 's'},
      {"server_ip", required_argument, nullptr, 's'},
      {"verifier_ip", required_argument, nullptr, 'i'},
      {"server_port", required_argument, nullptr, 'p'},
      {"verifier_port", required_argument, nullptr, 'v'},
      {"host", required_argument, nullptr, 'h'},
      {"browser_port", required_argument, nullptr, 'b'},
      {"accept_timeout_ms", required_argument, nullptr, 't'},
      {"open", no_argument, nullptr, OPT_OPEN},
      {"fetch_favicon", no_argument, nullptr, OPT_FAVICON},
      {"no_csp", no_argument, nullptr, OPT_NO_CSP},
      {"stage", no_argument, nullptr, OPT_STAGE},
      {nullptr, 0, nullptr, 0}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) {
      break;
    }
    switch (opt) {
    case 'c': is_verifier = true; break;
    case 's': cfg.server_ip = optarg; break;
    case 'i': cfg.verifier_ip = optarg; break;
    case 'p': server_port_opt = static_cast<uint16_t>(std::stoi(optarg)); break;
    case 'v':
      cfg.verifier_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 'h': cfg.host = optarg; break;
    case 'b':
      cfg.listen_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 't': accept_timeout_ms = std::stoi(optarg); break;
    case OPT_OPEN: open_browser = true; break;
    case OPT_FAVICON: cfg.fetch_favicon = true; break;
    case OPT_NO_CSP: cfg.csp = false; break;
    case OPT_STAGE: cfg.stage = true; break;
    default: break;
    }
  }

  {
    const char *const env = ::getenv("SURF_TRUE");
    if (!env || env[0] != '1') {
      std::cerr << "[Proxy] SURF_TRUE=1 is required; this binary only "
                   "supports true mode\n";
      return 2;
    }
  }

  if (is_verifier) {
    return run_verifier(cfg.verifier_ip, cfg.verifier_port, accept_timeout_ms);
  }

  if (cfg.host.empty()) {
    std::cerr << "[Proxy] --host is required (this proxy fetches real sites)\n";
    return 2;
  }
  if (cfg.verifier_port == 0) {
    std::cerr << "[Proxy] --verifier_port is required\n";
    return 2;
  }

  const std::string resolved = resolve_hostname(cfg.host);
  if (resolved.empty()) {
    return 1;
  }
  cfg.server_ip = resolved;
  cfg.server_port = (server_port_opt != 0) ? server_port_opt : 443;

  g_origin_host = cfg.host;
  {
    const std::time_t now = std::time(nullptr);
    char when[64] = {};
    std::strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S UTC",
                  std::gmtime(&now));
    g_started_at = when;
  }

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWOTestCertificate(TLS_method());
  SSL_CTX_set_session_cache_mode(
      ps_ctx.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(ps_ctx.get(), new_session_cb);

  if (open_browser) {
    open_in_browser("http://127.0.0.1:" + std::to_string(cfg.listen_port) +
                    "/");
  }

  serve_to_browser(pv_ctx.get(), ps_ctx.get(), cfg);

  if (g_ticket_session) {
    SSL_SESSION_free(g_ticket_session);
    g_ticket_session = nullptr;
  }
  return 0;
}
