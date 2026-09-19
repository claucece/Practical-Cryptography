/*
  SURF demo: fetch a real page over Surf, then open it in a browser.

  Structurally this is MultiGet.b.cpp: one full 3P-HS for the page, then one
  Surf-PSK resumed handshake per discovered asset, one round per process, with
  a handoff directory carrying the ticket and PSK shares between them. What
  differs is the output. Instead of counting bytes, every fetched resource is
  written to an output directory, the HTML is rewritten to reference the local
  copies, and a provenance banner is injected recording what was attested:
  origin, time, SURF mode, records, and 2PC blocks per resource.

  The point is that the rendered page is the artifact. Anyone can look at it
  and see both the content and the claim being made about where it came from.

  Rounds accumulate into the output directory:

    <outdir>/raw/page.html   ... the origin's bytes, untouched
    <outdir>/raw/<file>      ... each asset, untouched
    <outdir>/manifest.tsv    ... one row per fetched resource
    <outdir>/index.html      ... rewritten page + banner, written by the last
                                 round, and the file to open

  Usage:
    ./SurfDemo --is_verifier --ip 127.0.0.1 -v 8444 --round full  --outdir /tmp/demo
    ./SurfDemo --host example.com -v 8444 --round full  --outdir /tmp/demo
*/

#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <gumbo.h>

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
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
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

static const char *g_surf_mode = "masked";
static SSL_SESSION *g_ticket_session = nullptr;

static std::string raw_dir(const std::string &d)      { return d + "/raw"; }
static std::string manifest_file(const std::string &d){ return d + "/manifest.tsv"; }
static std::string index_file(const std::string &d)   { return d + "/index.html"; }
static std::string assets_file(const std::string &d)  { return d + "/assets.tsv"; }
static std::string cursor_file(const std::string &d)  { return d + "/cursor"; }

struct Fetched {
  std::string path;
  std::string raw_ref;
  std::string local;
  std::size_t bytes = 0;
  std::size_t records = 0;
  std::size_t blocks = 0;
};

static bool append_manifest(const std::string &dir, const Fetched &f) {
  std::ofstream m(manifest_file(dir), std::ios::app);
  if (!m) return false;

  m << f.path << '\t' << f.raw_ref << '\t' << f.local << '\t' << f.bytes
    << '\t' << f.records << '\t' << f.blocks << '\n';
  m.flush();

  return m.good();
}

static std::vector<Fetched> read_manifest(const std::string &dir) {
  std::vector<Fetched> out;
  std::ifstream m(manifest_file(dir));
  std::string line;

  while (std::getline(m, line)) {
    std::istringstream ls(line);
    Fetched f;
    std::string bytes, records, blocks;
    if (!std::getline(ls, f.path, '\t')) continue;
    if (!std::getline(ls, f.raw_ref, '\t')) continue;
    if (!std::getline(ls, f.local, '\t')) continue;
    std::getline(ls, bytes, '\t');
    std::getline(ls, records, '\t');
    std::getline(ls, blocks, '\t');
    f.bytes = bytes.empty() ? 0 : std::stoul(bytes);
    f.records = records.empty() ? 0 : std::stoul(records);
    f.blocks = blocks.empty() ? 0 : std::stoul(blocks);
    out.push_back(std::move(f));
  }
  return out;
}

static bool write_queue(const std::string &dir,
                        const std::vector<std::pair<std::string, std::string>> &q) {
  std::ofstream f(assets_file(dir), std::ios::trunc);
  if (!f) return false;
  for (const auto &[path, raw] : q) f << path << '\t' << raw << '\n';
  f.flush();
  return f.good();
}

static std::vector<std::pair<std::string, std::string>>
read_queue(const std::string &dir) {
  std::vector<std::pair<std::string, std::string>> out;
  std::ifstream f(assets_file(dir));
  std::string line;

  while (std::getline(f, line)) {
    const auto tab = line.find('\t');
    if (tab == std::string::npos) continue;
    out.emplace_back(line.substr(0, tab), line.substr(tab + 1));
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

static std::string local_name(const std::string &path) {
  std::string s = path;
  if (!s.empty() && s[0] == '/') s.erase(0, 1);
  if (const auto q = s.find_first_of("?#"); q != std::string::npos) s.erase(q);
  if (s.empty()) s = "index";
  for (auto &c : s) {
    const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '.' ||
                    c == '-' || c == '_';
    if (!ok) c = '_';
  }
  return s;
}

static bool write_binary(const std::string &path, const std::string &data) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
  f.flush();

  return f.good();
}

static std::string read_file(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  std::ostringstream ss;
  ss << f.rdbuf();

  return ss.str();
}

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

static int new_session_cb(SSL * /*ssl*/, SSL_SESSION *session) {
  if (g_ticket_session != nullptr) return 0;
  g_ticket_session = session;
  return 1;
}

static double ms_since(const std::chrono::steady_clock::time_point start) {
  using namespace std::chrono;
  return duration_cast<duration<double, std::milli>>(steady_clock::now() - start)
      .count();
}

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
    return "";
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

static void collect_assets(
    GumboNode *node, const std::string &host,
    std::vector<std::pair<std::string, std::string>> &out) {
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
    if (!path.empty()) out.emplace_back(std::move(path), a->value);
  }

  const GumboVector *ch = &node->v.element.children;
  for (unsigned i = 0; i < ch->length; ++i)
    collect_assets(static_cast<GumboNode *>(ch->data[i]), host, out);
}

static std::vector<std::pair<std::string, std::string>>
parse_assets(const std::string &html, const std::string &host) {
  GumboOutput *output = gumbo_parse(html.c_str());
  if (!output) return {};
  std::vector<std::pair<std::string, std::string>> urls;
  collect_assets(output->root, host, urls);
  gumbo_destroy_output(&kGumboDefaultOptions, output);

  std::vector<std::pair<std::string, std::string>> deduped;
  std::unordered_set<std::string> seen;

  for (auto &u : urls)
    if (seen.insert(u.first).second) deduped.push_back(std::move(u));
  return deduped;
}

static std::string extract_body(const std::string &resp) {
  const auto pos = resp.find("\r\n\r\n");
  return (pos == std::string::npos) ? "" : resp.substr(pos + 4);
}

static bool is_html_response(const std::string &resp) {
  const auto pos = resp.find("\r\n\r\n");
  return pos != std::string::npos &&
         resp.substr(0, pos).find("text/html") != std::string::npos;
}

// Building the browsable page
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

static void replace_all(std::string &hay, const std::string &from,
                        const std::string &to) {
  if (from.empty()) return;
  std::size_t pos = 0;
  while ((pos = hay.find(from, pos)) != std::string::npos) {
    hay.replace(pos, from.size(), to);
    pos += to.size();
  }
}

static std::string banner(const std::string &host, const std::string &when,
                          const std::vector<Fetched> &items,
                          std::size_t expected, const std::string &current) {
  std::size_t total_bytes = 0, total_records = 0, total_blocks = 0;
  for (const auto &f : items) {
    total_bytes += f.bytes;
    total_records += f.records;
    total_blocks += f.blocks;
  }
  const bool complete = (expected > 0 && items.size() >= expected);
  const int pct =
      expected ? static_cast<int>(100 * items.size() / expected) : 0;

  std::ostringstream b;
  b << "<div id=\"surf-banner\" style=\""
       "font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;"
       "background:#0b1020;color:#d7e0ff;padding:14px 18px;"
       "border-bottom:2px solid #4c6ef5;\">"
    << "<div style=\"font-weight:700;color:#8fa7ff;margin-bottom:6px;\">"
    << (complete ? "Rendering over SURF" : "Rendering over SURF&hellip;")
    << "</div>"
    << "<div>origin: <b>" << html_escape(host) << "</b> &middot; "
    << html_escape(when) << " &middot; mode: <b>" << g_surf_mode << "</b></div>";

  if (!complete) {
    b << "<div style=\"margin:8px 0;height:6px;background:#1b2340;"
         "border-radius:3px;overflow:hidden;\">"
         "<div style=\"height:100%;width:"
      << pct
      << "%;background:#4c6ef5;transition:width .3s;\"></div></div>"
      << "<div>" << items.size() << " of " << expected << " resource(s)";
    if (!current.empty()) {
      b << " &middot; now: <b>" << html_escape(current) << "</b>"
        << " <span style=\"color:#7c8db5;\">(~20s of circuit preprocessing "
           "per resource)</span>";
    }
    b << "</div>";
  } else {
    b << "<div>" << items.size() << " resource(s) &middot; " << total_bytes
      << " bytes &middot; " << total_records
      << " TLS records attested &middot; " << total_blocks
      << " 2PC blocks</div>";
  }

  b << "<details style=\"margin-top:8px;\"><summary style=\"cursor:pointer;\">"
       "per-resource detail</summary>"
       "<table style=\"margin-top:8px;border-collapse:collapse;\">"
       "<tr style=\"color:#8fa7ff;text-align:left;\">"
       "<th style=\"padding:2px 14px 2px 0;\">path</th>"
       "<th style=\"padding:2px 14px 2px 0;\">bytes</th>"
       "<th style=\"padding:2px 14px 2px 0;\">records</th>"
       "<th style=\"padding:2px 0;\">blocks</th></tr>";
  for (const auto &f : items) {
    b << "<tr><td style=\"padding:2px 14px 2px 0;\">" << html_escape(f.path)
      << "</td><td style=\"padding:2px 14px 2px 0;\">" << f.bytes
      << "</td><td style=\"padding:2px 14px 2px 0;\">" << f.records
      << "</td><td style=\"padding:2px 0;\">" << f.blocks << "</td></tr>";
  }
  b << "</table></details></div>";
  return b.str();
}

// Writes <outdir>/index.html from whatever has been fetched so far, so the
// browser can be opened before the first round finishes and show the page
// filling in: unstyled at first, restyled when the CSS lands, then images.
static bool render_page(const std::string &outdir, const std::string &host,
                        std::size_t expected, const std::string &current) {
  const std::vector<Fetched> items = read_manifest(outdir);
  const bool complete = (expected > 0 && items.size() >= expected);

  const std::time_t now = std::time(nullptr);
  char when[64] = {};
  std::strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S UTC",
                std::gmtime(&now));
  const std::string bar = banner(host, when, items, expected, current);

  std::string html = read_file(raw_dir(outdir) + "/page.html");
  if (html.empty()) {
    // Nothing fetched yet: banner only, so there is something on screen during
    // the first round's preprocessing instead of a blank window.
    html = "<!doctype html><meta charset=\"utf-8\"><title>SURF</title>"
           "<body style=\"margin:0;background:#f6f7fb;\">" +
           bar +
           "<div style=\"padding:40px;font:15px/1.6 system-ui,sans-serif;"
           "color:#555;\">Waiting for the first response&hellip;</div></body>";
  } else {
    for (const auto &f : items) {
      if (f.raw_ref.empty()) continue;  // the page itself
      replace_all(html, f.raw_ref, "raw/" + f.local);
    }
    const auto body = html.find("<body");
    const auto close =
        (body == std::string::npos) ? std::string::npos : html.find('>', body);
    if (close != std::string::npos) {
      html.insert(close + 1, bar);
    } else {
      html.insert(0, bar);
    }
  }

  if (!complete) {
    html.insert(0, "<meta http-equiv=\"refresh\" content=\"2\">");
  }

  if (!write_binary(index_file(outdir), html)) {
    std::cerr << "[Demo] cannot write " << index_file(outdir) << "\n";
    return false;
  }
  if (complete) {
    std::cerr << "[Demo] wrote " << index_file(outdir) << " ("
              << items.size() << " resource(s))\n";
  }
  return true;
}

static void open_in_browser(const std::string &path) {
#if defined(__APPLE__)
  const std::string cmd = "open '" + path + "'";
#else
  const std::string cmd = "xdg-open '" + path + "' >/dev/null 2>&1";
#endif
  if (std::system(cmd.c_str()) != 0) {
    std::cerr << "[Demo] could not open a browser; the page is at " << path
              << "\n";
  }
}

// One 3P-HS + GET
struct GetResult {
  bool ok = false;
  bool new_session = false;
  std::string response;
  std::size_t records = 0;
  std::size_t blocks = 0;
};

static GetResult do_single_get(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                               const std::string &server_ip,
                               uint16_t server_port,
                               const std::string &verifier_ip,
                               uint16_t verifier_port,
                               const std::string &http_host,
                               const std::string &path,
                               bool allow_unclean_close,
                               SSL_SESSION **inout_session) {
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  const bool is_resumption = (*inout_session != nullptr);

  const std::string req = build_http_request(http_host, path);
  if (req.size() + 1 > kMaxRequestBytes + 1) {
    std::cerr << "[Demo] request is " << req.size()
              << " bytes; the 2PC encryption circuit is provisioned for "
              << kMaxRequestBytes << "\n";
    return {};
  }

  Prover prover{TLSSocket(pv_ctx, false), TLSSocket(ps_ctx, false)};
  prover.connection_to_server.set_ip_v4();
  prover.connection_to_verifier.set_ip_v4();

  const auto connect_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_verifier.connect_to(verifier_ip, verifier_port) ||
      !read_handshake(prover.connection_to_verifier)) {
    std::cerr << "[Demo] connecting to verifier failed\n";
    return {};
  }

  {
    const uint8_t mode = static_cast<uint8_t>(
        is_resumption ? Messaging::MessageHeaders::RUN_RESUMED
                      : Messaging::MessageHeaders::RUN_FULL);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &mode, 1) !=
        1) {
      std::cerr << "[Demo] failed to send run-type tag\n";
      return {};
    }
  }

  if (!prover.connection_to_server.set_verifier_connection(
          prover.connection_to_verifier.get_ssl_object()) ||
      !set_callbacks(prover.connection_to_server)) {
    std::cerr << "[Demo] wiring the origin connection failed\n";
    return {};
  }

  if (is_resumption) {
    SSL_set_session(prover.connection_to_server.get_ssl_object(),
                    *inout_session);
    SSL_SESSION_free(*inout_session);
    *inout_session = nullptr;
  }

  if (!http_host.empty() &&
      http_host.find_first_not_of("0123456789.") != std::string::npos) {
    SSL_set_tlsext_host_name(prover.connection_to_server.get_ssl_object(),
                             http_host.c_str());
  }

  std::cerr << "[Demo] preprocessing circuits (this is the slow part)\n";
  const auto preprocess_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.preprocess_circuits()) {
    std::cerr << "[Demo] preprocess_circuits failed\n";
    return {};
  }
  const double preprocess_ms = ms_since(preprocess_start);

  const auto origin_start = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.connect_to(server_ip, server_port)) {
    std::cerr << "[Demo] connecting to the origin failed\n";
    return {};
  }
  const double origin_connect_ms = ms_since(origin_start);

  SSL *ps = prover.connection_to_server.get_ssl_object();
  const bool reused = SSL_session_reused(ps) == 1;
  if (is_resumption && !reused) {
    std::cerr << "[Demo] resumed round did not resume; the origin rejected "
                 "the ticket\n";
    return {};
  }

  if (!prover.connection_to_server.write(
          reinterpret_cast<const uint8_t *>(req.data()), req.size(),
          nullptr)) {
    std::cerr << "[Demo] request write failed\n";
    return {};
  }

  std::string response;
  char buf[4096];
  for (;;) {
    int n = prover.connection_to_server.read(buf, static_cast<int>(sizeof(buf)));
    if (n <= 0) break;
    response.append(buf, static_cast<size_t>(n));
  }

  if (ps->surf_true_mode) {
    bssl::Array<uint8_t> plaintext;
    if (!ThreePartyHandshake::true_surf_release(ps, plaintext,
                                                !allow_unclean_close)) {
      std::cerr << "[Demo] attestation failed: the response could not be "
                   "shown to be complete\n";
      return {};
    }
    response.assign(reinterpret_cast<const char *>(plaintext.data()),
                    plaintext.size());
  }

  GetResult result;
  result.records = ps->surf_records.size();
  {
    std::vector<SurfBlockMap::RecordDims> recs;
    for (const auto &r : ps->surf_records) {
      recs.push_back({r.seq, static_cast<uint32_t>(r.ciphertext.size())});
    }
    result.blocks = SurfBlockMap::total_blocks(recs);
  }

  std::cerr << "[Demo] " << path << ": " << response.size() << " bytes, "
            << result.records << " records, " << result.blocks << " blocks"
            << " (preprocess " << static_cast<long>(preprocess_ms) << " ms, "
            << "origin " << static_cast<long>(origin_connect_ms) << " ms)\n";

  if (ps->psk_circuit != nullptr) {
    const uint8_t skip =
        static_cast<uint8_t>(Messaging::MessageHeaders::PSK_SKIP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &skip, 1) !=
        1) {
      return {};
    }
  } else if (g_ticket_session) {
    *inout_session = g_ticket_session;
    g_ticket_session = nullptr;
    result.new_session = true;
  }

  {
    const uint8_t stop = static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
    if (SSL_write(prover.connection_to_verifier.get_ssl_object(), &stop, 1) !=
        1) {
      return {};
    }
  }

  SSL_shutdown(ps);
  result.ok = true;
  result.response = std::move(response);
  return result;
}

// Rounds
static int demo_full_round(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                           const std::string &server_ip, uint16_t server_port,
                           const std::string &verifier_ip,
                           uint16_t verifier_port, const std::string &host,
                           const std::string &path,
                           const std::string &handoff_dir,
                           const std::string &outdir, std::size_t max_assets,
                           bool allow_unclean_close, bool open_browser) {
  SSL_SESSION *session = nullptr;

  // Render and open before fetching anything, so the ~20 seconds of circuit
  // preprocessing is visible as a progress bar rather than a silent wait.
  render_page(outdir, host, 0, path);
  if (open_browser) open_in_browser(index_file(outdir));

  std::cerr << "[Demo] fetching https://" << host << path << "\n";
  GetResult r = do_single_get(pv_ctx, ps_ctx, server_ip, server_port,
                              verifier_ip, verifier_port, host, path,
                              allow_unclean_close, &session);
  if (!r.ok) {
    std::cerr << "[Demo] the initial fetch failed\n";
    return 1;
  }

  const std::string body = extract_body(r.response);
  if (!write_binary(raw_dir(outdir) + "/page.html", body)) {
    std::cerr << "[Demo] cannot write the page\n";
    if (session) SSL_SESSION_free(session);
    return 1;
  }
  append_manifest(outdir, Fetched{path, "", "page.html", body.size(),
                                  r.records, r.blocks});

  std::vector<std::pair<std::string, std::string>> assets;
  if (is_html_response(r.response)) assets = parse_assets(body, host);
  if (assets.size() > max_assets) assets.resize(max_assets);
  std::cerr << "[Demo] " << assets.size() << " asset(s) to fetch\n";

  if (!write_queue(outdir, assets) || !write_cursor(outdir, 0)) {
    std::cerr << "[Demo] cannot write the asset queue\n";
    if (session) SSL_SESSION_free(session);
    return 1;
  }

  // The browser is already open and refreshing, so this just updates it: the
  // page appears now, and each asset lands as its round completes. With no
  // assets, expected == 1 and this render is the final one.
  render_page(outdir, host, 1 + assets.size(),
              assets.empty() ? "" : assets.front().first);

  if (!session) {
    std::cerr << "[Demo] no NewSessionTicket; cannot fetch assets\n";
    return assets.empty() ? 0 : 1;
  }
  const bool saved =
      RoundHandoff::save_prover(handoff_dir, session, session->surf_psk_share);
  SSL_SESSION_free(session);
  if (!saved) {
    std::cerr << "[Demo] cannot write the handoff\n";
    return 1;
  }
  return 0;
}

static int demo_resumed_round(SSL_CTX *pv_ctx, SSL_CTX *ps_ctx,
                              const std::string &server_ip,
                              uint16_t server_port,
                              const std::string &verifier_ip,
                              uint16_t verifier_port, const std::string &host,
                              const std::string &handoff_dir,
                              const std::string &outdir,
                              bool allow_unclean_close,
                              bool /*open_browser*/) {
  const auto queue = read_queue(outdir);
  if (queue.empty()) {
    std::cerr << "[Demo] no asset queue; run --round full first\n";
    return 1;
  }
  const std::size_t cursor = read_cursor(outdir);
  if (cursor >= queue.size()) {
    std::cerr << "[Demo] all assets fetched\n";
    return 2;
  }
  const auto &[path, raw_ref] = queue[cursor];

  RoundHandoff::Share psk_share{};
  SSL_SESSION *session =
      RoundHandoff::load_prover(handoff_dir, ps_ctx, psk_share);
  if (!session) {
    std::cerr << "[Demo] cannot load the handoff from " << handoff_dir << "\n";
    return 1;
  }

  std::cerr << "[Demo] asset " << (cursor + 1) << "/" << queue.size() << ": "
            << path << "\n";
  GetResult r = do_single_get(pv_ctx, ps_ctx, server_ip, server_port,
                              verifier_ip, verifier_port, host, path,
                              allow_unclean_close, &session);
  if (!r.ok) {
    if (session) SSL_SESSION_free(session);
    return 1;
  }

  const std::string local = local_name(path);
  const std::string body = extract_body(r.response);
  if (!write_binary(raw_dir(outdir) + "/" + local, body)) {
    std::cerr << "[Demo] cannot write " << local << "\n";
    if (session) SSL_SESSION_free(session);
    return 1;
  }
  append_manifest(outdir,
                  Fetched{path, raw_ref, local, body.size(), r.records,
                          r.blocks});

  if (!write_cursor(outdir, cursor + 1)) {
    if (session) SSL_SESSION_free(session);
    return 1;
  }

  if (r.new_session && session) {
    RoundHandoff::save_prover(handoff_dir, session, session->surf_psk_share);
  }
  if (session) SSL_SESSION_free(session);

  // Update the open browser. Naming the next asset makes the wait legible;
  // when this was the last one, expected == items and the refresh is dropped.
  const std::string next =
      (cursor + 1 < queue.size()) ? queue[cursor + 1].first : "";
  render_page(outdir, host, 1 + queue.size(), next);
  return 0;
}

int main(int argc, char *argv[]) {
  std::cerr.setf(std::ios::unitbuf);
  bool is_verifier = false;
  bool open_browser = false;
  bool allow_unclean_close = false;
  bool build_only = false;
  std::string server_ip = "127.0.0.1";
  std::string verifier_ip = "127.0.0.1";
  std::string host;
  std::string path = "/";
  std::string handoff_dir = "/tmp/surf_demo_handoff";
  std::string outdir = "/tmp/surf_demo";
  Round round = Round::Full;
  int accept_timeout_ms = 120000;
  std::size_t max_assets = 4;
  uint16_t server_port{}, verifier_port{};

  enum { OPT_OPEN = 1000, OPT_UNCLEAN, OPT_BUILD_ONLY };
  const char *const short_opts = "bs:i:p:v:h:r:t:R:d:m:o:";
  const option long_opts[] = {
      {"is_verifier",       no_argument,       nullptr, 'b'},
      {"ip",                required_argument, nullptr, 's'},
      {"server_ip",         required_argument, nullptr, 's'},
      {"verifier_ip",       required_argument, nullptr, 'i'},
      {"server_port",       required_argument, nullptr, 'p'},
      {"verifier_port",     required_argument, nullptr, 'v'},
      {"host",              required_argument, nullptr, 'h'},
      {"path",              required_argument, nullptr, 'r'},
      {"round",             required_argument, nullptr, 'R'},
      {"handoff",           required_argument, nullptr, 'd'},
      {"outdir",            required_argument, nullptr, 'o'},
      {"max_assets",        required_argument, nullptr, 'm'},
      {"accept_timeout_ms", required_argument, nullptr, 't'},
      {"open",              no_argument,       nullptr, OPT_OPEN},
      {"allow_unclean_close", no_argument,     nullptr, OPT_UNCLEAN},
      {"build_only",        no_argument,       nullptr, OPT_BUILD_ONLY},
      {nullptr, 0, nullptr, 0}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) break;
    switch (opt) {
    case 'b': is_verifier = true; break;
    case 's': server_ip = optarg; break;
    case 'i': verifier_ip = optarg; break;
    case 'p': server_port = static_cast<uint16_t>(std::stoi(optarg)); break;
    case 'v': verifier_port = static_cast<uint16_t>(std::stoi(optarg)); break;
    case 'h': host = optarg; break;
    case 'r': path = optarg; break;
    case 'd': handoff_dir = optarg; break;
    case 'o': outdir = optarg; break;
    case 'm': max_assets = static_cast<std::size_t>(std::stoul(optarg)); break;
    case 't': accept_timeout_ms = std::stoi(optarg); break;
    case OPT_OPEN: open_browser = true; break;
    case OPT_UNCLEAN: allow_unclean_close = true; break;
    case OPT_BUILD_ONLY: build_only = true; break;
    case 'R': {
      const std::string arg(optarg);
      if (arg == "full") round = Round::Full;
      else if (arg == "resumed") round = Round::Resumed;
      else { std::cerr << "--round must be 'full' or 'resumed'\n"; return 2; }
      break;
    }
    default: break;
    }
  }

  {
    const char *const env = ::getenv("SURF_TRUE");
    g_surf_mode = (env && env[0] == '1') ? "true" : "masked";
  }

  std::error_code ec;
  std::filesystem::create_directories(raw_dir(outdir), ec);
  std::filesystem::create_directories(handoff_dir, ec);

  // Rebuild the page from an existing manifest without fetching anything.
  if (build_only) {
    // Re-assemble from the existing manifest without fetching. Passing the
    // manifest size as |expected| marks it complete, so no meta-refresh.
    const std::size_t n = read_manifest(outdir).size();
    if (!render_page(outdir, host.empty() ? server_ip : host, n, "")) return 1;
    if (open_browser) open_in_browser(index_file(outdir));
    return 0;
  }

  if (is_verifier) {
    Server verifier(CreateContextWithTestCertificate(TLS_method()), verifier_ip,
                    false, /*backlog=*/64, verifier_port);
    verifier.set_attestation();
    verifier.set_accept_timeout(accept_timeout_ms);
    verifier.get_portnumber(&verifier_port);
    std::cerr << "[Verifier] port=" << verifier_port << " mode=" << g_surf_mode
              << "\n";

    const auto kind = verifier.accept_and_read_mode(true);
    if (kind == Server::SessionKind::Idle) {
      std::cerr << "[Verifier] no prover connected\n";
      return 1;
    }
    const bool resumed = (kind == Server::SessionKind::Resumed);
    if (resumed) {
      RoundHandoff::Share share{};
      if (!RoundHandoff::load_share(
              RoundHandoff::verifier_share_path(handoff_dir), share)) {
        std::cerr << "[Verifier] cannot load the PSK share\n";
        return 1;
      }
      verifier.set_psk_share(share);
    }

    const bool worked =
        resumed ? verifier.run_resumption(Server::ServerState::DONE, false,
                                          true, /*already_accepted=*/true)
                : verifier.run(Server::ServerState::DONE, false, true,
                               /*already_accepted=*/true);
    if (!worked) {
      std::cerr << "[Verifier] run failed\n";
      return 1;
    }
    if (!RoundHandoff::save_share(
            RoundHandoff::verifier_share_path(handoff_dir),
            verifier.get_psk_share())) {
      return 1;
    }
    std::cerr << "[Verifier] done\n";
    return 0;
  }

  if (host.empty()) {
    std::cerr << "[Demo] --host is required (this demo fetches real sites)\n";
    return 2;
  }
  const std::string resolved = resolve_hostname(host);
  if (resolved.empty()) return 1;
  server_ip = resolved;
  if (server_port == 0) server_port = 443;

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWOTestCertificate(TLS_method());
  SSL_CTX_set_session_cache_mode(
      ps_ctx.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(ps_ctx.get(), new_session_cb);

  const int rc =
      (round == Round::Full)
          ? demo_full_round(pv_ctx.get(), ps_ctx.get(), server_ip, server_port,
                            verifier_ip, verifier_port, host, path,
                            handoff_dir, outdir, max_assets,
                            allow_unclean_close, open_browser)
          : demo_resumed_round(pv_ctx.get(), ps_ctx.get(), server_ip,
                               server_port, verifier_ip, verifier_port, host,
                               handoff_dir, outdir, allow_unclean_close,
                               open_browser);

  if (g_ticket_session) {
    SSL_SESSION_free(g_ticket_session);
    g_ticket_session = nullptr;
  }

  return rc;
}
