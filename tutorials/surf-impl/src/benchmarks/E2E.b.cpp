/*
  This file exists to allow one to easily benchmark how long the 3P-HS takes in
  an end-to-end setting.

  Rounds run one per process. `--round full` performs the full handshake and
  writes the session ticket and both parties' PSK shares to the handoff
  directory; `--round resumed` reads them back and performs the PSK-resumption
  handshake.
*/

#include <getopt.h>

#include "../ssl/ThreePartyHandshake.hpp"
#include "../nodes/Server.hpp"
#include "../ssl/Messaging.hpp"
#include "../ssl/Roundhandoff.hpp"
#include "../ssl/TestUtil.hpp"
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <openssl/err.h>
#include <sys/socket.h>
#include <csignal>
#include <fcntl.h>

namespace {

enum class Round { Full, Resumed };

void render_in_terminal(const std::string &label, const std::string &response) {
  // Extract body from HTTP response
  auto header_end = response.find("\r\n\r\n");
  if (header_end == std::string::npos) return;
  const std::string body = response.substr(header_end + 4);

  std::cerr << "\n=== " << label << " ===\n";

  // Write body to a temp file and pipe through w3m
  const std::string tmp = "/tmp/e2e_render.html";
  FILE* f = fopen(tmp.c_str(), "w");
  if (!f) return;
  fwrite(body.c_str(), 1, body.size(), f);
  fclose(f);

  // DANGER: this heavily depends on your path to elinks
  const std::string cmd = "/opt/homebrew/bin/elinks -dump -dump-color-mode 1 " + tmp;
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) return;
  char buf[256];
  while (fgets(buf, sizeof(buf), pipe)) {
    std::cerr << buf;
  }
  pclose(pipe);
}

void dump_err_queue(const char* tag) {
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

// Read the single DONE_HS marker byte sent by the verifier.
bool read_handshake(TLSSocket &sock) {
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

// Install all callbacks
bool set_callbacks(TLSSocket &socket) {
  socket.set_make_circuits();
  return socket.set_handshake_callback() && socket.set_keyshare_callback() &&
         socket.set_derive_shared_secret_callback() &&
         socket.set_derive_handshake_keys_callback() &&
         socket.set_commit_to_server_certificate_callback() &&
         socket.set_combine_handshake_secret_shares_callback() &&
         socket.set_derive_traffic_keys_callback() &&
         socket.set_derive_gcm_shares_callback() &&
         socket.set_derive_resumption_keys_callback() &&
         socket.set_derive_psk_keys_callback() &&
         socket.set_derive_binder_callback() &&
         socket.set_surf_encrypt_callback() &&
         socket.set_surf_decrypt_callback() &&
         socket.set_rotate_traffic_keys_callback();
}

// Reads one complete HTTP response (headers plus Content-Length bytes of body)
// from |ssl|, or returns what it managed to read before the peer closed.
std::string read_http_response(SSL *const ssl) {
  uint8_t buf[4096];
  std::string response;
  for (;;) {
    const int nr = SSL_read(ssl, buf, sizeof(buf));
    if (nr > 0) {
      response += std::string(reinterpret_cast<char *>(buf),
                              static_cast<size_t>(nr));
      const auto header_end = response.find("\r\n\r\n");
      if (header_end != std::string::npos) {
        const auto cl_pos = response.find("Content-Length: ");
        if (cl_pos != std::string::npos) {
          const size_t cl = std::stoul(response.substr(cl_pos + 16));
          if (response.size() >= header_end + 4 + cl) {
            break;
          }
        }
      }
      continue;
    }
    const int ssl_err = SSL_get_error(ssl, nr);
    if (ssl_err == SSL_ERROR_ZERO_RETURN || ssl_err == SSL_ERROR_SYSCALL) {
      break;
    }
  }
  return response;
}

// SURF TRUE mode. Runs the whole attestation in one go after the read loop:
// commit, submit every record's tag, take k_v, decrypt. Returns the response
// payload; in TRUE mode SSL_read yields nothing, since no record can be
// opened while it arrives.
std::string true_surf_attest(SSL *const origin_ssl,
                             SSL *const verifier_ssl,
                             const char *const label) {
  bssl::Array<uint8_t> plaintext;
  if (!ThreePartyHandshake::true_surf_release(origin_ssl, plaintext)) {
    std::cerr << "[Prover] " << label << " true_surf_release failed\n";
    return {};
  }
  std::cerr << "[Prover] " << label
            << " surf_records=" << origin_ssl->surf_records.size()
            << " payload=" << plaintext.size() << "\n";

  const uint8_t stop = static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
  SSL_write(verifier_ssl, &stop, 1);

  return std::string(reinterpret_cast<const char *>(plaintext.data()),
                     plaintext.size());
}

// SURF ROTATE mode. Same drain as TRUE; release runs per epoch.
std::string rotate_surf_attest(SSL *const origin_ssl, SSL *const verifier_ssl,
                               const char *const label) {
  bssl::Array<uint8_t> plaintext;
  if (!ThreePartyHandshake::rotate_surf_release(origin_ssl, plaintext)) {
    std::cerr << "[Prover] " << label << " rotate_surf_release failed\n";
    return {};
  }
  std::cerr << "[Prover] " << label
            << " surf_records=" << origin_ssl->surf_records.size()
            << " payload=" << plaintext.size() << "\n";
  const uint8_t stop = static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
  SSL_write(verifier_ssl, &stop, 1);
  return std::string(reinterpret_cast<const char *>(plaintext.data()),
                     plaintext.size());
}

// Dispatches on the origin connection's mode.
std::string capture_attest(SSL *const origin_ssl, SSL *const verifier_ssl,
                           const char *const label) {
  return origin_ssl->surf_mode == Surf::Mode::Rotate
             ? rotate_surf_attest(origin_ssl, verifier_ssl, label)
             : true_surf_attest(origin_ssl, verifier_ssl, label);
}

// ROTATE mode, per-round flow. Captures records until one of |ct_len|
// |stop_len| arrives (6 = a KeyUpdate) or, with |stop_len| == 0, until the
// peer's FIN. The length is only a trigger; the release verifies the
// boundary cryptographically.
void drain_until(SSL *const os, const size_t stop_len) {
  uint8_t sink[4096];
  for (;;) {
    if (stop_len != 0 && os->surf_records.size() > os->surf_epoch_start &&
        os->surf_records.back().ciphertext.size() == stop_len) {
      return;
    }
    const int n = SSL_read(os, sink, sizeof(sink));
    if (n > 0) continue;
    const int e = SSL_get_error(os, n);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
      struct pollfd pfd{};
      pfd.fd = SSL_get_fd(os);
      pfd.events = (e == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
      if (::poll(&pfd, 1, 10000) <= 0) return;
      continue;
    }
    return;  // FIN or fatal
  }
}

// SURF attestation over whatever records this connection captured: verify every
// record's tag, then derive the keystream, then tell the verifier to stop.
void attest_records(SSL *const origin_ssl, SSL *const verifier_ssl,
                    const char *const label) {
  std::vector<SurfBlockMap::RecordDims> recs;
  for (const auto &r : origin_ssl->surf_records) {
    recs.push_back({r.seq, static_cast<uint32_t>(r.ciphertext.size())});
  }
  std::cerr << "[Prover] " << label
            << " surf_records=" << origin_ssl->surf_records.size()
            << " nblocks=" << SurfBlockMap::total_blocks(recs) << "\n";

  const uint8_t stop = static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
  SSL_write(verifier_ssl, &stop, 1);
}

// origin server
void server_hs(std::promise<bool> &&res, Server *server, bool is_resumption) {
  if (!server || !server->accept()) {
    std::cerr << "[Server] accept failed\n";
    res.set_value(false);
    return;
  }
  std::cerr << "[Server] accepted\n";

  if (!server->do_handshake()) {
    std::cerr << "[Server] do_handshake failed\n";
    res.set_value(false);
    return;
  }

  if (!is_resumption) {
    if (!server->write_handshake_done()) {
      res.set_value(false);
      return;
    }
  }

  if (is_resumption) {
    std::cerr << "[Server] waiting for request on resumed connection\n";
    uint8_t req_buf[4096];
    int nr = SSL_read(server->get_ssl(), req_buf, sizeof(req_buf));
    if (nr < 0) {
      int ssl_err = SSL_get_error(server->get_ssl(), nr);
      std::cerr << "[Server] SSL_read error: " << ssl_err << "\n";
      dump_err_queue("Server/SSL_read");
    }
    if (nr > 0) {
      std::cerr << "[Server] received request:\n" << std::string((char*)req_buf, nr) << "\n";
    }
    const std::string body =
      "<html><body style='background:white'>"
      "<h1 style='color:green'>I AM A: Resumed connection!</h1>"
      "<p style='color:blue'>Session successfully resumed via SURF PSK</p>"
      "</body></html>";

    const std::string response =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: " + std::to_string(body.size()) + "\r\n"
      "Connection: close\r\n\r\n" + body;
    SSL_write(server->get_ssl(), response.c_str(), response.size());
    SSL_shutdown(server->get_ssl());
    ::shutdown(SSL_get_fd(server->get_ssl()), SHUT_WR);

    res.set_value(true);
    return;
  }

  const char *const rot_env = ::getenv("SURF_ROTATE");
  const bool rotate_mode = rot_env && rot_env[0] == '1';

  if (rotate_mode) {
    // ROTATE: same responses as the other modes, one read per request. The
    // read that returns request 1 also processes the KeyUpdate, so the
    // origin's own KeyUpdate goes out after response 0 and before response 1.
    const std::array<std::pair<std::string, std::string>, 2> pages = {{
        {"<html><body><h1>SURF</h1></body></html>", "text/html"},
        {"h1{color:green}", "text/css"},
    }};
    for (size_t i = 0; i < pages.size(); i++) {
      uint8_t req_buf[4096];
      const int nr = SSL_read(server->get_ssl(), req_buf, sizeof(req_buf));
      if (nr > 0) {
        std::cerr << "[Server] received request:\n"
                  << std::string((char *)req_buf, nr) << "\n";
      }
      const bool last = (i + 1 == pages.size());
      const std::string response =
          "HTTP/1.1 200 OK\r\nContent-Type: " + pages[i].second +
          "\r\nContent-Length: " + std::to_string(pages[i].first.size()) +
          "\r\n" + (last ? "Connection: close" : "Connection: keep-alive") +
          "\r\n\r\n" + pages[i].first;
      SSL_write(server->get_ssl(), response.c_str(), response.size());
    }
  } else {
    // 2) Serve index.html
    // The prover writes both GETs back-to-back before reading anything, so the
    // first SSL_read here returns both. A second read would block forever
    // waiting for a third request that never comes -- and in TRUE mode that
    // deadlocks the pair, because the prover cannot finish its drain until
    // this thread reaches SSL_shutdown.
    bool read_requests = false;
    auto serve = [&](const std::string &body, const std::string &content_type,
                     bool close) {
      if (!read_requests) {
        uint8_t req_buf[4096];
        int nr = SSL_read(server->get_ssl(), req_buf, sizeof(req_buf));
        if (nr > 0) {
          std::cerr << "[Server] received request(s):\n"
                    << std::string((char *)req_buf, nr) << "\n";
        }
        read_requests = true;
      }
      const std::string connection_header =
          close ? "Connection: close" : "Connection: keep-alive";
      const std::string response =
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: " + content_type + "\r\n"
          "Content-Length: " + std::to_string(body.size()) + "\r\n" +
          connection_header + "\r\n\r\n" + body;
      SSL_write(server->get_ssl(), response.c_str(), response.size());
    };

    // For elinks to render, it needs to be inside the html
    serve("<html><body><h1>SURF</h1></body></html>", "text/html", false);
    serve("h1{color:green}", "text/css", true);
  }

  SSL_shutdown(server->get_ssl());
  ::shutdown(SSL_get_fd(server->get_ssl()), SHUT_WR);

  res.set_value(true);
  return;
}

// Runs one round's worth of verifier-side MPC plus the origin server thread.
// The verifier's PSK share crosses the round boundary: the full round derives
// it in derive_psk and the resumed round consumes it in do_ks and
// do_psk_binder, so it is saved and reloaded here.
bool server_run(Server &server, Server &verifier, const Round round,
                const std::string &handoff_dir) {
  std::promise<bool> server_promise;
  auto s_fut = server_promise.get_future();
  const bool is_resumption = (round == Round::Resumed);
  std::thread server_thread(server_hs, std::move(server_promise), &server,
                            is_resumption);

  bool worked;
  if (round == Round::Full) {
    std::cerr << "[Server] Running full round\n";
    worked = verifier.run(Server::ServerState::DONE, true, true);
  } else {
    RoundHandoff::Share share{};
    if (!RoundHandoff::load_share(
            RoundHandoff::verifier_share_path(handoff_dir), share)) {
      std::cerr << "[Server] cannot load verifier PSK share\n";
      server_thread.join();
      return false;
    }
    verifier.set_psk_share(share);
    std::cerr << "[Server] Running resumed round\n";
    worked = verifier.run_resumption(Server::ServerState::DONE, true, true);
  }

  server_thread.join();

  if (round == Round::Full && worked) {
    if (!RoundHandoff::save_share(
            RoundHandoff::verifier_share_path(handoff_dir),
            verifier.get_psk_share())) {
      std::cerr << "[Server] failed to save verifier PSK share\n";
      return false;
    }
  }

  return worked && s_fut.get();
}

// prover, full

// The first NewSessionTicket's session is the only one whose surf_psk_share
// matches a PSK we actually derived (derive_psk_keys runs once), so later
// tickets are declined.
SSL_SESSION *g_ticket_session = nullptr;

int new_session_cb(SSL *, SSL_SESSION *session) {
  if (g_ticket_session) {
    // Returning 0 leaves ownership with BoringSSL, which frees it.
    return 0;
  }
  g_ticket_session = session;
  return 1;
}

bool run_prover_full(SSL_CTX *const pv_ctx, SSL_CTX *const ps_ctx,
                     const std::string &ip, const uint16_t server_port,
                     const uint16_t verifier_port,
                     const std::string &handoff_dir) {
  TLSSocket connection_to_verifier(pv_ctx, false);
  TLSSocket connection_to_server(ps_ctx, false);
  connection_to_server.set_ip_v4();
  connection_to_verifier.set_ip_v4();

  // 1) Connect to verifier and wait for DONE_HS marker.
  if (!connection_to_verifier.connect_to(ip, verifier_port) ||
      !read_handshake(connection_to_verifier)) {
    std::cerr << "[Prover] connecting to verifier on:" << ip << ":"
              << verifier_port << " failed!" << std::endl;
    return false;
  }

  // 2) Link verifier channel into the server connection.
  if (!connection_to_server.set_verifier_connection(
          connection_to_verifier.get_ssl_object())) {
    std::cerr << "[Prover] Setting verifier failed" << std::endl;
    return false;
  }

  // 3) Install all TLS callbacks
  if (!set_callbacks(connection_to_server)) {
    std::cerr << "[Prover] Setting callbacks failed" << std::endl;
    return false;
  }

  // 3.5) Offline phase: run circuit preprocessing before opening the origin
  // connection so the origin socket does not idle through the WAN MPC.
  if (!connection_to_server.preprocess_circuits()) {
    std::cerr << "[Prover] preprocess_circuits failed" << std::endl;
    return false;
  }

  // 4) Connect to the server
  if (!connection_to_server.connect_to(ip, server_port)) {
    dump_err_queue("Prover/SSL_connect");
    return false;
  }

  SSL *const os = connection_to_server.get_ssl_object();
  std::cerr << "[Prover] session_reused=" << SSL_session_reused(os) << "\n";

  // 5) Requests
  if (os->surf_mode == Surf::Mode::Rotate) {
    // Same two requests as the other modes, so the runs are comparable:
    // GET /index.html + KeyUpdate -> response 0 -> release epoch 0 -> rotate;
    // GET /styles.css (close)     -> response 1 + close_notify -> release.
    const int fd = SSL_get_fd(os);
    ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);

    const std::array<std::string, 2> paths = {"/index.html", "/styles.css"};
    const std::array<std::string, 2> labels = {"index.html", "styles.css"};
    for (size_t i = 0; i < paths.size(); i++) {
      const bool last = (i + 1 == paths.size());
      const std::string req = "GET " + paths[i] + " HTTP/1.1\r\nHost: " + ip +
                              "\r\nConnection: " +
                              (last ? "close" : "keep-alive") + "\r\n\r\n";
      const int w = SSL_write(os, req.c_str(), static_cast<int>(req.size()));
      std::cerr << "[Prover] write" << i << "=" << w << "\n";
      if (w <= 0) {
        dump_err_queue("Prover/write");
        return false;
      }
      if (!last && !SSL_key_update(os, SSL_KEY_UPDATE_REQUESTED)) {
        dump_err_queue("Prover/key_update");
        return false;
      }

      drain_until(os, last ? 0 : 6);

      bssl::Array<uint8_t> pt;
      if (!ThreePartyHandshake::rotate_surf_release_epoch(os, pt, last)) {
        std::cerr << "[Prover] release of epoch " << i << " failed\n";
        return false;
      }
      render_in_terminal(labels[i],
                         std::string(reinterpret_cast<const char *>(pt.data()),
                                     pt.size()));
    }
    const uint8_t stop = static_cast<uint8_t>(Messaging::MessageHeaders::STOP);
    SSL_write(connection_to_verifier.get_ssl_object(), &stop, 1);
  } else {
    // Send both GET requests back-to-back.
    const std::string request1 = "GET /index.html HTTP/1.1\r\nHost: " + ip +
                                 "\r\nConnection: keep-alive\r\n\r\n";
    const std::string request2 = "GET /styles.css HTTP/1.1\r\nHost: " + ip +
                                 "\r\nConnection: close\r\n\r\n";

    const int w1 = SSL_write(os, request1.c_str(),
                             static_cast<int>(request1.size()));
    std::cerr << "[Prover] write1=" << w1;
    if (w1 <= 0) {
      std::cerr << " ssl_err=" << SSL_get_error(os, w1);
      dump_err_queue("Prover/write1");
    }
    std::cerr << "\n";

    const int w2 = SSL_write(os, request2.c_str(),
                             static_cast<int>(request2.size()));
    std::cerr << "[Prover] write2=" << w2;
    if (w2 <= 0) {
      std::cerr << " ssl_err=" << SSL_get_error(os, w2);
      dump_err_queue("Prover/write2");
    }
    std::cerr << "\n";
  }

  // 6) Read both responses in order. In TRUE mode every record is captured
  // sealed and SSL_read yields nothing, so this just drains to close; the
  // payload comes out of true_surf_attest below.
 if (os->surf_mode == Surf::Mode::True) {
    std::cerr << "[Prover] entering TRUE drain, records="
              << os->surf_records.size() << "\n";
    // The fd is blocking, so SSL_read parks in read(2) and the poll below is
    // unreachable. A receive timeout is what actually bounds this loop.
    struct timeval tv{10, 0};
    ::setsockopt(SSL_get_fd(os), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // The 3-byte close_notify heuristic is gone from tls_open_record, so
    // SSL_read never reports a clean shutdown here: it returns WANT_READ
    // until the peer's FIN. Break on any non-retryable result.
    uint8_t sink[4096];
    for (;;) {
      const int n = SSL_read(os, sink, sizeof(sink));
      if (n > 0) continue;
      const int e = SSL_get_error(os, n);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        struct pollfd pfd{};
        pfd.fd = SSL_get_fd(os);
        pfd.events = (e == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
        if (::poll(&pfd, 1, 10000) <= 0) break;
        continue;
      }
      std::cerr << "[Prover] drain ended n=" << n << " ssl_err=" << e << "\n";
      break;
    }
  } else {
    for (int i = 0; i < 2; i++) {
      const std::string response = read_http_response(os);
      if (!response.empty()) {
        render_in_terminal((i == 0) ? "index.html" : "styles.css", response);
      }
    }
  }

  // 7) SURF: derive the keystream over the captured records. The commitment
  // opening happens inside the circuit (Algorithm 2), so there is no separate
  // MASK_OPEN step: the verifier gets E_i and never sees b_i.
  //
  // TRUE mode instead runs the whole attestation here: commit, tags, k_v,
  // decrypt and hands back the payload, since nothing was readable while it
  // arrived. Both responses share one connection, so they come back
  // concatenated.
  if (os->surf_mode == Surf::Mode::True) {
    const std::string all =
        capture_attest(os, connection_to_verifier.get_ssl_object(), "full");
    // One render per response; the payload is all responses concatenated.
    size_t pos = 0, k = 0;
    while (pos < all.size()) {
      auto next = all.find("HTTP/1.1", pos + 1);
      if (next == std::string::npos) next = all.size();
      render_in_terminal("response " + std::to_string(k++),
                         all.substr(pos, next - pos));
      pos = next;
    }
  } else if (os->surf_mode == Surf::Mode::Masked) {
    attest_records(os, connection_to_verifier.get_ssl_object(), "full");
  }

  // 8) Hand the ticket and our PSK share to the resumed round's process. This
  // must happen before SSL_shutdown, which does not invalidate the session
  if (!g_ticket_session) {
    std::cerr << "[Prover] no session ticket captured; cannot hand off\n";
    return false;
  }
  const bool saved = RoundHandoff::save_prover(
      handoff_dir, g_ticket_session, g_ticket_session->surf_psk_share);

  SSL_shutdown(os);
  SSL_SESSION_free(g_ticket_session);
  g_ticket_session = nullptr;

  if (!saved) {
    std::cerr << "[Prover] failed to write handoff\n";
    return false;
  }
  std::cerr << "[Prover] wrote handoff to " << handoff_dir << "\n";
  return true;
}

// prover, resumed

bool run_prover_resumed(SSL_CTX *const pv_ctx, SSL_CTX *const ps_ctx,
                        const std::string &ip, const uint16_t server_port,
                        const uint16_t verifier_port,
                        const std::string &handoff_dir) {
  // Reattaching surf_psk_share to the loaded session is enough: the prover's
  // ssl->psk_share is lifted off the session in do_read_server_hello, and
  // derive_binder reads the session field directly.
  RoundHandoff::Share psk_share{};
  SSL_SESSION *const session =
      RoundHandoff::load_prover(handoff_dir, ps_ctx, psk_share);
  if (!session) {
    std::cerr << "[Prover] cannot load handoff from " << handoff_dir << "\n";
    return false;
  }
  std::cerr << "[Prover] loaded session and PSK share from " << handoff_dir
            << "\n";

  TLSSocket connection_to_verifier(pv_ctx, false);
  connection_to_verifier.set_ip_v4();
  if (!connection_to_verifier.connect_to(ip, verifier_port) ||
      !read_handshake(connection_to_verifier)) {
    std::cerr << "[Prover] failed to open verifier tunnel on:" << ip << ":"
              << verifier_port << std::endl;
    SSL_SESSION_free(session);
    return false;
  }

  TLSSocket resumed_connection(ps_ctx, false);
  resumed_connection.set_ip_v4();

  SSL_set_session(resumed_connection.get_ssl_object(), session);
  SSL_SESSION_free(session);  // SSL_set_session takes its own reference.

  if (!set_callbacks(resumed_connection)) {
    std::cerr << "[Prover] Setting callbacks on resumed connection failed\n";
    return false;
  }

  if (!resumed_connection.set_verifier_connection(
          connection_to_verifier.get_ssl_object())) {
    std::cerr << "[Prover] Setting verifier on resumed connection failed\n";
    return false;
  }

  // Offline phase: must run after set_verifier_connection (it needs the
  // verifier channel) and before connecting to the origin.
  if (!resumed_connection.preprocess_circuits()) {
    std::cerr << "[Prover] preprocess_circuits failed on resumed connection\n";
    return false;
  }

  SSL *const rssl = resumed_connection.get_ssl_object();
  if (!resumed_connection.connect_to(ip, server_port)) {
    dump_err_queue("Prover/resumed");
    std::cerr << "[Prover] resumed SSL state: " << SSL_state_string_long(rssl)
              << "\n";
    std::cerr << "[Prover] resumed in_init: " << SSL_in_init(rssl) << "\n";
    std::cerr << "[Prover] errno: " << strerror(errno) << "\n";
    return false;
  }

  std::cerr << "[Prover] resumed connect ok session_reused="
            << SSL_session_reused(rssl) << "\n";

  const std::string req = "POST /verify HTTP/1.1\r\n"
                          "Host: " + ip + "\r\n"
                          "Content-Length: 0\r\n"
                          "Connection: close\r\n\r\n";
  SSL_write(rssl, req.c_str(), static_cast<int>(req.size()));
  std::cerr << "[Prover] sent request on resumed connection\n";

  // Attestation on the resumed connection, mirroring the full round. Without
  // this the verifier reaches SHUTDOWN with nothing to attest and reports
  // GCM_VERIFY / KS_DERIVE as zero.
  if (rssl->surf_true_mode) {
    std::cerr << "[Prover] entering TRUE drain, records="
              << rssl->surf_records.size() << "\n";
    // The fd is blocking, so SSL_read parks in read(2) and the poll below is
    // unreachable. A receive timeout is what actually bounds this loop.
    struct timeval tv{10, 0};
    ::setsockopt(SSL_get_fd(rssl), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // The 3-byte close_notify heuristic is gone from tls_open_record, so
    // SSL_read never reports a clean shutdown here: it returns WANT_READ
    // until the peer's FIN. Break on any non-retryable result.
    uint8_t sink[4096];
    for (;;) {
      const int n = SSL_read(rssl, sink, sizeof(sink));
      if (n > 0) continue;
      const int e = SSL_get_error(rssl, n);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        struct pollfd pfd{};
        pfd.fd = SSL_get_fd(rssl);
        pfd.events = (e == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
        if (::poll(&pfd, 1, 10000) <= 0) break;
        continue;
      }
      std::cerr << "[Prover] drain ended n=" << n << " ssl_err=" << e << "\n";
      break;
    }
    render_in_terminal(
        "index.html (resumed)",
        capture_attest(rssl, connection_to_verifier.get_ssl_object(),
                       "resumed"));
  } else {
    render_in_terminal("index.html (resumed)", read_http_response(rssl));
    attest_records(rssl, connection_to_verifier.get_ssl_object(), "resumed");
  }

  SSL_shutdown(rssl);
  return true;
}

}  // namespace

int main(int argc, char *argv[]) {
  signal(SIGPIPE, SIG_IGN);

  bool is_server = false;
  std::string ip = "127.0.0.1";
  std::string handoff_dir = "/tmp/surf_handoff";
  Round round = Round::Full;

  uint16_t server_port{}, verifier_port{};

  const char *const short_opts = "sa:p:v:r:d:";
  const option long_opts[] = {
      {"is_server", no_argument, nullptr, 's'},
      {"ip", required_argument, nullptr, 'a'},
      {"server_port", required_argument, nullptr, 'p'},
      {"verifier_port", required_argument, nullptr, 'v'},
      {"round", required_argument, nullptr, 'r'},
      {"handoff", required_argument, nullptr, 'd'},
      {nullptr, 0, nullptr, 0}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) {
      break;
    }

    switch (opt) {
    case 's':
      is_server = true;
      break;
    case 'a':
      ip = std::string(optarg);
      break;
    case 'p':
      server_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 'v':
      verifier_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 'r': {
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
    case 'd':
      handoff_dir = std::string(optarg);
      break;
    default:
      break;
    }
  }

  const char *const round_name = (round == Round::Full) ? "full" : "resumed";

  if (is_server) {
    Server verifier(CreateContextWithTestCertificate(TLS_method()), ip.c_str(),
                    false, 1, verifier_port);
    Server server(CreateContextWithTestCertificate(TLS_method()), ip.c_str(),
                  false, 1, server_port);

    verifier.set_attestation();

    // The origin must decrypt a ticket minted by the previous round's process.
    // SSL_CTX_new generates a fresh ticket key per process, so without a fixed
    // key the resumed round silently falls back to a full handshake. Note this
    // also disables BoringSSL's automatic 48-hour key rotation, which is fine
    // for a benchmark and would not be for a deployment.
    static const uint8_t kTicketKey[48] = {
        0x53, 0x55, 0x52, 0x46, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x74, 0x69, 0x63,
        0x6b, 0x65, 0x74, 0x6b, 0x65, 0x79, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d};
    if (!SSL_CTX_set_tlsext_ticket_keys(server.get_ctx(), kTicketKey,
                                        sizeof(kTicketKey))) {
      std::cerr << "[Server] failed to fix the origin ticket key\n";
      return 1;
    }

    // No-ops when we asked for specific ports; still needed for the port-0 case.
    verifier.get_portnumber(&verifier_port);
    server.get_portnumber(&server_port);

    std::cerr << "[Server] round=" << round_name << " connect to server on:"
              << ip << ":" << server_port << " verifier on:" << ip << ":"
              << verifier_port << std::endl;
    std::cerr << "[Server] client command: ./E2EBench --ip " << ip << " -p "
              << server_port << " -v " << verifier_port << " --round "
              << round_name << " --handoff " << handoff_dir << std::endl;

    return server_run(server, verifier, round, handoff_dir) ? 0 : 1;
  }

  // Prover/client mode.
  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWithTestCertificate(TLS_method());
  SSL_CTX_set_session_cache_mode(
      ps_ctx.get(), SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(ps_ctx.get(), new_session_cb);

  const bool ok =
      (round == Round::Full)
          ? run_prover_full(pv_ctx.get(), ps_ctx.get(), ip, server_port,
                            verifier_port, handoff_dir)
          : run_prover_resumed(pv_ctx.get(), ps_ctx.get(), ip, server_port,
                               verifier_port, handoff_dir);

  std::cerr << "[Prover] round=" << round_name << " ok=" << ok << "\n";
  return ok ? 0 : 1;
}