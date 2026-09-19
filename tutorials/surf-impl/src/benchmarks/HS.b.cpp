/*
  This file exists to allow one to easily benchmark how long the 3P-HS takes in
  an end-to-end setting. At a high-level, this file similarly to the tests in
  Server.t.cpp: we simply run the 3P-HS forward between two parties.
*/

#include <getopt.h>

#include "../nodes/Server.hpp"
#include "../ssl/Messaging.hpp"
#include "../ssl/TestUtil.hpp"
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
#include <openssl/err.h>

static void render_in_terminal(const std::string &label, const std::string &response) {
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

// Read the single DONE_HS marker byte sent by the verifier.
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

// Install all callbacks
static bool set_callbacks(TLSSocket &socket) {
  socket.set_make_circuits();
  return socket.set_handshake_callback() && socket.set_keyshare_callback() &&
         socket.set_derive_shared_secret_callback() &&
         socket.set_derive_handshake_keys_callback() &&
         socket.set_commit_to_server_certificate_callback() &&
         socket.set_combine_handshake_secret_shares_callback() &&
         socket.set_derive_psk_keys_callback() &&
         socket.set_derive_traffic_keys_callback() &&
         socket.set_derive_gcm_shares_callback() &&
         socket.set_derive_resumption_keys_callback() &&
         socket.set_derive_psk_keys_callback();
}

static void server_hs(std::promise<bool> &&res, Server *server, bool is_resumption = false) {
  std::cerr << "[Server] server_hs called, is_resumption=" << is_resumption << "\n";
  if (!server || !server->accept()) {
    std::cerr << "[Server] accept failed\n";
    res.set_value(false);
    return;
  }
  std::cerr << "[Server] accepted\n";

  if (is_resumption) {
    SSL_CTX_set_num_tickets(server->get_ctx(), 0);
    server->get_ssl()->session_ctx->num_tickets = 0;
  }
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
    res.set_value(true);
    return;
  }

  // 2) Serve index.html
  auto serve = [&](const std::string &body, const std::string &content_type, bool close) {
    uint8_t req_buf[4096];
    int nr = SSL_read(server->get_ssl(), req_buf, sizeof(req_buf));
    if (nr > 0) {
       std::cerr << "[Server] received request:\n" << std::string((char*)req_buf, nr) << "\n";
    }
    const std::string connection_header = close ? "Connection: close" : "Connection: keep-alive";
    const std::string response =
      "HTTP/1.1 200 OK\r\n" // We will need HTTP2
      "Content-Type: " + content_type + "\r\n"
      "Content-Length: " + std::to_string(body.size()) + "\r\n" +
      connection_header + "\r\n"
      "\r\n" + body;
    SSL_write(server->get_ssl(), response.c_str(), response.size());
  };

  // For elinks to render, it needs to be inside the html: WHATEVER
  serve(
  "<html><head>"
  "<style>"
  "h1 { color: green; }"
  "h2 { color: blue; }"
  "p { color: red; }"
  "li { color: red; }"
  "body { font-family: sans-serif; }"
  "</style>"
  "</head><body>"
  "<h1>Hello from the LOL server!</h1>"
  "<h2>Connection secured with 3-party handshake: SURF</h2>"
  "<ul>"
  "<li>Prover: verified</li>"
  "<li>Verifier: attested</li>"
  "<li>PSK: derived</li>"
  "</ul>"
  "<p>All traffic is end-to-end encrypted with TLS 1.3. Yay!!.</p>"
  "<form method='POST' action='/verify'>"
  "<button type='submit'>Click to verify via PSK resumption</button>"
  "</form>"
  "</body></html>",
  "text/html", false);
  serve(
  "h1 { color: green; }\n"
  "h2 { color: blue; }\n"
  "body { font-family: sans-serif; }\n",
  "text/css", true);
  SSL_shutdown(server->get_ssl());

  res.set_value(true);
  return;
}

static bool server_run(Server &server, Server &verifier) {
  // We just run the server in its own thread and the verifier on this thread.
  std::promise<bool> server_promise;
  auto s_fut = server_promise.get_future();
  std::thread server_thread(server_hs, std::move(server_promise), &server, false);
  std::cerr << "[Server] Running benchmark" << std::endl;
  auto worked = verifier.run(Server::ServerState::DONE, true, true);
  server_thread.join();

  // Second connection (resumption)
  std::cerr << "[Server] Waiting for resumed connection\n";
  std::promise<bool> server_promise2;
  auto s_fut2 = server_promise2.get_future();
  std::thread server_thread2(server_hs, std::move(server_promise2), &server, true);
  server_thread2.join();

  return worked;
}

int main(int argc, char *argv[]) {
  // Parse the arguments.
  bool is_server = false;
  std::string ip = "127.0.0.1";

  uint16_t server_port{}, verifier_port{};

  const char *const short_opts = "sa:p:v:";
  const option long_opts[] = {
      {"is_server", no_argument, nullptr, 's'},
      {"ip", required_argument, nullptr, 'a'},
      {"server port", required_argument, nullptr, 'p'},
      {"verifier port", required_argument, nullptr, 'v'}};

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
    default:
      break;
    }
  }

  if (is_server) {
    Server verifier(CreateContextWithTestCertificate(TLS_method()), ip.c_str(),
                    false, 1);
    Server server(CreateContextWithTestCertificate(TLS_method()), ip.c_str(),
                  false, 1);

    verifier.get_portnumber(&verifier_port);
    server.get_portnumber(&server_port);

    std::cerr << "[Server] connect to server on:" << ip << ":" << server_port
              << " verifier on:" << ip << ":" << verifier_port << std::endl;

    std::cerr << "[Server] Alternatively, you can run the client program by "
                 "pasting the following command into another terminal: \n"
              << "./E2EBench --ip " << ip << " -p " << server_port << " -v "
              << verifier_port << std::endl;

    server_run(server, verifier);
    return 0;
  }

  // Prover/client mode
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWithTestCertificate(TLS_method());

  static SSL_SESSION *ticket_session = nullptr;

  SSL_CTX_sess_set_new_cb(ps_ctx.get(), [](SSL *ssl, SSL_SESSION *session) -> int {
    ticket_session = session;
    std::cerr << "[Prover] Got session ticket, len="
              << session->ticket.size() << "\n";
    return 1; // take ownership - we free it later
  });

  Prover prover{TLSSocket(pv_ctx.get(), false),
                TLSSocket(ps_ctx.get(), false)};
  prover.connection_to_server.set_ip_v4();
  prover.connection_to_verifier.set_ip_v4();

  // 1) Connect to verifier and wait for DONE_HS marker.
  if (!prover.connection_to_verifier.connect_to(ip, verifier_port) ||
      !read_handshake(prover.connection_to_verifier)) {
    std::cerr << "[Prover] connecting to verifier on:" << ip << ":"
              << verifier_port << " failed!" << std::endl;
    std::abort();
  }

  // DEBUG: what SSL* does the server-connection currently use?
  SSL *s = prover.connection_to_server.get_ssl_object();
  std::cerr << "[Prover] initial server-ssl=" << (void *)s << "\n";

  // 2) Link verifier channel into the server connection.
  if (!prover.connection_to_server.set_verifier_connection(
          prover.connection_to_verifier.get_ssl_object())) {
    std::cerr << "[Prover] Setting verifier failed" << std::endl;
    std::abort();
  }

  s = prover.connection_to_server.get_ssl_object();
  std::cerr << "[Prover] after set_verifier_connection server-ssl=" << (void *)s
            << "\n";

  // 3) Install all TLS callbacks
  if (!set_callbacks(prover.connection_to_server)) {
    std::cerr << "[Prover] Setting callbacks failed" << std::endl;
    std::abort();
  }

  s = prover.connection_to_server.get_ssl_object();
  std::cerr << "[Prover] after set_callbacks server-ssl=" << (void *)s << "\n";

  // 3.5) Offline phase: run circuit preprocessing before opening the origin
  // connection so the origin socket does not idle through the WAN MPC.
  if (!prover.connection_to_server.preprocess_circuits()) {
    std::cerr << "[Prover] preprocess_circuits failed" << std::endl;
    std::abort();
  }

  // 4) Connect to the server
  bool ok = prover.connection_to_server.connect_to(ip, server_port);

  s = prover.connection_to_server.get_ssl_object();
  std::cerr << "[Prover] connect_to ok=" << ok
          << " in_init=" << SSL_in_init(s)
          << " state=" << SSL_state_string_long(s) << "\n";

  if (!ok) {
    dump_err_queue("Prover/SSL_connect");
    std::abort();
  }

  // 5) Check whether the handshake was resumed
  std::cerr << "[Prover] session_reused="
            << SSL_session_reused(prover.connection_to_server.get_ssl_object())
            << "\n";

  // 6) Send both GET requests back-to-back
  const std::string request1 = "GET /index.html HTTP/1.1\r\nHost: " + ip + "\r\nConnection: keep-alive\r\n\r\n";
  const std::string request2 = "GET /styles.css HTTP/1.1\r\nHost: " + ip + "\r\nConnection: close\r\n\r\n";
  SSL_write(prover.connection_to_server.get_ssl_object(), request1.c_str(), request1.size());
  SSL_write(prover.connection_to_server.get_ssl_object(), request2.c_str(), request2.size());

  // 7) Read both responses in order
  uint8_t resp_buf[4096];
  int nr;
  for (int i = 0; i < 2; i++) {
    std::string response;
    while (true) {
      nr = SSL_read(prover.connection_to_server.get_ssl_object(), resp_buf, sizeof(resp_buf));
      if (nr > 0) {
        response += std::string((char*)resp_buf, nr);
        // Check if we have a complete HTTP response (headers + body)
        auto header_end = response.find("\r\n\r\n");
        if (header_end != std::string::npos) {
          // Find Content-Length and check if body is complete
          auto cl_pos = response.find("Content-Length: ");
          if (cl_pos != std::string::npos) {
            size_t cl = std::stoul(response.substr(cl_pos + 16));
            if (response.size() >= header_end + 4 + cl) {
              break; // complete response received
            }
          }
        }
        continue;
      }
      int ssl_err = SSL_get_error(prover.connection_to_server.get_ssl_object(), nr);
      if (ssl_err == SSL_ERROR_ZERO_RETURN || ssl_err == SSL_ERROR_SYSCALL) break;
    }
    if (!response.empty()) {
    const std::string label = (i == 0) ? "index.html" : "styles.css";
    render_in_terminal(label, response);
    }
  }

  // Use the saved session
  SSL_SESSION *saved_session = ticket_session;
  if (saved_session) {
    printf("[Prover] session ticket len=%zu\n", saved_session->ticket.size());
    std::cerr << "[Prover] saved session for resumption\n";
  }

  // 8) Shutdown
  SSL_shutdown(prover.connection_to_server.get_ssl_object());

  // 9) Open a second connection using session resumption
  TLSSocket resumed_connection(ps_ctx.get(), false);
  resumed_connection.set_ip_v4();

  if (saved_session) {
    std::cerr << "[Prover] I have a saved session\n";
    SSL_set_session(resumed_connection.get_ssl_object(), saved_session);
    SSL_SESSION_free(saved_session); // release
  }

  // This is for the verifier: ignore for now
  if (!set_callbacks(resumed_connection)) {
   std::cerr << "[Prover] Setting callbacks on resumed connection failed\n";
   std::abort();
  }

  if (!resumed_connection.set_verifier_connection(
         prover.connection_to_verifier.get_ssl_object())) {
   std::cerr << "[Prover] Setting verifier on resumed connection failed\n";
   std::abort();
  }

  // Offline phase: must run after set_verifier_connection (it needs the verifier
  // channel) and before connecting to the origin.
  if (!resumed_connection.preprocess_circuits()) {
    std::cerr << "[Prover] preprocess_circuits failed on resumed connection\n";
    std::abort();
  }

  bool ok2 = resumed_connection.connect_to(ip, server_port);
  if (!ok2) {
    dump_err_queue("Prover/resumed");
    SSL *r = resumed_connection.get_ssl_object();
    std::cerr << "[Prover] resumed SSL state: " << SSL_state_string_long(r) << "\n";
    std::cerr << "[Prover] resumed in_init: " << SSL_in_init(r) << "\n";
    std::cerr << "[Prover] errno: " << strerror(errno) << "\n";
  }

  std::cerr << "[Prover] resumed connect_to ok=" << ok2
        << " session_reused=" << SSL_session_reused(resumed_connection.get_ssl_object()) << "\n";

  if (ok2) {
    std::cerr << "[Prover] sending GET request on resumed connection\n";
    const std::string req =
      "POST /verify HTTP/1.1\r\n"
      "Host: " + ip + "\r\n"
      "Content-Length: 0\r\n"
      "Connection: close\r\n\r\n";
    SSL_write(resumed_connection.get_ssl_object(), req.c_str(), req.size());
    std::cerr << "[Prover] sent GET request\n";

    std::string response;
    while (true) {
      nr = SSL_read(resumed_connection.get_ssl_object(), resp_buf, sizeof(resp_buf));
      if (nr > 0) {
        response += std::string((char*)resp_buf, nr);
        auto header_end = response.find("\r\n\r\n");
        if (header_end != std::string::npos) {
          auto cl_pos = response.find("Content-Length: ");
          if (cl_pos != std::string::npos) {
            size_t cl = std::stoul(response.substr(cl_pos + 16));
            if (response.size() >= header_end + 4 + cl) break;
          }
        }
        continue;
      }
      int ssl_err = SSL_get_error(resumed_connection.get_ssl_object(), nr);
      if (ssl_err == SSL_ERROR_ZERO_RETURN || ssl_err == SSL_ERROR_SYSCALL) break;
    }
    render_in_terminal("index.html (resumed)", response);
    SSL_shutdown(resumed_connection.get_ssl_object());
  }

  return 0;
}
