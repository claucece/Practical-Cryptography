#include "Server.hpp"
#include "../Decl.hpp"
#include "../ssl/Messaging.hpp"
#include "../ssl/GHash.hpp"
#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.
#include <array>
#include <cerrno>
#include <iostream>
#include <poll.h>
#include "openssl/sha.h"
#include <algorithm>

#define CONCAT_IMPL(x, y) x##y
#define MACRO_CONCAT(x, y) CONCAT_IMPL(x, y)
#define TIME(event)                                                            \
  Timer::TimeIt<Timer::TimerType> MACRO_CONCAT(timer, __COUNTER__)(timer, event)
#define TRACK_IF_INTERESTED(event, amount)                                     \
  do {                                                                         \
    if constexpr (BandwidthTracker::TrackerType::is_interested(event)) {       \
      *bandwidth_tracker.get_memory_for(event) += amount;                      \
    }                                                                          \
  } while (0)
#define TRACK_ROUNDS_IF_INTERESTED(event, amount)                              \
  do {                                                                         \
    if constexpr (RoundTracker::TrackerType::is_interested(event)) {           \
      *round_tracker.get_memory_for(event) += amount;                          \
    }                                                                          \
  } while (0)

#define PRINT_IF_LOUD(x)                                                       \
  do {                                                                         \
    if (true) {                                                          \
      std::cerr << "[Server] " << x << std::endl;                              \
    }                                                                          \
  } while (0)

SSL *Server::get_ssl() { return socket.get_ssl_object(); }

const Timer::TimerType &Server::get_timer() const noexcept { return this->timer; }

const BandwidthTracker::TrackerType &
Server::get_bandwidth_tracker() const noexcept {
  return this->bandwidth_tracker;
}

const RoundTracker::TrackerType &Server::get_round_tracker() const noexcept {
  return this->round_tracker;
}

void Server::set_cipher_suite(const uint16_t cipher_suite_in) noexcept {
  this->cipher_suite = cipher_suite_in;
}

void Server::set_version(const uint16_t version_in) noexcept {
  this->version = version_in;
}

KeyShare &Server::get_active_share() { return key_shares[active_key_share]; }

// Starting the server
Server::Server(bssl::UniquePtr<SSL_CTX> &&ctx, const std::string &ip_address,
               const bool is_ip_v6, const int backlog,
               const uint16_t port) noexcept
    : ssl_ctx{std::move(ctx)}, key_shares{}, public_key{},
      additive_share{}, state{ServerState::ACCEPT}, ret_code{},
      socket(*ssl_ctx), buffer{}, x_secret{}, transcript{}, transcript_obj{false},
      handshake_key_shares{}, version{}, cipher_suite{}, timer{},
      bandwidth_tracker{}, round_tracker{} {
  // Not really much we can do here in case of failure.
  [[maybe_unused]] const bool initialised_correctly =
      socket.is_ssl_valid() && buffer.Init(SSL3_RT_MAX_PLAIN_LENGTH);

  assert_and_assume(initialised_correctly);

  // This is called an immediately-invoked lambda expression.
  // See the README for more.
  [[maybe_unused]] const bool setup = [&]() {
    if (is_ip_v6) {
      return socket.set_ip_v6() && socket.set_addr(ip_address) &&
             socket.set_port(port) && socket.bind() && socket.listen(backlog);
    }

    return socket.set_ip_v4() && socket.set_addr(ip_address) &&
           socket.set_port(port) && socket.bind() && socket.listen(backlog);
  }();

  assert_and_assume(setup);

  {
    if (!Surf::mode_from_env(this->mode)) {
      std::abort();  // misconfiguration, not a runtime failure
    }
    this->true_surf = Surf::is_capture(this->mode);
    std::cerr << "[Server] SURF mode: " << Surf::mode_name(this->mode) << "\n";

    const char *const r = ::getenv("SURF_RETAIN");
    this->retain_ct = !(r && r[0] == '0');
  }
}

bool Server::set_accept_timeout(int milliseconds) noexcept {
  return socket.set_accept_timeout(milliseconds);
}

std::array<uint16_t, 2> Server::get_curve_ids() const noexcept {
  return {key_shares[0].get_group_id(), key_shares[1].get_group_id()};
}

bool Server::get_additive_share(bssl::Array<uint8_t> &arr) const noexcept {
  bssl::Array<uint8_t> share_1, share_2;
  if (!key_shares[0].get_additive_share(share_1) ||
      !key_shares[1].get_additive_share(share_2)) {
    PRINT_IF_LOUD("Failed to get additive shares");
    return false;
  }

  if (!arr.Init(share_1.size() + share_2.size())) {
    PRINT_IF_LOUD("Failed to init shares in get_additive_shares");
    return false;
  }

  if (!share_1.empty()) {
    std::copy(share_1.begin(), share_1.end(), arr.begin());
  }

  if (!share_2.empty()) {
    const auto offset = share_1.size();
    std::copy(share_2.begin(), share_2.end(), arr.begin() + offset);
  }
  return true;
}

bool Server::get_public_key(bssl::Array<uint8_t> &arr) const noexcept {

  bssl::Array<uint8_t> share_1, share_2;
  if (!key_shares[0].get_public_key(share_1) ||
      !key_shares[1].get_public_key(share_2)) {
    PRINT_IF_LOUD("Failed to get public keys in get_public_key");
    return false;
  }

  if (!arr.Init(share_1.size() + share_2.size())) {
    PRINT_IF_LOUD("Failed to init array in get_public_key");
    return false;
  }

  if (!share_1.empty()) {
    std::copy(share_1.begin(), share_1.end(), arr.begin());
  }

  if (!share_2.empty()) {
    const auto offset = share_1.size();
    std::copy(share_2.begin(), share_2.end(), arr.begin() + offset);
  }

  return true;
}

static constexpr Server::ServerState
next_state(const Server::ServerState state) {
  // This function returns the "next" server state from a given `state`.
  // You can view this function as a transition graph: it tells you where the
  // server is going.

  // To make this as neat as possible, we'll exploit certain properties of the
  // ServerState enum. It's an ordered enum: each state follows from the next
  // one.
  // This is equivalent to incrementing each state, with DONE being the maximum.
  // We can handle this.
  // Should check first that the sizes match up.
  static_assert(sizeof(Server::ServerState) == sizeof(uint8_t),
                "Error: ServerState is no longer the sizeof a uint8_t");

  switch (state) {
  case Server::ServerState::DONE:
    return state;
  case Server::ServerState::READING_SKS:
    return Server::ServerState::FINISHING_TPH;
  default:
    return static_cast<Server::ServerState>((static_cast<uint8_t>(state) + 1));
  }
}

static bool read_keyshare(Messaging::MessageHeaders &header, TLSSocket &socket,
                          bssl::Array<uint8_t> &buffer,
                          bssl::Array<uint8_t> &out) {
  // A bare single SSL_read can return SSL_ERROR_WANT_READ here when the peer
  // hasn't pushed the key-share message yet: over a real network there is RTT
  // latency before the record arrives, whereas on loopback it is always already
  // buffered. Treating that transient as a hard failure breaks READING_SKS /
  // READING_KS against real hosts with "Failed to read ... header". Poll and
  // retry until the record arrives, exactly as read_exact_blocking does for the
  // fixed-size control messages. The whole key share always fits in one record
  // (see Messaging::pack_key_bytes), so a single successful read returns it.
  SSL *const ssl = socket.get_ssl_object();
  int nr_bytes;
  for (;;) {
    nr_bytes = socket.read(buffer.data(), static_cast<int>(buffer.size()));
    if (nr_bytes > 0) {
      break;
    }
    const int err = SSL_get_error(ssl, nr_bytes);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      // SSL_ERROR_ZERO_RETURN (clean shutdown) or a genuine fatal error.
      return false;
    }
    struct pollfd pfd;
    pfd.fd = SSL_get_fd(ssl);
    pfd.events =
        static_cast<short>(err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN);
    pfd.revents = 0;
    if (::poll(&pfd, 1, -1) < 0 && errno != EINTR) {
      return false;
    }
  }

  // The only check we do here is that the header is valid: the callers know
  // better with regards to what they want to do with the output data.
  return Messaging::unpack_key_bytes(
      header, bssl::MakeSpan(buffer.data(), static_cast<size_t>(nr_bytes)),
      out);
}

bool Server::read_sks_keyshare() noexcept {
  // Note: we don't actually need to check the state here, otherwise
  // we wouldn't have entered this function.
  // But we do it anyway: in release builds this will turn off.
  assert(this->state == ServerState::READING_SKS);
  TIME(Events::State::READING_SKS);

  // Now we'll just delegate to the actual routine.
  // We also want the key share to be a server key share (ideally)
  // We received the actual server key share from the server
  Messaging::MessageHeaders header;
  if (!read_keyshare(header, socket, buffer, client_public_key) ||
      header != Messaging::MessageHeaders::SERVER_KEY_SHARE) {
    PRINT_IF_LOUD("Failed to read sks_key_share header");
    return false;
  }

  // The + here is to account for us reading the header too.
  TRACK_ROUNDS_IF_INTERESTED(Events::State::READING_SKS, 1);
  TRACK_IF_INTERESTED(Events::State::READING_SKS,
                      client_public_key.size() +
                          sizeof(Messaging::MessageHeaders));

  // NOTE: we'll do the actual parsing when it comes to creating the key share.
  // Update the state
  this->state = next_state(this->state);
  return true;
}

bool Server::read_keyshare_after_handshake() noexcept {
  // NOTE: we don't check the state here. This is because in normal
  // operation we have the guard in the `run` function to check this,
  // and also because it interferes with testing a bit.
  // Now we'll just delegate to the actual routine.
  TIME(Events::State::READING_KS);
  Messaging::MessageHeaders header;
  if (!read_keyshare(header, socket, buffer, client_public_key) ||
      header != Messaging::MessageHeaders::COLLECT) {
    PRINT_IF_LOUD("Failed to read origin server key share after handshake");
    return false;
  }

  // The + here is to account for us reading the header too.
  TRACK_ROUNDS_IF_INTERESTED(Events::State::READING_KS, 1);
  TRACK_IF_INTERESTED(Events::State::READING_KS,
                      client_public_key.size() +
                          sizeof(Messaging::MessageHeaders));

  // Again, we'll look into parsing this in the next step.
  // Update the state
  this->state = next_state(ServerState::READING_KS);
  return true;
}

bool Server::get_portnumber(uint16_t *const out) const noexcept {
  return socket.get_portnumber(out);
}

bool Server::accept() noexcept {
  TIME(Events::State::ACCEPT);
  if (socket.accept()) {
    this->state = next_state(this->state);
    return true;
  }
  PRINT_IF_LOUD("Failed to accept connection");
  return false;
}

// Start the server handshake: this is verifier to client
bool Server::do_handshake() noexcept {
  // Note: if there's a message on the socket, then we need to read that
  // message, and ultimately dispatch to another function. The reason for this
  // is because the SSL_read function does the handshake implicitly if there
  // are any pending. In addition, because we share a single BIO across both
  // reading and writing, writing out the handshake done would overwrite the
  // sent data. Otherwise we'll just do the normal handshake. 1 is the success
  // condition
  TIME(Events::State::HANDSHAKE);

  if (socket.do_handshake() != 1) {
    PRINT_IF_LOUD("Failed to do handshake");
    return false;
  }

  // If there's nothing here to read, then we'll go to writing
  // the handshake out.
  // When all messages of the handshake are done, we reach this level
  if (socket.pending() == 0) {
    this->state = ServerState::HANDSHAKE_DONE;
    return true;
  }

  // We're actually now reading the key share.
  // We read the key share from the client
  this->state = ServerState::READING_KS;

  // Read the data that's waiting for us.
  const auto read = socket.read(buffer.data(), static_cast<int>(buffer.size()));
  if (read <= 0) {
    // We failed
    PRINT_IF_LOUD("Failed to read extra data in handshake");
    return false;
  }

  // the + here is because of the write that we're about to do (see below).
  TRACK_ROUNDS_IF_INTERESTED(Events::State::HANDSHAKE, 1);
  TRACK_IF_INTERESTED(Events::State::HANDSHAKE,
                      static_cast<uint64_t>(read) +
                          sizeof(Messaging::MessageHeaders));

  // Otherwise, we might have a message we need. We'll write that the
  // handshake succeeded, then we'll parse it.
  Messaging::MessageHeaders header;
  if (!write_handshake_done() ||
      !Messaging::unpack_key_bytes(header, buffer, client_public_key) ||
      header != Messaging::MessageHeaders::COLLECT) {
    PRINT_IF_LOUD("Failed to write handshake done or unpack key bytes");
    return false;
  }

  this->state = ServerState::MAKING_KS;
  return true;
}

// Create the shares of the client
// MAKING_KS
bool Server::create_new_share() noexcept {
  TIME(Events::State::MAKING_KS);
  return create_new_share(this->client_public_key);
}

// This is where MPC pre-processing happens: the offline phase for verifier and client
bool Server::do_preproc(const bool should_preproc) noexcept {
  TIME(Events::State::CIRCUIT_PREPROC);

  if (!should_preproc) {
    this->state = ServerState::READING_KS;
    return true;
  }

  // Initialise the circuits. Warning: the layout here has to be like this. This
  // is because the call to the constructor for the underlying object may
  // exchange data over "ssl", which can confuse emp.
  //
  // Circuit preprocessing now runs before the key shares are exchanged, so the
  // negotiated group is not yet known here. The ClientHello only ever offers a
  // single NIST key share (SECP256R1), so we build circuit A for that fixed
  // group. Circuit B (SECP384R1) is never negotiated and is therefore not
  // built. The prover side (ThreePartyHandshake::preprocess_circuits) must match
  // this set and order exactly, since do_preproc is interactive OT.
  handshake_circuits[0].reset(EmpWrapperAG2PC::build_derive_hs_circuit(
      socket.get_ssl_object(), SSL_CURVE_SECP256R1, emp::BOB,
      EmpWrapperAG2PCConstants::HANDSHAKE_CIRCUIT_TAG_A));
  if (handshake_circuits[0]) {
    PRINT_IF_LOUD("Preproc HS1 circuit");
    handshake_circuits[0]->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        handshake_circuits[0]->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               handshake_circuits[0]->get_round_counter());
    if (handshake_circuits[0]->has_io_failed()) {
      PRINT_IF_LOUD("Preproc HS1 circuit failed; abandoning run");
      return false;
    }
  }

  traffic_circuit.reset(EmpWrapperAG2PC::build_derive_ts_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::TRAFFIC_CIRCUIT_TAG));
  if (traffic_circuit) {
    PRINT_IF_LOUD("Preproc traffic circuit");
    traffic_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        traffic_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               traffic_circuit->get_round_counter());
    if (traffic_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc traffic circuit failed; abandoning run");
      return false;
    }
  }

  gcm_circuit.reset(EmpWrapperAG2PC::build_gcm_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::GCM_CIRCUIT_TAG));
  if (gcm_circuit) {
    PRINT_IF_LOUD("Preproc gcm share circuit");
    gcm_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        gcm_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               gcm_circuit->get_round_counter());
    if (gcm_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc gcm share circuit failed; abandoning run");
      return false;
    }
  }

  resumption_circuit.reset(EmpWrapperAG2PC::build_derive_res_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::RMS_CIRCUIT_TAG));
  if (resumption_circuit) {
    PRINT_IF_LOUD("Preproc res circuit");
    resumption_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        resumption_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               resumption_circuit->get_round_counter());
    if (resumption_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc res circuit failed; abandoning run");
      return false;
    }
  }

  // Two PSK circuits, one per ticket_nonce width (1-byte LiteSpeed/BoringSSL,
  // 8-byte OpenSSL/nginx). The origin's nonce width is only known to the prover
  // (post-handshake), so both are preprocessed here in lock-step with the
  // prover's matching pair; the prover signals which to run via
  // DERIVE_PSK/DERIVE_PSK_8 in derive_psk.
  psk_circuit.reset(EmpWrapperAG2PC::build_derive_psk_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::PSK_CIRCUIT_TAG));
  if (psk_circuit) {
    PRINT_IF_LOUD("Preproc psk circuit");
    psk_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        psk_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               psk_circuit->get_round_counter());
    if (psk_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc psk circuit failed; abandoning run");
      return false;
    }
  }

  psk_circuit_8.reset(EmpWrapperAG2PC::build_derive_psk_circuit_8(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::PSK_CIRCUIT_TAG_8));
  if (psk_circuit_8) {
    PRINT_IF_LOUD("Preproc psk circuit (8-byte nonce)");
    psk_circuit_8->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        psk_circuit_8->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               psk_circuit_8->get_round_counter());
    if (psk_circuit_8->has_io_failed()) {
      PRINT_IF_LOUD("Preproc psk circuit (8-byte) failed; abandoning run");
      return false;
    }
  }

  psk_circuit_0.reset(EmpWrapperAG2PC::build_derive_psk_circuit_0(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::PSK_CIRCUIT_TAG_0));
  if (psk_circuit_0) {
    PRINT_IF_LOUD("Preproc psk circuit (0-byte nonce)");
    psk_circuit_0->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        psk_circuit_0->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               psk_circuit_0->get_round_counter());
    if (psk_circuit_0->has_io_failed()) {
      PRINT_IF_LOUD("Preproc psk circuit (0-byte) failed; abandoning run");
      return false;
    }
  }

  // Binder circuit for the resumed ClientHello.
  binder_circuit.reset(EmpWrapperAG2PC::build_derive_binder_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::BINDER_CIRCUIT_TAG));
  if (binder_circuit) {
    PRINT_IF_LOUD("Preproc binder circuit");
    binder_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        binder_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               binder_circuit->get_round_counter());
    if (binder_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Failed to preprocess binder circuit in do_preproc");
      return false;
    }
  }

  // GCM tag verification circuit
  gcm_vfy_circuit.reset(
      true_surf ? EmpWrapperAG2PC::build_gcm_vfy_commit_circuit(
                      socket.get_ssl_object(), emp::BOB,
                      EmpWrapperAG2PCConstants::GCM_VFY_COMMIT_CIRCUIT_TAG)
                : EmpWrapperAG2PC::build_gcm_vfy_circuit(
                      socket.get_ssl_object(), emp::BOB,
                      EmpWrapperAG2PCConstants::GCM_VFY_CIRCUIT_TAG));
  if (gcm_vfy_circuit) {
    if (true_surf) {
      PRINT_IF_LOUD("Preproc gcm vfy circuit (with key commitment)");
    } else {
      PRINT_IF_LOUD("Preproc gcm vfy circuit");
    }
    gcm_vfy_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        gcm_vfy_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               gcm_vfy_circuit->get_round_counter());
    if (gcm_vfy_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc gcm vfy circuit failed; abandoning run");
      return false;
    }
  }

  // Reveal and verify the mask
  if (!true_surf) {
  ks_block_circuit.reset(EmpWrapperAG2PC::build_ks_batch_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::KS_BATCH_CIRCUIT_TAG));
  if (ks_block_circuit) {
    PRINT_IF_LOUD("Preproc ks block circuit");
    ks_block_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        ks_block_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               ks_block_circuit->get_round_counter());
    if (ks_block_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc ks block circuit failed; abandoning run");
      return false;
    }
  }
  } else {
    PRINT_IF_LOUD("TRUE mode: skipping ks block circuit");
  }

  // SURF 2PC-AES-GCM encryption (Algorithm 1).
  aes_enc_circuit.reset(EmpWrapperAG2PC::build_aes_enc_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::AES_ENC_CIRCUIT_TAG));
  if (aes_enc_circuit) {
    PRINT_IF_LOUD("Preproc aes enc circuit");
    aes_enc_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        aes_enc_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               aes_enc_circuit->get_round_counter());
    if (aes_enc_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc aes enc circuit failed; abandoning run");
      return false;
    }
  }

  gcm_tag_circuit.reset(EmpWrapperAG2PC::build_gcm_tag_circuit(
      socket.get_ssl_object(), emp::BOB,
      EmpWrapperAG2PCConstants::GCM_TAG_CIRCUIT_TAG));
  if (gcm_tag_circuit) {
    PRINT_IF_LOUD("Preproc gcm tag circuit");
    gcm_tag_circuit->do_preproc();
    TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                        gcm_tag_circuit->get_counter());
    TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                               gcm_tag_circuit->get_round_counter());
    if (gcm_tag_circuit->has_io_failed()) {
      PRINT_IF_LOUD("Preproc gcm tag circuit failed; abandoning run");
      return false;
    }
  }

  if (mode == Surf::Mode::Rotate) {
    rotate_circuit.reset(EmpWrapperAG2PC::build_derive_rotate_circuit(
        socket.get_ssl_object(), emp::BOB,
        EmpWrapperAG2PCConstants::ROTATE_CIRCUIT_TAG));
    if (rotate_circuit) {
      PRINT_IF_LOUD("Preproc rotate circuit");
      rotate_circuit->do_preproc();
      TRACK_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                          rotate_circuit->get_counter());
      TRACK_ROUNDS_IF_INTERESTED(Events::State::CIRCUIT_PREPROC,
                                 rotate_circuit->get_round_counter());
      if (rotate_circuit->has_io_failed()) {
        PRINT_IF_LOUD("Preproc rotate circuit failed; abandoning run");
        return false;
      }
    }
  }

  this->state = next_state(this->state);
  return true;
}

// Create the shares of the client
// MAKING_KS
bool Server::create_new_share(
    const bssl::Array<uint8_t> &other_key_bytes) noexcept {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // The input key bytes array can be one of two things here.
  // 1. It can be an array that contains a single public key.
  // If this is the case, then the array will have a 16-bit group ID,
  // a 16-bit length, and then a key.
  // 2. It can be an array that contains two public keys.
  // In this case the format is the same as before, but there'll be
  // some extra length left over when we load the key.
  CBS cbs, key;
  CBS_init(&cbs, other_key_bytes.data(), other_key_bytes.size());

  // It turns out we can implicitly convert between CBS' and Spans, so this call
  // can be direct.
  uint16_t group_id[2];
  if (!CBS_get_u16(&cbs, &group_id[0]) ||
      !CBS_get_u16_length_prefixed(&cbs, &key) ||
      !key_shares[0].create_new_share(group_id[0], key)) {
    PRINT_IF_LOUD("Failed to create first key share");
    return false;
  }

  // If there's not another key left then we're done.
  if (CBS_len(&cbs) == 0) {
    this->state = next_state(this->state);
    return true;
  }

  // Otherwise, make the other share.
  // Here we're a bit more lucky; we just need to
  // convert the CBS back into an array.
  bssl::Array<uint8_t> key_2_bytes;
  if (!CBS_get_u16(&cbs, &group_id[1]) ||
      !CBS_get_u16_length_prefixed(&cbs, &key) ||
      !key_shares[1].create_new_share(group_id[1], key)) {
    PRINT_IF_LOUD("Failed to create second key share");
    return false;
  }

  if (CBS_len(&cbs) != 0) {
    PRINT_IF_LOUD("Received extra data in create_new_share");
    return false;
  }

  this->state = next_state(this->state);
  return true;
}

// Send the client/verifier shares
bool Server::send_additive_share() {
  TIME(Events::State::WRITING_KS);
  if (!get_additive_share(additive_share)) {
    PRINT_IF_LOUD("Failed to get additive share in send_additive_share");
    return false;
  }

  bssl::Array<uint8_t> bytes;
  if (!Messaging::pack_key_bytes(Messaging::MessageHeaders::OK, additive_share,
                                 bytes)) {
    PRINT_IF_LOUD("Failed to pack key bytes in send_additive_share");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::WRITING_KS, 1);
  TRACK_IF_INTERESTED(Events::State::WRITING_KS, bytes.size());

  if (socket.write(bytes.data(), bytes.size(), &ret_code)) {
    this->state = next_state(this->state);
    return true;
  }
  PRINT_IF_LOUD("Failed to send bytes in send_additive_share");
  return false;
}

// Loop-until-complete blocking read that tolerates SSL_ERROR_WANT_READ /
// WANT_WRITE. The accepted prover<->verifier connection can return WANT_READ
// (errno EAGAIN) from SSL_read when the lock-step peer simply hasn't sent the
// next control byte yet: over a real network there is RTT latency between
// messages, so the byte is briefly "not there", whereas on loopback it is
// always already present. A bare single SSL_read treats that transient as a
// hard failure, which desynchronises the protocol (e.g. the resumed-handshake
// DERIVE_PSK header read failing with amount_read=-1, ssl_err=WANT_READ). Here
// we instead wait for the socket to become ready and retry until all `len`
// bytes are read. Returns true iff every byte was read.
static bool read_exact_blocking(SSL *const ssl, void *const buf,
                                const std::size_t len) noexcept {
  if (!ssl) return false;
  auto *const p = static_cast<uint8_t *>(buf);
  std::size_t total = 0;
  while (total < len) {
    const int n =
        SSL_read(ssl, p + total, static_cast<int>(len - total));
    if (n > 0) {
      total += static_cast<std::size_t>(n);
      continue;
    }
    const int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      // Block until the socket is ready, rather than busy-spinning, then retry.
      struct pollfd pfd;
      pfd.fd = SSL_get_fd(ssl);
      pfd.events =
          static_cast<short>(err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN);
      pfd.revents = 0;
      const int pr = ::poll(&pfd, 1, -1);
      if (pr < 0) {
        if (errno == EINTR) continue;
        return false;
      }
      continue;
    }
    std::cerr << "[read_exact_blocking] n=" << n << " err=" << err
              << " total=" << total << "/" << len << std::endl;
    // SSL_ERROR_ZERO_RETURN (clean shutdown) or a genuine fatal error.
    return false;
  }
  return true;
}

template <typename T, typename F>
static bool read_single_integral(TLSSocket &socket, T &out, F &&func) noexcept {
  // Note; this would be an obvious optimisation point, as sending small
  // messages is expensive. The system call costs the same regardless of the
  // number of bytes you send.
  static_assert(std::is_integral_v<T> || std::is_same_v<std::byte, T>,
                "Error: cannot instantiate read_single_integral with "
                "non-integral or byte T");

  T buf;
  CBS in_cbs;

  // Use a retrying, loop-until-complete read (see read_exact_blocking): a bare
  // single SSL_read can return short / WANT_READ over a real network and break
  // the lock-step framing.
  if (!read_exact_blocking(socket.get_ssl_object(), &buf, sizeof(T))) {
    return false;
  }

  // This cast is legal because uint8_t can alias any other type.
  CBS_init(&in_cbs, reinterpret_cast<const uint8_t *>(&buf), sizeof(buf));
  return func(in_cbs, out);
}

static bool read_single_u64(TLSSocket &socket, uint64_t &size) noexcept {
  auto func = [](CBS &cbs, uint64_t &arg) { return CBS_get_u64(&cbs, &arg); };

  return read_single_integral(socket, size, func);
}

static bool read_single_u16(TLSSocket &socket, uint16_t &val) noexcept {
  auto func = [](CBS &cbs, uint16_t &arg) { return CBS_get_u16(&cbs, &arg); };
  return read_single_integral(socket, val, func);
}

static bool read_single_header(TLSSocket &socket,
                               Messaging::MessageHeaders &header) {
  static_assert(
      sizeof(Messaging::MessageHeaders) == sizeof(uint8_t),
      "Error: sizeof(Messaging::MessageHeaders is no longer sizeof(uint8_t)");

  uint8_t in_header;
  auto func = [](CBS &cbs, uint8_t &arg) {
    if (!CBS_get_u8(&cbs, &arg)) {
      std::cerr << "[read_single_header] CBS_get_u8 failed" << std::endl;
      return false;
    }
    if (!Messaging::is_valid_header(arg)) {
      std::cerr << "[read_single_header] invalid header byte "
                << static_cast<int>(arg) << std::endl;
      return false;
    }
    return true;
  };
  if (!read_single_integral(socket, in_header, func)) {
    return false;
  }

  header = static_cast<Messaging::MessageHeaders>(in_header);
  return true;
}


static bool write_single_header(TLSSocket &socket,
                                const Messaging::MessageHeaders header) {
  // Note; this would be an obvious optimisation point, as sending small
  // messages is expensive. The system call costs the same regardless of the
  // number of bytes you send.
  // This is also expensive because we heap allocate etc.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> arr;

  // This static check here is to make sure that the
  // size of the enum hasn't changed without us noticing (this sort of silent
  // break is insidious).
  static_assert(
      sizeof(Messaging::MessageHeaders) == sizeof(uint8_t),
      "Error: sizeof(Messaging::MessageHeaders is no longer sizeof(uint8_t)");

  if (!CBB_init(cbb.get(), 1) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &arr) ||
      !socket.write(arr.data(), sizeof(uint8_t))) {
    return false;
  }

  return true;
}

// Read the AES masks for commitments
bool Server::read_mask_commitments() noexcept {
  TIME(Events::State::MASK_COMMIT);

  // Masked mode only.
  if (true_surf) {
    PRINT_IF_LOUD("TRUE mode: skipping mask commitment read");
    this->state = next_state(this->state);
    return true;
  }

  SSL *const ssl = socket.get_ssl_object();
  if (!ssl) {
    return false;
  }

  Messaging::MessageHeaders header;
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::MASK_COMMITMENTS) {
    PRINT_IF_LOUD("Failed to read MASK_COMMITMENTS in read_mask_commitments");
    return false;
  }

  if (!read_exact_blocking(ssl, mask_commitment.data(),
                           MaskConstants::kCommitSize)) {
    PRINT_IF_LOUD("Short read in read_mask_commitments");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::MASK_COMMIT, 1);
  TRACK_IF_INTERESTED(Events::State::MASK_COMMIT,
                      sizeof(Messaging::MessageHeaders) +
                          MaskConstants::kCommitSize);

  this->state = next_state(this->state);
  return true;
}

bool Server::read_key_commitment() noexcept {
  TIME(Events::State::KEY_COMMIT);
  if (!true_surf || key_committed || key_released) {
    PRINT_IF_LOUD("Refusing KEY_COMMIT (wrong mode, duplicate, or post-release)");
    return false;
  }
  if (!read_exact_blocking(socket.get_ssl_object(), key_commitment.data(),
                           key_commitment.size())) {
    PRINT_IF_LOUD("Short read in read_key_commitment");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::KEY_COMMIT, 1);
  TRACK_IF_INTERESTED(Events::State::KEY_COMMIT,
                      sizeof(Messaging::MessageHeaders) +
                          key_commitment.size());
  key_committed = true;
  PRINT_IF_LOUD("Key commitment received");
  return true;
}

bool Server::release_key() noexcept {
  TIME(Events::State::KEY_RELEASE);
  if (!true_surf || !key_committed || key_released) {
    PRINT_IF_LOUD("Refusing KEY_RELEASE (wrong mode, uncommitted, or repeat)");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::KEY_RELEASE, 1);
  TRACK_IF_INTERESTED(Events::State::KEY_RELEASE,
                      sizeof(Messaging::MessageHeaders) +
                          traffic_key_shares.server_key_share.size());

  // Latch before writing: verify_gcm_tag consults this, and from the moment
  // k_v is on the wire the prover can forge any record. Everything it will
  // ever attest was submitted and verified before now.
  key_released = true;
  PRINT_IF_LOUD("Releasing k_v after " << verified_seqs.size()
                                       << " verified records");
  return socket.write(traffic_key_shares.server_key_share.data(),
                      traffic_key_shares.server_key_share.size());
}

bool Server::rotate_key_op() noexcept {
  TIME(Events::State::ROTATE_KEY);
  const auto t0 = std::chrono::steady_clock::now();
  SSL *const ssl = socket.get_ssl_object();
  if (!ssl || mode != Surf::Mode::Rotate || !rotate_circuit || !gcm_circuit) {
    PRINT_IF_LOUD("Refusing ROTATE_KEY (wrong mode or circuits missing)");
    return false;
  }

  uint8_t dir;
  if (!read_exact_blocking(ssl, &dir, 1) || dir > 1) {
    PRINT_IF_LOUD("Bad direction in rotate_key_op");
    return false;
  }
  const bool is_client = (dir == 0);
  if (!is_client && !key_released) {
    PRINT_IF_LOUD("Refusing ROTATE_KEY 1: current epoch not released");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::ROTATE_KEY, 1);
  TRACK_IF_INTERESTED(Events::State::ROTATE_KEY,
                      sizeof(Messaging::MessageHeaders) + 1);

  [[maybe_unused]] const auto old_amount = rotate_circuit->get_counter();
  [[maybe_unused]] const auto old_rounds = rotate_circuit->get_round_counter();

  EmpWrapperAG2PCConstants::RotateCircuitIn in{};
  in.secret_share =
      is_client ? traffic_key_shares.CATS_share : traffic_key_shares.SATS_share;
  EmpWrapperAG2PCConstants::RotateCircuitOut out{};
  if (!ThreePartyHandshake::run_rotate_circuit(in, out, rotate_circuit.get(),
                                               true)) {
    PRINT_IF_LOUD("Failed to run rotate circuit");
    return false;
  }
  TRACK_IF_INTERESTED(Events::State::ROTATE_KEY,
                      rotate_circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::ROTATE_KEY,
                             rotate_circuit->get_round_counter() - old_rounds);

  auto &secret =
      is_client ? traffic_key_shares.CATS_share : traffic_key_shares.SATS_share;
  auto &key = is_client ? traffic_key_shares.client_key_share
                        : traffic_key_shares.server_key_share;
  auto &iv = is_client ? traffic_key_shares.client_iv
                       : traffic_key_shares.server_iv;
  auto &gcm = is_client ? client_gcm_powers : server_gcm_powers;
  secret = out.next_share;
  key = out.key_share;
  iv = out.iv;

  uint64_t bandwidth = 0;
  if (!ThreePartyHandshake::make_gcm_share_for(ssl, key, gcm_circuit.get(),
                                               gcm, &bandwidth)) {
    PRINT_IF_LOUD("Failed to re-derive GCM share after rotation");
    return false;
  }
  TRACK_IF_INTERESTED(Events::State::ROTATE_KEY, bandwidth);

  // Sequence numbers restart under the new key.
  if (is_client) {
    encrypted_seqs.clear();
    encrypted_ct.clear();
    encrypt_ct_len = 0;
  } else {
    verified_seqs.clear();
    key_committed = false;
    key_released = false;
    key_commitment.fill(0);
    epoch++;
  }

  const double rotate_ms =
      std::chrono::duration<double, std::milli>(
          std::chrono::steady_clock::now() - t0).count();
  PRINT_IF_LOUD("Rotated " << (is_client ? "client" : "server")
                           << " traffic key (epoch " << epoch << ") in "
                           << rotate_ms << " ms");
  return true;
}

// Verify the GCM tag over one attested record. The GCM_VERIFY header has
// already been consumed by attest(). Wire format:
//   u64 seq || u16 aad_len || aad || u32 ct_len || ciphertext || 16-byte tag
bool Server::verify_gcm_tag() noexcept {
  TIME(Events::State::GCM_VERIFY);

  SSL *const ssl = socket.get_ssl_object();
  if (!ssl) {
    return false;
  }

  // TRUE mode gates. The commitment must be in hand before any ciphertext, so
  // the circuit has something to open against; and once k_v is out the prover
  // can forge any record, so nothing submitted afterwards is attestable.
  if (true_surf) {
    if (!key_committed) {
      PRINT_IF_LOUD("Refusing GCM_VERIFY: no key commitment received");
      return false;
    }
    if (key_released) {
      PRINT_IF_LOUD("Refusing GCM_VERIFY: k_v already released");
      return false;
    }
  }

  std::array<uint8_t, sizeof(uint64_t)> seq_buf;
  if (!read_exact_blocking(ssl, seq_buf.data(), seq_buf.size())) {
    PRINT_IF_LOUD("Failed to read seq in verify_gcm_tag");
    return false;
  }
  uint64_t seq = 0;
  for (unsigned i = 0; i < 8; i++) {
    seq = (seq << 8) | seq_buf[i];
  }

  std::array<uint8_t, sizeof(uint16_t)> aad_len_buf;
  if (!read_exact_blocking(ssl, aad_len_buf.data(), aad_len_buf.size())) {
    PRINT_IF_LOUD("Failed to read aad length in verify_gcm_tag");
    return false;
  }
  const uint16_t aad_len = static_cast<uint16_t>(
      (static_cast<uint16_t>(aad_len_buf[0]) << 8) | aad_len_buf[1]);

  // The TLS 1.3 AAD is the 5-byte record header. Anything else is malformed.
  if (aad_len != SSL3_RT_HEADER_LENGTH) {
    PRINT_IF_LOUD("Bad aad length in verify_gcm_tag");
    return false;
  }

  std::vector<uint8_t> aad(aad_len);
  if (!read_exact_blocking(ssl, aad.data(), aad.size())) {
    PRINT_IF_LOUD("Failed to read aad in verify_gcm_tag");
    return false;
  }

  std::array<uint8_t, sizeof(uint32_t)> ct_len_buf;
  if (!read_exact_blocking(ssl, ct_len_buf.data(), ct_len_buf.size())) {
    PRINT_IF_LOUD("Failed to read ciphertext length in verify_gcm_tag");
    return false;
  }
  const uint32_t ct_len = (static_cast<uint32_t>(ct_len_buf[0]) << 24) |
                          (static_cast<uint32_t>(ct_len_buf[1]) << 16) |
                          (static_cast<uint32_t>(ct_len_buf[2]) << 8) |
                          static_cast<uint32_t>(ct_len_buf[3]);

  // A TLS record's ciphertext cannot exceed the plaintext limit, and the GHASH
  // powers only run to 1088 blocks. Bound before allocating: ct_len is
  // attacker-controlled.
  if (ct_len == 0 || ct_len > SSL3_RT_MAX_PLAIN_LENGTH + 1) {
    PRINT_IF_LOUD("Bad ciphertext length in verify_gcm_tag");
    return false;
  }

  {
    const size_t nblocks_gh = 1 + (static_cast<size_t>(ct_len) + 15) / 16 + 1;
    PRINT_IF_LOUD("ghash needs " << nblocks_gh << " powers, table has "
                                 << (sizeof(server_gcm_powers) / 16));
  }

  std::vector<uint8_t> ciphertext(ct_len);
  if (!read_exact_blocking(ssl, ciphertext.data(), ciphertext.size())) {
    PRINT_IF_LOUD("Short read on ciphertext in verify_gcm_tag");
    return false;
  }

  std::array<uint8_t, 16> server_tag;
  if (!read_exact_blocking(ssl, server_tag.data(), server_tag.size())) {
    PRINT_IF_LOUD("Failed to read server tag in verify_gcm_tag");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::GCM_VERIFY, 1);
  TRACK_IF_INTERESTED(Events::State::GCM_VERIFY,
                      sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) +
                          sizeof(uint16_t) + aad_len + sizeof(uint32_t) +
                          ct_len + 16);

  // This party's share of P_{A||C||len(A)||len(C)}({h^i}).
  EmpWrapperAG2PCConstants::GCMVfyCircuitIn input{};
  if (!GHash::share(server_gcm_powers,
                   bssl::MakeConstSpan(aad.data(), aad.size()),
                   bssl::MakeConstSpan(ciphertext.data(), ciphertext.size()),
                   input.tag_share)) {
    PRINT_IF_LOUD("Failed to compute ghash share in verify_gcm_tag");
    return false;
  }

  // J0 = (server_iv XOR seq) || 0x00000001. Derived independently by both
  // parties from values they already hold; the circuit's IV-equality check is
  // what catches a mismatch.
  input.iv.fill(0);
  std::copy(traffic_key_shares.server_iv.cbegin(),
            traffic_key_shares.server_iv.cend(), input.iv.begin());
  for (unsigned i = 0; i < 8; i++) {
    input.iv[11 - i] ^= static_cast<uint8_t>(seq >> (8 * i));
  }
  input.iv[15] = 1;

  input.key = traffic_key_shares.server_key_share;
  input.server_tag = server_tag;

  if (!gcm_vfy_circuit) {
    PRINT_IF_LOUD("GCM vfy circuit is null in verify_gcm_tag");
    return false;
  }

  // TRUE mode runs the 96-byte variant, which additionally opens the prover's
  // key commitment on the same wires that carry k_c into the AES. Masked mode
  // needs no such check: there, E_i already binds the key.
  if (true_surf) {
    EmpWrapperAG2PCConstants::GCMVfyCommitCircuitIn cin{};
    cin.key = input.key;
    cin.iv = input.iv;
    cin.tag_share = input.tag_share;
    cin.server_tag = input.server_tag;
    cin.d_k = key_commitment;
    // cin.r_k stays zero: BOB-side padding.

    EmpWrapperAG2PCConstants::GCMVfyCommitCircuitOut cout{};
    if (!ThreePartyHandshake::run_gcm_vfy_commit_circuit(
            cin, cout, gcm_vfy_circuit.get())) {
      PRINT_IF_LOUD("Failed to run gcm vfy commit circuit in verify_gcm_tag");
      return false;
    }
    if (cout.cheated) {
      PRINT_IF_LOUD("GCM verify: parties supplied mismatched IV or tag");
      return false;
    }
    if (!cout.key_opened) {
      PRINT_IF_LOUD("GCM verify: key commitment did not open -- the prover fed "
                    "a key share other than the one it committed to");
      return false;
    }
    if (!cout.tag_passed) {
      if (mode == Surf::Mode::Rotate) {
        PRINT_IF_LOUD("GCM verify: tag did not match (not attested)");
        return write_single_header(socket, Messaging::MessageHeaders::TAG_REJECT);
      }

      PRINT_IF_LOUD("GCM verify: tag did not match");
      return false;
    }

    // Retained so a later disclosure can yield plaintext: this party never
    // learns k_c during the run, so it cannot decrypt now.
    if (retain_ct) {
      attested_ct.emplace_back(seq, std::move(ciphertext));
    }
    verified_seqs.push_back(seq);
    PRINT_IF_LOUD("GCM tag verified (key commitment opened)");
    if (mode == Surf::Mode::Rotate &&
        !write_single_header(socket, Messaging::MessageHeaders::TAG_OK)) return false;

    PRINT_IF_LOUD("GCM tag verified (key commitment opened)");
    return true;
  }

  EmpWrapperAG2PCConstants::GCMVfyCircuitOut output{};
  if (!ThreePartyHandshake::run_gcm_vfy_circuit(input, output,
                                                gcm_vfy_circuit.get())) {
    PRINT_IF_LOUD("Failed to run gcm vfy circuit in verify_gcm_tag");
    return false;
  }

  if (output.cheated) {
    PRINT_IF_LOUD("GCM verify: parties supplied mismatched IV or tag");
    return false;
  }
  if (!output.tag_passed) {
    PRINT_IF_LOUD("GCM verify: tag did not match");
    return false;
  }

  verified_seqs.push_back(seq);
  PRINT_IF_LOUD("GCM tag verified");
  return true;
}


bool Server::derive_keystream_blocks() noexcept {
  TIME(Events::State::KS_DERIVE);

  SSL *const ssl = socket.get_ssl_object();
  if (!ssl || !ks_block_circuit) {
    return false;
  }

  // KS_DERIVE || u32 nrec || nrec x (u64 seq || u32 ct_len). The header is
  // already consumed by attest(); the boundaries let this side build the same
  // counter blocks the prover does.
  std::array<uint8_t, sizeof(uint32_t)> nrec_buf;
  if (!read_exact_blocking(ssl, nrec_buf.data(), nrec_buf.size())) {
    return false;
  }
  const uint32_t nrec = (static_cast<uint32_t>(nrec_buf[0]) << 24) |
                        (static_cast<uint32_t>(nrec_buf[1]) << 16) |
                        (static_cast<uint32_t>(nrec_buf[2]) << 8) |
                        static_cast<uint32_t>(nrec_buf[3]);
  // Sanity bound: every record is at least one block.
  if (nrec == 0 || nrec > MaskConstants::kNumMasks) {
    PRINT_IF_LOUD("Bad record count in derive_keystream_blocks");
    return false;
  }

  std::vector<SurfBlockMap::RecordDims> recs;
  recs.reserve(nrec);
  for (uint32_t i = 0; i < nrec; i++) {
    std::array<uint8_t, sizeof(uint64_t) + sizeof(uint32_t)> ent;
    if (!read_exact_blocking(ssl, ent.data(), ent.size())) {
      return false;
    }
    uint64_t seq = 0;
    for (unsigned k = 0; k < 8; k++) seq = (seq << 8) | ent[k];
    const uint32_t ct_len = (static_cast<uint32_t>(ent[8]) << 24) |
                            (static_cast<uint32_t>(ent[9]) << 16) |
                            (static_cast<uint32_t>(ent[10]) << 8) |
                            static_cast<uint32_t>(ent[11]);
    if (ct_len == 0 || ct_len > SSL3_RT_MAX_PLAIN_LENGTH + 1) {
      PRINT_IF_LOUD("Bad ciphertext length in derive_keystream_blocks");
      return false;
    }
    recs.push_back({seq, ct_len});
  }

  // Each record's tag must be verified before its keystream is revealed: the
  // keystream is what lets the prover open plaintext, and an unverified record
  // could carry a ciphertext the origin never sent. Per-record attestation
  // derives one record at a time, so this is keyed on the record's sequence
  // number rather than on a count of verified records.
  for (const auto &r : recs) {
    if (std::find(verified_seqs.cbegin(), verified_seqs.cend(), r.seq) ==
        verified_seqs.cend()) {
      std::cerr << "[Server] refusing keystream: record seq " << r.seq
                << " has no verified tag\n";
      return false;
    }
  }

  const size_t nblocks = SurfBlockMap::total_blocks(recs);
  if (nblocks == 0) {
    return true;
  }

  constexpr auto N = EmpWrapperAG2PCConstants::KS_BATCH_N;
  const size_t nbatches = (nblocks + N - 1) / N;

  [[maybe_unused]] const auto old_amount = ks_block_circuit->get_counter();
  [[maybe_unused]] const auto old_rounds = ks_block_circuit->get_round_counter();

  size_t preprocs = 0;
  double preproc_s = 0.0;
  const auto t_start = std::chrono::steady_clock::now();

  for (size_t batch = 0; batch < nbatches; batch++) {
    // Mirrors the prover: explicit, lock-step re-preprocessing. See
    // ThreePartyHandshake::derive_keystream.
    if (ks_block_circuit->ks_batches_remaining() == 0) {
      const auto t_pp = std::chrono::steady_clock::now();
      ks_block_circuit->do_preproc();
      preproc_s += std::chrono::duration<double>(
          std::chrono::steady_clock::now() - t_pp).count();
      preprocs++;

      if (ks_block_circuit->has_io_failed()) {
        PRINT_IF_LOUD("ks block re-preprocessing failed");
        return false;
      }
    }

    EmpWrapperAG2PCConstants::KSBatchCircuitIn in{};
    in.key = traffic_key_shares.server_key_share;
    in.d = mask_commitment;
    // in.s / in.r stay zero: BOB-side padding.

    for (unsigned j = 0; j < N; j++) {
      const size_t idx = batch * N + j;
      uint64_t seq;
      uint32_t counter;

      if (idx < nblocks) {
        if (!SurfBlockMap::resolve(recs, idx, seq, counter)) {
          return false;
        }
      } else {
        // Mirrors the prover: padding gets a counter that cannot collide with
        // a real block's, since the mask is AES_s(ctr) and a repeat would give
        // E_pad == E_real. See ThreePartyHandshake::derive_keystream.
        if (!SurfBlockMap::resolve(recs, nblocks - 1, seq, counter)) {
          return false;
        }
        counter = 0x80000000u | static_cast<uint32_t>(idx);
      }

      SurfBlockMap::ctr_block(traffic_key_shares.server_iv.data(), seq,
                              counter, in.ctr[j]);
    }

    EmpWrapperAG2PCConstants::KSBatchCircuitOut out{};
    if (!ThreePartyHandshake::run_ks_batch_circuit(in, out,
                                                   ks_block_circuit.get()) ||
        !out.ok) {
      std::cerr << "[Server] ks batch " << batch << " failed\n";
      return false;
    }
  }

  {
    const auto total_s = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();
    std::cerr << "[Server] ks: " << nblocks << " blocks, " << nbatches
              << " batches, " << preprocs << " preprocs (" << preproc_s
              << " s), total " << total_s << " s, other "
              << (total_s - preproc_s) << " s\n";
  }

  TRACK_IF_INTERESTED(Events::State::KS_DERIVE,
                      ks_block_circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::KS_DERIVE,
                             ks_block_circuit->get_round_counter() - old_rounds);

  return true;
}

bool Server::encrypt_blocks() noexcept {
  TIME(Events::State::AES_ENCRYPT);
  SSL *const ssl = socket.get_ssl_object();
  if (!ssl || !aes_enc_circuit) {
    PRINT_IF_LOUD("encrypt_blocks: null ssl or aes_enc_circuit");
    return false;
  }
  constexpr auto N = EmpWrapperAG2PCConstants::AES_ENC_N;

  std::array<uint8_t, sizeof(uint64_t)> seq_buf;
  if (!read_exact_blocking(ssl, seq_buf.data(), seq_buf.size())) {
    PRINT_IF_LOUD("Failed to read seq in encrypt_blocks");
    return false;
  }
  uint64_t seq = 0;
  for (unsigned i = 0; i < 8; i++) {
    seq = (seq << 8) | seq_buf[i];
  }

  // Algorithm 1's freshness requirement. The circuit only checks that both
  // parties agree on the counter; nothing in it prevents a replay, and GCM
  // under nonce reuse leaks the plaintext XOR and the authentication key.
  if (std::find(encrypted_seqs.cbegin(), encrypted_seqs.cend(), seq) !=
      encrypted_seqs.cend()) {
    PRINT_IF_LOUD("Refusing encryption: sequence number " << seq
                  << " already used");
    return false;
  }

  std::array<uint8_t, sizeof(uint32_t)> len_buf;
  if (!read_exact_blocking(ssl, len_buf.data(), len_buf.size())) {
    PRINT_IF_LOUD("Failed to read plaintext length in encrypt_blocks");
    return false;
  }
  const uint32_t pt_len = (static_cast<uint32_t>(len_buf[0]) << 24) |
                          (static_cast<uint32_t>(len_buf[1]) << 16) |
                          (static_cast<uint32_t>(len_buf[2]) << 8) |
                          static_cast<uint32_t>(len_buf[3]);
  if (pt_len == 0 || pt_len > SSL3_RT_MAX_PLAIN_LENGTH) {
    PRINT_IF_LOUD("Bad plaintext length in encrypt_blocks");
    return false;
  }

  const size_t nblocks = (static_cast<size_t>(pt_len) + 15) / 16;
  const size_t nbatches = (nblocks + N - 1) / N;

  TRACK_ROUNDS_IF_INTERESTED(Events::State::AES_ENCRYPT, 1);
  TRACK_IF_INTERESTED(Events::State::AES_ENCRYPT,
                      sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) +
                          sizeof(uint32_t));

  encrypted_ct.assign(nbatches * N, {});
  [[maybe_unused]] const auto old_amount = aes_enc_circuit->get_counter();
  [[maybe_unused]] const auto old_rounds =
      aes_enc_circuit->get_round_counter();

  for (size_t batch = 0; batch < nbatches; batch++) {
    EmpWrapperAG2PCConstants::AESEncBatchCircuitIn in{};
    in.key = traffic_key_shares.client_key_share;

    for (unsigned j = 0; j < N; j++) {
      const size_t idx = batch * N + j;
      const size_t src = (idx < nblocks) ? idx : nblocks - 1;
      // Counters start at 2: J0 = nonce || 1 belongs to the tag.
      SurfBlockMap::ctr_block(traffic_key_shares.client_iv.data(), seq,
                              static_cast<uint32_t>(src) + 2, in.ctr[j]);
      // in.pt stays zero: BOB-side padding.
    }

    EmpWrapperAG2PCConstants::AESEncBatchCircuitOut out{};
    if (!ThreePartyHandshake::run_aes_enc_batch_circuit(in, out,
                                                        aes_enc_circuit.get())) {
      PRINT_IF_LOUD("Failed to run aes enc circuit");
      return false;
    }
    if (!out.ok) {
      PRINT_IF_LOUD("Encrypt: counter mismatch between parties");
      return false;
    }
    for (unsigned j = 0; j < N; j++) {
      encrypted_ct[batch * N + j] = out.ct[j];
    }
  }

  encrypt_ct_len = pt_len;
  encrypted_seqs.push_back(seq);

  TRACK_IF_INTERESTED(Events::State::AES_ENCRYPT,
                      aes_enc_circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::AES_ENCRYPT,
                             aes_enc_circuit->get_round_counter() - old_rounds);
  return true;
}

bool Server::make_gcm_tag() noexcept {
  TIME(Events::State::GCM_TAG);
  SSL *const ssl = socket.get_ssl_object();
  if (!ssl || !gcm_tag_circuit) {
    PRINT_IF_LOUD("make_gcm_tag: null ssl or gcm_tag_circuit");
    return false;
  }

  std::array<uint8_t, sizeof(uint16_t)> aad_len_buf;
  if (!read_exact_blocking(ssl, aad_len_buf.data(), aad_len_buf.size())) {
    return false;
  }
  const uint16_t aad_len = static_cast<uint16_t>(
      (static_cast<uint16_t>(aad_len_buf[0]) << 8) | aad_len_buf[1]);
  if (aad_len != SSL3_RT_HEADER_LENGTH) {
    PRINT_IF_LOUD("Bad aad length in make_gcm_tag");
    return false;
  }

  encrypt_aad.assign(aad_len, 0);
  if (!read_exact_blocking(ssl, encrypt_aad.data(), encrypt_aad.size())) {
    return false;
  }

  std::array<uint8_t, sizeof(uint32_t)> ct_len_buf;
  if (!read_exact_blocking(ssl, ct_len_buf.data(), ct_len_buf.size())) {
    return false;
  }
  const uint32_t ct_len = (static_cast<uint32_t>(ct_len_buf[0]) << 24) |
                          (static_cast<uint32_t>(ct_len_buf[1]) << 16) |
                          (static_cast<uint32_t>(ct_len_buf[2]) << 8) |
                          static_cast<uint32_t>(ct_len_buf[3]);

  // The prover does not resend the ciphertext: we hold it from the encryption
  // circuit's public output. It may only tell us where to truncate, and that
  // must agree with what we already computed.
  if (ct_len != encrypt_ct_len || encrypted_ct.empty()) {
    PRINT_IF_LOUD("Ciphertext length disagrees with encrypt_blocks");
    return false;
  }

  std::vector<uint8_t> ct(ct_len);
  for (size_t i = 0; i < ct_len; i++) {
    ct[i] = encrypted_ct[i / 16][i % 16];
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::GCM_TAG, 1);
  TRACK_IF_INTERESTED(Events::State::GCM_TAG,
                      sizeof(Messaging::MessageHeaders) + sizeof(uint16_t) +
                          aad_len + sizeof(uint32_t));

  EmpWrapperAG2PCConstants::GCMTagCircuitIn input{};
  input.key_share = traffic_key_shares.client_key_share;

  // J0 = (client_iv XOR seq) || 0x00000001, derived from the seq we recorded.
  SurfBlockMap::ctr_block(traffic_key_shares.client_iv.data(),
                          encrypted_seqs.back(), 1, input.iv);

  // tau_v: local, since GHASH is linear in the H-powers.
  if (!GHash::share(client_gcm_powers,
                    bssl::MakeConstSpan(encrypt_aad.data(), encrypt_aad.size()),
                    bssl::MakeConstSpan(ct.data(), ct.size()),
                    input.tag_share)) {
    PRINT_IF_LOUD("Failed to compute ghash share in make_gcm_tag");
    return false;
  }
  // input.mask_or_unused stays zero: BOB-side padding.

  [[maybe_unused]] const auto old_amount = gcm_tag_circuit->get_counter();
  [[maybe_unused]] const auto old_rounds = gcm_tag_circuit->get_round_counter();

  EmpWrapperAG2PCConstants::GCMTagCircuitOut output{};
  if (!ThreePartyHandshake::run_gcm_tag_circuit(input, output,
                                                gcm_tag_circuit.get())) {
    PRINT_IF_LOUD("Failed to run gcm tag circuit in make_gcm_tag");
    return false;
  }
  if (output.cheated) {
    PRINT_IF_LOUD("GCM tag: parties supplied mismatched J0");
    return false;
  }
  // output.tag is tau XOR the prover's mask: this party learns nothing from it.

  TRACK_IF_INTERESTED(Events::State::GCM_TAG,
                      gcm_tag_circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::GCM_TAG,
                             gcm_tag_circuit->get_round_counter() - old_rounds);
  return true;
}

static bool handshake_done_impl(TLSSocket &socket) {
  if (socket.pending() != 0) {
    std::cerr << "Error: attempted to write handshake done, but another "
                 "message was waiting.\n"
              << "This will likely cause data loss." << std::endl;
  }
  return write_single_header(socket, Messaging::MessageHeaders::DONE_HS);
}

bool Server::do_ectf() noexcept {
  // We'll read a single header. If the header isn't what we wanted (e.g a
  // Messaging::MessageHeaders::DO_ECTF) then we bail. Otherwise, we'll do the
  // ECTF.
 Messaging::MessageHeaders mode;
  if (!read_single_header(socket, mode) ||
      (mode != Messaging::MessageHeaders::HS_MODE_FULL &&
       mode != Messaging::MessageHeaders::HS_MODE_RESUMED)) {
    PRINT_IF_LOUD("Failed to read handshake-mode flag in do_ectf");
    return false;
  }
  this->resumed_handshake =
      (mode == Messaging::MessageHeaders::HS_MODE_RESUMED);

  TIME(Events::State::ECTF_WAIT);
  Messaging::MessageHeaders header = Messaging::MessageHeaders::SIZE;
  TRACK_IF_INTERESTED(Events::State::ECTF_WAIT,
                      sizeof(Messaging::MessageHeaders));
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::DO_ECTF) {
    PRINT_IF_LOUD("Failed to read ectf header");
    return false;
  }

  // If not, then call into the ECTF functionality directly.
  auto &key_share = key_shares[active_key_share];
  const auto worked =
      ECtF::ectf(x_secret, socket.get_ssl_object(), key_share.get_x_secret(),
                 key_share.get_y_secret(), key_share.get_group_id(), true,
                 bandwidth_tracker.is_interested(Events::State::ECTF_WAIT),
                 bandwidth_tracker.get_memory_for(Events::State::ECTF_WAIT),
                 round_tracker.get_memory_for(Events::State::ECTF_WAIT));
  if (!worked) {
    PRINT_IF_LOUD("Failed to complete ectf");
    return false;
  }

  // Update the state machine.
  this->state = next_state(this->state);
  return true;
}

bool Server::finish_ectf() noexcept {
  TIME(Events::State::ECTF_DONE);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::ECTF_DONE, 1);
  TRACK_IF_INTERESTED(Events::State::ECTF_DONE,
                      sizeof(Messaging::MessageHeaders::ECTF_DONE));
  // We'll just write a single header.
  if (!write_single_header(socket, Messaging::MessageHeaders::ECTF_DONE)) {
    PRINT_IF_LOUD("Failed to write ectf finished header");
    return false;
  }

  // We're done with the ECTF!
  this->state = next_state(this->state);
  return true;
}

// Done with the client and verifier handshake.
bool Server::write_handshake_done() noexcept {
  TIME(Events::State::HANDSHAKE_DONE);
  // Again, we need to peek here to make sure we haven't received anything in.
  if (socket.pending() != 0) {
    // Read the data that's waiting for us.
    const auto read =
        socket.read(buffer.data(), static_cast<int>(buffer.size()));
    if (read <= 0) {
      PRINT_IF_LOUD("Failed to read extra data in write_handshake_done");
      // We failed
      return false;
    }

    TRACK_ROUNDS_IF_INTERESTED(Events::State::HANDSHAKE_DONE, 1);
    TRACK_IF_INTERESTED(Events::State::HANDSHAKE_DONE,
                        static_cast<uint64_t>(read));

    // If we've read a message here, then it's a keyshare.
    // We'll write out the handshake and then do the parsing.
    // WARNING: if another message has been sent in the meantime this
    // will log an error.
    Messaging::MessageHeaders header;
    if (!handshake_done_impl(socket) ||
        !Messaging::unpack_key_bytes(header, buffer, client_public_key) ||
        header != Messaging::MessageHeaders::COLLECT) {
      PRINT_IF_LOUD("Failed to unpack extra key bytes in write_handshake_done");
      return false;
    }

    // We'll need to update the state here
    this->state = ServerState::MAKING_KS;
    return true;
  }

  if (!handshake_done_impl(socket)) {
    PRINT_IF_LOUD("Failed to execute handshake_done in write_handshake_done");
    return false;
  }

  // Run circuit preprocessing (the offline phase) before reading the key share.
  // The prover runs its preprocessing before opening the origin connection, so
  // the verifier must be ready to preprocess here, before the key-share
  // exchange. (The piggyback path above sets MAKING_KS for the legacy case where
  // COLLECT arrives with the handshake; in the new flow COLLECT arrives later so
  // it never fires.)
  this->state = ServerState::CIRCUIT_PREPROC;
  return true;
}

// Finish the client to origin server TPH
bool Server::finish_tph() noexcept {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  TIME(Events::State::FINISHING_TPH);
  // In this situation we have a key share (in client_public_key)
  // and a key share of our own in share. As a result, all we really need
  // to do is finish off the EC multiplication.

  // The first thing to check is that the read key has a
  // key share that matches one of ours.

  CBS cbs, key;
  CBS_init(&cbs, client_public_key.data(), client_public_key.size());
  if (client_public_key.size() == 0) {
    PRINT_IF_LOUD("Empty client public key in finish_tph");
    return false;
  }

  // Extract the group's ID and make sure the buffer is well-formed.
  uint16_t group_id;
  if (!CBS_get_u16(&cbs, &group_id) ||
      !CBS_get_u16_length_prefixed(&cbs, &key) || CBS_len(&cbs) != 0) {
    PRINT_IF_LOUD("Failed to extract group ID from buffer in finish_tph");
    return false;
  }

  // Now we'll extract the key share that matches ours.
  const auto active_element = std::find_if(
      std::cbegin(key_shares), std::cend(key_shares),
      [&](const KeyShare &share) { return share.get_group_id() == group_id; });

  // If the key share doesn't match, then we have to bail.
  if (active_element == std::cend(key_shares)) {
    PRINT_IF_LOUD("No matching key share in finish_tph");
    return false;
  }

  // Now we'll turn that iterator into something useful.
  // Note; this cast is fine. In fact, because active_key_share is always at
  // most key_shares.size() - 1, we can tell the compiler that.
  active_key_share = static_cast<unsigned>(
      std::distance(std::cbegin(key_shares), active_element));

  // Now we'll actually "do the work".
  if (key_shares[active_key_share].finish(key)) {
    this->state = ServerState::WRITING_HS_RECV;
    return true;
  }

  PRINT_IF_LOUD("Failed to finish key share in finish_tph");
  return false;
}

// We are done with the key shares. We let the verifier know.
bool Server::write_hs_recv() noexcept {
  TIME(Events::State::WRITING_HS_RECV);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::WRITING_HS_RECV, 1);
  TRACK_IF_INTERESTED(Events::State::WRITING_HS_RECV,
                      sizeof(Messaging::MessageHeaders));
  if (socket.pending() != 0) {
    // This means there's data waiting for us.
    // Right now we have to abort here, in lieu of better
    // error checking.
    PRINT_IF_LOUD("Waiting data on write_hs_recv: aborting");
    std::abort();
  }

  // Now we'll just write a single header.
  if (!write_single_header(socket, Messaging::MessageHeaders::HS_RECV)) {
    PRINT_IF_LOUD("Failed to write HS_RECV in write_hs_recv");
    return false;
  }

  // Move to the next one.
  this->state = next_state(this->state);
  return true;
}

bool Server::do_psk_binder() noexcept {
  if (!this->is_resumption_run) {
    this->state = next_state(this->state);
    return true;
  }

  TIME(Events::State::PSK_BINDER);

  Messaging::MessageHeaders header;
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::DERIVE_BINDER) {
    PRINT_IF_LOUD("Failed to read DERIVE_BINDER in do_psk_binder");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::PSK_BINDER, 1);
  TRACK_IF_INTERESTED(Events::State::PSK_BINDER,
                      sizeof(Messaging::MessageHeaders));

  EmpWrapperAG2PCConstants::BinderCircuitIn input{};
  // ch_hash stays zero: it is Alice-only input.
  input.psk_share = psk_shares.PSK_share;

  if (!binder_circuit) {
    PRINT_IF_LOUD("Binder circuit is null in do_psk_binder");
    return false;
  }

  [[maybe_unused]] const auto old_amount = binder_circuit->get_counter();
  [[maybe_unused]] const auto old_rounds = binder_circuit->get_round_counter();

  EmpWrapperAG2PCConstants::BinderCircuitOut output;
  if (!ThreePartyHandshake::run_binder_circuit(input, output,
                                               binder_circuit.get(), true)) {
    PRINT_IF_LOUD("Failed to run binder circuit in do_psk_binder");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::PSK_BINDER,
                      binder_circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::PSK_BINDER,
                             binder_circuit->get_round_counter() - old_rounds);

  // Single-use: free it so the prover cannot re-run the circuit.
  binder_circuit.reset(nullptr);

  this->state = next_state(this->state);
  return true;
}

static constexpr bool should_stop(const Server::ServerState current,
                                  const Server::ServerState stop) {
  static_assert(sizeof(Server::ServerState) == sizeof(uint8_t),
                "Error: Server::ServerState is no longer sizeof(uint8_t)");

  return static_cast<uint8_t>(current) >= static_cast<uint8_t>(stop);
}

static bool read_transcript_data(TLSSocket &socket,
                                 bssl::Array<uint8_t> &buffer,
                                 std::vector<uint8_t> &transcript,
                                 const Messaging::MessageHeaders target_header,
                                 Server &server) noexcept {
  // First of all we need to read whatever header we have. We can also read the
  // size too.
  Messaging::MessageHeaders header;
  uint64_t size;

  if (!read_single_header(socket, header) || header != target_header) {
    return false;
  }

  // If we're in the initial portion we also have two
  // extra 16 bit values to read, corresponding to the SSL version
  // and the cipher suite used. Read those in too, since they're used
  // for the hash.
  if (target_header == Messaging::MessageHeaders::TRANSCRIPT_INIT) {
    uint16_t version, cipher_suite;
    if (!read_single_u16(socket, version) ||
        !read_single_u16(socket, cipher_suite)) {
      return false;
    }
    server.set_version(version);
    server.set_cipher_suite(cipher_suite);
  }

  // Now we can read the size.
  if (!read_single_u64(socket, size)) {
    return false;
  }

  if (target_header == Messaging::MessageHeaders::CERTIFICATE_CTX_RECV) {
    // There should be `size` many bytes that are committed to and an additional
    // 32 bytes for the key if we're in the Certificate RECV stage.
    constexpr auto hash_size = 32;
    if (socket.pending() != static_cast<int>(size + hash_size)) {
      return false;
    }
    // Make sure we read those extra bytes in too.
    size += hash_size;
  }

  // Reserve the size up.
  transcript.reserve(transcript.size() + size);

  do {
    const auto read =
        socket.read(buffer.data(), static_cast<int>(buffer.size()));
    if (read <= 0) {
      // We failed to read.
      return false;
    }

    // The buffer is already at the right size, so this will not cause
    // allocations.
    transcript.insert(transcript.end(), buffer.begin(), buffer.begin() + read);
  } while (socket.pending() != 0);

  return true;
}

bool Server::do_cert_wait() noexcept {
  // A resumed origin handshake carries no server Certificate, so the prover
  // forwards none: skip the read to stay in lock-step. (Mode learnt in
  // write_ks_done.)
  if (this->resumed_handshake) {
    this->state = next_state(this->state);
    return true;
  }
  TIME(Events::State::CERT_WAIT);
  // Here we just read the transcript message from the other party and
  // then reveal our secrets to them.
  if (!read_transcript_data(socket, buffer, transcript,
                            Messaging::MessageHeaders::CERTIFICATE_CTX_SEND,
                            *this)) {
    PRINT_IF_LOUD("Failed to read data in do_cert_wait");
    return false;
  }

  constexpr auto hash_size = 32;
  static_assert(sizeof(server_key_comm) == sizeof(uint8_t) * hash_size,
                "Error: mismatched hash size!");
  // The last hash_size bytes should be a commitment to the key, so we extract
  // those separately. N.B This check should be impossible if the other party is
  // playing honestly.
  if (transcript.size() < hash_size) {
    PRINT_IF_LOUD("Transcript size too small in do_cert_wait");
    return false;
  }

  memcpy(server_key_comm.data(),
         transcript.data() + transcript.size() - hash_size,
         sizeof(server_key_comm));

  TRACK_ROUNDS_IF_INTERESTED(Events::State::CERT_WAIT, 1);
  TRACK_IF_INTERESTED(Events::State::CERT_WAIT,
                      sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) +
                          transcript.size());

  transcript.resize(transcript.size() - hash_size);

  // Now we can just move on.
  this->state = next_state(this->state);
  return true;
}

// Signal we received the certificate
bool Server::write_cert_recv() noexcept {
  TIME(Events::State::CERT_WRITE);
  // We write out a single header followed by the SHTS and CHTS.
  // Note that we've already recovered the value of fk_s and the other secets,
  // which we'll check before we derive the traffic secrets.
  bssl::Array<uint8_t> out_arr;
  const auto size = sizeof(Messaging::MessageHeaders) +
                    handshake_key_shares.SHTS_share.size() +
                    handshake_key_shares.CHTS_share.size();

  if (!out_arr.Init(size)) {
    PRINT_IF_LOUD("Failed to create buffer in write_cert_recv");
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(
                      Messaging::MessageHeaders::CERTIFICATE_CTX_RECV)) ||
      !CBB_add_bytes(cbb.get(), handshake_key_shares.CHTS_share.data(),
                     handshake_key_shares.CHTS_share.size()) ||
      !CBB_add_bytes(cbb.get(), handshake_key_shares.SHTS_share.data(),
                     handshake_key_shares.SHTS_share.size()) ||
      !CBBFinishArray(cbb.get(), &out_arr)) {
    PRINT_IF_LOUD("Failed to serialise into buffer in write_cert_recv");
    return false;
  }

  // Write it.
  if (!socket.write(out_arr.data(), out_arr.size())) {
    PRINT_IF_LOUD("Failed to write shares in write_cert_recv");
    return false;
  }

  TRACK_ROUNDS_IF_INTERESTED(Events::State::CERT_WRITE, 1);
  TRACK_IF_INTERESTED(Events::State::CERT_WRITE, size);
  this->state = next_state(this->state);
  return true;
}

// Derive handshake keys
bool Server::do_ks() noexcept {
  // We just call into the circuit routine directly here: there's no need to
  // update anything.
  TIME(Events::State::KS_WAIT);

  // With that updated, we can actually run the key derivation circuit.
  // The key derivation circuit only requires _us_ to provide the input mask,
  // which is generated inside the circuit calling function.
  EmpWrapperAG2PCConstants::HandshakeCircuitIn input{};

  // Populate the input.
  if (!input.key_share.CopyFrom(x_secret)) {
    PRINT_IF_LOUD("Failed to copy key share in do_ks");
    return false;
  }
  input.psk_share = this->resumed_handshake
                        ? psk_shares.PSK_share
                        : decltype(psk_shares.PSK_share){};

  [[maybe_unused]] const auto old_amount =
      handshake_circuits[active_key_share]->get_counter();
  [[maybe_unused]] const auto old_rounds =
      handshake_circuits[active_key_share]->get_round_counter();

  {
    // KS_CIRCUIT covers only the circuit evaluation. KS_WAIT (the enclosing
    // scope) additionally includes the time the verifier spends parked here
    // waiting for the prover, which depends on how quickly the origin
    // completes its handshake. Use KS_CIRCUIT for the circuit cost and
    // KS_WAIT - KS_CIRCUIT for the wait, as with DERIVE_TS / DERIVE_TS_WAIT.
    TIME(Events::State::KS_CIRCUIT);
    if (!ThreePartyHandshake::run_handshake_circuit(
            input, handshake_key_shares,
            handshake_circuits[active_key_share].get(), true)) {
      PRINT_IF_LOUD("Failed to run handshake circuit in do_ks");
      return false;
    }
  }

  TRACK_IF_INTERESTED(
      Events::State::KS_CIRCUIT,
      handshake_circuits[active_key_share]->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(
      Events::State::KS_CIRCUIT,
      handshake_circuits[active_key_share]->get_round_counter() - old_rounds);

  // Free old memory. This can be substantial.
  handshake_circuits[active_key_share].reset(nullptr);
  this->state = next_state(this->state);
  return true;
}

// We are done deriving handshake keys
bool Server::write_ks_done() noexcept {
  TIME(Events::State::KS_DONE);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::KS_DONE, 1);
  TRACK_IF_INTERESTED(Events::State::KS_DONE,
                      sizeof(Messaging::MessageHeaders));
  // We'll just write a single header.
  if (!write_single_header(socket, Messaging::MessageHeaders::KS_DONE)) {
    PRINT_IF_LOUD("Failed to write ks_done in write_ks_done");
    return false;
  }

  // We're done with the KS!
  this->state = next_state(this->state);
  return true;
}

// Derive traffic keys
bool Server::derive_ts() noexcept {
  TIME(Events::State::DERIVE_TS_WAIT);

  // The first thing to do is to read the header from the other party.
  // This is just a single byte to indicate that they want to derive
  // traffic secrets.
  Messaging::MessageHeaders header;
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::DERIVE_TS) {
    PRINT_IF_LOUD("Failed to read derive_ts header in derive_ts");
    return false;
  }

  TIME(Events::State::DERIVE_TS);
  // Now we just call into the joint derivation circuit with the relevant
  // information.
  EmpWrapperAG2PCConstants::TrafficCircuitIn input{};
  input.ms_share = handshake_key_shares.MS_share;

  [[maybe_unused]] const auto old_amount = traffic_circuit->get_counter();
  [[maybe_unused]] const auto old_rounds =
      traffic_circuit->get_round_counter();

  // Call into the traffic secrets circuit. The hardcoded "true" means "we are
  // the verifier".
  if (!ThreePartyHandshake::run_traffic_circuit(input, traffic_key_shares,
                                                traffic_circuit.get(), true)) {
    PRINT_IF_LOUD("Failed to run traffic secret circuit in derive_ts");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::DERIVE_TS,
                      traffic_circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::DERIVE_TS,
                             traffic_circuit->get_round_counter() - old_rounds);

  // The shares we need are actually written directly into storage, so we don't
  // need to unpack here (i.e we can just move on to the next state).
  this->state = next_state(this->state);
  return true;
}

bool Server::read_header_draining_encryption(
    Messaging::MessageHeaders &out) noexcept {
  for (;;) {
    if (!read_single_header(socket, out)) {
      PRINT_IF_LOUD("read_single_header failed inside encryption drain");
      return false;
    }
    if (out == Messaging::MessageHeaders::AES_ENC) {
      if (!encrypt_blocks()) {
        PRINT_IF_LOUD("Failed to encrypt blocks");
        return false;
      }
      continue;
    }
    if (out == Messaging::MessageHeaders::GCM_TAG) {
      if (!make_gcm_tag()) {
        PRINT_IF_LOUD("Failed to make gcm tag");
        return false;
      }
      continue;
    }

    if (out == Messaging::MessageHeaders::GCM_VERIFY) {
      if (!verify_gcm_tag()) {
        PRINT_IF_LOUD("Failed to verify gcm tag");
        return false;
      }
      continue;
    }
    if (out == Messaging::MessageHeaders::KS_DERIVE) {
      if (!derive_keystream_blocks()) {
        PRINT_IF_LOUD("Failed to derive keystream blocks");
        return false;
      }
      continue;
    }

    // SURF TRUE mode. All of its traffic lands here: the prover runs the whole
    // attestation after its read loop drains, which is while this party is
    // parked in derive_psk waiting for the PSK header. KEY_COMMIT precedes the
    // first GCM_VERIFY; KEY_RELEASE follows the last one. Both must be drained
    // rather than returned, or they would be misread as the PSK header.
    if (out == Messaging::MessageHeaders::KEY_COMMIT) {
      if (!read_key_commitment()) {
        PRINT_IF_LOUD("Failed to read key commitment");
        return false;
      }
      continue;
    }
    if (out == Messaging::MessageHeaders::KEY_RELEASE) {
      if (!release_key()) {
        PRINT_IF_LOUD("Failed to release key");
        return false;
      }
      continue;
    }

    if (out == Messaging::MessageHeaders::ROTATE_KEY) {
      if (!rotate_key_op()) {
        PRINT_IF_LOUD("Failed to rotate key");
        return false;
      }
      continue;
    }

    return true;
  }
}

bool Server::derive_psk() noexcept {
  // Reset per run: only the PSK_SKIP branch below sets this true, and a later
  // PSK-present run must not inherit a stale skip from an earlier run.
  this->psk_skipped = false;

  // The first thing to do is to read the header from the other party.
  // This is just a single byte: DERIVE_PSK (the prover derived a PSK and wants
  // to run the joint circuit) or PSK_SKIP (the resumed origin produced no
  // NewSessionTicket in time, derive_psk_keys never fired, no PSK exists).
  //
  // This read blocks until the prover sends the header, which only happens once
  // its origin connection yields a NewSessionTicket. That wait (which balloons
  // on later resumptions when the origin is slow to issue a fresh ticket) is
  // timed separately as DERIVE_PSK_WAIT so it doesn't inflate DERIVE_PSK, which
  // should reflect only the MPC circuit cost.
  Messaging::MessageHeaders header;
  {
    // NOTE: AES_ENCRYPT / GCM_TAG time is nested inside DERIVE_PSK_WAIT here,
    // since the encryption rounds happen while we are blocked waiting for the
    // PSK header. Subtract them to recover the true PSK wait.
    TIME(Events::State::DERIVE_PSK_WAIT);
    if (!read_header_draining_encryption(header)) {
      PRINT_IF_LOUD("Failed to read derive_psk header in derive_psk");
      return false;
    }
  }
  TIME(Events::State::DERIVE_PSK);

  // PSK_SKIP: no PSK to derive. Skip the circuit and the remaining PSK states
  // (PSK_DONE) so we stay in lock-step
  // instead of blocking on a circuit run / reveal the prover never drives.
  if (header == Messaging::MessageHeaders::PSK_SKIP) {
    PRINT_IF_LOUD("PSK skipped: prover sent PSK_SKIP (no NewSessionTicket)");
    this->psk_skipped = true;
    this->state = next_state(this->state);
    return true;
  }

  // The prover signals the origin's ticket_nonce width via the header: it ran
  // the 1-byte circuit (DERIVE_PSK) or the 8-byte one (DERIVE_PSK_8). We must
  // run the matching circuit so the MPC stays in lock-step. The verifier holds
  // no nonce (it feeds zeros), so only the circuit/input-type differs by width.
  const bool use_8 = (header == Messaging::MessageHeaders::DERIVE_PSK_8);
  const bool use_0 = (header == Messaging::MessageHeaders::DERIVE_PSK_0);

  if (header != Messaging::MessageHeaders::DERIVE_PSK && !use_8 && !use_0) {
    PRINT_IF_LOUD("Unexpected header in derive_psk (want DERIVE_PSK, "
                  "DERIVE_PSK_8 or PSK_SKIP)");
    return false;
  }

  EmpWrapperAG2PC *const circuit =
      use_0 ? psk_circuit_0.get() : (use_8 ? psk_circuit_8.get()
                                           : psk_circuit.get());
  if (!circuit) {
    PRINT_IF_LOUD("PSK circuit for requested nonce width is null");
    return false;
  }

  [[maybe_unused]] const auto old_amount = circuit->get_counter();
  [[maybe_unused]] const auto old_rounds = circuit->get_round_counter();

  // Call into the joint derivation circuit. The hardcoded "true" means "we are
  // the verifier".
  bool ok;
  if (use_0) {
    EmpWrapperAG2PCConstants::PskCircuitIn0 input{};
    input.rms_share = resumption_shares.RMS_share;
    ok = ThreePartyHandshake::run_psk_circuit_0(input, psk_shares, circuit, true);
  } else if (use_8) {
    EmpWrapperAG2PCConstants::PskCircuitIn8 input{};
    input.rms_share = resumption_shares.RMS_share;
    ok = ThreePartyHandshake::run_psk_circuit_8(input, psk_shares, circuit,
                                                true);
  } else {
    EmpWrapperAG2PCConstants::PskCircuitIn input{};
    input.rms_share = resumption_shares.RMS_share;
    ok = ThreePartyHandshake::run_psk_circuit(input, psk_shares, circuit, true);
  }
  if (!ok) {
    PRINT_IF_LOUD("Failed to run psk circuit in derive_psk");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::DERIVE_PSK,
                      circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(Events::State::DERIVE_PSK,
                             circuit->get_round_counter() - old_rounds);

  // The shares we need are actually written directly into storage, so we don't
  // need to unpack here (i.e we can just move on to the next state).
  this->state = next_state(this->state);
  return true;
}

bool Server::write_completed_psk() noexcept {
  // No PSK was derived this run (prover sent PSK_SKIP): skip the PSK_DONE the
  // prover never reads.
  if (this->psk_skipped) {
    PRINT_IF_LOUD("PSK skipped: no PSK_DONE to send");
    this->state = next_state(this->state);
    return true;
  }
  if (!write_single_header(socket, Messaging::MessageHeaders::PSK_DONE)) {
    PRINT_IF_LOUD(
        "Failed to write PSK_DONE in write_completed_psk");
    return false;
  }
  this->state = next_state(this->state);
  return true;
}

bool Server::shutdown() noexcept {
  SSL_shutdown(socket.get_ssl_object());
  this->state = ServerState::DONE;
  return true;
}

bool Server::derive_gcm_shares() noexcept {
  TIME(Events::State::DERIVE_GCM_SHARES);
  // In this state we wait for the prover to issue the write to
  // us and then go from there.
  Messaging::MessageHeaders header;
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::GCM_SHARE_START) {
    PRINT_IF_LOUD("Failed to read GCM_SHARE_START in derive_gcm_shares");
    return false;
  }

  // Call into the GCM derivation functions. The main bulk of the work is
  // actually handled in the 3PH routine, which also derives all of the relevant
  // circuitry code too.
  // As before, the bulk of the storage for this function is stored in the class
  // itself.
  PRINT_IF_LOUD("Calling into derivation circuit");
  uint64_t bandwidth;
  [[maybe_unused]] const auto old_rounds = gcm_circuit->get_round_counter();
  if (!ThreePartyHandshake::make_gcm_shares(
          socket.get_ssl_object(), traffic_key_shares.client_key_share,
          traffic_key_shares.server_key_share, gcm_circuit.get(),
          client_gcm_powers, server_gcm_powers, &bandwidth)) {
    PRINT_IF_LOUD("Failed to make gcm shares in derive_gcm_shares");
    return false;
  }
  TRACK_ROUNDS_IF_INTERESTED(Events::State::DERIVE_GCM_SHARES,
                             gcm_circuit->get_round_counter() - old_rounds);

  TRACK_IF_INTERESTED(Events::State::DERIVE_GCM_SHARES, bandwidth);

  // Move on to the next state.
  this->state = next_state(this->state);
  return true;
}

bool Server::write_completed_derivation() noexcept {
  if (!write_single_header(socket, Messaging::MessageHeaders::GCM_SHARE_DONE)) {
    PRINT_IF_LOUD(
        "Failed to write GCM_SHARE_DONE in write_completed_derivation");
    return false;
  }
  this->state = next_state(this->state);
  return true;
}

// This needs to be separate from the traffic ones
bool Server::derive_res() noexcept {
  TIME(Events::State::DERIVE_RES);

  // The first thing to do is to read the header from the other party.
  // This is just a single byte to indicate that they want to derive
  // res secrets.
  Messaging::MessageHeaders header;
  if (!read_single_header(socket, header) ||
      header != Messaging::MessageHeaders::DERIVE_RES) {
    PRINT_IF_LOUD("Failed to read derive_res header in derive_res");
    return false;
  }

  // We just call into the joint derivation circuit with the relevant
  // information.
  EmpWrapperAG2PCConstants::ResumptionCircuitIn input{};
  input.ms_share = handshake_key_shares.MS_share; // no ticket here

  [[maybe_unused]] const auto old_amount = resumption_circuit->get_counter();
  [[maybe_unused]] const auto old_rounds =
      resumption_circuit->get_round_counter();

  // Call into the traffic secrets circuit. The hardcoded "true" means "we are
  // the verifier".
  if (!ThreePartyHandshake::run_resumption_circuit(input, resumption_shares,
                                                resumption_circuit.get(), true)) {
    PRINT_IF_LOUD("Failed to run resumption circuit in derive_rms");
    return false;
  }

  TRACK_IF_INTERESTED(Events::State::DERIVE_RES,
                      resumption_circuit->get_counter() - old_amount);
  TRACK_ROUNDS_IF_INTERESTED(
      Events::State::DERIVE_RES,
      resumption_circuit->get_round_counter() - old_rounds);

  // The shares we need are actually written directly into storage, so we don't
  // need to unpack here (i.e we can just move on to the next state).
  this->state = next_state(this->state);
  return true;
}

bool Server::write_completed_res() noexcept {
  if (!write_single_header(socket, Messaging::MessageHeaders::RES_DONE)) {
    PRINT_IF_LOUD(
        "Failed to write RES_DONE in write_completed_derivation");
    return false;
  }
  this->state = next_state(this->state);
  return true;
}

bool Server::attest() noexcept {
  Messaging::MessageHeaders header;
  bool worked = true;
  while (worked) {
    // Read the single header in from the other party.
    if (!read_single_header(socket, header)) {
      return false;
    }

    switch (header) {
    case Messaging::MessageHeaders::STOP:
      return true;
    case Messaging::MessageHeaders::AES_ENC:
      worked = encrypt_blocks();
      break;
    case Messaging::MessageHeaders::GCM_TAG:
      worked = make_gcm_tag();
      break;
    case Messaging::MessageHeaders::GCM_VERIFY:
      worked = verify_gcm_tag();
      break;
    case Messaging::MessageHeaders::KS_DERIVE:
      worked = derive_keystream_blocks();
      break;
    // SURF TRUE mode, for a prover that releases after PSK derivation rather
    // than before it. The normal path drains these in
    // read_header_draining_encryption; these cases keep the shutdown path
    // working too.
    case Messaging::MessageHeaders::KEY_COMMIT:
      worked = read_key_commitment();
      break;
    case Messaging::MessageHeaders::KEY_RELEASE:
      worked = release_key();
      break;
    case Messaging::MessageHeaders::ROTATE_KEY:
      worked = rotate_key_op();
      break;
    default:
      worked = false;
      break;
    }
  }
  return worked;
}

void Server::reset_per_connection_state() noexcept {
  this->timer = Timer::TimerType{};
  this->bandwidth_tracker = BandwidthTracker::TrackerType{};
  this->round_tracker = RoundTracker::TrackerType{};
  this->encrypted_seqs.clear();
  this->encrypted_ct.clear();
  this->encrypt_ct_len = 0;
  this->verified_seqs.clear();
  this->key_committed = false;
  this->key_released = false;
  this->key_commitment.fill(0);
  this->attested_ct.clear();
  this->epoch = 0;
}

Server::SessionKind Server::accept_and_read_mode(const bool print) noexcept {
  // Front half shared by run()/run_resumption(): accept a prover, complete the
  // prover<->verifier handshake, then read the 1-byte run-type tag the prover
  // sends right after it reads DONE_HS (before any preprocessing). The tag tells
  // us which state machine to walk, so the verifier no longer has to infer
  // full-vs-resumed from the accept() timeout.
  this->loud = print;

  // Reset per-connection state here (not in the run()/run_resumption()
  // continuation, which we enter with already_accepted=true) so ACCEPT and
  // HANDSHAKE timings are captured in the same run as the rest.
  reset_per_connection_state();

  this->state = ServerState::ACCEPT;
  PRINT_IF_LOUD("Accepting");
  if (!accept()) {
    // accept() timed out: no prover is connecting right now.
    return SessionKind::Idle;
  }
  PRINT_IF_LOUD("Doing handshake");
  if (!do_handshake()) {
    return SessionKind::Idle;
  }
  // In the bench flow the prover sends nothing until it has read DONE_HS, so
  // do_handshake() always takes the no-pending branch and parks us at
  // HANDSHAKE_DONE. Write DONE_HS now; this advances the state to
  // CIRCUIT_PREPROC, the continuation entry point.
  if (this->state != ServerState::HANDSHAKE_DONE) {
    PRINT_IF_LOUD("Unexpected state after handshake in accept_and_read_mode");
    return SessionKind::Idle;
  }
  PRINT_IF_LOUD("Finished handshake");
  if (!write_handshake_done()) {
    return SessionKind::Idle;
  }

  // The prover has now received DONE_HS and sent its run-type tag.
  Messaging::MessageHeaders mode;
  if (!read_single_header(socket, mode) ||
      (mode != Messaging::MessageHeaders::RUN_FULL &&
       mode != Messaging::MessageHeaders::RUN_RESUMED)) {
    PRINT_IF_LOUD("Failed to read run-type tag in accept_and_read_mode");
    return SessionKind::Idle;
  }
  return (mode == Messaging::MessageHeaders::RUN_RESUMED) ? SessionKind::Resumed
                                                          : SessionKind::Full;
}

bool Server::run(const ServerState stop_state, const bool print,
                 const bool should_preproc, const bool already_accepted) {
  /*
     This is a standard intepreter loop for dispatching into functions
     dependent on state. This only works because the server is a single
     connection entity.

     The way this loop works is as follows. We store all state (e.g all read
     variables) as member variables in this server. We then (in an ideal
     situation) walk through the switch in order: we first accept, then
     handshake... If we fail at any step we return an error to the
     caller. We'll also write an error to the connecting client if there's an
     actionable error: for example, if the key share that was sent to us isn't
     what we expected, or if some error occurs.
  */

  // Reset the state. When already_accepted, accept_and_read_mode() has already
  // walked ACCEPT..HANDSHAKE_DONE (leaving us at CIRCUIT_PREPROC) and reset the
  // timer/bandwidth tracker, so we must not clobber that here.
  if (!already_accepted) {
    this->state = ServerState::ACCEPT;
    this->loud = print;
    // Reset per-run stats so each call is self-contained (matches
    // run_resumption()); otherwise the timer accumulates across provers.
    reset_per_connection_state();
  }

  this->is_resumption_run = false;

  bool was_successful;
  while (!should_stop(this->state, stop_state)) {
    switch (this->state) {
    case ServerState::ACCEPT:
      PRINT_IF_LOUD("Accepting");
      was_successful = accept();
      break;
    case ServerState::HANDSHAKE:
      PRINT_IF_LOUD("Doing handshake");
      was_successful = do_handshake();
      break;
    case ServerState::HANDSHAKE_DONE:
      PRINT_IF_LOUD("Finished handshake");
      was_successful = write_handshake_done();
      break;
    case ServerState::READING_KS:
      PRINT_IF_LOUD("Reading key share");
      was_successful = read_keyshare_after_handshake();
      break;
    case ServerState::MAKING_KS:
      PRINT_IF_LOUD("Creating key share");
      was_successful = create_new_share();
      break;
    case ServerState::CIRCUIT_PREPROC:
      PRINT_IF_LOUD("Preprocessing circuits");
      was_successful = do_preproc(should_preproc);
      break;
    case ServerState::MASK_COMMIT:
      PRINT_IF_LOUD("Reading mask commitments");
      was_successful = read_mask_commitments();
      break;
    case ServerState::WRITING_KS:
      PRINT_IF_LOUD("Writing key share");
      was_successful = send_additive_share();
      break;
    case ServerState::PSK_BINDER:
      PRINT_IF_LOUD("Deriving PSK binder");
      was_successful = do_psk_binder();
      break;
    case ServerState::READING_SKS:
      PRINT_IF_LOUD("Reading server key share");
      was_successful = read_sks_keyshare();
      break;
    case ServerState::FINISHING_TPH:
      PRINT_IF_LOUD("Finishing 3PH");
      was_successful = finish_tph();
      break;
    case ServerState::WRITING_HS_RECV:
      PRINT_IF_LOUD("Writing HS_RECV");
      was_successful = write_hs_recv();
      break;
    case ServerState::ECTF_WAIT:
      PRINT_IF_LOUD("Doing ectf");
      was_successful = do_ectf();
      break;
    case ServerState::ECTF_DONE:
      PRINT_IF_LOUD("Finished ectf");
      was_successful = finish_ectf();
      break;
    case ServerState::KS_WAIT:
      PRINT_IF_LOUD("Doing HS derivation");
      was_successful = do_ks();
      break;
    case ServerState::KS_DONE:
      PRINT_IF_LOUD("Finished HS derivation");
      was_successful = write_ks_done();
      break;
    case ServerState::CERT_WAIT:
      PRINT_IF_LOUD("Reading cert");
      was_successful = do_cert_wait();
      break;
    case ServerState::CERT_RECV:
      PRINT_IF_LOUD("Read cert");
      was_successful = write_cert_recv();
      break;
    case ServerState::DERIVE_TS:
      PRINT_IF_LOUD("Deriving TS");
      was_successful = derive_ts();
      break;
    case ServerState::GCM_SHARE_DERIVE:
      PRINT_IF_LOUD("Deriving GCM shares");
      was_successful = derive_gcm_shares();
      break;
    case ServerState::GCM_SHARE_DONE:
      PRINT_IF_LOUD("Derived GCM shares");
      was_successful = write_completed_derivation();
      break;
    case ServerState::DERIVE_RES:
      PRINT_IF_LOUD("Deriving resumption");
      was_successful = derive_res();
      break;
    case ServerState::RES_DONE:
      PRINT_IF_LOUD("Derived resumption");
      was_successful = write_completed_res();
      break;
    case ServerState::DERIVE_PSK:
      PRINT_IF_LOUD("Deriving psk");
      was_successful = derive_psk();
      break;
    case ServerState::PSK_DONE:
      PRINT_IF_LOUD("Derived psk");
      was_successful = write_completed_psk();
      break;
    case ServerState::SHUTDOWN:
      PRINT_IF_LOUD("Shutting down");
      if (should_attest) {
        was_successful = attest();
        if (!was_successful) break;
      }
      was_successful = shutdown();
      break;
    default:
      // We terminate here, because this implies a logic error on our
      // part.
      // Note: in a release build we could make this an unreachable.
      cout << "SERVER STATE " << static_cast<int>(this->state) << std::endl;
      std::abort();
    }

    if (!was_successful) {
      break;
    }
  }

  // Skip the summary when accept() timed out: no prover connected within the
  // window, so the state never advanced past ACCEPT and the timings are empty.
  if (print && this->state != ServerState::ACCEPT) {
    std::cerr << "TIMINGS:" << std::endl;
    timer.print();
    std::cerr << "DATA:" << std::endl;
    bandwidth_tracker.print();
    round_tracker.print();
  }

  return was_successful;
}

bool Server::run_resumption(const ServerState stop_state, const bool print,
                            const bool should_preproc,
                            const bool already_accepted) {
  // Verifier-side MPC for a PSK-resumption handshake. Same dispatch as run(),
  // walking a prescribed state list that omits CERT_WAIT/CERT_RECV (resumed
  // handshakes carry no server Certificate). The circuits were consumed by
  // the first run; CIRCUIT_PREPROC here rebuilds them fresh.
  static const ServerState kResumptionStates[] = {
      ServerState::ACCEPT,           ServerState::HANDSHAKE,
      ServerState::HANDSHAKE_DONE,   ServerState::CIRCUIT_PREPROC,
      ServerState::MASK_COMMIT,
      ServerState::READING_KS,       ServerState::MAKING_KS,
      ServerState::WRITING_KS,       Server::ServerState::PSK_BINDER,
      ServerState::READING_SKS,
      ServerState::FINISHING_TPH,    ServerState::WRITING_HS_RECV,
      ServerState::ECTF_WAIT,        ServerState::ECTF_DONE,
      ServerState::KS_WAIT,          ServerState::KS_DONE,
      ServerState::CERT_WAIT,        ServerState::CERT_RECV,
      ServerState::DERIVE_TS,        ServerState::GCM_SHARE_DERIVE,
      ServerState::GCM_SHARE_DONE,   ServerState::DERIVE_RES,
      ServerState::RES_DONE,         ServerState::DERIVE_PSK,
      ServerState::PSK_DONE,
      ServerState::SHUTDOWN,
  };

  // When already_accepted, accept_and_read_mode() walked ACCEPT..HANDSHAKE_DONE
  // and reset the timer/bandwidth tracker, so we skip the first three states
  // (ACCEPT, HANDSHAKE, HANDSHAKE_DONE) and leave the stats intact.
  constexpr size_t kPreambleStates = 3;
  if (!already_accepted) {
    this->loud = print;
    // Reset per-run stats so the resumption report isn't cumulative with run().
    reset_per_connection_state();
  }

  // Free the previous run's circuits before rebuilding, so preprocessing does
  // not run with ~780 MiB of the prior round still resident.
  for (auto &c : handshake_circuits) c.reset(nullptr);
  traffic_circuit.reset(nullptr);
  gcm_circuit.reset(nullptr);
  resumption_circuit.reset(nullptr);
  psk_circuit.reset(nullptr);
  psk_circuit_8.reset(nullptr);
  psk_circuit_0.reset(nullptr);
  binder_circuit.reset(nullptr);
  gcm_vfy_circuit.reset(nullptr);
  ks_block_circuit.reset(nullptr);
  aes_enc_circuit.reset(nullptr);
  gcm_tag_circuit.reset(nullptr);
  rotate_circuit.reset(nullptr);

  this->is_resumption_run = true;
  bool was_successful = true;

  const size_t start_index = already_accepted ? kPreambleStates : 0;
  for (size_t idx = start_index;
       idx < sizeof(kResumptionStates) / sizeof(kResumptionStates[0]); ++idx) {
    const ServerState s = kResumptionStates[idx];
    if (should_stop(s, stop_state)) {
      break;
    }
    this->state = s;

    switch (s) {
    case ServerState::ACCEPT:
      PRINT_IF_LOUD("Accepting (resumption)");
      was_successful = accept();
      break;
    case ServerState::HANDSHAKE:
      PRINT_IF_LOUD("Doing handshake (resumption)");
      was_successful = do_handshake();
      break;
    case ServerState::HANDSHAKE_DONE:
      PRINT_IF_LOUD("Finished handshake (resumption)");
      was_successful = write_handshake_done();
      break;
    case ServerState::READING_KS:
      PRINT_IF_LOUD("Reading key share");
      was_successful = read_keyshare_after_handshake();
      break;
    case ServerState::MAKING_KS:
      PRINT_IF_LOUD("Creating key share");
      was_successful = create_new_share();
      break;
    case ServerState::CIRCUIT_PREPROC:
      PRINT_IF_LOUD("Preprocessing circuits (resumption)");
      was_successful = do_preproc(should_preproc);
      break;
    case ServerState::MASK_COMMIT:
      PRINT_IF_LOUD("Reading mask commitments (resumption)");
      was_successful = read_mask_commitments();
      break;
    case ServerState::WRITING_KS:
      PRINT_IF_LOUD("Writing key share");
      was_successful = send_additive_share();
      break;
    case ServerState::PSK_BINDER:
      PRINT_IF_LOUD("Deriving PSK binder");
      was_successful = do_psk_binder();
      break;
    case ServerState::READING_SKS:
      PRINT_IF_LOUD("Reading server key share");
      was_successful = read_sks_keyshare();
      break;
    case ServerState::FINISHING_TPH:
      PRINT_IF_LOUD("Finishing 3PH");
      was_successful = finish_tph();
      break;
    case ServerState::WRITING_HS_RECV:
      PRINT_IF_LOUD("Writing HS_RECV");
      was_successful = write_hs_recv();
      break;
    case ServerState::ECTF_WAIT:
      PRINT_IF_LOUD("Doing ectf");
      was_successful = do_ectf();
      break;
    case ServerState::ECTF_DONE:
      PRINT_IF_LOUD("Finished ectf");
      was_successful = finish_ectf();
      break;
    case ServerState::KS_WAIT:
      PRINT_IF_LOUD("Doing HS derivation");
      was_successful = do_ks();
      break;
    case ServerState::KS_DONE:
      PRINT_IF_LOUD("Finished HS derivation");
      was_successful = write_ks_done();
      break;
    case ServerState::CERT_WAIT:
      PRINT_IF_LOUD("Reading cert (resumption)");
      was_successful = do_cert_wait();
      break;
    case ServerState::CERT_RECV:
      PRINT_IF_LOUD("Writing shares (resumption)");
      was_successful = write_cert_recv();
      break;
    case ServerState::DERIVE_TS:
      PRINT_IF_LOUD("Deriving TS");
      was_successful = derive_ts();
      break;
    case ServerState::GCM_SHARE_DERIVE:
      PRINT_IF_LOUD("Deriving GCM shares");
      was_successful = derive_gcm_shares();
      break;
    case ServerState::GCM_SHARE_DONE:
      PRINT_IF_LOUD("Derived GCM shares");
      was_successful = write_completed_derivation();
      break;
    case ServerState::DERIVE_RES:
      PRINT_IF_LOUD("Deriving resumption");
      was_successful = derive_res();
      break;
    case ServerState::RES_DONE:
      PRINT_IF_LOUD("Derived resumption");
      was_successful = write_completed_res();
      break;
    case ServerState::DERIVE_PSK:
      PRINT_IF_LOUD("Deriving psk");
      was_successful = derive_psk();
      break;
    case ServerState::PSK_DONE:
      PRINT_IF_LOUD("Derived psk");
      was_successful = write_completed_psk();
      break;
    case ServerState::SHUTDOWN:
      PRINT_IF_LOUD("Shutting down");
      if (should_attest) {
        was_successful = attest();
        if (!was_successful) break;
      }
      was_successful = shutdown();
      break;
    default:
      cout << "SERVER STATE (resumption) " << static_cast<int>(s) << std::endl;
      std::abort();
    }

    if (!was_successful) {
      break;
    }
  }

  // Skip the summary when accept() timed out (state never left ACCEPT): the
  // prover ended its session, so there are no resumption timings to report.
  if (print && this->state != ServerState::ACCEPT) {
    std::cerr << "TIMINGS (resumption):" << std::endl;
    timer.print();
    std::cerr << "DATA (resumption):" << std::endl;
    bandwidth_tracker.print();
    round_tracker.print();
  }

  return was_successful;
}

SSL_CTX *Server::get_ctx() noexcept { return ssl_ctx.get(); }
const bssl::Array<uint8_t> &Server::get_x_secret() const noexcept {
  return x_secret;
}

void Server::set_attestation() noexcept { should_attest = true; }

#undef TRACK_IF_INTERESTED
#undef TRACK_ROUNDS_IF_INTERESTED
#undef TIME
#undef MACRO_CONCAT
#undef CONCAT_IMPL
#undef PRINT_IF_LOUD