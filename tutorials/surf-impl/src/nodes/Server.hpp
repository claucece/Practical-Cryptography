#ifndef INCLUDED_SERVER_HPP
#define INCLUDED_SERVER_HPP

#include "../mta/ectf.hpp"            // Needed for ECTF operations.
#include "../ssl/EmpWrapperAG2PC.hpp" // Needed for layout.
#include "../ssl/TLSSocket.hpp"       // Needed for TLS connections.
#include "BandwidthTracker.hpp"
#include "KeyShare.hpp" // Needed for key share work.
#include "RoundTracker.hpp"
#include "Timer.hpp"
#include "../ssl/Messaging.hpp"

/**
   Server. This class contains a server object. This is meant to represent a
server in the TLS attestation protocol.

Please note that this class contains some untested methods. This is primarily
for situations where providing open tests would break this class' encapsulation.
These methods are primarily wrappers around functions that the socket provides:
as a result, these functions are (by proxy) tested in the socket's test suite.
**/

class Server {
public:
  enum class ServerState : uint8_t {
    /**
       ACCEPT. The server is waiting for an incoming connection.
       Next action here is to accept a new connection.
    **/
    ACCEPT = 0,
    /**
       HANDSHAKE. The server has accepted a connection. The next step
       is to handshake with the new connection.
    **/
    HANDSHAKE = 1,
    /**
       HANDSHAKE_DONE. The server has done the handshake. We now need to tell
    the client that it worked.
    **/
    HANDSHAKE_DONE = 2,
    /**
       CIRCUIT_PREPROC. The server has done the handshake. The next step is to
       run circuit preprocessing, if applicable. This runs before the key-share
       exchange so the slow garbled-circuit preprocessing (the offline phase)
       happens before the prover opens its connection to the origin server.
    **/
    CIRCUIT_PREPROC = 3,

    MASK_COMMIT = 4,
    /**
       READING_KS. Circuit preprocessing is done. The next step is to read
       the key share.
    **/
    READING_KS = 5,
    /**
       MAKING_KS. The server has read the client's key share. The next step
       is to make a new one of our own.
    **/
    MAKING_KS = 6,

    /**
       WRITING_KS. The server has successfully made a key share. The next step
       is to write our own out.
    **/
    WRITING_KS = 7,

    PSK_BINDER = 8,

    /**
       READING_SKS. The server is now waiting for the client to send over the
    other parties' key share.
    **/
    READING_SKS = 9,

    /**
       FINISHING_TPH. The server has read the other parties' key share and is
       now processing it.
    **/
    FINISHING_TPH = 10,

    /**
       WRITING_HS_RECV. The server has read the other parties' key share and
     processed it. The server now writes a message saying it has done so.
     **/
    WRITING_HS_RECV = 11,

    /**
       ECTF_WAIT. The server has written the acknowledgement of receiving the
    key share and read the transcript. The server is now waiting to do the ECTF
    work.
    **/
    ECTF_WAIT = 12,

    /**
       ECTF_DONE. The server has finished the ECTF protocol. The server writes a
    message to the prover to mention that it has finished.
    **/
    ECTF_DONE = 13,

    /**
       KS_WAIT. The server is waiting for the updated transcript from the
    client.
    **/
    KS_WAIT = 14,

    /**
       KS_DONE. The server has advanced the key schedule. The server writes a
     message to the prover to mention that it has finished.
     **/
    KS_DONE = 15,

    /**
       CERT_WAIT. The server is waiting for the prover to commit to the
    certificate.
    **/
    CERT_WAIT = 16,

    CERT_RECV = 17,

    DERIVE_TS = 18,

    GCM_SHARE_DERIVE = 19,
    GCM_SHARE_DONE = 20,

    DERIVE_RES = 21,
    RES_DONE = 22,

    DERIVE_PSK = 23,
    PSK_DONE = 24,

    SHUTDOWN = 25,

    /**
       DONE. We're done.
    **/
    DONE = 26,

    /**
       SIZE. This is the number of elements in the enumeration.
    **/
    SIZE = 27,
  };

  /**
     Server. This constructor accepts an rvalue unique ptr to a SSL_CTX, an
  ip_address, a boolean denoting whether the address is an ip v4 address, and a
  backlog parameter, and builds `this` server.

     @snippet Server.t.cpp ServerConstructorTests
     @param[in] ctx: the SSL_CTX for `this` server.
     @param[in] ip_address: the ip_address to bind to.
     @param[in] is_ip_v6: true if the `ip_address` is ip_v6, false otherwise.
     @param[in] backlog: the number of backlogged connections to accept.
     @param[in] port: the port to bind to. If 0 (the default) the OS assigns an
  ephemeral port, which can then be retrieved via get_portnumber.
  **/
  Server(bssl::UniquePtr<SSL_CTX> &&ctx, const std::string &ip_address,
         const bool is_ip_v6, const int backlog,
         const uint16_t port = 0) noexcept;

  /**
     run. This function runs the Server's code. In particular, this function
     is responsible for doing a single handshake->generating key share run.
     If at any step this function fails, then this function will return `false`.
     Otherwise, this function will return `true`.

     @snippet Server.t.cpp ServerRunTests
     @param[in] stop_state: the state in which to stop the loop. Mostly
     only useful for testing.
     @param[in] print: true if the server should print stats, false otherwise.
  Only useful for testing.
     @param[in] should_preproc: true if the server should run circuit
  preprocessing, false otherwise. False is only useful during testing.
     @return true in case of success, false otherwise.
  **/
  bool run(const ServerState stop_state = ServerState::DONE,
           const bool print = false, const bool should_preproc = true,
           const bool already_accepted = false);

  /**
     run_resumption. Verifier-side MPC state machine for a TLS 1.3 PSK
     resumption handshake. Equivalent to run() but skips CERT_WAIT/CERT_RECV
     since a resumed handshake carries no server certificate. Circuits are
     rebuilt fresh (the first run consumed them).
  **/
  bool run_resumption(const ServerState stop_state = ServerState::DONE,
                      const bool print = false,
                      const bool should_preproc = true,
                      const bool already_accepted = false);

  /**
     SessionKind. The classification of an incoming MPC session, as declared by
     the prover's run-type tag (see accept_and_read_mode).
  **/
  enum class SessionKind { Idle, Full, Resumed };

  /**
     accept_and_read_mode. Accepts one prover connection, completes the
     prover<->verifier handshake (ACCEPT, HANDSHAKE, HANDSHAKE_DONE), and reads
     the 1-byte run-type tag the prover sends immediately afterwards. Resets the
     per-run timer/bandwidth tracker first (so a following run()/run_resumption()
     called with already_accepted=true must NOT reset again). On success the
     state is left at CIRCUIT_PREPROC, ready for that continuation.

     Returns SessionKind::Full or ::Resumed per the tag, or ::Idle when accept()
     times out (no prover) or the pre-tag handshake fails. This lets the verifier
     dispatch run() vs run_resumption() deterministically from the tag instead of
     inferring it from the accept() timeout.
     @param[in] print: true if the server should print stats / progress.
  **/
  SessionKind accept_and_read_mode(const bool print = false) noexcept;

  /**
     set_accept_timeout. Sets a timeout on accept() so that when no new
  connection arrives within |milliseconds|, accept() returns false and a
  run() loop exits naturally. Must be called after construction (listen() has
  already been called by the constructor). Returns false if setsockopt fails.
     @param[in] milliseconds: timeout in milliseconds.
     @return true in case of success, false otherwise.
  **/
  bool set_accept_timeout(int milliseconds) noexcept;

  /**
     create_new_public_key. This function accepts a `curve_id` corresponding
     to an elliptic curve and generates a new public key for `this` server
     using the curve. This function returns true on success and false otherwise.

     This function fails if:
     1) `curve_id` doesn't correspond to a valid elliptic curve.
     2) generating the public key somehow fails.

     This function does not throw.

     @snippet Server.t.cpp ServerCreatePublicKeyTests

     @param[in] curve_id: the identifier for the curve.
     @return true in case of success, false otherwise.
     @remarks At present we do not support the non-NIST curves. This may change
  in future.
  **/
  bool create_new_public_key(const uint16_t curve_id) noexcept;

  /**
     send_additive_share. This function serialises `this` socket's additive
  share across the TLSSocket. This function returns true on success and false on
  error. This function will return false if:
     1. Packing the key bytes fails.
     2. Writing the bytes fails.

     This function does not throw.
     @snippet Server.t.cpp ServerSendAdditiveShareTests
     @return true in case of success, false otherwise.
  **/
  bool send_additive_share();
  /**
     accept. This function accepts a new connection for `this` socket. This
   function returns true on success and false on an error.

     This function does not throw.
     @return true if a new connection succeeds, false otherwise.
   **/
  bool accept() noexcept;
  /**
     do_handshake. This function runs a SSL handshake between `this` socket and
  a new connection. This function returns true on success and false on an error.
     This function does not throw.
     @return true in case of success, false otherwise.
  **/
  bool do_handshake() noexcept;

  /**
     read_keyshare_after_handshake. This function reads the keyshare from
  another node after the handshake has occurred. This function returns true on
  success and false on an error. This function does not throw.
     @return true in case of success, false otherwise.
  **/
  bool read_keyshare_after_handshake() noexcept;

  /**
     read_sks_keyshare. This function reads the keyshare from
  another node. This corresponds to reading the key bytes of a third party.
  This function returns true on
  success and false on an error. This function does not throw.
  @return true in case of success, false otherwise.
  **/
  bool read_sks_keyshare() noexcept;

  /**
     get_curve_ids. This function returns the curve ID of each key share in an
  array. In particular, this array is {key_shares[0]'s curve ID, key_share[1]'s
  curve_ID}. If key_shares[i] is not initialised, then the ith position of the
  array shall be equal to 1. This function does not throw and does not modify
  this object.
     @snippet Server.t.cpp ServerGetCurveIDTests
     @return an array containing the curve ids.
  **/
  std::array<uint16_t, 2> get_curve_ids() const noexcept;

  /**
     create_new_share. This function accepts a public key
  corresponding to another node (`other_key_bytes`) and computes a new additive
  share for those key shares. The exact semantics of this are a bit confusing.

     Please note that calling this function causes a new public key to be
  generated for `this` server.

     This function returns false if:
     1. the call to Server::create_new_public_key fails.
     2. adding the two public keys together fails.
     3. exporting the public keys fails as a series of bytes fails.

     This function does not throw.
     @snippet Server.t.cpp ServerCreateNewShareTests
     @param[in] other_key_bytes: the public key of the other node.
     @return true in case of success, false otherwise.
  **/
  bool create_new_share(const bssl::Array<uint8_t> &other_key_bytes) noexcept;

  /**
     create_new_share. This function is a wrapper function for calling the other
     create_new_share method. This function simply calls the other
  create_new_share method with `this` socket's client_curve_id and
  client_public_key respectively.

     @return true in case of success, false otherwise.
  **/
  bool create_new_share() noexcept;

  bool do_preproc(const bool should_preproc) noexcept;

  bool read_mask_commitments() noexcept;

  /**
     verify_gcm_tag. Reads a record's ciphertext, AAD, sequence number and
     server tag from the prover, computes the verifier's GHASH share over that
     ciphertext from server_gcm_powers, and runs the joint verification circuit.

     The ciphertext is forwarded in full rather than reconstructed: the verifier
     never saw the origin's records, and a tag check over prover-supplied GHASH
     output would prove only that the two shares agree, not that the ciphertext
     is what the prover claims.
     @return true iff the tag verified and neither party's IV/tag input differed.
  **/
  bool verify_gcm_tag() noexcept;

  // SURF TRUE mode. Reads Gamma(r_k, k_c^server) from the prover. Stored
  // unopened: this party never learns k_c, and therefore never decrypts.
  bool read_key_commitment() noexcept;

  // SURF TRUE mode. Returns k_v and latches: all further GCM_VERIFY is
  // refused, since from here the prover holds k and could forge any record.
  bool release_key() noexcept;

  // SURF ROTATE mode. ROTATE_KEY || u8 direction: runs the rotate circuit for
  // one direction, re-derives that direction's GCM share, and clears the
  // per-key sequence bookkeeping. The server direction may only rotate after
  // the epoch it closes has been released; it then resets the commitment
  // latches so the next epoch needs a fresh KEY_COMMIT.
  bool rotate_key_op() noexcept;

  /**
     derive_keystream_blocks. Reads the captured record boundaries from the
     prover, then runs one keystream circuit per block. Each yields
     E_i = AES.Enc(k_c ^ k_v, ctr_i) ^ b_i: the verifier holds a sealed copy of
     the keystream it cannot read until the prover opens b_i at MASK_OPEN.
     The KS_DERIVE header has already been consumed by attest().
     @return true if every block derived and no counter mismatch was detected.
  **/
  bool derive_keystream_blocks() noexcept;

 /**
     encrypt_blocks. Reads the record's sequence number and plaintext length
     from the prover, then runs the batched encryption circuit. The verifier
     supplies its key share and the counter blocks and learns the ciphertext
     (Algorithm 1: "return C to V"), but never the plaintext. The AES_ENC header
     has already been consumed by attest().
  **/
  bool encrypt_blocks() noexcept;

  /**
     make_gcm_tag. Reads the AAD and true ciphertext length, computes this
     party's GHASH share over the ciphertext it already holds from
     encrypt_blocks, and runs the joint tag circuit. The tag itself is masked by
     the prover, so this party learns nothing from the output beyond the ok bit.
     The GCM_TAG header has already been consumed by attest().
  **/
  bool make_gcm_tag() noexcept;

  /**
     read_header_draining_encryption. Reads the next control header, handling
     any 2PC-AES-GCM encryption traffic that arrives first. The prover writes
     its request from inside SSL_write, which happens after the handshake but
     before the origin's NewSessionTicket, so AES_ENC / GCM_TAG land in the
     middle of the lock-step stream at the DERIVE_PSK read. The number of
     records is not known in advance (one pair per SSL_write), so this drains
     rather than occupying fixed states. Writes the first non-encryption header
     to |out|. Returns false on a read failure or a failed encryption round.
  **/
  bool read_header_draining_encryption(
      Messaging::MessageHeaders &out) noexcept;

  /**
     finish_tph. This function finishes the three party handshake. In
  particular, this function computes the shared key share from the received key
  share (from Server::read_sks_keyshare). This function does not throw.

     This function will return false if:
     1. the received key share is invalid.
     2. if the received key share does not match either key share held by this
  object.

     @return true if successful, false otherwise.
  **/
  bool finish_tph() noexcept;

  /**
     write_hs_recv. This function writes an acknowledgement to the client that
     the handshake was received and completed successfully. This function
     returns true if the write was successful and false otherwise. In
  particular, this function returns false if:

     1. writing the header fails.

     This function does not throw.
     @return true if successful, false otherwise.
  **/
  bool write_hs_recv() noexcept;

  /**
     do_psk_binder. On a resumption run, jointly computes the PSK binder for
     the resumed ClientHello. HMAC is non-linear in its key, so neither party
     can compute a partial binder from its PSK share alone; the circuit
     recombines the shares internally and outputs the binder publicly (it ships
     in the clear inside the ClientHello anyway). Self-skips on a full
     handshake, which has no PSK and therefore no binder. This function does
     not throw.
     @return true in case of success, false otherwise.
  **/
  bool do_psk_binder() noexcept;

  /**
     do_ectf. This function carries out the ECtF functionality provided by
  mta/ECtF.hpp. Essentially, this function produces additive shares of the `x`
  co-ordinate of the shared key, which is then used for the TLS PRF. This
  function does not throw.
     @return true in case of success, false otherwise.
  **/
  bool do_ectf() noexcept;

  /**
     finish_ectf. This function writes an acknowledgement to the client that
     the ectf has finished successfully. This function returns true if the write
     was successful and false otherwise.

     This function does not throw.
     @return true if successful, false otherwise.
  **/
  bool finish_ectf() noexcept;

  /**
     get_portnumber. This function writes a copy of `this` socket's port number
  to the `out` parameter. This function returns true when successful and false
  otherwise.

     This function will fail unless:
     1. There has been a successful binding (see StatefulSocket::bind for more).
     2. The out pointer is non-null.

     This function does not modify `this` object and does not throw.
     @param[out] out: the location to write the port number.
     @return true on success, false otherwise.
  **/
  bool get_portnumber(uint16_t *const out) const noexcept;

  /**
     write_handshake_done. This function writes a simple DONE_HS message to
  `this` socket's connection. This function returns true in case of success and
  false otherwise.

     @snippet Server.t.cpp ServerWriteHandshakeDoneTests
     @return true if successful, false otherwise.
  **/
  bool write_handshake_done() noexcept;

  /**
     get_ctx. This function returns a copy of the SSL_CTX that's associated with
  `this` socket. This function does not throw any exceptions and does not modify
  `this` socket directly: however, as the returned pointer is not const, then
  this method cannot be const.
     @return a copy of `this` object's SSL_CTX.
  **/
  SSL_CTX *get_ctx() noexcept;

  /**
    get_additive_share. This function writes a copy of `this` server's
 additive share to the `arr` parameter. This function returns `true` if the
 write is successful and false otherwise.
    This function will fail if:
    1. resizing the input `arr` fails.
    This function will return true even if an additive share has not yet been
 generated. This will manifest as `arr` being an array of size 0.
    This function does not modify `this` object and does not throw.
    @snippet Server.t.cpp ServerGetAdditiveShareTests
    @param[out] arr: the array to overwrite. This will throw away any previous
    data in the array.
    @return true in case of success, false otherwise.
 **/
  bool get_additive_share(bssl::Array<uint8_t> &arr) const noexcept;
  /**
  get_public_key.
  This function writes a copy of `this` server's public key to the `arr`
  parameter.This function returns `true` if the write is successful and false
  otherwise .This function will fail if:
  1. resizing the input `arr` fails.

  This function will return true even if a public key has not yet been
  generated. This will manifest as `arr` being an array of size 0. This function
  does not modify `this` object and does not throw.

  @snippet Server.t.cpp ServerGetPublicKeyTests
  @param[out] arr: the array to overwrite. This will throw away any previous
  data in the array.
  @return true in case of success, false otherwise.
  **/
  bool get_public_key(bssl::Array<uint8_t> &arr) const noexcept;

  /**
   **/
  SSL *get_ssl();

  KeyShare &get_active_share();

  const bssl::Array<uint8_t> &get_x_secret() const noexcept;

  /**
     was_resumed. Returns whether the most recent run()/run_resumption() saw an
     origin handshake that actually resumed (PSK accepted), as reported by the
     prover's handshake-mode flag. False when the origin fell back to a full
     handshake. Lets benchmarks label a resumption-run CSV row by what really
     happened rather than by what was attempted.
  **/
  bool was_resumed() const noexcept { return resumed_handshake; }

  /**
     get_timer. Returns the per-event timer populated during run() /
     run_resumption(). Used by benchmarks to emit per-step state-machine
     timings. Each run()/run_resumption() resets the timer, so this reflects
     only the most recent handshake.
  **/
  const Timer::TimerType &get_timer() const noexcept;

/**
     get_psk_share / set_psk_share. The verifier's half of the SURF PSK,
     derived in the full round's derive_psk and consumed in the resumed round
     by do_ks and do_psk_binder. When the two rounds run in separate processes
     the benchmark carries these 16 bytes across the
     boundary itself.
  **/
  const decltype(EmpWrapperAG2PCConstants::PskCircuitOut::PSK_share) &
  get_psk_share() const noexcept { return psk_shares.PSK_share; }

  void set_psk_share(
      const decltype(EmpWrapperAG2PCConstants::PskCircuitOut::PSK_share) &s)
      noexcept { psk_shares.PSK_share = s; }

  /**
     get_bandwidth_tracker. Returns the per-event bandwidth tracker populated
     during run() / run_resumption(). Used by benchmarks to emit per-step
     data-usage columns. Each run()/run_resumption() resets the tracker, so this
     reflects only the most recent handshake.
  **/
  const BandwidthTracker::TrackerType &get_bandwidth_tracker() const noexcept;

  /**
     get_round_tracker. Returns the per-event round tracker populated during
     run() / run_resumption(). Used by benchmarks to emit per-step
     communication-round columns alongside the byte columns. Each
     run()/run_resumption() resets the tracker, so this reflects only the most
     recent handshake.
  **/
  const RoundTracker::TrackerType &get_round_tracker() const noexcept;

  /**
     do_ks. This function reads the handshake transcript from the prover and
  stores the result in `transcript`. This is then used to advance the key
  schedule using the `x` secret. This function
  **/
  bool do_ks() noexcept;

  bool do_cert_wait() noexcept;
  bool write_cert_recv() noexcept;

  bool write_ks_done() noexcept;

  bool read_h6() noexcept;
  bool write_h6_recv() noexcept;

  bool derive_ts() noexcept;

  bool derive_gcm_shares() noexcept;
  bool write_completed_derivation() noexcept;

  bool derive_res() noexcept;
  bool write_completed_res() noexcept;

  bool derive_psk() noexcept;
  bool write_completed_psk() noexcept;

  bool shutdown() noexcept;

  void set_version(const uint16_t version) noexcept;
  void set_cipher_suite(const uint16_t cipher_suite) noexcept;

  void set_attestation() noexcept;

  bool attest() noexcept;

private:
  /**
     ssl_ctx. This is a pointer to the SSL_CTX that
     controls the socket's SSL object. `this` server
     owns the context.
  **/
  bssl::UniquePtr<SSL_CTX> ssl_ctx;

  /**
     shares. This is a pointer to the server's share object.
     Here, `share` means "the BoringSSL KeyShare object":
     this is just responsible for generating keys that are involved in the TLS
  attestation process.
  **/

  KeyShare key_shares[2];

  /**
     public_key. This contains `this` server's current public key in a
  serialised format. This will be empty in some circumstances.
  **/
  bssl::Array<uint8_t> public_key;
  /**
     additive_share. This contains `this` server's additive share of the 3 party
  handshake key. This will be empty in some circumstances.
  **/
  bssl::Array<uint8_t> additive_share;
  /**
     state. This contains `this` server's current state inside the Server::run
  function. See ServerState for more.
  **/
  ServerState state;

  /**
     active_key_share. This variable denotes the current active key share. This
  variable only has any meaning after `finish_tph`.
  **/
  unsigned int active_key_share;

  // This is the state read from the client

  /**
     client_public_key. This contains the serialised public key from the client.
  **/
  bssl::Array<uint8_t> client_public_key;
  /**
     client_group_id. This contains the group ID of the public key from the
  client.
  **/
  uint16_t client_group_id;

  /**
     ret_code. This contains the current BoringSSL return code from any
  BoringSSL operations. This exists to make it easier to debug the code.
  **/
  int ret_code;

  /**
     socket. This is the TLS socke that's used for communications.
  **/
  TLSSocket socket;

  /**
     buffer. This contains the serialised public key from the client prior to
     parsing. More broadly, this contains any "peeked" message.
     This exists to save on heap allocations.
  **/
  bssl::Array<uint8_t> buffer;

  /**
     x_secret. This contains the produced x_secret that's used in the TLS PRF.
  **/
  bssl::Array<uint8_t> x_secret;

  /**
     transcript. This contains the transcript read from the prover at various
   stages in the protocol.
   **/
  std::vector<uint8_t> transcript;

  std::vector<uint8_t> h6;

  bssl::SSLTranscript transcript_obj;
  EmpWrapperAG2PCConstants::HandshakeCircuitOut handshake_key_shares;
  EmpWrapperAG2PCConstants::TrafficCircuitOut traffic_key_shares;
  EmpWrapperAG2PCConstants::AESGCMBulkShareType client_gcm_powers;
  EmpWrapperAG2PCConstants::AESGCMBulkShareType server_gcm_powers;
  EmpWrapperAG2PCConstants::ResumptionCircuitOut resumption_shares;
  EmpWrapperAG2PCConstants::PskCircuitOut psk_shares{};
  // mask_commitments. The per-block mask commitments received from the prover
  // during preprocessing. Indexed by block number; checked when the prover
  // later opens a block by revealing its mask.
  std::array<uint8_t, 32> mask_commitment{};

  std::array<uint8_t, 32> key_commitment{};
  // true_surf means "sealed capture" (True or Rotate); mode tells them apart.
  Surf::Mode mode{Surf::Mode::Masked};
  bool true_surf{false};
  unsigned epoch{0};  // ROTATE: current server-key epoch
  bool key_committed{false};
  bool key_released{false};
  // Ciphertext retained per verified record, so a later disclosure can yield
  // plaintext. ~1.9 MiB for a 1.9 MB response; SURF_RETAIN=0 to disable.
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> attested_ct;
  bool retain_ct{true};

  // masked_keystream. E_i for each captured block, indexed by global block
  // number. Sealed under the prover's b_i: opening index i at MASK_OPEN yields
  // the keystream, and hence M_i = C_i ^ E_i ^ b_i.
  std::vector<std::array<uint8_t, 16>> masked_keystream;

  // Ciphertext from the most recent encrypt_blocks, indexed by block. Held so
  // make_gcm_tag can compute its GHASH share without the prover resending it.
  std::vector<std::array<uint8_t, 16>> encrypted_ct;
  // The AAD and true ciphertext length for that record.
  std::vector<uint8_t> encrypt_aad;
  size_t encrypt_ct_len{0};

  // Sequence numbers already consumed for encryption. Algorithm 1 requires
  // that an (IV, counter) pair is never reused: GCM under nonce reuse leaks
  // the plaintext XOR and, worse, the authentication key. The circuit checks
  // only that the parties AGREE on the counter, not that it is fresh, so the
  // freshness requirement is enforced here.
  std::vector<uint64_t> encrypted_seqs;

  std::unique_ptr<EmpWrapperAG2PC> aes_enc_circuit;
  std::unique_ptr<EmpWrapperAG2PC> gcm_tag_circuit;

  // Sequence numbers whose GCM tag verified this connection. Per-record
  // attestation derives one record's keystream at a time, so the gate is "this
  // record's tag verified", not "all of them did" -- a count no longer
  // identifies which record is being asked for.
  std::vector<uint64_t> verified_seqs;

  /**
     reset_per_connection_state. Clears everything whose lifetime is one
     prover connection: the timer and trackers, and the encryption state.

     TLS sequence numbers restart at 0 when the application keys are installed,
     so the Algorithm 1 freshness check in encrypt_blocks is only meaningful
     within one connection; carrying encrypted_seqs across runs makes the
     resumed connection's first record look like a replay. record_tag_ok has
     the same lifetime: derive_keystream_blocks compares its size against the
     record count the prover claims for THIS connection.

     Called from run(), run_resumption() and accept_and_read_mode(), each of
     which begins a fresh connection.
  **/
  void reset_per_connection_state() noexcept;

  uint16_t version;
  uint16_t cipher_suite;

  bool was_sf_right;

  /**
     timer. This object is used to record how long the various events that occur
  during the TLS handshake take. Each event can be found in Events.hpp.
  **/
  Timer::TimerType timer;

  /**
     bandwidth_tracker. This object is used to track how much bandwidth is
  consumed during various parts of this program. Each event can be found in
  Events.hpp.
  **/
  BandwidthTracker::TrackerType bandwidth_tracker;

  /**
     round_tracker. This object is used to track the number of communication
  rounds (outbound messages) consumed during various parts of this program. Each
  event can be found in Events.hpp. Mirrors bandwidth_tracker.
  **/
  RoundTracker::TrackerType round_tracker;

  std::array<std::unique_ptr<EmpWrapperAG2PC>, 2> handshake_circuits;
  std::unique_ptr<EmpWrapperAG2PC> traffic_circuit;
  std::unique_ptr<EmpWrapperAG2PC> aes_split_circuit;
  std::unique_ptr<EmpWrapperAG2PC> aes_joint_circuit;
  std::unique_ptr<EmpWrapperAG2PC> gcm_circuit;
  std::unique_ptr<EmpWrapperAG2PC> resumption_circuit;
  std::unique_ptr<EmpWrapperAG2PC> psk_circuit;
  // 8-byte ticket_nonce PSK circuit (OpenSSL/nginx origins); psk_circuit is the
  // 1-byte variant. The prover signals which to run via DERIVE_PSK/DERIVE_PSK_8.
  std::unique_ptr<EmpWrapperAG2PC> psk_circuit_8;
  std::unique_ptr<EmpWrapperAG2PC> psk_circuit_0;
  std::unique_ptr<EmpWrapperAG2PC> binder_circuit;

  std::unique_ptr<EmpWrapperAG2PC> gcm_vfy_circuit;
  std::unique_ptr<EmpWrapperAG2PC> ks_block_circuit;
  std::unique_ptr<EmpWrapperAG2PC> rotate_circuit;

  std::array<uint8_t, 32> server_key_comm;

  bool should_attest{false};
  bool loud{false};

  // SURF resumption robustness. Set in write_ks_done from the prover's
  // handshake-mode flag: true when the origin handshake actually resumed (no
  // server Certificate), false on a full handshake. Gates CERT_WAIT
  // so the verifier's state machine matches whatever the origin really
  // did, even when an external server declines a ticket and falls back to a
  // full handshake mid-resumption.
  bool resumed_handshake{false};

  // True while walking run_resumption()'s state list. Distinct from
  // resumed_handshake, which reports what the server did: this is just which driver
  // we're in, known from the run-type tag
  // at accept_and_read_mode. do_psk_binder needs it because run() walks
  // PSK_BINDER too and must skip it.
  bool is_resumption_run{false};

  // SURF resumption robustness: set in derive_psk when the prover sends PSK_SKIP
  // (resumed origin produced no NewSessionTicket, so no PSK was derived). Gates
  // write_completed_psk / reveal_psk_share so the verifier skips the rest of the
  // PSK phase instead of writing PSK_DONE / a PSK reveal the prover never reads.
  bool psk_skipped{false};
};

#endif
