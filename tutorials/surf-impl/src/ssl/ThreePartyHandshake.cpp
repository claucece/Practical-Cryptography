#include "ThreePartyHandshake.hpp"
#include "../mta/F2128MtA.hpp"
#include "../mta/ectf.hpp"
#include "Messaging.hpp"
#include "Util.hpp"
#include "openssl/digest.h"
#include "openssl/hkdf.h"
#include "openssl/ssl.h"
#include "GHash.hpp"
#include "ssl/internal.h"
#include <cerrno>
#include <poll.h>
#include <tuple>


// Macros rarely help readability. Here, though, it makes life a lot easier.
#define RETURN_FALSE_IF_SSL_FAILED(ssl_size, target_size)                      \
  do {                                                                         \
    if (ssl_size <= 0 || static_cast<unsigned>(ssl_size) != target_size)       \
      return false;                                                            \
  } while (0)


// Loop-until-complete blocking read that tolerates SSL_ERROR_WANT_READ /
// WANT_WRITE. The prover<->verifier connection can return WANT_READ (errno
// EAGAIN) from SSL_read when the lock-step peer hasn't yet sent the next
// control byte: over a real network there is RTT latency between messages, so
// the byte is briefly "not there", whereas on loopback it is always already
// present. A bare single SSL_read treats that transient as a hard failure,
// which desynchronises the protocol. Here we wait for the socket to become
// ready and retry until all `len` bytes are read. Returns true iff every byte
// was read.
static bool read_exact_blocking(SSL *const ssl, void *const buf,
                                const std::size_t len) noexcept {
  if (!ssl) return false;
  auto *const p = static_cast<uint8_t *>(buf);
  std::size_t total = 0;
  while (total < len) {
    const int n = SSL_read(ssl, p + total, static_cast<int>(len - total));
    if (n > 0) {
      total += static_cast<std::size_t>(n);
      continue;
    }
    const int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
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
    return false; // clean shutdown or fatal error
  }
  return true;
}

template <Messaging::MessageHeaders target_header>
static bool is_correct_header(SSL *ssl) noexcept {
  // This function just reads a single header from `ssl` and checks that it is
  // the one that was expected. This can return false if reading fails too.
  static_assert(sizeof(target_header) == sizeof(uint8_t),
                "is_correct_header assumes sizeof(target_header) == 1");
  uint8_t header_buf;
  // Use a retrying, loop-until-complete read (see read_exact_blocking): a bare
  // single SSL_read can return WANT_READ over a real network and break the
  // lock-step framing.
  if (!read_exact_blocking(ssl, &header_buf, sizeof(header_buf))) {
    return false;
  }

  // We now need to convert out of the serialisation format. This is likely a
  // big endian value, so we need to explicitly undo that conversion.
  CBS in_cbs;
  CBS_init(&in_cbs, &header_buf, sizeof(header_buf));

  uint8_t in_header;
  if (!CBS_get_u8(&in_cbs, &in_header) ||
      !Messaging::is_valid_header(in_header)) {
    return false;
  }

  return static_cast<Messaging::MessageHeaders>(in_header) == target_header;
}

static void delete_circuits(SSL *ssl) noexcept {
  // This is just a helper function to minimise code duplication.
  delete ssl->ks_circuit;
  delete ssl->handshake_circuit_a;
  delete ssl->handshake_circuit_b;
  delete ssl->traffic_circuit;
  delete ssl->gcm_circuit;
  delete ssl->resumption_circuit;
  delete ssl->psk_circuit;
  delete ssl->psk_circuit_8;
  delete ssl->psk_circuit_0;
  delete ssl->binder_circuit;
  delete ssl->gcm_vfy_circuit;
  delete ssl->ks_block_circuit;
  delete ssl->aes_enc_circuit;
  delete ssl->gcm_tag_circuit;
  delete ssl->rotate_circuit;
}

// We forward the server key share
bool ThreePartyHandshake::three_party_handshake_send_received_key_shares(
    SSL *ssl, uint16_t group_id, CBS &in_cbs) {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // If there's no verifier, then we have to bail.
  if (!ssl || ssl->verifier == nullptr) {
    return false;
  }

  // Similarly, if the array is empty then it doesn't make any sense: what would
  // we be sending?
  const auto size = CBS_len(&in_cbs);
  if (size == 0) {
    return false;
  }

  // And finally, if the SSL connection is a server then this makes no sense.
  if (SSL_is_server(ssl)) {
    return false;
  }

  // The CBS input isn't in exactly the right format for the receiver,
  // so we'll convert it here.
  bssl::ScopedCBB scbb;
  CBB out;
  bssl::Array<uint8_t> arr;
  const auto *const data = CBS_data(&in_cbs);

  if (!CBB_init(scbb.get(), 64) || !CBB_add_u16(scbb.get(), group_id) ||
      !CBB_add_u16_length_prefixed(scbb.get(), &out) ||
      !CBB_add_bytes(&out, data, sizeof(uint8_t) * size) ||
      !CBBFinishArray(scbb.get(), &arr)) {
    return false;
  }

  // Now arr holds everything in the right format, so we'll just write it
  bssl::Array<uint8_t> key_share_packed;
  if (!Messaging::pack_key_bytes(Messaging::MessageHeaders::SERVER_KEY_SHARE,
                                 arr, key_share_packed)) {
    return false;
  }

  // This is just an abbreviation.
  auto verifier = ssl->verifier;

  // NOTE: this cast is fine. This is because:
  // 1) SSL3_RT_MAX_PLAIN_LENGTH is much less than the maximum positive value
  // stored in an int on all systems. See
  // https://www.open-std.org/JTC1/SC22/WG14/www/docs/n1256.pdf for INT_MAX.
  // Whilst this is from the C standard, C++ draws on this fact. 2) We know that
  // SSL3_RT_MAX_PLAIN_LENGTH is the maximum value we'll pass here because of
  // the check above.
  const auto amount_written =
      SSL_write(verifier, key_share_packed.data(),
                static_cast<int>(key_share_packed.size()));

  // It is, of course, possible this write will fail.
  // However, if there's a handshake on the verifier that has yet to go through
  // this will still work: the handshake will go through in the background.
  RETURN_FALSE_IF_SSL_FAILED(amount_written, key_share_packed.size());

  // We expect the resulting message from the server to be a single
  // header in size.
  // To guard against problems we re-use the key_share_packed array though.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We've now just read a single header into the key_share_packed array.
  if (!is_correct_header<Messaging::MessageHeaders::HS_RECV>(verifier)) {
    return false;
  }

  // NOTE: in some testing situations we want to bail here.
  // We'll do that if the "thrower" is set.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::HS_RECV)) {
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::preprocess_circuits(SSL *ssl) {
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  if (!ssl || ssl->verifier == nullptr || SSL_is_server(ssl)) {
    return false;
  }

  if (!Surf::mode_from_env(ssl->surf_mode)) {
    return false;
  }
  ssl->surf_true_mode = Surf::is_capture(ssl->surf_mode);
  std::cerr << "[Prover] SURF mode: " << Surf::mode_name(ssl->surf_mode) << "\n";

  // No-op if circuits are disabled (tests) or already built (the offline phase
  // already ran before the origin connection was opened). Idempotent.
  if (!ssl->should_make_circuits || ssl->handshake_circuit_a) {
    return true;
  }

  auto verifier = ssl->verifier;
  // The ClientHello offers a single NIST key share (SECP256R1); see
  // ssl_set_nist_curves + ssl_setup_key_shares. Circuit B (SECP384R1) is never
  // negotiated, so it is not preprocessed. Both prover and verifier must agree
  // on this set (do_preproc is interactive) -- see Server::do_preproc.
  ssl->handshake_circuit_a = EmpWrapperAG2PC::build_derive_hs_circuit(
      verifier, SSL_CURVE_SECP256R1, emp::ALICE,
      EmpWrapperAG2PCConstants::HANDSHAKE_CIRCUIT_TAG_A);
  if (ssl->handshake_circuit_a) {
    ssl->handshake_circuit_a->do_preproc();
    if (ssl->handshake_circuit_a->has_io_failed()) {
      return false;
    }
  }

  ssl->traffic_circuit = EmpWrapperAG2PC::build_derive_ts_circuit(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::TRAFFIC_CIRCUIT_TAG);
  if (ssl->traffic_circuit) {
    ssl->traffic_circuit->do_preproc();
    if (ssl->traffic_circuit->has_io_failed()) {
      return false;
    }
  }

  ssl->gcm_circuit = EmpWrapperAG2PC::build_gcm_circuit(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::GCM_CIRCUIT_TAG);
  if (ssl->gcm_circuit) {
    ssl->gcm_circuit->do_preproc();
    if (ssl->gcm_circuit->has_io_failed()) {
      return false;
    }
  }

  ssl->resumption_circuit = EmpWrapperAG2PC::build_derive_res_circuit(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::RMS_CIRCUIT_TAG);
  if (ssl->resumption_circuit) {
    ssl->resumption_circuit->do_preproc();
    if (ssl->resumption_circuit->has_io_failed()) {
      return false;
    }
  }

  // Two PSK circuits, one per ticket_nonce width: the server's nonce is only
  // known once its NewSessionTicket arrives (post-handshake), but preprocessing
  // must happen now, so we preprocess both and pick the matching one in
  // derive_psk_keys off ssl->ticket_nonce.size(). Both must be preprocessed in
  // lock-step with the verifier's matching pair (see Server::preproc).
  ssl->psk_circuit = EmpWrapperAG2PC::build_derive_psk_circuit(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::PSK_CIRCUIT_TAG);
  if (ssl->psk_circuit) {
    ssl->psk_circuit->do_preproc();
    if (ssl->psk_circuit->has_io_failed()) {
      return false;
    }
  }

  ssl->psk_circuit_8 = EmpWrapperAG2PC::build_derive_psk_circuit_8(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::PSK_CIRCUIT_TAG_8);
  if (ssl->psk_circuit_8) {
    ssl->psk_circuit_8->do_preproc();
    if (ssl->psk_circuit_8->has_io_failed()) {
      return false;
    }
  }

  ssl->psk_circuit_0 = EmpWrapperAG2PC::build_derive_psk_circuit_0(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::PSK_CIRCUIT_TAG_0);
  if (ssl->psk_circuit_0) {
    ssl->psk_circuit_0->do_preproc();
    if (ssl->psk_circuit_0->has_io_failed()) {
      return false;
    }
  }

  ssl->binder_circuit = EmpWrapperAG2PC::build_derive_binder_circuit(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::BINDER_CIRCUIT_TAG);
  if (ssl->binder_circuit) {
    ssl->binder_circuit->do_preproc();
    if (ssl->binder_circuit->has_io_failed()) {
      return false;
    }
  }

  ssl->gcm_vfy_circuit =
      ssl->surf_true_mode
          ? EmpWrapperAG2PC::build_gcm_vfy_commit_circuit(
                verifier, emp::ALICE,
                EmpWrapperAG2PCConstants::GCM_VFY_COMMIT_CIRCUIT_TAG)
          : EmpWrapperAG2PC::build_gcm_vfy_circuit(
                verifier, emp::ALICE,
                EmpWrapperAG2PCConstants::GCM_VFY_CIRCUIT_TAG);
  if (ssl->gcm_vfy_circuit) {
    ssl->gcm_vfy_circuit->do_preproc();
    if (ssl->gcm_vfy_circuit->has_io_failed()) {
      return false;
    }
  }

  if (!ssl->surf_true_mode) {
    ssl->ks_block_circuit = EmpWrapperAG2PC::build_ks_batch_circuit(
        verifier, emp::ALICE, EmpWrapperAG2PCConstants::KS_BATCH_CIRCUIT_TAG);
    if (ssl->ks_block_circuit) {
      ssl->ks_block_circuit->do_preproc();
      if (ssl->ks_block_circuit->has_io_failed()) {
        return false;
      }
    }
  }

  ssl->aes_enc_circuit = EmpWrapperAG2PC::build_aes_enc_circuit(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::AES_ENC_CIRCUIT_TAG);
  if (ssl->aes_enc_circuit) {
    ssl->aes_enc_circuit->do_preproc();
    if (ssl->aes_enc_circuit->has_io_failed()) {
      return false;
    }
  }

  ssl->gcm_tag_circuit = EmpWrapperAG2PC::build_gcm_tag_circuit(
      verifier, emp::ALICE, EmpWrapperAG2PCConstants::GCM_TAG_CIRCUIT_TAG);
  if (ssl->gcm_tag_circuit) {
    ssl->gcm_tag_circuit->do_preproc();
    if (ssl->gcm_tag_circuit->has_io_failed()) {
      return false;
    }
  }

  if (ssl->surf_mode == Surf::Mode::Rotate) {
    ssl->rotate_circuit = EmpWrapperAG2PC::build_derive_rotate_circuit(
        verifier, emp::ALICE, EmpWrapperAG2PCConstants::ROTATE_CIRCUIT_TAG);
    if (ssl->rotate_circuit) {
      ssl->rotate_circuit->do_preproc();
      if (ssl->rotate_circuit->has_io_failed()) {
        return false;
      }
    }
  }

  // Commit to the seed the per-block masks are derived from. The circuit
  // computes b_i = AES_s(ctr_i) on wires and opens this commitment once per
  // batch, so there is no per-block mask budget.
  //
  // s must be fresh per session and independent of the traffic key: E_i is
  // AES_k(ctr_i) ^ AES_s(ctr_i), the xor of two PRFs on the same input, which
  // is only sound for independent keys. Never persist s across sessions.
  if (!ssl->surf_true_mode) {
    if (!RAND_bytes(ssl->mask_seed.data(), ssl->mask_seed.size()) ||
        !RAND_bytes(ssl->mask_seed_key.data(), ssl->mask_seed_key.size())) {
      return false;
    }

    std::array<uint8_t, MaskConstants::kCommitSize> commitment;
    if (!MaskConstants::hirose_commit_host(ssl->mask_seed_key.data(),
                                           ssl->mask_seed.data(),
                                           commitment.data())) {
      return false;
    }

    bssl::Array<uint8_t> commit_buf;
    const auto commit_size =
        sizeof(Messaging::MessageHeaders) + MaskConstants::kCommitSize;
    bssl::ScopedCBB cbb;
    if (!commit_buf.Init(commit_size) || !CBB_init(cbb.get(), commit_size) ||
        !CBB_add_u8(cbb.get(),
                    static_cast<uint8_t>(
                        Messaging::MessageHeaders::MASK_COMMITMENTS)) ||
        !CBB_add_bytes(cbb.get(), commitment.data(), commitment.size()) ||
        !CBBFinishArray(cbb.get(), &commit_buf)) {
      return false;
    }

    const auto written = SSL_write(verifier, commit_buf.data(),
                                 static_cast<int>(commit_buf.size()));
    RETURN_FALSE_IF_SSL_FAILED(written, commit_buf.size());
  }

  ssl->next_mask_index = 0;

  return true;
}

// SURF TRUE mode. Gamma(r_k, k_c^server) under fresh randomness, sent once per
// session ahead of the first record's GCM_VERIFY. The verifier stores the
// digest and never opens it: it never learns k_c, so it is never allowed to decrypt
static bool surf_send_key_commitment(SSL *ssl) {
  if (!RAND_bytes(ssl->surf_key_commit_rand.data(),
                  ssl->surf_key_commit_rand.size())) {
    return false;
  }

  std::array<uint8_t, MaskConstants::kCommitSize> d_k{};
  if (!MaskConstants::hirose_commit_host(ssl->surf_key_commit_rand.data(),
                                         ssl->server_key_share.data(),
                                         d_k.data())) {
    return false;
  }

  const auto size = sizeof(Messaging::MessageHeaders) + d_k.size();
  bssl::Array<uint8_t> buf;
  bssl::ScopedCBB cbb;
  if (!buf.Init(size) || !CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(Messaging::MessageHeaders::KEY_COMMIT)) ||
      !CBB_add_bytes(cbb.get(), d_k.data(), d_k.size()) ||
      !CBBFinishArray(cbb.get(), &buf)) {
    return false;
  }

  const auto written =
      SSL_write(ssl->verifier, buf.data(), static_cast<int>(buf.size()));
  if (written <= 0 || static_cast<unsigned>(written) != buf.size()) {
    return false;
  }
  ssl->surf_key_committed = true;
  return true;
}

// Verify the record tag and allow for decryption
bool ThreePartyHandshake::verify_record_tag(SSL *ssl, size_t record_index,
                                            bool *tag_ok) {
  if (!ssl || !ssl->verifier || !ssl->gcm_vfy_circuit) {
    return false;
  }
  if (record_index >= ssl->surf_records.size()) {
    return false;
  }

  // TRUE mode: the circuit opens Gamma(d_k, r_k, k_c) on wires, so the
  // verifier must already hold d_k. Sent lazily on the first record, which is
  // still before the verifier has seen any ciphertext.
  if (ssl->surf_true_mode && !ssl->surf_key_committed &&
      !surf_send_key_commitment(ssl)) {
    return false;
  }

  auto verifier = ssl->verifier;
  const auto &rec = ssl->surf_records[record_index];

  // TLS 1.3 AAD is the record header as it appeared on the wire:
  // 0x17 || 0x03 0x03 || u16(ciphertext_len + tag_len)
  const size_t record_len = rec.ciphertext.size() + 16;
  std::array<uint8_t, 5> aad{
      SSL3_RT_APPLICATION_DATA,
      0x03, 0x03,
      static_cast<uint8_t>(record_len >> 8),
      static_cast<uint8_t>(record_len & 0xff)};

  // Wire format: u64 seq || u16 aad_len || aad || u32 ct_len || ct || tag
  const auto size = sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) +
                    sizeof(uint16_t) + aad.size() + sizeof(uint32_t) +
                    rec.ciphertext.size() + rec.tag.size();

  bssl::Array<uint8_t> out_arr;
  bssl::ScopedCBB cbb;
  if (!out_arr.Init(size) || !CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(
                      Messaging::MessageHeaders::GCM_VERIFY)) ||
      !CBB_add_u64(cbb.get(), rec.seq) ||
      !CBB_add_u16(cbb.get(), static_cast<uint16_t>(aad.size())) ||
      !CBB_add_bytes(cbb.get(), aad.data(), aad.size()) ||
      !CBB_add_u32(cbb.get(), static_cast<uint32_t>(rec.ciphertext.size())) ||
      !CBB_add_bytes(cbb.get(), rec.ciphertext.data(),
                     rec.ciphertext.size()) ||
      !CBB_add_bytes(cbb.get(), rec.tag.data(), rec.tag.size()) ||
      !CBBFinishArray(cbb.get(), &out_arr)) {
    return false;
  }

  const auto written =
      SSL_write(verifier, out_arr.data(), static_cast<int>(out_arr.size()));
  RETURN_FALSE_IF_SSL_FAILED(written, out_arr.size());

  EmpWrapperAG2PCConstants::GCMVfyCircuitIn input{};

  // This party's share of P_{A||C||len(A)||len(C)}({h^i}). Local: GHASH is
  // linear in the H-powers, so the verifier computes its half independently
  // and the MPC XORs the two together.
  if (!GHash::share(ssl->sgcm_share,
                    bssl::MakeConstSpan(aad.data(), aad.size()),
                    bssl::MakeConstSpan(rec.ciphertext.data(),
                                        rec.ciphertext.size()),
                    input.tag_share)) {
    return false;
  }

  // J0 = (server_iv XOR seq) || 0x00000001. Note ssl->server_iv holds the
  // 12-byte IV at offset 4,
  // whereas the circuit wants a bare 16-byte counter block.
  input.iv.fill(0);
  std::copy(ssl->server_iv.cbegin() + 4, ssl->server_iv.cbegin() + 16,
            input.iv.begin());
  for (unsigned i = 0; i < 8; i++) {
    input.iv[11 - i] ^= static_cast<uint8_t>(rec.seq >> (8 * i));
  }
  input.iv[15] = 1;

  input.key = ssl->server_key_share;
  std::copy(rec.tag.cbegin(), rec.tag.cend(), input.server_tag.begin());

  // TRUE mode additionally opens the key
  // commitment. Masked mode is unchanged: there, E_i already binds the key,
  // so a second opening would be redundant.
  if (ssl->surf_true_mode) {
    EmpWrapperAG2PCConstants::GCMVfyCommitCircuitIn cin{};
    cin.key = input.key;
    cin.iv = input.iv;
    cin.tag_share = input.tag_share;
    cin.server_tag = input.server_tag;
    cin.r_k = ssl->surf_key_commit_rand;
    // cin.d_k stays zero: ALICE-side padding.

    EmpWrapperAG2PCConstants::GCMVfyCommitCircuitOut cout{};
    if (!ThreePartyHandshake::run_gcm_vfy_commit_circuit(
            cin, cout, ssl->gcm_vfy_circuit)) {
      return false;
    }
   if (ssl->surf_mode != Surf::Mode::Rotate) {
      // N.B. as below, these bits arrived from the verifier over the wire.
      return cout.tag_passed && !cout.cheated && cout.key_opened;
    }

    // ROTATE: the verifier's explicit verdict drives the epoch search.
    uint8_t ack;
    if (!read_exact_blocking(verifier, &ack, 1)) {
      return false;
    }
    if (cout.cheated || !cout.key_opened) {
      return false;
    }
    if (ack == static_cast<uint8_t>(Messaging::MessageHeaders::TAG_OK)) {
      if (tag_ok) *tag_ok = true;
      return true;
    }
    if (ack == static_cast<uint8_t>(Messaging::MessageHeaders::TAG_REJECT) &&
        tag_ok) {
      *tag_ok = false;
      return true;
    }
    return false;
  }

  EmpWrapperAG2PCConstants::GCMVfyCircuitOut output{};
  if (!ThreePartyHandshake::run_gcm_vfy_circuit(input, output,
                                                ssl->gcm_vfy_circuit)) {
    return false;
  }

  // N.B. these bits arrived from the verifier over the wire (amortized circuits
  // only evaluate output for BOB), so they are informational here rather than
  // independently trustworthy. The verifier's own copy is the one that counts.
  return output.tag_passed && !output.cheated;
}

static_assert(MaskConstants::kMaskSize == 16, "mask must be one AES block");

// Derive the keystream
bool ThreePartyHandshake::derive_keystream(SSL *ssl, size_t record_index) {
  if (!ssl || !ssl->verifier || !ssl->ks_block_circuit) {
    return false;
  }
  constexpr auto N = EmpWrapperAG2PCConstants::KS_BATCH_N;
  auto verifier = ssl->verifier;

  if (record_index >= ssl->surf_records.size()) {
    return false;
  }
  const auto &rec = ssl->surf_records[record_index];
  const std::vector<SurfBlockMap::RecordDims> recs{
      {rec.seq, static_cast<uint32_t>(rec.ciphertext.size())}};

  const size_t nblocks = SurfBlockMap::total_blocks(recs);
  if (nblocks == 0 || nblocks > MaskConstants::kNumMasks) {
    std::cerr << "[Prover] bad block count: " << nblocks
              << " (kNumMasks=" << MaskConstants::kNumMasks << ")\n";
    return false;
  }

  // The keystream buffer holds one record at a time. tls_open_record consumes
  // it immediately in the same call and nothing reads it afterwards, so there
  // is no reason to accumulate across records -- and accumulating would cap a
  // connection at kNumMasks total blocks rather than per record.
  const size_t base = 0;

  const size_t nbatches = (nblocks + N - 1) / N;

  // Tell the verifier the record boundaries so it derives the same counters.
  // KS_DERIVE || u32 nrec || nrec x (u64 seq || u32 ct_len)
  const auto size = sizeof(Messaging::MessageHeaders) + sizeof(uint32_t) +
                    recs.size() * (sizeof(uint64_t) + sizeof(uint32_t));
  bssl::Array<uint8_t> out_arr;
  bssl::ScopedCBB cbb;
  if (!out_arr.Init(size) || !CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(Messaging::MessageHeaders::KS_DERIVE)) ||
      !CBB_add_u32(cbb.get(), static_cast<uint32_t>(recs.size()))) {
    return false;
  }
  for (const auto &r : recs) {
    if (!CBB_add_u64(cbb.get(), r.seq) || !CBB_add_u32(cbb.get(), r.ct_len)) {
      return false;
    }
  }
  if (!CBBFinishArray(cbb.get(), &out_arr)) {
    return false;
  }
  const auto written =
      SSL_write(verifier, out_arr.data(), static_cast<int>(out_arr.size()));
  RETURN_FALSE_IF_SSL_FAILED(written, out_arr.size());

  if (ssl->keystream.size() != MaskConstants::kNumMasks * 16 &&
      !ssl->keystream.Init(MaskConstants::kNumMasks * 16)) {
    return false;
  }


  for (size_t batch = 0; batch < nbatches; batch++) {
    // Re-preprocess explicitly rather than letting derive_ks_batch do it
    // inline. Both parties compute the same batch count from the same
    // (seq, ct_len), so this fires at the same point on both sides; the
    // inline version fires from inside the circuit call, where the ordering
    // is not agreed and the stream desyncs.
    if (ssl->ks_block_circuit->ks_batches_remaining() == 0) {
      ssl->ks_block_circuit->do_preproc();
      if (ssl->ks_block_circuit->has_io_failed()) {
        return false;
      }
    }

    EmpWrapperAG2PCConstants::KSBatchCircuitIn in{};
    in.key = ssl->server_key_share;
    in.s = ssl->mask_seed;
    in.r = ssl->mask_seed_key;
    // in.d stays zero: ALICE-side padding.

    for (unsigned j = 0; j < N; j++) {
      const size_t idx = batch * N + j;
      uint64_t seq;
      uint32_t counter;

      if (idx < nblocks) {
        if (!SurfBlockMap::resolve(recs, idx, seq, counter)) {
          return false;
        }
      } else {
        // Padding must not share a counter block with a real slot: the mask
        // is AES_s(ctr), so a repeat gives E_pad == E_real. A real block's
        // counter never has the top bit set (a record is at most 2^10
        // blocks), so this cannot collide. Both parties derive it from
        // (idx, nblocks) alone, so nothing crosses the wire.
        if (!SurfBlockMap::resolve(recs, nblocks - 1, seq, counter)) {
          return false;
        }
        counter = 0x80000000u | static_cast<uint32_t>(idx);
      }

      SurfBlockMap::ctr_block(ssl->server_iv.data() + 4, seq, counter,
                              in.ctr[j]);
    }

    EmpWrapperAG2PCConstants::KSBatchCircuitOut out{};
    if (!run_ks_batch_circuit(in, out, ssl->ks_block_circuit)) {
      return false;
    }
    if (!out.ok) {
      return false;
    }

 for (unsigned j = 0; j < N; j++) {
      const size_t idx = batch * N + j;
      if (idx >= nblocks) break;

      // The circuit returns E_i = AES_k(ctr_i) ^ AES_s(ctr_i). We hold s, so
      // we strip the mask locally to recover the keystream. The verifier
      // cannot: it never learns s.
      std::array<uint8_t, 16> b{};
      if (!MaskConstants::aes_ecb_block(ssl->mask_seed.data(),
                                        in.ctr[j].data(), b.data())) {
        return false;
      }
      uint8_t *const dst = ssl->keystream.data() + (base + idx) * 16;
      for (unsigned k = 0; k < 16; k++) {
        dst[k] = out.masked_ks[j][k] ^ b[k];
      }
    }

  }

  ssl->next_mask_index = nblocks;

  return true;
}

bool ThreePartyHandshake::attest_record(SSL *ssl, size_t record_index) {
  // TRUE mode does not attest per record: nothing can be opened while it
  // arrives, so tls_open_record only captures, and every tag circuit runs
  // later in true_surf_release.
  if (ssl->surf_true_mode) {
    return true;
  }

  if (!verify_record_tag(ssl, record_index)) {
    std::cerr << "[Prover] verify_record_tag failed on record "
              << record_index << "\n";
    return false;
  }
  return derive_keystream(ssl, record_index);
}

bool ThreePartyHandshake::run_ks_batch_circuit(
    const EmpWrapperAG2PCConstants::KSBatchCircuitIn &in,
    EmpWrapperAG2PCConstants::KSBatchCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept {
  if (!circuit) {
    return false;
  }
  constexpr auto N = EmpWrapperAG2PCConstants::KS_BATCH_N;

  EmpWrapperAG2PCConstants::aes_ks_batch_input_type input{};
  unsigned pos = 0;
  std::copy(in.key.cbegin(), in.key.cend(), input.begin() + pos);
  pos += 16;
  for (unsigned i = 0; i < N; i++) {
    std::copy(in.ctr[i].cbegin(), in.ctr[i].cend(), input.begin() + pos);
    pos += 16;
  }
  std::copy(in.s.cbegin(), in.s.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.r.cbegin(), in.r.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.d.cbegin(), in.d.cend(), input.begin() + pos);
  pos += 32;
  assert(pos == input.size());

  EmpWrapperAG2PCConstants::aes_ks_batch_output_type output{};
  if (!circuit->derive_ks_batch(input, output)) {
    return false;
  }
  for (unsigned i = 0; i < N; i++) {
    std::copy(output.cbegin() + i * 16, output.cbegin() + (i + 1) * 16,
              out.masked_ks[i].begin());
  }
  const auto ok_byte = output[16 * N];
  if (ok_byte != 0x00 && ok_byte != 0xFF) {
    return false;  // repeated-bit byte; anything else means a desync
  }
  out.ok = (ok_byte != 0);
  return true;
}

bool ThreePartyHandshake::run_aes_enc_batch_circuit(
    const EmpWrapperAG2PCConstants::AESEncBatchCircuitIn &in,
    EmpWrapperAG2PCConstants::AESEncBatchCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept {
  if (!circuit) {
    return false;
  }
  constexpr auto N = EmpWrapperAG2PCConstants::AES_ENC_N;

  EmpWrapperAG2PCConstants::aes_enc_batch_input_type input{};
  unsigned pos = 0;
  std::copy(in.key.cbegin(), in.key.cend(), input.begin() + pos);
  pos += 16;
  for (unsigned i = 0; i < N; i++) {
    std::copy(in.ctr[i].cbegin(), in.ctr[i].cend(), input.begin() + pos);
    pos += 16;
  }
  for (unsigned i = 0; i < N; i++) {
    std::copy(in.pt[i].cbegin(), in.pt[i].cend(), input.begin() + pos);
    pos += 16;
  }
  assert(pos == input.size());

  EmpWrapperAG2PCConstants::aes_enc_batch_output_type output{};
  if (!circuit->encrypt_batch(input, output)) {
    return false;
  }
  for (unsigned i = 0; i < N; i++) {
    std::copy(output.cbegin() + i * 16, output.cbegin() + (i + 1) * 16,
              out.ct[i].begin());
  }
  const auto ok_byte = output[16 * N];
  if (ok_byte != 0x00 && ok_byte != 0xFF) {
    return false;  // repeated-bit byte; anything else means a desync
  }
  out.ok = (ok_byte != 0);
  return true;
}

bool ThreePartyHandshake::run_gcm_tag_circuit(
    const EmpWrapperAG2PCConstants::GCMTagCircuitIn &in,
    EmpWrapperAG2PCConstants::GCMTagCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept {
  if (!circuit) {
    return false;
  }

  EmpWrapperAG2PC::aes_gcm_tag_input_type input{};
  unsigned pos = 0;
  std::copy(in.key_share.cbegin(), in.key_share.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.iv.cbegin(), in.iv.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.tag_share.cbegin(), in.tag_share.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.mask_or_unused.cbegin(), in.mask_or_unused.cend(),
            input.begin() + pos);
  pos += 16;
  assert(pos == input.size());

  EmpWrapperAG2PC::aes_gcm_tag_output_type output{};
  if (!circuit->make_tag(input, output)) {
    return false;
  }

  // Byte 0 is a repeated bit: 1 iff the two IVs matched.
  if (output[0] != 0x00 && output[0] != 0xFF) {
    return false;
  }
  out.cheated = (output[0] == 0);
  std::copy(output.cbegin() + 1, output.cend(), out.tag.begin());
  return true;
}

bool ThreePartyHandshake::encrypt_request(SSL *ssl,
                                          bssl::Span<const uint8_t> plaintext,
                                          uint8_t inner_type,
                                          bssl::Array<uint8_t> &record_out) {
  if (!ssl || !ssl->verifier || !ssl->aes_enc_circuit || !ssl->gcm_tag_circuit) {
    return false;
  }
  constexpr auto N = EmpWrapperAG2PCConstants::AES_ENC_N;
  auto verifier = ssl->verifier;

  // RFC 8446 5.2: the encrypted payload is the plaintext followed by the inner
  // content type (we emit no padding). len(C) counts that byte.
  const size_t pt_len = plaintext.size() + 1;
  if (pt_len == 0 || pt_len > SSL3_RT_MAX_PLAIN_LENGTH) {
    return false;
  }
  const size_t nblocks = (pt_len + 15) / 16;
  const size_t nbatches = (nblocks + N - 1) / N;
  if (nbatches > 4) {  // aes_enc_iters
    return false;
  }

  std::vector<uint8_t> inner(nbatches * N * 16, 0);
  std::copy(plaintext.begin(), plaintext.end(), inner.begin());
  inner[plaintext.size()] = inner_type;

  const uint64_t seq = ssl->s3->write_sequence;

  // Tell the verifier which record this is, so it derives identical counters.
  // AES_ENC || u64 seq || u32 pt_len
  const auto hdr_size = sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) +
                        sizeof(uint32_t);
  bssl::Array<uint8_t> hdr_arr;
  {
    bssl::ScopedCBB cbb;
    if (!hdr_arr.Init(hdr_size) || !CBB_init(cbb.get(), hdr_size) ||
        !CBB_add_u8(cbb.get(),
                    static_cast<uint8_t>(Messaging::MessageHeaders::AES_ENC)) ||
        !CBB_add_u64(cbb.get(), seq) ||
        !CBB_add_u32(cbb.get(), static_cast<uint32_t>(pt_len)) ||
        !CBBFinishArray(cbb.get(), &hdr_arr)) {
      return false;
    }
  }
  const auto hdr_written =
      SSL_write(verifier, hdr_arr.data(), static_cast<int>(hdr_arr.size()));
  RETURN_FALSE_IF_SSL_FAILED(hdr_written, hdr_arr.size());

  std::vector<uint8_t> ct(nbatches * N * 16, 0);
  for (size_t batch = 0; batch < nbatches; batch++) {
    EmpWrapperAG2PCConstants::AESEncBatchCircuitIn in{};
    in.key = ssl->client_key_share;

    for (unsigned j = 0; j < N; j++) {
      const size_t idx = batch * N + j;
      // Tail padding reuses the last real counter so the equality gate still
      // passes; those blocks are discarded by the truncation below.
      const size_t src = (idx < nblocks) ? idx : nblocks - 1;
      // GCM counters within a record start at 2: J0 = nonce || 1 is consumed
      // by the tag.
      SurfBlockMap::ctr_block(ssl->client_iv.data() + 4, seq,
                              static_cast<uint32_t>(src) + 2, in.ctr[j]);
      OPENSSL_memcpy(in.pt[j].data(), inner.data() + idx * 16, 16);
    }

    EmpWrapperAG2PCConstants::AESEncBatchCircuitOut out{};
    if (!run_aes_enc_batch_circuit(in, out, ssl->aes_enc_circuit)) {
      return false;
    }
    if (!out.ok) {
      return false;  // the parties disagreed on a counter block
    }
    for (unsigned j = 0; j < N; j++) {
      OPENSSL_memcpy(ct.data() + (batch * N + j) * 16, out.ct[j].data(), 16);
    }
  }
  ct.resize(pt_len);

  // TLS 1.3 AAD is the record header as it goes on the wire.
  const size_t record_len = pt_len + 16;
  std::array<uint8_t, 5> aad{SSL3_RT_APPLICATION_DATA, 0x03, 0x03,
                             static_cast<uint8_t>(record_len >> 8),
                             static_cast<uint8_t>(record_len & 0xff)};

  // GCM_TAG || u16 aad_len || aad || u32 ct_len. The verifier already holds the
  // ciphertext from the encryption circuit's public output, so we do not resend
  // it; it needs only the AAD and the true length to truncate its copy.
  const auto tag_msg_size = sizeof(Messaging::MessageHeaders) +
                            sizeof(uint16_t) + aad.size() + sizeof(uint32_t);
  bssl::Array<uint8_t> tag_msg;
  {
    bssl::ScopedCBB cbb;
    if (!tag_msg.Init(tag_msg_size) || !CBB_init(cbb.get(), tag_msg_size) ||
        !CBB_add_u8(cbb.get(),
                    static_cast<uint8_t>(Messaging::MessageHeaders::GCM_TAG)) ||
        !CBB_add_u16(cbb.get(), static_cast<uint16_t>(aad.size())) ||
        !CBB_add_bytes(cbb.get(), aad.data(), aad.size()) ||
        !CBB_add_u32(cbb.get(), static_cast<uint32_t>(pt_len)) ||
        !CBBFinishArray(cbb.get(), &tag_msg)) {
      return false;
    }
  }
  const auto tag_written =
      SSL_write(verifier, tag_msg.data(), static_cast<int>(tag_msg.size()));
  RETURN_FALSE_IF_SSL_FAILED(tag_written, tag_msg.size());

  EmpWrapperAG2PCConstants::GCMTagCircuitIn tag_in{};
  tag_in.key_share = ssl->client_key_share;

  // J0 = (client_iv XOR seq) || 0x00000001.
  SurfBlockMap::ctr_block(ssl->client_iv.data() + 4, seq, 1, tag_in.iv);

  // tau_c: local, since GHASH is linear in the H-powers.
  if (!GHash::share(ssl->cgcm_share,
                    bssl::MakeConstSpan(aad.data(), aad.size()),
                    bssl::MakeConstSpan(ct.data(), ct.size()),
                    tag_in.tag_share)) {
    return false;
  }

  // One-time mask: the circuit reveals tau XOR mask, so BOB never sees tau.
  Util::generate_random_bytes<16>(tag_in.mask_or_unused.data());

  EmpWrapperAG2PCConstants::GCMTagCircuitOut tag_out{};
  if (!run_gcm_tag_circuit(tag_in, tag_out, ssl->gcm_tag_circuit)) {
    return false;
  }
  if (tag_out.cheated) {
    return false;  // the parties supplied different J0
  }
  std::array<uint8_t, 16> tag{};
  for (unsigned i = 0; i < 16; i++) {
    tag[i] = tag_out.tag[i] ^ tag_in.mask_or_unused[i];
  }

  if (!record_out.Init(aad.size() + ct.size() + tag.size())) {
    return false;
  }
  std::copy(aad.cbegin(), aad.cend(), record_out.begin());
  std::copy(ct.cbegin(), ct.cend(), record_out.begin() + aad.size());
  std::copy(tag.cbegin(), tag.cend(),
            record_out.begin() + aad.size() + ct.size());
  return true;
}

// The 3PC
bool ThreePartyHandshake::three_party_handshake_comm(SSL *ssl,
                                                     bssl::SSL_HANDSHAKE *hs) {

  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // If there's no verifier, then we have to bail.
  if (!ssl || ssl->verifier == nullptr || !hs) {
    return false;
  }

  // Similarly, we shouldn't expect this code to run on a server.
  if (SSL_is_server(ssl)) {
    return false;
  }

  // This is primarily because later on we'll overwrite these key bytes without
  // overwriting the other parts of the key.
  ssl->key_store.CopyFrom(hs->key_share_bytes);

  // By the time this function has been called the key shares are already in an
  // array format that can be used and serialised: so, we'll just use that.
  bssl::Array<uint8_t> key_share_packed;
  if (!Messaging::pack_key_bytes(Messaging::MessageHeaders::COLLECT,
                                 hs->key_share_bytes, key_share_packed)) {
    return false;
  }

  auto verifier = ssl->verifier;
  // NOTE: this cast is fine. This is because:
  // 1) SSL3_RT_MAX_PLAIN_LENGTH is much less than the maximum positive value
  // stored in an int on all systems. See
  // https://www.open-std.org/JTC1/SC22/WG14/www/docs/n1256.pdf for INT_MAX.
  // Whilst this is from the C standard, C++ draws on this fact. 2) We know that
  // SSL3_RT_MAX_PLAIN_LENGTH is the maximum value we'll pass here because of
  // the check above.
  const auto amount_written =
      SSL_write(verifier, key_share_packed.data(),
                static_cast<int>(key_share_packed.size()));
  // It is, of course, possible this write will fail.
  // However, if there's a handshake on the verifier that has yet to go through
  // this will still work: the handshake will go through in the background.
  RETURN_FALSE_IF_SSL_FAILED(amount_written, key_share_packed.size());

  // Circuit preprocessing (offline phase). This is a no-op here if the prover
  // already ran it before opening the origin connection (the normal benchmark
  // path), which keeps the origin TCP connection from idling open across the
  // WAN MPC. If it was not run earlier it still runs inline here so any caller
  // that did not preprocess offline keeps working.
  if (!preprocess_circuits(ssl)) {
    return false;
  }

  // Now we'll need to read the response from the verifier.
  // We re-use the packed array for this, so we'll stash the size.
  const auto expected_size = key_share_packed.size();
  const auto amount_read = SSL_read(verifier, key_share_packed.data(),
                                    static_cast<int>(expected_size));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, expected_size);

  bssl::Array<uint8_t> new_key_bytes;
  Messaging::MessageHeaders header;
  if (!Messaging::unpack_key_bytes(header, key_share_packed, new_key_bytes)) {
    return false;
  }

  if (header != Messaging::MessageHeaders::OK) {
    return false;
  }

  // new_key_bytes is in exactly the format we want for sending on to the
  // server. So, we just copy it over.
  if (!hs->key_share_bytes.CopyFrom(new_key_bytes)) {
    return false;
  }

  // NOTE: in some testing situations we want to bail here.
  // We'll do that if the "thrower" is set.
  if (ssl->thrower &&
      ssl->throw_state == static_cast<uint8_t>(Messaging::MessageHeaders::OK)) {
    // Tidy up the used memory.
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::derive_handshake_secret(
    bssl::SSL_HANDSHAKE *hs, SSL *ssl, bssl::Array<uint8_t> &secret) {
  if (!hs || !ssl || secret.size() == 0 || SSL_is_server(ssl) ||
      !ssl->verifier) {
    return false;
  }

  // All we have to do here is the regular ECtF functionality.
  // This is already provided for us in the ECtF namespace: all we really need
  // to do is to send a message saying that we're ready, and then we can call
  // into the ECtF routines.
  // Note: we have the secrets stored in `secret` (the x secret) and
  // `y_key_store` of the ssl object.

  // This is just an abbreviation.
  auto verifier = ssl->verifier;

  constexpr static auto header = Messaging::MessageHeaders::DO_ECTF;
  static_assert(sizeof(Messaging::MessageHeaders) == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // Handshake-mode flag, sent ahead of DO_ECTF in the same record. The verifier
  // needs it before KS_WAIT (do_ks feeds a zero PSK share on a full handshake
  // and its real share on a resumed one), which is earlier than the KS_DONE
  // point where the flag used to be sent. session_reused is final here:
  // ServerHello has been processed by the time this callback fires.
  const auto mode = ssl->s3->session_reused
                        ? Messaging::MessageHeaders::HS_MODE_RESUMED
                        : Messaging::MessageHeaders::HS_MODE_FULL;

  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!CBB_init(cbb.get(), 2 * sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(mode)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  const auto amount_written =
      SSL_write(verifier, write_to.data(), 2 * sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, 2 * sizeof(uint8_t));

  // Now we'll drop right into the ECtF functionality. We'll play the prover.
  if (!ECtF::ectf(ssl->x_key_store, verifier, secret, ssl->y_key_store,
                  hs->new_session->group_id, false)) {
    return false;
  }

  // As a side effect, we'll now mark which of the circuits we've set up is
  // actually the correct one. We delete the incorrect one, freeing any memory.
  if (ssl->should_make_circuits) {
    if (hs->new_session->group_id == SSL_CURVE_SECP256R1) {
      std::swap(ssl->ks_circuit, ssl->handshake_circuit_a);
      delete ssl->handshake_circuit_b;
    } else if (hs->new_session->group_id == SSL_CURVE_SECP384R1) {
      std::swap(ssl->ks_circuit, ssl->handshake_circuit_b);
      delete ssl->handshake_circuit_a;
    } else {
      return false;
    }
  }

  // Now we can just check that it worked via the header we receive.
  if (!is_correct_header<Messaging::MessageHeaders::ECTF_DONE>(verifier)) {
    return false;
  }

  // And now check if we need to bail.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::ECTF_DONE)) {
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}


bool ThreePartyHandshake::derive_handshake_keys(bssl::SSL_HANDSHAKE *hs,
                                                SSL *ssl,
                                                bssl::Array<uint8_t> &secret) {
  // Preconditions: it has to be the verifier.
  if (!hs || !ssl || secret.size() == 0 || SSL_is_server(ssl) ||
      !ssl->verifier) {
    return false;
  }

  // Just an alias
  auto verifier = ssl->verifier;

  const auto group_id = hs->new_session->group_id;
  assert(group_id != 0);

  // We don't support these curves at present.
  // Adding support for SECP224R1 just requires us to make a couple of new
  // circuits: the other two are far harder.
  // Of the KEM ones, I don't even have an idea.
  if (group_id == SSL_CURVE_X25519 ||
      group_id == SSL_GROUP_X25519_MLKEM768 ||
      group_id == SSL_GROUP_X25519_KYBER768_DRAFT00) {
    return false;
  }

  // We can just call the Circuit derivation routine directly.
  // Note that this function needs the hash to be passed in by us.
  EmpWrapperAG2PCConstants::HandshakeCircuitIn input{};

  if (!Util::get_hash(&hs->transcript, input.hash) ||
      !input.key_share.CopyFrom(bssl::Span(
          ssl->x_key_store.data(), ssl->x_key_store.size()))
      ) {
    return false;
  }

  // Resumed: the PSK stays secret-shared. Both parties feed their share and the
  // circuit derives ES then dES internally, so neither side ever holds the PSK
  // Full: no PSK, so dES is the fixed constant and the share is zero.
  input.psk_share = ssl->s3->session_reused
                        ? ssl->psk_share
                        : decltype(ssl->psk_share){};

  EmpWrapperAG2PCConstants::HandshakeCircuitOut output;

  // NOTE: We wrap the underlying circuit in a unique_ptr so that it is always
  // deleted when this function exits, even if due to an exception.
  auto circuit = std::unique_ptr<EmpWrapperAG2PC>(ssl->ks_circuit);
  ssl->ks_circuit = nullptr;

  if (!ThreePartyHandshake::run_handshake_circuit(input, output, circuit.get(),
                                                  false)) {
    return false;
  }

  // N.B If you ever want to change this program to support larger than 128 bit
  // secrets, you'll need to modify the definitions in the SSL struct.
  // NOTE: the +4 here is because the AES IV is 12 bytes initially, before being
  // expanded into 16 bytes by another circuit.
  std::copy(output.iv.cbegin(), output.iv.cend(), ssl->shs_iv.begin() + 4);

  ssl->ms_share = output.MS_share;
  ssl->dhs_share = output.dHS_share;
  ssl->fk_s = output.fk_s;
  ssl->server_key_share = output.server_key_share;
  ssl->shts_share = output.SHTS_share;
  ssl->chts_share = output.CHTS_share;

  // Now wait for the header.
  if (!is_correct_header<Messaging::MessageHeaders::KS_DONE>(verifier)) {
    return false;
  }

  // If we need to bail, bail.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::KS_DONE)) {
    delete_circuits(ssl);
    // N.B The C++ standard guarantees that all destructors are called here, so
    // this is fine.
    ssl->thrower();
  }

  return true;
}

template <unsigned long size, bool verifier>
static bool run_handshake_circuit_internal(
    EmpWrapperAG2PC *const circuit,
    const EmpWrapperAG2PCConstants::HandshakeCircuitIn &in,
    EmpWrapperAG2PCConstants::HandshakeCircuitOut &out) noexcept {

  std::array<uint8_t, size> in_arr{};
  unsigned pos{};

  // We assume that we're using SHA-256 here.
  static constexpr auto hash_size = 32;
  static constexpr auto psk_share_size = 16;

  std::copy(in.psk_share.cbegin(), in.psk_share.cend(), in_arr.begin());
  pos += psk_share_size;

  // Alice-only inputs (verifier leaves them zero): dES first, then the
  // transcript hash. This must match the wire-feed order in
  // ProduceCombinedCircuit (DeriveCircuits.cpp).
  if (!verifier) {
    std::copy(in.hash.cbegin(), in.hash.cend(), in_arr.begin() + pos);
  }

  // Move forward in the buffer. We'll do this until the end to make sure we've
  // actually written properly.
  pos += hash_size;

  // First we need to generate the randomness. We'll do this in the
  // output buffer and then copy over.
  Util::generate_random_bytes<EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE>(
      out.xor_mask);

  std::copy(out.xor_mask.cbegin(), out.xor_mask.cend(), in_arr.begin() + pos);
  pos += static_cast<unsigned>(EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE);

  assert(pos == hash_size + psk_share_size +
                    EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE);

  BIGNUM *b = BN_new();

  // Our input circuits expect a little-endian input representation; thus, we
  // need to convert.
  if (!b || !BN_bin2bn(in.key_share.data(), in.key_share.size(), b) ||
      !BN_bn2le_padded(in_arr.data() + pos, in.key_share.size(), b)) {
    return false;
  }

  BN_free(b);

  // This cast is fine because the size can only correspond to a small secret
  // (256 bits, 384 bits etc).
  pos += static_cast<unsigned>(in.key_share.size());

  // We should have filled the whole array.
  assert(pos == in_arr.size());

  std::array<uint8_t, EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE>
      out_arr{};
  // SURF: This is the important "online" call, but it just calls a 2pc garbled functionality
  // based on the size of "out_arr"
  // The "in_arr" has the hash.
  if (!circuit->derive_hs(in_arr, out_arr)) {
    return false;
  }

  // With the circuit done, the output depends on the caller.
  // If the caller is the prover/verifier, then they get the lower/upper 16
  // bytes of each 32 byte chunk up to the 160th byte. After that lives the
  // IV/key depending on the caller.
  unsigned offset = (verifier) ? 16 : 0;

  auto copy_func = [&](auto &dest, const unsigned inc) {
    std::copy(out_arr.cbegin() + offset,
              out_arr.cbegin() + offset + dest.size(), dest.begin());
    offset += inc;
  };

  // This assigns the handshake keys
  // Each secret is half of the hash_size in size, since these are all evenly
  // split. However, the step size is exactly the same as hash_size.
  copy_func(out.dHE_share, hash_size);
  copy_func(out.CHTS_share, hash_size); // 32
  copy_func(out.SHTS_share, hash_size); // 64
  copy_func(out.dHS_share, hash_size);  // 96
  copy_func(out.MS_share, hash_size);   // 128
                                      // Offset here will be 160 for the prover
                                      // and 176 for the verifier, because of
  // the post increase. All of the bytes below 160 have been used, but those
  // after 160 haven't been touched.
  assert(offset == static_cast<unsigned>(160 + (verifier * 16)));

  // Reset the offset, so that we can actually copy the right bits.
  offset = 160;
  copy_func(out.fk_s, hash_size);

  // The next 128 bits are the AES key, always.
  // If the caller is the prover, then their output is just the
  // mask they fed in.
  copy_func(out.server_key_share, 16);

  // Now we need to copy over the IV, and then we should be done.
  copy_func(out.iv, 12);

  // We should be right at the end of the buffer.
  assert(offset == EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE);

  // Now we need to apply the xor against each of the secrets to recover their
  // original values.
  unsigned mask_offset = 0;

  // N.B all secrets are 16 bytes here so we're fine.
  auto xor_func = [&](auto &dest,
                      const unsigned xor_size = sizeof(decltype(dest))) {
    for (unsigned i = 0; i < xor_size; i++) {
      dest[i] ^= out.xor_mask[i + mask_offset];
    }
    mask_offset += static_cast<unsigned>(xor_size);
  };

  xor_func(out.dHE_share);
  xor_func(out.CHTS_share);
  xor_func(out.SHTS_share);
  xor_func(out.dHS_share);
  xor_func(out.MS_share);

  // We don't need to do the mask portion.
  // mask_offset should be the HANDSHAKE_MASK_SIZE minus the mask that's for the
  // key.
  assert(mask_offset == EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE -
                            sizeof(out.server_key_share));

  // We're all done.
  return true;
}

bool ThreePartyHandshake::run_handshake_circuit(
    const EmpWrapperAG2PCConstants::HandshakeCircuitIn &in,
    EmpWrapperAG2PCConstants::HandshakeCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  // Really only one precondition here, which is that the circuit exists to prevent
  // NULL ptr.
  if (!circuit)
    return false;

  // Because the input arguments to the circuit functions are templates,
  // we dispatch here based on the circuit's size.
  switch (circuit->get_size()) {
  case 256:
    if (verifier) {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE, true>(
          circuit, in, out);
    } else {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE, false>(
          circuit, in, out);
    }
  case 384:
    if (verifier) {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_384_IN_SIZE, true>(
          circuit, in, out);
    } else {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_384_IN_SIZE, false>(
          circuit, in, out);
    }
  default:
    return false;
  }
}

template <bool is_verifier>
static bool run_traffic_circuit_internal(
    const EmpWrapperAG2PCConstants::TrafficCircuitIn &in,
    EmpWrapperAG2PCConstants::TrafficCircuitOut &out,
    EmpWrapperAG2PC *const circuit) {
  // Input: ms share 16 || hash 32 (ALICE only) || mask 64.
  EmpWrapperAG2PCConstants::derive_ts_input_type input{};
  unsigned offset{};
  std::copy(in.ms_share.begin(), in.ms_share.end(), input.begin());
  offset += sizeof(in.ms_share);
  if (!is_verifier) {
    std::copy(in.hash.cbegin(), in.hash.cend(), input.begin() + offset);
  }
  offset += sizeof(in.hash);

  Util::generate_random_bytes<EmpWrapperAG2PCConstants::TRAFFIC_MASK_SIZE>(
      input.data() + offset);
  std::copy(input.cbegin() + offset, input.cend(), out.xor_mask.begin());
  assert(offset + out.xor_mask.size() ==
         EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_IN_SIZE);

  EmpWrapperAG2PCConstants::derive_ts_output_type output;
  if (!circuit->derive_ts(input, output)) {
    return false;
  }

  // Output: cts 16 || ctiv 12 || sts 16 || stiv 12 || cats 32 || sats 32.
  // Keys: ALICE's share is her mask, BOB's is the revealed value. IVs public.
  // CATS/SATS: split shares, ALICE lo half under mask[32..48)/[48..64), BOB hi
  // half under the same offsets of BOB's own mask.
  std::copy(output.cbegin() + 16, output.cbegin() + 28, out.client_iv.begin());
  std::copy(output.cbegin() + 44, output.cbegin() + 56, out.server_iv.begin());
  if (!is_verifier) {
    std::copy(out.xor_mask.cbegin(), out.xor_mask.cbegin() + 16,
              out.client_key_share.begin());
    std::copy(out.xor_mask.cbegin() + 16, out.xor_mask.cbegin() + 32,
              out.server_key_share.begin());
  } else {
    std::copy(output.cbegin(), output.cbegin() + 16, out.client_key_share.begin());
    std::copy(output.cbegin() + 28, output.cbegin() + 44,
              out.server_key_share.begin());
  }
  const unsigned half = is_verifier ? 16 : 0;
  for (unsigned i = 0; i < 16; i++) {
    out.CATS_share[i] = output[56 + half + i] ^ out.xor_mask[32 + i];
    out.SATS_share[i] = output[88 + half + i] ^ out.xor_mask[48 + i];
  }
  return true;
}

bool ThreePartyHandshake::run_traffic_circuit(
    const EmpWrapperAG2PCConstants::TrafficCircuitIn &in,
    EmpWrapperAG2PCConstants::TrafficCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {

  if (!circuit) {
    return false;
  }

  if (verifier) {
    return run_traffic_circuit_internal<true>(in, out, circuit);
  } else {
    return run_traffic_circuit_internal<false>(in, out, circuit);
  }
}

// SURF
template <bool is_verifier>
static bool run_resumption_circuit_internal(
    const EmpWrapperAG2PCConstants::ResumptionCircuitIn &in,
    EmpWrapperAG2PCConstants::ResumptionCircuitOut &out,
    EmpWrapperAG2PC *const circuit) {

  // This function simply calls into the garbled circuit after appropriately
  // copying over the relevant input bits.
  EmpWrapperAG2PCConstants::derive_res_input_type input{};
  unsigned pos{};

  // Both parties feed in their share of MS.
  std::copy(in.ms_share.begin(), in.ms_share.end(), input.begin());
  pos += sizeof(in.ms_share);

  if (!is_verifier) {
    // Copy over the hash input (with CF). Notably, the verifier does not do this as they
    // do not hold anything useful here.
    std::copy(in.hash.cbegin(), in.hash.cend(), input.begin() + pos);
  }

  // Both parties need to move forward.
  pos += sizeof(in.hash);

  // Generate the random mask too for both parties.
  Util::generate_random_bytes<sizeof(uint8_t) *
                              EmpWrapperAG2PCConstants::RESUMPTION_MASK_SIZE>(
      input.data() + pos);

  std::copy(input.cbegin() + pos, input.cend(), out.xor_mask.begin());

  // Call into the circuit.
  EmpWrapperAG2PCConstants::derive_res_output_type output; // 32
  if (!circuit->derive_res(input, output)) {
    return false;
  }

  // With the circuit done, the output depends on the caller.
  // If the caller is the prover/verifier, then they get the lower/upper 16
  // bytes of the 32 byte chunk.
  unsigned offset = (is_verifier) ? 16 : 0;

  auto copy_func = [&](auto &dest, const unsigned inc) {
    std::copy(output.cbegin() + offset,
              output.cbegin() + offset + dest.size(), dest.begin());
    offset += inc;
  };

  static constexpr auto rms_size = 16;
  copy_func(out.RMS_share, rms_size);   // 16

  // Now we need to apply the xor against each of the secrets to recover their
  // original values.
  unsigned mask_offset = 0;

  // N.B all secrets are 16 bytes here so we're fine.
  auto xor_func = [&](auto &dest,
                      const unsigned xor_size = sizeof(decltype(dest))) {
    for (unsigned i = 0; i < xor_size; i++) {
      dest[i] ^= out.xor_mask[i + mask_offset];
    }
    mask_offset += static_cast<unsigned>(xor_size);
  };

  xor_func(out.RMS_share);

  assert(mask_offset == EmpWrapperAG2PCConstants::RESUMPTION_MASK_SIZE);

  return true;
}

bool ThreePartyHandshake::derive_resumption_keys(bssl::SSL_HANDSHAKE *hs,
                                                SSL *ssl) {
  // Preconditions: it has to be the verifier.
  if (!hs || !ssl || SSL_is_server(ssl) ||
      !ssl->verifier) {
    return false;
  }

  // Just an alias
  auto verifier = ssl->verifier;

  // N.B. Unlike derive_psk_keys (fired once per NewSessionTicket), this callback
  // is fired exactly once per handshake (tls13_client.cc, server-Finished
  // processing), so there is no multi-ticket double-fire to guard against here.

  // We signal that we're ready to derive resumption. This is just a single
  // header that we have to write.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");


  // We have to make the header a big-endian value. You know, for compatibility.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!write_to.Init(sizeof(uint8_t))) {
    return false;
  }

  constexpr static auto header = Messaging::MessageHeaders::DERIVE_RES;

  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  // Now just write it.
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));

  // We can just call the circuit derivation routine directly.
  // Note that this function needs the hash to be passed in by us.
  EmpWrapperAG2PCConstants::ResumptionCircuitIn input{};
  input.ms_share = ssl->ms_share;
  // We can fetch the hash directly.
  if (!Util::get_hash(&hs->transcript, input.hash)) {
    return false;
  }

  EmpWrapperAG2PCConstants::ResumptionCircuitOut output;

  // NOTE: We wrap the underlying circuit in a unique_ptr so that it is always
  // deleted when this function exits, even if due to an exception.
  // We load the offline
  auto circuit = std::unique_ptr<EmpWrapperAG2PC>(ssl->resumption_circuit);
  // Prevent double-free.
  // TODO: I'm not sure we need this
  ssl->resumption_circuit = nullptr;

  if (!ThreePartyHandshake::run_resumption_circuit(input, output, circuit.get(),
                                                  false)) {
    return false;
  }

  ssl->rms_share = output.RMS_share;

  // Wait for the verifier to signal that resumption derivation is complete.
  // Without this read, the RES_DONE byte sits in the receive buffer and
  // corrupts the subsequent PSK circuit communication.
  if (!is_correct_header<Messaging::MessageHeaders::RES_DONE>(verifier)) {
    return false;
  }

  // If we need to bail, bail.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::RES_DONE)) {
    delete_circuits(ssl);
    // N.B The C++ standard guarantees that all destructors are called here, so
    // this is fine.
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::run_resumption_circuit(
    const EmpWrapperAG2PCConstants::ResumptionCircuitIn &in,
    EmpWrapperAG2PCConstants::ResumptionCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  if (!circuit) {
    return false;
  }

  if (verifier) {
    return run_resumption_circuit_internal<true>(in, out, circuit);
  } else {
    return run_resumption_circuit_internal<false>(in, out, circuit);
  }
}

// SURF
// Templated on the input struct (PskCircuitIn / PskCircuitIn8) and matching
// serialized array type (derive_psk_input_type / _8) so the 1-byte and 8-byte
// ticket_nonce variants share one body: the nonce-dependent offsets all flow
// from sizeof(in.ticket_nonce) and input.size().
template <bool is_verifier, typename InStruct, typename InArray>
static bool run_psk_circuit_internal(
    const InStruct &in,
    EmpWrapperAG2PCConstants::PskCircuitOut &out,
    EmpWrapperAG2PC *const circuit) {

  // This function simply calls into the garbled circuit after appropriately
  // copying over the relevant input bits.
  InArray input{};
  unsigned pos{};

  // Both parties feed in their share of RMS.
  std::copy(in.rms_share.begin(), in.rms_share.end(), input.begin());
  pos += sizeof(in.rms_share);

  if (!is_verifier) {
    // Copy over the hash input and nonce. Notably, the verifier does not do this as they
    // do not hold anything useful here.
    std::copy(in.ticket_nonce.cbegin(), in.ticket_nonce.cend(), input.begin() + pos);
  }

  // Both parties need to move forward.
  pos += in.ticket_nonce.size();

  // Generate the random mask too for both parties.
  Util::generate_random_bytes<sizeof(uint8_t) *
                              EmpWrapperAG2PCConstants::PSK_MASK_SIZE>(
      input.data() + pos);
  std::copy(input.cbegin() + pos, input.cend(), out.xor_mask.begin());

  assert(pos + out.xor_mask.size() == input.size());

  // Call into the circuit.
  EmpWrapperAG2PCConstants::derive_psk_output_type output;
  if (!circuit->derive_psk(input, output)) {
    return false;
  }

  // With the circuit done, the output depends on the caller.
  // If the caller is the prover/verifier, then they get the lower/upper 16
  // bytes of the 32 byte chunk.
  unsigned offset = (is_verifier) ? 16 : 0;

  auto copy_func = [&](auto &dest, const unsigned inc) {
    std::copy(output.cbegin() + offset,
              output.cbegin() + offset + dest.size(), dest.begin());
    offset += inc;
  };

  static constexpr auto psk_share_size = 16;
  copy_func(out.PSK_share, psk_share_size);

  // Now we need to apply the xor against each of the secrets to recover their
  // original values.
  unsigned mask_offset = 0;

  // N.B all secrets are 16 bytes here so we're fine.
  auto xor_func = [&](auto &dest,
                      const unsigned xor_size = sizeof(decltype(dest))) {
    for (unsigned i = 0; i < xor_size; i++) {
      dest[i] ^= out.xor_mask[i + mask_offset];
    }
    mask_offset += static_cast<unsigned>(xor_size);
  };

  xor_func(out.PSK_share);

  assert(mask_offset == EmpWrapperAG2PCConstants::PSK_MASK_SIZE);

  return true;
}

bool ThreePartyHandshake::derive_psk_keys(SSL *ssl) {
  // Preconditions: it has to be the verifier.
  if (!ssl || SSL_is_server(ssl) ||
      !ssl->verifier) {
    return false;
  }

  // Just an alias
  auto verifier = ssl->verifier;

  // Guard against multiple NewSessionTickets. BoringSSL fires this callback
  // once per NST (cutler.pl sends two), but the SURF PSK can only be derived
  // once: the first invocation consumes ssl->psk_circuit (set to nullptr below)
  // and runs the single matching DERIVE_PSK MPC session with the verifier. A
  // later invocation finds the circuit already null and must no-op *before*
  // writing the DERIVE_PSK header — otherwise it emits a stray DERIVE_PSK byte
  // the verifier never reads (it walks DERIVE_PSK exactly once), desynchronising
  // the lock-step stream over a real network.
  //
  // We return true (not false): returning false would make
  // tls13_process_new_session_ticket fail, surfacing as an SSL_read error mid
  // post-handshake. The resumption session is kept consistent with the derived
  // PSK on the benchmark side instead: new_session_cb captures only the FIRST
  // ticket's session (the one whose PSK we derived here), so later tickets are
  // harmlessly ignored.
  if (!ssl->psk_circuit && !ssl->psk_circuit_8  && !ssl->psk_circuit_0) {
    // Fired again after the PSK was already derived (a later NewSessionTicket).
    // Both circuits are consumed together on the first firing, so if both are
    // gone the PSK for ticket #1 is already in hand. Harmless no-op.
    return true;
  }

  // The PSK derivation is HKDF-Expand-Label(RMS, "resumption", ticket_nonce,
  // 32), and the nonce is baked (length-prefixed) into the HkdfLabel inside the
  // garbled circuit, so the circuit's nonce width must match the server's
  // exactly. We pre-derived two circuits (1-byte: LiteSpeed/BoringSSL; 8-byte:
  // OpenSSL/nginx) and pick the matching one here, telling the verifier which to
  // run via DERIVE_PSK vs DERIVE_PSK_8. Any other width is unsupported: fail
  // loudly rather than derive a silently-wrong PSK (which the origin would
  // reject as a bad binder).
  const size_t nonce_len = ssl->ticket_nonce.size();
  Messaging::MessageHeaders header;
  if (nonce_len == 0) {
    header = Messaging::MessageHeaders::DERIVE_PSK_0;
  } else if (nonce_len == 1) {
    header = Messaging::MessageHeaders::DERIVE_PSK;
  } else if (nonce_len == 8) {
    header = Messaging::MessageHeaders::DERIVE_PSK_8;
  } else {
    std::cerr << "[Prover] unsupported ticket_nonce width " << nonce_len
              << " (circuits exist for 0, 1 and 8)\n";
    return false;
  }

  // We signal that we're ready to derive psk. This is just a single
  // header that we have to write.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We have to make the header a big-endian value. You know, for compatibility.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!write_to.Init(sizeof(uint8_t))) {
    return false;
  }

  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  // Now just write it.
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));

  // NOTE: We wrap both underlying circuits in unique_ptrs so they are always
  // deleted when this function exits (the unused one included), even on an
  // exception. Both are consumed here so the multi-ticket guard above latches.
  auto circuit = std::unique_ptr<EmpWrapperAG2PC>(ssl->psk_circuit);
  auto circuit_8 = std::unique_ptr<EmpWrapperAG2PC>(ssl->psk_circuit_8);
  auto circuit_0 = std::unique_ptr<EmpWrapperAG2PC>(ssl->psk_circuit_0);

  ssl->psk_circuit = nullptr;
  ssl->psk_circuit_8 = nullptr;
  ssl->psk_circuit_0 = nullptr;

  // Call into the matching circuit derivation routine.
  EmpWrapperAG2PCConstants::PskCircuitOut output;

  if (nonce_len == 0) {
    EmpWrapperAG2PCConstants::PskCircuitIn0 input{};
    input.rms_share = ssl->rms_share;
    if (!ThreePartyHandshake::run_psk_circuit_0(input, output,
                                                circuit_0.get(), false)) {
      return false;
    }
  } else if (nonce_len == 1) {
    EmpWrapperAG2PCConstants::PskCircuitIn input{};
    input.rms_share = ssl->rms_share;
    std::copy(ssl->ticket_nonce.begin(), ssl->ticket_nonce.end(),
              input.ticket_nonce.begin());
    if (!ThreePartyHandshake::run_psk_circuit(input, output, circuit.get(),
                                              false)) {
      return false;
    }
  } else {
    EmpWrapperAG2PCConstants::PskCircuitIn8 input{};
    input.rms_share = ssl->rms_share;
    std::copy(ssl->ticket_nonce.begin(), ssl->ticket_nonce.end(),
              input.ticket_nonce.begin());
    if (!ThreePartyHandshake::run_psk_circuit_8(input, output, circuit_8.get(),
                                                false)) {
      return false;
    }
  }

  ssl->psk_share = output.PSK_share;

  // Wait for the verifier to signal that PSK derivation is complete.
  // Without this read, the PSK_DONE byte sits in the receive buffer.
  if (!is_correct_header<Messaging::MessageHeaders::PSK_DONE>(verifier)) {
    return false;
  }

  // If we need to bail, bail.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::PSK_DONE)) {
    delete_circuits(ssl);
    // N.B The C++ standard guarantees that all destructors are called here, so
    // this is fine.
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::run_psk_circuit(
    const EmpWrapperAG2PCConstants::PskCircuitIn &in,
    EmpWrapperAG2PCConstants::PskCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  if (!circuit) {
    return false;
  }

  using InStruct = EmpWrapperAG2PCConstants::PskCircuitIn;
  using InArray = EmpWrapperAG2PCConstants::derive_psk_input_type;
  if (verifier) {
    return run_psk_circuit_internal<true, InStruct, InArray>(in, out, circuit);
  } else {
    return run_psk_circuit_internal<false, InStruct, InArray>(in, out, circuit);
  }
}

bool ThreePartyHandshake::run_psk_circuit_8(
    const EmpWrapperAG2PCConstants::PskCircuitIn8 &in,
    EmpWrapperAG2PCConstants::PskCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  if (!circuit) {
    return false;
  }

  using InStruct = EmpWrapperAG2PCConstants::PskCircuitIn8;
  using InArray = EmpWrapperAG2PCConstants::derive_psk_input_type_8;
  if (verifier) {
    return run_psk_circuit_internal<true, InStruct, InArray>(in, out, circuit);
  } else {
    return run_psk_circuit_internal<false, InStruct, InArray>(in, out, circuit);
  }
}

bool ThreePartyHandshake::run_psk_circuit_0(
    const EmpWrapperAG2PCConstants::PskCircuitIn0 &in,
    EmpWrapperAG2PCConstants::PskCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  if (!circuit) {
    return false;
  }
  using InStruct = EmpWrapperAG2PCConstants::PskCircuitIn0;
  using InArray = EmpWrapperAG2PCConstants::derive_psk_input_type_0;
  return verifier
             ? run_psk_circuit_internal<true, InStruct, InArray>(in, out, circuit)
             : run_psk_circuit_internal<false, InStruct, InArray>(in, out, circuit);
}

template <bool is_verifier>
static bool run_binder_circuit_internal(
    const EmpWrapperAG2PCConstants::BinderCircuitIn &in,
    EmpWrapperAG2PCConstants::BinderCircuitOut &out,
    EmpWrapperAG2PC *const circuit) {

  EmpWrapperAG2PCConstants::derive_binder_input_type input{};
  unsigned pos{};

  // Both parties feed their PSK share.
  std::copy(in.psk_share.cbegin(), in.psk_share.cend(), input.begin());
  pos += sizeof(in.psk_share);

  // Alice-only: the truncated-ClientHello hash.
  if (!is_verifier) {
    std::copy(in.ch_hash.cbegin(), in.ch_hash.cend(), input.begin() + pos);
  }
  pos += sizeof(in.ch_hash);
  assert(pos == input.size());

  EmpWrapperAG2PCConstants::derive_binder_output_type output;
  if (!circuit->derive_binder(input, output)) {
    return false;
  }

  // Public output: no mask, no split.
  std::copy(output.cbegin(), output.cend(), out.binder.begin());
  return true;
}

bool ThreePartyHandshake::run_binder_circuit(
    const EmpWrapperAG2PCConstants::BinderCircuitIn &in,
    EmpWrapperAG2PCConstants::BinderCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  if (!circuit) return false;
  return verifier ? run_binder_circuit_internal<true>(in, out, circuit)
                  : run_binder_circuit_internal<false>(in, out, circuit);
}

template <bool is_verifier>
static bool run_rotate_circuit_internal(
    const EmpWrapperAG2PCConstants::RotateCircuitIn &in,
    EmpWrapperAG2PCConstants::RotateCircuitOut &out,
    EmpWrapperAG2PC *const circuit) {
  // Input: secret share 16 || secret' mask 16 || key' mask 16 (ALICE only).
  EmpWrapperAG2PCConstants::derive_rotate_input_type input{};
  std::copy(in.secret_share.cbegin(), in.secret_share.cend(), input.begin());
  Util::generate_random_bytes<32>(out.xor_mask.data());
  std::copy(out.xor_mask.cbegin(), out.xor_mask.cbegin() + 16,
            input.begin() + 16);
  if (!is_verifier) {
    std::copy(out.xor_mask.cbegin() + 16, out.xor_mask.cend(),
              input.begin() + 32);
  }

  // Output: secret' 32 (lo^alice, hi^bob) || key'^alice_mask 16 || iv' 12.
  EmpWrapperAG2PCConstants::derive_rotate_output_type output{};
  if (!circuit->derive_rotate(input, output)) {
    return false;
  }
  const unsigned half = is_verifier ? 16 : 0;
  for (unsigned i = 0; i < 16; i++) {
    out.next_share[i] = output[half + i] ^ out.xor_mask[i];
    out.key_share[i] = is_verifier ? output[32 + i] : out.xor_mask[16 + i];
  }
  std::copy(output.cbegin() + 48, output.cend(), out.iv.begin());
  return true;
}

bool ThreePartyHandshake::run_rotate_circuit(
    const EmpWrapperAG2PCConstants::RotateCircuitIn &in,
    EmpWrapperAG2PCConstants::RotateCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  if (!circuit) {
    return false;
  }
  return verifier ? run_rotate_circuit_internal<true>(in, out, circuit)
                  : run_rotate_circuit_internal<false>(in, out, circuit);
}

// Installs placeholder write AEAD state. tls_set_write_state first flushes
// pending handshake data, so the queued KeyUpdate is sealed here, through
// surf_encrypt, under the key still in ssl->client_key_share; it then resets
// write_sequence. Call this BEFORE replacing the client key share.
static bool surf_reset_write_state(SSL *ssl) {
  const SSL_SESSION *session = SSL_get_session(ssl);
  if (!session) {
    return false;
  }
  auto ctx = bssl::SSLAEADContext::Create(
      evp_aead_seal, bssl::ssl_session_protocol_version(session),
      session->cipher, bssl::MakeConstSpan(ssl->client_key_share.data(), 16),
      {}, bssl::MakeConstSpan(ssl->client_iv.data() + 4, 12));
  if (!ctx) {
    return false;
  }
  return ssl->method->set_write_state(ssl, ssl_encryption_application,
                                      std::move(ctx), {});
}

bool ThreePartyHandshake::rotate_traffic_keys(SSL *ssl,
                                              enum evp_aead_direction_t dir) {
  if (!ssl || !ssl->verifier || ssl->surf_mode != Surf::Mode::Rotate ||
      !ssl->rotate_circuit || !ssl->gcm_circuit) {
    return false;
  }
  auto verifier = ssl->verifier;
  const bool is_write = (dir == evp_aead_seal);

  // Seal the pending KeyUpdate under the old key (AES_ENC || GCM_TAG on the
  // wire), then rotate. The verifier drains those before ROTATE_KEY.
  if (is_write) {
    if (!surf_reset_write_state(ssl)) {
      return false;
    }
    // set_write_state only seals the KeyUpdate into pending_flight; push it to
    // the origin now, or it waits for the next application write -- which in
    // a per-round flow never comes before we block on the response.
    if (ssl->method->flush(ssl) <= 0) {
      return false;
    }
  }

  const uint8_t msg[2] = {
      static_cast<uint8_t>(Messaging::MessageHeaders::ROTATE_KEY),
      static_cast<uint8_t>(is_write ? 0 : 1)};
  const auto written = SSL_write(verifier, msg, sizeof(msg));
  RETURN_FALSE_IF_SSL_FAILED(written, sizeof(msg));

  EmpWrapperAG2PCConstants::RotateCircuitIn in{};
  in.secret_share = is_write ? ssl->cats_share : ssl->sats_share;
  EmpWrapperAG2PCConstants::RotateCircuitOut out{};
  if (!run_rotate_circuit(in, out, ssl->rotate_circuit, false)) {
    return false;
  }

  auto &secret = is_write ? ssl->cats_share : ssl->sats_share;
  auto &key = is_write ? ssl->client_key_share : ssl->server_key_share;
  auto &iv = is_write ? ssl->client_iv : ssl->server_iv;
  auto &gcm = is_write ? ssl->cgcm_share : ssl->sgcm_share;
  secret = out.next_share;
  key = out.key_share;
  std::copy(out.iv.cbegin(), out.iv.cend(), iv.begin() + 4);

  // H = AES_k'(0) changed: fresh H-powers for the new key.
  if (!make_gcm_share_for(verifier, key, ssl->gcm_circuit, gcm, nullptr)) {
    return false;
  }

  // Read direction: the records are already captured, so there is no AEAD
  // state to reset; only the per-epoch commitment latches.
  if (!is_write) {
    ssl->surf_key_committed = false;
    ssl->surf_key_released = false;
  }
  return true;
}


// Runs the GCM tag-verification circuit. Input layout, 64 bytes, identical for
// both parties and matching DeriveGCMVerify in DeriveCircuits.cpp:
//   key_share (16) || iv (16) || tag_share (16) || server_tag (16)
//
// The circuit recovers k = k_c ^ k_v, computes AES.Enc(k, J0), XORs both
// parties' GHASH shares into it, and compares against the server tag. It also
// checks that both parties supplied the same IV and the same server tag; the
// verification bit is only meaningful when they did.
//
// Unlike the derivation circuits there is no Alice-only input and no split
// output, so there is no per-party variation: both sides call this identically.
//
// N.B. this is an amortized circuit, so only BOB (the verifier) evaluates the
// output; ALICE receives it over the wire from BOB (see exec_small_internal).
// The prover's copy of these bits is therefore not independently trustworthy —
// which is fine, since it is the verifier that needs to trust the result.
bool ThreePartyHandshake::run_gcm_vfy_circuit(
    const EmpWrapperAG2PCConstants::GCMVfyCircuitIn &in,
    EmpWrapperAG2PCConstants::GCMVfyCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept {
  if (!circuit) {
    return false;
  }

  EmpWrapperAG2PCConstants::aes_gcm_vfy_input_type input{};
  unsigned pos = 0;

  std::copy(in.key.cbegin(), in.key.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.iv.cbegin(), in.iv.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.tag_share.cbegin(), in.tag_share.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.server_tag.cbegin(), in.server_tag.cend(), input.begin() + pos);
  pos += 16;
  assert(pos == input.size());

  EmpWrapperAG2PCConstants::aes_gcm_vfy_output_type output{};
  if (!circuit->verify_tag(input, output)) {
    return false;
  }

  // The circuit fills each output byte with a repeated bit, so each byte is
  // 0x00 or 0xFF. Anything else means the stream desynced.
  if ((output[0] != 0x00 && output[0] != 0xFF) ||
      (output[1] != 0x00 && output[1] != 0xFF)) {
    return false;
  }

  out.tag_passed = (output[0] != 0);
  // The circuit's second output is 1 iff NEITHER party cheated, so the struct
  // field is its negation.
  out.cheated = (output[1] == 0);
  return true;
}

bool ThreePartyHandshake::run_gcm_vfy_commit_circuit(
    const EmpWrapperAG2PCConstants::GCMVfyCommitCircuitIn &in,
    EmpWrapperAG2PCConstants::GCMVfyCommitCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept {
  if (!circuit) {
    return false;
  }

  EmpWrapperAG2PCConstants::aes_gcm_vfy_commit_input_type input{};
  unsigned pos = 0;
  std::copy(in.key.cbegin(), in.key.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.iv.cbegin(), in.iv.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.tag_share.cbegin(), in.tag_share.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.server_tag.cbegin(), in.server_tag.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.r_k.cbegin(), in.r_k.cend(), input.begin() + pos);
  pos += 16;
  std::copy(in.d_k.cbegin(), in.d_k.cend(), input.begin() + pos);
  pos += 32;
  assert(pos == input.size());

  EmpWrapperAG2PCConstants::aes_gcm_vfy_commit_output_type output{};
  if (!circuit->verify_tag_commit(input, output)) {
    return false;
  }

  // Each output byte is a repeated bit; anything else means a desync.
  for (unsigned i = 0; i < 3; i++) {
    if (output[i] != 0x00 && output[i] != 0xFF) {
      return false;
    }
  }
  out.tag_passed = (output[0] != 0);
  out.cheated = (output[1] == 0);
  out.key_opened = (output[2] != 0);
  return true;
}

bool ThreePartyHandshake::commit_to_session_ticket(SSL *ssl, const uint8_t *data, size_t len) {
  if (!ssl) return false;

  SSL *verifier = ssl->verifier;
  if (!verifier) return false;

  // Send the encrypted session ticket blob to the verifier
  bssl::Array<uint8_t> tmp_buffer;
  constexpr auto hash_size = 32;
  const auto size = sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) + len + hash_size;
  if (!tmp_buffer.Init(size)) return false;

  // Hash of client_key_share || server_key_share
  bssl::ScopedEVP_MD_CTX hash_{};
  const auto *md = EVP_sha256();
  unsigned out_len{};
  std::array<uint8_t, hash_size> tmp;
  if (!EVP_DigestInit_ex(hash_.get(), md, nullptr) ||
      !EVP_DigestUpdate(hash_.get(), ssl->client_key_share.data(),
                        ssl->client_key_share.size()) ||
      !EVP_DigestUpdate(hash_.get(), ssl->server_key_share.data(),
                        ssl->server_key_share.size()) ||
      !EVP_DigestFinal_ex(hash_.get(), tmp.data(), &out_len) ||
      out_len != hash_size) {
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(
                      Messaging::MessageHeaders::SESSION_CTX_SEND)) ||
      !CBB_add_u64(cbb.get(), len) ||
      (!CBB_add_bytes(cbb.get(), data, len)) ||
      !CBB_add_bytes(cbb.get(), tmp.data(), hash_size) ||
      !CBBFinishArray(cbb.get(), &tmp_buffer)) {
    return false;
  }

  const auto amount_written = SSL_write(verifier, tmp_buffer.data(),
                                        static_cast<int>(tmp_buffer.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, tmp_buffer.size());

  // In response we expect:
  // 1) The CATS share (128 bits)
  // 2) The SATS share (128 bits)
  // So we're expecting 32 bytes + sizeof(Header) back.
  using TSO = EmpWrapperAG2PCConstants::TrafficCircuitOut;
  constexpr auto share_size = std::tuple_size_v<decltype(TSO::client_key_share)>;
  constexpr auto buf_size = sizeof(TSO::client_key_share) + sizeof(TSO::server_key_share) +
                            sizeof(Messaging::MessageHeaders);

  std::array<uint8_t, buf_size> buf_in;
  const auto amount_read = SSL_read(verifier, buf_in.data(),
                                    static_cast<int>(buf_in.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, buf_in.size());

  CBS in_cbs;
  CBS_init(&in_cbs, buf_in.data(), buf_in.size());
  uint8_t in_header;
  if (!CBS_get_u8(&in_cbs, &in_header) ||
      !Messaging::is_valid_header(in_header) ||
      static_cast<Messaging::MessageHeaders>(in_header) !=
          Messaging::MessageHeaders::SESSION_CTX_RECV) {
    return false;
  }

  // Reconstruct full keys by XORing prover + verifier shares
  std::array<uint8_t, 16> client_traffic_key{};
  std::array<uint8_t, 16> server_traffic_key{};

  uint8_t tmp_share;
  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) return false;
    client_traffic_key[i] = ssl->client_key_share[i] ^ tmp_share;
  }
  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) return false;
    server_traffic_key[i] = ssl->server_key_share[i] ^ tmp_share;
  }

  // Install the traffic keys into the TLS record layer
  bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();
  const SSL_SESSION *session = hs->new_session.get();

  const EVP_AEAD *aead;
  size_t discard;
  if (!bssl::ssl_cipher_get_evp_aead(&aead, &discard, &discard, session->cipher,
                               bssl::ssl_session_protocol_version(session))) {
    return false;
  }

  const size_t key_len = EVP_AEAD_key_length(aead);
  const size_t iv_len  = EVP_AEAD_nonce_length(aead);

  bssl::Span<const uint8_t> client_key(client_traffic_key.data(), key_len);
  bssl::Span<const uint8_t> client_iv(ssl->client_iv.data() + 4, iv_len);
  bssl::Span<const uint8_t> server_key(server_traffic_key.data(), key_len);
  bssl::Span<const uint8_t> server_iv(ssl->server_iv.data() + 4, iv_len);

  auto write_aead = bssl::SSLAEADContext::Create(evp_aead_seal,
                                           bssl::ssl_session_protocol_version(session),
                                           session->cipher, client_key, {}, client_iv);
  auto read_aead  = bssl::SSLAEADContext::Create(evp_aead_open,
                                           bssl::ssl_session_protocol_version(session),
                                           session->cipher, server_key, {}, server_iv);
  if (!write_aead || !read_aead) {
    return false;
  }

  return ssl->method->set_write_state(ssl, ssl_encryption_application,
                                      std::move(write_aead), {}) &&
         ssl->method->set_read_state(ssl, ssl_encryption_application,
                                     std::move(read_aead), {});
}

bool ThreePartyHandshake::commit_to_server_certificate(bssl::SSL_HANDSHAKE *hs,
                                                       SSL *ssl) {
  if (!hs || !ssl) {
    return false;
  }

  SSL *verifier = ssl->verifier;
  if (!verifier) {
    return false;
  }

  // Just forward the handshake data to the other party. We also send over a
  // hash of our key share: we prove commitments to this later on during
  // attestation.
  bssl::Array<uint8_t> tmp_buffer;
  constexpr auto hash_size = 32; // SHA-256 Hash.
  const auto size = sizeof(Messaging::MessageHeaders) +
                    ssl->s3->read_buffer.span().size() + hash_size;

  if (!tmp_buffer.Init(size)) {
    return false;
  }

  bssl::ScopedEVP_MD_CTX hash_{};
  const auto *md = EVP_sha256();
  unsigned out_len{};
  std::array<uint8_t, hash_size> tmp;
  if (!EVP_DigestInit_ex(hash_.get(), md, nullptr) ||
      !EVP_DigestUpdate(hash_.get(), ssl->server_key_share.data(),
                        ssl->server_key_share.size()) ||
      !EVP_DigestFinal_ex(hash_.get(), tmp.data(), &out_len) ||
      out_len != hash_size) {
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(
                      Messaging::MessageHeaders::CERTIFICATE_CTX_SEND)) ||
      !CBB_add_u64(cbb.get(), ssl->s3->hs_buf->length) ||
      !CBB_add_bytes(
          cbb.get(),
          reinterpret_cast<const uint8_t *>(ssl->s3->read_buffer.span().data()),
          sizeof(uint8_t) * ssl->s3->read_buffer.span().size()) ||
      !CBB_add_bytes(cbb.get(), reinterpret_cast<const uint8_t *>(tmp.data()),
                     sizeof(tmp)) ||
      !CBBFinishArray(cbb.get(), &tmp_buffer)) {
    return false;
  }

  const auto t0 = std::chrono::steady_clock::now();
  const auto amount_written = SSL_write(verifier, tmp_buffer.data(),
                                        static_cast<int>(tmp_buffer.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, tmp_buffer.size());
  fprintf(stderr, "[cert-send] %.3f ms\n",
          std::chrono::duration<double, std::milli>(
              std::chrono::steady_clock::now() - t0).count());

  // In response we expect the following secrets:
  // 1) The CHTS share (128 bits)
  // 2) The SHTS share (128 bits).
  // So we're expecting 32 bytes + sizeof(Header) back.
  using HSO = EmpWrapperAG2PCConstants::HandshakeCircuitOut;
  constexpr auto buf_size = sizeof(HSO::CHTS_share) + sizeof(HSO::SHTS_share) +
                            sizeof(Messaging::MessageHeaders);

  static_assert(sizeof(HSO::CHTS_share) == sizeof(HSO::SHTS_share));
  // This is really ugly C++, but essentially it says "this is the size of the
  // array CHTS". This is done without constructing such an object.
  constexpr auto share_size = std::tuple_size_v<decltype(HSO::CHTS_share)>;

  // Space to read into.
  std::array<uint8_t, buf_size> buf_in;

  // Read in the header.
  const auto amount_read =
      SSL_read(verifier, buf_in.data(), static_cast<int>(buf_in.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, buf_in.size());

  // Extract out all the good bits.
  CBS in_cbs;
  CBS_init(&in_cbs, buf_in.data(), buf_in.size());
  uint8_t in_header;
  if (!CBS_get_u8(&in_cbs, &in_header) ||
      !Messaging::is_valid_header(in_header) ||
      static_cast<Messaging::MessageHeaders>(in_header) !=
          Messaging::MessageHeaders::CERTIFICATE_CTX_RECV) {
    return false;
  }

  // The first 16 bytes will be the bytes for the CHTS, and the next 16 will be
  // for the SHTS.
  auto &ir_chts = ssl->chts_share;
  auto &ir_shts = ssl->shts_share;

  auto &chts = hs->client_handshake_secret;
  auto &shts = hs->server_handshake_secret;

  // Arguably this check is a static condition, but it's better to check
  // here that this is true.
  if (ir_chts.size() != share_size || ir_shts.size() != share_size) {
    return false;
  }

  if (chts.size() != 2 * share_size) {
    if (!chts.TryResize(2 * share_size)) return false;
    //std::fill(chts.begin(), chts.end(), 0);
  }
  if (shts.size() != 2 * share_size) {
    if (!shts.TryResize(2 * share_size)) return false;
    //std::fill(shts.begin(), shts.end(), 0);
  }

  // As we got the "first half" of each key share we just need to copy over
  // the other share into the requisite place.
  if (chts.size() != 2 * share_size || shts.size() != 2 * share_size) {
    return false;
  }

  std::copy(ir_chts.cbegin(), ir_chts.cend(), chts.begin());
  std::copy(ir_shts.cbegin(), ir_shts.cend(), shts.begin());

  uint8_t tmp_share;

  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) {
      return false;
    }
    chts[i + share_size] = tmp_share;
  }

  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) {
      return false;
    }

    shts[i + share_size] = tmp_share;
  }

  // We will reveal the keys when we derive the traffic keys.
  return true;
}

bool ThreePartyHandshake::combine_handshake_secret_shares(
    bssl::SSL_HANDSHAKE *hs, SSL *ssl) {
  // Resumption-safe share-combine. Reads CHTS_share_hi || SHTS_share_hi from
  // the verifier and concatenates with the prover's 16B lo-shares to populate
  // hs->client_handshake_secret / hs->server_handshake_secret before
  // tls13_set_traffic_key runs. On non-resumed handshakes this step is
  // piggy-backed onto commit_to_server_certificate; on resumption there is no
  // Certificate message, so the verifier sends the shares in a dedicated
  // CERTIFICATE_CTX_RECV-tagged frame right after KS_DONE.
  if (!hs || !ssl) {
    return false;
  }
  SSL *verifier = ssl->verifier;
  if (!verifier) {
    return false;
  }

  using HSO = EmpWrapperAG2PCConstants::HandshakeCircuitOut;
  constexpr auto buf_size = sizeof(HSO::CHTS_share) + sizeof(HSO::SHTS_share) +
                            sizeof(Messaging::MessageHeaders);
  static_assert(sizeof(HSO::CHTS_share) == sizeof(HSO::SHTS_share));
  constexpr auto share_size = std::tuple_size_v<decltype(HSO::CHTS_share)>;

  std::array<uint8_t, buf_size> buf_in;
  const auto amount_read =
      SSL_read(verifier, buf_in.data(), static_cast<int>(buf_in.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, buf_in.size());

  CBS in_cbs;
  CBS_init(&in_cbs, buf_in.data(), buf_in.size());
  uint8_t in_header;
  if (!CBS_get_u8(&in_cbs, &in_header) ||
      !Messaging::is_valid_header(in_header) ||
      static_cast<Messaging::MessageHeaders>(in_header) !=
          Messaging::MessageHeaders::CERTIFICATE_CTX_RECV) {
    return false;
  }

  auto &ir_chts = ssl->chts_share;
  auto &ir_shts = ssl->shts_share;
  auto &chts = hs->client_handshake_secret;
  auto &shts = hs->server_handshake_secret;

  if (ir_chts.size() != share_size || ir_shts.size() != share_size) {
    return false;
  }
  if (chts.size() != 2 * share_size && !chts.TryResize(2 * share_size)) {
    return false;
  }
  if (shts.size() != 2 * share_size && !shts.TryResize(2 * share_size)) {
    return false;
  }
  std::copy(ir_chts.cbegin(), ir_chts.cend(), chts.begin());
  std::copy(ir_shts.cbegin(), ir_shts.cend(), shts.begin());

  uint8_t tmp_share;
  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) return false;
    chts[i + share_size] = tmp_share;
  }
  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) return false;
    shts[i + share_size] = tmp_share;
  }
  return true;
}

bool ThreePartyHandshake::derive_traffic_keys(bssl::SSL_HANDSHAKE *hs,
                                              SSL *ssl) {
  if (!hs || !ssl || !ssl->verifier) {
    return false;
  }

  // Alias.
  auto verifier = ssl->verifier;

  // We signal that we're ready to derive traffic secrets. This is just a single
  // header that we have to write.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We have to make the header a big-endian value. You know, for compatibility.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!write_to.Init(sizeof(uint8_t))) {
    return false;
  }

  constexpr static auto header = Messaging::MessageHeaders::DERIVE_TS;

  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  // Now just write it.
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));

  // Now we'll just call the derivation routine directly.
  // We need to pack our inputs first.
  EmpWrapperAG2PCConstants::TrafficCircuitIn input;
  input.ms_share = ssl->ms_share;
  // We can fetch the hash directly.
  if (!Util::get_hash(&hs->transcript, input.hash)) {
    return false;
  }

  // Call the circuit.
  EmpWrapperAG2PCConstants::TrafficCircuitOut output;

  // N.B Again we wrap ssl->traffic_circuit in a unique_ptr so it is cleaned up
  // even in case of failure.
  auto circuit = std::unique_ptr<EmpWrapperAG2PC>(ssl->traffic_circuit);
  // Prevent double-free.
  ssl->traffic_circuit = nullptr;

  // False here means "not the verifier".
  const auto t0 = std::chrono::steady_clock::now();
  if (!run_traffic_circuit(input, output, circuit.get(), false)) {
    return false;
  }
  fprintf(stderr, "[prover] derive_ts circuit %.3f ms\n",
          std::chrono::duration<double, std::milli>(
              std::chrono::steady_clock::now() - t0).count());

  // Copy the output secrets over.
  ssl->client_key_share = output.client_key_share;
  ssl->server_key_share = output.server_key_share;
  ssl->cats_share = output.CATS_share;
  ssl->sats_share = output.SATS_share;

  // Note: the +4s here are because the AES IV is 96 bits to begin with,
  // but we later expand this to 128 bits.
  std::copy(output.client_iv.cbegin(), output.client_iv.cend(),
            ssl->client_iv.begin() + 4);
  std::copy(output.server_iv.cbegin(), output.server_iv.cend(),
            ssl->server_iv.begin() + 4);

  // NOTE: in some testing situations we want to bail here.
  // We'll do that if the "thrower" is set.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::DERIVE_TS)) {
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::derive_binder(SSL *ssl,
                                        bssl::Span<const uint8_t> ch_hash,
                                        bssl::Span<uint8_t> binder_out) {
  if (!ssl || !ssl->verifier || !ssl->binder_circuit || !ssl->session) {
    return false;
  }
  auto verifier = ssl->verifier;

  // Signal the verifier to run its half of the binder circuit.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(
                      Messaging::MessageHeaders::DERIVE_BINDER)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));

  EmpWrapperAG2PCConstants::BinderCircuitIn input{};
  // The prover's PSK share was carried across from the first session on the
  // SSL_SESSION; the verifier holds the other half.
  input.psk_share = ssl->session->surf_psk_share;

  if (ch_hash.size() != input.ch_hash.size()) {
    return false;
  }
  std::copy(ch_hash.begin(), ch_hash.end(), input.ch_hash.begin());

  // One-shot: the preprocessed material is single-use, and letting the prover
  // re-run this would give it an HMAC oracle under a binder_key it cannot see.
  auto circuit = std::unique_ptr<EmpWrapperAG2PC>(ssl->binder_circuit);
  ssl->binder_circuit = nullptr;

  EmpWrapperAG2PCConstants::BinderCircuitOut output;
  if (!ThreePartyHandshake::run_binder_circuit(input, output, circuit.get(),
                                               false)) {
    return false;
  }

  if (binder_out.size() != output.binder.size()) {
    return false;
  }
  std::copy(output.binder.cbegin(), output.binder.cend(), binder_out.begin());
  return true;
}

static bool
run_gcm_share_circuit(const EmpWrapperAG2PCConstants::GCMCircuitIn &in,
                      EmpWrapperAG2PCConstants::GCMCircuitOut &out,
                      EmpWrapperAG2PC *const circuit) noexcept {

  EmpWrapperAG2PC::derive_gcm_input_type arr{};
  // The 2PC circuits take little-endian input (cf. BN_bn2le_padded in
  // run_handshake_circuit_internal), so the AES key share must be byte-reversed
  // on the way in. Feeding it big-endian makes the circuit compute
  // AES(byterev(k), 0) instead of AES(k, 0).
  for (unsigned i = 0; i < in.key_share.size(); i++) {
    arr[i] = in.key_share[in.key_share.size() - 1 - i];
  }
  memcpy(arr.data() + in.key_share.size(), in.xor_mask.data(),
         sizeof(in.xor_mask));


  // This uses the fact that out.power_share is the exact right type.
  return circuit->derive_gcm_shares(arr, out.power_share);
}

template <bool is_verifier>
static bool
make_gcm_share(SSL *const ssl, const std::array<uint8_t, 16> &key_share,
               EmpWrapperAG2PC *const circuit,
               EmpWrapperAG2PCConstants::AESGCMBulkShareType &out_shares,
               uint64_t *bandwidth) noexcept {

  // Pack the data into the right types.
  EmpWrapperAG2PCConstants::GCMCircuitIn in;
  in.key_share = key_share;
  Util::generate_random_bytes<sizeof(in.xor_mask)>(in.xor_mask.data());

  EmpWrapperAG2PCConstants::GCMCircuitOut out;

  static_assert(sizeof(EmpWrapperAG2PC::derive_gcm_input_type) == 32,
              "gcm input is not exactly key||mask -- the tail was uninitialised");

  if (!run_gcm_share_circuit(in, out, circuit)) {
    return false;
  }

  // We now need to convert to an emp::block for the
  // input.
  // The circuit reveals H*m_bob ^ m_alice publicly. ALICE (the prover) must
  // strip its own mask so the multiplicative sharing is (H*m_bob) x m_bob^-1.
  std::array<uint8_t, 16> unmasked = out.power_share;
  if (!is_verifier) {
    for (unsigned i = 0; i < 16; i++) {
      unmasked[i] ^= in.xor_mask[i];
    }
  }

  const auto input = (is_verifier)
                         ? F2128_MTA::inv(F2128_MTA::arr_to_block(in.xor_mask))
                         : F2128_MTA::arr_to_block(unmasked);

  // Now run the routine
  uint64_t m_bandwidth[2]{};
  const auto share =
      (is_verifier) ? F2128_MTA::generate_shares_verifier_batched(
                          *ssl, input, m_bandwidth[0])
                    : F2128_MTA::generate_shares_prover_batched(*ssl, input,
                                                                m_bandwidth[1]);

  m_bandwidth[0] += m_bandwidth[1];
  if (is_verifier) {
    uint64_t tmp_bandwidth;
    if (SSL_read(ssl, &tmp_bandwidth, sizeof(tmp_bandwidth)) !=
        sizeof(tmp_bandwidth)) {
      return false;
    }

    if (bandwidth) {
      *bandwidth = tmp_bandwidth + m_bandwidth[0];
    }
  } else {
    if (SSL_write(ssl, &m_bandwidth[0], sizeof(m_bandwidth[0])) !=
        sizeof(m_bandwidth[0])) {
      return false;
    }
  }

  // Copy over.
  memcpy(out_shares.data(), share.data(), sizeof(share));
  return true;
}

bool ThreePartyHandshake::make_gcm_shares(
    SSL *const ssl, const std::array<uint8_t, 16> &ckey_share,
    const std::array<uint8_t, 16> &skey_share, EmpWrapperAG2PC *const circuit,
    EmpWrapperAG2PCConstants::AESGCMBulkShareType &cgcm_share,
    EmpWrapperAG2PCConstants::AESGCMBulkShareType &sgcm_share,
    uint64_t *bandwidth) noexcept {
  if (!ssl || !circuit) {
    return false;
  }

  // We do the client share first and then the server share. To make life
  // neater, these are done in subroutines.
  if (SSL_is_server(ssl)) {
      return make_gcm_share<true>(ssl, ckey_share, circuit, cgcm_share, bandwidth) &&
             make_gcm_share<true>(ssl, skey_share, circuit, sgcm_share, bandwidth);
  } else {
      return make_gcm_share<false>(ssl, ckey_share, circuit, cgcm_share, bandwidth) &&
             make_gcm_share<false>(ssl, skey_share, circuit, sgcm_share, bandwidth);
  }
}

bool ThreePartyHandshake::make_gcm_share_for(
    SSL *const ssl, const std::array<uint8_t, 16> &key_share,
    EmpWrapperAG2PC *const circuit,
    EmpWrapperAG2PCConstants::AESGCMBulkShareType &out,
    uint64_t *bandwidth) noexcept {
  if (!ssl || !circuit) {
    return false;
  }
  return SSL_is_server(ssl)
             ? make_gcm_share<true>(ssl, key_share, circuit, out, bandwidth)
             : make_gcm_share<false>(ssl, key_share, circuit, out, bandwidth);
}

bool ThreePartyHandshake::derive_gcm_shares(SSL *const ssl) noexcept {
  if (!ssl || !ssl->verifier) {
    return false;
  }

  // Alias.
  auto verifier = ssl->verifier;

  // Tell the verifier we want to make gcm shares.
  // We signal that we're ready to derive traffic secrets. This is just a single
  // header that we have to write.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We have to make the header a big-endian value. You know, for compatibility.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!write_to.Init(sizeof(uint8_t))) {
    return false;
  }

  constexpr static auto header = Messaging::MessageHeaders::GCM_SHARE_START;

  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  // Now just write it
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));

  // We can actually just call the helper function
  const auto worked =
      make_gcm_share<false>(verifier, ssl->client_key_share, ssl->gcm_circuit,
                            ssl->cgcm_share, nullptr) &&
      make_gcm_share<false>(verifier, ssl->server_key_share, ssl->gcm_circuit,
                            ssl->sgcm_share, nullptr);

  if (!worked) {
    return false;
  }

  // There's no need to rederive the GCM shares.
  if (ssl->surf_mode != Surf::Mode::Rotate) {
    delete ssl->gcm_circuit;
    ssl->gcm_circuit = nullptr;
  }

  // Wait for the verifier to signal that GCM share derivation is complete.
  // Without this read, the GCM_SHARE_DONE byte sits in the receive buffer and
  // corrupts the subsequent resumption circuit communication.
  if (!is_correct_header<Messaging::MessageHeaders::GCM_SHARE_DONE>(verifier)) {
    return false;
  }

  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::GCM_SHARE_DONE)) {
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}

// Decrypts one captured record in place under the reconstructed key. |out|
// receives ct_len bytes: the plaintext including the trailing inner content
// type. Only valid once k is known.
static bool true_surf_open_record(SSL *ssl, const SSL::SurfRecord &rec,
                                  std::vector<uint8_t> &out) {
  const std::vector<SurfBlockMap::RecordDims> recs{
      {rec.seq, static_cast<uint32_t>(rec.ciphertext.size())}};
  const size_t ct_len = rec.ciphertext.size();
  const size_t nblocks = (ct_len + 15) / 16;

  out.assign(ct_len, 0);
  std::array<uint8_t, 16> ks{};
  for (size_t idx = 0; idx < nblocks; idx++) {
    uint64_t seq;
    uint32_t counter;
    if (!SurfBlockMap::resolve(recs, idx, seq, counter)) {
      return false;
    }
    std::array<uint8_t, 16> ctr{};
    SurfBlockMap::ctr_block(ssl->server_iv.data() + 4, seq, counter, ctr);
    if (!MaskConstants::aes_ecb_block(ssl->surf_full_server_key.data(),
                                      ctr.data(), ks.data())) {
      return false;
    }
    const size_t n = std::min<size_t>(16, ct_len - idx * 16);
    for (size_t j = 0; j < n; j++) {
      out[idx * 16 + j] = rec.ciphertext[idx * 16 + j] ^ ks[j];
    }
  }
  return true;
}

// True iff |pt| (inner plaintext, content-type byte included) is a
// warning-level close_notify. This is the integrity half of the termination
// change: the read loop now stops at the peer's FIN, which an attacker can
// forge, so the only thing distinguishing a complete response from a truncated
// one is that the origin's last record really was a close_notify. Checked here
// because it is the first point at which anything can be decrypted.
static bool surf_is_close_notify(const std::vector<uint8_t> &pt) {
  size_t n = pt.size();
  while (n > 0 && pt[n - 1] == 0) {  // RFC 8446 5.4 padding
    n--;
  }
  if (n == 0 || pt[n - 1] != SSL3_RT_ALERT) {
    return false;
  }
  n--;
  return n == 2 && pt[0] == SSL3_AL_WARNING && pt[1] == SSL_AD_CLOSE_NOTIFY;
}

bool ThreePartyHandshake::true_surf_release(SSL *ssl,
                                            bssl::Array<uint8_t> &out,
                                            bool require_close_notify) {
  if (!ssl || !ssl->verifier || !ssl->surf_true_mode ||
      ssl->surf_key_released) {
    return false;
  }
  auto verifier = ssl->verifier;

  // 1) Submit every captured record for joint tag verification. The first call
  // sends KEY_COMMIT, so the verifier holds the digest before any ciphertext.
  for (size_t i = 0; i < ssl->surf_records.size(); i++) {
    if (!verify_record_tag(ssl, i)) {
      std::cerr << "[Prover] tag verification failed on record " << i << "\n";
      return false;
    }
  }

  // 2) Ask for k_v. The verifier latches here and refuses further GCM_VERIFY:
  // from this point we hold k and could forge any record, so nothing submitted
  // afterwards would be attestable. Everything we will ever attest went over
  // the wire in step 1.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> hdr;
  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(Messaging::MessageHeaders::KEY_RELEASE)) ||
      !CBBFinishArray(cbb.get(), &hdr)) {
    return false;
  }
  const auto written =
      SSL_write(verifier, hdr.data(), static_cast<int>(hdr.size()));
  RETURN_FALSE_IF_SSL_FAILED(written, hdr.size());

  std::array<uint8_t, 16> kv{};
  if (!read_exact_blocking(verifier, kv.data(), kv.size())) {
    return false;
  }
  for (unsigned i = 0; i < 16; i++) {
    ssl->surf_full_server_key[i] = ssl->server_key_share[i] ^ kv[i];
  }
  ssl->surf_key_released = true;

  // 3) Decrypt everything. Two passes so the output array can be sized before
  // filling: only application-data records contribute, each giving ct_len - 1
  // bytes (RFC 8446 5.2, the inner content type is the last byte).
  std::vector<std::vector<uint8_t>> opened(ssl->surf_records.size());
  size_t total = 0;
  for (size_t i = 0; i < ssl->surf_records.size(); i++) {
    if (!true_surf_open_record(ssl, ssl->surf_records[i], opened[i])) {
      return false;
    }

    if (opened[i].empty()) {
      continue;
    }

    std::cerr << "[Prover] record " << i << " len=" << opened[i].size()
              << " inner=0x" << std::hex
              << static_cast<int>(opened[i].back()) << std::dec << "\n";

    if (opened[i].back() == SSL3_RT_APPLICATION_DATA) {
      total += opened[i].size() - 1;
    }
  }

  // A close_notify anywhere but last means the origin ended the stream and
  // something appended records afterwards.
  for (size_t i = 0; i + 1 < opened.size(); i++) {
    if (surf_is_close_notify(opened[i])) {
      std::cerr << "[Prover] close_notify at record " << i << " of "
                << opened.size() << " -- data after end of stream\n";
      return false;
    }
  }

  // The stream must end exactly where the origin said it did. Without this a
  // forged FIN yields a short page with rc=0.
  if (require_close_notify &&
      (opened.empty() || !surf_is_close_notify(opened.back()))) {
    std::cerr << "[Prover] response not terminated by close_notify: "
              << (opened.empty()
                      ? "no records"
                      : "last record len=" + std::to_string(opened.back().size()))
              << " -- truncated\n";
    return false;
  }

  if (!out.Init(total)) {
    return false;
  }
  size_t off = 0;
  for (const auto &pt : opened) {
    if (pt.empty() || pt.back() != SSL3_RT_APPLICATION_DATA) {
      continue;
    }
    std::copy(pt.cbegin(), pt.cend() - 1, out.begin() + off);
    off += pt.size() - 1;
  }
  if (off != total) {
    return false;
  }

  // 4) Feed decrypted handshake records back into the handshake layer. They
  // were captured sealed, so tls_open_record never handed them up and
  // tls13_process_new_session_ticket never ran -- which means ticket_nonce was
  // never parsed and derive_psk_keys never fired. This is what makes a
  // TRUE-mode connection resumable. The verifier is still parked in
  // derive_psk(), so the PSK circuit has a counterparty.
  for (const auto &pt : opened) {
    if (pt.empty() || pt.back() != SSL3_RT_HANDSHAKE) {
      continue;
    }
    if (!bssl::tls_append_handshake_data(
            ssl, bssl::MakeConstSpan(pt.data(), pt.size() - 1))) {
      return false;
    }
    bssl::SSLMessage msg;
    while (ssl->method->get_message(ssl, &msg)) {
      if (!bssl::tls13_post_handshake(ssl, msg)) {
        return false;
      }
      ssl->method->next_message(ssl);
    }
  }

  return true;
}

// True iff |pt| (inner content type included) is a KeyUpdate handshake
// message: type 0x18, u24 length 1, one body byte. The origin's last record
// under an epoch's key, hence the epoch boundary.
static bool surf_is_key_update(const std::vector<uint8_t> &pt) {
  size_t n = pt.size();
  while (n > 0 && pt[n - 1] == 0) {  // RFC 8446 5.4 padding
    n--;
  }
  if (n == 0 || pt[n - 1] != SSL3_RT_HANDSHAKE) {
    return false;
  }
  n--;
  return n == 5 && pt[0] == SSL3_MT_KEY_UPDATE && pt[1] == 0 && pt[2] == 0 &&
         pt[3] == 1;
}

// KEY_RELEASE for the current epoch; reconstructs k = k_c ^ k_v.
static bool surf_release_epoch_key(SSL *ssl) {
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> hdr;
  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(
                                 Messaging::MessageHeaders::KEY_RELEASE)) ||
      !CBBFinishArray(cbb.get(), &hdr)) {
    return false;
  }
  const auto written =
      SSL_write(ssl->verifier, hdr.data(), static_cast<int>(hdr.size()));
  RETURN_FALSE_IF_SSL_FAILED(written, hdr.size());

  std::array<uint8_t, 16> kv{};
  if (!read_exact_blocking(ssl->verifier, kv.data(), kv.size())) {
    return false;
  }
  for (unsigned i = 0; i < 16; i++) {
    ssl->surf_full_server_key[i] = ssl->server_key_share[i] ^ kv[i];
  }
  ssl->surf_key_released = true;
  return true;
}

// ROTATE mode release. Per epoch N:
//   KEY_COMMIT(k_c^N) -> GCM_VERIFY in order until the first reject
//   -> KEY_RELEASE (k_v^N) -> decrypt locally -> last record must be the
//   origin's KeyUpdate -> ROTATE_KEY 1 -> epoch N+1.
// The released key is always a closed epoch's. s_{N+1} is derived from shares
// of s_N inside the circuit, and k^N = Expand(s_N, "key") reveals nothing about
// s_N, so holding k^N does not let the prover forge under k^{N+1}.
bool ThreePartyHandshake::rotate_surf_release(SSL *ssl,
                                              bssl::Array<uint8_t> &out,
                                              bool require_close_notify) {
  if (!ssl || !ssl->verifier || ssl->surf_mode != Surf::Mode::Rotate ||
      ssl->surf_key_released) {
    return false;
  }
  const size_t n = ssl->surf_records.size();
  std::vector<std::vector<uint8_t>> opened;
  std::vector<bool> is_boundary;
  size_t start = 0;

  for (unsigned epoch = 0;; epoch++) {
    // 1) Commit to this epoch's k_c, then verify in order until a record is
    //    rejected: that one is the first record of the next epoch.
    ssl->surf_key_committed = false;
    ssl->surf_key_released = false;
    if (!surf_send_key_commitment(ssl)) {
      return false;
    }
    size_t end = start;
    for (; end < n; end++) {
      bool ok = true;
      if (!verify_record_tag(ssl, end, &ok)) {
        std::cerr << "[Prover] epoch " << epoch << ": verify failed on record "
                  << end << "\n";
        return false;
      }
      if (!ok) {
        break;
      }
    }
    if (end == start) {
      std::cerr << "[Prover] epoch " << epoch << ": no verifiable record at "
                << start << "\n";
      return false;
    }

    // 2) Release this epoch's key and open its records.
    if (!surf_release_epoch_key(ssl)) {
      return false;
    }
    for (size_t j = start; j < end; j++) {
      std::vector<uint8_t> pt;
      if (!true_surf_open_record(ssl, ssl->surf_records[j], pt)) {
        return false;
      }
      opened.push_back(std::move(pt));
      is_boundary.push_back(false);
    }
    std::cerr << "[Prover] epoch " << epoch << ": records [" << start << ", "
              << end << ") released\n";
    if (end == n) {
      break;
    }

    // 3) The epoch must end with the origin's KeyUpdate; anything else is a
    //    record that verified under neither key.
    if (!surf_is_key_update(opened.back())) {
      std::cerr << "[Prover] record " << end - 1
                << " is not a KeyUpdate: bad epoch boundary\n";
      return false;
    }
    is_boundary.back() = true;

    // 4) Rotate the server direction jointly. The origin's write_sequence
    //    restarted at 0 after its KeyUpdate; the capture path did not.
    if (!rotate_traffic_keys(ssl, evp_aead_open)) {
      return false;
    }
    for (size_t j = end; j < n; j++) {
      ssl->surf_records[j].seq = j - end;
    }
    start = end;
  }
  ssl->surf_key_released = true;

  // 5) Termination and assembly, as in true_surf_release.
  size_t total = 0;
  for (const auto &pt : opened) {
    if (!pt.empty() && pt.back() == SSL3_RT_APPLICATION_DATA) {
      total += pt.size() - 1;
    }
  }
  for (size_t i = 0; i + 1 < opened.size(); i++) {
    if (surf_is_close_notify(opened[i])) {
      std::cerr << "[Prover] close_notify at record " << i << " of "
                << opened.size() << " -- data after end of stream\n";
      return false;
    }
  }
  if (require_close_notify &&
      (opened.empty() || !surf_is_close_notify(opened.back()))) {
    std::cerr << "[Prover] response not terminated by close_notify -- "
                 "truncated\n";
    return false;
  }

  if (!out.Init(total)) {
    return false;
  }
  size_t off = 0;
  for (const auto &pt : opened) {
    if (pt.empty() || pt.back() != SSL3_RT_APPLICATION_DATA) {
      continue;
    }
    std::copy(pt.cbegin(), pt.cend() - 1, out.begin() + off);
    off += pt.size() - 1;
  }
  if (off != total) {
    return false;
  }

  // 6) Replay handshake records (NewSessionTicket) into the handshake layer.
  //    KeyUpdates are skipped: they were consumed as epoch boundaries, and
  //    tls13_post_handshake would fire the rotate hook a second time.
  for (size_t i = 0; i < opened.size(); i++) {
    const auto &pt = opened[i];
    if (is_boundary[i] || pt.empty() || pt.back() != SSL3_RT_HANDSHAKE) {
      continue;
    }
    if (!bssl::tls_append_handshake_data(
            ssl, bssl::MakeConstSpan(pt.data(), pt.size() - 1))) {
      return false;
    }
    bssl::SSLMessage msg;
    while (ssl->method->get_message(ssl, &msg)) {
      if (!bssl::tls13_post_handshake(ssl, msg)) {
        return false;
      }
      ssl->method->next_message(ssl);
    }
  }
  return true;
}

bool ThreePartyHandshake::rotate_surf_release_epoch(
    SSL *ssl, bssl::Array<uint8_t> &out, bool final_epoch) {
  if (!ssl || !ssl->verifier || ssl->surf_mode != Surf::Mode::Rotate) {
    return false;
  }
  const size_t start = ssl->surf_epoch_start;
  const size_t n = ssl->surf_records.size();
  if (start >= n) {
    std::cerr << "[Prover] epoch " << ssl->surf_epoch << ": no records\n";
    return false;
  }

  // 1) Commit and verify everything captured so far under this epoch's key.
  //    Unlike the batch release, every record must verify: the caller only
  //    calls this once it believes the origin's KeyUpdate has arrived and
  //    nothing of the next epoch has.
  ssl->surf_key_committed = false;
  ssl->surf_key_released = false;
  if (!surf_send_key_commitment(ssl)) {
    return false;
  }
  for (size_t i = start; i < n; i++) {
    bool ok = true;
    if (!verify_record_tag(ssl, i, &ok)) {
      return false;
    }
    if (!ok) {
      std::cerr << "[Prover] epoch " << ssl->surf_epoch << ": record " << i
                << " is not under this epoch's key\n";
      return false;
    }
  }

  // 2) Release and open.
  if (!surf_release_epoch_key(ssl)) {
    return false;
  }
  std::vector<std::vector<uint8_t>> opened;
  for (size_t j = start; j < n; j++) {
    std::vector<uint8_t> pt;
    if (!true_surf_open_record(ssl, ssl->surf_records[j], pt)) {
      return false;
    }
    opened.push_back(std::move(pt));
  }
  std::cerr << "[Prover] epoch " << ssl->surf_epoch << ": records [" << start
            << ", " << n << ") released\n";

  // 3) Boundary. Non-final: last record must be the origin's KeyUpdate. Final:
  //    last record must be close_notify, and none may appear earlier.
  bool skip_last = false;
  if (!final_epoch) {
    if (!surf_is_key_update(opened.back())) {
      std::cerr << "[Prover] epoch " << ssl->surf_epoch
                << ": last record is not a KeyUpdate\n";
      return false;
    }
    skip_last = true;
  } else {
    if (!surf_is_close_notify(opened.back())) {
      std::cerr << "[Prover] response not terminated by close_notify\n";
      return false;
    }
  }
  for (size_t i = 0; i + 1 < opened.size(); i++) {
    if (surf_is_close_notify(opened[i])) {
      std::cerr << "[Prover] close_notify before end of stream\n";
      return false;
    }
  }

  // 4) Assemble this epoch's application data.
  size_t total = 0;
  for (const auto &pt : opened) {
    if (!pt.empty() && pt.back() == SSL3_RT_APPLICATION_DATA) {
      total += pt.size() - 1;
    }
  }
  if (!out.Init(total)) {
    return false;
  }
  size_t off = 0;
  for (const auto &pt : opened) {
    if (pt.empty() || pt.back() != SSL3_RT_APPLICATION_DATA) {
      continue;
    }
    std::copy(pt.cbegin(), pt.cend() - 1, out.begin() + off);
    off += pt.size() - 1;
  }

  // 5) Replay handshake records (NewSessionTicket), skipping the KeyUpdate.
  for (size_t i = 0; i < opened.size(); i++) {
    const auto &pt = opened[i];
    if ((skip_last && i + 1 == opened.size()) || pt.empty() ||
        pt.back() != SSL3_RT_HANDSHAKE) {
      continue;
    }
    if (!bssl::tls_append_handshake_data(
            ssl, bssl::MakeConstSpan(pt.data(), pt.size() - 1))) {
      return false;
    }
    bssl::SSLMessage msg;
    while (ssl->method->get_message(ssl, &msg)) {
      if (!bssl::tls13_post_handshake(ssl, msg)) {
        return false;
      }
      ssl->method->next_message(ssl);
    }
  }

  // 6) Rotate the read direction and restart the capture sequence number, as
  //    the origin's write sequence restarted after its KeyUpdate.
  if (!final_epoch) {
    if (!rotate_traffic_keys(ssl, evp_aead_open)) {
      return false;
    }
    ssl->s3->read_sequence = 0;
    ssl->surf_epoch_start = n;
    ssl->surf_epoch++;
  }
  return true;
}

#undef RETURN_FALSE_IF_SSL_FAILED
