#ifndef INCLUDED_THREEPARTYHANDSHAKE_HPP
#define INCLUDED_THREEPARTYHANDSHAKE_HPP

#include "EmpWrapperAG2PC.hpp" // Needed for circuit out
#include "SurfMode.hpp"
#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.
#include <cstdint>
#include <array>
#include <vector>
#include <cstdlib>

/**
   SurfBlockMap. The shared mapping from a global keystream-block index to the
   (record, GCM counter) pair that produced it. Both parties must compute
   identical counter blocks or every derived keystream block is silently wrong,
   so this lives in one place and both sides call it.

   Blocks are numbered across the concatenation of all captured records'
   ciphertext in arrival order, matching surf_block_at in ThreePartyHandshake.cc.
**/
namespace SurfBlockMap {

/// RecordDims. The per-record data both parties need to agree on the mapping:
/// the record's TLS sequence number and its ciphertext length (tag excluded).
struct RecordDims {
  uint64_t seq;
  uint32_t ct_len;
};

/**
   ctr_block. Builds the 16-byte AES-CTR input for one block.

   TLS 1.3 (RFC 8446 5.3): nonce = static_iv XOR (seq right-aligned in 12
   bytes). GCM (SP 800-38D): the counter within a record starts at 2, because
   J0 = nonce || 0x00000001 is consumed by the tag. An off-by-one here surfaces
   only as a bogus tag mismatch during attestation, which is the worst possible
   place to debug it.

   @param[in] static_iv: the 12-byte traffic IV. NOTE the prover holds this at
   offset 4 of a 16-byte array (ssl->server_iv); the verifier holds it bare at
   offset 0 (traffic_key_shares.server_iv). Callers pass the right pointer.
**/
inline void ctr_block(const uint8_t static_iv[12], uint64_t seq,
                      uint32_t counter, std::array<uint8_t, 16> &out) noexcept {
  out.fill(0);
  for (int i = 0; i < 8; i++) {
    out[11 - i] = static_cast<uint8_t>(seq >> (8 * i));
  }
  for (int i = 0; i < 12; i++) {
    out[i] ^= static_iv[i];
  }
  out[12] = static_cast<uint8_t>(counter >> 24);
  out[13] = static_cast<uint8_t>(counter >> 16);
  out[14] = static_cast<uint8_t>(counter >> 8);
  out[15] = static_cast<uint8_t>(counter);
}

/**
   resolve. Maps a global block index to its record's sequence number and its
   in-record GCM counter. Returns false if the index is past the captured
   traffic.
**/
inline bool resolve(const std::vector<RecordDims> &recs, size_t index,
                    uint64_t &seq, uint32_t &counter) noexcept {
  size_t acc = 0;
  for (const auto &r : recs) {
    const size_t n = (static_cast<size_t>(r.ct_len) + 15) / 16;
    if (index < acc + n) {
      seq = r.seq;
      counter = static_cast<uint32_t>(index - acc) + 2;
      return true;
    }
    acc += n;
  }
  return false;
}

/// total_blocks. The number of 16-byte blocks across all records, with a
/// trailing partial block counted whole (it is zero-padded on the right).
inline size_t total_blocks(const std::vector<RecordDims> &recs) noexcept {
  size_t n = 0;
  for (const auto &r : recs) {
    n += (static_cast<size_t>(r.ct_len) + 15) / 16;
  }
  return n;
}

} // namespace SurfBlockMap

/**
 * @brief ThreePartyHandshake. This namespace contains a series  of functions
 *for doing TLS 1.3 Three Party Handshakes.
 *
 * This namespace is a bit weird. This is to get around certain quirks / design
 *choices in BoringSSL. For example, BoringSSL makes it really hard to overwrite
 *fields that have already been set-up (which is a good thing!) but it makes it
 * difficult for us to do a three-party handshake.
 *
 * To get around this, we re-use parts of BoringSSL to do the handshake.
 * Precisely, we establish a connection between the prover and verifier,
 * generate the keyshares on the prover and send the shares to the verifier in
 * application data. The verifier then takes those key shares and uses
 * BoringSSL's key establishment code to compute their part of the local shares.
 *
 * @remarks Note that we have to use a C-style OOP construct here. Precisely,
 * functions like three_party_handshake_comm() have to take their owner as a
 * parameter. This is because C doesn't have implicit "this" sadly. This also
 * means we can't use other C++ features like exceptions (everything has to be
 *an error code).
 **/
namespace ThreePartyHandshake {

/**
   @brief handshake_function_type. This is a public declaration for the
   function pointer we use for the three-party handshake hook.
   This is placed here to make it easier for users of this namespace
   to get the function type without needing to dig deeply into BoringSSL.
**/
using handshake_function_type = SSL::key_share_callback_function_type;

/**
   @brief send_key_share_function_type. This is a public declaration
   for the function pointer that we use to send the received key share from
   the server back to the verifier. This is placed here to make it easier
   for users of this namespace to get the function type without needing to dig
   deeply back into BoringSSL.
**/
using send_key_share_function_type =
    SSL::key_share_received_callback_function_type;

/**
   @brief derive_shared_secret_function_type. This is a public declaration for
the function pointer that we use to derive the shared master secret in TLS. This
is placed here to make it easier for users of this namespace to get the function
type without needing to dig deeply back into BoringSSL.
**/
using derive_shared_secret_function_type =
    SSL::derive_shared_secret_function_type;

/**
   @brief derive_handshake_secrets_function_type. This is a public declaration
   for the function pointer that we use to derive handshake secrets in TLS. This
   is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_handshake_secrets_function_type =
    SSL::derive_shared_secret_function_type;

/**
   @brief derive_handshake_keys_function_type. This is a public declaration
   for the function pointer that we use to derive handshake keys in TLS. This
   is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_handshake_keys_function_type =
    SSL::derive_handshake_keys_function_type;

using commit_to_server_certificate_function_type =
    SSL::commit_to_server_certificate_function_type;

using combine_handshake_secret_shares_function_type =
    SSL::combine_handshake_secret_shares_function_type;

/**
     @brief derive_traffic_keys_function_type. This is a public declaration for
the function pointer that we use to derive shares of the traffic secrets in TLS.
This is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_traffic_keys_function_type =
    SSL::derive_traffic_keys_function_type;

/**
     @brief derive_resumption_keys_function_type. This is a public declaration for
the function pointer that we use to derive shares of the resumption secrets in TLS.
This is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_resumption_keys_function_type =
    SSL::derive_resumption_keys_function_type;

/**
     @brief derive_psk_keys_function_type. This is a public declaration for
the function pointer that we use to derive shares of the psk secrets in TLS.
This is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using derive_psk_keys_function_type =
    SSL::derive_psk_keys_function_type;

/**
     @brief commit_to_session_ticket_function_type. This is a public declaration for
the function pointer that we use to commit to session ticket in TLS.
This is placed here to make it easier for users of this namespace to get the
function type without needing to dig deeply back into BoringSSL.
**/
using commit_to_session_ticket_function_type =
    SSL::commit_to_session_ticket_function_type;

using derive_gcm_shares_function_type = SSL::derive_gcm_shares_function_type;

using surf_encrypt_function_type = SSL::surf_encrypt_function_type;

using rotate_traffic_keys_function_type = SSL::rotate_traffic_keys_function_type;
/**
     @brief derive_binder_function_type. This is a public declaration for the
function pointer that we use to jointly compute the PSK binder for a resumed
ClientHello. This is placed here to make it easier for users of this namespace
to get the function type without needing to dig deeply back into BoringSSL.
**/
using derive_binder_function_type = SSL::derive_binder_function_type;

/**
 * @brief three_party_handshake_comm. This function accepts an SSL object
 * (representing a current SSL connection) and (using that SSL object's
 * `verifier`) contacts a third party in order to generate shared keyshares.
 * Concretely, this function forwards the SSL object's `hs` values to another
 * party, who then replies with a new set of `hs` values for the SSL object to
 * use in the outgoing handshake. This function returns true in case of
 * success and false in case of error.
 * @snippet ThreePartyHandshake.t.cpp ThreePartyHandshakeCommTests
 *
 * @param ssl: the ssl object to be modified.
 * @param hs: the ssl handshake object.
 * @returns true if the key shares change, false otherwise.
 */
bool three_party_handshake_comm(SSL *ssl, bssl::SSL_HANDSHAKE *hs);

/**
 * @brief preprocess_circuits. Runs the offline circuit-preprocessing phase
 * against `ssl->verifier`. This is the slow interactive garbled-circuit
 * preprocessing (OT round-trips) lifted out of three_party_handshake_comm so a
 * prover can run it *before* opening the connection to the origin server.
 * Running it before the origin TCP connect avoids the origin's TLS/idle timeout
 * firing while the MPC runs over a WAN link (the loopback case was always fast
 * enough; remote verifiers were not).
 *
 * Idempotent: a no-op when `should_make_circuits` is false (the testing path) or
 * when the circuits have already been built (the offline phase already ran). The
 * circuit build order MUST match Server::do_preproc since do_preproc is
 * interactive OT and both parties must agree.
 *
 * @param ssl: the ssl object whose verifier connection is used.
 * @returns true on success (including the no-op cases), false on error.
 */
bool preprocess_circuits(SSL *ssl);

/**
 @brief three_party_handshake_send_received_key_shares. This function accepts an
SSL object (representing a current SSL connection) and (using that's SSL
object's `verifier`) forwards the received key share on to a third party.
Concretely, this part of the handshake is the sending of the received key share
from the `server` on to the `verifier`. This function returns true in case of
success and false in case of error.

 @snippet ThreePartyHandshake.t.cpp ThreePartyHandshakeHSKSTests
 @param[in] ssl: the SSL object.
 @param[in] group_id: the ID of the elliptic curve.
 @param[in] cbs: the CBS that contains the data.
 @return true if `this` connection receives a "HS_RECV" message, false
otherwise.
**/
bool three_party_handshake_send_received_key_shares(SSL *ssl, uint16_t group_id,
                                                    CBS &cbs);

/**
   derived_shared_key_master_secret. This function accepts an SSL object
(representing a current SSL connection) and (using that SSL object's `verifier`)
derives a shared secret.

Concretely, this part of the handshake is the 2PC derivation of the shared
secret between the prover and the verifier. This function does not throw and
returns true in the case of success, false otherwise.

@param[in] hs: the handshake object.
@param[in] ssl: the SSL object.
@param[in] secret: the y-coordinate of the secret.
@return true in case of success, false otherwise.
**/
bool derive_shared_master_secret(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                                 bssl::Array<uint8_t> &secret);

/**
   advance_key_schedule. This function accepts an SSL object (representing a
current SSL connection) and (using that SSL object's `verifier`) advances the
key schedule for both parties. Concretely, this takes place by forwarding the
buffer from the `hs` to the `verifier` and by calling ssl_advance_key_share on
the prover. This function returns true in case of success and false
otherwise.
   @param[in] hs: the handshake object.
   @param[in] ssl: the SSL object.
   @param[in] secret: the derived secret.
   @return true in case of success, false otherwise.
**/
bool advance_key_schedule(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                          bssl::Array<uint8_t> &secret);

/**
   derive_handshake_secret. This function accepts an SSL object (representing a
current SSL connection) and (using that SSL object's `verifier`) derives a
handshake traffic secret. Concretely, this function runs the ECtF portion of the
protocol.

@param[in] hs: the handshake object.
@param[in] ssl: the SSL object.
@param[in] secret: the x-coordinate of the derived secret.
@return true in case of success, false otherwise.
**/

bool derive_handshake_secret(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                             bssl::Array<uint8_t> &secret);
/**
   Concretely, this part of the handshake is the 2PC
derivation of the handshake traffic secrets: this function derives the HS, CHTS,
SHTS and dHS shares. In addition, this function also derives both sets of
handshake keys and IVs: these are distributed depending on the caller.
**/
bool derive_handshake_keys(bssl::SSL_HANDSHAKE *hs, SSL *ssl,
                           bssl::Array<uint8_t> &secret);

bool derive_traffic_keys(bssl::SSL_HANDSHAKE *hs, SSL *ssl);

bool derive_resumption_keys(bssl::SSL_HANDSHAKE *hs, SSL *ssl);

bool derive_psk_keys(SSL *ssl);

bool commit_to_session_ticket(SSL *ssl, const uint8_t *data, size_t len);

bool commit_to_server_certificate(bssl::SSL_HANDSHAKE *hs, SSL *ssl);
bool combine_handshake_secret_shares(bssl::SSL_HANDSHAKE *hs, SSL *ssl);
bool derive_binder(SSL *ssl, bssl::Span<const uint8_t> ch_hash,
                   bssl::Span<uint8_t> binder_out);

bool aes_encrypt(SSL *const ssl, bssl::Array<uint8_t> &in,
                 bssl::Array<uint8_t> &out) noexcept;
bool aes_decrypt(SSL *const ssl, bssl::Array<uint8_t> &in,
                 bssl::Array<uint8_t> &out) noexcept;

bool commit_to(SSL *const ssl, const bssl::Array<uint8_t> &blocks,
               const bssl::Array<unsigned> &blocks_to_commit_to,
               bssl::Array<uint8_t> &commitment) noexcept;

// Verifies the GCM tag over one captured application record. Forwards the
// record's AAD, ciphertext and tag to the verifier so it can compute its own
// GHASH share, then runs the joint circuit. |record_index| indexes
// ssl->surf_records in arrival order.
// |tag_ok|: when non-null (ROTATE mode), a tag mismatch sets *tag_ok=false and
// returns true instead of failing. Cheating and a bad commitment stay fatal.
bool verify_record_tag(SSL *ssl, size_t record_index, bool *tag_ok = nullptr);

// Derives one masked keystream block per ciphertext block of the record at
// |record_index| in ssl->surf_records. Sends that record's boundary first so
// both parties build identical counter blocks. Masks are consumed
// incrementally: ssl->next_mask_index advances by this record's real blocks.
bool derive_keystream(SSL *ssl, size_t record_index);

using surf_decrypt_function_type = SSL::surf_decrypt_function_type;

// Attests the record at |record_index| in ssl->surf_records: verifies its GCM
// tag, then derives its keystream. Called from tls_open_record as each record
// arrives, so the verifier sees GCM_VERIFY || KS_DERIVE per record rather than
// one batch at shutdown.
bool attest_record(SSL *ssl, size_t record_index);

// SURF TRUE mode. Requests k_v from the verifier, reconstructs the server
// traffic key, and decrypts every record captured so far. |plaintext_out|
// receives the concatenated application-data payloads, inner content type
// stripped, in arrival order. Terminal: the verifier attests nothing after.
bool true_surf_release(SSL *ssl, bssl::Array<uint8_t> &plaintext_out,
                       bool require_close_notify = true);

// SURF ROTATE mode release. Per epoch: KEY_COMMIT -> GCM_VERIFY until the
// first reject -> KEY_RELEASE -> local decrypt -> ROTATE_KEY 1. The last
// record of every non-final epoch must be the origin's KeyUpdate.
bool rotate_surf_release(SSL *ssl, bssl::Array<uint8_t> &plaintext_out,
                         bool require_close_notify = true);

// ROTATE mode, one epoch at a time. Releases records
// [ssl->surf_epoch_start, ssl->surf_records.size()): commit, verify, take
// k_v, decrypt, and -- unless |final_epoch| -- require the last record to be
// the origin's KeyUpdate and rotate the read direction. |plaintext_out|
// receives this epoch's application data. With |final_epoch| the stream must
// end in close_notify, and handshake records are replayed as usual.
bool rotate_surf_release_epoch(SSL *ssl, bssl::Array<uint8_t> &plaintext_out,
                               bool final_epoch);

// Joint RFC 8446 7.2 rotation of one direction. Wire: ROTATE_KEY || u8 dir.
// Seal direction: also installs fresh write state (which seals the pending
// KeyUpdate under the old key and resets write_sequence).
bool rotate_traffic_keys(SSL *ssl, enum evp_aead_direction_t direction);

bool run_rotate_circuit(const EmpWrapperAG2PCConstants::RotateCircuitIn &in,
                        EmpWrapperAG2PCConstants::RotateCircuitOut &out,
                        EmpWrapperAG2PC *const circuit,
                        const bool verifier) noexcept;

// One GCM share (H-powers) for |key_share|; dispatches on SSL_is_server.
bool make_gcm_share_for(SSL *const ssl, const std::array<uint8_t, 16> &key_share,
                        EmpWrapperAG2PC *const circuit,
                        EmpWrapperAG2PCConstants::AESGCMBulkShareType &out,
                        uint64_t *bandwidth) noexcept;

// Runs one batched keystream circuit. Both parties supply the same input
// shape; ALICE fills b, BOB fills d.
bool run_ks_batch_circuit(
    const EmpWrapperAG2PCConstants::KSBatchCircuitIn &in,
    EmpWrapperAG2PCConstants::KSBatchCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept;

// SURF 2PC-AES-GCM encryption (Algorithm 1). Encrypts `plaintext` under the
// client traffic key, jointly with the verifier, and writes the complete TLS
// record (5-byte header || ciphertext || 16-byte tag) to `record_out`.
//
// `inner_type` is the TLS 1.3 inner content type (SSL3_RT_APPLICATION_DATA for
// request data); it is appended to the plaintext before encryption per RFC
// 8446 5.2, and is counted in len(C) for the GHASH input. Getting this wrong
// produces a tag the origin rejects with no diagnostic.
bool encrypt_request(SSL *ssl, bssl::Span<const uint8_t> plaintext,
                     uint8_t inner_type, bssl::Array<uint8_t> &record_out);

// Runs one batched encryption circuit. Both parties supply the same input
// shape; only ALICE fills pt.
bool run_aes_enc_batch_circuit(
    const EmpWrapperAG2PCConstants::AESEncBatchCircuitIn &in,
    EmpWrapperAG2PCConstants::AESEncBatchCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept;

// Runs the joint tag circuit. Both parties supply the same input shape; only
// ALICE supplies a real mask, and only ALICE can strip it.
bool run_gcm_tag_circuit(
    const EmpWrapperAG2PCConstants::GCMTagCircuitIn &in,
    EmpWrapperAG2PCConstants::GCMTagCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept;

bool make_gcm_shares(SSL *const ssl, const std::array<uint8_t, 16> &ckey_share,
                     const std::array<uint8_t, 16> &skey_share,
                     EmpWrapperAG2PC *const circuit,
                     EmpWrapperAG2PCConstants::AESGCMBulkShareType &cgcm_share,
                     EmpWrapperAG2PCConstants::AESGCMBulkShareType &sgcm_share,
                     uint64_t *bandwidth) noexcept;

bool derive_gcm_shares(SSL *const ssl) noexcept;

bool run_handshake_circuit(
    const EmpWrapperAG2PCConstants::HandshakeCircuitIn &in,
    EmpWrapperAG2PCConstants::HandshakeCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept;

bool run_resumption_circuit(
    const EmpWrapperAG2PCConstants::ResumptionCircuitIn &in,
    EmpWrapperAG2PCConstants::ResumptionCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept;

bool run_psk_circuit(
    const EmpWrapperAG2PCConstants::PskCircuitIn &in,
    EmpWrapperAG2PCConstants::PskCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept;

// 8-byte ticket_nonce variant (OpenSSL/nginx origins).
bool run_psk_circuit_8(
    const EmpWrapperAG2PCConstants::PskCircuitIn8 &in,
    EmpWrapperAG2PCConstants::PskCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept;

// Zero-byte ticket_nonce variant (GitHub Pages and similar).
bool run_psk_circuit_0(
    const EmpWrapperAG2PCConstants::PskCircuitIn0 &in,
    EmpWrapperAG2PCConstants::PskCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept;

// PSK binder for a resumed ClientHello. Both parties feed their PSK share and
// the binder is public output
bool run_binder_circuit(
    const EmpWrapperAG2PCConstants::BinderCircuitIn &in,
    EmpWrapperAG2PCConstants::BinderCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept;

// GCM tag verification for an attested record. Both parties supply the same
// input shape, so unlike the derivation circuits there is no `verifier` flag.
bool run_gcm_vfy_circuit(
    const EmpWrapperAG2PCConstants::GCMVfyCircuitIn &in,
    EmpWrapperAG2PCConstants::GCMVfyCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept;

// SURF TRUE mode's tag circuit: as above, plus an in-circuit Gamma.Open over
// the prover's key share. Both parties supply the same input shape; ALICE
// fills r_k, BOB fills d_k.
bool run_gcm_vfy_commit_circuit(
    const EmpWrapperAG2PCConstants::GCMVfyCommitCircuitIn &in,
    EmpWrapperAG2PCConstants::GCMVfyCommitCircuitOut &out,
    EmpWrapperAG2PC *const circuit) noexcept;

bool run_traffic_circuit(const EmpWrapperAG2PCConstants::TrafficCircuitIn &in,
                         EmpWrapperAG2PCConstants::TrafficCircuitOut &out,
                         EmpWrapperAG2PC *const circuit,
                         const bool verifier) noexcept;
} // namespace ThreePartyHandshake

/**
   This section of the file contains some checks to make sure that everything
 lines up. The compiler will also complain, but this makes life easier
 (friendlier error messages).
 **/

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::three_party_handshake_comm),
                   ThreePartyHandshake::handshake_function_type>,
    "Error: three_party_handshake_comm does not match "
    "handshake_function_type");

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::
                                three_party_handshake_send_received_key_shares),
                   ThreePartyHandshake::send_key_share_function_type>,
    "Error: three_party_send_received_key_shares does not match "
    "send_key_share_function_type");

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::derive_shared_master_secret),
                   ThreePartyHandshake::derive_shared_secret_function_type>,
    "Error: derive_shared_master_secret does not match "
    "derive_shared_secret_function_type");

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::derive_handshake_secret),
                   ThreePartyHandshake::derive_handshake_secrets_function_type>,
    "Error: derive_handshake_secret does not match "
    "derive_handshake_secrets_function_type");

static_assert(
    std::is_same_v<decltype(&ThreePartyHandshake::derive_binder),
                   ThreePartyHandshake::derive_binder_function_type>,
    "Error: derive_binder does not match derive_binder_function_type");
#endif
