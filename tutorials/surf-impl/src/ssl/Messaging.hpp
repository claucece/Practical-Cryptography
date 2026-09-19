#ifndef INCLUDED_MESSAGING_HPP
#define INCLUDED_MESSAGING_HPP

#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.
#include <cstdint>
#include <openssl/evp.h>

/**
 * @brief Messaging. This namespace represents a namespace for doing Messaging
 *operations. In particular, this namespace is concerned with translating
 *bytestreams into messages that can be understood by any party inside this
 *program.
 **/

namespace Messaging {
/**
@brief MessageHeaders. This enum class contains the headers that messages in
the ThreePartyHandshake use. These are deliberately constrained to be 8 bits:
this is to reduce bandwidth.
**/
enum class MessageHeaders : std::uint8_t {
  /**
     COLLECT. This header indicates the message was sent from a prover to a
  verifier. This message will contain TLS key shares that are to be adjusted.
  **/
  COLLECT = 0,
  /**
     OK. This header indicates the message was sent from a verifier to the
   prover. This message contains the new TLS key shares that are to be used in
   the three party handshake.
   **/
  OK = 1,

  /**
     DONE_HS. This header indicates a successful initial SSL handshake has been
  completed from the verifier's side. This is a signal for the prover to send
  over their TLS key shares.
  **/
  DONE_HS = 2,

  /**
     SERVER_KEY_SHARE. This header indicates that this message contains the
     `server's` key share, sent from the `prover` to the `verifier`.
  **/
  SERVER_KEY_SHARE = 3,

  /**
     HS_RECV. This header indicates that this message contains an
  acknowledgement from the `verifier` that it has received and used the
  `server's` key share.
  **/
  HS_RECV = 4,

  /**
     DO_ECTF. This header indicates that this message should start the ECtF
  functionality. This will only be sent after HS_RECV has been received.
  **/
  DO_ECTF = 5,

  /**
     ECTF_DONE. This header indicates that this message contains an
  acknowledgement from the `verifier` that it has finished the ECTF with the
  prover.
  **/
  ECTF_DONE = 6,

  /**
     ADVANCE_KS. This header indicates that this message contains the transcript
   of the handshake, which is to be used to advance the key schedule. This is
   sent by the prover to the verifier.
   **/
  ADVANCE_KS = 7,

  /**
     KS_DONE. This header indicates that the verifier has advanced their key
  schedule successfully.
   **/
  KS_DONE = 8,

  /**
     TRANSCRIPT_INIT. This header indicates that this message is the first part
  of the transcript from the prover to the verifier.
  **/
  TRANSCRIPT_INIT = 9,

  /**
     TRANSCRIPT_INIT_DONE. This header indicates that the verifier successfully
  processed the initial transcript from the prover.
  **/
  TRANSCRIPT_INIT_DONE = 10,

  CERTIFICATE_CTX_SEND = 11,
  CERTIFICATE_CTX_RECV = 12,
  H6_SEND = 13,
  H6_RECV = 14,

  DERIVE_TS = 16,

  GCM_SHARE_START = 17,
  GCM_SHARE_DONE = 18,

  DERIVE_RES = 19,
  RES_DONE = 20,

  DERIVE_PSK = 21,
  PSK_DONE = 22,

  COMMIT = 23,
  COMMIT_TO = 24,

  AES_ENC = 25,

  SESSION_CTX_SEND = 26,
  SESSION_CTX_RECV = 27,

  STOP = 28,

  // SURF resumption robustness. The prover sends one of these to the verifier
  // right after KS_DONE to declare whether the origin handshake actually
  // resumed (PSK accepted) or fell back to a full handshake. An external origin
  // can decline a session ticket nondeterministically, so the verifier cannot
  // assume a resumption attempt resumes; this flag lets its state machine match
  // the real handshake (i.e. whether a Certificate / CertificateVerify hash is
  // forwarded) instead of desynchronising.
  HS_MODE_FULL = 29,
  HS_MODE_RESUMED = 30,

  // SURF resumption robustness. On a resumed run the prover sends this in place
  // of DERIVE_PSK when the origin connection produced no NewSessionTicket in
  // time (so derive_psk_keys never fired and no PSK was derived). It tells the
  // verifier to skip the whole PSK phase (circuit + PSK_DONE)
  // instead of blocking forever on a DERIVE_PSK / PSK reveal that never comes.
  PSK_SKIP = 31,

  // SURF session classification. Sent by the prover to the verifier as the very
  // first byte after the prover<->verifier handshake (right after it reads
  // DONE_HS, before any preprocessing), declaring whether THIS MPC session is a
  // full handshake (a new prover session) or a Surf-PSK resumption. The verifier
  // reads it in accept_and_read_mode and dispatches run() vs run_resumption()
  // deterministically, instead of guessing from the accept() timeout. This is
  // the prover's *intent* and is distinct from HS_MODE_* (which reports what the
  // origin actually did, learnt later in write_ks_done): a RUN_RESUMED session
  // can still see the origin decline the ticket and report HS_MODE_FULL.
  RUN_FULL = 32,
  RUN_RESUMED = 33,

  // SURF resumption robustness. Sent by the prover in place of DERIVE_PSK when
  // the origin's NewSessionTicket carries an 8-byte ticket_nonce (the
  // OpenSSL/nginx convention) rather than the 1-byte nonce used by
  // LiteSpeed/BoringSSL. The PSK = HKDF-Expand-Label(RMS, "resumption",
  // ticket_nonce, 32) bakes the nonce (length-prefixed) into the HkdfLabel, so
  // the garbled circuit's nonce width must match the server's exactly. The
  // prover picks the matching pre-derived circuit off ssl->ticket_nonce.size()
  // and tells the verifier which one to run via this header vs DERIVE_PSK.
  DERIVE_PSK_8 = 34,

  // SURF. Sent by the prover immediately before running the binder circuit,
  // during construction of the resumed ClientHello. The verifier replies by
  // running its half at PSK_BINDER; there is no ack, the circuit run is itself
  // the synchronisation.
  DERIVE_BINDER = 35,

  MASK_COMMITMENTS = 36,

  GCM_VERIFY = 37,
  KS_DERIVE = 38,

  // SURF 2PC-AES-GCM encryption (Algorithm 1). Sent by the prover after the
  // AES_ENC batches for a record, to run the joint tag circuit. Carries the
  // record's AAD and ciphertext length only: the verifier already holds the
  // ciphertext from the encryption circuit's public output.
  GCM_TAG = 39,

  // Gamma(r_k, k_c^server). Sent once, before the first GCM_VERIFY: the
  // verifier must hold the digest before it holds any ciphertext, and before
  // k_v has moved in the other direction.
  KEY_COMMIT = 40,

  // SURF TRUE mode. Sent once every record the prover intends to attest has
  // been submitted and verified. The verifier latches, refuses all further
  // GCM_VERIFY, and returns its 16-byte server_key_share.
  KEY_RELEASE = 41,

  DERIVE_PSK_0 = 42,

  // SURF ROTATE mode.
  ROTATE_KEY = 43,
  TAG_OK = 44,
  TAG_REJECT = 45,

  /**
     SIZE. This contains the number of elements in the enum. This should ideally
  be last in the enum. Note that this will also signify an invalid header in
  certain settings.
  **/
  SIZE = 46,
};

/**
 @brief header_size. This constant contains the number of bytes needed to
contain the minimal information for each message. This should not vary across
machines as the header comprises of machine independent types.
**/
static constexpr auto header_size = sizeof(MessageHeaders);

/**
   is_valid_header. This function accepts an 8-bit integer and returns true if
   `header` corresponds to a valid MessageHeader and false otherwise. This
function does not throw.
   @param[in] header: the 8-bit value to check.
   @return true if header corresponds to a MessageHeader, false otherwise.
**/
constexpr bool is_valid_header(const std::uint8_t header) noexcept;

/**
 @brief pack_key_bytes. This function accepts a Span of bytes
(corresponding to key bytes) and formats the bytes for serialisation, writing
the result to the `out` parameter.

 In particular, this function returns an array of bytes corresponding to:
 1) An 8 bit integer, containing the `header` argument,
 2) The bytes of the keying material.

 This function returns true on success and false on error.

 If this function is supplied with an array of size 0, then this function will
return false. Note that this function can also encode at most
SSL3_RT_MAX_PLAIN_LENGTH bytes. Because of the pre-packing we provide, this
means that `key_share_bytes` can contain at most SSL3_RT_MAX_PLAIN_LENGTH - 1
bytes. If `key_share_bytes` exceeds this length then false will be returned.

 @snippet Messaging.t.cpp MessagingPackKeyBytesTests

 @param[in] header: the message header to send.
 @param[in] key_share_bytes: a reference to the keying bytes.
 @param[out] out: a reference to an output array.
 @return true on success, false on error.
**/
bool pack_key_bytes(const MessageHeaders header,
                    const bssl::Span<const uint8_t> key_share_bytes,
                    bssl::Array<uint8_t> &out);

/**
 @brief pack_key_bytes. This function accepts an OpenSSL array of bytes
(corresponding to key bytes) and formats the bytes for serialisation, writing
the result to the `out` parameter.

 In particular, this function returns an array of bytes corresponding to:
 1) An 8 bit integer, containing the `header` argument,
 2) The bytes of the keying material.

 This function returns true on success and false on error.

 If this function is supplied with an array of size 0, it will return false.
 This is primarily for error checking. Note that this
 function can also encode at most SSL3_RT_MAX_PLAIN_LENGTH bytes. Because
 of the pre-packing we provide, this means that `key_share_bytes` can
 contain at most SSL3_RT_MAX_PLAIN_LENGTH - 1 bytes. If `key_share_bytes`
 exceeds this length then false will be returned.

 @snippet Messaging.t.cpp MessagingPackKeyBytesTests

 @param[in] header: the message header to send.
 @param[in] key_share_bytes: a reference to the keying bytes.
 @param[out] out: a reference to an output array.
 @return true on success, false on error.
**/
bool pack_key_bytes(const MessageHeaders header,
                    const bssl::Array<uint8_t> &key_share_bytes,
                    bssl::Array<uint8_t> &out);

/**
   @brief unpack_key_bytes. This function accepts a Span of bytes
 (corresponding to a message), parses the contents and writes the result to
 the `out` parameter.

   In particular, this function:
   1) Checks the initial 8 bit header.
   2) Copies the rest of the message into a new array and returns the new
 array.

   This function returns true on success and false on failures.

   This function will return false in the following circumstances:
   1) If `input` is an array of size 0.
   2) If `input` has a size larger than SSL3_RT_MAX_PLAIN_LENGTH.
   4) If the first 8 bits do not correspond to a valid header.
   5) If `input` is an array of size header_size.

   @snippet Messaging.t.cpp MessagingUnpackKeyBytesTests
   @param[out] out_header: the location to store the header.
   @param[in] input: the array to read from.
   @param[out] out: the location to write the output.
   @return true on success, false on error.
 **/
bool unpack_key_bytes(MessageHeaders &out_header,
                      const bssl::Span<const uint8_t> input,
                      bssl::Array<uint8_t> &out);

/**
 @brief unpack_key_bytes. This function accepts an OpenSSL array of bytes
(corresponding to a message), parses the contents and writes the result to
the `out` parameter.

 In particular, this function:
 1. Checks the initial 8 bit header.
 2. Copies the rest of the message into a new array and returns the new
array.

 This function returns true on success and false on failures.

 This function will return false in the following circumstances:
 1. If `input` is an array of size 0.
 2. If `input` has a size larger than SSL3_RT_MAX_PLAIN_LENGTH.
 3. If the first 8 bits do not correspond to a valid header.
 4. If `input` is an array of size header_size.
 5. If the size read from `input` does not match the size of the `input`
array.

 @param[out] out_header: the location to store the header.
 @param[in] input: the array to read from.
 @param[out] out: the location to write the output.
 @return true on success, false on error.
**/
bool unpack_key_bytes(MessageHeaders &out_header,
                      const bssl::Array<uint8_t> &input,
                      bssl::Array<uint8_t> &out);

} // namespace Messaging

/**
   MaskConstants. Parameters for the per-block mask commitments sent during
   preprocessing.

   kNumMasks bounds the ciphertext one connection can commit to at
   kNumMasks * kMaskSize bytes.
**/
namespace MaskConstants {
/// kNumMasks. The number of masks committed to up-front.
static constexpr std::size_t kNumMasks = 1088;
/// kMaskSize. The size of a single mask, in bytes: one AES block.
static constexpr std::size_t kMaskSize = 16;
/// kCommitSize. The size of a single commitment, in bytes: SHA-256.
static constexpr std::size_t kCommitSize = 32;

/// kHiroseC. The fixed nonzero constant in the Hirose construction.
/// MUST stay bit-identical to kHiroseC in DeriveCircuits.cpp.
inline constexpr std::array<uint8_t, 16> kHiroseC{
    0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

/// aes_ecb_block. One raw AES-128 block encryption.
inline bool aes_ecb_block(const uint8_t key[16], const uint8_t in[16],
                          uint8_t out[16]) noexcept {
  bssl::ScopedEVP_CIPHER_CTX ctx;
  int len = 0;
  uint8_t buf[32];  // EVP may write a full extra block
  if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key,
                          nullptr)) {
    return false;
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  if (!EVP_EncryptUpdate(ctx.get(), buf, &len, in, 16) || len != 16) {
    return false;
  }
  for (unsigned i = 0; i < 16; i++) {
    out[i] = buf[i];
  }
  return true;
}

/// hirose_commit_host. Gamma'.Commit over bytes:
///   G_i = AES_{r}(b)   ^ b
///   H_i = AES_{r}(b^c) ^ b ^ c
/// `out` receives G_i || H_i, 32 bytes. MUST agree byte for byte with
/// hirose_commit in DeriveCircuits.cpp, which recomputes this on wires: if
/// the two drift, every in-circuit opening fails and it will look like a mask
/// indexing desync rather than a constant mismatch.
inline bool hirose_commit_host(const uint8_t r[16], const uint8_t b[16],
                               uint8_t out[32]) noexcept {
  uint8_t bc[16];
  for (unsigned i = 0; i < 16; i++) {
    bc[i] = static_cast<uint8_t>(b[i] ^ kHiroseC[i]);
  }

  bssl::ScopedEVP_CIPHER_CTX ctx;
  int len = 0;
  uint8_t g[32], h[32];  // EVP may write up to a full extra block
  if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, r, nullptr)) {
    return false;
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  if (!EVP_EncryptUpdate(ctx.get(), g, &len, b, 16) || len != 16 ||
      !EVP_EncryptUpdate(ctx.get(), h, &len, bc, 16) || len != 16) {
    return false;
  }

  for (unsigned i = 0; i < 16; i++) {
    out[i] = static_cast<uint8_t>(g[i] ^ b[i]);
    out[16 + i] = static_cast<uint8_t>(h[i] ^ bc[i]);
  }
  return true;
}
} // namespace MaskConstants

#include "Messaging.inl"
#endif
