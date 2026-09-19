#ifndef INCLUDED_EMPWRAPPER_AG2PC_HPP
#define INCLUDED_EMPWRAPPER_AG2PC_HPP
#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.

#include "EmpWrapper.hpp"
#include <array>
#include <cstdint>

#include <emp-ag2pc/2pc.h>
#include <emp-ag2pc/amortized_2pc.h>
#include <emp-tool/circuits/circuit_file.h>

#include "Util.hpp" // This is needed for type conversion.

/**
   EmpWrapperAG2PCConstants. This namespace contains a series of constants
   that are used to make certain declarations less awkward. These are separate
   from the main class to hide the templated nature of that class.
   Note that this namespace requires C++17 for initialisation order.
**/
namespace EmpWrapperAG2PCConstants {
/**
  HANDSHAKE_MASK_SIZE. This contains the number of inputs bytes needed for the
  XOR mask for the handshake circuits. These bytes are used during the garbled
  circuit to obscure output. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned HANDSHAKE_MASK_SIZE = 96;

/**
  TRAFFIC_MASK_SIZE. This contains the number of inputs bytes needed for the XOR
mask for the traffic secret circuits. These bytes are used during the garbled
circuit to obscure output. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned TRAFFIC_MASK_SIZE = 64;

/**
  RESUMPTION_MASK_SIZE. This contains the number of inputs bytes needed for the XOR
mask for the resumption secret circuits. These bytes are used during the garbled
circuit to obscure output. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned RESUMPTION_MASK_SIZE = 16;

/**
  PSK_MASK_SIZE. This contains the number of inputs bytes needed for the XOR
mask for the psk secret circuits. These bytes are used during the garbled
circuit to obscure output. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned PSK_MASK_SIZE = 16;

/**
   GCM_MASK_SIZE. This contains the number of input bytes needed for the GCM
mask for the GCM share derivation circuit. These bytes are used to obscure
output. CHAR_BIT == 8 is assumed.
**/
inline constexpr unsigned GCM_MASK_SIZE = 16;

/**
   HANDSHAKE_SECRETS_256_IN_SIZE. This contains the number of input bytes
   needed for running the handshake secret derivation circuit. The
   exact derivation comes from 32 bytes from the hash portion, MASK_SIZE for
   the input mask, and the rest for the additive share of the shared secret. This
   assumes CHAR_BIT = 8.
**/
inline constexpr unsigned HANDSHAKE_SECRETS_256_IN_SIZE =
    16 + 32 + HANDSHAKE_MASK_SIZE + 32;

/**
   HANDSHAKE_SECRETS_384_IN_SIZE. This contains the number of input bytes
   needed for running the handshake secret derivation circuit. The
   exact derivation comes from 32 bytes for dES, 32 bytes from the hash
   portion, MASK_SIZE for the input mask, and the rest for the additive share
   of the shared secret. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned HANDSHAKE_SECRETS_384_IN_SIZE =
    16 + 32 + HANDSHAKE_MASK_SIZE + 48;

/**
   HANDSHAKE_SECRETS_OUTPUT_SIZE. This contains the number of output bytes
   that are written by the handshake secret derivation circuit. The exact
   derivation is from the dHE/CHTS/SHTS/dHS/MS each taking up 32 bytes (so 160),
   with the fk_s (32 bytes) and the key share / iv (28).
   This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned HANDSHAKE_SECRETS_OUTPUT_SIZE = 220;

/**
   RESUMPTION_SECRETS_IN_SIZE. This contains the number of input bytes
   needed for running the resumption secret derivation circuit. The
   exact derivation comes from 32 bytes from the hash portion, MASK_SIZE for
   the input mask, and the rest for the master key. This
   assumes CHAR_BIT = 8.
**/
inline constexpr unsigned RESUMPTION_SECRETS_IN_SIZE =
    16 + RESUMPTION_MASK_SIZE + 32;

/**
   RESUMPTION_SECRETS_OUTPUT_SIZE. This contains the number of output bytes
   that are written by the resumption secret derivation circuit. The exact
   derivation is from the RMS 32 bytes
   This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned RESUMPTION_SECRETS_OUTPUT_SIZE = 32;

/**
   PSK_SECRETS_IN_SIZE. This contains the number of input bytes
   needed for running the psk derivation circuit (1-byte ticket_nonce variant,
   for LiteSpeed/BoringSSL origins). The exact derivation comes from 16 bytes of
   the RMS share, PSK_MASK_SIZE for the input mask, and 1 for the ticket_nonce.
   This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned PSK_SECRETS_IN_SIZE =
    16 + PSK_MASK_SIZE + 1;

/**
   PSK_SECRETS_IN_SIZE_8. As PSK_SECRETS_IN_SIZE but for the 8-byte ticket_nonce
   variant (the OpenSSL/nginx convention). The nonce width is baked into the
   HkdfLabel inside the circuit, so it must match the origin's NewSessionTicket
   nonce exactly; this drives the larger combined_psk_8.txt circuit.
**/
inline constexpr unsigned PSK_SECRETS_IN_SIZE_8 =
    16 + PSK_MASK_SIZE + 8;

inline constexpr unsigned PSK_SECRETS_IN_SIZE_0 = 16 + PSK_MASK_SIZE;

/**
   PSK_SECRETS_OUTPUT_SIZE. This contains the number of output bytes
   that are written by the res secret derivation circuit. The exact
   derivation is from the RES 32 bytes
   This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned PSK_SECRETS_OUTPUT_SIZE = 32;

/**
   TRAFFIC_SECRETS_IN_SIZE. This contains the number of input bytes needed
   for running the traffic key derivation circuit. The exact derivation comes
   from the fact that the hash input is 256 bits, the master secret input is 128
   bits (16), and we need 256 bits of masking. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned TRAFFIC_SECRETS_IN_SIZE = TRAFFIC_MASK_SIZE + 16 + 32;

/**
   TRAFFIC_SECRETS_OUTPUT_SIZE. This contains the number of output bytes
produced by running the traffic key derivation circuit. The exact derivation
comes from the fact that we output 2 128 bit secrets (32 bytes) and 2 12-byte
IVs (24 bytes). Again, this assumes CHAR_BIT = 8.
**/
inline constexpr unsigned TRAFFIC_SECRETS_OUTPUT_SIZE = 120;

inline constexpr unsigned BINDER_IN_SIZE = 48;   // 16 psk share + 32 CH hash
inline constexpr unsigned BINDER_OUT_SIZE = 32;

/**
   BINDER_CIRCUIT_TAG. Tag for the PSK binder circuit.
**/
inline constexpr auto BINDER_CIRCUIT_TAG = 9;

/**
   GCM_VFY_CIRCUIT_TAG. Tag for the GCM tag-verification circuit.
**/
inline constexpr auto GCM_VFY_CIRCUIT_TAG = 10;

/**
   GCM_IN_SIZE. This contains the number of input bytes needed for running the
GCM share derivation circuit. This number comes from 16 bytes for the AES key
shares, and GCM_MASK_SIZE bytes for the output mask. CHAR_BIT == 8 is assumed.
**/
inline constexpr unsigned GCM_IN_SIZE = 16 + GCM_MASK_SIZE;

/**
   GCM_OUTPUT_SIZE. This contains the number of output bytes needed for running
the GCM share derivation circuit. This number comes from the number of maksed
bits supplied in.
**/
inline constexpr unsigned GCM_OUTPUT_SIZE = GCM_MASK_SIZE;

/**
   GCM_TAG_INPUT_SIZE. This contains the number of input bytes needed for
 running the GCM tagging circuit. This assumes CHAR_BIT = 8.
 **/
inline constexpr unsigned GCM_TAG_INPUT_SIZE = 64;

/**
   GCM_TAG_OUTPUT_SIZE. This contains the number of output bytes produced
   by the GCM tagging circuit. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned GCM_TAG_OUTPUT_SIZE = 17;

/**
   GCM_VFY_INPUT_SIZE. This contains the number of input bytes for running
   the GCM verification circuit. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned GCM_VFY_INPUT_SIZE = 64;

/**
   GCM_VFY_OUTPUT_SIZE. This contains the number of bytes produced by the GCM
verification circuit. This assumes CHAR_BIT = 8.
**/
inline constexpr unsigned GCM_VFY_OUTPUT_SIZE = 2;

inline constexpr unsigned AES_GCM_INPUT_SIZE = 384 / 8;
inline constexpr unsigned AES_GCM_OUTPUT_SIZE = 17;

/**
   GCM_VFY_COMMIT_*. SURF TRUE mode's tag circuit: as the masked one, plus an
   in-circuit Gamma.Open over the prover's key share.
**/
inline constexpr unsigned GCM_VFY_COMMIT_INPUT_SIZE = 112;
inline constexpr unsigned GCM_VFY_COMMIT_OUTPUT_SIZE = 3;

inline constexpr auto AES_GCM_VFY_COMMIT_FILEPATH =
    "../2pc/key-derivation/derive_gcm_verify_commit.txt";
inline constexpr auto GCM_VFY_COMMIT_CIRCUIT_TAG = 15;

struct GCMVfyCommitCircuitIn {
  std::array<uint8_t, 16> key;
  std::array<uint8_t, 16> iv;
  std::array<uint8_t, 16> tag_share;
  std::array<uint8_t, 16> server_tag;
  std::array<uint8_t, 16> r_k;   // ALICE only
  std::array<uint8_t, 32> d_k;   // BOB only
};

struct GCMVfyCommitCircuitOut {
  bool tag_passed;
  bool cheated;
  bool key_opened;
};

using aes_gcm_vfy_commit_input_type =
    std::array<uint8_t, GCM_VFY_COMMIT_INPUT_SIZE>;
using aes_gcm_vfy_commit_output_type =
    std::array<uint8_t, GCM_VFY_COMMIT_OUTPUT_SIZE>;


// Binder
struct BinderCircuitIn {
  std::array<uint8_t, 16> psk_share;
  std::array<uint8_t, 32> ch_hash;   // H(Truncate(ClientHello))
};
struct BinderCircuitOut {
  std::array<uint8_t, 32> binder;
};


/** ResumptionCircuitIn. This struct is used as an input type for running the
joint resumption secret derivation circuits. This is primarily here to make
certain inputs neater to write.**/
struct ResumptionCircuitIn {
  std::array<uint8_t, 32> hash;
  std::array<uint8_t, 16> ms_share;
};

/** ResumptionCircuitOut. This struct is used as an output type for running the
joint resumption secret derivation functions. The output bytes are as specified
in the circuit's description.**/
struct ResumptionCircuitOut {
  std::array<uint8_t, RESUMPTION_MASK_SIZE> xor_mask;
  std::array<uint8_t, 16> RMS_share;
};

/** PskCircuitIn. This struct is used as an input type for running the
joint psk secret derivation circuits. This is primarily here to make
certain inputs neater to write.**/
struct PskCircuitIn {
  std::array<uint8_t, 16> rms_share;
  std::array<uint8_t, 1> ticket_nonce;
};

/** PskCircuitIn8. As PskCircuitIn but for the 8-byte ticket_nonce variant
(OpenSSL/nginx origins). **/
struct PskCircuitIn8 {
  std::array<uint8_t, 16> rms_share;
  std::array<uint8_t, 8> ticket_nonce;
};

struct PskCircuitIn0 {
  std::array<uint8_t, 16> rms_share;
  std::array<uint8_t, 0> ticket_nonce;
};

/** PskCircuitOut. This struct is used as an output type for running the
joint resumption secret derivation functions. The output bytes are as specified
in the circuit's description.**/
struct PskCircuitOut {
  std::array<uint8_t, PSK_MASK_SIZE> xor_mask;
  std::array<uint8_t, 16> PSK_share; // 32 in total
};

/**
  HandshakeCircuitIn. This struct is used as an input type for running the
joint handshake derivation circuits. This is primarily here to make certain
inputs neater to write.
**/
struct HandshakeCircuitIn {
  std::array<uint8_t, 32> hash;
  bssl::Array<uint8_t> key_share;
  std::array<uint8_t, 16> psk_share;
};

/**
   HandshakeCircuitOut. This struct is used as an output type for running the
joint handshake derivation functions. The output bytes are as specified in the
circuit's description.
**/
struct HandshakeCircuitOut {
  std::array<uint8_t, HANDSHAKE_MASK_SIZE> xor_mask;
  std::array<uint8_t, 16> dHE_share;
  std::array<uint8_t, 16> CHTS_share;
  std::array<uint8_t, 16> SHTS_share;
  std::array<uint8_t, 16> dHS_share;
  std::array<uint8_t, 16> MS_share;
  std::array<uint8_t, 32> fk_s;
  std::array<uint8_t, 16> server_key_share;
  std::array<uint8_t, 12> iv;
};

// We get half of each derived secret (80 bytes in total) + fk_s, with the
// output mask present too.
static_assert(sizeof(HandshakeCircuitOut) == 96 + 44 + HANDSHAKE_MASK_SIZE,
              "Error: HandshakeCircuitOut is not the right size.");

/**
  TrafficCircuitIn. This struct is used as an input type for running the
joint traffic derivation circuits. This is primarily here to make certain
inputs neater to write. It is just the hash and the share of ms.
**/
struct TrafficCircuitIn {
  std::array<uint8_t, 32> hash;
  std::array<uint8_t, 16> ms_share;
};

/**
   TrafficCircuitOut. This struct is used as an output type for running the
joint handshake derivation functions. The output bytes are as specified in the
circuit's description.
**/
struct TrafficCircuitOut {
  std::array<uint8_t, TRAFFIC_MASK_SIZE> xor_mask;
  std::array<uint8_t, 16> client_key_share;  // prover: mask; verifier: key XOR mask
  std::array<uint8_t, 12> client_iv;
  std::array<uint8_t, 16> server_key_share;  // prover: mask; verifier: key XOR mask
  std::array<uint8_t, 12> server_iv;
  std::array<uint8_t, 16> CATS_share;
  std::array<uint8_t, 16> SATS_share;
  std::array<uint8_t, 16> client_traffic_key{};
  std::array<uint8_t, 16> server_traffic_key{};
};

/**
   GCMCircuitIn. This struct is used as an input type for running the joint AES
GCM derivation functions. The input bytes are specified in the circuit's
description.
**/
struct GCMCircuitIn {
  std::array<uint8_t, GCM_MASK_SIZE> xor_mask;
  std::array<uint8_t, 16> key_share;
};

/**
   GCMCircuitOut. This struct is used as an output type for running the joint
AES GCM derivation functions. The input bytes are specified in the circuit's
description.
**/
struct GCMCircuitOut {
  std::array<uint8_t, GCM_MASK_SIZE> power_share;
};

/**
   GCMTagCircuitIn. This struct is used as an input type for running the joint
   AES GCM encryption functions. The input bytes are specified in the circuit's
   description.
**/
struct GCMTagCircuitIn {
  std::array<uint8_t, 16> key_share;
  std::array<uint8_t, 16> iv;
  std::array<uint8_t, 16> tag_share;
  std::array<uint8_t, 16> mask_or_unused;
};

/**
   GCMTagCircuitOut. This struct is used as an output type for running the joint
   AES GCM verification circuits. The output bytes are as specified in the
circuit's description.
**/
struct GCMTagCircuitOut {
  bool cheated;
  // Revealed only to P1.
  std::array<uint8_t, 16> tag;
};

/**
   GCMVfyCircuitIn. This struct is used to model input for the joint AES gcm
   verification functions. The input bytes are as specified in the circuit
   description.
**/
struct GCMVfyCircuitIn {
  std::array<uint8_t, 16> key;
  std::array<uint8_t, 16> iv;
  std::array<uint8_t, 16> tag_share;
  std::array<uint8_t, 16> server_tag;
};

struct GCMVfyCircuitOut {
  bool tag_passed;
  bool cheated;
};

/**
   AESCircuitJointIn. This struct is used as an input type for the running
the joint AES circuit, where each party learns the entire ciphertext.
The input bytes are as specified in the circuit.
**/
struct AESCircuitJointIn {
  std::array<uint8_t, 16> pt_or_unused;
  std::array<uint8_t, 16> key;
  std::array<uint8_t, 16> iv;
};

/**
   AESCircuitJointOut. This struct is used as an output type for the running the
joint AES circuit, where each party learns the entire ciphertext.
The output bytes are as specified in the circuit.
**/
struct AESCircuitJointOut {
  bool cheated;
  std::array<uint8_t, 16> pt;
};

// Maximum keystream-circuit invocations before AmortizedC2PC re-preprocesses
// inline. Batched attestation needs ceil(total_blocks / KS_BATCH_N); per-record
// attestation needs one invocation per record, so the bound is the record count
// rather than the block count.
inline constexpr unsigned KS_MAX_INVOCATIONS = 16;

// Batched keystream and in-circuit commitment opening (Algorithm 2). One
// invocation covers KS_BATCH_N blocks: the commitment checks, counter checks
// and keystream derivations share a single `ok` gate, so a bad opening zeroes
// the whole batch. The verifier supplies only the digest d_i, never b_i.
//
// Input (bytes, same shape both parties):
//   key 16 || ctr 16*N || b 16*N || d 32*N
// Output: masked_ks 16*N || ok 1
inline constexpr unsigned KS_BATCH_N = 16;

inline constexpr unsigned ks_batch_in_size(const unsigned n) noexcept {
  return 16 * n + 80;   // key 16 + ctr 16n + s 16 + r 16 + d 32
}

inline constexpr unsigned ks_batch_out_size(const unsigned n) noexcept {
  return 16 * n + 1;
}
inline constexpr unsigned KS_BATCH_INPUT_SIZE = ks_batch_in_size(KS_BATCH_N);
inline constexpr unsigned KS_BATCH_OUTPUT_SIZE = ks_batch_out_size(KS_BATCH_N);

// Benchmark-only: the n=1 point of the amortization curve.
inline constexpr auto KS_BATCH_1_FILEPATH =
    "../2pc/key-derivation/derive_keystream_batch_1.txt";
inline constexpr unsigned KS_BATCH_1_INPUT_SIZE = ks_batch_in_size(1);
inline constexpr unsigned KS_BATCH_1_OUTPUT_SIZE = ks_batch_out_size(1);

inline constexpr auto KS_BATCH_FILEPATH =
    "../2pc/key-derivation/derive_keystream_batch_16.txt";
inline constexpr auto KS_BATCH_CIRCUIT_TAG = 12;

struct KSBatchCircuitIn {
  std::array<uint8_t, 16> key;
  std::array<std::array<uint8_t, 16>, KS_BATCH_N> ctr;
  std::array<uint8_t, 16> s;    // ALICE only
  std::array<uint8_t, 16> r;    // ALICE only
  std::array<uint8_t, 32> d;    // BOB only
};

struct KSBatchCircuitOut {
  std::array<std::array<uint8_t, 16>, KS_BATCH_N> masked_ks;
  bool ok;
};

using aes_ks_batch_input_type = std::array<uint8_t, KS_BATCH_INPUT_SIZE>;
using aes_ks_batch_output_type = std::array<uint8_t, KS_BATCH_OUTPUT_SIZE>;

// SURF 2PC-AES-GCM encryption (Algorithm 1). One invocation covers AES_ENC_N
// blocks; the counter checks and the n encryptions share a single `ok` bit, so
// a counter disagreement zeroes the batch. No key commitments: the ciphertext is
// public output by construction, so there is no b_i / d_i / in-circuit SHA-256
// and the per-block cost is far below the keystream batch.
// Input (bytes, same shape both parties):
//   key 16 || ctr 16*N || pt 16*N
// Output: ct 16*N || ok 1
inline constexpr unsigned AES_ENC_N = 16;

inline constexpr unsigned aes_enc_in_size(const unsigned n) noexcept {
  return 16 + 32 * n;
}
inline constexpr unsigned aes_enc_out_size(const unsigned n) noexcept {
  return 16 * n + 1;
}

inline constexpr unsigned AES_ENC_INPUT_SIZE = aes_enc_in_size(AES_ENC_N);
inline constexpr unsigned AES_ENC_OUTPUT_SIZE = aes_enc_out_size(AES_ENC_N);

inline constexpr auto AES_ENC_FILEPATH =
    "../2pc/key-derivation/aes_gcm_enc_batch_16.txt";
inline constexpr auto AES_ENC_CIRCUIT_TAG = 13;
inline constexpr auto GCM_TAG_CIRCUIT_TAG = 14;

struct AESEncBatchCircuitIn {
  std::array<uint8_t, 16> key;
  std::array<std::array<uint8_t, 16>, AES_ENC_N> ctr;
  std::array<std::array<uint8_t, 16>, AES_ENC_N> pt;   // ALICE only
};

struct AESEncBatchCircuitOut {
  std::array<std::array<uint8_t, 16>, AES_ENC_N> ct;
  bool ok;
};

using aes_enc_batch_input_type = std::array<uint8_t, AES_ENC_INPUT_SIZE>;
using aes_enc_batch_output_type = std::array<uint8_t, AES_ENC_OUTPUT_SIZE>;

/**
   BINDER_FILEPATH. This is the filepath for the Bristol Format circuit that
computes the resumed-ClientHello PSK binder from both parties' PSK shares.
**/
inline constexpr auto BINDER_FILEPATH =
    "../2pc/key-derivation/derive_binder.txt";

/**
   AES128_FULL_FILEPATH. This contains the file path for the AES 128 full
circuit from n-for-1-auth.
**/
inline constexpr auto AES128_FULL_FILEPATH =
    "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt";

/**
   AES_CTR_JOINT_FILEPATH. This contains the file path for the AES CTR-mode
circuit where both parties learn the entire output.
**/
inline constexpr auto AES_CTR_JOINT_FILEPATH =
    "../2pc/key-derivation/aes_ctr_joint.txt";

/**
   AES_GCM_TAG_FILEPATH. This contains the file path for the AES GCM tagging
   circuit.
**/
inline constexpr auto AES_GCM_TAG_FILEPATH =
    "../2pc/key-derivation/derive_gcm_tag.txt";

/**
   AES_GCM_VFY_FILEPATH. This contains the filepath for the AES GCM tag
verification circuit.
**/
inline constexpr auto AES_GCM_VFY_FILEPATH =
    "../2pc/key-derivation/derive_gcm_verify.txt";

/**
   SHA256_FILEPATH. This contains the filepath for the SHA256 Bristol Format
   circuit. Here we use the SHA-256-multiblock-aligned circuit from
 n-for-1-auth.
 **/
inline constexpr auto SHA256_FILEPATH =
    "../emp-tool/emp-tool/circuits/files/bristol_format/"
    "sha-256-multiblock-aligned.txt";

/**
   MA_256_FILEPATH. This contains the filepath for the ModAdd256 Bristol
Fashion circuit. Here we use the ModAdd256 circuit made for this project.
**/
inline constexpr auto MA_256_FILEPATH = "../2pc/vhdl/ModAdd256.txt";
/**
 MA_256_FILEPATH. This contains the filepath for the ModAdd384 Bristol Fashion
 circuit. Here we use the ModAdd384 circuit made for this project.
**/
inline constexpr auto MA_384_FILEPATH = "../2pc/vhdl/ModAdd384.txt";
/**
 MA_521_FILEPATH. This contains the filepath for the ModAdd521 Bristol Fashion
 circuit. Here we use the ModAdd521 circuit made for this project.
**/
inline constexpr auto MA_521_FILEPATH = "../2pc/vhdl/ModAdd521.txt";

/**
   CATS_FILEPATH. This is the filepath for the DeriveCATS Bristol Format
 circuit.

 **/
inline constexpr auto CATS_FILEPATH = "../2pc/key-derivation/derive_cats.txt";

/**
   CHTS_FILEPATH. This is the filepath for the DeriveCHTS Bristol Format
circuit.
**/
inline constexpr auto CHTS_FILEPATH = "../2pc/key-derivation/derive_chts.txt";

/**
   CHI_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Client Handshake IV.
**/
inline constexpr auto CHI_FILEPATH =
    "../2pc/key-derivation/derive_client_handshake_iv.txt";

/**
 CHK_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Client Handshake key.
**/
inline constexpr auto CHK_FILEPATH =
    "../2pc/key-derivation/derive_client_handshake_key.txt";

/**
   CTI_FILEPATH. This is the filepath for the Bristol Format circuit that
derivies the Client Traffic IV.
**/
inline constexpr auto CTI_FILEPATH =
    "../2pc/key-derivation/derive_client_traffic_iv.txt";

/**
   CTK_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Client Traffic Key.
**/
inline constexpr auto CTK_FILEPATH =
    "../2pc/key-derivation/derive_client_traffic_key.txt";

/**
   DHS_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Derived handshake secret.
**/
inline constexpr auto DHS_FILEPATH = "../2pc/key-derivation/derive_dhs.txt";

/**
   EMS_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the early secret.
**/
inline constexpr auto EMS_FILEPATH = "../2pc/key-derivation/derive_ems.txt";

/**
   RMS_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the resumption secret.
**/
inline constexpr auto RMS_FILEPATH = "../2pc/key-derivation/combined_rms.txt";

/**
   PSK_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the psk secret.
**/
inline constexpr auto PSK_FILEPATH = "../2pc/key-derivation/combined_psk.txt";

/**
   PSK_FILEPATH_8. Filepath for the 8-byte ticket_nonce PSK circuit
   (OpenSSL/nginx origins).
**/
inline constexpr auto PSK_FILEPATH_8 =
    "../2pc/key-derivation/combined_psk_8.txt";

inline constexpr auto PSK_FILEPATH_0 =
    "../2pc/key-derivation/combined_psk_0.txt";

/**
   DHS_256_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the handshake secret with secrets on the 256-bit NIST curve.
**/
inline constexpr auto DH_256_FILEPATH =
    "../2pc/key-derivation/derive_hs_256.txt";

/**
   DHS_384_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the handshake secret with secrets on the 384-bit NIST curve.
**/
inline constexpr auto DH_384_FILEPATH =
    "../2pc/key-derivation/derive_hs_384.txt";

/**
 DHS_521_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the handshake secret with secrets on the 521-bit NIST curve.
**/
inline constexpr auto DH_521_FILEPATH =
    "../2pc/key-derivation/derive_hs_521.txt";

/**
     MS_FILEPATH. This is the filepath for the Bristol Format circuit that
   derives the master secret. **/
inline constexpr auto MS_FILEPATH = "../2pc/key-derivation/derive_ms.txt";

/**
   SATS_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Server Application Traffic Secret.
**/
inline constexpr auto SATS_FILEPATH = "../2pc/key-derivation/derive_sats.txt";

/**
   SHI_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Server Handshake IV.
**/
inline constexpr auto SHI_FILEPATH =
    "../2pc/key-derivation/derive_server_handshake_iv.txt";

/**
   SHK_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Sever Handshake key.
**/
inline constexpr auto SHK_FILEPATH =
    "../2pc/key-derivation/derive_server_handshake_key.txt";

/**
   STI_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Server Traffic IV.
***/
inline constexpr auto STI_FILEPATH =
    "../2pc/key-derivation/derive_server_traffic_iv.txt";

/**
 STK_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Sever traffic key.
**/
inline constexpr auto STK_FILEPATH =
    "../2pc/key-derivation/derive_server_traffic_key.txt";

/**
   SHTS_FILEPATH. This is the filepath for the Bristol Format circuit that
derives the Server Handshake Traffic Secret.
**/
inline constexpr auto SHTS_FILEPATH = "../2pc/key-derivation/derive_shts.txt";
/**
   CHS_256_FILEPATH. This is the filepath for the Bristol Format circuit that
derives shares of dHS, dHE, SHTS and CHTS, as well as the
client handshake key / IV and server handshake key / IV for 256-bit secret
shares.
**/
inline constexpr auto CHS_256_FILEPATH =
    "../2pc/key-derivation/derive_handshake_secrets_256.txt";

/**
   CHS_384_FILEPATH. This is the filepath for the Bristol Format circuit that
derives shares of dHS, dHE, SHTS and CHTS, as well as the
client handshake key / IV and server handshake key / IV for 384-bit secret
shares.
**/
inline constexpr auto CHS_384_FILEPATH =
    "../2pc/key-derivation/derive_handshake_secrets_384.txt";

/**
   TS_FILEPATH. This is the filepath for the Bristol Format circuit that derives
   shares of CATS, SATS, EMS, as well as ther server traffic key / IV and client
traffic key /IV
**/
inline constexpr auto TS_FILEPATH =
    "../2pc/key-derivation/derive_traffic_secrets_combined.txt";

/**
   GCM_FILEPATH. THis is the filepath for the GCM share derivation circuit for
producing all AES GCM shares (up to 1024).
**/
inline constexpr auto GCM_FILEPATH =
    "../2pc/key-derivation/derive_gcm_mult_shares.txt";

inline constexpr auto GCM_NAIVE_FILEPATH =
    "../2pc/key-derivation/derive_gcm_mult_shares_naive.txt";

inline constexpr auto AES_COMMIT_FILEPATH =
    "../2pc/key-derivation/derive_ctx_commitments.txt";
inline constexpr auto AES_COMMIT_IN_SIZE = 48;
inline constexpr auto AES_COMMIT_OUT_SIZE = 17;

inline constexpr auto AES_2PC_256_FILEPATH =
    "../2pc/key-derivation/aes_ctr_batch_16.txt";
inline constexpr auto AES_2PC_512_FILEPATH =
    "../2pc/key-derivation/aes_ctr_batch_32.txt";
inline constexpr auto AES_2PC_1K_FILEPATH =
    "../2pc/key-derivation/aes_ctr_batch_64.txt";
inline constexpr auto AES_2PC_2K_FILEPATH =
    "../2pc/key-derivation/aes_ctr_batch_128.txt";

inline constexpr auto AES_2PC_256_IN_SIZE = 288;
inline constexpr auto AES_2PC_512_IN_SIZE = 544;
inline constexpr auto AES_2PC_1K_IN_SIZE = 1056;
inline constexpr auto AES_2PC_2K_IN_SIZE = 2128;

inline constexpr auto AES_2PC_256_OUT_SIZE = 257;
inline constexpr auto AES_2PC_512_OUT_SIZE = 513;
inline constexpr auto AES_2PC_1K_OUT_SIZE = 1025;
inline constexpr auto AES_2PC_2K_OUT_SIZE = 2049;

inline constexpr auto ROTATE_KEY_FILEPATH =
    "../2pc/key-derivation/derive_rotate_key.txt";
// SURF ROTATE (RFC 8446 7.2), one direction per run.
// Input:  secret share 16 || secret' mask 16 || key' mask 16 (ALICE; BOB pads)
// Output: secret' 32 (lo^alice, hi^bob) || key'^alice_key_mask 16 || iv' 12
inline constexpr unsigned ROTATE_KEY_IN_SIZE = 48;
inline constexpr unsigned ROTATE_KEY_OUT_SIZE = 60;
inline constexpr auto ROTATE_CIRCUIT_TAG = 16;

struct RotateCircuitIn {
  std::array<uint8_t, 16> secret_share;
};
struct RotateCircuitOut {
  std::array<uint8_t, 16> next_share;
  std::array<uint8_t, 16> key_share;   // prover: its mask; verifier: key XOR mask
  std::array<uint8_t, 12> iv;
  std::array<uint8_t, 32> xor_mask;
};

using derive_rotate_input_type = std::array<uint8_t, ROTATE_KEY_IN_SIZE>;
using derive_rotate_output_type = std::array<uint8_t, ROTATE_KEY_OUT_SIZE>;

/**
    derive_hs_256_input_type. This is the input type that is expected for
 the 256-bit handshake derivation routines. This is placed here to make
 certain declarations less awkward.
 **/
using derive_hs_256_input_type =
    std::array<uint8_t,
               EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE>;

/**
   derive_hs_384_input_type. This is the input type that is expected for the
384-bit handshake derivation routines. This is placed here to make certain
declarations less awkward.
**/
using derive_hs_384_input_type =
    std::array<uint8_t,
               EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_384_IN_SIZE>;

/**
   derive_hs_output_type. This is the output type that is expected for
the handshake derivation routines. This is placed here to make certain
declarations less awkward.
**/
using derive_hs_output_type =
    std::array<uint8_t,
               EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE>;

/**
   derive_res_output_type. This is the output type that is expected for
the resumption derivation routines. This is placed here to make certain
declarations less awkward.
**/
using derive_res_input_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::RESUMPTION_SECRETS_IN_SIZE>;

using derive_res_output_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::RESUMPTION_SECRETS_OUTPUT_SIZE>;

/**
   derive_psk_output_type. This is the output type that is expected for
the psk derivation routines. This is placed here to make certain
declarations less awkward.
**/
using derive_psk_input_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::PSK_SECRETS_IN_SIZE>;

using derive_psk_input_type_8 =
    std::array<uint8_t, EmpWrapperAG2PCConstants::PSK_SECRETS_IN_SIZE_8>;

using derive_psk_input_type_0 =
    std::array<uint8_t, EmpWrapperAG2PCConstants::PSK_SECRETS_IN_SIZE_0>;

using derive_psk_output_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::PSK_SECRETS_OUTPUT_SIZE>;

using derive_binder_input_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::BINDER_IN_SIZE>;

using derive_binder_output_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::BINDER_OUT_SIZE>;

/**
   derive_ts_input_type. This is the input type that is expected for the
   traffic derivation routines. This is placed here to make certain declarations
less awkward.
**/
using derive_ts_input_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_IN_SIZE>;

/**
   derived_ts_output_type. This is the output type that is expected for
the traffic derivation routines. This is placed here to make certain
declarations less awkward.
**/
using derive_ts_output_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_OUTPUT_SIZE>;

/**
   derive_gcm_secrets_output_type. This is the output type that is expected for
the AES GCM share derivation circuits. This is placed here to make certain
declarations easier.
**/
using derive_gcm_secrets_output_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::GCM_OUTPUT_SIZE>;
/**
   derive_gcm_input_type. This is the input type that is expected for the AES
GCM share derivation circuits. This is placed here to make certain declarations
easier.
**/
using derive_gcm_input_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::GCM_IN_SIZE>;

/**
   aes_joint_input_type. This is the input type that is expected for the joint
AES CTR mode circuits. This is placed here to make certain declarations easier.
**/
using aes_joint_input_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::AES_GCM_INPUT_SIZE>;

/**
   aes_joint_output_type. This is the output type that is expected for the joint
AES CTR mode circuits. This is placed here to make certain declarations easier.
**/
using aes_joint_output_type =
    std::array<uint8_t, EmpWrapperAG2PCConstants::AES_GCM_OUTPUT_SIZE>;

using aes_gcm_tag_input_type = std::array<uint8_t, GCM_TAG_INPUT_SIZE>;
using aes_gcm_tag_output_type = std::array<uint8_t, GCM_TAG_OUTPUT_SIZE>;
using aes_gcm_vfy_input_type = std::array<uint8_t, GCM_VFY_INPUT_SIZE>;
using aes_gcm_vfy_output_type = std::array<uint8_t, GCM_VFY_OUTPUT_SIZE>;

/**
   HANDSHAKE_CIRCUIT_TAG_A. This is the tag for the setup file for the first
handshake circuit. This is primarily here to allow us to inspect the setup
files as they are made.
**/
inline constexpr auto HANDSHAKE_CIRCUIT_TAG_A = 0;
/**
   HANDSHAKE_CIRCUIT_TAG_B. This is the tag for the setup file for the second
handshake circuit. This is primarily here to allow us to inspect the setup files
as they are made.
**/
inline constexpr auto HANDSHAKE_CIRCUIT_TAG_B = 1;

/**
   TRAFFIC_CIRCUIT_TAG. This is the tag for the setup file for the traffic
secret circuit. This is primarily here to allow us to inspect the setup files as
they are made.
**/
inline constexpr auto TRAFFIC_CIRCUIT_TAG = 2;

/**
   GCM_CIRCUIT_TAG. This is the tag for the setup file for the gcm secret
circuit. This is primarily here to allow us to inspect the setup files as they
are made.
**/
inline constexpr auto GCM_CIRCUIT_TAG = 3;

/**
   AES_JOINT_CIRCUIT_TAG. This is the tag for the setup file for the joint aes
circuit. This is primarily here to allow us to inspect the setup files as they
are made.
**/
inline constexpr auto AES_JOINT_CIRCUIT_TAG = 4;

/**
   AES_SPLIT_CIRCUIT_TAG. This is the tag for the setup file for the split aes
circuit. This is primarily here to allow us to inspect the setup files as they
are made.
**/
inline constexpr auto AES_SPLIT_CIRCUIT_TAG = 5;

/**
   RMS_CIRCUIT_TAG. This is the tag for the setup file for the resumption
circuit. This is primarily here to allow us to inspect the setup files as they
are made.
**/
inline constexpr auto RMS_CIRCUIT_TAG = 6;

/**
   PSK_CIRCUIT_TAG. This is the tag for the setup file for the psk
circuit. This is primarily here to allow us to inspect the setup files as they
are made.
**/
inline constexpr auto PSK_CIRCUIT_TAG = 7;

/**
   PSK_CIRCUIT_TAG_8. Tag for the 8-byte ticket_nonce PSK circuit. Distinct from
   PSK_CIRCUIT_TAG so both PSK circuits can be preprocessed concurrently on their
   own MPC channels.
**/
inline constexpr auto PSK_CIRCUIT_TAG_8 = 8;

inline constexpr auto PSK_CIRCUIT_TAG_0 = 11;

using AESGCMBulkShareType = std::array<uint8_t, 1088 * 16>;

} // namespace EmpWrapperAG2PCConstants

/**
   EmpWrapperAGC2PC. This class contains a series of wrapper functions
   for interacting with the EMP toolkit's authenticated garbling (AG).

   This class primarily exists to make it easier to call code that interacts
with EmpAG2PC, but without adding extra overhead.

   This class is structured so that you may instantiate certain portions of it
   in stages. This is designed to move certain parts of the preprocessing stage
   before the TLS handshake, as in our tests this was rather expensive compared
to the mere cost of running the circuit (as one might expect).

   Please note that using this class requires you to have a clear
conceptualisation of which party plays which role in your protocol. The exact
usage will depend on your circuit too, as EMPAG2PC allows one to have different
outputs depending on the party. We typically stick to the prover playing "Alice"
and the verifier playing "Bob", but this is just our convention.

   Usage-wise, this class should model how one might use EmpAGPC. We provide a
series of builder functions that return the right circuit for a given file path
(or you may specify the right class using an argument). The initial
preprocessing can be carried out by calling do_preproc(), which in turn can be
granularised by calling do_preproc_indep() and do_preproc_dep(). Running the
actual circuit is done via calling the appropriate running function.
**/

class EmpWrapperAG2PC {
public:
  /**
     derive_hs_256_input_type. This is the input type that is expected for the
  256-bit handshake derivation routines. This is placed here to make certain
  declarations less awkward.
  **/
  using derive_hs_256_input_type =
      EmpWrapperAG2PCConstants::derive_hs_256_input_type;
  /**
     derive_hs_384_input_type. This is the input type that is expected for the
  384-bit handshake derivation routines. This is placed here to make certain
  declarations less awkward.
  **/
  using derive_hs_384_input_type =
      EmpWrapperAG2PCConstants::derive_hs_384_input_type;

  /**
     derive_hs_output_type. This is the output type that is expected
  for the handshake derivation routines. This is placed here to make certain
  declarations less awkward.
  **/
  using derive_hs_output_type = EmpWrapperAG2PCConstants::derive_hs_output_type;

  using derive_res_input_type =
      EmpWrapperAG2PCConstants::derive_res_input_type;

  using derive_res_output_type =
      EmpWrapperAG2PCConstants::derive_res_output_type;

  using derive_psk_input_type =
      EmpWrapperAG2PCConstants::derive_psk_input_type;

  using derive_psk_input_type_8 =
      EmpWrapperAG2PCConstants::derive_psk_input_type_8;

  using derive_psk_input_type_0 =
      EmpWrapperAG2PCConstants::derive_psk_input_type_0;

  using derive_psk_output_type =
      EmpWrapperAG2PCConstants::derive_psk_output_type;

  using derive_binder_input_type =
      EmpWrapperAG2PCConstants::derive_binder_input_type;

  using derive_binder_output_type =
      EmpWrapperAG2PCConstants::derive_binder_output_type;

  /**
     derive_ts_input_type. This is the input type that is expected for the
     traffic derivation routines. This is placed here to make certain
  declarations less awkward.
  **/
  using derive_ts_input_type = EmpWrapperAG2PCConstants::derive_ts_input_type;

  /**
     derive_ts_output_type. This is the output type that is expected for
  the traffic derivation routines. This is placed here to make certain
  declarations less awkward.
  **/
  using derive_ts_output_type = EmpWrapperAG2PCConstants::derive_ts_output_type;

  using derive_rotate_input_type =
      EmpWrapperAG2PCConstants::derive_rotate_input_type;
  using derive_rotate_output_type =
      EmpWrapperAG2PCConstants::derive_rotate_output_type;

  /**
     derive_gcm_input_type. This is the input type that is expected for the AES
  GCM share derivation circuits. This is placed here to make certain
  declarations easier.
  **/
  using derive_gcm_input_type = EmpWrapperAG2PCConstants::derive_gcm_input_type;
  /**
     derive_gcm_secrets_output_type. This is the output type that is expected
  for the AES GCM share derivation circuits. This is placed here to make certain
  declarations easier.
  **/
  using derive_gcm_secrets_output_type =
      EmpWrapperAG2PCConstants::derive_gcm_secrets_output_type;
  /**
     aes_joint_input_type. This is the input type that is expected for the joint
  AES CTR mode circuits. This is placed here to make certain declarations
  easier.
  **/
  using aes_joint_input_type = EmpWrapperAG2PCConstants::aes_joint_input_type;

  /**
     aes_joint_output_type. This is the output type that is expected for the
  joint AES CTR mode circuits. This is placed here to make certain declarations
  easier.
  **/
  using aes_joint_output_type = EmpWrapperAG2PCConstants::aes_joint_output_type;

  using aes_gcm_tag_input_type =
      EmpWrapperAG2PCConstants::aes_gcm_tag_input_type;
  using aes_gcm_tag_output_type =
      EmpWrapperAG2PCConstants::aes_gcm_tag_output_type;

  using aes_gcm_vfy_input_type =
      EmpWrapperAG2PCConstants::aes_gcm_vfy_input_type;
  using aes_gcm_vfy_output_type =
      EmpWrapperAG2PCConstants::aes_gcm_vfy_output_type;

  using aes_gcm_vfy_commit_input_type =
      EmpWrapperAG2PCConstants::aes_gcm_vfy_commit_input_type;
  using aes_gcm_vfy_commit_output_type =
      EmpWrapperAG2PCConstants::aes_gcm_vfy_commit_output_type;

  using aes_ks_batch_input_type =
      EmpWrapperAG2PCConstants::aes_ks_batch_input_type;
  using aes_ks_batch_output_type =
      EmpWrapperAG2PCConstants::aes_ks_batch_output_type;
  using aes_enc_batch_input_type =
      EmpWrapperAG2PCConstants::aes_enc_batch_input_type;
  using aes_enc_batch_output_type =
      EmpWrapperAG2PCConstants::aes_enc_batch_output_type;

private:
  /**
     SingleCircuitType. This type contains the type of the underlying 2PC object
  used in this class. This is private because it's only here to make certain
  usage less awkward.
  **/
  using SingleCircuitType = emp::C2PC<EmpWrapper<>, 1, emp::FerretCOT>;

  // Circuits that require templating for setup are more complicated.
  // Essentially, the number of executions is templated, making everything
  // slightly more complicated. To circumvent this, we independently choosen how
  // many rounds we will do: each execution increments a counter, and then we
  // reset that counter when we've gone past the exec count.
  static constexpr auto aes_iters = 2;
  using AESCircuitType =
      emp::AmortizedC2PC<EmpWrapper<>, aes_iters, emp::FerretCOT>;

  // 2 is the default because we need to derive shares once for the Client key
  // and once for the server key.
  static constexpr auto kMaxKeyUpdates = 1;
  static constexpr auto gcm_iters = 2 + 2 * kMaxKeyUpdates;
  using GCMCircuitType =
      emp::AmortizedC2PC<EmpWrapper<>, gcm_iters, emp::FerretCOT>;

  // One iteration per attested record's tag.
  static constexpr auto tag_iters = 8;
  using GCMTagCircuitType =
      emp::AmortizedC2PC<EmpWrapper<>, tag_iters, emp::FerretCOT>;

  // One iteration per batch of AES_ENC_N plaintext blocks. Four batches covers
  // a 1 KB request at N=16.
  static constexpr auto aes_enc_iters = 4;
  using AESEncCircuitType =
      emp::AmortizedC2PC<EmpWrapper<>, aes_enc_iters, emp::FerretCOT>;

  // One iteration per attested record. TLS allows many records per connection,
  // but attestation only covers the captured response, so this is sized to a
  // handful rather than to the protocol maximum.
  static constexpr auto vfy_iters = 128;
  using GCMVfyCircuitType =
      emp::AmortizedC2PC<EmpWrapper<>, vfy_iters, emp::FerretCOT>;

  // One iteration per batch of KS_BATCH_N blocks. ks_iters * KS_BATCH_N must
  // equal MaskConstants::kNumMasks (asserted in ThreePartyHandshake.cc).
  static constexpr auto ks_iters = EmpWrapperAG2PCConstants::KS_MAX_INVOCATIONS;
  using KSBlockCircuitType =
      emp::AmortizedC2PC<EmpWrapper<>, ks_iters, emp::FerretCOT>;

  // One iteration per rotated direction: client then server per key update.
  static constexpr auto rotate_iters = 2;
  using RotateCircuitType =
      emp::AmortizedC2PC<EmpWrapper<>, rotate_iters, emp::FerretCOT>;

  /**
     EmpWrapperAG2PC. This constructor simply creates the underlying EMP objects
  and loads the circuit from `filepath`. This function is private to encourage
     calling the builder functions instead. This function does not throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] filepath: the filepath for the circuit.
  **/
  EmpWrapperAG2PC(SSL *const ssl, const char *const filepath) noexcept;

  /**
     get_secret_size. This function is a helper function that returns 256 if
  filepath corresponds to the 256-bit secret derivation function, 384 if
  filepath corresponds to the 384-bit secret derivation function, and 0
  otherwise. This function is used to enforce certain runtime assertions.
     @param[in] filepath: the filepath of the circuit.
     @return 256 if filepath is for 256 bit secret derivation, 384 if filepath
  is for 384 bit secret derivation, 0 otherwise.
  **/
  static constexpr unsigned
  get_secret_size(const char *const filepath) noexcept;

  /**
     exec_small_internal. This function is the internal function for running
  garbled circuits. derivation, as well as AES encryptions. This is internal to
  handle certain nasty/difficult parts of the API regarding sizes. This function
  returns true if successful and false otherwise. The inputs are taken from
  `in_secret` and written into `output`. This function never throws.
     @tparam input_size: the size of the input in bytes.
     @tparam output_size: the size of the output in bytes.
     @param[in] in_secret: the input secret array.
     @param[out] out_secret: the location to write the output secret.
     @return true if successful, false otherwise.
  **/
  template <unsigned long input_size, unsigned long output_size>
  bool exec_small_internal(const std::array<uint8_t, input_size> &in_secret,
                           std::array<uint8_t, output_size> &output) noexcept;

public:
  /**
     build_derive_hs_256. This function returns a new EmpWrapperAG2PC object
  that can be used for deriving 256-bit handshake secrets. This function does
  not throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This
  is asserted.
     @return a new EmpWrapperAGC2PC object that can be used for deriving 256-bit
  handshake secrets.
  **/
  static EmpWrapperAG2PC *build_derive_hs_256(SSL *const ssl, const int mode,
                                              const int tag) noexcept;

  static EmpWrapperAG2PC *build_gcm_vfy_circuit(SSL *const ssl, const int mode,
                                                const int tag) noexcept;

  static EmpWrapperAG2PC *build_gcm_vfy_commit_circuit(
      SSL *const ssl, const int mode, const int tag) noexcept;

  static EmpWrapperAG2PC *build_gcm_tag_circuit(SSL *const ssl, const int mode,
                                                const int tag) noexcept;

  static EmpWrapperAG2PC *build_ks_batch_circuit(SSL *const ssl, const int mode,
                                                 const int tag) noexcept;

  bool derive_ks_batch(const aes_ks_batch_input_type &in,
                       aes_ks_batch_output_type &out) noexcept;

  /**
     ks_batches_remaining. How many more keystream-circuit invocations fit
     before AmortizedC2PC would re-preprocess inline. Callers drive that
     re-preprocessing explicitly instead (see derive_keystream), because an
     inline one fires mid-call at a point the two parties do not agree on.
  **/
  inline unsigned ks_batches_remaining() const noexcept {
    return (run_times >= ks_iters) ? 0u
                                   : static_cast<unsigned>(ks_iters) - run_times;
  }

  /**
     build_aes_enc_circuit. Builds the batched AES-GCM encryption circuit
     (Algorithm 1's C line). ALICE is the prover and supplies the plaintext.
  **/
  static EmpWrapperAG2PC *build_aes_enc_circuit(SSL *const ssl, const int mode,
                                                const int tag) noexcept;

  /**
     encrypt_batch. Runs one batch: AES_ENC_N ciphertext blocks plus the shared
     ok bit. Re-preprocesses automatically once aes_enc_iters batches have run.
  **/
  bool encrypt_batch(const aes_enc_batch_input_type &in,
                     aes_enc_batch_output_type &out) noexcept;

  /**
   build_derive_hs_384. This function returns a new EmpWrapperAG2PC object that
can be used for deriving 384-bit handshake secrets. This function does not
throw.
   @param[in] ssl: the SSL connection to use. Must not be null.
   @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This is
asserted.
   @return a new EmpWrapperAGC2PC object that can be used for deriving 384-bit
handshake secrets.
**/
  static EmpWrapperAG2PC *build_derive_hs_384(SSL *const ssl, const int mode,
                                              const int tag) noexcept;

  /**
     build_derive_hs_circuit. This function returns a new EmpWrapperAG2PC object
  that can be used for deriving handshake secrets corresponding to `nid`. This
  function does not throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] nid: the BoringSSL ID for the curve used.
     @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This
  is asserted.
     @return a new EmpWrapperAGC2PC object that can be used for deriving
  handshake secrets over a curve with id `nid`. If `nid` is not a valid ID, this
  function returns a nullptr.
  **/
  static EmpWrapperAG2PC *build_derive_hs_circuit(SSL *const ssl,
                                                  const uint16_t id,
                                                  const int mode,
                                                  const int tag) noexcept;

  /**
     build_derive_ts_circuit. This function returns a new EmpWrapperAGC2PC
  object that can be used for deriving traffic secrets. This function does not
  throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This
  is asserted.
     @return a new EmpWrapperAG2PC object that can be used for deriving traffic
  secrets.
  **/
  static EmpWrapperAG2PC *build_derive_ts_circuit(SSL *const ssl,
                                                  const int mode,
                                                  const int tag) noexcept;

  /**
     build_derive_rotate_circuit. SURF ROTATE key-update circuit
  (derive_rotate_key.txt). A single circuit re-preprocessed explicitly before
  every run after the first; both sides call derive_rotate the same number of
  times, so the re-preprocessing stays in lock-step.
  **/
  static EmpWrapperAG2PC *build_derive_rotate_circuit(SSL *const ssl,
                                                      const int mode,
                                                      const int tag) noexcept;

  bool derive_rotate(const derive_rotate_input_type &in,
                     derive_rotate_output_type &out) noexcept;

  /**
     build_resumption_circuit. This function returns a new EmpWrapperAGC2PC
  object that can be used for computing resumption secrets with joint output. This
  function does not throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This
  is asserted.
     @return a new EmpWrapperAG2PC object that can be used for resumption secrets
  with joint output.
  **/
  static EmpWrapperAG2PC *build_derive_res_circuit(SSL *const ssl,
                                                  const int mode,
                                                  const int tag) noexcept;


  /**
     build_psk_circuit. This function returns a new EmpWrapperAGC2PC
  object that can be used for computing psk secrets with joint output. This
  function does not throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This
  is asserted.
     @return a new EmpWrapperAG2PC object that can be used for resumption secrets
  with joint output.
  **/
  static EmpWrapperAG2PC *build_derive_psk_circuit(SSL *const ssl,
                                                  const int mode,
                                                  const int tag) noexcept;

  /**
     build_derive_psk_circuit_8. As build_derive_psk_circuit but loads the
  8-byte ticket_nonce circuit (combined_psk_8.txt) for OpenSSL/nginx origins.
  **/
  static EmpWrapperAG2PC *build_derive_psk_circuit_8(SSL *const ssl,
                                                     const int mode,
                                                     const int tag) noexcept;

  static EmpWrapperAG2PC *build_derive_psk_circuit_0(SSL *const ssl,
                                                     const int mode,
                                                     const int tag) noexcept;

  /**
     build_derive_binder_circuit. This function returns a new EmpWrapperAG2PC
  object that can be used for computing the PSK binder for a resumed
  ClientHello. Both parties feed their PSK share; the binder is public output,
  since it ships in the clear inside the ClientHello. This function does not
  throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] mode: emp::ALICE if the caller is the prover, emp::BOB
  otherwise.
     @return a new EmpWrapperAG2PC object for computing the PSK binder.
  **/
  static EmpWrapperAG2PC *build_derive_binder_circuit(SSL *const ssl,
                                                      const int mode,
                                                      const int tag) noexcept;

  /**
     build_joint_aes_circuit. This function returns a new EmpWrapperAGC2PC
  object that can be used for computing AES encryptions with joint output. This
  function does not throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This
  is asserted.
     @return a new EmpWrapperAG2PC object that can be used for AES encryptions
  with joint output.
  **/
  static EmpWrapperAG2PC *build_joint_aes_circuit(SSL *const ssl,
                                                  const int mode,
                                                  const int tag) noexcept;

  /**
     build_gcm_circuit. This function returns a new EmpWrapperAGC2PC object that
  can be used for computing AES GCM power shares. This function does not throw.
     @param[in] ssl: the SSL connection to use. Must not be null.
     @param[in] mode: emp::ALICE if the caller plays, emp::BOB otherwise. This
  is asserted.
     @return a new EmpWrapperAG2PC object that can be used for computing AES GCM
  shares.
  **/
  static EmpWrapperAG2PC *build_gcm_circuit(SSL *const ssl, const int mode,
                                            const int tag) noexcept;

  /**
     derive_ts. This function accepts as input a set of secrets (`in_secret`)
  and runs the 2PC circuit between this object and the other party, storing the
  results in `out`. This funciton returns true if successful and false
  otherwise. This function does not throw.

     @param[in] in_secret. The input secret. More can be seen about the layout
  in the remarks.
     @param[out] out. The location to write the output secret. More can be seen
  about the layout in the remarks.
     @return true if successful, false otherwise.
     @remarks The secret layout for this function is a bit tenuous. Briefly, for
  256 bit secrets our circuits give the lower 128 bits to the "Alice" party and
  the upper 128 bits to the "Bob" party. Because emp was not built with this use
  case in mind, each party must supply an appropriate xor mask in their input
  secret that covers the output secrets they have. However, emp is not built
  with this in mind, and so each party gets the (essentially encrypted) output
  secrets.

     For the output:

     1) The first  32 bytes are the CATS.
     2) The second 32 bytes are the SATS.
     3) The third  32 bytes are the EMS.
     4) The next 28 bytes are the client key and IV.
     5) The last 28 bytes are the server key and IV.

     For the input:

     1) The first 16 bytes are the shares of the master secret (MS), with the
     division being that ALICE supplies the first 16 bytes of MS and Bob
  supplies the second 16 bytes of MS. 2) The next 16 bytes are the shares of H3
  = Hash(ClientHello || ... || ServerFinished). This follows the same convention
  as for the MS. 3) The next 104 bytes are the xor mask described above.
  **/
  bool derive_ts(const derive_ts_input_type &in_secret,
                 derive_ts_output_type &out) noexcept;

  /**
     derive_hs. This function accepts an input set of secrets (`in_secret`) and
     and runs the 2PC circuit between this object and the other party, storing
  the results in `out`. This function returns true if successful and false
  otherwise. This function does not throw. This function can only be called on
  for the 256-bit NIST curves: otherwise a runtime assertion is triggered.

     @param[in] in_secret. The input secret. More can be seen about the layout
  in the remarks.
     @param[out] out. The location to write the output secret. More can be seen
  about the layout in the remarks.
     @return true if successful, false otherwise.

     @remarks The secret layout for this function is a bit tenuous. Briefly, for
  256 bit secrets our circuits give the lower 128 bits to the "Alice" party and
  the upper 128 bits to the "Bob" party. Because emp was not built with this use
  case in mind, each party must supply an appropriate xor mask in their input
  secret that covers the output secrets they have. However, emp is not built
  with this in mind, and so each party gets the (essentially encrypted) output
  secrets.

     For the output:

     1) The first 32 bytes are the dHE secret.
     2) The second 32 bytes are the CHTS.
     3) The third 32 bytes are the SHTS.
     4) The fourth 32 bytes are the DHS.
     5) The fifth 32 bytes are the MS.
     6) Finally, the last 32 bytes are the fk_s value.

     For the input:

     1) The first 32 bytes are  H_2 = Hash(ClientHello || ServerHello) (Alice)
  or unused for Bob. 2) The next 80 bytes are the xor mask described above. 3)
  The next 32 bytes are the additive secret derived in the ECtF routine.
  **/
  bool derive_hs(const derive_hs_256_input_type &in_secret,
                 derive_hs_output_type &out) noexcept;

  /**
   derive_hs. This function accepts an input set of secrets (`in_secret`) and
   and runs the 2PC circuit between this object and the other party, storing the
results in `out`. This function returns true if successful and false otherwise.
This function does not throw. This function can only be called on for the
384-bit NIST curves: otherwise a runtime assertion is triggered.

   @param[in] in_secret. The input secret. More can be seen about the layout in
the remarks.
   @param[out] out. The location to write the output secret. More can be seen
about the layout in the remarks.
   @return true if successful, false otherwise.

   @remarks The secret layout for this function is a bit tenuous. Briefly, for
256 bit secrets our circuits give the lower 128 bits to the "Alice" party and
the upper 128 bits to the "Bob" party. Because emp was not built with this use
case in mind, each party must supply an appropriate xor mask in their input
secret that covers the output secrets they have. However, emp is not built with
this in mind, and so each party gets the (essentially encrypted) output secrets.

   For the output:

   1) The first 32 bytes are the dHE secret.
   2) The second 32 bytes are the CHTS.
   3) The third 32 bytes are the SHTS.
   4) The fourth 32 bytes are the DHS.
   5) The fifth 32 bytes are the MS.
   6) Finally, the last 32 bytes are the fk_s value.

   For the input:

   1) The first 32 bytes are either  H_2 = Hash(ClientHello || ServerHello)
(Alice) or unused (Bob). 2) The next 80 bytes are the xor mask described above.
   3) The next 48 bytes are the additive secret derived in the ECtF routine.
**/
  bool derive_hs(const derive_hs_384_input_type &in,
                 derive_hs_output_type &out) noexcept;

  bool derive_res(const derive_res_input_type &in,
                 derive_res_output_type &out) noexcept;

  bool derive_psk(const derive_psk_input_type &in,
                 derive_psk_output_type &out) noexcept;

  // 8-byte ticket_nonce variant (OpenSSL/nginx origins).
  bool derive_psk(const derive_psk_input_type_8 &in,
                 derive_psk_output_type &out) noexcept;

  bool derive_psk(const derive_psk_input_type_0 &in,
                  derive_psk_output_type &out) noexcept;

  /**
     derive_binder. Runs the binder circuit. Both parties supply their 16-byte
  PSK share; only Alice supplies H(Truncate(ClientHello)). Both learn the
  32-byte binder.
     Input layout:  psk_share (16) || ch_hash (32, Alice only)
     Output layout: binder (32), public to both parties.
  **/
  bool derive_binder(const derive_binder_input_type &in,
                     derive_binder_output_type &out) noexcept;

  /**
     derive_gcm_shares. This function accepts as input an AES key share and a
  mask and returns (in `out`) this parties' share of the AES GCM powers. This
  function returns true on success and false otherwise. This function does not
  throw.
     @param[in] in. The input secret. More can be seen on the layout in the
  remarks.
     @param[out] out. The location to write the output secret. More about the
  layout can be seen in the remarks.
     @return true if successful, false otherwise.
     @remarks The secret layout here is as follows:

     1) The first 16 bytes are a share of h.
     ....

     And so on.

     The input layout is slightly different:
     1) The first 16 bytes contain the AES key share.
     2) The remaining bytes contain the mask for the GCM mask.
  **/
  bool derive_gcm_shares(const derive_gcm_input_type &in,
                         derive_gcm_secrets_output_type &out) noexcept;

  /**
     do_joint_aes. This function accepts as input the plaintext (from Alice, or
  unused values from Bob), a key share, an IV share, and an output IV mask,
     producing a ciphertext and a new (additively shared) IV in `out`.
     This function returns true on success and false otherwise. This function
  does not throw.
     @param[in] in. The input secret. More can be seen on the layout in the
  remarks.
     @param[out] out. The location to write the output secret. More about the
  layout can be seen in the remarks.
     @return true if successful, false otherwise.
     @remarks The input layout here is as follows:

     1) The first 16 bytes are either the plaintext (Alice) or unused bytes
  (Bob) 2) The second 16 bytes are the key share. 3) The third 16 bytes are the
  expanded IV share. 4) The fourth 16 bytes are the mask for the newly produced
  IV.

     The output layout is:
     1) The first 16 bytes are the ciphertext. Both parties see this.
     2) The second 16 bytes are the expanded IV. Alice's output is their input
  IV mask, whereas Bob's share is the expanded IV \xor Alice's IV mask.
  **/
  bool do_joint_aes(const aes_joint_input_type &in,
                    aes_joint_output_type &out) noexcept;

  bool make_tag(const EmpWrapperAG2PC::aes_gcm_tag_input_type &in,
                EmpWrapperAG2PC::aes_gcm_tag_output_type &out) noexcept;

  bool verify_tag(const EmpWrapperAG2PC::aes_gcm_vfy_input_type &in,
                  EmpWrapperAG2PC::aes_gcm_vfy_output_type &out) noexcept;
  bool verify_tag_commit(
      const EmpWrapperAG2PC::aes_gcm_vfy_commit_input_type &in,
      EmpWrapperAG2PC::aes_gcm_vfy_commit_output_type &out) noexcept;

  /**
     do_prepropc. This function executes both the dependent and independent
  preprocessing used for this circuit. This function does not throw.
  **/
  void do_preproc() noexcept;
  /**
     do_prepropc. This function executes the function independent preprocessing
     used for this circuit. This function does not throw.
  **/
  void do_preproc_indep() noexcept;
  /**
     do_prepropc. This function executes the function dependent preprocessing
     used for this circuit. This function does not throw.
  **/
  void do_preproc_dep() noexcept;

  /**
     get_size. This function returns the secret size associated with this
     circuit. See the doc for `secret_size` for more. This function does not
     throw or modify this object.
     @return the size of the secret associated with this circuit.
  **/
  inline unsigned get_size() const noexcept;

  /**
     reset_counter. This function resets the bandwidth counter associated
  globally with the socket that is used by this circuit object. Care must be
  taken to make sure that this is actually what you want to do. This function
  does not throw.
  **/
  inline void reset_counter() noexcept;

  /**
     get_counter. This function retrieves the bandwidth counter associated
  globally with the socket that is used by this circuit object. Care must be
  taken to make sure that this is actually what you want to do. This function
  does not throw or modify this object.
     @return the number of bytes sent by sockets that share the same underlying
  socket.
  **/
  inline uint64_t get_counter() const noexcept;

  /**
     get_round_counter. This function retrieves the round counter (number of
  outbound messages flushed) associated with the socket used by this circuit
  object. It is a proxy for the number of communication rounds. The same caveats
  as get_counter() apply. This function does not throw or modify this object.
     @return the number of rounds (outbound messages) for the underlying socket.
  **/
  inline uint64_t get_round_counter() const noexcept;

  /**
     has_io_failed. This function returns true if the underlying connection has
  suffered a fatal I/O error or a 2PC consistency check (e.g. emp's FEQ) has
  failed. Once set, any preprocessing or online execution on this circuit (and
  on any other circuit sharing the connection) produces garbage: the caller
  must abandon the protocol run. This function does not throw.
     @return true if this circuit's connection is no longer usable.
  **/
  inline bool has_io_failed() const noexcept;

private:
  /**
   set_twopc. This is a setup function that enables the twopc unamortized
circuit. This function does not throw.
   @param[in] mode: emp::ALICE if the player is ALICE, emp::BOB otherwise.
   @param[in] tag: the tag to use for the circuit.
**/
  void set_twopc(const int mode, const int tag) noexcept;
  /**
     set_gcm. This is a setup function that enables the amortized gcm circuit.
  This function does not throw.
     @param[in] mode: emp::ALICE if the player is ALICE, emp::BOB otherwise.
     @param[in] tag: the tag to use for the circuit.
  **/
  void set_gcm(const int mode, const int tag) noexcept;

  /**
     set_aes. This is a setup function that enables the aes circuit. This
  function does not throw.
     @param[in] mode: emp::ALICE if the player is ALICE, emp::BOB otherwise.
     @param[in] tag: the tag to use for the circuit.
  **/
  void set_aes(const int mode, const int tag) noexcept;

  void set_gcm_vfy(const int mode, const int tag) noexcept;
  void set_gcm_vfy_commit(const int mode, const int tag) noexcept;
  void set_gcm_tag(const int mode, const int tag) noexcept;
  void set_ks_batch(const int mode, const int tag) noexcept;
  void set_aes_enc(const int mode, const int tag) noexcept;
  void set_rotate(const int mode, const int tag) noexcept;

  // This is just an enum to denote which unique ptr is active.
  enum class CircuitType {
    NONE = 0,
    SINGLE,
    GCM,
    GCM_VFY,
    GCM_TAG,
    AES,
    KS_BATCH,
    AES_ENC,
    ROTATE
  };

  /**
     wrapper. This variable contains the wrapper around the EmpThreadSocket used
  in this class. This is here solely to tie the lifetime of the circuit to
  `this` object.
  **/
  EmpWrapper<> wrapper;
  /**
     addr. This variable contains the wrapper around the EmpThreadSocket used in
  this class. This is here solely to tie the lifetime of the circuit to `this`
  object. Note that the members of this always point to `addr`: this is only
  here to satisfy certain emp usage.
  **/
  EmpWrapper<> *addr[2];

  /**
     circuit. This variable contains the BristolFormat circuit that is used for
  this 2PC. This is used during setup to provide the right input circuit.
  **/
  emp::BristolFormat circuit;

  /**
     twopc. This is the member variable that is actually used to interact with
  emp if the circuit is a non-amortized circuit.
  **/
  std::unique_ptr<SingleCircuitType> twopc;

  /**
     aes. This is the member variable that is actually used to interact with emp
  if the circuit is an aes circuit.
  **/
  std::unique_ptr<AESCircuitType> aes;
  /**
     gcm. This is the member variable that is actually used to interact with emp
  if the circuit is a gcm circuit.
  **/
  std::unique_ptr<GCMCircuitType> gcm;

  std::unique_ptr<GCMVfyCircuitType> gcm_vfy;
  std::unique_ptr<GCMTagCircuitType> gcm_tag;
  std::unique_ptr<KSBlockCircuitType> ks_batch;
  std::unique_ptr<AESEncCircuitType> aes_enc;
  std::unique_ptr<RotateCircuitType> rotate;

  /**
     secret_size. This variable is used as a guard to make sure that the correct
  functions are called at runtime for handshake secret derivation.
  **/
  unsigned secret_size;

  /**
     type. This indicates which type of circuit is being used.
  **/
  CircuitType type{CircuitType::NONE};

  /**
     run_times. This variable indicates how many times the circuit has been run.
  This is used to automatically trigger preprocessing if needed.
  **/
  unsigned run_times{0};
};

// Inline definitions live here.
#include "EmpWrapperAG2PC.inl"

#endif
