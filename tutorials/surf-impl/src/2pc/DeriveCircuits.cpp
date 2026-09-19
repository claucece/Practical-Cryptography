/**
   This file contains the code for deriving the circuits used by this project.
It is not a test file and it should be considered as a separate entity from the
rest of the code.

Please note that the notation used in this file for various circuits etc comes
from https://eprint.iacr.org/2020/1044.pdf, in particular Figure 1.

This file is a little bit long, but it seems to actually be the best way to keep
the code separate from the rest of the code-base.

Understanding the code:

- This file is designed to be self-contained. Where appropriate, each function
has a "testable" version that lets you check that it works as we would expect
(compared to n-for-1 auth).

- This file deals a lot with sharing the output of a garbled circuit. We employ
3 distinct approaches for this:
  1. For 256-bit outputs, we give the lower 128-bits to Alice and the upper
128-bits to Bob. Each party must supply a unique 128 bit mask to prevent
leakage.
  2. For 128-bit outputs in the combined circuit, both Alice and Bob supply a
128-bit mask. Alice receives the keys produced (xored with the mask) whereas Bob
receives the IVs produced (xored with the mask).
  3. For 128-bit outputs, Bob must supply a unique 128-bit mask (m) to xor
against the produced output (o). Alice receives m \xor o and Bob receives
nothing. We do this because if we were to follow approach (1), either Alice or
Bob could attempt to brute-force the key after just a few messages -- it would
take around 2^64 operations, which isn't high-enough. This allows us to do
better: in fact, if Bob's mask is unique, this is equivalent to a OTP. This does
mean that all circuits that require 128-bit inputs must deal with removing this
mask -- in practice, this just requires Alice to provide m \xor o, and for Bob
to provide m, which can then be xored together. This only costs an additional
128 XOR gates, which are nominally expensive in a garbled circuit.
**/

#include "../Decl.hpp" // Needed for macros.
#include "../emp-ot/emp-ot/emp-ot.h"
#include "../mta/EmpBlockArray.hpp" // Needed for an array that respects attributes.
#include "../ssl/Util.hpp"          // Needed for various utilities.
#include "CircuitSynthesis.hpp"     // Needed for circuit synthesis.
#include <openssl/sha.h>

// The first load of functions are essentially just utilities.

// This function takes a public output and returns an array of bytes.
// The way this function works is as follows: emp outputs each bit of
// its output into a separate block. Assuming that there are 8-bits in a byte,
// we can copy over each set of 8 blocks into our array, bit by bit.
// We assume that the output is little-endian, so we start on the lower
// element and shift along.
// NOTE: as a pre-condition we assume that output has at least 8 * nr_bytes
// entries. If this is not true, you will encounter undefined behaviour.
template <unsigned nr_bytes>
static std::array<unsigned char, nr_bytes>
print_hash_to_string(const emp::block *const output) {
  unsigned char digest_char[nr_bytes]{};

  // Just to make sure the hard-coding doesn't break anything.
  // N.B This may not actually be a problem because emp probably assumes
  // that CHAR_BIT == 8.
  static_assert(CHAR_BIT == 8, "Error: function expects CHAR_BIT == 8");

  bool output_bool[nr_bytes * 8];
  emp::ProtocolExecution::prot_exec->reveal(output_bool, emp::PUBLIC, output,
                                            nr_bytes * 8);

  for (unsigned i = 0; i < nr_bytes; i++) {
    unsigned char w = 1;
    for (unsigned j = 0; j < 8; j++) {
      digest_char[i] += static_cast<unsigned char>(
          w * static_cast<unsigned char>(output_bool[i * 8 + j]));
      w *= 2;
    }
  }

  std::array<unsigned char, nr_bytes> out;
  memcpy(out.data(), digest_char, nr_bytes);
  return out;
}

static std::array<unsigned char, 32> get_empty_hash() noexcept {
  static constexpr std::array<unsigned char, 32> empty_hash{
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
      0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
      0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

  return empty_hash;
}

template <unsigned int length> static EC_GROUP *get_curve() noexcept {
  // This function returns the group associated with the NIST curve with
  // bit-size `length`. This is used for modular arithmetic.
  static_assert(length == 256 || length == 384 || length == 521,
                "Error: mismatched size");

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  static constexpr auto curve_id = [&]() {
    if constexpr (length == 256) {
      return SSL_CURVE_SECP256R1;
    } else if constexpr (length == 384) {
      return SSL_CURVE_SECP384R1;
    } else {
      return SSL_CURVE_SECP521R1;
    }
  }();

  return EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id));
}

template <unsigned prime_length>
static std::array<bool, prime_length>
serialise_bignum(const BIGNUM *const num) noexcept {
  // This function serialises `num` into an array as a big endian number.
  // This is just used for generating circuits and will not be used in the
  // circuits themselves.
  assert(num);
  std::array<bool, prime_length> arr;
  for (unsigned i = 0; i < prime_length; i++) {
    arr[i] = BN_is_bit_set(num, static_cast<int>(i));
  }
  return arr;
}

template <unsigned size>
static constexpr std::array<bool, 8 * size>
chars_to_bools(const unsigned char *const arr) noexcept {
  // This function turns an input pointer into a sequence of
  // bools. Each bit in the input char array maps to a single bool
  // in the output array.
  // Note: arr must point to an array of at least `size` unsigned
  // chars, else the result is undefined.
  std::array<bool, 8 * size> out;
  for (unsigned i = 0; i < size; i++) {
    unsigned char w = arr[i];
    for (unsigned j = 0; j < 8; j++) {
      out[i * 8 + j] = w & 1;
      w >>= 1;
    }
  }

  return out;
}

template <unsigned size>
static constexpr EmpBlockArray<size * 8>
chars_to_blocks(const unsigned char *const arr) noexcept {
  // This function turns an input pointer of chars into a sequence of blocks.
  // Each bit in the input char array maps to a single block in the output
  // array. Note that emp::setup_plain_prot must have been called before a call
  // to this function.
  EmpBlockArray<size * 8> out{};
  const emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  const emp::block one = emp::CircuitExecution::circ_exec->public_label(true);

  for (unsigned i = 0; i < size; i++) {
    unsigned char w = arr[i];
    for (unsigned j = 0; j < 8; j++) {
      out[i * 8 + j] = w & 1 ? one : zero;
      w >>= 1;
    }
  }
  return out;
}

static void extract_secret_each(emp::block *const derived_secret,
                                bool *const alice_out_ptr = nullptr,
                                bool *const bob_out_ptr = nullptr) {

  bool alice_out_bool[128];
  bool bob_out_bool[128];
  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool, emp::ALICE,
                                            derived_secret, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool, emp::BOB,
                                            derived_secret + 128, 128);

  // Write to the out parameters if supplied.
  if (alice_out_ptr) {
    memcpy(alice_out_ptr, alice_out_bool, sizeof(bool) * 128);
  }

  if (bob_out_ptr) {
    memcpy(bob_out_ptr, bob_out_bool, sizeof(bool) * 128);
  }
}

// This enum exists solely to specialise DeriveIVOrKey.
// In essense, this enum specifies which type of derivation we are doing:
// either IVs for the handshake, keys for the handshake, IVs for the record
// layer, keys for the record layer, or other secrets.
enum class TypeOfDerivation {
  CLIENT_HANDSHAKE_IV = 0,
  CLIENT_TRAFFIC_IV = 1,
  SERVER_HANDSHAKE_IV = 2,
  SERVER_TRAFFIC_IV = 3,
  CLIENT_HANDSHAKE_KEY = 4,
  CLIENT_TRAFFIC_KEY = 5,
  SERVER_HANDSHAKE_KEY = 6,
  SERVER_TRAFFIC_KEY = 7,
  DHS = 8,
  SERVER_HTS = 9,
  CLIENT_HTS = 10,
  MS = 11,
  CATS = 12,
  SATS = 13,
  EMS = 14,
  FK_S = 15,
  RMS = 16,
  PSK = 17,
  SIZE = 18
};

template <TypeOfDerivation mode>
static constexpr const char *get_tag() noexcept {
  // This function exists to return the right tag for calls into the
  // hkdf_expand_label function.
  static_assert(mode != TypeOfDerivation::SIZE, "mode cannot == SIZE");
  // We don't call tag for MS: this is because the master secret isn't
  // derived using a call to hkdf_expand_label.
  static_assert(mode != TypeOfDerivation::MS, "MS should not call get_tag");
  switch (mode) {
  case TypeOfDerivation::CLIENT_HANDSHAKE_IV:
  case TypeOfDerivation::CLIENT_TRAFFIC_IV:
  case TypeOfDerivation::SERVER_HANDSHAKE_IV:
  case TypeOfDerivation::SERVER_TRAFFIC_IV:
    return "iv";
  case TypeOfDerivation::DHS:
    return "derived";
  case TypeOfDerivation::CLIENT_HANDSHAKE_KEY:
  case TypeOfDerivation::CLIENT_TRAFFIC_KEY:
  case TypeOfDerivation::SERVER_HANDSHAKE_KEY:
  case TypeOfDerivation::SERVER_TRAFFIC_KEY:
    return "key";
  case TypeOfDerivation::SERVER_HTS:
    return "s hs traffic";
  case TypeOfDerivation::CLIENT_HTS:
    return "c hs traffic";
  case TypeOfDerivation::CATS:
    return "c ap traffic";
  case TypeOfDerivation::SATS:
    return "s ap traffic";
  case TypeOfDerivation::FK_S:
    return "finished";
  case TypeOfDerivation::EMS:
    return "exp master";
  case TypeOfDerivation::RMS:
    return "res master";
  case TypeOfDerivation::PSK:
    return "resumption";
  }

  // The compiler should be able to deduce this, but you never know.
  COMPAT_UNREACHABLE();
}

template <TypeOfDerivation mode>
static constexpr const char *get_filename() noexcept {
  // This function exists solely to return the filename to be used for
  // derivation circuits. This is primarily to make DeriveIVOrKey neater.
  static_assert(mode != TypeOfDerivation::SIZE, "mode cannot == SIZE");
  switch (mode) {
  case TypeOfDerivation::CLIENT_HANDSHAKE_IV:
    return "derive_client_handshake_iv.txt";
  case TypeOfDerivation::CLIENT_TRAFFIC_IV:
    return "derive_client_traffic_iv.txt";
  case TypeOfDerivation::SERVER_HANDSHAKE_IV:
    return "derive_server_handshake_iv.txt";
  case TypeOfDerivation::SERVER_TRAFFIC_IV:
    return "derive_server_traffic_iv.txt";
  case TypeOfDerivation::CLIENT_HANDSHAKE_KEY:
    return "derive_client_handshake_key.txt";
  case TypeOfDerivation::CLIENT_TRAFFIC_KEY:
    return "derive_client_traffic_key.txt";
  case TypeOfDerivation::SERVER_HANDSHAKE_KEY:
    return "derive_server_handshake_key.txt";
  case TypeOfDerivation::SERVER_TRAFFIC_KEY:
    return "derive_server_traffic_key.txt";
  case TypeOfDerivation::SERVER_HTS:
    return "derive_shts.txt";
  case TypeOfDerivation::CLIENT_HTS:
    return "derive_chts.txt";
  case TypeOfDerivation::DHS:
    return "derive_dhs.txt";
  case TypeOfDerivation::MS:
    return "derive_ms.txt";
  case TypeOfDerivation::CATS:
    return "derive_cats.txt";
  case TypeOfDerivation::SATS:
    return "derive_sats.txt";
  case TypeOfDerivation::EMS:
    return "derive_ems.txt";
  case TypeOfDerivation::RMS:
    return "derive_rms.txt";
  case TypeOfDerivation::PSK:
    return "derive_psk.txt";
  }
}

/**
   SplitData. This struct exists solely to represent a succinct return type
   for splitting the test_data into two separate arrays (see DerivationTestCase
 for more).
   @tparam size: the size of the input test case. This is multiplied by
 4 to make it so that each output char corresponds to a single bit of the input
 across both arrays.
 **/
template <unsigned size> struct SplitData {
  /**
     client_out. This array holds the client output, which corresponds to the
  first size * 4 bits of the input data.
  **/
  std::array<bool, size * 4> client_out;
  /**
   sever_out. This array holds the client output, which corresponds to the
second size * 4 bits of the input data.
  **/
  std::array<bool, size * 4> server_out;
};

/**
   DerivationTestCase. This struct models a test case for the derivation
circuits. This struct exists solely to make sure that the outputs of our
circuits are identical to the circuits produced by n-for-1 auth's circuits. We
thank the authors of the n-for-1-auth project for providing these in their
source code.

   This struct acts as follows. Firstly, it contains array holding some known
test data. In all cases these were lifted directly from n-for-1-auth's
generate_handshake_circuits.cpp file. The second array it holds is the answer
produced by the circuits produced by the n-for-1-auth codebase. In this
situation, the output was generated by calling the "print_many_bytes_function"
(in n-for-1-auth's generate_handshake_circuits.cpp) with the result of the
circuit.
@tparam in_size: the number of chars in the test_data.
@tparam out_size: the number of chars in the expected answer.
**/
template <unsigned in_size = 32, unsigned out_size = 16>
struct DerivationTestCase {
  // We require that both in_size and out_size are multiples of 2.
  static_assert(in_size % 2 == 0, "Error: in_size is not a multiple of 2");
  static_assert(out_size % 2 == 0, "Error: out_size is not a multiple of 2");

  /**
     test_data. This is the test data lifted from n-for-1-auth.
  **/
  std::array<unsigned char, in_size> test_data;
  /**
     expected_answer. This is the answer produced by the n-for-1-auth circuits.
     Note that here we are assuming AES.
  **/
  std::array<unsigned char, out_size> expected_answer;

  /**
     copy_test_data. This function returns a SplitData object with the
     first `in_size/2` entries of
     `test_data` in `client_out` and the second `in_size/2` entries of
  `test_data` in `server_out`. This function does not throw or modify this test
  object.
  **/
  constexpr SplitData<in_size> copy_test_data() const noexcept {
    return SplitData<in_size>{
        chars_to_bools<in_size / 2>(test_data.data()),
        chars_to_bools<in_size / 2>(test_data.data() + in_size / 2)};
  }
};

template <TypeOfDerivation mode>
static constexpr DerivationTestCase<32, 32>
get_test_data_for_secret() noexcept {
  // This function provides test cases from n-for-1-auth
  // for deriving traffic secrets.
  // In particular, this function should only be called by DeriveDHS,
  // DeriveSCHTS, or DeriveMS.
  // Note that some of these test cases are repeats.
  static_assert(
      mode == TypeOfDerivation::SERVER_HTS ||
          mode == TypeOfDerivation::CLIENT_HTS ||
          mode == TypeOfDerivation::DHS || mode == TypeOfDerivation::MS ||
          mode == TypeOfDerivation::CATS || mode == TypeOfDerivation::SATS ||
          mode == TypeOfDerivation::RMS || mode == TypeOfDerivation::EMS ||
          mode == TypeOfDerivation::PSK,
      "Error: cannot call get_test_data_for_secret with supplied mode");

  constexpr std::array<unsigned char, 32> handshake_test_data{
      0xfb, 0x9f, 0xc8, 0x06, 0x89, 0xb3, 0xa5, 0xd0, 0x2c, 0x33, 0x24,
      0x3b, 0xf6, 0x9a, 0x1b, 0x1b, 0x20, 0x70, 0x55, 0x88, 0xa7, 0x94,
      0x30, 0x4a, 0x6e, 0x71, 0x20, 0x15, 0x5e, 0xdf, 0x14, 0x9a};

  constexpr std::array<unsigned char, 32> chts_expected{
      0xFF, 0x0E, 0x5B, 0x96, 0x52, 0x91, 0xC6, 0x08, 0xC1, 0xE8, 0xCD,
      0x26, 0x7E, 0xEF, 0xC0, 0xAF, 0xCC, 0x5E, 0x98, 0xA2, 0x78, 0x63,
      0x73, 0xF0, 0xDB, 0x47, 0xB0, 0x47, 0x86, 0xD7, 0x2A, 0xEA};
  constexpr std::array<unsigned char, 32> shts_expected{
      0xA2, 0x06, 0x72, 0x65, 0xE7, 0xF0, 0x65, 0x2A, 0x92, 0x3D, 0x5D,
      0x72, 0xAB, 0x04, 0x67, 0xC4, 0x61, 0x32, 0xEE, 0xB9, 0x68, 0xB6,
      0xA3, 0x2D, 0x31, 0x1C, 0x80, 0x58, 0x68, 0x54, 0x88, 0x14};

  constexpr std::array<unsigned char, 32> dhs_expected{
      0xDE, 0x9F, 0x5C, 0x98, 0xDB, 0x42, 0x61, 0xA4, 0x69, 0x11, 0xF1,
      0x34, 0x9C, 0x1B, 0xA2, 0xC8, 0x4D, 0xD8, 0x44, 0x82, 0x24, 0x9F,
      0x8F, 0x2C, 0xB3, 0xA9, 0x89, 0xE4, 0xE4, 0xA8, 0x04, 0xE6};

  constexpr std::array<unsigned char, 32> ms_expected{
      0x7F, 0x28, 0x82, 0xBB, 0x9B, 0x9A, 0x46, 0x26, 0x59, 0x41, 0x65,
      0x3E, 0x9C, 0x2F, 0x19, 0x06, 0x71, 0x18, 0x15, 0x1E, 0x21, 0xD1,
      0x2E, 0x57, 0xA7, 0xB6, 0xAC, 0xA1, 0xF8, 0x15, 0x0C, 0x8D};

  constexpr std::array<unsigned char, 32> ats_test_data{
      0x7f, 0x28, 0x82, 0xbb, 0x9b, 0x9a, 0x46, 0x26, 0x59, 0x41, 0x65,
      0x3e, 0x9c, 0x2f, 0x19, 0x06, 0x71, 0x18, 0x15, 0x1e, 0x21, 0xd1,
      0x2e, 0x57, 0xa7, 0xb6, 0xac, 0xa1, 0xf8, 0x15, 0x0c, 0x8d};

  constexpr std::array<unsigned char, 32> cats_expected_data{
      0xb8, 0x82, 0x22, 0x31, 0xc1, 0xd6, 0x76, 0xec, 0xca, 0x1c, 0x11,
      0xff, 0xf6, 0x59, 0x42, 0x80, 0x31, 0x4d, 0x03, 0xa4, 0xe9, 0x1c,
      0xf1, 0xaf, 0x7f, 0xe7, 0x3f, 0x8f, 0x7b, 0xe2, 0xc1, 0x1b};

  constexpr std::array<unsigned char, 32> sats_expected_data{
      0x3F, 0xC3, 0x5E, 0xA7, 0x06, 0x93, 0x06, 0x9A, 0x27, 0x79, 0x56,
      0xAF, 0xA2, 0x3B, 0x8F, 0x45, 0x43, 0xCE, 0x68, 0xAC, 0x59, 0x5F,
      0x2A, 0xAC, 0xE0, 0x5C, 0xD7, 0xA1, 0xC9, 0x20, 0x23, 0xD5};

  constexpr std::array<unsigned char, 32> ems_expected_data{
      0x07, 0x98, 0xFA, 0x25, 0xDA, 0x1E, 0x8B, 0x74, 0x87, 0xB2, 0x45,
      0xD7, 0xC4, 0xAF, 0x9B, 0x24, 0x98, 0x8D, 0xE3, 0xAE, 0xFA, 0x0E,
      0xF6, 0x32, 0x59, 0xFD, 0x6C, 0x9D, 0x0B, 0x52, 0xAE, 0xED};

  constexpr std::array<unsigned char, 32> rms_expected{
      0x38, 0xbc, 0x15, 0x93, 0x73, 0x1c, 0xab, 0xac,
      0xd8, 0xd5, 0xad, 0xb3, 0xdb, 0xf5, 0xa2, 0x48,
      0xc5, 0xec, 0x80, 0xec, 0x20, 0xf9, 0xdd, 0xa1,
      0x0b, 0xc1, 0x48, 0x0c, 0x60, 0xfe, 0x83, 0xf0};

  constexpr std::array<unsigned char, 32> psk_expected{
      0x4f, 0x5b, 0xcf, 0xb6, 0x0f, 0x6b, 0x75, 0x74,
      0xb4, 0xd2, 0xe4, 0x71, 0xdd, 0x08, 0x43, 0x58,
      0xac, 0x3a, 0xea, 0x20, 0xd6, 0xba, 0x83, 0xa9,
      0xb6, 0x2f, 0x0b, 0xc0, 0x36, 0x3c, 0x50, 0x71};

  switch (mode) {
  case TypeOfDerivation::SERVER_HTS:
    return DerivationTestCase<32, 32>{handshake_test_data, shts_expected};
  case TypeOfDerivation::CLIENT_HTS:
    return DerivationTestCase<32, 32>{handshake_test_data, chts_expected};
  case TypeOfDerivation::DHS:
    return DerivationTestCase<32, 32>{handshake_test_data, dhs_expected};
  case TypeOfDerivation::MS:
    return DerivationTestCase<32, 32>{dhs_expected, ms_expected};
  case TypeOfDerivation::CATS:
    return DerivationTestCase<32, 32>{ats_test_data, cats_expected_data};
  case TypeOfDerivation::SATS:
    return DerivationTestCase<32, 32>{ats_test_data, sats_expected_data};
  case TypeOfDerivation::EMS:
    return DerivationTestCase<32, 32>{ats_test_data, ems_expected_data};
  case TypeOfDerivation::RMS:
    return DerivationTestCase<32, 32>{ats_test_data, rms_expected};
  case TypeOfDerivation::PSK:
    return DerivationTestCase<32, 32>{rms_expected, psk_expected};
  };
}

template <TypeOfDerivation mode>
static constexpr DerivationTestCase<32, 16>
get_test_data_for_iv_or_key() noexcept {

  // This function provides test cases from n-for-1-auth for deriving the IV
  // or the key.
  // Note that some of these test cases are repeats: however,
  // in case we ever change these values later, they're
  // separate in this file.
  constexpr std::array<unsigned char, 32> handshake_iv_test_data{
      0xff, 0x0e, 0x5b, 0x96, 0x52, 0x91, 0xc6, 0x08, 0xc1, 0xe8, 0xcd,
      0x26, 0x7e, 0xef, 0xc0, 0xaf, 0xcc, 0x5e, 0x98, 0xa2, 0x78, 0x63,
      0x73, 0xf0, 0xdb, 0x47, 0xb0, 0x47, 0x86, 0xd7, 0x2a, 0xea};

  constexpr std::array<unsigned char, 16> handshake_iv_answer{
      0xCE, 0xDA, 0xD4, 0xDC, 0x4A, 0xD2, 0xCC, 0xEA,
      0x24, 0xCD, 0x89, 0xB5, 0x8B, 0x7A, 0x39, 0xB5};

  constexpr std::array<unsigned char, 32> traffic_iv_test_data{
      0xb8, 0x82, 0x22, 0x31, 0xc1, 0xd6, 0x76, 0xec, 0xca, 0x1c, 0x11,
      0xff, 0xf6, 0x59, 0x42, 0x80, 0x31, 0x4d, 0x03, 0xa4, 0xe9, 0x1c,
      0xf1, 0xaf, 0x7f, 0xe7, 0x3f, 0x8f, 0x7b, 0xe2, 0xc1, 0x1b};

  constexpr std::array<unsigned char, 16> traffic_iv_answer{
      0xF1, 0x15, 0x6A, 0x67, 0xE0, 0xA3, 0xC1, 0x1C,
      0xF5, 0x6F, 0x9F, 0x6C, 0x22, 0x73, 0x1D, 0x21};

  constexpr std::array<unsigned char, 32> handshake_key_test_data{
      0xff, 0x0e, 0x5b, 0x96, 0x52, 0x91, 0xc6, 0x08, 0xc1, 0xe8, 0xcd,
      0x26, 0x7e, 0xef, 0xc0, 0xaf, 0xcc, 0x5e, 0x98, 0xa2, 0x78, 0x63,
      0x73, 0xf0, 0xdb, 0x47, 0xb0, 0x47, 0x86, 0xd7, 0x2a, 0xea};

  constexpr std::array<unsigned char, 16> handshake_key_answer{
      0x71, 0x54, 0xF3, 0x14, 0xE6, 0xBE, 0x7D, 0xC0,
      0x08, 0xDF, 0x2C, 0x83, 0x2B, 0xAA, 0x1D, 0x39};

  constexpr std::array<unsigned char, 32> traffic_key_test_data{
      0xb8, 0x82, 0x22, 0x31, 0xc1, 0xd6, 0x76, 0xec, 0xca, 0x1c, 0x11,
      0xff, 0xf6, 0x59, 0x42, 0x80, 0x31, 0x4d, 0x03, 0xa4, 0xe9, 0x1c,
      0xf1, 0xaf, 0x7f, 0xe7, 0x3f, 0x8f, 0x7b, 0xe2, 0xc1, 0x1b};

  constexpr std::array<unsigned char, 16> traffic_key_answer{
      0x49, 0x13, 0x4B, 0x95, 0x32, 0x8F, 0x27, 0x9F,
      0x01, 0x83, 0x86, 0x05, 0x89, 0xAC, 0x67, 0x07};


  if constexpr (mode == TypeOfDerivation::CLIENT_HANDSHAKE_IV ||
                mode == TypeOfDerivation::SERVER_HANDSHAKE_IV) {
    return DerivationTestCase<32, 16>{handshake_iv_test_data,
                                      handshake_iv_answer};
  } else if constexpr (mode == TypeOfDerivation::CLIENT_TRAFFIC_IV ||
                       mode == TypeOfDerivation::SERVER_TRAFFIC_IV) {
    return DerivationTestCase<32, 16>{traffic_iv_test_data, traffic_iv_answer};
  } else if constexpr (mode == TypeOfDerivation::CLIENT_HANDSHAKE_KEY ||
                       mode == TypeOfDerivation::SERVER_HANDSHAKE_KEY) {
    return DerivationTestCase<32, 16>{handshake_key_test_data,
                                      handshake_key_answer};
  } else if constexpr (mode == TypeOfDerivation::CLIENT_TRAFFIC_KEY ||
                       mode == TypeOfDerivation::SERVER_TRAFFIC_KEY) {
    return DerivationTestCase<32, 16>{traffic_key_test_data,
                                      traffic_key_answer};
  }
}

template <unsigned int length> static void DeriveHS() {
  static_assert(length == 256 || length == 384 || length == 521,
                "Error: mismatched size");
  emp::setup_plain_prot(true, "derive_hs_" + std::to_string(length) + ".txt");
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // This function naively looks like this:
  // HS = HKDF.Extract(dES, DHE), where DHE is the shared secret.
  // Because DHE and HS both need to be shared, we apply the following input
  // format:
  // 1. dES is the public input comprising the first 256-bits.
  // 2. DHE is split into two `length` long chunks, which we then add modulo
  // the relevant prime,
  //    and
  // 3. The final 256 bits are masks for the output: each party inputs
  // 128-bits of this input,
  //    which is then xored with the output of the HKDF function. This is to
  //    make the split of the shares easier to compute on either side. This is
  //    done inside extract_secret_each.

  // For the circuit evaluation, we'll just generate random data of the right
  // size.
  // Note that ES = HKDF.Extract(0, 0) and dES = HKDF.Expand(ES, "derived",
  // Hash(0)), which is a constant: so we can just use this a priori as a public
  // input.
  constexpr std::array<unsigned char, 32> dES{
      0x6F, 0x26, 0x15, 0xA1, 0x08, 0xC7, 0x02, 0xC5, 0x67, 0x8F, 0x54,
      0xFC, 0x9D, 0xBA, 0xB6, 0x97, 0x16, 0xC0, 0x76, 0x18, 0x9C, 0x48,
      0x25, 0x0C, 0xEB, 0xEA, 0xC3, 0x57, 0x6C, 0x36, 0x11, 0xBA};

  auto context = chars_to_blocks<32>(dES.data());

  // Now we need to generate two random secrets that are `length`-bits in
  // size. This is just for the sake of this circuit generation: the exact
  // values don't matter. Note however that the prime very much _does_ matter.
  bssl::UniquePtr<EC_GROUP> curve(get_curve<length>());
  const auto order = EC_GROUP_get0_order(curve.get());

  // Now we'll make the random data.
  BIGNUM *a = BN_CTX_get(bn_ctx.get());
  BIGNUM *b = BN_CTX_get(bn_ctx.get());
  assert(a && b);

  // We need to turn the order into a bool array.
  auto p_as_arr = serialise_bignum<length>(order);
  BN_rand_range_ex(a, 1, order);
  BN_rand_range_ex(b, 1, order);

  auto a_as_arr = serialise_bignum<length>(a);
  auto b_as_arr = serialise_bignum<length>(b);

  // Now we'll call the addition routine. The answer size will be exactly
  // `length` blocks.
  // WARNING: this is a hack!

  // Essentially, in emp each block corresponds to a single bit. This means
  // that doing byte-wise operations on the block is a bit difficult. To
  // circumvent this, we round up only if the input prime is 521 bits (since
  // 256 and 384 are both multiples of 8).
  constexpr auto size = length == 521 ? 528 : length;
  emp::block addition[size];
  if constexpr (length == 521) {
    const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
    std::fill(std::begin(addition) + 521, std::end(addition), zero);
  }

  CircuitSynthesis::add_two_mod_p(a_as_arr.data(), b_as_arr.data(),
                                  p_as_arr.data(), addition, length);

  // So now we've fed in both dES and the addition mod p. This forms
  // the first lot of our data, which we'll then feed into hkdf_expand_label.
  emp::block derived_secret[256];

  // derived_secret = HKDF.Extract(dES, DHE), with DHE = addition and
  // dES = context.
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{context.data(), 256},
                                 EmpBlockNonOwningSpan{addition, size},
                                 derived_secret);
  // Note: the masks are generated and produced in here,
  extract_secret_each(derived_secret);
  emp::finalize_plain_prot();
}

template <TypeOfDerivation mode>
static constexpr std::array<unsigned char, 32> get_hash_test_data() {
  static_assert(mode == TypeOfDerivation::SERVER_HTS ||
                    mode == TypeOfDerivation::CLIENT_HTS ||
                    mode == TypeOfDerivation::CATS ||
                    mode == TypeOfDerivation::SATS ||
                    mode == TypeOfDerivation::RMS ||
                    mode == TypeOfDerivation::EMS,
                "Error: cannot instantiate get_hash_test_data");

  constexpr std::array<unsigned char, 32> hello_hash_test_data{
      0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda, 0xe4, 0x04, 0x4d,
      0xa9, 0x32, 0x35, 0x0c, 0xf6, 0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f,
      0x1e, 0x6f, 0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5};

  constexpr std::array<unsigned char, 32> handshake_hash_test_data{
      0x22, 0x84, 0x4b, 0x93, 0x0e, 0x5e, 0x0a, 0x59, 0xa0, 0x9d, 0x5a,
      0xc3, 0x5f, 0xc0, 0x32, 0xfc, 0x91, 0x16, 0x3b, 0x19, 0x38, 0x74,
      0xa2, 0x65, 0x23, 0x6e, 0x56, 0x80, 0x77, 0x37, 0x8d, 0x8b};

  constexpr std::array<unsigned char, 32> resumption_hash{
      0x9a, 0x3f, 0xd2, 0x41, 0xbe, 0x6c, 0x58, 0x07, 0xe4, 0x11, 0x9b,
      0x8d, 0x72, 0xa5, 0x0c, 0xf9, 0x35, 0xda, 0x62, 0x1e, 0x48, 0xbc,
      0x07, 0x93, 0xaf, 0x5d, 0xe7, 0x14, 0x68, 0x9c, 0x21, 0xf2};

  switch (mode) {
  case TypeOfDerivation::SERVER_HTS:
  case TypeOfDerivation::CLIENT_HTS:
    return hello_hash_test_data;
  case TypeOfDerivation::RMS:
    return resumption_hash;
  default:
    return handshake_hash_test_data;
  }
}

template <TypeOfDerivation mode, bool testing>
static void DeriveSessionSecrets() {
  // This function just derives the expansion circuit for deriving the client
  // handshake secret.
  static_assert(mode == TypeOfDerivation::SERVER_HTS ||
                    mode == TypeOfDerivation::CLIENT_HTS ||
                    mode == TypeOfDerivation::EMS ||
                    mode == TypeOfDerivation::SATS ||
                    mode == TypeOfDerivation::CATS ||
                    mode == TypeOfDerivation::RMS,
                "Error: DeriveSCHTS only works with the listed types");

  emp::setup_plain_prot(!testing, get_filename<mode>());

  // We follow the following convention: Alice is the prover, Bob is the
  // verifier. Note that as per the convention described in deriveHS, Alice
  // holds the "lower" 128 entries of HS, whereas Bob holds the "upper 128"
  // entries of HS.

  // This comes from n-for-1-auth.
  constexpr auto hash_test_data = get_hash_test_data<mode>();

  const auto test_data = get_test_data_for_secret<mode>();
  const auto split_data = test_data.copy_test_data();
  auto alice_input = split_data.client_out;
  auto bob_input = split_data.server_out;

  // We feed them in into a singular array.
  emp::block joint_input[256];
  emp::ProtocolExecution::prot_exec->feed(joint_input, emp::ALICE,
                                          alice_input.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_input + 128, emp::BOB,
                                          bob_input.data(), 128);

  auto hash_bool = chars_to_bools<32>(hash_test_data.data());

  emp::block hash[256];
  emp::ProtocolExecution::prot_exec->feed(hash, emp::ALICE, hash_bool.data(),
                                          256);
  emp::block derived[256];

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{joint_input, 256}, get_tag<mode>(),
      EmpBlockNonOwningSpan{hash, 256}, derived, 32);

  // If testing, we'll check that the outputs are as expected.
  if constexpr (testing) {
    const auto result = print_hash_to_string<32>(derived);
    assert(result == test_data.expected_answer);
  } else {
    // Now the same xoring as before.
    extract_secret_each(derived);
  }
  emp::finalize_plain_prot();
}

template <TypeOfDerivation mode>
static constexpr std::array<unsigned char, 2> get_ticket_nonce_test_data() {
  static_assert(mode == TypeOfDerivation::PSK,
                "Error: cannot instantiate get_ticket_nonce_test_data");
  constexpr std::array<unsigned char, 2> ticket_nonce_test_data{
      0x00};

  return ticket_nonce_test_data;
}

//derive psk
template <bool testing> static void DerivePSK() {
  static constexpr auto mode = TypeOfDerivation::PSK;
  emp::setup_plain_prot(!testing, get_filename<mode>());

  const auto nonce_data = get_ticket_nonce_test_data<mode>();
  const auto test_data = get_test_data_for_secret<mode>();
  const auto split_data = test_data.copy_test_data();
  auto alice_input = split_data.client_out;
  auto bob_input = split_data.server_out;

  emp::block joint_input[256];
  emp::ProtocolExecution::prot_exec->feed(joint_input, emp::ALICE,
                                          alice_input.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_input + 128, emp::BOB,
                                          bob_input.data(), 128);

  auto nonce_bool = chars_to_bools<2>(nonce_data.data());
  emp::block nonce[16];
  emp::ProtocolExecution::prot_exec->feed(nonce, emp::ALICE, nonce_bool.data(),
                                          16);
  emp::block derived[16];

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{joint_input, 256}, get_tag<mode>(),
      EmpBlockNonOwningSpan{nonce, 16}, derived, 32);

  // If testing, we'll check that the outputs are as expected.
  if constexpr (testing) {
    const auto result = print_hash_to_string<32>(derived);
    //assert(result == test_data.expected_answer);
  } else {
    // Now the same xoring as before.
    extract_secret_each(derived);
  }
  emp::finalize_plain_prot();
}

template <bool testing> static void DeriveDHS() {
  static constexpr auto mode = TypeOfDerivation::DHS;
  // This function is essentially the same as deriveCHTS, but with
  // a slight optimisation: namely, we use the empty hash for the final
  // set of input bits during circuit construction.
  // In n-for-1-auth this function is the first part of DeriveMasterSecret.
  emp::setup_plain_prot(!testing, get_filename<mode>());

  auto context = chars_to_blocks<32>(get_empty_hash().data());

  // Now we've got those done, we can just do the expansion as before.
  const auto test_data = get_test_data_for_secret<mode>();
  const auto split_data = test_data.copy_test_data();
  auto alice_input = split_data.client_out;
  auto bob_input = split_data.server_out;

  emp::block joint_input[256];
  emp::ProtocolExecution::prot_exec->feed(joint_input, emp::ALICE,
                                          alice_input.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_input + 128, emp::BOB,
                                          bob_input.data(), 128);

  emp::block dhs[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{joint_input, 256}, get_tag<mode>(),
      EmpBlockNonOwningSpan{context.data(), 256}, dhs, 32);

  if constexpr (testing) {
    const auto result = print_hash_to_string<32>(dhs);
    assert(result == test_data.expected_answer);
  } else {
    extract_secret_each(dhs);
  }

  emp::finalize_plain_prot();
}

template <bool testing> static void DeriveMS() {
  static constexpr auto mode = TypeOfDerivation::MS;
  // This function is essentially the same as deriveDHS, but with
  // an extra label expansion at the end. This is because this part of the
  // PRF is executed _after_ we've derived the dHS in our application.

  emp::setup_plain_prot(!testing, get_filename<mode>());

  // Now we've got those done, we can just do the expansion as before.
  // Note that the value returned below from get_test_data_for_secret
  // is the output of deriveDHS.
  const auto test_data = get_test_data_for_secret<mode>();
  const auto split_data = test_data.copy_test_data();
  auto alice_input = split_data.client_out;
  auto bob_input = split_data.server_out;

  emp::block joint_input[256];
  emp::ProtocolExecution::prot_exec->feed(joint_input, emp::ALICE,
                                          alice_input.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_input + 128, emp::BOB,
                                          bob_input.data(), 128);

  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  emp::block zero_key[256];
  std::fill(zero_key, zero_key + 256, zero);
  emp::block derived_secret[256];
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{joint_input, 256},
                                 EmpBlockNonOwningSpan{zero_key, 256},
                                 derived_secret);

  if constexpr (testing) {
    const auto result = print_hash_to_string<32>(derived_secret);
    assert(result == test_data.expected_answer);
  } else {
    extract_secret_each(derived_secret);
  }

  emp::finalize_plain_prot();
}

template <TypeOfDerivation mode, bool testing = false> static void DeriveATS() {
  static_assert(mode == TypeOfDerivation::CATS ||
                    mode == TypeOfDerivation::SATS ||
                    mode == TypeOfDerivation::EMS,
                "Error: cannot call deriveATS with supplied mode");
}

template <TypeOfDerivation mode, bool testing = false>
static void DeriveIVOrKey() {
  // We change the name of the output file depending on the template argument.
  // We only produce the actual circuits in non-test modes though.
  emp::setup_plain_prot(!testing, get_filename<mode>());

  // We use the hardcoded test data to make sure everything works.
  static constexpr auto data = get_test_data_for_iv_or_key<mode>();

  // Note that unlike n-for-1-auth we expect this to have been split here,
  // so we'll split the test data in half like this.
  const auto split = data.copy_test_data();
  auto client_secret = split.client_out;
  auto server_secret = split.server_out;

  emp::block joint_secret[256];
  emp::ProtocolExecution::prot_exec->feed(joint_secret, emp::ALICE,
                                          client_secret.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(joint_secret + 128, emp::BOB,
                                          server_secret.data(), 128);

  // We also have to feed in the input masks here before we do any work.
  bool bob_mask[128];
  for (auto &v : bob_mask) {
    v = rand();
  }

  // This does mean that Bob feeds in more input than Alice. We expect the
  // library of choice to deal with this.
  emp::block bob_mask_input[128];
  emp::ProtocolExecution::prot_exec->feed(bob_mask_input, emp::BOB, bob_mask,
                                          128);

  // We assume AES-128 here, which means we always need 128-bit output.
  emp::block derived[128];

  // This span isn't actually used.
  emp::block empty_span;

  // Now we produce the value.
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{joint_secret, 256}, get_tag<mode>(),
      EmpBlockNonOwningSpan{&empty_span, 0}, derived, 16);

  // In testing mode, all we do here is check that the produced value is the
  // same as we expected.
  if constexpr (testing) {
    // Firstly we reveal the output in derived.
    const auto revealed = print_hash_to_string<16>(derived);
    static_assert(sizeof(revealed) == sizeof(data.expected_answer),
                  "Error: revealed is not 128-bits in size");
    assert(revealed == data.expected_answer);
  } else {
    // Note that this is in an "else", as we've already revealed the outputs
    // publicly in the other case above.

    // At the point we need to split up the produced value.
    // This is trickier than the other functions: we cannot use the extract
    // secret function here, because we're using a 128-bit key: this would
    // open us up to a 2^65 bit attack for both the AES key and the IV, which
    // is less than ideal. To circumvent this, we use a classical idea: Bob
    // supplies an additional 128-bit mask (`mask`) as input. Alice received
    // `derived xor mask` as her share, whilst Bob keeps `mask` as theirs.
    // This is a full secret share, but it also doesn't rely on us doing any
    // clever splitting.

    emp::block alice_out[128];
    for (unsigned i = 0; i < 128; i++) {
      alice_out[i] = emp::CircuitExecution::circ_exec->xor_gate(
          derived[i], bob_mask_input[i]);
    }

    bool alice_out_bool[128];
    // Bob gets nothing, as they already know the mask they supplied.
    emp::ProtocolExecution::prot_exec->reveal(alice_out_bool, emp::ALICE,
                                              alice_out, 128);
  }
  emp::finalize_plain_prot();
}

static void assert_valid_filepath(const char *const filepath) noexcept {
  // This function checks that filepath corresponds to a valid file.
  // Otherwise, we assert(false). This will only do anything in debug builds:
  // otherwise, it's an empty function.
  FILE *f = std::fopen(filepath, "r");
  assert(f);
  std::fclose(f);
}

static void DeriveAESEncryption() {
  // This function produces a circuit for a singular AES encryption.
  // This is only useful for our use case: essentially, the keys produced by
  // DeriveIVOrKey are masked with a mask, m, supplied by Bob. Alice receives k
  // \xor m, Bob receives nothing. Whenever they wish to do an AES encryption,
  // Bob needs to supply m, whilst Alice supplies k /xor m. The AES circuit, as
  // pre-processing, needs to compute m /xor k /xor m = k, before the encryption
  // can be carried out. This function just appends this pre-processing.
  emp::setup_plain_prot(true, "aes_128_full_masked.txt");

  // We'll use some random data to test this.
  const auto data =
      get_test_data_for_iv_or_key<TypeOfDerivation::CLIENT_HANDSHAKE_KEY>()
          .test_data;

  // A test key is already stored elsewhere in this program.
  const auto key =
      get_test_data_for_iv_or_key<TypeOfDerivation::CLIENT_HANDSHAKE_KEY>()
          .expected_answer;

  // This is just a randomly generated mask.
  constexpr std::array<unsigned char, 16> bob_mask{
      0x67, 0xC6, 0x69, 0x73, 0x51, 0xFF, 0x4A, 0xEC,
      0x29, 0xCD, 0xBA, 0xAB, 0xF2, 0xFB, 0xE3, 0x46};

  // Alice's input consists of this along with some random data.
  auto alice_message = chars_to_bools<16>(data.data());
  auto alice_key = chars_to_bools<16>(key.data());
  auto bob_bools = chars_to_bools<16>(bob_mask.data());
  std::array<bool, 128> bob_blank;
  for (unsigned i = 0; i < 128; i++) {
    bob_blank[i] = rand();
  }

  emp::block alice_message_input[128];
  emp::block alice_key_input[128];

  emp::block bob_key_input[128];
  emp::block bob_extra_input[128];

  emp::PlainProt::prot_exec->feed(alice_message_input, emp::ALICE,
                                  alice_message.data(), 128);
  emp::PlainProt::prot_exec->feed(alice_key_input, emp::ALICE, alice_key.data(),
                                  128);

  emp::PlainProt::prot_exec->feed(bob_key_input, emp::BOB, bob_bools.data(),
                                  128);
  emp::PlainProt::prot_exec->feed(bob_extra_input, emp::BOB, bob_blank.data(),
                                  128);

  // Derive the circuit key.
  emp::block c_key[128];
  for (unsigned i = 0; i < 128; i++) {
    c_key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_key_input[i],
                                                          bob_key_input[i]);
  }

  // Encrypt the block. It needs to be double packed, with the keys in the first
  // 128 bits and the message in the next 128.
  emp::block aes_in[256];
  memcpy(aes_in, c_key, sizeof(emp::block) * 128);
  memcpy(aes_in + 128, alice_message_input, sizeof(emp::block) * 128);

  emp::block out[128];
  assert_valid_filepath(CircuitSynthesis::AES128_FULL_FILEPATH);
  emp::BristolFormat bf(CircuitSynthesis::AES128_FULL_FILEPATH);
  bf.compute(out, aes_in, aes_in);

  // Both parties learn the result.
  bool result[128];
  emp::ProtocolExecution::prot_exec->reveal(result, emp::PUBLIC, out, 128);
  emp::finalize_plain_prot();
}

// COMBINED KEYING MATERIAL CIRCUITS
// This portion of the code actually combines all of the individual key
// derivation circuits into one, larger circuit. The point of this is to reduce
// the practical running time of these circuits: most of the information is
// repeated anyway, and this means that garbled circuit libraries like EMP can
// typically run faster. This also contains duplicate code from the other
// functions.
// This does not store neither the MS
template <unsigned int length> static void ProduceCombinedCircuit() noexcept {
  static_assert(length == 256 || length == 384 || length == 521,
                "Error: mismatched length");
  emp::setup_plain_prot(true, "derive_handshake_secrets_" +
                                  std::to_string(length) + ".txt");
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  assert(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  // This function is similar to DeriveHS. We compute ES = HKDF.Extract(0, PSK),
  // dES = HKDF.Expand-Label(ES, "derived", H("")), and HS = HKDF.Extract(dES,
  // DHE), before feeding HS into the computation for CHTS, SHTS and dHS. Each
  // party needs to supply their share of the PSK, their share of the DHE value
  // (comprising of |length| bits) and a mask that is big enough to XOR out
  // their portion of the secret. Because we split secrets evenly, this is
  // expected to be 512 bits for the secrets up to (and including) dHS. We also
  // require that the prover (Alice) inputs the transcript.

  // The same circuit serves both modes. On a full handshake RFC 8446
  // uses PSK = 0^Hash.length, so both parties feed zero shares and the
  // derivation below reproduces the fixed constant as in DiStefano
  // exactly.

  // Now we need to generate two random secrets that are `length`-bits in size.
  // This is just for circuit generation. We simply generate over the base field
  // of the corresponding elliptic curve.
  bssl::UniquePtr<EC_GROUP> curve(get_curve<length>());
  assert(curve);
  BIGNUM *order = BN_CTX_get(bn_ctx.get());
  assert(order);
  if (!EC_GROUP_get_curve_GFp(curve.get(), order, nullptr, nullptr,
                              bn_ctx.get())) {
    std::abort();
  }

  // `a` is Alice's input, `b` is Bob's.
  BIGNUM *a = BN_CTX_get(bn_ctx.get());
  BIGNUM *b = BN_CTX_get(bn_ctx.get());
  assert(a && b);

  // We need to turn the order into a bool array.
  auto p_as_arr = serialise_bignum<length>(order);
  BN_rand_range_ex(a, 1, order);
  BN_rand_range_ex(b, 1, order);

  // And the randomly generated numbers too.
  auto a_as_arr = serialise_bignum<length>(a);
  auto b_as_arr = serialise_bignum<length>(b);

  // Now we'll call the addition routine. The answer size will be exactly
  // `length` blocks.
  // WARNING: this is a hack!

  // Essentially, in emp each block corresponds to a single bit. This means
  // that doing byte-wise operations on the block is a bit difficult. To
  // circumvent this, we round up only if the input prime is 521 bits (since
  // 256 and 384 are both multiples of 8).
  constexpr auto size = length == 521 ? 528 : length;
  emp::block addition[size];
  if constexpr (length == 521) {
    const auto zero_block = emp::CircuitExecution::circ_exec->public_label(false);
    std::fill(std::begin(addition) + 521, std::end(addition), zero_block);
  }

  // We'll store the prime input in this block.
  emp::block p_block[size];

  // WARNING: this may be confusing if you aren't familiar with certain features
  // of EMP (this took the author of this code a while to figure out too!).
  // Essentially, emp's circuit generation tools work best if you feed in all of
  // the inputs at the beginning. It turns out that emp labels each gate with a
  // unique ID. For some reason, if inputs are fed in after computation, then
  // emp gets confused and so the circuits essentially break during runtime.
  // This seems to be because Bristol Format circuits assume that the lower
  // input wires are for the first party, whereas the upper input wires are for
  // the second: this can get confusing with emp, where wires are labelled as
  // they are fed in (and so input mismatches are easy to create). To fix this,
  // we feed everything in first. This is in order of use, but with the
  // exception that the additive shares must go last. We also feed in each input
  // in order of the party: we put Alice's inputs in the low wires and Bob's in
  // the upper wires. This is deliberate to prevent circuits from being
  // mismatched. We also break an abstraction around the addition circuits and
  // just call them directly.
  constexpr auto h2_test_data =
      get_hash_test_data<TypeOfDerivation::CLIENT_HTS>();
  auto h2_bool = chars_to_bools<32>(h2_test_data.data());
  emp::block h2[256];

  // We need the all zero string for the MS and for the ES extraction salt.
  static constexpr std::array<bool, 256> zero{};
  emp::block zero_key[256];

  // H("") is constant for a fixed hash function. It's used in the derivation of
  // both dES and dHS, so we just place it here.
  auto h0_bool = chars_to_bools<32>(get_empty_hash().data());
  emp::block h0[256];

  // PSK shares. Alice holds the low 128 bits, Bob the high 128.
  // The output of one session's PSK circuit feeds straight into the next session's handshake
  // circuit without either party ever holding the whole value. The concrete
  // bits here are only for circuit generation.
  std::array<bool, 128> alice_psk_bool{}, bob_psk_bool{};
  for (unsigned i = 0; i < 128; i++) {
    alice_psk_bool[i] = rand();
    bob_psk_bool[i] = rand();
  }
  emp::block psk[256];

  // Public info first.
  emp::ProtocolExecution::prot_exec->feed(h0, emp::PUBLIC, h0_bool.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(zero_key, emp::PUBLIC, zero.data(),
                                          256);
  emp::ProtocolExecution::prot_exec->feed(p_block, emp::PUBLIC, p_as_arr.data(),
                                          size);

  // Now we'll set up the rest of our inputs. We do everything in a particular
  // order to make sure the wires are consistent. This does involve breaking a
  // particular abstraction around addition, because we need to make sure
  // everything is fed in correctly.

  // We have to feed in two masks for xoring, since emp-ag2pc doesn't obscure
  // outputs, which we need.
  // In total we need:
  // 128 bits for each derived secret (so 768 bits per party) (768 here comes
  // from the 7 secrets dHE, CHTS, SHTS, DHS, MS and the AES key).
  constexpr auto mask_bits = 768;
  bool alice_mask[mask_bits], bob_mask[mask_bits];
  for (unsigned i = 0; i < mask_bits; i++) {
    alice_mask[i] = rand();
    bob_mask[i] = rand();
  }

  emp::block alice_mask_block[mask_bits], bob_mask_block[mask_bits];
  emp::block alice_share_in[length], bob_share_in[length];

  // WARNING WARNING WARNING: this is going to be very confusing...
  // We need to feed in Bob's inputs first, and then Alice's.
  // Why? Well, it's because of an emp-ag2pc bug. This is explained in more
  // detail in EmpWrapperAG2PC.cpp, but essentially emp-ag2pc treats the second
  // set of input wires as Alice's input, which means we need to feed in Bob's
  // input first to make sure that everything lines up properly.

  // So, Bob's first. Bob's total input-bit count must equal Alice's (the
  // EmpWrapperAG2PC runtime forces a symmetric per-party buffer size). Bob's
  // PSK share is real input; the 256-bit block that mirrors Alice's h2 is
  // ignored padding.
  emp::block bob_empty[256];
  emp::ProtocolExecution::prot_exec->feed(psk + 128, emp::BOB,
                                          bob_psk_bool.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(bob_empty, emp::BOB, h2_bool.data(),
                                          256); // This will be ignored
  emp::ProtocolExecution::prot_exec->feed(bob_mask_block, emp::BOB, bob_mask,
                                          mask_bits);
  emp::ProtocolExecution::prot_exec->feed(bob_share_in, emp::BOB,
                                          b_as_arr.data(), length);

  // Then Alice's. The PSK share goes first so runtime serialization puts it at
  // pos 0 of each party's portion of the circuit input buffer.
  emp::ProtocolExecution::prot_exec->feed(psk, emp::ALICE,
                                          alice_psk_bool.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(h2, emp::ALICE, h2_bool.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(alice_mask_block, emp::ALICE,
                                          alice_mask, mask_bits);
  emp::ProtocolExecution::prot_exec->feed(alice_share_in, emp::ALICE,
                                          a_as_arr.data(), length);

  // Copy over the wires for the right inputs. This is an abstraction break.
  emp::block add_in[3 * length];
  memcpy(add_in + 0 * length, p_block, sizeof(emp::block) * length);
  memcpy(add_in + 1 * length, bob_share_in, sizeof(emp::block) * length);
  memcpy(add_in + 2 * length, alice_share_in, sizeof(emp::block) * length);

  static constexpr auto file_path = []() {
    if constexpr (length == 256) {
      return CircuitSynthesis::MA_256_FILEPATH;
    } else if constexpr (length == 384) {
      return CircuitSynthesis::MA_384_FILEPATH;
    } else if constexpr (length == 521) {
      return CircuitSynthesis::MA_521_FILEPATH;
    }

    // Because of the static assert this is definitely true: however, the
    // compiler may not be clever enough to know that.
    assert(false);
  }();

  // We'll make sure the file actually exists (in debug mode only!)
  assert_valid_filepath(file_path);

  emp::BristolFashion bf(file_path);

  // Now we'll run the addition.
  bf.compute(addition, add_in);

  // The outputs of the circuits here are actually different from what the HKDF
  // functions expect. Briefly, the HKDF functions expect little-endian input
  // with the bits in a reasonable order. However, for some reason our circuits
  // output them in big endian order with the bits _reveresed_. We can resolve
  // this issue at generation time (so it doesn't cost the circuits anything),
  // but it's a known headache.
  CircuitSynthesis::rearrange_sum_bits(addition, size);

  // Recover dES from the PSK shares. Note the calling syntax for hkdf_extract
  // is backwards: the first span is the salt, the second is the IKM.
  //
  //   ES  = HKDF.Extract(0, PSK)
  //   dES = HKDF.Expand-Label(ES, "derived", H(""), 32)
  //
  // get_tag<DHS>() is "derived", which is the same label TLS 1.3 uses for both
  // ES -> dES and HS -> dHS.
  emp::block es[256];
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{zero_key, 256},
                                 EmpBlockNonOwningSpan{psk, 256}, es);

  emp::block des[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{es, 256}, get_tag<TypeOfDerivation::DHS>(),
      EmpBlockNonOwningSpan{h0, 256}, des, 32);

  // So now we've got both dES and the addition mod p. This forms the first lot
  // of our data, which we'll then feed into hkdf_expand_label.
  emp::block derived_secret[256];

  // derived_secret = HKDF.Extract(dES, DHE), with DHE = addition.
  // NOTE: the size does not need to be padded here as the sizes are already
  // correct.
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{des, 256},
                                 EmpBlockNonOwningSpan{addition, size},
                                 derived_secret);

  unsigned curr = 0;
  auto xor_secrets = [&](emp::block *blocks) {
    for (unsigned i = 0; i < 128; i++) {
      blocks[i] = emp::CircuitExecution::circ_exec->xor_gate(
          alice_mask_block[curr], blocks[i]);
      blocks[i + 128] = emp::CircuitExecution::circ_exec->xor_gate(
          bob_mask_block[curr], blocks[i + 128]);
      ++curr;
    }
  };

  // Now we can generate CHTS, SHTS and dHS.
  // CHTS
  emp::block derived_chts[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_secret, 256},
      get_tag<TypeOfDerivation::CLIENT_HTS>(), EmpBlockNonOwningSpan{h2, 256},
      derived_chts, 32);

  // SHTS.
  emp::block derived_shts[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_secret, 256},
      get_tag<TypeOfDerivation::SERVER_HTS>(), EmpBlockNonOwningSpan{h2, 256},
      derived_shts, 32);

  // dHS.
  emp::block derived_dhs[256];

  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_secret, 256},
      get_tag<TypeOfDerivation::DHS>(), EmpBlockNonOwningSpan{h0, 256},
      derived_dhs, 32);

  // MS
  emp::block ms[256];
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{derived_dhs, 256},
                                 EmpBlockNonOwningSpan{zero_key, 256}, ms);

  // We don't derive traffic keys here: instead, we just derive the fk_s, which
  // is jointly output. The reason for this is to instead allow the prover to do
  // this. The fk_s + certificate check already validates the transcript so far,
  // thanks to key independence.

  // This isn't actually used.
  emp::block *empty_span = nullptr;

  // fks
  emp::block fks[256];
  CircuitSynthesis::hkdf_expand_label(EmpBlockNonOwningSpan{derived_shts, 256},
                                      get_tag<TypeOfDerivation::FK_S>(),
                                      EmpBlockNonOwningSpan{empty_span, 0}, fks,
                                      32);


  emp::block aes_key[128];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_shts, 256},
      get_tag<TypeOfDerivation::SERVER_HANDSHAKE_KEY>(),
      EmpBlockNonOwningSpan{empty_span, 0}, aes_key, 16);

  emp::block iv[96];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_shts, 256},
      get_tag<TypeOfDerivation::SERVER_HANDSHAKE_IV>(),
      EmpBlockNonOwningSpan{empty_span, 0}, iv, 12);

  bool aes_out[128];
  bool iv_out[96];

  bool alice_out_bool[mask_bits], bob_out_bool[mask_bits];
  xor_secrets(derived_secret);
  xor_secrets(derived_chts);
  xor_secrets(derived_shts);
  xor_secrets(derived_dhs);
  xor_secrets(ms);

  for (unsigned i = 0; i < 128; i++) {
    aes_key[i] = emp::CircuitExecution::circ_exec->xor_gate(
        aes_key[i], alice_mask_block[curr]);
    curr++;
  }

  assert(curr == mask_bits);

  bool fks_out[256];

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool, emp::ALICE,
                                            derived_secret, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool, emp::BOB,
                                            derived_secret + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 128, emp::ALICE,
                                            derived_chts, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 128, emp::BOB,
                                            derived_chts + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 256, emp::ALICE,
                                            derived_shts, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 256, emp::BOB,
                                            derived_shts + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 384, emp::ALICE,
                                            derived_dhs, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 384, emp::BOB,
                                            derived_dhs + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(alice_out_bool + 512, emp::ALICE,
                                            ms, 128);
  emp::ProtocolExecution::prot_exec->reveal(bob_out_bool + 512, emp::BOB,
                                            ms + 128, 128);

  emp::ProtocolExecution::prot_exec->reveal(fks_out, emp::PUBLIC, fks, 256);
  emp::ProtocolExecution::prot_exec->reveal(aes_out, emp::PUBLIC, aes_key, 128);
  emp::ProtocolExecution::prot_exec->reveal(iv_out, emp::PUBLIC, iv, 96);
  emp::finalize_plain_prot();
}


// We also have combined circuits for the traffic keys too. These are similar to
// the end of the above function, but they require less care and are smaller. In
// addition, they don't need to consider their input secret size, which makes
// everything much easier.
// Traffic keys plus CATS/SATS shares. The shares feed the key-update circuit:
// RFC 8446 7.2 rotates the traffic *secret*, and revealing a traffic key
// says nothing about the secret it was expanded from.
//
// Masks per party, 512 bits. Alice: cts | sts | CATS lo | SATS lo.
// Bob: unused | unused | CATS hi | SATS hi. Output, 120 bytes:
//   cts 16 || ctiv 12 || sts 16 || stiv 12 || cats 32 || sats 32
static void ProduceCombinedTrafficCircuits() noexcept {
  emp::setup_plain_prot(true, "derive_traffic_secrets_combined.txt");
  constexpr auto mask_bits = 512;

  std::array<bool, 256> ms_b, h3_b;
  std::array<bool, mask_bits> alice_mask_bits, bob_mask_bits;
  for (unsigned i = 0; i < 256; i++) {
    ms_b[i] = rand();
    h3_b[i] = rand();
  }
  for (unsigned i = 0; i < mask_bits; i++) {
    alice_mask_bits[i] = rand();
    bob_mask_bits[i] = rand();
  }

  emp::block ms[256]{}, h3[256]{};
  emp::block alice_mask[mask_bits], bob_mask[mask_bits];
  std::array<bool, 256> empty_b{};
  emp::block empty[256];

  emp::ProtocolExecution::prot_exec->feed(ms + 128, emp::BOB, ms_b.data() + 128, 128);
  emp::ProtocolExecution::prot_exec->feed(empty, emp::BOB, empty_b.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(bob_mask, emp::BOB, bob_mask_bits.data(), mask_bits);
  emp::ProtocolExecution::prot_exec->feed(ms, emp::ALICE, ms_b.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(h3, emp::ALICE, h3_b.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(alice_mask, emp::ALICE, alice_mask_bits.data(), mask_bits);

  emp::block derived_cats[256], derived_sats[256];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{ms, 256}, get_tag<TypeOfDerivation::CATS>(),
      EmpBlockNonOwningSpan{h3, 256}, derived_cats, 32);
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{ms, 256}, get_tag<TypeOfDerivation::SATS>(),
      EmpBlockNonOwningSpan{h3, 256}, derived_sats, 32);

  emp::block *empty_span = nullptr;
  emp::block cts[128], ctiv[96], sts[128], stiv[96];
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_cats, 256},
      get_tag<TypeOfDerivation::CLIENT_TRAFFIC_KEY>(),
      EmpBlockNonOwningSpan{empty_span, 0}, cts, 16);
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_cats, 256},
      get_tag<TypeOfDerivation::CLIENT_TRAFFIC_IV>(),
      EmpBlockNonOwningSpan{empty_span, 0}, ctiv, 12);
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_sats, 256},
      get_tag<TypeOfDerivation::SERVER_TRAFFIC_KEY>(),
      EmpBlockNonOwningSpan{empty_span, 0}, sts, 16);
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{derived_sats, 256},
      get_tag<TypeOfDerivation::SERVER_TRAFFIC_IV>(),
      EmpBlockNonOwningSpan{empty_span, 0}, stiv, 12);

  auto &ce = *emp::CircuitExecution::circ_exec;
  for (unsigned i = 0; i < 128; i++) {
    cts[i] = ce.xor_gate(alice_mask[i], cts[i]);
    sts[i] = ce.xor_gate(alice_mask[128 + i], sts[i]);
    derived_cats[i] = ce.xor_gate(alice_mask[256 + i], derived_cats[i]);
    derived_cats[128 + i] = ce.xor_gate(bob_mask[256 + i], derived_cats[128 + i]);
    derived_sats[i] = ce.xor_gate(alice_mask[384 + i], derived_sats[i]);
    derived_sats[128 + i] = ce.xor_gate(bob_mask[384 + i], derived_sats[128 + i]);
  }

  bool out_bool[128 + 96 + 128 + 96 + 256 + 256];
  unsigned off = 0;
  auto rev = [&](emp::block *b, unsigned n) {
    emp::ProtocolExecution::prot_exec->reveal(out_bool + off, emp::PUBLIC, b, n);
    off += n;
  };
  rev(cts, 128);
  rev(ctiv, 96);
  rev(sts, 128);
  rev(stiv, 96);
  rev(derived_cats, 256);
  rev(derived_sats, 256);
  emp::finalize_plain_prot();
}

// We also have combined circuits for the resumption keys too. These are similar to
// the end of the above function, but they require less care and are smaller.
static void ProduceCombinedRMS() noexcept {
  emp::setup_plain_prot(true, "combined_rms.txt");

  constexpr unsigned RMS_BITS  = 256; // 32 bytes
  constexpr unsigned HALF_BITS = 128; // 16 bytes, mask bits

  // Dummy randomness to build a concrete circuit instance in plain mode.
  std::array<bool, 256> ms_b{};
  std::array<bool, 256> h6_b{};
  std::array<bool, HALF_BITS> alice_mask_bits{};
  std::array<bool, HALF_BITS> bob_mask_bits{};

  for (unsigned i = 0; i < 256; i++) {
    ms_b[i] = rand();
    h6_b[i] = rand();
  }

  for (unsigned i = 0; i < HALF_BITS; i++) {
    alice_mask_bits[i] = rand();
    bob_mask_bits[i] = rand();
  }

  emp::block ms[256]{};
  emp::block h6[256]{};

  emp::block alice_mask[HALF_BITS]{};
  emp::block bob_mask[HALF_BITS]{};

  std::array<bool, 256> empty_b{};
  emp::block empty[256]{};

  //
  // INPUT WIRES
  //
  // Bob:   MS[128..255] (128 bits) || dummy H6 (256 bits) || bob_mask (128 bits)
  // Alice: MS[0..127]   (128 bits) || real  H6 (256 bits) || alice_mask (128 bits)
  //
  // => n1 = 128 + 256 + 128 = 512 bits  (64 bytes)
  // => n2 = 128 + 256 + 128 = 512 bits  (64 bytes)
  // => out wires total = 256 bits (but we will reveal halves to different parties)
  //

  // Feed Bob's inputs.
  emp::ProtocolExecution::prot_exec->feed(ms + 128, emp::BOB, ms_b.data() + 128, 128);
  emp::ProtocolExecution::prot_exec->feed(empty, emp::BOB, empty_b.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(bob_mask, emp::BOB, bob_mask_bits.data(), HALF_BITS);

  // Feed Alice's inputs.
  emp::ProtocolExecution::prot_exec->feed(ms, emp::ALICE, ms_b.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(h6, emp::ALICE, h6_b.data(), 256);
  emp::ProtocolExecution::prot_exec->feed(alice_mask, emp::ALICE, alice_mask_bits.data(), HALF_BITS);

  // Compute RMS = 32 bytes.
  emp::block rms[RMS_BITS]{};
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{ms, 256},
      get_tag<TypeOfDerivation::RMS>(),
      EmpBlockNonOwningSpan{h6, 256},
      rms,
      /*out_len_bytes=*/32);

  // XOR lower 128 bits against alice_mask, upper 128 bits against bob_mask.
  for (unsigned i = 0; i < 128; i++) {
    rms[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_mask[i], rms[i]);
  }
  for (unsigned i = 0; i < 128; i++) {
    rms[128 + i] = emp::CircuitExecution::circ_exec->xor_gate(bob_mask[i], rms[128 + i]);
  }

  bool out_bool[RMS_BITS];
  emp::ProtocolExecution::prot_exec->reveal(out_bool, emp::PUBLIC, rms, 256);

  emp::finalize_plain_prot();
}

// We also have combined circuits for the psk keys too. These are similar to
// the end of the above function, but they require less care and are smaller.
template <unsigned NONCE_BYTES>
static void ProduceCombinedPSK(const char *fname) noexcept {
  emp::setup_plain_prot(true, fname);

  constexpr unsigned PSK_BITS  = 256; // 32 bytes
  constexpr unsigned HALF_BITS = 128; // 16 bytes, mask bits
  // The ticket_nonce width must match the origin server's NewSessionTicket
  // nonce exactly, since HKDF-Expand-Label bakes the (length-prefixed) nonce
  // into the HkdfLabel. LiteSpeed/BoringSSL use 1 byte; OpenSSL/nginx use 8.
  // Zero-length C arrays are ill-formed; floor the storage at one block.
  constexpr unsigned NONCE_BITS = NONCE_BYTES * 8;
  constexpr unsigned NONCE_STORAGE = (NONCE_BITS == 0) ? 1 : NONCE_BITS;

  // Dummy randomness to build a concrete circuit instance in plain mode.
  std::array<bool, 256> rms_b{};
  std::array<bool, NONCE_STORAGE> ticket_b{};
  std::array<bool, HALF_BITS> alice_mask_bits{};
  std::array<bool, HALF_BITS> bob_mask_bits{};

  for (unsigned i = 0; i < 256; i++) {
    rms_b[i] = rand();
  }

  for (unsigned i = 0; i < NONCE_BITS; i++) {
    ticket_b[i] = rand();
  }

  for (unsigned i = 0; i < HALF_BITS; i++) {
    alice_mask_bits[i] = rand();
    bob_mask_bits[i] = rand();
  }

  emp::block rms[256]{};
  emp::block ticket[NONCE_STORAGE]{};

  emp::block alice_mask[HALF_BITS]{};
  emp::block bob_mask[HALF_BITS]{};

  std::array<bool, NONCE_STORAGE> empty_b{};
  emp::block empty[NONCE_STORAGE]{};

  //
  // INPUT WIRES
  //
  // Bob:   RMS[128..255] (128 bits) || dummy ticket (16 bits) || bob_mask (128 bits)
  // Alice: RMS[0..127]   (128 bits) || real  ticket (16 bits) || alice_mask (128 bits)
  //
  // => n1 = 128 + 16 + 128 = 272 bits  (34 bytes)
  // => n2 = 128 + 16 + 128 = 272 bits  (34 bytes)
  // => out wires total = 256 bits (but we will reveal halves to different parties)
  //

  // Feed Bob's inputs.
  emp::ProtocolExecution::prot_exec->feed(rms + 128, emp::BOB, rms_b.data() + 128, 128);
  if constexpr (NONCE_BITS > 0) {
    emp::ProtocolExecution::prot_exec->feed(empty, emp::BOB, empty_b.data(), NONCE_BITS);
  }
  emp::ProtocolExecution::prot_exec->feed(bob_mask, emp::BOB, bob_mask_bits.data(), HALF_BITS);

  // Feed Alice's inputs.
  emp::ProtocolExecution::prot_exec->feed(rms, emp::ALICE, rms_b.data(), 128);
  if constexpr (NONCE_BITS > 0) {
    emp::ProtocolExecution::prot_exec->feed(ticket, emp::ALICE, ticket_b.data(), NONCE_BITS);
  }
  emp::ProtocolExecution::prot_exec->feed(alice_mask, emp::ALICE, alice_mask_bits.data(), HALF_BITS);

  // Compute PSK = 32 bytes.
  emp::block psk[PSK_BITS]{};
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{rms, 256},
      get_tag<TypeOfDerivation::PSK>(),
      EmpBlockNonOwningSpan{ticket, NONCE_BITS},
      psk,
      /*out_len_bytes=*/32);

  // XOR lower 128 bits against alice_mask, upper 128 bits against bob_mask.
  for (unsigned i = 0; i < 128; i++) {
    psk[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_mask[i], psk[i]);
  }
  for (unsigned i = 0; i < 128; i++) {
    psk[128 + i] = emp::CircuitExecution::circ_exec->xor_gate(bob_mask[i], psk[128 + i]);
  }

  bool out_bool[PSK_BITS];
  emp::ProtocolExecution::prot_exec->reveal(out_bool, emp::PUBLIC, psk, 256);

  emp::finalize_plain_prot();
}

// SURF: the PSK binder for a resumed ClientHello. The binder is
// HMAC(finished_key, H(Truncate(ClientHello)))
static void ProduceBinderCircuit() noexcept {
  emp::setup_plain_prot(true, "derive_binder.txt");

  // Dummy input for circuit generation only.
  std::array<bool, 128> alice_psk_bool{}, bob_psk_bool{};
  std::array<bool, 256> ch_hash_bool{};
  for (unsigned i = 0; i < 128; i++) {
    alice_psk_bool[i] = rand();
    bob_psk_bool[i] = rand();
  }
  for (unsigned i = 0; i < 256; i++) {
    ch_hash_bool[i] = rand();
  }

  static constexpr std::array<bool, 256> zero{};
  emp::block zero_key[256];
  auto h0_bool = chars_to_bools<32>(get_empty_hash().data());
  emp::block h0[256];

  emp::ProtocolExecution::prot_exec->feed(zero_key, emp::PUBLIC, zero.data(),
                                          256);
  emp::ProtocolExecution::prot_exec->feed(h0, emp::PUBLIC, h0_bool.data(), 256);

  //   Bob:   psk[128..255] (128) || dummy CH hash (256)   = 384 bits (48 bytes)
  //   Alice: psk[0..127]   (128) || real  CH hash (256)   = 384 bits (48 bytes)
  emp::block psk[256];
  emp::block ch_hash[256];
  emp::block bob_empty[256];

  emp::ProtocolExecution::prot_exec->feed(psk + 128, emp::BOB,
                                          bob_psk_bool.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(bob_empty, emp::BOB,
                                          ch_hash_bool.data(), 256); // ignored

  emp::ProtocolExecution::prot_exec->feed(psk, emp::ALICE,
                                          alice_psk_bool.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(ch_hash, emp::ALICE,
                                          ch_hash_bool.data(), 256);

  // ES = HKDF-Extract(0, PSK)
  emp::block es[256];
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{zero_key, 256},
                                 EmpBlockNonOwningSpan{psk, 256}, es);

  // binder_key = Derive-Secret(ES, "res binder", "")
  emp::block binder_key[256];
  CircuitSynthesis::hkdf_expand_label(EmpBlockNonOwningSpan{es, 256},
                                      "res binder",
                                      EmpBlockNonOwningSpan{h0, 256},
                                      binder_key, 32);

  // finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
  emp::block *empty_span = nullptr;
  emp::block finished_key[256];
  CircuitSynthesis::hkdf_expand_label(EmpBlockNonOwningSpan{binder_key, 256},
                                      get_tag<TypeOfDerivation::FK_S>(),
                                      EmpBlockNonOwningSpan{empty_span, 0},
                                      finished_key, 32);

  // binder = HMAC(finished_key, H(truncated CH)). HKDF-Extract(salt, IKM) is
  // exactly HMAC(salt, IKM), so we reuse it rather than adding a primitive.
  emp::block binder[256];
  CircuitSynthesis::hkdf_extract(EmpBlockNonOwningSpan{finished_key, 256},
                                 EmpBlockNonOwningSpan{ch_hash, 256}, binder);

  bool out_bool[256];
  emp::ProtocolExecution::prot_exec->reveal(out_bool, emp::PUBLIC, binder, 256);
  emp::finalize_plain_prot();
}

static void DeriveAESSplit() noexcept {
  // This circuit implements the initial IV expansion for AES-CTR mode.
  // Essentially, if you're familiar with the AES-CTR diagram, this computes IV
  // || 0^31 || 1 and outputs shares to both parties. This is important because
  // it takes a 96 bit IV known by both parties and outputs a 128-bit share of
  // the total IV. This is because the IV that's derived in the handshake isn't
  // actually the full IV, but just a portion. The outputs are the output IV
  // (but masked) along with shares of the encryption of the first counter.
  emp::setup_plain_prot(true, "aes_ctr_split.txt");

  // We accept as input a 128 bit key share, 96 bits (the IV), a 128 bit mask
  // (for the output IV), and 128 bit mask (for the output ciphertext).
  constexpr auto input_size = 480;
  std::array<bool, input_size> alice_in, bob_in;
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE,
                                          alice_in.data(), input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in.data(),
                                          input_size);

  // Recover the key.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // Recover the IV
  emp::block iv[128];
  for (unsigned i = 0; i < 96; i++) {
    iv[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                       bob_blocks[i]);
  }

  // Fill in the rest with 0s and 1.
  emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  emp::block one = emp::CircuitExecution::circ_exec->public_label(true);
  std::fill(iv + 96, iv + 127, zero);
  iv[127] = one;

  // Now we encrypt the IV to produce the first part.
  // The AES circuit needs the key and then the plaintext.
  emp::block input[256];
  memcpy(input, key, 128 * sizeof(emp::block));
  memcpy(input + 128, iv, 128 * sizeof(emp::block));

  // Run the encryption.
  emp::block output[128];
  assert(Util::is_valid_filepath(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt"));
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  bf.compute(output, input, input);

  // Now we need to mask the output IV from above.
  emp::block output_iv[128];
  for (unsigned i = 0; i < 128; i++) {
    emp::block tmp = emp::CircuitExecution::circ_exec->xor_gate(
        iv[i], alice_blocks[224 + i]);
    output_iv[i] =
        emp::CircuitExecution::circ_exec->xor_gate(tmp, bob_blocks[224 + i]);
  }

  // And finally mask the output of the encrypted IV too.
  emp::block output_ctx[128];
  for (unsigned i = 0; i < 128; i++) {
    emp::block tmp = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], alice_blocks[352 + i]);
    output_ctx[i] =
        emp::CircuitExecution::circ_exec->xor_gate(tmp, bob_blocks[352 + i]);
  }

  bool out_ctx[128], out_iv[128];
  emp::ProtocolExecution::prot_exec->reveal(out_iv, emp::PUBLIC, output_iv,
                                            128);
  emp::ProtocolExecution::prot_exec->reveal(out_ctx, emp::PUBLIC, output_ctx,
                                            128);
  emp::finalize_plain_prot();
}

static void pclmulqdq(const emp::block *a, const emp::block *b,
                      emp::block *c) noexcept {

  // This is an implementation of the pseudocode found at:
  // https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
  // Page 8. In particular, this function implements a carryless multiplication
  // over "a" and "b". The function expects `a` and `b` to point to 64 blocks,
  // with `c` pointing to 128 blocks.
  // The algorithm implemented is essentially
  // https://www.felixcloutier.com/x86/pclmulqdq (the "Operation" algorithm).
  assert(a);
  assert(b);
  assert(c);

  emp::block tmp;

  for (unsigned i = 0; i < 64; i++) {
    tmp = emp::CircuitExecution::circ_exec->and_gate(a[0], b[i]);
    for (unsigned j = 1; j <= i; j++) {
      tmp = emp::CircuitExecution::circ_exec->xor_gate(
          tmp, emp::CircuitExecution::circ_exec->and_gate(a[j], b[i - j]));
    }
    c[i] = tmp;
  }

  for (unsigned i = 64; i < 127; i++) {
    tmp = emp::CircuitExecution::circ_exec->public_label(false);
    for (unsigned j = i - 63; j < 64; j++) {
      tmp = emp::CircuitExecution::circ_exec->xor_gate(
          tmp, emp::CircuitExecution::circ_exec->and_gate(a[j], b[i - j]));
    }
    c[i] = tmp;
  }

  c[127] = emp::CircuitExecution::circ_exec->public_label(false);
}

static EmpBlockArray<128> pclmulqdq(const emp::block *const a,
                                    const emp::block *const b) noexcept {
  EmpBlockArray<128> out;
  pclmulqdq(a, b, out.data());
  return out;
}

static void DeriveGCMMultiplicativeSharesNaive() noexcept {
  // This function produces a circuit for a multiplicative share of AES GCM
  // using naive multiplication. This just implements the multiplication
  // algorithm as you'd expect from AES-GCM.
  emp::setup_plain_prot(true, "derive_gcm_mult_shares_naive.txt");
  // We feed in this many mask bits per party.
  static constexpr auto mask_input = 128;
  // And this many key bits per party.
  static constexpr auto key_input = 128;
  // So there's this many input bits in total.
  static constexpr auto input_size = mask_input + key_input;

  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

  bool alice_input[input_size], bob_input[input_size];
  emp::block alice_blocks[input_size], bob_blocks[input_size];
  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  // Feed the input into the garbled circuit.
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  // Produce the key.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block gcm_key_raw[128];
  bf.compute(gcm_key_raw, circuit_in, circuit_in);

  // Now we multiply through by Bob's share.
  // The multiplication algorithm below
  // comes from the NIST GCM spec
  // (https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
  // page 8, Alg 1).

  auto mult = [zero](emp::block(&z)[128], const emp::block(&x)[128],
                     const emp::block(&y)[128]) {
    // This is a branchless implementation, designed to avoid the use of `ifs`.
    emp::block v[128];
    memcpy(v, x, sizeof(emp::block) * 128);
    emp::block one = emp::CircuitExecution::circ_exec->public_label(true);

    // R is defined in the spec as 111000010000......
    emp::block R[128];
    std::fill(std::begin(R), std::end(R), zero);
    R[0] = one;
    R[1] = one;
    R[2] = one;
    R[7] = one;

    std::fill(std::begin(z), std::end(z), zero);
    emp::block tmp_v[128];
    emp::block tmp_r[128];

    for (unsigned i = 0; i < 128; i++) {
      // NIST says Z = Z \xor V if Y[i] == 1 and Z = Z otherwise.
      // This can be rewritten as Z = Z \xor (V \and arr(Y[i]))
      for (unsigned j = 0; j < 128; j++) {
        tmp_v[j] = emp::CircuitExecution::circ_exec->and_gate(v[j], y[i]);
      }

      for (unsigned j = 0; j < 128; j++) {
        z[j] = emp::CircuitExecution::circ_exec->xor_gate(z[j], tmp_v[j]);
      }

      // NIST also says that if v[127] == 0 then v = v >> 1, else v = v >> 1
      // \xor R Clearly this is equivalent to v = v >> 1 \xor (R \and v[127]).
      for (unsigned j = 0; j < 8; j++) {
        tmp_r[j] = emp::CircuitExecution::circ_exec->and_gate(v[127], R[j]);
      }

      // Rotate to the right by 1.
      std::rotate(std::rbegin(v), std::rbegin(v) + 1, std::rend(v));
      // Zero out the lowest.
      v[0] = zero;

      // Now xor in R.
      for (unsigned j = 0; j < 8; j++) {
        v[j] = emp::CircuitExecution::circ_exec->xor_gate(v[j], tmp_r[j]);
      }
    }

    // Everything is in Z here.
  };

  emp::block prod[128];
  emp::block bob_share[128];
  memcpy(bob_share, bob_blocks + 128, sizeof(bob_share));

  // Multiply through.
  mult(prod, gcm_key_raw, bob_share);

  // Mask against Alice's share.
  for (unsigned i = 0; i < 128; i++) {
    prod[i] = emp::CircuitExecution::circ_exec->xor_gate(prod[i],
                                                         alice_blocks[i + 128]);
  }

  bool output[128];
  emp::ProtocolExecution::prot_exec->reveal(output, emp::PUBLIC, prod, 128);
  emp::finalize_plain_prot();
}

static void gcm_mult(const emp::block (&a)[128], const emp::block (&b)[128],
                     emp::block (&c)[128]) noexcept {

  EmpBlockArray<128> XMMMASK;
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  const auto one = emp::CircuitExecution::circ_exec->public_label(true);
  std::fill(XMMMASK.begin(), XMMMASK.begin() + 32, one);
  std::fill(XMMMASK.begin() + 32, XMMMASK.end(), zero);

  auto tmp3 = pclmulqdq(a, b);
  auto tmp6 = pclmulqdq(a + 64, b + 64);

  auto tmp4 = CircuitSynthesis::shuffle_epi32(a, 78);
  auto tmp5 = CircuitSynthesis::shuffle_epi32(b, 78);
  tmp4 = CircuitSynthesis::xor_si128(tmp4.data(), a);
  tmp5 = CircuitSynthesis::xor_si128(tmp5.data(), b);
  tmp4 = pclmulqdq(tmp4.data(), tmp5.data());
  tmp4 = CircuitSynthesis::xor_si128(tmp4, tmp3);
  tmp4 = CircuitSynthesis::xor_si128(tmp4, tmp6);
  tmp5 = CircuitSynthesis::slli_si128(tmp4, 8);
  tmp4 = CircuitSynthesis::srli_si128(tmp4, 8);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp5);
  tmp6 = CircuitSynthesis::xor_si128(tmp6, tmp4);
  auto tmp7 = CircuitSynthesis::srli_epi32(tmp6, 31);
  auto tmp8 = CircuitSynthesis::srli_epi32(tmp6, 30);
  auto tmp9 = CircuitSynthesis::srli_epi32(tmp6, 25);
  tmp7 = CircuitSynthesis::xor_si128(tmp7, tmp8);
  tmp7 = CircuitSynthesis::xor_si128(tmp7, tmp9);
  tmp8 = CircuitSynthesis::shuffle_epi32(tmp7, 147);
  tmp7 = CircuitSynthesis::and_si128(XMMMASK, tmp8);
  tmp8 = CircuitSynthesis::andnot_si128(XMMMASK, tmp8);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp8);
  tmp6 = CircuitSynthesis::xor_si128(tmp6, tmp7);
  auto tmp10 = CircuitSynthesis::slli_epi32(tmp6, 1);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp10);
  auto tmp11 = CircuitSynthesis::slli_epi32(tmp6, 2);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp11);
  auto tmp12 = CircuitSynthesis::slli_epi32(tmp6, 7);
  tmp3 = CircuitSynthesis::xor_si128(tmp3, tmp12);
  tmp3 = CircuitSynthesis::xor_si128(tmp6, tmp3);
  std::copy(tmp3.begin(), tmp3.end(), &c[0]);
}

static void DeriveGCMMultiplicativeShares() noexcept {
  // This function produces a circuit that generates multiplicative
  // shares of the initial AES GCM share.
  emp::setup_plain_prot(true, "derive_gcm_mult_shares.txt");

  // We feed in this many mask bits per party.
  static constexpr auto mask_input = 128;
  // And this many key bits per party.
  static constexpr auto key_input = 128;
  // So there's this many input bits in total.
  static constexpr auto input_size = mask_input + key_input;

  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);

  bool alice_input[input_size], bob_input[input_size];
  emp::block alice_blocks[input_size], bob_blocks[input_size];
  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  // Feed the input into the garbled circuit.
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  // Produce the key.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block gcm_key_raw[128];
  bf.compute(gcm_key_raw, circuit_in, circuit_in);

  // Now we multiply through by Bob's input mask.
  // This just uses the regular multiplication algorithm over GF(2^128).
  // It turns out this is actually faster than the naive multiplication
  // algorithm from the NIST manual in terms of AND gates.
  // This algorithm is essentially a transcription of the algorithm used in
  // F2128MtA.inl for garbled circuits, which is Algorithm 7 of
  // https://www.intel.com/content/dam/develop/public/us/en/documents/carry-less-multiplication-instruction.pdf,
  // originally. We just adapted it for garbled circuits.
  emp::block a[128], b[128], c[128];
  memcpy(a, gcm_key_raw, sizeof(a));
  memcpy(b, bob_blocks + 128, sizeof(b));
  gcm_mult(a, b, c);

  // Add Alice's 128 bits as a mask.
  for (unsigned i = 0; i < 128; i++) {
    c[i] =
        emp::CircuitExecution::circ_exec->xor_gate(c[i], alice_blocks[128 + i]);
  }

  bool out[128];
  emp::ProtocolExecution::prot_exec->reveal(out, emp::PUBLIC, c, 128);
  emp::finalize_plain_prot();
}

static void DeriveGCMAdditiveShares() noexcept {
  // This function derives additive shares of all GCM shares up to h^1024.
  // This function is not intended to be used: it is only provided to show the
  // circuit costs from the paper.
  emp::setup_plain_prot(true, "derive_gcm_add_shares.txt");
  static constexpr auto mask_input = 131072;
  static constexpr auto key_input = 128;
  static constexpr auto input_size = mask_input + key_input;
  constexpr auto BLOCK = 1024;

  emp::block zero = emp::CircuitExecution::circ_exec->public_label(false);
  bool *alice_in = new bool[input_size];
  bool *bob_in = new bool[input_size];

  // Produce random input data for both.
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block *alice_blocks = new emp::block[input_size];
  emp::block *bob_blocks = new emp::block[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_in,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in,
                                          input_size);

  // Produce the key.
  emp::block key[128];

  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  std::fill(std::begin(circuit_in) + 128, std::end(circuit_in), zero);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block gcm_key_raw[128];
  bf.compute(gcm_key_raw, circuit_in, circuit_in);

  // Now produce the rest.
  emp::block middle_results[128][128];
  memset(middle_results, 0, sizeof(emp::block) * 128 * 128);
  for (int i = 0; i < 128; i++) {
    middle_results[0][i] = gcm_key_raw[i];
  }

  for (int i = 1; i < 128; i++) {
    middle_results[i][0] = middle_results[i - 1][127];
    for (int j = 1; j < 128; j++) {
      middle_results[i][j] = middle_results[i - 1][j - 1];
    }

    middle_results[i][7] = emp::CircuitExecution::circ_exec->xor_gate(
        middle_results[i - 1][6], middle_results[i - 1][127]);
    middle_results[i][2] = emp::CircuitExecution::circ_exec->xor_gate(
        middle_results[i - 1][1], middle_results[i - 1][127]);
    middle_results[i][1] = emp::CircuitExecution::circ_exec->xor_gate(
        middle_results[i - 1][0], middle_results[i - 1][127]);
  }

  emp::block *result = new emp::block[128 * BLOCK];
  for (int i = 0; i < 128 * BLOCK; i++) {
    result[i] = zero;
  }

  for (int i = 0; i < 128; i++) {
    result[i] = gcm_key_raw[i];
  }

  for (int b = 1; b < BLOCK; b++) {
    for (int i = 0; i < 128; i++) {
      for (int j = 0; j < 128; j++) {
        emp::block tmp = emp::CircuitExecution::circ_exec->and_gate(
            middle_results[i][j], result[(b - 1) * 128 + i]);
        result[b * 128 + j] = emp::CircuitExecution::circ_exec->xor_gate(
            result[b * 128 + j], tmp);
      }
    }
  }

  emp::block *out = new emp::block[128 * BLOCK];

  CircuitSynthesis::change_endian(EmpBlockNonOwningSpan{result, 128 * BLOCK},
                                  out);

  for (unsigned i = 0; i < 128 * BLOCK; i++) {
    emp::block tmp = emp::CircuitExecution::circ_exec->xor_gate(
        alice_blocks[128 + i], bob_blocks[128 + i]);
    out[i] = emp::CircuitExecution::circ_exec->xor_gate(out[i], tmp);
  }

  bool out_arr[128 * BLOCK];

  emp::ProtocolExecution::prot_exec->reveal(out_arr, emp::PUBLIC, out,
                                            128 * BLOCK);
  delete[] out;
  delete[] result;
  delete[] bob_blocks;
  delete[] alice_blocks;
  delete[] bob_in;
  delete[] alice_in;
  emp::finalize_plain_prot();
}

static emp::block or_gate(emp::block a, emp::block b) noexcept {
  // This function just mimics an OR gate using De Morgan's theorem.
  // I.e a || b = !(!a & !b).
  emp::block inv_a = emp::CircuitExecution::circ_exec->not_gate(a);
  emp::block inv_b = emp::CircuitExecution::circ_exec->not_gate(b);
  return emp::CircuitExecution::circ_exec->not_gate(
      emp::CircuitExecution::circ_exec->and_gate(inv_a, inv_b));
}

template <unsigned int length>
static emp::block equals(const emp::block *const a,
                         const emp::block *const b) noexcept {
  // This function checks whether `a` and `b` are equal by xoring their elements
  // in a pairwise fashion and then ORing each produced bit.
  // This costs `length-1` AND gates (the first one will be optimised away
  // as `out` == 0, so it's just the same as a[i]^b[i].
  assert(a);
  assert(b);
  emp::block out = emp::CircuitExecution::circ_exec->public_label(false);
  for (unsigned i = 0; i < length; i++) {
    out = or_gate(out, emp::CircuitExecution::circ_exec->xor_gate(a[i], b[i]));
  }

  // Make the output bit 1 if the answer is 0, 0 otherwise.
  return emp::CircuitExecution::circ_exec->not_gate(out);
}

// aes128_full.txt does not use the byte convention chars_to_bools produces.
// Measured against the FIPS-197 C.1 vector, the raw circuit computes
// bitrev(AES(byterev(key), byterev(plaintext)))
// where byterev reverses the 16 byte-groups and bitrev reverses the 8 bits
// within each byte. Pre-reversing both inputs and un-reversing the output
// recovers a plain AES-128 block encryption.
static void rev_bytes128(const emp::block *in, emp::block *out) noexcept {
  for (unsigned i = 0; i < 16; i++)
    for (unsigned j = 0; j < 8; j++)
      out[i * 8 + j] = in[(15 - i) * 8 + j];
}

static void rev_bits128(const emp::block *in, emp::block *out) noexcept {
  for (unsigned i = 0; i < 16; i++)
    for (unsigned j = 0; j < 8; j++)
      out[i * 8 + j] = in[i * 8 + (7 - j)];
}

static void aes128_encrypt(emp::BristolFormat &bf, const emp::block *key,
                           const emp::block *pt, emp::block *out) noexcept {
  emp::block in[256], raw[128];
  rev_bytes128(key, in);
  rev_bytes128(pt, in + 128);
  bf.compute(raw, in, in);
  rev_bits128(raw, out);
}

// SURF Gamma': Hirose double-block-length compression from AES-128
//
//   G_i = AES_{r_i}(b_i)     XOR b_i
//   H_i = AES_{r_i}(b_i^c)   XOR b_i XOR c
//
// c is any fixed nonzero constant; the two-call structure is what gives
// 2^128 collision bound.
// ~21.3k ANDs with ~12.8k.
//
// r_i MUST be fresh per slot. Two slots sharing r whose b values differ by
// exactly c produce cross-related commitments and hiding breaks.
static constexpr std::array<unsigned char, 16> kHiroseC{
    0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

// out receives 256 blocks: G_i (128) || H_i (128).
static void hirose_commit(emp::BristolFormat &bf, const emp::block *const r,
                          const emp::block *const b, const emp::block *const c,
                          emp::block *const out) noexcept {
  // XOR against a public constant costs no AND gates.
  emp::block bc[128];
  for (unsigned i = 0; i < 128; i++) {
    bc[i] = emp::CircuitExecution::circ_exec->xor_gate(b[i], c[i]);
  }

  emp::block g[128], h[128];
  aes128_encrypt(bf, r, b, g);
  aes128_encrypt(bf, r, bc, h);

  for (unsigned i = 0; i < 128; i++) {
    out[i] = emp::CircuitExecution::circ_exec->xor_gate(g[i], b[i]);
    out[128 + i] = emp::CircuitExecution::circ_exec->xor_gate(h[i], bc[i]);
  }
}

// Host-side AES-128 via the same circuit gadget, for the testing path only.
static std::array<unsigned char, 16>
aes128_host(const std::array<unsigned char, 16> &key,
            const std::array<unsigned char, 16> &pt) noexcept {
  const auto k_bits = chars_to_bools<16>(key.data());
  const auto p_bits = chars_to_bools<16>(pt.data());

  emp::block k_blk[128], p_blk[128];
  emp::ProtocolExecution::prot_exec->feed(k_blk, emp::PUBLIC, k_bits.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(p_blk, emp::PUBLIC, p_bits.data(), 128);

  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  emp::block out[128];
  aes128_encrypt(bf, k_blk, p_blk, out);
  return print_hash_to_string<16>(out);
}

// Host-side reference, for the testing path and for the verifier at
// MASK_COMMIT. aes128_encrypt reproduces plain AES-128 over byte arrays fed
// through chars_to_bools (this is what the FIPS-197 C.1 check asserts), so the
// two agree byte for byte.
static std::array<unsigned char, 32>
hirose_commit_host(const std::array<unsigned char, 16> &r,
                   const std::array<unsigned char, 16> &b) noexcept {
  std::array<unsigned char, 16> bc{};
  for (unsigned i = 0; i < 16; i++) {
    bc[i] = static_cast<unsigned char>(b[i] ^ kHiroseC[i]);
  }

  const auto r_bits = chars_to_bools<16>(r.data());
  const auto b_bits = chars_to_bools<16>(b.data());
  const auto bc_bits = chars_to_bools<16>(bc.data());

  emp::block r_blk[128], b_blk[128], bc_blk[128];
  emp::ProtocolExecution::prot_exec->feed(r_blk, emp::PUBLIC, r_bits.data(),
                                          128);
  emp::ProtocolExecution::prot_exec->feed(b_blk, emp::PUBLIC, b_bits.data(),
                                          128);
  emp::ProtocolExecution::prot_exec->feed(bc_blk, emp::PUBLIC, bc_bits.data(),
                                          128);

  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block g[128], h[128];
  aes128_encrypt(bf, r_blk, b_blk, g);
  aes128_encrypt(bf, r_blk, bc_blk, h);

  const auto g_bytes = print_hash_to_string<16>(g);
  const auto h_bytes = print_hash_to_string<16>(h);

  std::array<unsigned char, 32> out{};
  for (unsigned i = 0; i < 16; i++) {
    out[i] = static_cast<unsigned char>(g_bytes[i] ^ b[i]);
    out[16 + i] = static_cast<unsigned char>(h_bytes[i] ^ bc[i]);
  }
  return out;
}

// FIPS-197 C.1: AES-128(000102...0f, 00112233...ff) = 69c4e0d8...c55a.
// The key-share constants below are chosen so kc ^ kv is exactly that key, and
// the counter/plaintext block is exactly that input, so the circuit's expected
// output is a published vector rather than one we computed ourselves.
//
// Every one of these is asymmetric under BOTH byte reversal and bit reversal.
// Two rounds of testing on the decryption path were invalidated by
// byte-palindromic constants (0f0f..0f, 11..11): a convention bug is invisible
// under those.
static constexpr std::array<unsigned char, 16> kFipsKc{
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static constexpr std::array<unsigned char, 16> kFipsKv{
    0x2b, 0x7f, 0x17, 0x15, 0x2c, 0xab, 0xd4, 0xa1,
    0xa3, 0xfe, 0x1f, 0x83, 0x05, 0xc2, 0x41, 0x33};
// kFipsKc ^ kFipsKv == 000102030405060708090a0b0c0d0e0f
static constexpr std::array<unsigned char, 16> kFipsPt{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static constexpr std::array<unsigned char, 16> kFipsCt{
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

// SURF: Algorithm 1's tag line, tau <- tau_c XOR tau_v XOR AES.Enc(k, J0).
//
// Input layout, 64 bytes, identical shape for both parties and matching
// GCMTagCircuitIn:
//   key_share (16) || iv/J0 (16) || tag_share (16) || mask (16, ALICE only)
//
// Both parties feed the same J0 (checked on wires); each feeds its own GHASH
// share, computed locally because GHASH is linear in the H-powers. The output
// is masked with ALICE's one-time mask before reveal, so BOB never learns the
// tag: BOB sees tau XOR mask and forwards it, ALICE strips its own mask. This
// matters because Algorithm 1 gives tau to C only.
//
// Output: ok (1 byte, 0x00 or 0xFF) || tau XOR mask (16 bytes).
//
// `testing` runs in plain mode against the FIPS-197 C.1 vector and asserts the
// revealed value matches; it emits no circuit file.
template <bool testing = false> static void DeriveGCMTag() {
  emp::setup_plain_prot(!testing, "derive_gcm_tag.txt");
  constexpr auto input_size = 128 + 128 + 128 + 128;

  constexpr auto kc = kFipsKc;
  constexpr auto kv = kFipsKv;
  constexpr auto j0 = kFipsPt;  // the AES input; J0 in the real protocol
  constexpr std::array<unsigned char, 16> ts_a{
      0x9d, 0x1c, 0x37, 0x54, 0xe1, 0x08, 0x72, 0xbb,
      0x4a, 0xf5, 0x63, 0x20, 0xd7, 0x8e, 0x01, 0xcc};
  constexpr std::array<unsigned char, 16> ts_b{
      0x35, 0x81, 0x0f, 0x66, 0xa2, 0xdb, 0x14, 0x7f,
      0xe9, 0x3c, 0x50, 0xb8, 0x6d, 0x24, 0xf1, 0x0a};
  constexpr std::array<unsigned char, 16> mask{
      0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec,
      0x29, 0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 0x46};

  bool alice_in[input_size]{}, bob_in[input_size]{};
  if constexpr (testing) {
    const auto kc_b = chars_to_bools<16>(kc.data());
    const auto kv_b = chars_to_bools<16>(kv.data());
    const auto j0_b = chars_to_bools<16>(j0.data());
    const auto ta_b = chars_to_bools<16>(ts_a.data());
    const auto tb_b = chars_to_bools<16>(ts_b.data());
    const auto mk_b = chars_to_bools<16>(mask.data());
    std::copy(kc_b.begin(), kc_b.end(), alice_in + 0);
    std::copy(j0_b.begin(), j0_b.end(), alice_in + 128);
    std::copy(ta_b.begin(), ta_b.end(), alice_in + 256);
    std::copy(mk_b.begin(), mk_b.end(), alice_in + 384);
    std::copy(kv_b.begin(), kv_b.end(), bob_in + 0);
    std::copy(j0_b.begin(), j0_b.end(), bob_in + 128);
    std::copy(tb_b.begin(), tb_b.end(), bob_in + 256);
    // BOB's mask wires stay zero: they are ignored padding.
  } else {
    for (unsigned i = 0; i < input_size; i++) {
      alice_in[i] = rand();
      bob_in[i] = rand();
    }
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  // BOB first: see the WARNING in ProduceCombinedCircuit.
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_in,
                                          input_size);

  // Recover k = k_c XOR k_v. The upper half of key_and_iv only preserves the
  // old shape; aes128_encrypt takes key and plaintext as separate pointers.
  emp::block key_and_iv[256];
  for (unsigned i = 0; i < 128; i++) {
    key_and_iv[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                               bob_blocks[i]);
  }
  memcpy(key_and_iv + 128, alice_blocks + 128, sizeof(emp::block) * 128);

  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  // WAS: bf.compute(output, key_and_iv, key_and_iv). The raw circuit computes
  // bitrev(AES(byterev(k), byterev(pt))); aes128_encrypt undoes that. The
  // reversals are pure permutations of the block array and emit no gates.
  emp::block output[128];
  aes128_encrypt(bf, key_and_iv, alice_blocks + 128, output);

  // XOR in both GHASH shares.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], emp::CircuitExecution::circ_exec->xor_gate(
                       alice_blocks[i + 256], bob_blocks[i + 256]));
  }

  // Algorithm 1: "if IVc != IVv then return Error".
  const auto were_same = equals<128>(alice_blocks + 128, bob_blocks + 128);
  emp::block ok_arr[128];
  std::fill(std::begin(ok_arr), std::end(ok_arr), were_same);
  for (unsigned i = 0; i < 128; i++) {
    output[i] =
        emp::CircuitExecution::circ_exec->and_gate(ok_arr[i], output[i]);
  }

  bool ok_b[8];
  emp::ProtocolExecution::prot_exec->reveal(ok_b, emp::PUBLIC, ok_arr, 8);

  // Mask against ALICE's one-time mask so BOB never sees tau.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], alice_blocks[384 + i]);
  }

  if constexpr (testing) {
    const auto revealed = print_hash_to_string<16>(output);

    // tau = AES(k, J0) ^ tau_a ^ tau_b, then masked. AES(k, J0) is the FIPS
    // vector by construction of kFipsKc / kFipsKv / kFipsPt above.
    std::array<unsigned char, 16> expected{};
    for (unsigned i = 0; i < 16; i++) {
      expected[i] = kFipsCt[i] ^ ts_a[i] ^ ts_b[i] ^ mask[i];
    }

    fprintf(stderr, "[gcm_tag_test] got ");
    for (auto v : revealed) fprintf(stderr, "%02x", v);
    fprintf(stderr, "  want ");
    for (auto v : expected) fprintf(stderr, "%02x", v);
    fprintf(stderr, "\n");
    if (revealed != expected) {
      fprintf(stderr, "[gcm_tag_test] FAILED: derive_gcm_tag.txt would be "
                      "miscompiled; refusing to emit it.\n");
      std::abort();
    }
  } else {
    bool tag[128];
    emp::ProtocolExecution::prot_exec->reveal(tag, emp::PUBLIC, output, 128);
  }
  emp::finalize_plain_prot();
}


static void DeriveGCMVerify() {
  emp::setup_plain_prot(true, "derive_gcm_verify.txt");
  // This is essentially the same setup as with the tagging, but
  // here we also take the server tag from both parties.
  // That, and there's no mask on the output: we just only output one bit.
  constexpr auto input_size = 128 + 128 + 128 + 128;

  bool alice_input[input_size], bob_input[input_size];
  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  // Recover the key and IV.
  emp::block key_and_iv[256];
  for (unsigned i = 0; i < 128; i++) {
    key_and_iv[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                               bob_blocks[i]);
  }

  // Just copy over Alice's IV for now.
  memcpy(key_and_iv + 128, alice_blocks + 128, sizeof(emp::block) * 128);
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block output[128];
  aes128_encrypt(bf, key_and_iv, alice_blocks + 128, output);

  // Now we can produce the tag shares too. We just xor against the output
  // directly.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], emp::CircuitExecution::circ_exec->xor_gate(
                       alice_blocks[i + 256], bob_blocks[i + 256]));
  }

  // Now we check if the IVs were the same.
  const auto were_ivs_same = equals<128>(alice_blocks + 128, bob_blocks + 128);

  // And we also do the same for the server tags.
  const auto were_tags_same = equals<128>(alice_blocks + 384, bob_blocks + 384);

  // Combine into a single bit.
  const auto did_either_cheat = emp::CircuitExecution::circ_exec->and_gate(were_ivs_same, were_tags_same);

  // Now check if the tags were the same. We just use one of the input tags.
  // We also mask against the cheating information, because otherwise the output
  // is unreliable.
  const auto tag_verify = emp::CircuitExecution::circ_exec->and_gate(
      equals<128>(output, alice_blocks + 384), did_either_cheat);

  // Now we pad out the tag_verify to 8 bits, and the same with
  // did_either_cheat.
  emp::block tv[8], pc[8];
  std::fill(std::begin(tv), std::end(tv), tag_verify);
  std::fill(std::begin(pc), std::end(pc), did_either_cheat);

  bool tag_vf[8], party_cheat[8];
  emp::ProtocolExecution::prot_exec->reveal(tag_vf, emp::PUBLIC, tv, 8);
  emp::ProtocolExecution::prot_exec->reveal(party_cheat, emp::PUBLIC, pc, 8);
  emp::finalize_plain_prot();
}

// SURF TRUE mode. Algorithm 1's tag check plus an in-circuit key-commitment
// opening:
//
//   Gamma.Open(d_k, r_k, k_c)  AND  (tau_c ^ tau_v ^ AES_{k_c+k_v}(J0) == tau)
//
// Needed only in TRUE mode. Masked mode binds the key implicitly: V receives
// E_i = AES_k(ctr_i) ^ b_i, so once b_i is opened the keystream
// is fixed by a value V already holds. TRUE mode
// has no E_i, so V would hold ciphertext, tags and its own k_v with nothing
// tying k_c to what it verified. AES-GCM is not key-committing: a tag can
// authenticate under more than one key, so the comparison below does not by
// itself pin k_c, and a prover could pass here and open a different k_c later,
// presenting a different plaintext for the same recorded ciphertext.
//
// One wire bundle (kOffKey) feeds both the AES key and the Hirose input, so
// the tagged key and the opened key cannot differ.
//
// Input, 96 bytes, identical shape for both parties:
//   key_share (16) || iv/J0 (16) || tag_share (16) || server_tag (16)
//     || r_k (16, ALICE; BOB pads) || d_k (32, BOB; ALICE pads)
//
// Output: tag_passed (1) || cheated (1) || key_opened (1), repeated-bit bytes.
static void DeriveGCMVerifyCommit() {
  emp::setup_plain_prot(true, "derive_gcm_verify_commit.txt");

  constexpr unsigned kOffKey = 0;
  constexpr unsigned kOffIv = kOffKey + 128;
  constexpr unsigned kOffTagShare = kOffIv + 128;
  constexpr unsigned kOffServerTag = kOffTagShare + 128;
  constexpr unsigned kOffRk = kOffServerTag + 128;
  constexpr unsigned kOffDk = kOffRk + 128;
  constexpr unsigned input_size = kOffDk + 256;

  bool *alice_input = new bool[input_size]();
  bool *bob_input = new bool[input_size]();
  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  emp::block *alice_blocks = new emp::block[input_size];
  emp::block *bob_blocks = new emp::block[input_size];
  // BOB first: see the WARNING in ProduceCombinedCircuit.
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  // Recover k = k_c ^ k_v.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block output[128];
  aes128_encrypt(bf, key, alice_blocks + kOffIv, output);

  // XOR in both GHASH shares: GHASH is linear in the H-powers, so each party
  // computes its half locally over its own copy of A || C || len.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], emp::CircuitExecution::circ_exec->xor_gate(
                       alice_blocks[i + kOffTagShare],
                       bob_blocks[i + kOffTagShare]));
  }

  // Gamma.Open on ALICE's key-share wires, the same wires feeding the AES.
  const auto c_blocks = chars_to_blocks<16>(kHiroseC.data());
  emp::block key_commit[256];
  hirose_commit(bf, alice_blocks + kOffRk, alice_blocks + kOffKey,
                c_blocks.data(), key_commit);
  const auto key_opened = equals<256>(key_commit, bob_blocks + kOffDk);

  // Both parties must have supplied the same J0 and the same server tag.
  const auto were_ivs_same =
      equals<128>(alice_blocks + kOffIv, bob_blocks + kOffIv);
  const auto were_tags_same =
      equals<128>(alice_blocks + kOffServerTag, bob_blocks + kOffServerTag);
  const auto did_either_cheat =
      emp::CircuitExecution::circ_exec->and_gate(were_ivs_same, were_tags_same);

  // Meaningful only if neither party cheated AND the key opened: a passing tag
  // under an unopened key proves nothing.
  const auto tag_and_key = emp::CircuitExecution::circ_exec->and_gate(
      equals<128>(output, alice_blocks + kOffServerTag), key_opened);
  const auto tag_verify =
      emp::CircuitExecution::circ_exec->and_gate(tag_and_key, did_either_cheat);

  emp::block tv[8], pc[8], ko[8];
  std::fill(std::begin(tv), std::end(tv), tag_verify);
  std::fill(std::begin(pc), std::end(pc), did_either_cheat);
  std::fill(std::begin(ko), std::end(ko), key_opened);

  bool tag_vf[8], party_cheat[8], key_ok[8];
  emp::ProtocolExecution::prot_exec->reveal(tag_vf, emp::PUBLIC, tv, 8);
  emp::ProtocolExecution::prot_exec->reveal(party_cheat, emp::PUBLIC, pc, 8);
  emp::ProtocolExecution::prot_exec->reveal(key_ok, emp::PUBLIC, ko, 8);

  delete[] bob_blocks;
  delete[] alice_blocks;
  delete[] bob_input;
  delete[] alice_input;
  emp::finalize_plain_prot();
}

static void DeriveCTXCommitments() {
  emp::setup_plain_prot(true, "derive_ctx_commitments.txt");

  // This circuit derives commitments to a particular AES CTR mode "block key".
  // Both parties feed in shares of an IV and their key, learning shares of K_I
  // = Enc(K, IV + I). Note that this assumes that the prover has already
  // committed to their key shares!

  // In this model, the prover supplies the IV, their key share, and the output
  // mask. The verifier supplies the IV and their key share, with 128 unused
  // wires.

  constexpr auto input_size = 128 + 128 + 128;

  bool alice_input[input_size];
  bool bob_input[input_size];

  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);

  // Recover the IV and the key.
  emp::block IV[128], key[128];
  for (unsigned i = 0; i < 128; i++) {
    IV[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                       bob_blocks[i]);
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i + 128],
                                                        bob_blocks[i + 128]);
  }

  // Now we can do the full encryption.
  // The full AES circuit expects key then ciphertext in a single block.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  memcpy(circuit_in + 128, IV, sizeof(IV));
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block output[128];
  bf.compute(output, circuit_in, circuit_in);

  // Check the IVs are the same.
  const auto were_same = equals<128>(alice_blocks, bob_blocks);

  // Produce the additive shares. This is just done by XORING
  // the produced ciphertext with the mask
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], alice_blocks[i + 256]);
    // Mask against the output.
    output[i] =
        emp::CircuitExecution::circ_exec->and_gate(output[i], were_same);
  }

  bool output_b[128];
  bool output_same[8];
  emp::block same_arr[8];
  std::fill(std::begin(same_arr), std::end(same_arr), were_same);
  emp::ProtocolExecution::prot_exec->reveal(output_b, emp::PUBLIC, output, 128);
  emp::ProtocolExecution::prot_exec->reveal(output_same, emp::PUBLIC, same_arr,
                                            8);
  emp::finalize_plain_prot();
}

static void DeriveKeystream() {
  emp::setup_plain_prot(true, "derive_keystream.txt");

  // SURF per-block keystream. Both parties feed a key share and the same
  // counter block; the prover additionally feeds the one-time mask b_i.
  // The circuit outputs E_i = AES.Enc(k_c ^ k_v, ctr) ^ b_i, which the
  // verifier holds sealed until b_i is opened at MASK_OPEN.
  //
  // Input layout (48 bytes, identical shape for both parties, matching
  // KSBlockCircuitIn): key (128) || ctr (128) || mask (128).
  // Bob's mask wires are unused padding: only Alice supplies a real b_i.
  constexpr auto input_size = 128 + 128 + 128;

  bool alice_input[input_size];
  bool bob_input[input_size];

  for (unsigned i = 0; i < input_size; i++) {
    alice_input[i] = rand();
    bob_input[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);

  // Recover the AES key from the two shares.
  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  // The counter block is public and fed by both; we take Alice's copy and
  // check the two agree below. A mismatch means the parties disagree on the
  // block map, which would silently yield the wrong keystream.
  emp::block circuit_in[256];
  memcpy(circuit_in, key, sizeof(key));
  memcpy(circuit_in + 128, alice_blocks + 128, sizeof(emp::block) * 128);

  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block output[128];
  bf.compute(output, circuit_in, circuit_in);

  const auto were_ctrs_same =
      equals<128>(alice_blocks + 128, bob_blocks + 128);

  // Mask with b_i (Alice's third input; Bob's is unused padding), then gate
  // on the counter check so a disagreeing run yields zeros rather than a
  // usable keystream.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->xor_gate(
        output[i], alice_blocks[i + 256]);
    output[i] =
        emp::CircuitExecution::circ_exec->and_gate(output[i], were_ctrs_same);
  }

  bool output_b[128];
  bool output_same[8];
  emp::block same_arr[8];
  std::fill(std::begin(same_arr), std::end(same_arr), were_ctrs_same);
  emp::ProtocolExecution::prot_exec->reveal(output_b, emp::PUBLIC, output, 128);
  emp::ProtocolExecution::prot_exec->reveal(output_same, emp::PUBLIC, same_arr,
                                            8);
  emp::finalize_plain_prot();
}

// SURF batched keystream with in-circuit commitment opening. Algorithm 2's
// per-block loop as a single invocation: the commitment check, the counter
// checks and the n keystream derivations all gate one shared `ok` bit, so a
// failed opening zeroes the whole batch.
//
// The masks are derived in-circuit from a single committed seed:
//
//   b_i = AES_s(ctr_i)
//   E_i = AES_k(ctr_i) XOR b_i
//
// so Gamma' is opened once per batch rather than once per slot. Binding is
// unchanged: to shift any b_i the prover needs an s' opening to the same
// commitment (2^128 under Hirose), and s' would move every mask at once.
//
// Hiding is now computational rather than information-theoretic: the b_i are
// PRF outputs, not independent uniform values. This requires that no two
// slots ever share a counter block, a repeat means a repeated mask, and
// E_i XOR E_j cancels it. Real blocks are distinct by (seq, counter);
// padding slots are given counters with the top bit set (see the host side).
// It also requires s independent of k, since E_i is the xor of two PRFs on
// the same input.
//
// Input layout, identical shape for both parties (bits):
//   key 128        each party's traffic-key share
//   ctr 128 * n    both parties; checked for equality
//   s   128        ALICE: the committed mask seed.  BOB: padding
//   r   128        ALICE: the commitment key.       BOB: padding
//   d   256        BOB:   G || H.                   ALICE: padding
// => 128n + 640 bits, i.e. 16n + 80 bytes per party.
//
// Output: E_i (128 * n) || ok (8).
template <unsigned n, bool testing = false>
static void DeriveKeystreamBatch(const bool corrupt = false) {
  emp::setup_plain_prot(!testing, "derive_keystream_batch_" +
                                      std::to_string(n) + ".txt");

  constexpr unsigned kOffKey = 0;
  constexpr unsigned kOffCtr = kOffKey + 128;
  constexpr unsigned kOffS = kOffCtr + 128 * n;
  constexpr unsigned kOffR = kOffS + 128;
  constexpr unsigned kOffD = kOffR + 128;
  constexpr unsigned input_size = kOffD + 256;

  std::array<unsigned char, 16> kc{}, kv{}, ctr{}, s{}, r{};
  for (unsigned i = 0; i < 16; i++) {
    kc[i] = static_cast<unsigned char>(rand());
    kv[i] = static_cast<unsigned char>(rand());
    ctr[i] = static_cast<unsigned char>(rand());
    s[i] = static_cast<unsigned char>(rand());
    r[i] = static_cast<unsigned char>(rand());
  }

  std::array<unsigned char, 32> expected_commit{};
  if constexpr (testing) {
    expected_commit = hirose_commit_host(r, s);
  }
  auto d = expected_commit;
  if (corrupt) {
    d[0] ^= 0x01;
  }

  const auto kc_bits = chars_to_bools<16>(kc.data());
  const auto kv_bits = chars_to_bools<16>(kv.data());
  const auto ctr_bits = chars_to_bools<16>(ctr.data());
  const auto s_bits = chars_to_bools<16>(s.data());
  const auto r_bits = chars_to_bools<16>(r.data());
  const auto d_bits = chars_to_bools<32>(d.data());

  bool *alice_input = new bool[input_size]();
  bool *bob_input = new bool[input_size]();

  std::copy(kc_bits.begin(), kc_bits.end(), alice_input + kOffKey);
  std::copy(kv_bits.begin(), kv_bits.end(), bob_input + kOffKey);
  std::copy(s_bits.begin(), s_bits.end(), alice_input + kOffS);
  std::copy(r_bits.begin(), r_bits.end(), alice_input + kOffR);
  std::copy(d_bits.begin(), d_bits.end(), bob_input + kOffD);
  for (unsigned blk = 0; blk < n; blk++) {
    std::copy(ctr_bits.begin(), ctr_bits.end(),
              alice_input + kOffCtr + 128 * blk);
    std::copy(ctr_bits.begin(), ctr_bits.end(),
              bob_input + kOffCtr + 128 * blk);
  }

  emp::block *alice_blocks = new emp::block[input_size];
  emp::block *bob_blocks = new emp::block[input_size];
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  const auto c_blocks = chars_to_blocks<16>(kHiroseC.data());

  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block ok = emp::CircuitExecution::circ_exec->public_label(true);

  // Gamma'.Open, once for the whole batch: (G, H) must equal Hirose(r, s).
  emp::block commit[256];
  hirose_commit(bf, alice_blocks + kOffR, alice_blocks + kOffS,
                c_blocks.data(), commit);
  ok = emp::CircuitExecution::circ_exec->and_gate(
      ok, equals<256>(commit, bob_blocks + kOffD));

  emp::block *out = new emp::block[128 * n];

  for (unsigned blk = 0; blk < n; blk++) {
    const unsigned c = kOffCtr + 128 * blk;

    // Both parties must agree on the counter block.
    ok = emp::CircuitExecution::circ_exec->and_gate(
        ok, equals<128>(alice_blocks + c, bob_blocks + c));

    emp::block ks[128], b[128];
    aes128_encrypt(bf, key, alice_blocks + c, ks);
    aes128_encrypt(bf, alice_blocks + kOffS, alice_blocks + c, b);

    for (unsigned j = 0; j < 128; j++) {
      out[128 * blk + j] =
          emp::CircuitExecution::circ_exec->xor_gate(ks[j], b[j]);
    }
  }

  // All-or-nothing: a bad opening zeroes the entire batch.
  for (unsigned i = 0; i < 128 * n; i++) {
    out[i] = emp::CircuitExecution::circ_exec->and_gate(out[i], ok);
  }

  emp::block ok_arr[8];
  std::fill(std::begin(ok_arr), std::end(ok_arr), ok);

  if constexpr (testing) {
    const auto got_commit = print_hash_to_string<32>(commit);
    const auto got_e = print_hash_to_string<16>(out);
    bool ok_b[8];
    emp::ProtocolExecution::prot_exec->reveal(ok_b, emp::PUBLIC, ok_arr, 8);

    std::array<unsigned char, 16> k_full{}, want_e{};
    for (unsigned i = 0; i < 16; i++) {
      k_full[i] = static_cast<unsigned char>(kc[i] ^ kv[i]);
    }
    const auto ks_host = aes128_host(k_full, ctr);
    const auto b_host = aes128_host(s, ctr);
    for (unsigned i = 0; i < 16; i++) {
      // out is gated on ok, so on the corrupt run it is all zero by design.
      want_e[i] = corrupt ? 0
                          : static_cast<unsigned char>(ks_host[i] ^ b_host[i]);
    }

    fprintf(stderr, "[ks_batch_test n=%u corrupt=%d] commit ", n, int(corrupt));
    for (auto v : got_commit) fprintf(stderr, "%02x", v);
    fprintf(stderr, " want ");
    for (auto v : expected_commit) fprintf(stderr, "%02x", v);
    fprintf(stderr, "  E_0 ");
    for (auto v : got_e) fprintf(stderr, "%02x", v);
    fprintf(stderr, " want ");
    for (auto v : want_e) fprintf(stderr, "%02x", v);
    fprintf(stderr, "  ok=%d\n", int(ok_b[0]));

    if (got_commit != expected_commit) {
      fprintf(stderr, "[ks_batch_test] FAILED: in-circuit Gamma' disagrees "
                      "with the host construction.\n");
      std::abort();
    }
    if (got_e != want_e) {
      fprintf(stderr, "[ks_batch_test] FAILED: E_0 != AES_k(ctr) ^ AES_s(ctr); "
                      "the seed-derived mask is miswired.\n");
      std::abort();
    }
    if (ok_b[0] == corrupt) {
      fprintf(stderr, "[ks_batch_test] FAILED: opening gate did not %s.\n",
              corrupt ? "reject a corrupted d" : "accept an honest d");
      std::abort();
    }
  } else {
    bool *out_b = new bool[128 * n];
    bool ok_b[8];
    emp::ProtocolExecution::prot_exec->reveal(out_b, emp::PUBLIC, out, 128 * n);
    emp::ProtocolExecution::prot_exec->reveal(ok_b, emp::PUBLIC, ok_arr, 8);
    delete[] out_b;
  }

  delete[] out;
  delete[] bob_blocks;
  delete[] alice_blocks;
  delete[] bob_input;
  delete[] alice_input;
  emp::finalize_plain_prot();
}

// SURF 2PC-AES-GCM encryption (Algorithm 1's per-block loop) as a single
// invocation covering n blocks. This mirrors DeriveKeystreamBatch, minus the
// commitment machinery: the ciphertext is public output by construction, so
// there is no b_i, no d_i and no in-circuit SHA-256.
//
// Counter blocks are computed host-side (SurfBlockMap::ctr_block) and checked
// for equality on wires, rather than incremented in-circuit with Inc128.txt.
// Inc128 has never been checked against a published vector and its bit
// convention is unknown; here it would be correctness-critical rather than
// comparison-based. This also makes the encrypt and keystream paths symmetric.
//
// Input layout, identical shape for both parties (bits):
//   key  128        each party's traffic-key share
//   ctr  128 * n    both parties; checked for equality
//   pt   128 * n    ALICE: the plaintext blocks.  BOB: padding
// => 128 + 256n bits, i.e. 16 + 32n bytes per party.
//
// Output: C_i (128 * n) || ok (8).
template <unsigned n, bool testing = false> static void DeriveAESEncBatch() {
  emp::setup_plain_prot(!testing, "aes_gcm_enc_batch_" + std::to_string(n) +
                                      ".txt");

  constexpr unsigned kOffKey = 0;
  constexpr unsigned kOffCtr = kOffKey + 128;
  constexpr unsigned kOffPt = kOffCtr + 128 * n;
  constexpr unsigned input_size = kOffPt + 128 * n;

  constexpr auto kc = kFipsKc;
  constexpr auto kv = kFipsKv;
  constexpr auto ctr = kFipsPt;  // the AES input; a counter block in practice
  constexpr std::array<unsigned char, 16> pt{
      0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
      0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a};

  bool *alice_input = new bool[input_size]();
  bool *bob_input = new bool[input_size]();

  if constexpr (testing) {
    const auto kc_b = chars_to_bools<16>(kc.data());
    const auto kv_b = chars_to_bools<16>(kv.data());
    const auto ct_b = chars_to_bools<16>(ctr.data());
    const auto pt_b = chars_to_bools<16>(pt.data());
    std::copy(kc_b.begin(), kc_b.end(), alice_input + kOffKey);
    std::copy(kv_b.begin(), kv_b.end(), bob_input + kOffKey);
    for (unsigned blk = 0; blk < n; blk++) {
      std::copy(ct_b.begin(), ct_b.end(), alice_input + kOffCtr + 128 * blk);
      std::copy(ct_b.begin(), ct_b.end(), bob_input + kOffCtr + 128 * blk);
      std::copy(pt_b.begin(), pt_b.end(), alice_input + kOffPt + 128 * blk);
    }
  } else {
    for (unsigned i = 0; i < input_size; i++) {
      alice_input[i] = rand();
      bob_input[i] = rand();
    }
  }

  emp::block *alice_blocks = new emp::block[input_size];
  emp::block *bob_blocks = new emp::block[input_size];
  // BOB first: see the WARNING in ProduceCombinedCircuit.
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_input,
                                          input_size);
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE, alice_input,
                                          input_size);

  emp::block key[128];
  for (unsigned i = 0; i < 128; i++) {
    key[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                        bob_blocks[i]);
  }

  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  emp::block ok = emp::CircuitExecution::circ_exec->public_label(true);
  emp::block *out = new emp::block[128 * n];

  for (unsigned blk = 0; blk < n; blk++) {
    const unsigned c = kOffCtr + 128 * blk;
    const unsigned p = kOffPt + 128 * blk;

    // Algorithm 1: "if IVc != IVv then return Error".
    ok = emp::CircuitExecution::circ_exec->and_gate(
        ok, equals<128>(alice_blocks + c, bob_blocks + c));

    emp::block ks[128];
    aes128_encrypt(bf, key, alice_blocks + c, ks);

    for (unsigned j = 0; j < 128; j++) {
      out[128 * blk + j] = emp::CircuitExecution::circ_exec->xor_gate(
          ks[j], alice_blocks[p + j]);
    }
  }

  // All-or-nothing, as in DeriveKeystreamBatch: a counter disagreement zeroes
  // the whole batch rather than emitting n-1 usable ciphertext blocks.
  for (unsigned i = 0; i < 128 * n; i++) {
    out[i] = emp::CircuitExecution::circ_exec->and_gate(out[i], ok);
  }

  emp::block ok_arr[8];
  std::fill(std::begin(ok_arr), std::end(ok_arr), ok);

  if constexpr (testing) {
    const auto revealed = print_hash_to_string<16>(out);

    // C_0 = AES(k, ctr_0) ^ M_0, with AES(k, ctr_0) the FIPS vector by
    // construction of kFipsKc / kFipsKv / kFipsPt above.
    std::array<unsigned char, 16> expected{};
    for (unsigned i = 0; i < 16; i++) {
      expected[i] = kFipsCt[i] ^ pt[i];
    }

    fprintf(stderr, "[aes_enc_test n=%u] got ", n);
    for (auto v : revealed) fprintf(stderr, "%02x", v);
    fprintf(stderr, "  want ");
    for (auto v : expected) fprintf(stderr, "%02x", v);
    fprintf(stderr, "\n");
    if (revealed != expected) {
      fprintf(stderr, "[aes_enc_test] FAILED: refusing to emit "
                      "aes_gcm_enc_batch_%u.txt\n", n);
      std::abort();
    }
  } else {
    bool *out_b = new bool[128 * n];
    bool ok_b[8];
    emp::ProtocolExecution::prot_exec->reveal(out_b, emp::PUBLIC, out, 128 * n);
    emp::ProtocolExecution::prot_exec->reveal(ok_b, emp::PUBLIC, ok_arr, 8);
    delete[] out_b;
  }

  delete[] out;
  delete[] bob_blocks;
  delete[] alice_blocks;
  delete[] bob_input;
  delete[] alice_input;
  emp::finalize_plain_prot();
}

static void DeriveAESJoint() noexcept {
  // This circuit accepts a 128 bit plaintext block, a 128 bit key share from
  // each party, and a 128 bit IV. Each party learns the full output. Note
  // that if the IVs do not match the output is all 0s. Also, only Alice
  // supplies an input plaintext e.g Bob's first 128 bits are unused.
  emp::setup_plain_prot(true, "aes_ctr_joint.txt");
  constexpr auto input_size = 384;
  std::array<bool, input_size> alice_in, bob_in;
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE,
                                          alice_in.data(), input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in.data(),
                                          input_size);

  // Recover the key.
  emp::block key_and_iv[256];
  for (unsigned i = 0; i < 128; i++) {
    key_and_iv[i] = emp::CircuitExecution::circ_exec->xor_gate(
        alice_blocks[i + 128], bob_blocks[i + 128]);
  }

  // For now just take Alice's IV.
  memcpy(key_and_iv + 128, alice_blocks + 256, sizeof(emp::block) * 128);
  // Run the encryption.
  emp::block output[128];
  assert(Util::is_valid_filepath(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt"));
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  bf.compute(output, key_and_iv, key_and_iv);

  // Now we need to check that the IVs were the same.
  emp::block were_ivs_same = equals<128>(alice_blocks + 256, bob_blocks + 256);

  emp::block mask[128];
  std::fill(std::begin(mask), std::end(mask), were_ivs_same);

  // Do the XOR with the plaintext.
  for (unsigned i = 0; i < 128; i++) {
    output[i] =
        emp::CircuitExecution::circ_exec->xor_gate(output[i], alice_blocks[i]);
  }

  // Mask out the output.
  for (unsigned i = 0; i < 128; i++) {
    output[i] = emp::CircuitExecution::circ_exec->and_gate(output[i], mask[i]);
  }

  // Now reveal if they cheated. Again, pad to a multiple of 8.
  bool were_sameb[8];
  bool ctxt[128];
  emp::ProtocolExecution::prot_exec->reveal(were_sameb, emp::PUBLIC, mask, 8);
  emp::ProtocolExecution::prot_exec->reveal(ctxt, emp::PUBLIC, output, 128);
  emp::finalize_plain_prot();
}

// SURF ROTATE: RFC 8446 7.2 key update, one direction per invocation.
// secret' = HKDF-Expand-Label(secret, "traffic upd", "", 32)
// key'    = HKDF-Expand-Label(secret', "key", "", 16)
// iv'     = HKDF-Expand-Label(secret', "iv",  "", 12)
static void DeriveRotateKey() {
  emp::setup_plain_prot(true, "derive_rotate_key.txt");
  constexpr unsigned kOffShare = 0, kOffSecretMask = 128, kOffKeyMask = 256;
  constexpr unsigned in_bits = 384;

  std::array<bool, in_bits> a_in, b_in;
  for (unsigned i = 0; i < in_bits; i++) {
    a_in[i] = rand();
    b_in[i] = rand();
  }
  emp::block a[in_bits], b[in_bits];
  emp::ProtocolExecution::prot_exec->feed(b, emp::BOB, b_in.data(), in_bits);
  emp::ProtocolExecution::prot_exec->feed(a, emp::ALICE, a_in.data(), in_bits);

  emp::block secret[256];
  memcpy(secret, a + kOffShare, sizeof(emp::block) * 128);
  memcpy(secret + 128, b + kOffShare, sizeof(emp::block) * 128);

  emp::block *empty_span = nullptr;
  emp::block next[256], key[128], iv[96];
  CircuitSynthesis::hkdf_expand_label(EmpBlockNonOwningSpan{secret, 256},
                                      "traffic upd",
                                      EmpBlockNonOwningSpan{empty_span, 0},
                                      next, 32);
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{next, 256},
      get_tag<TypeOfDerivation::SERVER_TRAFFIC_KEY>(),
      EmpBlockNonOwningSpan{empty_span, 0}, key, 16);
  CircuitSynthesis::hkdf_expand_label(
      EmpBlockNonOwningSpan{next, 256},
      get_tag<TypeOfDerivation::SERVER_TRAFFIC_IV>(),
      EmpBlockNonOwningSpan{empty_span, 0}, iv, 12);

  auto &ce = *emp::CircuitExecution::circ_exec;
  for (unsigned i = 0; i < 128; i++) {
    next[i] = ce.xor_gate(a[kOffSecretMask + i], next[i]);
    next[128 + i] = ce.xor_gate(b[kOffSecretMask + i], next[128 + i]);
    key[i] = ce.xor_gate(a[kOffKeyMask + i], key[i]);
  }

  bool out_bool[256 + 128 + 96];
  emp::ProtocolExecution::prot_exec->reveal(out_bool, emp::PUBLIC, next, 256);
  emp::ProtocolExecution::prot_exec->reveal(out_bool + 256, emp::PUBLIC, key, 128);
  emp::ProtocolExecution::prot_exec->reveal(out_bool + 384, emp::PUBLIC, iv, 96);
  emp::finalize_plain_prot();
}

static void TestAES128Full() {
  emp::setup_plain_prot(false, "aes_test.txt");
  // NIST FIPS-197 C.1: key 000102...0f, pt 00112233...ff
  //                    ct  69c4e0d86a7b0430d8cdb78070b4c55a
  std::array<unsigned char,16> key{}, pt{};
  for (unsigned i = 0; i < 16; i++) { key[i] = i; pt[i] = uint8_t(i*0x11); }
  auto kb = chars_to_bools<16>(key.data());
  auto pb = chars_to_bools<16>(pt.data());
  emp::block in[256];
  emp::ProtocolExecution::prot_exec->feed(in, emp::PUBLIC, kb.data(), 128);
  emp::ProtocolExecution::prot_exec->feed(in + 128, emp::PUBLIC, pb.data(), 128);
  emp::block out[128];
  emp::BristolFormat bf(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");
  bf.compute(out, in, in);
  const auto r = print_hash_to_string<16>(out);
  fprintf(stderr, "[aes_test] ");
  for (auto v : r) fprintf(stderr, "%02x", v);
  fprintf(stderr, "  (FIPS-197 expects 69c4e0d86a7b0430d8cdb78070b4c55a)\n");
  emp::finalize_plain_prot();
}

template <unsigned size> static void DeriveAESEnc() {
  // This function derives batched AES GCM encryptions
  // i.e it produces circuits for encrypting fixed size requests.
  // `size` inputs the number of AES-GCM blocks to encrypt. Each block is taken
  // to be 128 bits. Everything (including incrementing the IVs) is done
  // internally.
  emp::setup_plain_prot(true, "aes_ctr_batch_" + std::to_string(size) + ".txt");
  constexpr auto input_size = 256 + size * 128;
  std::array<bool, input_size> alice_in, bob_in;
  for (unsigned i = 0; i < input_size; i++) {
    alice_in[i] = rand();
    bob_in[i] = rand();
  }

  emp::block alice_blocks[input_size], bob_blocks[input_size];
  emp::ProtocolExecution::prot_exec->feed(alice_blocks, emp::ALICE,
                                          alice_in.data(), input_size);
  emp::ProtocolExecution::prot_exec->feed(bob_blocks, emp::BOB, bob_in.data(),
                                          input_size);

  // Check that the IVs were the same.
  // Now we need to check that the IVs were the same.
  emp::block were_ivs_same = equals<128>(alice_blocks + 128, bob_blocks + 128);

  // We'll recover the IV for later use. For now we'll just use Alice's.
  emp::block IV[128];
  memcpy(IV, alice_blocks + 128, sizeof(IV));

  // Recover the key.
  emp::block cipher_in[256];
  for (unsigned i = 0; i < 128; i++) {
    cipher_in[i] = emp::CircuitExecution::circ_exec->xor_gate(alice_blocks[i],
                                                              bob_blocks[i]);
  }

  emp::block cipher_out[128];

  // Load the circuit.
  assert(Util::is_valid_filepath(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt"));
  emp::BristolFormat aes(
      "../emp-tool/emp-tool/circuits/files/bristol_format/aes128_full.txt");

  assert(Util::is_valid_filepath("../2pc/vhdl/Inc128.txt"));
  emp::BristolFashion inc("../2pc/vhdl/Inc128.txt");

  bool were_same_b[8];
  emp::block same[8];
  std::fill(std::begin(same), std::end(same), were_ivs_same);
  emp::ProtocolExecution::prot_exec->reveal(were_same_b, emp::PUBLIC, same, 8);

  emp::block ctxt[128];
  bool *ctxt_out = new bool[size * 128];

  // Now do the encryption. Each encryption is done by first adding 1 to the IV
  // and then using that as input to the circuit.
  for (unsigned i = 0; i < size; i++) {
    inc.compute(cipher_in + 128, IV);
    memcpy(IV, cipher_in + 128, sizeof(IV));
    aes.compute(cipher_out, cipher_in, cipher_in);
    for (unsigned j = 0; j < 128; j++) {
      ctxt[j] = emp::CircuitExecution::circ_exec->xor_gate(
          cipher_out[j], alice_blocks[(i * 128) + j + 256]);
    }

    emp::ProtocolExecution::prot_exec->reveal(ctxt_out + 128 * i, emp::PUBLIC,
                                              ctxt, 128);
  }

  delete[] ctxt_out;
  emp::finalize_plain_prot();
}

// These functions are just to make calling the various templated functions
// easier.
static void DeriveHS256() { DeriveHS<256>(); }
static void DeriveHS384() { DeriveHS<384>(); }
static void DeriveHS521() { DeriveHS<521>(); }

static void DeriveCombined256() { ProduceCombinedCircuit<256>(); }
static void DeriveCombined384() { ProduceCombinedCircuit<384>(); }
static void DeriveCombinedTS() { ProduceCombinedTrafficCircuits(); }
static void DeriveCombinedRMS() { ProduceCombinedRMS(); }
static void DeriveCombinedPSK() {
  // 1-byte nonce: LiteSpeed/BoringSSL origins. 8-byte nonce: OpenSSL/nginx.
  ProduceCombinedPSK<0>("combined_psk_0.txt");
  ProduceCombinedPSK<1>("combined_psk.txt");
  ProduceCombinedPSK<8>("combined_psk_8.txt");
}

static void DeriveBinder() { ProduceBinderCircuit(); }

template <TypeOfDerivation mode>
static void dispatch_to_derive_session_secrets() {

  DeriveSessionSecrets<mode, true>();
  DeriveSessionSecrets<mode, false>();
}

static void DeriveCHTSATS() {
  dispatch_to_derive_session_secrets<TypeOfDerivation::CLIENT_HTS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::SERVER_HTS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::SATS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::CATS>();
  dispatch_to_derive_session_secrets<TypeOfDerivation::EMS>();
}

template <TypeOfDerivation mode> static void dispatch_to_derive_key_or_iv() {
  // We call the testing version of the function first: if it works, we call
  // the version that produces the actual results.
  DeriveIVOrKey<mode, true>();
  DeriveIVOrKey<mode, false>();
}

static void DeriveTrafficKeyAndIVs() {
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_HANDSHAKE_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_TRAFFIC_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_HANDSHAKE_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_TRAFFIC_IV>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_HANDSHAKE_KEY>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::CLIENT_TRAFFIC_KEY>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_HANDSHAKE_KEY>();
  dispatch_to_derive_key_or_iv<TypeOfDerivation::SERVER_TRAFFIC_KEY>();
}

static void DeriveMSAndDHS() {
  DeriveDHS<true>();
  DeriveDHS<false>();
  DeriveMS<true>();
  DeriveMS<false>();
}

static void DeriveRMSandPSK() {
  dispatch_to_derive_session_secrets<TypeOfDerivation::RMS>();
  DerivePSK<true>();
  DerivePSK<false>();
}

int main(int, char **) {
  TestAES128Full();
  DeriveHS256();
  DeriveHS384();
  DeriveHS521();
  DeriveCHTSATS();
  DeriveMSAndDHS();
  DeriveTrafficKeyAndIVs();
  DeriveRMSandPSK();
  DeriveAESEncryption();
  DeriveGCMMultiplicativeSharesNaive();
  DeriveAESEnc<16>();
  DeriveAESEnc<32>();
  DeriveAESEnc<64>();
  DeriveAESEnc<128>();
  DeriveRotateKey();
  DeriveCombined256();
  DeriveCombined384();
  DeriveCombinedTS();
  DeriveGCMMultiplicativeShares();
  DeriveCombinedRMS();
  DeriveCombinedPSK();
  DeriveBinder();
  DeriveCTXCommitments();
  DeriveAESJoint();
  DeriveGCMTag<true>();                   // tag circuit vs a host AES
  DeriveGCMTag();                         // emit derive_gcm_tag.txt
  DeriveGCMVerify();
  DeriveGCMVerifyCommit();
  //DeriveKeystream();
  DeriveKeystreamBatch<1, true>(false);   // digest gate accepts a real opening
  DeriveKeystreamBatch<1, true>(true);    // and rejects a corrupted one
  DeriveKeystreamBatch<1>();              // emit derive_keystream_batch_1.txt
  DeriveKeystreamBatch<16>();             // emit derive_keystream_batch_16.txt

  DeriveAESEncBatch<1, true>();           // encrypt circuit vs a host AES
  DeriveAESEncBatch<1>();                 // emit aes_gcm_enc_batch_1.txt
  DeriveAESEncBatch<2>();
  DeriveAESEncBatch<4>();
  DeriveAESEncBatch<16>();
}
