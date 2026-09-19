#ifndef INCLUDED_GHASH_HPP
#define INCLUDED_GHASH_HPP

#include "../mta/F2128MtA.hpp"
#include "EmpWrapperAG2PC.hpp"
#include <algorithm>
#include <array>
#include <cstring>

/**
   GHash. Local evaluation of the GHASH polynomial from a party's additive
   shares of the H-powers.

   GHASH is Sigma_j B_j * H^(n-j+1) over GF(2^128), where B_1..B_n are the AAD
   blocks, then the ciphertext blocks, then the length block, each zero-padded
   on the right to 16 bytes. It is *linear* in the powers, so each party
   evaluates the same public polynomial against its own share vector and the two
   results XOR to the true GHASH. No interaction and no circuit is needed: that
   locality is the whole point of deriving the powers via MtA.
**/
namespace GHash {
namespace detail {
// GHASH numbers bits with the MSB of byte 0 as x^0; F2128_MTA::mul numbers them
// with the LSB of byte 0 as x^0. Reversing the bits within each byte (byte order
// preserved) is the isomorphism between the two:
//     mul(bitrev(A), bitrev(B)) == bitrev(ghash_mul(A, B)).
// The H-powers arrive here already in natural order: the share circuit emits
// bitrev(H) * m_bob ^ m_alice, so the MtA reconstructs bitrev(H) and the ladder
// squares/multiplies it under mul. The raw GCM-order bytes crossing this
// boundary (the AAD, ciphertext and length blocks in, the tag share out)
// are the values that need converting.
inline std::array<uint8_t, 16>
bitrev(const std::array<uint8_t, 16> &in) noexcept {
  std::array<uint8_t, 16> o{};
  for (unsigned i = 0; i < 16; i++) {
    uint8_t b = in[i], r = 0;
    for (unsigned j = 0; j < 8; j++)
      r = static_cast<uint8_t>(r | (((b >> j) & 1u) << (7 - j)));
    o[i] = r;
  }
  return o;
}
}

/**
   share. Computes this party's share of P_{A||C||len(A)||len(C)}({h^i}).

   |powers| is indexed from zero: powers[i] is a share of H^(i+1) (see the
   do_batched_ot test in F2128MtA.t.cpp). Block j of n therefore pairs with
   powers[n-j], NOT powers[j] — walking forward silently produces garbage.

   @param[in] powers: this party's additive shares of H^1..H^1024.
   @param[in] aad: the additional authenticated data (the record header).
   @param[in] ciphertext: the record ciphertext, tag excluded.
   @param[out] out: this party's GHASH share.
   @return false if the input needs more than 1024 powers, true otherwise.
**/
inline bool
share(const EmpWrapperAG2PCConstants::AESGCMBulkShareType &powers,
      bssl::Span<const uint8_t> aad, bssl::Span<const uint8_t> ciphertext,
      std::array<uint8_t, 16> &out) noexcept {

  const size_t aad_blocks = (aad.size() + 15) / 16;
  const size_t ct_blocks = (ciphertext.size() + 15) / 16;
  const size_t n = aad_blocks + ct_blocks + 1;   // +1 for the length block

  constexpr size_t kMaxPowers =
      sizeof(EmpWrapperAG2PCConstants::AESGCMBulkShareType) / 16;
  if (n > kMaxPowers) {
    return false;
  }

  // Fetches block j (1-based) of the A || C || len concatenation.
  const auto block_at = [&](size_t j) -> std::array<uint8_t, 16> {
    std::array<uint8_t, 16> b{};
    if (j <= aad_blocks) {
      const size_t off = (j - 1) * 16;
      const size_t len = std::min<size_t>(16, aad.size() - off);
      memcpy(b.data(), aad.data() + off, len);
    } else if (j <= aad_blocks + ct_blocks) {
      const size_t off = (j - aad_blocks - 1) * 16;
      const size_t len = std::min<size_t>(16, ciphertext.size() - off);
      memcpy(b.data(), ciphertext.data() + off, len);
    } else {
      // len(A) || len(C), each a 64-bit big-endian *bit* count.
      const uint64_t abits = static_cast<uint64_t>(aad.size()) * 8;
      const uint64_t cbits = static_cast<uint64_t>(ciphertext.size()) * 8;
      for (unsigned i = 0; i < 8; i++) {
        b[i]     = static_cast<uint8_t>(abits >> (56 - 8 * i));
        b[8 + i] = static_cast<uint8_t>(cbits >> (56 - 8 * i));
      }
    }
    return b;
  };

  emp::block acc = emp::zero_block;
  for (size_t j = 1; j <= n; j++) {
    const auto b = block_at(j);
    std::array<uint8_t, 16> power_bytes;
    memcpy(power_bytes.data(), powers.data() + (n - j) * 16, 16);
    acc ^= F2128_MTA::mul(F2128_MTA::arr_to_block(detail::bitrev(b)),
                          F2128_MTA::arr_to_block(power_bytes));
  }

  out = detail::bitrev(F2128_MTA::block_to_arr(acc));
  return true;
}

} // namespace GHash

#endif
