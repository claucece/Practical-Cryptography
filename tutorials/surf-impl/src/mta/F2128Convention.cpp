/*
  F2128Convention.cpp

  Single process. No SSL, no circuit, no preprocessing, no peer. Answers one
  question: which field convention does F2128_MTA::mul implement?

  Build alongside the other benches (it only needs F2128MtA.hpp + OpenSSL) and
  run with no arguments. Runtime is microseconds.

  Why this exists: every check run against the GCM tag path so far (key shares
  reconstruct, power_share agrees across parties, cheated==false) is invariant
  under a bit-reflection of the field representation, because they are all
  XOR/equality checks. Only a multiplication can see the difference, and the
  H-power derivation is the first multiplication in the pipeline. So the
  convention has never actually been tested.
*/

#include "F2128MtA.hpp"

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>

using Bytes = std::array<uint8_t, 16>;

static void print(const char *label, const Bytes &b) {
  std::printf("%-22s", label);
  for (auto v : b) std::printf("%02x", v);
  std::printf("\n");
}

static Bytes to_bytes(const emp::block b) { return F2128_MTA::block_to_arr(b); }
static emp::block to_block(const Bytes &b) { return F2128_MTA::arr_to_block(b); }

static bool eq(const Bytes &a, const Bytes &b) {
  return std::memcmp(a.data(), b.data(), 16) == 0;
}

// Reverse the order of all 128 bits: byte-reverse, and bit-reverse within each
// byte. This is the map between GHASH's representation (MSB of byte 0 is the
// x^0 coefficient) and the natural little-endian polynomial representation
// (bit i of the 128-bit integer is the x^i coefficient).
static Bytes reflect(const Bytes &in) {
  Bytes out{};
  for (unsigned i = 0; i < 16; i++) {
    uint8_t b = in[i], r = 0;
    for (unsigned j = 0; j < 8; j++) r = uint8_t(r | (((b >> j) & 1u) << (7 - j)));
    out[i] = r;   // bit-reverse in place; byte order preserved
  }
  return out;
}

// mul, but interpreting both operands as GHASH-order blocks.
static Bytes mul_gcm(const Bytes &a, const Bytes &b) {
  const auto prod = F2128_MTA::mul(to_block(reflect(a)), to_block(reflect(b)));
  return reflect(to_bytes(prod));
}

static Bytes mul_nat(const Bytes &a, const Bytes &b) {
  return to_bytes(F2128_MTA::mul(to_block(a), to_block(b)));
}

static Bytes random_bytes() {
  Bytes out{};
  // Deterministic so failures are reproducible; any fixed nonzero value works.
  static uint64_t s = 0x9e3779b97f4a7c15ull;
  for (auto &v : out) {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    v = uint8_t(s);
  }
  return out;
}

int main() {
  int failures = 0;
  const auto expect = [&](const char *name, bool cond) {
    std::printf("%-46s %s\n", name, cond ? "PASS" : "FAIL");
    if (!cond) failures++;
  };

  const Bytes a = random_bytes();
  const Bytes b = random_bytes();

  // The multiplicative identity, written in each convention.
  Bytes one_nat{}; one_nat[0] = 0x01;   // bit 0 of byte 0 == x^0
  Bytes one_gcm{}; one_gcm[0] = 0x80;   // bit 7 of byte 0 == x^0

  print("a", a);
  print("one_nat", one_nat);
  print("one_gcm", one_gcm);
  std::printf("\n");

  // ---- The discriminating test. Exactly one of these two should pass. ----
  const bool nat = eq(mul_nat(a, one_nat), a);
  const bool gcm = eq(mul_nat(a, one_gcm), a);

  print("mul(a, one_nat)", mul_nat(a, one_nat));
  print("mul(a, one_gcm)", mul_nat(a, one_gcm));
  std::printf("\n");

  expect("mul is NATURAL order (identity = 01 00 ..)", nat);
  expect("mul is GCM order      (identity = 80 00 ..)", gcm);

  if (nat == gcm) {
    std::printf("\n*** mul matched %s identity. Something is wrong with the\n"
                "    test or with mul itself; stop and read the reduction.\n",
                nat ? "BOTH" : "NEITHER");
    return 1;
  }

  std::printf("\n  => mul operates in %s order.\n",
              nat ? "NATURAL polynomial" : "GCM (reflected)");
  std::printf("  => arr_to_block performs no reflection, so any GCM-derived\n"
              "     value (H, H-powers, GHASH operands) handed to mul is %s.\n\n",
              nat ? "IN THE WRONG FIELD" : "correctly interpreted");

  // ---- Consistency checks, whichever convention won. ----
  const Bytes one = nat ? one_nat : one_gcm;
  const auto mul_ = nat ? mul_nat : mul_gcm;   // note: mul_gcm(x,y) here is the
                                               // reflected wrapper, which is
                                               // the identity map when mul is
                                               // already GCM order -- so this
                                               // stays meaningful either way.

  expect("commutative: a*b == b*a", eq(mul_(a, b), mul_(b, a)));
  expect("a * 1 == a", eq(mul_(a, one), a));

  // inv() is built from mul by exponentiation, so it inherits mul's convention.
  // It cannot disagree, but a failure here means inv's ladder is wrong.
  {
    const auto a_inv = to_bytes(F2128_MTA::inv(to_block(a)));
    print("inv(a)", a_inv);
    expect("a * inv(a) == 1 (natural order)",
           eq(mul_nat(a, a_inv), one_nat));
  }

  // Distributivity over XOR -- catches a broken carry-less reduction that
  // happens to fix the identity element.
  {
    const Bytes c = random_bytes();
    Bytes bc{}, lhs{}, rhs{};
    for (unsigned i = 0; i < 16; i++) bc[i] = uint8_t(b[i] ^ c[i]);
    lhs = mul_(a, bc);
    const auto ab = mul_(a, b), ac = mul_(a, c);
    for (unsigned i = 0; i < 16; i++) rhs[i] = uint8_t(ab[i] ^ ac[i]);
    expect("a*(b^c) == a*b ^ a*c", eq(lhs, rhs));
  }

  std::printf("\n%d failure(s)\n", failures);
  return failures == 0 ? 0 : 1;
}
