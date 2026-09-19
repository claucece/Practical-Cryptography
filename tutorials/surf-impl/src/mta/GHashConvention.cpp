/*
  GHashConvention.cpp

  Single process. No SSL, no circuit, no peer, no preprocessing. Runs in
  milliseconds.

  Question: does GHash::share compute the GHASH polynomial in the right field,
  and does it hand back a value in the representation gcm_vfy_circuit expects?

  Context. The isolated GCM-share test established that the share circuit emits
      P = bitrev(H) * m_bob ^ m_alice
  and that the MtA reconstructs bitrev(H), where bitrev reverses the bits within
  each byte (byte order preserved). That map is exactly the isomorphism between
  GHASH's representation (MSB of byte 0 == x^0) and the one F2128_MTA::mul
  implements (LSB of byte 0 == x^0): bitrev(A)*bitrev(B) == bitrev(ghash_mul(A,B)).

  So ssl->sgcm_share holds powers of h = bitrev(H) in NATURAL order. Two
  conversions therefore have to happen somewhere:

    in   - the AAD/ciphertext blocks and the length block are raw GCM-order
           bytes and must be bitrev'd before being multiplied by those powers;
    out  - the resulting tag_share is in natural order, but gcm_vfy_circuit
           XORs it into AES(k,J0) and compares against rec.tag, which is raw
           GCM order, so it must be bitrev'd back.

  A missing conversion at either end gives exactly the observed symptom: key
  shares fine, IV gate fine, cheated==false, tag_passed==false.

  This test computes the true GHASH value from a known-good OpenSSL AES-GCM
  vector (G = tag ^ AES(K,J0)) and checks GHash::share's output against every
  combination of {correct powers, wrong-field powers} x {natural out, GCM out}.
  Exactly one should match if GHash::share is otherwise correct. If none do,
  the bug is inside GHash::share itself -- block ordering, padding of the
  partial final block, or the length block.
*/

#include "../ssl/GHash.hpp"
#include "../ssl/EmpWrapperAG2PC.hpp"
#include "../mta/F2128MtA.hpp"

#include <openssl/evp.h>
#include <openssl/span.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

using Bytes = std::array<uint8_t, 16>;

static void print(const char *label, const Bytes &b) {
  std::printf("  %-30s", label);
  for (auto v : b) std::printf("%02x", v);
  std::printf("\n");
}

static bool eq(const Bytes &a, const Bytes &b) {
  return std::memcmp(a.data(), b.data(), 16) == 0;
}
static Bytes xr(const Bytes &a, const Bytes &b) {
  Bytes o{};
  for (unsigned i = 0; i < 16; i++) o[i] = uint8_t(a[i] ^ b[i]);
  return o;
}

// Bit-reverse within each byte; byte order preserved. GHASH repr <-> natural.
static Bytes bitrev(const Bytes &in) {
  Bytes out{};
  for (unsigned i = 0; i < 16; i++) {
    uint8_t b = in[i], r = 0;
    for (unsigned j = 0; j < 8; j++) r = uint8_t(r | (((b >> j) & 1u) << (7 - j)));
    out[i] = r;
  }
  return out;
}

static Bytes to_bytes(const emp::block b) { return F2128_MTA::block_to_arr(b); }
static emp::block to_block(const Bytes &b) { return F2128_MTA::arr_to_block(b); }

// ---------------------------------------------------------------------------
// Fixed vector. AAD is 5 bytes (a TLS 1.3 record header) and the plaintext is
// deliberately NOT a multiple of 16, so the partial-block zero padding and the
// length block are both exercised.
// ---------------------------------------------------------------------------
static const Bytes kKey = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t kIV[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
static const uint8_t kAAD[5] = {0x17, 0x03, 0x03, 0x00, 0x2b};

static Bytes aes_ecb(const Bytes &key, const uint8_t in[16]) {
  Bytes out{};
  bssl::ScopedEVP_CIPHER_CTX ctx;
  int outl = 0;
  if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(),
                          nullptr)) {
    std::abort();
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  EVP_EncryptUpdate(ctx.get(), out.data(), &outl, in, 16);
  return out;
}

int main() {
  // ---- 1. Produce a known-good ciphertext + tag with OpenSSL. ----
  std::vector<uint8_t> pt(37);
  for (size_t i = 0; i < pt.size(); i++) pt[i] = uint8_t(i * 7 + 1);
  std::vector<uint8_t> ct(pt.size());
  Bytes tag{};

  {
    bssl::ScopedEVP_CIPHER_CTX ctx;
    int outl = 0, tmp = 0;
    if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) ||
        !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) ||
        !EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, kKey.data(), kIV) ||
        !EVP_EncryptUpdate(ctx.get(), nullptr, &outl, kAAD, int(sizeof(kAAD))) ||
        !EVP_EncryptUpdate(ctx.get(), ct.data(), &outl, pt.data(), int(pt.size())) ||
        !EVP_EncryptFinal_ex(ctx.get(), ct.data() + outl, &tmp) ||
        !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
      std::printf("openssl gcm failed\n");
      return 1;
    }
  }

  // ---- 2. Recover the pure GHASH value: G = tag ^ AES(K, J0). ----
  uint8_t j0[16] = {0};
  std::memcpy(j0, kIV, 12);
  j0[15] = 1;
  const Bytes ek_j0 = aes_ecb(kKey, j0);
  const Bytes G = xr(tag, ek_j0);

  uint8_t zero[16] = {0};
  const Bytes H = aes_ecb(kKey, zero);

  std::printf("vector: aad=%zu bytes, ct=%zu bytes\n", sizeof(kAAD), ct.size());
  print("H = AES(K,0)", H);
  print("bitrev(H)", bitrev(H));
  print("tag", tag);
  print("AES(K,J0)", ek_j0);
  print("G = GHASH(A,C)", G);
  print("bitrev(G)", bitrev(G));
  std::printf("\n");

  // ---- 3. Build both candidate power tables. ----
  // powers[i] holds h^(i+1)  (see generate_shares_batched: "the element at 0 is
  // actually a share of h^1").
  using Bulk = EmpWrapperAG2PCConstants::AESGCMBulkShareType;
  constexpr unsigned kNPow = unsigned(sizeof(F2128_MTA::ShareType) / sizeof(emp::block));

  const auto build = [&](const Bytes &h) {
    F2128_MTA::ShareType s{};
    emp::block cur = to_block(h);
    const emp::block base = cur;
    for (unsigned i = 0; i < kNPow; i++) {
      s[i] = cur;
      cur = F2128_MTA::mul(cur, base);
    }
    return s;
  };

  struct Variant { const char *name; F2128_MTA::ShareType powers; };
  std::vector<Variant> variants;
  variants.push_back({"powers of bitrev(H)  [correct]", build(bitrev(H))});
  variants.push_back({"powers of raw H      [wrong field]", build(H)});

  // ---- 4. Run GHash::share, split additively, and compare. ----
  const auto aad_span = bssl::MakeConstSpan(kAAD, sizeof(kAAD));
  const auto ct_span = bssl::MakeConstSpan(ct.data(), ct.size());

  int matches = 0;
  for (auto &v : variants) {
    // Additive split of the power table, mirroring the real protocol. This also
    // tests that GHash::share is linear in the powers -- if it is not, the two
    // halves will not recombine and every comparison below fails.
    F2128_MTA::ShareType pa{}, pb{};
    for (unsigned i = 0; i < kNPow; i++) {
      Bytes r{};
      Util::generate_random_bytes<16>(r.data());
      pa[i] = to_block(r);
      pb[i] = F2128_MTA::mul(emp::zero_block, emp::zero_block); // placeholder
      pb[i] = to_block(xr(r, to_bytes(v.powers[i])));
    }

    Bulk ba{}, bb{}, bfull{};
    std::memcpy(ba.data(), pa.data(), sizeof(pa));
    std::memcpy(bb.data(), pb.data(), sizeof(pb));
    std::memcpy(bfull.data(), v.powers.data(), sizeof(v.powers));

    Bytes sa{}, sb{}, sfull{};
    if (!GHash::share(ba, aad_span, ct_span, sa) ||
        !GHash::share(bb, aad_span, ct_span, sb) ||
        !GHash::share(bfull, aad_span, ct_span, sfull)) {
      std::printf("GHash::share failed for %s\n", v.name);
      continue;
    }

    const Bytes combined = xr(sa, sb);
    std::printf("[%s]\n", v.name);
    print("share(full)", sfull);
    print("share(a) ^ share(b)", combined);
    std::printf("  %-30s %s\n", "linear in powers?",
                eq(combined, sfull) ? "YES" : "NO  <-- not a linear function");

    const struct { const char *n; Bytes val; } checks[] = {
        {"== G            (GCM order)", G},
        {"== bitrev(G)    (natural)", bitrev(G)},
    };
    for (const auto &c : checks) {
      const bool hit = eq(sfull, c.val);
      std::printf("  %-30s %s\n", c.n, hit ? "MATCH" : "");
      if (hit) matches++;
    }
    std::printf("\n");
  }

  if (matches == 0) {
    std::printf("No combination matched.\n"
                "  => the bug is inside GHash::share, not the representation:\n"
                "     check block order (h^n for the FIRST block), zero-padding\n"
                "     of the partial final block, and the length block\n"
                "     u64be(bitlen(A)) || u64be(bitlen(C)).\n");
    return 1;
  }
  std::printf("%d match(es). The matching row names the convention GHash::share\n"
              "actually uses; tag_share must reach gcm_vfy_circuit in GCM order.\n",
              matches);
  return 0;
}
