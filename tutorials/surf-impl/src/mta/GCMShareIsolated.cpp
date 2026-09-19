/*
  GCMShareIsolated.cpp

  Two processes, fixed key shares, no TLS handshake with an origin, no
  keystream, no record capture. Runs exactly the gcm share circuit and the MtA,
  and checks each layer separately.

  Usage:
      ./GCMShareIsolated -s                  # verifier / BOB, prints the port
      ./GCMShareIsolated --ip 127.0.0.1 -v <port>

  Both key shares are compile-time constants, so BOTH sides can compute
  H = AES.Enc(k_c ^ k_v, 0) locally and check the circuit's output against
  candidate relations directly.

  Established by this harness plus E2E instrumentation:
    - the circuit computes  bitrev(H) * m_bob ^ m_alice
      where bitrev reverses bits within each byte (byte order preserved), which
      is the isomorphism between GHASH's representation and the one
      F2128_MTA::mul implements;
    - the circuit takes its AES key LITTLE-ENDIAN, so run_gcm_share_circuit
      must byte-reverse key_share on the way in (cf. BN_bn2le_padded in
      run_handshake_circuit_internal);
    - make_gcm_share's XOR-strip of m_alice is correct;
    - the MtA is correct in natural order.

  Layers:
    L1  What does the circuit compute? Enumerate candidate relations.
    L2  Is the MtA correct in isolation? Random inputs, outputs XOR to product.
    L3  Does the composition reconstruct bitrev(H)?

  NOTE the key constants are deliberately chosen so k_c ^ k_v is NOT
  byte-palindromic. An earlier version used values XORing to 0f0f..0f, which is
  invariant under byte reversal and hid the little-endian key bug for several
  rounds of testing. Any fixed vector in this codebase should be asymmetric.
*/

#include <getopt.h>

#include "../nodes/Server.hpp"
#include "../ssl/TestUtil.hpp"
#include "../ssl/EmpWrapperAG2PC.hpp"
#include "../mta/F2128MtA.hpp"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>

using Bytes = std::array<uint8_t, 16>;

// XOR is 3c0f0f3c0f0f0f0f0f0f0f0f0f0f0ffd -- not a byte palindrome.
static constexpr Bytes kProverKeyShare = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static constexpr Bytes kVerifierKeyShare = {
    0x3c, 0x1e, 0x2d, 0x0f, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0x02};

// Set true to reproduce the E2E environment: preprocess and execute other
// circuits on the same channel before touching the gcm circuit. Both were
// tested and found innocent, so this defaults off to keep runs fast.
static constexpr bool kReproduceE2EContext = false;

static void print(const char *label, const Bytes &b) {
  std::fprintf(stderr, "  %-26s", label);
  for (auto v : b) std::fprintf(stderr, "%02x", v);
  std::fprintf(stderr, "\n");
}

static bool eq(const Bytes &a, const Bytes &b) {
  return std::memcmp(a.data(), b.data(), 16) == 0;
}

static Bytes xr(const Bytes &a, const Bytes &b) {
  Bytes o{};
  for (unsigned i = 0; i < 16; i++) o[i] = uint8_t(a[i] ^ b[i]);
  return o;
}

static Bytes to_bytes(const emp::block b) { return F2128_MTA::block_to_arr(b); }
static emp::block to_block(const Bytes &b) { return F2128_MTA::arr_to_block(b); }

// Bit-reverse within each byte; byte order preserved. This is the GHASH <->
// natural representation map: mul(bitrev(A), bitrev(B)) == bitrev(ghash(A,B)).
static Bytes reflect(const Bytes &in) {
  Bytes out{};
  for (unsigned i = 0; i < 16; i++) {
    uint8_t b = in[i], r = 0;
    for (unsigned j = 0; j < 8; j++) r = uint8_t(r | (((b >> j) & 1u) << (7 - j)));
    out[i] = r;
  }
  return out;
}

static Bytes mul_nat(const Bytes &a, const Bytes &b) {
  return to_bytes(F2128_MTA::mul(to_block(a), to_block(b)));
}

static Bytes mul_gcm(const Bytes &a, const Bytes &b) {
  return reflect(to_bytes(
      F2128_MTA::mul(to_block(reflect(a)), to_block(reflect(b)))));
}

static Bytes aes_zero(const Bytes &k) {
  Bytes out{};
  bssl::ScopedEVP_CIPHER_CTX ctx;
  uint8_t zero[16] = {0};
  int outl = 0;
  if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, k.data(),
                          nullptr)) {
    std::abort();
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  EVP_EncryptUpdate(ctx.get(), out.data(), &outl, zero, 16);
  return out;
}

// Mirrors run_gcm_share_circuit in ThreePartyHandshake.cc, INCLUDING the
// little-endian key conversion. Layout: key (16, byte-reversed) || mask (16).
static bool run_share_circuit(const Bytes &key_share, const Bytes &mask,
                              Bytes &power_share, EmpWrapperAG2PC *circuit) {
  EmpWrapperAG2PC::derive_gcm_input_type arr{};
  for (unsigned i = 0; i < 16; i++) arr[i] = key_share[15 - i];
  std::memcpy(arr.data() + 16, mask.data(), 16);
  return circuit->derive_gcm_shares(arr, power_share);
}

static bool exchange(SSL *ssl, bool i_write_first, const Bytes &mine,
                     Bytes &theirs) {
  if (i_write_first) {
    if (SSL_write(ssl, mine.data(), 16) != 16) return false;
    return SSL_read(ssl, theirs.data(), 16) == 16;
  }
  if (SSL_read(ssl, theirs.data(), 16) != 16) return false;
  return SSL_write(ssl, mine.data(), 16) == 16;
}

static void identify_circuit_relation(const Bytes &P, const Bytes &H,
                                      const Bytes &m_alice,
                                      const Bytes &m_bob) {
  const Bytes m_xor = xr(m_alice, m_bob);
  bool any = false;

  struct Cand { const char *name; Bytes value; };
  const Cand cands[] = {
      {"bitrev(H) * m_b ^ m_a  [TRUE]", xr(mul_nat(reflect(H), m_bob), m_alice)},
      {"H * (m_a ^ m_b)        [nat]", mul_nat(H, m_xor)},
      {"H * (m_a ^ m_b)        [gcm]", mul_gcm(H, m_xor)},
      {"H * m_b                [nat]", mul_nat(H, m_bob)},
      {"H * m_b                [gcm]", mul_gcm(H, m_bob)},
      {"H * m_a                [nat]", mul_nat(H, m_alice)},
      {"H * m_b ^ m_a          [nat]", xr(mul_nat(H, m_bob), m_alice)},
      {"H * m_b ^ m_a          [gcm]", xr(mul_gcm(H, m_bob), m_alice)},
      {"H * m_a ^ m_b          [nat]", xr(mul_nat(H, m_alice), m_bob)},
      {"H * (m_a^m_b) ^ m_a    [nat]", xr(mul_nat(H, m_xor), m_alice)},
  };

  std::fprintf(stderr, "\n[L1] what does the circuit compute?\n");
  for (const auto &c : cands) {
    const bool hit = eq(P, c.value);
    std::fprintf(stderr, "  %-32s %s\n", c.name, hit ? "<== MATCH" : "");
    if (hit) any = true;
  }
  if (!any) {
    std::fprintf(stderr,
                 "  no candidate matched. Check run_share_circuit's key\n"
                 "  byte-order conversion, and remember that palindromic test\n"
                 "  constants hide byte-order bugs.\n");
  }
}

int main(int argc, char *argv[]) {
  bool is_verifier = false;
  std::string ip = "127.0.0.1";
  uint16_t port{};

  const char *const short_opts = "sa:v:";
  const option long_opts[] = {{"is_server", no_argument, nullptr, 's'},
                              {"ip", required_argument, nullptr, 'a'},
                              {"port", required_argument, nullptr, 'v'},
                              {nullptr, 0, nullptr, 0}};
  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) break;
    switch (opt) {
      case 's': is_verifier = true; break;
      case 'a': ip = std::string(optarg); break;
      case 'v': port = uint16_t(std::stoi(optarg)); break;
      default: break;
    }
  }

  SSL *chan = nullptr;
  auto prover_ctx = CreateContextWithTestCertificate(TLS_method());
  Server verifier_side(CreateContextWithTestCertificate(TLS_method()),
                       ip.c_str(), false, 1);
  TLSSocket prover_side(prover_ctx.get(), false);

  if (is_verifier) {
    verifier_side.get_portnumber(&port);
    std::fprintf(stderr, "[verifier] listening on %s:%u\n"
                         "[verifier] run: ./GCMShareIsolated --ip %s -v %u\n",
                 ip.c_str(), port, ip.c_str(), port);
    if (!verifier_side.accept() || !verifier_side.do_handshake()) {
      std::fprintf(stderr, "[verifier] accept/handshake failed\n");
      return 1;
    }
    chan = verifier_side.get_ssl();
  } else {
    prover_side.set_ip_v4();
    if (!prover_side.connect_to(ip, port)) {
      std::fprintf(stderr, "[prover] connect failed\n");
      return 1;
    }
    chan = prover_side.get_ssl_object();
  }

  const auto role = is_verifier ? emp::BOB : emp::ALICE;
  const char *who = is_verifier ? "verifier/BOB" : "prover/ALICE";
  const Bytes my_key = is_verifier ? kVerifierKeyShare : kProverKeyShare;
  const Bytes H = aes_zero(xr(kProverKeyShare, kVerifierKeyShare));

  std::fprintf(stderr, "\n=== %s ===\n", who);
  print("k_c ^ k_v", xr(kProverKeyShare, kVerifierKeyShare));
  print("H = AES(k,0)", H);
  print("bitrev(H) [expected L3]", reflect(H));

  EmpWrapperAG2PC *pre[3] = {nullptr, nullptr, nullptr};
  if (kReproduceE2EContext) {
    pre[0] = EmpWrapperAG2PC::build_derive_hs_circuit(
        chan, SSL_CURVE_SECP256R1, role,
        EmpWrapperAG2PCConstants::HANDSHAKE_CIRCUIT_TAG_A);
    pre[1] = EmpWrapperAG2PC::build_derive_ts_circuit(
        chan, role, EmpWrapperAG2PCConstants::TRAFFIC_CIRCUIT_TAG);
    pre[2] = EmpWrapperAG2PC::build_joint_aes_circuit(
        chan, role, EmpWrapperAG2PCConstants::AES_JOINT_CIRCUIT_TAG);
    for (auto *c : pre) {
      if (!c) { std::fprintf(stderr, "pre-build failed\n"); return 1; }
      c->do_preproc();
      if (c->has_io_failed()) { std::fprintf(stderr, "pre-preproc failed\n"); return 1; }
    }
    std::array<uint8_t, EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE> hi{};
    std::array<uint8_t, EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE> ho{};
    if (!pre[0]->derive_hs(hi, ho)) { std::fprintf(stderr, "derive_hs failed\n"); return 1; }
    EmpWrapperAG2PCConstants::derive_ts_input_type ti{};
    EmpWrapperAG2PCConstants::derive_ts_output_type to{};
    if (!pre[1]->derive_ts(ti, to)) { std::fprintf(stderr, "derive_ts failed\n"); return 1; }
  }

  // gcm_iters == 2, so one preprocessed circuit covers two invocations.
  EmpWrapperAG2PC *circuit = EmpWrapperAG2PC::build_gcm_circuit(
      chan, role, EmpWrapperAG2PCConstants::GCM_CIRCUIT_TAG);
  if (!circuit) {
    std::fprintf(stderr, "build_gcm_circuit failed\n");
    return 1;
  }
  circuit->do_preproc();
  if (circuit->has_io_failed()) {
    std::fprintf(stderr, "do_preproc failed\n");
    return 1;
  }

  // ---- L1: identify the relation (invocation 1 of 2) ----
  {
    Bytes my_mask{};
    Util::generate_random_bytes<16>(my_mask.data());

    Bytes P{};
    if (!run_share_circuit(my_key, my_mask, P, circuit)) {
      std::fprintf(stderr, "derive_gcm_shares failed\n");
      return 1;
    }

    Bytes their_mask{};
    if (!exchange(chan, !is_verifier, my_mask, their_mask)) {
      std::fprintf(stderr, "mask exchange failed\n");
      return 1;
    }
    const Bytes m_alice = is_verifier ? their_mask : my_mask;
    const Bytes m_bob   = is_verifier ? my_mask : their_mask;

    print("m_alice", m_alice);
    print("m_bob", m_bob);
    print("power_share", P);
    identify_circuit_relation(P, H, m_alice, m_bob);
  }

  // ---- L2: MtA alone, no GCM semantics ----
  {
    std::fprintf(stderr, "\n[L2] MtA on random inputs\n");
    Bytes mine{};
    Util::generate_random_bytes<16>(mine.data());

    uint64_t bw = 0;
    const auto share = is_verifier
        ? F2128_MTA::generate_shares_verifier_batched(*chan, to_block(mine), bw)
        : F2128_MTA::generate_shares_prover_batched(*chan, to_block(mine), bw);

    const Bytes my_out = to_bytes(share[0]);
    Bytes their_in{}, their_out{};
    if (!exchange(chan, !is_verifier, mine, their_in) ||
        !exchange(chan, !is_verifier, my_out, their_out)) {
      std::fprintf(stderr, "L2 exchange failed\n");
      return 1;
    }

    const Bytes recon = xr(my_out, their_out);
    print("share_mine ^ share_theirs", recon);
    print("mul(in_p, in_v) [nat]", mul_nat(mine, their_in));
    std::fprintf(stderr, "  MtA correct [nat]: %s\n",
                 eq(recon, mul_nat(mine, their_in)) ? "YES" : "NO");
  }

  // ---- L3: composition, as make_gcm_share performs it (invocation 2 of 2) ----
  {
    std::fprintf(stderr, "\n[L3] composition -> is the result bitrev(H)?\n");
    Bytes my_mask{};
    Util::generate_random_bytes<16>(my_mask.data());

    Bytes P{};
    if (!run_share_circuit(my_key, my_mask, P, circuit)) {
      std::fprintf(stderr, "derive_gcm_shares failed\n");
      return 1;
    }

    // ALICE XOR-strips its own mask; BOB inverts its own.
    const emp::block input =
        is_verifier ? F2128_MTA::inv(to_block(my_mask))
                    : to_block(xr(P, my_mask));

    uint64_t bw = 0;
    const auto share = is_verifier
        ? F2128_MTA::generate_shares_verifier_batched(*chan, input, bw)
        : F2128_MTA::generate_shares_prover_batched(*chan, input, bw);

    const Bytes my_out = to_bytes(share[0]);
    Bytes their_out{};
    if (!exchange(chan, !is_verifier, my_out, their_out)) {
      std::fprintf(stderr, "L3 exchange failed\n");
      return 1;
    }

    const Bytes recon = xr(my_out, their_out);
    const Bytes want = reflect(H);
    print("XOR", recon);
    print("expected bitrev(H)", want);
    std::fprintf(stderr, "  L3 %s\n", eq(recon, want) ? "PASS" : "FAIL");
  }

  delete circuit;
  for (auto *c : pre) delete c;
  return 0;
}
