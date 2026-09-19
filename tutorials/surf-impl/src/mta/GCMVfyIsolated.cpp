/*
  GCMVfyIsolated.cpp

  Two processes, synthetic inputs, no TLS handshake, no records, no GHASH.
  Finds the byte-order packing the gcm_vfy circuit actually expects.

  Usage:
      ./GCMVfyIsolated -s
      ./GCMVfyIsolated --ip 127.0.0.1 -v <port>

  Why this works without any real crypto: the circuit checks

      AES(k_p ^ k_v, J0) ^ tag_share_p ^ tag_share_v == server_tag

  E2E has already proven this equation holds exactly on real data
  (AES(k,J0) ^ share_p ^ share_v reproduced server_tag bit for bit), so the
  maths is not in question -- only the packing is. We can therefore construct a
  satisfying instance from thin air: pick k_p, k_v, J0 and both tag shares
  freely, then DEFINE server_tag as whatever makes the equation true. Any
  correct packing must report tag_passed.

  The loop tries all 16 subsets of {key, iv, tag_share, server_tag} byte-
  reversal. Both parties apply the same subset, so `cheated` (which checks the
  two sides supplied matching iv and server_tag) should stay false throughout;
  if it does not, the equality gate reads different wires than assumed and that
  is itself the finding.

  Circuit lifetime: vfy_iters == 8, so ONE preprocessed circuit serves eight
  invocations. Rebuilding per iteration tears the channel down, so we rebuild
  only every eighth mask.

  NOTE the key shares are chosen so their XOR is NOT byte-palindromic. Earlier
  fixed vectors in this codebase XORed to 0f0f..0f, which is invariant under
  byte reversal and hid exactly this class of bug for several rounds.
*/

#include <getopt.h>

#include "../nodes/Server.hpp"
#include "../ssl/TestUtil.hpp"
#include "../ssl/EmpWrapperAG2PC.hpp"

#include <openssl/evp.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>

using Bytes = std::array<uint8_t, 16>;

static const Bytes kKeyP = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const Bytes kKeyV = {0x3c, 0x1e, 0x2d, 0x0f, 0x4b, 0x5a, 0x69, 0x78,
                            0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0x02};
// A plausible J0: 12-byte IV then counter 1.
static const Bytes kJ0 = {0x57, 0xc8, 0x23, 0xd6, 0x13, 0xb3, 0x10, 0xb8,
                          0xcf, 0x32, 0xb1, 0x2b, 0x00, 0x00, 0x00, 0x01};
static const Bytes kSharePr = {0x56, 0x82, 0x86, 0x84, 0x0d, 0xea, 0xf5, 0x81,
                               0x06, 0x55, 0xbb, 0xbf, 0xd7, 0x53, 0x64, 0x62};
static const Bytes kShareVf = {0xfc, 0x0b, 0x7d, 0x4d, 0x49, 0xde, 0x47, 0x9e,
                               0x51, 0x1e, 0xc8, 0x17, 0x1d, 0xd6, 0x46, 0x74};

// Set to 8 if a rebuild mid-run kills the channel: run once, then set
// kMaskBase to 8 and run again.
static constexpr unsigned kMaskBase = 8;
static constexpr unsigned kMaskCount = 16;
static constexpr unsigned kVfyIters = 8;

static Bytes xr(const Bytes &a, const Bytes &b) {
  Bytes o{};
  for (unsigned i = 0; i < 16; i++) o[i] = uint8_t(a[i] ^ b[i]);
  return o;
}

static Bytes rev(const Bytes &in) {
  Bytes o{};
  for (unsigned i = 0; i < 16; i++) o[i] = in[15 - i];
  return o;
}

static void print(const char *label, const Bytes &b) {
  std::fprintf(stderr, "  %-22s", label);
  for (auto v : b) std::fprintf(stderr, "%02x", v);
  std::fprintf(stderr, "\n");
}

static Bytes aes_ecb(const Bytes &key, const Bytes &in) {
  Bytes out{};
  bssl::ScopedEVP_CIPHER_CTX ctx;
  int outl = 0;
  if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(),
                          nullptr)) {
    std::abort();
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  EVP_EncryptUpdate(ctx.get(), out.data(), &outl, in.data(), 16);
  return out;
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
                         "[verifier] run: ./GCMVfyIsolated --ip %s -v %u\n",
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

  // Construct a satisfying instance.
  const Bytes K = xr(kKeyP, kKeyV);
  const Bytes ek = aes_ecb(K, kJ0);
  const Bytes server_tag = xr(xr(ek, kSharePr), kShareVf);

  std::fprintf(stderr, "\n=== %s ===\n",
               is_verifier ? "verifier/BOB" : "prover/ALICE");
  print("k_p ^ k_v", K);
  print("J0", kJ0);
  print("AES(K,J0)", ek);
  print("share_p", kSharePr);
  print("share_v", kShareVf);
  print("server_tag (derived)", server_tag);
  std::fprintf(stderr, "  (AES ^ share_p ^ share_v == server_tag by "
                       "construction)\n\n");

  const Bytes my_key = is_verifier ? kKeyV : kKeyP;
  const Bytes my_share = is_verifier ? kShareVf : kSharePr;

  static const char *names[4] = {"key", "iv", "tag_share", "server_tag"};

  EmpWrapperAG2PC *c = nullptr;
  unsigned used = 0;

  for (unsigned n = 0; n < kMaskCount; n++) {
    const unsigned mask = kMaskBase + n;
    if (mask >= 16) break;

    // One preprocessed circuit covers vfy_iters invocations. Rebuilding on
    // every iteration tears the channel down, so only rebuild when spent.
    if (c == nullptr || used == kVfyIters) {
      delete c;
      used = 0;
      c = EmpWrapperAG2PC::build_gcm_vfy_circuit(
          chan, role, EmpWrapperAG2PCConstants::GCM_VFY_CIRCUIT_TAG);
      if (!c) {
        std::fprintf(stderr, "build failed at mask %u\n", mask);
        return 1;
      }
      c->do_preproc();
      if (c->has_io_failed()) {
        std::fprintf(stderr, "preproc failed at mask %u\n", mask);
        return 1;
      }
    }

    const auto pick = [&](unsigned bit, const Bytes &v) {
      return (mask & (1u << bit)) ? rev(v) : v;
    };

    EmpWrapperAG2PC::aes_gcm_vfy_input_type input{};
    unsigned pos = 0;
    const auto put = [&](const Bytes &b) {
      std::copy(b.cbegin(), b.cend(), input.begin() + pos);
      pos += 16;
    };
    put(pick(0, my_key));
    put(pick(1, kJ0));
    put(pick(2, my_share));
    put(pick(3, server_tag));

    EmpWrapperAG2PC::aes_gcm_vfy_output_type output{};
    const bool ran = c->verify_tag(input, output);
    used++;

    char label[96] = "";
    for (unsigned b = 0; b < 4; b++) {
      if (mask & (1u << b)) {
        std::strcat(label, names[b]);
        std::strcat(label, " ");
      }
    }
    if (label[0] == '\0') std::strcpy(label, "(none)");

    if (!ran) {
      std::fprintf(stderr, "  mask %2u  reversed: %-34s verify_tag FAILED (io)\n",
                   mask, label);
      continue;
    }

    const bool ok0 = (output[0] == 0x00 || output[0] == 0xFF);
    const bool ok1 = (output[1] == 0x00 || output[1] == 0xFF);
    const bool passed = ok0 && output[0] != 0;
    const bool cheated = ok1 && output[1] == 0;

    std::fprintf(stderr,
                 "  mask %2u  reversed: %-34s tag_passed=%d cheated=%d%s%s\n",
                 mask, label, passed, cheated,
                 (ok0 && ok1) ? "" : "  [MALFORMED OUTPUT]",
                 (passed && !cheated) ? "   <== THIS ONE" : "");
  }

  delete c;

  std::fprintf(stderr,
               "\nIf exactly one row says THIS ONE, that is the packing\n"
               "run_gcm_vfy_circuit must use. If none do, the circuit is not\n"
               "checking the equation we assume -- read DeriveGCMVerify in\n"
               "DeriveCircuits.cpp for the actual input wire order.\n"
               "If the run dies at mask 8, set kMaskBase = 8 and re-run to\n"
               "cover the second half.\n");
  return 0;
}
