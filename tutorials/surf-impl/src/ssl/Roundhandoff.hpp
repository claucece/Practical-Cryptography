#ifndef INCLUDED_ROUNDHANDOFF_HPP
#define INCLUDED_ROUNDHANDOFF_HPP

#include <array>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "openssl/ssl.h"
#include "ssl/internal.h"

/**
   RoundHandoff. Carries the state that a PSK-resumption round needs from the
   full round that preceded it, so the two can run in separate processes.

   Three things cross the boundary:

     session.bin       the origin's session ticket, via SSL_SESSION_to_bytes
     prover_psk.bin    the prover's 16-byte share of the SURF PSK
     verifier_psk.bin  the verifier's 16-byte share of the same PSK

   The two shares are separate files rather than fields inside session.bin
   because surf_psk_share is a SURF addition to SSL_SESSION and does not
   survive SSL_SESSION_to_bytes / _from_bytes. Extending BoringSSL's ASN.1
   serialisation would work, but it is a change to a vendored dependency that a
   submodule update would silently revert, and nothing here needs to
   interoperate with a stock BoringSSL: both ends are E2EBench. So we serialise
   the ticket with the library function and carry the SURF field alongside.

   This is benchmark plumbing. The shares are secret material written to disk
   in the clear, which is fine for a loopback benchmark and is not fine for
   anything else.
**/
namespace RoundHandoff {

  inline constexpr size_t kShareSize = 16;
  using Share = std::array<uint8_t, kShareSize>;

  inline std::string session_path(const std::string &dir) {
    return dir + "/session.bin";
  }
  inline std::string prover_share_path(const std::string &dir) {
    return dir + "/prover_psk.bin";
  }
  inline std::string verifier_share_path(const std::string &dir) {
    return dir + "/verifier_psk.bin";
  }

  inline bool write_file(const std::string &path, const uint8_t *const data,
                         const size_t len) noexcept {
    FILE *const f = fopen(path.c_str(), "wb");
    if (!f) {
      std::cerr << "[handoff] cannot open " << path << " for writing\n";
      return false;
    }
    const size_t written = fwrite(data, 1, len, f);
    const bool ok = (written == len) && (fclose(f) == 0);
    if (!ok) {
      std::cerr << "[handoff] short write to " << path << "\n";
    }
    return ok;
  }

  inline bool read_file(const std::string &path,
                        std::vector<uint8_t> &out) noexcept {
    FILE *const f = fopen(path.c_str(), "rb");
    if (!f) {
      std::cerr << "[handoff] cannot open " << path << " for reading\n";
      return false;
    }
    out.clear();
    uint8_t buf[4096];
    for (;;) {
      const size_t n = fread(buf, 1, sizeof(buf), f);
      if (n == 0) {
        break;
      }
      out.insert(out.end(), buf, buf + n);
    }
    const bool ok = (ferror(f) == 0);
    fclose(f);
    if (!ok) {
      std::cerr << "[handoff] read error on " << path << "\n";
    }
    return ok;
  }

  // shares

  inline bool save_share(const std::string &path, const Share &share) noexcept {
    return write_file(path, share.data(), share.size());
  }

  inline bool load_share(const std::string &path, Share &out) noexcept {
    std::vector<uint8_t> bytes;
    if (!read_file(path, bytes)) {
      return false;
    }
    if (bytes.size() != kShareSize) {
      std::cerr << "[handoff] " << path << " is " << bytes.size()
                << " bytes, expected " << kShareSize << "\n";
      return false;
    }
    std::copy(bytes.cbegin(), bytes.cend(), out.begin());
    return true;
  }

  // session ticket

  inline bool save_session(const std::string &dir,
                           const SSL_SESSION *const session) noexcept {
    if (!session) {
      std::cerr << "[handoff] no session to save\n";
      return false;
    }
    uint8_t *data = nullptr;
    size_t len = 0;
    if (!SSL_SESSION_to_bytes(session, &data, &len)) {
      std::cerr << "[handoff] SSL_SESSION_to_bytes failed\n";
      return false;
    }
    // SSL_SESSION_to_bytes serialises a placeholder string rather than failing
    // when the session is not resumable, which would then parse back as
    // garbage. Catch it here, where the cause is still obvious.
    static const char kNotResumable[] = "NOT RESUMABLE";
    if (len == sizeof(kNotResumable) - 1 &&
        memcmp(data, kNotResumable, len) == 0) {
      std::cerr << "[handoff] session is not resumable; nothing to hand off\n";
      OPENSSL_free(data);
      return false;
    }
    const bool ok = write_file(session_path(dir), data, len);
    OPENSSL_free(data);
    return ok;
  }

  // Returns a new reference the caller owns and must SSL_SESSION_free.
  inline SSL_SESSION *load_session(const std::string &dir,
                                   const SSL_CTX *const ctx) noexcept {
    std::vector<uint8_t> bytes;
    if (!read_file(session_path(dir), bytes) || bytes.empty()) {
      return nullptr;
    }
    SSL_SESSION *const session =
        SSL_SESSION_from_bytes(bytes.data(), bytes.size(), ctx);
    if (!session) {
      std::cerr << "[handoff] SSL_SESSION_from_bytes failed on "
                << bytes.size() << " bytes\n";
    }
    return session;
  }

  inline bool save_prover(const std::string &dir, const SSL_SESSION *session,
                          const Share &psk_share) noexcept {
    return save_session(dir, session) &&
           save_share(prover_share_path(dir), psk_share);
  }

  inline SSL_SESSION *load_prover(const std::string &dir, SSL_CTX *const ctx,
                                  Share &out_psk_share) noexcept {
    if (!load_share(prover_share_path(dir), out_psk_share)) {
      return nullptr;
    }
    SSL_SESSION *const session = load_session(dir, ctx);
    if (!session) {
      return nullptr;
    }
    session->surf_psk_share = out_psk_share;
    return session;
  }
}

#endif
