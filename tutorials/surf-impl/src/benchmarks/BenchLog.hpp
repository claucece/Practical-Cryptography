#ifndef INCLUDED_BENCHLOG_HPP
#define INCLUDED_BENCHLOG_HPP

/*
  Shared helpers for correlatable benchmark CSV logging.

  The prover<->verifier TLS connection has a 32-byte client_random that both
  ends observe (SSL_get_client_random). Logging it as hex on the prover side
  (total connection time) and on the verifier side (per-step state-machine
  timings) lets the two CSVs be joined on `client_random`.
*/

#include <openssl/ssl.h>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unistd.h>

namespace BenchLog {

// hostname of the machine running this process; "unknown" on failure.
inline std::string host() {
  char buf[256];
  if (::gethostname(buf, sizeof(buf)) == 0) {
    buf[sizeof(buf) - 1] = '\0';
    return std::string(buf);
  }
  return "unknown";
}

// ISO-8601 local timestamp, e.g. 2026-05-29T14:03:11.
inline std::string now_iso() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  ::localtime_r(&t, &tm);
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
  return os.str();
}

// 64-char lowercase hex of the TLS client_random, or "" if unavailable.
inline std::string client_random_hex(SSL *ssl) {
  if (!ssl) return {};
  uint8_t rnd[32];
  const size_t n = SSL_get_client_random(ssl, rnd, sizeof(rnd));
  if (n == 0) return {};
  std::ostringstream os;
  os << std::hex << std::setfill('0');
  for (size_t i = 0; i < n; ++i) {
    os << std::setw(2) << static_cast<unsigned>(rnd[i]);
  }
  return os.str();
}

// Append-only CSV writer that emits `header` exactly once (when the file is
// newly created or empty). Construct once, then call row() per record.
class CsvLog {
public:
  CsvLog(const std::string &path, const std::string &header)
      : out_(path, std::ios::app) {
    // tellp() == 0 means the file was just created (or is empty): write header.
    if (out_ && out_.tellp() == std::streampos(0)) {
      out_ << header << '\n';
    }
  }

  // `fields` should be a pre-formatted, comma-separated record (no trailing
  // newline). Flushes so a long-running verifier's rows are durable per run.
  void row(const std::string &fields) {
    out_ << fields << '\n';
    out_.flush();
  }

  bool ok() const { return static_cast<bool>(out_); }

private:
  std::ofstream out_;
};

} // namespace BenchLog

#endif
