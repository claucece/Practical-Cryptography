#ifndef INCLUDED_EMPWRAPPER_HPP
#error "Do not include EmpWrapper.inl without EmpWrapper.hpp"
#endif

#include <cstdint>
#include <thread>
#include <type_traits>

// Macro bits.
#ifndef __APPLE__
#include <endian.h>
#else
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

template <typename BufferType, typename CounterType, bool prepend_header>
EmpWrapper<BufferType, CounterType, prepend_header>::EmpWrapper(
    SSL *const ssl_in)
    : ssl{ssl_in}, write_buffer{}, read_buffer{}, counter_w{} {

  write_buffer.resize((prepend_header) * sizeof(uint64_t));
  read_buffer.resize((prepend_header) * sizeof(uint64_t));
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline bool EmpWrapper<BufferType, CounterType, prepend_header>::is_valid_ssl()
    const noexcept {
  return ssl != nullptr;
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline SSL *
EmpWrapper<BufferType, CounterType, prepend_header>::get_ssl() noexcept {
  return ssl;
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline bool EmpWrapper<BufferType, CounterType, prepend_header>::has_io_failed()
    const noexcept {
  return io_failed;
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::mark_io_failed() noexcept {
  io_failed = true;
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::reset_bandwidth() noexcept {
  counter_w.reset_read();
  counter_w.reset_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::reset_read_counter() noexcept {
  counter_w.reset_read();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::reset_write_counter() noexcept {
  counter_w.reset_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline std::size_t
EmpWrapper<BufferType, CounterType, prepend_header>::get_write_counter()
    const noexcept {
  return counter_w.get_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline std::size_t
EmpWrapper<BufferType, CounterType, prepend_header>::get_round_counter()
    const noexcept {
  return counter_w.get_rounds();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline void EmpWrapper<BufferType, CounterType,
                       prepend_header>::reset_round_counter() noexcept {
  counter_w.reset_rounds();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline std::size_t
EmpWrapper<BufferType, CounterType, prepend_header>::get_read_counter()
    const noexcept {
  return counter_w.get_read();
}

template <typename BufferType, typename CounterType, bool prepend_header>
inline std::size_t
EmpWrapper<BufferType, CounterType, prepend_header>::get_bandwidth()
    const noexcept {
  return counter_w.get_read() + counter_w.get_write();
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
inline typename std::enable_if_t<BufferType::can_buffer(), T>
EmpWrapper<BufferType, CounterType, prepend_header>::flush() noexcept {
  static_assert(std::is_void_v<T>,
                "Error: can only instantiate can_buffer with T = void");
  const auto size = write_buffer.size();
  if (size == 0 ||
      (prepend_header && write_buffer.size() == sizeof(uint64_t))) {
    return;
  }

  // If we pre-pend the header, then update the size finally before sending.
  if constexpr (prepend_header) {
    const auto buffer_size = htobe64(write_buffer.size());
    memcpy(write_buffer.data(), &buffer_size, sizeof(buffer_size));
    // We've already added the rest of the writes earlier.
    counter_w.track_write(sizeof(buffer_size));
  }

  if (!io_failed &&
      !Util::process_data(ssl, write_buffer.data(),
                          static_cast<size_t>(write_buffer.size()),
                          SSL_write)) {
    io_failed = true;
  }
  // One buffered batch was just put on the wire: count it as a round.
  counter_w.track_round();

  // If we pre-pend the header, then reserve enough space for that.
  if constexpr (prepend_header) {
    write_buffer.resize(sizeof(size));
  } else {
    write_buffer.clear();
  }
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
inline typename std::enable_if_t<!BufferType::can_buffer(), T>
EmpWrapper<BufferType, CounterType, prepend_header>::flush() const noexcept {
  static_assert(std::is_void_v<T>,
                "Error: can only instantiate can_buffer with T = void");
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
void EmpWrapper<BufferType, CounterType, prepend_header>::send_data_internal(
    const void *const data, const T nbyte) noexcept {
  // We only accept integral sizes here.
  static_assert(
      std::is_integral_v<T>,
      "Error: send_data_internal can only be instantiated with integral types");

  // We need to check that the largest possible `T` fits into a
  // std::size and it's non-zero. The non-zero is below: here we just check
  // statically that the sizes line up.
  static_assert(std::numeric_limits<T>::max() <=
                    std::numeric_limits<size_t>::max(),
                "Error: the largest possible `T` cannot be represented as a "
                "std::size_t");
  assert(nbyte >= 0);
  assert(is_valid_ssl());

  // If buffering is supported, then buffer. We'll flush if the buffer is full.
  if constexpr (BufferType::can_buffer()) {
    write_buffer.buffer_data(data,
                             static_cast<typename BufferType::SizeType>(nbyte));

    if (write_buffer.should_send()) {
      flush();
    }

  } else {
    // Just flush it.
    if (!io_failed &&
        !Util::process_data(ssl, static_cast<const char *>(data),
                            static_cast<size_t>(nbyte), SSL_write)) {
      io_failed = true;
    }
    // Unbuffered: every send is its own message on the wire, so count a round.
    counter_w.track_round();
  }

  counter_w.track_write(nbyte);
}

template <typename BufferType, typename CounterType, bool prepend_header>
template <typename T>
void EmpWrapper<BufferType, CounterType, prepend_header>::recv_data_internal(
    void *const data, const T nbyte) noexcept {
  // We only accept integral sizes here.
  static_assert(
      std::is_integral_v<T>,
      "Error: send_data_internal can only be instantiated with integral types");
  // We need to check that the largest possible `T` fits into a
  // std::size and it's non-zero. The non-zero is below: here we just check
  // statically that the sizes line up.
  static_assert(std::numeric_limits<T>::max() <=
                    std::numeric_limits<size_t>::max(),
                "Error: the largest possible `T` cannot be represented as a "
                "std::size_t");
  assert(nbyte >= 0);
  assert(is_valid_ssl());

  // Once a fatal I/O error has occurred, every further receive returns zeroed
  // bytes immediately: the connection is dead, and the run is going to be
  // abandoned by whoever checks has_io_failed(). Zero-filling keeps emp's
  // remaining (garbage) computation deterministic and free of syscalls.
  if (io_failed) {
    memset(data, 0, static_cast<size_t>(nbyte));
    return;
  }

  // If there's no buffering scheme, just exit.
  if constexpr (!BufferType::can_buffer()) {
    if (!Util::process_data(ssl, static_cast<char *>(data),
                            static_cast<size_t>(nbyte), SSL_read)) {
      io_failed = true;
    }
    counter_w.track_read(nbyte);
    return;
  } else if constexpr (BufferType::can_buffer()) {
    // Check if there's enough bytes in the read buffer.
    const auto nr_read_bytes = read_buffer.read_bytes_size();

    // If so, just use them.
    if (nr_read_bytes >= nbyte) {
      read_buffer.read_bytes(data, nbyte);
      return;
    }

    // Otherwise, we need to read from the buffer and then whatever else is
    // coming in, too.
    const auto to_read = nbyte - nr_read_bytes;

    read_buffer.read_bytes(data, nr_read_bytes);

    // Now the read buffer must be empty, we can read from the socket.
    const std::size_t header_size = [this, to_read]() -> std::size_t {
      if constexpr (prepend_header) {
        // We need to read the size, too. Use Util::process_data (not a single
        // SSL_read) so that a header split across TCP segments — common over a
        // real network, though never on loopback — is read in full. A raw
        // SSL_read here returns a short count when the 8-byte header spans
        // segments, which silently collapses the framing and desynchronises the
        // 2PC stream.
        uint64_t tmp_header_size = 0;
        if (!Util::process_data(ssl,
                                reinterpret_cast<char *>(&tmp_header_size),
                                sizeof(tmp_header_size), SSL_read)) {
          io_failed = true;
          return 0;
        }
        counter_w.track_read(sizeof(tmp_header_size));
        // N.B The subtraction is needed here: otherwise the socket will try to
        // read the header bytes again.
        const uint64_t total = be64toh(tmp_header_size);
        if (total < sizeof(tmp_header_size)) return 0;
        const uint64_t payload64 = total - sizeof(tmp_header_size);
        if (payload64 > std::numeric_limits<std::size_t>::max()) return 0;
        return static_cast<std::size_t>(payload64);
      } else {
        // Just return the number of bytes to read.
        return to_read;
      }
    }();

    // The header read above may have failed; bail out with zeroed output
    // rather than under-reading from the (now empty) read buffer below.
    if (io_failed) {
      memset(reinterpret_cast<char *>(data) + nr_read_bytes, 0,
             static_cast<size_t>(to_read));
      return;
    }

    // DIAGNOSTIC (temporary): a desynced 2PC stream surfaces here as an
    // implausible frame length read off the wire. Capture context before the
    // resize would throw length_error/bad_alloc, and fail the run cleanly.
    if (header_size > (static_cast<std::size_t>(1) << 30)) {  // >256 MiB
      fprintf(stderr,
              "[EmpWrapper] IMPLAUSIBLE frame: header_size=%zu nbyte=%lld "
              "nr_read_bytes=%zu to_read=%zu prev_read_buffer_size=%zu\n",
              header_size, static_cast<long long>(nbyte), nr_read_bytes,
              to_read, read_buffer.size());
      io_failed = true;
      memset(reinterpret_cast<char *>(data) + nr_read_bytes, 0,
             static_cast<size_t>(to_read));
      return;
    }

    // Resize the read buffer to the right size.
    read_buffer.resize(header_size);

    // And now read in those bytes.
    if (!Util::process_data(ssl, static_cast<char *>(read_buffer.data()),
                            static_cast<size_t>(header_size), SSL_read)) {
      io_failed = true;
    }
    read_buffer.add_read(header_size);
    counter_w.track_read(header_size);

    // If there's no a pre-pended size, then read any remaining bytes into the
    // buffer, too.
    if constexpr (!prepend_header) {
      if (!io_failed) {
        if (const auto bytes = SSL_pending(ssl); bytes > 0) {
          // Resize the buffer.
          read_buffer.resize(bytes + header_size);
          if (!Util::process_data(
                  ssl, static_cast<char *>(read_buffer.data() + header_size),
                  bytes, SSL_read)) {
            io_failed = true;
          }
          read_buffer.add_read(bytes);
          counter_w.track_read(bytes);
        }
      }
    }

    // DIAGNOSTIC (temporary): this is the suspected framing bug. If a single
    // emp recv needs more bytes than the frame we just read provides, the
    // assert in read_bytes is compiled out under -DNDEBUG and we under-read,
    // desynchronising the stream. Log it the first few times it happens.
    if (to_read > read_buffer.read_bytes_size()) {
      static thread_local unsigned hits = 0;
      if (hits++ < 16) {
        fprintf(stderr,
                "[EmpWrapper] UNDER-READ: to_read=%zu but only %zu buffered "
                "(header_size=%zu nbyte=%lld nr_read_bytes=%zu)\n",
                to_read, read_buffer.read_bytes_size(), header_size,
                static_cast<long long>(nbyte), nr_read_bytes);
      }
    }

    // Copy over those we read.
    read_buffer.read_bytes(reinterpret_cast<char *>(data) + nr_read_bytes,
                           to_read);
  }
}
