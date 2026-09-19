#ifndef INCLUDED_UTIL_HPP
#error Do not include Util.inl without Util.hpp
#endif

template <unsigned long size>
int Util::generate_random_bytes(std::array<uint8_t, size> &out) noexcept {
  return RAND_bytes(out.data(), size);
}

template <unsigned long size, typename T>
int Util::generate_random_bytes(T *const data) noexcept {
  assert(data);
  static_assert(std::is_trivial_v<T>,
                "Error: you should only instantiate generate_random_bytes with "
                "a trivial type T");
  return RAND_bytes(reinterpret_cast<uint8_t *>(data), size);
}

constexpr int Util::get_nid_from_uint16(const uint16_t group_id) noexcept {
  switch (group_id) {
  case SSL_CURVE_SECP256R1:
    return NID_X9_62_prime256v1;
  case SSL_CURVE_SECP384R1:
    return NID_secp384r1;
  case SSL_CURVE_SECP521R1:
    return NID_secp521r1;
  default:
    return 0;
  }
}

constexpr bool Util::is_nist_curve(const uint16_t curve_id) noexcept {
  return (curve_id == SSL_CURVE_SECP256R1) ||
         (curve_id == SSL_CURVE_SECP384R1) || (curve_id == SSL_CURVE_SECP521R1);
}

template <size_t size>
constexpr std::array<uint8_t, size / 8>
Util::convert_bool_to_uint8(const std::array<bool, size> &in) noexcept {

  // This is just to make sure we cover the whole array.
  static_assert(size % 8 == 0, "Error: size must be a multiple of 8");

  // For compatibility purposes.
  static_assert(CHAR_BIT == 8, "Error: this function expects CHAR_BIT == 8");

  // This must be default initialised, otherwise the loop exhibits UB.
  std::array<uint8_t, size / 8> out{};

  for (unsigned i = 0; i < size / 8; i++) {
    for (unsigned j = 0; j < 8; j++) {
      out[i] |= static_cast<uint8_t>(in[i * 8 + j]);
      out[i] = static_cast<uint8_t>(out[i] << 1);
    }
  }
  return out;
}

template <size_t size>
constexpr void Util::convert_uint8_to_bool(const uint8_t *in,
                                           bool *out) noexcept {
  // For compatibility purposes
  static_assert(CHAR_BIT == 8, "Error: this function expects CHAR_BIT == 8");
  for (uint64_t i = 0; i < size; i++) {
    uint8_t curr = in[i];
    for (unsigned j = 0; j < 8; j++) {
      *out = curr & 1;
      out++;
      curr = static_cast<uint8_t>(curr >> 1);
    }
  }
}

template <typename RT, typename F>
bool Util::process_data(SSL *const ssl, RT *const data, const std::size_t nbyte,
                        F &&func) noexcept(noexcept(func)) {

  // This function is a wrapper function for doing generic I/O.
  // It turned out that the code for sending data and reading data
  // internally is really similar: the only customisation point
  // that was interesting for us is the function that we're calling,
  // which we can thankfully turn into a type parameter here.

  // Firstly we need to make sure that the buffers are actually valid.
  assert(ssl);
  assert(data);

  // The way this function works is as follows: we walk through the
  // `data` parameter by using pointer arithmetic. The RT parameter
  // is expected to be a char * of some kind: this is because the underlying
  // functions expect these to be a char * of some kind.
  static_assert(std::is_same_v<std::remove_cv_t<RT>, char> ||
                    std::is_same_v<std::remove_cv_t<RT>, const char>,
                "Error: process_data expects data to be a char *");

  // We keep track of the amount of data that we read here, since we'll
  // increment the `data` pointer for either reading or writing.
  size_t data_processed{};
  while (data_processed < nbyte) {
    // We need to clamp the maximum we can do here.
    // If we have more than SSL3_RT_MAX_PLAIN_LENGTH to operate on, we'll
    // only deal with SSL3_RT_MAX_PLAIN_LENGTH: otherwise, we'll deal with the
    // remaining data that we've got. Note that the cast here is safe, since
    // SSL3_RT_MAX_PLAIN_LENGTH is less than the maximum value that can be held
    // in an `int`. In the other case, nbyte - data_processed is less than
    // SSL3_RT_MAX_PLAIN_LENGTH, so the cast is always safe.
    const int amount_to_process = static_cast<int>(std::min(
        static_cast<size_t>(SSL3_RT_MAX_PLAIN_LENGTH), nbyte - data_processed));

    // Note that this is an int for both of the functions that we expect to pass
    // in here. This is only really because of the API we have here in this
    // file. It isn't always guaranteed in general.
    const int amount_processed =
        func(ssl, data + data_processed, amount_to_process);
    if (amount_processed <= 0) {
      // The prover<->verifier connection can transiently return
      // SSL_ERROR_WANT_READ (errno EAGAIN) when the lock-step peer simply
      // hasn't produced the next message yet — the same behaviour
      // read_exact_blocking in nodes/Server.cpp handles for the control
      // channel. Treating it as fatal abandons the buffer part-filled, which
      // desynchronises the 2PC transcript: both sides then report "SPCOT
      // consistency check fails" and emp's FEQ check exits the process. Wait
      // for the socket and retry instead.
      const int ssl_err = SSL_get_error(ssl, amount_processed);
      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        struct pollfd pfd;
        pfd.fd = SSL_get_fd(ssl);
        pfd.events = static_cast<short>(
            ssl_err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN);
        pfd.revents = 0;
        if (::poll(&pfd, 1, -1) >= 0 || errno == EINTR) {
          continue;
        }
        // poll itself failed hard; fall through to the diagnostic below.
      }
      // A genuine failure (peer reset, clean shutdown, ...). We cannot report
      // it to emp (IOChannel's interface is void), so log enough to attribute
      // the failure and return; treating 0 as an error here also stops the old
      // behaviour of spinning forever on a closed connection.
      std::fprintf(stderr,
                   "[Util::process_data] I/O failed: ret=%d ssl_err=%d "
                   "errno=%d (%s) processed=%zu of %zu bytes\n",
                   amount_processed, ssl_err, errno, strerror(errno),
                   data_processed, nbyte);
      return false;
    }

    // This should always be the case, because we either processed all of the
    // data we had left, or we processed SSL3_RT_MAX_PLAIN_LENGTH bytes.
    assert(amount_processed <= amount_to_process);
    // This is always a valid cast because amount_processed > 0
    // and it's an int. Since we're upcasting, this is fine.
    data_processed += static_cast<size_t>(amount_processed);
  }
  return true;
}
