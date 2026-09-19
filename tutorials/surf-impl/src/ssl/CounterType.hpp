#ifndef INCLUDED_COUNTERTYPE_HPP
#define INCLUDED_COUNTERTYPE_HPP

#include <cstddef>

/**
   RWCounter. This policy class implements a simple bandwidth tracking type
   for EmpWrapper that solely tracks reads or writes. This can be disabled for
   better performance if this is desired.
**/
class RWCounter {
public:
  /**
     track_write. This function adds `bytes` to the number of sent bytes so
   far. This function does not throw.
      @snippet CounterType.t.cpp RWCounterTrackWrite
      @param[in] bytes: the number of bytes sent.
   **/
  inline void track_write(const std::size_t bytes) noexcept;
  /**
     track_write. This function adds `bytes` to the number of read bytes so far.
     This function does not throw.
     @snippet CounterType.t.cpp RWCounterTrackRead
     @param[in] bytes: the number of bytes read.
  **/
  inline void track_read(const std::size_t bytes) noexcept;

  /**
     get_read. This function returns the number of read bytes so far.
     This function does not throw.
     @snippet CounterType.t.cpp RWCounterGetRead
     @return the number of bytes read so far.
  **/
  inline std::size_t get_read() const noexcept;
  /**
     get_write. This function returns the number of written bytes so far.
     This function does not throw.
     @snippet CounterType.t.cpp RWCounterGetWrite
     @return the number of bytes written so far.
  **/
  inline std::size_t get_write() const noexcept;

  /**
     reset_read. This function resets the number of bytes read so far to 0.
     @snippet CounterType.t.cpp RWCounterResetRead
     This function does not throw.
  **/
  inline void reset_read() noexcept;

  /**
     reset_write. This function resets the number of bytes written so far to 0.
     @snippet CounterType.t.cpp RWCounterResetWrite
     This function does not throw.
  **/
  inline void reset_write() noexcept;

  /**
     track_round. This function records that a single message was flushed to the
   wire. The round counter is a proxy for the number of communication rounds:
   one increment per outbound message, which (in a synchronous, alternating
   protocol) corresponds to one round-trip's worth of latency. This function
   does not throw.
  **/
  inline void track_round() noexcept;

  /**
     get_rounds. This function returns the number of outbound messages flushed so
   far. This function does not throw.
     @return the number of rounds (outbound messages) so far.
  **/
  inline std::size_t get_rounds() const noexcept;

  /**
     reset_rounds. This function resets the round counter to 0. This function
   does not throw.
  **/
  inline void reset_rounds() noexcept;

private:
  /**
      read_counter. This is the counter for the number of bytes read.
   **/
  std::size_t read_counter{};
  /**
     write_counter. This is the counter for the number of bytes written.
  **/
  std::size_t write_counter{};
  /**
     round_counter. This is the counter for the number of outbound messages
     flushed to the wire. See track_round().
  **/
  std::size_t round_counter{};
};

/**
   NoCounter. This policy class implements a simple bandwidth tracking type for
   EmpWrapper that does nothing. This class should be used if optimum
performance is required.
**/
class NoCounter {
public:
  /**
     track_write. This function is a stub for adding to the write counter.
     It does nothing.
     @snippet CounterType.t.cpp NoCounterTrackWrite
   **/
  inline constexpr void track_write(const std::size_t) noexcept;
  /**
     track_read. This function is a stub for adding to the read counter.
     It does nothing.
     @snippet CounterType.t.cpp NoCounterTrackRead
   **/
  inline constexpr void track_read(const std::size_t) noexcept;
  /**
     get_read. This function is a stub for returning the read counter.
     This function only ever returns 0.
     @snippet CounterType.t.cpp NoCounterGetRead
     @return 0.
   **/
  inline constexpr std::size_t get_read() noexcept;

  /**
     get_write. This function is a stub for returning the write counter.
     This function only ever returns 0.
     @snippet CounterType.t.cpp NoCounterGetWrite
     @return 0.
   **/
  inline constexpr std::size_t get_write() noexcept;

  /**
     reset_read. This function is a stub for resetting the read counter.
     This function does nothing.
     @snippet CounterType.t.cpp NoCounterResetRead
   **/
  inline constexpr void reset_read() noexcept;
  /**
     reset_write. This function is a stub for resetting the write counter.
     This function does nothing.
     @snippet CounterType.t.cpp NoCounterResetWrite
   **/
  inline constexpr void reset_write() noexcept;

  /**
     track_round. This function is a stub for recording an outbound message.
     It does nothing.
   **/
  inline constexpr void track_round() noexcept;
  /**
     get_rounds. This function is a stub for returning the round counter.
     This function only ever returns 0.
     @return 0.
   **/
  inline constexpr std::size_t get_rounds() noexcept;
  /**
     reset_rounds. This function is a stub for resetting the round counter.
     This function does nothing.
   **/
  inline constexpr void reset_rounds() noexcept;
};

#include "CounterType.inl"

#endif
