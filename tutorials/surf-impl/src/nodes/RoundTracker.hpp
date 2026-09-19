#ifndef INCLUDED_ROUNDTRACKER_HPP
#define INCLUDED_ROUNDTRACKER_HPP

#include "Events.hpp"
#include <array>
#include <cstdint>
#include <iostream>

/**
   RoundTracker. This namespace mirrors BandwidthTracker, but instead of
counting bytes it counts the number of communication rounds (outbound messages
put on the wire) per protocol event. Combined with a measured RTT, the per-event
round count gives the latency-bound network cost of each step (rounds * RTT),
which is the quantity that is independent of any particular link's bandwidth.
**/
namespace RoundTracker {
/**
   ActiveTracker. This class records all round events in an array.
**/
class ActiveTracker {
public:
  static constexpr bool is_interested(const Events::State) noexcept {
    return true;
  }

  uint64_t *get_memory_for(const Events::State state) noexcept {
    return &data[static_cast<unsigned>(state)];
  }

  void print() const noexcept {
    for (unsigned i = 0; i < static_cast<unsigned>(Events::State::SIZE); i++) {
      std::cerr << Events::as_string[i] << ":" << data[i] << " rounds\n";
    }
    std::cerr << "\n";
  }

  using DataArray =
      std::array<uint64_t, static_cast<unsigned>(Events::State::SIZE)>;

  // Per-event round counts recorded since the last reset. Used by benchmarks to
  // emit per-step round columns, mirroring Timer::get_times() and
  // BandwidthTracker::get_data().
  const DataArray &get_data() const noexcept { return data; }

  // Sum of all per-event round counts.
  uint64_t total() const noexcept {
    uint64_t sum = 0;
    for (const uint64_t v : data) sum += v;
    return sum;
  }

private:
  DataArray data;
};

/**
   NoTracker. This class records nothing.
**/
class NoTracker {
public:
  static constexpr bool is_interested(const Events::State) noexcept {
    return false;
  }

  uint64_t *get_memory_for(const Events::State) const noexcept {
    return nullptr;
  }

  void print() const noexcept {}

  using DataArray =
      std::array<uint64_t, static_cast<unsigned>(Events::State::SIZE)>;

  const DataArray &get_data() const noexcept {
    static const DataArray zero{};
    return zero;
  }

  uint64_t total() const noexcept { return 0; }
};

using TrackerType = ActiveTracker;

} // namespace RoundTracker

#endif
