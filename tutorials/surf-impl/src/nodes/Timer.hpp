#ifndef INCLUDED_TIMER_HPP
#define INCLUDED_TIMER_HPP
#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <sys/resource.h>
#include "Events.hpp"
/**
   Timer. This namespace implements a series of counters for tracking how long certain events take inside the protocol.
   Essentially, this namespace contains two different counters that do different things.

   Each scope records three things:
     - wall time;
     - thread CPU time, so a scope that grows without burning CPU can be
       identified as a stall rather than as extra work;
     - process rusage counters (minor faults, context switches), to separate
       "more instructions executed" from "same instructions, worse memory
       behaviour".
**/
namespace Timer {
  using TimesArray = std::array<std::chrono::duration<double>,
                                static_cast<unsigned>(Events::State::SIZE)>;

  // Thread CPU time in seconds. Counts only time this thread was actually on
  // a core, so wall - cpu is time spent blocked or descheduled.
  inline double thread_cpu_now() noexcept {
    timespec ts{};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return static_cast<double>(ts.tv_sec) +
           static_cast<double>(ts.tv_nsec) * 1e-9;
  }

  struct Usage {
    long minflt;  // minor page faults: pages mapped without disk I/O
    long nivcsw;  // involuntary context switches: preempted by the scheduler
    long nvcsw;   // voluntary context switches: blocked on I/O or a lock
  };

  // NOTE: RUSAGE_SELF is process-wide, not thread-local. This is for MacOS
  inline Usage usage_now() noexcept {
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    return Usage{ru.ru_minflt, ru.ru_nivcsw, ru.ru_nvcsw};
  }

  class ActiveTimer {
    TimesArray times{};
    std::array<double, static_cast<unsigned>(Events::State::SIZE)> cpu_times{};
    std::array<long, static_cast<unsigned>(Events::State::SIZE)> minflts{};
    std::array<long, static_cast<unsigned>(Events::State::SIZE)> nivcsws{};
    std::array<long, static_cast<unsigned>(Events::State::SIZE)> nvcsws{};
    std::array<std::chrono::time_point<std::chrono::steady_clock>,
               static_cast<unsigned>(Events::State::SIZE)>
        counters{};

  public:
    void end(const Events::State event,
             const std::chrono::time_point<std::chrono::steady_clock> time,
             const double cpu_start, const Usage &u0) noexcept {
      const unsigned i = static_cast<unsigned>(event);
      times[i] += std::chrono::steady_clock::now() - time;
      cpu_times[i] += thread_cpu_now() - cpu_start;
      const Usage u1 = usage_now();
      minflts[i] += u1.minflt - u0.minflt;
      nivcsws[i] += u1.nivcsw - u0.nivcsw;
      nvcsws[i] += u1.nvcsw - u0.nvcsw;
    }

    // Per-event accumulated durations, indexed by Events::State.
    const TimesArray &get_times() const noexcept { return times; }

    void print() noexcept {
      for (unsigned i = 0; i < static_cast<unsigned>(Events::State::SIZE); i++) {
        std::cerr << Events::as_string[i] << ":" << times[i].count() << "s\n";
      }
      std::cerr << "\n";

      std::cerr << "CPUTIMINGS\n";
      for (unsigned i = 0; i < static_cast<unsigned>(Events::State::SIZE); i++) {
        const double wall_ms = times[i].count() * 1e3;
        const double cpu_ms = cpu_times[i] * 1e3;
        if (wall_ms == 0.0 && cpu_ms == 0.0) {
          continue;
        }
        std::cerr << "[cpu] " << Events::as_string[i]
                  << " wall_ms=" << wall_ms
                  << " cpu_ms=" << cpu_ms
                  << " stall_ms=" << (wall_ms - cpu_ms)
                  << " minflt=" << minflts[i]
                  << " nivcsw=" << nivcsws[i]
                  << " nvcsw=" << nvcsws[i] << "\n";
      }
      std::cerr << "\n";
    }
  };

  class NoTimer {
    TimesArray times{};

  public:
    void end(const Events::State,
             const std::chrono::time_point<std::chrono::steady_clock>,
             const double, const Usage &) noexcept {}
    const TimesArray &get_times() const noexcept { return times; }
    void print() noexcept {}
  };

  template <typename T> class TimeIt {
  public:
    TimeIt(T &timer, Events::State event) noexcept
        : timer_{timer}, val_{std::chrono::steady_clock::now()},
          cpu_{thread_cpu_now()}, u0_{usage_now()}, event_{event} {}
    ~TimeIt() noexcept { timer_.end(event_, val_, cpu_, u0_); }

  private:
    T &timer_;
    std::chrono::time_point<std::chrono::steady_clock> val_;
    double cpu_;
    Usage u0_;
    Events::State event_;
  };

  using TimerType = ActiveTimer;
}
#endif
