/** @file ucp_time.cpp
 *  @brief High-resolution clock implementation -- mirrors C# Ucp.Internal.Stopwatch.
 *
 *  Provides microsecond-granularity timestamps based on std::chrono::steady_clock.
 *  ReadStopwatchMicroseconds() reads the raw counter every call; NowMicroseconds()
 *  caches the value at millisecond granularity to reduce call overhead when
 *  many timestamps are generated in quick succession (e.g. packet encoding).
 *
 *  On Windows, sets the OS timer resolution to 1 ms via timeBeginPeriod(1)
 *  during static initialization (mirrors C# UcpTime static constructor).
 */

#include "ucp/ucp_time.h"
#include "ucp/ucp_constants.h"

#include <atomic>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN32
namespace {
struct TimerInit {
    TimerInit() noexcept { timeBeginPeriod(1); }
    ~TimerInit() noexcept { timeEndPeriod(1); }
};
const TimerInit g_timer_init;
} // namespace
#endif

namespace ucp {
using namespace Constants;
namespace {

using SteadyClock = std::chrono::steady_clock;

SteadyClock::time_point g_start_time = SteadyClock::now();
std::atomic<int64_t> g_cached_microseconds{0};
std::atomic<int64_t> g_cached_elapsed_millis{0};

} // namespace

/** @brief Reads the raw stopwatch counter in microseconds (every call recomputes, no caching).
 *  @return Microseconds since a fixed epoch (program start). */
int64_t UcpTime::ReadStopwatchMicroseconds() noexcept {
    auto now = SteadyClock::now();
    int64_t elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - g_start_time).count();
    return elapsed / Constants::NANOS_PER_MICRO;
}

/** @brief Returns the current microsecond timestamp, cached and refreshed at millisecond granularity.
 *  Reduces clock call overhead when many timestamps are needed in rapid succession.
 *  @return Microseconds since a fixed epoch (program start). */
int64_t UcpTime::NowMicroseconds() noexcept {
    auto now = SteadyClock::now();
    int64_t elapsed_ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(now - g_start_time).count();
    int64_t elapsed_millis = elapsed_ticks / Constants::NANOS_PER_MILLI;
    if (elapsed_millis != g_cached_elapsed_millis.load(std::memory_order_acquire)) {
        g_cached_microseconds.store(elapsed_ticks / Constants::NANOS_PER_MICRO, std::memory_order_release);
        g_cached_elapsed_millis.store(elapsed_millis, std::memory_order_release);
    }
    return g_cached_microseconds.load(std::memory_order_acquire);
}

} // namespace ucp
