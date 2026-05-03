/** @file ucp_time.cpp
 *  @brief High-resolution clock implementation — mirrors C# Ucp.Internal.Stopwatch.
 *
 *  Provides microsecond-granularity timestamps based on std::chrono::steady_clock.
 *  ReadStopwatchMicroseconds() reads the raw counter every call; NowMicroseconds()
 *  caches the value at millisecond granularity to reduce call overhead when
 *  many timestamps are generated in quick succession (e.g. packet encoding).
 */

#include "ucp/ucp_time.h"

#include <chrono>

namespace ucp {
namespace {

using SteadyClock = std::chrono::steady_clock;

SteadyClock::time_point g_start_time = SteadyClock::now();  //< Fixed epoch for all UcpTime measurements.
int64_t g_cached_microseconds      = 0;                     //< Most recent cached microsecond value.
int64_t g_cached_elapsed_millis    = 0;                     //< Millisecond guard for cache updates.

/** @brief Convert steady_clock::ticks to microseconds. */
int64_t TicksToMicros(int64_t ticks) {
    return (ticks * 1000000LL) / SteadyClock::period::den;
}

/** @brief Convert steady_clock::ticks to milliseconds. */
int64_t TicksToMillis(int64_t ticks) {
    return (ticks * 1000LL) / SteadyClock::period::den;
}

} // anonymous namespace

int64_t UcpTime::ReadStopwatchMicroseconds() {
    auto now = SteadyClock::now();
    int64_t elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - g_start_time).count();
    return elapsed / 1000LL;
}

int64_t UcpTime::NowMicroseconds() {
    auto now = SteadyClock::now();
    int64_t elapsed_ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(now - g_start_time).count();
    int64_t elapsed_millis = elapsed_ticks / 1000000LL;
    // Only update the cache when the millisecond changes (coarse-grained caching)
    if (elapsed_millis != g_cached_elapsed_millis) {
        g_cached_microseconds   = elapsed_ticks / 1000LL;
        g_cached_elapsed_millis = elapsed_millis;
    }
    return g_cached_microseconds;
}

} // namespace ucp
