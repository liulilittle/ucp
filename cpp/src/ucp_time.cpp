/** @file ucp_time.cpp
 *  @brief High-resolution clock implementation — mirrors C# Ucp.Internal.Stopwatch.
 *
 *  Provides microsecond-granularity timestamps based on std::chrono::steady_clock.
 *  ReadStopwatchMicroseconds() reads the raw counter every call; NowMicroseconds()
 *  caches the value at millisecond granularity to reduce call overhead when
 *  many timestamps are generated in quick succession (e.g. packet encoding).
 */

#include "ucp/ucp_time.h"  //< Include the corresponding header declaring the UcpTime class interface

#include <atomic>  //< Provides std::atomic<T> with acquire/release ordering to match C# Volatile.Read / Volatile.Write
#include <chrono>  //< Provides std::chrono::steady_clock — monotonic clock unaffected by system time adjustments

namespace ucp {  //< Begin UCP protocol namespace
namespace {  //< Anonymous (translation-unit-local) namespace for internal state and type aliases

using SteadyClock = std::chrono::steady_clock;  //< Type alias for the monotonic high-resolution clock — matches C# Stopwatch behavior

SteadyClock::time_point g_start_time = SteadyClock::now();  //< Fixed baseline time-point captured once at static initialization (C# StartTicks)
std::atomic<int64_t> g_cached_microseconds{0};               //< Cached microsecond value updated at millisecond boundaries (C# _cachedMicroseconds)
std::atomic<int64_t> g_cached_elapsed_millis{0};             //< Millisecond guard — cache invalidated only when this changes (C# _cachedElapsedMilliseconds)

} // anonymous namespace  //< End of translation-unit-local scope

int64_t UcpTime::ReadStopwatchMicroseconds() {  //< Returns a fresh microsecond timestamp computed on every call — matches C# ReadStopwatchMicroseconds()
    auto now = SteadyClock::now();  //< Capture the current steady-clock time point
    int64_t elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - g_start_time).count();  //< Compute elapsed nanoseconds since the fixed epoch
    return elapsed / 1000LL;  //< Convert nanoseconds to microseconds and return (matches C# ticks-to-microseconds conversion)
}  //< End of ReadStopwatchMicroseconds

int64_t UcpTime::NowMicroseconds() {  //< Returns cached microseconds, recomputed at most once per millisecond — matches C# NowMicroseconds()
    auto now = SteadyClock::now();  //< Capture the current steady-clock time point
    int64_t elapsed_ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(now - g_start_time).count();  //< Elapsed nanoseconds since the fixed epoch
    int64_t elapsed_millis = elapsed_ticks / 1000000LL;  //< Convert nanoseconds to whole milliseconds for cache-invalidation comparison
    if (elapsed_millis != g_cached_elapsed_millis.load(std::memory_order_acquire)) {  //< If the millisecond counter has changed, invalidate and refresh the cache (acquire to match C# Volatile.Read)
        g_cached_microseconds.store(elapsed_ticks / 1000LL, std::memory_order_release);  //< Store the fresh microsecond value into the cache (release to match C# Volatile.Write)
        g_cached_elapsed_millis.store(elapsed_millis, std::memory_order_release);  //< Update the millisecond guard so subsequent calls skip recomputation (release to match C# Volatile.Write)
    }  //< End of cache-invalidation block
    return g_cached_microseconds.load(std::memory_order_acquire);  //< Return the cached microsecond value with acquire ordering (matches C# Volatile.Read)
}  //< End of NowMicroseconds

} // namespace ucp  //< Close UCP namespace
