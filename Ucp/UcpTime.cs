using System.Diagnostics; // Provides high-resolution Stopwatch for monotonic timestamps
using System.Threading;   // Provides Volatile.Read/Write for lock-free shared state

namespace Ucp // Root namespace for the UCP reliable-transport protocol library
{
    /// <summary>
    /// Generates local monotonic microsecond timestamps suitable for RTT echo
    /// measurement. Based on Stopwatch.GetTimestamp() for high-resolution,
    /// non-wall-clock time that is unaffected by system time adjustments.
    /// This ensures RTT calculations remain accurate even if the system clock
    /// is changed by NTP corrections or user action during a connection.
    /// </summary>
    internal static class UcpTime // Monotonic microsecond clock for protocol timing, pacing, and RTT measurement
    {
        /// <summary>Baseline Stopwatch ticks at static initialization time, used as the zero-point for all timestamps.</summary>
        private static readonly long StartTicks = Stopwatch.GetTimestamp(); // Captured once at type init so all times are relative

        /// <summary>Cached elapsed milliseconds, used to throttle microsecond updates to once per millisecond boundary.</summary>
        private static long _cachedElapsedMilliseconds; // Coarse guard value to detect when the millisecond has ticked over

        /// <summary>Cached microsecond value updated once per millisecond boundary to avoid recomputation on every call.</summary>
        private static long _cachedMicroseconds; // The last-computed microsecond value, served to callers of NowMicroseconds()

        /// <summary>
        /// Returns the current monotonic time in microseconds, computed fresh
        /// on every call. This is the highest-precision time source and should
        /// be used when exact timing is critical (e.g., RTT measurement, timer
        /// expiry calculation). Converts Stopwatch ticks to microseconds using
        /// the tick-frequency constant.
        /// </summary>
        /// <returns>Microseconds since static initialization.</returns>
        public static long ReadStopwatchMicroseconds() // Computes a fresh, uncached microsecond timestamp on every invocation
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks; // Compute ticks elapsed since type initialization
            return (elapsedTicks * UcpConstants.MICROS_PER_SECOND) / Stopwatch.Frequency; // Convert raw ticks to microseconds via frequency division
        }

        /// <summary>
        /// Returns a cached monotonic time in microseconds, updated at most once
        /// per millisecond. This reduces the cost of frequent time reads in the
        /// protocol engine while keeping sub-microsecond precision. Many call sites
        /// (e.g., per-packet pacing checks) don't need fresh timestamps on every
        /// invocation, so the cached value avoids expensive tick-to-microsecond
        /// conversion overhead.
        /// </summary>
        /// <returns>Microseconds since static initialization (cached).</returns>
        public static long NowMicroseconds() // Returns the cached microsecond timestamp, recomputing only at millisecond boundaries
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks; // Raw tick delta from the baseline
            long elapsedMilliseconds = (elapsedTicks * UcpConstants.MICROS_PER_MILLI) / Stopwatch.Frequency; // Coarse elapsed time in milliseconds for cache-invalidation check
            if (elapsedMilliseconds != Volatile.Read(ref _cachedElapsedMilliseconds)) // If the millisecond counter has ticked over, invalidate the cache
            {
                // Only recompute the microsecond cache when the millisecond counter changes.
                Volatile.Write(ref _cachedMicroseconds, (elapsedTicks * UcpConstants.MICROS_PER_SECOND) / Stopwatch.Frequency); // Store fresh microsecond value for subsequent reads
                Volatile.Write(ref _cachedElapsedMilliseconds, elapsedMilliseconds); // Update the millisecond guard so next calls skip recomputation
            }

            return Volatile.Read(ref _cachedMicroseconds); // Serve the cached microsecond value (freshly updated or from this millisecond)
        }
    }
}
