using System.Diagnostics;
using System.Threading;

namespace Ucp
{
    /// <summary>
    /// Generates local monotonic microsecond timestamps suitable for RTT echo
    /// measurement. Based on Stopwatch.GetTimestamp() for high-resolution,
    /// non-wall-clock time that is unaffected by system time adjustments.
    /// </summary>
    internal static class UcpTime
    {
        /// <summary>Baseline Stopwatch ticks at static initialization time.</summary>
        private static readonly long StartTicks = Stopwatch.GetTimestamp();

        /// <summary>Cached elapsed milliseconds, used to throttle microsecond updates.</summary>
        private static long _cachedElapsedMilliseconds;

        /// <summary>Cached microsecond value updated once per millisecond boundary.</summary>
        private static long _cachedMicroseconds;

        /// <summary>
        /// Returns the current monotonic time in microseconds, computed fresh
        /// on every call. Use when precision is critical.
        /// </summary>
        /// <returns>Microseconds since static initialization.</returns>
        public static long ReadStopwatchMicroseconds()
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks;
            return (elapsedTicks * UcpConstants.MICROS_PER_SECOND) / Stopwatch.Frequency;
        }

        /// <summary>
        /// Returns a cached monotonic time in microseconds, updated at most once
        /// per millisecond. This reduces the cost of frequent time reads in the
        /// protocol engine while keeping sub-microsecond precision.
        /// </summary>
        /// <returns>Microseconds since static initialization (cached).</returns>
        public static long NowMicroseconds()
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks;
            long elapsedMilliseconds = (elapsedTicks * UcpConstants.MICROS_PER_MILLI) / Stopwatch.Frequency;
            if (elapsedMilliseconds != Volatile.Read(ref _cachedElapsedMilliseconds))
            {
                // Only recompute the microsecond cache when the millisecond counter changes.
                Volatile.Write(ref _cachedMicroseconds, (elapsedTicks * UcpConstants.MICROS_PER_SECOND) / Stopwatch.Frequency);
                Volatile.Write(ref _cachedElapsedMilliseconds, elapsedMilliseconds);
            }

            return Volatile.Read(ref _cachedMicroseconds);
        }
    }
}
