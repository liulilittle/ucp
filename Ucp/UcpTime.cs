using System.Diagnostics;
using System.Threading;

namespace Ucp
{
    /// <summary>
    /// Generates local monotonic microsecond timestamps suitable for RTT echo measurement.
    /// </summary>
    internal static class UcpTime
    {
        private static readonly long StartTicks = Stopwatch.GetTimestamp();
        private static long _cachedElapsedMilliseconds;
        private static long _cachedMicroseconds;

        public static long ReadStopwatchMicroseconds()
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks;
            return (elapsedTicks * UcpConstants.MICROS_PER_SECOND) / Stopwatch.Frequency;
        }

        public static long NowMicroseconds()
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks;
            long elapsedMilliseconds = (elapsedTicks * UcpConstants.MICROS_PER_MILLI) / Stopwatch.Frequency;
            if (elapsedMilliseconds != Volatile.Read(ref _cachedElapsedMilliseconds))
            {
                Volatile.Write(ref _cachedMicroseconds, (elapsedTicks * UcpConstants.MICROS_PER_SECOND) / Stopwatch.Frequency);
                Volatile.Write(ref _cachedElapsedMilliseconds, elapsedMilliseconds);
            }

            return Volatile.Read(ref _cachedMicroseconds);
        }
    }
}
