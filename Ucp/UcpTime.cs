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
            return (elapsedTicks * 1000000L) / Stopwatch.Frequency;
        }

        public static long NowMicroseconds()
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks;
            long elapsedMilliseconds = (elapsedTicks * 1000L) / Stopwatch.Frequency;
            if (elapsedMilliseconds != Volatile.Read(ref _cachedElapsedMilliseconds))
            {
                Volatile.Write(ref _cachedMicroseconds, (elapsedTicks * 1000000L) / Stopwatch.Frequency);
                Volatile.Write(ref _cachedElapsedMilliseconds, elapsedMilliseconds);
            }

            return Volatile.Read(ref _cachedMicroseconds);
        }
    }
}
