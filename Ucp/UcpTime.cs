using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Ucp
{

    internal static class UcpTime
    {
        [DllImport("winmm.dll", EntryPoint = "timeBeginPeriod")]
        private static extern uint Win32TimeBeginPeriod(uint uPeriod);

        [DllImport("winmm.dll", EntryPoint = "timeEndPeriod")]
        private static extern uint Win32TimeEndPeriod(uint uPeriod);

        static UcpTime()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    Win32TimeBeginPeriod(1);
                    AppDomain.CurrentDomain.ProcessExit += (_, _) => Win32TimeEndPeriod(1);
                }
            }
            catch { }
        }

        private static readonly long StartTicks = Stopwatch.GetTimestamp();

        private static long _cachedElapsedMilliseconds;

        private static long _cachedMicroseconds;

        public static long ReadStopwatchMicroseconds()
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks;

            return (long)((double)elapsedTicks / Stopwatch.Frequency * UcpConstants.MICROS_PER_SECOND);
        }

        public static long NowMicroseconds()
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - StartTicks;
            long elapsedMilliseconds = (elapsedTicks * UcpConstants.MICROS_PER_MILLI) / Stopwatch.Frequency;
            if (elapsedMilliseconds != Volatile.Read(ref _cachedElapsedMilliseconds))
            {
                Volatile.Write(ref _cachedMicroseconds, ReadStopwatchMicroseconds());
                Volatile.Write(ref _cachedElapsedMilliseconds, elapsedMilliseconds);
            }
            return Volatile.Read(ref _cachedMicroseconds);
        }
    }
}
