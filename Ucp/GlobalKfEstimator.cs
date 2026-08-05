using System;
using System.Threading;

namespace Ucp
{
    public static class GlobalKfEstimator
    {
        private const long KCC_KF_OVERFLOW_GUARD = 1L << 31;
        private const int KCC_KF_INNOV_SHIFT = 10;
        private const int KCC_KF_VAR_SHIFT = 2 * KCC_KF_INNOV_SHIFT;
        private const int KCC_KF_CHI2_NUM = 384;
        private const int KCC_KF_CHI2_DEN = 100;
        private const int KCC_KF_Q_SHIFT = 20;
        private const int KCC_KF_STEADY_R_PCT = 5;
        private const int KCC_KF_STARTUP_R_PCT = 15;
        private const long KCC_INNOV_SQ_CAP = 3000000000L;
        private const int KCC_PCT_BASE = 100;

        private static long _globalBw;
        private static long _globalBwPeak;
        private static long _kfX;
        private static long _kfP;
        private static long _kfXSteady;
        private static int _active;

        private static readonly object _lock = new object();

        internal static void UpdateBw(long bw)
        {
            if (bw <= 0)
                return;

            Interlocked.Exchange(ref _globalBw, bw);
            Interlocked.Exchange(ref _active, 1);

            long peak = Volatile.Read(ref _globalBwPeak);
            while (bw > peak)
            {
                if (Interlocked.CompareExchange(ref _globalBwPeak, bw, peak) == peak)
                    break;
                peak = Volatile.Read(ref _globalBwPeak);
            }
        }

        internal static void KfUpdate(long z, int rPct, bool check)
        {
            if (z == 0)
                return;

            long r = z * (long)rPct / KCC_PCT_BASE;
            if (r > int.MaxValue)
                r = int.MaxValue;
            long R = r * r;

            long P, x;
            lock (_lock)
            {
                P = Volatile.Read(ref _kfP);
                x = Volatile.Read(ref _kfX);
            }

            P += (1L << KCC_KF_Q_SHIFT);

            if (Volatile.Read(ref _active) == 0)
            {
                lock (_lock)
                {
                    if (Volatile.Read(ref _active) == 0)
                    {
                        Volatile.Write(ref _kfX, z);
                        Volatile.Write(ref _kfP, Math.Max(R, 1L));
                        Volatile.Write(ref _active, 1);
                        return;
                    }
                    P = Volatile.Read(ref _kfP);
                    x = Volatile.Read(ref _kfX);
                }
                P += (1L << KCC_KF_Q_SHIFT);
            }

            if (check)
            {
                long delta = z - x;
                long nu2 = delta < 0 ? -delta : delta;
                long S = P + R;
                if (nu2 > KCC_INNOV_SQ_CAP)
                    nu2 = KCC_INNOV_SQ_CAP;

                nu2 = (nu2 >> KCC_KF_INNOV_SHIFT) * (nu2 >> KCC_KF_INNOV_SHIFT);
                S >>= KCC_KF_VAR_SHIFT;
                if (S > 0 && nu2 * KCC_KF_CHI2_DEN > (long)KCC_KF_CHI2_NUM * S)
                    return;
            }

            long Pcopy = P;
            long Rcopy = R;
            long xcopy = x;
            long zcopy = z;
            int shift = 0;

            long maxV = Pcopy + Rcopy;
            while (maxV >= KCC_KF_OVERFLOW_GUARD)
            {
                Pcopy >>= 1; Rcopy >>= 1; maxV >>= 1; shift++;
            }
            xcopy >>= shift;
            zcopy >>= shift;

            long denom = Pcopy + Rcopy;
            if (denom == 0) denom = 1;
            x = (xcopy * Rcopy + zcopy * Pcopy) / denom;
            P = Pcopy * Rcopy / denom;
            if (shift > 0)
            {
                x <<= shift;
                P <<= shift;
            }

            long q = 1L << KCC_KF_Q_SHIFT;
            if (P < q)
                P = q;

            if (x > 0)
            {
                lock (_lock)
                {
                    Volatile.Write(ref _kfX, x);
                    Volatile.Write(ref _kfP, P);
                }

                long oldSteady = Volatile.Read(ref _kfXSteady);
                while (x > oldSteady)
                {
                    if (Interlocked.CompareExchange(ref _kfXSteady, x, oldSteady) == oldSteady)
                        break;
                    oldSteady = Volatile.Read(ref _kfXSteady);
                }
            }
        }

        internal static void KfFeedProbeBw(long bw, bool firstRtt)
        {
            if (firstRtt)
                KfUpdate(bw, KCC_KF_STARTUP_R_PCT, false);
            else
                KfUpdate(bw, KCC_KF_STEADY_R_PCT, true);
        }

        internal static bool KfIsActive()
        {
            return Volatile.Read(ref _active) != 0;
        }

        internal static long GetKfXValue()
        {
            return Volatile.Read(ref _kfX);
        }

        internal static long GetKfInitBw(long discountNum, long discountDen, int cwndSegs, long srttUs, long rttMinFloorUs, int pacingInitGain, int bbrScale, int bwScale)
        {
            if (Volatile.Read(ref _active) == 0)
                return 0;

            long fair = Volatile.Read(ref _kfX);
            if (fair == 0)
                return 0;

            // Use only the current KF estimate, not the steady peak. The kernel
            // only applies the steady peak when kcc_kf_mode != 0 (tcp_kcc.c:
            // 5179-5184) and kf_mode defaults to off; the C++ port uses only
            // s_kfX (ucp_cc.cpp:1585). _kfXSteady is still maintained by
            // KfUpdate and Reset, but is not consulted here.

            long initBw = fair * Math.Max(discountNum, 0) / Math.Max(discountDen, 1);
            initBw = (initBw << bbrScale) / Math.Max(pacingInitGain, 1);

            long srtt = Math.Max(srttUs, rttMinFloorUs);
            if (srtt <= 0) srtt = 1;
            long localFloor = ((long)cwndSegs << bwScale) / srtt;
            if (initBw < localFloor)
                return 0;

            return Math.Min(initBw, int.MaxValue);
        }

        public static void Reset()
        {
            Interlocked.Exchange(ref _globalBw, 0);
            Interlocked.Exchange(ref _globalBwPeak, 0);
            Interlocked.Exchange(ref _kfX, 0);
            Interlocked.Exchange(ref _kfP, 0);
            Interlocked.Exchange(ref _kfXSteady, 0);
            Interlocked.Exchange(ref _active, 0);
        }
    }
}
