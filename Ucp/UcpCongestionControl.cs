// ============================================================================
//  PPP PRIVATE NETWORK(TM) X - Universal Communication Protocol (UCP)
//  UcpCongestionControl.cs - KCC 2.0 (Geodesic Congestion Control)
//
//  This is a faithful userspace port of the authoritative reference
//  implementation linux/tcp_kcc.c (MODULE_VERSION "2.0") into the UCP
//  protocol stack.  Every constant, state variable, and formula below
//  mirrors the C source of truth (linux/tcp_kcc.c, authoritative).
//
//  Design overview (KCC 2.0):
//    - 3-mode finite state machine: STARTUP -> DRAIN -> PROBE_BW.
//      There is NO PROBE_RTT mode: min_rtt tracking is handled
//      continuously by the geodesic estimator (G1/G3) and the
//      traditional min_rtt window with sticky fast-fall semantics.
//    - Geodesic estimator (G1/G2/G3): separates the RTT sample z into
//      propagation delay, queuing delay and noise using minimal-path
//      rules:
//        G1: innovation <= 0  -> x_est = min(x_est, z)     (instant drop)
//        G2: innovation >  0  -> x_est = min(x_est + 12.2% growth, z)
//        G3: dual-threshold path-increase detection (fast 6x @ 1.10x,
//            slow 7x @ 1.05x of min_rtt) with a one-shot <5ms lock.
//    - Bandwidth: sliding-window max (10-RTT minmax), LT-BW policer
//      detection, and the cross-connection Kalman filter (KF) floor.
//    - Pacing: single-step multiply: bw * gain >> 8 * 990000 >> 24
//      (1% haircut folded in), per-mode pacing gain cycling.
//    - cwnd: BDP target = ceil(bw * model_rtt * gain >> 8 >> 24) plus
//      ACK-aggregation compensation, TSO headroom, even rounding and a
//      probe bonus; slow-start growth until full_bw_reached, then
//      min(cwnd + acked, target).
//    - The UCP protocol layer supplies higher-fidelity signals than the
//      kernel TCP stack (byte-granular delivery samples, precise loss
//      events from NAK/SACK, EDT pacing feedback, peer window reports).
//
//  Thread-safety: the per-ACK pipeline (OnAck and friends) MUST be called
//  from the connection's single worker thread.  The externally visible
//  properties (CongestionWindowBytes, PacingRateBytesPerSecond,
//  EstimatedLossPercent) are read by the diagnostics path from other
//  threads, so they use Interlocked/Volatile accessors.
// ============================================================================

using System;
using System.Diagnostics;
using System.Threading;

namespace Ucp
{
    /// <summary>
    /// KCC 2.0 congestion control: geodesic RTT estimation, sliding-window
    /// max bandwidth, LT-BW policer detection, PROBE_BW gain cycling and
    /// BDP-driven cwnd targeting.  Mirrors linux/tcp_kcc.c ("2.0").
    /// </summary>
    internal sealed class UcpCongestionControl
    {
        // --------------------------------------------------------------------
        // Fixed-point scales (tcp_kcc.c:2934-2937, 3370-3374).
        // Bandwidth samples are stored as bytes-per-microsecond shifted left
        // by BW_SCALE (24); gains are stored in 1/256 units.
        // --------------------------------------------------------------------
        private const int BW_SCALE = UcpConstants.UCP_BW_SCALE;                    // 24
        private const long BW_UNIT = UcpConstants.UCP_BW_UNIT;                     // 1 << 24
        private const int BBR_SCALE = UcpConstants.UCP_GAIN_SCALE;                 // 8
        private const int BBR_UNIT = UcpConstants.UCP_GAIN_UNIT;                   // 256
        private const int KCC_SCALE_SHIFT = UcpConstants.UCP_KCC_SCALE_SHIFT;      // 10
        private const long KCC_SCALE = 1L << KCC_SCALE_SHIFT;                      // 1024 (KCC_SCALE)
        private const long MICROS_PER_SECOND = UcpConstants.MICROS_PER_SECOND;     // 1000000
        private const long MICROS_PER_MILLI = UcpConstants.MICROS_PER_MILLI;       // 1000
        private const long MIN_RTT_UNINIT = 0xFFFFFFFFL;                           // sentinel: kernel uses literal U32_MAX (tcp_kcc.c:5250)

        // --------------------------------------------------------------------
        // CA states (tcp_kcc.c bbr_ca_state equivalents).
        // --------------------------------------------------------------------
        private const int CA_OPEN = UcpConstants.UCP_CA_OPEN;                      // 0
        private const int CA_RECOVERY = UcpConstants.UCP_CA_RECOVERY;              // 2
        private const int CA_LOSS = UcpConstants.UCP_CA_LOSS;                      // 3

        // --------------------------------------------------------------------
        // Deterministic PRNG for PROBE_BW phase randomization (flow de-sync).
        // Mirrors kcc_random_below() from tcp_kcc.c.
        // --------------------------------------------------------------------
        private static int _rngSeed = Environment.TickCount;
        private static readonly ThreadLocal<Random> _tlsRng =
            new ThreadLocal<Random>(() => new Random(Interlocked.Increment(ref _rngSeed)));
        private static Random Rng => _tlsRng.Value;

        // --------------------------------------------------------------------
        // Compile-time gates (mirror the kernel module parameters
        // drain_and_or_mode=1, extra_acked_gain=1).  They are static readonly
        // (not const) so the gated bodies stay fully compiled and reachable
        // for static analysis; the Release JIT constant-folds and eliminates
        // them at runtime.  ECN is NOT a compile-time gate here: it is a
        // runtime toggle driven by UcpConfiguration.EcnEnabled (default off,
        // mirroring the kernel ecn_enable=0 module parameter).
        // --------------------------------------------------------------------
        private static readonly bool DrainAndOrMode = UcpConstants.UCP_DRAIN_AND_OR_MODE != 0;
        private static readonly bool ExtraAckedGainActive = UcpConstants.UCP_EXTRA_ACKED_GAIN_NUM > 0;

        // --------------------------------------------------------------------
        // Configuration-derived values.
        // --------------------------------------------------------------------
        private readonly UcpConfiguration _config;
        private readonly int _mss;
        private readonly int _maxCwndBytes;
        private readonly long _initialBw;
        private readonly long _maxPacingRate;
        private readonly int _initialCwndBytes;
        private readonly bool _enableDebugLog;
        private readonly bool _ecnEnabled;

        // --------------------------------------------------------------------
        // KCC 2.0 per-connection state (mirrors struct kcc / kcc_ext).
        // --------------------------------------------------------------------
        private long _minRttUs;                        // min_rtt_us (MIN_RTT_UNINIT until first sample)
        private long _minRttStampUs;                   // min_rtt_stamp

        private long _rttCnt;                          // round counter
        private long _nextRttDelivered;                // delivered at next round boundary
        private long _cycleMstampUs;                   // PROBE_BW cycle start mstamp

#pragma warning disable CS0414 // _idleRestart is reserved kernel state: written by the idle-restart path, read in future pacing extensions (mirrors C++ _kccIdleRestart)
        private bool _roundStart;                      // round_start flag
        private bool _idleRestart;                     // idle_restart flag (reserved kernel state; cleared on delivery)
#pragma warning restore CS0414
        private bool _packetConservation;              // packet_conservation flag
        private bool _ltIsSampling;                    // lt_is_sampling flag
        private int _ltRttCnt;                         // lt_rtt_cnt (12-bit in kernel)
        private int _minRttFastFallCnt;                // min_rtt_fast_fall_cnt (3-bit in kernel)
        private int _cycleIdx;                         // cycle_idx (3-bit in kernel)

        private bool _fullBwReached;                   // full_bw_reached flag
        private int _fullBwCnt;                        // full_bw_cnt (2-bit in kernel)
        private bool _hasSeenRtt;                      // has_seen_rtt flag
        private bool _ltUseBw;                         // lt_use_bw flag
        private int _pacingGain;                       // pacing_gain (10-bit in kernel)
        private int _cwndGain;                         // cwnd_gain (10-bit in kernel)
        private bool _locked;                          // one-shot <5ms path lock
        private int _confirmCnt;                       // G3 fast confirmation counter (3-bit)
        private int _confirmSlowCnt;                   // G3 slow confirmation counter (3-bit)
        private int _caState;                          // current CA state
        private int _prevCaState;                      // previous CA state

        private long _priorCwnd;                       // cwnd saved before recovery
        private long _fullBw;                          // full_bw (bottleneck estimate at exit)
        private long _ltBw;                            // lt_bw (long-term bandwidth)
        private long _ltLastDelivered;                 // lt_last_delivered
        private long _ltLastStampUs;                   // lt_last_stamp
        private long _ltLastLost;                      // lt_last_lost

        private long _xEst;                            // geodesic propagation-delay estimate (us * 1024)
        private long _pEst;                            // convergence proxy (p_est)
        private long _qDelayAvg;                       // queuing-delay EWMA (us)
        private int _sampleCnt;                        // geodesic sample counter
        private long _jitterEwma;                      // jitter EWMA (us)
        private long _mrUpdateRttCnt;                  // round counter of last min_rtt update
        private long _srttUs;                          // smoothed RTT, stored << SRTT_SHIFT (kernel semantics)

        private long _ecnEwma;                         // ECN EWMA (BBR_UNIT-scaled)
        private long _ecnCeMarks;                      // cumulative CE marks seen
        private long _lastDeliveredCe;                 // CE marks consumed by last EWMA update

        private long _ackEpochMstampUs;                // ACK-aggregation epoch start
        private readonly long[] _extraAcked = new long[2]; // dual-window extra-acked maxima (bytes)
        private long _ackEpochAcked;                   // bytes acked in current epoch
        private int _extraAckedWinRtts;                // rounds since window rotation
        private int _extraAckedWinIdx;                 // active window index

        private long _roundRttMin;                     // min RTT of current round (MIN_RTT_UNINIT sentinel)
        private long _prevRoundRttMin;                 // min RTT of previous round
        private long _drainEnterStampUs;               // drain_enter_stamp

        // --------------------------------------------------------------------
        // Delivery / loss accounting.
        // --------------------------------------------------------------------
        private long _lastAckUs;                       // mstamp of the last ACK
        private long _prevAckUs;                       // mstamp of the previous ACK
        private long _prevDelivered;                   // total delivered before the last ACK
        private long _totalDelivered;                  // cumulative bytes delivered
        private long _totalLost;                       // cumulative bytes lost
        private long _flightBytes;                     // bytes in flight at last ACK
        private bool _currSampleLosses;                // loss observed in the current round
        private long _ackLosses;                       // bytes lost reported by the last ACK

        // --------------------------------------------------------------------
        // App-limited / pacing / peer flow-control state.
        // --------------------------------------------------------------------
        private bool _isAppLimited;                    // app-limited flag
        private long _pacingWstampUs;                  // EDT write timestamp (us)
        private long _pacingNowUsEdt;                  // EDT "now" (us)
        private long _peerWindowBytes;                 // peer-advertised receive window (flow-control cap)

        // --------------------------------------------------------------------
        // Bandwidth ring buffer (sliding-window max over UCP_BW_RT_CYCLE_LEN
        // rounds) and the precomputed PROBE_BW gain table.
        // --------------------------------------------------------------------
        private struct BwSample
        {
            internal long Val;                         // BW_UNIT-scaled bandwidth sample
            internal long RoundCnt;                    // round counter of the sample
        }

        private readonly BwSample[] _bwSamples = new BwSample[UcpConstants.UCP_BW_RT_CYCLE_LEN];
        private int _bwSampleCur;
        private int _bwSampleCount;
        private long _maxBw;                           // current sliding-window max bandwidth

        private readonly int[] _cycleGainTable;

        // --------------------------------------------------------------------
        // Externally visible state (thread-safe accessors for the PCB and
        // diagnostics; the private fields below are worker-thread only).
        // --------------------------------------------------------------------
        private long _congestionWindowBytes;
        private double _pacingRateBytesPerSecond;
        private double _estimatedLossPercent;

        private UcpMode _mode = UcpMode.Startup;

        internal UcpMode Mode
        {
            get { return _mode; }
            private set { _mode = value; }
        }

        /// <summary>Minimum observed RTT in microseconds (0 until the first sample).</summary>
        internal long MinRttMicros
        {
            get { return _minRttUs == MIN_RTT_UNINIT ? 0 : _minRttUs; }
        }

        internal long CongestionWindowBytes
        {
            get { return Interlocked.Read(ref _congestionWindowBytes); }
            private set { Interlocked.Exchange(ref _congestionWindowBytes, value); }
        }

        internal double PacingRateBytesPerSecond
        {
            get { return Volatile.Read(ref _pacingRateBytesPerSecond); }
            private set { Volatile.Write(ref _pacingRateBytesPerSecond, value); }
        }

        internal double EstimatedLossPercent
        {
            get { return Volatile.Read(ref _estimatedLossPercent); }
            private set { Volatile.Write(ref _estimatedLossPercent, value); }
        }

        /// <summary>Cross-connection Kalman filter switch (KCC2.0 kf_enable).</summary>
        internal bool IsKfEnabled { get; set; } = false;

        // --------------------------------------------------------------------
        // Diagnostic / test accessors (map to the geodesic estimator state).
        // --------------------------------------------------------------------
        internal long SampleCnt { get { return _sampleCnt; } }

        internal long GeodesicXEst { get { return _xEst; } }
        internal long GeodesicPEst { get { return _pEst; } }
        internal long GeodesicQDelayAvg { get { return _qDelayAvg; } }
        internal long GeodesicJitterEwma { get { return _jitterEwma; } }
        internal int GeodesicSampleCnt { get { return _sampleCnt; } }

        internal long MaxBwBytesPerSec { get { return (_maxBw * MICROS_PER_SECOND) >> BW_SCALE; } }
        internal double BtlBwBytesPerSecond { get { return (double)((_maxBw * MICROS_PER_SECOND) >> BW_SCALE); } }
        internal int PacingGainUnits { get { return _pacingGain; } }
        internal int CwndGainUnits { get { return _cwndGain; } }
        internal double PacingGain { get { return (double)_pacingGain / BBR_UNIT; } }
        internal double CwndGain { get { return (double)_cwndGain / BBR_UNIT; } }
        internal bool FullBwReached { get { return _fullBwReached; } }
        internal long TotalDelivered { get { return _totalDelivered; } }
        internal bool IsLtUseBw { get { return _ltUseBw; } }
        internal long LtBwValue { get { return (_ltBw * MICROS_PER_SECOND) >> BW_SCALE; } }
        internal long EcnEwmaValue { get { return _ecnEwma; } }
        internal int ProbeBwCycleIdx { get { return _cycleIdx; } }

        // --------------------------------------------------------------------
        // Constructor.  Seeds all KCC 2.0 per-connection state.
        // --------------------------------------------------------------------
        internal UcpCongestionControl(UcpConfiguration config)
        {
            _config = config ?? new UcpConfiguration();
            _mss = _config.Mss > 0 ? _config.Mss : 1;
            _maxCwndBytes = _config.MaxCongestionWindowBytes;
            _initialBw = _config.InitialBandwidthBytesPerSecond;
            _maxPacingRate = _config.MaxPacingRateBytesPerSecond;
            _initialCwndBytes = _config.InitialCongestionWindowBytes > 0
                ? _config.InitialCongestionWindowBytes
                : UcpConstants.UCP_CWND_MIN_TARGET * _mss;
            _enableDebugLog = _config.EnableDebugLog;
            _ecnEnabled = _config.EcnEnabled;

            _mode = UcpMode.Startup;
            _minRttUs = MIN_RTT_UNINIT;
            _minRttStampUs = 0;
            _rttCnt = 0;
            _nextRttDelivered = 0;
            _cycleMstampUs = 0;
            _roundStart = false;
            _idleRestart = false;
            _packetConservation = false;
            _ltIsSampling = false;
            _ltRttCnt = 0;
            _minRttFastFallCnt = 0;
            _cycleIdx = 0;
            _fullBwReached = false;
            _fullBwCnt = 0;
            _hasSeenRtt = false;
            _ltUseBw = false;
            _pacingGain = UcpConstants.UCP_HIGH_GAIN;
            _cwndGain = UcpConstants.UCP_HIGH_GAIN;
            _locked = false;
            _confirmCnt = 0;
            _confirmSlowCnt = 0;
            _caState = CA_OPEN;
            _prevCaState = CA_OPEN;
            _priorCwnd = 0;
            _fullBw = 0;
            _ltBw = 0;
            _ltLastDelivered = 0;
            _ltLastStampUs = 0;
            _ltLastLost = 0;
            _xEst = 0;
            _pEst = UcpConstants.UCP_P_EST_INIT;
            _qDelayAvg = 0;
            _sampleCnt = 0;
            _jitterEwma = 0;
            _mrUpdateRttCnt = 0;
            _srttUs = 0;
            _ecnEwma = 0;
            _ecnCeMarks = 0;
            _lastDeliveredCe = 0;
            _ackEpochMstampUs = 0;
            _ackEpochAcked = 0;
            _extraAckedWinRtts = 0;
            _extraAckedWinIdx = 0;
            _extraAcked[0] = 0;
            _extraAcked[1] = 0;
            _roundRttMin = 0xFFFFFFFFL;
            _prevRoundRttMin = 0xFFFFFFFFL;
            _drainEnterStampUs = 0;
            _lastAckUs = 0;
            _prevAckUs = 0;
            _prevDelivered = 0;
            _totalDelivered = 0;
            _totalLost = 0;
            _flightBytes = 0;
            _currSampleLosses = false;
            _ackLosses = 0;
            _isAppLimited = false;
            _pacingWstampUs = 0;
            _pacingNowUsEdt = 0;
            _peerWindowBytes = 0;
            CongestionWindowBytes = _initialCwndBytes;
            PacingRateBytesPerSecond = (_initialBw > 0 ? _initialBw : MICROS_PER_SECOND) * UcpConstants.UCP_HIGH_GAIN / BBR_UNIT;
            if (_maxPacingRate > 0 && PacingRateBytesPerSecond > _maxPacingRate)
            {
                PacingRateBytesPerSecond = _maxPacingRate;
            }

            // Precompute the 256-slot gain table (8-phase cycle repeated):
            // {1.25, 0.75, 1.0 x6} in 1/256 units.
            _cycleGainTable = new int[UcpConstants.UCP_GAIN_SLOTS];
            for (int i = 0; i < UcpConstants.UCP_GAIN_SLOTS; i++)
            {
                int phase = i % UcpConstants.UCP_PROBE_BW_CYCLE_LEN;
                int num, den;
                if (phase == 0) { num = UcpConstants.UCP_GAIN_PROBE_PHASE_NUM; den = UcpConstants.UCP_GAIN_PROBE_PHASE_DEN; }
                else if (phase == 1) { num = UcpConstants.UCP_GAIN_DRAIN_PHASE_NUM; den = UcpConstants.UCP_GAIN_DRAIN_PHASE_DEN; }
                else { num = UcpConstants.UCP_GAIN_CRUISE_PHASE_NUM; den = UcpConstants.UCP_GAIN_CRUISE_PHASE_DEN; }
                long val = (long)BBR_UNIT * num / den;
                _cycleGainTable[i] = val > UcpConstants.UCP_GAIN_MAX ? UcpConstants.UCP_GAIN_MAX : (int)val;
            }

            // Seed the sliding-window max with the configured initial bandwidth
            // estimate until the first real delivery sample arrives.
            long initBw = _initialBw > 0
                ? (_initialBw << BW_SCALE) / MICROS_PER_SECOND
                : BW_UNIT;
            if (initBw <= 0) initBw = BW_UNIT;
            BwUpdate(initBw, 0);
            _maxBw = BwMax();

            // KF fast-start: if the cross-connection filter has history, seed
            // the initial cwnd from the discounted fair-share bandwidth
            // (mirrors kcc_init / kcc_kf_get_init_bw).  The peer-declared
            // window acts as the flow-control send cap — the fixed initial
            // cwnd is NOT an upper bound on the first send.
            if (IsKfEnabled)
            {
                long kfInitBw = GlobalKfEstimator.GetKfInitBw(
                    UcpConstants.UCP_KF_DISCOUNT_NUM,
                    UcpConstants.UCP_KF_DISCOUNT_DEN,
                    (int)(CongestionWindowBytes / _mss),
                    _srttUs >> UcpConstants.UCP_SRTT_SHIFT,
                    UcpConstants.UCP_RTT_MIN_FLOOR_US,
                    UcpConstants.UCP_PACING_INIT_GAIN,
                    BBR_SCALE,
                    BW_SCALE);
                if (kfInitBw > 0)
                {
                    if (kfInitBw > int.MaxValue) kfInitBw = int.MaxValue;
                    BwUpdate(kfInitBw, _rttCnt);
                    _maxBw = BwMax();
                    PacingRateBytesPerSecond = (kfInitBw * MICROS_PER_SECOND) >> BW_SCALE;
                    if (_maxPacingRate > 0 && PacingRateBytesPerSecond > _maxPacingRate)
                    {
                        PacingRateBytesPerSecond = _maxPacingRate;
                    }
                    long lo = Math.Max(CongestionWindowBytes / _mss, 1);
                    long initCwndSegs = Bdp(kfInitBw, BBR_UNIT) / _mss;
                    long peerCapSegs = UcpConstants.UCP_KF_CWND_SEGS_MAX;
                    if (_peerWindowBytes > 0)
                    {
                        peerCapSegs = Math.Min(peerCapSegs, Math.Max(1, _peerWindowBytes / _mss));
                    }
                    initCwndSegs = Math.Min(Math.Max(initCwndSegs, lo), peerCapSegs);
                    CongestionWindowBytes = initCwndSegs * _mss;
                    _hasSeenRtt = true;
                }
            }
        }

        // --------------------------------------------------------------------
        // SetPeerWindow — flow-control window from the peer.
        //
        // The peer's advertised receive window is the flow-control cap: the
        // effective send window is min(cwnd, peerWindow).  During STARTUP
        // (before full bandwidth is reached) the cwnd is raised toward the
        // peer window so the first send is not artificially limited to the
        // fixed initial cwnd; after full bandwidth, cwnd is BDP-driven and
        // the peer window only ever caps it downward.  The cap is bounded by
        // KCC_KF_CWND_SEGS_MAX segments (peer-window flow control is a UCP
        // concept; KF cwnd cap mirrors tcp_kcc.c kcc_kf_cwnd_segs_max).
        // --------------------------------------------------------------------
        internal void SetPeerWindow(long windowBytes)
        {
            if (windowBytes <= 0) return;
            long bounded = Math.Min(windowBytes, (long)UcpConstants.UCP_KF_CWND_SEGS_MAX * _mss);
            if (bounded < _mss) bounded = _mss;
            _peerWindowBytes = bounded;
            if (CongestionWindowBytes > bounded)
            {
                CongestionWindowBytes = bounded;
            }
            else if (_mode == UcpMode.Startup && !_fullBwReached)
            {
                CongestionWindowBytes = bounded;
            }
        }

        // --------------------------------------------------------------------
        // OnAck — per-ACK pipeline entry (mirrors kcc_main).
        //   1. Update the model (bw, ECN, ACK aggregation, cycle, full-bw,
        //      drain, min_rtt, gains).
        //   2. Feed the cross-connection KF during PROBE_BW round starts.
        //   3. Apply cwnd constraints (ECN backoff).
        //   4. Set pacing rate and cwnd.
        // --------------------------------------------------------------------
        internal void OnAck(long nowMicros, long deliveredBytes, long sampleRttMicros, long flightBytes)
        {
            _flightBytes = flightBytes;
            if (deliveredBytes < 0) deliveredBytes = 0;
            long acked = deliveredBytes;
            long rttUs = sampleRttMicros;

            _prevDelivered = _totalDelivered;
            _totalDelivered += acked;
            _prevAckUs = _lastAckUs;
            _lastAckUs = nowMicros;

            // SRTT EWMA (7/8) with kernel tcp semantics: srtt is stored
            // left-shifted by SRTT_SHIFT (3) and blended with the shifted
            // sample so that srtt >> 3 yields the smoothed RTT in us.
            if (rttUs > 0)
            {
                if (_srttUs == 0)
                {
                    _srttUs = rttUs << UcpConstants.UCP_SRTT_SHIFT;
                    if (_minRttUs == MIN_RTT_UNINIT)
                    {
                        _minRttUs = rttUs;
                        _minRttStampUs = nowMicros;
                    }
                }
                else
                {
                    _srttUs = (_srttUs * 7 + (rttUs << UcpConstants.UCP_SRTT_SHIFT)) / 8;
                }
            }

            // Snapshot and clear the losses attributed to this ACK.
            long ackLosses = _ackLosses;
            _ackLosses = 0;

            UpdateModel(nowMicros, acked, rttUs, acked, flightBytes);

            // KF feed at PROBE_BW round starts with cruise gain (mirrors the
            // kcc_kf_update call inside kcc_main: startup R pct + no chi2
            // check on the first round, steady R pct + chi2 check after).
            if (IsKfEnabled && _roundStart && _mode == UcpMode.ProbeBw &&
                _pacingGain == BBR_UNIT && acked > 0 && _prevAckUs > 0)
            {
                long intervalUs = Math.Max(1L, nowMicros - _prevAckUs);
                KfFeedProbeBwSample(acked, intervalUs);
            }

            ApplyCwndConstraints();

            long pacingBw = _ltUseBw && _ltBw > 0 ? _ltBw : _maxBw;
            SetPacingRate(pacingBw, _pacingGain);
            SetCwnd(pacingBw, _cwndGain, acked, flightBytes, ackLosses);
        }

        // --------------------------------------------------------------------
        // UpdateModel — the estimation pipeline (mirrors kcc_update_model).
        // Ordering is load-bearing: bandwidth before drain, cycle advance
        // before gains, min_rtt before gain assignment.
        // --------------------------------------------------------------------
        private void UpdateModel(long nowMicros, long delivered, long rttUs, long acked, long flightBytes)
        {
            // Bandwidth sample: delivered bytes per microsecond, BW_UNIT-scaled.
            long intervalUs = nowMicros - _prevAckUs;
            if (intervalUs < 0) intervalUs = 0;
            long bw = 0;
            if (delivered > 0 && intervalUs > 0)
            {
                ulong d = (ulong)delivered;
                if (d < (ulong.MaxValue >> BW_SCALE))
                {
                    bw = (long)((d << BW_SCALE) / (ulong)intervalUs);
                }
            }
            UpdateBw(nowMicros, bw, delivered, intervalUs, _prevDelivered);

            // Fallback: keep the configured initial bandwidth until a real sample.
            if (_maxBw <= 0)
            {
                long initBw = _initialBw > 0
                    ? (_initialBw << BW_SCALE) / MICROS_PER_SECOND
                    : BW_UNIT;
                if (initBw <= 0) initBw = BW_UNIT;
                BwUpdate(initBw, _rttCnt);
                _maxBw = BwMax();
            }

            UpdateEcnEwma(delivered, 0);
            UpdateAckAggregation(nowMicros, delivered, acked, intervalUs);
            UpdateCyclePhase();
            CheckFullBwReached();
            CheckDrain(nowMicros);
            if (rttUs > 0)
            {
                UpdateMinRtt(rttUs, nowMicros, delivered);
            }

            // Per-round min RTT filter (round_rtt_min).
            if (rttUs >= 0 && _roundStart)
            {
                if (rttUs < _roundRttMin) _roundRttMin = rttUs;
            }

            // Assign gains per mode (mirrors kcc_update_gains).
            switch (_mode)
            {
                case UcpMode.Startup:
                    _pacingGain = UcpConstants.UCP_HIGH_GAIN;
                    _cwndGain = UcpConstants.UCP_HIGH_GAIN;
                    break;
                case UcpMode.Drain:
                    _pacingGain = UcpConstants.UCP_DRAIN_GAIN;
                    _cwndGain = UcpConstants.UCP_HIGH_GAIN;
                    break;
                case UcpMode.ProbeBw:
                    _pacingGain = _ltUseBw ? BBR_UNIT : GetCyclePacingGain();
                    _cwndGain = UcpConstants.UCP_CWND_GAIN;
                    break;
                default:
                    break;
            }
        }

        // --------------------------------------------------------------------
        // UpdateBw — round boundary tracking + sliding-window max bandwidth.
        // Mirrors kcc_update_bw.  A new round begins when delivered reaches
        // the next_rtt_delivered watermark.
        // --------------------------------------------------------------------
        private void UpdateBw(long nowMicros, long bw, long delivered, long intervalUs, long priorDelivered)
        {
            _roundStart = false;
            if (delivered < 0 || intervalUs <= 0)
            {
                return;
            }

            // Round boundary: prior_delivered >= next_rtt_delivered triggers
            // a new round and resets the per-round loss flag.
            if (!(priorDelivered < _nextRttDelivered))
            {
                _nextRttDelivered = _totalDelivered;
                _rttCnt++;
                _roundStart = true;
                _packetConservation = false;
                _currSampleLosses = false;
                _prevRoundRttMin = _roundRttMin;
                _roundRttMin = 0xFFFFFFFFL;
            }

            UpdateLtBw(nowMicros, 0);

            // Sliding-window max: only update when not app-limited or when
            // the sample is at least the current max (mirrors minmax_running_max).
            long prevMax = BwMax();
            if (!_isAppLimited || bw >= prevMax)
            {
                BwUpdate(bw, _rttCnt);
                _maxBw = BwMax();
            }
        }

        // --------------------------------------------------------------------
        // BwUpdate / BwMax — 10-slot ring buffer sliding-window max.  Samples
        // older than UCP_BW_RT_CYCLE_LEN rounds are treated as stale.
        // --------------------------------------------------------------------
        private void BwUpdate(long bw, long rttCnt)
        {
            if (bw <= 0) return;
            if (_bwSampleCount == 0)
            {
                _bwSampleCount = 1;
                _bwSampleCur = 0;
                _bwSamples[0].Val = bw;
                _bwSamples[0].RoundCnt = rttCnt;
                return;
            }
            int next = (_bwSampleCur + 1) % UcpConstants.UCP_BW_RT_CYCLE_LEN;
            _bwSamples[next].Val = bw;
            _bwSamples[next].RoundCnt = rttCnt;
            _bwSampleCur = next;
            if (_bwSampleCount < UcpConstants.UCP_BW_RT_CYCLE_LEN) _bwSampleCount++;
        }

        private long BwMax()
        {
            if (_bwSampleCount == 0) return 0;
            long result = 0;
            for (int i = 0; i < _bwSampleCount; i++)
            {
                if (_rttCnt - _bwSamples[i].RoundCnt >= UcpConstants.UCP_BW_RT_CYCLE_LEN)
                {
                    continue;
                }
                if (_bwSamples[i].Val > result) result = _bwSamples[i].Val;
            }
            if (result == 0 && _bwSampleCount > 0)
            {
                for (int i = 0; i < _bwSampleCount; i++)
                {
                    if (_bwSamples[i].Val > result) result = _bwSamples[i].Val;
                }
            }
            return result;
        }

        // --------------------------------------------------------------------
        // GeodesicUpdate — the G1/G2 estimator (mirrors kcc_update).
        // See linux/tcp_kcc.c for the exact arithmetic:
        //   G1: innovation <= 0 -> x_est = min(x_est, z)       (instant drop)
        //   G2: innovation >  0 -> x_est = min(x_est + 12.2%, z) (bounded growth)
        //   staleness pull-back after 128 rounds without a min_rtt update
        //   jitter EWMA (7/8) capped at max(min_rtt, 500000)
        //   qdelay EWMA (7/8) of max(0, z - x_est)
        //   p_est decay/growth as a convergence proxy.
        // --------------------------------------------------------------------
        private void GeodesicUpdate(long rttUs)
        {
            long rtt = Math.Max(rttUs, UcpConstants.UCP_RTT_MIN_FLOOR_US);
            long z = rtt << KCC_SCALE_SHIFT;

            if (_sampleCnt == 0)
            {
                _xEst = z;
                _pEst = UcpConstants.UCP_P_EST_INIT;
                _qDelayAvg = 0;
                _jitterEwma = Math.Max(rtt >> UcpConstants.UCP_JITTER_SEED_SHIFT, 1);
                _sampleCnt = 1;
                return;
            }

            // Cold-start ceiling: clamp x_est to min_rtt on the second sample
            // to prevent overshoot from an inflated initial sample.
            if (_sampleCnt == 1 && _minRttUs != MIN_RTT_UNINIT && _minRttUs > 0)
            {
                long ceiling = _minRttUs << KCC_SCALE_SHIFT;
                if (_xEst > ceiling) _xEst = ceiling;
            }

            long innovation = z - _xEst;
            long absInnov = innovation >= 0 ? innovation : -innovation;

            // G1: instant downward absorption (censored min).
            if (innovation <= 0)
            {
                _xEst = Math.Min(_xEst, z);
            }
            // G2: bounded geometric growth capped at the observation.
            else
            {
                long growth = _xEst * UcpConstants.UCP_G2_GROWTH_NUM / UcpConstants.UCP_G2_GROWTH_DEN;
                long newX = _xEst + growth;
                if (newX < _xEst) newX = long.MaxValue;
                _xEst = Math.Min(newX, z);
            }

            // Staleness pull-back: after 128 rounds without a min_rtt update
            // and x_est within 1.10x of min_rtt, pull back to 95% and
            // restart the window.
            if (_minRttUs != MIN_RTT_UNINIT &&
                _rttCnt - _mrUpdateRttCnt >= UcpConstants.UCP_STALENESS_RNDS)
            {
                long mrScaled = _minRttUs << KCC_SCALE_SHIFT;
                if (_xEst <= mrScaled * UcpConstants.UCP_G3_FAST_TH_NUM / UcpConstants.UCP_G3_FAST_TH_DEN)
                {
                    _xEst = mrScaled * UcpConstants.UCP_PD_NOISE_GATE_NUM / UcpConstants.UCP_PD_NOISE_GATE_DEN;
                    _mrUpdateRttCnt = _rttCnt;
                }
            }

            // Jitter EWMA (7/8), capped at max(min_rtt, 500000).
            {
                long rawJitter = absInnov >> KCC_SCALE_SHIFT;
                _jitterEwma = _sampleCnt > 1
                    ? (_jitterEwma * UcpConstants.UCP_EWMA_JITTER_NUM + rawJitter) / UcpConstants.UCP_EWMA_JITTER_DEN
                    : rawJitter;
                long jitterCap = _minRttUs != MIN_RTT_UNINIT
                    ? Math.Max(_minRttUs, UcpConstants.UCP_RTT_SAMPLE_MAX_US)
                    : UcpConstants.UCP_RTT_SAMPLE_MAX_US;
                if (_jitterEwma > jitterCap) _jitterEwma = jitterCap;
            }

            // Queuing-delay EWMA (7/8): max(0, z - x_est) >> 10.
            {
                long qdelayInstant = z > _xEst ? (z - _xEst) >> KCC_SCALE_SHIFT : 0;
                if (_sampleCnt == 1)
                {
                    _qDelayAvg = qdelayInstant;
                }
                else
                {
                    _qDelayAvg = (_qDelayAvg * UcpConstants.UCP_EWMA_QDELAY_NUM + qdelayInstant) / UcpConstants.UCP_EWMA_QDELAY_DEN;
                }
            }

            if (_sampleCnt < int.MaxValue) _sampleCnt++;

            // Convergence proxy p_est: decay toward the floor when x_est is
            // at/below 1.05x min_rtt; growth toward init when above 1.10x.
            if (_sampleCnt >= UcpConstants.UCP_MIN_SAMPLES)
            {
                long pFloor = UcpConstants.UCP_P_EST_FLOOR;
                long xEstUs = _xEst >> KCC_SCALE_SHIFT;
                if (xEstUs <= _minRttUs * UcpConstants.UCP_G3_SLOW_TH_NUM / UcpConstants.UCP_G3_SLOW_TH_DEN &&
                    _confirmCnt == 0 && _confirmSlowCnt == 0)
                {
                    long delta = _pEst > pFloor ? (_pEst - pFloor) >> UcpConstants.UCP_P_EST_DECAY_SHIFT : 0;
                    if (_pEst > pFloor + delta)
                    {
                        _pEst -= Math.Max(delta, 1);
                    }
                }
                else if (xEstUs > _minRttUs * UcpConstants.UCP_G3_FAST_TH_NUM / UcpConstants.UCP_G3_FAST_TH_DEN)
                {
                    long delta = _pEst < UcpConstants.UCP_P_EST_INIT
                        ? (UcpConstants.UCP_P_EST_INIT - _pEst) >> UcpConstants.UCP_P_EST_GROWTH_SHIFT
                        : 0;
                    if (_pEst + delta < UcpConstants.UCP_P_EST_MAX)
                    {
                        _pEst += Math.Max(delta, 1);
                    }
                }
            }
        }

        // --------------------------------------------------------------------
        // UpdateMinRtt — min_rtt maintenance with G3 detection, the one-shot
        // <5ms lock, sticky fast-fall, the SRTT guard and geodesic takeover
        // (mirrors kcc_update_min_rtt).
        // --------------------------------------------------------------------
        private void UpdateMinRtt(long rttUs, long nowMicros, long delivered)
        {
            if (rttUs <= 0) return;
            bool minFallCntIncrThisAck = false;
            long rtt = rttUs;
            long mrSnapshot = _minRttUs;

            GeodesicUpdate(rttUs);

            // One-shot lock: any sample below 5ms proves a fiber path where
            // G3 step detection is physically impossible; lock forever.
            if (rtt < UcpConstants.UCP_LOCK_THRESH_US)
            {
                _locked = true;
            }

            // G3 dual-threshold consecutive-event detection.  When min_rtt is
            // at least 7.5ms both the fast (1.10x) and slow (1.05x) paths are
            // monitored; in the 5ms..7.5ms gray zone only the fast path runs.
            if (!_locked && _minRttUs >= UcpConstants.UCP_FAST_ONLY_THRESH_US)
            {
                if (_xEst >= _minRttUs * KCC_SCALE * UcpConstants.UCP_G3_FAST_TH_NUM / UcpConstants.UCP_G3_FAST_TH_DEN)
                {
                    if (_confirmCnt < UcpConstants.UCP_BITFIELD_3BIT_MAX) _confirmCnt++;
                }
                else
                {
                    _confirmCnt = 0;
                }
                if (_xEst >= _minRttUs * KCC_SCALE * UcpConstants.UCP_G3_SLOW_TH_NUM / UcpConstants.UCP_G3_SLOW_TH_DEN)
                {
                    if (_confirmSlowCnt < UcpConstants.UCP_BITFIELD_3BIT_MAX) _confirmSlowCnt++;
                }
                else
                {
                    _confirmSlowCnt = 0;
                }
            }
            else if (!_locked && _minRttUs >= UcpConstants.UCP_LOCK_THRESH_US)
            {
                if (_xEst >= _minRttUs * KCC_SCALE * UcpConstants.UCP_G3_FAST_TH_NUM / UcpConstants.UCP_G3_FAST_TH_DEN)
                {
                    if (_confirmCnt < UcpConstants.UCP_BITFIELD_3BIT_MAX) _confirmCnt++;
                }
                else
                {
                    _confirmCnt = 0;
                }
                _confirmSlowCnt = 0;
            }
            else
            {
                _confirmCnt = 0;
                _confirmSlowCnt = 0;
            }

            // Baseline return: x_est at/below min_rtt resets both counters.
            if (_xEst <= _minRttUs * KCC_SCALE)
            {
                _confirmCnt = 0;
                _confirmSlowCnt = 0;
            }

            // Fast path confirmed (6 consecutive) -> min_rtt = x_est.
            if (_confirmCnt >= UcpConstants.UCP_G3_FAST_CNT)
            {
                _minRttUs = _xEst >> KCC_SCALE_SHIFT;
                _minRttStampUs = nowMicros;
                _confirmCnt = 0;
                _confirmSlowCnt = 0;
                _pEst = UcpConstants.UCP_P_EST_INIT;
                _mrUpdateRttCnt = _rttCnt;
            }
            // Slow path confirmed (7 consecutive) -> min_rtt = x_est.
            else if (_confirmSlowCnt >= UcpConstants.UCP_G3_SLOW_CNT)
            {
                _minRttUs = _xEst >> KCC_SCALE_SHIFT;
                _minRttStampUs = nowMicros;
                _confirmCnt = 0;
                _confirmSlowCnt = 0;
                _pEst = UcpConstants.UCP_P_EST_INIT;
                _mrUpdateRttCnt = _rttCnt;
            }

            // While any G3 counter is non-zero, freeze the traditional min_rtt
            // manipulation to protect the threshold baseline.
            if (_confirmCnt > 0 || _confirmSlowCnt > 0)
            {
                return;
            }

            // Traditional min_rtt: fast fall (/4), sticky fall (75%), direct.
            if (rtt <= _minRttUs)
            {
                rtt = Math.Max(rtt, UcpConstants.UCP_RTT_MIN_FLOOR_US);
                if (rtt < _minRttUs * UcpConstants.UCP_MINRTT_STICKY_NUM / UcpConstants.UCP_MINRTT_STICKY_DEN)
                {
                    if (rtt < _minRttUs / UcpConstants.UCP_MINRTT_FAST_FALL_DIV)
                    {
                        _minRttUs = rtt;
                        _minRttFastFallCnt = 0;
                    }
                    else
                    {
                        _minRttFastFallCnt = Math.Min(_minRttFastFallCnt + 1, UcpConstants.UCP_BITFIELD_3BIT_MAX);
                        minFallCntIncrThisAck = true;
                        if (_minRttFastFallCnt >= UcpConstants.UCP_MINRTT_FAST_FALL_CNT)
                        {
                            _minRttUs = rtt;
                            _minRttFastFallCnt = 0;
                        }
                        else if (_roundStart)
                        {
                            _minRttUs = Math.Max(UcpConstants.UCP_RTT_MIN_FLOOR_US,
                                _minRttUs * UcpConstants.UCP_MINRTT_STICKY_NUM / UcpConstants.UCP_MINRTT_STICKY_DEN);
                        }
                    }
                }
                else
                {
                    _minRttUs = rtt;
                    _minRttFastFallCnt = 0;
                }
                _minRttStampUs = nowMicros;
            }
            else if (rtt >= _minRttUs)
            {
                _minRttFastFallCnt = 0;
            }

            // SRTT guard: if SRTT < min_rtt * 90/100, override min_rtt.
            if (_srttUs > 0 && _minRttUs > 0)
            {
                long srttShifted = Math.Max(_srttUs >> UcpConstants.UCP_SRTT_SHIFT, 1);
                if (srttShifted < _minRttUs * UcpConstants.UCP_MINRTT_SRTT_GUARD_NUM / UcpConstants.UCP_MINRTT_SRTT_GUARD_DEN)
                {
                    _minRttUs = srttShifted;
                    _minRttStampUs = nowMicros;
                }
            }

            if (delivered > 0)
            {
                _idleRestart = false;
            }

            // Geodesic takeover: x_est reliably below min_rtt (95% gate)
            // pulls min_rtt down using the same fast-fall accumulator.
            if (_xEst > 0 && _sampleCnt >= UcpConstants.UCP_MIN_SAMPLES)
            {
                long krtt = _xEst >> KCC_SCALE_SHIFT;
                if (krtt < _minRttUs && krtt < _minRttUs * UcpConstants.UCP_PD_NOISE_GATE_NUM / UcpConstants.UCP_PD_NOISE_GATE_DEN)
                {
                    if (!minFallCntIncrThisAck)
                    {
                        _minRttFastFallCnt = Math.Min(_minRttFastFallCnt + 1, UcpConstants.UCP_BITFIELD_3BIT_MAX);
                        if (_minRttFastFallCnt >= UcpConstants.UCP_MINRTT_FAST_FALL_CNT)
                        {
                            _minRttUs = krtt;
                            _minRttFastFallCnt = 0;
                            _minRttStampUs = nowMicros;
                            _mrUpdateRttCnt = _rttCnt;
                        }
                    }
                }
                else
                {
                    _minRttFastFallCnt = 0;
                }
            }

            if (_minRttUs != mrSnapshot)
            {
                _mrUpdateRttCnt = _rttCnt;
            }
        }

        // --------------------------------------------------------------------
        // SetPacingRate — single-step rate computation (mirrors
        // kcc_rate_bytes_per_sec in byte space):
        //   rate = bw * gain >> 8 * 990000 >> 24
        // The kernel multiplies bw (packets/µs) by mss first; in this
        // byte-oriented port bw is already bytes/µs, so the mss factor is
        // folded into the bandwidth sample and must NOT be applied again.
        // Monotonic in STARTUP, always applies after full_bw_reached.
        // --------------------------------------------------------------------
        private void SetPacingRate(long bw, int gain)
        {
            if (bw <= 0) bw = BW_UNIT;
            long rate = (bw * gain) >> BBR_SCALE;
            rate = (rate * 990000L) >> BW_SCALE;
            if (_maxPacingRate > 0 && rate > _maxPacingRate) rate = _maxPacingRate;

            // Boot-rate lift on first RTT: high_gain * cwnd / RTT.
            // The lifted rate must still respect the configured pacing ceiling.
            if (!_hasSeenRtt && _srttUs > 0)
            {
                _hasSeenRtt = true;
                long rttUs = Math.Max(_srttUs >> UcpConstants.UCP_SRTT_SHIFT, 1);
                long cwndSegs = CongestionWindowBytes / _mss;
                long bdpBw = (cwndSegs * BW_UNIT) / rttUs;
                long bootRate = bdpBw * _mss;
                bootRate = (bootRate * UcpConstants.UCP_HIGH_GAIN) >> BBR_SCALE;
                bootRate = (bootRate * 990000L) >> BW_SCALE;
                if (_maxPacingRate > 0 && bootRate > _maxPacingRate) bootRate = _maxPacingRate;
                if (bootRate > rate) rate = bootRate;
            }

            // KF floor in STARTUP: never pace below 50% of the KF fair-share.
            // kfBw is byte-granular (from the cross-connection KF), so no mss
            // factor applies (mirrors tcp_kcc.c kcc_set_pacing_rate KF path).
            if (IsKfEnabled && !_fullBwReached && _mode == UcpMode.Startup)
            {
                long kfBw = GlobalKfEstimator.GetKfXValue();
                if (kfBw > 0)
                {
                    long initBw = kfBw * UcpConstants.UCP_KF_DISCOUNT_NUM / UcpConstants.UCP_KF_DISCOUNT_DEN;
                    initBw = (initBw << BBR_SCALE) / UcpConstants.UCP_HIGH_GAIN;
                    long kfRate = (initBw * 990000L) >> BW_SCALE;
                    if (kfRate > rate) rate = kfRate;
                }
            }

            if (_fullBwReached)
            {
                PacingRateBytesPerSecond = rate;
            }
            else if (rate > PacingRateBytesPerSecond)
            {
                PacingRateBytesPerSecond = rate;
            }
        }

        // --------------------------------------------------------------------
        // SetCwnd — cwnd update per kcc_set_cwnd: loss deduction, recovery
        // conservation, BDP target, slow-start growth, floor at 4 segments.
        // --------------------------------------------------------------------
        private void SetCwnd(long bw, int gain, long acked, long flightBytes, long losses)
        {
            long cwnd = CongestionWindowBytes;
            int caState = _caState;
            if (acked <= 0)
            {
                goto done_cwnd;
            }

            // Loss deduction (mirrors kcc_set_cwnd_to_recover_or_restore).
            if (losses > 0)
            {
                if (cwnd > losses)
                {
                    cwnd -= losses;
                }
                else
                {
                    cwnd = UcpConstants.UCP_CWND_ABSOLUTE_MIN * _mss;
                }
            }

            // Recovery transitions: entering recovery pins the cwnd to
            // inflight + acked (packet conservation); leaving recovery
            // restores at least the prior cwnd.
            if (caState == CA_RECOVERY && _prevCaState != CA_RECOVERY)
            {
                _packetConservation = true;
                cwnd = flightBytes + acked;
                _nextRttDelivered = _totalDelivered;
                _prevCaState = caState;
            }
            else if (_prevCaState >= CA_RECOVERY && caState < CA_RECOVERY)
            {
                cwnd = Math.Max(cwnd, _priorCwnd);
                _packetConservation = false;
                _prevCaState = caState;
            }

            if (_packetConservation)
            {
                cwnd = Math.Max(cwnd, flightBytes + acked);
                // Exit recovery once the conservation constraint is met: a
                // forward ACK that acknowledges everything that was in flight
                // (flightBytes + acked <= cwnd) proves the recovery window has
                // drained. The kernel reference exits TCP_CA_Recovery via the
                // TCP state machine; UCP's PCB does not drive CA state, so the
                // CC must self-exit here or cwnd stays pinned at flight size
                // forever (throughput collapse under sustained loss).
                if (acked > 0 && flightBytes + acked <= cwnd)
                {
                    _packetConservation = false;
                    _prevCaState = CA_OPEN;
                    _caState = CA_OPEN;
                    cwnd = Math.Max(cwnd, _priorCwnd);
                }
                else
                {
                    goto done_cwnd;
                }
            }

            if (bw > 0)
            {
                long target = Bdp(bw, gain);

                // ACK aggregation compensation, only when min_rtt >= 7.5ms
                // (single compensation; the KCC 1.0 confidence FSM layer was
                // a structural error and is removed in KCC 2.0).
                if (_minRttUs >= UcpConstants.UCP_FAST_ONLY_THRESH_US)
                {
                    long aggBase = AckAggCwndBonus(bw);
                    if (aggBase > 0)
                    {
                        target += aggBase;
                    }
                }

                // TSO/GSO headroom + even rounding + probe bonus.
                target += (long)UcpConstants.UCP_TSO_HEADROOM_MULT * TsoSegsGoal() * _mss;
                target = (target + 1) & ~1L;
                if (_mode == UcpMode.ProbeBw && _cycleIdx == 0)
                {
                    target += (long)UcpConstants.UCP_PROBE_CWND_BONUS * _mss;
                }

                if (_fullBwReached)
                {
                    cwnd = Math.Min(cwnd + acked, target);
                }
                else
                {
                    // Slow start: grow by acked while below the BDP target, or while
                    // fewer than INITIAL_CWND_PACKETS (10) packets have been delivered
                    // in total (mirrors tcp_kcc.c:4050 "cwnd < target ||
                    // tp->delivered < TCP_INIT_CWND"). The peer-declared window
                    // (flow control) remains the send cap via SetPeerWindow and the
                    // PCB send gate; this latch only guarantees initial growth.
                    if (cwnd < target || (_totalDelivered / _mss) < UcpConstants.INITIAL_CWND_PACKETS)
                    {
                        cwnd += acked;
                    }
                }
            }

        done_cwnd:
            if (_maxCwndBytes > 0 && cwnd > _maxCwndBytes)
            {
                cwnd = _maxCwndBytes;
            }
            if (!_packetConservation)
            {
                cwnd = Math.Max(cwnd, (long)UcpConstants.UCP_CWND_MIN_TARGET * _mss);
            }
            CongestionWindowBytes = cwnd;
        }

        // --------------------------------------------------------------------
        // Bdp — ceil(bw * model_rtt * gain >> 8 >> 24) with the G4 geodesic
        // model RTT floor.  All quantities are in byte space.
        // --------------------------------------------------------------------
        private long Bdp(long bw, int gain)
        {
            if (bw <= 0)
            {
                return _initialCwndBytes > 0 ? _initialCwndBytes : (long)UcpConstants.UCP_CWND_MIN_TARGET * _mss;
            }
            long modelRtt = GetModelRtt();
            if (modelRtt <= 0)
            {
                return _initialCwndBytes > 0 ? _initialCwndBytes : (long)UcpConstants.UCP_CWND_MIN_TARGET * _mss;
            }

            // Pre-convergence floor: until the geodesic estimator has at
            // least MIN_SAMPLES and a valid x_est, never let the model RTT
            // collapse below the configured floor.
            if (modelRtt < UcpConstants.UCP_BDP_MIN_RTT_US &&
                !(_sampleCnt >= UcpConstants.UCP_MIN_SAMPLES && _xEst > 0))
            {
                modelRtt = UcpConstants.UCP_BDP_MIN_RTT_US;
            }
            if (modelRtt <= 0) modelRtt = 1;

            ulong w;
            if ((ulong)bw > ulong.MaxValue / (ulong)modelRtt)
            {
                w = ulong.MaxValue;
            }
            else
            {
                w = (ulong)bw * (ulong)modelRtt;
            }
            if (w > ulong.MaxValue / (ulong)gain)
            {
                w = ulong.MaxValue;
            }
            else
            {
                w = w * (ulong)gain;
            }
            w = w >> BBR_SCALE;
            return (long)((w + (ulong)BW_UNIT - 1) >> BW_SCALE);
        }

        // --------------------------------------------------------------------
        // GetModelRtt — G4 safety floor: min(x_est >> 10, min_rtt), with a
        // cold-start fallback to min_rtt (or the default RTT before the
        // first sample).
        // --------------------------------------------------------------------
        private long GetModelRtt()
        {
            if (_xEst == 0 || _sampleCnt < UcpConstants.UCP_MIN_SAMPLES)
            {
                return _minRttUs == MIN_RTT_UNINIT
                    ? UcpConstants.UCP_DEFAULT_RTT_US
                    : _minRttUs;
            }
            long xUs = _xEst >> KCC_SCALE_SHIFT;
            return Math.Min(xUs, _minRttUs);
        }

        // --------------------------------------------------------------------
        // Inflight — BDP + quantization budget (TSO headroom, even rounding,
        // probe bonus in cycle phase 0).  Mirrors kcc_inflight.
        // --------------------------------------------------------------------
        private long Inflight(long bw, int gain)
        {
            if (_minRttUs == MIN_RTT_UNINIT) return 0;
            long inflight = Bdp(bw, gain);
            inflight += (long)UcpConstants.UCP_TSO_HEADROOM_MULT * TsoSegsGoal() * _mss;
            inflight = (inflight + 1) & ~1L;
            if (_mode == UcpMode.ProbeBw && _cycleIdx == 0)
            {
                inflight += (long)UcpConstants.UCP_PROBE_CWND_BONUS * _mss;
            }
            return inflight;
        }

        // --------------------------------------------------------------------
        // PacketsInNetAtEdt — inflight projected at the EDT (earliest
        // departure time), used by the cycle-phase and drain decisions.
        // --------------------------------------------------------------------
        private long PacketsInNetAtEdt(long bw)
        {
            long nowUs = _pacingNowUsEdt > 0 ? _pacingNowUsEdt : _lastAckUs;
            long wstampUs = _pacingWstampUs > 0 ? _pacingWstampUs : nowUs;
            long inflightAtEdt = _flightBytes;
            if (_pacingGain > BBR_UNIT)
            {
                inflightAtEdt += (long)TsoSegsGoal() * _mss;
            }
            long deltaUs = wstampUs - nowUs;
            if (deltaUs <= 0)
            {
                return inflightAtEdt;
            }
            long deltaNs = deltaUs * 1000;
            if (deltaNs <= UcpConstants.UCP_EDT_NEAR_NOW_NS)
            {
                return inflightAtEdt;
            }
            long intervalDelivered = 0;
            if (bw > 0)
            {
                intervalDelivered = (bw * deltaUs) >> BW_SCALE;
            }
            if (intervalDelivered >= inflightAtEdt)
            {
                return 0;
            }
            return inflightAtEdt - intervalDelivered;
        }

        // --------------------------------------------------------------------
        // Cycle-phase machinery (PROBE_BW pacing gain cycling).
        // --------------------------------------------------------------------
        private int GetCyclePacingGain()
        {
            return _cycleGainTable[_cycleIdx & (UcpConstants.UCP_PROBE_BW_CYCLE_LEN - 1)];
        }

        private void AdvanceCyclePhase()
        {
            _cycleIdx = (_cycleIdx + 1) & (UcpConstants.UCP_PROBE_BW_CYCLE_LEN - 1);
            _cycleMstampUs = _lastAckUs;
        }

        private void UpdateCyclePhase()
        {
            if (_mode != UcpMode.ProbeBw) return;

            bool isFullLength = (_lastAckUs - _cycleMstampUs) > _minRttUs;
            bool advance = false;
            if (_pacingGain == BBR_UNIT)
            {
                advance = isFullLength;
            }
            else if (_pacingGain > BBR_UNIT)
            {
                long inflight = PacketsInNetAtEdt(_maxBw);
                advance = isFullLength &&
                    (_currSampleLosses || inflight >= Inflight(_maxBw, _pacingGain));
            }
            else
            {
                long inflight = PacketsInNetAtEdt(_maxBw);
                advance = (isFullLength && inflight <= Inflight(_maxBw, BBR_UNIT)) ||
                    (_lastAckUs - _cycleMstampUs) > _minRttUs * 4;
            }
            if (advance)
            {
                AdvanceCyclePhase();
            }
        }

        // --------------------------------------------------------------------
        // CheckFullBwReached — STARTUP exit: 3 rounds without 1.25x growth.
        // --------------------------------------------------------------------
        private void CheckFullBwReached()
        {
            if (_fullBwReached || !_roundStart || _isAppLimited)
            {
                return;
            }
            long bwThresh = (_fullBw * UcpConstants.UCP_KCC_FULL_BW_THRESH) >> BBR_SCALE;
            long maxBw = BwMax();
            if (maxBw >= bwThresh)
            {
                _fullBw = maxBw;
                _fullBwCnt = 0;
                return;
            }
            _fullBwCnt++;
            _fullBwReached = _fullBwCnt >= UcpConstants.UCP_KCC_FULL_BW_CNT;
        }

        // --------------------------------------------------------------------
        // CheckDrain — enter DRAIN from STARTUP, exit to PROBE_BW when the
        // pipe is drained (AND gate by default: drained AND 1 RTT, or the
        // 4x min_rtt timeout).
        // --------------------------------------------------------------------
        private void CheckDrain(long nowMicros)
        {
            if (_mode == UcpMode.Startup && _fullBwReached)
            {
                _mode = UcpMode.Drain;
                _drainEnterStampUs = nowMicros;
            }

            if (_mode == UcpMode.Drain)
            {
                long inflight = PacketsInNetAtEdt(_maxBw);
                long bdp = Inflight(_maxBw, BBR_UNIT);
                long drainElapsed = nowMicros - _drainEnterStampUs;
                long minRtt = _minRttUs == MIN_RTT_UNINIT
                    ? UcpConstants.UCP_DEFAULT_RTT_US
                    : _minRttUs;
                bool drained = inflight <= bdp;
                bool timeout = drainElapsed > minRtt * 4;
                bool oneRtt = drainElapsed > minRtt;
                bool exit;
                if (DrainAndOrMode)
                {
                    exit = (drained && oneRtt) || timeout;
                }
                else
                {
                    exit = drained || timeout;
                }
                if (exit)
                {
                    _mode = UcpMode.ProbeBw;
                    _cwndGain = UcpConstants.UCP_CWND_GAIN;
                    _cycleIdx = (UcpConstants.UCP_PROBE_BW_CYCLE_LEN - 1 - RandomBelow(UcpConstants.UCP_PROBE_BW_CYCLE_RAND)) &
                        (UcpConstants.UCP_PROBE_BW_CYCLE_LEN - 1);
                    _cycleMstampUs = _lastAckUs;
                    AdvanceCyclePhase();
                    _pacingGain = GetCyclePacingGain();
                }
            }
        }

        // --------------------------------------------------------------------
        // ACK aggregation measurement (dual-window sliding max, 5-RTT
        // rotation).  Mirrors kcc_update_ack_aggregation.
        // --------------------------------------------------------------------
        private void UpdateAckAggregation(long nowMicros, long delivered, long acked, long intervalUs)
        {
            if (acked <= 0 || delivered < 0 || intervalUs <= 0) return;
            if (_roundStart)
            {
                _extraAckedWinRtts = Math.Min(_extraAckedWinRtts + 1, UcpConstants.UCP_EXTRA_ACKED_WIN_RTTS_MAX);
                if (_extraAckedWinRtts >= UcpConstants.UCP_AGG_WINDOW_ROTATION_RTTS)
                {
                    _extraAckedWinRtts = 0;
                    _extraAckedWinIdx = _extraAckedWinIdx == 0 ? 1 : 0;
                    _extraAcked[_extraAckedWinIdx] = 0;
                }
            }

            long epochUs = _ackEpochMstampUs > 0 ? nowMicros - _ackEpochMstampUs : 0;
            long activeBw = _ltUseBw && _ltBw > 0 ? _ltBw : _maxBw;
            long expectedAckedBytes = 0;
            if (activeBw > 0 && epochUs > 0)
            {
                expectedAckedBytes = (long)(((ulong)activeBw * (ulong)epochUs) >> BW_SCALE);
            }

            // Restart the epoch when the expected acked matches the actual
            // (the pipe is drained) or the epoch accumulator is about to wrap.
            if (_ackEpochMstampUs == 0 || _ackEpochAcked <= expectedAckedBytes ||
                (ulong)_ackEpochAcked + (ulong)acked >= (ulong)UcpConstants.UCP_ACK_EPOCH_MAX)
            {
                _ackEpochAcked = 0;
                _ackEpochMstampUs = nowMicros;
            }
            _ackEpochAcked = Math.Min(_ackEpochAcked + acked, UcpConstants.UCP_ACK_EPOCH_MAX);

            // Extra acked = actual acked above what bandwidth predicts.
            epochUs = nowMicros - _ackEpochMstampUs;
            expectedAckedBytes = 0;
            if (activeBw > 0 && epochUs > 0)
            {
                expectedAckedBytes = (long)(((ulong)activeBw * (ulong)epochUs) >> BW_SCALE);
            }
            long extraAcked = _ackEpochAcked > expectedAckedBytes
                ? _ackEpochAcked - expectedAckedBytes : 0;
            // Cap the excess ACKed count at the congestion window in SEGMENTS,
            // matching the kernel (tcp_kcc.c:4749 caps at tp->snd_cwnd) and the
            // C++ port (ucp_cc.cpp:1030 divides by MSS). A bytes-unit cap here
            // would be ~MSS times too loose.
            extraAcked = Math.Min(extraAcked, CongestionWindowBytes / _mss);
            if (extraAcked > _extraAcked[_extraAckedWinIdx])
            {
                _extraAcked[_extraAckedWinIdx] = extraAcked;
            }
        }

        // --------------------------------------------------------------------
        // AckAggCwndBonus — gain x max(extra_acked), capped at bw x 100ms.
        // Mirrors kcc_ack_aggregation_cwnd.  Only applied when full_bw_reached.
        // --------------------------------------------------------------------
        private long AckAggCwndBonus(long bw)
        {
            if (!_fullBwReached) return 0;
            if (!ExtraAckedGainActive) return 0;
            long maxExtra = Math.Max(_extraAcked[0], _extraAcked[1]);
            long extraAckedGain = ((long)UcpConstants.UCP_EXTRA_ACKED_GAIN_NUM * BBR_UNIT) / UcpConstants.UCP_EXTRA_ACKED_GAIN_DEN;
            long bonus = (maxExtra * extraAckedGain) / BBR_UNIT;
            long cap = (bw * UcpConstants.UCP_EXTRA_ACKED_MAX_MS_RATIO * MICROS_PER_MILLI) >> BW_SCALE;
            if (bonus > cap) bonus = cap;
            return bonus;
        }

        // --------------------------------------------------------------------
        // UpdateEcnEwma — ECN EWMA (mirrors kcc_update_ecn_ewma).  Runtime-
        // gated by UcpConfiguration.EcnEnabled (default off, mirroring the
        // kernel ecn_enable=0 default).  When disabled the EWMA never updates.
        // --------------------------------------------------------------------
        private void UpdateEcnEwma(long delivered, long losses)
        {
            if (!_ecnEnabled) return;
            if (delivered <= 0 || losses < 0) return;
            long ceDelta = _ecnCeMarks - _lastDeliveredCe;
            _lastDeliveredCe = _ecnCeMarks;
            long total = delivered + losses;
            if (ceDelta > 0)
            {
                long instant = (ceDelta << BBR_SCALE) / total;
                if (_ecnEwma == 0)
                {
                    _ecnEwma = instant;
                }
                else
                {
                    _ecnEwma = (_ecnEwma * UcpConstants.UCP_ECN_EWMA_RETAINED + instant) / UcpConstants.UCP_ECN_EWMA_TOTAL;
                }
            }
            else
            {
                if (_ecnEwma > 0)
                {
                    if (_roundStart)
                    {
                        _ecnEwma = _ecnEwma * UcpConstants.UCP_ECN_EWMA_RETAINED / UcpConstants.UCP_ECN_EWMA_TOTAL;
                    }
                    else
                    {
                        if (_ecnEwma < UcpConstants.UCP_ECN_EWMA_FLOOR)
                        {
                            _ecnEwma = 0;
                        }
                        else
                        {
                            _ecnEwma = (_ecnEwma * UcpConstants.UCP_ECN_IDLE_DECAY_NUM) / UcpConstants.UCP_ECN_IDLE_DECAY_DEN;
                        }
                    }
                }
            }
        }

        // --------------------------------------------------------------------
        // ApplyCwndConstraints — ECN backoff (mirrors kcc_apply_cwnd_constraints).
        // Runtime-gated by UcpConfiguration.EcnEnabled (default off).
        // --------------------------------------------------------------------
        private void ApplyCwndConstraints()
        {
            if (!_ecnEnabled) return;
            if (_sampleCnt < UcpConstants.UCP_MIN_SAMPLES) return;
            if (_ecnEwma == 0) return;
            long ecnBackoff = ((long)UcpConstants.UCP_ECN_BACKOFF_NUM << BBR_SCALE) / UcpConstants.UCP_ECN_BACKOFF_DEN;
            if (ecnBackoff == 0) return;
            if (_pacingGain > BBR_UNIT)
            {
                long ecnScale = (1L << (BBR_SCALE + BBR_SCALE)) / _pacingGain;
                ecnBackoff = (ecnBackoff * ecnScale) >> BBR_SCALE;
            }
            long factor = BBR_UNIT - Math.Min(ecnBackoff, (long)BBR_UNIT);
            if (_qDelayAvg > CongThresh())
            {
                _cwndGain = (int)Math.Min(_cwndGain,
                    Math.Max(UcpConstants.UCP_GAIN_FLOOR,
                        (_cwndGain * factor) >> BBR_SCALE));
            }
        }

        // --------------------------------------------------------------------
        // LT-BW (long-term bandwidth / policer detection).  Mirrors
        // kcc_lt_bw_sampling + kcc_lt_bw_interval_done:
        //   - sampling starts on a loss in a round (min 5 geodesic samples)
        //   - interval is 4 RTTs minimum, 16 RTTs maximum
        //   - a candidate needs >= 50/256 loss ratio to be recorded
        //   - consistency gate: within 1/8 ratio or 500 B/s of lt_bw
        //   - EMA (1/2) blend while consistent, expiry after 48 RTTs
        //   - qdelay > congest threshold or SRTT > min_rtt + 5ms resets.
        // --------------------------------------------------------------------
        private void ResetLtBw()
        {
            _ltBw = 0;
            _ltUseBw = false;
            _ltIsSampling = false;
            _ltRttCnt = 0;
            _ltLastDelivered = _totalDelivered;
            _ltLastLost = _totalLost;
            _ltLastStampUs = _lastAckUs;
        }

        private void UpdateLtBw(long nowMicros, long lossVal)
        {
            if (_ltUseBw)
            {
                // While lt_bw is active, count rounds in PROBE_BW and expire
                // after LT_BW_MAX_RTTS rounds (restart the cycle on expiry).
                if (_mode == UcpMode.ProbeBw && _roundStart)
                {
                    int cnt = _ltRttCnt + 1;
                    if (cnt >= UcpConstants.UCP_LT_RTT_CNT_MAX) cnt = UcpConstants.UCP_LT_RTT_CNT_MAX;
                    _ltRttCnt = cnt;
                    if (cnt >= UcpConstants.UCP_LT_BW_MAX_RTTS)
                    {
                        ResetLtBw();
                        _mode = UcpMode.ProbeBw;
                        _cycleIdx = (UcpConstants.UCP_PROBE_BW_CYCLE_LEN - 1 - RandomBelow(UcpConstants.UCP_PROBE_BW_CYCLE_RAND)) &
                            (UcpConstants.UCP_PROBE_BW_CYCLE_LEN - 1);
                        _cycleMstampUs = _lastAckUs;
                        _cwndGain = UcpConstants.UCP_CWND_GAIN;
                        AdvanceCyclePhase();
                    }
                }
                return;
            }

            if (_sampleCnt < UcpConstants.UCP_MIN_SAMPLES)
            {
                return;
            }

            if (!_ltIsSampling)
            {
                if (_isAppLimited)
                {
                    ResetLtBw();
                    return;
                }
                if (!_currSampleLosses) return;
                _ltIsSampling = true;
                _ltLastDelivered = _totalDelivered;
                _ltLastStampUs = nowMicros;
                _ltLastLost = _totalLost;
                _ltRttCnt = 0;
                return;
            }

            if (_isAppLimited)
            {
                ResetLtBw();
                return;
            }

            if (_roundStart)
            {
                int cnt = _ltRttCnt + 1;
                if (cnt >= UcpConstants.UCP_LT_RTT_CNT_MAX) cnt = UcpConstants.UCP_LT_RTT_CNT_MAX;
                _ltRttCnt = cnt;
            }
            if (_ltRttCnt < UcpConstants.UCP_LT_INTVL_MIN_RTTS) return;
            int ltTimeout = UcpConstants.UCP_LT_INTVL_MAX_MULT * UcpConstants.UCP_LT_INTVL_MIN_RTTS;
            if (_ltRttCnt > ltTimeout)
            {
                ResetLtBw();
                return;
            }

            long delivered = _totalDelivered - _ltLastDelivered;
            long elapsedUs = nowMicros - _ltLastStampUs;
            if (elapsedUs < MICROS_PER_MILLI || delivered <= 0) return;
            long lostSince = _totalLost - _ltLastLost;
            if (lostSince < 0) lostSince = 0;

            // Loss gate: the interval must have lost at least 50/256 of the
            // delivered bytes to be a plausible policer fingerprint.
            if (((ulong)lostSince << BBR_SCALE) < (ulong)UcpConstants.UCP_LT_LOSS_THRESH * (ulong)delivered)
            {
                return;
            }

            long intervalBw = (long)(((ulong)delivered << BW_SCALE) / (ulong)elapsedUs);

            if (_ltBw != 0)
            {
                long diff = intervalBw > _ltBw ? intervalBw - _ltBw : _ltBw - intervalBw;
                long ratioThresh = _ltBw * UcpConstants.UCP_LT_BW_RATIO_NUM / UcpConstants.UCP_LT_BW_RATIO_DEN;
                long bwDiffBps = (diff * MICROS_PER_SECOND) >> BW_SCALE;
                if (diff <= ratioThresh || bwDiffBps <= UcpConstants.UCP_LT_BW_DIFF)
                {
                    // Stability check passed (mirrors tcp_kcc.c:4120-4121):
                    // only now apply the qdelay/srtt safety checks
                    // (tcp_kcc.c:4136-4144).
                    if (_qDelayAvg > CongThresh())
                    {
                        ResetLtBw();
                        return;
                    }
                    if (_srttUs > 0 && _minRttUs != MIN_RTT_UNINIT &&
                        (_srttUs >> UcpConstants.UCP_SRTT_SHIFT) > _minRttUs + UcpConstants.UCP_LT_BW_ITHRESH)
                    {
                        ResetLtBw();
                        return;
                    }

                    // Consistent with the policer estimate: EMA (1/2) blend
                    // toward the new sample and activate the policer cap.
                    _ltBw = (intervalBw * UcpConstants.UCP_LT_BW_EMA_NUM +
                        _ltBw * (UcpConstants.UCP_LT_BW_EMA_DEN - UcpConstants.UCP_LT_BW_EMA_NUM)) / UcpConstants.UCP_LT_BW_EMA_DEN;
                    _ltBw = Math.Max(_ltBw, 1);
                    _ltUseBw = true;
                    _ltRttCnt = 0;
                    _pacingGain = BBR_UNIT;
                    _ltLastLost = _totalLost;
                    return;
                }
                else
                {
                    // Not consistent: adopt the new sample as the new
                    // candidate and restart the interval.
                    _ltBw = intervalBw;
                    _ltLastDelivered = _totalDelivered;
                    _ltLastStampUs = nowMicros;
                    _ltRttCnt = 0;
                    _ltLastLost = _totalLost;
                    return;
                }
            }
            else
            {
                _ltBw = intervalBw;
                _ltRttCnt = 0;
            }
            _ltLastDelivered = _totalDelivered;
            _ltLastStampUs = nowMicros;
            _ltLastLost = _totalLost;
            if (_ltRttCnt >= UcpConstants.UCP_LT_BW_MAX_RTTS)
            {
                ResetLtBw();
            }
        }

        // --------------------------------------------------------------------
        // TSO helpers (mirror kcc_min_tso_segs / kcc_tso_segs_goal).
        // --------------------------------------------------------------------
        private int MinTsoSegs()
        {
            int divisor = UcpConstants.UCP_MIN_TSO_RATE_DIV;
            if (_jitterEwma > UcpConstants.UCP_TSO_HIGH_JITTER_THRESH_US)
            {
                divisor = Math.Min(UcpConstants.UCP_TSO_DIV_CEIL, divisor << UcpConstants.UCP_TSO_DIV_DOUBLE_SHIFT);
            }
            long tsoRateThresh = Math.Max(1, UcpConstants.UCP_MIN_TSO_RATE / divisor);
            return (PacingRateBytesPerSecond > 0 && PacingRateBytesPerSecond < tsoRateThresh)
                ? UcpConstants.UCP_TSO_SEGS_LOW
                : UcpConstants.UCP_TSO_SEGS_DEFAULT;
        }

        private int TsoSegsGoal()
        {
            int minSegs = MinTsoSegs();
            long segs = _mss > 0
                ? ((long)PacingRateBytesPerSecond >> 10) / _mss
                : UcpConstants.UCP_TSO_SEGS_DEFAULT;
            if (segs > int.MaxValue) segs = int.MaxValue;
            return Math.Min(UcpConstants.UCP_TSO_MAX_SEGS, Math.Max(minSegs, (int)segs));
        }

        // --------------------------------------------------------------------
        // Thresholds (mirror kcc_clean_thresh / kcc_cong_thresh).
        // --------------------------------------------------------------------
        private long CleanThresh()
        {
            return Math.Max(
                _minRttUs * UcpConstants.UCP_QDELAY_CLEAN_BP / UcpConstants.UCP_QDELAY_BP_BASE,
                UcpConstants.UCP_QDELAY_FLOOR_US);
        }

        private long CongThresh()
        {
            return Math.Max(
                _minRttUs * UcpConstants.UCP_QDELAY_CONG_BP / UcpConstants.UCP_QDELAY_BP_BASE,
                UcpConstants.UCP_QDELAY_FLOOR_US);
        }

        // --------------------------------------------------------------------
        // RandomBelow — deterministic PROBE_BW phase randomization.
        // --------------------------------------------------------------------
        private static int RandomBelow(int bound)
        {
            if (bound <= 1) return 0;
            return Rng.Next(bound);
        }

        // --------------------------------------------------------------------
        // KfFeedProbeBwSample — feed the cross-connection Kalman filter
        // (GlobalKfEstimator, KCC2.0-compatible) at PROBE_BW round starts.
        // --------------------------------------------------------------------
        private void KfFeedProbeBwSample(long delivered, long intervalUs)
        {
            if (delivered <= 0 || intervalUs <= 0) return;
            ulong d = (ulong)delivered;
            long kbw = (long)((d << BW_SCALE) / (ulong)intervalUs);
            bool firstRtt = !GlobalKfEstimator.KfIsActive();
            GlobalKfEstimator.KfFeedProbeBw(kbw, firstRtt);
        }

        // --------------------------------------------------------------------
        // ResetGlobalKf — reset the cross-connection Kalman filter state
        // (delegates to GlobalKfEstimator).
        // --------------------------------------------------------------------
        internal static void ResetGlobalKf()
        {
            GlobalKfEstimator.Reset();
        }

        // --------------------------------------------------------------------
        // Loss / recovery / control event handlers.
        // --------------------------------------------------------------------

        // FEC recovery proves forward progress; clear app-limited so the
        // bandwidth filter keeps accepting samples.  Recovered bytes are NOT
        // added to _totalDelivered — they were reconstructed locally and did
        // not contribute to on-wire delivery.
        internal void OnFecRecovery(long nowMicros, long recoveredBytes)
        {
            if (recoveredBytes <= 0) return;
            if (_isAppLimited) _isAppLimited = false;
        }

        // NAK-based loss: accounts lost bytes and updates the loss-rate EWMA.
        // Mirrors kcc's NAK loss path.
        internal void OnNakLoss(long nowMicros, long lostBytes)
        {
            if (lostBytes <= 0) return;
            _totalLost += lostBytes;
            _ackLosses += lostBytes;
            _currSampleLosses = true;
            {
                long roundDelivered = Math.Max(0, _totalDelivered - _prevDelivered);
                long totalInRound = roundDelivered + lostBytes;
                if (totalInRound > 0)
                {
                    double instantPct = (double)UcpConstants.UCP_PCT_BASE * (double)lostBytes / (double)totalInRound;
                    EstimatedLossPercent = EstimatedLossPercent * 0.95 + instantPct * 0.05;
                }
                else
                {
                    EstimatedLossPercent = EstimatedLossPercent * 0.95 + 5.0;
                }
            }
            if (_caState < CA_RECOVERY)
            {
                _priorCwnd = CongestionWindowBytes;
            }
            else
            {
                _priorCwnd = Math.Max(_priorCwnd, CongestionWindowBytes);
            }
            SetCaState(CA_RECOVERY);
            UpdateLtBw(nowMicros, 0);
        }

        // Packet-send hook: records the EDT context and clears app-limited.
        internal void OnPacketSent(long nowMicros, bool isRetransmit)
        {
            _pacingNowUsEdt = nowMicros;
            _pacingWstampUs = nowMicros;
            _isAppLimited = false;
        }

        // EDT state from the pacing controller (used by drain/cycle decisions).
        internal void SetEdtState(long nowUs, long wstampUs)
        {
            _pacingNowUsEdt = nowUs;
            _pacingWstampUs = wstampUs;
        }

        // Fast retransmit: marks the round as lossy and enters recovery when
        // the loss is congestion-induced.  Mirrors the KCC 2.0 loss path
        // (each lost segment counted exactly once, like the kernel's
        // rs->losses): the lost bytes are accounted a single time by
        // OnPacketLoss below, and the loss rate derived from them feeds the
        // loss EWMA so the adaptive-FEC / loss estimate stays accurate.
        // Accounting the bytes here as well would double-count every fast-
        // retransmit loss, inflating _ackLosses (over-reducing cwnd) and
        // _totalLost (tripping the LT-BW 50/256 loss gate at ~20% loss).
        internal void OnFastRetransmit(long nowMicros, bool isCongestionLoss, long lostBytes = 0)
        {
            _currSampleLosses = true;
            if (isCongestionLoss)
            {
                if (_caState < CA_RECOVERY)
                {
                    _priorCwnd = CongestionWindowBytes;
                }
                SetCaState(CA_RECOVERY);
            }
            double lossRate = 0.0;
            if (lostBytes > 0)
            {
                long deliveredSince = Math.Max(0, _totalDelivered - _prevDelivered);
                long total = deliveredSince + lostBytes;
                if (total > 0)
                {
                    lossRate = (double)lostBytes / (double)total;
                }
            }
            OnPacketLoss(nowMicros, lossRate, isCongestionLoss, lostBytes);
            UpdateLtBw(nowMicros, 0);
        }

        // Packet loss: accounts lost bytes, updates the loss-rate EWMA
        // (75/25 blend, fraction clamped to [0, 0.99]), and enters recovery
        // for congestion losses.  Mirrors kcc's loss handling.
        internal void OnPacketLoss(long nowMicros, double lossRate, bool isCongestionLoss, long lostBytes = 0)
        {
            if (nowMicros <= 0) return;
            if (lostBytes > 0)
            {
                _totalLost += lostBytes;
                _ackLosses += lostBytes;
                _currSampleLosses = true;
            }
            if (isCongestionLoss)
            {
                if (_caState < CA_RECOVERY)
                {
                    _priorCwnd = CongestionWindowBytes;
                }
                SetCaState(CA_RECOVERY);
            }
            {
                double fraction = lossRate;
                if (fraction < 0.0) fraction = 0.0;
                if (fraction > 0.99) fraction = 0.99;
                EstimatedLossPercent = EstimatedLossPercent * 0.75 + fraction * 100.0 * 0.25;
            }
            UpdateLtBw(nowMicros, 0);
        }

        // ECN CE marks accumulate until the next EWMA update consumes them.
        internal void OnCeMark(long ceMarks = 1)
        {
            if (ceMarks > 0)
            {
                _ecnCeMarks += ceMarks;
            }
        }

        // RTO: back to CA_OPEN, discard the full-bw history, restart the
        // round, restore the initial cwnd and the STARTUP gains.  The mode
        // is intentionally left untouched (mirrors the kernel RTO handling:
        // kcc_set_state(TCP_CA_Loss) + kcc_cwnd_event, tcp_kcc.c:3729-3745,
        // 5389-5399).
        internal void OnRto()
        {
            _caState = CA_OPEN;
            _fullBw = 0;
            _fullBwCnt = 0;
            _roundStart = true;
            _pacingGain = UcpConstants.UCP_HIGH_GAIN;
            _cwndGain = UcpConstants.UCP_HIGH_GAIN;
            CongestionWindowBytes = _initialCwndBytes;
            UpdateLtBw(_lastAckUs, 0);
        }

        // Path change: full KCC 2.0 state reset back to STARTUP defaults.
        // Mirrors the kcc reset sequence used on path migration.
        internal void OnPathChange(long nowMicros)
        {
            _mode = UcpMode.Startup;
            _minRttUs = MIN_RTT_UNINIT;
            _minRttStampUs = 0;
            _rttCnt = 0;
            _nextRttDelivered = 0;
            _cycleMstampUs = 0;
            _roundStart = false;
            _idleRestart = false;
            _packetConservation = false;
            _ltIsSampling = false;
            _ltRttCnt = 0;
            _minRttFastFallCnt = 0;
            _cycleIdx = 0;
            _fullBwReached = false;
            _fullBwCnt = 0;
            _locked = false;
            _confirmCnt = 0;
            _confirmSlowCnt = 0;
            _hasSeenRtt = false;
            _ltUseBw = false;
            _pacingGain = UcpConstants.UCP_HIGH_GAIN;
            _cwndGain = UcpConstants.UCP_HIGH_GAIN;
            _priorCwnd = 0;
            _fullBw = 0;
            _ltBw = 0;
            _ltLastDelivered = 0;
            _ltLastStampUs = 0;
            _ltLastLost = 0;
            _xEst = 0;
            _pEst = UcpConstants.UCP_P_EST_INIT;
            _qDelayAvg = 0;
            _sampleCnt = 0;
            _jitterEwma = 0;
            _mrUpdateRttCnt = 0;
            _srttUs = 0;
            _ecnEwma = 0;
            _ecnCeMarks = 0;
            _lastDeliveredCe = 0;
            _ackEpochMstampUs = 0;
            _ackEpochAcked = 0;
            _extraAckedWinRtts = 0;
            _extraAckedWinIdx = 0;
            _extraAcked[0] = 0;
            _extraAcked[1] = 0;
            _roundRttMin = 0xFFFFFFFFL;
            _prevRoundRttMin = 0xFFFFFFFFL;
            _drainEnterStampUs = 0;
            _caState = CA_OPEN;
            _prevCaState = CA_OPEN;
            _totalLost = 0;
            _currSampleLosses = false;
            _ackLosses = 0;
            _bwSampleCount = 0;
            _bwSampleCur = 0;
            _maxBw = 0;
            _pacingWstampUs = 0;
            _pacingNowUsEdt = 0;

            long initBw = _initialBw > 0
                ? (_initialBw << BW_SCALE) / MICROS_PER_SECOND
                : BW_UNIT;
            if (initBw <= 0) initBw = BW_UNIT;
            BwUpdate(initBw, 0);
            _maxBw = BwMax();

            CongestionWindowBytes = _initialCwndBytes;
            EstimatedLossPercent = 0;
            PacingRateBytesPerSecond = (_initialBw > 0 ? _initialBw : MICROS_PER_SECOND) * UcpConstants.UCP_HIGH_GAIN / BBR_UNIT;
            if (_maxPacingRate > 0 && PacingRateBytesPerSecond > _maxPacingRate)
            {
                PacingRateBytesPerSecond = _maxPacingRate;
            }
        }

        // Idle restart: a fresh burst may start from a drained pipe; reset
        // the ACK-aggregation epoch and, in PROBE_BW, drop to cruise gain.
        internal void OnIdleRestart()
        {
            _idleRestart = true;
            _ackEpochMstampUs = 0;
            _ackEpochAcked = 0;
            if (_mode == UcpMode.ProbeBw)
            {
                _pacingGain = BBR_UNIT;
            }
        }

        // CA state transitions: entering LOSS discards the full-bw history
        // and restarts the round; entering RECOVERY saves the prior cwnd.
        internal void SetCaState(int state)
        {
            int newState = state;
            int prevState = _caState;
            if (newState == prevState) return;
            _prevCaState = prevState;
            _caState = newState;
            if (newState == CA_LOSS)
            {
                _fullBw = 0;
                _fullBwCnt = 0;
                _roundStart = true;
                _nextRttDelivered = _totalDelivered;
            }
            if (newState == CA_RECOVERY && !_packetConservation)
            {
                if (_prevCaState < CA_RECOVERY)
                {
                    _priorCwnd = CongestionWindowBytes;
                }
                else
                {
                    _priorCwnd = Math.Max(_priorCwnd, CongestionWindowBytes);
                }
            }
        }

        // App-limited flag with the transition side effects: leaving the
        // app-limited state marks an idle restart and resets the ACK epoch.
        internal void SetAppLimited(bool isAppLimited)
        {
            if (_isAppLimited && !isAppLimited)
            {
                _idleRestart = true;
                _ackEpochMstampUs = 0;
                _ackEpochAcked = 0;
            }
            _isAppLimited = isAppLimited;
        }

        private void TraceLog(string message)
        {
            if (_enableDebugLog)
            {
                Trace.WriteLine("[UCP CC] " + message);
            }
        }
    }
}
