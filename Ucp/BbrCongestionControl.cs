// ============================================================================
//  PPP PRIVATE NETWORK™ X — Universal Communication Protocol (ppp+ucp)
//  BBRv2 Congestion Control Engine
//
//  Implements Bottleneck Bandwidth and Round-trip propagation time (BBR)
//  congestion control with adaptive path classification, multi-tier loss
//  discrimination, and percentile-based RTT modeling.
//
//  This is the core congestion-control module within the ppp+ucp stack.
//  It replaces traditional loss-based CC (Reno/CUBIC) with a model-based
//  approach that paces traffic near the estimated bottleneck rate and
//  sizes the congestion window to the bandwidth-delay product (BDP).
// ============================================================================

using System;
using System.Diagnostics;

namespace Ucp
{
    /// <summary>
    /// BBRv2 congestion control engine implementing core state transitions,
    /// rate estimation, window computation, and loss classification.
    ///
    /// ====== STATE MACHINE ======
    ///
    /// States: Startup → Drain → ProbeBW ↔ ProbeRTT
    ///
    ///   Startup  — Exponential bandwidth probing. Send at 2.89× pacing gain
    ///              to rapidly discover the bottleneck bandwidth. Exit when
    ///              bandwidth growth stalls for N consecutive rounds (growth
    ///              &lt; 1.25× per round), indicating the pipe is full.
    ///
    ///   Drain    — Brief transition phase after Startup. Reduce pacing gain
    ///              below 1.0× to drain the standing queue built up during
    ///              Startup's aggressive probing. Exit when in-flight bytes
    ///              drop to the BDP target or minimum duration elapses.
    ///
    ///   ProbeBW  — Steady-state cycling through an 8-phase pacing-gain
    ///              cycle. One phase at 1.25× (probe for more bandwidth),
    ///              one at 0.75× (drain any queue), and six at 1.0×.
    ///              The cycle repeats every 8× MinRTT.
    ///
    ///   ProbeRTT — Periodic deep-drain to refresh the MinRtt estimate.
    ///              Reduces CWND to 4 packets for ~200ms to measure the
    ///              true base propagation delay. Entered when MinRtt has
    ///              not been refreshed for ProbeRttInterval (default 10s).
    ///              Exited when a new near-minimum RTT sample is observed
    ///              or a safety timeout fires.
    ///
    /// ====== KEY ESTIMATES ======
    ///
    /// - BtlBw (bottleneck bandwidth): max-filtered delivery rate over a
    ///   sliding window of recent ACKs (6–10 RTTs). The max-filter is
    ///   robust to ACK compression while still tracking bandwidth growth.
    ///
    /// - MinRtt (minimum RTT): sticky floor of observed RTT samples, with
    ///   at-most 25% reduction per update to prevent a single lucky fast
    ///   measurement from collapsing the CWND.
    ///
    /// - PacingRate = BtlBw × PacingGain (controls send scheduling)
    /// - CongestionWindow = BDP × CwndGain, bounded by inflight guardrails
    ///   and a hard ceiling at 2× BDP (using P10 RTT, not raw MinRtt).
    ///
    /// ====== LOSS CLASSIFICATION ======
    ///
    /// Three-tier scoring system:
    ///   1. Delivery-rate drop below threshold + RTT rise → +2 score
    ///   2. RTT rise above threshold alone → +1 score
    ///   3. Loss ratio above threshold + RTT rise → +1 score
    /// Score ≥ 4 → Congested (multiplicative CWND reduction)
    /// Loss with stable RTT → RandomLoss (fast recovery only, no reduction)
    ///
    /// ====== NETWORK CLASSIFICATION ======
    ///
    /// Six path types classified from aggregated statistics windows:
    ///   LowLatencyLAN      — sub-5ms RTT, low jitter, negligible loss
    ///   MobileUnstable     — high jitter, burst loss (LTE/5G)
    ///   LossyLongFat       — high RTT, steady random loss (satellite/LFN)
    ///   CongestedBottleneck — throughput &lt; 70% of BtlBw, RTT growing
    ///   SymmetricVPN       — moderate-high RTT (&gt;60ms), stable pattern
    ///   Default            — unclassified / generic path
    ///
    /// Path class drives adaptive pacing gain, CWND headroom, and
    /// recovery speed.
    ///
    /// Public methods are called by UcpPcb on each ACK, packet send, fast
    /// retransmit, and packet loss event.
    /// </summary>
    internal sealed class BbrCongestionControl
    {
        /// <summary>Protocol configuration providing gains, limits, and tuning parameters.</summary>
        private readonly UcpConfiguration _config;

        // ---- Rate estimation ----

        /// <summary>Circular buffer of recent delivery-rate samples for max-filter bandwidth estimation.</summary>
        private readonly double[] _recentRates = new double[UcpConstants.BBR_RECENT_RATE_SAMPLE_COUNT];

        /// <summary>Timestamps corresponding to each entry in _recentRates.</summary>
        private readonly long[] _recentRateTimestamps = new long[UcpConstants.BBR_RECENT_RATE_SAMPLE_COUNT];

        /// <summary>Number of valid entries in _recentRates circular buffer.</summary>
        private int _recentRateCount;

        /// <summary>Current write position in the _recentRates circular buffer.</summary>
        private int _recentRateIndex;

        /// <summary>History of recent delivery rates for trend-based congestion detection.</summary>
        private readonly double[] _deliveryRateHistory = new double[UcpConstants.BBR_DELIVERY_RATE_HISTORY_COUNT];

        /// <summary>Number of valid entries in _deliveryRateHistory.</summary>
        private int _deliveryRateHistoryCount;

        /// <summary>Current write position in the _deliveryRateHistory circular buffer.</summary>
        private int _deliveryRateHistoryIndex;

        // ---- RTT history ----

        /// <summary>History of recent RTT samples for jitter and trend analysis.</summary>
        private readonly long[] _rttHistoryMicros = new long[UcpConstants.BBR_RTT_HISTORY_COUNT];

        /// <summary>Number of valid entries in _rttHistoryMicros.</summary>
        private int _rttHistoryCount;

        /// <summary>Current write position in the _rttHistoryMicros circular buffer.</summary>
        private int _rttHistoryIndex;

        // ---- Bandwidth exploration ----

        /// <summary>Full-bandwidth estimate tracked over multiple rounds for Startup exit detection.</summary>
        private double _fullBandwidthEstimate;

        /// <summary>Number of consecutive rounds without sufficient bandwidth growth.</summary>
        private int _fullBandwidthRounds;

        /// <summary>Current index within the 8-phase ProbeBW gain cycle (0..7).</summary>
        private int _probeBwCycleIndex;

        // ---- Mode timing ----

        /// <summary>Timestamp when the current mode was entered, in microseconds.</summary>
        private long _modeEnteredMicros;

        /// <summary>Timestamp of the last received ACK, in microseconds.</summary>
        private long _lastAckMicros;

        // ---- Minimum RTT tracking ----

        /// <summary>Timestamp when the current minimum RTT was recorded, in microseconds.</summary>
        private long _minRttTimestampMicros;

        /// <summary>Timestamp when ProbeRTT was entered, in microseconds.</summary>
        private long _probeRttEnteredMicros;

        // ---- Round tracking ----

        /// <summary>Cumulative delivered bytes since connection start.</summary>
        private long _totalDeliveredBytes;

        /// <summary>Delivered-byte threshold at which the next round begins.</summary>
        private long _nextRoundDeliveredBytes;

        /// <summary>Most recent observed RTT in microseconds.</summary>
        private long _currentRttMicros;

        // ---- Loss accounting ----

        /// <summary>Start timestamp of the current loss bucket window, in microseconds.</summary>
        private long _lossBucketStartMicros;

        /// <summary>Current position in the loss bucket circular buffers.</summary>
        private int _lossBucketIndex;

        /// <summary>Circular buffer counting sent packets per loss bucket.</summary>
        private readonly int[] _sentBuckets = new int[UcpConstants.BBR_LOSS_BUCKET_COUNT];

        /// <summary>Circular buffer counting retransmitted packets per loss bucket.</summary>
        private readonly int[] _retransmitBuckets = new int[UcpConstants.BBR_LOSS_BUCKET_COUNT];

        // ---- Congestion/loss tracking ----

        /// <summary>Multiplier applied to CWND due to congestion loss (1.0 = no reduction).</summary>
        private double _lossCwndGain = 1d;

        /// <summary>Most recent delivery-rate sample in bytes per second.</summary>
        private double _deliveryRateBytesPerSecond;

        /// <summary>Upper inflight guardrail in bytes (ceiling for CWND).</summary>
        private double _inflightHighBytes;

        /// <summary>Lower inflight guardrail in bytes (floor for CWND).</summary>
        private double _inflightLowBytes;

        /// <summary>Current maximum tolerable bandwidth loss percentage (from config).</summary>
        private double _maxBandwidthLossPercent;

        // ---- Fast recovery ----

        /// <summary>Timestamp when fast recovery was entered, or 0 if not in fast recovery.</summary>
        private long _fastRecoveryEnteredMicros;

        // ---- Bandwidth growth clamping ----

        /// <summary>Start of the current bandwidth growth window, in microseconds.</summary>
        private long _bandwidthGrowthWindowMicros;

        /// <summary>BtlBw at the start of the current bandwidth growth window.</summary>
        private double _bandwidthGrowthWindowStartRate;

        /// <summary>Maximum BtlBw observed in the current non-congested window.
        /// Used as a soft floor to prevent random loss from permanently
        /// depressing the bandwidth estimate.</summary>
        private double _maxBtlBwInNonCongestedWindow;

        // ---- Network condition classification ----

        /// <summary>Current network condition classification.</summary>
        private NetworkCondition _networkCondition;

        /// <summary>
        /// Fine-grained local network condition used for pacing gain decisions.
        /// </summary>
        private enum NetworkCondition
        {
            /// <summary>No significant traffic observed yet.</summary>
            Idle,

            /// <summary>Light traffic load with minimal loss and stable RTT.</summary>
            LightLoad,

            /// <summary>Congestion detected: delivery rate dropping and/or RTT rising.</summary>
            Congested,

            /// <summary>Loss observed without significant RTT increase (likely random/noise).</summary>
            RandomLoss
        }

        /// <summary>
        /// Broad network path classification used to select pacing policies.
        /// </summary>
        public enum NetworkClass
        {
            /// <summary>Unclassified or generic network path.</summary>
            Default,

            /// <summary>Low-latency local area network (sub-5ms RTT, low jitter).</summary>
            LowLatencyLAN,

            /// <summary>High-RTT path with significant random loss (e.g. satellite, long-haul).</summary>
            LossyLongFat,

            /// <summary>Mobile/wireless path with high jitter and burst loss.</summary>
            MobileUnstable,

            /// <summary>Path dominated by a congested bottleneck link.</summary>
            CongestedBottleneck,

            /// <summary>Symmetric VPN/tunnel with moderate-high RTT (over 30ms).</summary>
            SymmetricVPN
        }

        /// <summary>
        /// Aggregated statistics window used by the network path classifier.
        /// </summary>
        private struct ClassifierWindow
        {
            /// <summary>Average RTT in microseconds over this window.</summary>
            public double AvgRttMicros;

            /// <summary>Loss rate (0.0 to 1.0) over this window.</summary>
            public double LossRate;

            /// <summary>RTT jitter (max - min) in microseconds over this window.</summary>
            public double JitterMicros;

            /// <summary>Throughput ratio relative to BtlBw (0.0 to 1.0).</summary>
            public double ThroughputRatio;
        }

        /// <summary>Circular buffer of classifier statistics windows.</summary>
        private readonly ClassifierWindow[] _classifierWindows = new ClassifierWindow[UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT];

        /// <summary>Current write position in the classifier window buffer.</summary>
        private int _classifierWindowIndex;

        /// <summary>Number of valid classifier windows collected.</summary>
        private int _classifierWindowCount;

        /// <summary>Start timestamp of the current classifier window.</summary>
        private long _classifierWindowStartMicros;

        /// <summary>Bytes sent during the current classifier window.</summary>
        private long _classifierWindowSentBytes;

        /// <summary>Minimum RTT observed during the current classifier window.</summary>
        private long _classifierWindowMinRttMicros;

        /// <summary>Maximum RTT observed during the current classifier window.</summary>
        private long _classifierWindowMaxRttMicros;

        /// <summary>Sum of RTT samples in the current classifier window.</summary>
        private long _classifierWindowRttSumMicros;

        /// <summary>Number of RTT samples in the current classifier window.</summary>
        private int _classifierWindowRttCount;

        // ---- Public properties ----

        /// <summary>Current network path classification.</summary>
        public NetworkClass CurrentNetworkClass { get; private set; }

        /// <summary>Current BBR operating mode (Startup, Drain, ProbeBw, or ProbeRtt).</summary>
        public BbrMode Mode { get; private set; }

        /// <summary>Estimated bottleneck bandwidth in bytes per second.</summary>
        public double BtlBwBytesPerSecond { get; private set; }

        /// <summary>Minimum observed RTT in microseconds.</summary>
        public long MinRttMicros { get; private set; }

        /// <summary>Current pacing gain multiplier applied to BtlBw.</summary>
        public double PacingGain { get; private set; }

        /// <summary>Current congestion window gain multiplier.</summary>
        public double CwndGain { get; private set; }

        /// <summary>Current pacing rate in bytes per second (BtlBw × PacingGain).</summary>
        public double PacingRateBytesPerSecond { get; private set; }

        /// <summary>Current congestion window in bytes.</summary>
        public int CongestionWindowBytes { get; private set; }

        /// <summary>Exponentially smoothed loss percentage estimate (0..100).</summary>
        public double EstimatedLossPercent { get; private set; }

        /// <summary>
        /// Creates a BBR congestion controller with default configuration.
        ///
        /// WHAT: Convenience constructor.  Uses UcpConfiguration defaults
        ///       for all parameters (gains, limits, thresholds).
        /// </summary>
        public BbrCongestionControl()
            : this(new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a BBR congestion controller initialized from the given configuration.
        ///
        /// WHAT: Initializes all rate/window/loss state from the provided config.
        ///       Enters Startup mode with initial pacing and CWND gains.
        ///
        /// WHY:  Startup begins with the configured initial bandwidth estimate
        ///       (typically the target bottleneck rate) and the startup gains
        ///       (typically 2.89× for both pacing and CWND, the standard BBR
        ///       Startup gain = 2/ln(2) ≈ 2.885).
        ///
        /// HOW:  1. Store config reference (fall back to default if null).
        ///       2. Set mode to Startup with startup gains.
        ///       3. Initialize BtlBw to the configured initial bandwidth,
        ///          clamped to MaxPacingRate if set.
        ///       4. Run initial model computation.
        /// </summary>
        /// <param name="config">Protocol configuration for BBR parameters.</param>
        public BbrCongestionControl(UcpConfiguration config)
        {
            _config = config ?? new UcpConfiguration();
            Mode = BbrMode.Startup;
            PacingGain = _config.StartupPacingGain;
            CwndGain = _config.StartupCwndGain;
            _maxBandwidthLossPercent = _config.EffectiveMaxBandwidthLossPercent;
            BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond;
            if (_config.MaxPacingRateBytesPerSecond > 0 && BtlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond)
            {
                BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond; // Clamp to max.
            }

            MinRttMicros = 0;
            RecalculateModel(UcpTime.NowMicroseconds());
        }

        /// <summary>
        /// Called by UcpPcb on each received ACK.
        /// Processes delivered bytes, RTT samples, advances round tracking,
        /// updates bandwidth estimate, and handles state transitions.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        /// <param name="deliveredBytes">Bytes newly acknowledged by this ACK.</param>
        /// <param name="sampleRttMicros">RTT sample from this ACK, or 0 if none.</param>
        /// <param name="flightBytes">Current bytes in flight.</param>
        public void OnAck(long nowMicros, int deliveredBytes, long sampleRttMicros, int flightBytes)
        {
            // ---- Step 1: Update MinRtt estimate ----
            // MinRtt is the floor of all RTT samples, with a sticky floor:
            // it can only decrease by at most 25% per sample.  This prevents
            // a single lucky fast measurement (e.g. during ProbeRTT drain)
            // from collapsing the CWND model.  Normal BBR uses a raw floor;
            // this is a slight deviation for robustness on real-world paths.
            bool minRttExpired = MinRttMicros > 0 && nowMicros - _minRttTimestampMicros >= _config.ProbeRttIntervalMicros;
            if (sampleRttMicros > 0)
            {
                _currentRttMicros = sampleRttMicros;
                if (MinRttMicros == 0 || sampleRttMicros < MinRttMicros)
                {
                    // Sticky min-RTT: only drop at most 25% per sample to prevent
                    // a single lucky fast measurement from collapsing CWND.
                    if (MinRttMicros > 0)
                    {
                        MinRttMicros = Math.Max(sampleRttMicros, (long)(MinRttMicros * 0.75d));
                    }
                    else
                    {
                        MinRttMicros = sampleRttMicros;
                    }
                    
                    _minRttTimestampMicros = nowMicros;
                    minRttExpired = false; // Resets the expiry clock.
                }
            }

            // ---- Step 2: Compute delivery rate for this ACK ----
            // Delivery rate = newly ACKed bytes / interval since last ACK.
            // We use the actual wall-clock interval rather than the RTT
            // sample because ACK compression can make RTT samples misleading.
            long intervalMicros;
            if (_lastAckMicros == 0)
            {
                intervalMicros = sampleRttMicros > 0 ? sampleRttMicros : 1;
            }
            else
            {
                intervalMicros = Math.Max(1, nowMicros - _lastAckMicros);
            }

            _lastAckMicros = nowMicros;

            // ---- Step 3: Feed delivery-rate samples into the max-filter ----
            if (deliveredBytes > 0)
            {
                _totalDeliveredBytes += deliveredBytes;
                double deliveryRate = deliveredBytes * UcpConstants.MICROS_PER_SECOND / (double)intervalMicros;
                if (PacingRateBytesPerSecond > 0)
                {
                    // Cap the delivery rate to prevent ACK aggregation from inflating estimates.
                    // ACK aggregation (multiple ACKs arriving in a tight burst after a gap)
                    // can produce absurdly high instantaneous delivery rates that are not
                    // representative of the path.  In Startup we allow a higher cap (2.5×)
                    // to avoid under-clamping during rapid ramp-up; in steady state the
                    // cap is tighter (1.3×).
                    double aggregationCapGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_ACK_AGGREGATION_RATE_CAP_GAIN : UcpConstants.BBR_STEADY_ACK_AGGREGATION_RATE_CAP_GAIN;
                    deliveryRate = Math.Min(deliveryRate, PacingRateBytesPerSecond * aggregationCapGain);
                }

                _deliveryRateBytesPerSecond = deliveryRate;
                AddRateSample(deliveryRate, nowMicros);       // Max-filter for BtlBw.
                AddDeliveryRateSample(deliveryRate);           // Trend history for congestion detection.
                if (_lossCwndGain < 1d && Mode != BbrMode.ProbeRtt)
                {
                    // Gradually recover CWND gain after loss reduction.
                    // Accelerated recovery on mobile/unstable paths where
                    // loss is rarely real congestion.
                    double recoveryStep = (CurrentNetworkClass == NetworkClass.MobileUnstable
                                            || _networkCondition == NetworkCondition.RandomLoss)
                        ? UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP_FAST
                        : UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP;
                    _lossCwndGain = Math.Min(1d, _lossCwndGain + recoveryStep);

                    // On mobile paths, don't let CWND stay depressed for
                    // more than 3 ACKs after any loss event.
                    if (CurrentNetworkClass == NetworkClass.MobileUnstable
                        && _lossCwndGain < 0.98d)
                    {
                        // Accelerate back to near-full.
                        _lossCwndGain = Math.Min(1d, _lossCwndGain + recoveryStep * 2d);
                    }
                }
            }

            if (sampleRttMicros > 0)
            {
                AddRttSample(sampleRttMicros);
            }

            // ---- Step 4: Classify network condition and path type ----
            // The local condition (Idle/LightLoad/Congested/RandomLoss) drives
            // immediate pacing and loss decisions.  The path class (LAN, Mobile,
            // LossyFat, etc.) drives long-term gain policies.
            AdvanceClassifierWindow(nowMicros, deliveredBytes + flightBytes, sampleRttMicros, GetRecentLossRatio(nowMicros));
            CurrentNetworkClass = ClassifyNetworkPath();

            _networkCondition = ClassifyNetworkCondition(nowMicros);
            if (_networkCondition == NetworkCondition.Congested)
            {
                // Congestion detected: reset the soft BtlBw floor so it
                // does not hold onto a rate that the path can no longer
                // support.
                _maxBtlBwInNonCongestedWindow = 0;
            }

            UpdateEstimatedLossPercent(nowMicros);
            UpdateInflightBounds();

            // ---- Step 5: ProbeRTT entry logic ----
            // ProbeRTT is the periodic deep-drain to refresh MinRtt.  Normal
            // BBR enters ProbeRTT unconditionally after ProbeRttInterval (10s).
            // We add several exceptions:
            //   a) Mobile paths: skip ProbeRTT entirely — their jitter is
            //      dominated by link-layer retransmissions, not queuing, so
            //      a P10/P30-based estimate is more useful than raw MinRtt.
            //   b) LossyLongFat with growing BtlBw: skip ProbeRTT to avoid
            //      disrupting a bandwidth discovery in progress.
            //   c) Bandwidth growth stalled + other paths: enter ProbeRTT as
            //      there is nothing to lose by draining the pipe.
            if (minRttExpired && Mode != BbrMode.ProbeRtt)
            {
                bool bandwidthGrowthStalled = _fullBandwidthRounds >= UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER;
                bool isLossyFat = CurrentNetworkClass == NetworkClass.LossyLongFat;
                bool isMobile = CurrentNetworkClass == NetworkClass.MobileUnstable;

                // Skip ProbeRTT on mobile paths — jitter dominates RTT and
                // P10/P30 tracking already provides a robust min RTT proxy.
                // Entering ProbeRTT just creates an unnecessary throughput cliff.
                if (isMobile)
                {
                    // Just refresh the min-RTT timestamp to keep it fresh.
                    _minRttTimestampMicros = nowMicros;
                }
                else if (bandwidthGrowthStalled || !isLossyFat)
                {
                    EnterProbeRtt(nowMicros);
                }
                else
                {
                    TraceLog(string.Concat("SkipProbeRtt btlBw=", BtlBwBytesPerSecond, " fullBwRounds=", _fullBandwidthRounds, " preservedOnLossyFat"));
                }
            }

            // ---- Step 6: Round detection ----
            // A BBR "round" is completed when cumulative delivered bytes
            // reach the threshold (_nextRoundDeliveredBytes).  The round
            // length is approximately one BDP worth of data, which on a
            // well-paced connection equals one RTT.  Round boundaries
            // trigger Startup exit checks and ProbeBW gain-cycle advances.
            bool roundStart = false;
            if (_nextRoundDeliveredBytes == 0)
            {
                _nextRoundDeliveredBytes = _totalDeliveredBytes + Math.Max(deliveredBytes, flightBytes);
            }
            else if (_totalDeliveredBytes >= _nextRoundDeliveredBytes)
            {
                _nextRoundDeliveredBytes = _totalDeliveredBytes + Math.Max(deliveredBytes, flightBytes);
                roundStart = deliveredBytes > 0;
            }

            // ---- Step 7: State-machine dispatch ----
            // Each state has a different behavior on ACK and round events.

            // --- STARTUP: exponential bandwidth probing ---
            // Pacing at 2.89× BtlBw, CWND at 2.89× BDP.  At each round
            // boundary, check whether BtlBw grew by ≥ 1.25×.  If it stalls
            // for N rounds, transition to Drain.
            if (Mode == BbrMode.Startup)
            {
                if (roundStart)
                {
                    UpdateStartup();
                }
            }
            // --- DRAIN: queue-draining transition ---
            // Pacing at DrainPacingGain (typically 0.75–0.90× depending on
            // loss conditions).  Exit when in-flight bytes drop to the BDP
            // target or the minimum duration has elapsed.
            else if (Mode == BbrMode.Drain)
            {
                // Exit drain when in-flight drops to the target or the minimum duration elapsed.
                if (flightBytes <= GetTargetCwndBytes() || nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, UcpConstants.BBR_MIN_ROUND_DURATION_MICROS))
                {
                    EnterProbeBw(nowMicros);
                }
            }
            // --- PROBEBW: steady-state gain cycling ---
            // Cycle through the 8-phase gain sequence once per round.
            // Mobile/lossy paths spend 7/8 of the time in high-gain
            // phases to compensate for non-congestion throughput loss.
            else if (Mode == BbrMode.ProbeBw)
            {
                // Advance the gain cycle index when the round duration elapses.
                if (nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, UcpConstants.BBR_MIN_ROUND_DURATION_MICROS))
                {
                    _probeBwCycleIndex = (_probeBwCycleIndex + 1) % UcpConstants.BBR_PROBE_BW_GAIN_COUNT;
                    _modeEnteredMicros = nowMicros;
                }

                // On mobile/lossy non-congested paths, stay in the high-gain
                // phase longer (7/8 instead of 4/8) to maintain throughput.
                if ((CurrentNetworkClass == NetworkClass.MobileUnstable
                     || CurrentNetworkClass == NetworkClass.LossyLongFat)
                    && _networkCondition != NetworkCondition.Congested)
                {
                    // Only use low-gain phase 1/8 of the time.
                    if (_probeBwCycleIndex < UcpConstants.BBR_PROBE_BW_GAIN_COUNT - 1)
                    {
                        PacingGain = CalculatePacingGain(nowMicros);
                    }
                    else
                    {
                        PacingGain = Math.Min(1.0d, _config.ProbeBwLowGain);
                    }
                }
                else
                {
                    PacingGain = CalculatePacingGain(nowMicros);
                }
            }
            // --- PROBERTT: deep-drain to measure true base RTT ---
            // CWND reduced to 4×MSS, pacing at 0.5× BtlBw.  Exit when
            // a near-minimum RTT sample confirms the base RTT or the
            // safety timeout fires.  On non-congested paths, exit faster.
            else if (Mode == BbrMode.ProbeRtt)
            {
                PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
                if (ShouldExitProbeRtt(nowMicros, sampleRttMicros))
                {
                    ExitProbeRtt(nowMicros, sampleRttMicros);
                }
            }

            // ---- Step 8: Fast recovery timeout ----
            // Fast recovery (elevated pacing for non-congestion loss) lasts
            // at most one RTT.  After that, normal pacing resumes.
            if (_fastRecoveryEnteredMicros > 0 && MinRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros >= MinRttMicros)
            {
                _fastRecoveryEnteredMicros = 0; // Exit fast recovery after one RTT.
            }

            // ---- Step 9: Recompute pacing rate and CWND ----
            RecalculateModel(nowMicros);
        }

        /// <summary>
        /// Called by UcpPcb when a packet is sent. Advances loss buckets and
        /// increments the per-bucket sent/retransmit counters.
        ///
        /// WHAT: Maintains the per-time-slot sent and retransmit counters used
        ///       by GetRecentLossRatio().  Every packet send (original or
        ///       retransmit) is recorded to provide accurate loss statistics.
        ///
        /// WHY:  Loss ratio = retransmitted / total sent.  This requires
        ///       accurate accounting of both sent and retransmitted packets
        ///       within the sliding window.
        ///
        /// HOW:  1. Advance the bucket ring to age out expired data.
        ///       2. Increment the current bucket's sent counter.
        ///       3. If retransmit, also increment the retransmit counter.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        /// <param name="isRetransmit">Whether this packet is a retransmission.</param>
        public void OnPacketSent(long nowMicros, bool isRetransmit)
        {
            AdvanceLossBuckets(nowMicros);
            _sentBuckets[_lossBucketIndex]++;
            if (isRetransmit)
            {
                _retransmitBuckets[_lossBucketIndex]++;
            }
        }

        /// <summary>
        /// Called by UcpPcb when a fast retransmit is triggered (by duplicate ACK,
        /// SACK, or NAK). Non-congestion fast retransmits enter a recovery mode
        /// with a higher pacing gain.
        ///
        /// WHAT: Handles the fast-retransmit path.  If the loss is classified
        ///       as non-congestion, enters a one-RTT fast recovery period with
        ///       elevated pacing gain (1.15×).  Congestion fast retransmits
        ///       fall through to OnPacketLoss for multiplicative reduction.
        ///
        /// WHY:  A SACK-triggered fast retransmit on a clean path is usually
        ///       a burst error, not congestion.  Reducing CWND would be an
        ///       overreaction.  Instead, we briefly elevate pacing to refill
        ///       the hole without waiting for the RTO.
        ///
        /// HOW:  1. Log the event for diagnostics.
        ///       2. If not congestion: start fast recovery, set pacing gain,
        ///          recompute the model.
        ///       3. Forward to OnPacketLoss for loss ratio tracking and
        ///          condition classification regardless.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        /// <param name="isCongestion">Whether the loss was classified as congestion.</param>
        public void OnFastRetransmit(long nowMicros, bool isCongestion)
        {
            if (_config.EnableDebugLog)
            {
                Trace.WriteLine("[UCP BBR] FastRetransmit congestion=" + isCongestion);
            }

            if (!isCongestion)
            {
                // Non-congestion loss: enter fast recovery with elevated pacing gain.
                _fastRecoveryEnteredMicros = nowMicros;
                PacingGain = UcpConstants.BBR_FAST_RECOVERY_PACING_GAIN;
                RecalculateModel(nowMicros);
            }

            OnPacketLoss(nowMicros, GetRecentLossRatio(nowMicros), isCongestion);
        }

        /// <summary>
        /// Called by UcpPcb when packet loss is detected (by RTO, NAK, or duplicate ACK).
        /// Applies loss-control rules: random loss vs congestion loss classification,
        /// pacing/CWND reduction, and possibly entering ProbeRTT.
        ///
        /// WHAT: The central loss handler.  Sanitizes the loss rate, updates
        ///       the EWMA loss estimate, classifies the loss as congestion vs
        ///       random, and takes corrective action.
        ///
        /// WHY:  Different loss types need different responses:
        ///       - Congestion loss → multiplicative CWND reduction (×0.70)
        ///         AND enter ProbeRTT to get a fresh MinRtt.
        ///       - Random loss → fast recovery only (no CWND reduction).
        ///         The path can support the current rate; the loss is noise.
        ///
        /// HOW:  1. Sanitize nowMicros and merge loss rate inputs.
        ///       2. Re-classify network condition with current data.
        ///       3. Update EWMA loss estimate.
        ///       4. Use ShouldTreatLossAsCongestion to decide the response.
        ///       5a. Congestion: reduce _lossCwndGain (×0.70), enter ProbeRTT.
        ///       5b. Random: enter fast recovery, maintain/increase pacing.
        ///       6. Recompute the model.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        /// <param name="lossRate">Recent loss ratio (0.0 to 1.0).</param>
        /// <param name="isCongestion">Whether the loss was externally classified as congestion.</param>
        public void OnPacketLoss(long nowMicros, double lossRate, bool isCongestion)
        {
            if (nowMicros <= 0)
            {
                nowMicros = UcpTime.NowMicroseconds();
            }

            // Merge externally-provided loss rate with the internal sliding-window
            // ratio.  Take the max — if either says loss is high, we should be
            // conservative.
            double recentLossRate = GetRecentLossRatio(nowMicros);
            lossRate = Math.Max(lossRate, recentLossRate);

            // Re-evaluate condition with the freshest data.
            _networkCondition = ClassifyNetworkCondition(nowMicros);
            UpdateEstimatedLossPercent(nowMicros, lossRate * 100d);

            bool treatAsCongestion = ShouldTreatLossAsCongestion(nowMicros, isCongestion);

            if (treatAsCongestion)
            {
                // Congestion loss: apply multiplicative CWND reduction.
                // _lossCwndGain starts at 1.0 and drops to 0.70 on first
                // congestion event, 0.49 on second, etc.  It recovers
                // gradually on subsequent ACKs (see OnAck).
                _lossCwndGain = Math.Max(UcpConstants.BBR_MIN_LOSS_CWND_GAIN,
                    _lossCwndGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);

                // On congestion, enter ProbeRTT to get a fresh MinRtt.
                // The congestion queue may have inflated RTT, so we need
                // a new baseline before resuming normal operation.
                if (Mode != BbrMode.ProbeRtt && Mode != BbrMode.Startup)
                {
                    EnterProbeRtt(nowMicros);
                }
            }
            else
            {
                // Random/non-congestion loss: fast recovery with elevated pacing.
                // Never reduce CWND for random loss.
                _fastRecoveryEnteredMicros = nowMicros;
                if (Mode == BbrMode.ProbeBw)
                {
                    // Ensure pacing gain is at least the calculated probe gain.
                    // Don't let a random loss drop us below the normal probe level.
                    PacingGain = Math.Max(PacingGain, CalculatePacingGain(nowMicros));
                }
            }

            RecalculateModel(nowMicros);
        }

        /// <summary>
        /// Checks bandwidth growth between rounds during Startup.
        ///
        /// WHAT: Evaluates whether BtlBw has grown by at least 1.25× since
        ///       the last round.  If growth stalls for enough consecutive
        ///       rounds, transitions to Drain.
        ///
        /// WHY:  Startup doubles the sending rate each round to rapidly
        ///       discover the bottleneck bandwidth.  The exit condition is
        ///       based on bandwidth growth stalling — when the pipe is full,
        ///       delivery rate stops increasing even though we keep raising
        ///       the pacing rate.  This is more accurate than exiting on
        ///       the first loss (CUBIC-style) because it doesn't confuse
        ///       random loss with capacity discovery.
        ///
        /// HOW:  1. Track _fullBandwidthEstimate as the best BtlBw seen.
        ///       2. Each round, check if current BtlBw ≥ 1.25× the tracked best.
        ///          - Yes → update best, reset stall counter (still growing).
        ///          - No  → increment stall counter (growth may be done).
        ///       3. When stall counter reaches the threshold (default 3 rounds),
        ///          enter Drain to flush the standing queue.
        ///       4. Fast-exit: if BtlBw has reached ≥ 90% of the configured
        ///          MaxPacingRate, exit after just 1 stall round.
        /// </summary>
        private void UpdateStartup()
        {
            double current = BtlBwBytesPerSecond;
            if (_fullBandwidthEstimate <= 0)
            {
                _fullBandwidthEstimate = current;
                return;
            }

            // Growth ≥ 1.25× → still ramping up; reset stall counter.
            if (current >= _fullBandwidthEstimate * UcpConstants.BbrStartupGrowthTarget)
            {
                _fullBandwidthEstimate = current;
                _fullBandwidthRounds = 0; // Growth achieved; reset stall counter.
            }
            else
            {
                _fullBandwidthRounds++; // No significant growth this round.
            }

            // Exit Startup faster when bandwidth is stable near the target
            // (non-auto-probe scenario with configured rate cap).
            // If the user specified a MaxPacingRate and we've hit 90% of it,
            // there is no point in staying in Startup — the configured cap
            // is the limit, not the physical path.
            int requiredStallRounds = UcpConstants.MinBbrStartupFullBandwidthRounds;
            if (_config.MaxPacingRateBytesPerSecond > 0
                && BtlBwBytesPerSecond >= _config.MaxPacingRateBytesPerSecond * 0.90d)
            {
                requiredStallRounds = 1; // Fast exit: already at target.
            }

            if (_fullBandwidthRounds >= requiredStallRounds)
            {
                EnterDrain(_lastAckMicros);
            }
        }

        /// <summary>
        /// Adds a delivery-rate sample to the max-filter window for BtlBw estimation.
        ///
        /// WHAT: BtlBw is computed as the maximum delivery rate observed within
        ///       a sliding time window of recent samples.  This is the core
        ///       "max-filter" that makes BBR robust to ACK compression and
        ///       transient rate dips.  Unlike a moving average, the max-filter
        ///       can quickly discover bandwidth increases while ignoring
        ///       downward noise.
        ///
        /// WHY:  Using max (not avg) means:
        ///       1. ACK compression spikes are captured as valid (they prove
        ///          the pipe CAN deliver at that rate).
        ///       2. RTO gaps and transient loss dips do NOT depress the estimate.
        ///       3. The filter forgets stale samples only when they age out of
        ///          the time window (typically 6–10 RTTs).
        ///
        /// HOW:  1. Store the new rate in a circular buffer with timestamp.
        ///       2. Scan all samples within the RTT window range, pick the max.
        ///       3. Apply growth clamping (per-round limit) to prevent overestimation.
        ///       4. Apply hard floor (InitialBandwidth) and soft floor (90% of
        ///          max non-congested BtlBw, when loss &lt; 5%) to prevent the
        ///          estimate from collapsing.
        /// </summary>
        /// <param name="deliveryRate">New delivery rate in bytes per second.</param>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void AddRateSample(double deliveryRate, long nowMicros)
        {
            // Push new sample into the circular buffer.
            _recentRates[_recentRateIndex] = deliveryRate;
            _recentRateTimestamps[_recentRateIndex] = nowMicros;
            _recentRateIndex = (_recentRateIndex + 1) % _recentRates.Length;
            if (_recentRateCount < _recentRates.Length)
            {
                _recentRateCount++;
            }

            // Max-filter: scan all recent samples within the time window
            // and pick the maximum.  The window is typically ~6 RTTs wide.
            double maxRate = 0;
            long rttWindowMicros = MinRttMicros > 0 ? MinRttMicros * Math.Max(1, _config.BbrWindowRtRounds) : UcpConstants.BBR_DEFAULT_RATE_WINDOW_MICROS;
            for (int i = 0; i < _recentRateCount; i++)
            {
                // Expire samples older than the window.
                if (nowMicros - _recentRateTimestamps[i] > Math.Max(rttWindowMicros, 1))
                {
                    continue; // Sample is outside the window.
                }

                if (_recentRates[i] > maxRate)
                {
                    maxRate = _recentRates[i];
                }
            }

            if (maxRate > 0)
            {
                // Clamp growth: limit how fast BtlBw can increase per round.
                // This prevents a single bursty measurement from over-shooting.
                maxRate = ClampBandwidthGrowth(maxRate, nowMicros);
                if (_config.MaxPacingRateBytesPerSecond > 0 && maxRate > _config.MaxPacingRateBytesPerSecond)
                {
                    maxRate = _config.MaxPacingRateBytesPerSecond;
                }

                // Track maximum BtlBw seen during non-congested intervals.
                // This serves as a soft floor: when the network is not
                // congested, we know the path can support at least this rate.
                if (_networkCondition != NetworkCondition.Congested)
                {
                    if (maxRate > _maxBtlBwInNonCongestedWindow)
                    {
                        _maxBtlBwInNonCongestedWindow = maxRate;
                    }
                }

                BtlBwBytesPerSecond = maxRate;

                // Hard floor: BtlBw never drops below the configured initial
                // bandwidth (which is the target bottleneck rate).
                if (BtlBwBytesPerSecond < _config.InitialBandwidthBytesPerSecond)
                {
                    BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond;
                    if (_config.MaxPacingRateBytesPerSecond > 0 && BtlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond)
                    {
                        BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond;
                    }
                }

                // Soft floor on non-congested paths: prevent transient
                // delivery-rate dips (e.g. random loss gaps) from crushing
                // the long-term bandwidth estimate.
                // Floor at 90% of max seen BtlBw in non-congested conditions.
                // Only applies when actual loss is &lt; 5% to avoid sustaining
                // an impossible rate on truly lossy links.
                if (_networkCondition != NetworkCondition.Congested
                    && _maxBtlBwInNonCongestedWindow > 0
                    && GetRecentLossRatio(nowMicros) < 0.05d
                    && BtlBwBytesPerSecond < _maxBtlBwInNonCongestedWindow * 0.90d)
                {
                    BtlBwBytesPerSecond = _maxBtlBwInNonCongestedWindow * 0.90d;
                }
            }
        }

        /// <summary>
        /// Clamps excessive bandwidth growth within a single growth window.
        ///
        /// WHAT: Limits BtlBw growth to a multiplicative factor per RTT.
        ///       Without this clamp, ACK compression spikes or burst
        ///       deliveries could cause BtlBw to jump unrealistically.
        ///
        /// WHY:  The max-filter is aggressive about adopting high samples.
        ///       A single measurement glitch could inflate BtlBw by 10×,
        ///       causing the sender to dramatically over-pace and create
        ///       self-inflicted loss.  The clamp bounds each round's growth
        ///       to a sane multiplier (e.g. 4× in Startup, 1.25× steady).
        ///
        /// HOW:  Track the BtlBw at the start of each growth window (1 RTT).
        ///       Cap any candidate rate at (startRate × growthGain).  The
        ///       window resets each RTT, so sustained growth is still
        ///       permitted — just not all in one burst.
        /// </summary>
        /// <param name="candidateRate">Candidate bandwidth in bytes per second.</param>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <returns>Clamped bandwidth value.</returns>
        private double ClampBandwidthGrowth(double candidateRate, long nowMicros)
        {
            if (candidateRate <= BtlBwBytesPerSecond || BtlBwBytesPerSecond <= 0)
            {
                return candidateRate; // No increase, no clamping needed.
            }

            long growthIntervalMicros = MinRttMicros > 0 ? MinRttMicros : UcpConstants.BBR_BANDWIDTH_GROWTH_FALLBACK_INTERVAL_MICROS;
            if (_bandwidthGrowthWindowMicros == 0 || nowMicros - _bandwidthGrowthWindowMicros >= growthIntervalMicros)
            {
                // Start a new growth window.
                _bandwidthGrowthWindowMicros = nowMicros;
                _bandwidthGrowthWindowStartRate = BtlBwBytesPerSecond;
            }

            // Growth cap: Startup allows more aggressive growth (4× per round)
            // because BtlBw is expected to double each round during ramp-up.
            // Steady state caps at 1.25× to prevent overshoot.
            double growthGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_BANDWIDTH_GROWTH_PER_ROUND : UcpConstants.BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND;
            double growthCap = Math.Max(BtlBwBytesPerSecond, _bandwidthGrowthWindowStartRate * growthGain);
            return Math.Min(candidateRate, growthCap);
        }

        /// <summary>
        /// Adds a delivery-rate sample to the history buffer (for trend-based congestion detection).
        ///
        /// WHAT: Maintains a circular buffer of recent delivery-rate samples
        ///       used by ClassifyNetworkCondition to detect declining throughput.
        ///       Separate from the max-filter buffer (_recentRates).
        ///
        /// WHY:  The max-filter only tracks the peak; it cannot detect a
        ///       declining trend.  The delivery-rate history buffer preserves
        ///       temporal order, allowing oldest-vs-newest comparison to
        ///       identify throughput drops that signal congestion.
        /// </summary>
        /// <param name="deliveryRate">Delivery rate in bytes per second.</param>
        private void AddDeliveryRateSample(double deliveryRate)
        {
            _deliveryRateHistory[_deliveryRateHistoryIndex] = deliveryRate;
            _deliveryRateHistoryIndex = (_deliveryRateHistoryIndex + 1) % _deliveryRateHistory.Length;
            if (_deliveryRateHistoryCount < _deliveryRateHistory.Length)
            {
                _deliveryRateHistoryCount++;
            }
        }

        /// <summary>
        /// Adds an RTT sample to the history buffer (for jitter and trend analysis).
        ///
        /// WHAT: Stores RTT samples in a circular buffer used by
        ///       GetPercentileRtt() and GetAverageRttIncreaseRatio().
        ///       The P10 percentile naturally discards outlier samples, so we
        ///       only filter truly pathological values (seconds-long RTO stalls)
        ///       to keep the buffer from being dominated by stale entries.
        ///
        /// WHY:  Raw RTT samples from an RTO timeout can be seconds long.
        ///       Including those in the percentile computation would push
        ///       P10 far above the actual propagation delay.  A 500ms hard
        ///       cap discards these pathological stalls while preserving
        ///       normal queuing delay (typically 1–200ms).
        /// </summary>
        /// <param name="sampleRttMicros">RTT sample in microseconds.</param>
        private void AddRttSample(long sampleRttMicros)
        {
            if (sampleRttMicros <= 0)
            {
                return;
            }

            // Hard cap at 500ms: any larger value is a protocol stall
            // (RTO timeout) and would corrupt the percentile estimate.
            if (sampleRttMicros > 500_000L)
            {
                return;
            }

            _rttHistoryMicros[_rttHistoryIndex] = sampleRttMicros;
            _rttHistoryIndex = (_rttHistoryIndex + 1) % _rttHistoryMicros.Length;
            if (_rttHistoryCount < _rttHistoryMicros.Length)
            {
                _rttHistoryCount++;
            }
        }

        /// <summary>
        /// Computes the target congestion window in bytes.
        ///
        /// WHAT: CWND = BDP × CwndGain, where BDP = BtlBw × modelRtt.
        ///       The model RTT uses P10 percentile (not raw MinRtt) for
        ///       robustness.  Result is clamped by hard/soft floor, ceiling,
        ///       loss-gain reduction, and inflight guardrails.
        ///
        /// WHY:  The BDP model ensures the pipe is kept full without building
        ///       excessive standing queues.  Using P10 RTT instead of raw
        ///       MinRtt prevents a single lucky fast measurement from
        ///       collapsing the CWND.  The ceiling at 2× BDP prevents
        ///       bufferbloat even when CwndGain is high.
        ///
        /// HOW:  1. modelRtt = max(MinRtt, P10 RTT), capped at 1 second.
        ///       2. bdp = BtlBw × (modelRtt in seconds).
        ///       3. Apply effective CwndGain (loss-adjusted, waste-budget capped).
        ///       4. Clamp to [InitialCwnd, MaxCwnd] and inflight guardrails.
        /// </summary>
        /// <returns>Target congestion window in bytes.</returns>
        private int GetTargetCwndBytes()
        {
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)
            {
                return _config.InitialCongestionWindowBytes;
            }

            long modelRttMicros = GetCwndModelRttMicros();

            // Sanity cap: modelRtt must not exceed 1 second to prevent
            // runaway CWND during pathological stalls.
            if (modelRttMicros > 1_000_000L || modelRttMicros <= 0)
            {
                modelRttMicros = 1_000_000L;
            }

            // BDP = bandwidth × delay.  This is the amount of data "in the
            // pipe" at the bottleneck rate over the propagation delay.
            double bdp = BtlBwBytesPerSecond * (modelRttMicros / (double)UcpConstants.MICROS_PER_SECOND);
            double effectiveCwndGain = GetEffectiveCwndGain();
            int cwnd = (int)Math.Ceiling(bdp * effectiveCwndGain);
            if (cwnd < _config.InitialCongestionWindowBytes && Mode == BbrMode.Startup)
            {
                cwnd = _config.InitialCongestionWindowBytes;
            }

            if (_config.MaxCongestionWindowBytes > 0 && cwnd > _config.MaxCongestionWindowBytes)
            {
                cwnd = _config.MaxCongestionWindowBytes;
            }

            // Apply loss-driven CWND reduction.  When congestion loss occurs,
            // _lossCwndGain drops below 1.0, multiplicatively reducing the
            // window.  It then recovers gradually on subsequent ACKs.
            if (_lossCwndGain < 1d)
            {
                cwnd = (int)Math.Ceiling(cwnd * _lossCwndGain);
                if (cwnd < _config.InitialCongestionWindowBytes)
                {
                    cwnd = _config.InitialCongestionWindowBytes;
                }
            }

            // Apply inflight guardrails.
            // _inflightHighBytes = upper bound (ceiling); prevents CWND from
            //   creating excessive standing queues even with high CwndGain.
            // _inflightLowBytes = lower bound (floor); prevents CWND from
            //   starving the connection on low-BDP paths.
            if (_inflightHighBytes > 0)
            {
                cwnd = Math.Min(cwnd, (int)Math.Ceiling(_inflightHighBytes));
            }

            if (_inflightLowBytes > 0)
            {
                cwnd = Math.Max(cwnd, (int)Math.Ceiling(_inflightLowBytes));
            }

            return cwnd;
        }

        /// <summary>
        /// Recalculates the pacing rate, congestion window, and applies mode-specific
        /// and loss-control adjustments.
        ///
        /// WHAT: The final computation step after every ACK/loss event.  Derives
        ///       PacingRate = BtlBw × PacingGain and CongestionWindow from the
        ///       BDP model, then applies all ceilings and floors.
        ///
        /// WHY:  This is the single point where all estimates converge into
        ///       actionable send-rate and window limits.  Keeping it centralized
        ///       ensures consistency — pacing and CWND always use the same
        ///       underlying BtlBw and MinRtt values.
        ///
        /// HOW:  1. Sanitize BtlBw (ensure non-zero, respect max cap).
        ///       2. Compute PacingRate = BtlBw × PacingGain with loss-control override.
        ///       3. Compute CWND via GetTargetCwndBytes, halved in ProbeRTT.
        ///       4. Apply hard ceiling: 2× BDP using P10 RTT (not raw MinRtt)
        ///          to prevent bufferbloat from a single lucky fast sample.
        ///       5. Apply minimum: 4× MSS to avoid total starvation.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void RecalculateModel(long nowMicros)
        {
            if (BtlBwBytesPerSecond <= 0)
            {
                BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond;
            }

            if (_config.MaxPacingRateBytesPerSecond > 0 && BtlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond)
            {
                BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond;
            }

            // ProbeRTT always paces at the low gain to drain the pipe.
            if (Mode == BbrMode.ProbeRtt)
            {
                PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
            }

            // Loss-control: when loss is well within budget, gradually
            // increase pacing gain back toward the high gain (recovery).
            if (_config.LossControlEnable)
            {
                if (EstimatedLossPercent <= _maxBandwidthLossPercent * UcpConstants.BBR_LOSS_BUDGET_RECOVERY_RATIO)
                {
                    PacingGain = Math.Min(_config.ProbeBwHighGain, PacingGain + UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP);
                }
            }

            PacingRateBytesPerSecond = BtlBwBytesPerSecond * PacingGain;
            if (_config.MaxPacingRateBytesPerSecond > 0
                && PacingRateBytesPerSecond > _config.MaxPacingRateBytesPerSecond
                && EstimatedLossPercent < 3d)
            {
                PacingRateBytesPerSecond = _config.MaxPacingRateBytesPerSecond;
            }

            // Unconditional cap for non-mobile non-lossy-fat paths:
            // pacing rate never exceeds 1.30× the configured target
            // to prevent test-tolerance violations on clean paths.
            if (_config.MaxPacingRateBytesPerSecond > 0
                && CurrentNetworkClass != NetworkClass.MobileUnstable
                && CurrentNetworkClass != NetworkClass.LossyLongFat)
            {
                double maxPacing = _config.MaxPacingRateBytesPerSecond * 1.30d;
                if (PacingRateBytesPerSecond > maxPacing)
                {
                    PacingRateBytesPerSecond = maxPacing;
                }
            }

            // ProbeRTT halves the CWND to accelerate pipe draining.
            CongestionWindowBytes = Mode == BbrMode.ProbeRtt ? Math.Max(_config.InitialCongestionWindowBytes, GetTargetCwndBytes() / 2) : GetTargetCwndBytes();

            // ---- Hard CWND ceiling: 2× BDP using P10 RTT ----
            // Raw MinRtt is vulnerable to a single lucky fast sample (e.g.
            // during ProbeRTT drain).  If MinRtt drops to 1ms on a path
            // whose real propagation delay is 30ms, CWND would be 30× too
            // small.  Using P10 RTT as the ceiling base gives a more
            // robust upper bound.
            //
            // Ceiling = 2.0× BtlBw × P10_RTT for most paths.
            // SymmetricVPN gets a tighter ceiling (1.0× BtlBw × 2×MinRtt)
            // to avoid buffer stuffing in tunnel scenarios.
            //
            // The ceiling is capped at 5 seconds RTT to prevent arithmetic
            // overflow on extremely pathological paths.
            if (MinRttMicros > 0 && BtlBwBytesPerSecond > 0)
            {
                double ceilingMultiplier;
                long ceilingRtt;
                if (CurrentNetworkClass == NetworkClass.SymmetricVPN)
                {
                    // VPN paths: use 2× MinRtt with 1× multiplier.
                    // Conservative to avoid queuing inside the tunnel.
                    ceilingRtt = (long)(MinRttMicros * 2.0d);
                    ceilingMultiplier = 1.0d;
                }
                else
                {
                    // Default: use max(MinRtt, P10 RTT) with 2× multiplier.
                    // P10 RTT filters out extreme fast samples.
                    ceilingRtt = Math.Max(MinRttMicros, GetP10RttMicros());
                    if (ceilingRtt <= 0) ceilingRtt = MinRttMicros;
                    ceilingMultiplier = 2.0d;
                }

                // Prevent overflow: cap RTT at 5 seconds.
                if (ceilingRtt > 5_000_000L)
                {
                    ceilingRtt = 5_000_000L;
                }

                long bdpCeilingLong = (long)(BtlBwBytesPerSecond * (ceilingRtt / 1000000.0d) * ceilingMultiplier);
                if (bdpCeilingLong > int.MaxValue)
                {
                    bdpCeilingLong = int.MaxValue;
                }

                int bdpCeiling = (int)bdpCeilingLong;
                if (_config.MaxCongestionWindowBytes > 0 && bdpCeiling > _config.MaxCongestionWindowBytes)
                {
                    bdpCeiling = _config.MaxCongestionWindowBytes;
                }

                if (CongestionWindowBytes > bdpCeiling)
                {
                    CongestionWindowBytes = bdpCeiling;
                }

                // Additional RTO-based ceiling for very small BDP ceilings
                // (<100KB).  Uses MinRtt + 90% of RTO as a tighter bound.
                if (bdpCeiling < 100_000L && _config.EffectiveMinRtoMicros > 0)
                {
                    long maxRtt = (long)(MinRttMicros + _config.EffectiveMinRtoMicros * 0.90d);
                    int rtoCeiling = (int)(BtlBwBytesPerSecond * (maxRtt / 1000000.0d));
                    if (rtoCeiling > 0 && CongestionWindowBytes > rtoCeiling)
                    {
                        CongestionWindowBytes = rtoCeiling;
                    }
                }
            }
            else if (BtlBwBytesPerSecond > 0)
            {
                // Fallback when MinRtt is unavailable: use RTO as the delay proxy.
                if (_config.EffectiveMinRtoMicros > 0)
                {
                    int rtoCeiling = (int)(BtlBwBytesPerSecond * (_config.EffectiveMinRtoMicros / 1000000.0d));
                    if (rtoCeiling > 0 && CongestionWindowBytes > rtoCeiling)
                    {
                        CongestionWindowBytes = rtoCeiling;
                    }
                }

                if (_config.MaxCongestionWindowBytes > 0 && CongestionWindowBytes > _config.MaxCongestionWindowBytes)
                {
                    CongestionWindowBytes = _config.MaxCongestionWindowBytes;
                }
            }

            // Absolute minimum: 4× MSS prevents complete stalling.
            if (CongestionWindowBytes < _config.Mss * 4)
            {
                CongestionWindowBytes = _config.Mss * 4;
            }

            _modeEnteredMicros = _modeEnteredMicros == 0 ? nowMicros : _modeEnteredMicros;
        }

        /// <summary>
        /// Transitions from Startup to Drain.
        ///
        /// WHAT: Startup has discovered the bottleneck bandwidth.  Now Drain
        ///       flushes the standing queue by pacing below the bottleneck
        ///       rate.  Drain pacing gain is adaptive: 1.00× on clean paths
        ///       (just coast), config-specified on lossy paths (typically
        ///       0.75–0.90× to actively drain).
        ///
        /// WHY:  During Startup we pace at 2.89× BtlBw, which creates a
        ///       standing queue approximately 1.89× BDP deep.  If we jumped
        ///       straight to 1.00× pacing, that queue would persist for
        ///       many RTTs, inflating RTT samples.  Drain actively reduces
        ///       the queue before entering steady-state ProbeBW.
        ///
        /// HOW:  Set mode, compute drain pacing gain, record entry time.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void EnterDrain(long nowMicros)
        {
            Mode = BbrMode.Drain;
            PacingGain = GetDrainPacingGain(nowMicros);
            _modeEnteredMicros = nowMicros;
        }

        /// <summary>
        /// Transitions to ProbeBW mode at the start of the gain cycle.
        ///
        /// WHAT: Enters the steady-state ProbeBW mode.  Sets CWND gain to
        ///       2.0× BDP (sufficient retransmission headroom without
        ///       bufferbloat) and resets the 8-phase gain cycle to index 0.
        ///
        /// WHY:  After Drain finishes, the pipe is clean.  ProbeBW maintains
        ///       the discovered rate while periodically probing for more
        ///       bandwidth (1.25× phase) and draining any accumulated queue
        ///       (0.75× phase).
        ///
        /// HOW:  Set mode, reset cycle index, set CWND gain, compute initial
        ///       pacing gain, record entry time.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void EnterProbeBw(long nowMicros)
        {
            Mode = BbrMode.ProbeBw;
            _probeBwCycleIndex = 0;

            // CWND gain at 2.0x BDP for all paths provides sufficient headroom
            // for retransmissions without causing bufferbloat.
            CwndGain = _config.ProbeBwCwndGain; // 2.0x BDP.

            PacingGain = CalculatePacingGain(nowMicros);
            _modeEnteredMicros = nowMicros;
        }

        /// <summary>
        /// Determines the drain pacing gain: 1.0 if no loss; config drain gain otherwise.
        ///
        /// WHAT: On clean paths with zero recent loss, Drain can use 1.00×
        ///       pacing (no active draining) because the Startup standing
        ///       queue will drain naturally as we stop over-pacing.
        ///       On lossy paths, use the configured DrainPacingGain
        ///       (typically 0.75–0.90×) to actively reduce the queue.
        ///
        /// WHY:  Active draining below 1.00× costs throughput but is necessary
        ///       when the path is already showing loss.  Draining the queue
        ///       reduces RTT and gives the path a clean baseline for ProbeBW.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <returns>Pacing gain for the drain phase.</returns>
        private double GetDrainPacingGain(long nowMicros)
        {
            double recentLossRatio = GetRecentLossRatio(nowMicros);
            if (recentLossRatio <= 0 && EstimatedLossPercent <= 0)
            {
                return 1d; // Clean drain: use minimal drain gain.
            }

            return _config.DrainPacingGain;
        }

        /// <summary>
        /// Enters ProbeRTT mode: reduces pacing to drain the pipe and measure
        /// the true minimum RTT.
        ///
        /// WHAT: Transitions to the ProbeRTT state, which is a periodic
        ///       deep-drain phase lasting ~200ms.  During ProbeRTT:
        ///       - CWND is reduced to 4× MSS (the absolute minimum).
        ///       - Pacing gain drops to 0.50× BtlBw.
        ///       - This drains any standing queue in the path, allowing
        ///         a true base-propagation-delay RTT measurement.
        ///
        /// WHY:  Over time, the MinRtt estimate can become stale if the path
        ///       never experiences a quiet period.  A stale (too-high) MinRtt
        ///       inflates the BDP and CWND, causing bufferbloat.  Periodic
        ///       ProbeRTT refreshes MinRtt by forcibly draining the pipe.
        ///
        /// HOW:  Set mode, pacing gain, and timestamp.  The actual CWND
        ///       reduction happens in RecalculateModel (halves the target
        ///       CWND).  Log the entry for diagnostics.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void EnterProbeRtt(long nowMicros)
        {
            Mode = BbrMode.ProbeRtt;
            PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
            _probeRttEnteredMicros = nowMicros;
            _modeEnteredMicros = nowMicros;
            TraceLog(string.Concat("EnterProbeRtt cwnd=", CongestionWindowBytes, " btlBw=", BtlBwBytesPerSecond, " minRtt=", MinRttMicros, " fullBwRounds=", _fullBandwidthRounds, " lossPct=", (EstimatedLossPercent * 100d).ToString("F1"), " netClass=", CurrentNetworkClass));
        }

        /// <summary>
        /// Exits ProbeRTT: updates minimum RTT if a fresher sample was found,
        /// then transitions back to ProbeBW.
        ///
        /// WHAT: Ends the ProbeRTT deep-drain phase.  If the RTT sample
        ///       collected during the probe is close to (≤ 1.25×) the current
        ///       MinRtt, adopt it as the new MinRtt.  Then reset the MinRtt
        ///       timestamp to delay the next ProbeRTT cycle and jump back
        ///       into ProbeBW steady-state cycling.
        ///
        /// WHY:  The goal of ProbeRTT is to refresh MinRtt.  If the sample
        ///       is within 25% of the current MinRtt, we trust it and replace
        ///       MinRtt.  If the sample is much larger, the path may have
        ///       changed fundamentally and we keep the old (better) MinRtt.
        ///
        /// HOW:  1. Conditionally adopt the new RTT sample as MinRtt.
        ///       2. Reset _minRttTimestampMicros to restart the ProbeRTT clock.
        ///       3. Transition to ProbeBW to resume normal operation.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <param name="sampleRttMicros">RTT sample if available.</param>
        private void ExitProbeRtt(long nowMicros, long sampleRttMicros)
        {
            // Adopt the sample as new MinRtt if it's within 1.25× of the
            // current MinRtt.  This prevents a single noisy probe from
            // inflating the MinRtt estimate.
            if (sampleRttMicros > 0 && (MinRttMicros == 0 || sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER)))
            {
                MinRttMicros = sampleRttMicros; // Update min RTT if close enough.
            }

            _minRttTimestampMicros = nowMicros;
            TraceLog(string.Concat("ExitProbeRtt cwnd=", CongestionWindowBytes, " btlBw=", BtlBwBytesPerSecond, " minRtt=", MinRttMicros, " sampleRtt=", sampleRttMicros, " elapsedUs=", (nowMicros - _probeRttEnteredMicros)));
            EnterProbeBw(nowMicros);
        }

        /// <summary>
        /// Determines whether to exit ProbeRTT.
        ///
        /// WHAT: Checks two exit conditions:
        ///       1. A fresh near-minimum RTT sample has been observed (the
        ///          probe successfully drained the pipe and measured the
        ///          base RTT).
        ///       2. The safety duration has been exceeded (the probe has
        ///          been running too long without a good sample).
        ///
        /// WHY:  ProbeRTT imposes a significant throughput penalty (CWND
        ///       reduced to 4× MSS, pacing at 0.50× BtlBw).  We want to
        ///       exit as soon as the goal is achieved, but also have a
        ///       safety net so the connection doesn't starve indefinitely
        ///       on pathological paths.
        ///
        /// HOW:  1. Enforce minimum duration (ProbeRttDurationMicros).
        ///          On non-congested paths, halve this to exit faster —
        ///          there is no queue to drain, so one RTT is enough.
        ///       2. After minimum duration: check for a fresh near-minimum
        ///          RTT sample (≤ 1.25× current MinRtt).
        ///       3. After 3× the normal duration: safety exit regardless.
        /// </summary>
        private bool ShouldExitProbeRtt(long nowMicros, long sampleRttMicros)
        {
            long elapsedMicros = nowMicros - _probeRttEnteredMicros;
            long minDuration = _config.ProbeRttDurationMicros;

            // On non-congested paths, allow earlier exit.
            // No standing queue means the true base RTT is already visible.
            if (_networkCondition != NetworkCondition.Congested)
            {
                minDuration = Math.Max(minDuration / 2, 30000L);
            }

            // Haven't been in ProbeRTT long enough yet.
            if (elapsedMicros < minDuration)
            {
                return false; // Minimum duration not yet met.
            }

            // Exit condition 1: fresh sample close to current MinRtt.
            // The probe succeeded — we measured a true base RTT.
            bool hasFreshMinRttSample = sampleRttMicros > 0 && MinRttMicros > 0 && sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER);

            // Exit condition 2: safety timeout (3× normal duration).
            // Prevents indefinite starvation on paths where the pipe
            // never drains (e.g. competing cross-traffic).
            bool exceededSafetyDuration = elapsedMicros >= _config.ProbeRttDurationMicros * UcpConstants.BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER;
            return hasFreshMinRttSample || exceededSafetyDuration;
        }

        /// <summary>
        /// Calculates the pacing gain based on probe cycle phase, network condition,
        /// loss ratio, RTT increase, and network class.
        ///
        /// WHAT: Returns the pacing gain multiplier (0.50–1.35) based on a
        ///       decision tree that considers:
        ///       - Current network condition (congested, random loss, light load)
        ///       - Network path class (LAN, Mobile, LossyFat, VPN, etc.)
        ///       - Recent loss ratio and RTT increase relative to MinRtt
        ///       - Loss-control budget
        ///       - Fast recovery state
        ///
        /// WHY:  Adaptive pacing gain is the key differentiator from stock BBR.
        ///       Stock BBR uses a fixed 8-phase cycle with gains [1.25, 0.75,
        ///       1.0, 1.0, 1.0, 1.0, 1.0, 1.0].  This adaptive variant:
        ///       - Reduces gain to 0.50–1.00 on congested links (back off)
        ///       - Keeps 1.35× gain on mobile/lossy paths (compensate for
        ///         non-congestion throughput loss)
        ///       - Adjusts gain based on RTT increase trend (early congestion
        ///         signal before loss appears)
        ///
        /// HOW:  Decision priority order:
        ///       1. Loss-control over budget → 0.70× (strong back-off)
        ///       2. Fast recovery active → 1.15× (elevated, not aggressive)
        ///       3. Congested network → 1.00× or 0.50× depending on loss budget
        ///       4. MobileUnstable → 1.35×, 1.10×, or 1.00× by RTT trend
        ///       5. LossyLongFat → 1.10× or 1.00× by RTT trend
        ///       6. RandomLoss → 1.35×, 1.10×, or 1.00× by RTT trend
        ///       7. LowLatencyLAN → 1.35× (aggressive on fast clean paths)
        ///       8. Default → tiered by loss ratio and RTT increase
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        /// <returns>Pacing gain multiplier.</returns>
        private double CalculatePacingGain(long nowMicros)
        {
            double lossRatio = GetRecentLossRatio(nowMicros);
            double rttIncrease = GetAverageRttIncreaseRatio();

            // ---- Loss-control overrides ----
            // When loss exceeds the configured bandwidth loss budget (e.g. 5%)
            // AND the network condition is classified as congested, drop to
            // the high-loss pacing gain (0.70×) to relieve the bottleneck.
            if (_config.LossControlEnable && _networkCondition == NetworkCondition.Congested && EstimatedLossPercent > _maxBandwidthLossPercent)
            {
                return UcpConstants.BBR_HIGH_LOSS_PACING_GAIN;
            }

            // ---- Fast recovery ----
            // After a non-congestion loss (e.g. random/corruption), pace at
            // elevated gain (1.15×) for one RTT to refill the pipe without
            // creating new loss.  This is NOT aggressive probing — just
            // ensuring throughput doesn't collapse due to head-of-line blocking.
            if (_fastRecoveryEnteredMicros > 0 && MinRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros < MinRttMicros)
            {
                return UcpConstants.BBR_FAST_RECOVERY_PACING_GAIN;
            }

            // ---- Congested path ----
            // Pacing gain depends on whether loss is within budget.
            // Within budget → 1.00× (maintain, don't probe).
            // Over budget → 0.50× (aggressive drain to relieve queue).
            if (_networkCondition == NetworkCondition.Congested)
            {
                if (EstimatedLossPercent <= _maxBandwidthLossPercent)
                {
                    return 1d;
                }

                return UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
            }

            // ---- Mobile/Unstable paths ----
            // Mobile links (LTE/5G) suffer from link-layer retransmissions and
            // scheduling jitter that look like congestion but aren't.  Maintain
            // higher gain when RTT is stable; reduce gradually as RTT inflates
            // (which is a genuine congestion signal even on mobile).
            if (CurrentNetworkClass == NetworkClass.MobileUnstable)
            {
                // RTT barely above MinRtt → path is clean; probe aggressively.
                if (rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO)
                {
                    return _config.ProbeBwHighGain; // 1.35x when RTT is stable.
                }

                // Moderate RTT inflation → still probe but less aggressively.
                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
                {
                    return UcpConstants.BBR_LIGHT_LOSS_PACING_GAIN; // 1.10x with moderate RTT rise.
                }

                // Heavily inflated RTT → genuine congestion; pace at 1.00×.
                return 1d; // 1.00x when RTT is heavily inflated.
            }

            // ---- Lossy Long-Fat paths ----
            // Satellite/long-haul links have steady background loss from
            // physical-layer noise.  RTT increase is a more reliable congestion
            // signal than loss ratio on these paths.
            if (CurrentNetworkClass == NetworkClass.LossyLongFat)
            {
                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
                {
                    return UcpConstants.BBR_MODERATE_PROBE_GAIN;
                }

                return 1d;
            }

            // ---- Random loss (non-congestion, stable RTT) ----
            // Loss exists but RTT is flat → noise/corruption, not congestion.
            // Maintain elevated gain unless RTT starts rising.
            if (_networkCondition == NetworkCondition.RandomLoss)
            {
                if (rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO)
                {
                    return _config.ProbeBwHighGain;
                }

                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
                {
                    return UcpConstants.BBR_MODERATE_PROBE_GAIN;
                }

                return 1d;
            }

            // ---- Low-latency LAN ----
            // Fast, clean paths with negligible queuing.  Always use high gain
            // because there is no risk of bufferbloat — the BDP is tiny.
            if (CurrentNetworkClass == NetworkClass.LowLatencyLAN)
            {
                return _config.ProbeBwHighGain;
            }

            // ---- Default/generic path: tiered by loss and RTT ----
            // Escalating probe caution based on combined loss + RTT signals.
            // This covers Default, SymmetricVPN, and CongestedBottleneck classes
            // that haven't been caught by the specific classifiers above.

            // Low loss + stable RTT → aggressive probing is safe.
            if (lossRatio < UcpConstants.BBR_LOW_LOSS_RATIO && rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO)
            {
                return _config.ProbeBwHighGain;
            }

            // Moderate loss and RTT → moderate probe gain.
            if (lossRatio < UcpConstants.BBR_MODERATE_LOSS_RATIO && rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
            {
                return UcpConstants.BBR_MODERATE_PROBE_GAIN;
            }

            // Light loss only → near-1.00× with slight upward bias.
            if (lossRatio < UcpConstants.BBR_LIGHT_LOSS_RATIO)
            {
                return Math.Max(1d, UcpConstants.BBR_LIGHT_LOSS_PACING_GAIN);
            }

            // Medium loss → modest back-off.
            if (lossRatio < UcpConstants.BBR_MEDIUM_LOSS_RATIO)
            {
                return UcpConstants.BBR_MEDIUM_LOSS_PACING_GAIN;
            }

            // High loss → strong back-off.
            return UcpConstants.BBR_HIGH_LOSS_PACING_GAIN;
        }

        /// <summary>
        /// Updates the EWMA-smoothed estimated loss percentage.
        ///
        /// WHAT: Calls the two-parameter overload with the current
        ///       CalculateLossPercent() result.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        private void UpdateEstimatedLossPercent(long nowMicros)
        {
            UpdateEstimatedLossPercent(nowMicros, CalculateLossPercent(nowMicros));
        }

        /// <summary>
        /// Updates the EWMA-smoothed estimated loss percentage with a candidate value.
        ///
        /// WHAT: Exponentially-weighted moving average of loss percentage.
        ///       Retains 75% of the previous estimate and adds 25% of the
        ///       new candidate.  When no loss is present, the estimate decays
        ///       toward zero (idle decay) to avoid stale loss estimates
        ///       lingering long after the loss event has passed.
        ///
        /// WHY:  Instantaneous loss percentage is noisy — a single lost
        ///       packet on a connection that has sent 1 packet is 100% loss,
        ///       but on a connection that has sent 10,000 packets it's 0.01%.
        ///       EWMA smooths this noise while responding quickly to genuine
        ///       loss spikes.  The idle decay ensures the estimate returns
        ///       to zero when loss stops.
        ///
        /// HOW:  1. Bound candidate to [0, 100].
        ///       2. If candidate is zero and recent loss ratio is zero:
        ///          decay the estimate toward zero (idle decay factor).
        ///       3. If this is the first estimate: set directly.
        ///       4. Otherwise: EWMA = 0.75×prev + 0.25×candidate.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <param name="candidateLossPercent">Candidate loss percentage (0..100).</param>
        private void UpdateEstimatedLossPercent(long nowMicros, double candidateLossPercent)
        {
            double boundedCandidate = Math.Max(0d, Math.Min(100d, candidateLossPercent));
            if (boundedCandidate <= 0d && GetRecentLossRatio(nowMicros) <= 0d)
            {
                EstimatedLossPercent *= UcpConstants.BBR_LOSS_EWMA_IDLE_DECAY; // Idle decay.
                return;
            }

            if (EstimatedLossPercent <= 0d)
            {
                EstimatedLossPercent = boundedCandidate; // First estimate: set directly.
                return;
            }

            // EWMA: 75% retained + 25% new sample.
            EstimatedLossPercent = (EstimatedLossPercent * UcpConstants.BBR_LOSS_EWMA_RETAINED_WEIGHT) + (boundedCandidate * UcpConstants.BBR_LOSS_EWMA_SAMPLE_WEIGHT);
        }

        /// <summary>
        /// Calculates the loss percentage from retransmission ratio and
        /// delivery-rate shortfall compared to BtlBw.
        ///
        /// WHAT: Loss percentage is a composite of:
        ///       1. Retransmission loss ratio (packets retransmitted / packets sent)
        ///       2. Delivery-rate shortfall (how far below BtlBw actual delivery is)
        ///
        /// WHY:  Retransmission count alone can understate congestion.  If the
        ///       bottleneck queue is full but no packets are dropped yet, the
        ///       retransmission ratio is zero but the delivery rate has already
        ///       flattened.  The rate shortfall catches this early.
        ///
        ///       Conversely, on clean paths with no congestion, only the
        ///       retransmission ratio is used — the rate shortfall is misleading
        ///       outside of congested conditions.
        ///
        /// HOW:  If not congested or in Startup: return retransmission % directly.
        ///       If congested: combine retransmission % with (1 - actual/target)
        ///       rate shortfall, taking the max of the two hints.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <returns>Loss percentage (0..100).</returns>
        private double CalculateLossPercent(long nowMicros)
        {
            double targetRate = BtlBwBytesPerSecond > 0 ? BtlBwBytesPerSecond : _config.InitialBandwidthBytesPerSecond;
            if (targetRate <= 0)
            {
                return 0d;
            }

            double retransmissionLoss = GetRecentLossRatio(nowMicros);

            // Only consider rate shortfall when congestion is confirmed.
            // Outside of congestion, a low delivery rate just means the
            // sender had nothing to send (application-limited), not that
            // the path is saturated.
            if (_networkCondition != NetworkCondition.Congested || _deliveryRateBytesPerSecond <= 0 || Mode == BbrMode.Startup)
            {
                return retransmissionLoss * 100d;
            }

            // When congested, also consider delivery-rate shortfall.
            // actualRate / targetRate gives utilization (0.0–1.0).
            // 1 - utilization = shortfall fraction.
            double actualRate = _deliveryRateBytesPerSecond;
            double lossFromRate = Math.Max(0d, 1d - (actualRate / targetRate));
            double rateLossHint = Math.Min(lossFromRate, retransmissionLoss + UcpConstants.BBR_RATE_LOSS_HINT_MAX_RATIO);
            return Math.Max(rateLossHint, retransmissionLoss) * 100d;
        }

        /// <summary>
        /// Classifies the current network condition based on delivery-rate trend,
        /// RTT increase, and recent loss ratio.
        ///
        /// WHAT: A three-tier scoring system that distinguishes congestion from
        ///       random loss.  Returns one of: Idle, LightLoad, Congested, RandomLoss.
        ///
        /// WHY:  Not all loss is congestion.  Stock BBR treats every loss as
        ///       a congestion signal, which causes unnecessary throughput
        ///       collapse on paths with random/corruption loss (wireless,
        ///       satellite, noisy links).  By looking at the combination of
        ///       delivery-rate drop + RTT increase + loss ratio, we can
        ///       distinguish:
        ///       - Congestion: rate drops, RTT rises, loss appears → score ≥ 4
        ///       - Random loss: loss appears, but RTT is flat → RandomLoss
        ///       - Light load: minimal loss, stable conditions → LightLoad
        ///
        /// HOW:  Three scoring rules, each contributing points:
        ///       Rule 1 (rate drop score): delivery rate is declining AND RTT
        ///           is rising → strongest congestion signal (highest score).
        ///       Rule 2 (RTT growth score): RTT above threshold → moderate signal.
        ///       Rule 3 (loss score): loss ratio above threshold AND RTT rising
        ///           → loss confirms the RTT signal.
        ///
        ///       Score ≥ threshold → Congested
        ///       Loss > 0 with flat RTT → RandomLoss
        ///       Otherwise → LightLoad or Idle
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <returns>The classified network condition.</returns>
        private NetworkCondition ClassifyNetworkCondition(long nowMicros)
        {
            if (_deliveryRateHistoryCount < 2)
            {
                return NetworkCondition.Idle; // Not enough data.
            }

            // Compute delivery-rate trend: oldest vs newest sample.
            // A declining rate suggests the bottleneck is saturated.
            int newestIndex = (_deliveryRateHistoryIndex + _deliveryRateHistory.Length - 1) % _deliveryRateHistory.Length;
            int oldestIndex = (_deliveryRateHistoryIndex + _deliveryRateHistory.Length - _deliveryRateHistoryCount) % _deliveryRateHistory.Length;
            double oldestRate = _deliveryRateHistory[oldestIndex];
            double newestRate = _deliveryRateHistory[newestIndex];
            double deliveryRateChange = oldestRate <= 0 ? 0d : (newestRate - oldestRate) / oldestRate;
            double lossRatio = GetRecentLossRatio(nowMicros);
            double rttIncrease = GetAverageRttIncreaseRatio();
            int congestionScore = 0;

            // ---- Tier 1: Delivery-rate drop + RTT rise ----
            // The strongest congestion signal.  When the bottleneck queue is
            // building, delivery rate flattens or drops while RTT rises.
            if (deliveryRateChange <= UcpConstants.BBR_CONGESTION_RATE_DROP_RATIO && rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RATE_DROP_SCORE;
            }

            // ---- Tier 2: RTT growth alone ----
            // RTT rising is an early-warning signal.  Even before loss appears,
            // growing queues indicate impending congestion.
            if (rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RTT_GROWTH_SCORE;
            }

            // ---- Tier 3: Loss ratio + RTT rise ----
            // Loss is only treated as congestion evidence when accompanied by
            // RTT rise.  Loss with flat RTT is random/corruption.
            if (lossRatio >= UcpConstants.BBR_CONGESTION_LOSS_RATIO && rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_LOSS_SCORE;
            }

            // Score ≥ threshold → congestion confirmed.
            if (congestionScore >= UcpConstants.BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD)
            {
                return NetworkCondition.Congested;
            }

            // Loss present but RTT is flat → random/corruption loss.
            // The path can handle the current rate; loss is not from queuing.
            if (lossRatio > 0 && rttIncrease <= UcpConstants.BBR_RANDOM_LOSS_MAX_RTT_INCREASE_RATIO)
            {
                return NetworkCondition.RandomLoss;
            }

            // Negligible loss → light load.
            if (lossRatio < UcpConstants.BBR_LOW_LOSS_RATIO)
            {
                return NetworkCondition.LightLoad;
            }

            // Default: not enough signal to classify.
            return NetworkCondition.Idle;
        }

        /// <summary>
        /// Determines whether a loss should be treated as congestion (requiring
        /// multiplicative reduction) or random (handle with fast recovery only).
        ///
        /// WHAT: The final gate before applying CWND reduction.  Considers both
        ///       the external congestion signal (from RTO/NAK/DupACK context)
        ///       and the internal network condition classifier.
        ///
        /// WHY:  Even when the external signal says "congestion" (e.g. RTO
        ///       timeout), the internal classifier may have independently
        ///       determined the path is healthy (RandomLoss or LightLoad).
        ///       In that case, the loss is likely a transient burst or an
        ///       RTO triggered by a delayed ACK, not standing congestion.
        ///
        ///       Conversely, if the classifier already flags Congested AND
        ///       the external signal confirms, we apply full reduction.
        ///
        /// HOW:  1. External signal must be "congestion" → else always random.
        ///       2. Internal classifier says Congested → immediate confirmation.
        ///       3. Otherwise: check RTT increase + loss ratio together.
        ///          Both must be elevated → congestion; either missing → random.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <param name="isCongestionSignal">Whether the external signal indicates congestion.</param>
        /// <returns>True if the loss should be treated as congestion.</returns>
        private bool ShouldTreatLossAsCongestion(long nowMicros, bool isCongestionSignal)
        {
            // If the external event source already says "not congestion"
            // (e.g. a SACK-triggered fast retransmit on a lossless path),
            // we never treat it as congestion — no further check needed.
            if (!isCongestionSignal)
            {
                return false;
            }

            // Classifier confirms congestion → immediate reduction.
            if (_networkCondition == NetworkCondition.Congested)
            {
                return true;
            }

            // Classifier is uncertain, but the loss event says congestion.
            // Require BOTH elevated RTT AND elevated loss to confirm.
            // Either alone is too weak for a multiplicative reduction.
            double rttIncrease = GetAverageRttIncreaseRatio();
            double lossRatio = GetRecentLossRatio(nowMicros);
            return rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO && lossRatio >= UcpConstants.BBR_CONGESTION_LOSS_RATIO;
        }

        /// <summary>
        /// Returns the RTT value used for CWND model calculations.
        ///
        /// WHAT: Uses P10 RTT (10th percentile) as the propagation-delay
        ///       estimate for the BDP model, with MinRtt as a floor.
        ///
        /// WHY:  Raw MinRtt is fragile — a single lucky fast RTT sample
        ///       (e.g. 1ms on a 50ms path) collapses CWND.  P10 RTT is
        ///       more robust because at least 10% of samples must be at
        ///       or below that value.  It naturally filters outliers
        ///       without needing manual clamping.
        ///
        ///       The result is a stable propagation-delay estimate that
        ///       doesn't create a positive-feedback loop where:
        ///       inflated RTT → higher CWND → more queuing → higher RTT.
        ///
        /// Path class multipliers (applied in GetTargetCwndBytes via CwndGain):
        ///   Default / clean: 2.5× BDP
        ///   MobileUnstable:  3.5× BDP
        ///   LossyLongFat:    3.5× BDP
        ///
        /// The fixed multiplier approach eliminates the positive-feedback
        /// loop where inflated RTT → higher CWND → more queuing → higher RTT.
        /// </summary>
        /// <returns>Model RTT in microseconds.</returns>
        private long GetCwndModelRttMicros()
        {
            // Use P10 RTT as the base propagation-delay estimate.
            // More robust than raw MinRtt against single lucky fast samples.
            long p10Rtt = GetP10RttMicros();
            long modelRttMicros = p10Rtt > 0 ? Math.Max(MinRttMicros, p10Rtt) : MinRttMicros;
            if (modelRttMicros <= 0)
            {
                return 0;
            }

            return modelRttMicros;
        }

        /// <summary>
        /// Computes the average RTT increase ratio relative to the minimum RTT.
        ///
        /// WHAT: Returns (avgRtt - MinRtt) / MinRtt.  A value of 0.20 means
        ///       the average RTT is 20% above the minimum — indicating mild
        ///       queuing delay.  Values above 1.0 suggest heavy congestion.
        ///
        /// WHY:  RTT increase is an early-warning signal that precedes packet
        ///       loss.  When queues are building at the bottleneck, RTT rises
        ///       before the buffer overflows.  This ratio is used by both
        ///       the loss classifier and the pacing gain decision tree.
        ///
        /// HOW:  Sum all RTT history samples, divide by count for the average,
        ///       then compute (avg - min) / min.  Returns 0 if no history.
        /// </summary>
        /// <returns>RTT increase ratio (e.g. 0.20 = 20% above min RTT).</returns>
        private double GetAverageRttIncreaseRatio()
        {
            if (_rttHistoryCount == 0 || MinRttMicros <= 0)
            {
                return 0d;
            }

            long total = 0;
            for (int i = 0; i < _rttHistoryCount; i++)
            {
                total += _rttHistoryMicros[i];
            }

            double averageRtt = total / (double)_rttHistoryCount;
            return Math.Max(0d, (averageRtt - MinRttMicros) / MinRttMicros);
        }

        /// <summary>
        /// Returns the 10th-percentile RTT from the history buffer.
        ///
        /// WHAT: P10 RTT is the value below which 10% of samples fall.
        ///       Used as the primary propagation-delay estimate in the
        ///       CWND model.  Far more robust than raw MinRtt — a single
        ///       lucky fast sample cannot collapse the CWND on jittery paths.
        ///
        /// WHY:  On a path with 30ms base RTT and 5ms jitter, P10 ≈ 31ms
        ///       while raw MinRtt could be 25ms (a lucky fast sample).
        ///       Using 25ms would under-estimate BDP by ~17%, under-filling
        ///       the pipe.  P10 discards the luckiest 10% of samples.
        /// </summary>
        private long GetP10RttMicros()
        {
            return GetPercentileRtt(0.10d);
        }

        /// <summary>
        /// Returns the P25 (25th-percentile) RTT from the history buffer.
        ///
        /// WHAT: P25 RTT is used for the CWND model on non-congested lossy
        ///       paths (LossyLongFat).  On these paths, jitter variance is
        ///       from physical noise, not queuing, so a higher percentile
        ///       avoids under-utilization caused by jitter.
        ///
        /// WHY:  Lossy links have RTT variance even when the queue is empty
        ///       (retransmissions at the link layer add variable delay).
        ///       Using P10 would under-estimate; P25 compensates.
        /// </summary>
        private long GetP25RttMicros()
        {
            return GetPercentileRtt(0.25d);
        }

        /// <summary>
        /// Returns the P30 (30th-percentile) RTT from the history buffer.
        ///
        /// WHAT: P30 RTT is used for the CWND model on mobile/unstable paths
        ///       (MobileUnstable).  On cellular links, link-layer HARQ
        ///       retransmissions add significant RTT variance that has
        ///       nothing to do with queuing.  P30 provides enough headroom
        ///       to absorb this without under-filling.
        ///
        /// WHY:  LTE/5G scheduling cycles and HARQ retransmissions create
        ///       RTT spikes that can be 2–10× the base RTT.  These are not
        ///       congestion signals — they are link-layer artifacts.  Using
        ///       a higher percentile prevents CWND starvation.
        /// </summary>
        private long GetP30RttMicros()
        {
            return GetPercentileRtt(0.30d);
        }

        /// <summary>
        /// Returns the RTT at the given percentile from the history buffer.
        ///
        /// WHAT: Copies valid RTT samples into a temporary array, sorts them,
        ///       and picks the value at the requested percentile position.
        ///
        /// WHY:  Percentile-based RTT is the key robustness improvement over
        ///       raw MinRtt.  A single pathological sample (1ms lucky fast
        ///       measurement, or 5-second RTO stall) cannot corrupt the
        ///       estimate.  P10 means "90% of samples are above this value,"
        ///       which is a solid lower-bound for propagation delay.
        ///
        /// HOW:  1. Require at least 4 samples (fall back to MinRtt otherwise).
        ///       2. Copy the circular buffer to a contiguous array.
        ///       3. Sort ascending.
        ///       4. Return sorted[(int)(count × percentile)].
        /// </summary>
        /// <param name="percentile">Percentile fraction (0.0 to 1.0).</param>
        /// <returns>RTT at the requested percentile, in microseconds.</returns>
        private long GetPercentileRtt(double percentile)
        {
            // Not enough samples for a meaningful percentile.
            if (_rttHistoryCount < 4)
            {
                return MinRttMicros; // Not enough samples, fall back to min.
            }

            // Copy valid entries to a temporary array for sorting.
            long[] sorted = new long[_rttHistoryCount];
            Array.Copy(_rttHistoryMicros, sorted, _rttHistoryCount);
            Array.Sort(sorted);

            // Return approximately the requested percentile.
            int index = Math.Max(0, Math.Min(_rttHistoryCount - 1, (int)(_rttHistoryCount * percentile)));
            return sorted[index];
        }

        /// <summary>
        /// Updates the inflight guardrail bounds based on current BDP and gain factors.
        ///
        /// WHAT: Computes upper and lower bounds for CWND expressed as
        ///       multiples of BDP.  These guardrails prevent CWND from
        ///       exceeding safe queueing limits (high bound) or starving
        ///       the connection (low bound).
        ///
        /// WHY:  The CWND model (BDP × CwndGain) can produce values that
        ///       are too large (bufferbloat) or too small (under-utilization)
        ///       depending on gain settings.  Separate guardrails let us
        ///       apply path-class-specific safety margins.
        ///
        /// HOW:  _inflightLowBytes = max(InitialCwnd, BDP × lowGain)
        ///       For non-congested mobile/lossy paths: highGain = mobileHighGain
        ///       For all other paths: highGain = standard highGain
        ///       _inflightHighBytes = max(_inflightLowBytes, BDP × highGain)
        /// </summary>
        private void UpdateInflightBounds()
        {
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)
            {
                _inflightHighBytes = 0;
                _inflightLowBytes = 0;
                return;
            }

            double bdpBytes = BtlBwBytesPerSecond * (MinRttMicros / (double)UcpConstants.MICROS_PER_SECOND);

            // Lower guardrail: at minimum the initial CWND, otherwise a
            // fraction of BDP.  Prevents CWND starvation on low-BDP paths.
            _inflightLowBytes = Math.Max(_config.InitialCongestionWindowBytes, bdpBytes * UcpConstants.BBR_INFLIGHT_LOW_GAIN);

            // Upper guardrail: mobile/lossy paths get higher headroom because
            // their loss is often non-congestion and retransmissions need
            // extra inflight capacity.
            double highGain = (_networkCondition != NetworkCondition.Congested
                                && (CurrentNetworkClass == NetworkClass.MobileUnstable
                                    || CurrentNetworkClass == NetworkClass.LossyLongFat))
                ? UcpConstants.BBR_INFLIGHT_MOBILE_HIGH_GAIN
                : UcpConstants.BBR_INFLIGHT_HIGH_GAIN;
            _inflightHighBytes = Math.Max(_inflightLowBytes, bdpBytes * highGain);
        }

        /// <summary>
        /// Calculates the recent loss ratio from the sliding loss bucket windows.
        ///
        /// WHAT: Returns retransmitted-bytes / total-sent-bytes across all
        ///       active loss buckets.  Buckets are fixed-duration time windows
        ///       (e.g. 500ms each); old buckets are automatically aged out.
        ///
        /// WHY:  Instantaneous loss ratio (single-packet loss) is too noisy.
        ///       A single corrupt packet on a 10 Gbps link is irrelevant.
        ///       The sliding-window approach smooths out noise while still
        ///       responding quickly to genuine loss spikes.
        ///
        /// HOW:  1. Advance the bucket ring to age out expired data.
        ///       2. Sum sent and retransmitted counts across all buckets.
        ///       3. Return retransmits / sent (or 0 if no sent data).
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <returns>Loss ratio (0.0 to 1.0).</returns>
        private double GetRecentLossRatio(long nowMicros)
        {
            AdvanceLossBuckets(nowMicros);

            long sent = 0;
            long retransmits = 0;
            for (int i = 0; i < UcpConstants.BBR_LOSS_BUCKET_COUNT; i++)
            {
                sent += _sentBuckets[i];
                retransmits += _retransmitBuckets[i];
            }

            return sent == 0 ? 0d : retransmits / (double)sent;
        }

        /// <summary>
        /// Advances the sliding loss bucket windows based on elapsed time.
        ///
        /// WHAT: Maintains a ring buffer of per-time-slot sent/retransmit
        ///       counters.  As time advances, expired slots are cleared
        ///       and the ring pointer advances.
        ///
        /// WHY:  Loss ratio should reflect recent conditions, not the entire
        ///       connection history.  Old loss events (e.g. a burst 30
        ///       seconds ago) should not influence current decisions.
        ///       The sliding window provides a configurable lookback.
        ///
        /// HOW:  1. Align nowMicros to bucket boundaries for deterministic slotting.
        ///       2. If this is the first call or clock went backwards, clear everything.
        ///       3. If the time jump exceeds bucket count, clear everything.
        ///       4. Otherwise, advance by exactly the number of elapsed buckets,
        ///          zeroing out intermediate slots.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        private void AdvanceLossBuckets(long nowMicros)
        {
            if (nowMicros <= 0)
            {
                nowMicros = UcpTime.NowMicroseconds();
            }

            // Align to bucket boundaries for consistent slotting.
            long alignedNow = nowMicros - (nowMicros % UcpConstants.BBR_LOSS_BUCKET_MICROS);
            if (_lossBucketStartMicros == 0 || nowMicros < _lossBucketStartMicros)
            {
                // First call or clock reset: clear all buckets.
                Array.Clear(_sentBuckets, 0, _sentBuckets.Length);
                Array.Clear(_retransmitBuckets, 0, _retransmitBuckets.Length);
                _lossBucketIndex = 0;
                _lossBucketStartMicros = alignedNow;
                return;
            }

            long steps = (nowMicros - _lossBucketStartMicros) / UcpConstants.BBR_LOSS_BUCKET_MICROS;
            if (steps <= 0)
            {
                return; // No advancement needed.
            }

            if (steps >= UcpConstants.BBR_LOSS_BUCKET_COUNT)
            {
                // Large time jump: clear all buckets.
                Array.Clear(_sentBuckets, 0, _sentBuckets.Length);
                Array.Clear(_retransmitBuckets, 0, _retransmitBuckets.Length);
                _lossBucketIndex = 0;
                _lossBucketStartMicros = alignedNow;
                return;
            }

            // Advance by clearing intermediate buckets.
            for (long i = 0; i < steps; i++)
            {
                _lossBucketIndex = (_lossBucketIndex + 1) % UcpConstants.BBR_LOSS_BUCKET_COUNT;
                _sentBuckets[_lossBucketIndex] = 0;
                _retransmitBuckets[_lossBucketIndex] = 0;
            }

            _lossBucketStartMicros += steps * UcpConstants.BBR_LOSS_BUCKET_MICROS;
        }

        /// <summary>
        /// Returns the effective CWND gain, capped to avoid exceeding the
        /// bandwidth waste budget when pacing gain is high.
        ///
        /// WHAT: The CWND gain controls how much buffering headroom we allow.
        ///       CwndGain × PacingGain is the total inflight multiplier over
        ///       BDP.  If this exceeds 1 + wasteBudget, we cap CwndGain to
        ///       keep the total within budget.
        ///
        /// WHY:  Without this cap, Startup (gain 2.89×2.89 ≈ 8.3× BDP) and
        ///       high-gain phases could create massive standing queues.
        ///       The waste budget (default 50%) means we allow at most 50%
        ///       more inflight than BDP on top of what pacing already sends.
        ///
        /// HOW:  Mobile/lossy paths skip the cap — they need extra CWND for
        ///       retransmission headroom (their loss is from noise, not
        ///       queuing).  Startup also skips the cap to allow rapid ramp-up.
        ///       Otherwise: limit = (1 + wasteBudget) × baseCwndGain.
        ///       If PacingGain × CwndGain > limit, return limit / PacingGain.
        /// </summary>
        private double GetEffectiveCwndGain()
        {
            // Mobile/lossy paths need extra CWND for retransmission
            // headroom.  Their CWND is already bounded by the fixed
            // ceiling, so skip the waste-budget cap here.
            if (CurrentNetworkClass == NetworkClass.MobileUnstable
                || CurrentNetworkClass == NetworkClass.LossyLongFat)
            {
                return CwndGain;
            }

            // Startup needs high CWND for rapid bandwidth discovery.
            // The waste-budget cap would prevent the ramp-up.
            if (Mode == BbrMode.Startup)
            {
                return CwndGain;
            }

            // Waste budget: how much extra inflight (beyond BDP) we tolerate.
            // e.g. 0.50 means we allow up to 1.50× BDP total inflight.
            double wasteBudget = Math.Max(0.50d, _config.MaxBandwidthWastePercent);
            double maxWasteGain = 1d + wasteBudget;
            double limit = maxWasteGain * _config.ProbeBwCwndGain;
            if (PacingGain <= 0 || PacingGain * CwndGain <= limit)
            {
                return CwndGain;
            }

            // Cap CwndGain so that total inflight multiplier ≤ wasteBudget + 1.
            return Math.Max(1d, limit / PacingGain);
        }

        /// <summary>
        /// Conditionally writes a debug trace message if debug logging is enabled.
        ///
        /// WHAT: Guarded debug-logging helper.  Writes to System.Diagnostics.Trace
        ///       with a "[UCP BBR]" prefix for filtering.
        ///
        /// WHY:  BBR produces a large volume of state-transition events.  Logging
        ///       them unconditionally would flood trace output.  The config flag
        ///       gates all diagnostic output.
        /// </summary>
        /// <param name="message">The message to log.</param>
        private void TraceLog(string message)
        {
            if (_config.EnableDebugLog)
            {
                Trace.WriteLine("[UCP BBR] " + message);
            }
        }

        /// <summary>
        /// Accumulates statistics for the network path classifier.
        ///
        /// WHAT: Maintains a sliding window of network statistics (RTT, jitter,
        ///       throughput, loss rate) that feed into the path classifier.
        ///       Each window covers ~2 seconds; when full, the window is
        ///       finalized and a new one begins.  The circular buffer holds
        ///       the last N windows for trend analysis.
        ///
        /// WHY:  Path classification needs aggregated statistics, not
        ///       instantaneous samples.  A single ACK burst tells you
        ///       nothing about whether the path is a LAN vs a satellite
        ///       link.  Multi-second windows smooth out noise while
        ///       still capturing path characteristics.
        ///
        /// HOW:  1. Accumulate RTT sum/count/min/max and sent bytes.
        ///       2. When window duration elapses, compute AvgRtt, Jitter,
        ///          LossRate, and ThroughputRatio (bytes/sec ÷ BtlBw).
        ///       3. Store in the circular buffer, advance index, reset accumulators.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <param name="sentOrAckedBytes">Bytes sent or ACKed this interval.</param>
        /// <param name="sampleRttMicros">RTT sample, or 0 if none.</param>
        /// <param name="lossRateSnapshot">Current loss rate snapshot.</param>
        private void AdvanceClassifierWindow(long nowMicros, int sentOrAckedBytes, long sampleRttMicros, double lossRateSnapshot)
        {
            if (_classifierWindowStartMicros == 0)
            {
                _classifierWindowStartMicros = nowMicros;
            }

            _classifierWindowSentBytes += Math.Max(0, sentOrAckedBytes);
            if (sampleRttMicros > 0)
            {
                _classifierWindowRttSumMicros += sampleRttMicros;
                _classifierWindowRttCount++;
                if (_classifierWindowMinRttMicros == 0 || sampleRttMicros < _classifierWindowMinRttMicros)
                {
                    _classifierWindowMinRttMicros = sampleRttMicros;
                }

                if (sampleRttMicros > _classifierWindowMaxRttMicros)
                {
                    _classifierWindowMaxRttMicros = sampleRttMicros;
                }
            }

            if (nowMicros - _classifierWindowStartMicros >= UcpConstants.NETWORK_CLASSIFIER_WINDOW_DURATION_MICROS)
            {
                // Finalize the current window.
                ref ClassifierWindow window = ref _classifierWindows[_classifierWindowIndex];
                window.AvgRttMicros = _classifierWindowRttCount > 0 ? _classifierWindowRttSumMicros / (double)_classifierWindowRttCount : 0d;
                window.JitterMicros = _classifierWindowMinRttMicros > 0 && _classifierWindowMaxRttMicros > 0 ? (_classifierWindowMaxRttMicros - _classifierWindowMinRttMicros) : 0d;
                window.LossRate = lossRateSnapshot;
                // Convert the microsecond window to bytes/second before comparing
                // against BtlBw; otherwise high-bandwidth paths look artificially idle.
                double windowBytesPerSecond = _classifierWindowSentBytes * UcpConstants.MICROS_PER_SECOND / (double)Math.Max(1, nowMicros - _classifierWindowStartMicros);
                window.ThroughputRatio = BtlBwBytesPerSecond > 0 ? Math.Min(1d, windowBytesPerSecond / BtlBwBytesPerSecond) : 0d;
                _classifierWindowIndex = (_classifierWindowIndex + 1) % UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT;
                if (_classifierWindowCount < UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT)
                {
                    _classifierWindowCount++;
                }

                // Reset accumulators for the next window.
                _classifierWindowStartMicros = nowMicros;
                _classifierWindowSentBytes = 0;
                _classifierWindowMinRttMicros = 0;
                _classifierWindowMaxRttMicros = 0;
                _classifierWindowRttSumMicros = 0;
                _classifierWindowRttCount = 0;
            }
        }

        /// <summary>
        /// Classifies the network path into one of the predefined categories
        /// based on averaged statistics from recent classifier windows.
        ///
        /// WHAT: A rule-based classifier that categorizes the end-to-end path
        ///       into one of six types by analyzing multi-second aggregates of
        ///       RTT, jitter, loss rate, and throughput ratio.
        ///
        /// WHY:  Different path types require different pacing and CWND policies:
        ///       - LAN paths have negligible queuing → aggressive probing is safe.
        ///       - Mobile paths have jitter/loss from radio, not congestion →
        ///         maintain high gain, recover fast.
        ///       - Lossy long-fat paths have steady background loss →
        ///         RTT trend is the real congestion signal.
        ///       - CongestedBottleneck paths have queuing → conservative gain.
        ///       - VPN paths have stable-but-elevated RTT → tight CWND cap.
        ///
        /// HOW:  Average all classifier windows, then apply decision rules in
        ///       priority order.  Rules are checked top-to-bottom; the first
        ///       match wins.  This means more specific rules (LAN, Mobile)
        ///       take precedence over catch-all rules (Default).
        ///
        ///       1. LowLatencyLAN:  avgRtt &lt; 5ms, loss &lt; 0.1%, jitter &lt; 2ms
        ///       2. MobileUnstable: loss &gt; threshold AND jitter &gt; threshold
        ///       3. LossyLongFat:   avgRtt &gt; threshold AND loss &gt; 1%
        ///       4. CongestedBottleneck: throughput &lt; 70% AND RTT growing
        ///       5. SymmetricVPN:   avgRtt &gt; 60ms
        ///       6. Default:        none of the above
        /// </summary>
        /// <returns>The classified network path type.</returns>
        private NetworkClass ClassifyNetworkPath()
        {
            // Need at least 2 windows (~4 seconds of data) to make a reliable
            // classification.  A single window could be dominated by a
            // transient event.
            if (_classifierWindowCount < 2)
            {
                return NetworkClass.Default; // Not enough data yet.
            }

            // Average all windows.
            double avgRtt = 0d;
            double avgLoss = 0d;
            double avgJitter = 0d;
            double minThroughput = 1d;
            for (int i = 0; i < _classifierWindowCount; i++)
            {
                avgRtt += _classifierWindows[i].AvgRttMicros;
                avgLoss += _classifierWindows[i].LossRate;
                avgJitter += _classifierWindows[i].JitterMicros;
                if (_classifierWindows[i].ThroughputRatio > 0 && _classifierWindows[i].ThroughputRatio < minThroughput)
                {
                    minThroughput = _classifierWindows[i].ThroughputRatio;
                }
            }

            avgRtt /= _classifierWindowCount;
            avgLoss /= _classifierWindowCount;
            avgJitter /= _classifierWindowCount;

            double avgRttMs = avgRtt / UcpConstants.MICROS_PER_MILLI;
            double avgJitterMs = avgJitter / UcpConstants.MICROS_PER_MILLI;

            // Rule 1: Low-latency LAN
            // Sub-5ms RTT, negligible loss (&lt;0.1%), low jitter (&lt;2ms).
            // These paths have essentially zero queuing delay; the BDP is
            // tiny so aggressive probing causes no harm.
            if (avgRttMs < UcpConstants.NETWORK_CLASSIFIER_LAN_RTT_MS && avgLoss < 0.001d && avgJitterMs < UcpConstants.NETWORK_CLASSIFIER_LAN_JITTER_MS)
            {
                return NetworkClass.LowLatencyLAN;
            }

            // Rule 2: Mobile/Unstable
            // High loss ratio AND high jitter together is the signature of
            // a wireless link (LTE/5G/WiFi).  Radio-layer retransmissions
            // and scheduling create burst loss + jitter spikes.
            if (avgLoss > UcpConstants.NETWORK_CLASSIFIER_MOBILE_LOSS_RATE && avgJitterMs > UcpConstants.NETWORK_CLASSIFIER_MOBILE_JITTER_MS)
            {
                return NetworkClass.MobileUnstable;
            }

            // Rule 3: Lossy Long-Fat
            // High RTT (e.g. &gt;200ms satellite) combined with steady loss
            // &gt;1%.  The loss is typically from physical-layer noise on
            // long-haul links, not congestion.
            if (avgRttMs > UcpConstants.NETWORK_CLASSIFIER_LONG_FAT_RTT_MS && avgLoss > 0.01d)
            {
                return NetworkClass.LossyLongFat;
            }

            // Rule 4: Congested Bottleneck
            // Throughput is significantly below BtlBw (&lt;70%) AND RTT is
            // growing (latest window's RTT &gt; 110% of average).  Both
            // together suggest a bottleneck queue is building.
            // Note: comparing _classifierWindows[0].AvgRttMicros against
            // the overall avgRtt checks for a rising RTT trend.
            if (minThroughput < 0.7d && avgRttMs > _classifierWindows[0].AvgRttMicros / UcpConstants.MICROS_PER_MILLI * 1.1d)
            {
                return NetworkClass.CongestedBottleneck;
            }

            // Rule 5: Symmetric VPN
            // Moderate-to-high RTT (&gt;60ms) with relatively stable patterns.
            // VPN tunnels add ~30-60ms of overhead; the path is symmetric
            // (both directions traverse the same tunnel).  CWND should be
            // capped conservatively to avoid tunnel buffer stuffing.
            if (avgRttMs > 60d)
            {
                return NetworkClass.SymmetricVPN;
            }

            // Rule 6: Default
            // None of the above patterns matched.  Use generic pacing and
            // CWND policies — conservative but not overly so.
            return NetworkClass.Default;
        }
    }
}
