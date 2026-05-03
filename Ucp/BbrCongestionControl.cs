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
            : this(new UcpConfiguration()) // Delegate to the parameterized constructor with default config as baseline.
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
            _config = config ?? new UcpConfiguration(); // Store config reference; fall back to default if null to ensure we always have valid settings.
            Mode = BbrMode.Startup; // Start in Startup mode to rapidly discover the bottleneck bandwidth via exponential probing.
            PacingGain = _config.StartupPacingGain; // Set initial pacing gain (typically 2.89×, derived from 2/ln(2), for exponential startup ramp-up).
            CwndGain = _config.StartupCwndGain; // Set initial CWND gain (typically 2.89×) to match the pacing gain for aggressive probing.
            _maxBandwidthLossPercent = _config.EffectiveMaxBandwidthLossPercent; // Load the maximum tolerable loss percentage from config (e.g. 5% for loss-control decisions).
            BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond; // Initialize BtlBw to the configured target bottleneck rate as the starting estimate.
            if (_config.MaxPacingRateBytesPerSecond > 0 && BtlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) // A hard rate cap is configured and the initial BtlBw exceeds it.
            {
                BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond; // Clamp to max.
            }

            MinRttMicros = 0; // No RTT samples collected yet; MinRtt starts at zero until the first ACK arrives.
            RecalculateModel(UcpTime.NowMicroseconds()); // Compute the initial pacing rate and CWND from the starting BtlBw and MinRtt estimates.
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
            // from collapsing the CWND model, while still allowing MinRtt
            // to track improving path conditions.
            bool minRttExpired = MinRttMicros > 0 && nowMicros - _minRttTimestampMicros >= _config.ProbeRttIntervalMicros; // Determine if MinRtt has gone stale (exceeded the configured ProbeRTT refresh interval).
            if (sampleRttMicros > 0) // Only process valid (non-zero) RTT samples — some ACKs carry no RTT measurement.
            {
                _currentRttMicros = sampleRttMicros; // Record the most recent RTT sample for round-tracking and diagnostic purposes.
                if (MinRttMicros == 0 || sampleRttMicros < MinRttMicros) // First-ever RTT sample OR a new candidate minimum that beats the current floor.
                {
                    // Sticky min-RTT: only drop at most 25% per sample to prevent
                    // a single lucky fast measurement from collapsing CWND.
                    if (MinRttMicros > 0) // Not the first sample — use the sticky floor to prevent excessive reduction.
                    {
                        MinRttMicros = Math.Max(sampleRttMicros, (long)(MinRttMicros * 0.75d)); // Allow at most 25% reduction per sample to prevent CWND collapse from one lucky fast measurement.
                    }
                    else
                    {
                        MinRttMicros = sampleRttMicros; // First-ever RTT sample: use it directly as the initial MinRtt baseline.
                    }
                    
                    _minRttTimestampMicros = nowMicros; // Record the time of this MinRtt update to track freshness for the ProbeRTT interval timer.
                    minRttExpired = false; // Resets the expiry clock.
                }
            }

            // ---- Step 2: Compute delivery rate for this ACK ----
            // Delivery rate = newly ACKed bytes / interval since last ACK.
            // We use the actual wall-clock interval rather than the RTT
            // sample because ACK compression can make RTT samples misleading.
            long intervalMicros;
            if (_lastAckMicros == 0) // First ACK ever received — no previous timestamp exists to compute a real interval.
            {
                intervalMicros = sampleRttMicros > 0 ? sampleRttMicros : 1; // Use the RTT sample itself as a fallback interval, or 1us to avoid division by zero.
            }
            else
            {
                intervalMicros = Math.Max(1, nowMicros - _lastAckMicros); // Compute wall-clock interval since the last ACK, with a 1us minimum to avoid divide-by-zero.
            }

            _lastAckMicros = nowMicros; // Update the last-ACK timestamp for the next interval computation on the next ACK.

            // ---- Step 3: Feed delivery-rate samples into the max-filter ----
            if (deliveredBytes > 0) // Only process ACKs that actually acknowledge new data — pure window updates may carry zero bytes.
            {
                _totalDeliveredBytes += deliveredBytes; // Accumulate total delivered bytes (since connection start) for round boundary detection.
                double deliveryRate = deliveredBytes * UcpConstants.MICROS_PER_SECOND / (double)intervalMicros; // Compute the instantaneous delivery rate in bytes per second.
                if (PacingRateBytesPerSecond > 0) // Only apply the ACK aggregation cap when we have a valid pacing rate baseline to compare against.
                {
                    // Cap the delivery rate to prevent ACK aggregation from inflating estimates.
                    // ACK aggregation (multiple ACKs arriving in a tight burst after a gap)
                    // can produce absurdly high instantaneous delivery rates that are not
                    // representative of the path.  In Startup we allow a higher cap (2.5×)
                    // to avoid under-clamping during rapid ramp-up; in steady state the
                    // cap is tighter (1.3×).
                    double aggregationCapGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_ACK_AGGREGATION_RATE_CAP_GAIN : UcpConstants.BBR_STEADY_ACK_AGGREGATION_RATE_CAP_GAIN; // Select the cap gain: looser 2.5x in Startup (to allow rapid ramp-up), tighter 1.3x in steady state (to prevent overshoot).
                    deliveryRate = Math.Min(deliveryRate, PacingRateBytesPerSecond * aggregationCapGain); // Clamp the delivery rate to at most the pacing rate multiplied by the aggregation cap gain.
                }

                _deliveryRateBytesPerSecond = deliveryRate; // Store the most recent delivery rate for diagnostics and loss-percentage calculations.
                AddRateSample(deliveryRate, nowMicros);       // Max-filter for BtlBw.
                AddDeliveryRateSample(deliveryRate);           // Trend history for congestion detection.
                if (_lossCwndGain < 1d && Mode != BbrMode.ProbeRtt) // CWND loss reduction is active (gain < 1.0) and we're not in the ProbeRTT drain phase (which handles recovery differently).
                {
                    // Gradually recover CWND gain after loss reduction.
                    // Accelerated recovery on mobile/unstable paths where
                    // loss is rarely real congestion.
                    double recoveryStep = (CurrentNetworkClass == NetworkClass.MobileUnstable
                                            || _networkCondition == NetworkCondition.RandomLoss)
                        ? UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP_FAST // Fast recovery step for mobile/random-loss paths where loss is typically noise.
                        : UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP; // Standard (slower) recovery step for all other path types.
                    _lossCwndGain = Math.Min(1d, _lossCwndGain + recoveryStep); // Increment CWND gain by one recovery step toward 1.0 (full recovery), never exceeding 1.0.

                    // On mobile paths, don't let CWND stay depressed for
                    // more than 3 ACKs after any loss event.
                    if (CurrentNetworkClass == NetworkClass.MobileUnstable
                        && _lossCwndGain < 0.98d) // CWND gain is still significantly below full on a mobile path — loss was likely non-congestion.
                    {
                        // Accelerate back to near-full.
                        _lossCwndGain = Math.Min(1d, _lossCwndGain + recoveryStep * 2d); // Apply a double recovery step to rapidly restore throughput on mobile links.
                    }
                }
            }

            if (sampleRttMicros > 0) // A valid RTT sample was included with this ACK — store it for jitter and percentile analysis.
            {
                AddRttSample(sampleRttMicros); // Feed the RTT sample into the history buffer (capped at 500ms to filter RTO stalls).
            }

            // ---- Step 4: Classify network condition and path type ----
            // The local condition (Idle/LightLoad/Congested/RandomLoss) drives
            // immediate pacing and loss decisions.  The path class (LAN, Mobile,
            // LossyFat, etc.) drives long-term gain policies.
            AdvanceClassifierWindow(nowMicros, deliveredBytes + flightBytes, sampleRttMicros, GetRecentLossRatio(nowMicros)); // Accumulate bytes, RTT, and loss data into the classifier window for path-type classification.
            CurrentNetworkClass = ClassifyNetworkPath(); // Classify the end-to-end network path (LAN, Mobile, LossyFat, VPN, etc.) from multi-second aggregated statistics.

            _networkCondition = ClassifyNetworkCondition(nowMicros); // Classify the instantaneous local network condition (Idle, LightLoad, Congested, or RandomLoss) from recent trends.
            if (_networkCondition == NetworkCondition.Congested) // The network is congested — the path's capacity may have changed.
            {
                // Congestion detected: reset the soft BtlBw floor so it
                // does not hold onto a rate that the path can no longer
                // support.
                _maxBtlBwInNonCongestedWindow = 0; // Invalidate the non-congested BtlBw soft floor since congestion indicates the path cannot sustain its previous rate.
            }

            UpdateEstimatedLossPercent(nowMicros); // Update the EWMA-smoothed loss percentage estimate from the current loss data.
            UpdateInflightBounds(); // Recompute the upper and lower inflight guardrails (CWND ceilings/floors) based on current BDP and path class.

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
            if (minRttExpired && Mode != BbrMode.ProbeRtt) // MinRtt has gone stale AND we're not currently in the middle of a ProbeRTT cycle.
            {
                bool bandwidthGrowthStalled = _fullBandwidthRounds >= UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER; // Check if bandwidth discovery has stalled for a sufficient number of rounds.
                bool isLossyFat = CurrentNetworkClass == NetworkClass.LossyLongFat; // Determine if the current path is classified as lossy long-fat (satellite/long-haul).
                bool isMobile = CurrentNetworkClass == NetworkClass.MobileUnstable; // Determine if the current path is classified as mobile/unstable (LTE/5G/WiFi).

                // Skip ProbeRTT on mobile paths — jitter dominates RTT and
                // P10/P30 tracking already provides a robust min RTT proxy.
                // Entering ProbeRTT just creates an unnecessary throughput cliff.
                if (isMobile) // Mobile path detected — skip ProbeRTT entirely to avoid a throughput penalty on a path dominated by non-queuing jitter.
                {
                    // Just refresh the min-RTT timestamp to keep it fresh.
                    _minRttTimestampMicros = nowMicros; // Reset the MinRtt timestamp so the ProbeRTT interval timer restarts without actually entering the probe.
                }
                else if (bandwidthGrowthStalled || !isLossyFat) // Bandwidth growth has stalled (always safe to probe) OR path is not lossy-long-fat (probe won't disrupt bandwidth discovery).
                {
                    EnterProbeRtt(nowMicros); // Enter the ProbeRTT deep-drain phase to collect a fresh minimum RTT measurement.
                }
                else
                {
                    TraceLog(string.Concat("SkipProbeRtt btlBw=", BtlBwBytesPerSecond, " fullBwRounds=", _fullBandwidthRounds, " preservedOnLossyFat")); // Log the decision to skip ProbeRTT on a lossy fat path that still has active bandwidth growth.
                }
            }

            // ---- Step 6: Round detection ----
            // A BBR "round" is completed when cumulative delivered bytes
            // reach the threshold (_nextRoundDeliveredBytes).  The round
            // length is approximately one BDP worth of data, which on a
            // well-paced connection equals one RTT.  Round boundaries
            // trigger Startup exit checks and ProbeBW gain-cycle advances.
            bool roundStart = false; // Default: no round boundary detected unless proven otherwise below.
            if (_nextRoundDeliveredBytes == 0) // First ACK — the round-delivered threshold has not been initialized yet.
            {
                _nextRoundDeliveredBytes = _totalDeliveredBytes + Math.Max(deliveredBytes, flightBytes); // Initialize the next round boundary at approximately one BDP's worth of data ahead.
            }
            else if (_totalDeliveredBytes >= _nextRoundDeliveredBytes) // Cumulative delivered bytes have crossed the round boundary — a new round begins.
            {
                _nextRoundDeliveredBytes = _totalDeliveredBytes + Math.Max(deliveredBytes, flightBytes); // Advance the round boundary by another BDP's worth of data for the next round.
                roundStart = deliveredBytes > 0; // Mark the round start (only meaningful if actual data bytes were delivered this ACK).
            }

            // ---- Step 7: State-machine dispatch ----
            // Each state has a different behavior on ACK and round events.

            // --- STARTUP: exponential bandwidth probing ---
            // Pacing at 2.89× BtlBw, CWND at 2.89× BDP.  At each round
            // boundary, check whether BtlBw grew by ≥ 1.25×.  If it stalls
            // for N rounds, transition to Drain.
            if (Mode == BbrMode.Startup) // We are in Startup mode — evaluate bandwidth growth at each round boundary.
            {
                if (roundStart) // A round boundary has been reached during Startup.
                {
                    UpdateStartup(); // Run the Startup bandwidth-growth check and potentially transition to Drain if growth has stalled.
                }
            }
            // --- DRAIN: queue-draining transition ---
            // Pacing at DrainPacingGain (typically 0.75–0.90× depending on
            // loss conditions).  Exit when in-flight bytes drop to the BDP
            // target or the minimum duration has elapsed.
            else if (Mode == BbrMode.Drain) // We are in Drain mode — waiting for the standing queue to be flushed.
            {
                // Exit drain when in-flight drops to the target or the minimum duration elapsed.
                if (flightBytes <= GetTargetCwndBytes() || nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, UcpConstants.BBR_MIN_ROUND_DURATION_MICROS)) // In-flight has drained to the CWND target OR the minimum drain duration has elapsed.
                {
                    EnterProbeBw(nowMicros); // Transition to ProbeBW steady-state cycling — the pipe is now clean.
                }
            }
            // --- PROBEBW: steady-state gain cycling ---
            // Cycle through the 8-phase gain sequence once per round.
            // Mobile/lossy paths spend 7/8 of the time in high-gain
            // phases to compensate for non-congestion throughput loss.
            else if (Mode == BbrMode.ProbeBw) // We are in ProbeBW mode — advance the gain cycle and adjust for path class.
            {
                // Advance the gain cycle index when the round duration elapses.
                if (nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, UcpConstants.BBR_MIN_ROUND_DURATION_MICROS)) // A full round has elapsed since the current gain-phase began — time to cycle.
                {
                    _probeBwCycleIndex = (_probeBwCycleIndex + 1) % UcpConstants.BBR_PROBE_BW_GAIN_COUNT; // Advance to the next phase in the 8-phase gain cycle (wrapping from 7 back to 0).
                    _modeEnteredMicros = nowMicros; // Record the timestamp when this new gain-phase began for the next round-duration check.
                }

                // On mobile/lossy non-congested paths, stay in the high-gain
                // phase longer (7/8 instead of 4/8) to maintain throughput.
                if ((CurrentNetworkClass == NetworkClass.MobileUnstable
                     || CurrentNetworkClass == NetworkClass.LossyLongFat)
                    && _networkCondition != NetworkCondition.Congested) // Path is mobile or lossy-fat AND not currently congested — use extended high-gain policy.
                {
                    // Only use low-gain phase 1/8 of the time.
                    if (_probeBwCycleIndex < UcpConstants.BBR_PROBE_BW_GAIN_COUNT - 1) // Not in the final (drain) phase of the cycle — use the normal adaptive pacing gain.
                    {
                        PacingGain = CalculatePacingGain(nowMicros); // Compute the adaptive pacing gain for the current cycle phase and path conditions.
                    }
                    else
                    {
                        PacingGain = Math.Min(1.0d, _config.ProbeBwLowGain); // In the drain phase: use the configured low gain, capped at 1.0x so we never exceed the bottleneck rate.
                    }
                }
                else
                {
                    PacingGain = CalculatePacingGain(nowMicros); // Standard path or congested — use the normal adaptive pacing gain for the current cycle index.
                }
            }
            // --- PROBERTT: deep-drain to measure true base RTT ---
            // CWND reduced to 4×MSS, pacing at 0.5× BtlBw.  Exit when
            // a near-minimum RTT sample confirms the base RTT or the
            // safety timeout fires.  On non-congested paths, exit faster.
            else if (Mode == BbrMode.ProbeRtt) // We are in ProbeRTT mode — maintain the low pacing gain and check for exit conditions.
            {
                PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN; // Enforce the ProbeRTT low pacing gain (0.50×) to drain the pipe and measure the true base RTT.
                if (ShouldExitProbeRtt(nowMicros, sampleRttMicros)) // Check exit conditions: fresh near-minimum RTT sample observed OR safety timeout expired.
                {
                    ExitProbeRtt(nowMicros, sampleRttMicros); // Exit ProbeRTT: adopt the new MinRtt if valid, then transition back to ProbeBW.
                }
            }

            // ---- Step 8: Fast recovery timeout ----
            // Fast recovery (elevated pacing for non-congestion loss) lasts
            // at most one RTT.  After that, normal pacing resumes.
            if (_fastRecoveryEnteredMicros > 0 && MinRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros >= MinRttMicros) // Fast recovery is active and one full RTT has elapsed since it was entered.
            {
                _fastRecoveryEnteredMicros = 0; // Exit fast recovery after one RTT.
            }

            // ---- Step 9: Recompute pacing rate and CWND ----
            RecalculateModel(nowMicros); // Run the final model recomputation: derive pacing rate (BtlBw × PacingGain) and CWND (BDP × CwndGain) from all updated estimates.
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
            AdvanceLossBuckets(nowMicros); // Age out expired loss buckets and advance the ring pointer to the current time slot.
            _sentBuckets[_lossBucketIndex]++; // Increment the sent-packet counter for the current bucket — every packet (original or retransmit) counts toward the total.
            if (isRetransmit) // This packet is a retransmission (RTO, fast retransmit, or SACK-triggered retransmit).
            {
                _retransmitBuckets[_lossBucketIndex]++; // Increment the retransmit counter — this directly feeds the loss ratio (retransmits / sent).
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
            if (_config.EnableDebugLog) // Debug logging is enabled in the configuration — emit a diagnostic trace to aid troubleshooting.
            {
                Trace.WriteLine("[UCP BBR] FastRetransmit congestion=" + isCongestion); // Log the fast retransmit event along with its congestion classification.
            }

            if (!isCongestion) // The loss was NOT classified as congestion by the caller — treat as random/burst loss.
            {
                // Non-congestion loss: enter fast recovery with elevated pacing gain.
                _fastRecoveryEnteredMicros = nowMicros; // Mark the start of the fast recovery period (lasts at most one RTT).
                PacingGain = UcpConstants.BBR_FAST_RECOVERY_PACING_GAIN; // Elevate pacing gain to 1.15× to rapidly refill the loss hole without creating new loss.
                RecalculateModel(nowMicros); // Recompute pacing rate and CWND with the elevated fast-recovery pacing gain.
            }

            OnPacketLoss(nowMicros, GetRecentLossRatio(nowMicros), isCongestion); // Always forward to the general loss handler for EWMA loss-tracking and condition re-classification.
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
            if (nowMicros <= 0) // Timestamp was not provided (zero/negative) — use the current real time as a fallback.
            {
                nowMicros = UcpTime.NowMicroseconds(); // Get the current high-resolution timestamp to ensure valid timing for all subsequent decisions.
            }

            // Merge externally-provided loss rate with the internal sliding-window
            // ratio.  Take the max — if either says loss is high, we should be
            // conservative.
            double recentLossRate = GetRecentLossRatio(nowMicros); // Get the internally-tracked loss ratio from the sliding per-bucket sent/retransmit counters.
            lossRate = Math.Max(lossRate, recentLossRate); // Be conservative: use the higher of the externally-provided and internally-computed loss rates.

            // Re-evaluate condition with the freshest data.
            _networkCondition = ClassifyNetworkCondition(nowMicros); // Re-run the three-tier congestion classifier with the most recent delivery-rate and RTT data.
            UpdateEstimatedLossPercent(nowMicros, lossRate * 100d); // Update the EWMA-smoothed loss percentage estimate with the new loss data (converted from ratio to percent).

            bool treatAsCongestion = ShouldTreatLossAsCongestion(nowMicros, isCongestion); // Determine whether this loss event warrants multiplicative CWND reduction vs fast recovery only.

            if (treatAsCongestion) // This loss is confirmed as congestion — apply aggressive multiplicative reduction.
            {
                // Congestion loss: apply multiplicative CWND reduction.
                // _lossCwndGain starts at 1.0 and drops to 0.70 on first
                // congestion event, 0.49 on second, etc.  It recovers
                // gradually on subsequent ACKs (see OnAck).
                _lossCwndGain = Math.Max(UcpConstants.BBR_MIN_LOSS_CWND_GAIN,
                    _lossCwndGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION); // Multiply current CWND gain by 0.70 for multiplicative reduction, with a hard floor to prevent total starvation.

                // On congestion, enter ProbeRTT to get a fresh MinRtt.
                // The congestion queue may have inflated RTT, so we need
                // a new baseline before resuming normal operation.
                if (Mode != BbrMode.ProbeRtt && Mode != BbrMode.Startup) // Only enter ProbeRTT if we're not already probing and not in the initial ramp-up (Startup handles itself).
                {
                    EnterProbeRtt(nowMicros); // Enter ProbeRTT deep-drain to refresh the MinRtt estimate after the congestion queue has subsided.
                }
            }
            else
            {
                // Random/non-congestion loss: fast recovery with elevated pacing.
                // Never reduce CWND for random loss.
                _fastRecoveryEnteredMicros = nowMicros; // Start the fast recovery timer for non-congestion loss (one RTT of elevated pacing).
                if (Mode == BbrMode.ProbeBw) // We are in steady-state ProbeBW — ensure the pacing gain stays at or above the normal calculated level.
                {
                    // Ensure pacing gain is at least the calculated probe gain.
                    // Don't let a random loss drop us below the normal probe level.
                    PacingGain = Math.Max(PacingGain, CalculatePacingGain(nowMicros)); // Take the higher of current and calculated pacing gains — never let random loss reduce pacing.
                }
            }

            RecalculateModel(nowMicros); // Recompute pacing rate and CWND with the updated loss parameters, reflecting any gain changes.
        }

        /// <summary>
        /// Called when the underlying network path changes (e.g., NAT rebinding,
        /// mobile handover between WiFi and cellular). Resets path-specific
        /// estimates while preserving the congestion window and pacing rate
        /// as a starting point for the new path.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        public void OnPathChange(long nowMicros)
        {
            // Preserve BtlBw and pacing rate as starting point for the new path.
            // Reset: MinRtt (path delay changed), RTT history (stale samples),
            // classifier windows (path characteristics changed),
            // bandwidth growth window (different bottleneck).
            _minRttTimestampMicros = 0; // Reset min-RTT timestamp so the next RTT sample becomes the new baseline for the new path.
            MinRttMicros = 0; // Reset minimum RTT — the new path has a different propagation delay that must be re-measured.
            Array.Clear(_rttHistoryMicros, 0, _rttHistoryMicros.Length); // Clear all stale RTT samples collected from the old path to prevent them from corrupting new estimates.
            _rttHistoryCount = 0; // Reset RTT history sample count so the new path starts with a fresh buffer.
            _rttHistoryIndex = 0; // Reset RTT history write position to the start of the circular buffer.
            _bandwidthGrowthWindowMicros = 0; // Reset bandwidth growth window — the new path has different bottleneck characteristics.
            _bandwidthGrowthWindowStartRate = 0; // Reset growth window starting rate so the first sample on the new path establishes a fresh baseline.
            _classifierWindowCount = 0; // Reset classifier window count — old path statistics are stale and must not influence path classification.
            _classifierWindowIndex = 0; // Reset classifier write position to the start of the circular buffer.
            _classifierWindowStartMicros = 0; // Reset classifier window start timestamp so a new window begins on the next ACK.
            _fullBandwidthRounds = 0; // Reset startup full-bandwidth round counter — the new path needs fresh bandwidth discovery.
            _fullBandwidthEstimate = 0; // Reset full-bandwidth estimate so bandwidth growth is re-evaluated from scratch on the new path.
            // Stay in current mode but reset round tracking so the first ACK starts a fresh round.
            _nextRoundDeliveredBytes = 0; // Reset round boundary tracking so the next ACK initializes a new round on the new path.
            RecalculateModel(nowMicros); // Recompute cwnd and pacing rate with the reset parameter state as the starting point for the new path.
            TraceLog(string.Concat("PathChange btlBw=", BtlBwBytesPerSecond, " cwnd=", CongestionWindowBytes)); // Log the path change event with key state for diagnostics.
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
            double current = BtlBwBytesPerSecond; // Snapshot the current BtlBw estimate for comparison against the tracked full-bandwidth best.
            if (_fullBandwidthEstimate <= 0) // First round of Startup — no previous best exists to compare against.
            {
                _fullBandwidthEstimate = current; // Initialize the full-bandwidth estimate to the current BtlBw as the baseline.
                return; // Nothing more to do on the first round — exit early.
            }

            // Growth ≥ 1.25× → still ramping up; reset stall counter.
            if (current >= _fullBandwidthEstimate * UcpConstants.BbrStartupGrowthTarget) // BtlBw grew by at least the growth target (1.25×) since the tracked best — bandwidth is still being discovered.
            {
                _fullBandwidthEstimate = current; // Update the tracked best BtlBw to the new higher value.
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
            int requiredStallRounds = UcpConstants.MinBbrStartupFullBandwidthRounds; // Default number of consecutive stall rounds required to exit Startup (typically 3).
            if (_config.MaxPacingRateBytesPerSecond > 0
                && BtlBwBytesPerSecond >= _config.MaxPacingRateBytesPerSecond * 0.90d) // A user-configured rate cap exists AND we've reached 90% of it — fast exit is appropriate.
            {
                requiredStallRounds = 1; // Fast exit: already at target.
            }

            if (_fullBandwidthRounds >= requiredStallRounds) // Bandwidth has stalled for the required number of rounds — the pipe is full and Startup should end.
            {
                EnterDrain(_lastAckMicros); // Transition to Drain mode to flush the standing queue accumulated during Startup's aggressive probing.
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
        ///          the time window (typically 6-10 RTTs).
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
            _recentRates[_recentRateIndex] = deliveryRate; // Store the delivery rate value at the current circular buffer write position.
            _recentRateTimestamps[_recentRateIndex] = nowMicros; // Store the corresponding timestamp for age-based sample expiry during the max-filter scan.
            _recentRateIndex = (_recentRateIndex + 1) % _recentRates.Length; // Advance the write position (wrapping around to 0 when reaching the end of the buffer).
            if (_recentRateCount < _recentRates.Length) // The buffer has not yet filled up (first pass through) — increment the valid sample count.
            {
                _recentRateCount++; // Increase the count of valid entries available for the max-filter scan.
            }

            // Max-filter: scan all recent samples within the time window
            // and pick the maximum.  The window is typically ~6 RTTs wide.
            double maxRate = 0; // Initialize the maximum rate accumulator to zero before the scan.
            long rttWindowMicros = MinRttMicros > 0 ? MinRttMicros * Math.Max(1, _config.BbrWindowRtRounds) : UcpConstants.BBR_DEFAULT_RATE_WINDOW_MICROS; // Compute the sliding window duration: MinRtt multiplied by the configured number of RTT rounds, or a fixed default if no MinRtt Yet.
            for (int i = 0; i < _recentRateCount; i++) // Iterate through all valid entries in the circular rate buffer.
            {
                // Expire samples older than the window.
                if (nowMicros - _recentRateTimestamps[i] > Math.Max(rttWindowMicros, 1)) // The sample's age exceeds the sliding window — it is stale and must be ignored.
                {
                    continue; // Sample is outside the window.
                }

                if (_recentRates[i] > maxRate) // This sample's rate is higher than the current running maximum.
                {
                    maxRate = _recentRates[i]; // Update the running maximum with this higher value.
                }
            }

            if (maxRate > 0) // At least one valid (in-window) sample was found — a new BtlBw candidate exists.
            {
                // Clamp growth: limit how fast BtlBw can increase per round.
                // This prevents a single bursty measurement from over-shooting.
                maxRate = ClampBandwidthGrowth(maxRate, nowMicros); // Apply the per-round growth clamp to prevent unrealistic bandwidth jumps from a single ACK burst.
                if (_config.MaxPacingRateBytesPerSecond > 0 && maxRate > _config.MaxPacingRateBytesPerSecond) // A hard user-configured rate cap exists and the candidate rate exceeds it.
                {
                    maxRate = _config.MaxPacingRateBytesPerSecond; // Clamp to the configured maximum — never exceed the user-specified rate limit.
                }

                // Track maximum BtlBw seen during non-congested intervals.
                // This serves as a soft floor: when the network is not
                // congested, we know the path can support at least this rate.
                if (_networkCondition != NetworkCondition.Congested) // The path is not congested — this delivery rate is a valid indicator of true path capacity.
                {
                    if (maxRate > _maxBtlBwInNonCongestedWindow) // The new candidate exceeds the previously tracked non-congested maximum BtlBw.
                    {
                        _maxBtlBwInNonCongestedWindow = maxRate; // Update the non-congested maximum — this strengthens the soft floor for future rate depressions.
                    }
                }

                BtlBwBytesPerSecond = maxRate; // Set the official bottleneck bandwidth estimate to the max-filter scan result.

                // Hard floor: BtlBw never drops below the configured initial
                // bandwidth (which is the target bottleneck rate).
                if (BtlBwBytesPerSecond < _config.InitialBandwidthBytesPerSecond) // BtlBw fell below the configured initial bandwidth floor.
                {
                    BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond; // Restore BtlBw to the hard floor — the path is expected to support at least this rate.
                    if (_config.MaxPacingRateBytesPerSecond > 0 && BtlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) // The hard floor itself exceeds the configured rate cap — re-apply the cap.
                    {
                        BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond; // Clamp to the rate cap on top of the hard floor.
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
                    && BtlBwBytesPerSecond < _maxBtlBwInNonCongestedWindow * 0.90d) // Not congested, soft floor exists, loss is under 5%, and BtlBw fell below 90% of the non-congested peak.
                {
                    BtlBwBytesPerSecond = _maxBtlBwInNonCongestedWindow * 0.90d; // Restore BtlBw to 90% of the best non-congested rate — prevent a transient gap from permanently depressing the estimate.
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
            if (candidateRate <= BtlBwBytesPerSecond || BtlBwBytesPerSecond <= 0) // The candidate rate does not exceed the current estimate, or no current estimate exists — no clamping is needed.
            {
                return candidateRate; // No increase, no clamping needed.
            }

            long growthIntervalMicros = MinRttMicros > 0 ? MinRttMicros : UcpConstants.BBR_BANDWIDTH_GROWTH_FALLBACK_INTERVAL_MICROS; // Determine the growth window duration: use the measured MinRtt, or a fixed fallback if not yet available.
            if (_bandwidthGrowthWindowMicros == 0 || nowMicros - _bandwidthGrowthWindowMicros >= growthIntervalMicros) // No growth window is active yet, or the current window has expired — start a new window.
            {
                // Start a new growth window.
                _bandwidthGrowthWindowMicros = nowMicros; // Record the start time of this new bandwidth growth window.
                _bandwidthGrowthWindowStartRate = BtlBwBytesPerSecond; // Snapshot the current BtlBw as the baseline rate for this window's growth cap.
            }

            // Growth cap: Startup allows more aggressive growth (4× per round)
            // because BtlBw is expected to double each round during ramp-up.
            // Steady state caps at 1.25× to prevent overshoot.
            double growthGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_BANDWIDTH_GROWTH_PER_ROUND : UcpConstants.BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND; // Select the per-round growth multiplier: aggressive 4× in Startup (rapid discovery), conservative 1.25× in steady state (prevent overshoot).
            double growthCap = Math.Max(BtlBwBytesPerSecond, _bandwidthGrowthWindowStartRate * growthGain); // Compute the maximum allowed rate: the starting rate multiplied by the growth gain, floored at the current BtlBw to avoid regressing.
            return Math.Min(candidateRate, growthCap); // Clamp the candidate rate to at most the computed growth cap.
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
            _deliveryRateHistory[_deliveryRateHistoryIndex] = deliveryRate; // Store the delivery rate at the current write position in the trend-history circular buffer.
            _deliveryRateHistoryIndex = (_deliveryRateHistoryIndex + 1) % _deliveryRateHistory.Length; // Advance the write position by one (wrapping around at the end of the buffer).
            if (_deliveryRateHistoryCount < _deliveryRateHistory.Length) // The buffer has not yet wrapped — increase the valid entry count.
            {
                _deliveryRateHistoryCount++; // Increment the count of valid samples available for oldest-vs-newest trend comparison.
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
        ///       normal queuing delay (typically 1-200ms).
        /// </summary>
        /// <param name="sampleRttMicros">RTT sample in microseconds.</param>
        private void AddRttSample(long sampleRttMicros)
        {
            if (sampleRttMicros <= 0) // Invalid RTT sample (zero or negative) — nothing to store.
            {
                return; // Skip silently — bogus samples would corrupt the history buffer.
            }

            // Hard cap at 500ms: any larger value is a protocol stall
            // (RTO timeout) and would corrupt the percentile estimate.
            if (sampleRttMicros > 500_000L) // RTT exceeds 500ms (indicative of an RTO stall rather than normal queuing delay).
            {
                return; // Discard the sample to prevent it from inflating percentile calculations with pathological values.
            }

            _rttHistoryMicros[_rttHistoryIndex] = sampleRttMicros; // Store the valid RTT sample at the current write position in the history buffer.
            _rttHistoryIndex = (_rttHistoryIndex + 1) % _rttHistoryMicros.Length; // Advance the write position by one (wrapping around at the buffer end).
            if (_rttHistoryCount < _rttHistoryMicros.Length) // The buffer has not yet wrapped — increase the valid sample count.
            {
                _rttHistoryCount++; // Increment the count of valid RTT samples for percentile and average calculations.
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
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0) // Either BtlBw or MinRtt is unavailable — cannot compute a meaningful BDP.
            {
                return _config.InitialCongestionWindowBytes; // Return the configured initial CWND as a safe starting point (typically 10-20 MSS).
            }

            long modelRttMicros = GetCwndModelRttMicros(); // Get the model RTT (P10-based propagation-delay estimate with MinRtt as floor).

            // Sanity cap: modelRtt must not exceed 1 second to prevent
            // runaway CWND during pathological stalls.
            if (modelRttMicros > 500_000L || modelRttMicros <= 0) // Model RTT is above 500ms or invalid — cap it to prevent CWND explosion.
            {
                modelRttMicros = 500_000L; // Cap model RTT at 500ms — any stall longer than this is not representative of normal path conditions.
            }

            // BDP = bandwidth × delay.  This is the amount of data "in the
            // pipe" at the bottleneck rate over the propagation delay.
            double bdp = BtlBwBytesPerSecond * (modelRttMicros / (double)UcpConstants.MICROS_PER_SECOND); // Compute BDP in bytes: bandwidth (bytes/sec) × propagation delay (seconds).
            double effectiveCwndGain = GetEffectiveCwndGain(); // Get the effective CWND gain (adjusted for waste budget and path-class multipliers).
            int cwnd = (int)Math.Ceiling(bdp * effectiveCwndGain); // Compute the target CWND: BDP × effective gain, rounded up to the nearest integer byte.
            if (cwnd < _config.InitialCongestionWindowBytes && Mode == BbrMode.Startup) // CWND fell below the initial floor during Startup — keep at least the initial value to allow ramp-up.
            {
                cwnd = _config.InitialCongestionWindowBytes; // Restore CWND to the configured initial floor to ensure reliable startup probing.
            }

            if (_config.MaxCongestionWindowBytes > 0 && cwnd > _config.MaxCongestionWindowBytes) // A hard maximum CWND is configured and the computed CWND exceeds it.
            {
                cwnd = _config.MaxCongestionWindowBytes; // Clamp CWND to the configured upper bound to prevent unbounded growth (e.g. on high-BDP paths).
            }

            // Apply loss-driven CWND reduction.  When congestion loss occurs,
            // _lossCwndGain drops below 1.0, multiplicatively reducing the
            // window.  It then recovers gradually on subsequent ACKs.
            if (_lossCwndGain < 1d) // Loss reduction is active — the CWND needs to be scaled down multiplicatively.
            {
                cwnd = (int)Math.Ceiling(cwnd * _lossCwndGain); // Apply the loss-driven multiplicative reduction: cwnd = cwnd × _lossCwndGain.
                if (cwnd < _config.InitialCongestionWindowBytes) // The reduced CWND has fallen below the absolute minimum floor.
                {
                    cwnd = _config.InitialCongestionWindowBytes; // Restore CWND to the initial floor to prevent complete starvation during loss events.
                }
            }

            // Apply inflight guardrails.
            // _inflightHighBytes = upper bound (ceiling); prevents CWND from
            //   creating excessive standing queues even with high CwndGain.
            // _inflightLowBytes = lower bound (floor); prevents CWND from
            //   starving the connection on low-BDP paths.
            if (_inflightHighBytes > 0) // An upper inflight guardrail has been computed — apply the ceiling.
            {
                cwnd = Math.Min(cwnd, (int)Math.Ceiling(_inflightHighBytes)); // Clamp CWND to at most the upper inflight guardrail (typically ~2-3× BDP depending on path class).
            }

            if (_inflightLowBytes > 0) // A lower inflight guardrail has been computed — apply the floor.
            {
                cwnd = Math.Max(cwnd, (int)Math.Ceiling(_inflightLowBytes)); // Clamp CWND to at least the lower inflight guardrail to prevent under-utilization.
            }

            return cwnd; // Return the fully clamped target congestion window in bytes.
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
        ///       3. Compute CWND via GetTargetCwndBytes (BDP × CwndGain model).
        ///       4. Apply hard ceiling: 200ms worth of BtlBw flat cap prevents
        ///          pathological CWND growth during Startup while allowing
        ///          sufficient BDP for all paths.  This is a time-based ceiling,
        ///          not tied to the measured RTT.
        ///       5. Apply absolute minimum: 2× MSS to avoid total starvation.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void RecalculateModel(long nowMicros)
        {
            if (BtlBwBytesPerSecond <= 0) // BtlBw is invalid (zero or negative) — restore it to a safe default.
            {
                BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond; // Set BtlBw to the configured initial bandwidth as a safe fallback.
            }

            if (_config.MaxPacingRateBytesPerSecond > 0 && BtlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) // A user-configured rate cap exists and the current BtlBw exceeds it.
            {
                BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond; // Clamp BtlBw to the configured maximum — never let the estimate exceed the user's limit.
            }

            // ProbeRTT always paces at the low gain to drain the pipe.
            if (Mode == BbrMode.ProbeRtt) // We are in the ProbeRTT deep-drain phase — enforce the low pacing gain unconditionally.
            {
                PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN; // Override pacing gain to the ProbeRTT low value (0.50×) to drain the standing queue.
            }

            // Loss-control: when loss is well within budget, gradually
            // increase pacing gain back toward the high gain (recovery).
            if (_config.LossControlEnable) // The loss-control feature is enabled in the configuration.
            {
                if (EstimatedLossPercent <= _maxBandwidthLossPercent * UcpConstants.BBR_LOSS_BUDGET_RECOVERY_RATIO) // Current loss is well within the bandwidth loss budget — safe to increase pacing gain.
                {
                    PacingGain = Math.Min(_config.ProbeBwHighGain, PacingGain + UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP); // Slowly increment pacing gain by one recovery step toward the high probe gain, capped at the config limit.
                }
            }

            PacingRateBytesPerSecond = BtlBwBytesPerSecond * PacingGain; // Compute the pacing rate as BtlBw multiplied by the current pacing gain.
            if (_config.MaxPacingRateBytesPerSecond > 0
                && PacingRateBytesPerSecond > _config.MaxPacingRateBytesPerSecond
                && EstimatedLossPercent < 3d) // Pacing rate exceeds the configured cap BUT loss is under 3% — clamp rather than penalizing.
            {
                PacingRateBytesPerSecond = _config.MaxPacingRateBytesPerSecond; // Clamp the pacing rate to the user-configured maximum.
            }

            // Unconditional cap for non-mobile non-lossy-fat paths:
            // pacing rate never exceeds 1.50× the configured target
            // to prevent excessive queueing on clean paths.
            if (_config.MaxPacingRateBytesPerSecond > 0
                && CurrentNetworkClass != NetworkClass.MobileUnstable
                && CurrentNetworkClass != NetworkClass.LossyLongFat) // A rate cap is configured and the path is a standard (non-mobile, non-lossy) type.
            {
                double maxPacing = _config.MaxPacingRateBytesPerSecond * 1.50d; // Compute the 1.50× safety cap relative to the configured maximum pacing rate.
                if (PacingRateBytesPerSecond > maxPacing) // The current pacing rate exceeds the 1.50× safety cap.
                {
                    PacingRateBytesPerSecond = maxPacing; // Clamp the pacing rate to 1.50× of the configured max — prevent excessive queuing on clean paths.
                }
            }

            // CWND is computed from the BDP model.  A flat ceiling at
            // 200ms worth of BtlBw prevents pathological CWND growth
            // during Startup while allowing sufficient BDP for all paths.
            CongestionWindowBytes = GetTargetCwndBytes(); // Compute the target CWND from the BDP model (BtlBw × modelRtt × CwndGain) with all guardrails applied.
            if (BtlBwBytesPerSecond > 0) // BtlBw is valid — apply the time-based absolute ceiling.
            {
                int timeCeiling = (int)(BtlBwBytesPerSecond * 0.200d); // Compute 200ms worth of data at the current BtlBw rate as the absolute CWND ceiling.
                if (CongestionWindowBytes > timeCeiling) // The BDP-model CWND exceeds the 200ms time-based ceiling.
                {
                    CongestionWindowBytes = timeCeiling; // Clamp CWND to the 200ms ceiling — prevents pathological CWND growth during Startup or high-gain phases.
                }
            }

            // Absolute minimum: 2× MSS prevents complete stalling.
            if (CongestionWindowBytes < _config.Mss * 2) // CWND has fallen below 2× MSS — the connection is at risk of stalling.
            {
                CongestionWindowBytes = _config.Mss * 2; // Enforce the absolute minimum CWND of 2× MSS to ensure the connection can always send at least two segments.
            }

            _modeEnteredMicros = _modeEnteredMicros == 0 ? nowMicros : _modeEnteredMicros; // Initialize the mode-entered timestamp on the first invocation if not already set by a mode-transition call.
        }

        /// <summary>
        /// Transitions from Startup to Drain.
        ///
        /// WHAT: Startup has discovered the bottleneck bandwidth.  Now Drain
        ///       flushes the standing queue by pacing below the bottleneck
        ///       rate.  Drain pacing gain is adaptive: 1.00× on clean paths
        ///       (just coast), config-specified on lossy paths (typically
        ///       0.75-0.90× to actively drain).
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
            Mode = BbrMode.Drain; // Transition the state machine to Drain mode to flush the standing queue.
            PacingGain = GetDrainPacingGain(nowMicros); // Compute the adaptive drain pacing gain (1.00× on clean paths, lower on lossy paths).
            _modeEnteredMicros = nowMicros; // Record the entry timestamp for drain-duration exit checks.
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
            Mode = BbrMode.ProbeBw; // Transition the state machine to the steady-state ProbeBW cycling mode.
            _probeBwCycleIndex = 0; // Reset the 8-phase gain cycle to the first phase (index 0).

            // CWND gain at 2.0x BDP for all paths provides sufficient headroom
            // for retransmissions without causing bufferbloat.
            CwndGain = _config.ProbeBwCwndGain; // 2.0x BDP.

            PacingGain = CalculatePacingGain(nowMicros); // Compute the initial ProbeBW pacing gain based on current network condition and path class.
            _modeEnteredMicros = nowMicros; // Record the entry timestamp for tracking the duration of each gain-cycle phase.
        }

        /// <summary>
        /// Determines the drain pacing gain: 1.0 if no loss; config drain gain otherwise.
        ///
        /// WHAT: On clean paths with zero recent loss, Drain can use 1.00×
        ///       pacing (no active draining) because the Startup standing
        ///       queue will drain naturally as we stop over-pacing.
        ///       On lossy paths, use the configured DrainPacingGain
        ///       (typically 0.75-0.90×) to actively reduce the queue.
        ///
        /// WHY:  Active draining below 1.00× costs throughput but is necessary
        ///       when the path is already showing loss.  Draining the queue
        ///       reduces RTT and gives the path a clean baseline for ProbeBW.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <returns>Pacing gain for the drain phase.</returns>
        private double GetDrainPacingGain(long nowMicros)
        {
            double recentLossRatio = GetRecentLossRatio(nowMicros); // Get the recent loss ratio from the sliding bucket windows.
            if (recentLossRatio <= 0 && EstimatedLossPercent <= 0) // Both recent and smoothed loss are zero — the path is completely clean.
            {
                return 1d; // Clean drain: use minimal drain gain.
            }

            return _config.DrainPacingGain; // Loss is present — return the configured drain pacing gain for active queue draining (typically 0.75-0.90×).
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
            Mode = BbrMode.ProbeRtt; // Transition to the ProbeRTT deep-drain mode to measure the true base RTT.
            PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN; // Set pacing gain to the ProbeRTT low value (0.50×) to drain the pipe.
            _probeRttEnteredMicros = nowMicros; // Record the entry timestamp for ProbeRTT exit-condition evaluation (duration checks).
            _modeEnteredMicros = nowMicros; // Standard mode-entry timestamp (used by other methods for duration tracking).
            TraceLog(string.Concat("EnterProbeRtt cwnd=", CongestionWindowBytes, " btlBw=", BtlBwBytesPerSecond, " minRtt=", MinRttMicros, " fullBwRounds=", _fullBandwidthRounds, " lossPct=", (EstimatedLossPercent * 100d).ToString("F1"), " netClass=", CurrentNetworkClass)); // Log the ProbeRTT entry with full diagnostic context for offline analysis.
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
            if (sampleRttMicros > 0 && (MinRttMicros == 0 || sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER))) // A valid RTT sample exists AND it is within 1.25× of the current MinRtt (probe succeeded in finding the true base RTT).
            {
                MinRttMicros = sampleRttMicros; // Update min RTT if close enough.
            }

            _minRttTimestampMicros = nowMicros; // Reset the MinRtt timestamp to restart the ProbeRTT interval timer — delays the next probe cycle.
            TraceLog(string.Concat("ExitProbeRtt cwnd=", CongestionWindowBytes, " btlBw=", BtlBwBytesPerSecond, " minRtt=", MinRttMicros, " sampleRtt=", sampleRttMicros, " elapsedUs=", (nowMicros - _probeRttEnteredMicros))); // Log the ProbeRTT exit with diagnostic context including elapsed time.
            EnterProbeBw(nowMicros); // Transition back to ProbeBW steady-state cycling with the refreshed MinRtt estimate.
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
            long elapsedMicros = nowMicros - _probeRttEnteredMicros; // Compute how long we have been in ProbeRTT (microseconds since entry).
            long minDuration = _config.ProbeRttDurationMicros; // Get the configured minimum ProbeRTT duration (~200ms by default).

            // On non-congested paths, allow earlier exit.
            // No standing queue means the true base RTT is already visible.
            if (_networkCondition != NetworkCondition.Congested) // The path is not congested — RTT is likely already near the true propagation minimum.
            {
                minDuration = Math.Max(minDuration / 2, 30000L); // Halve the minimum ProbeRTT duration, but never below 30ms as an absolute safety floor.
            }

            // Haven't been in ProbeRTT long enough yet.
            if (elapsedMicros < minDuration) // The minimum required ProbeRTT duration has not yet elapsed — must wait longer.
            {
                return false; // Minimum duration not yet met.
            }

            // Exit condition 1: fresh sample close to current MinRtt.
            // The probe succeeded — we measured a true base RTT.
            bool hasFreshMinRttSample = sampleRttMicros > 0 && MinRttMicros > 0 && sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER); // A valid RTT sample was observed that is within 1.25× of the current MinRtt — the probe achieved its goal.

            // Exit condition 2: safety timeout (3× normal duration).
            // Prevents indefinite starvation on paths where the pipe
            // never drains (e.g. competing cross-traffic).
            bool exceededSafetyDuration = elapsedMicros >= _config.ProbeRttDurationMicros * UcpConstants.BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER; // ProbeRTT has been running for 3× the normal duration — safety timeout has fired.
            return hasFreshMinRttSample || exceededSafetyDuration; // Exit ProbeRTT if either the probe succeeded (good RTT sample observed) or the safety timeout expired (prevent indefinite starvation).
        }

        /// <summary>
        /// Calculates the pacing gain based on probe cycle phase, network condition,
        /// loss ratio, RTT increase, and network class.
        ///
        /// WHAT: Returns the pacing gain multiplier (0.50-1.35) based on a
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
        ///       - Reduces gain to 0.50-1.00 on congested links (back off)
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
            double lossRatio = GetRecentLossRatio(nowMicros); // Get the recent loss ratio (retransmits / sent) from the sliding bucket windows.
            double rttIncrease = GetAverageRttIncreaseRatio(); // Get how much the average RTT exceeds MinRtt: (avg - min) / min.

            // ---- Loss-control overrides ----
            // When loss exceeds the configured bandwidth loss budget (e.g. 5%)
            // AND the network condition is classified as congested, drop to
            // the high-loss pacing gain (0.70×) to relieve the bottleneck.
            if (_config.LossControlEnable && _networkCondition == NetworkCondition.Congested && EstimatedLossPercent > _maxBandwidthLossPercent) // Loss-control is active, path is congested, and loss has blown past the bandwidth loss budget.
            {
                return UcpConstants.BBR_HIGH_LOSS_PACING_GAIN; // Return the aggressive back-off pacing gain (0.70×) to relieve the congested bottleneck.
            }

            // ---- Fast recovery ----
            // After a non-congestion loss (e.g. random/corruption), pace at
            // elevated gain (1.15×) for one RTT to refill the pipe without
            // creating new loss.  This is NOT aggressive probing — just
            // ensuring throughput doesn't collapse due to head-of-line blocking.
            if (_fastRecoveryEnteredMicros > 0 && MinRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros < MinRttMicros) // Fast recovery is active and has not yet exceeded one RTT since entry.
            {
                return UcpConstants.BBR_FAST_RECOVERY_PACING_GAIN; // Return the elevated fast-recovery pacing gain (1.15×) to refill the loss hole.
            }

            // ---- Congested path ----
            // Pacing gain depends on whether loss is within budget.
            // Within budget → 1.00× (maintain, don't probe).
            // Over budget → 0.50× (aggressive drain to relieve queue).
            if (_networkCondition == NetworkCondition.Congested) // The network condition classifier confirms the path is currently congested.
            {
                if (EstimatedLossPercent <= _maxBandwidthLossPercent) // Loss is still within the tolerable bandwidth loss budget — no need for aggressive back-off.
                {
                    return 1d; // Pace at exactly the bottleneck rate — maintain current throughput without probing higher.
                }

                return UcpConstants.BBR_PROBE_RTT_PACING_GAIN; // Loss exceeds the budget — return the ProbeRTT low gain (0.50×) to aggressively drain the bottleneck queue.
            }

            // ---- Mobile/Unstable paths ----
            // Mobile links (LTE/5G) suffer from link-layer retransmissions and
            // scheduling jitter that look like congestion but aren't.  Maintain
            // higher gain when RTT is stable; reduce gradually as RTT inflates
            // (which is a genuine congestion signal even on mobile).
            if (CurrentNetworkClass == NetworkClass.MobileUnstable) // The path is classified as mobile/unstable (high jitter, burst loss, LTE/5G/WiFi).
            {
                // RTT barely above MinRtt → path is clean; probe aggressively.
                if (rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO) // RTT is stable (barely above MinRtt) — the jitter is link-layer noise, not queuing.
                {
                    return _config.ProbeBwHighGain; // 1.35x when RTT is stable.
                }

                // Moderate RTT inflation → still probe but less aggressively.
                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO) // RTT is moderately elevated — possible early congestion signal even on mobile.
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
            if (CurrentNetworkClass == NetworkClass.LossyLongFat) // The path is classified as lossy long-fat (satellite, long-haul undersea cable with steady background loss).
            {
                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO) // RTT is relatively stable — the background loss is from physical noise, not queuing.
                {
                    return UcpConstants.BBR_MODERATE_PROBE_GAIN; // Return the moderate probe gain (1.10×) to compensate for steady background throughput loss.
                }

                return 1d; // RTT is rising significantly — this is genuine congestion; pace at 1.00× to avoid making it worse.
            }

            // ---- Random loss (non-congestion, stable RTT) ----
            // Loss exists but RTT is flat → noise/corruption, not congestion.
            // Maintain elevated gain unless RTT starts rising.
            if (_networkCondition == NetworkCondition.RandomLoss) // Loss is present but the condition classifier says it's random (RTT was stable when loss appeared).
            {
                if (rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO) // RTT is completely stable — the path can handle the current rate despite the random loss.
                {
                    return Math.Max(1d, _config.ProbeBwHighGain); // Return at minimum 1.00×, ideally the full high probe gain (1.35×) since the loss is not from congestion.
                }

                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO) // RTT is moderately rising — possible onset of congestion on top of the existing random loss.
                {
                    return Math.Max(1d, UcpConstants.BBR_MODERATE_PROBE_GAIN); // Return at minimum 1.00×, with a moderate probe gain (1.10×) for cautious recovery.
                }

                return 1d; // RTT is rising significantly — treat as genuine congestion; pace conservatively at 1.00×.
            }

            // ---- Low-latency LAN ----
            // Fast, clean paths with negligible queuing.  Always use high gain
            // because there is no risk of bufferbloat — the BDP is tiny.
            if (CurrentNetworkClass == NetworkClass.LowLatencyLAN) // The path is a low-latency LAN (sub-5ms RTT, minimal jitter, negligible loss).
            {
                return _config.ProbeBwHighGain; // Always use the aggressive high probe gain (1.35×) — zero queuing risk on a LAN.
            }

            // ---- Default/generic path: tiered by loss and RTT ----
            // Escalating probe caution based on combined loss + RTT signals.
            // This covers Default, SymmetricVPN, and CongestedBottleneck classes
            // that haven't been caught by the specific classifiers above.

            // Low loss + stable RTT → aggressive probing is safe.
            if (lossRatio < UcpConstants.BBR_LOW_LOSS_RATIO && rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO) // Both loss and RTT increase are low — the path is healthy and can tolerate aggressive probing.
            {
                return Math.Max(1d, _config.ProbeBwHighGain); // Return at minimum 1.00×, ideally the full high probe gain (1.35×) for aggressive bandwidth discovery.
            }

            // Moderate loss and RTT → moderate probe gain.
            if (lossRatio < UcpConstants.BBR_MODERATE_LOSS_RATIO && rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO) // Both loss and RTT are moderate — cautious probing is appropriate.
            {
                return Math.Max(1d, UcpConstants.BBR_MODERATE_PROBE_GAIN); // Return at minimum 1.00×, with a moderate probe gain (1.10×) for balanced bandwidth probing.
            }

            // Light loss only → near-1.00× with slight upward bias.
            if (lossRatio < UcpConstants.BBR_LIGHT_LOSS_RATIO) // Loss is light (below the light-loss threshold) — a slight upward bias is still safe.
            {
                return Math.Max(1d, UcpConstants.BBR_LIGHT_LOSS_PACING_GAIN); // Return at minimum 1.00×, with a slight upward bias for light-loss conditions.
            }

            // Medium loss → modest back-off.
            if (lossRatio < UcpConstants.BBR_MEDIUM_LOSS_RATIO) // Loss is at a medium level — dial back probing modestly to avoid compounding the loss.
            {
                return Math.Max(1d, UcpConstants.BBR_MEDIUM_LOSS_PACING_GAIN); // Return at minimum 1.00×, with a modest back-off for medium loss conditions.
            }

            // High loss → strong back-off.
            return Math.Max(1d, UcpConstants.BBR_HIGH_LOSS_PACING_GAIN); // Loss is high — use the strong back-off pacing gain (0.70×) to relieve the path.
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
            UpdateEstimatedLossPercent(nowMicros, CalculateLossPercent(nowMicros)); // Delegate to the two-parameter EWMA update with a freshly computed loss percentage.
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
            double boundedCandidate = Math.Max(0d, Math.Min(100d, candidateLossPercent)); // Clamp the candidate loss percentage to the valid range [0, 100] to prevent nonsensical values.
            if (boundedCandidate <= 0d && GetRecentLossRatio(nowMicros) <= 0d) // No current loss candidate and no recent loss in the sliding window — the loss event has fully passed.
            {
                EstimatedLossPercent *= UcpConstants.BBR_LOSS_EWMA_IDLE_DECAY; // Idle decay.
                return; // Exit early — there is no new loss signal to incorporate into the EWMA.
            }

            if (EstimatedLossPercent <= 0d) // This is the first time we are setting the EWMA loss estimate (or it has fully decayed to zero).
            {
                EstimatedLossPercent = boundedCandidate; // First estimate: set directly.
                return; // Exit early — no previous value exists for EWMA blending.
            }

            // EWMA: 75% retained + 25% new sample.
            EstimatedLossPercent = (EstimatedLossPercent * UcpConstants.BBR_LOSS_EWMA_RETAINED_WEIGHT) + (boundedCandidate * UcpConstants.BBR_LOSS_EWMA_SAMPLE_WEIGHT); // Blend the new sample (25% weight) with the previous estimate (75% weight) for a smooth, responsive estimate.
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
            double targetRate = BtlBwBytesPerSecond > 0 ? BtlBwBytesPerSecond : _config.InitialBandwidthBytesPerSecond; // Determine the target delivery rate: current BtlBw if valid, otherwise the configured initial bandwidth.
            if (targetRate <= 0) // No valid target rate is available — cannot compute a meaningful loss percentage.
            {
                return 0d; // Return zero — there is no basis for computing a loss percentage.
            }

            double retransmissionLoss = GetRecentLossRatio(nowMicros); // Get the recent retransmission-based loss ratio from the sliding bucket windows.

            // Only consider rate shortfall when congestion is confirmed.
            // Outside of congestion, a low delivery rate just means the
            // sender had nothing to send (application-limited), not that
            // the path is saturated.
            if (_networkCondition != NetworkCondition.Congested || _deliveryRateBytesPerSecond <= 0 || Mode == BbrMode.Startup) // Path is not congested, no recent delivery rate, or still in Startup — rate shortfall is not a congestion signal.
            {
                return retransmissionLoss * 100d; // Return the straightforward retransmission-based loss percentage (ratio × 100).
            }

            // When congested, also consider delivery-rate shortfall.
            // actualRate / targetRate gives utilization (0.0-1.0).
            // 1 - utilization = shortfall fraction.
            double actualRate = _deliveryRateBytesPerSecond; // Snapshot the most recent delivery rate for the shortfall calculation.
            double lossFromRate = Math.Max(0d, 1d - (actualRate / targetRate)); // Compute the rate shortfall fraction: how far below target the actual delivery is (1.0 - utilization).
            double rateLossHint = Math.Min(lossFromRate, retransmissionLoss + UcpConstants.BBR_RATE_LOSS_HINT_MAX_RATIO); // Cap the rate-based loss hint: it can be at most the retransmission ratio plus a configurable margin, to prevent over-stating loss from application-limited gaps.
            return Math.Max(rateLossHint, retransmissionLoss) * 100d; // Return the higher of the two loss signals (rate shortfall or retransmission), converted to a percentage.
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
            if (_deliveryRateHistoryCount < 2) // Less than 2 delivery-rate samples in the trend buffer — cannot compute a meaningful rate change.
            {
                return NetworkCondition.Idle; // Not enough data.
            }

            // Compute delivery-rate trend: oldest vs newest sample.
            // A declining rate suggests the bottleneck is saturated.
            int newestIndex = (_deliveryRateHistoryIndex + _deliveryRateHistory.Length - 1) % _deliveryRateHistory.Length; // Compute the circular buffer index of the newest (most recently written) sample.
            int oldestIndex = (_deliveryRateHistoryIndex + _deliveryRateHistory.Length - _deliveryRateHistoryCount) % _deliveryRateHistory.Length; // Compute the circular buffer index of the oldest (first valid) sample.
            double oldestRate = _deliveryRateHistory[oldestIndex]; // Retrieve the oldest delivery rate sample for the trend baseline.
            double newestRate = _deliveryRateHistory[newestIndex]; // Retrieve the newest delivery rate sample for the trend endpoint.
            double deliveryRateChange = oldestRate <= 0 ? 0d : (newestRate - oldestRate) / oldestRate; // Compute the relative delivery-rate change: positive means increasing throughput, negative means declining (congestion signal).
            double lossRatio = GetRecentLossRatio(nowMicros); // Get the recent packet loss ratio for the scoring rules.
            double rttIncrease = GetAverageRttIncreaseRatio(); // Get the RTT increase ratio (avg - min) / min for the scoring rules.
            int congestionScore = 0; // Initialize the cumulative congestion score — starts at zero, each rule adds points.

            // ---- Tier 1: Delivery-rate drop + RTT rise ----
            // The strongest congestion signal.  When the bottleneck queue is
            // building, delivery rate flattens or drops while RTT rises.
            if (deliveryRateChange <= UcpConstants.BBR_CONGESTION_RATE_DROP_RATIO && rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO) // Delivery rate is declining AND RTT is rising — the strongest combined congestion signal.
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RATE_DROP_SCORE; // Add the highest-weight score (typically +2) for the rate-drop + RTT-rise combination.
            }

            // ---- Tier 2: RTT growth alone ----
            // RTT rising is an early-warning signal.  Even before loss appears,
            // growing queues indicate impending congestion.
            if (rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO) // RTT has risen above the congestion threshold — queues are building at the bottleneck.
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RTT_GROWTH_SCORE; // Add the RTT-growth score (typically +1) for early-warning queue buildup detection.
            }

            // ---- Tier 3: Loss ratio + RTT rise ----
            // Loss is only treated as congestion evidence when accompanied by
            // RTT rise.  Loss with flat RTT is random/corruption.
            if (lossRatio >= UcpConstants.BBR_CONGESTION_LOSS_RATIO && rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO) // Loss ratio exceeds the threshold AND RTT is rising — loss confirms the congestion signal.
            {
                congestionScore += UcpConstants.BBR_CONGESTION_LOSS_SCORE; // Add the loss-confirmed score (typically +1) — loss is corroborating evidence for congestion.
            }

            // Score ≥ threshold → congestion confirmed.
            if (congestionScore >= UcpConstants.BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD) // The cumulative congestion score meets or exceeds the classifier threshold (typically 4).
            {
                return NetworkCondition.Congested; // Congestion confirmed — apply multiplicative CWND reduction and conservative pacing.
            }

            // Loss present but RTT is flat → random/corruption loss.
            // The path can handle the current rate; loss is not from queuing.
            if (lossRatio > 0 && rttIncrease <= UcpConstants.BBR_RANDOM_LOSS_MAX_RTT_INCREASE_RATIO) // Loss exists but RTT is flat (not rising) — this is random/corruption loss, not queuing.
            {
                return NetworkCondition.RandomLoss; // Classify as random loss — use fast recovery (elevated pacing) without CWND reduction.
            }

            // Negligible loss → light load.
            if (lossRatio < UcpConstants.BBR_LOW_LOSS_RATIO) // Loss ratio is below the low-loss threshold — the path is essentially clean.
            {
                return NetworkCondition.LightLoad; // Classify as light load — aggressive probing is safe on a lightly loaded path.
            }

            // Default: not enough signal to classify.
            return NetworkCondition.Idle; // Insufficient data or ambiguous signals — return Idle as the safe default (no action taken).
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
            if (!isCongestionSignal) // External source explicitly flags this as non-congestion — trust the signal and skip all further classification.
            {
                return false; // Treat as non-congestion loss (random) — fast recovery only, no CWND reduction.
            }

            // Classifier confirms congestion → immediate reduction.
            if (_networkCondition == NetworkCondition.Congested) // The internal three-tier classifier independently confirms the path is congested — both signals align.
            {
                return true; // Treat as congestion — both external (RTO/NAK) and internal (classifier) signals agree on congestion.
            }

            // Classifier is uncertain, but the loss event says congestion.
            // Require BOTH elevated RTT AND elevated loss to confirm.
            // Either alone is too weak for a multiplicative reduction.
            double rttIncrease = GetAverageRttIncreaseRatio(); // Get the average RTT increase ratio for cross-verification with the external signal.
            double lossRatio = GetRecentLossRatio(nowMicros); // Get the recent loss ratio for cross-verification with the external signal.
            return rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO && lossRatio >= UcpConstants.BBR_CONGESTION_LOSS_RATIO; // Both RTT AND loss must be elevated to confirm congestion; either alone is insufficient for multiplicative reduction.
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
            // More robust than raw MinRtt against single lucky fast samples,
            // and provides sufficient retransmission headroom on jittery paths.
            // The hard CWND ceiling (using MinRtt directly) prevents bufferbloat.
            long p10Rtt = GetP10RttMicros(); // Compute the 10th-percentile RTT from the history buffer (robust to occasional fast samples).
            long modelRttMicros = p10Rtt > 0 ? Math.Max(MinRttMicros, p10Rtt) : MinRttMicros; // Use max(MinRtt, P10-RTT) as the model RTT; fall back to raw MinRtt if P10 is not yet available (fewer than 4 samples).
            if (modelRttMicros <= 0) // No valid model RTT could be determined — no RTT samples have been collected yet.
            {
                return 0; // Return zero to signal that CWND computation cannot proceed — use initial CWND instead.
            }

            return modelRttMicros; // Return the model RTT (robust, percentile-based) for BDP calculation in GetTargetCwndBytes.
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
            if (_rttHistoryCount == 0 || MinRttMicros <= 0) // No RTT history samples OR MinRtt has never been set — cannot compute the ratio.
            {
                return 0d; // Return zero — no RTT increase data is available.
            }

            long total = 0; // Initialize the running sum accumulator for the arithmetic mean.
            for (int i = 0; i < _rttHistoryCount; i++) // Iterate through all valid RTT samples in the history buffer.
            {
                total += _rttHistoryMicros[i]; // Accumulate each RTT sample into the running sum.
            }

            double averageRtt = total / (double)_rttHistoryCount; // Compute the simple arithmetic mean of all RTT samples: sum / count.
            return Math.Max(0d, (averageRtt - MinRttMicros) / MinRttMicros); // Return the relative increase ratio: (avg - min) / min, clamped to prevent negative values (avg should never be below min due to the sticky floor).
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
            return GetPercentileRtt(0.10d); // Delegate to the generic percentile function with the 10th percentile (P10).
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
            return GetPercentileRtt(0.25d); // Delegate to the generic percentile function with the 25th percentile (P25).
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
        ///       RTT spikes that can be 2-10× the base RTT.  These are not
        ///       congestion signals — they are link-layer artifacts.  Using
        ///       a higher percentile prevents CWND starvation.
        /// </summary>
        private long GetP30RttMicros()
        {
            return GetPercentileRtt(0.30d); // Delegate to the generic percentile function with the 30th percentile (P30).
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
            if (_rttHistoryCount < 4) // Fewer than 4 RTT samples — percentile computation is unreliable with too few data points.
            {
                return MinRttMicros; // Not enough samples, fall back to min.
            }

            // Copy valid entries to a temporary array for sorting.
            long[] sorted = new long[_rttHistoryCount]; // Allocate a temporary array sized exactly to the number of valid samples.
            Array.Copy(_rttHistoryMicros, sorted, _rttHistoryCount); // Copy the valid portion of the circular buffer into the contiguous temporary array.
            Array.Sort(sorted); // Sort the temporary array in ascending order — the lowest values come first, highest last.

            // Return approximately the requested percentile.
            int index = Math.Max(0, Math.Min(_rttHistoryCount - 1, (int)(_rttHistoryCount * percentile))); // Compute the index: count × percentile fraction, clamped to the valid range [0, count-1].
            return sorted[index]; // Return the RTT value at the computed percentile position in the sorted array.
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
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0) // Missing critical estimates — BDP cannot be computed for guardrail derivation.
            {
                _inflightHighBytes = 0; // Reset the upper guardrail to zero (meaning no ceiling is applied during clamping).
                _inflightLowBytes = 0; // Reset the lower guardrail to zero (meaning no floor is applied during clamping).
                return; // Exit early — guardrails cannot be established without valid BtlBw and MinRtt.
            }

            double bdpBytes = BtlBwBytesPerSecond * (MinRttMicros / (double)UcpConstants.MICROS_PER_SECOND); // Compute the bandwidth-delay product in bytes using raw MinRtt for guardrail simplicity.

            // Lower guardrail: at minimum the initial CWND, otherwise a
            // fraction of BDP.  Prevents CWND starvation on low-BDP paths.
            _inflightLowBytes = Math.Max(_config.InitialCongestionWindowBytes, bdpBytes * UcpConstants.BBR_INFLIGHT_LOW_GAIN); // Set the lower bound: the higher of the configured initial CWND or a small fraction of BDP.

            // Upper guardrail: mobile/lossy paths get higher headroom because
            // their loss is often non-congestion and retransmissions need
            // extra inflight capacity.
            double highGain = (_networkCondition != NetworkCondition.Congested
                                && (CurrentNetworkClass == NetworkClass.MobileUnstable
                                    || CurrentNetworkClass == NetworkClass.LossyLongFat))
                ? UcpConstants.BBR_INFLIGHT_MOBILE_HIGH_GAIN // Non-congested mobile/lossy path — allow more inflight headroom for non-congestion retransmissions.
                : UcpConstants.BBR_INFLIGHT_HIGH_GAIN; // All other path types — use the standard (conservative) inflight high gain.
            _inflightHighBytes = Math.Max(_inflightLowBytes, bdpBytes * highGain); // Set the upper bound: the higher of the lower guardrail or BDP multiplied by the path-class-appropriate high gain.
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
            AdvanceLossBuckets(nowMicros); // Age out expired loss buckets before computing the ratio to ensure data freshness.

            long sent = 0; // Initialize the total-sent accumulator to zero.
            long retransmits = 0; // Initialize the total-retransmit accumulator to zero.
            for (int i = 0; i < UcpConstants.BBR_LOSS_BUCKET_COUNT; i++) // Iterate through all buckets in the sliding window.
            {
                sent += _sentBuckets[i]; // Accumulate the sent-packet count from this bucket into the running total.
                retransmits += _retransmitBuckets[i]; // Accumulate the retransmit count from this bucket into the running total.
            }

            return sent == 0 ? 0d : retransmits / (double)sent; // Compute the loss ratio: retransmits / total-sent; return zero if no packets were sent to avoid divide-by-zero.
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
            if (nowMicros <= 0) // Timestamp is invalid (zero or negative) — use the current real time as a fallback.
            {
                nowMicros = UcpTime.NowMicroseconds(); // Get the current high-resolution timestamp to ensure correct bucket slot alignment.
            }

            // Align to bucket boundaries for consistent slotting.
            long alignedNow = nowMicros - (nowMicros % UcpConstants.BBR_LOSS_BUCKET_MICROS); // Round down the timestamp to the nearest bucket boundary for deterministic time-slot allocation.
            if (_lossBucketStartMicros == 0 || nowMicros < _lossBucketStartMicros) // First call ever (no window started) OR clock went backwards (system time adjustment).
            {
                // First call or clock reset: clear all buckets.
                Array.Clear(_sentBuckets, 0, _sentBuckets.Length); // Zero out all sent-packet bucket counters to start fresh.
                Array.Clear(_retransmitBuckets, 0, _retransmitBuckets.Length); // Zero out all retransmit bucket counters to start fresh.
                _lossBucketIndex = 0; // Reset the ring buffer write position to the first bucket.
                _lossBucketStartMicros = alignedNow; // Set the window start time to the current aligned timestamp.
                return; // Done — all buckets are cleared and a new window begins now.
            }

            long steps = (nowMicros - _lossBucketStartMicros) / UcpConstants.BBR_LOSS_BUCKET_MICROS; // Calculate how many full bucket durations have elapsed since the window start.
            if (steps <= 0) // No full bucket boundaries have been crossed — nothing to advance.
            {
                return; // No advancement needed.
            }

            if (steps >= UcpConstants.BBR_LOSS_BUCKET_COUNT) // The elapsed time exceeds the total window span — all buckets are stale.
            {
                // Large time jump: clear all buckets.
                Array.Clear(_sentBuckets, 0, _sentBuckets.Length); // Clear all sent counters since the entire window is now expired.
                Array.Clear(_retransmitBuckets, 0, _retransmitBuckets.Length); // Clear all retransmit counters since the entire window is now expired.
                _lossBucketIndex = 0; // Reset the ring buffer write position to the first bucket.
                _lossBucketStartMicros = alignedNow; // Reset the window start to the current aligned timestamp.
                return; // Done — all stale data is discarded, new window starts now.
            }

            // Advance by clearing intermediate buckets.
            for (long i = 0; i < steps; i++) // Iterate through each elapsed bucket step to clear the now-expired time slots.
            {
                _lossBucketIndex = (_lossBucketIndex + 1) % UcpConstants.BBR_LOSS_BUCKET_COUNT; // Advance the ring buffer index to the next slot (wrapping around at the buffer end).
                _sentBuckets[_lossBucketIndex] = 0; // Clear the sent counter at the new (now-active) slot — old data must not carry over.
                _retransmitBuckets[_lossBucketIndex] = 0; // Clear the retransmit counter at the new (now-active) slot — old data must not carry over.
            }

            _lossBucketStartMicros += steps * UcpConstants.BBR_LOSS_BUCKET_MICROS; // Advance the window start time by exactly the number of buckets that were cleared.
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
                || CurrentNetworkClass == NetworkClass.LossyLongFat) // Path is mobile or lossy-fat — these need extra CWND for non-congestion retransmission headroom.
            {
                return CwndGain; // Return the CWND gain unchanged (no waste-budget cap) to maintain retransmission headroom.
            }

            // Startup needs high CWND for rapid bandwidth discovery.
            // The waste-budget cap would prevent the ramp-up.
            if (Mode == BbrMode.Startup) // We are in Startup mode — the waste budget would artificially limit bandwidth discovery.
            {
                return CwndGain; // Return the CWND gain unchanged (no waste-budget cap) to allow exponential Startup ramp-up.
            }

            // Waste budget: how much extra inflight (beyond BDP) we tolerate.
            // e.g. 0.50 means we allow up to 1.50× BDP total inflight.
            double wasteBudget = Math.Max(0.50d, _config.MaxBandwidthWastePercent); // Determine the waste budget: use configured value, but never below 0.50 (50%) to maintain some headroom.
            double maxWasteGain = 1d + wasteBudget; // Compute the total permissible inflight multiplier: 1.0 (base BDP) + wasteBudget.
            double limit = maxWasteGain * _config.ProbeBwCwndGain; // Compute the absolute gain ceiling: waste-budget cap multiplied by the base ProbeBW CWND gain.
            if (PacingGain <= 0 || PacingGain * CwndGain <= limit) // Pacing gain is invalid (can't compute) OR the total inflight is already within the waste budget.
            {
                return CwndGain; // No cap needed — the total inflight (CwndGain × PacingGain) is within the waste budget.
            }

            // Cap CwndGain so that total inflight multiplier ≤ wasteBudget + 1.
            return Math.Max(1d, limit / PacingGain); // Derive a capped CWND gain: limit / pacing gain, floored at 1.0 so CWND never drops below BDP.
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
            if (_config.EnableDebugLog) // Debug logging is enabled in the configuration — the message passes the gate.
            {
                Trace.WriteLine("[UCP BBR] " + message); // Emit the message to the System.Diagnostics.Trace output with a recognizable prefix for filtering.
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
            if (_classifierWindowStartMicros == 0) // This is the first classifier window — initialize the start timestamp.
            {
                _classifierWindowStartMicros = nowMicros; // Set the window start to the current timestamp for duration tracking.
            }

            _classifierWindowSentBytes += Math.Max(0, sentOrAckedBytes); // Accumulate sent/acked bytes into the current window (clamp negative values to zero for safety).
            if (sampleRttMicros > 0) // A valid RTT sample was provided with this call — update the RTT statistics.
            {
                _classifierWindowRttSumMicros += sampleRttMicros; // Add this RTT sample to the running sum for average computation.
                _classifierWindowRttCount++; // Increment the sample count for the denominator of the average.
                if (_classifierWindowMinRttMicros == 0 || sampleRttMicros < _classifierWindowMinRttMicros) // First RTT sample in this window OR a new minimum was observed.
                {
                    _classifierWindowMinRttMicros = sampleRttMicros; // Update the window's minimum RTT with this lower value.
                }

                if (sampleRttMicros > _classifierWindowMaxRttMicros) // This RTT sample exceeds the current window maximum.
                {
                    _classifierWindowMaxRttMicros = sampleRttMicros; // Update the window's maximum RTT with this higher value.
                }
            }

            if (nowMicros - _classifierWindowStartMicros >= UcpConstants.NETWORK_CLASSIFIER_WINDOW_DURATION_MICROS) // The classifier window duration has elapsed — finalize and store this window.
            {
                // Finalize the current window.
                ref ClassifierWindow window = ref _classifierWindows[_classifierWindowIndex]; // Get a reference to the current slot in the classifier window circular buffer.
                window.AvgRttMicros = _classifierWindowRttCount > 0 ? _classifierWindowRttSumMicros / (double)_classifierWindowRttCount : 0d; // Compute the average RTT: sum / count, or zero if no samples were collected.
                window.JitterMicros = _classifierWindowMinRttMicros > 0 && _classifierWindowMaxRttMicros > 0 ? (_classifierWindowMaxRttMicros - _classifierWindowMinRttMicros) : 0d; // Compute the RTT jitter: max - min, or zero if either value is missing.
                window.LossRate = lossRateSnapshot; // Store the current loss rate snapshot in this classifier window.
                // Convert the microsecond window to bytes/second before comparing
                // against BtlBw; otherwise high-bandwidth paths look artificially idle.
                double windowBytesPerSecond = _classifierWindowSentBytes * UcpConstants.MICROS_PER_SECOND / (double)Math.Max(1, nowMicros - _classifierWindowStartMicros); // Compute the throughput in bytes/sec over the classifier window duration.
                window.ThroughputRatio = BtlBwBytesPerSecond > 0 ? Math.Min(1d, windowBytesPerSecond / BtlBwBytesPerSecond) : 0d; // Compute the throughput ratio: actual / BtlBw, capped at 1.0 so utilization can never exceed 100%.
                _classifierWindowIndex = (_classifierWindowIndex + 1) % UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT; // Advance the circular buffer write position by one (wrapping around at the end).
                if (_classifierWindowCount < UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT) // The buffer has not yet filled up — increase the valid window count.
                {
                    _classifierWindowCount++; // Increment the count of finalized classifier windows available for path classification.
                }

                // Reset accumulators for the next window.
                _classifierWindowStartMicros = nowMicros; // Start a new classifier window at the current timestamp.
                _classifierWindowSentBytes = 0; // Reset sent bytes counter for the new window.
                _classifierWindowMinRttMicros = 0; // Reset min RTT tracker for the new window.
                _classifierWindowMaxRttMicros = 0; // Reset max RTT tracker for the new window.
                _classifierWindowRttSumMicros = 0; // Reset RTT sum accumulator for the new window.
                _classifierWindowRttCount = 0; // Reset RTT sample counter for the new window.
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
            if (_classifierWindowCount < 2) // Fewer than 2 finalized classifier windows — not enough data for reliable classification.
            {
                return NetworkClass.Default; // Not enough data yet.
            }

            // Average all windows.
            double avgRtt = 0d; // Initialize the running average RTT accumulator.
            double avgLoss = 0d; // Initialize the running average loss accumulator.
            double avgJitter = 0d; // Initialize the running average jitter accumulator.
            double minThroughput = 1d; // Initialize the minimum throughput tracker (start high, reduce when lower values are found).
            for (int i = 0; i < _classifierWindowCount; i++) // Iterate through all finalized classifier windows.
            {
                avgRtt += _classifierWindows[i].AvgRttMicros; // Accumulate this window's average RTT into the running sum.
                avgLoss += _classifierWindows[i].LossRate; // Accumulate this window's loss rate into the running sum.
                avgJitter += _classifierWindows[i].JitterMicros; // Accumulate this window's jitter into the running sum.
                if (_classifierWindows[i].ThroughputRatio > 0 && _classifierWindows[i].ThroughputRatio < minThroughput) // This window has a valid throughput ratio that is lower than the current minimum.
                {
                    minThroughput = _classifierWindows[i].ThroughputRatio; // Update the minimum throughput tracker to this lower value.
                }
            }

            avgRtt /= _classifierWindowCount; // Compute the arithmetic mean RTT across all windows.
            avgLoss /= _classifierWindowCount; // Compute the arithmetic mean loss rate across all windows.
            avgJitter /= _classifierWindowCount; // Compute the arithmetic mean jitter across all windows.

            double avgRttMs = avgRtt / UcpConstants.MICROS_PER_MILLI; // Convert the average RTT from microseconds to milliseconds for readable threshold comparison.
            double avgJitterMs = avgJitter / UcpConstants.MICROS_PER_MILLI; // Convert the average jitter from microseconds to milliseconds for readable threshold comparison.

            // Rule 1: Low-latency LAN
            // Sub-5ms RTT, negligible loss (&lt;0.1%), low jitter (&lt;2ms).
            // These paths have essentially zero queuing delay; the BDP is
            // tiny so aggressive probing causes no harm.
            if (avgRttMs < UcpConstants.NETWORK_CLASSIFIER_LAN_RTT_MS && avgLoss < 0.001d && avgJitterMs < UcpConstants.NETWORK_CLASSIFIER_LAN_JITTER_MS) // RTT < 5ms, loss < 0.1%, jitter < 2ms — this is a classic LAN.
            {
                return NetworkClass.LowLatencyLAN; // Classify as low-latency LAN — use aggressive pacing (1.35×) on this clean high-speed path.
            }

            // Rule 2: Mobile/Unstable
            // High loss ratio AND high jitter together is the signature of
            // a wireless link (LTE/5G/WiFi).  Radio-layer retransmissions
            // and scheduling create burst loss + jitter spikes.
            if (avgLoss > UcpConstants.NETWORK_CLASSIFIER_MOBILE_LOSS_RATE && avgJitterMs > UcpConstants.NETWORK_CLASSIFIER_MOBILE_JITTER_MS) // Loss rate exceeds the mobile threshold AND jitter exceeds the mobile threshold — this is a wireless/mobile path.
            {
                return NetworkClass.MobileUnstable; // Classify as mobile/unstable — use extended high-gain cycles and fast recovery for non-congestion radio loss.
            }

            // Rule 3: Lossy Long-Fat
            // High RTT (e.g. &gt;200ms satellite) combined with steady loss
            // &gt;1%.  The loss is typically from physical-layer noise on
            // long-haul links, not congestion.
            if (avgRttMs > UcpConstants.NETWORK_CLASSIFIER_LONG_FAT_RTT_MS && avgLoss > 0.01d) // RTT exceeds the long-fat threshold AND loss is above 1% — this is a satellite/long-haul path.
            {
                return NetworkClass.LossyLongFat; // Classify as lossy long-fat — use RTT-trend-based gain decisions and higher inflight guardrails.
            }

            // Rule 4: Congested Bottleneck
            // Throughput is significantly below BtlBw (&lt;70%) AND RTT is
            // growing (latest window's RTT &gt; 110% of average).  Both
            // together suggest a bottleneck queue is building.
            // Note: comparing _classifierWindows[0].AvgRttMicros against
            // the overall avgRtt checks for a rising RTT trend.
            if (minThroughput < 0.7d && avgRttMs > _classifierWindows[0].AvgRttMicros / UcpConstants.MICROS_PER_MILLI * 1.1d) // Throughput is below 70% of BtlBw AND the latest window's RTT exceeds 110% of the average (RTT is rising).
            {
                return NetworkClass.CongestedBottleneck; // Classify as congested bottleneck — use conservative pacing gains and tight CWND limits.
            }

            // Rule 5: Symmetric VPN
            // Moderate-to-high RTT (&gt;60ms) with relatively stable patterns.
            // VPN tunnels add ~30-60ms of overhead; the path is symmetric
            // (both directions traverse the same tunnel).  CWND should be
            // capped conservatively to avoid tunnel buffer stuffing.
            if (avgRttMs > 60d) // Average RTT exceeds 60ms — this is likely a VPN tunnel or long-distance routed path.
            {
                return NetworkClass.SymmetricVPN; // Classify as symmetric VPN — cap CWND conservatively to avoid tunnel bufferbloat.
            }

            // Rule 6: Default
            // None of the above patterns matched.  Use generic pacing and
            // CWND policies — conservative but not overly so.
            return NetworkClass.Default; // No specific pattern matched — return the generic default classification.
        }
    }
}
