using System;
using System.Diagnostics;

namespace Ucp
{
    /// <summary>
    /// BBRv1 congestion control engine implementing core state transitions,
    /// rate estimation, window computation, and loss classification.
    ///
    /// States: Startup → Drain → ProbeBW ↔ ProbeRTT
    ///
    /// Key estimates:
    /// - BtlBw (bottleneck bandwidth): max delivery rate over recent RTT window
    /// - MinRtt (minimum RTT): floor of observed RTT samples
    /// - PacingRate = BtlBw × PacingGain
    /// - CongestionWindow = BDP × CwndGain, bounded by inflight guardrails
    ///
    /// The loss classifier distinguishes random loss (no pacing/cwnd reduction)
    /// from congestion loss (multiplicative reduction). A separate network
    /// classifier categorizes the path into: LowLatencyLAN, MobileUnstable,
    /// LossyLongFat, CongestedBottleneck, SymmetricVPN, or Default.
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

        /// <summary>Number of loss events since the last ProbeRTT phase.</summary>
        private int _lossEventsSinceLastProbeRtt;

        /// <summary>Timestamp of the most recent packet loss, in microseconds.</summary>
        private long _lastLossMicros;

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

        // ---- Network condition classification ----

        /// <summary>Current network condition classification.</summary>
        private NetworkCondition _networkCondition;

        /// <summary>Count of consecutive losses treated as non-congestion (random loss).</summary>
        private int _consecutiveNonCongestionLosses;

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
        /// </summary>
        public BbrCongestionControl()
            : this(new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a BBR congestion controller initialized from the given configuration.
        /// Enters Startup mode with initial pacing and CWND gains.
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
            bool minRttExpired = MinRttMicros > 0 && nowMicros - _minRttTimestampMicros >= _config.ProbeRttIntervalMicros;
            if (sampleRttMicros > 0)
            {
                _currentRttMicros = sampleRttMicros;
                if (MinRttMicros == 0 || sampleRttMicros < MinRttMicros)
                {
                    MinRttMicros = sampleRttMicros;
                    _minRttTimestampMicros = nowMicros;
                    minRttExpired = false; // Resets the expiry clock.
                }
            }

            // Calculate the interval since the last ACK for delivery-rate estimation.
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

            if (deliveredBytes > 0)
            {
                _totalDeliveredBytes += deliveredBytes;
                _consecutiveNonCongestionLosses = 0;
                double deliveryRate = deliveredBytes * UcpConstants.MICROS_PER_SECOND / (double)intervalMicros;
                if (PacingRateBytesPerSecond > 0)
                {
                    // Cap the delivery rate to prevent ACK aggregation from inflating estimates.
                    double aggregationCapGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_ACK_AGGREGATION_RATE_CAP_GAIN : UcpConstants.BBR_STEADY_ACK_AGGREGATION_RATE_CAP_GAIN;
                    deliveryRate = Math.Min(deliveryRate, PacingRateBytesPerSecond * aggregationCapGain);
                }

                _deliveryRateBytesPerSecond = deliveryRate;
                AddRateSample(deliveryRate, nowMicros);
                AddDeliveryRateSample(deliveryRate);
                if (_lossCwndGain < 1d && Mode != BbrMode.ProbeRtt)
                {
                    // Gradually recover CWND gain after loss reduction.
                    _lossCwndGain = Math.Min(1d, _lossCwndGain + UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP);
                }
            }

            if (sampleRttMicros > 0)
            {
                AddRttSample(sampleRttMicros);
            }

            // Update the network path classifier.
            AdvanceClassifierWindow(nowMicros, deliveredBytes + flightBytes, sampleRttMicros, GetRecentLossRatio(nowMicros));
            CurrentNetworkClass = ClassifyNetworkPath();

            _networkCondition = ClassifyNetworkCondition(nowMicros);
            UpdateEstimatedLossPercent(nowMicros);
            UpdateInflightBounds();

            if (minRttExpired && Mode != BbrMode.ProbeRtt)
            {
                bool bandwidthGrowthStalled = _fullBandwidthRounds >= UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER;
                bool isLossyFat = CurrentNetworkClass == NetworkClass.LossyLongFat;
                if (bandwidthGrowthStalled || !isLossyFat)
                {
                    EnterProbeRtt(nowMicros);
                }
            }

            // Determine if a new BBR round has started (enough data delivered to
            // trigger gain cycling / startup exit checks).
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

            if (Mode == BbrMode.Startup)
            {
                if (roundStart)
                {
                    UpdateStartup();
                }
            }
            else if (Mode == BbrMode.Drain)
            {
                // Exit drain when in-flight drops to the target or the minimum duration elapsed.
                if (flightBytes <= GetTargetCwndBytes() || nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, UcpConstants.BBR_MIN_ROUND_DURATION_MICROS))
                {
                    EnterProbeBw(nowMicros);
                }
            }
            else if (Mode == BbrMode.ProbeBw)
            {
                // Advance the gain cycle index when the round duration elapses.
                if (nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, UcpConstants.BBR_MIN_ROUND_DURATION_MICROS))
                {
                    _probeBwCycleIndex = (_probeBwCycleIndex + 1) % UcpConstants.BBR_PROBE_BW_GAIN_COUNT;
                    _modeEnteredMicros = nowMicros;
                }

                PacingGain = CalculatePacingGain(nowMicros);
            }
            else if (Mode == BbrMode.ProbeRtt)
            {
                PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
                if (ShouldExitProbeRtt(nowMicros, sampleRttMicros))
                {
                    ExitProbeRtt(nowMicros, sampleRttMicros);
                }
            }

            if (_fastRecoveryEnteredMicros > 0 && MinRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros >= MinRttMicros)
            {
                _fastRecoveryEnteredMicros = 0; // Exit fast recovery after one RTT.
            }

            RecalculateModel(nowMicros);
        }

        /// <summary>
        /// Called by UcpPcb when a packet is sent. Advances loss buckets and
        /// increments the per-bucket sent/retransmit counters.
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

            double recentLossRate = GetRecentLossRatio(nowMicros);
            lossRate = isCongestion ? Math.Max(lossRate, recentLossRate) : recentLossRate;
            _networkCondition = ClassifyNetworkCondition(nowMicros);
            UpdateEstimatedLossPercent(nowMicros, lossRate * 100d);
            if (!ShouldTreatLossAsCongestion(nowMicros, isCongestion))
            {
                TraceLog("RandomLoss lossRate=" + lossRate.ToString("F4"));
                _fastRecoveryEnteredMicros = nowMicros;
                _consecutiveNonCongestionLosses++;
                long outageGapMicros = Math.Max(MinRttMicros > 0 ? MinRttMicros * 3 : 0, 300000L);
                if (_consecutiveNonCongestionLosses >= 3 && nowMicros - _lastAckMicros >= outageGapMicros)
                {
                    PacingGain = Math.Max(1.5d, PacingGain);
                    _consecutiveNonCongestionLosses = 0;
                }
                else if (Mode == BbrMode.ProbeBw)
                {
                    PacingGain = Math.Max(PacingGain, CalculatePacingGain(nowMicros));
                    RecalculateModel(nowMicros);
                }

                return;
            }

            // Loss-control: reduce pacing and CWND when over the loss budget.
            if (_config.LossControlEnable && _networkCondition == NetworkCondition.Congested && EstimatedLossPercent > _maxBandwidthLossPercent)
            {
                PacingGain = Math.Max(UcpConstants.BBR_HIGH_LOSS_PACING_GAIN, PacingGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);
                _lossCwndGain = Math.Max(UcpConstants.BBR_MIN_LOSS_CWND_GAIN, _lossCwndGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);
                RecalculateModel(nowMicros);
                return;
            }

            // Track loss events and trigger ProbeRTT if the threshold is exceeded.
            long resetWindowMicros = Math.Max(MinRttMicros > 0 ? MinRttMicros * UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER : 0, UcpConstants.MICROS_PER_SECOND);
            if (_lastLossMicros == 0 || nowMicros - _lastLossMicros > resetWindowMicros)
            {
                _lossEventsSinceLastProbeRtt = 0; // Reset counter after a quiet period.
            }

            _lastLossMicros = nowMicros;
            _lossEventsSinceLastProbeRtt++;
            if (_lossEventsSinceLastProbeRtt >= UcpConstants.BBR_PROBE_RTT_CONGESTION_LOSS_THRESHOLD && Mode != BbrMode.ProbeRtt)
            {
                EnterProbeRtt(nowMicros);
                _lossEventsSinceLastProbeRtt = 0;
                RecalculateModel(nowMicros);
                return;
            }

            if (Mode == BbrMode.ProbeBw)
            {
                PacingGain = Math.Max(PacingGain, CalculatePacingGain(nowMicros));
            }

            TraceLog("LossSignal lossRate=" + lossRate.ToString("F4") + " pacingGain=" + PacingGain.ToString("F2"));
            RecalculateModel(nowMicros);
        }

        /// <summary>
        /// Checks bandwidth growth between rounds during Startup.
        /// Transitions to Drain if growth stalls for enough consecutive rounds.
        /// </summary>
        private void UpdateStartup()
        {
            double current = BtlBwBytesPerSecond;
            if (_fullBandwidthEstimate <= 0)
            {
                _fullBandwidthEstimate = current;
                return;
            }

            if (current >= _fullBandwidthEstimate * UcpConstants.BbrStartupGrowthTarget)
            {
                _fullBandwidthEstimate = current;
                _fullBandwidthRounds = 0; // Growth achieved; reset stall counter.
            }
            else
            {
                _fullBandwidthRounds++; // No significant growth this round.
            }

            if (_fullBandwidthRounds >= UcpConstants.MinBbrStartupFullBandwidthRounds)
            {
                EnterDrain(_lastAckMicros);
            }
        }

        /// <summary>
        /// Adds a delivery-rate sample to the max-filter window for BtlBw estimation.
        /// Scans recent samples within the RTT window and picks the maximum as BtlBw,
        /// with growth clamping to prevent overestimation.
        /// </summary>
        /// <param name="deliveryRate">New delivery rate in bytes per second.</param>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void AddRateSample(double deliveryRate, long nowMicros)
        {
            _recentRates[_recentRateIndex] = deliveryRate;
            _recentRateTimestamps[_recentRateIndex] = nowMicros;
            _recentRateIndex = (_recentRateIndex + 1) % _recentRates.Length;
            if (_recentRateCount < _recentRates.Length)
            {
                _recentRateCount++;
            }

            double maxRate = 0;
            long rttWindowMicros = MinRttMicros > 0 ? MinRttMicros * Math.Max(1, _config.BbrWindowRtRounds) : UcpConstants.BBR_DEFAULT_RATE_WINDOW_MICROS;
            for (int i = 0; i < _recentRateCount; i++)
            {
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
                maxRate = ClampBandwidthGrowth(maxRate, nowMicros);
                if (_config.MaxPacingRateBytesPerSecond > 0 && maxRate > _config.MaxPacingRateBytesPerSecond)
                {
                    maxRate = _config.MaxPacingRateBytesPerSecond;
                }

                BtlBwBytesPerSecond = maxRate;

                // Ensure BtlBw never drops below the initial bandwidth floor.
                if (BtlBwBytesPerSecond < _config.InitialBandwidthBytesPerSecond)
                {
                    BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond;
                    if (_config.MaxPacingRateBytesPerSecond > 0 && BtlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond)
                    {
                        BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond;
                    }
                }
            }
        }

        /// <summary>
        /// Clamps excessive bandwidth growth within a single growth window.
        /// Prevents transient spikes (e.g. ACK compression) from inflating BtlBw.
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

            double growthGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_BANDWIDTH_GROWTH_PER_ROUND : UcpConstants.BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND;
            double growthCap = Math.Max(BtlBwBytesPerSecond, _bandwidthGrowthWindowStartRate * growthGain);
            return Math.Min(candidateRate, growthCap);
        }

        /// <summary>
        /// Adds a delivery-rate sample to the history buffer (for trend-based congestion detection).
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
        /// </summary>
        /// <param name="sampleRttMicros">RTT sample in microseconds.</param>
        private void AddRttSample(long sampleRttMicros)
        {
            _rttHistoryMicros[_rttHistoryIndex] = sampleRttMicros;
            _rttHistoryIndex = (_rttHistoryIndex + 1) % _rttHistoryMicros.Length;
            if (_rttHistoryCount < _rttHistoryMicros.Length)
            {
                _rttHistoryCount++;
            }
        }

        /// <summary>
        /// Computes the target congestion window in bytes: BDP × CWND gain,
        /// bounded by configured min/max and loss-adjusted gain.
        /// </summary>
        /// <returns>Target congestion window in bytes.</returns>
        private int GetTargetCwndBytes()
        {
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)
            {
                return _config.InitialCongestionWindowBytes;
            }

            long modelRttMicros = GetCwndModelRttMicros();
            double bdp = BtlBwBytesPerSecond * (modelRttMicros / (double)UcpConstants.MICROS_PER_SECOND);
            double effectiveCwndGain = GetEffectiveCwndGain();
            int cwnd = (int)Math.Ceiling(bdp * effectiveCwndGain);
            if (cwnd < _config.InitialCongestionWindowBytes)
            {
                cwnd = _config.InitialCongestionWindowBytes;
            }

            if (_config.MaxCongestionWindowBytes > 0 && cwnd > _config.MaxCongestionWindowBytes)
            {
                cwnd = _config.MaxCongestionWindowBytes;
            }

            if (_lossCwndGain < 1d)
            {
                cwnd = (int)Math.Ceiling(cwnd * _lossCwndGain);
                if (cwnd < _config.InitialCongestionWindowBytes)
                {
                    cwnd = _config.InitialCongestionWindowBytes;
                }
            }

            // Apply inflight guardrails.
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

            if (Mode == BbrMode.ProbeRtt)
            {
                PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
            }

            if (_config.LossControlEnable)
            {
                if (_networkCondition == NetworkCondition.Congested && EstimatedLossPercent > _maxBandwidthLossPercent && GetRecentLossRatio(nowMicros) > 0)
                {
                    PacingGain = Math.Max(UcpConstants.BBR_HIGH_LOSS_PACING_GAIN, PacingGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);
                }
                else if (EstimatedLossPercent <= _maxBandwidthLossPercent * UcpConstants.BBR_LOSS_BUDGET_RECOVERY_RATIO)
                {
                    PacingGain = Math.Min(_config.ProbeBwHighGain, PacingGain + UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP);
                }
            }

            PacingRateBytesPerSecond = BtlBwBytesPerSecond * PacingGain;
            if (_config.MaxPacingRateBytesPerSecond > 0 && PacingRateBytesPerSecond > _config.MaxPacingRateBytesPerSecond)
            {
                PacingRateBytesPerSecond = _config.MaxPacingRateBytesPerSecond;
            }

            CongestionWindowBytes = Mode == BbrMode.ProbeRtt ? Math.Max(_config.InitialCongestionWindowBytes, GetTargetCwndBytes() / 2) : GetTargetCwndBytes();
            _modeEnteredMicros = _modeEnteredMicros == 0 ? nowMicros : _modeEnteredMicros;
        }

        /// <summary>
        /// Transitions from Startup to Drain. Uses drain pacing gain based on
        /// current loss conditions.
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
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void EnterProbeBw(long nowMicros)
        {
            Mode = BbrMode.ProbeBw;
            _probeBwCycleIndex = 0;
            CwndGain = _config.ProbeBwCwndGain;
            PacingGain = CalculatePacingGain(nowMicros);
            _modeEnteredMicros = nowMicros;
        }

        /// <summary>
        /// Determines the drain pacing gain: 1.0 if no loss; config drain gain otherwise.
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
        /// Enters ProbeRTT mode: reduces pacing to drain the pipe and measure the true minimum RTT.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void EnterProbeRtt(long nowMicros)
        {
            Mode = BbrMode.ProbeRtt;
            PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
            _probeRttEnteredMicros = nowMicros;
            _modeEnteredMicros = nowMicros;
            TraceLog("EnterProbeRtt");
        }

        /// <summary>
        /// Exits ProbeRTT: updates minimum RTT if a fresher sample was found,
        /// then transitions back to ProbeBW.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <param name="sampleRttMicros">RTT sample if available.</param>
        private void ExitProbeRtt(long nowMicros, long sampleRttMicros)
        {
            if (sampleRttMicros > 0 && (MinRttMicros == 0 || sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER)))
            {
                MinRttMicros = sampleRttMicros; // Update min RTT if close enough.
            }

            _minRttTimestampMicros = nowMicros;
            TraceLog("ExitProbeRtt");
            EnterProbeBw(nowMicros);
        }

        /// <summary>
        /// Determines whether to exit ProbeRTT: either a fresh near-minimum RTT sample
        /// was observed, or the safety duration has been exceeded.
        /// </summary>
        private bool ShouldExitProbeRtt(long nowMicros, long sampleRttMicros)
        {
            long elapsedMicros = nowMicros - _probeRttEnteredMicros;
            if (elapsedMicros < _config.ProbeRttDurationMicros)
            {
                return false; // Minimum duration not yet met.
            }

            bool hasFreshMinRttSample = sampleRttMicros > 0 && MinRttMicros > 0 && sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER);
            bool exceededSafetyDuration = elapsedMicros >= _config.ProbeRttDurationMicros * UcpConstants.BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER;
            return hasFreshMinRttSample || exceededSafetyDuration;
        }

        /// <summary>
        /// Calculates the pacing gain based on probe cycle phase, network condition,
        /// loss ratio, RTT increase, and network class.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        /// <returns>Pacing gain multiplier.</returns>
        private double CalculatePacingGain(long nowMicros)
        {
            double lossRatio = GetRecentLossRatio(nowMicros);
            double rttIncrease = GetAverageRttIncreaseRatio();

            // Loss-control overrides for congested conditions.
            if (_config.LossControlEnable && _networkCondition == NetworkCondition.Congested && EstimatedLossPercent > _maxBandwidthLossPercent)
            {
                return UcpConstants.BBR_HIGH_LOSS_PACING_GAIN;
            }

            // Fast recovery gain if still within one RTT of the trigger.
            if (_fastRecoveryEnteredMicros > 0 && MinRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros < MinRttMicros)
            {
                return UcpConstants.BBR_FAST_RECOVERY_PACING_GAIN;
            }

            if (_networkCondition == NetworkCondition.Congested)
            {
                if (EstimatedLossPercent <= _maxBandwidthLossPercent)
                {
                    return 1d; // Within budget, maintain pacing.
                }

                return UcpConstants.BBR_PROBE_RTT_PACING_GAIN; // Over budget, reduce.
            }

            if (CurrentNetworkClass == NetworkClass.MobileUnstable)
            {
                // Mobile loss is usually random or route-induced; keep probing so
                // recovery is fast unless congestion evidence appears elsewhere.
                return UcpConstants.BBR_MODERATE_PROBE_GAIN;
            }

            if (CurrentNetworkClass == NetworkClass.LossyLongFat)
            {
                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
                {
                    return UcpConstants.BBR_MODERATE_PROBE_GAIN;
                }

                return 1d;
            }

            if (_networkCondition == NetworkCondition.RandomLoss)
            {
                if (rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO)
                {
                    return _config.ProbeBwHighGain; // Low RTT increase: probe aggressively.
                }

                if (rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
                {
                    return UcpConstants.BBR_MODERATE_PROBE_GAIN;
                }

                return 1d;
            }

            if (CurrentNetworkClass == NetworkClass.LowLatencyLAN)
            {
                return _config.ProbeBwHighGain; // LAN paths can tolerate aggressive probing.
            }

            // Default: use loss-ratio and RTT-increase based tiered gains.
            if (lossRatio < UcpConstants.BBR_LOW_LOSS_RATIO && rttIncrease < UcpConstants.BBR_LOW_RTT_INCREASE_RATIO)
            {
                return _config.ProbeBwHighGain;
            }

            if (lossRatio < UcpConstants.BBR_MODERATE_LOSS_RATIO && rttIncrease < UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
            {
                return UcpConstants.BBR_MODERATE_PROBE_GAIN;
            }

            if (lossRatio < UcpConstants.BBR_LIGHT_LOSS_RATIO)
            {
                return Math.Max(1d, UcpConstants.BBR_LIGHT_LOSS_PACING_GAIN);
            }

            if (lossRatio < UcpConstants.BBR_MEDIUM_LOSS_RATIO)
            {
                return UcpConstants.BBR_MEDIUM_LOSS_PACING_GAIN;
            }

            return UcpConstants.BBR_HIGH_LOSS_PACING_GAIN; // Severe loss: no pacing inflation.
        }

        /// <summary>
        /// Updates the EWMA-smoothed estimated loss percentage.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        private void UpdateEstimatedLossPercent(long nowMicros)
        {
            UpdateEstimatedLossPercent(nowMicros, CalculateLossPercent(nowMicros));
        }

        /// <summary>
        /// Updates the EWMA-smoothed estimated loss percentage with a candidate value.
        /// When no loss is present, the estimate decays toward zero.
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
            if (_networkCondition != NetworkCondition.Congested || _deliveryRateBytesPerSecond <= 0 || Mode == BbrMode.Startup)
            {
                return retransmissionLoss * 100d;
            }

            // When congested, also consider delivery-rate shortfall.
            double actualRate = _deliveryRateBytesPerSecond;
            double lossFromRate = Math.Max(0d, 1d - (actualRate / targetRate));
            double rateLossHint = Math.Min(lossFromRate, retransmissionLoss + UcpConstants.BBR_RATE_LOSS_HINT_MAX_RATIO);
            return Math.Max(rateLossHint, retransmissionLoss) * 100d;
        }

        /// <summary>
        /// Classifies the current network condition based on delivery-rate trend,
        /// RTT increase, and recent loss ratio.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <returns>The classified network condition.</returns>
        private NetworkCondition ClassifyNetworkCondition(long nowMicros)
        {
            if (_deliveryRateHistoryCount < 2)
            {
                return NetworkCondition.Idle;
            }

            int newestIndex = (_deliveryRateHistoryIndex + _deliveryRateHistory.Length - 1) % _deliveryRateHistory.Length;
            int oldestIndex = (_deliveryRateHistoryIndex + _deliveryRateHistory.Length - _deliveryRateHistoryCount) % _deliveryRateHistory.Length;
            double oldestRate = _deliveryRateHistory[oldestIndex];
            double newestRate = _deliveryRateHistory[newestIndex];
            double deliveryRateChange = oldestRate <= 0 ? 0d : (newestRate - oldestRate) / oldestRate;
            double lossRatio = GetRecentLossRatio(nowMicros);
            double rttIncrease = GetAverageRttIncreaseRatio();
            int congestionScore = 0;

            if (deliveryRateChange <= UcpConstants.BBR_CONGESTION_RATE_DROP_RATIO && rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RATE_DROP_SCORE;
            }

            if (rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RTT_GROWTH_SCORE;
            }

            if (lossRatio >= UcpConstants.BBR_CONGESTION_LOSS_RATIO && rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_LOSS_SCORE;
            }

            if (congestionScore >= UcpConstants.BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD)
            {
                return NetworkCondition.Congested;
            }

            if (lossRatio > 0 && rttIncrease <= UcpConstants.BBR_RANDOM_LOSS_MAX_RTT_INCREASE_RATIO)
            {
                return NetworkCondition.RandomLoss;
            }

            if (lossRatio < UcpConstants.BBR_LOW_LOSS_RATIO)
            {
                return NetworkCondition.LightLoad;
            }

            return NetworkCondition.Idle;
        }

        /// <summary>
        /// Determines whether a loss should be treated as congestion (requiring
        /// multiplicative reduction) or random (handle with fast recovery only).
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        /// <param name="isCongestionSignal">Whether the external signal indicates congestion.</param>
        /// <returns>True if the loss should be treated as congestion.</returns>
        private bool ShouldTreatLossAsCongestion(long nowMicros, bool isCongestionSignal)
        {
            if (!isCongestionSignal)
            {
                return false;
            }

            if (_networkCondition == NetworkCondition.Congested)
            {
                return true;
            }

            double rttIncrease = GetAverageRttIncreaseRatio();
            double lossRatio = GetRecentLossRatio(nowMicros);
            return rttIncrease >= UcpConstants.BBR_CONGESTION_RTT_INCREASE_RATIO && lossRatio >= UcpConstants.BBR_CONGESTION_LOSS_RATIO;
        }

        /// <summary>
        /// Returns the RTT value used for CWND model calculations. On congested paths
        /// uses min RTT; on lossy paths adds a cushion to avoid under-utilization.
        /// </summary>
        /// <returns>Model RTT in microseconds.</returns>
        private long GetCwndModelRttMicros()
        {
            long modelRttMicros = MinRttMicros;
            if (modelRttMicros <= 0)
            {
                return 0;
            }

            if (_networkCondition == NetworkCondition.Congested)
            {
                return modelRttMicros; // Use min RTT for congestion scenarios.
            }

            if (_currentRttMicros > modelRttMicros)
            {
                long cappedCurrentRttMicros = (long)Math.Min(_currentRttMicros, modelRttMicros * UcpConstants.BBR_RANDOM_LOSS_CWND_RTT_CUSHION);
                modelRttMicros = Math.Max(modelRttMicros, cappedCurrentRttMicros);
            }

            return modelRttMicros;
        }

        /// <summary>
        /// Computes the average RTT increase ratio relative to the minimum RTT.
        /// Returns 0 if no history or min RTT is available.
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
        /// Updates the inflight guardrail bounds based on current BDP and gain factors.
        /// </summary>
        private void UpdateInflightBounds()
        {
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)
            {
                _inflightHighBytes = 0;
                _inflightLowBytes = 0;
                return;
            }

            long modelRttMicros = GetCwndModelRttMicros();
            if (modelRttMicros <= 0)
            {
                _inflightHighBytes = 0;
                _inflightLowBytes = 0;
                return;
            }

            double bdpBytes = BtlBwBytesPerSecond * (modelRttMicros / (double)UcpConstants.MICROS_PER_SECOND);
            _inflightLowBytes = Math.Max(_config.InitialCongestionWindowBytes, bdpBytes * UcpConstants.BBR_INFLIGHT_LOW_GAIN);
            _inflightHighBytes = Math.Max(_inflightLowBytes, bdpBytes * UcpConstants.BBR_INFLIGHT_HIGH_GAIN);
        }

        /// <summary>
        /// Calculates the recent loss ratio from the sliding loss bucket windows.
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
        /// Clears old buckets and initializes new ones as time moves forward.
        /// </summary>
        /// <param name="nowMicros">Current timestamp.</param>
        private void AdvanceLossBuckets(long nowMicros)
        {
            if (nowMicros <= 0)
            {
                nowMicros = UcpTime.NowMicroseconds();
            }

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
        /// </summary>
        private double GetEffectiveCwndGain()
        {
            double maxWasteGain = 1d + Math.Max(0d, _config.MaxBandwidthWastePercent);
            double limit = maxWasteGain * _config.ProbeBwCwndGain;
            if (PacingGain <= 0 || PacingGain * CwndGain <= limit)
            {
                return CwndGain; // Within budget.
            }

            return Math.Max(1d, limit / PacingGain); // Scale down to stay within waste budget.
        }

        /// <summary>
        /// Conditionally writes a debug trace message if debug logging is enabled.
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
        /// When a window's duration has elapsed, finalizes it and starts a new one.
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
        /// </summary>
        /// <returns>The classified network path type.</returns>
        private NetworkClass ClassifyNetworkPath()
        {
            if (_classifierWindowCount < 2)
            {
                return NetworkClass.Default; // Not enough data yet.
            }

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

            if (avgRttMs < UcpConstants.NETWORK_CLASSIFIER_LAN_RTT_MS && avgLoss < 0.001d && avgJitterMs < UcpConstants.NETWORK_CLASSIFIER_LAN_JITTER_MS)
            {
                return NetworkClass.LowLatencyLAN;
            }

            if (avgLoss > UcpConstants.NETWORK_CLASSIFIER_MOBILE_LOSS_RATE && avgJitterMs > UcpConstants.NETWORK_CLASSIFIER_MOBILE_JITTER_MS)
            {
                return NetworkClass.MobileUnstable;
            }

            if (avgRttMs > UcpConstants.NETWORK_CLASSIFIER_LONG_FAT_RTT_MS && avgLoss > 0.01d)
            {
                return NetworkClass.LossyLongFat;
            }

            if (minThroughput < 0.7d && avgRttMs > _classifierWindows[0].AvgRttMicros / UcpConstants.MICROS_PER_MILLI * 1.1d)
            {
                return NetworkClass.CongestedBottleneck;
            }

            if (avgRttMs > 30d)
            {
                return NetworkClass.SymmetricVPN;
            }

            return NetworkClass.Default;
        }
    }
}
