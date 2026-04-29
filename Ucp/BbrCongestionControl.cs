using System;
using System.Diagnostics;

namespace Ucp
{
    /// <summary>
    /// Engineering-oriented BBRv1 controller that implements core state transitions and rate/window estimates.
    /// </summary>
    internal sealed class BbrCongestionControl
    {
        private readonly UcpConfiguration _config;
        private readonly double[] _recentRates = new double[UcpConstants.BBR_RECENT_RATE_SAMPLE_COUNT];
        private readonly long[] _recentRateTimestamps = new long[UcpConstants.BBR_RECENT_RATE_SAMPLE_COUNT];
        private readonly int[] _sentBuckets = new int[UcpConstants.BBR_LOSS_BUCKET_COUNT];
        private readonly int[] _retransmitBuckets = new int[UcpConstants.BBR_LOSS_BUCKET_COUNT];
        private readonly double[] _deliveryRateHistory = new double[UcpConstants.BBR_DELIVERY_RATE_HISTORY_COUNT];
        private readonly long[] _rttHistoryMicros = new long[UcpConstants.BBR_RTT_HISTORY_COUNT];
        private int _recentRateCount;
        private int _recentRateIndex;
        private int _deliveryRateHistoryCount;
        private int _deliveryRateHistoryIndex;
        private int _rttHistoryCount;
        private int _rttHistoryIndex;
        private double _fullBandwidthEstimate;
        private int _fullBandwidthRounds;
        private int _probeBwCycleIndex;
        private long _modeEnteredMicros;
        private long _lastAckMicros;
        private long _minRttTimestampMicros;
        private long _probeRttEnteredMicros;
        private long _totalDeliveredBytes;
        private long _nextRoundDeliveredBytes;
        private long _currentRttMicros;
        private long _lossBucketStartMicros;
        private int _lossBucketIndex;
        private int _lossEventsSinceLastProbeRtt;
        private long _lastLossMicros;
        private double _lossCwndGain = 1d;
        private double _deliveryRateBytesPerSecond;
        private double _inflightHighBytes;
        private double _inflightLowBytes;
        private double _maxBandwidthLossPercent;
        private long _fastRecoveryEnteredMicros;
        private long _bandwidthGrowthWindowMicros;
        private double _bandwidthGrowthWindowStartRate;
        private NetworkCondition _networkCondition;

        private enum NetworkCondition
        {
            Idle,
            LightLoad,
            Congested,
            RandomLoss
        }

        public enum NetworkClass
        {
            Default,
            LowLatencyLAN,
            LossyLongFat,
            MobileUnstable,
            CongestedBottleneck,
            SymmetricVPN
        }

        private struct ClassifierWindow
        {
            public double AvgRttMicros;
            public double LossRate;
            public double JitterMicros;
            public double ThroughputRatio;
        }

        private readonly ClassifierWindow[] _classifierWindows = new ClassifierWindow[UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT];
        private int _classifierWindowIndex;
        private int _classifierWindowCount;
        private long _classifierWindowStartMicros;
        private long _classifierWindowSentBytes;
        private long _classifierWindowMinRttMicros;
        private long _classifierWindowMaxRttMicros;
        private long _classifierWindowRttSumMicros;
        private int _classifierWindowRttCount;

        public NetworkClass CurrentNetworkClass { get; private set; }

        public BbrMode Mode { get; private set; }

        public double BtlBwBytesPerSecond { get; private set; }

        public long MinRttMicros { get; private set; }

        public double PacingGain { get; private set; }

        public double CwndGain { get; private set; }

        public double PacingRateBytesPerSecond { get; private set; }

        public int CongestionWindowBytes { get; private set; }

        public double EstimatedLossPercent { get; private set; }

        public BbrCongestionControl()
            : this(new UcpConfiguration())
        {
        }

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
                BtlBwBytesPerSecond = _config.MaxPacingRateBytesPerSecond;
            }

            MinRttMicros = 0;
            RecalculateModel(UcpTime.NowMicroseconds());
        }

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
                    minRttExpired = false;
                }
            }

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
                    double aggregationCapGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_ACK_AGGREGATION_RATE_CAP_GAIN : UcpConstants.BBR_STEADY_ACK_AGGREGATION_RATE_CAP_GAIN;
                    deliveryRate = Math.Min(deliveryRate, PacingRateBytesPerSecond * aggregationCapGain);
                }

                _deliveryRateBytesPerSecond = deliveryRate;
                AddRateSample(deliveryRate, nowMicros);
                AddDeliveryRateSample(deliveryRate);
                if (_lossCwndGain < 1d && Mode != BbrMode.ProbeRtt)
                {
                    _lossCwndGain = Math.Min(1d, _lossCwndGain + UcpConstants.BBR_LOSS_CWND_RECOVERY_STEP);
                }
            }

            if (sampleRttMicros > 0)
            {
                AddRttSample(sampleRttMicros);
            }

            AdvanceClassifierWindow(nowMicros, deliveredBytes + flightBytes, sampleRttMicros, GetRecentLossRatio(nowMicros));
            CurrentNetworkClass = ClassifyNetworkPath();

            _networkCondition = ClassifyNetworkCondition(nowMicros);
            UpdateEstimatedLossPercent(nowMicros);
            UpdateInflightBounds();

            if (minRttExpired && Mode != BbrMode.ProbeRtt)
            {
                bool bandwidthGrowthStalled = _fullBandwidthRounds >= UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER;
                if (bandwidthGrowthStalled)
                {
                    EnterProbeRtt(nowMicros);
                }
            }

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
                if (flightBytes <= GetTargetCwndBytes() || nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, UcpConstants.BBR_MIN_ROUND_DURATION_MICROS))
                {
                    EnterProbeBw(nowMicros);
                }
            }
            else if (Mode == BbrMode.ProbeBw)
            {
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
                _fastRecoveryEnteredMicros = 0;
            }

            RecalculateModel(nowMicros);
        }

        public void OnPacketSent(long nowMicros, bool isRetransmit)
        {
            AdvanceLossBuckets(nowMicros);
            _sentBuckets[_lossBucketIndex]++;
            if (isRetransmit)
            {
                _retransmitBuckets[_lossBucketIndex]++;
            }
        }

        public void OnFastRetransmit(long nowMicros, bool isCongestion)
        {
            if (_config.EnableDebugLog)
            {
                Trace.WriteLine("[UCP BBR] FastRetransmit congestion=" + isCongestion);
            }

            if (!isCongestion)
            {
                _fastRecoveryEnteredMicros = nowMicros;
                PacingGain = UcpConstants.BBR_FAST_RECOVERY_PACING_GAIN;
                RecalculateModel(nowMicros);
            }

            OnPacketLoss(nowMicros, GetRecentLossRatio(nowMicros), isCongestion);
        }

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

            if (_config.LossControlEnable && _networkCondition == NetworkCondition.Congested && EstimatedLossPercent > _maxBandwidthLossPercent)
            {
                PacingGain = Math.Max(UcpConstants.BBR_HIGH_LOSS_PACING_GAIN, PacingGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);
                _lossCwndGain = Math.Max(UcpConstants.BBR_MIN_LOSS_CWND_GAIN, _lossCwndGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);
                RecalculateModel(nowMicros);
                return;
            }

            long resetWindowMicros = Math.Max(MinRttMicros > 0 ? MinRttMicros * UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER : 0, UcpConstants.MICROS_PER_SECOND);
            if (_lastLossMicros == 0 || nowMicros - _lastLossMicros > resetWindowMicros)
            {
                _lossEventsSinceLastProbeRtt = 0;
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

            PacingGain = Math.Max(UcpConstants.BBR_MIN_CONGESTION_PACING_GAIN, PacingGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);
            _lossCwndGain = Math.Max(UcpConstants.BBR_MIN_LOSS_CWND_GAIN, _lossCwndGain * UcpConstants.BBR_CONGESTION_LOSS_REDUCTION);
            if (Mode == BbrMode.ProbeBw)
            {
                PacingGain = Math.Min(PacingGain, CalculatePacingGain(nowMicros));
            }

            TraceLog("CongestionLoss lossRate=" + lossRate.ToString("F4") + " pacingGain=" + PacingGain.ToString("F2"));
            RecalculateModel(nowMicros);
        }

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
                _fullBandwidthRounds = 0;
            }
            else
            {
                _fullBandwidthRounds++;
            }

            if (_fullBandwidthRounds >= UcpConstants.MinBbrStartupFullBandwidthRounds)
            {
                EnterDrain(_lastAckMicros);
            }
        }

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
                    continue;
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

        private double ClampBandwidthGrowth(double candidateRate, long nowMicros)
        {
            if (candidateRate <= BtlBwBytesPerSecond || BtlBwBytesPerSecond <= 0)
            {
                return candidateRate;
            }

            long growthIntervalMicros = MinRttMicros > 0 ? MinRttMicros : UcpConstants.BBR_BANDWIDTH_GROWTH_FALLBACK_INTERVAL_MICROS;
            if (_bandwidthGrowthWindowMicros == 0 || nowMicros - _bandwidthGrowthWindowMicros >= growthIntervalMicros)
            {
                _bandwidthGrowthWindowMicros = nowMicros;
                _bandwidthGrowthWindowStartRate = BtlBwBytesPerSecond;
            }

            double growthGain = Mode == BbrMode.Startup ? UcpConstants.BBR_STARTUP_BANDWIDTH_GROWTH_PER_ROUND : UcpConstants.BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND;
            double growthCap = Math.Max(BtlBwBytesPerSecond, _bandwidthGrowthWindowStartRate * growthGain);
            return Math.Min(candidateRate, growthCap);
        }

        private void AddDeliveryRateSample(double deliveryRate)
        {
            _deliveryRateHistory[_deliveryRateHistoryIndex] = deliveryRate;
            _deliveryRateHistoryIndex = (_deliveryRateHistoryIndex + 1) % _deliveryRateHistory.Length;
            if (_deliveryRateHistoryCount < _deliveryRateHistory.Length)
            {
                _deliveryRateHistoryCount++;
            }
        }

        private void AddRttSample(long sampleRttMicros)
        {
            _rttHistoryMicros[_rttHistoryIndex] = sampleRttMicros;
            _rttHistoryIndex = (_rttHistoryIndex + 1) % _rttHistoryMicros.Length;
            if (_rttHistoryCount < _rttHistoryMicros.Length)
            {
                _rttHistoryCount++;
            }
        }

        private int GetTargetCwndBytes()
        {
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)
            {
                return _config.InitialCongestionWindowBytes;
            }

            double bdp = BtlBwBytesPerSecond * (MinRttMicros / (double)UcpConstants.MICROS_PER_SECOND);
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

        private void EnterDrain(long nowMicros)
        {
            Mode = BbrMode.Drain;
            PacingGain = GetDrainPacingGain(nowMicros);
            _modeEnteredMicros = nowMicros;
        }

        private void EnterProbeBw(long nowMicros)
        {
            Mode = BbrMode.ProbeBw;
            _probeBwCycleIndex = 0;
            CwndGain = _config.ProbeBwCwndGain;
            PacingGain = CalculatePacingGain(nowMicros);
            _modeEnteredMicros = nowMicros;
        }

        private double GetDrainPacingGain(long nowMicros)
        {
            double recentLossRatio = GetRecentLossRatio(nowMicros);
            if (recentLossRatio <= 0 && EstimatedLossPercent <= 0)
            {
                return 1d;
            }

            return _config.DrainPacingGain;
        }

        private void EnterProbeRtt(long nowMicros)
        {
            Mode = BbrMode.ProbeRtt;
            PacingGain = UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
            _probeRttEnteredMicros = nowMicros;
            _modeEnteredMicros = nowMicros;
            TraceLog("EnterProbeRtt");
        }

        private void ExitProbeRtt(long nowMicros, long sampleRttMicros)
        {
            if (sampleRttMicros > 0 && (MinRttMicros == 0 || sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER)))
            {
                MinRttMicros = sampleRttMicros;
            }

            _minRttTimestampMicros = nowMicros;
            TraceLog("ExitProbeRtt");
            EnterProbeBw(nowMicros);
        }

        private bool ShouldExitProbeRtt(long nowMicros, long sampleRttMicros)
        {
            long elapsedMicros = nowMicros - _probeRttEnteredMicros;
            if (elapsedMicros < _config.ProbeRttDurationMicros)
            {
                return false;
            }

            bool hasFreshMinRttSample = sampleRttMicros > 0 && MinRttMicros > 0 && sampleRttMicros <= (long)(MinRttMicros * UcpConstants.BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER);
            bool exceededSafetyDuration = elapsedMicros >= _config.ProbeRttDurationMicros * UcpConstants.BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER;
            return hasFreshMinRttSample || exceededSafetyDuration;
        }

        private double CalculatePacingGain(long nowMicros)
        {
            double lossRatio = GetRecentLossRatio(nowMicros);
            double rttIncrease = GetAverageRttIncreaseRatio();

            if (_config.LossControlEnable && _networkCondition == NetworkCondition.Congested && EstimatedLossPercent > _maxBandwidthLossPercent)
            {
                return UcpConstants.BBR_HIGH_LOSS_PACING_GAIN;
            }

            if (_fastRecoveryEnteredMicros > 0 && MinRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros < MinRttMicros)
            {
                return UcpConstants.BBR_FAST_RECOVERY_PACING_GAIN;
            }

            if (_networkCondition == NetworkCondition.Congested)
            {
                return UcpConstants.BBR_PROBE_RTT_PACING_GAIN;
            }

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

            return UcpConstants.BBR_HIGH_LOSS_PACING_GAIN;
        }

        private void UpdateEstimatedLossPercent(long nowMicros)
        {
            UpdateEstimatedLossPercent(nowMicros, CalculateLossPercent(nowMicros));
        }

        private void UpdateEstimatedLossPercent(long nowMicros, double candidateLossPercent)
        {
            double boundedCandidate = Math.Max(0d, Math.Min(100d, candidateLossPercent));
            if (boundedCandidate <= 0d && GetRecentLossRatio(nowMicros) <= 0d)
            {
                EstimatedLossPercent *= UcpConstants.BBR_LOSS_EWMA_IDLE_DECAY;
                return;
            }

            if (EstimatedLossPercent <= 0d)
            {
                EstimatedLossPercent = boundedCandidate;
                return;
            }

            EstimatedLossPercent = (EstimatedLossPercent * UcpConstants.BBR_LOSS_EWMA_RETAINED_WEIGHT) + (boundedCandidate * UcpConstants.BBR_LOSS_EWMA_SAMPLE_WEIGHT);
        }

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

            double actualRate = _deliveryRateBytesPerSecond;
            double lossFromRate = Math.Max(0d, 1d - (actualRate / targetRate));
            double rateLossHint = Math.Min(lossFromRate, retransmissionLoss + UcpConstants.BBR_RATE_LOSS_HINT_MAX_RATIO);
            return Math.Max(rateLossHint, retransmissionLoss) * 100d;
        }

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
            if (deliveryRateChange <= UcpConstants.BBR_CONGESTION_RATE_DROP_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RATE_DROP_SCORE;
            }

            if (rttIncrease >= UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO)
            {
                congestionScore += UcpConstants.BBR_CONGESTION_RTT_GROWTH_SCORE;
            }

            if (lossRatio >= UcpConstants.BBR_MODERATE_LOSS_RATIO && rttIncrease >= UcpConstants.BBR_LOW_RTT_INCREASE_RATIO)
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
            return rttIncrease >= UcpConstants.BBR_MODERATE_RTT_INCREASE_RATIO && lossRatio >= UcpConstants.BBR_MODERATE_LOSS_RATIO;
        }

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

        private void UpdateInflightBounds()
        {
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)
            {
                _inflightHighBytes = 0;
                _inflightLowBytes = 0;
                return;
            }

            double bdpBytes = BtlBwBytesPerSecond * (MinRttMicros / (double)UcpConstants.MICROS_PER_SECOND);
            _inflightLowBytes = Math.Max(_config.InitialCongestionWindowBytes, bdpBytes * UcpConstants.BBR_INFLIGHT_LOW_GAIN);
            _inflightHighBytes = Math.Max(_inflightLowBytes, bdpBytes * UcpConstants.BBR_INFLIGHT_HIGH_GAIN);
        }

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

        private void AdvanceLossBuckets(long nowMicros)
        {
            if (nowMicros <= 0)
            {
                nowMicros = UcpTime.NowMicroseconds();
            }

            long alignedNow = nowMicros - (nowMicros % UcpConstants.BBR_LOSS_BUCKET_MICROS);
            if (_lossBucketStartMicros == 0 || nowMicros < _lossBucketStartMicros)
            {
                Array.Clear(_sentBuckets, 0, _sentBuckets.Length);
                Array.Clear(_retransmitBuckets, 0, _retransmitBuckets.Length);
                _lossBucketIndex = 0;
                _lossBucketStartMicros = alignedNow;
                return;
            }

            long steps = (nowMicros - _lossBucketStartMicros) / UcpConstants.BBR_LOSS_BUCKET_MICROS;
            if (steps <= 0)
            {
                return;
            }

            if (steps >= UcpConstants.BBR_LOSS_BUCKET_COUNT)
            {
                Array.Clear(_sentBuckets, 0, _sentBuckets.Length);
                Array.Clear(_retransmitBuckets, 0, _retransmitBuckets.Length);
                _lossBucketIndex = 0;
                _lossBucketStartMicros = alignedNow;
                return;
            }

            for (long i = 0; i < steps; i++)
            {
                _lossBucketIndex = (_lossBucketIndex + 1) % UcpConstants.BBR_LOSS_BUCKET_COUNT;
                _sentBuckets[_lossBucketIndex] = 0;
                _retransmitBuckets[_lossBucketIndex] = 0;
            }

            _lossBucketStartMicros += steps * UcpConstants.BBR_LOSS_BUCKET_MICROS;
        }

        private double GetEffectiveCwndGain()
        {
            double maxWasteGain = 1d + Math.Max(0d, _config.MaxBandwidthWastePercent);
            double limit = maxWasteGain * _config.ProbeBwCwndGain;
            if (PacingGain <= 0 || PacingGain * CwndGain <= limit)
            {
                return CwndGain;
            }

            return Math.Max(1d, limit / PacingGain);
        }

        private void TraceLog(string message)
        {
            if (_config.EnableDebugLog)
            {
                Trace.WriteLine("[UCP BBR] " + message);
            }
        }

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
                ref ClassifierWindow window = ref _classifierWindows[_classifierWindowIndex];
                window.AvgRttMicros = _classifierWindowRttCount > 0 ? _classifierWindowRttSumMicros / (double)_classifierWindowRttCount : 0d;
                window.JitterMicros = _classifierWindowMinRttMicros > 0 && _classifierWindowMaxRttMicros > 0 ? (_classifierWindowMaxRttMicros - _classifierWindowMinRttMicros) : 0d;
                window.LossRate = lossRateSnapshot;
                window.ThroughputRatio = BtlBwBytesPerSecond > 0 ? Math.Min(1d, (_classifierWindowSentBytes / (double)Math.Max(1, nowMicros - _classifierWindowStartMicros)) / BtlBwBytesPerSecond) : 0d;
                _classifierWindowIndex = (_classifierWindowIndex + 1) % UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT;
                if (_classifierWindowCount < UcpConstants.NETWORK_CLASSIFIER_WINDOW_COUNT)
                {
                    _classifierWindowCount++;
                }

                _classifierWindowStartMicros = nowMicros;
                _classifierWindowSentBytes = 0;
                _classifierWindowMinRttMicros = 0;
                _classifierWindowMaxRttMicros = 0;
                _classifierWindowRttSumMicros = 0;
                _classifierWindowRttCount = 0;
            }
        }

        private NetworkClass ClassifyNetworkPath()
        {
            if (_classifierWindowCount < 2)
            {
                return NetworkClass.Default;
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

        private int _consecutiveNonCongestionLosses;
    }
}
