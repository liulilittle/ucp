using System;

namespace Ucp
{
    /// <summary>
    /// Engineering-oriented BBRv1 controller that implements core state transitions and rate/window estimates.
    /// </summary>
    internal sealed class BbrCongestionControl
    {
        private static readonly double[] ProbeBwGains = new double[] { 1.25d, 0.75d, 1d, 1d, 1d, 1d, 1d, 1d };

        private readonly UcpConfiguration _config;
        private readonly double[] _recentRates = new double[10];
        private readonly long[] _recentRateTimestamps = new long[10];
        private int _recentRateCount;
        private int _recentRateIndex;
        private double _fullBandwidthEstimate;
        private int _fullBandwidthRounds;
        private int _probeBwCycleIndex;
        private long _modeEnteredMicros;
        private long _lastAckMicros;
        private long _minRttTimestampMicros;
        private long _probeRttEnteredMicros;
        private long _totalDeliveredBytes;
        private long _nextRoundDeliveredBytes;

        public BbrMode Mode { get; private set; }

        public double BtlBwBytesPerSecond { get; private set; }

        public long MinRttMicros { get; private set; }

        public double PacingGain { get; private set; }

        public double CwndGain { get; private set; }

        public double PacingRateBytesPerSecond { get; private set; }

        public int CongestionWindowBytes { get; private set; }

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
                double deliveryRate = deliveredBytes * 1000000d / intervalMicros;
                AddRateSample(deliveryRate, nowMicros);
            }

            if (minRttExpired && Mode != BbrMode.ProbeRtt)
            {
                EnterProbeRtt(nowMicros);
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
                if (flightBytes <= GetTargetCwndBytes() || nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, 1000))
                {
                    EnterProbeBw(nowMicros);
                }
            }
            else if (Mode == BbrMode.ProbeBw)
            {
                if (nowMicros - _modeEnteredMicros >= Math.Max(MinRttMicros, 1000))
                {
                    _probeBwCycleIndex = (_probeBwCycleIndex + 1) % ProbeBwGains.Length;
                    _modeEnteredMicros = nowMicros;
                    PacingGain = GetProbeBwGain(_probeBwCycleIndex);
                }
            }
            else if (Mode == BbrMode.ProbeRtt)
            {
                if (nowMicros - _probeRttEnteredMicros >= _config.ProbeRttDurationMicros)
                {
                    if (sampleRttMicros > 0)
                    {
                        MinRttMicros = sampleRttMicros;
                        _minRttTimestampMicros = nowMicros;
                    }

                    EnterProbeBw(nowMicros);
                }
            }

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
            for (int i = 0; i < _recentRateCount; i++)
            {
                long rttWindowMicros = MinRttMicros > 0 ? MinRttMicros * Math.Max(1, _config.BbrWindowRtRounds) : 1000000L;
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

        private int GetTargetCwndBytes()
        {
            if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)
            {
                return _config.InitialCongestionWindowBytes;
            }

            double bdp = BtlBwBytesPerSecond * (MinRttMicros / 1000000d);
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

            PacingRateBytesPerSecond = BtlBwBytesPerSecond * PacingGain;
            if (_config.MaxPacingRateBytesPerSecond > 0 && PacingRateBytesPerSecond > _config.MaxPacingRateBytesPerSecond)
            {
                PacingRateBytesPerSecond = _config.MaxPacingRateBytesPerSecond;
            }

            CongestionWindowBytes = Mode == BbrMode.ProbeRtt ? _config.InitialCongestionWindowBytes : GetTargetCwndBytes();
            _modeEnteredMicros = _modeEnteredMicros == 0 ? nowMicros : _modeEnteredMicros;
        }

        private void EnterDrain(long nowMicros)
        {
            Mode = BbrMode.Drain;
            PacingGain = _config.DrainPacingGain;
            _modeEnteredMicros = nowMicros;
        }

        private void EnterProbeBw(long nowMicros)
        {
            Mode = BbrMode.ProbeBw;
            _probeBwCycleIndex = 0;
            CwndGain = _config.ProbeBwCwndGain;
            PacingGain = GetProbeBwGain(_probeBwCycleIndex);
            _modeEnteredMicros = nowMicros;
        }

        private void EnterProbeRtt(long nowMicros)
        {
            Mode = BbrMode.ProbeRtt;
            PacingGain = 1.0d;
            _probeRttEnteredMicros = nowMicros;
            _modeEnteredMicros = nowMicros;
        }

        private double GetProbeBwGain(int index)
        {
            if (index == 0)
            {
                return _config.ProbeBwHighGain;
            }

            if (index == 1)
            {
                return _config.ProbeBwLowGain;
            }

            return ProbeBwGains[index];
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
    }
}
