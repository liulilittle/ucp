using System;

namespace Ucp
{

    internal sealed class PacingController
    {
        private const long kMinPacingWaitMicros = 100;
        private readonly object _sync = new object();
        private readonly int _sendQuantumBytes;

        private readonly int _minimumPacketCapacityBytes;

        private readonly long _maxPacingRateBytesPerSecond;

        private readonly long _minPacingIntervalMicros;

        private readonly long _bucketDurationMicros;

        private double _tokens;

        private double _capacity;

        private long _lastRefillMicros;

        public double PacingRateBytesPerSecond { get; private set; }

        public int SendQuantumBytes
        {
            get { return _sendQuantumBytes; }
        }

        public PacingController(double initialRateBytesPerSecond)
            : this(new UcpConfiguration(), initialRateBytesPerSecond)
        {
        }

        public PacingController(UcpConfiguration config, double initialRateBytesPerSecond)
        {
            config = config ?? new UcpConfiguration();
            _sendQuantumBytes = config.SendQuantumBytes > 0 ? config.SendQuantumBytes : config.Mss;
            _minimumPacketCapacityBytes = UcpConstants.DATA_HEADER_SIZE_WITH_ACK + Math.Max(1, config.MaxPayloadSize);
            _maxPacingRateBytesPerSecond = config.MaxPacingRateBytesPerSecond;
            _minPacingIntervalMicros = config.MinPacingIntervalMicros;
            _bucketDurationMicros = config.PacingBucketDurationMicros <= 0 ? UcpConstants.DEFAULT_PACING_BUCKET_DURATION_MICROS : config.PacingBucketDurationMicros;
            SetRate(initialRateBytesPerSecond, 0);
            _tokens = Math.Max(Math.Min(_capacity, (double)_sendQuantumBytes), (double)_minimumPacketCapacityBytes);
        }

        public void SetRate(double rateBytesPerSecond, long nowMicros)
        {
            lock (_sync)
            {
                if (rateBytesPerSecond <= 0)
                {
                    rateBytesPerSecond = _sendQuantumBytes;
                }

                if (_maxPacingRateBytesPerSecond > 0 && rateBytesPerSecond > _maxPacingRateBytesPerSecond)
                {
                    rateBytesPerSecond = _maxPacingRateBytesPerSecond;
                }

                Refill(nowMicros);
                PacingRateBytesPerSecond = rateBytesPerSecond;
                _capacity = Math.Max(Math.Max(_sendQuantumBytes, _minimumPacketCapacityBytes), rateBytesPerSecond * _bucketDurationMicros / UcpConstants.MICROS_PER_SECOND);
                if (_tokens > _capacity)
                {
                    _tokens = _capacity;
                }

                _lastRefillMicros = nowMicros;
            }
        }

        public bool TryConsume(int bytes, long nowMicros)
        {
            lock (_sync)
            {
                Refill(nowMicros);
                bool result;
                if (_tokens >= bytes)
                {
                    _tokens -= bytes;
                    result = true;
                }
                else
                {
                    result = false;
                }
                return result;
            }
        }

        public void ForceConsume(int bytes, long nowMicros)
        {
            lock (_sync)
            {
                Refill(nowMicros);
                if (_tokens > 0)
                    _tokens = 0;
            }
        }

        public long GetWaitTimeMicros(int bytes, long nowMicros)
        {
            lock (_sync)
            {
                Refill(nowMicros);
                if (_tokens >= bytes)
                {
                    if (_minPacingIntervalMicros > 0)
                    {
                        return _minPacingIntervalMicros;
                    }
                    return 0;
                }

                if (PacingRateBytesPerSecond <= 0)
                {
                    return UcpConstants.DEFAULT_PACING_WAIT_MICROS;
                }

                double deficit = bytes - _tokens;
                long waitMicros = (long)Math.Ceiling((deficit / PacingRateBytesPerSecond) * UcpConstants.MICROS_PER_SECOND);
                if (waitMicros < kMinPacingWaitMicros)
                {
                    waitMicros = kMinPacingWaitMicros;
                }
                if (_minPacingIntervalMicros > 0 && waitMicros < _minPacingIntervalMicros)
                {
                    return _minPacingIntervalMicros;
                }

                return waitMicros;
            }
        }

        private void Refill(long nowMicros)
        {
            if (0 == _lastRefillMicros)
            {
                _lastRefillMicros = nowMicros;
                return;
            }

            long elapsedMicros = nowMicros - _lastRefillMicros;
            if (elapsedMicros <= 0)
            {
                return;
            }

            _tokens += (elapsedMicros / (double)UcpConstants.MICROS_PER_SECOND) * PacingRateBytesPerSecond;
            if (_tokens > _capacity)
            {
                _tokens = _capacity;
            }

            _lastRefillMicros = nowMicros;
        }
    }
}
