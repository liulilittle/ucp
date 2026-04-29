using System;

namespace Ucp
{
    /// <summary>
    /// Token-bucket based pacing controller. Tokens are measured in bytes.
    /// </summary>
    /// <summary>
    /// Token-bucket pacing controller. Tokens are measured in bytes and
    /// refilled proportionally to the elapsed time and current pacing rate.
    /// Capacity = rate × bucketDuration / 1s. Provides TryConsume for
    /// non-blocking send eligibility checks and GetWaitTime for delayed flush
    /// scheduling when tokens are insufficient.
    /// </summary>
    internal sealed class PacingController
    {
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
            _minimumPacketCapacityBytes = UcpConstants.DataHeaderSize + Math.Max(1, config.MaxPayloadSize);
            _maxPacingRateBytesPerSecond = config.MaxPacingRateBytesPerSecond;
            _minPacingIntervalMicros = config.MinPacingIntervalMicros;
            _bucketDurationMicros = config.PacingBucketDurationMicros <= 0 ? UcpConstants.DEFAULT_PACING_BUCKET_DURATION_MICROS : config.PacingBucketDurationMicros;
            SetRate(initialRateBytesPerSecond, 0);
            _tokens = _capacity;
        }

        public void SetRate(double rateBytesPerSecond, long nowMicros)
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

        public bool TryConsume(int bytes, long nowMicros)
        {
            Refill(nowMicros);
            if (_tokens >= bytes)
            {
                _tokens -= bytes;
                return true;
            }

            return false;
        }

        public long GetWaitTimeMicros(int bytes, long nowMicros)
        {
            Refill(nowMicros);
            if (_tokens >= bytes)
            {
                return 0;
            }

            if (PacingRateBytesPerSecond <= 0)
            {
                return UcpConstants.DEFAULT_PACING_WAIT_MICROS;
            }

            double deficit = bytes - _tokens;
            long waitMicros = (long)Math.Ceiling((deficit / PacingRateBytesPerSecond) * UcpConstants.MICROS_PER_SECOND);
            if (_minPacingIntervalMicros > 0 && waitMicros < _minPacingIntervalMicros)
            {
                return _minPacingIntervalMicros;
            }

            return waitMicros;
        }

        private void Refill(long nowMicros)
        {
            if (_lastRefillMicros == 0)
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
