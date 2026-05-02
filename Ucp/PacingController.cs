using System;

namespace Ucp
{
    /// <summary>
    /// Token-bucket pacing controller. Tokens are measured in bytes and
    /// refilled proportionally to the elapsed time and current pacing rate.
    /// Capacity = rate × bucketDuration / 1s. Provides TryConsume for
    /// non-blocking send eligibility checks and GetWaitTime for delayed flush
    /// scheduling when tokens are insufficient.
    /// </summary>
    internal sealed class PacingController
    {
        /// <summary>Minimum number of bytes sent in one transmit quantum.</summary>
        private readonly int _sendQuantumBytes;

        /// <summary>Minimum capacity to always allow at least one packet to be sent.</summary>
        private readonly int _minimumPacketCapacityBytes;

        /// <summary>Absolute maximum pacing rate ceiling in bytes per second.</summary>
        private readonly long _maxPacingRateBytesPerSecond;

        /// <summary>Minimum interval between paced sends in microseconds.</summary>
        private readonly long _minPacingIntervalMicros;

        /// <summary>Token bucket refill window duration in microseconds.</summary>
        private readonly long _bucketDurationMicros;

        /// <summary>Current token balance in bytes.</summary>
        private double _tokens;

        /// <summary>Maximum token bucket capacity in bytes.</summary>
        private double _capacity;

        /// <summary>Microsecond timestamp of the last refill operation.</summary>
        private long _lastRefillMicros;

        /// <summary>Current pacing rate in bytes per second.</summary>
        public double PacingRateBytesPerSecond { get; private set; }

        /// <summary>Minimum send quantum in bytes.</summary>
        public int SendQuantumBytes
        {
            get { return _sendQuantumBytes; }
        }

        /// <summary>
        /// Creates a pacing controller with default configuration and the given
        /// initial rate.
        /// </summary>
        /// <param name="initialRateBytesPerSecond">Initial pacing rate in bytes per second.</param>
        public PacingController(double initialRateBytesPerSecond)
            : this(new UcpConfiguration(), initialRateBytesPerSecond)
        {
        }

        /// <summary>
        /// Creates a pacing controller initialized from configuration and an
        /// initial rate. The token bucket starts full.
        /// </summary>
        /// <param name="config">Configuration for quantum, capacity, and clamping.</param>
        /// <param name="initialRateBytesPerSecond">Initial pacing rate in bytes per second.</param>
        public PacingController(UcpConfiguration config, double initialRateBytesPerSecond)
        {
            config = config ?? new UcpConfiguration();
            _sendQuantumBytes = config.SendQuantumBytes > 0 ? config.SendQuantumBytes : config.Mss;
            _minimumPacketCapacityBytes = UcpConstants.DATA_HEADER_SIZE_WITH_ACK + Math.Max(1, config.MaxPayloadSize);
            _maxPacingRateBytesPerSecond = config.MaxPacingRateBytesPerSecond;
            _minPacingIntervalMicros = config.MinPacingIntervalMicros;
            _bucketDurationMicros = config.PacingBucketDurationMicros <= 0 ? UcpConstants.DEFAULT_PACING_BUCKET_DURATION_MICROS : config.PacingBucketDurationMicros;
            SetRate(initialRateBytesPerSecond, 0);
            _tokens = _capacity; // Start with a full bucket.
        }

        /// <summary>
        /// Updates the pacing rate and recalculates the token bucket capacity.
        /// Clamps the rate to the configured maximum and ensures the bucket
        /// capacity is at least sufficient for one packet.
        /// </summary>
        /// <param name="rateBytesPerSecond">New pacing rate in bytes per second.</param>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        public void SetRate(double rateBytesPerSecond, long nowMicros)
        {
            if (rateBytesPerSecond <= 0)
            {
                rateBytesPerSecond = _sendQuantumBytes; // Floor: one quantum per second.
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
                _tokens = _capacity; // Don't retain tokens above the new capacity.
            }

            _lastRefillMicros = nowMicros;
        }

        /// <summary>
        /// Attempts to consume the given number of bytes from the token bucket.
        /// Returns true if sufficient tokens were available; false otherwise.
        /// </summary>
        /// <param name="bytes">Number of bytes to consume.</param>
        /// <param name="nowMicros">Current timestamp for refill calculation.</param>
        /// <returns>True if tokens were consumed successfully.</returns>
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

        /// <summary>
        /// Charges bytes immediately even when the token bucket is empty.
        /// This is used only for urgent recovery retransmits where waiting for
        /// smooth pacing can cause the connection to time out. The negative token
        /// balance is bounded by one bucket so later sends repay the burst as debt.
        /// </summary>
        /// <param name="bytes">Number of bytes to force-consume.</param>
        /// <param name="nowMicros">Current timestamp for refill calculation.</param>
        public void ForceConsume(int bytes, long nowMicros)
        {
            Refill(nowMicros);
            if (_tokens > 0)
            {
                _tokens = 0;
            }
        }

        /// <summary>
        /// Estimates the wait time in microseconds until enough tokens are available
        /// to send the given number of bytes.
        /// </summary>
        /// <param name="bytes">Number of bytes to send.</param>
        /// <param name="nowMicros">Current timestamp for refill calculation.</param>
        /// <returns>Wait time in microseconds; 0 if tokens are already sufficient.</returns>
        public long GetWaitTimeMicros(int bytes, long nowMicros)
        {
            Refill(nowMicros);
            if (_tokens >= bytes)
            {
                return 0;
            }

            if (PacingRateBytesPerSecond <= 0)
            {
                return UcpConstants.DEFAULT_PACING_WAIT_MICROS; // Fallback wait time.
            }

            double deficit = bytes - _tokens;
            long waitMicros = (long)Math.Ceiling((deficit / PacingRateBytesPerSecond) * UcpConstants.MICROS_PER_SECOND);
            if (_minPacingIntervalMicros > 0 && waitMicros < _minPacingIntervalMicros)
            {
                return _minPacingIntervalMicros; // Respect minimum pacing interval.
            }

            return waitMicros;
        }

        /// <summary>
        /// Refills the token bucket proportionally to the time elapsed since
        /// the last refill at the current pacing rate.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
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

            // Add tokens: rate (bytes/sec) * elapsed (sec).
            _tokens += (elapsedMicros / (double)UcpConstants.MICROS_PER_SECOND) * PacingRateBytesPerSecond;
            if (_tokens > _capacity)
            {
                _tokens = _capacity; // Cap at bucket capacity.
            }

            _lastRefillMicros = nowMicros;
        }
    }
}
