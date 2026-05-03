using System; // Provides Math.Max, Math.Ceiling for capacity clamping and wait time computation

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
        private readonly int _sendQuantumBytes; // Smallest batch size the sender will emit; derived from config or MSS

        /// <summary>Minimum capacity to always allow at least one packet to be sent.</summary>
        private readonly int _minimumPacketCapacityBytes; // Ensures the bucket can hold at least one full packet even at the lowest rate

        /// <summary>Absolute maximum pacing rate ceiling in bytes per second.</summary>
        private readonly long _maxPacingRateBytesPerSecond; // Hard ceiling from config; SetRate clamps the rate to this value

        /// <summary>Minimum interval between paced sends in microseconds.</summary>
        private readonly long _minPacingIntervalMicros; // Prevents bursty micro-sends; wait times are floored at this interval

        /// <summary>Token bucket refill window duration in microseconds.</summary>
        private readonly long _bucketDurationMicros; // Controls bucket depth: larger window → larger capacity → smoother pacing

        /// <summary>Current token balance in bytes.</summary>
        private double _tokens; // Tracks available sending budget; decremented on consume, incremented on refill

        /// <summary>Maximum token bucket capacity in bytes.</summary>
        private double _capacity; // Ceiling for token accumulation; prevents sending huge bursts after idle periods

        /// <summary>Microsecond timestamp of the last refill operation.</summary>
        private long _lastRefillMicros; // Used to compute elapsed time since last refill for proportional token addition

        /// <summary>Current pacing rate in bytes per second.</summary>
        public double PacingRateBytesPerSecond { get; private set; } // Exposed for diagnostics; updated via SetRate, clamped by config

        /// <summary>Minimum send quantum in bytes.</summary>
        public int SendQuantumBytes
        {
            get { return _sendQuantumBytes; } // Simple pass-through to the backing readonly field for external read access
        }

        /// <summary>
        /// Creates a pacing controller with default configuration and the given
        /// initial rate.
        /// </summary>
        /// <param name="initialRateBytesPerSecond">Initial pacing rate in bytes per second.</param>
        public PacingController(double initialRateBytesPerSecond)
            : this(new UcpConfiguration(), initialRateBytesPerSecond) // Delegate to the config-based constructor with default settings
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
            config = config ?? new UcpConfiguration(); // Defensive fallback: use defaults if null is passed
            _sendQuantumBytes = config.SendQuantumBytes > 0 ? config.SendQuantumBytes : config.Mss; // Use configured quantum or fall back to MSS as a sensible one-packet batch size
            _minimumPacketCapacityBytes = UcpConstants.DATA_HEADER_SIZE_WITH_ACK + Math.Max(1, config.MaxPayloadSize); // Calculate the minimum bytes for one full packet (header + payload)
            _maxPacingRateBytesPerSecond = config.MaxPacingRateBytesPerSecond; // Cache the absolute maximum rate ceiling for fast clamping in SetRate
            _minPacingIntervalMicros = config.MinPacingIntervalMicros; // Cache the minimum inter-send gap to avoid timer granularity issues
            _bucketDurationMicros = config.PacingBucketDurationMicros <= 0 ? UcpConstants.DEFAULT_PACING_BUCKET_DURATION_MICROS : config.PacingBucketDurationMicros; // Use configured bucket window or protocol default if zero/negative
            SetRate(initialRateBytesPerSecond, 0); // Apply the initial rate and pre-fill the bucket at time zero
            _tokens = _capacity; // Start with a full bucket so the first send is immediately eligible
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
            if (rateBytesPerSecond <= 0) // Guard against zero or negative rate that would break refill and wait-time math
            {
                rateBytesPerSecond = _sendQuantumBytes; // Floor: one quantum per second ensures the bucket still refills slowly
            }

            if (_maxPacingRateBytesPerSecond > 0 && rateBytesPerSecond > _maxPacingRateBytesPerSecond) // Check if the requested rate exceeds the configured ceiling
            {
                rateBytesPerSecond = _maxPacingRateBytesPerSecond; // Clamp to the maximum allowed rate to prevent excessive send bursts
            }

            Refill(nowMicros); // Refill tokens based on elapsed time at the current (old) rate before switching to the new rate
            PacingRateBytesPerSecond = rateBytesPerSecond; // Commit the new pacing rate for subsequent refills and wait-time calculations
            _capacity = Math.Max(Math.Max(_sendQuantumBytes, _minimumPacketCapacityBytes), rateBytesPerSecond * _bucketDurationMicros / UcpConstants.MICROS_PER_SECOND); // Recalculate bucket capacity from new rate, floored at one-packet size
            if (_tokens > _capacity) // If the old bucket had more tokens than the new smaller capacity allows
            {
                _tokens = _capacity; // Don't retain tokens above the new capacity; prevents surplus from being carried forward
            }

            _lastRefillMicros = nowMicros; // Reset the refill timestamp so future refills are measured from this rate change point
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
            Refill(nowMicros); // Add tokens proportional to elapsed time before checking balance
            if (_tokens >= bytes) // Check if the bucket has enough tokens to cover the requested byte count
            {
                _tokens -= bytes; // Deduct the consumed bytes from the token balance
                return true; // Signal that the send is eligible and tokens were consumed
            }

            return false; // Insufficient tokens; the caller should defer this send or use ForceConsume
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
            Refill(nowMicros); // Add tokens proportional to elapsed time before draining
            if (_tokens > 0) // If there are any positive tokens available in the bucket
            {
                _tokens = 0; // Drain tokens to zero so the next regular send is blocked until refill; this creates temporary backpressure after a forced urgent send
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
            Refill(nowMicros); // Add tokens proportional to elapsed time before checking balance
            if (_tokens >= bytes) // If the bucket already has enough tokens to cover the requested bytes
            {
                return 0; // No wait needed; the send can proceed immediately
            }

            if (PacingRateBytesPerSecond <= 0) // Guard against zero pacing rate which would cause division by zero
            {
                return UcpConstants.DEFAULT_PACING_WAIT_MICROS; // Fallback wait time when the rate is undefined or stopped
            }

            double deficit = bytes - _tokens; // Calculate how many tokens we are short of the required amount
            long waitMicros = (long)Math.Ceiling((deficit / PacingRateBytesPerSecond) * UcpConstants.MICROS_PER_SECOND); // Convert byte deficit to seconds of refill time, then to microseconds, rounding up
            if (_minPacingIntervalMicros > 0 && waitMicros < _minPacingIntervalMicros) // If the computed wait is shorter than the minimum pacing interval
            {
                return _minPacingIntervalMicros; // Respect minimum pacing interval to avoid excessive CPU churn from tiny waits
            }

            return waitMicros; // Return the estimated wait time in microseconds
        }

        /// <summary>
        /// Refills the token bucket proportionally to the time elapsed since
        /// the last refill at the current pacing rate.
        /// </summary>
        /// <param name="nowMicros">Current timestamp in microseconds.</param>
        private void Refill(long nowMicros)
        {
            if (_lastRefillMicros == 0) // First-ever refill call; no elapsed time to compute yet
            {
                _lastRefillMicros = nowMicros; // Initialize the timestamp so the next refill computes actual elapsed time
                return; // Exit early; no tokens to add on the very first call
            }

            long elapsedMicros = nowMicros - _lastRefillMicros; // Compute how many microseconds have passed since the last refill
            if (elapsedMicros <= 0) // Guard against non-monotonic clock or same-timestamp duplicate calls
            {
                return; // No time has elapsed; skip refill to avoid zero or negative token additions
            }

            // Add tokens: rate (bytes/sec) * elapsed (sec).
            _tokens += (elapsedMicros / (double)UcpConstants.MICROS_PER_SECOND) * PacingRateBytesPerSecond; // Add tokens = elapsed seconds × bytes per second; floating point for fractional precision
            if (_tokens > _capacity) // Check if the token balance exceeds the bucket capacity ceiling
            {
                _tokens = _capacity; // Cap at bucket capacity to prevent unlimited token accumulation during idle periods
            }

            _lastRefillMicros = nowMicros; // Update the last refill timestamp for the next refill calculation
        }
    }
}
