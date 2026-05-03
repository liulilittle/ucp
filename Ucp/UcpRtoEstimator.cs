using System; // Provides Math.Abs/Math.Max for clipping and delta computation

namespace Ucp
{
    /// <summary>
    /// RFC 6298 style RTO estimator with configurable min/max bounds,
    /// exponential backoff, and Karn-style sample protection during recovery.
    /// Uses SRTT + 4*RTTVAR with 1/8 and 1/4 smoothing weights respectively.
    /// This is the core adaptive timer that governs how long the sender waits
    /// before concluding a packet is lost and retransmitting it.
    /// </summary>
    internal sealed class UcpRtoEstimator
    {
        /// <summary>Minimum RTO floor derived from configuration; prevents overly aggressive retransmission.</summary>
        private readonly long _minRtoMicros; // Hard lower bound; RTO will never drop below this regardless of network conditions

        /// <summary>Maximum RTO ceiling derived from configuration; prevents excessively long timeouts.</summary>
        private readonly long _maxRtoMicros; // Hard upper bound; RTO will never exceed this even under extreme backoff

        /// <summary>Exponential backoff multiplier applied on each successive Backoff() call after repeated timeouts.</summary>
        private readonly double _backoffFactor; // Typically 2.0; doubles the RTO on each consecutive unacknowledged retransmission

        /// <summary>Smoothed round-trip time in microseconds (SRTT), an EWMA of recent RTT samples.</summary>
        public long SmoothedRttMicros { get; private set; } // Exponentially weighted moving average of valid RTT measurements

        /// <summary>RTT variance estimate in microseconds (RTTVAR), tracking deviation of samples from SRTT.</summary>
        public long RttVarianceMicros { get; private set; } // EWMA of the absolute difference between samples and SRTT

        /// <summary>Current retransmission timeout value in microseconds; the timer duration used by the connection.</summary>
        public long CurrentRtoMicros { get; private set; } // Computed as SRTT + 4*RTTVAR, then clamped to [minRto, maxRto]

        /// <summary>
        /// Creates a new RTO estimator with default configuration values.
        /// Uses UcpConfiguration defaults for min/max RTO and backoff factor.
        /// This parameterless constructor is convenient for simple usage scenarios.
        /// </summary>
        public UcpRtoEstimator()
            : this(new UcpConfiguration()) // Delegate to the config-based constructor with default settings
        {
        }

        /// <summary>
        /// Creates a new RTO estimator initialized from the given configuration.
        /// Extracts the effective (clamped) min/max RTO bounds and the exponential
        /// backoff multiplier, then sets the initial RTO to the larger of the min
        /// RTO and the protocol's defined initial RTO constant.
        /// </summary>
        /// <param name="config">Configuration providing min/max RTO and backoff factor.</param>
        public UcpRtoEstimator(UcpConfiguration config)
        {
            config = config ?? new UcpConfiguration(); // Defensive fallback: use defaults if null is passed
            _minRtoMicros = config.EffectiveMinRtoMicros; // Cache the clamped minimum RTO for fast access in Update/Backoff
            _maxRtoMicros = config.EffectiveMaxRtoMicros; // Cache the clamped maximum RTO for fast access in Update/Backoff
            _backoffFactor = config.EffectiveRetransmitBackoffFactor; // Cache the backoff multiplier (typically 2.0)
            CurrentRtoMicros = Math.Max(_minRtoMicros, UcpConstants.INITIAL_RTO_MICROS); // Set initial RTO at the larger of min-bound and protocol default
        }

        /// <summary>
        /// Updates the RTO estimate with a new RTT sample following RFC 6298.
        /// On the first valid sample, initializes SRTT to the sample and RTTVAR
        /// to half the sample. On subsequent samples, applies the EWMA smoothing
        /// formulas with 1/8 and 1/4 weights. The RTO is computed as SRTT + 4*RTTVAR
        /// and clamped to the configured [minRto, maxRto] range.
        /// This method should be called once per measured RTT sample, excluding
        /// samples measured during retransmission (Karn's algorithm).
        /// </summary>
        /// <param name="sampleMicros">New RTT sample in microseconds from a non-retransmitted packet acknowledgment.</param>
        public void Update(long sampleMicros)
        {
            if (sampleMicros <= 0) // Reject invalid, zero, or negative samples that would corrupt the estimator
            {
                return; // Silently ignore invalid input; caller may inadvertently pass uninitialized timestamps
            }

            if (SmoothedRttMicros == 0) // No previous sample exists; this is the first valid RTT measurement
            {
                // First sample: initialize SRTT and RTTVAR directly per RFC 6298.
                SmoothedRttMicros = sampleMicros; // Bootstrap SRTT to the first measured value
                RttVarianceMicros = sampleMicros / UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER; // Initialize RTTVAR to half the first sample (2 = divisor)
            }
            else
            {
                // Apply EWMA smoothing: SRTT = 7/8*SRTT + 1/8*sample, RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - sample|.
                long delta = Math.Abs(SmoothedRttMicros - sampleMicros); // Absolute prediction error for variance update
                RttVarianceMicros = ((RttVarianceMicros * UcpConstants.RTT_VAR_PREVIOUS_WEIGHT) + delta) / UcpConstants.RTT_VAR_DENOM; // RTTVAR = (3*RTTVAR + |error|)/4
                SmoothedRttMicros = ((SmoothedRttMicros * UcpConstants.RTT_SMOOTHING_PREVIOUS_WEIGHT) + sampleMicros) / UcpConstants.RTT_SMOOTHING_DENOM; // SRTT = (7*SRTT + sample)/8
            }

            // Compute RTO = SRTT + 4*RTTVAR, clamped to [minRto, maxRto].
            long candidate = SmoothedRttMicros + (UcpConstants.RTO_GAIN_MULTIPLIER * RttVarianceMicros); // RFC 6298: RTO = SRTT + max(G, 4*RTTVAR) where G is typically the clock granularity
            if (candidate < _minRtoMicros) // Enforce the minimum RTO floor from configuration
            {
                candidate = _minRtoMicros; // Floor clamping: RTO must not be too small to avoid spurious timeouts
            }

            if (candidate > _maxRtoMicros) // Enforce the maximum RTO ceiling from configuration
            {
                candidate = _maxRtoMicros; // Ceiling clamping: RTO must not grow unboundedly, ensuring timely recovery
            }

            CurrentRtoMicros = candidate; // Commit the computed and clamped RTO value for use by the retransmission timer
        }

        /// <summary>
        /// Applies exponential backoff to the current RTO, used on consecutive
        /// retransmission timeouts (i.e., when a retransmitted packet itself
        /// times out). The backoff is multiplied by the configured backoff factor,
        /// then bounded by the max-backoff-min-RTO product and the max-RTO ceiling.
        /// This implements the classic exponential backoff strategy to avoid
        /// congestive collapse when the network is heavily loaded.
        /// </summary>
        public void Backoff()
        {
            double backedOff = CurrentRtoMicros * _backoffFactor; // Multiply current RTO by the exponential backoff factor (typically 2x)
            double maxBackoff = Math.Max(CurrentRtoMicros, _minRtoMicros * UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER); // Lower-bound the backoff at max(current, minRto*multiplier) to avoid tiny backoff values
            if (backedOff > maxBackoff) // Cap the backed-off value at the computed lower-bound maximum
            {
                backedOff = maxBackoff; // Apply the max backoff cap; prevents unbounded growth beyond a sane limit
            }

            if (backedOff > _maxRtoMicros) // Enforce the absolute maximum RTO ceiling from configuration
            {
                backedOff = _maxRtoMicros; // Hard ceiling to prevent the RTO from blocking the connection indefinitely
            }

            CurrentRtoMicros = (long)backedOff; // Cast back to long and commit the backed-off RTO value
        }
    }
}
