using System;

namespace Ucp
{
    /// <summary>
    /// RFC 6298 style RTO estimator with configurable min/max bounds,
    /// exponential backoff, and Karn-style sample protection during recovery.
    /// Uses SRTT + 4*RTTVAR with 1/8 and 1/4 smoothing weights respectively.
    /// </summary>
    internal sealed class UcpRtoEstimator
    {
        /// <summary>Minimum RTO floor derived from configuration.</summary>
        private readonly long _minRtoMicros;

        /// <summary>Maximum RTO ceiling derived from configuration.</summary>
        private readonly long _maxRtoMicros;

        /// <summary>Exponential backoff multiplier applied on each Backoff() call.</summary>
        private readonly double _backoffFactor;

        /// <summary>Smoothed round-trip time in microseconds (SRTT).</summary>
        public long SmoothedRttMicros { get; private set; }

        /// <summary>RTT variance estimate in microseconds (RTTVAR).</summary>
        public long RttVarianceMicros { get; private set; }

        /// <summary>Current retransmission timeout value in microseconds.</summary>
        public long CurrentRtoMicros { get; private set; }

        /// <summary>
        /// Creates a new RTO estimator with default configuration values.
        /// </summary>
        public UcpRtoEstimator()
            : this(new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a new RTO estimator initialized from the given configuration.
        /// </summary>
        /// <param name="config">Configuration providing min/max RTO and backoff factor.</param>
        public UcpRtoEstimator(UcpConfiguration config)
        {
            config = config ?? new UcpConfiguration();
            _minRtoMicros = config.EffectiveMinRtoMicros;
            _maxRtoMicros = config.EffectiveMaxRtoMicros;
            _backoffFactor = config.EffectiveRetransmitBackoffFactor;
            CurrentRtoMicros = Math.Max(_minRtoMicros, UcpConstants.INITIAL_RTO_MICROS);
        }

        /// <summary>
        /// Updates the RTO estimate with a new RTT sample following RFC 6298.
        /// On first sample, initializes SRTT and RTTVAR directly.
        /// </summary>
        /// <param name="sampleMicros">New RTT sample in microseconds.</param>
        public void Update(long sampleMicros)
        {
            if (sampleMicros <= 0)
            {
                return;
            }

            if (SmoothedRttMicros == 0)
            {
                // First sample: initialize SRTT and RTTVAR directly.
                SmoothedRttMicros = sampleMicros;
                RttVarianceMicros = sampleMicros / UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER;
            }
            else
            {
                // Apply EWMA smoothing: SRTT = 7/8*SRTT + 1/8*sample, RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - sample|.
                long delta = Math.Abs(SmoothedRttMicros - sampleMicros);
                RttVarianceMicros = ((RttVarianceMicros * UcpConstants.RTT_VAR_PREVIOUS_WEIGHT) + delta) / UcpConstants.RTT_VAR_DENOM;
                SmoothedRttMicros = ((SmoothedRttMicros * UcpConstants.RTT_SMOOTHING_PREVIOUS_WEIGHT) + sampleMicros) / UcpConstants.RTT_SMOOTHING_DENOM;
            }

            // Compute RTO = SRTT + 4*RTTVAR, clamped to [minRto, maxRto].
            long candidate = SmoothedRttMicros + (UcpConstants.RTO_GAIN_MULTIPLIER * RttVarianceMicros);
            if (candidate < _minRtoMicros)
            {
                candidate = _minRtoMicros;
            }

            if (candidate > _maxRtoMicros)
            {
                candidate = _maxRtoMicros;
            }

            CurrentRtoMicros = candidate;
        }

        /// <summary>
        /// Applies exponential backoff to the current RTO, used on consecutive
        /// retransmission timeouts. The backoff is bounded by the min-RTO
        /// multiplier and max-RTO ceiling.
        /// </summary>
        public void Backoff()
        {
            double backedOff = CurrentRtoMicros * _backoffFactor;
            double maxBackoff = Math.Max(CurrentRtoMicros, _minRtoMicros * UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER);
            if (backedOff > maxBackoff)
            {
                backedOff = maxBackoff;
            }

            if (backedOff > _maxRtoMicros)
            {
                backedOff = _maxRtoMicros;
            }

            CurrentRtoMicros = (long)backedOff;
        }
    }
}
