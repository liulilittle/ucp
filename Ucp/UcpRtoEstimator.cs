using System;

namespace Ucp
{
    /// <summary>
    /// RFC6298-style RTO estimator with a configurable default 1.5x backoff factor.
    /// </summary>
    /// <summary>
    /// RFC 6298 style RTO estimator with configurable min/max bounds,
    /// exponential backoff, and Karn-style sample protection during recovery.
    /// Uses SRTT + 4*RTTVAR with 1/8 and 1/4 smoothing weights respectively.
    /// </summary>
    internal sealed class UcpRtoEstimator
    {
        private readonly long _minRtoMicros;
        private readonly long _maxRtoMicros;
        private readonly double _backoffFactor;

        public long SmoothedRttMicros { get; private set; }

        public long RttVarianceMicros { get; private set; }

        public long CurrentRtoMicros { get; private set; }

        public UcpRtoEstimator()
            : this(new UcpConfiguration())
        {
        }

        public UcpRtoEstimator(UcpConfiguration config)
        {
            config = config ?? new UcpConfiguration();
            _minRtoMicros = config.EffectiveMinRtoMicros;
            _maxRtoMicros = config.EffectiveMaxRtoMicros;
            _backoffFactor = config.EffectiveRetransmitBackoffFactor;
            CurrentRtoMicros = Math.Max(_minRtoMicros, UcpConstants.INITIAL_RTO_MICROS);
        }

        public void Update(long sampleMicros)
        {
            if (sampleMicros <= 0)
            {
                return;
            }

            if (SmoothedRttMicros == 0)
            {
                SmoothedRttMicros = sampleMicros;
                RttVarianceMicros = sampleMicros / UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER;
            }
            else
            {
                long delta = Math.Abs(SmoothedRttMicros - sampleMicros);
                RttVarianceMicros = ((RttVarianceMicros * UcpConstants.RTT_VAR_PREVIOUS_WEIGHT) + delta) / UcpConstants.RTT_VAR_DENOM;
                SmoothedRttMicros = ((SmoothedRttMicros * UcpConstants.RTT_SMOOTHING_PREVIOUS_WEIGHT) + sampleMicros) / UcpConstants.RTT_SMOOTHING_DENOM;
            }

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
