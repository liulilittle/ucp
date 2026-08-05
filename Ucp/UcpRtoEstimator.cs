using System;

namespace Ucp
{

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

            if (0 == SmoothedRttMicros)
            {

                SmoothedRttMicros = sampleMicros;
                RttVarianceMicros = sampleMicros / UcpConstants.UCP_INITIAL_RTTVAR_DIVISOR;
            }
            else
            {

                long delta = SmoothedRttMicros > sampleMicros ? SmoothedRttMicros - sampleMicros : sampleMicros - SmoothedRttMicros;
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
            double minBackoff = Math.Max(CurrentRtoMicros, _minRtoMicros * UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER);
            if (backedOff < minBackoff)
            {
                backedOff = minBackoff;
            }

            if (backedOff > _maxRtoMicros)
            {
                backedOff = _maxRtoMicros;
            }

            CurrentRtoMicros = (long)backedOff;
        }
    }
}
