using System;

namespace Ucp
{
    /// <summary>
    /// RFC6298-style RTO estimator with a configurable default 1.5x backoff factor.
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
            CurrentRtoMicros = Math.Max(_minRtoMicros, 300000);
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
                RttVarianceMicros = sampleMicros / 2;
            }
            else
            {
                long delta = Math.Abs(SmoothedRttMicros - sampleMicros);
                RttVarianceMicros = ((RttVarianceMicros * 3) + delta) / 4;
                SmoothedRttMicros = ((SmoothedRttMicros * 7) + sampleMicros) / 8;
            }

            long candidate = SmoothedRttMicros + (4 * RttVarianceMicros);
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
            if (backedOff > _maxRtoMicros)
            {
                backedOff = _maxRtoMicros;
            }

            CurrentRtoMicros = (long)backedOff;
        }
    }
}
