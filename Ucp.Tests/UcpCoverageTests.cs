using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Ucp;
using Ucp.Internal;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpCoverageTests
    {
        private readonly ITestOutputHelper _output;
        public UcpCoverageTests(ITestOutputHelper output) { _output = output; }

        [Fact]
        public void UcpSequenceComparer_ExhaustiveEdgeCases()
        {
            uint maxVal = uint.MaxValue;
            uint half = 0x80000000U;
            uint zero = 0;

            Assert.True(UcpSequenceComparer.IsAfter(zero, maxVal));
            Assert.True(UcpSequenceComparer.IsBefore(maxVal, zero));
            Assert.Equal(1, UcpSequenceComparer.Instance.Compare(zero, maxVal));
            Assert.Equal(-1, UcpSequenceComparer.Instance.Compare(maxVal, zero));
            Assert.Equal(0, UcpSequenceComparer.Instance.Compare(zero, zero));
            Assert.Equal(0, UcpSequenceComparer.Instance.Compare(maxVal, maxVal));
            Assert.True(UcpSequenceComparer.IsAfter(maxVal, half));
            Assert.True(UcpSequenceComparer.IsBefore(half, maxVal));
        }

        [Fact]
        public void RtoEstimator_DefaultConstructorIsValid()
        {
            var config = new UcpConfiguration();
            var est = new UcpRtoEstimator(config);
            Assert.True(est.CurrentRtoMicros > 0);
            Assert.True(est.SmoothedRttMicros >= 0);
            Assert.True(est.RttVarianceMicros >= 0);
        }

        [Fact]
        public void PacingController_ZeroRateDoesNotCrash()
        {
            var config = new UcpConfiguration();
            var controller = new PacingController(config, 0);
            controller.SetRate(0, 0);
            int cap = config.Mss + config.MaxPayloadSize + 20;
            while (controller.TryConsume(cap, 0)) { }
            Assert.True(controller.GetWaitTimeMicros(cap, 0) > 0);
        }

        [Fact]
        public void Geodesic_JitterEwmaTracksTrueNoise()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long baseRtt = 50000;

            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, baseRtt, 24000);
                now += baseRtt;
            }
            long jitterBefore = cc.GeodesicJitterEwma;

            var rng = new Random(42);
            for (int i = 0; i < 30; i++)
            {
                long noise = rng.Next(-5000, 5001);
                cc.OnAck(now, 24000, baseRtt + noise, 24000);
                now += baseRtt;
            }
            Assert.True(cc.GeodesicJitterEwma > jitterBefore,
                $"jitter EWMA should track injected noise: after={cc.GeodesicJitterEwma} before={jitterBefore}");
        }

        [Fact]
        public void Geodesic_OutlierRejection_DoesNotDiverge()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 25000;

            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long xEstBefore = cc.GeodesicXEst;
            cc.OnAck(now, 24000, rttUs * 10, 24000);
            long xEstAfter = cc.GeodesicXEst;
            Assert.True(xEstAfter >= xEstBefore * 80 / 100);
        }

        [Fact]
        public void EcnEwma_DecaysWhenNoCeMarks()
        {
            var config = new UcpConfiguration();
            config.EcnEnabled = true;
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;

            cc.OnCeMark(100);
            cc.OnAck(now, 24000, 50000, 24000);
            long ecnAfterMark = cc.EcnEwmaValue;
            Assert.True(ecnAfterMark > 0);

            for (int i = 0; i < 10; i++)
            {
                now += 50000;
                cc.OnAck(now, 24000, 50000, 24000);
            }
            Assert.True(cc.EcnEwmaValue < ecnAfterMark,
                $"ecnEwma should decay: {cc.EcnEwmaValue} >= {ecnAfterMark}");
        }

        [Fact]
        public void Geodesic_G2GrowthCovarianceReset()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;

            cc.OnAck(now, 24000, 10000, 24000);
            now += 10000;
            long baseX = cc.GeodesicXEst;

            // A higher RTT is a positive innovation: G2 grows x_est by at most
            // 12.2% and caps it at the observation (no covariance overshoot).
            cc.OnAck(now, 24000, 15000, 24000);
            long grown = cc.GeodesicXEst;
            long growthBound = baseX + baseX * UcpConstants.UCP_G2_GROWTH_NUM / UcpConstants.UCP_G2_GROWTH_DEN;
            Assert.True(grown > baseX,
                $"x_est should grow on a positive innovation: {grown} <= {baseX}");
            Assert.True(grown <= growthBound,
                $"G2 growth should be bounded by 12.2%: {grown} > {growthBound}");
            Assert.True(grown <= 15000 * 1024,
                $"x_est should be capped at the observation: {grown} > {15000 * 1024}");
        }
    }
}
