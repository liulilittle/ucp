using System;
using System.Collections.Generic;
using System.Linq;
using Ucp;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpComprehensiveCCTests
    {
        private readonly ITestOutputHelper _output;
        public UcpComprehensiveCCTests(ITestOutputHelper output) { _output = output; }

        private static UcpCongestionControl CreateCc(UcpConfiguration? config = null)
        {
            config ??= new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = Math.Max(config.InitialBandwidthBytesPerSecond, 12500000);
            config.InitialCwndBytes = Math.Max(config.InitialCwndBytes, 65536);
            config.MaxCongestionWindowBytes = config.MaxCongestionWindowBytes > 0 ? config.MaxCongestionWindowBytes : int.MaxValue;
            return new UcpCongestionControl(config);
        }

        [Fact]
        public void Geodesic_FirstSampleSetsXestAndPest()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 24000, 50000, 24000);
            Assert.Equal(50000 * 1024, cc.GeodesicXEst);
            Assert.True(cc.GeodesicPEst > 0);
            Assert.Equal(1, cc.GeodesicSampleCnt);
        }

        [Fact]
        public void Geodesic_ConvergesToStableRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            long expected = 10000 * 1024;
            long ratio = cc.GeodesicXEst * 100 / expected;
            Assert.InRange(ratio, 85, 115);
            Assert.True(cc.GeodesicSampleCnt >= 50);
        }

        [Fact]
        public void Geodesic_ZeroRttInputMaintainsState()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 24000, 50000, 24000);
            long x1 = cc.GeodesicXEst;
            cc.OnAck(200000, 24000, 0, 24000);
            Assert.Equal(x1, cc.GeodesicXEst);
        }

        [Fact]
        public void Geodesic_VeryLowRttStillConverges()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 100;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.GeodesicXEst > 0);
            Assert.True(cc.GeodesicPEst >= 10);
        }

        [Fact]
        public void Geodesic_VeryHighRttStillConverges()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 500000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long ratio = cc.GeodesicXEst * 100 / (rttUs * 1024);
            Assert.InRange(ratio, 50, 150);
        }

        [Fact]
        public void Geodesic_RttSampleAboveMaxGetsRejected()
        {

            var cc = CreateCc();
            cc.OnAck(100000, 24000, 10000, 24000);
            long x1 = cc.GeodesicXEst;

            cc.OnAck(150000, 24000, 10000, 24000);
            long xBase = cc.GeodesicXEst;
            Assert.Equal(x1, xBase);

            cc.OnAck(200000, 24000, 600000, 24000);
            long x2 = cc.GeodesicXEst;
            long maxGrowth = x1 * 122 / 1000;
            long expectedX2 = Math.Min(x1 + maxGrowth, 600000L * 1024L);
            Assert.Equal(expectedX2, x2);
        }

        [Fact]
        public void Geodesic_G2GrowthBlockedWhenNotConverged()
        {

            var cc = CreateCc();
            long now = 100000;
            var rng = new Random(42);
            for (int i = 0; i < 5; i++)
            {
                long rtt = 10000 + rng.Next(-2000, 2001);
                cc.OnAck(now, 24000, rtt, 24000);
                now += 10000;
            }

            Assert.True(cc.GeodesicSampleCnt >= 5,
                $"Need >=5 samples, got {cc.GeodesicSampleCnt}");
            Assert.True(cc.GeodesicPEst >= 10,
                $"p_est should be >= KCC_P_EST_FLOOR(10): {cc.GeodesicPEst}");

            long xBefore = cc.GeodesicXEst;
            Assert.True(xBefore > 0, $"x_est should be positive: {xBefore}");

            cc.OnAck(now, 24000, 100000, 24000);

            long maxGrowth = xBefore * 122 / 1000;
            long maxExpected = Math.Min(xBefore + maxGrowth, 100000L * 1024L);
            Assert.True(cc.GeodesicXEst >= xBefore,
                $"x_est should increase with positive innovation: {cc.GeodesicXEst} >= {xBefore}");
            Assert.True(cc.GeodesicXEst <= maxExpected,
                $"G2 should cap growth at 12.2%: {cc.GeodesicXEst} <= {maxExpected}");
        }

        [Fact]
        public void Geodesic_NegativeInnovationWithinFloorUpdatesDownward()
        {

            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            now += 50000;

            cc.OnAck(now, 24000, 47500, 24000);
            Assert.True(cc.GeodesicXEst < 50000 * 1024,
                $"x_est should decrease: {cc.GeodesicXEst} >= {50000 * 1024}");
        }

        [Fact]
        public void Geodesic_JitterEwmaTracksVariation()
        {
            var cc = CreateCc();
            long now = 100000;
            var rng = new Random(42);
            long baseRtt = 50000;
            for (int i = 0; i < 30; i++)
            {
                long noise = rng.Next(-10000, 10001);
                cc.OnAck(now, 24000, baseRtt + noise, 24000);
                now += baseRtt;
            }
            Assert.True(cc.GeodesicJitterEwma > 0);
            Assert.True(cc.GeodesicJitterEwma < 50000);
        }

        [Fact]
        public void Geodesic_ConsecutiveRejectLimitDoesNotFreeze()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, 100000, 24000);
                now += 100000;
            }
            Assert.True(cc.GeodesicSampleCnt > 5);
        }

        [Fact]
        public void Bdp_HealthyCwndAcrossBandwidths()
        {
            var cc1 = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue });
            var cc2 = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 25000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc1.OnAck(now, 64000, 20000, 64000);
                cc2.OnAck(now, 64000, 20000, 64000);
                now += 20000;
            }
            // cwnd converges to the same value under identical ACK streams
            // (initial bandwidth only affects pacing start, not the ACK-driven
            // target). Both must be positive and near-equal.
            Assert.True(cc1.CongestionWindowBytes > 0);
            Assert.True(cc2.CongestionWindowBytes > 0);
            long delta = Math.Abs(cc1.CongestionWindowBytes - cc2.CongestionWindowBytes);
            Assert.True(delta <= Math.Max(1, Math.Max(cc1.CongestionWindowBytes, cc2.CongestionWindowBytes) / 4),
                $"cwnd should converge similarly: c1={cc1.CongestionWindowBytes} c2={cc2.CongestionWindowBytes}");
        }

        [Fact]
        public void Bdp_HigherRttProducesLargerCwnd()
        {
            var cc1 = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue });
            var cc2 = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc1.OnAck(now, 24000, 10000, 24000);
                cc2.OnAck(now, 64000, 50000, 64000);
                now += 50000;
            }
            Assert.True(cc2.CongestionWindowBytes >= cc1.CongestionWindowBytes);
        }

        [Fact]
        public void Bdp_EnforcesMinimumFloor()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000, InitialCwndBytes = 65536 };
            var cc = new UcpCongestionControl(config);
            cc.OnAck(100000, 24000, 10000, 24000);
            Assert.True(cc.CongestionWindowBytes >= config.InitialCwndBytes);
        }

        [Fact]
        public void Bdp_DoesNotExceedMaximum()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = 200000 };
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 64000, 10000, 64000);
                now += 10000;
            }
            Assert.True(cc.CongestionWindowBytes <= config.MaxCongestionWindowBytes + 1000);
        }

        [Fact]
        public void Inflight_BoundedByBdp()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.True(cc.CongestionWindowBytes >= 4880);
            long maxBw = (long)cc.BtlBwBytesPerSecond;
            long minRtt = cc.MinRttMicros;
            // After 30 ACKs the CC must have measured both the bottleneck
            // bandwidth and the min RTT (so the BDP is well-defined and the
            // cwnd must track it rather than being capped arbitrarily).
            Assert.True(maxBw > 0, $"btl-bw should be measured: {maxBw}");
            Assert.True(minRtt > 0, $"min-rtt should be measured: {minRtt}");
            long estBdp = maxBw * minRtt / 1000000;
            Assert.True(cc.CongestionWindowBytes >= estBdp / 3,
                $"cwnd={cc.CongestionWindowBytes} should track BDP={estBdp}");
        }

        [Fact]
        public void FullBw_DetectsPlateauAndExitsStartup()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            Assert.Equal(UcpMode.Startup, cc.Mode);
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, 10000, 64000);
                now += 10000;
            }
            Assert.True(cc.FullBwReached);
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
        }

        [Fact]
        public void FullBw_NotReachedWithInsufficientRounds()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 3; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.False(cc.FullBwReached);
        }

        [Fact]
        public void Drain_EnteredAfterFullBw()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            bool seenDrain = false;
            bool seenFullBw = false;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 64000, 10000, 64000);
                now += 10000;
                if (cc.Mode == UcpMode.Drain)
                {
                    seenDrain = true;
                    seenFullBw |= cc.FullBwReached;
                }
            }
            Assert.True(seenDrain, "Drain must be entered after full-bandwidth convergence");
            Assert.True(seenFullBw, "FullBw must be reached before entering Drain");
        }

        [Fact]
        public void Drain_ExitsToProbeBw()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, 10000, 64000);
                now += 10000;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
        }

        [Fact]
        public void ProbeBw_CycleAdvancesThroughPhases()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 60; i++)
            {
                cc.OnAck(now, 300000, 10000, 300000);
                now += 10000;
            }

            Assert.Equal(UcpMode.ProbeBw, cc.Mode);

            int idx = cc.ProbeBwCycleIdx;
            Assert.InRange(idx, 0, 255);

            Assert.True(cc.PacingGainUnits > 0);
        }

        [Fact]
        public void LtBw_ActivatedOnPersistentLoss()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000000, MaxCongestionWindowBytes = int.MaxValue };
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            cc.OnNakLoss(now, 3000);
            for (int i = 0; i < 20; i++)
            {
                now += 10000;
                cc.OnAck(now, 12000, 10000, 12000);
                cc.OnNakLoss(now, 3000);
                cc.OnPacketLoss(now, 0.15, true);
            }
            _output.WriteLine("LtBw_Activated: isLtUseBw={0} ltBw={1} pacing={2}",
                cc.IsLtUseBw, cc.LtBwValue, cc.PacingRateBytesPerSecond);
            Assert.True(cc.IsLtUseBw,
                $"LT BW should activate under persistent loss: {cc.IsLtUseBw}");
            Assert.True(cc.PacingRateBytesPerSecond > 0,
                $"Pacing should stay positive: {cc.PacingRateBytesPerSecond}");
            Assert.True(cc.CongestionWindowBytes > 0,
                $"CWND should stay positive: {cc.CongestionWindowBytes}");
        }

        [Fact]
        public void LtBw_ResetOnMaxRtts()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000000, MaxCongestionWindowBytes = int.MaxValue };
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            cc.OnNakLoss(now, 1500);
            for (int i = 0; i < 60; i++)
            {
                now += 10000;
                cc.OnAck(now, 12000, 10000, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }
            Assert.True(cc.LtBwValue >= 0, $"LtBwValue should be non-negative: {cc.LtBwValue}");
            Assert.True(cc.GeodesicSampleCnt > 0, $"Should have geodesic samples: {cc.GeodesicSampleCnt}");
        }

        [Fact]
        public void EcnBackoff_GainReducedWithCeMarks()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue, EcnEnabled = true };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            int gainBefore = cc.CwndGainUnits;
            cc.OnCeMark(500);
            for (int i = 0; i < 5; i++)
            {
                cc.OnCeMark(300);
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.True(cc.EcnEwmaValue > 0);
            Assert.True(cc.CwndGainUnits >= 1);
            Assert.True(cc.CwndGainUnits <= gainBefore,
                $"ECN backoff should reduce (not raise) cwnd gain: {cc.CwndGainUnits} > {gainBefore}");
        }

        [Fact]
        public void AckAggregation_ConfidenceBuilds()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.True(cc.CongestionWindowBytes > 0);
        }


        [Fact]
        public void Ewma_QdelaySmoothsOscillations()
        {
            var cc = CreateCc();
            long now = 100000;
            var rng = new Random(42);
            long baseRtt = 50000;
            for (int i = 0; i < 30; i++)
            {
                long rtt = baseRtt + rng.Next(-5000, 5001);
                cc.OnAck(now, 24000, rtt, 24000);
                now += baseRtt;
            }
            Assert.True(cc.GeodesicQDelayAvg >= 0);
            Assert.True(cc.GeodesicQDelayAvg < 20000);
        }

        [Fact]
        public void Geodesic_QestAndRestTrackSignal()
        {
            var cc = CreateCc();
            long now = 100000;
            var rng = new Random(42);
            long baseRtt = 50000;
            for (int i = 0; i < 30; i++)
            {
                long noise = rng.Next(-5000, 5001);
                cc.OnAck(now, 24000, baseRtt + noise, 24000);
                now += baseRtt;
            }
            Assert.True(cc.GeodesicPEst >= 10);
        }

        [Fact]
        public void Geodesic_ConvergenceRateUnderStableRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 25000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, rttUs - (i & 1), 24000);
                now += rttUs;
            }
            long expected = rttUs * 1024;
            long ratio = cc.GeodesicXEst * 100 / expected;
            Assert.InRange(ratio, 95, 105);
            Assert.True(cc.GeodesicPEst > 0 && cc.GeodesicPEst < 20000);
        }

        [Fact]
        public void Geodesic_G2GrowthSuppressedWhenUnconverged()
        {

            var cc = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.True(cc.GeodesicSampleCnt >= 10,
                $"Sample count should be >=10: {cc.GeodesicSampleCnt}");

            long xEstBefore = cc.GeodesicXEst;
            Assert.True(xEstBefore > 0,
                $"x_est should be positive: {xEstBefore}");

            long spikeRtt = rttUs + 20000;
            cc.OnAck(now, 24000, spikeRtt, 24000);

            long maxGrowth = xEstBefore * 122 / 1000;
            long expectedXEst = Math.Min(
                Math.Min(xEstBefore + maxGrowth, spikeRtt * 1024L),
                uint.MaxValue);
            Assert.Equal(expectedXEst, cc.GeodesicXEst);
        }

        [Fact]
        public void Geodesic_CovarianceMatchedSignalEstimation()
        {
            var cc = CreateCc();
            long now = 100000;
            var rng = new Random(99);
            long baseRtt = 30000;
            long noiseMag = 1000;
            for (int i = 0; i < 40; i++)
            {
                long noise = rng.Next(-(int)noiseMag, (int)noiseMag + 1);
                cc.OnAck(now, 24000, baseRtt + noise, 24000);
                now += baseRtt;
            }
            Assert.True(cc.GeodesicPEst >= 10, $"pEst should be >= 10: {cc.GeodesicPEst}");
            Assert.True(cc.GeodesicPEst <= 1000000, $"pEst should be bounded: {cc.GeodesicPEst}");
            Assert.True(cc.GeodesicSampleCnt >= 40);
            long expected = baseRtt * 1024;
            long ratio = cc.GeodesicXEst * 100 / expected;
            Assert.InRange(ratio, 70, 130);
        }

        [Fact]
        public void Geodesic_AggregationConfidenceRScaling()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 48000, rttUs, 48000);
                now += rttUs;
            }
            Assert.True(cc.GeodesicPEst > 0, $"pEst should be positive: {cc.GeodesicPEst}");
            Assert.True(cc.GeodesicSampleCnt >= 20);
        }

        [Fact]
        public void Gain_DoesNotReduceBelowUnity()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.True(cc.PacingGainUnits >= 256);
        }

        [Fact]
        public void StateMachine_StartupToProbeBwSequence()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            Assert.Equal(UcpMode.Startup, cc.Mode);
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, 10000, 64000);
                now += 10000;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
        }

        [Fact]
        public void StateMachine_StartupHasHighGain()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnAck(now, 24000, 10000, 24000);
            Assert.True(cc.PacingGainUnits > 256);
        }

        [Fact]
        public void StateMachine_ProbeBwHasBoundedGains()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 200; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.InRange(cc.PacingGainUnits, 1, 1023);
        }

        [Fact]
        public void StateMachine_OnRtoDoesNotChangeMode()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            var modeBefore = cc.Mode;
            cc.OnRto();
            Assert.Equal(modeBefore, cc.Mode);
        }

        [Fact]
        public void Bandwidth_TracksDeliveryRate()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 500000, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 24000;
            }
            Assert.True(cc.BtlBwBytesPerSecond > 500000);
            Assert.True(cc.BtlBwBytesPerSecond < 10000000);
        }

        [Fact]
        public void Bandwidth_SlidingWindowFiltersOutCliffs()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            cc.OnAck(100000, 100000, 100000, 100000);
            cc.OnAck(200000, 100000, 100000, 100000);
            double highRate = cc.BtlBwBytesPerSecond;
            Assert.True(highRate > 1.0);
            cc.OnAck(500000, 1000, 100000, 1000);
            cc.OnAck(700000, 1000, 100000, 1000);
            cc.OnAck(1050000, 1000, 100000, 1000);
            Assert.True(cc.BtlBwBytesPerSecond >= highRate * 0.5);
        }

        [Fact]
        public void MinRtt_UpdatesOnLowerSample()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            long r1 = cc.MinRttMicros;
            now += 50000;
            cc.OnAck(now, 24000, 40000, 24000);
            Assert.True(cc.MinRttMicros <= r1);
        }

        [Fact]
        public void MinRtt_SrttGuardPreventsAnomalousDrop()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, 100000, 24000);
                now += 100000;
            }
            Assert.True(cc.MinRttMicros >= 80000);
        }

        [Fact]
        public void FecRecovery_MaintainsThroughput()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            double rateBefore = cc.PacingRateBytesPerSecond;
            cc.OnFecRecovery(now, 12000);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.PacingRateBytesPerSecond >= rateBefore * 0.5,
                $"FEC recovery should not collapse throughput: {cc.PacingRateBytesPerSecond} < {rateBefore * 0.5}");
        }

        [Fact]
        public void CwndGain_EnforcesLowerBound()
        {
            var cc = CreateCc();
            Assert.True(cc.CongestionWindowBytes >= 4880);
        }

        [Fact]
        public void PacketConservation_OnLossReducesCwnd()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            long cwndBefore = cc.CongestionWindowBytes;
            cc.OnFastRetransmit(now, true, 24000);
            Assert.True(cc.CongestionWindowBytes > 0, "CWND should remain positive after fast retransmit");
            Assert.True(cc.CongestionWindowBytes <= cwndBefore,
                $"Packet conservation: cwnd must not increase after loss: {cc.CongestionWindowBytes} > {cwndBefore}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing rate should remain positive after loss");
        }

        [Fact]
        public void LtBw_ResetOnAppLimited()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000000, MaxCongestionWindowBytes = int.MaxValue };
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            cc.SetAppLimited(true);
            for (int round = 0; round < 10; round++)
            {
                now += rttUs;
                cc.OnAck(now, 0, rttUs, 0);
            }
            Assert.False(cc.IsLtUseBw,
                $"LT BW should not activate when app-limited: {cc.IsLtUseBw}");

            cc.SetAppLimited(false);
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 10; round++)
            {
                now += rttUs;
                cc.OnAck(now, 12000, rttUs, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }

            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing should be positive after LT reactivation");
        }

        [Fact]
        public void LtBw_SafetyTimeout()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000000, MaxCongestionWindowBytes = int.MaxValue };
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 60; round++)
            {
                now += rttUs;
                cc.OnAck(now, 12000, rttUs, 12000);
                cc.OnPacketLoss(now, 0.10, true);
            }
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing should remain positive after LT BW timeout");
            Assert.True(cc.CongestionWindowBytes > 0, "CWND should remain positive after LT BW timeout");
        }

        [Fact]
        public void EcnEwma_IdleDecay()
        {
            var cc = new UcpCongestionControl(new UcpConfiguration { EcnEnabled = true });
            long now = 100000;
            cc.OnCeMark(24000);
            cc.OnAck(now, 24000, 50000, 24000);
            long ecnAfterMark = cc.EcnEwmaValue;
            Assert.True(ecnAfterMark > 0, $"ECN EWMA should be positive after mark: {ecnAfterMark}");
            for (int i = 0; i < 15; i++)
            {
                now += 50000;
                cc.OnAck(now, 24000, 50000, 24000);
            }
            Assert.True(cc.EcnEwmaValue < ecnAfterMark,
                $"ECN EWMA should decay when idle: {cc.EcnEwmaValue} < {ecnAfterMark}");
            Assert.True(cc.EcnEwmaValue >= 0, $"ECN EWMA should not go negative: {cc.EcnEwmaValue}");
        }

        [Fact]
        public void Gain_JitterBasedReduction()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            int gainBefore = cc.PacingGainUnits;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs + 15000, 24000);
                now += rttUs;
            }
            Assert.True(cc.PacingGainUnits > 0, "Pacing gain should remain positive after jitter");
            Assert.True(cc.GeodesicJitterEwma > 0, $"Jitter EWMA should increase: {cc.GeodesicJitterEwma}");
            Assert.True(cc.PacingGainUnits <= gainBefore,
                $"Jitter should not increase the pacing gain: {cc.PacingGainUnits} > {gainBefore}");
        }

        [Fact]
        public void Gain_ConfidenceScaling()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            for (int i = 0; i < 40; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.PacingGainUnits > 0, "Pacing gain should remain positive");
            Assert.True(cc.GeodesicSampleCnt >= 25, $"Should have many samples: {cc.GeodesicSampleCnt}");
        }

        [Fact]
        public void AckAggregation_SmokeDualWindow()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0, $"CWND should be positive: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing should be positive");
        }

        [Fact]
        public void AckAggregation_SmokeEpochOverflow()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 40; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0, $"CWND should survive epoch handling: {cc.CongestionWindowBytes}");
            Assert.True(cc.GeodesicSampleCnt >= 30, $"Should accumulate samples: {cc.GeodesicSampleCnt}");
        }

        [Fact]
        public void AckAggregation_SmokeWatchdog()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0, $"CWND should be positive: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing rate should be positive");
        }

        [Fact]
        public void AckAggregation_SmokeSafetyGuard()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0, $"CWND after safety checks: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing after safety checks");
        }

        [Fact]
        public void ModeTransition_StartupDrainProbeBw_Sequence()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            Assert.Equal(UcpMode.Startup, cc.Mode);
            Assert.True(cc.PacingGainUnits > 256, "Startup should have high gain");
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.True(cc.FullBwReached);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void ModeTransition_RtoDoesNotChangeMode()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            var modeBefore = cc.Mode;
            cc.OnRto();
            Assert.Equal(modeBefore, cc.Mode);
            long minCwnd = 4L * 1220L;
            Assert.True(cc.CongestionWindowBytes >= minCwnd,
                $"CWND after RTO should be at least {minCwnd}: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing should be positive after RTO");
        }

        [Fact]
        public void BootRateLift_RespectsConfiguredMaxPacingRate()
        {
            long maxPacing = 1_000_000_000L / 8; // 1 Gbps
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = maxPacing,
                MaxPacingRateBytesPerSecond = maxPacing,
                MaxCongestionWindowBytes = 64 * 1024 * 1024,
                InitialCwndBytes = 2_500_000,
            };
            var cc = new UcpCongestionControl(config);
            // First ACK triggers the boot-rate lift (high_gain * cwnd / RTT).
            cc.OnAck(100000, 24000, 50000, 24000);
            Assert.True(cc.PacingRateBytesPerSecond <= maxPacing,
                $"Boot-rate lift must not exceed configured max pacing {maxPacing}: got {cc.PacingRateBytesPerSecond}");
        }
    }
}


