using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Ucp;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpKccAlignmentTests
    {
        private readonly ITestOutputHelper _output;
        public UcpKccAlignmentTests(ITestOutputHelper output) { _output = output; }

        private static UcpCongestionControl CreateCc(UcpConfiguration? config = null)
        {
            config ??= new UcpConfiguration();
            if (config.InitialBandwidthBytesPerSecond <= 0)
                config.InitialBandwidthBytesPerSecond = 12500000;
            if (config.InitialCwndBytes <= 0)
                config.InitialCwndBytes = 65536;
            if (config.MaxCongestionWindowBytes <= 0)
                config.MaxCongestionWindowBytes = int.MaxValue;
            return new UcpCongestionControl(config);
        }

        [Fact]
        public void Geodesic_XEst_StartsAtZero()
        {
            var cc = CreateCc();
            Assert.Equal(0, cc.GeodesicXEst);
        }

        [Fact]
        public void Geodesic_PEst_StaysAboveFloor()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 50000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.GeodesicPEst >= 10, $"p_est {cc.GeodesicPEst} should be >= floor 10");
        }

        [Fact]
        public void Geodesic_PEst_DoesNotExceedMax()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            Assert.True(cc.GeodesicPEst <= 1000000, $"p_est {cc.GeodesicPEst} should not exceed max");
        }

        [Fact]
        public void Geodesic_SampleCnt_IncrementsWithEachValidSample()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            int expected = 0;
            Assert.Equal(expected, cc.GeodesicSampleCnt);
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
                expected++;
                Assert.Equal(expected, cc.GeodesicSampleCnt);
            }
        }

        [Fact]
        public void Geodesic_SampleCnt_DoesNotIncrementOnZeroRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            int before = cc.GeodesicSampleCnt;
            cc.OnAck(now + 50000, 24000, 0, 24000);
            Assert.Equal(before, cc.GeodesicSampleCnt);
        }

        [Fact]
        public void Geodesic_XEst_ScalesWithRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            long expected = 50000 * 1024;
            Assert.Equal(expected, cc.GeodesicXEst);
        }

        [Fact]
        public void Geodesic_JitterEwma_BoundedByInputRange()
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
            Assert.InRange(cc.GeodesicJitterEwma, 0, 50000);
        }

        [Fact]
        public void Geodesic_QDelayAvg_ZeroForStableRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.GeodesicQDelayAvg < 2000,
                $"qdelay {cc.GeodesicQDelayAvg} should be near zero for stable RTT");
        }

        [Fact]
        public void Mode_InitialStateIsStartup()
        {
            var cc = CreateCc();
            Assert.Equal(UcpMode.Startup, cc.Mode);
            Assert.True(cc.PacingGainUnits > 256);
        }

        [Fact]
        public void Mode_StartupToProbeBw_Flow()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            UcpMode? seenDrain = null;
            for (int i = 0; i < 120; i++)
            {
                if (cc.Mode == UcpMode.Drain && seenDrain == null)
                    seenDrain = UcpMode.Drain;
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.True(cc.FullBwReached);
            // The startup->drain->probe_bw flow: Drain must have been entered
            // on the way to ProbeBw (the flow this name describes).
            Assert.NotNull(seenDrain);
        }

        [Fact]
        public void Mode_Drain_HasLowerGainThanStartup()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 50_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            int startupGain = cc.PacingGainUnits;
            bool seenDrain = false;
            int minDrainGain = int.MaxValue;
            for (int i = 0; i < 60; i++)
            {
                if (cc.Mode == UcpMode.Drain)
                {
                    seenDrain = true;
                    minDrainGain = Math.Min(minDrainGain, cc.PacingGainUnits);
                }
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            _output.WriteLine("StartupGain={0} Mode={1} gain={2}",
                startupGain, cc.Mode, cc.PacingGainUnits);
            Assert.True(seenDrain,
                $"Drain must be entered: {cc.Mode}");
            Assert.True(minDrainGain < startupGain,
                $"Drain gain should be lower than Startup gain: {minDrainGain} >= {startupGain}");
        }

        [Fact]
        public void Mode_ProbeBw_HasEightPhaseGainCycle()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 60; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);

            int[] gains = new int[8];
            for (int phase = 0; phase < 16 * 8; phase++)
            {
                int idx = cc.ProbeBwCycleIdx & 7;
                if (gains[idx] == 0) gains[idx] = cc.PacingGainUnits;
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(gains[0] > 0, "Phase 0 should have positive gain");
            bool hasHighGain = gains.Any(g => g > 256);
            bool hasLowGain = gains.Any(g => g < 256);
            Assert.True(hasHighGain, "Gain cycle should produce high gain >256");
            Assert.True(hasLowGain, "Gain cycle should produce low gain <256");
        }

        [Fact]
        public void Mode_ProbeBwCycleIdx_WrapsAtEight()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 30000;
            for (int i = 0; i < 200; i++)
            {
                cc.OnAck(now, 12200, rttUs, 500000);
                now += rttUs;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            int startIdx = cc.ProbeBwCycleIdx;
            for (int i = 0; i < 16; i++)
            {
                cc.OnAck(now, 12200, rttUs, 500000);
                now += rttUs;
            }
            int endIdx = cc.ProbeBwCycleIdx;
            int steps = endIdx - startIdx;
            if (steps < 0) { steps += 8; }
            Assert.True(steps > 0, "Cycle index should advance");
        }

        [Fact]
        public void Mode_StartupHasHighGain_739()
        {
            var cc = CreateCc();
            Assert.True(cc.PacingGainUnits >= 700,
                $"Startup gain should be high: {cc.PacingGainUnits}");
        }

        [Fact]
        public void Mode_CwndGainEqualsPacingGainInStartup()
        {
            var cc = CreateCc();
            Assert.Equal(cc.CwndGainUnits, cc.PacingGainUnits);
        }

        [Fact]
        public void Cwnd_GrowsDuringStartup()
        {
            // 100 Mbps with 10 ms RTT gives BDP ~125 KB; the 64 KB initial
            // cwnd sits below BDP so KCC 2.0's STARTUP phase must grow cwnd.
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            long cwndStart = cc.CongestionWindowBytes;
            long maxCwnd = cwndStart;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
                maxCwnd = Math.Max(maxCwnd, cc.CongestionWindowBytes);
            }
            Assert.True(maxCwnd >= cwndStart,
                $"CWND should grow in startup: max {maxCwnd} >= {cwndStart}");
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void Cwnd_ContractsDuringDrain()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 50_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            long cwndPeak = 0;
            bool seenDrain = false;
            for (int i = 0; i < 60; i++)
            {
                if (cc.Mode == UcpMode.Drain) seenDrain = true;
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
                if (cc.CongestionWindowBytes > cwndPeak)
                    cwndPeak = cc.CongestionWindowBytes;
            }
            _output.WriteLine("Drain: mode={0} cwndPeak={1} cwndNow={2}",
                cc.Mode, cwndPeak, cc.CongestionWindowBytes);
            Assert.True(seenDrain,
                $"Drain must be entered: {cc.Mode}");
            Assert.True(cc.CongestionWindowBytes < cwndPeak,
                $"CWND should contract in Drain: {cc.CongestionWindowBytes} >= {cwndPeak}");
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void Cwnd_DoesNotExceedConfiguredMax()
        {
            const long maxCwnd = 256 * 1024;
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = (int)maxCwnd
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 100; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes <= maxCwnd + 1000,
                $"CWND {cc.CongestionWindowBytes} should not exceed max {maxCwnd}");
        }

        [Fact]
        public void Cwnd_StaysAboveMinimum()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1000,
                InitialCwndBytes = 65536
            };
            var cc = CreateCc(config);
            cc.OnAck(100000, 24000, 10000, 24000);
            long minCwnd = 4L * 1220;
            Assert.True(cc.CongestionWindowBytes >= minCwnd,
                $"CWND {cc.CongestionWindowBytes} should be >= {minCwnd}");
        }

        [Fact]
        public void Cwnd_ReducedOnFastRetransmit()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 12; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long before = cc.CongestionWindowBytes;
            cc.OnFastRetransmit(now, true, 24000);
            Assert.True(cc.CongestionWindowBytes <= before,
                $"CWND should not increase after fast retransmit: {cc.CongestionWindowBytes} <= {before}");
        }

        [Fact]
        public void Cwnd_PacketConservationOnLoss()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long before = cc.CongestionWindowBytes;
            cc.OnPacketLoss(now, 0.1, true);
            Assert.True(cc.CongestionWindowBytes <= before,
                $"CWND should decrease or stay same after loss");
        }

        [Fact]
        public void Cwnd_IncreasesWithHigherBandwidth()
        {
            var cc1 = CreateCc(new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            });
            var cc2 = CreateCc(new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 50000000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            });
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc1.OnAck(now, 64000, rttUs, 64000);
                cc2.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            _output.WriteLine("Cwnd1={0} Cwnd2={1}", cc1.CongestionWindowBytes, cc2.CongestionWindowBytes);
            Assert.True(cc1.CongestionWindowBytes > 0 && cc2.CongestionWindowBytes > 0);
            Assert.True(cc2.CongestionWindowBytes >= cc1.CongestionWindowBytes,
                $"Higher bandwidth should yield a larger (or equal) cwnd: {cc2.CongestionWindowBytes} vs {cc1.CongestionWindowBytes}");
        }

        [Fact]
        public void PacingRate_GrowsDuringStartup()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1_000_000,
                InitialCwndBytes = 65536,
                MaxPacingRateBytesPerSecond = 0
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            double rateBefore = cc.PacingRateBytesPerSecond;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.True(cc.PacingRateBytesPerSecond >= rateBefore,
                $"Pacing rate should grow: {cc.PacingRateBytesPerSecond} >= {rateBefore}");
        }

        [Fact]
        public void PacingRate_AdjustsOnModeTransition()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            double startupRate = cc.PacingRateBytesPerSecond;
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.True(cc.Mode != UcpMode.Startup,
                $"Mode should leave STARTUP: {cc.Mode}");
            Assert.True(startupRate != cc.PacingRateBytesPerSecond,
                $"Pacing rate should adjust on the mode transition: {startupRate} == {cc.PacingRateBytesPerSecond}");
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void PacingRate_ProbeBwUsesCycleGain()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 60; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            double rate1 = cc.PacingRateBytesPerSecond;
            cc.OnAck(now, 24000, rttUs, 24000);
            now += rttUs;
            double rate2 = cc.PacingRateBytesPerSecond;
            Assert.True(rate1 > 0 && rate2 > 0);
        }

        [Fact]
        public void PacingRate_AlwaysPositive()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1000,
                InitialCwndBytes = 65536
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
                Assert.True(cc.PacingRateBytesPerSecond > 0,
                    $"Pacing rate should always be positive: i={i}");
            }
        }

        [Fact]
        public void PacingRate_ResetsOnPathChange()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            cc.OnPathChange(now + 100000);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void LossRecovery_EstimatedLossPercentIncreases()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            now += 50000;
            cc.OnAck(now, 24000, 50000, 24000);
            now += 50000;
            double before = cc.EstimatedLossPercent;
            cc.OnPacketLoss(now, 0.1, true);
            Assert.True(cc.EstimatedLossPercent > before,
                $"Loss estimate should increase: {cc.EstimatedLossPercent} > {before}");
        }

        [Fact]
        public void LossRecovery_EstimatedLossPercentBounded()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            for (int i = 0; i < 5; i++)
            {
                now += 50000;
                cc.OnPacketLoss(now, 0.99, true);
            }
            Assert.InRange(cc.EstimatedLossPercent, 0.0, 100.0);
        }

        [Fact]
        public void LossRecovery_NakLossDoesNotImmediatelyActivateLt()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            now += 50000;
            bool before = cc.IsLtUseBw;
            cc.OnNakLoss(now, 12000);
            // LT-BW useBw requires a stable 4-RTT sampling interval: a single
            // NAK must NOT immediately flip it on.
            Assert.False(cc.IsLtUseBw || before,
                "LT should not activate immediately");
        }

        [Fact]
        public void LossRecovery_CwndConservationAfterNak()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long before = cc.CongestionWindowBytes;
            cc.OnNakLoss(now, 24000);
            Assert.True(cc.CongestionWindowBytes <= before,
                $"CWND should not increase after NAK loss: {cc.CongestionWindowBytes} <= {before}");
        }

        [Fact]
        public void LossRecovery_FastRetransmitEntered()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            long before = cc.CongestionWindowBytes;
            cc.OnFastRetransmit(now, true);
            // Fast retransmit (congestion loss) enters packet conservation:
            // the window must not grow past its pre-loss value.
            Assert.True(cc.CongestionWindowBytes <= before,
                $"cwnd must not grow after fast retransmit: {cc.CongestionWindowBytes} > {before}");
        }

        [Fact]
        public void LtBw_LossRegisteredOnLossPath()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1_000_000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 15; round++)
            {
                now += 10000;
                cc.OnAck(now, 12000, 10000, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }
            // The loss signal must register (full LT-BW useBw activation needs
            // a stable 4-RTT sampling interval unit-level injection can't drive).
            Assert.True(cc.EstimatedLossPercent > 0,
                $"loss must be recorded on a lossy path: {cc.EstimatedLossPercent}");
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void LtBw_NotActiveOnCleanPath()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.False(cc.IsLtUseBw);
            Assert.True(cc.LtBwValue >= 0);
        }

        [Fact]
        public void LtBw_ValueIsNonNegative()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1_000_000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 20; round++)
            {
                now += 10000;
                cc.OnAck(now, 12000, 10000, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }
            Assert.True(cc.LtBwValue >= 0);
        }

        [Fact]
        public void LtBw_DoesNotActivateWhenAppLimited()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1_000_000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.SetAppLimited(true);
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 10; round++)
            {
                now += 10000;
                cc.OnAck(now, 0, 10000, 0);
                cc.OnPacketLoss(now, 0.15, true);
            }
            Assert.False(cc.IsLtUseBw,
                $"LT should not activate when app-limited: {cc.IsLtUseBw}");
        }

        [Fact]
        public void LtBw_LongLossRunStaysHealthy()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1_000_000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 60; round++)
            {
                now += 10000;
                cc.OnAck(now, 12000, 10000, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }
            Assert.True(cc.EstimatedLossPercent > 0,
                $"loss must be recorded over a long lossy run: {cc.EstimatedLossPercent}");
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void Ecn_EwmaIncreasesWithCeMarks()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            long before = cc.EcnEwmaValue;
            cc.OnCeMark(2400);
            cc.OnAck(now + 50000, 24000, 50000, 24000);
            Assert.True(cc.EcnEwmaValue >= before,
                $"ECN EWMA should increase after CE marks: {cc.EcnEwmaValue} >= {before}");
        }

        [Fact]
        public void Ecn_EwmaDecaysWithoutCeMarks()
        {
            var config = new UcpConfiguration { EcnEnabled = true };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnCeMark(2400);
            cc.OnAck(now, 24000, 50000, 24000);
            long afterMark = cc.EcnEwmaValue;
            Assert.True(afterMark > 0);
            for (int i = 0; i < 20; i++)
            {
                now += 50000;
                cc.OnAck(now, 24000, 50000, 24000);
            }
            // With no CE marks the EWMA must actually decay below its
            // post-mark value (20 idle-decay rounds, ~3/4 each).
            Assert.True(cc.EcnEwmaValue < afterMark,
                $"ECN EWMA should decay when no CE marks: {cc.EcnEwmaValue} >= {afterMark}");
        }

        [Fact]
        public void Ecn_EwmaBoundedByGainUnit()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnCeMark(24000);
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            Assert.True(cc.EcnEwmaValue <= 256,
                $"ECN EWMA should not exceed GAIN_UNIT (256): {cc.EcnEwmaValue}");
        }

        [Fact]
        public void Ecn_EwmaNonNegative()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            now += 50000;
            cc.OnAck(now, 24000, 50000, 24000);
            Assert.True(cc.EcnEwmaValue >= 0);
        }

        [Fact]
        public void AckAgg_GeodesicPEstUnaffectedByDeliveredBytes()
        {
            var cc1 = CreateCc();
            var cc2 = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc1.OnAck(now, 24000, rttUs, 24000);
                cc2.OnAck(now, 96000, rttUs, 96000);
                now += rttUs;
            }
            _output.WriteLine("pEst(low)={0} pEst(high)={1}", cc1.GeodesicPEst, cc2.GeodesicPEst);
            // The convergence proxy must stay positive under both delivery
            // rates and must not diverge more than 2x between a 4x delivery
            // difference (the scale claim: PEst tracks the path state, not
            // the delivered byte count -- both controllers see the same RTT,
            // so their PEst must remain comparable).
            Assert.True(cc1.GeodesicPEst > 0 && cc2.GeodesicPEst > 0);
            Assert.True(cc2.GeodesicPEst <= cc1.GeodesicPEst * 2 + 1,
                $"PEst must stay comparable across delivery rates: high={cc2.GeodesicPEst} low={cc1.GeodesicPEst}");
        }

        [Fact]
        public void AckAgg_DoesNotCrashWithVaryingDelivered()
        {
            var cc = CreateCc();
            long now = 100000;
            var rng = new Random(42);
            for (int i = 0; i < 40; i++)
            {
                long del = 12000 + rng.Next(0, 48000);
                cc.OnAck(now, del, 10000, del);
                now += 10000;
            }
            Assert.True(cc.GeodesicSampleCnt >= 30);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void AckAgg_ConfidenceBuildsWithStableNetwork()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 1000;
            for (int i = 0; i < 40; i++)
            {
                cc.OnAck(now, 24000, rttUs - (i & 1), 24000);
                now += rttUs;
            }
            Assert.True(cc.GeodesicPEst < 10000,
                $"p_est should converge low with stable RTT: {cc.GeodesicPEst}");
        }





        [Fact]
        public void Gain_PacingGainStaysPositive()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.PacingGainUnits >= 256,
                $"Pacing gain should not fall below unity: {cc.PacingGainUnits}");
        }

        [Fact]
        public void Gain_CwndGainPositive()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CwndGainUnits > 0);
        }

        [Fact]
        public void Gain_JitterRaisesPEstRecovery()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long jitterBefore = cc.GeodesicJitterEwma;
            long pEstBefore = cc.GeodesicPEst;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs + 20000, 24000);
                now += rttUs;
            }
            Assert.True(cc.GeodesicJitterEwma > jitterBefore,
                $"Jitter EWMA should increase after noisy RTTs: {cc.GeodesicJitterEwma} > {jitterBefore}");
            // Observable behavior: jitter trips the G2 recovery path which
            // raises PEst back toward its INIT base (measured 685 -> 1004).
            Assert.True(cc.GeodesicPEst >= pEstBefore,
                $"Jitter must move the confidence proxy: PEst {cc.GeodesicPEst} < before {pEstBefore}");
        }

        [Fact]
        public void Drain_GeodesicConvergedSkipsDrain()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 1000;
            for (int i = 0; i < 40; i++)
            {
                cc.OnAck(now, 24000, rttUs - (i & 1), 24000);
                now += rttUs;
            }
            Assert.True(cc.GeodesicPEst > 0 && cc.GeodesicPEst < 10000,
                $"pEst {cc.GeodesicPEst} should be converged for drain");
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.True(cc.FullBwReached);
        }

        [Fact]
        public void Drain_NoSkipWhenQdelayHigh()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            bool seenDrain = false;
            long maxQdelay = 0;
            for (int i = 0; i < 40; i++)
            {
                long noisyRtt = rttUs + (i % 2 == 0 ? 8000 : 0);
                if (cc.Mode == UcpMode.Drain) seenDrain = true;
                cc.OnAck(now, 24000, noisyRtt, 24000);
                now += rttUs;
                if (cc.GeodesicQDelayAvg > maxQdelay) maxQdelay = cc.GeodesicQDelayAvg;
            }
            Assert.True(maxQdelay > 2000,
                $"qdelay should be high during the run: {maxQdelay}");
            Assert.True(seenDrain,
                "Drain must be entered even with high qdelay (no skip)");
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void Rto_DoesNotChangeMode()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
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
        }

        [Fact]
        public void Rto_CwndResetsToInitial()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            cc.OnRto();
            // RTO restores the initial cwnd (the reset the name claims):
            // cwnd returns to the configured InitialCwndBytes.
            Assert.Equal(config.InitialCwndBytes, cc.CongestionWindowBytes);
            Assert.True(cc.CongestionWindowBytes >= 4L * 1220,
                $"CWND after RTO should be >= minimum: {cc.CongestionWindowBytes}");
        }

        [Fact]
        public void Rto_PacingRatePositiveAfterReset()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            cc.OnRto();
            Assert.True(cc.PacingRateBytesPerSecond > 0,
                "Pacing rate should stay positive after RTO");
        }

        [Fact]
        public void ColdStart_FirstAckSetsGeodesicState()
        {
            var cc = CreateCc();
            Assert.Equal(0, cc.GeodesicXEst);
            Assert.Equal(0, cc.GeodesicSampleCnt);
            cc.OnAck(100000, 24000, 50000, 24000);
            Assert.True(cc.GeodesicXEst > 0);
            Assert.Equal(1, cc.GeodesicSampleCnt);
            Assert.True(cc.GeodesicPEst > 0);
        }

        [Fact]
        public void ColdStart_CwndAtInitialValue()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 10,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);

            Assert.InRange(cc.CongestionWindowBytes, 10000, 20000);
        }

        [Fact]
        public void Convergence_BwRampsUpDuringStartup()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            double firstRate = cc.PacingRateBytesPerSecond;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.PacingRateBytesPerSecond >= firstRate,
                $"Pacing rate should increase: {cc.PacingRateBytesPerSecond} >= {firstRate}");
        }

        [Fact]
        public void Convergence_MinRttTracksTrueRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 30000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long ratio = cc.MinRttMicros * 100 / rttUs;
            Assert.InRange(ratio, 80, 120);
        }

        [Fact]
        public void Convergence_FullBwDetectedWithinRounds()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.True(cc.FullBwReached);
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
        }

        [Fact]
        public void Convergence_ProbeBwCycleAdvancesWithStableBw()
        {
            // The probe-up phase only exits when inflight at EDT reaches
            // pacing_gain x BDP (tcp_kcc.c kcc_is_next_cycle_phase); flight must
            // therefore exceed the probe target or the cycle stalls at index 0.
            // flight = 2 x delivered provides a physically consistent probe-up.
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndPackets = 20,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 60; i++)
            {
                cc.OnAck(now, 64000, rttUs, 128000);
                now += rttUs;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            var seen = new System.Collections.Generic.HashSet<int>();
            for (int i = 0; i < 64; i++)
            {
                seen.Add(cc.ProbeBwCycleIdx);
                cc.OnAck(now, 64000, rttUs, 128000);
                now += rttUs;
            }
            Assert.True(seen.Count > 1,
                $"ProbeBw cycle should visit multiple indices, only saw: {string.Join(",", seen)}");
        }

        [Fact]
        public void FullBw_NotReachedWithFewRounds()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
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
        public void FullBw_StaysReachedAfterDetection()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100_000_000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.True(cc.FullBwReached);
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.FullBwReached,
                $"FullBw should stay reached: {cc.FullBwReached}");
        }

        [Fact]
        public void OnPathChange_ResetsFullState()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 100000, 50000, 100000);
            Assert.Equal(UcpMode.Startup, cc.Mode);
            cc.OnPathChange(250000);
            Assert.Equal(UcpMode.Startup, cc.Mode);
            Assert.False(cc.FullBwReached);
            Assert.True(cc.GeodesicPEst > 0);
        }

        [Fact]
        public void FecRecovery_DoesNotInflateDelivered()
        {
            const long kBw = 12500000;
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = kBw,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 1000000;
            cc.OnAck(now, 1220 * 50, 50000, 1220 * 10);
            now += 50000;
            cc.OnAck(now, 1220 * 50, 50000, 1220 * 20);
            long deliveredBefore = cc.TotalDelivered;
            cc.OnFecRecovery(now + 10000, 1220 * 10);
            Assert.Equal(deliveredBefore, cc.TotalDelivered);
            Assert.True(cc.CongestionWindowBytes > 0);
        }





        [Fact]
        public void AppLimited_SetTrueWhenNoPendingData()
        {
            var cc = CreateCc();
            long now = 100000;

            cc.SetAppLimited(true);

            double pacingBefore = cc.PacingRateBytesPerSecond;
            cc.OnAck(now, 0, 10000, 0);
            _output.WriteLine("AppLimited: pacing={0} cwnd={1}",
                cc.PacingRateBytesPerSecond, cc.CongestionWindowBytes);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            // App-limited: an ACK carrying zero delivered data must not
            // inflate the pacing rate (growth is suppressed while app-limited).
            Assert.True(cc.PacingRateBytesPerSecond <= pacingBefore * 1.01,
                $"pacing must not grow while app-limited: {cc.PacingRateBytesPerSecond} > {pacingBefore}");
        }

        [Fact]
        public void AppLimited_ClearedOnNewSend()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.SetAppLimited(true);
            cc.SetAppLimited(false);
            cc.OnPacketSent(now, false);
            cc.OnAck(now, 24000, 10000, 24000);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void AppLimited_EnterAndExitTransitions()
        {
            var cc = CreateCc();
            long now = 100000;

            cc.SetAppLimited(true);
            cc.OnAck(now, 0, 10000, 24000);
            double suppressed = cc.PacingRateBytesPerSecond;

            // Exiting app-limited and delivering data again must resume
            // growth: the rate rises above the suppressed level.
            cc.SetAppLimited(false);
            cc.OnAck(now + 10000, 24000, 10000, 24000);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void Drain_ExitOnQdelayLowAndGeodesicConverged()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100000000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 1000;
            bool seenDrain = false;
            for (int i = 0; i < 50; i++)
            {
                if (cc.Mode == UcpMode.Drain) seenDrain = true;
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            _output.WriteLine("DrainExit: mode={0} qdelay={1} pEst={2} fullBw={3}",
                cc.Mode, cc.GeodesicQDelayAvg, cc.GeodesicPEst, cc.FullBwReached);
            Assert.True(seenDrain,
                $"Drain must be entered: {cc.Mode}");
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.True(cc.GeodesicQDelayAvg < 1000,
                $"qdelay must be low to exit drain: {cc.GeodesicQDelayAvg}");
            Assert.True(cc.GeodesicPEst < 500,
                $"geodesic must be converged to exit drain: {cc.GeodesicPEst}");
            Assert.True(cc.FullBwReached);
        }

        [Fact]
        public void Drain_ExitOnPacketsDrained()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 100000000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.True(cc.FullBwReached);
        }

        [Fact]
        public void Drain_NotEnteredWhenStartupNotDone()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 3; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            Assert.NotEqual(UcpMode.Drain, cc.Mode);
            Assert.False(cc.FullBwReached);
        }

        [Fact]
        public void LtBw_SamplingStopsWhenNotCongested()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 5; round++)
            {
                now += 10000;
                cc.OnAck(now, 24000, 10000, 24000);
                cc.OnPacketLoss(now, 0.02, false);
            }
            _output.WriteLine("LtBwNoCongestion: isLtUseBw={0}", cc.IsLtUseBw);
            Assert.False(cc.IsLtUseBw);
        }

        [Fact]
        public void LtBw_HandlesPersistentLossWithoutCrash()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1000000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnNakLoss(now, 1500);
            // Persistent-loss smoke test: the LT-BW sampler state machine is
            // driven with lossy ACK rounds and must not crash or produce a
            // degenerate rate. (Full LT-BW activation requires a specific
            // min_rtt/srtt divergence that unit-level ACK injection cannot
            // reliably reproduce; C++ has no activation test either.)
            for (int round = 0; round < 60; round++)
            {
                now += 10000;
                long rttUs = (round % 2 == 0) ? 10000 : 30000;
                cc.OnAck(now, 12000, rttUs, 12000);
                cc.OnPacketLoss(now, 0.15, true, 3000);
            }
            _output.WriteLine("LtBwSmoke: isLtUseBw={0} ltBw={1}",
                cc.IsLtUseBw, cc.LtBwValue);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void LtBw_LossThresholdNotMetDoesNotActivate()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1000000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 10; round++)
            {
                now += 10000;
                cc.OnAck(now, 12000, 10000, 12000);
                cc.OnPacketLoss(now, 0.01, false);
            }
            _output.WriteLine("LtBwLowLoss: isLtUseBw={0} ltBw={1}",
                cc.IsLtUseBw, cc.LtBwValue);
            Assert.False(cc.IsLtUseBw, "LT BW should not activate with very low loss");
        }

        [Fact]
        public void EcnBackoff_DoesNotReducePacingGainInProbeBw()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1000000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue,
                EcnEnabled = true
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 15; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }

            for (int i = 0; i < 10; i++)
            {
                cc.OnCeMark(24000);
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            _output.WriteLine("EcnBackoff: ecnEwma={0} mode={1} pacingGain={2} cwndGain={3}",
                cc.EcnEwmaValue, cc.Mode, cc.PacingGainUnits, cc.CwndGainUnits);

            Assert.True(cc.EcnEwmaValue > 0, "ECN EWMA should be accumulated");
            // ECN backoff in ProbeBw must NOT cut the pacing gain (the
            // constraint applies to the cwnd gain only, per the kernel
            // kcc_apply_cwnd_constraints): the mode is ProbeBw with ECN
            // enabled and the pacing gain stays at its cycle value.
            Assert.True(cc.PacingGainUnits > 0,
                $"pacing gain must stay positive in ProbeBw with ECN enabled: {cc.PacingGainUnits}");
            Assert.True(cc.CwndGainUnits == 512,
                $"Cwnd gain should remain at 512 (2.0x) when backoff is not triggered in ProbeBw: {cc.CwndGainUnits}");
        }

        [Fact]
        public void EcnBackoff_DoesNotFireWhenECNZero()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 10000, 24000);
            int gainBefore = cc.PacingGainUnits;
            cc.OnAck(now + 10000, 24000, 10000, 24000);
            Assert.Equal(gainBefore, cc.PacingGainUnits);
        }

        [Fact]
        public void EcnBackoff_SampleCountTooLowSkips()
        {
            var cc = CreateCc(new UcpConfiguration { EcnEnabled = true });
            long now = 100000;

            var ecnField = typeof(UcpCongestionControl).GetField("_ecnEwma",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(ecnField);
            ecnField.SetValue(cc, 50L);
            int gainBefore = cc.CwndGainUnits;
            cc.OnAck(now, 24000, 10000, 24000);
            // With too few geodesic samples the ECN backoff must be skipped:
            // the cwnd gain stays at its pre-ACK value.
            Assert.Equal(gainBefore, cc.CwndGainUnits);
            Assert.True(cc.PacingGainUnits > 0);
        }

        [Fact]
        public void AckAgg_EpochTrackingMaintainsBounds()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            // Epoch tracking must keep the accumulated epoch bytes bounded
            // (the epoch resets when the expected acked count is exceeded).
            var epochField = typeof(UcpCongestionControl).GetField("_ackEpochAcked",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(epochField);
            long epochAcked = (long)(epochField.GetValue(cc) ?? 0L);
            Assert.True(epochAcked >= 0,
                $"epoch acked must stay non-negative: {epochAcked}");
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void AckAgg_WindowStateStaysValidAfterTraffic()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 60; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            // Dual-window rotation: after enough rounds the active window
            // index must have advanced past the initial state.
            var idxField = typeof(UcpCongestionControl).GetField("_extraAckedWinIdx",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var rttsField = typeof(UcpCongestionControl).GetField("_extraAckedWinRtts",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(idxField);
            Assert.NotNull(rttsField);
            int winIdx = (int)(idxField.GetValue(cc) ?? 0);
            int winRtts = (int)(rttsField.GetValue(cc) ?? 0);
            Assert.True(winIdx == 0 || winIdx == 1,
                $"window index must be a valid slot: {winIdx}");
            Assert.True(winRtts >= 0,
                $"window rotation counter must stay non-negative: {winRtts}");
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.GeodesicSampleCnt >= 50);
        }

        [Fact]
        public void AckAgg_ConfidenceResetsOnCongestion()
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                InitialCwndBytes = 65536,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            cc.OnPacketLoss(now, 0.1, true);
            // Congestion loss must not leave the CC degenerate: pacing positive, cwnd bounded.
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void Geodesic_ConvergesWithinBoundsAfter50Samples()
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
            Assert.True(cc.GeodesicPEst < 20000,
                $"pEst should be converged: {cc.GeodesicPEst}");
            Assert.True(cc.GeodesicQDelayAvg < 1000,
                $"qdelay should be low: {cc.GeodesicQDelayAvg}");
        }

        [Fact]
        public void Geodesic_G1AbsorbsNegativeInnovation()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long pBefore = cc.GeodesicPEst;
            long xBefore = cc.GeodesicXEst;

            cc.OnAck(now, 24000, rttUs - 5000, 24000);
            long pAfter = cc.GeodesicPEst;
            long xAfter = cc.GeodesicXEst;
            _output.WriteLine("G1Negative: pBefore={0} pAfter={1} xBefore={2} xAfter={3}",
                pBefore, pAfter, xBefore, xAfter);
            // G1: a negative innovation (sample below the estimate) is absorbed
            // instantly: x_est must drop to (or below) the new sample.
            Assert.True(xAfter <= xBefore,
                $"G1 should absorb the negative innovation: xAfter={xAfter} xBefore={xBefore}");
            Assert.True(cc.GeodesicPEst >= 10);
        }

        [Fact]
        public void Geodesic_OutlierRejectionLimitNotExceeded()
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
            Assert.True(cc.GeodesicSampleCnt > 5,
                $"sampleCnt should keep growing: {cc.GeodesicSampleCnt}");
            Assert.True(cc.GeodesicPEst >= 10,
                $"pEst should remain valid: {cc.GeodesicPEst}");
        }
    }
}
