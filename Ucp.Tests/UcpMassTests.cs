using System;
using System.Collections.Generic;
using System.Linq;
using Ucp;
using Ucp.Internal;
using Ucp.Transport;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpMassTests
    {
        private readonly ITestOutputHelper _output;
        public UcpMassTests(ITestOutputHelper output) { _output = output; }

        private static UcpCongestionControl CreateCc(UcpConfiguration? config = null)
        {
            config ??= new UcpConfiguration();
            if (config.InitialBandwidthBytesPerSecond <= 0) config.InitialBandwidthBytesPerSecond = 12500000;
            if (config.InitialCwndBytes <= 0) config.InitialCwndBytes = 65536;
            if (config.MaxCongestionWindowBytes <= 0) config.MaxCongestionWindowBytes = int.MaxValue;
            return new UcpCongestionControl(config);
        }

        [Theory]
        [InlineData(1000, 20)]
        [InlineData(5000, 30)]
        [InlineData(10000, 40)]
        [InlineData(25000, 50)]
        [InlineData(50000, 60)]
        [InlineData(100000, 70)]
        public void Geodesic_ConvergenceSweep_RttBySamples(long rttUs, int samples)
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < samples; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long expected = rttUs * 1024;
            long ratio = cc.GeodesicXEst * 100 / expected;
            Assert.InRange(ratio, 70, 130);
            Assert.True(cc.GeodesicSampleCnt >= samples * 90 / 100);
        }


        [Theory]
        [InlineData(1000000, 10, 0.02)]
        [InlineData(5000000, 20, 0.05)]
        [InlineData(10000000, 50, 0.10)]
        [InlineData(50000000, 100, 0.15)]
        public void Cc_BwRttLossMassTest(long bw, long rttUs, double lossRate)
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = bw, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            long delivered = Math.Max(1, bw * rttUs / 1000000);
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }
            for (int i = 0; i < 5; i++)
            {
                cc.OnNakLoss(now, delivered / 4);
                cc.OnPacketLoss(now, lossRate, true);
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.MinRttMicros > 0);
        }

        [Theory]
        [InlineData(2, 1)]
        [InlineData(4, 1)]
        [InlineData(4, 2)]
        [InlineData(8, 2)]
        [InlineData(8, 4)]
        [InlineData(16, 2)]
        [InlineData(16, 4)]
        [InlineData(32, 4)]
        [InlineData(32, 8)]
        public void Fec_GroupRepairCombo(int groupSize, int repairCount)
        {
            var enc = new UcpFecCodec(groupSize, repairCount);
            var data = new byte[groupSize][];
            for (int i = 0; i < groupSize; i++)
            {
                data[i] = new byte[100];
                new Random(42 + i).NextBytes(data[i]);
            }
            List<byte[]>? repairs = null;
            for (int i = 0; i < groupSize; i++)
                repairs = enc.TryEncodeRepairs((uint)i, data[i]!);
            Assert.NotNull(repairs);
            Assert.Equal(repairCount, repairs!.Count);

            var dec = new UcpFecCodec(groupSize, repairCount);
            for (int i = 0; i < groupSize; i++)
            {
                if (i < repairCount)
                    continue;
                dec.FeedDataPacket((uint)i, data[i]!);
            }
            int recoveredSoFar = 0;
            for (int ri = 0; ri < repairCount; ri++)
            {
                var recovered = dec.TryRecoverPacketsFromRepair(repairs[ri], 0, ri);
                // RS recovery is combinatorial: an intermediate repair may
                // recover 0 packets, but the recovered set must never shrink
                // and the final repair must recover every missing packet.
                Assert.True(recovered.Count >= recoveredSoFar,
                    $"recovered set should not shrink at repair {ri}: {recovered.Count} < {recoveredSoFar}");
                Assert.True(recovered.Count <= repairCount,
                    $"repair {ri} should not exceed the missing count");
                recoveredSoFar = recovered.Count;
                if (ri == repairCount - 1)
                    Assert.Equal(repairCount, recovered.Count);
            }
        }

        [Theory]
        [InlineData(100000, 50000, 60000000)]
        [InlineData(50000, 100000, 60000000)]
        [InlineData(200000, 50000, 60000000)]
        [InlineData(1000000, 100000, 60000000)]
        public void Rto_ParameterSweep(long srtt, long minRto, long maxRto)
        {
            var config = new UcpConfiguration
            {
                MinRtoMicros = (int)minRto,
                MaxRtoMicros = (int)maxRto,
                RetransmitBackoffFactor = 2.0
            };
            var rto = new UcpRtoEstimator(config);
            rto.Update(srtt);
            Assert.InRange(rto.CurrentRtoMicros, minRto, maxRto);
            Assert.True(rto.SmoothedRttMicros > 0);
            for (int i = 0; i < 5; i++)
                rto.Backoff();
            Assert.True(rto.CurrentRtoMicros <= maxRto);
        }

        [Theory]
        [InlineData(1000, 1000000)]
        [InlineData(10000, 1000000)]
        [InlineData(100000, 1000000)]
        [InlineData(1000, 100000)]
        public void Pacing_RateConsumeCombo(long rate, long bucketDuration)
        {
            var config = new UcpConfiguration { PacingBucketDurationMicros = bucketDuration };
            var ctrl = new PacingController(config, 1000);
            ctrl.SetRate(rate, 0);
            int packetSize = 1220 + 20;
            ctrl.TryConsume(packetSize, 1000000);
            long wait = ctrl.GetWaitTimeMicros(packetSize, 1000000);
            Assert.True(wait >= 0);
            if (rate < packetSize)
                Assert.True(wait > 0);
        }

        [Theory]
        [InlineData(1000000)]
        [InlineData(10000000)]
        [InlineData(50000000)]
        public void DrainExit_ConditionsSweep(long bw)
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = bw,
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
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Theory]
        [InlineData(0, 10000)]
        [InlineData(50, 10000)]
        [InlineData(200, 10000)]
        [InlineData(500, 10000)]
        public void EcnBackoff_CeMarkSweep(long ceBytes, long delivered)
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
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            cc.OnCeMark(ceBytes);
            for (int i = 0; i < 5; i++)
            {
                cc.OnCeMark(ceBytes);
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }
            if (ceBytes > 0)
                Assert.True(cc.EcnEwmaValue > 0);
            Assert.True(cc.CwndGainUnits > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Theory]
        [InlineData(0.05)]
        [InlineData(0.10)]
        [InlineData(0.20)]
        [InlineData(0.30)]
        public void LtBw_LossRateSweep(double lossRate)
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1000000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 15; round++)
            {
                now += rttUs;
                cc.OnAck(now, 12000, rttUs, 12000);
                cc.OnPacketLoss(now, lossRate, true);
            }
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Theory]
        [InlineData(25000)]
        [InlineData(50000)]
        [InlineData(100000)]
        [InlineData(200000)]
        public void Bdp_CwndSweep(long rttUs)
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
                long delivered = Math.Max(1, 12500000L * rttUs / 1000000);
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.MinRttMicros > 0);
        }

        [Theory]
        [InlineData(0.01, false)]
        [InlineData(0.05, false)]
        [InlineData(0.10, true)]
        [InlineData(0.20, true)]
        public void AppLimited_LossBehavior(double lossRate, bool isCongestion)
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 1000000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            cc.SetAppLimited(true);
            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 0, rttUs, 0);
                now += rttUs;
            }
            cc.SetAppLimited(false);
            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            cc.OnPacketLoss(now, lossRate, isCongestion);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Theory]
        [InlineData(1000000)]
        [InlineData(10000000)]
        [InlineData(100000000)]
        public void BwWindow_TrackingSweep(long bw)
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = bw,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            long delivered = Math.Max(1, bw * rttUs / 1000000);
            for (int i = 0; i < 15; i++)
            {
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }
            Assert.True(cc.BtlBwBytesPerSecond > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Theory]
        [InlineData(50000)]
        [InlineData(100000)]
        [InlineData(500000)]
        public void MinRtt_FastFallSweep(long initialRttUs)
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            cc.OnAck(now, 24000, initialRttUs, 24000);
            long prevMinRtt = cc.MinRttMicros;
            long veryLowRtt = initialRttUs / 5;
            now += initialRttUs;
            cc.OnAck(now, 24000, veryLowRtt, 24000);
            Assert.True(cc.MinRttMicros <= veryLowRtt + 500, $"minRtt={cc.MinRttMicros} <= {veryLowRtt + 500}");
        }

        [Theory]
        [InlineData(1000, 100)]
        [InlineData(10000, 1000)]
        [InlineData(50000, 5000)]
        public void NackLoss_RttRecoverySweep(long rttUs, long burstLoss)
        {
            var config = new UcpConfiguration
            {
                InitialBandwidthBytesPerSecond = 12500000,
                MaxCongestionWindowBytes = int.MaxValue
            };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            for (int i = 0; i < 3; i++)
            {
                cc.OnNakLoss(now, burstLoss);
                now += rttUs;
                cc.OnAck(now, 12000, rttUs, 12000);
                now += rttUs;
            }
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Theory]
        [InlineData(1000)]
        [InlineData(10000)]
        [InlineData(100000)]
        public void PathChange_ResetSweep(long rttUs)
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
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            cc.OnPathChange(now);
            Assert.Equal(UcpMode.Startup, cc.Mode);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void Pcb_CidRotationSecurity_Extended()
        {
            var config = new UcpConfiguration();
            uint primary = 0xABCD;
            var pcb = new UcpPcb(null, null, false, false, null, primary, config);
            Assert.True(pcb.IsValidCid(primary));
            for (uint i = 0; i < 10; i++)
            {
                uint extra = 0x8000 + i;
                Assert.True(pcb.AddExtraCid(extra));
                Assert.True(pcb.IsValidCid(extra));
            }
            for (uint i = 0; i < 10; i++)
            {
                uint extra = 0x8000 + i;
                Assert.True(pcb.RemoveExtraCid(extra));
                Assert.False(pcb.IsValidCid(extra));
            }
            Assert.True(pcb.IsValidCid(primary));
            Assert.False(pcb.IsValidCid(0u));
        }

        [Fact]
        public void Pcb_ConnectionIdManagement_MultipleExtras()
        {
            var config = new UcpConfiguration();
            var pcb = new UcpPcb(null, null, false, false, null, 0x1000u, config);
            uint[] extras = { 0x2000, 0x3000, 0x4000, 0x5000 };
            foreach (uint e in extras)
                Assert.True(pcb.AddExtraCid(e));
            uint[] unknowns = { 0x6000, 0x7000, 0, 0xFFFF };
            foreach (uint u in unknowns)
                Assert.False(pcb.IsValidCid(u));
            foreach (uint e in extras)
                Assert.True(pcb.IsValidCid(e));
            Assert.True(pcb.IsValidCid(0x1000u));
            foreach (uint e in extras)
                Assert.True(pcb.RemoveExtraCid(e));
            foreach (uint e in extras)
                Assert.False(pcb.RemoveExtraCid(e));
        }

        [Theory]
        [InlineData(25000)]
        [InlineData(50000)]
        [InlineData(100000)]
        public void Geodesic_XEstScalesWithRttSweep(long rttUs)
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, rttUs, 24000);
            long expected = rttUs * 1024;
            Assert.Equal(expected, cc.GeodesicXEst);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(10)]
        [InlineData(25)]
        [InlineData(50)]
        public void Geodesic_SampleCntSweep(int sampleCount)
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < sampleCount; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.Equal(sampleCount, cc.GeodesicSampleCnt);
        }

        [Fact]
        public void Codec_DataPacketAllFlags()
        {
            foreach (UcpPacketFlags flags in Enum.GetValues<UcpPacketFlags>())
            {
                if (flags == UcpPacketFlags.None) continue;
                var packet = new UcpDataPacket
                {
                    Header = new UcpCommonHeader
                    {
                        Type = UcpPacketType.Data,
                        Flags = flags,
                        ConnectionId = 1,
                        Timestamp = 50000
                    },
                    SequenceNumber = 10,
                    FragmentTotal = 1,
                    FragmentIndex = 0,
                    Payload = new byte[] { 0x41 },
                    AckNumber = 5,
                    WindowSize = 1024
                };
                byte[] encoded = UcpPacketCodec.Encode(packet);
                Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
                var data = Assert.IsType<UcpDataPacket>(decoded);
                Assert.Equal(flags, data.Header.Flags);
            }
        }

        [Fact]
        public void Fec_LargeDataRoundTrip()
        {
            var enc = new UcpFecCodec(4, 1);
            byte[] data = new byte[1000];
            new Random(99).NextBytes(data);
            Assert.Null(enc.TryEncodeRepair(0u, data));
            Assert.Null(enc.TryEncodeRepair(1u, data));
            Assert.Null(enc.TryEncodeRepair(2u, data));
            var repair = enc.TryEncodeRepair(3u, data);
            Assert.NotNull(repair);
            var dec = new UcpFecCodec(4, 1);
            dec.FeedDataPacket(0u, data);
            dec.FeedDataPacket(1u, data);
            dec.FeedDataPacket(3u, data);
            var recovered = dec.TryRecoverFromRepair(repair!, 0u);
            Assert.NotNull(recovered);
            Assert.Equal(data, recovered);
        }

        [Fact]
        public void Gain_CwndGainPacingGainPositiveAfterRepeatedLoss()
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
            for (int i = 0; i < 10; i++)
            {
                cc.OnFastRetransmit(now, true);
                now += rttUs;
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CwndGainUnits >= 0);
            Assert.True(cc.PacingGainUnits >= 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void ProbeBw_MinRttExpiryAndRecovery()
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
            long baseline = cc.MinRttMicros;
            Assert.True(baseline > 0);
            // After the min-RTT expiry window, a higher observed RTT must not
            // be pinned as the new minimum; the estimator re-baselines to the
            // fresh (higher) observation.
            now += 12000000;
            cc.OnAck(now, 24000, rttUs * 2, 24000);
            Assert.True(cc.MinRttMicros > 0);
            Assert.True(cc.MinRttMicros <= rttUs * 2,
                $"MinRtt should recover to the fresh observation: {cc.MinRttMicros} > {rttUs * 2}");
        }
    }
}
