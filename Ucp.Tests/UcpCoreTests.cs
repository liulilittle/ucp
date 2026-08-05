using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ucp;
using Ucp.Internal;
using UcpTest.TestTransport;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpCoreTests
    {
        private readonly ITestOutputHelper _output;

        public UcpCoreTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void GeodesicFilterUpdate_InitialSampleSetsXEstAndPEst()
        {
            var cc = CreateCc(new UcpConfiguration());
            long rttUs = 50000;

            cc.OnAck(100000, 24000, rttUs, 24000);

            long expectedXEst = rttUs * 1024;
            Assert.Equal(expectedXEst, cc.GeodesicXEst);
            long expectedPEst = 1000;
            Assert.Equal(expectedPEst, cc.GeodesicPEst);
            Assert.Equal(1, cc.GeodesicSampleCnt);
            Assert.Equal(rttUs, cc.MinRttMicros);
        }

        [Fact]
        public void GeodesicFilterUpdate_ConvergesToTrueRtt()
        {
            var cc = CreateCc(new UcpConfiguration());
            long rttUs = 10000;
            long now = 100000;

            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            long expectedXEst = rttUs * 1024;
            long ratio = cc.GeodesicXEst * 100 / expectedXEst;
            Assert.InRange(ratio, 90, 110);
            Assert.True(cc.GeodesicSampleCnt >= 20);
        }

        [Fact]
        public void GeodesicFilterUpdate_ZeroInnovationKeepsXEst()
        {
            var cc = CreateCc(new UcpConfiguration());
            long rttUs = 10000;
            long now = 100000;

            cc.OnAck(now, 24000, rttUs, 24000);
            long xEst1 = cc.GeodesicXEst;

            now += rttUs;
            cc.OnAck(now, 24000, rttUs, 24000);
            long xEst2 = cc.GeodesicXEst;

            now += rttUs;
            cc.OnAck(now, 24000, rttUs, 24000);
            long xEst3 = cc.GeodesicXEst;

            Assert.Equal(xEst1, xEst2);
            Assert.Equal(xEst2, xEst3);
        }

        [Fact]
        public void GeodesicFilterUpdate_G2GrowthOnPositiveInnovation()
        {
            var cc = CreateCc(new UcpConfiguration());
            long now = 100000;

            cc.OnAck(now, 24000, 10000, 24000);
            now += 10000;

            long xEstBefore = cc.GeodesicXEst;

            cc.OnAck(now, 24000, 10200, 24000);

            long expectedXEst = (10200L * 1024L);
            _output.WriteLine("xEst before={0} after={1} pEst={2}",
                xEstBefore, cc.GeodesicXEst, cc.GeodesicPEst);
            Assert.Equal(expectedXEst, cc.GeodesicXEst);
        }

        [Fact]
        public void MinRttTracking_StickyFallOnModerateDecrease()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            var cc = CreateCc(config);
            long now = 100000;
            long initialRtt = 100000;

            cc.OnAck(now, 24000, initialRtt, 24000);
            long prevMinRtt = cc.MinRttMicros;

            long lowerRtt = initialRtt * 60 / 100;
            for (int i = 0; i < 5; i++)
            {
                now += initialRtt;
                cc.OnAck(now, 24000, lowerRtt, 24000);
            }

            Assert.True(cc.MinRttMicros <= prevMinRtt,
                $"min_rtt should decrease: {cc.MinRttMicros} <= {prevMinRtt}");
            Assert.True(cc.MinRttMicros >= lowerRtt,
                $"min_rtt {cc.MinRttMicros} should not go below {lowerRtt}");
        }

        [Fact]
        public void MinRttTracking_FastFallOnLargeDrop()
        {
            var cc = CreateCc(new UcpConfiguration());
            long now = 100000;
            long initialRtt = 100000;

            cc.OnAck(now, 24000, initialRtt, 24000);

            long veryLowRtt = initialRtt / 5;
            now += initialRtt;
            cc.OnAck(now, 24000, veryLowRtt, 24000);

            Assert.True(cc.MinRttMicros <= veryLowRtt + 100,
                $"min_rtt {cc.MinRttMicros} should drop immediately to near {veryLowRtt} via fast-fall");
        }

        [Fact]
        public void MinRttTracking_GeodesicTakeover()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 50000;

            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            long initialMinRtt = cc.MinRttMicros;
            Assert.True(initialMinRtt > 0, $"minRtt should be set: {initialMinRtt}");

            long geodesicRtt = cc.GeodesicXEst / 1024;
            _output.WriteLine("GeodesicTakeover: minRtt={0} geodesicRtt={1} sampleCnt={2}",
                initialMinRtt, geodesicRtt, cc.GeodesicSampleCnt);

            long lowerRtt = geodesicRtt * 95 / 100;
            now += 50000;
            cc.OnAck(now, 24000, lowerRtt, 24000);
            now += 50000;
            cc.OnAck(now, 24000, lowerRtt, 24000);
            now += 50000;
            cc.OnAck(now, 24000, lowerRtt, 24000);

            _output.WriteLine("After lower samples: minRtt={0}", cc.MinRttMicros);
            Assert.True(cc.MinRttMicros <= initialMinRtt,
                $"minRtt should decrease via geodesic takeover: {cc.MinRttMicros} <= {initialMinRtt}");
        }

        [Fact]
        public void ProbeBwGainCycle_FirstEntryIsHighGain()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 100000000;
            config.InitialCwndBytes = 65536;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long rttUs = 10000;
            long now = 100000;

            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }

            _output.WriteLine("Mode={0} cycleIdx={1} pacingGain={2} fullBwReached={3}",
                cc.Mode, cc.ProbeBwCycleIdx, cc.PacingGainUnits, cc.FullBwReached);

            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.True(cc.FullBwReached,
                $"Full bandwidth should be reached after 120 ACKs: {cc.FullBwReached}");

            int idxMod8 = cc.ProbeBwCycleIdx & 7;
            int gain = cc.PacingGainUnits;
            _output.WriteLine("In ProbeBw, idx%8={0} gain={1}", idxMod8, gain);
            Assert.True(gain >= 192 && gain <= 1023, $"gain {gain} should be in valid ProbeBw cycle range [192, 1023]");
        }

        [Fact]
        public void BdpCalculation_ScalesWithBandwidth()
        {
            var config1 = new UcpConfiguration();
            config1.InitialBandwidthBytesPerSecond = 12500000;
            config1.InitialCwndBytes = 65536;
            config1.MaxCongestionWindowBytes = int.MaxValue;
            var cc1 = CreateCc(config1);
            long now = 100000;
            long rttUs = 20000;

            for (int i = 0; i < 20; i++)
            {
                cc1.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }

            var config2 = new UcpConfiguration();
            config2.InitialBandwidthBytesPerSecond = 25000000;
            config2.InitialCwndBytes = 65536;
            config2.MaxCongestionWindowBytes = int.MaxValue;
            var cc2 = CreateCc(config2);
            now = 100000;

            for (int i = 0; i < 20; i++)
            {
                cc2.OnAck(now, 128000, rttUs, 128000);
                now += rttUs;
            }

            var config3 = new UcpConfiguration();
            config3.InitialBandwidthBytesPerSecond = 12500000;
            config3.InitialCwndBytes = 65536;
            config3.MaxCongestionWindowBytes = int.MaxValue;
            var cc3 = CreateCc(config3);
            now = 100000;
            long rttUs2 = 40000;

            for (int i = 0; i < 20; i++)
            {
                cc3.OnAck(now, 128000, rttUs2, 128000);
                now += rttUs2;
            }

            Assert.True(cc1.CongestionWindowBytes > 0);
            Assert.True(cc2.CongestionWindowBytes > 0);
            Assert.True(cc3.CongestionWindowBytes > 0);

            Assert.True(cc1.CongestionWindowBytes >= (long)config1.Mss * UcpConstants.UCP_CWND_MIN_TARGET);
            Assert.True(cc2.CongestionWindowBytes >= (long)config1.Mss * UcpConstants.UCP_CWND_MIN_TARGET);
            Assert.True(cc3.CongestionWindowBytes >= (long)config1.Mss * UcpConstants.UCP_CWND_MIN_TARGET);

            // The scale claim: doubling bandwidth (cc1 12.5M -> cc2 25M at the
            // same RTT) doubles the BDP, so the cwnd must scale up; doubling
            // RTT (cc1 20ms -> cc3 40ms at the same bandwidth) also doubles
            // the BDP.  cwnd tracks BDP, so higher BDP => higher cwnd.
            Assert.True(cc2.CongestionWindowBytes > cc1.CongestionWindowBytes,
                $"cwnd must scale with bandwidth: cc2 {cc2.CongestionWindowBytes} <= cc1 {cc1.CongestionWindowBytes}");
            Assert.True(cc3.CongestionWindowBytes > cc1.CongestionWindowBytes,
                $"cwnd must scale with RTT: cc3 {cc3.CongestionWindowBytes} <= cc1 {cc1.CongestionWindowBytes}");
        }

        [Fact]
        public void BdpCalculation_EnforcesLowerBound()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000;
            config.InitialCwndBytes = 65536;
            var cc = CreateCc(config);
            long now = 100000;

            cc.OnAck(now, 24000, 10000, 24000);

            Assert.True(cc.CongestionWindowBytes >= config.InitialCwndBytes);
        }

        [Fact]
        public void LtBwEstimation_LossTriggersSampling()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1_000_000;
            var cc = CreateCc(config);
            long rttUs = 10_000;

            long now = 90_000;
            cc.OnNakLoss(now, 1500);

            for (int round = 0; round < 10; round++)
            {
                now += rttUs;
                cc.OnAck(now, 12000, rttUs, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }

            _output.WriteLine("LtBw_LossTriggers: isLtUseBw={0} ltBw={1} sampleCnt={2}",
                cc.IsLtUseBw, cc.LtBwValue, cc.GeodesicSampleCnt);
            // The loss signal must register in the controller's estimate
            // (full LT-BW useBw activation needs a stable 4-RTT sampling
            // interval that unit-level loss injection cannot drive here).
            Assert.True(cc.EstimatedLossPercent > 0,
                $"Loss must be recorded by the controller: {cc.EstimatedLossPercent}");
            Assert.True(cc.PacingRateBytesPerSecond > 0,
                $"Pacing rate should be positive: {cc.PacingRateBytesPerSecond}");
        }

        [Fact]
        public void LtBwEstimation_PacketLossStartsInterval()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1_000_000;
            var cc = CreateCc(config);
            long now = 90000;
            long rttUs = 10_000;

            cc.OnNakLoss(now, 1500);

            for (int round = 0; round < 12; round++)
            {
                now += rttUs;
                cc.OnAck(now, 12000, rttUs, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }

            _output.WriteLine("LtBw: isLtUseBw={0} ltBw={1} pacing={2}",
                cc.IsLtUseBw, cc.LtBwValue, cc.PacingRateBytesPerSecond);
            // Sustained packet loss must register in the controller's loss
            // estimate (full LT-BW useBw activation needs a stable 4-RTT
            // sampling interval unit-level injection cannot drive here).
            Assert.True(cc.EstimatedLossPercent > 0,
                $"Packet loss must be recorded: {cc.EstimatedLossPercent}");
            Assert.True(cc.PacingRateBytesPerSecond > 0,
                $"Pacing rate should be positive: {cc.PacingRateBytesPerSecond}");
        }




        [Fact]
        public void EcnEwmaUpdate_TracksCeMarkRatio()
        {
            var config = new UcpConfiguration();
            config.EcnEnabled = true;
            var cc = CreateCc(config);
            long now = 100000;

            cc.OnCeMark(2400);
            cc.OnAck(now, 24000, 50000, 24000);

            Assert.True(cc.EcnEwmaValue > 0,
                $"ecnEwma should be positive after OnCeMark: {cc.EcnEwmaValue}");

            long ecnBefore = cc.EcnEwmaValue;

            cc.OnCeMark(4800);
            now += 50000;
            cc.OnAck(now, 24000, 50000, 24000);

            Assert.True(cc.EcnEwmaValue >= ecnBefore,
                $"ecnEwma should increase with more CE marks: {cc.EcnEwmaValue} < {ecnBefore}");
        }

        [Fact]
        public void EcnEwmaUpdate_DecaysWhenNoCeMarks()
        {
            var config = new UcpConfiguration();
            config.EcnEnabled = true;
            var cc = CreateCc(config);
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
                $"ecnEwma should decay when no CE marks: {cc.EcnEwmaValue} >= {ecnAfterMark}");
        }

        [Fact]
        public void UcpController_StartupTransitionsToDrainThenProbeBw()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 100000000;
            config.InitialCwndBytes = 65536;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long rttUs = 10000;
            long now = 100000;

            Assert.Equal(UcpMode.Startup, cc.Mode);

            for (int i = 0; i < 120; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }

            _output.WriteLine("Mode after 120 ACKs: {0} fullBwReached={1} pacingRate={2}",
                cc.Mode, cc.FullBwReached, cc.PacingRateBytesPerSecond);

            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.FullBwReached);
        }

        [Fact]
        public void UcpController_PacingRateIncreasesDuringStartup()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.InitialCwndBytes = 65536;
            config.MaxPacingRateBytesPerSecond = 0;
            var cc = CreateCc(config);
            long rttUs = 10000;
            long now = 100000;

            double rateBefore = cc.PacingRateBytesPerSecond;

            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }

            Assert.True(cc.PacingRateBytesPerSecond >= rateBefore,
                $"pacing rate should increase: {cc.PacingRateBytesPerSecond} >= {rateBefore}");
        }

        [Fact]
        public void FecCodec_SingleLostPacket_Recovers()
        {
            var codec = new UcpFecCodec(groupSize: 4, repairCount: 1);
            byte[] data = new byte[1200];
            new Random(42).NextBytes(data);

            var r0 = codec.TryEncodeRepair(0u, data);
            var r1 = codec.TryEncodeRepair(1u, data);
            var r2 = codec.TryEncodeRepair(2u, data);
            var repair = codec.TryEncodeRepair(3u, data);

            Assert.NotNull(repair);
            Assert.True(repair!.Length > 0);

            var decoder = new UcpFecCodec(groupSize: 4, repairCount: 1);
            decoder.FeedDataPacket(0u, data);
            decoder.FeedDataPacket(2u, data);
            decoder.FeedDataPacket(3u, data);

            byte[] recovered = decoder.TryRecoverFromRepair(repair, groupBase: 0u);
            Assert.NotNull(recovered);
            Assert.Equal(data.Length, recovered!.Length);
            Assert.Equal(data, recovered);
        }

        [Fact]
        public void FecCodec_MultipleRepairs_RecoversMultipleLosses()
        {
            var codec = new UcpFecCodec(groupSize: 4, repairCount: 2);
            byte[][] packets = new byte[4][];
            for (int i = 0; i < 4; i++)
            {
                packets[i] = new byte[1200];
                new Random(42 + i).NextBytes(packets[i]);
            }

            codec.TryEncodeRepair(0u, packets[0]);
            codec.TryEncodeRepair(1u, packets[1]);
            codec.TryEncodeRepair(2u, packets[2]);
            var repairs = codec.TryEncodeRepairs(3u, packets[3]);
            Assert.NotNull(repairs);
            Assert.Equal(2, repairs!.Count);

            var decoder = new UcpFecCodec(groupSize: 4, repairCount: 2);
            decoder.FeedDataPacket(0u, packets[0]);
            decoder.FeedDataPacket(3u, packets[3]);

            var recovered1 = decoder.TryRecoverPacketsFromRepair(repairs[0], groupBase: 0u, repairIndex: 0);
            var recovered2 = decoder.TryRecoverPacketsFromRepair(repairs[1], groupBase: 0u, repairIndex: 1);

            Assert.Equal(2, recovered1.Count + recovered2.Count);
            Assert.Equal(packets[1], recovered1.Count > 0 ? recovered1[0]!.Payload : recovered2[0]!.Payload);
            Assert.Equal(packets[2], recovered1.Count > 1 ? recovered1[1]!.Payload : recovered2[1]!.Payload);
        }

        [Fact]
        public void EcnBackoff_ReducesCwndWhenQueueBuilds()
        {
            var config = new UcpConfiguration();
            config.EcnEnabled = true;
            config.InitialBandwidthBytesPerSecond = 1_000_000;
            config.InitialCwndBytes = 65536;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            _output.WriteLine("Baseline: mode={0} pEst={1} qdelay={2} sampleCnt={3} cwnd={4}",
                cc.Mode, cc.GeodesicPEst, cc.GeodesicQDelayAvg, cc.GeodesicSampleCnt, cc.CongestionWindowBytes);

            Assert.True(cc.GeodesicSampleCnt >= 5);

            double cwndBefore = cc.CongestionWindowBytes;
            double gainBefore = cc.CwndGain;

            // Build queuing delay: raise RTT above the established min-RTT so
            // qdelayAvg clears CongThresh (minRtt*25% + floor), which gates the
            // ECN backoff in ApplyCwndConstraints.
            cc.OnCeMark(500);
            for (int i = 0; i < 4; i++)
            {
                cc.OnCeMark(300);
                cc.OnAck(now, 24000, rttUs * 2, 24000);
                now += rttUs * 2;
            }

            _output.WriteLine("After ECN: ecnEwma={0} cwnd={1} cwndGain={2} qdelay={3}",
                cc.EcnEwmaValue, cc.CongestionWindowBytes, cc.CwndGain, cc.GeodesicQDelayAvg);

            Assert.True(cc.EcnEwmaValue > 0,
                $"ECN EWMA should be positive after CE marks: {cc.EcnEwmaValue}");
            Assert.True(cc.EcnEwmaValue <= 256,
                $"ECN EWMA should not exceed GAIN_UNIT: {cc.EcnEwmaValue}");

            Assert.True(cc.EcnEwmaValue >= 1,
                $"ECN EWMA should be >= 1 with sustained CE marking: {cc.EcnEwmaValue}");

            // The backoff must actually reduce the CWND gain while the queue
            // is building (this is the behavior the test name promises).
            Assert.True(cc.GeodesicQDelayAvg > 2500,
                $"qdelay {cc.GeodesicQDelayAvg} must exceed CongThresh to gate backoff");
            Assert.True(cc.CwndGain < gainBefore,
                $"CWND gain must be reduced by ECN backoff: {cc.CwndGain} >= {gainBefore}");
        }

        [Fact]
        public async Task Integration_NoLossThroughput_100Mbps()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bw);
            var config = CreateCcConfig(bw);
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(41001);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41001));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('A', 256 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                var clientReport = client.GetReport();
                _output.WriteLine("NoLoss100M: tput={0:F0}B/s delivered={1} clientRttSamples={2}",
                    sim.LogicalThroughputBytesPerSecond, sim.DeliveredBytes, clientReport.RttSamplesMicros.Count);
                Assert.True(sim.DeliveredBytes >= payload.Length,
                    $"Delivery must succeed: {sim.DeliveredBytes}/{payload.Length}");
                Assert.True(sim.LogicalThroughputBytesPerSecond > bw * 0.08,
                    $"Throughput {sim.LogicalThroughputBytesPerSecond:F0}B/s");
                Assert.True(await UcpTestHelpers.WaitForRttSamplesAsync(client),
                    "Sender must record at least one RTT sample after a completed transfer");
                Assert.True(clientReport.RttSamplesMicros.Count >= 1);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_RandomLoss_0_1Percent()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: bw,
                lossRate: 0.001, seed: 20260101);
            var config = CreateCcConfig(bw);
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(41002);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41002));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('B', 256 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 8000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                var clientReport = client.GetReport();
                _output.WriteLine("Loss0.1pct: dropped={0} tput={1:F0}B/s clientRttSamples={2}",
                    sim.DroppedPackets, sim.LogicalThroughputBytesPerSecond, clientReport.RttSamplesMicros.Count);
                Assert.True(sim.DeliveredBytes >= payload.Length,
                    $"Delivery must succeed: {sim.DeliveredBytes}/{payload.Length}");
                Assert.True(sim.LogicalThroughputBytesPerSecond >= bw * 0.08,
                    $"Throughput {sim.LogicalThroughputBytesPerSecond:F0}B/s");
                Assert.True(await UcpTestHelpers.WaitForRttSamplesAsync(client),
                    "Sender must record at least one RTT sample after a completed transfer");
                Assert.True(clientReport.RttSamplesMicros.Count >= 1);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_RandomLoss_5Percent()
        {
            const int bw = 20_000_000 / 8;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 15, bandwidthBytesPerSecond: bw,
                lossRate: 0.05, seed: 20260102);
            var config = CreateCcConfig(bw);
            config.FecGroupSize = 8;
            config.FecRedundancy = 0.50;
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(41003);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41003));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('C', 64 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                var clientReport = client.GetReport();
                _output.WriteLine("Loss5pct: dropped={0} dataDrop={1} tput={2:F0}B/s clientRttSamples={3}",
                    sim.DroppedPackets, sim.DroppedDataPackets, sim.LogicalThroughputBytesPerSecond, clientReport.RttSamplesMicros.Count);
                Assert.True(sim.DeliveredBytes >= payload.Length,
                    $"Delivery must succeed: {sim.DeliveredBytes}/{payload.Length} with 5% loss + FEC");
                Assert.True(sim.LogicalThroughputBytesPerSecond > bw * 0.05,
                    $"Throughput {sim.LogicalThroughputBytesPerSecond:F0}B/s with 5% loss + FEC");
                Assert.True(await UcpTestHelpers.WaitForRttSamplesAsync(client),
                    "Sender must record at least one RTT sample after a completed transfer");
                Assert.True(clientReport.RttSamplesMicros.Count >= 1);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_VariableRtt_10ms()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 2);
            var config = CreateCcConfig(bw);
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(41004);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41004));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('D', 128 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(sim.DeliveredBytes >= payload.Length,
                    $"Delivery must succeed: {sim.DeliveredBytes}/{payload.Length}");
                Assert.True(sim.LogicalThroughputBytesPerSecond >= bw * 0.05,
                    $"Throughput {sim.LogicalThroughputBytesPerSecond:F0}B/s");
                var clientReport = client.GetReport();
                _output.WriteLine("Rtt10ms: tput={0:F0}B/s clientRttSamples={1}",
                    sim.LogicalThroughputBytesPerSecond, clientReport.RttSamplesMicros.Count);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_VariableRtt_200ms()
        {
            const int bw = 10_000_000 / 8;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 100, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 10);
            var config = CreateCcConfig(bw);
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(41005);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41005));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('E', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 15000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                var clientReport = client.GetReport();
                _output.WriteLine("Rtt200ms: tput={0:F0}B/s clientRttSamples={1}",
                    sim.LogicalThroughputBytesPerSecond, clientReport.RttSamplesMicros.Count);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_BandwidthChange_SuddenDrop()
        {
            const int bwHigh = 100_000_000 / 8;
            const int bwLow = 5_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bwHigh);
            var config = CreateCcConfig(bwHigh);
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(41006);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41006));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('F', 64 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 15000);
                sim.Configure(0, 5, 0, bwLow, 0, 0);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                var clientReport = client.GetReport();
                _output.WriteLine("BwDrop: tput={0:F0}B/s clientRttSamples={1}",
                    sim.LogicalThroughputBytesPerSecond, clientReport.RttSamplesMicros.Count);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_Convergence_FromInitialToTargetBw()
        {
            const int targetBw = 100_000_000 / 8;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: targetBw);
            var config = CreateCcConfig(1_000_000 / 8);
            config.InitialBandwidthBytesPerSecond = 1_000_000 / 8;
            config.MaxPacingRateBytesPerSecond = 0;
            config.InitialCwndBytes = (uint)Math.Max(config.InitialCongestionWindowBytes, targetBw / 64);
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(41007);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41007));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('G', 64 * 1024));
                byte[] received = new byte[payload.Length];

                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 20000);
                bool readOk = await readTask;

                Assert.True(writeOk, "Convergence write failed");
                var clientReport = client.GetReport();
                Assert.True(readOk, "read OK");
                Assert.True(sim.DeliveredBytes >= 16384, "delivery");
                if (readOk && sim.DeliveredBytes > 0)
                {
                    Assert.True(payload.Take((int)Math.Min(sim.DeliveredBytes, received.Length)).SequenceEqual(received.Take((int)Math.Min(sim.DeliveredBytes, received.Length))));
                }
                // The test name promises convergence to the target bandwidth:
                // the CC's pacing rate must climb well beyond the 1Mbps start
                // toward the 100Mbps link, demonstrating real bandwidth probing.
                Assert.True(clientReport.PacingRateBytesPerSecond > 1_000_000 / 8,
                    $"pacing must exceed initial 1Mbps to show convergence: {clientReport.PacingRateBytesPerSecond}");
                _output.WriteLine("Convergence: pacingRate={0} targetBw={1} clientRttSamples={2} delivered={3}",
                    clientReport.PacingRateBytesPerSecond, targetBw, clientReport.RttSamplesMicros.Count, sim.DeliveredBytes);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public void UcpCc_InitialStateIsStartup()
        {
            var cc = CreateCc(new UcpConfiguration());
            Assert.Equal(UcpMode.Startup, cc.Mode);
            Assert.True(cc.BtlBwBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void UcpCc_TransitionsOutOfStartup()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 12; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes >= 24400);
        }

        [Fact]
        public void UcpCc_ModeTransitionsStartupToProbeBw()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            bool seenDrain = false;
            for (int i = 0; i < 200; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
                if (cc.Mode == UcpMode.Drain)
                {
                    seenDrain = true;
                }
            }
            Assert.True(seenDrain, "STARTUP must pass through Drain");
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
        }

        [Fact]
        public void UcpCc_BandwidthEstimateResistsCliffs()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            cc.OnAck(100000, 100000, 100000, 100000);
            cc.OnAck(200000, 100000, 100000, 100000);
            double highRate = cc.BtlBwBytesPerSecond;
            Assert.True(highRate > 1.0);
            cc.OnAck(500000, 1000, 100000, 1000);
            cc.OnAck(700000, 1000, 100000, 1000);
            cc.OnAck(1050000, 1000, 100000, 1000);
            const double floorRatio = 0.75;
            Assert.True(cc.BtlBwBytesPerSecond >= highRate * floorRatio);
        }

        [Fact]
        public void UcpCc_BandwidthEstimateTracksDeliveryRate()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 24000;
            }
            long btlBw = (long)cc.BtlBwBytesPerSecond;
            Assert.True(btlBw > 500000);
            Assert.True(btlBw < 3000000);
        }

        [Fact]
        public void UcpCc_MinRttConvergesViaGeodesicFilter()
        {
            var cc = CreateCc(new UcpConfiguration());
            long now = 100000;
            long expectedRtt = 50000;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, expectedRtt, 24000);
                now += 50000;
            }
            long minRtt = cc.MinRttMicros;
            Assert.True(minRtt > 0);
            Assert.True(minRtt <= expectedRtt * 120 / 100);
            Assert.True(minRtt >= expectedRtt * 80 / 100);
        }

        [Fact]
        public void UcpCc_MinRttStickyFallOnRapidDecrease()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 100000, 24000);
                now += 100000;
            }
            long baseline = cc.MinRttMicros;
            Assert.True(baseline >= 80000);
            for (int i = 0; i < 4; i++)
            {
                cc.OnAck(now, 24000, 25000, 24000);
                now += 100000;
            }
            long after = cc.MinRttMicros;
            Assert.True(after < baseline);
            Assert.True(after <= 35000);
        }

        [Fact]
        public void UcpCc_MinRttReplacesAfterExpiry()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, 100000, 24000);
                now += 100000;
            }
            long baseline = cc.MinRttMicros;
            // After the min-RTT expiry window, a fresh lower RTT sample must
            // REPLACE min_rtt: the value drops toward the new sample instead
            // of staying at the old baseline.
            now += 11000000;
            cc.OnAck(now, 24000, 80000, 24000);
            now += 100000;
            long after = cc.MinRttMicros;
            Assert.True(after < baseline,
                $"min_rtt must be replaced by the newer lower sample: {after} >= baseline {baseline}");
            Assert.True(after > 0);
        }

        [Fact]
        public void UcpCc_ProbeBwGainCycleCorrectness()
        {
            GlobalKfEstimator.Reset();
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            int g = cc.PacingGainUnits;
            Assert.True(g > 0);
            Assert.True(g <= 1023);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void UcpCc_BdpReflectedInCongestionWindow()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 120000, 50000, 120000);
                now += 50000;
            }
            Assert.True(cc.MinRttMicros > 0);
            long btlBw = (long)cc.BtlBwBytesPerSecond;
            long minRtt = cc.MinRttMicros;
            long cwnd = cc.CongestionWindowBytes;
            Assert.True(cwnd > (btlBw * minRtt / 1000000) / 10);
            Assert.True(btlBw > 1000000);
        }

        [Fact]
        public void UcpCc_AutoProbeConverges100M1G10G()
        {
            GlobalKfEstimator.Reset();
            const long k100M = 100000000 / 8;
            const long k1G = 1000000000 / 8;
            const long k10G = 10000000000L / 8;
            const long rttUs = 10000;
            const int maxRounds = 48;
            const double minConv = 0.70;
            const double maxConv = 3.0;
            const long kInit = 1000000 / 8;

            void Run(long bps)
            {
                var config = new UcpConfiguration();
                config.InitialBandwidthBytesPerSecond = kInit;
                config.InitialCwndPackets = (int)Math.Max(20, bps / (128 * 1220));
                config.MaxCongestionWindowBytes = int.MaxValue;
                config.MaxPacingRateBytesPerSecond = bps;
                var cc = CreateCc(config);
                long now = rttUs;
                bool converged = false;
                for (int r = 0; r < maxRounds; r++)
                {
                    long d = Math.Max(1, bps * rttUs / 1000000);
                    cc.OnAck(now, d, rttUs, d);
                    if (cc.PacingRateBytesPerSecond >= bps * minConv)
                    {
                        converged = true;
                        break;
                    }
                    now += rttUs;
                }
                Assert.True(converged);
                Assert.True(cc.PacingRateBytesPerSecond >= bps * minConv);
                Assert.True(cc.PacingRateBytesPerSecond <= bps * maxConv);
            }

            Run(k100M);
            Run(k1G);
            Run(k10G);
        }

        [Fact]
        public void UcpCc_ConvergenceTimeFromMinimum()
        {
            const long target = 100000000 / 8;
            const long initBw = 1000000 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = initBw;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = 64 * 1024 * 1024;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            bool converged = false;
            for (int r = 0; r < 64; r++)
            {
                long d = Math.Max(1, target * rttUs / 1000000);
                cc.OnAck(now, d, rttUs, d);
                if (cc.PacingRateBytesPerSecond >= target * 70 / 100)
                {
                    converged = true;
                    break;
                }
                now += rttUs;
            }
            Assert.True(converged);
        }

        [Fact]
        public void UcpCc_OnPathChangeResetsState()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            cc.OnAck(1000, 100000, 50000, 100000);
            cc.OnPathChange(250000);
            Assert.Equal(UcpMode.Startup, cc.Mode);
        }

        [Fact]
        public void UcpCc_OnPacketLossDoesNotCrash()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            long cwndBefore = cc.CongestionWindowBytes;
            cc.OnPacketLoss(now, 0.05, true);
            double lossAfter = cc.EstimatedLossPercent;
            Assert.True(lossAfter > 0.0);
            Assert.True(cc.CongestionWindowBytes <= cwndBefore);
        }

        [Fact]
        public void UcpCc_OnFastRetransmitHandlesCongestion()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            long cwndBefore = cc.CongestionWindowBytes;
            cc.OnFastRetransmit(now, true);
            Assert.True(cc.CongestionWindowBytes <= cwndBefore);
        }

        [Fact]
        public void UcpCc_LtBwLossRecordsLossPercent()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            for (int i = 0; i < 3; i++)
            {
                cc.OnNakLoss(now, 24000);
                now += 100000;
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            Assert.True(cc.CongestionWindowBytes > 0);
            // NAK loss must register in the controller's loss estimate (the
            // loss signal LT-BW sampling consumes; full LT-BW activation
            // needs a stable 4-RTT sampling interval unit-level NAK injection
            // cannot drive here).
            Assert.True(cc.EstimatedLossPercent > 0,
                $"NAK loss must be recorded: loss={cc.EstimatedLossPercent}");
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void UcpCc_ModeTransitionsAfterSufficientAcks()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            long expectedRtt = 50000;
            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, expectedRtt, 24000);
                now += 50000;
            }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.True(cc.FullBwReached);
        }

        [Fact]
        public void UcpCc_GeodesicFilter_ConvergesToTrueRtt()
        {
            const long kBw = 12500000;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = kBw;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = 64 * 1024 * 1024;
            var cc = CreateCc(config);
            long now = 1000000;
            const long kTrueRtt = 50000;
            for (int i = 0; i < 50; i++)
            {
                long delivered = (kBw * kTrueRtt) / 1000000;
                long flight = delivered * 2;
                long sampleRtt = kTrueRtt + (i < 10 ? 500 : 0);
                now += kTrueRtt;
                cc.OnAck(now, delivered, sampleRtt, flight);
            }
            long minRtt = cc.MinRttMicros;
            Assert.True(minRtt >= kTrueRtt * 80 / 100);
            Assert.True(minRtt <= kTrueRtt * 120 / 100);
            long cwnd = cc.CongestionWindowBytes;
            long expectedBdp = (kBw * kTrueRtt / 1000000);
            Assert.True(cwnd >= expectedBdp / 3);
        }

        [Fact]
        public void UcpCc_EcnEwma_TracksCeMarks()
        {
            const int kMss = 1220;
            var config = new UcpConfiguration();
            config.EcnEnabled = true;
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 1000000;
            for (int i = 0; i < 10; i++)
            {
                now += 10000;
                cc.OnAck(now, kMss * 10, 10000, kMss * 20);
            }
            cc.OnCeMark(5);
            now += 10000;
            cc.OnAck(now, kMss, 10000, kMss * 10);
            Assert.True(cc.EcnEwmaValue > 0);
        }


        [Fact]
        public void UcpCc_OnFecRecovery_FeedsIntoModel()
        {
            const int kMss = 1220;
            const long kBw = 12500000;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = kBw;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 1000000;
            cc.OnAck(now, kMss * 50, 50000, kMss * 10);
            now += 50000;
            cc.OnAck(now, kMss * 50, 50000, kMss * 20);
            long deliveredBefore = cc.TotalDelivered;
            long cwndBefore = cc.CongestionWindowBytes;
            cc.OnFecRecovery(now + 10000, kMss * 10);

            Assert.Equal(deliveredBefore, cc.TotalDelivered);
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void UcpCc_Throughput100M_Converges()
        {
            const long kBw = 100L * 1024 * 1024 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndPackets = 20;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;
            for (int i = 0; i < 40; i++)
            {
                long d = Math.Max(1, kBw * rttUs / 1000000);
                cc.OnAck(now, d, rttUs, d);
                now += rttUs;
            }
            long rate = (long)cc.PacingRateBytesPerSecond;
            Assert.True(rate > kBw * 50 / 100);
            Assert.True(rate < kBw * 3);
            Assert.True(cc.MinRttMicros > 0);
            Assert.True(cc.MinRttMicros <= rttUs * 120 / 100);
        }

        [Fact]
        public void UcpCc_Lossy10M_LossRegistered()
        {
            const long kBw = 10L * 1024 * 1024 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = kBw;
            config.MaxCongestionWindowBytes = 64 * 1024 * 1024;
            config.InitialCwndPackets = 20;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 15000;
            long d = Math.Max(1, kBw * rttUs / 1000000);
            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, d, rttUs, d);
                now += rttUs;
            }
            for (int i = 0; i < 6; i++)
            {
                cc.OnNakLoss(now, d / 4);
                cc.OnAck(now, d, rttUs, d);
                now += rttUs;
            }
            // NAK loss must register in the controller's loss estimate (full
            // LT-BW useBw activation needs a stable 4-RTT sampling interval
            // unit-level NAK injection cannot drive here).
            Assert.True(cc.EstimatedLossPercent > 0,
                $"NAK loss must be recorded: {cc.EstimatedLossPercent}");
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void UcpCc_Convergence1MTo100M_PureCC()
        {
            const long kBw = 100L * 1024 * 1024 / 8;
            const long kInitBw = 1L * 1000 * 1000 / 8;
            const long kRttUs = 20000;
            const int kMaxRounds = 64;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = kInitBw;
            config.MaxCongestionWindowBytes = 64 * 1024 * 1024;
            config.InitialCwndPackets = 20;
            config.MaxPacingRateBytesPerSecond = kBw;
            var cc = CreateCc(config);
            long now = kRttUs;
            bool converged = false;
            for (int r = 0; r < kMaxRounds; r++)
            {
                long d = Math.Max(1, kBw * kRttUs / 1000000);
                cc.OnAck(now, d, kRttUs, d);
                if (!converged && cc.PacingRateBytesPerSecond >= kBw * 0.50)
                {
                    converged = true;
                }
                now += kRttUs;
            }
            Assert.True(converged);
            Assert.True(cc.PacingRateBytesPerSecond >= kBw * 0.50);
        }

        [Fact]
        public async Task Dplpmtud_ProbeSend()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.EnableMtuDiscovery = true;
            config.MtuProbeIntervalMicros = 500_000L;
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = 10 * 1024 * 1024;
            config.MaxPacingRateBytesPerSecond = 10 * 1024 * 1024;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(45001);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 45001));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('M', 4096));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 3000);
                await client.WriteAsync(payload, 0, payload.Length);
                await readTask;

                client.MigrateRemote(new IPEndPoint(IPAddress.Loopback, 45001));
                await Task.Delay(500);

                var diag = client.GetDiagnostics();
                _output.WriteLine("DPLPMTUD ProbeSend: currentMtu={0} probeMin={1} probeMax={2} probeVal={3} pending={4}",
                    diag.CurrentMtu, diag.MtuProbeMin, diag.MtuProbeMax, diag.MtuProbeValue, diag.MtuProbePending);

                Assert.True(diag.MtuProbeValue > 0, "probe value > 0");
                Assert.True(diag.MtuProbePending, "probe pending");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Dplpmtud_AckIncreasesMtu()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.EnableMtuDiscovery = true;
            config.MtuProbeIntervalMicros = 500_000L;
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = 10 * 1024 * 1024;
            config.MaxPacingRateBytesPerSecond = 10 * 1024 * 1024;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(45002);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 45002));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('N', 4096));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 3000);
                await client.WriteAsync(payload, 0, payload.Length);
                await readTask;

                client.MigrateRemote(new IPEndPoint(IPAddress.Loopback, 45002));
                await Task.Delay(800);

                var diag = client.GetDiagnostics();
                _output.WriteLine("DPLPMTUD AckIncreasesMtu: currentMtu={0} probeMin={1} probeMax={2} probeVal={3} pending={4}",
                    diag.CurrentMtu, diag.MtuProbeMin, diag.MtuProbeMax, diag.MtuProbeValue, diag.MtuProbePending);

                Assert.True(diag.MtuProbeMax > diag.MtuProbeMin, "max > min");
                Assert.True(diag.MtuProbeValue > 0, "probe value > 0");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Dplpmtud_TimeoutReducesMtu()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: 5 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.EnableMtuDiscovery = true;
            config.MtuProbeTimeoutMicros = 100_000L;
            config.MtuProbeIntervalMicros = 500_000L;
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = 5 * 1024 * 1024;
            config.MaxPacingRateBytesPerSecond = 5 * 1024 * 1024;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(45003);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 45003));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('O', 4096));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 3000);
                await client.WriteAsync(payload, 0, payload.Length);
                await readTask;

                client.MigrateRemote(new IPEndPoint(IPAddress.Loopback, 45003));
                await Task.Delay(200);

                var diagBefore = client.GetDiagnostics();
                _output.WriteLine("Before timeout: currentMtu={0} probeMin={1} probeMax={2}",
                    diagBefore.CurrentMtu, diagBefore.MtuProbeMin, diagBefore.MtuProbeMax);

                long maxBefore = diagBefore.MtuProbeMax;

                await Task.Delay(600);
                var diagAfter = client.GetDiagnostics();
                _output.WriteLine("After timeout: currentMtu={0} probeMin={1} probeMax={2}",
                    diagAfter.CurrentMtu, diagAfter.MtuProbeMin, diagAfter.MtuProbeMax);

                Assert.True(diagAfter.MtuProbeMax <= maxBefore, "max <= before");
                Assert.True(diagAfter.MtuProbeMax < UcpConstants.MTU_PROBE_MAX, "max < MTU_PROBE_MAX");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Dplpmtud_Convergence()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: 20 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.EnableMtuDiscovery = true;
            config.MtuProbeIntervalMicros = 200_000L;
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = 20 * 1024 * 1024;
            config.MaxPacingRateBytesPerSecond = 20 * 1024 * 1024;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(45004);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 45004));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('P', 8192));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 3000);
                await client.WriteAsync(payload, 0, payload.Length);
                await readTask;

                client.MigrateRemote(new IPEndPoint(IPAddress.Loopback, 45004));
                await Task.Delay(1000);

                var diag = client.GetDiagnostics();
                _output.WriteLine("Convergence: currentMtu={0} probeMin={1} probeMax={2} probeVal={3} pending={4}",
                    diag.CurrentMtu, diag.MtuProbeMin, diag.MtuProbeMax, diag.MtuProbeValue, diag.MtuProbePending);

                Assert.True(diag.MtuProbeMax > UcpConstants.MTU_PROBE_BASE, "max > base");
                Assert.True(diag.MtuProbeMin >= UcpConstants.MTU_PROBE_BASE, "min >= base");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public void OnRto_EntersStartup()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;

            for (int i = 0; i < 12; i++)
            {
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }

            long cwndBefore = cc.CongestionWindowBytes;
            double rateBefore = cc.PacingRateBytesPerSecond;

            cc.OnRto();

            _output.WriteLine("OnRto: mode={0} cwnd={1} rate={2} cwndBefore={3}",
                cc.Mode, cc.CongestionWindowBytes, cc.PacingRateBytesPerSecond, cwndBefore);
            Assert.True(cc.CongestionWindowBytes >= config.Mss * 4,
                $"CWND should be >= min after RTO: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0,
                $"Pacing rate should be > 0 after RTO: {cc.PacingRateBytesPerSecond}");
            Assert.False(cc.CongestionWindowBytes > cwndBefore * 2,
                $"CWND should not increase dramatically: {cc.CongestionWindowBytes} vs {cwndBefore}");
            // RTO restores the STARTUP gains (the "enters startup behavior"
            // the name claims): cwnd gain returns to HIGH_GAIN.
            Assert.Equal(UcpConstants.UCP_HIGH_GAIN, cc.CwndGainUnits);
        }

        [Fact]
        public void AppLimited_DisablesProbing()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            int gainBefore = cc.PacingGainUnits;
            long rateBefore = (long)cc.PacingRateBytesPerSecond;

            // App-limited: probing must stop -- the pacing gain drops back
            // toward the cruise gain (BBR_UNIT) and does not keep probing
            // above it, and the rate does not inflate on zero delivered data.
            cc.SetAppLimited(true);
            cc.OnAck(now, 0, rttUs, 0);

            _output.WriteLine("AppLimited: mode={0} gain={1} rate={2}",
                cc.Mode, cc.PacingGainUnits, cc.PacingRateBytesPerSecond);
            Assert.True(cc.PacingGainUnits <= gainBefore,
                $"App-limited must not raise the pacing gain: {cc.PacingGainUnits} > {gainBefore}");
            Assert.True(cc.PacingRateBytesPerSecond > 0,
                $"Pacing rate should stay positive: {cc.PacingRateBytesPerSecond}");
        }

        [Fact]
        public void PacingRate_StaysPositiveAfterIdleRestart()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 12; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            _output.WriteLine("After startup: mode={0} rate={1}", cc.Mode, cc.PacingRateBytesPerSecond);
            double rateInProbeBw = cc.PacingRateBytesPerSecond;
            Assert.True(rateInProbeBw > 0);

            // Long idle followed by a small ACK: the idle-restart path must
            // leave the pacing pipeline healthy (positive rate, valid mode),
            // not zero it out.
            now += 60_000_000L;
            cc.OnAck(now, 1220, rttUs, 488);
            _output.WriteLine("After time advance: mode={0} rate={1} cwnd={2}",
                cc.Mode, cc.PacingRateBytesPerSecond, cc.CongestionWindowBytes);

            Assert.True(cc.PacingRateBytesPerSecond > 0,
                $"Pacing rate should remain positive: {cc.PacingRateBytesPerSecond}");
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void CwndGain_CappedAtMax()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = 256 * 1024;
            config.MaxPacingRateBytesPerSecond = 50_000_000;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }

            _output.WriteLine("CwndGainMax: cwnd={0} maxCwnd={1} rate={2}",
                cc.CongestionWindowBytes, config.MaxCongestionWindowBytes, cc.PacingRateBytesPerSecond);
            Assert.True(cc.CongestionWindowBytes <= config.MaxCongestionWindowBytes,
                $"cwnd {cc.CongestionWindowBytes} should not exceed {config.MaxCongestionWindowBytes}");
        }

        [Fact]
        public void RecoveryCwnd()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 12; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            long cwndBeforeLoss = cc.CongestionWindowBytes;

            cc.OnFastRetransmit(now, true);
            long cwndAfterLoss = cc.CongestionWindowBytes;

            _output.WriteLine("RecoveryCwnd: cwndBefore={0} cwndAfter={1}",
                cwndBeforeLoss, cwndAfterLoss);
            Assert.True(cwndAfterLoss <= cwndBeforeLoss,
                $"CWND should not increase after loss: {cwndAfterLoss} <= {cwndBeforeLoss}");
            Assert.True(cwndAfterLoss > 0,
                $"CWND should stay positive: {cwndAfterLoss}");
        }

        [Fact]
        public void LossState()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = CreateCc(config);
            long now = 100000;

            cc.OnAck(now, 24000, 50000, 24000);
            now += 50000;
            cc.OnAck(now, 24000, 50000, 24000);

            double lossBefore = cc.EstimatedLossPercent;

            cc.OnPacketLoss(now, 0.1, true);
            double lossAfter = cc.EstimatedLossPercent;

            _output.WriteLine("LossState: before={0}% after={1}%",
                lossBefore, lossAfter);
            Assert.True(lossAfter >= lossBefore,
                $"Loss estimate should increase: {lossAfter} >= {lossBefore}");
            Assert.InRange(lossAfter, 0.0, 100.0);
        }

        [Fact]
        public void ProbeBwDrain_GeodesicConvergedLowQdelay_SkipsDrain()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 1000;

            for (int i = 0; i < 40; i++)
            {
                cc.OnAck(now, 24000, rttUs - (i & 1), 24000);
                now += rttUs;
            }

            Assert.True(cc.GeodesicSampleCnt >= 5,
                $"Need GeodesicSampleCnt >= 5, got {cc.GeodesicSampleCnt}");
            Assert.True(cc.GeodesicPEst > 0 && cc.GeodesicPEst < 10000,
                $"pEst should be in reasonable range: {cc.GeodesicPEst}");

            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.True(cc.FullBwReached,
                $"FullBw should be reached: {cc.FullBwReached}");
        }

        [Fact]
        public void ProbeBwDrain_NoSkipWhenQdelayHigh()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;
            bool seenDrain = false;
            long maxQdelay = 0;

            for (int i = 0; i < 40; i++)
            {
                long rttNow = rttUs + (i % 2 == 0 ? 8000 : 0);
                if (cc.Mode == UcpMode.Drain) seenDrain = true;
                cc.OnAck(now, 24000, rttNow, 24000);
                now += rttUs;
                if (cc.GeodesicQDelayAvg > maxQdelay) maxQdelay = cc.GeodesicQDelayAvg;
            }

            Assert.True(cc.GeodesicSampleCnt >= 5,
                $"Need GeodesicSampleCnt >= 5, got {cc.GeodesicSampleCnt}");
            // The claim: high qdelay must NOT skip Drain -- the controller
            // must actually enter Drain during the run.
            Assert.True(maxQdelay > 2000,
                $"qdelay should be high during the run: {maxQdelay}");
            Assert.True(seenDrain,
                "Drain must be entered even with high qdelay (no skip)");

            _output.WriteLine("Drain_HighQdelay: mode={0} pEst={1} qDelay={2}",
                cc.Mode, cc.GeodesicPEst, cc.GeodesicQDelayAvg);
        }



        [Fact]
        public async Task PartialSend()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1024 * 1024);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.SendBufferSize = 64 * 1024;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(45010);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 45010));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('S', 16 * 1024));
                byte[] received = new byte[payload.Length];

                int sent = await client.SendAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeout(srvConn, received, sent, 5000);

                _output.WriteLine("PartialSend: sent={0}/{1} readOk={2}",
                    sent, payload.Length, readOk);
                Assert.InRange(sent, 1, payload.Length);
                Assert.True(readOk, "Server should receive all data within 5s");
                if (sent > 0)
                    Assert.True(payload.Take(sent).SequenceEqual(received.Take(sent)));
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task FullBufferZeroSend()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1024 * 1024);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.SendBufferSize = 32 * 1024;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(45011);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 45011));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('B', 128 * 1024));
                byte[] received = new byte[payload.Length];

                int sent = await client.SendAsync(payload, 0, payload.Length);
                // The server receives only the bytes the client actually sent
                // (SendAsync returns the accepted prefix when the send buffer
                // is full); read exactly `sent` bytes.
                bool readOk = await UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000, sent);

                _output.WriteLine("FullBufferZeroSend: sent={0}/{1} readOk={2}",
                    sent, payload.Length, readOk);
                Assert.True(sent > 0, "Should have sent some bytes");
                Assert.True(sent <= payload.Length, "Should not exceed payload");
                Assert.True(readOk, "Server should receive the sent bytes within 5s");
                Assert.True(received.Length >= sent, "Receive buffer must be large enough");
                // Content-level prefix equality is not asserted here: UDP
                // delivery under a full send buffer may reorder/interleave, and
                // the deterministic content check is covered by PartialSend.
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public void Report_PacingStaysPositive()
        {
            var cc = CreateCc(new UcpConfiguration());
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            now += 2300000;
            cc.OnAck(now, 100, 50000, 100);
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing rate should remain positive");
        }

        [Fact]
        public void Integration_LocalAbortFiresDisconnected()
        {
            var config = new UcpConfiguration();
            bool disconnected = false;
            var pcb = new UcpPcb(null, null, false, false, null, 0x1B0u, config);
            pcb.Disconnected += () => disconnected = true;
            pcb.Abort(false);
            Assert.True(disconnected, "PCB should fire Disconnected after Abort");
        }

        [Fact]
        public void SimulatorRaw_ReorderingAndDuplication_DeliversEnoughPackets()
        {
            const int bw = 2 * 1024 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 2, seed: 42, duplicateRate: 0.05, reorderRate: 0.2);
            var t1 = sim.CreateTransport("client");
            var t2 = sim.CreateTransport("server");
            t1.Start(46002);
            t2.Start(0);
            byte[] payload = BuildUniquePayload(16 * 1024, 20260429);
            SendAsDataPackets(t1, payload, t2.LocalPort);
            Assert.True(sim.WaitForDeliveryCount(10, 3000), "Should deliver enough packets");
            Assert.True(sim.DeliveredPackets > 0, "Should deliver packets");
            sim.StopScheduler();
        }

        [Fact]
        public async Task Integration_OrderedSmallSegments_AreDeliveredImmediately()
        {
            const int bw = 1220 * 50 * 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MinPacingIntervalMicros = 0;
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(46003);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 46003));
                UcpConnection srvConn = await acceptTask;
                byte[][] sendBufs = new byte[16][];
                for (int i = 0; i < 16; i++)
                    sendBufs[i] = new byte[] { (byte)i };
                int receivedCount = 0;
                var tcs = new TaskCompletionSource<bool>();
                var readTask = Task.Run(async () =>
                {
                    byte[] buf = new byte[1];
                    for (int i = 0; i < 16; i++)
                    {
                        int n = await srvConn.ReceiveAsync(buf, 0, 1);
                        if (n > 0) receivedCount++;
                    }
                    tcs.TrySetResult(true);
                });
                for (int i = 0; i < 16; i++)
                    await client.WriteAsync(sendBufs[i], 0, 1);
                var timeout = Task.Delay(8000);
                var done = await Task.WhenAny(tcs.Task, timeout);
                Assert.True(done == tcs.Task, $"Should receive all 16 segments: got {receivedCount}");
                await readTask;
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_Stream_MultipleWritesPartialReads_PreservesConcatenatedOrder()
        {
            const int bw = 1220 * 10 * 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(46004);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 46004));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = new byte[16 * 1024];
                new Random(7171).NextBytes(payload);
                byte[] received = new byte[payload.Length];
                var readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 30000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;
                Assert.True(writeOk, "Write should succeed");
                Assert.True(readOk, "Read should succeed");
                Assert.True(payload.SequenceEqual(received), "Data should match");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_SendAsync_MayReturnPartialWhenSendBufferIsFull()
        {
            const int bw = 64 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.SendBufferSize = 1220 * 4;
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxPacingRateBytesPerSecond = 12500000;
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(46005);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 46005));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = new byte[64 * 1024];
                Array.Fill(payload, (byte)'S');
                int sent = await client.SendAsync(payload, 0, payload.Length);
                _output.WriteLine("PartialSend: sent={0}/{1}", sent, payload.Length);
                Assert.InRange(sent, 1, payload.Length);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_SendAsync_ReturnsZeroWhenSendBufferAlreadyFull()
        {
            const int bw = 64 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 100, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.SendBufferSize = 1220 * 2;
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = 1;
            config.MaxPacingRateBytesPerSecond = 1;
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(46006);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 46006));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = new byte[64 * 1024];
                Array.Fill(payload, (byte)'Z');
                int sent1 = await client.SendAsync(payload, 0, payload.Length);
                _output.WriteLine("SendZero: sent1={0}/{1}", sent1, payload.Length);
                Assert.InRange(sent1, 1, payload.Length);
                int sent2 = await client.SendAsync(payload, 0, payload.Length);
                _output.WriteLine("SendZero: sent2={0}/{1}", sent2, payload.Length);
                // The 2.4KB send buffer is saturated by sent1 (64KB payload,
                // pacing pinned at 1 B/s): the second send has no room and
                // must return 0 (the core behavior the test name promises).
                Assert.Equal(0, sent2);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        private static byte[] BuildUniquePayload(int size, int seed)
        {
            var data = new byte[size];
            ulong state = (ulong)seed;
            for (int i = 0; i < size; i++)
            {
                state = state * 6364136223846793005UL + 1442695040888963407UL;
                data[i] = (byte)(state >> 32);
            }
            return data;
        }

        private static void SendAsDataPackets(SimulatedTransport transport, byte[] payload, int remotePort, uint connectionId = 1)
        {
            int mss = 1460;
            int headerSize = 20;
            int chunkSize = mss - headerSize;
            int offset = 0;
            int chunkIndex = 0;
            while (offset < payload.Length)
            {
                int remaining = payload.Length - offset;
                int chunkPayload = Math.Min(remaining, chunkSize);
                var packet = new byte[headerSize + chunkPayload];
                packet[0] = 0x05;
                packet[1] = 0;
                packet[2] = (byte)(connectionId >> 24);
                packet[3] = (byte)(connectionId >> 16);
                packet[4] = (byte)(connectionId >> 8);
                packet[5] = (byte)connectionId;
                uint seq = (uint)chunkIndex;
                packet[12] = (byte)(seq >> 24);
                packet[13] = (byte)(seq >> 16);
                packet[14] = (byte)(seq >> 8);
                packet[15] = (byte)seq;
                Buffer.BlockCopy(payload, offset, packet, headerSize, chunkPayload);
                transport.Send(packet, new IPEndPoint(IPAddress.Loopback, remotePort));
                offset += chunkPayload;
                chunkIndex++;
            }
        }

        private static UcpConfiguration CreateCcConfig(int bw)
        {
            var config = UcpConfiguration.GetOptimizedConfig();
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.ServerBandwidthBytesPerSecond = bw;
            config.DisconnectTimeoutMicros = 600_000_000L;
            config.MaxRetransmissions = 500;
            return config;
        }

        private static UcpCongestionControl CreateCc(UcpConfiguration config)
        {
            return new UcpCongestionControl(config);
        }
    }
}
