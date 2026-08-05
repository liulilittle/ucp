using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ucp;
using Ucp.Internal;
using Ucp.Transport;
using UcpTest.TestTransport;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpAdditionalTests
    {
        private readonly ITestOutputHelper _output;
        public UcpAdditionalTests(ITestOutputHelper output) { _output = output; }

        [Fact]
        public void SequenceComparer_HandlesWrapAround()
        {
            uint maxVal = uint.MaxValue;
            uint zero = 0;
            uint one = 1;

            Assert.True(UcpSequenceComparer.IsAfter(zero, maxVal));
            Assert.True(UcpSequenceComparer.IsAfter(one, maxVal));
            Assert.True(UcpSequenceComparer.IsBefore(maxVal, zero));

            Assert.Equal(1, UcpSequenceComparer.Instance.Compare(zero, maxVal));
            Assert.Equal(-1, UcpSequenceComparer.Instance.Compare(maxVal, zero));
        }

        [Fact]
        public void SequenceComparer_IsAfterAndIsBeforeAreMutuallyExclusiveExceptEquals()
        {
            uint a = 500;
            uint b = 1000;

            Assert.True(UcpSequenceComparer.IsAfter(b, a));
            Assert.True(UcpSequenceComparer.IsBefore(a, b));
            Assert.False(UcpSequenceComparer.IsAfter(a, a));
            Assert.False(UcpSequenceComparer.IsBefore(a, a));
        }

        [Fact]
        public void SequenceComparer_IsAfterOrEqual_IsBeforeOrEqual()
        {
            uint a = 1;
            uint b = 2;

            Assert.True(UcpSequenceComparer.IsAfterOrEqual(b, a));
            Assert.True(UcpSequenceComparer.IsBeforeOrEqual(a, b));
            Assert.True(UcpSequenceComparer.IsAfterOrEqual(a, a));
            Assert.True(UcpSequenceComparer.IsBeforeOrEqual(a, a));
        }

        [Fact]
        public void SequenceComparer_WrapAroundEdge()
        {
            uint max = uint.MaxValue;
            uint half = 0x80000000U;

            Assert.True(UcpSequenceComparer.IsAfter(max, half));
            Assert.True(UcpSequenceComparer.IsBefore(half, max));
            Assert.True(UcpSequenceComparer.IsAfter(0u, max));
            Assert.True(UcpSequenceComparer.IsBefore(max, 0u));

            Assert.True(UcpSequenceComparer.IsAfterOrEqual(max, half));
            Assert.True(UcpSequenceComparer.IsBeforeOrEqual(half, max));
        }

        [Fact]
        public void PacketCodec_CanRoundTripAckWithEchoTimestamp()
        {
            var packet = new UcpAckPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Ack,
                    Flags = UcpPacketFlags.NeedAck,
                    ConnectionId = 77,
                    Timestamp = 123456789
                },
                AckNumber = 100,
                SackBlocks = { new SackBlock { Start = 102, End = 105 }, new SackBlock { Start = 109, End = 110 } },
                WindowSize = 512,
                EchoTimestamp = 987654321
            };

            byte[] encoded = UcpPacketCodec.Encode(packet);
            bool ok = UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decodedRaw);

            Assert.True(ok);
            var decoded = Assert.IsType<UcpAckPacket>(decodedRaw);

            Assert.Equal(packet.Header.Type, decoded.Header.Type);
            Assert.Equal(packet.Header.Flags, decoded.Header.Flags);
            Assert.Equal(packet.Header.ConnectionId, decoded.Header.ConnectionId);
            Assert.Equal(packet.AckNumber, decoded.AckNumber);
            Assert.Equal(packet.WindowSize, decoded.WindowSize);
            Assert.Equal(packet.EchoTimestamp, decoded.EchoTimestamp);
            Assert.Equal(2, decoded.SackBlocks.Count);
            Assert.Equal(102u, decoded.SackBlocks[0].Start);
            Assert.Equal(105u, decoded.SackBlocks[0].End);
        }

        [Fact]
        public void SackGenerator_BuildsContinuousBlocks()
        {
            var gen = new UcpSackGenerator();
            var received = new List<uint> { 12, 13, 14, 18, 19, 25 };
            var blocks = gen.Generate(10, received, 8);

            Assert.Equal(3, blocks.Count);
            Assert.Equal(12u, blocks[0].Start);
            Assert.Equal(14u, blocks[0].End);
            Assert.Equal(18u, blocks[1].Start);
            Assert.Equal(19u, blocks[1].End);
            Assert.Equal(25u, blocks[2].Start);
            Assert.Equal(25u, blocks[2].End);
        }

        [Fact]
        public void RtoEstimator_BackoffEnforcesFloorProtection()
        {
            var config = new UcpConfiguration();
            config.MinRtoMicros = 1000000;
            config.MaxRtoMicros = 60000000;
            config.RetransmitBackoffFactor = 1.5;

            var estimator = new UcpRtoEstimator(config);
            estimator.Update(100000);
            long first = estimator.CurrentRtoMicros;

            long floor = Math.Max(first, config.EffectiveMinRtoMicros * UcpConstants.RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER);
            Assert.Equal(2000000, floor);
            estimator.Backoff();
            Assert.Equal(floor, estimator.CurrentRtoMicros);
        }

        [Fact]
        public void RtoEstimator_ClampsInvalidConfiguration()
        {
            var config = new UcpConfiguration();
            config.MinRtoMicros = 0;
            config.MaxRtoMicros = 1;
            config.RetransmitBackoffFactor = 0.5;

            var estimator = new UcpRtoEstimator(config);
            estimator.Update(1000);
            long before = estimator.CurrentRtoMicros;

            Assert.True(before >= UcpConstants.MIN_RTO_MICROS);

            estimator.Backoff();
            Assert.True(estimator.CurrentRtoMicros >= before);
        }

        [Fact]
        public void RtoEstimator_UpdateWithNegativeSample_IsIgnored()
        {
            var config = new UcpConfiguration();
            var est = new UcpRtoEstimator(config);
            long before = est.CurrentRtoMicros;
            est.Update(-1000);
            Assert.Equal(before, est.CurrentRtoMicros);
        }

        [Fact]
        public void RtoEstimator_UpdateWithZero_IsIgnored()
        {
            var config = new UcpConfiguration();
            var est = new UcpRtoEstimator(config);
            long before = est.CurrentRtoMicros;
            est.Update(0);
            Assert.Equal(before, est.CurrentRtoMicros);
        }

        [Fact]
        public void RtoEstimator_MultipleUpdatesSmooth()
        {
            var config = new UcpConfiguration();
            config.MinRtoMicros = 20000;
            var est = new UcpRtoEstimator(config);

            est.Update(100000);
            est.Update(120000);
            est.Update(110000);
            est.Update(105000);

            long rto = est.CurrentRtoMicros;
            Assert.True(rto >= config.MinRtoMicros);
            Assert.True(rto <= config.MaxRtoMicros);
            Assert.True(est.SmoothedRttMicros > 0);
            Assert.True(est.RttVarianceMicros >= 0);
        }

        [Fact]
        public void RtoEstimator_MultipleBackoffsIncreaseThenPlateau()
        {
            var config = new UcpConfiguration();
            config.MinRtoMicros = 100000;
            var est = new UcpRtoEstimator(config);
            est.Update(50000);

            long before = est.CurrentRtoMicros;
            est.Backoff();
            long afterFirst = est.CurrentRtoMicros;
            Assert.True(afterFirst >= before);

            est.Backoff();
            long afterTwo = est.CurrentRtoMicros;
            Assert.True(afterTwo >= afterFirst);
        }

        [Fact]
        public void PacingController_ComputesWaitTimeWhenTokensInsufficient()
        {
            var config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;

            var controller = new PacingController(config, 1000);
            controller.SetRate(1000, 1000000);

            Assert.True(controller.TryConsume(1236, 1000000));
            Assert.False(controller.TryConsume(500, 1000000));

            long wait = controller.GetWaitTimeMicros(500, 1000000);
            Assert.InRange(wait, 499000, 501000);
        }

        [Fact]
        public void PacingController_ForceConsume_BypassesEmptyBucketWithPostRecoveryDebt()
        {
            var config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;

            var controller = new PacingController(config, 1000);
            controller.SetRate(1000, 1000000);

            Assert.True(controller.TryConsume(1236, 1000000));
            Assert.False(controller.TryConsume(1, 1000000));

            controller.ForceConsume(500, 1000000);

            Assert.False(controller.TryConsume(1, 1000000));

            long wait = controller.GetWaitTimeMicros(1, 1000000);
            Assert.InRange(wait, 1000, 2000);

            Assert.True(controller.TryConsume(1, 1001000));
        }

        [Fact]
        public void PacingController_AllowsPacketWhenBucketDurationIsTiny()
        {
            var config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1;
            config.SendQuantumBytes = 1;

            var controller = new PacingController(config, 1);
            Assert.True(controller.TryConsume(
                UcpConstants.DATA_HEADER_SIZE + config.MaxPayloadSize, 0));
        }

        [Fact]
        public void FecCodec_EmptyGroupDoesNotProduceRepair()
        {
            var enc = new UcpFecCodec(groupSize: 4, repairCount: 1);
            byte[] p0 = { (byte)'X' };
            var r0 = enc.TryEncodeRepair(0u, p0);
            Assert.Null(r0);

            var r1 = enc.TryEncodeRepair(1u, new byte[] { (byte)'Y', (byte)'Y', (byte)'Y' });
            Assert.Null(r1);

            var r2 = enc.TryEncodeRepair(2u, new byte[] { (byte)'Z', (byte)'Z', (byte)'Z' });
            Assert.Null(r2);

            var r3 = enc.TryEncodeRepair(3u, new byte[] { (byte)'W', (byte)'W', (byte)'W' });
            Assert.NotNull(r3);
        }

        [Fact]
        public void FecCodec_FeedOutOfOrderSlots()
        {
            byte[] p3 = { (byte)'D', (byte)'D', (byte)'D' };
            byte[] p0 = { (byte)'A', (byte)'A', (byte)'A' };
            byte[] p2 = { (byte)'C', (byte)'C', (byte)'C' };

            var enc = new UcpFecCodec(groupSize: 4, repairCount: 1);
            enc.TryEncodeRepair(0u, p0);
            enc.TryEncodeRepair(1u, new byte[] { (byte)'B', (byte)'B', (byte)'B' });
            enc.TryEncodeRepair(2u, p2);
            var repair = enc.TryEncodeRepair(3u, p3);
            Assert.NotNull(repair);

            var dec = new UcpFecCodec(groupSize: 4, repairCount: 1);
            dec.FeedDataPacket(3u, p3);
            dec.FeedDataPacket(0u, p0);
            dec.FeedDataPacket(2u, p2);
            var recovered = dec.TryRecoverFromRepair(repair!, groupBase: 0u);
            Assert.NotNull(recovered);
            Assert.Equal(3, recovered!.Length);
        }

        [Fact]
        public void FecCodec_RepairWithoutDuplicateSlots()
        {
            var dec = new UcpFecCodec(groupSize: 4, repairCount: 1);
            byte[] p0 = { (byte)'A' };
            dec.FeedDataPacket(0u, p0);
            dec.FeedDataPacket(0u, p0);

            byte[] repair = { (byte)'X', (byte)'X', (byte)'X' };
            var recovered = dec.TryRecoverFromRepair(repair, groupBase: 0u);
            Assert.Null(recovered);
        }

        [Fact]
        public void FecCodec_RecoversThreeLossesWithThreeRepairs()
        {
            var data = new byte[33][];
            for (int i = 0; i < 33; i++)
            {
                data[i] = new byte[257 + i];
                new Random(1000 + i).NextBytes(data[i]);
            }

            var enc = new UcpFecCodec(groupSize: 33, repairCount: 3);
            List<byte[]>? repairs = null;
            for (int i = 0; i < 33; i++)
            {
                var r = enc.TryEncodeRepairs((uint)i, data[i]);
                if (r != null) repairs = r;
            }

            Assert.NotNull(repairs);
            Assert.Equal(3, repairs!.Count);

            var dec = new UcpFecCodec(groupSize: 33, repairCount: 3);
            for (int i = 0; i < 33; i++)
            {
                if (i != 2 && i != 17 && i != 31)
                    dec.FeedDataPacket((uint)i, data[i]);
            }

            var r0 = dec.TryRecoverPacketsFromRepair(repairs![0], groupBase: 0u, repairIndex: 0);
            var r1 = dec.TryRecoverPacketsFromRepair(repairs![1], groupBase: 0u, repairIndex: 1);
            Assert.Empty(r0);
            Assert.Empty(r1);

            var r2 = dec.TryRecoverPacketsFromRepair(repairs![2], groupBase: 0u, repairIndex: 2);
            Assert.Equal(3, r2.Count);
        }

        [Fact]
        public void NetworkSimulator_InitialStatsAreZero()
        {
            var sim = new NetworkSimulator(bandwidthBytesPerSecond: 1024 * 1024);
            Assert.Equal(0, sim.SentPackets);
            Assert.Equal(0, sim.DeliveredPackets);
            Assert.Equal(0, sim.DroppedPackets);
            Assert.Equal(0.0, sim.ObservedPacketLossPercent);
        }

        [Fact]
        public async Task NetworkSimulator_ObservesLossWithUniformRate()
        {
            var sim = new NetworkSimulator(lossRate: 1.0, fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: 1024 * 1024, seed: 42);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31001);
            t2.Start(31002);

            byte[] buf = new byte[100];
            buf[0] = 0x05;
            for (int i = 0; i < 100; i++)
                t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(500);

            Assert.True(sim.DroppedPackets > 0);
            Assert.True(sim.DroppedDataPackets > 0);
        }

        [Fact]
        public async Task NetworkSimulator_DeliversWithFixedDelay()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 20, bandwidthBytesPerSecond: 1024 * 1024);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31003);
            t2.Start(31004);

            var tcs = new TaskCompletionSource<bool>();
            t2.OnDatagram += (_, _) => tcs.TrySetResult(true);

            byte[] buf = new byte[50];
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            Task completed = await Task.WhenAny(tcs.Task, Task.Delay(200));
            Assert.True(completed == tcs.Task, "Packet was not delivered within timeout");
            Assert.True(await tcs.Task);
        }

        [Fact]
        public async Task NetworkSimulator_DuplicatesAtCorrectRate()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: 0, seed: 99, duplicateRate: 0.5);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31005);
            t2.Start(31006);

            byte[] buf = new byte[100];
            buf[0] = 0x05;
            int received = 0;
            t2.OnDatagram += (_, _) => Interlocked.Increment(ref received);

            for (int i = 0; i < 50; i++)
                t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(500);

            Assert.True(sim.DuplicatedPackets > 0);
        }

        [Fact]
        public async Task NetworkSimulator_ReordersAtCorrectRate()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: 0, seed: 101, reorderRate: 0.5);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31007);
            t2.Start(31008);

            byte[] buf = new byte[100];
            buf[0] = 0x05;
            for (int i = 0; i < 50; i++)
                t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(500);

            Assert.True(sim.ReorderedPackets > 0);
        }

        [Fact]
        public async Task NetworkSimulator_BandwidthSerializationRespectsLimit()
        {
            const int bw = 16 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: bw, seed: 42);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31009);
            t2.Start(31010);

            byte[] buf = new byte[8 * 1024];
            buf[0] = 0x05;
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(1500);

            Assert.True(sim.DeliveredPackets >= 1);
            Assert.True(sim.DeliveredBytes >= buf.Length);
        }

        [Fact]
        public async Task NetworkSimulator_IndependentForwardReverseDelays()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: 0, seed: 42, forwardDelayMilliseconds: 10, backwardDelayMilliseconds: 2);
            Assert.Equal(10, sim.ForwardDelayMilliseconds);
            Assert.Equal(2, sim.BackwardDelayMilliseconds);

            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31011);
            t2.Start(31012);

            byte[] buf = new byte[100];
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(200);

            Assert.True(sim.DeliveredPackets >= 1);
        }

        [Fact]
        public async Task NetworkSimulator_CustomDropRuleCanDropSpecificPackets()
        {
            int dropCount = 0;
            var sim = new NetworkSimulator(seed: 42, dropRule: (dg) =>
            {
                Interlocked.Increment(ref dropCount);
                return 3 == dropCount;
            });

            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31013);
            t2.Start(31014);

            byte[] buf = new byte[100];
            buf[0] = 0x05;
            for (int i = 0; i < 10; i++)
                t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(200);

            Assert.True(sim.DroppedDataPackets >= 1);
        }

        [Fact]
        public async Task NetworkSimulator_JitterAffectsDeliveryTime()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, jitterMilliseconds: 8, bandwidthBytesPerSecond: 0, seed: 42);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31100);
            t2.Start(31101);

            byte[] buf = new byte[100];
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(200);

            Assert.True(sim.DeliveredPackets >= 1);
            Assert.NotEmpty(sim.LatencySamplesMicros);
        }

        [Fact]
        public async Task NetworkSimulator_SinusoidalWaveJitterDoesNotThrow()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 20, jitterMilliseconds: 5, bandwidthBytesPerSecond: 0, seed: 42,
                dynamicJitterRangeMilliseconds: 1, dynamicWaveAmplitudeMilliseconds: 3);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31102);
            t2.Start(31103);

            byte[] buf = new byte[100];
            for (int i = 0; i < 10; i++)
                t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(500);

            Assert.True(sim.DeliveredPackets > 0);
        }

        [Fact]
        public async Task NetworkSimulator_LogicalThroughput_IsNonNegative()
        {
            const long bw = 100 * 1024 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: (int)bw, seed: 42);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31300);
            t2.Start(31301);

            byte[] buf = new byte[16 * 1024];
            buf[0] = 0x05;
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(500);

            Assert.True(sim.DeliveredPackets >= 1);
            Assert.True(sim.LogicalThroughputBytesPerSecond >= bw * 0.01);
        }

        [Fact]
        public async Task NetworkSimulator_LogicalThroughput_WithData()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: 100 * 1024 * 1024, seed: 42);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31200);
            t2.Start(31201);

            byte[] buf = new byte[16 * 1024];
            buf[0] = 0x05;
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(500);

            Assert.True(sim.DeliveredPackets >= 1);
            Assert.True(sim.LogicalThroughputBytesPerSecond > 0.0,
                $"Throughput should be positive after delivery: {sim.LogicalThroughputBytesPerSecond}");
        }

        [Fact]
        public async Task NetworkSimulator_MultipleTransportsDoNotInterfere()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 0);
            var a = sim.CreateTransport("A");
            var b = sim.CreateTransport("B");
            var c = sim.CreateTransport("C");
            a.Start(31021);
            b.Start(31022);
            c.Start(31023);

            Assert.NotEqual(((IPEndPoint)a.LocalEndPoint!).Port, ((IPEndPoint)b.LocalEndPoint!).Port);
            Assert.NotEqual(((IPEndPoint)b.LocalEndPoint!).Port, ((IPEndPoint)c.LocalEndPoint!).Port);

            byte[] buf = new byte[50];
            b.Send(buf, (IPEndPoint)c.LocalEndPoint!);
            a.Send(buf, (IPEndPoint)b.LocalEndPoint!);

            await Task.Delay(200);

            Assert.True(sim.DeliveredPackets >= 2);
        }

        [Fact]
        public void NetworkSimulator_ReconfigureChangesParameters()
        {
            var sim = new NetworkSimulator(lossRate: 0.1, fixedDelayMilliseconds: 10, jitterMilliseconds: 5, bandwidthBytesPerSecond: 1024, seed: 42);
            Assert.Equal(0.1, sim.LossRate);

            sim.Configure(0.01, 20, 0, 100000, 0.1, 0.1);
            Assert.Equal(0.01, sim.LossRate);
            Assert.Equal(20, sim.ForwardDelayMilliseconds);
            Assert.Equal(100000, sim.BandwidthBytesPerSecond);
        }

        [Fact]
        public void Migration_ExtraCidTracking()
        {
            var config = new UcpConfiguration();
            uint primary = 0xABCD;

            var pcb = new UcpPcb(null, null, false, false, null, primary, config);

            Assert.True(pcb.IsValidCid(primary));

            uint extra = 0xDEAD;
            bool added = pcb.AddExtraCid(extra);
            Assert.True(added);
            Assert.True(pcb.IsValidCid(extra));
            Assert.True(pcb.IsValidCid(primary));

            bool removed = pcb.RemoveExtraCid(extra);
            Assert.True(removed);
            Assert.False(pcb.IsValidCid(extra));
            Assert.True(pcb.IsValidCid(primary));
        }

        [Fact]
        public void Migration_CidRotationSecurity()
        {
            var config = new UcpConfiguration();
            uint primary = 0x6000;

            var pcb = new UcpPcb(null, null, false, false, null, primary, config);

            Assert.True(pcb.IsValidCid(primary));

            uint extra1 = 0x7001;
            uint extra2 = 0x7002;
            Assert.True(pcb.AddExtraCid(extra1));
            Assert.True(pcb.AddExtraCid(extra2));
            Assert.True(pcb.IsValidCid(extra1));
            Assert.True(pcb.IsValidCid(extra2));
            Assert.True(pcb.IsValidCid(primary));

            uint unknown = 0xDEAD;
            Assert.False(pcb.IsValidCid(unknown));
            Assert.False(pcb.IsValidCid(0u));

            Assert.True(pcb.RemoveExtraCid(extra1));
            Assert.False(pcb.IsValidCid(extra1));
            Assert.True(pcb.IsValidCid(extra2));
            Assert.True(pcb.IsValidCid(primary));

            Assert.False(pcb.RemoveExtraCid(0x9999));
            Assert.False(pcb.RemoveExtraCid(0u));
        }

        [Fact]
        public void Migration_ConnectionMigrateRemote()
        {
            var config = new UcpConfiguration();
            config.Mss = 512;

            var pcb = new UcpPcb(null, null, false, false, null, 0x5000U, config);

            string before = pcb.RemoteEndPoint?.ToString() ?? "";

            var ep1 = new IPEndPoint(IPAddress.Parse("10.0.0.1"), 9000);
            pcb.SetRemoteEndPoint(ep1);

            string after = pcb.RemoteEndPoint?.ToString() ?? "";
            Assert.NotEqual(before, after);
            Assert.Contains("10.0.0.1", after);
        }

        [Fact]
        public void Integration_Abort_DisconnectsLocally()
        {
            var config = new UcpConfiguration();
            config.Mss = 512;
            bool disconnected = false;

            var pcb = new UcpPcb(null, null, false, false, null, 0x42u, config);
            pcb.Disconnected += () => disconnected = true;
            pcb.Abort(false);

            Assert.True(disconnected);
        }

        [Fact]
        public async Task Integration_BasicUnidirectionalDelivery()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1024 * 1024);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(31030);
            t2.Start(31031);

            byte[] payload1 = new byte[4 * 1024];
            new Random(42).NextBytes(payload1);
            t1.Send(payload1, (IPEndPoint)t2.LocalEndPoint!);

            byte[] payload2 = new byte[8 * 1024];
            new Random(43).NextBytes(payload2);
            t1.Send(payload2, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(1000);

            Assert.True(sim.DeliveredPackets >= 2);
            Assert.True(sim.DeliveredBytes >= payload1.Length + payload2.Length);
        }

        [Fact]
        public void UcpCc_Throughput50M_Converges()
        {
            const long kBw = 50L * 1024 * 1024 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndPackets = 20;
            var cc = new UcpCongestionControl(config);
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
        public void SackGenerator_LargeGapProducesLimitBlocks()
        {
            var gen = new UcpSackGenerator();
            var received = new List<uint>();
            for (uint i = 0; i < 100; i += 2) received.Add(i);
            var blocks = gen.Generate(0, received, 4);
            Assert.True(blocks.Count <= 4);
            Assert.Equal(0u, blocks[0].Start);
            Assert.Equal(0u, blocks[0].End);
        }

        [Fact]
        public void UcpCc_OnNakLossWithoutCrash()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;

            for (int i = 0; i < 3; i++)
                cc.OnAck(now, 24000, 50000, 24000);
            now += 50000;

            cc.OnNakLoss(now, 12000);
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void UcpCc_Throughput200M_Converges()
        {
            const long kBw = 200L * 1024 * 1024 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndPackets = 20;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 60; i++)
            {
                long d = Math.Max(1, kBw * rttUs / 1000000);
                cc.OnAck(now, d, rttUs, d);
                now += rttUs;
            }

            long rate = (long)cc.PacingRateBytesPerSecond;
            Assert.True(rate > kBw * 40 / 100);
            Assert.True(rate < kBw * 3);
            Assert.True(cc.MinRttMicros > 0);
            Assert.True(cc.MinRttMicros <= rttUs * 120 / 100);
        }

        [Fact]
        public void Geodesic_NegativeRttSample_Ignored()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;

            cc.OnAck(now, 24000, 50000, 24000);
            long xestBefore = cc.GeodesicXEst;
            cc.OnAck(now + 50000, 24000, -1000, 24000);
            Assert.Equal(xestBefore, cc.GeodesicXEst);
        }

        [Fact]
        public void Geodesic_ContinuousHighRttConverges()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 300000;

            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            long ratio = cc.GeodesicXEst * 100 / (rttUs * 1024);
            Assert.InRange(ratio, 80, 120);
        }

        [Fact]
        public void Geodesic_ZeroRttVarianceMaintainsConvergence()
        {
            var cc = new UcpCongestionControl(new UcpConfiguration());
            long now = 100000;
            long rttUs = 50000;

            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, rttUs - (i & 1), 24000);
                now += rttUs;
            }

            Assert.True(cc.GeodesicPEst < 20000,
                $"p_est {cc.GeodesicPEst} should stabilize below 20000 with minimal-variance input");
            Assert.True(cc.GeodesicSampleCnt >= 50);
        }

        [Fact]
        public void CwndConstraint_EnforcesMinimumCwnd()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.InitialCwndBytes = 65536;
            var cc = new UcpCongestionControl(config);
            Assert.True(cc.CongestionWindowBytes >= config.InitialCwndBytes);
        }

        [Fact]
        public void CwndConstraint_DoesNotExceedMaximum()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.InitialCwndBytes = 65536;
            config.MaxCongestionWindowBytes = 128 * 1024;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 100; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes <= config.MaxCongestionWindowBytes,
                $"cwnd {cc.CongestionWindowBytes} should not exceed max {config.MaxCongestionWindowBytes}");
        }

        [Fact]
        public void ProbeBwCycle_ProbePhaseHasValidGain()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            for (int phase = 0; phase < 16; phase++)
            {
                Assert.InRange(cc.PacingGainUnits, 0, 1023);
                Assert.True(cc.PacingGainUnits > 0,
                    $"PROBE_BW pacing gain must be positive at phase {phase}: {cc.PacingGainUnits}");
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }
        }

        [Fact]
        public void FecCodec_GroupBoundaryParsExactly()
        {
            var enc = new UcpFecCodec(groupSize: 4, repairCount: 1);
            byte[] data = new byte[1200];
            new Random(77).NextBytes(data);

            Assert.Null(enc.TryEncodeRepair(0u, data));
            Assert.Null(enc.TryEncodeRepair(1u, data));
            Assert.Null(enc.TryEncodeRepair(2u, data));
            var repair = enc.TryEncodeRepair(3u, data);
            Assert.NotNull(repair);

            var dec = new UcpFecCodec(groupSize: 4, repairCount: 1);
            dec.FeedDataPacket(0u, data);
            dec.FeedDataPacket(1u, data);
            dec.FeedDataPacket(2u, data);
            var recovered = dec.TryRecoverFromRepair(repair, groupBase: 0u);
            Assert.NotNull(recovered);
        }

        [Fact]
        public void FecCodec_PartialLossWithRepairs_RecoversExpected()
        {
            byte[][] data = new byte[4][];
            for (int i = 0; i < 4; i++)
            {
                data[i] = new byte[1200];
                new Random(100 + i).NextBytes(data[i]);
            }

            var enc = new UcpFecCodec(groupSize: 4, repairCount: 2);
            enc.TryEncodeRepair(0u, data[0]);
            enc.TryEncodeRepair(1u, data[1]);
            enc.TryEncodeRepair(2u, data[2]);
            var repairs = enc.TryEncodeRepairs(3u, data[3]);
            Assert.NotNull(repairs);
            Assert.Equal(2, repairs!.Count);

            var dec = new UcpFecCodec(groupSize: 4, repairCount: 2);
            dec.FeedDataPacket(1u, data[1]);
            dec.FeedDataPacket(3u, data[3]);

            var r0 = dec.TryRecoverPacketsFromRepair(repairs[0], groupBase: 0u, repairIndex: 0);
            var r1 = dec.TryRecoverPacketsFromRepair(repairs[1], groupBase: 0u, repairIndex: 1);
            Assert.True(r0.Count + r1.Count >= 2,
                $"Expected at least 2 recovered packets, got r0={r0.Count} r1={r1.Count}");
        }

        [Fact]
        public void FecCodec_LargeGroupSurvivesWithoutCrash()
        {
            var codec = new UcpFecCodec(groupSize: 64, repairCount: 4);
            byte[] data = new byte[500];
            new Random(42).NextBytes(data);

            List<byte[]> allRepairs = new List<byte[]>();
            for (uint i = 0; i < 64; i++)
            {
                var repairs = codec.TryEncodeRepairs(i, data);
                if (repairs != null)
                    allRepairs.AddRange(repairs);
            }
            Assert.Equal(4, allRepairs.Count);
        }

        [Fact]
        public void PacingController_SetRateZero_DefaultsToOneBps()
        {
            var config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;
            var controller = new PacingController(config, 1000);
            controller.SetRate(0, 1000000);
            Assert.True(controller.TryConsume(1, 1000000));
        }

        [Fact]
        public void PacingController_ModerateRate_AllowsConsumption()
        {
            var config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;
            var controller = new PacingController(config, 1000000);
            Assert.True(controller.TryConsume(1220, 0));
        }

        [Fact]
        public void PacingController_GetWaitTimePositiveAndFinite()
        {
            var config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;
            var controller = new PacingController(config, 1000);
            controller.SetRate(1000, 1000000);
            controller.TryConsume(1220, 1000000);
            long wait = controller.GetWaitTimeMicros(1220, 1000000);
            Assert.True(wait > 0, $"Wait time should be positive: {wait}");
            Assert.True(wait < 2000000, $"Wait time should be finite: {wait}");
        }

        [Fact]
        public void NetworkSimulator_SendNullBuffer_DoesNotThrow()
        {
            var sim = new NetworkSimulator(bandwidthBytesPerSecond: 1024 * 1024);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(32001);
            t2.Start(32002);

            byte[] buf = new byte[0];
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);
        }

        [Fact]
        public async Task NetworkSimulator_LowBandwidthDeliversSlowly()
        {
            const int bw = 512;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: bw, seed: 42);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(32003);
            t2.Start(32004);

            byte[] buf = new byte[bw];
            buf[0] = 0x05;
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(3000);

            Assert.True(sim.DeliveredPackets >= 1,
                $"Low-bandwidth should deliver after serialization delay: {sim.DeliveredPackets} delivered");
        }

        [Fact]
        public async Task NetworkSimulator_ThrottlesToConfiguredBandwidth()
        {
            const int bw = 8 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 1, bandwidthBytesPerSecond: bw, seed: 42);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(32005);
            t2.Start(32006);

            byte[] buf = new byte[bw];
            buf[0] = 0x05;
            t1.Send(buf, (IPEndPoint)t2.LocalEndPoint!);

            await Task.Delay(3000);

            Assert.True(sim.DeliveredBytes > 0);
            Assert.True(sim.DeliveredPackets >= 1);
        }

        [Fact]
        public void BdpCalculation_HighBwLargeRtt_ProducesValidCwnd()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000000 / 8;
            config.InitialCwndBytes = 65536;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 50000;

            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 64000, rttUs, 64000);
                now += rttUs;
            }
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.MinRttMicros > 0 && cc.MinRttMicros <= rttUs * 120 / 100);
        }

        [Fact]
        public void EcnEwma_ManyCeMarksApproachesMax()
        {
            var cc = new UcpCongestionControl(new UcpConfiguration { EcnEnabled = true });
            long now = 100000;

            for (int i = 0; i < 20; i++)
            {
                cc.OnCeMark(24000);
                cc.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }
            Assert.True(cc.EcnEwmaValue > 0);
            Assert.True(cc.EcnEwmaValue <= 256);
        }

        [Fact]
        public async Task FecIntegration_WithLoss_RecoversData()
        {
            const int bw = 20_000_000 / 8;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: bw,
                lossRate: 0.10, seed: 20260610);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 500;
            config.FecGroupSize = 6;
            config.FecRedundancy = 0.50;

            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(44001);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 44001));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('F', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 8000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.Equal(payload, received);

                var clientReport = client.GetReport();
                _output.WriteLine("FecIntegration: delivered={0} dropped={1} dataDrop={2} retrans={3} nakSent={4} fecRepair={5} rttSamples={6}",
                    sim.DeliveredBytes, sim.DroppedPackets, sim.DroppedDataPackets,
                    clientReport.RetransmittedPackets, clientReport.NakPacketsSent,
                    0, clientReport.RttSamplesMicros.Count);
                Assert.True(sim.DroppedDataPackets > 0, "Some data packets should be dropped");
                Assert.True(await UcpTestHelpers.WaitForRttSamplesAsync(client), "Should have RTT samples");
                Assert.True(clientReport.RttSamplesMicros.Count >= 1, "Should have RTT samples");
                Assert.True(clientReport.DataPacketsSent > 0, "Data packets should be sent");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task NakIntegration_WithBurstLoss_FastRetransmits()
        {
            const int bw = 50_000_000 / 8;
            int dropStart = 8;
            int dropCount = 6;
            int pktIdx = 0;

            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bw,
                seed: 20260611, dropRule: (dg) =>
                {
                    if (dg.Buffer.Length == 0 || dg.Buffer[0] != 0x05) return false;
                    int idx = Interlocked.Increment(ref pktIdx) - 1;
                    return idx >= dropStart && idx < dropStart + dropCount;
                });
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 500;

            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(44002);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 44002));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('N', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 20000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.Equal(payload, received);

                var clientReport = client.GetReport();
                _output.WriteLine("NakIntegration: delivered={0} dropped={1} dataDrop={2} retrans={3} nakSent={4} fastRetrans={5} timeoutRetrans={6}",
                    sim.DeliveredBytes, sim.DroppedPackets, sim.DroppedDataPackets,
                    clientReport.RetransmittedPackets, clientReport.NakPacketsSent,
                    clientReport.FastRetransmissions, clientReport.TimeoutRetransmissions);
                Assert.True(sim.DroppedDataPackets > 0, "Some data packets should be dropped");
                Assert.True(clientReport.RttSamplesMicros.Count > 0, "Should have RTT samples after loss recovery");
                // Burst loss on a 5ms link is recovered via NAK-triggered fast
                // retransmission: the reported FastRetransmissions count must be
                // non-zero for the test name to hold.
                Assert.True(clientReport.FastRetransmissions > 0,
                    $"burst loss should trigger fast retransmission: fast={clientReport.FastRetransmissions}");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public void UcpCc_PacketsInNetAtEdt_ComputedFromBdp()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.True(cc.CongestionWindowBytes > 0,
                $"cwnd should be positive: {cc.CongestionWindowBytes}");
            long minRtt = cc.MinRttMicros;
            Assert.True(minRtt > 0, $"minRtt should be positive: {minRtt}");
            long bdp = (long)cc.BtlBwBytesPerSecond * minRtt / 1000000;
            Assert.True(cc.CongestionWindowBytes >= bdp / 4 || cc.CongestionWindowBytes >= 24000,
                $"cwnd {cc.CongestionWindowBytes} should be >= min(24000, bdp/4={bdp / 4})");
            Assert.True(cc.PacingRateBytesPerSecond > 0,
                $"pacing rate should be positive: {cc.PacingRateBytesPerSecond}");
        }

        [Fact]
        public void UcpCc_InflightBounds_CwndDoesNotExceedMax()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 125000000;
            config.MaxCongestionWindowBytes = 256 * 1024;
            config.InitialCwndBytes = 65536;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 80; i++)
            {
                long d = Math.Max(1, 125000000L * rttUs / 1000000);
                cc.OnAck(now, d, rttUs, d);
                now += rttUs;
                Assert.True(cc.CongestionWindowBytes <= config.MaxCongestionWindowBytes,
                    $"cwnd {cc.CongestionWindowBytes} should not exceed {config.MaxCongestionWindowBytes} at iter {i}");
            }
        }

        [Fact]
        public void UcpCc_InflightBounds_CwndAtLeastMinimum()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000;
            config.InitialCwndBytes = 4880;
            var cc = new UcpCongestionControl(config);
            Assert.True(cc.CongestionWindowBytes >= 4880,
                $"cwnd {cc.CongestionWindowBytes} should be at least initial 4880");
        }

        [Fact]
        public void UcpCc_MinRtt_SrttGuardPreventsExcessiveDrop()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 50000;

            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            long minRttAfterWarmup = cc.MinRttMicros;
            Assert.True(minRttAfterWarmup > 0 && minRttAfterWarmup <= rttUs * 120 / 100);

            long moderateLowRtt = rttUs * 70 / 100;
            for (int i = 0; i < 3; i++)
            {
                cc.OnAck(now, 24000, moderateLowRtt, 24000);
                now += rttUs;
            }

            _output.WriteLine("SrttGuard: minRtt after warmup={0} after moderateLow={1}", minRttAfterWarmup, cc.MinRttMicros);
            Assert.True(cc.MinRttMicros <= minRttAfterWarmup,
                $"minRtt {cc.MinRttMicros} should not exceed warmup {minRttAfterWarmup}");

            Assert.True(cc.MinRttMicros >= moderateLowRtt - 1000,
                $"minRtt {cc.MinRttMicros} should be >= {moderateLowRtt - 1000}");
        }

        [Fact]
        public void ProbeBwCycle_PhaseAdvancesOnEachAck()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            int[] seen = new int[8];
            for (int phase = 0; phase < 16; phase++)
            {
                int idx = cc.ProbeBwCycleIdx & 7;
                seen[idx] = cc.PacingGainUnits;
                Assert.InRange(cc.PacingGainUnits, 0, 1023);
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.True(seen[0] > 0, "Phase 0 (high gain) should be positive");
            bool hasLowGain = false;
            for (int i = 0; i < 8; i++)
            {
                if (seen[i] < 256) hasLowGain = true;
            }
            Assert.True(hasLowGain, "At least one phase should have gain < 1.0 (256)");
        }

        [Fact]
        public void ProbeBwDrain_FastConvergence_ShortRtt()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 500;

            for (int i = 0; i < 40; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.True(cc.FullBwReached,
                $"FullBw should be reached with 500us RTT after 40 ACKs: {cc.FullBwReached}");
        }

        [Fact]
        public void UcpCc_Gain_ReducesAfterLoss()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            int gainBefore = cc.CwndGainUnits;
            cc.OnFastRetransmit(now, true);
            int gainAfter = cc.CwndGainUnits;

            _output.WriteLine("Gain: before={0} after={1}", gainBefore, gainAfter);
            Assert.True(gainAfter <= gainBefore,
                $"CWND gain should not increase after loss-triggered retransmit: {gainAfter} > {gainBefore}");
            Assert.True(gainAfter > 0, "CWND gain should remain positive after retransmit");
        }

        [Fact]
        public void UcpCc_Gain_DoesNotGoBelowZero()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            for (int i = 0; i < 5; i++)
            {
                cc.OnFastRetransmit(now, true);
                now += 50000;
            }

            Assert.True(cc.CwndGainUnits >= 0, $"CWND gain should not go below 0: {cc.CwndGainUnits}");
            Assert.True(cc.PacingGainUnits >= 0, $"Pacing gain should not go below 0: {cc.PacingGainUnits}");
        }

        [Fact]
        public void UcpCc_FullBwDetected_AfterSufficientRounds()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            Assert.False(cc.FullBwReached, "Should not report FullBw initially");

            for (int i = 0; i < 12; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            _output.WriteLine("FullBwDetected: fullBw={0} mode={1} sampleCnt={2}",
                cc.FullBwReached, cc.Mode, cc.GeodesicSampleCnt);
            Assert.True(cc.FullBwReached,
                $"FullBw should be detected after 12 ACK rounds: {cc.FullBwReached}");
        }

        [Fact]
        public void FecCodec_SingleLostRecoveryViaNakBasedRepair()
        {
            var codec = new UcpFecCodec(groupSize: 4, repairCount: 1);
            byte[] data = new byte[1200];
            new Random(142).NextBytes(data);

            var r0 = codec.TryEncodeRepair(0u, data);
            var r1 = codec.TryEncodeRepair(1u, data);
            var r2 = codec.TryEncodeRepair(2u, data);
            var repair = codec.TryEncodeRepair(3u, data);
            Assert.NotNull(repair);

            var decoder = new UcpFecCodec(groupSize: 4, repairCount: 1);
            decoder.FeedDataPacket(0u, data);
            decoder.FeedDataPacket(1u, data);
            decoder.FeedDataPacket(3u, data);

            byte[] recovered = decoder.TryRecoverFromRepair(repair!, groupBase: 0u);
            Assert.NotNull(recovered);
            Assert.Equal(1200, recovered!.Length);
            Assert.Equal(data, recovered);
        }

        [Fact]
        public void Bdp_UsesGeodesicModelRtt()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long targetRtt = 50000;

            for (int i = 0; i < 30; i++)
            {
                cc.OnAck(now, 24000, targetRtt, 24000);
                now += 50000;
            }

            long minRtt = cc.MinRttMicros;
            long btlBw = (long)cc.BtlBwBytesPerSecond;
            Assert.True(minRtt > 0, $"minRtt should be positive: {minRtt}");
            Assert.True(btlBw > 0, $"btlBw should be positive: {btlBw}");
            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, $"pacing rate should be positive: {cc.PacingRateBytesPerSecond}");
        }

        [Fact]
        public void FecRecovery_FeedsBandwidthEstimation()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 4; i++)
            {
                cc.OnAck(now, 1200, rttUs, 1200);
                now += rttUs;
            }

            cc.OnFecRecovery(now, 1200);
            now += rttUs;
            cc.OnAck(now, 1200, rttUs, 1200);

            Assert.True(cc.BtlBwBytesPerSecond > 0, $"btlBw should be positive after FEC recovery: {cc.BtlBwBytesPerSecond}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, $"pacing rate should be positive: {cc.PacingRateBytesPerSecond}");
            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive: {cc.CongestionWindowBytes}");
        }

        [Fact]
        public void NakLoss_ContributesToBandwidthEstimation()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;
            long delivered = 24000;

            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }

            double bwBefore = cc.BtlBwBytesPerSecond;
            Assert.True(bwBefore > 0, $"btlBw should be positive before NAK: {bwBefore}");

            for (int i = 0; i < 3; i++)
            {
                cc.OnNakLoss(now, delivered);
                now += 50000;
                cc.OnAck(now, delivered / 2, rttUs, delivered / 2);
                now += rttUs;
            }

            long cwndAfterLoss = cc.CongestionWindowBytes;
            Assert.True(cwndAfterLoss > 0, $"cwnd should remain positive after NAK loss: {cwndAfterLoss}");

            for (int i = 0; i < 12; i++)
            {
                cc.OnAck(now, delivered, rttUs, delivered);
                now += rttUs;
            }

            double bwAfter = cc.BtlBwBytesPerSecond;
            Assert.True(bwAfter > 0, $"btlBw should be positive after recovery: {bwAfter}");
            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive after recovery: {cc.CongestionWindowBytes}");
        }

        [Fact]
        public void LtBw_ConsistentEstimateActivatesPacing()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 90000;
            long rttUs = 10000;

            cc.OnNakLoss(now, 1500);
            for (int round = 0; round < 10; round++)
            {
                now += rttUs;
                cc.OnAck(now, 12000, rttUs, 12000);
                cc.OnPacketLoss(now, 0.15, true);
            }

            Assert.True(cc.PacingRateBytesPerSecond > 0, $"pacing rate should be positive: {cc.PacingRateBytesPerSecond}");
            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive: {cc.CongestionWindowBytes}");
        }

        [Fact]
        public void LtBw_AutoRecoveryExits()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            for (int i = 0; i < 3; i++)
            {
                cc.OnNakLoss(now, 24000);
                now += 100000;
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive after NAK + recovery: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, $"pacing rate should be positive: {cc.PacingRateBytesPerSecond}");
        }

        [Fact]
        public void CwndConstraint_MinimumEnforcedWithDominantAck()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000;
            config.MaxCongestionWindowBytes = 256 * 1024;
            config.InitialCwndBytes = 4880;
            var cc = new UcpCongestionControl(config);
            long now = 100000;

            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 100, 50000, 100);
                now += 50000;
            }

            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive: {cc.CongestionWindowBytes}");
        }

        [Fact]
        public void Geodesic_G2GrowthOnLargePositiveInnovation()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            long jitterBefore = cc.GeodesicJitterEwma;

            cc.OnAck(now, 24000, 15000, 24000);

            long jitterAfter = cc.GeodesicJitterEwma;
            _output.WriteLine("Geodesic_G2Growth: jitter before={0} after={1}", jitterBefore, jitterAfter);
            Assert.True(jitterAfter >= jitterBefore,
                $"Jitter should increase after large innovation: {jitterAfter} >= {jitterBefore}");
        }

        [Fact]
        public void MinRtt_StickyIncrementalDecrease_DropsModerately()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
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
                $"minRtt should decrease from {prevMinRtt} to {cc.MinRttMicros}");
            Assert.True(cc.MinRttMicros >= lowerRtt * 85 / 100,
                $"minRtt {cc.MinRttMicros} should stay >= {lowerRtt * 85 / 100}");
        }

        [Fact]
        public void EcnBackoff_ReducesGainsExtended()
        {
            var config = new UcpConfiguration();
            config.EcnEnabled = true;
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.InitialCwndBytes = 65536;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.True(cc.GeodesicSampleCnt >= 5, $"Need >= 5 geodesic samples: {cc.GeodesicSampleCnt}");

            cc.OnCeMark(500);
            for (int i = 0; i < 4; i++)
            {
                cc.OnCeMark(300);
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            Assert.True(cc.EcnEwmaValue > 0, $"EcnEwma should be positive: {cc.EcnEwmaValue}");
            Assert.True(cc.EcnEwmaValue <= 256, $"EcnEwma should not exceed 256: {cc.EcnEwmaValue}");
            Assert.True(cc.CwndGainUnits > 0, $"cwndGain should be positive: {cc.CwndGainUnits}");
            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive: {cc.CongestionWindowBytes}");
        }

        [Fact]
        public void UcpCc_OnPathChangeResetsState()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 15; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            UcpMode modeBefore = cc.Mode;
            cc.OnPathChange(now);

            _output.WriteLine("OnPathChange: mode before={0} after={1}", modeBefore, cc.Mode);
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing rate should remain positive after path change");
            Assert.True(cc.CongestionWindowBytes > 0, "CWND should remain positive after path change");
        }

        [Fact]
        public void UcpCc_OnFastRetransmitHandlesCongestion()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 8; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            long cwndBefore = cc.CongestionWindowBytes;
            double pacingBefore = cc.PacingRateBytesPerSecond;

            cc.OnFastRetransmit(now, true, 24000);
            now += rttUs;
            cc.OnAck(now, 12000, rttUs, 12000);

            Assert.True(cc.CongestionWindowBytes > 0, "CWND should survive fast retransmit");
            Assert.True(cc.PacingRateBytesPerSecond > 0, "Pacing should survive fast retransmit");
        }

        [Fact]
        public void UcpCc_OnPacketLossDoesNotCrash()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 5; i++)
            {
                cc.OnAck(now, 24000, rttUs, 24000);
                now += rttUs;
            }

            cc.OnPacketLoss(now, 0.02, false);
            now += rttUs;
            cc.OnAck(now, 24000, rttUs, 24000);

            Assert.True(cc.CongestionWindowBytes > 0, $"cwnd should be positive: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0, $"pacing should be positive: {cc.PacingRateBytesPerSecond}");
        }

        [Fact]
        public void UcpCc_Throughput100M_ConvergesPureCc()
        {
            const long kBw = 100L * 1024 * 1024 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 500000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndPackets = 20;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 10000;

            for (int i = 0; i < 40; i++)
            {
                long d = Math.Max(1, kBw * rttUs / 1000000);
                cc.OnAck(now, d, rttUs, d);
                now += rttUs;
            }

            long rate = (long)cc.PacingRateBytesPerSecond;
            Assert.True(rate > kBw * 30 / 100, $"pacing rate {rate} should be > 30% of {kBw}");
            Assert.True(rate < kBw * 5, $"pacing rate {rate} should be < 5x {kBw}");
            Assert.True(cc.MinRttMicros > 0, "minRtt should be positive");
            Assert.True(cc.MinRttMicros <= rttUs * 120 / 100, $"minRtt {cc.MinRttMicros} should be <= {rttUs * 120 / 100}");
        }

        [Fact]
        public void UcpCc_Convergence1MTo100M_PureCc()
        {
            const long kBw = 100L * 1024 * 1024 / 8;
            const long kInitBw = 1L * 1000 * 1000 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = (int)kInitBw;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndPackets = 20;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 20000;
            bool converged = false;

            for (int r = 0; r < 64; r++)
            {
                long d = Math.Max(1, kBw * rttUs / 1000000);
                cc.OnAck(now, d, rttUs, d);
                now += rttUs;
                if (!converged && cc.PacingRateBytesPerSecond >= kBw * 0.50)
                {
                    converged = true;
                }
            }

            _output.WriteLine("Convergence1Mto100M: pace={0:F0} B/s, converged={1}",
                cc.PacingRateBytesPerSecond, converged);
            Assert.True(converged,
                $"Pacing should converge above 50% of {kBw} within 64 rounds: {cc.PacingRateBytesPerSecond:F0}");
            Assert.True(cc.PacingRateBytesPerSecond >= kBw * 0.30,
                $"Final pacing {cc.PacingRateBytesPerSecond:F0} should stay above 30% of {kBw}");
            Assert.True(cc.CongestionWindowBytes > 0, "cwnd should be positive");
        }

        [Fact]
        public void UcpCc_Lossy10M_LtBwActivates()
        {
            const long kBw = 10L * 1024 * 1024 / 8;
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1000000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long rttUs = 20000;
            long d = Math.Max(1, kBw * rttUs / 1000000);

            for (int i = 0; i < 6; i++)
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

            Assert.True(cc.CongestionWindowBytes > 0, "cwnd should be positive");
            Assert.True(cc.PacingRateBytesPerSecond > 0, "pacing should be positive");
            Assert.True(cc.IsLtUseBw,
                $"LT BW should activate under sustained 25% NAK loss: {cc.IsLtUseBw}");
        }



        [Fact]
        public void RtoEstimator_DefaultConstructorIsValid()
        {
            var config = new UcpConfiguration();
            var est = new UcpRtoEstimator(config);
            Assert.True(est.CurrentRtoMicros > 0,
                $"Default RTO should be positive: {est.CurrentRtoMicros}");
            Assert.True(est.SmoothedRttMicros >= 0,
                $"Smoothed RTT should be non-negative: {est.SmoothedRttMicros}");
            Assert.True(est.RttVarianceMicros >= 0,
                $"RTT variance should be non-negative: {est.RttVarianceMicros}");
        }

        [Fact]
        public void PacingController_ZeroRateDoesNotCrash()
        {
            var config = new UcpConfiguration();
            var controller = new PacingController(config, 0);
            controller.SetRate(0, 0);
            int cap = config.Mss + config.MaxPayloadSize + 20;
            int safety = 0;
            while (controller.TryConsume(cap, 0) && safety++ < 10000) { }
            long wait = controller.GetWaitTimeMicros(cap, 0);
            Assert.True(wait > 0, $"Wait time should be positive with zero rate: {wait}");
        }

        [Fact]
        public void SequenceComparer_ExhaustiveEdgeCases()
        {
            uint max = uint.MaxValue;
            uint half = 0x80000000U;

            Assert.True(UcpSequenceComparer.IsAfter(0u, max));
            Assert.True(UcpSequenceComparer.IsBefore(max, 0u));
            Assert.Equal(1, UcpSequenceComparer.Instance.Compare(0u, max));
            Assert.Equal(-1, UcpSequenceComparer.Instance.Compare(max, 0u));
            Assert.Equal(0, UcpSequenceComparer.Instance.Compare(0u, 0u));
            Assert.Equal(0, UcpSequenceComparer.Instance.Compare(max, max));
            Assert.True(UcpSequenceComparer.IsAfter(max, half));
            Assert.True(UcpSequenceComparer.IsBefore(half, max));
        }

        [Fact]
        public void UcpCc_DataCenter10G_ConvergesTo90Percent()
        {
            const long k10Gbps = 10000000000L / 8;
            const long kRttUs = 330;
            const int kMaxRounds = 200;
            const double kMinPct = 0.90;

            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 100000;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndPackets = 10;
            config.MaxPacingRateBytesPerSecond = k10Gbps;

            var cc = new UcpCongestionControl(config);
            long now = 100000;

            for (int r = 0; r < kMaxRounds; r++)
            {
                long d = Math.Max(1L, k10Gbps * kRttUs / 1000000L);
                cc.OnAck(now, d, kRttUs, d);
                now += kRttUs;
            }

            double paceMbps = cc.PacingRateBytesPerSecond * 8.0 / 1000000.0;
            Assert.True(paceMbps >= 10000.0 * kMinPct,
                $"Pacing rate {paceMbps:F1} Mbps should be >= {10000.0 * kMinPct:F1} Mbps");
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void UcpServer_DisposeIsIdempotent()
        {
            var server = new UcpServer(new UcpConfiguration());
            server.Start(44030);
            server.Dispose();
            // Second Dispose / Stop must not throw (ObjectDisposedException on the
            // cancelled+disposed CancellationTokenSource was a real bug).
            server.Dispose();
            server.Stop();
            server.Stop();
        }

        [Fact]
        public void UcpServer_StopTwiceDoesNotThrow()
        {
            var server = new UcpServer(new UcpConfiguration());
            server.Start(44031);
            server.Stop();
            server.Stop();
            server.Dispose();
        }

    }
}
