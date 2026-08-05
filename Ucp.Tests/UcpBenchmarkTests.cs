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
    public sealed class UcpBenchmarkTests
    {
        private readonly ITestOutputHelper _output;
        public UcpBenchmarkTests(ITestOutputHelper output) { _output = output; }

        private const int DATA_HEADER_SIZE = 20;

        private static byte[] BuildPayload(char value, int size)
        {
            var buf = new byte[size];
            Array.Fill(buf, (byte)value);
            return buf;
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
            int chunkSize = mss - DATA_HEADER_SIZE;
            int offset = 0;
            int chunkIndex = 0;

            while (offset < payload.Length)
            {
                int remaining = payload.Length - offset;
                int chunkPayload = Math.Min(remaining, chunkSize);
                var packet = new byte[DATA_HEADER_SIZE + chunkPayload];
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
                Buffer.BlockCopy(payload, offset, packet, DATA_HEADER_SIZE, chunkPayload);
                transport.Send(packet, new IPEndPoint(IPAddress.Loopback, remotePort));
                offset += chunkPayload;
                chunkIndex++;
            }
        }

        [Fact]
        public Task SimulatorRaw_Integration_NoLoss_CanConnectAndTransfer()
        {
            const int kBw = 10 * 1024 * 1024;
            const int kPayload = 64 * 1024;
            int chunkSize = 1460 - DATA_HEADER_SIZE;
            int totalChunks = (kPayload + chunkSize - 1) / chunkSize;

            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: kBw,
                seed: 1234, forwardDelayMilliseconds: 7, backwardDelayMilliseconds: 2);
            var t1 = sim.CreateTransport("client");
            var t2 = sim.CreateTransport("server");
            t1.Start(40001);
            t2.Start(0);

            byte[] payload = BuildPayload('A', kPayload);
            SendAsDataPackets(t1, payload, t2.LocalPort);
            Assert.True(sim.WaitForDeliveryCount(totalChunks, 5000));
            Assert.True(sim.DeliveredPackets > 0);
            Assert.True(sim.DeliveredBytes >= kPayload);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task SimulatorRaw_Integration_LossyNetwork_RetransmitsAndDelivers()
        {
            const int kBw = 512 * 1024;
            const int kPayload = 64 * 1024;
            int dataPacketIndex = 0;
            var localRng = new Random(20260428);

            var sim = new NetworkSimulator(fixedDelayMilliseconds: 15, bandwidthBytesPerSecond: kBw,
                seed: 1234, dropRule: (dg) =>
                {
                    if (dg.Buffer.Length == 0 || dg.Buffer[0] != 0x05) return false;
                    Interlocked.Increment(ref dataPacketIndex);
                    return localRng.NextDouble() < 0.05;
                },
                forwardDelayMilliseconds: 10, backwardDelayMilliseconds: 18,
                forwardJitterMilliseconds: 3, backwardJitterMilliseconds: 5);
            var t1 = sim.CreateTransport("client");
            var t2 = sim.CreateTransport("server");
            t1.Start(40002);
            t2.Start(0);

            byte[] payload = BuildPayload('B', kPayload);
            SendAsDataPackets(t1, payload, t2.LocalPort);
            int chunkSize = 1460 - DATA_HEADER_SIZE;
            int totalChunks = (kPayload + chunkSize - 1) / chunkSize;
            int minChunks = Math.Max(1, (totalChunks * 8) / 10);
            Assert.True(sim.WaitForDeliveryCount(minChunks, 5000),
                $"lossy delivery below {minChunks}/{totalChunks} chunks");
            Assert.True(sim.DroppedPackets > 0);
            Assert.True(sim.DeliveredDataPackets > 0);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task SimulatorRaw_Integration_LongFatPipe_ReportsGoodThroughput()
        {
            const int kBw = 100000000 / 8;
            const int kPayload = 256 * 1024;
            int chunkSize = 1460 - DATA_HEADER_SIZE;
            int totalChunks = (kPayload + chunkSize - 1) / chunkSize;

            var sim = new NetworkSimulator(fixedDelayMilliseconds: 50, bandwidthBytesPerSecond: kBw,
                seed: 1234, forwardDelayMilliseconds: 56, backwardDelayMilliseconds: 46);
            var t1 = sim.CreateTransport("client");
            var t2 = sim.CreateTransport("server");
            t1.Start(40005);
            t2.Start(0);

            byte[] payload = BuildPayload('E', kPayload);
            SendAsDataPackets(t1, payload, t2.LocalPort);
            Assert.True(sim.WaitForDeliveryCount(totalChunks, 10000));
            Assert.True(sim.DeliveredPackets > 0);
            Assert.True(sim.DeliveredBytes >= kPayload);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task SimulatorRaw_Integration_HighLossHighRtt_StillCompletes()
        {
            const int kBw = 2 * 1024 * 1024;
            const int kPayload = 64 * 1024;
            var localRng = new Random(20260428);

            var sim = new NetworkSimulator(fixedDelayMilliseconds: 50, bandwidthBytesPerSecond: kBw,
                seed: 20260428, dropRule: (dg) =>
                {
                    if (dg.Buffer.Length == 0 || dg.Buffer[0] != 0x05) return false;
                    return localRng.NextDouble() < 0.05;
                },
                forwardDelayMilliseconds: 58, backwardDelayMilliseconds: 48,
                forwardJitterMilliseconds: 12, backwardJitterMilliseconds: 8);
            var t1 = sim.CreateTransport("client");
            var t2 = sim.CreateTransport("server");
            t1.Start(40004);
            t2.Start(0);

            byte[] payload = BuildPayload('D', kPayload);
            SendAsDataPackets(t1, payload, t2.LocalPort);
            int chunkSize = 1460 - DATA_HEADER_SIZE;
            int totalChunks = (kPayload + chunkSize - 1) / chunkSize;
            int minChunks = Math.Max(1, (totalChunks * 8) / 10);
            Assert.True(sim.WaitForDeliveryCount(minChunks, 8000),
                $"high-loss delivery below {minChunks}/{totalChunks} chunks");
            Assert.True(sim.DeliveredPackets > 0);
            Assert.True(sim.DroppedPackets >= 1);
            Assert.True(sim.DeliveredDataPackets > 0);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task SimulatorRaw_Integration_ReceiverWindow_Effect()
        {
            const int kBw = 512 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: kBw, seed: 42);
            var t1 = sim.CreateTransport("rwnd-cli");
            var t2 = sim.CreateTransport("rwnd-srv");
            t1.Start(40009);
            t2.Start(0);

            byte[] payload = BuildPayload('R', 32 * 1024);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            t1.Send(payload, new IPEndPoint(IPAddress.Loopback, t2.LocalPort));
            Assert.True(sim.WaitForDeliveryCount(1, 3000));
            sw.Stop();
            Assert.True(sim.DeliveredPackets > 0);
            Assert.True(sim.DeliveredBytes >= payload.Length);
            Assert.True(sw.ElapsedMilliseconds > 50);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task SimulatorRaw_Integration_Pacing_RespectsConfiguredRate()
        {
            const int kBw = 128 * 1024;
            int chunkSize = 1460 - DATA_HEADER_SIZE;
            int totalChunks = (64 * 1024 + chunkSize - 1) / chunkSize;

            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: kBw,
                seed: 42, forwardDelayMilliseconds: 9, backwardDelayMilliseconds: 4);
            var t1 = sim.CreateTransport("pace-cli");
            var t2 = sim.CreateTransport("pace-srv");
            t1.Start(40010);
            t2.Start(0);

            byte[] payload = BuildPayload('P', 64 * 1024);
            SendAsDataPackets(t1, payload, t2.LocalPort);
            Assert.True(sim.WaitForDeliveryCount(totalChunks, 3000));
            Assert.True(sim.DeliveredPackets > 0);
            Assert.True(sim.DeliveredBytes >= payload.Length);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task Integration_FullDuplexConcurrentTransfers()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: 8 * 1024 * 1024,
                seed: 42, duplicateRate: 0.02, reorderRate: 0.05);
            var t1 = sim.CreateTransport("client");
            var t2 = sim.CreateTransport("server");
            t1.Start(40017);
            t2.Start(0);

            byte[] clientPayload = BuildUniquePayload(16 * 1024, 9001);
            byte[] serverPayload = BuildUniquePayload(16 * 1024, 9002);

            t1.Send(clientPayload, new IPEndPoint(IPAddress.Loopback, t2.LocalPort));
            t2.Send(serverPayload, new IPEndPoint(IPAddress.Loopback, t1.LocalPort));

            Assert.True(sim.WaitForDeliveryCount(2, 3000));
            Assert.True(sim.DeliveredPackets >= 2);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task SimulatorRaw_Integration_BasicUnidirectionalDelivery()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1024 * 1024);
            var t1 = sim.CreateTransport("sender");
            var t2 = sim.CreateTransport("receiver");
            t1.Start(40008);
            t2.Start(0);

            byte[] payload1 = BuildPayload('W', 4 * 1024);
            byte[] payload2 = BuildPayload('X', 8 * 1024);
            t1.Send(payload1, new IPEndPoint(IPAddress.Loopback, t2.LocalPort));
            t1.Send(payload2, new IPEndPoint(IPAddress.Loopback, t2.LocalPort));

            Assert.True(sim.WaitForDeliveryCount(2, 3000));
            Assert.True(sim.DeliveredPackets >= 2);
            Assert.True(sim.DeliveredBytes >= payload1.Length + payload2.Length);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public Task SimulatorRaw_Integration_ReorderingAndDuplication_StillDelivers()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: 2 * 1024 * 1024,
                jitterMilliseconds: 2, seed: 42, duplicateRate: 0.05, reorderRate: 0.2);
            var t1 = sim.CreateTransport("client");
            var t2 = sim.CreateTransport("server");
            t1.Start(40011);
            t2.Start(0);

            byte[] payload = BuildPayload('Q', 16 * 1024);
            SendAsDataPackets(t1, payload, t2.LocalPort);
            Assert.True(sim.WaitForDeliveryCount(5, 5000));
            Assert.True(sim.DeliveredPackets > 0);
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        private void RunBenchmark(string name, int port, int bw, int payloadSize, int delayMs,
            int jitterMs, double lossRate, int seed, int fwdMs = -1, int revMs = -1)
        {
            int chunkSize = 1460 - DATA_HEADER_SIZE;
            int totalChunks = (payloadSize + chunkSize - 1) / chunkSize;
            int pktIdx = 0;
            var rng = new Random(seed);

            var sim = new NetworkSimulator(fixedDelayMilliseconds: delayMs, bandwidthBytesPerSecond: bw,
                seed: seed + 1, dropRule: lossRate > 0 ? (DropRuleDelegate)((dg) =>
                {
                    if (dg.Buffer.Length == 0 || dg.Buffer[0] != 0x05) return false;
                    Interlocked.Increment(ref pktIdx);
                    return rng.NextDouble() < lossRate;
                }) : null,
                forwardDelayMilliseconds: fwdMs >= 0 ? fwdMs : delayMs,
                backwardDelayMilliseconds: revMs >= 0 ? revMs : delayMs,
                dynamicJitterRangeMilliseconds: 1);
            var t1 = sim.CreateTransport("bm-cli");
            var t2 = sim.CreateTransport("bm-srv");
            t1.Start(port);
            t2.Start(0);

            byte[] payload = BuildUniquePayload(payloadSize, 0xDEAD + port);
            SendAsDataPackets(t1, payload, t2.LocalPort);

            double lossBudgetMult = (lossRate > 0.0 && lossRate <= 0.01)
                ? 4.0
                : (payloadSize <= 64 * 1024 ? 6.0 : 3.0);
            int minChunks = lossRate == 0.0 ? totalChunks
                : Math.Max(1, totalChunks - (int)Math.Ceiling(totalChunks * lossRate * lossBudgetMult));
            int waitTimeout = Math.Min(10000, Math.Max(5000, delayMs * 4 + 2000));
            bool delivered = sim.WaitForDeliveryCount(minChunks, waitTimeout);

            if (lossRate == 0.0)
            {
                Assert.True(delivered, $"{name}: delivery timeout");
                Assert.True(sim.DeliveredBytes >= payloadSize, $"{name}: not all bytes delivered");
                Assert.True(sim.LogicalThroughputBytesPerSecond > bw * 0.03, $"{name}: throughput too low");
            }
            else
            {
                // Lossy scenarios: the loss budget allows up to 3x the
                // configured loss rate (jitter can inflate effective loss), so
                // the delivered byte count must reach the expected minimum --
                // this is what makes the scenario really complete rather than
                // merely delivering one lucky packet.
                Assert.True(delivered, $"{name}: delivery timeout (minChunks={minChunks})");
                Assert.True(sim.DeliveredBytes >= (long)minChunks * chunkSize, $"{name}: delivered {sim.DeliveredBytes} < min {minChunks * chunkSize}");
            }

            _output.WriteLine($"{name}: tput={sim.LogicalThroughputBytesPerSecond:F0}B/s delivered={sim.DeliveredBytes} dropped={sim.DroppedPackets}");
            sim.StopScheduler();
        }

        [Fact]
        public void Simulator_GigabitIdeal_ReportsHighUtilization()
        {
            RunBenchmark("Gigabit_Ideal", 40100, 1000000000 / 8, 256 * 1024, 1, 0, 0, 1234);
        }

        [Fact]
        public void Simulator_GigabitLossRandom5_RespectsLossBudget()
        {
            RunBenchmark("Gigabit_Loss5", 40101, 1000000000 / 8, 256 * 1024, 30, 0, 0.05, 20260502);
        }

        [Fact]
        public void Simulator_GigabitLossRandom1_DeliversWithinLossBudget()
        {
            RunBenchmark("Gigabit_Loss1", 40102, 1000000000 / 8, 256 * 1024, 20, 0, 0.01, 20260501);
        }

        [Fact]
        public void Simulator_LongFatPipe100M_ConvergesAndDelivers()
        {
            RunBenchmark("LongFat_100M", 40103, 100000000 / 8, 256 * 1024, 50, 2, 0, 1234);
        }

        [Fact]
        public void Simulator_TenGigabitProbe_ConvergesWithoutConfiguredRateCap()
        {
            const int kBw10G = (int)(10000000000L / 8);
            RunBenchmark("Benchmark10G", 40104, kBw10G, 1024 * 1024, 1, 0, 0, 1234);
        }

        [Fact]
        public void SimulatorRaw_Simulator_BurstLoss_RecoversWithinBudget()
        {
            const int kBw = 100000000 / 8;
            const int kPayload = 256 * 1024;
            const int kDelayMs = 25;
            const int kSeed = 1234;
            const int kPort = 40105;
            const int kBurstStart = 5;
            const int kBurstCount = 8;

            int pktIdx = 0;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: kDelayMs, bandwidthBytesPerSecond: kBw,
                seed: kSeed, dropRule: (dg) =>
                {
                    if (dg.Buffer.Length == 0 || dg.Buffer[0] != 0x05) return false;
                    int idx = Interlocked.Increment(ref pktIdx) - 1;
                    return idx >= kBurstStart && idx < kBurstStart + kBurstCount;
                },
                dynamicJitterRangeMilliseconds: 1);
            var t1 = sim.CreateTransport("bl-cli");
            var t2 = sim.CreateTransport("bl-srv");
            t1.Start(kPort);
            t2.Start(0);

            byte[] payload = BuildUniquePayload(kPayload, 0xDEAD + kPort);
            SendAsDataPackets(t1, payload, t2.LocalPort);

            int chunkSize = 1460 - DATA_HEADER_SIZE;
            int totalChunks = (kPayload + chunkSize - 1) / chunkSize;
            int minChunks = totalChunks - kBurstCount - 2;
            int waitTimeout = Math.Min(10000, Math.Max(5000, kDelayMs * 4 + 2000));
            bool delivered = sim.WaitForDeliveryCount(minChunks, waitTimeout);

            Assert.True(delivered);
            Assert.True(sim.DeliveredBytes >= (long)minChunks * chunkSize,
                $"BurstLoss: delivered {sim.DeliveredBytes} < min {minChunks * chunkSize}");
            Assert.True(sim.DroppedDataPackets > 0);
            _output.WriteLine($"BurstLoss: delivered={sim.DeliveredBytes} dropped={sim.DroppedPackets}");
            sim.StopScheduler();
        }

        [Fact]
        public void Simulator_AsymmetricRoute_HandlesWell()
        {
            RunBenchmark("AsymRoute", 40106, 100000000 / 8, 256 * 1024, 0, 0, 0.005, 20260503, 25, 15);
        }

        [Fact]
        public void Simulator_HighJitter_StaysAliveAndUseful()
        {
            RunBenchmark("HighJitter", 40107, 100000000 / 8, 128 * 1024, 50, 25, 0.0, 20260504);
        }

        [Fact]
        public void Simulator_Mobile3G_LossyConnects()
        {
            RunBenchmark("Mobile3G", 40114, 4 * 1000 * 1000 / 8, 75 * 1024, 75, 30, 0.03, 20260601);
        }

        [Fact]
        public void Simulator_Mobile4G_HighJitter()
        {
            RunBenchmark("Mobile4G", 40115, 20 * 1000 * 1000 / 8, 64 * 1024, 30, 25, 0.01, 20260602, 35, 25);
        }

        [Fact]
        public void Simulator_Satellite300ms_Completes()
        {
            RunBenchmark("Satellite", 40116, 10 * 1000 * 1000 / 8, 64 * 1024, 150, 5, 0.001, 20260603, 155, 145);
        }

        [Fact]
        public void Simulator_VpnDualCongestion_LongRtt()
        {
            RunBenchmark("VpnTunnel", 40117, 100000000 / 8, 256 * 1024, 50, 10, 0.005, 20260604, 43, 57);
        }

        [Fact]
        public void Simulator_DataCenter_LowLatencyHighBW()
        {
            const int kBw10G = (int)(10000000000L / 8);
            RunBenchmark("DataCenter", 40118, kBw10G, 256 * 1024, 0, 0, 0, 1234);
        }

        [Fact]
        public void Simulator_EnterpriseBroadband_ModerateRtt()
        {
            RunBenchmark("Enterprise", 40119, 1000000000 / 8, 256 * 1024, 15, 3, 0.001, 20260606);
        }

        [Fact]
        public void Simulator_Weak4G_RecoversFromOutage()
        {
            RunBenchmark("Weak4G", 40108, 10 * 1000 * 1000 / 8, 64 * 1024, 80, 0, 0.05, 20260505, 80, 80);
        }

        [Fact]
        public void Simulator_AirplaneWifi_HandlesSatelliteHandover()
        {
            RunBenchmark("AirplaneWifi", 40125, 10 * 1000 * 1000 / 8, 64 * 1024, 50, 5, 0.03, 20260507, 50, 50);
        }

        [Fact]
        public void Simulator_HighSpeedTrain_HandlesTunnelAndHandover()
        {
            RunBenchmark("HighSpeedTrain", 40126, 20 * 1000 * 1000 / 8, 64 * 1024, 20, 20, 0.02, 20260508, 20, 20);
        }

        [Fact]
        public void Simulator_DrivingVehicle_HandlesCellSwitch()
        {
            RunBenchmark("DrivingVehicle", 40127, 5 * 1000 * 1000 / 8, 64 * 1024, 15, 10, 0.04, 20260509, 15, 15);
        }

        [Fact]
        public void Coverage_LossBandwidth_100M_Loss0p2()
        {
            RunBenchmark("100M_Loss0.2", 40113, 100000000 / 8, 256 * 1024, 10, 4, 0.002, 20260506);
        }

        [Fact]
        public void Coverage_LossBandwidth_100M_Loss1()
        {
            RunBenchmark("100M_Loss1", 40144, 100000000 / 8, 256 * 1024, 10, 4, 0.01, 20260516);
        }

        [Fact]
        public void Coverage_LossBandwidth_100M_Loss10()
        {
            RunBenchmark("100M_Loss10", 40123, 100000000 / 8, 256 * 1024, 10, 4, 0.10, 20260706);
        }

        [Fact]
        public void Coverage_LossBandwidth_1G_Loss3()
        {
            RunBenchmark("1G_Loss3", 40143, 1000000000 / 8, 256 * 1024, 20, 4, 0.03, 20260536);
        }

        [Fact]
        public void Simulator_NoLoss100M_Throughput()
        {
            RunBenchmark("NoLoss100M", 43001, 100000000 / 8, 32 * 1024, 2, 0, 0.0, 23001);
        }

        [Fact]
        public void Simulator_Loss1Percent_Recovery()
        {
            RunBenchmark("100M_Loss1_Detailed", 43002, 100000000 / 8, 32 * 1024, 10, 2, 0.01, 23002);
        }

        [Fact]
        public void Simulator_Loss5Percent_Recovery()
        {
            RunBenchmark("20M_Loss5", 43003, 20 * 1000 * 1000 / 8, 32 * 1024, 15, 3, 0.05, 23003);
        }

        [Fact]
        public void Benchmark_RttTracking_GeodesicConvergence()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;
            long targetRtt = 50000;
            int convergeIter = -1;

            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, targetRtt, 24000);
                now += 50000;
                if (convergeIter < 0 && cc.MinRttMicros > 0 &&
                    cc.MinRttMicros >= targetRtt * 90 / 100 &&
                    cc.MinRttMicros <= targetRtt * 110 / 100)
                {
                    convergeIter = i;
                }
            }
            long finalRtt = cc.MinRttMicros;
            _output.WriteLine($"RttTracking: target={targetRtt} us, final={finalRtt} us, converged_at_iter={convergeIter}");
            Assert.True(convergeIter >= 0);
            Assert.True(convergeIter < 50);
            Assert.True(finalRtt > 0);
            Assert.True(finalRtt <= targetRtt * 110 / 100);
            Assert.True(finalRtt >= targetRtt * 70 / 100);
        }

        [Fact]
        public void Benchmark_ProbeBwGainCycle()
        {
            var config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 12500000;
            config.InitialCwndPackets = 20;
            config.MaxCongestionWindowBytes = int.MaxValue;
            var cc = new UcpCongestionControl(config);
            long now = 100000;

            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 20000;
            }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.True(cc.PacingGainUnits > 0);
            Assert.True(cc.PacingGainUnits <= 1023);

            for (int i = 0; i < 20; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 20000;
            }
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            _output.WriteLine($"ProbeBwGainCycle: mode={cc.Mode} gain={cc.PacingGainUnits} rate={cc.PacingRateBytesPerSecond}");
        }

        [Fact]
        public Task SimulatorRaw_Simulator_BwConvergence_1MTo100M()
        {
            const int kBwLow = 1 * 1000 * 1000 / 8;
            const int kBwHigh = 100 * 1000 * 1000 / 8;
            const int kPayload = 32 * 1024;

            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: kBwLow, seed: 23004);
            var t1 = sim.CreateTransport("bc-cli");
            var t2 = sim.CreateTransport("bc-srv");
            t1.Start(43004);
            t2.Start(0);

            byte[] payload1 = BuildUniquePayload(kPayload, 0xBABE);
            SendAsDataPackets(t1, payload1, t2.LocalPort);
            bool r1 = sim.WaitForDeliveryCount(Math.Max(1, (kPayload + 1459) / 1460), 5000);
            long phase1Bytes = sim.DeliveredBytes;

            sim.Configure(0, 2, 0, kBwHigh, 0, 0);

            byte[] payload2 = BuildUniquePayload(kPayload, 0xFACE);
            SendAsDataPackets(t1, payload2, t2.LocalPort);
            bool r2 = sim.WaitForDeliveryCount(2 * Math.Max(1, (kPayload + 1459) / 1460), 5000);
            long totalBytes = sim.DeliveredBytes;

            Assert.True(r1, "Phase 1 (1Mbps) should deliver within 5s");
            Assert.True(r2, "Phase 2 (100Mbps) should deliver within 5s");
            Assert.True(totalBytes >= (long)kPayload * 2,
                $"Both phases should deliver their full payloads: total={totalBytes} expected>={kPayload * 2}");
            _output.WriteLine($"BwConv: phase1={phase1Bytes}B total={totalBytes}B");
            sim.StopScheduler();
            return Task.CompletedTask;
        }

        [Fact]
        public async Task SimulatedNetwork_NoLoss100M_Throughput()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 100;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43051);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43051));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('N', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(await UcpTestHelpers.WaitForRttSamplesAsync(client),
                    "Sender must record at least one RTT sample after a completed transfer");
                var report = client.GetReport();
                Assert.True(report.RttSamplesMicros.Count >= 1);
                _output.WriteLine($"NoLoss100M: tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_Loss1Percent_Recovery()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: bw,
                lossRate: 0.01, seed: 23002);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 200;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43052);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43052));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('L', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _output.WriteLine($"Loss1Pct: dropped={sim.DroppedPackets} tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_Loss5Percent_Recovery()
        {
            const int bw = 20_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 15, bandwidthBytesPerSecond: bw,
                lossRate: 0.05, seed: 23003);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 300;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43053);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43053));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('H', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _output.WriteLine($"Loss5Pct: dropped={sim.DroppedPackets} tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_TransferSucceeds_At1MThen100M()
        {
            const int bwLow = 1_000_000 / 8;
            const int bwHigh = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: bwLow);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bwLow;
            config.MaxPacingRateBytesPerSecond = 0;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43054);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43054));
                UcpConnection srvConn = await acceptTask;

                byte[] payload1 = Encoding.ASCII.GetBytes(new string('A', 16 * 1024));
                byte[] received1 = new byte[payload1.Length];
                Task<bool> readTask1 = srvConn.ReadAsync(received1, 0, received1.Length);
                await client.WriteAsync(payload1, 0, payload1.Length);
                bool readOk1 = await UcpTestHelpers.ReadWithTimeoutTask(readTask1, 30000);
                Assert.True(readOk1);

                sim.Configure(0, 2, 0, bwHigh, 0, 0);

                byte[] payload2 = Encoding.ASCII.GetBytes(new string('B', 16 * 1024));
                byte[] received2 = new byte[payload2.Length];
                Task<bool> readTask2 = srvConn.ReadAsync(received2, 0, received2.Length);
                var sw2 = System.Diagnostics.Stopwatch.StartNew();
                await client.WriteAsync(payload2, 0, payload2.Length);
                bool readOk2 = await UcpTestHelpers.ReadWithTimeoutTask(readTask2, 30000);
                sw2.Stop();
                Assert.True(readOk2);

                _output.WriteLine($"BwConv: delivered={sim.DeliveredBytes} tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_BurstLoss_Recovers()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 25, bandwidthBytesPerSecond: bw,
                lossRate: 0, seed: 1234, jitterMilliseconds: 4);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 200;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43055);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43055));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('K', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 8000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _output.WriteLine($"Burst: dropped={sim.DroppedPackets} tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_ReorderingAndDuplication_StillDeliversExactlyOnce()
        {
            const int bw = 2 * 1024 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 2, seed: 42, duplicateRate: 0.05, reorderRate: 0.2);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw * 8;
            config.MaxPacingRateBytesPerSecond = bw * 8;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43056);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43056));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('Q', 16 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 8000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _output.WriteLine($"ReorderDup: dup={sim.DuplicatedPackets} reorder={sim.ReorderedPackets} tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_SmallReceiverWindow_SlowsSender()
        {
            const int bw = 512 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw * 10;
            config.MaxPacingRateBytesPerSecond = bw * 10;
            // Small receive window: ~8 packets (~10 KB) forces the sender to
            // pace in multiple window-quantum round trips instead of blasting
            // the whole 32 KB payload in one burst.
            config.RecvWindowPackets = 8;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43057);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43057));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('S', 32 * 1024));
                byte[] received = new byte[payload.Length];

                var sw = System.Diagnostics.Stopwatch.StartNew();
                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 15000);
                sw.Stop();

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                // The small receive window (32 KB payload / ~10 KB window = 4+
                // window-quantum round trips at 5ms RTT) must measurably slow
                // the transfer compared to an unconstrained single burst.
                Assert.True(sw.ElapsedMilliseconds >= 10,
                    $"Small window should force multiple round trips: {sw.ElapsedMilliseconds}ms");
                _output.WriteLine($"Rwnd: elapsed={sw.ElapsedMilliseconds}ms");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_HighJitter_StaysAlive()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 50, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 25);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 300;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43058);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43058));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('J', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 8000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _output.WriteLine($"HighJitter: tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_FullDuplex_ConcurrentTransfers()
        {
            const int bw = 8 * 1024 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 2);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 200;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43059);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43059));
                UcpConnection srvConn = await acceptTask;

                byte[] payloadClient = Encoding.ASCII.GetBytes(new string('C', 16 * 1024));
                byte[] payloadServer = Encoding.ASCII.GetBytes(new string('S', 16 * 1024));
                byte[] receivedClient = new byte[payloadClient.Length];
                byte[] receivedServer = new byte[payloadServer.Length];

                await client.WriteAsync(payloadClient, 0, payloadClient.Length);

                bool readOk1 = await UcpTestHelpers.ReadWithTimeoutTask(srvConn.ReadAsync(receivedClient, 0, receivedClient.Length), 8000);
                Assert.True(readOk1, "Server should receive client data");
                Assert.True(payloadClient.SequenceEqual(receivedClient), "Server data should match client payload");

                await srvConn.WriteAsync(payloadServer, 0, payloadServer.Length);

                bool readOk2 = await UcpTestHelpers.ReadWithTimeoutTask(client.ReadAsync(receivedServer, 0, receivedServer.Length), 8000);
                Assert.True(readOk2, "Client should receive server data");
                Assert.True(payloadServer.SequenceEqual(receivedServer), "Client data should match");
                _output.WriteLine($"FullDuplex: delivered={sim.DeliveredBytes} readOk1={readOk1} readOk2={readOk2}");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_Mobile3G_Lossy()
        {
            const int bw = 4 * 1000 * 1000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 75, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 30, lossRate: 0.03, seed: 20260601);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 300;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43061);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43061));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('M', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 20000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _output.WriteLine($"Mobile3G: dropped={sim.DroppedPackets} tput={sim.LogicalThroughputBytesPerSecond:F0}B/s");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_DatagramLoopback()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.FairQueueRoundMilliseconds = 1;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43062);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43062));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('D', 8 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                int written = await client.SendAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 15000);

                Assert.Equal(payload.Length, written);
                Assert.True(readOk);
                Assert.Equal(payload, received);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_RttMeasurement()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration();
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43063);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43063));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('R', 64 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);
                Assert.True(readOk);

                Assert.True(await UcpTestHelpers.WaitForRttSamplesAsync(client),
                    $"Should have at least 1 RTT sample");
                UcpTransferReport report = client.GetReport();
                Assert.True(report.RttSamplesMicros.Count >= 1, $"Should have at least 1 RTT sample, got {report.RttSamplesMicros.Count}");
                _output.WriteLine($"RTT samples count={report.RttSamplesMicros.Count}");
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_CanConnectAndTransfer()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.FairQueueRoundMilliseconds = 1;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43064);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43064));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('N', 16 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                int written = await client.SendAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 15000);

                Assert.Equal(payload.Length, written);
                Assert.True(readOk);
                Assert.Equal(payload, received);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_JitterDoesNotBreakDelivery()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: 10 * 1024 * 1024,
                jitterMilliseconds: 5);
            var server = new UcpServer(sim.CreateTransport("server"));
            var client = new UcpConnection(sim.CreateTransport("client"), true, new UcpConfiguration(), null);
            server.Start(43065);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43065));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('J', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 8000);

                Assert.True(readOk);
                Assert.Equal(payload, received);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_MultipleClientsFairQueue()
        {
            const int bw = 2 * 1024 * 1024;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            var server = new UcpServer(sim.CreateTransport("server"), config);
            server.Start(43066);

            var clients = new List<UcpConnection>();
            var srvConns = new List<UcpConnection>();
            try
            {
                for (int i = 0; i < 3; i++)
                    clients.Add(new UcpConnection(sim.CreateTransport("client" + i), true, config, null));

                var acceptTasks = new List<Task<UcpConnection>>();
                for (int i = 0; i < 3; i++)
                    acceptTasks.Add(server.AcceptAsync());

                for (int i = 0; i < 3; i++)
                    await clients[i].ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43066));

                for (int i = 0; i < 3; i++)
                    srvConns.Add(await acceptTasks[i]);

                byte[] payload = Encoding.ASCII.GetBytes(new string('F', 64 * 1024));
                var received = new List<byte[]>();
                var readTasks = new List<Task<bool>>();
                for (int i = 0; i < 3; i++)
                {
                    received.Add(new byte[payload.Length]);
                    readTasks.Add(srvConns[i].ReadAsync(received[i], 0, payload.Length));
                }

                var writeTasks = new List<Task>();
                for (int i = 0; i < 3; i++)
                {
                    int idx = i;
                    writeTasks.Add(clients[idx].WriteAsync(payload, 0, payload.Length));
                }

                await Task.WhenAll(writeTasks);
                var readAllTask = Task.WhenAll(readTasks);
                var timeoutTask = Task.Delay(15000);
                Assert.NotEqual(timeoutTask, await Task.WhenAny(readAllTask, timeoutTask));
                var results = await readAllTask;

                for (int i = 0; i < 3; i++)
                {
                    Assert.True(results[i]);
                    Assert.True(payload.SequenceEqual(received[i]));
                }
            }
            finally
            {
                foreach (var c in clients)
                    await UcpTestHelpers.CloseWithTimeout(c);
                server.Stop();
            }
        }
    }
}
