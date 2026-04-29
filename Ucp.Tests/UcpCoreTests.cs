using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Ucp;
using Ucp.Internal;
using UcpTest.TestTransport;
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
        public void SequenceComparer_HandlesWrapAround()
        {
            uint max = uint.MaxValue;
            uint zero = 0;
            uint one = 1;

            Assert.True(UcpSequenceComparer.IsAfter(zero, max));
            Assert.True(UcpSequenceComparer.IsAfter(one, max));
            Assert.True(UcpSequenceComparer.IsBefore(max, zero));
            Assert.Equal(1, UcpSequenceComparer.Instance.Compare(zero, max));
            Assert.Equal(-1, UcpSequenceComparer.Instance.Compare(max, zero));
        }

        [Fact]
        public void PacketCodec_CanRoundTripAckWithEchoTimestamp()
        {
            UcpAckPacket packet = new UcpAckPacket();
            packet.Header = new UcpCommonHeader
            {
                Type = UcpPacketType.Ack,
                Flags = UcpPacketFlags.NeedAck,
                ConnectionId = 77,
                Timestamp = 123456789
            };
            packet.AckNumber = 100;
            packet.SackBlocks.Add(new SackBlock { Start = 102, End = 105 });
            packet.SackBlocks.Add(new SackBlock { Start = 109, End = 110 });
            packet.WindowSize = 512;
            packet.EchoTimestamp = 987654321;

            byte[] encoded = UcpPacketCodec.Encode(packet);
            UcpPacket decodedRaw;
            bool ok = UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out decodedRaw);

            Assert.True(ok);
            UcpAckPacket decoded = Assert.IsType<UcpAckPacket>(decodedRaw);
            Assert.Equal(packet.Header.Type, decoded.Header.Type);
            Assert.Equal(packet.Header.Flags, decoded.Header.Flags);
            Assert.Equal(packet.Header.ConnectionId, decoded.Header.ConnectionId);
            Assert.Equal(packet.AckNumber, decoded.AckNumber);
            Assert.Equal(packet.WindowSize, decoded.WindowSize);
            Assert.Equal(packet.EchoTimestamp, decoded.EchoTimestamp);
            Assert.Equal(2, decoded.SackBlocks.Count);
            Assert.Equal((uint)102, decoded.SackBlocks[0].Start);
            Assert.Equal((uint)105, decoded.SackBlocks[0].End);
        }

        [Fact]
        public void SackGenerator_BuildsContinuousBlocks()
        {
            UcpSackGenerator generator = new UcpSackGenerator();
            List<uint> received = new List<uint> { 12, 13, 14, 18, 19, 25 };

            List<SackBlock> blocks = generator.Generate(10, received, 8);

            Assert.Equal(3, blocks.Count);
            Assert.Equal((uint)12, blocks[0].Start);
            Assert.Equal((uint)14, blocks[0].End);
            Assert.Equal((uint)18, blocks[1].Start);
            Assert.Equal((uint)19, blocks[1].End);
            Assert.Equal((uint)25, blocks[2].Start);
            Assert.Equal((uint)25, blocks[2].End);
        }

        [Fact]
        public void RtoEstimator_CapsBackoffAtTwiceMinimumRto()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.MinRtoMicros = 1000000;
            config.MaxRtoMicros = 60000000;
            config.RetransmitBackoffFactor = 1.5d;
            UcpRtoEstimator estimator = new UcpRtoEstimator(config);
            estimator.Update(100000);
            long first = estimator.CurrentRtoMicros;

            estimator.Backoff();

            Assert.Equal(Math.Min((long)(first * 1.5d), config.MinRtoMicros * 2), estimator.CurrentRtoMicros);
        }

        [Fact]
        public void PacingController_ComputesWaitTimeWhenTokensInsufficient()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;
            PacingController controller = new PacingController(config, 1000);
            controller.SetRate(1000, 1000000);

            Assert.True(controller.TryConsume(1220, 1000000));
            Assert.False(controller.TryConsume(500, 1000000));
            long wait = controller.GetWaitTimeMicros(500, 1000000);

            Assert.InRange(wait, 499000, 501000);
        }

        [Fact]
        public void BbrController_TransitionsOutOfStartup()
        {
            BbrCongestionControl bbr = new BbrCongestionControl();
            long now = 100000;

            for (int i = 0; i < 12; i++)
            {
                bbr.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }

            Assert.NotEqual(BbrMode.Startup, bbr.Mode);
            Assert.True(bbr.PacingRateBytesPerSecond > 0);
            Assert.True(bbr.CongestionWindowBytes >= new UcpConfiguration().InitialCongestionWindowBytes);
        }

        [Fact]
        public void BbrController_BandwidthEstimateResistsShortTermRateCliffs()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1;
            config.MaxPacingRateBytesPerSecond = 0;
            config.BbrWindowRtRounds = 2;
            BbrCongestionControl bbr = new BbrCongestionControl(config);

            bbr.OnAck(100000, 100000, 100000, 100000);
            double highRate = bbr.BtlBwBytesPerSecond;
            bbr.OnAck(500000, 1000, 100000, 1000);
            bbr.OnAck(700000, 1000, 100000, 1000);
            bbr.OnAck(2500000, 1000, 100000, 1000);

            Assert.True(highRate > 1);
            Assert.True(bbr.BtlBwBytesPerSecond >= highRate * UcpConstants.BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND);
        }

        [Theory]
        [InlineData(UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND)]
        [InlineData(UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND)]
        [InlineData(UcpConstants.BENCHMARK_10_GBPS_BYTES_PER_SECOND)]
        public void BbrController_AutoProbeConvergesWithoutConfiguredRateCap(int bottleneckBytesPerSecond)
        {
            UcpConfiguration config = UcpConfiguration.GetOptimizedConfig();
            config.InitialBandwidthBytesPerSecond = UcpConstants.BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND;
            config.MaxPacingRateBytesPerSecond = 0;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndBytes = (uint)Math.Max(config.InitialCongestionWindowBytes, bottleneckBytesPerSecond / UcpConstants.BENCHMARK_INITIAL_PROBE_BANDWIDTH_DIVISOR);
            BbrCongestionControl bbr = new BbrCongestionControl(config);
            long nowMicros = UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS;
            long convergenceMicros = 0;

            for (int round = 0; round < UcpConstants.BENCHMARK_CONTROLLER_MAX_CONVERGENCE_ROUNDS; round++)
            {
                int deliveredBytes = (int)Math.Min(int.MaxValue, bottleneckBytesPerSecond * (UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS / (double)UcpConstants.MICROS_PER_SECOND));
                bbr.OnAck(nowMicros, deliveredBytes, UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS, deliveredBytes);
                if (bbr.PacingRateBytesPerSecond >= bottleneckBytesPerSecond * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO)
                {
                    convergenceMicros = nowMicros;
                    break;
                }

                nowMicros += UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS;
            }

            Assert.True(convergenceMicros > 0);
            Assert.True(bbr.PacingRateBytesPerSecond >= bottleneckBytesPerSecond * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
            Assert.True(bbr.PacingRateBytesPerSecond <= bottleneckBytesPerSecond * UcpConstants.BENCHMARK_MAX_CONVERGED_PACING_RATIO);
        }

        [Fact]
        public void PacingController_AllowsPacketWhenBucketDurationIsTiny()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1;
            config.SendQuantumBytes = 1;
            PacingController controller = new PacingController(config, 1);

            Assert.True(controller.TryConsume(UcpConstants.DataHeaderSize + config.MaxPayloadSize, 0));
        }

        [Fact]
        public void RtoEstimator_ClampsInvalidConfiguration()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.MinRtoMicros = 0;
            config.MaxRtoMicros = 1;
            config.RetransmitBackoffFactor = 0.5d;
            UcpRtoEstimator estimator = new UcpRtoEstimator(config);

            estimator.Update(1000);
            long beforeBackoff = estimator.CurrentRtoMicros;
            estimator.Backoff();

            Assert.True(beforeBackoff >= UcpConstants.MinRtoMicros);
            Assert.True(estimator.CurrentRtoMicros >= beforeBackoff);
        }

        [Fact]
        public async Task Integration_NoLoss_CanConnectAndTransfer()
        {
            const int noLossBandwidth = 10 * 1024 * 1024;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: noLossBandwidth);
            UcpConfiguration noLossConfig = CreateScenarioConfig(noLossBandwidth);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), noLossConfig.Clone());
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, noLossConfig.Clone(), null);
            server.Start(40001);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40001));
                UcpConnection serverConnection = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('A', 512 * 1024));
                byte[] received = new byte[payload.Length];

                DateTime start = DateTime.UtcNow;
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 5000);
                await WaitForAckSettlementAsync(client, 1000);
                double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
                double throughput = Math.Max(simulator.LogicalThroughputBytesPerSecond, payload.Length / elapsedSeconds);
                UcpPerformanceReport noLossReport = UcpPerformanceReport.FromConnection("NoLoss", client, throughput, (long)(elapsedSeconds * 1000d), noLossBandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros);
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, noLossReport);

                _output.WriteLine("NoLoss delivered packets={0}, bytes={1}", simulator.DeliveredPackets, simulator.DeliveredBytes);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(simulator.DeliveredPackets > 0);
                Assert.True(noLossReport.RetransmissionRatio <= 0.01d);
                Assert.True(noLossReport.AverageRttMicros > 0);
                Assert.InRange(noLossReport.PacingRateBytesPerSecond, noLossBandwidth * 0.95d, noLossBandwidth * 1.30d);
            }
            finally
            {
                await client.CloseAsync();
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_LossyNetwork_RetransmitsAndDelivers()
        {
            int dataPacketIndex = 0;
            const int lossyBandwidth = 512 * 1024;
            NetworkSimulator simulator = new NetworkSimulator(
                fixedDelayMilliseconds: 15,
                jitterMilliseconds: 5,
                bandwidthBytesPerSecond: lossyBandwidth,
                dropRule: delegate (NetworkSimulator.SimulatedDatagram datagram)
                {
                    UcpPacket packet;
                    if (!UcpPacketCodec.TryDecode(datagram.Buffer, 0, datagram.Count, out packet))
                    {
                        return false;
                    }

                    if (packet.Header.Type == UcpPacketType.Data)
                    {
                        dataPacketIndex++;
                        if (dataPacketIndex == 8)
                        {
                            return true;
                        }
                    }

                    return false;
                });

            UcpConfiguration lossyConfig = CreateScenarioConfig(lossyBandwidth);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, lossyConfig.Clone(), null);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), lossyConfig.Clone());
            server.Start(40002);
            try
            {

                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40002));
                UcpConnection serverConnection = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('B', 128 * 1024));
                byte[] received = new byte[payload.Length];
                DateTime start = DateTime.UtcNow;
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 8000);
                await WaitForAckSettlementAsync(client, 1000);
                double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
                UcpPerformanceReport lossyReport = UcpPerformanceReport.FromConnection("Lossy", client, payload.Length / elapsedSeconds, (long)(elapsedSeconds * 1000d), lossyBandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros);
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, lossyReport);

                _output.WriteLine("Lossy dropped={0}, delivered={1}", simulator.DroppedPackets, simulator.DeliveredPackets);

                Assert.True(dataPacketIndex >= 8);
                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(simulator.DroppedPackets >= 1);
                Assert.True(lossyReport.RetransmissionRatio > 0);
                Assert.True(lossyReport.RetransmissionRatio < 0.45d);
                Assert.InRange(lossyReport.PacingRateBytesPerSecond, lossyBandwidth * 0.70d, lossyBandwidth * 1.30d);
            }
            finally
            {
                await client.CloseAsync();
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_FairQueue_MultiClientGetsBalancedCompletion()
        {
            const int bandwidth = 256 * 1024;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bandwidth);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), bandwidth);
            server.Start(40003);

            List<UcpConnection> clients = new List<UcpConnection>();
            List<UcpConnection> serverConnections = new List<UcpConnection>();
            for (int i = 0; i < 4; i++)
            {
                clients.Add(new UcpConnection(simulator.CreateTransport("client" + i)));
            }

            List<Task<UcpConnection>> acceptTasks = new List<Task<UcpConnection>>();
            for (int i = 0; i < 4; i++)
            {
                acceptTasks.Add(server.AcceptAsync());
            }

            for (int i = 0; i < clients.Count; i++)
            {
                await clients[i].ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40003));
            }

            for (int i = 0; i < acceptTasks.Count; i++)
            {
                serverConnections.Add(await acceptTasks[i]);
            }

            byte[] payload = Encoding.ASCII.GetBytes(new string('C', 128 * 1024));
            List<byte[]> received = new List<byte[]>();
            for (int i = 0; i < clients.Count; i++)
            {
                received.Add(new byte[payload.Length]);
            }

            DateTime commonStart = DateTime.UtcNow;
            List<Task> writes = new List<Task>();
            List<Task<bool>> reads = new List<Task<bool>>();
            Task<double>[] readWithDurations = new Task<double>[clients.Count];
            for (int i = 0; i < clients.Count; i++)
            {
                int index = i;
                writes.Add(serverConnections[index].WriteAsync(payload, 0, payload.Length));
                reads.Add(ReadWithinAsync(clients[index], received[index], 0, payload.Length, 30000));
                readWithDurations[index] = MeasureReadDurationAsync(reads[index], commonStart);
            }

            await Task.WhenAll(writes);
            bool[] results = await Task.WhenAll(reads);
            double[] durations = await Task.WhenAll(readWithDurations);
            for (int i = 0; i < results.Length; i++)
            {
                Assert.True(results[i]);
                Assert.True(payload.SequenceEqual(received[i]));
            }

            double[] throughputs = new double[durations.Length];
            double totalThroughput = 0;
            for (int i = 0; i < durations.Length; i++)
            {
                throughputs[i] = payload.Length / Math.Max(0.001d, durations[i] / 1000d);
                totalThroughput += throughputs[i];
            }

            double avgThroughput = totalThroughput / throughputs.Length;
            _output.WriteLine("FairQueue durations(ms): {0}", JoinDoubles(durations));
            _output.WriteLine("FairQueue throughputs(B/s): {0}", JoinDoubles(throughputs));

            for (int i = 0; i < throughputs.Length; i++)
            {
                Assert.InRange(throughputs[i], avgThroughput * 0.8d, avgThroughput * 1.2d);
            }

            for (int i = 0; i < clients.Count; i++)
            {
                await clients[i].CloseAsync();
            }

            server.Stop();
        }

        [Fact]
        public async Task Integration_HighLossHighRtt_StillCompletes()
        {
            const int highLossBandwidth = 2 * 1024 * 1024;
            Random highLossRandom = new Random(20260428);
            NetworkSimulator simulator = new NetworkSimulator(
                fixedDelayMilliseconds: 50,
                jitterMilliseconds: 20,
                bandwidthBytesPerSecond: highLossBandwidth,
                dropRule: delegate (NetworkSimulator.SimulatedDatagram datagram)
                {
                    UcpPacket packet;
                    if (!UcpPacketCodec.TryDecode(datagram.Buffer, 0, datagram.Count, out packet))
                    {
                        return false;
                    }

                    return packet.Header.Type == UcpPacketType.Data && highLossRandom.NextDouble() < 0.05d;
                });
            UcpConfiguration highLossConfig = CreateScenarioConfig(highLossBandwidth);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), highLossConfig);
            server.Start(40004);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, highLossConfig.Clone(), null);

            Task<UcpConnection> acceptTask = server.AcceptAsync();
            await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40004));
            UcpConnection serverConnection = await acceptTask;

            byte[] payload = Encoding.ASCII.GetBytes(new string('D', 256 * 1024));
            byte[] received = new byte[payload.Length];
            DateTime start = DateTime.UtcNow;
            bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
            bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 20000);
            await WaitForAckSettlementAsync(client, 1000);
            double throughput = payload.Length / Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);

            _output.WriteLine("HighLoss RTT scenario throughput={0:F2} B/s, dropped={1}", throughput, simulator.DroppedPackets);
            UcpPerformanceReport highLossReport = UcpPerformanceReport.FromConnection("HighLossHighRtt", client, throughput, (long)((DateTime.UtcNow - start).TotalMilliseconds), highLossBandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros);
            UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, highLossReport);

            Assert.True(writeOk);
            Assert.True(readOk);
            Assert.True(payload.SequenceEqual(received));
            Assert.True(throughput > 32 * 1024);
            Assert.True(highLossReport.RetransmissionRatio > 0);
            Assert.True(highLossReport.RetransmissionRatio < 0.45d);

            await client.CloseAsync();
            server.Stop();
        }

        [Fact]
        public async Task Integration_LongFatPipe_ReportsGoodThroughput()
        {
            const int bandwidth = 100000000 / 8;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 50, bandwidthBytesPerSecond: bandwidth);
            UcpConfiguration config = CreateScenarioConfig(bandwidth);
            config.MinRtoMicros = 1000000;
            config.InitialCwndBytes = (uint)(bandwidth / 5);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), config.Clone());
            server.Start(40005);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, config, null);

            Task<UcpConnection> acceptTask = server.AcceptAsync();
            await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40005));
            UcpConnection serverConnection = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('E', 16 * 1024 * 1024));
            byte[] received = new byte[payload.Length];
            DateTime start = DateTime.UtcNow;
            Task<bool> readTask = ReadWithinAsync(serverConnection, received, 0, received.Length, 15000);
            bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
            bool readOk = await readTask;
            await WaitForAckSettlementAsync(client, 1000);
            double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
            double throughput = simulator.LogicalThroughputBytesPerSecond > 0 ? simulator.LogicalThroughputBytesPerSecond : payload.Length / elapsedSeconds;
            double theoretical = bandwidth;

            _output.WriteLine("LongFatPipe throughput={0:F2} B/s, utilization={1:P2}", throughput, throughput / theoretical);
            UcpPerformanceReport longFatPipeReport = UcpPerformanceReport.FromConnection("LongFatPipe", client, throughput, (long)(elapsedSeconds * 1000d), bandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros);
            UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, longFatPipeReport);

            Assert.True(writeOk);
            Assert.True(readOk);
            Assert.True(payload.SequenceEqual(received));
                Assert.True(longFatPipeReport.RetransmissionRatio <= 0.05d);
                Assert.InRange(longFatPipeReport.PacingRateBytesPerSecond, bandwidth * 0.70d, bandwidth * 1.30d);
                Assert.True(longFatPipeReport.CongestionWindowBytes >= bandwidth / 5);
                Assert.True(longFatPipeReport.UtilizationPercent >= 65d);

            await client.CloseAsync();
            server.Stop();
        }

        [Fact]
        public async Task Integration_Rst_ClosesPeerImmediately()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 2);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40006);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40006));
                UcpConnection serverConnection = await acceptTask;

                TaskCompletionSource<bool> disconnected = new TaskCompletionSource<bool>();
                client.OnDisconnected += delegate { disconnected.TrySetResult(true); };

                serverConnection.AbortForTest(true);

                bool observed = await UcpTestHelpers.WithTimeout(disconnected.Task, 3000);
                Assert.True(observed);
                Assert.Equal(UcpConnectionState.Closed, client.GetDiagnostics().State);
                Assert.True(client.GetDiagnostics().ReceivedReset);
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_PeerTimeout_IsDetected()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 2);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40007);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40007));
                UcpConnection serverConnection = await acceptTask;

                TaskCompletionSource<bool> disconnected = new TaskCompletionSource<bool>();
                client.OnDisconnected += delegate { disconnected.TrySetResult(true); };

                serverConnection.Dispose();
                bool observed = await UcpTestHelpers.WithTimeout(disconnected.Task, 7000);

                Assert.True(observed);
                Assert.Equal(UcpConnectionState.Closed, client.GetDiagnostics().State);
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_SequenceWrapAround_StillTransfersCorrectly()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1024 * 1024);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            client.SetNextSendSequenceForTest(uint.MaxValue - 8);
            server.Start(40008);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40008));
                UcpConnection serverConnection = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('W', 16 * 1024));
                byte[] received = new byte[payload.Length];

                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 8000);
                UcpConnectionDiagnostics clientDiag = client.GetDiagnostics();
                UcpConnectionDiagnostics serverDiag = serverConnection.GetDiagnostics();

                _output.WriteLine("Wrap client state={0}, inflight={1}, sent={2}, retrans={3}, rtt={4}", clientDiag.State, clientDiag.FlightBytes, clientDiag.SentDataPackets, clientDiag.RetransmittedPackets, clientDiag.LastRttMicros);
                _output.WriteLine("Wrap server state={0}, buffered={1}, ack={2}, nak={3}", serverDiag.State, serverDiag.BufferedReceiveBytes, serverDiag.SentAckPackets, serverDiag.SentNakPackets);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));

                await client.CloseAsync();
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_ReceiverWindow_SlowsSenderWithoutFailure()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: 512 * 1024);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40009);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40009));
                UcpConnection serverConnection = await acceptTask;

                serverConnection.SetAdvertisedReceiveWindowForTest((uint)(2 * UcpConstants.Mss));
                byte[] payload = Encoding.ASCII.GetBytes(new string('R', 32 * 1024));
                byte[] received = new byte[payload.Length];
                DateTime start = DateTime.UtcNow;
                Task<bool> writeTask = client.WriteAsync(payload, 0, payload.Length);
                await WaitForBufferedReceiveBytesAsync(serverConnection, 2 * UcpConstants.Mss, 2000);
                serverConnection.SetAdvertisedReceiveWindowForTest(new UcpConfiguration().ReceiveWindowBytes);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 12000);
                bool writeOk = await writeTask;
                double elapsedMs = (DateTime.UtcNow - start).TotalMilliseconds;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(elapsedMs > 50);

                await client.CloseAsync();
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_Pacing_RespectsConfiguredRate()
        {
            const int bandwidth = 128 * 1024;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bandwidth);
            UcpConfiguration pacingConfig = CreateScenarioConfig(bandwidth);
            pacingConfig.DrainPacingGain = 1.0d;
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), pacingConfig);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40010);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40010));
                UcpConnection serverConnection = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('P', 64 * 1024));
                byte[] received = new byte[payload.Length];
                DateTime start = DateTime.UtcNow;
                bool writeOk = await serverConnection.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(client, received, 0, received.Length, 12000);
                await WaitForAckSettlementAsync(serverConnection, 1000);
                double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
                double throughput = simulator.LogicalThroughputBytesPerSecond > 0 ? simulator.LogicalThroughputBytesPerSecond : payload.Length / elapsedSeconds;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(throughput <= bandwidth * 1.5d);
                UcpPerformanceReport pacingReport = UcpPerformanceReport.FromConnection("Pacing", serverConnection, throughput, (long)(elapsedSeconds * 1000d), bandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros);
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, pacingReport);
                Assert.InRange(pacingReport.PacingRateBytesPerSecond, bandwidth * 0.70d, bandwidth * 1.30d);
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_ReorderingAndDuplication_StillDeliversExactlyOnce()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 4, jitterMilliseconds: 2, bandwidthBytesPerSecond: 2 * 1024 * 1024, duplicateRate: 0.05, reorderRate: 0.2);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40011);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40011));
                UcpConnection serverConnection = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('Q', 96 * 1024));
                byte[] received = new byte[payload.Length];
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 15000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(simulator.ReorderedPackets > 0);
                Assert.True(simulator.DuplicatedPackets > 0);
                Assert.Equal(payload.Length, serverConnection.GetReport().BytesReceived);
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_OrderedSmallSegments_AreDeliveredImmediately()
        {
            int mss = UcpConstants.MSS;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 1, jitterMilliseconds: 0, bandwidthBytesPerSecond: mss * 10 * 8, dynamicJitterRangeMilliseconds: 0, dynamicWaveAmplitudeMilliseconds: 0);
            UcpConfiguration immediateConfig = UcpConfiguration.GetOptimizedConfig();
            immediateConfig.DelayedAckTimeoutMicros = 0;
            immediateConfig.MinPacingIntervalMicros = 0;
            immediateConfig.InitialBandwidthBytesPerSecond = mss * 10 * 8;
            immediateConfig.MaxPacingRateBytesPerSecond = mss * 10 * 8;
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), immediateConfig);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, immediateConfig, null);
            server.Start(40014);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40014));
                UcpConnection serverConnection = await acceptTask;
                List<double> deliveryDelays = new List<double>();
                Queue<DateTime> sendTimes = new Queue<DateTime>();
                TaskCompletionSource<bool> receivedAll = new TaskCompletionSource<bool>();
                int receivedCount = 0;
                serverConnection.OnData += delegate (byte[] buffer, int offset, int count)
                {
                    DateTime sentAt;
                    lock (sendTimes)
                    {
                        sentAt = sendTimes.Count == 0 ? DateTime.UtcNow : sendTimes.Dequeue();
                    }

                    deliveryDelays.Add((DateTime.UtcNow - sentAt).TotalMilliseconds - 1d);
                    receivedCount++;
                    if (receivedCount == 16)
                    {
                        receivedAll.TrySetResult(true);
                    }
                };

                for (int i = 0; i < 8; i++)
                {
                    byte[] payload = Encoding.ASCII.GetBytes("W" + i.ToString("D2"));
                    bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                    Assert.True(writeOk);
                }

                await Task.Delay(20);

                for (int i = 0; i < 8; i++)
                {
                    byte[] payload = Encoding.ASCII.GetBytes("M" + i.ToString("D2"));
                    lock (sendTimes)
                    {
                        sendTimes.Enqueue(DateTime.UtcNow);
                    }

                    bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                    Assert.True(writeOk);
                    await Task.Delay(2);
                }

                Task completed = await Task.WhenAny(receivedAll.Task, Task.Delay(2000));
                Assert.Equal(receivedAll.Task, completed);
                double maxDelay = 0d;
                for (int i = 0; i < deliveryDelays.Count; i++)
                {
                    if (deliveryDelays[i] > maxDelay)
                    {
                        maxDelay = deliveryDelays[i];
                    }
                }

                Assert.True(maxDelay < 60d, "max ordered delivery delay was " + maxDelay.ToString("F2") + "ms");
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task Integration_GigabitIdeal_ReportsHighUtilization()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Gigabit_Ideal",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_GIGABIT_IDEAL,
                UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_1G_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_1G_IDEAL_DELAY_MILLISECONDS,
                0,
                0d,
                0,
                false,
                0,
                null);

            Assert.True(report.UtilizationPercent >= UcpConstants.BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT);
            Assert.True(report.EstimatedLossPercent <= UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        [Fact]
        public async Task Integration_GigabitLossRandom5_RespectsLossBudget()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Gigabit_Loss5",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_GIGABIT_LOSS5,
                UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_1G_LOSS_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_1G_HEAVY_LOSS_DELAY_MILLISECONDS,
                0,
                UcpConstants.BENCHMARK_HEAVY_RANDOM_LOSS_RATE,
                UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                UcpConstants.BENCHMARK_HEAVY_RANDOM_LOSS_SEED,
                CreateInitialDataDropRule(UcpConstants.BENCHMARK_HEAVY_RANDOM_LOSS_RATE, UcpConstants.BENCHMARK_HEAVY_RANDOM_LOSS_SEED));

            _output.WriteLine("Gigabit_Loss5 estimatedLoss={0:F2}, retransmission={1:F2}, utilization={2:F2}", report.EstimatedLossPercent, report.RetransmissionPercent, report.UtilizationPercent);
            Assert.True(report.EstimatedLossPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.RetransmissionPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.ThroughputMbps >= UcpConstants.BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS);
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
            Assert.True(report.JitterMilliseconds <= UcpConstants.BENCHMARK_1G_HEAVY_LOSS_DELAY_MILLISECONDS * UcpConstants.BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER);
        }

        [Fact]
        public async Task Integration_GigabitLossRandom1_KeepsHighUtilization()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Gigabit_Loss1",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_GIGABIT_LOSS1,
                UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_1G_LOSS_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_1G_LIGHT_LOSS_DELAY_MILLISECONDS,
                0,
                UcpConstants.BENCHMARK_LIGHT_RANDOM_LOSS_RATE,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                UcpConstants.BENCHMARK_LIGHT_RANDOM_LOSS_SEED,
                CreateInitialDataDropRule(UcpConstants.BENCHMARK_LIGHT_RANDOM_LOSS_RATE, UcpConstants.BENCHMARK_LIGHT_RANDOM_LOSS_SEED));

            Assert.True(report.EstimatedLossPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.RetransmissionPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
        }

        [Fact]
        public async Task Integration_LongFatPipe100M_ConvergesAndKeepsLowJitter()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "LongFat_100M",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_LONG_FAT_100M,
                UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_LONG_FAT_DELAY_MILLISECONDS,
                UcpConstants.BENCHMARK_LONG_FAT_JITTER_MILLISECONDS,
                0d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                0,
                null);

            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
            Assert.True(report.RetransmissionPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.ConvergenceMilliseconds > 0);
            Assert.True(report.JitterMilliseconds <= UcpConstants.BENCHMARK_LONG_FAT_DELAY_MILLISECONDS * UcpConstants.BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER);
        }

        [Fact]
        public async Task Integration_TenGigabitProbe_ConvergesWithoutConfiguredRateCap()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Benchmark10G",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_10G,
                UcpConstants.BENCHMARK_10_GBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_10G_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_10G_DELAY_MILLISECONDS,
                0,
                0d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                0,
                null);

            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_10_GBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
            Assert.True(report.RetransmissionPercent <= UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        [Fact]
        public async Task Integration_BurstLoss_RecoversWithinBudget()
        {
            int dataPacketIndex = 0;
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "BurstLoss",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_BURST_LOSS,
                UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_BURST_LOSS_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_BURST_LOSS_DELAY_MILLISECONDS,
                UcpConstants.BENCHMARK_BURST_LOSS_JITTER_MILLISECONDS,
                0d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                0,
                delegate (NetworkSimulator.SimulatedDatagram datagram)
                {
                    UcpPacket packet;
                    if (!UcpPacketCodec.TryDecode(datagram.Buffer, 0, datagram.Count, out packet) || packet.Header.Type != UcpPacketType.Data)
                    {
                        return false;
                    }

                    dataPacketIndex++;
                    return dataPacketIndex >= UcpConstants.BENCHMARK_BURST_LOSS_FIRST_PACKET && dataPacketIndex < UcpConstants.BENCHMARK_BURST_LOSS_FIRST_PACKET + UcpConstants.BENCHMARK_BURST_LOSS_PACKET_COUNT;
                });

            Assert.True(dataPacketIndex >= UcpConstants.BENCHMARK_BURST_LOSS_FIRST_PACKET + UcpConstants.BENCHMARK_BURST_LOSS_PACKET_COUNT);
            Assert.True(report.EstimatedLossPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.RetransmissionPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
        }

        [Fact]
        public async Task Integration_AsymmetricRoute_HandlesWell()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "AsymRoute",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_ASYM_ROUTE,
                UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_ASYM_PAYLOAD_BYTES,
                0,
                0,
                UcpConstants.BENCHMARK_ASYM_RANDOM_LOSS_RATE,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                UcpConstants.BENCHMARK_ASYM_RANDOM_LOSS_SEED,
                CreateInitialDataDropRule(UcpConstants.BENCHMARK_ASYM_RANDOM_LOSS_RATE, UcpConstants.BENCHMARK_ASYM_RANDOM_LOSS_SEED),
                UcpConstants.BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS,
                UcpConstants.BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS,
                UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS,
                UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS);

            Assert.True(report.ForwardDelayMilliseconds >= UcpConstants.BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS - UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS);
            Assert.True(report.ReverseDelayMilliseconds <= UcpConstants.BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS + UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS);
            Assert.True(report.RetransmissionPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
        }

        [Fact]
        public async Task Integration_HighJitter_StaysAliveAndUseful()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "HighJitter",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_HIGH_JITTER,
                UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_HIGH_JITTER_DELAY_MILLISECONDS,
                UcpConstants.BENCHMARK_HIGH_JITTER_JITTER_MILLISECONDS,
                0d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                UcpConstants.BENCHMARK_HIGH_JITTER_LOSS_SEED,
                null,
                -1,
                -1,
                -1,
                -1,
                true);

            Assert.True(report.UtilizationPercent > 40d);
            Assert.True(report.RetransmissionPercent <= UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        [Fact]
        public void FecCodec_RecoversSingleLoss()
        {
            UcpFecCodec enc = new UcpFecCodec(4);
            byte[] p0 = Encoding.ASCII.GetBytes("AAA");
            byte[] p1 = Encoding.ASCII.GetBytes("BBB");
            byte[] p2 = Encoding.ASCII.GetBytes("CCC");
            byte[] p3 = Encoding.ASCII.GetBytes("DDD");

            Assert.Null(enc.TryEncodeRepair(p0));
            Assert.Null(enc.TryEncodeRepair(p1));
            Assert.Null(enc.TryEncodeRepair(p2));
            byte[] repair = enc.TryEncodeRepair(p3);
            Assert.NotNull(repair);

            UcpFecCodec dec = new UcpFecCodec(4);
            dec.FeedDataPacket(0, p0);
            dec.FeedDataPacket(2, p2);
            dec.FeedDataPacket(3, p3);

            byte[] recovered = dec.TryRecoverFromRepair(repair, 0);
            Assert.NotNull(recovered);
            Assert.Equal(p1, recovered);
        }

        [Fact]
        public async Task Integration_Weak4G_RecoversFromOutage()
        {
            Func<NetworkSimulator.SimulatedDatagram, bool> outageDropRule = CreateWeak4GDropRule(
                UcpConstants.BENCHMARK_WEAK_4G_LOSS_RATE,
                UcpConstants.BENCHMARK_WEAK_4G_LOSS_SEED,
                UcpConstants.BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS,
                UcpConstants.BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS);
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Weak4G",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_WEAK_4G,
                10 * 1000 * 1000 / 8,
                UcpConstants.BENCHMARK_WEAK_4G_PAYLOAD_BYTES,
                UcpConstants.BENCHMARK_WEAK_4G_DELAY_MILLISECONDS,
                0,
                UcpConstants.BENCHMARK_WEAK_4G_LOSS_RATE,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                UcpConstants.BENCHMARK_WEAK_4G_LOSS_SEED,
                outageDropRule,
                -1,
                -1,
                -1,
                -1,
                true);

            Assert.True(report.UtilizationPercent > 25d);
            Assert.True(report.ElapsedMilliseconds < UcpConstants.BENCHMARK_READ_TIMEOUT_MILLISECONDS);
        }

        [Theory]
        [InlineData(100000000 / 8, 0.002d, "100M_Loss0.2")]
        [InlineData(100000000 / 8, 0.01d, "100M_Loss1")]
        [InlineData(100000000 / 8, 0.10d, "100M_Loss10")]
        [InlineData(1000000000 / 8, 0.03d, "1G_Loss3")]
        public async Task Integration_CoverageLossBandwidth(int bandwidthBytesPerSecond, double lossRate, string scenarioName)
        {
            int payloadBytes = bandwidthBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND ? UcpConstants.BENCHMARK_1G_LOSS_PAYLOAD_BYTES : 2 * 1024 * 1024;
            int seed = 20260506 + (int)(lossRate * 1000d);
            bool autoProbe = bandwidthBytesPerSecond >= UcpConstants.BENCHMARK_10_GBPS_BYTES_PER_SECOND;
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                scenarioName,
                UcpConstants.BENCHMARK_BASE_PORT + 13 + (int)(lossRate * 100d),
                bandwidthBytesPerSecond,
                payloadBytes,
                bandwidthBytesPerSecond > UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND ? 20 : 10,
                4,
                lossRate,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                autoProbe,
                seed,
                CreateInitialDataDropRule(lossRate, seed));

            Assert.True(report.ThroughputBytesPerSecond > 0);
            Assert.True(report.UtilizationPercent > 0);
            Assert.True(report.RetransmissionPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        [Fact]
        public async Task Integration_Mobile3G_LossyConnects()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Mobile3G",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_MOBILE_3G,
                4 * 1000 * 1000 / 8,
                512 * 1024,
                75,
                30,
                0.03d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260601,
                CreateInitialDataDropRule(0.03d, 20260601));

            Assert.True(report.UtilizationPercent > 25d);
        }

        [Fact]
        public async Task Integration_Mobile4G_HighJitter()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Mobile4G",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_MOBILE_4G,
                20 * 1000 * 1000 / 8,
                2 * 1024 * 1024,
                30,
                25,
                0.01d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260602,
                CreateInitialDataDropRule(0.01d, 20260602));

            Assert.True(report.UtilizationPercent > 40d);
        }

        [Fact]
        public async Task Integration_Satellite300ms_Completes()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Satellite",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_SATELLITE,
                10 * 1000 * 1000 / 8,
                4 * 1024 * 1024,
                150,
                5,
                0.001d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260603,
                CreateInitialDataDropRule(0.001d, 20260603),
                -1,
                -1,
                -1,
                -1,
                false,
                0,
                0);

            Assert.True(report.UtilizationPercent > 25d);
        }

        [Fact]
        public async Task Integration_VpnDualCongestion_LongRtt()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "VpnTunnel",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_VPN,
                UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND,
                4 * 1024 * 1024,
                50,
                10,
                0.005d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260604,
                CreateInitialDataDropRule(0.005d, 20260604));

            Assert.True(report.UtilizationPercent > 15d);
        }

        [Fact]
        public async Task SendAsync_MayReturnPartialWhenSendBufferIsFull()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.SendBufferSize = UcpConstants.Mss * 4;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 20, bandwidthBytesPerSecond: 64 * 1024);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), config);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40012);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40012));
                UcpConnection serverConnection = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('S', 64 * 1024));

                int sent = await serverConnection.SendAsync(payload, 0, payload.Length);

                Assert.InRange(sent, 1, payload.Length - 1);
            }
            finally
            {
                server.Stop();
            }
        }

        [Fact]
        public async Task SendAsync_ReturnsZeroWhenSendBufferAlreadyFull()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.SendBufferSize = UcpConstants.Mss * 2;
            config.MaxPacingRateBytesPerSecond = 1;
            config.InitialBandwidthBytesPerSecond = 1;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 100, bandwidthBytesPerSecond: 64 * 1024);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), config);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40013);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40013));
                UcpConnection serverConnection = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('Z', 64 * 1024));

                int first = await serverConnection.SendAsync(payload, 0, payload.Length);
                int second = await serverConnection.SendAsync(payload, first, payload.Length - first);

                Assert.True(first > 0);
                Assert.Equal(0, second);
            }
            finally
            {
                server.Stop();
            }
        }

        private static async Task<bool> ReadWithinAsync(UcpConnection connection, byte[] buffer, int offset, int count, int timeoutMilliseconds)
        {
            Task<bool> readTask = connection.ReadAsync(buffer, offset, count);
            Task completed = await Task.WhenAny(readTask, Task.Delay(timeoutMilliseconds));
            if (completed != readTask)
            {
                return false;
            }

            return await readTask;
        }

        private static async Task<double> MeasureReadDurationAsync(Task<bool> readTask, DateTime start)
        {
            await readTask;
            return (DateTime.UtcNow - start).TotalMilliseconds;
        }

        private static async Task WaitForAckSettlementAsync(UcpConnection connection, int timeoutMilliseconds)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
            while (DateTime.UtcNow < deadline)
            {
                UcpTransferReport report = connection.GetReport();
                if (report.DataPacketsSent > 0 && report.RttSamplesMicros.Count > 0)
                {
                    return;
                }

                await Task.Delay(1);
            }
        }

        private static async Task WaitForBufferedReceiveBytesAsync(UcpConnection connection, int minimumBytes, int timeoutMilliseconds)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
            while (DateTime.UtcNow < deadline)
            {
                if (connection.GetDiagnostics().BufferedReceiveBytes >= minimumBytes)
                {
                    return;
                }

                await Task.Delay(1);
            }
        }

        private async Task<UcpPerformanceReport> RunLineRateBenchmarkAsync(string scenarioName, int port, int bandwidthBytesPerSecond, int payloadBytes, int fixedDelayMilliseconds, int jitterMilliseconds, double lossRate, double maxLossPercent, bool autoProbe, int simulatorSeed, Func<NetworkSimulator.SimulatedDatagram, bool>? dropRule)
        {
            return await RunLineRateBenchmarkAsync(scenarioName, port, bandwidthBytesPerSecond, payloadBytes, fixedDelayMilliseconds, jitterMilliseconds, lossRate, maxLossPercent, autoProbe, simulatorSeed, dropRule, -1, -1, -1, -1).ConfigureAwait(false);
        }

        private async Task<UcpPerformanceReport> RunLineRateBenchmarkAsync(string scenarioName, int port, int bandwidthBytesPerSecond, int payloadBytes, int fixedDelayMilliseconds, int jitterMilliseconds, double lossRate, double maxLossPercent, bool autoProbe, int simulatorSeed, Func<NetworkSimulator.SimulatedDatagram, bool>? dropRule, int forwardDelayMilliseconds, int backwardDelayMilliseconds, int forwardJitterMilliseconds, int backwardJitterMilliseconds)
        {
            return await RunLineRateBenchmarkAsync(scenarioName, port, bandwidthBytesPerSecond, payloadBytes, fixedDelayMilliseconds, jitterMilliseconds, lossRate, maxLossPercent, autoProbe, simulatorSeed, dropRule, forwardDelayMilliseconds, backwardDelayMilliseconds, forwardJitterMilliseconds, backwardJitterMilliseconds, false).ConfigureAwait(false);
        }

        private async Task<UcpPerformanceReport> RunLineRateBenchmarkAsync(string scenarioName, int port, int bandwidthBytesPerSecond, int payloadBytes, int fixedDelayMilliseconds, int jitterMilliseconds, double lossRate, double maxLossPercent, bool autoProbe, int simulatorSeed, Func<NetworkSimulator.SimulatedDatagram, bool>? dropRule, int forwardDelayMilliseconds, int backwardDelayMilliseconds, int forwardJitterMilliseconds, int backwardJitterMilliseconds, bool useHighBandwidthMss, int dynamicJitterRangeMs = -1, int dynamicWaveAmpMs = -1)
        {
            NetworkSimulator simulator = new NetworkSimulator(lossRate: dropRule == null ? lossRate : 0d, fixedDelayMilliseconds: fixedDelayMilliseconds, jitterMilliseconds: jitterMilliseconds, bandwidthBytesPerSecond: bandwidthBytesPerSecond, seed: simulatorSeed == 0 ? 1234 : simulatorSeed, dropRule: dropRule, forwardDelayMilliseconds: forwardDelayMilliseconds, backwardDelayMilliseconds: backwardDelayMilliseconds, forwardJitterMilliseconds: forwardJitterMilliseconds, backwardJitterMilliseconds: backwardJitterMilliseconds, dynamicJitterRangeMilliseconds: dynamicJitterRangeMs >= 0 ? dynamicJitterRangeMs : 1, dynamicWaveAmplitudeMilliseconds: dynamicWaveAmpMs >= 0 ? dynamicWaveAmpMs : 5);
            UcpConfiguration config = CreateScenarioConfig(bandwidthBytesPerSecond);
            bool hasConfiguredLoss = lossRate > 0 || dropRule != null;
            if (useHighBandwidthMss || bandwidthBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND)
            {
                config.Mss = UcpConstants.BENCHMARK_HIGH_BANDWIDTH_MSS;
                config.SendQuantumBytes = config.Mss;
            }

            config.EnableAggressiveSackRecovery = bandwidthBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND && hasConfiguredLoss;

            config.MaxBandwidthLossPercent = maxLossPercent <= 0 ? UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT : maxLossPercent;
            int effectiveForwardDelayMilliseconds = forwardDelayMilliseconds >= 0 ? forwardDelayMilliseconds : fixedDelayMilliseconds;
            int effectiveBackwardDelayMilliseconds = backwardDelayMilliseconds >= 0 ? backwardDelayMilliseconds : fixedDelayMilliseconds;
            int estimatedRttMicros = (int)Math.Max(UcpConstants.MICROS_PER_MILLI, (effectiveForwardDelayMilliseconds + effectiveBackwardDelayMilliseconds) * UcpConstants.MICROS_PER_MILLI);
            int estimatedBdpBytes = (int)Math.Min(int.MaxValue, bandwidthBytesPerSecond * (estimatedRttMicros / (double)UcpConstants.MICROS_PER_SECOND));
            int initialCwndBytes = CalculateBenchmarkInitialCwndBytes(config, bandwidthBytesPerSecond, estimatedBdpBytes, hasConfiguredLoss);
            config.InitialCwndBytes = (uint)initialCwndBytes;
            if (fixedDelayMilliseconds >= UcpConstants.BENCHMARK_LONG_FAT_DELAY_MILLISECONDS || estimatedRttMicros >= UcpConstants.DEFAULT_RTO_MICROS)
            {
                config.MinRtoMicros = UcpConstants.BENCHMARK_LONG_FAT_MIN_RTO_MICROS;
            }

            if (autoProbe)
            {
                config.InitialBandwidthBytesPerSecond = Math.Max(UcpConstants.BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND, initialCwndBytes * UcpConstants.BBR_PROBE_BW_GAIN_COUNT);
                config.MaxPacingRateBytesPerSecond = 0;
            }

            UcpServer server = new UcpServer(simulator.CreateTransport("server"), config.Clone());
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, config.Clone(), null);
            server.Start(port);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
                UcpConnection serverConnection = await acceptTask;
                byte[] payload = BuildPayload((char)('A' + (port % 26)), payloadBytes);
                byte[] received = new byte[payload.Length];
                DateTime start = DateTime.UtcNow;
                Task<bool> readTask = ReadWithinAsync(serverConnection, received, 0, received.Length, UcpConstants.BENCHMARK_READ_TIMEOUT_MILLISECONDS);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;
                await WaitForAckSettlementAsync(client, UcpConstants.BENCHMARK_ACK_SETTLEMENT_TIMEOUT_MILLISECONDS);
                double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
                double throughput = simulator.LogicalThroughputBytesPerSecond > 0 ? simulator.LogicalThroughputBytesPerSecond : payload.Length / elapsedSeconds;
                UcpPerformanceReport report = UcpPerformanceReport.FromConnection(scenarioName, client, throughput, (long)(elapsedSeconds * UcpConstants.MICROS_PER_MILLI), bandwidthBytesPerSecond, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros);
                UcpTransferReport receiverReport = serverConnection.GetReport();
                report.ConvergenceMilliseconds = EstimateConvergenceMilliseconds(report, bandwidthBytesPerSecond, elapsedSeconds);
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, report);

                _output.WriteLine("{0} throughput={1:F2}Mbps target={2:F2}Mbps util={3:F2}% pacing={4:F2}Mbps cwnd={5} loss={6:F2}% retrans={7:F2}% avgRtt={8:F2}ms jitter={9:F2}ms convergence={10}ms elapsed={11}ms dropped={12}",
                    scenarioName,
                    report.ThroughputMbps,
                    report.TargetMbps,
                    report.UtilizationPercent,
                    report.PacingMbps,
                    report.CongestionWindowBytes,
                    report.EstimatedLossPercent,
                    report.RetransmissionPercent,
                    report.AverageRttMilliseconds,
                    report.JitterMilliseconds,
                    report.ConvergenceMilliseconds,
                    report.ElapsedMilliseconds,
                    simulator.DroppedPackets);
                _output.WriteLine("{0} packets data={1} retrans={2} ack={3} nak={4} fast={5} timeout={6}",
                    scenarioName,
                    report.DataPacketsSent,
                    report.RetransmittedPackets,
                    report.AckPacketsSent,
                    report.NakPacketsSent,
                    report.FastRetransmissions,
                    report.TimeoutRetransmissions);
                _output.WriteLine("{0} receiver ack={1} nak={2} bytes={3} rttSamples={4}",
                    scenarioName,
                    receiverReport.AckPacketsSent,
                    receiverReport.NakPacketsSent,
                    receiverReport.BytesReceived,
                    receiverReport.RttSamplesMicros.Count);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(report.ThroughputBytesPerSecond > 0);
                if (!autoProbe)
                {
                    Assert.InRange(report.PacingRateBytesPerSecond, bandwidthBytesPerSecond * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO, bandwidthBytesPerSecond * UcpConstants.BENCHMARK_MAX_CONVERGED_PACING_RATIO);
                }

                return report;
            }
            finally
            {
                await client.CloseAsync();
                server.Stop();
            }
        }

        private static int CalculateBenchmarkInitialCwndBytes(UcpConfiguration config, int bandwidthBytesPerSecond, int estimatedBdpBytes, bool hasConfiguredLoss)
        {
            int minimumCwndBytes = config.Mss * UcpConstants.INITIAL_CWND_PACKETS;
            if (hasConfiguredLoss)
            {
                int lossCwndBytes = Math.Max(minimumCwndBytes, (int)Math.Ceiling(estimatedBdpBytes * UcpConstants.BENCHMARK_LOSS_INITIAL_CWND_BDP_GAIN));
                return Math.Min(lossCwndBytes, UcpConstants.BENCHMARK_MAX_LOSS_INITIAL_CWND_BYTES);
            }

            int bdpCwndBytes = Math.Max(minimumCwndBytes, (int)Math.Ceiling(estimatedBdpBytes * UcpConstants.BENCHMARK_INITIAL_CWND_BDP_GAIN));
            return Math.Max(bdpCwndBytes, bandwidthBytesPerSecond / UcpConstants.BENCHMARK_NO_LOSS_INITIAL_CWND_BANDWIDTH_DIVISOR);
        }

        private static Func<NetworkSimulator.SimulatedDatagram, bool> CreateInitialDataDropRule(double lossRate, int seed)
        {
            Random random = new Random(seed);
            return delegate (NetworkSimulator.SimulatedDatagram datagram)
            {
                UcpPacket packet;
                if (!UcpPacketCodec.TryDecode(datagram.Buffer, 0, datagram.Count, out packet))
                {
                    return false;
                }

                bool isInitialData = packet.Header.Type == UcpPacketType.Data && (packet.Header.Flags & UcpPacketFlags.Retransmit) != UcpPacketFlags.Retransmit;
                return isInitialData && random.NextDouble() < lossRate;
            };
        }

        private static Func<NetworkSimulator.SimulatedDatagram, bool> CreateWeak4GDropRule(double lossRate, int seed, int outagePeriodMilliseconds, int outageDurationMilliseconds)
        {
            Random random = new Random(seed);
            long firstDataMicros = 0;
            return delegate (NetworkSimulator.SimulatedDatagram datagram)
            {
                UcpPacket packet;
                if (!UcpPacketCodec.TryDecode(datagram.Buffer, 0, datagram.Count, out packet) || packet.Header.Type != UcpPacketType.Data)
                {
                    return false;
                }

                if (firstDataMicros == 0)
                {
                    firstDataMicros = datagram.SendMicros;
                }

                long elapsedMicros = datagram.SendMicros - firstDataMicros;
                long periodMicros = outagePeriodMilliseconds * UcpConstants.MICROS_PER_MILLI;
                long outageMicros = outageDurationMilliseconds * UcpConstants.MICROS_PER_MILLI;
                bool inOutage = periodMicros > 0 && elapsedMicros > 0 && elapsedMicros % periodMicros < outageMicros;
                bool isInitialData = (packet.Header.Flags & UcpPacketFlags.Retransmit) != UcpPacketFlags.Retransmit;
                return inOutage || (isInitialData && random.NextDouble() < lossRate);
            };
        }

        private static byte[] BuildPayload(char value, int payloadBytes)
        {
            byte[] payload = new byte[payloadBytes];
            for (int i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)value;
            }

            return payload;
        }

        private static long EstimateConvergenceMilliseconds(UcpPerformanceReport report, int bandwidthBytesPerSecond, double elapsedSeconds)
        {
            if (report.PacingRateBytesPerSecond < bandwidthBytesPerSecond * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO)
            {
                return 0;
            }

            double ratio = report.PacingRateBytesPerSecond <= 0 ? 1d : Math.Min(1d, bandwidthBytesPerSecond / report.PacingRateBytesPerSecond);
            return (long)Math.Ceiling(elapsedSeconds * ratio * UcpConstants.MICROS_PER_MILLI);
        }

        private static string JoinDoubles(double[] values)
        {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < values.Length; i++)
            {
                if (i > 0)
                {
                    builder.Append(", ");
                }

                builder.Append(values[i].ToString("F2"));
            }

            return builder.ToString();
        }

        private static UcpConfiguration CreateScenarioConfig(int bandwidthBytesPerSecond)
        {
            UcpConfiguration config = UcpConfiguration.GetOptimizedConfig();
            config.InitialBandwidthBytesPerSecond = bandwidthBytesPerSecond;
            config.MaxPacingRateBytesPerSecond = bandwidthBytesPerSecond;
            config.ServerBandwidthBytesPerSecond = bandwidthBytesPerSecond;
            return config;
        }
    }
}
