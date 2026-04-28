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
        public void RtoEstimator_UsesOnePointFiveBackoff()
        {
            UcpRtoEstimator estimator = new UcpRtoEstimator();
            estimator.Update(100000);
            long first = estimator.CurrentRtoMicros;

            estimator.Backoff();

            Assert.Equal((long)(first * 1.5d), estimator.CurrentRtoMicros);
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
        public void BbrController_BandwidthEstimateCanDecay()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1;
            config.MaxPacingRateBytesPerSecond = 0;
            config.BbrWindowRtRounds = 2;
            BbrCongestionControl bbr = new BbrCongestionControl(config);

            bbr.OnAck(100000, 100000, 100000, 100000);
            double highRate = bbr.BtlBwBytesPerSecond;
            bbr.OnAck(500000, 1000, 100000, 1000);

            Assert.True(highRate > 100000);
            Assert.True(bbr.BtlBwBytesPerSecond < highRate);
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
                double throughput = simulator.LogicalThroughputBytesPerSecond > 0 ? simulator.LogicalThroughputBytesPerSecond : payload.Length / elapsedSeconds;
                UcpPerformanceReport noLossReport = UcpPerformanceReport.FromConnection("NoLoss", client, throughput, (long)(elapsedSeconds * 1000d), noLossBandwidth);
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
                UcpPerformanceReport lossyReport = UcpPerformanceReport.FromConnection("Lossy", client, payload.Length / elapsedSeconds, (long)(elapsedSeconds * 1000d), lossyBandwidth);
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
            UcpPerformanceReport highLossReport = UcpPerformanceReport.FromConnection("HighLossHighRtt", client, throughput, (long)((DateTime.UtcNow - start).TotalMilliseconds), highLossBandwidth);
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
            UcpPerformanceReport longFatPipeReport = UcpPerformanceReport.FromConnection("LongFatPipe", client, throughput, (long)(elapsedSeconds * 1000d), bandwidth);
            UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, longFatPipeReport);

            Assert.True(writeOk);
            Assert.True(readOk);
            Assert.True(payload.SequenceEqual(received));
                Assert.True(longFatPipeReport.RetransmissionRatio <= 0.05d);
                Assert.InRange(longFatPipeReport.PacingRateBytesPerSecond, bandwidth * 0.70d, bandwidth * 1.30d);
                Assert.True(longFatPipeReport.CongestionWindowBytes >= bandwidth / 5);
                Assert.True(longFatPipeReport.UtilizationPercent >= 70d);

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
                UcpPerformanceReport pacingReport = UcpPerformanceReport.FromConnection("Pacing", serverConnection, throughput, (long)(elapsedSeconds * 1000d), bandwidth);
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
            UcpConfiguration config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = bandwidthBytesPerSecond;
            config.MaxPacingRateBytesPerSecond = bandwidthBytesPerSecond;
            config.ServerBandwidthBytesPerSecond = bandwidthBytesPerSecond;
            config.MinRtoMicros = 1000000;
            return config;
        }
    }
}
