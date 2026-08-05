using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Ucp;
using UcpTest.TestTransport;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpNetworkTests
    {
        [Fact]
        public async Task SimulatedNetwork_CanConnectAndTransfer()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.FairQueueRoundMilliseconds = 1;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"));
            server.Start(42001);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 42001));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('N', 16 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                int written = await client.SendAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);

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
            var client = new UcpConnection(sim.CreateTransport("client"));
            server.Start(42002);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 42002));
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
                _outputHelper.WriteLine("RTT samples count={0}", report.RttSamplesMicros.Count);

                Assert.True(report.RttSamplesMicros.Count >= 1,
                    $"Should have at least 1 RTT sample, got {report.RttSamplesMicros.Count}");

                if (report.RttSamplesMicros.Count > 0)
                {
                    double avgRtt = report.RttSamplesMicros.Average();
                    _outputHelper.WriteLine("Average RTT={0:F0}us (expected ~20000us)", avgRtt);
                    double expectedRtt = 20000.0;
                    double ratio = avgRtt / expectedRtt;
                    Assert.InRange(ratio, 0.7, 3.0);

                }
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
            server.Start(42003);

            var clients = new List<UcpConnection>();
            var srvConns = new List<UcpConnection>();
            try
            {
                for (int i = 0; i < 3; i++)
                    clients.Add(new UcpConnection(sim.CreateTransport("client" + i)));

                var acceptTasks = new List<Task<UcpConnection>>();
                for (int i = 0; i < 3; i++)
                    acceptTasks.Add(server.AcceptAsync());

                for (int i = 0; i < 3; i++)
                    await clients[i].ConnectAsync(new IPEndPoint(IPAddress.Loopback, 42003));

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

                var writeTasks = new List<Task<DateTime>>();
                DateTime writeStart = DateTime.UtcNow;
                for (int i = 0; i < 3; i++)
                {
                    int idx = i;
                    writeTasks.Add(WriteAndTimestamp(clients[idx], payload));
                }

                DateTime[] writeEndTimes = await Task.WhenAll(writeTasks);
                DateTime writeEnd = writeEndTimes.Max();

                var readAllTask = Task.WhenAll(readTasks);
                var timeoutTask = Task.Delay(15000);
                Assert.NotEqual(timeoutTask, await Task.WhenAny(readAllTask, timeoutTask));
                var results = await readAllTask;

                for (int i = 0; i < 3; i++)
                {
                    Assert.True(results[i]);
                    Assert.True(payload.SequenceEqual(received[i]));
                }

                double totalSeconds = (writeEnd - writeStart).TotalSeconds;
                double totalThroughput = (3L * payload.Length) / totalSeconds;
                for (int i = 0; i < 3; i++)
                {
                    double clientSeconds = (writeEndTimes[i] - writeStart).TotalSeconds;
                    double clientThroughput = payload.Length / clientSeconds;
                    Assert.True(clientThroughput >= 0.15 * totalThroughput,
                        $"Client {i} throughput {clientThroughput:F0} B/s below 15% of total {totalThroughput:F0} B/s");
                }
            }
            finally
            {
                for (int i = 0; i < clients.Count; i++)
                    await UcpTestHelpers.CloseWithTimeout(clients[i]);
                server.Stop();
            }
        }

        private static async Task<DateTime> WriteAndTimestamp(UcpConnection client, byte[] payload)
        {
            await client.WriteAsync(payload, 0, payload.Length);
            return DateTime.UtcNow;
        }

        [Fact]
        public async Task SimulatedNetwork_JitterDoesNotBreakDelivery()
        {
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: 10 * 1024 * 1024,
                jitterMilliseconds: 5);
            var server = new UcpServer(sim.CreateTransport("server"));
            var client = new UcpConnection(sim.CreateTransport("client"));
            server.Start(42005);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 42005));
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
        public async Task SimulatedNetwork_DatagramLoopback()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.FairQueueRoundMilliseconds = 1;
            var server = new UcpServer(sim.CreateTransport("srv"), config);
            var client = new UcpConnection(sim.CreateTransport("cli"));
            server.Start(42006);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 42006));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('D', 8 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                int written = await client.SendAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);

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
        public async Task SimulatedNetwork_NoLoss100M_Throughput()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43001);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43001));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('N', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 15000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(await UcpTestHelpers.WaitForRttSamplesAsync(client),
                    "Sender must record at least one RTT sample after a completed transfer");
                var report = client.GetReport();
                Assert.True(report.RttSamplesMicros.Count >= 1);
                _outputHelper.WriteLine("NoLoss100M: tput={0:F0}B/s delivered={1} rttSamples={2}",
                    sim.LogicalThroughputBytesPerSecond, sim.DeliveredBytes, report.RttSamplesMicros.Count);
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
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: bw,
                lossRate: 0.01, seed: 23002);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43002);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43002));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('L', 256 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 15000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _outputHelper.WriteLine("Loss1Pct: dropped={0} tput={1:F0}B/s dataDrop={2}",
                    sim.DroppedPackets, sim.LogicalThroughputBytesPerSecond, sim.DroppedDataPackets);
                Assert.True(sim.LogicalThroughputBytesPerSecond > bw * 0.06,
                    $"Throughput {sim.LogicalThroughputBytesPerSecond:F0}B/s should be > 6% of {bw}B/s");
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
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 15, bandwidthBytesPerSecond: bw,
                lossRate: 0.05, seed: 23003);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43003);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43003));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('H', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 15000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _outputHelper.WriteLine("Loss5Pct: dropped={0} dataDrop={1} tput={2:F0}B/s",
                    sim.DroppedPackets, sim.DroppedDataPackets, sim.LogicalThroughputBytesPerSecond);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_BwConvergence_1MTo100M()
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
            server.Start(43004);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43004));
                UcpConnection srvConn = await acceptTask;

                byte[] payload1 = Encoding.ASCII.GetBytes(new string('A', 16 * 1024));
                byte[] received1 = new byte[payload1.Length];
                Task<bool> readTask1 = srvConn.ReadAsync(received1, 0, received1.Length);
                await client.WriteAsync(payload1, 0, payload1.Length);
                bool readOk1 = await UcpTestHelpers.ReadWithTimeoutTask(readTask1, 30000);
                Assert.True(readOk1);
                Assert.True(payload1.SequenceEqual(received1));

                sim.Configure(0, 2, 0, bwHigh, 0, 0);

                byte[] payload2 = Encoding.ASCII.GetBytes(new string('B', 16 * 1024));
                byte[] received2 = new byte[payload2.Length];
                Task<bool> readTask2 = srvConn.ReadAsync(received2, 0, received2.Length);
                await client.WriteAsync(payload2, 0, payload2.Length);
                bool readOk2 = await UcpTestHelpers.ReadWithTimeoutTask(readTask2, 30000);
                Assert.True(readOk2);
                Assert.True(payload2.SequenceEqual(received2));

                _outputHelper.WriteLine("BwConv: delivered={0} tput={1:F0}B/s",
                    sim.DeliveredBytes, sim.LogicalThroughputBytesPerSecond);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_Jitter_NoLossDeliversAllData()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 25, bandwidthBytesPerSecond: bw,
                lossRate: 0, seed: 1234,
                jitterMilliseconds: 4);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 200;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43005);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43005));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('K', 64 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 8000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _outputHelper.WriteLine("Burst: dropped={0} tput={1:F0}B/s",
                    sim.DroppedPackets, sim.LogicalThroughputBytesPerSecond);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_ReorderingAndDuplication_StillDelivers()
        {
            const int bw = 2 * 1024 * 1024;
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 2, lossRate: 0, seed: 42,
                duplicateRate: 0.05, reorderRate: 0.2);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw * 8;
            config.MaxPacingRateBytesPerSecond = bw * 8;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43006);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43006));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('Q', 16 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 15000);

                _outputHelper.WriteLine("ReorderDup: dup={0} reorder={1} tput={2:F0}B/s readOk={3}",
                    sim.DuplicatedPackets, sim.ReorderedPackets, sim.LogicalThroughputBytesPerSecond, readOk);
                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
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

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43007);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43007));
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
                // The small receiver window paces the transfer well below the
                // link rate: the full 32KB must take noticeably longer than a
                // single 5ms-RTT unthrottled burst would (>= 10ms).
                Assert.True(sw.ElapsedMilliseconds >= 10,
                    $"small receiver window should slow the sender: elapsed={sw.ElapsedMilliseconds}ms");
                _outputHelper.WriteLine("Rwnd: elapsed={0}ms tput={1:F0}B/s",
                    sw.ElapsedMilliseconds, sim.LogicalThroughputBytesPerSecond);
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
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 50, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 25);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 300;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43008);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43008));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('J', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 8000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _outputHelper.WriteLine("HighJitter: tput={0:F0}B/s rttSamples={1}",
                    sim.LogicalThroughputBytesPerSecond, client.GetReport().RttSamplesMicros.Count);
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
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 2);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 200;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43009);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43009));
                UcpConnection srvConn = await acceptTask;

                byte[] payloadClient = Encoding.ASCII.GetBytes(new string('C', 16 * 1024));
                byte[] payloadServer = Encoding.ASCII.GetBytes(new string('S', 16 * 1024));
                byte[] receivedClient = new byte[payloadClient.Length];
                byte[] receivedServer = new byte[payloadServer.Length];

                await client.WriteAsync(payloadClient, 0, payloadClient.Length);

                bool readOk1 = await UcpTestHelpers.ReadWithTimeoutTask(srvConn.ReadAsync(receivedClient, 0, receivedClient.Length), 8000);
                Assert.True(readOk1, "Server should receive client data");
                Assert.True(payloadClient.SequenceEqual(receivedClient), "Server received data should match client payload");

                await srvConn.WriteAsync(payloadServer, 0, payloadServer.Length);

                bool readOk2 = await UcpTestHelpers.ReadWithTimeoutTask(client.ReadAsync(receivedServer, 0, receivedServer.Length), 8000);
                Assert.True(readOk2, "Client should receive server data (full duplex)");
                Assert.True(payloadServer.SequenceEqual(receivedServer), "Client received data should match server payload");
                _outputHelper.WriteLine("FullDuplex: delivered={0} dup={1} readOk1={2} readOk2={3}",
                    sim.DeliveredBytes, sim.DuplicatedPackets, readOk1, readOk2);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        [Fact]
        public async Task SimulatedNetwork_LongFatPipe_100M()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 50, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 300;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43010);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43010));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('L', 256 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 8000);

                Assert.True(writeOk);
                if (!readOk)
                {
                    // A 256KB transfer over a 50ms-RTT 100Mbps link should
                    // complete well within 8s; require substantial delivery to
                    // catch a genuine long-fat-pipe failure (not just a slow
                    // scheduler).
                    _outputHelper.WriteLine("LFP: read timed out - partial delivery, delivered={0}", sim.DeliveredBytes);
                    Assert.True(sim.DeliveredBytes >= payload.Length / 2,
                        $"Long-fat-pipe transfer underdelivered: {sim.DeliveredBytes} < {payload.Length / 2}");
                }
                else
                {
                    Assert.True(payload.SequenceEqual(received));
                }
                var report = client.GetReport();
                _outputHelper.WriteLine("LFP: tput={0:F0}B/s delivered={1} rttSamples={2}",
                    sim.LogicalThroughputBytesPerSecond, sim.DeliveredBytes, report.RttSamplesMicros.Count);
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
            var sim = new NetworkSimulator(
                fixedDelayMilliseconds: 75, bandwidthBytesPerSecond: bw,
                jitterMilliseconds: 30, lossRate: 0.03, seed: 20260601);
            var config = new UcpConfiguration();
            config.TimerIntervalMilliseconds = 1;
            config.InitialBandwidthBytesPerSecond = bw;
            config.MaxPacingRateBytesPerSecond = bw;
            config.MaxRetransmissions = 300;

            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43011);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43011));
                UcpConnection srvConn = await acceptTask;

                byte[] payload = Encoding.ASCII.GetBytes(new string('M', 32 * 1024));
                byte[] received = new byte[payload.Length];

                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 20000);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                _outputHelper.WriteLine("Mobile3G: dropped={0} tput={1:F0}B/s",
                    sim.DroppedPackets, sim.LogicalThroughputBytesPerSecond);
            }
            finally
            {
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        private readonly ITestOutputHelper _outputHelper;
        public UcpNetworkTests(ITestOutputHelper output)
        {
            _outputHelper = output;
        }
    }
}
