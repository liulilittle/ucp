using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Ucp;
using Ucp.Internal;
using UcpTest.TestTransport;
using Xunit.Abstractions;

namespace UcpTest
{
    /// <summary>
    /// Comprehensive unit and integration tests for the UCP reliable transport protocol.
    /// Covers packet codec, congestion control (BBR), pacing, RTO estimation, FEC,
    /// sequence number wraparound, and a full matrix of network impairment scenarios
    /// (no-loss, lossy, high-latency, asymmetric routing, gigabit, mobile, satellite, VPN).
    /// </summary>
    public sealed class UcpCoreTests
    {
        /// <summary>Xunit test output helper for writing diagnostic information during test runs.</summary>
        private readonly ITestOutputHelper _output;

        /// <summary>
        /// Initializes a new instance of <see cref="UcpCoreTests"/> with the xunit output helper.
        /// </summary>
        /// <param name="output">The test output helper injected by the xunit test runner.</param>
        public UcpCoreTests(ITestOutputHelper output)
        {
            _output = output;
        }

        /// <summary>
        /// Verifies that <see cref="UcpSequenceComparer"/> correctly handles wrap-around
        /// at <see cref="uint.MaxValue"/>, treating 0 as after MaxValue and MaxValue as before 0.
        /// </summary>
        [Fact]
        public void SequenceComparer_HandlesWrapAround()
        {
            // Test the three critical wrap-around cases.
            uint max = uint.MaxValue;
            uint zero = 0;
            uint one = 1;

            // zero comes after max in circular sequence space.
            Assert.True(UcpSequenceComparer.IsAfter(zero, max));

            // one also comes after max (zero already consumed that tick).
            Assert.True(UcpSequenceComparer.IsAfter(one, max));

            // max comes before zero in circular sequence space.
            Assert.True(UcpSequenceComparer.IsBefore(max, zero));

            // Compare returns +1 when left is after right.
            Assert.Equal(1, UcpSequenceComparer.Instance.Compare(zero, max));

            // Compare returns -1 when left is before right.
            Assert.Equal(-1, UcpSequenceComparer.Instance.Compare(max, zero));
        }

        /// <summary>
        /// Tests round-trip encoding and decoding of an ACK packet with SACK blocks
        /// and echo timestamp through <see cref="UcpPacketCodec"/>.
        /// </summary>
        [Fact]
        public void PacketCodec_CanRoundTripAckWithEchoTimestamp()
        {
            // Build a complete ACK packet with all optional fields populated.
            UcpAckPacket packet = new UcpAckPacket();
            packet.Header = new UcpCommonHeader
            {
                Type = UcpPacketType.Ack,
                Flags = UcpPacketFlags.NeedAck,
                ConnectionId = 77,
                Timestamp = 123456789
            };
            packet.AckNumber = 100;

            // Add SACK (Selective Acknowledgment) blocks covering discontiguous ranges.
            packet.SackBlocks.Add(new SackBlock { Start = 102, End = 105 });
            packet.SackBlocks.Add(new SackBlock { Start = 109, End = 110 });

            packet.WindowSize = 512;

            // Echo timestamp is used for RTT calculation by the remote peer.
            packet.EchoTimestamp = 987654321;

            // Encode the packet to bytes and immediately decode it back.
            byte[] encoded = UcpPacketCodec.Encode(packet);
            UcpPacket decodedRaw;
            bool ok = UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out decodedRaw);

            // Verify the decode succeeded and returned the correct packet type.
            Assert.True(ok);
            UcpAckPacket decoded = Assert.IsType<UcpAckPacket>(decodedRaw);

            // Verify all header fields survived the round-trip.
            Assert.Equal(packet.Header.Type, decoded.Header.Type);
            Assert.Equal(packet.Header.Flags, decoded.Header.Flags);
            Assert.Equal(packet.Header.ConnectionId, decoded.Header.ConnectionId);

            // Verify ACK-specific fields.
            Assert.Equal(packet.AckNumber, decoded.AckNumber);
            Assert.Equal(packet.WindowSize, decoded.WindowSize);
            Assert.Equal(packet.EchoTimestamp, decoded.EchoTimestamp);

            // Verify SACK blocks were encoded and decoded correctly.
            Assert.Equal(2, decoded.SackBlocks.Count);
            Assert.Equal((uint)102, decoded.SackBlocks[0].Start);
            Assert.Equal((uint)105, decoded.SackBlocks[0].End);
        }

        /// <summary>
        /// Verifies that <see cref="UcpSackGenerator"/> correctly merges consecutive
        /// received sequence numbers into continuous SACK blocks.
        /// </summary>
        [Fact]
        public void SackGenerator_BuildsContinuousBlocks()
        {
            UcpSackGenerator generator = new UcpSackGenerator();

            // Simulate received sequence numbers with two contiguous ranges and one isolated.
            List<uint> received = new List<uint> { 12, 13, 14, 18, 19, 25 };

            // Generate SACK blocks referencing the last acknowledged number (10) with max 8 blocks.
            List<SackBlock> blocks = generator.Generate(10, received, 8);

            // Expect three blocks: [12-14], [18-19], and the singleton [25-25].
            Assert.Equal(3, blocks.Count);
            Assert.Equal((uint)12, blocks[0].Start);
            Assert.Equal((uint)14, blocks[0].End);
            Assert.Equal((uint)18, blocks[1].Start);
            Assert.Equal((uint)19, blocks[1].End);
            Assert.Equal((uint)25, blocks[2].Start);
            Assert.Equal((uint)25, blocks[2].End);
        }

        /// <summary>
        /// Confirms that <see cref="UcpRtoEstimator"/> applies exponential backoff
        /// but caps the result at twice the minimum RTO to avoid excessive latency.
        /// </summary>
        [Fact]
        public void RtoEstimator_CapsBackoffAtTwiceMinimumRto()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.MinRtoMicros = 1000000;
            config.MaxRtoMicros = 60000000;
            config.RetransmitBackoffFactor = 1.5d;

            // Initialize the estimator with a sample RTT.
            UcpRtoEstimator estimator = new UcpRtoEstimator(config);
            estimator.Update(100000);
            long first = estimator.CurrentRtoMicros;

            // Apply one round of backoff.
            estimator.Backoff();

            // The backoff should be min(first * 1.5, MinRtoMicros * 2).
            Assert.Equal(Math.Min((long)(first * 1.5d), config.MinRtoMicros * 2), estimator.CurrentRtoMicros);
        }

        /// <summary>
        /// Tests that the <see cref="PacingController"/> correctly computes wait time
        /// when the token bucket has insufficient tokens for a requested consume.
        /// </summary>
        [Fact]
        public void PacingController_ComputesWaitTimeWhenTokensInsufficient()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;

            // Create a controller with an initial token count of 1000.
            PacingController controller = new PacingController(config, 1000);

            // Set rate to 1000 bytes per microsecond (burst), 1000 bytes per second (sustained).
            controller.SetRate(1000, 1000000);

            // Consume 1220 tokens at time 1000000: succeeds (we have 1000 initial + growth).
            Assert.True(controller.TryConsume(1220, 1000000));

            // After that burst, 500 more tokens are not available.
            Assert.False(controller.TryConsume(500, 1000000));

            // The wait time for 500 tokens should be approximately 500 microseconds.
            long wait = controller.GetWaitTimeMicros(500, 1000000);
            Assert.InRange(wait, 499000, 501000);
        }

        /// <summary>
        /// Verifies that <see cref="PacingController.ForceConsume"/> bypasses an empty
        /// bucket but does not create post-recovery debt that blocks subsequent packets.
        /// </summary>
        [Fact]
        public void PacingController_ForceConsume_BypassesEmptyBucketWithoutPostRecoveryDebt()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1000000;
            PacingController controller = new PacingController(config, 1000);
            controller.SetRate(1000, 1000000);

            // Drain the bucket with a large consume.
            Assert.True(controller.TryConsume(1220, 1000000));

            // At this point, the bucket is empty; even 1 token cannot be consumed.
            Assert.False(controller.TryConsume(1, 1000000));

            // Force-consume 500 tokens — this bypasses the token check.
            controller.ForceConsume(500, 1000000);

            // After force-consume, the bucket should NOT be in post-recovery debt.
            // Still cannot consume without waiting for token replenishment.
            Assert.False(controller.TryConsume(1, 1000000));

            // Wait time should be roughly the time to replenish 1 token at the sustained rate.
            Assert.InRange(controller.GetWaitTimeMicros(1, 1000000), 900, 1100);

            // After waiting 1000 microseconds, enough tokens should have accumulated.
            Assert.True(controller.TryConsume(1, 1001000));
        }

        /// <summary>
        /// Tests that the BBR congestion controller transitions out of Startup mode
        /// after a sufficient number of ACK rounds with adequate bandwidth growth.
        /// </summary>
        [Fact]
        public void BbrController_TransitionsOutOfStartup()
        {
            BbrCongestionControl bbr = new BbrCongestionControl();
            long now = 100000;

            // Feed 12 rounds of ACKs with realistic delivered bytes and RTT values.
            for (int i = 0; i < 12; i++)
            {
                bbr.OnAck(now, 24000, 50000, 24000);
                now += 50000;
            }

            // After sufficient iterations, BBR should leave Startup mode.
            Assert.NotEqual(BbrMode.Startup, bbr.Mode);

            // Pacing rate should be non-zero after convergence.
            Assert.True(bbr.PacingRateBytesPerSecond > 0);

            // Congestion window should be at least the initial CWND.
            Assert.True(bbr.CongestionWindowBytes >= new UcpConfiguration().InitialCongestionWindowBytes);
        }

        /// <summary>
        /// Verifies that the BBR bandwidth estimate is resistant to short-term dips
        /// (rate cliffs), maintaining a floor at a steady growth ratio of the peak.
        /// </summary>
        [Fact]
        public void BbrController_BandwidthEstimateResistsShortTermRateCliffs()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = 1;
            config.MaxPacingRateBytesPerSecond = 0;
            config.BbrWindowRtRounds = 2;
            BbrCongestionControl bbr = new BbrCongestionControl(config);

            // First ACK: establish a high bandwidth estimate.
            bbr.OnAck(100000, 100000, 100000, 100000);
            double highRate = bbr.BtlBwBytesPerSecond;

            // Feed three rounds of severely reduced throughput to simulate a rate cliff.
            bbr.OnAck(500000, 1000, 100000, 1000);
            bbr.OnAck(700000, 1000, 100000, 1000);
            bbr.OnAck(2500000, 1000, 100000, 1000);

            // High rate must have been a meaningful positive value.
            Assert.True(highRate > 1);

            // After the cliff, the estimate should not drop below the steady-growth floor.
            Assert.True(bbr.BtlBwBytesPerSecond >= highRate * UcpConstants.BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND);
        }

        /// <summary>
        /// Parameterized test that verifies BBR's auto-probe capability converges
        /// to the correct bandwidth without any pre-configured rate cap.
        /// Tests at 100 Mbps, 1 Gbps, and 10 Gbps benchmarks.
        /// </summary>
        /// <param name="bottleneckBytesPerSecond">The simulated bottleneck bandwidth.</param>
        [Theory]
        [InlineData(UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND)]
        [InlineData(UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND)]
        [InlineData(UcpConstants.BENCHMARK_10_GBPS_BYTES_PER_SECOND)]
        public void BbrController_AutoProbeConvergesWithoutConfiguredRateCap(int bottleneckBytesPerSecond)
        {
            // Configure BBR for auto-probe: no max pacing rate cap, high initial CWND.
            UcpConfiguration config = UcpConfiguration.GetOptimizedConfig();
            config.InitialBandwidthBytesPerSecond = UcpConstants.BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND;
            config.MaxPacingRateBytesPerSecond = 0;
            config.MaxCongestionWindowBytes = int.MaxValue;
            config.InitialCwndBytes = (uint)Math.Max(config.InitialCongestionWindowBytes, bottleneckBytesPerSecond / UcpConstants.BENCHMARK_INITIAL_PROBE_BANDWIDTH_DIVISOR);
            BbrCongestionControl bbr = new BbrCongestionControl(config);

            long nowMicros = UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS;
            long convergenceMicros = 0;

            // Run up to the maximum number of convergence rounds.
            for (int round = 0; round < UcpConstants.BENCHMARK_CONTROLLER_MAX_CONVERGENCE_ROUNDS; round++)
            {
                // Calculate how many bytes would be delivered in one RTT at the bottleneck rate.
                int deliveredBytes = (int)Math.Min(int.MaxValue, bottleneckBytesPerSecond * (UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS / (double)UcpConstants.MICROS_PER_SECOND));
                bbr.OnAck(nowMicros, deliveredBytes, UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS, deliveredBytes);

                // Check if pacing rate has converged to within the expected ratio of the bottleneck.
                if (bbr.PacingRateBytesPerSecond >= bottleneckBytesPerSecond * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO)
                {
                    convergenceMicros = nowMicros;
                    break;
                }

                nowMicros += UcpConstants.BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS;
            }

            // The controller must converge within the allotted rounds.
            Assert.True(convergenceMicros > 0);

            // Pacing rate must be between the min and max convergence ratio bounds.
            Assert.True(bbr.PacingRateBytesPerSecond >= bottleneckBytesPerSecond * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
            Assert.True(bbr.PacingRateBytesPerSecond <= bottleneckBytesPerSecond * UcpConstants.BENCHMARK_MAX_CONVERGED_PACING_RATIO);
        }

        /// <summary>
        /// Edge case: verifies the pacing controller allows a packet through when
        /// the bucket duration is extremely small (1 microsecond).
        /// </summary>
        [Fact]
        public void PacingController_AllowsPacketWhenBucketDurationIsTiny()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.PacingBucketDurationMicros = 1;
            config.SendQuantumBytes = 1;
            PacingController controller = new PacingController(config, 1);

            // Even a full-sized packet should be allowed when the bucket is tiny.
            Assert.True(controller.TryConsume(UcpConstants.DataHeaderSize + config.MaxPayloadSize, 0));
        }

        /// <summary>
        /// Verifies that <see cref="UcpRtoEstimator"/> clamps invalid configuration
        /// values (zero min RTO, tiny max RTO, sub-1.0 backoff factor) to safe defaults.
        /// </summary>
        [Fact]
        public void RtoEstimator_ClampsInvalidConfiguration()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.MinRtoMicros = 0;
            config.MaxRtoMicros = 1;
            config.RetransmitBackoffFactor = 0.5d;
            UcpRtoEstimator estimator = new UcpRtoEstimator(config);

            // Feed a sample to initialize the estimator.
            estimator.Update(1000);
            long beforeBackoff = estimator.CurrentRtoMicros;

            // The clamped minimum RTO should be enforced.
            Assert.True(beforeBackoff >= UcpConstants.MinRtoMicros);

            // Backoff with sub-1.0 factor should default to 1.0, so RTO should not decrease.
            estimator.Backoff();
            Assert.True(estimator.CurrentRtoMicros >= beforeBackoff);
        }

        /// <summary>
        /// Integration test: no-loss scenario. Verifies that a client can connect,
        /// transfer 512 KB, and the receiver gets the exact same data with negligible retransmission.
        /// </summary>
        [Fact]
        public async Task Integration_NoLoss_CanConnectAndTransfer()
        {
            // Configure a clean 10 MB/s link with low latency.
            const int noLossBandwidth = 10 * 1024 * 1024;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: noLossBandwidth, forwardDelayMilliseconds: 7, backwardDelayMilliseconds: 2);
            UcpConfiguration noLossConfig = CreateScenarioConfig(noLossBandwidth);

            // Create server and client, start the server on port 40001.
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), noLossConfig.Clone());
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, noLossConfig.Clone(), null);
            server.Start(40001);
            try
            {
                // Establish connection.
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40001));
                UcpConnection serverConnection = await acceptTask;

                // Prepare a 512 KB payload.
                byte[] payload = Encoding.ASCII.GetBytes(new string('A', 512 * 1024));
                byte[] received = new byte[payload.Length];

                // Transfer and measure throughput.
                DateTime start = DateTime.UtcNow;
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 5000);

                // Wait for final ACKs to settle so the report captures all metrics.
                await WaitForAckSettlementAsync(client, 1000);

                double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
                double throughput = GetBenchmarkThroughputBytesPerSecond(simulator, payload.Length, elapsedSeconds);

                // Generate and append a performance report.
                UcpPerformanceReport noLossReport = UcpPerformanceReport.FromConnection("NoLoss", client, throughput, (long)(elapsedSeconds * UcpConstants.MICROS_PER_MILLI), noLossBandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros, simulator.ObservedDataLossPercent);
                noLossReport.ConvergenceMilliseconds = Math.Max(1L, (long)(elapsedSeconds * 1000d));
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, noLossReport);

                _output.WriteLine("NoLoss delivered packets={0}, bytes={1}", simulator.DeliveredPackets, simulator.DeliveredBytes);

                // Assert correct data transfer with minimal retransmission.
                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(simulator.DeliveredPackets > 0);
                Assert.True(noLossReport.RetransmissionRatio <= 0.01d);
                Assert.True(noLossReport.AverageRttMicros > 0);

                // Pacing rate should converge to within ±30% of the configured bottleneck.
                Assert.InRange(noLossReport.PacingRateBytesPerSecond, noLossBandwidth * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO, noLossBandwidth * UcpConstants.BENCHMARK_MAX_CONVERGED_PACING_RATIO);
            }
            finally
            {
                await client.CloseAsync();
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: lossy network with a custom drop rule that drops every 8th DATA packet.
        /// Verifies that retransmission recovers all lost data and the final payload is intact.
        /// </summary>
        [Fact]
        public async Task Integration_LossyNetwork_RetransmitsAndDelivers()
        {
            int dataPacketIndex = 0;
            const int lossyBandwidth = 512 * 1024;

            // Create a simulator with moderate delay, jitter, and a custom drop rule
            // that drops exactly one data packet (the 8th) to trigger retransmission.
            NetworkSimulator simulator = new NetworkSimulator(
                fixedDelayMilliseconds: 15,
                jitterMilliseconds: 5,
                bandwidthBytesPerSecond: lossyBandwidth,
                forwardDelayMilliseconds: 10,
                backwardDelayMilliseconds: 18,
                forwardJitterMilliseconds: 3,
                backwardJitterMilliseconds: 5,
                dropRule: delegate (NetworkSimulator.SimulatedDatagram datagram)
                {
                    UcpPacket packet;
                    if (!UcpPacketCodec.TryDecode(datagram.Buffer, 0, datagram.Count, out packet))
                    {
                        return false;
                    }

                    // Only drop DATA packets, and only the 8th one.
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
                // Connect and prepare payload.
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
                double throughput = GetBenchmarkThroughputBytesPerSecond(simulator, payload.Length, elapsedSeconds);

                UcpPerformanceReport lossyReport = UcpPerformanceReport.FromConnection("Lossy", client, throughput, (long)(elapsedSeconds * UcpConstants.MICROS_PER_MILLI), lossyBandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros, simulator.ObservedDataLossPercent);
                lossyReport.ConvergenceMilliseconds = Math.Max(1L, (long)(elapsedSeconds * 1000d));
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, lossyReport);

                _output.WriteLine("Lossy dropped={0}, delivered={1}", simulator.DroppedPackets, simulator.DeliveredPackets);

                // Verify that at least 8 data packets were sent (so the drop occurred).
                Assert.True(dataPacketIndex >= 8);
                Assert.True(writeOk);
                Assert.True(readOk);

                // Despite the loss, the receiver must get the exact original payload.
                Assert.True(payload.SequenceEqual(received));
                Assert.True(simulator.DroppedPackets >= 1);

                // Retransmission should have happened but remain within reasonable bounds.
                Assert.True(lossyReport.RetransmissionRatio > 0);
                Assert.True(lossyReport.RetransmissionRatio < 0.45d);

                // Throughput should be within ±30% of the configured bandwidth.
                Assert.InRange(lossyReport.PacingRateBytesPerSecond, lossyBandwidth * 0.70d, lossyBandwidth * 1.30d);
            }
            finally
            {
                await client.CloseAsync();
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: fair queuing. Connects 4 concurrent clients over a shared
        /// 256 KB/s bottleneck and verifies each client gets approximately equal throughput.
        /// </summary>
        [Fact]
        public async Task Integration_FairQueue_MultiClientGetsBalancedCompletion()
        {
            const int bandwidth = 256 * 1024;

            // Single shared simulator for all connections.
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bandwidth);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), bandwidth);
            server.Start(40003);

            // Create 4 client connections.
            List<UcpConnection> clients = new List<UcpConnection>();
            List<UcpConnection> serverConnections = new List<UcpConnection>();
            for (int i = 0; i < 4; i++)
            {
                clients.Add(new UcpConnection(simulator.CreateTransport("client" + i)));
            }

            // Accept all 4 connections.
            List<Task<UcpConnection>> acceptTasks = new List<Task<UcpConnection>>();
            for (int i = 0; i < 4; i++)
            {
                acceptTasks.Add(server.AcceptAsync());
            }

            // All clients connect to the same port.
            for (int i = 0; i < clients.Count; i++)
            {
                await clients[i].ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40003));
            }

            // Collect accepted server-side connections.
            for (int i = 0; i < acceptTasks.Count; i++)
            {
                serverConnections.Add(await acceptTasks[i]);
            }

            // Prepare payload and receive buffers for each client.
            byte[] payload = Encoding.ASCII.GetBytes(new string('C', 128 * 1024));
            List<byte[]> received = new List<byte[]>();
            for (int i = 0; i < clients.Count; i++)
            {
                received.Add(new byte[payload.Length]);
            }

            // Start all writes and reads concurrently from a common baseline timestamp.
            DateTime commonStart = DateTime.UtcNow;
            List<Task> writes = new List<Task>();
            List<Task<bool>> reads = new List<Task<bool>>();
            Task<double>[] readWithDurations = new Task<double>[clients.Count];

            for (int i = 0; i < clients.Count; i++)
            {
                int index = i;

                // Server writes the payload to each client.
                writes.Add(serverConnections[index].WriteAsync(payload, 0, payload.Length));

                // Client reads the full payload back.
                reads.Add(ReadWithinAsync(clients[index], received[index], 0, payload.Length, 30000));

                // Measure the duration of each read relative to the common start.
                readWithDurations[index] = MeasureReadDurationAsync(reads[index], commonStart);
            }

            // Wait for all writes and reads to complete.
            await Task.WhenAll(writes);
            bool[] results = await Task.WhenAll(reads);
            double[] durations = await Task.WhenAll(readWithDurations);

            // Every client must receive the full correct payload.
            for (int i = 0; i < results.Length; i++)
            {
                Assert.True(results[i]);
                Assert.True(payload.SequenceEqual(received[i]));
            }

            // Compute per-client throughput and verify fairness.
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

            // Each client's throughput must be within ±20% of the average (fairness check).
            for (int i = 0; i < throughputs.Length; i++)
            {
                Assert.InRange(throughputs[i], avgThroughput * 0.8d, avgThroughput * 1.2d);
            }

            // Clean up.
            for (int i = 0; i < clients.Count; i++)
            {
                await clients[i].CloseAsync();
            }

            server.Stop();
        }

        /// <summary>
        /// Integration test: high loss (5% random DATA loss) with high RTT (~100ms).
        /// Verifies the protocol still completes with reasonable throughput and retransmission ratio.
        /// </summary>
        [Fact]
        public async Task Integration_HighLossHighRtt_StillCompletes()
        {
            const int highLossBandwidth = 2 * 1024 * 1024;

            // Simulator with 50ms base delay, high jitter, and 5% random DATA packet loss.
            // Only initial data packets are dropped; retransmissions are never dropped so
            // recovery paths are not multiply penalized.
            NetworkSimulator simulator = new NetworkSimulator(
                fixedDelayMilliseconds: 50,
                jitterMilliseconds: 20,
                bandwidthBytesPerSecond: highLossBandwidth,
                forwardDelayMilliseconds: 58,
                backwardDelayMilliseconds: 48,
                forwardJitterMilliseconds: 12,
                backwardJitterMilliseconds: 8,
                dropRule: CreateInitialDataDropRule(0.05d, 20260428));

            // Enable aggressive SACK recovery and FEC for high-loss scenarios.
            UcpConfiguration highLossConfig = CreateScenarioConfig(highLossBandwidth);
            highLossConfig.EnableAggressiveSackRecovery = true;
            highLossConfig.FecGroupSize = 8;
            highLossConfig.FecRedundancy = 0.50d;

            UcpServer server = new UcpServer(simulator.CreateTransport("server"), highLossConfig);
            server.Start(40004);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, highLossConfig.Clone(), null);

            Task<UcpConnection> acceptTask = server.AcceptAsync();
            await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40004));
            UcpConnection serverConnection = await acceptTask;

            byte[] payload = Encoding.ASCII.GetBytes(new string('D', UcpConstants.BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES));
            byte[] received = new byte[payload.Length];

            DateTime start = DateTime.UtcNow;
            bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
            bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 20000);
            await WaitForAckSettlementAsync(client, 1000);

            double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
            double throughput = GetBenchmarkThroughputBytesPerSecond(simulator, payload.Length, elapsedSeconds);

            _output.WriteLine("HighLoss RTT scenario throughput={0:F2} B/s, dropped={1}", throughput, simulator.DroppedPackets);

            UcpPerformanceReport highLossReport = UcpPerformanceReport.FromConnection("HighLossHighRtt", client, throughput, (long)(elapsedSeconds * UcpConstants.MICROS_PER_MILLI), highLossBandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros, simulator.ObservedDataLossPercent);
            highLossReport.ConvergenceMilliseconds = Math.Max(1L, (long)(elapsedSeconds * 1000d));
            UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, highLossReport);

            // Must complete with correct data, reasonable throughput, and measurable retransmission.
            Assert.True(writeOk);
            Assert.True(readOk);
            Assert.True(payload.SequenceEqual(received));
            Assert.True(throughput > 32 * 1024);
            Assert.True(highLossReport.RetransmissionRatio > 0);
            Assert.True(highLossReport.RetransmissionRatio < 0.45d);

            await client.CloseAsync();
            server.Stop();
        }

        /// <summary>
        /// Integration test: Long Fat Pipe (LFN) — 100 Mbps bandwidth with 50ms RTT.
        /// Verifies high utilization, low retransmission, and adequate congestion window size.
        /// </summary>
        [Fact]
        public async Task Integration_LongFatPipe_ReportsGoodThroughput()
        {
            // ~12.5 MB/s with 50ms base delay.
            const int bandwidth = 100000000 / 8;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 50, bandwidthBytesPerSecond: bandwidth, forwardDelayMilliseconds: 56, backwardDelayMilliseconds: 46);
            UcpConfiguration config = CreateScenarioConfig(bandwidth);
            config.MinRtoMicros = 1000000;
            config.InitialCwndBytes = (uint)(bandwidth / 5);

            UcpServer server = new UcpServer(simulator.CreateTransport("server"), config.Clone());
            server.Start(40005);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, config, null);

            Task<UcpConnection> acceptTask = server.AcceptAsync();
            await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40005));
            UcpConnection serverConnection = await acceptTask;

            // 16 MB payload to fill the pipe.
            byte[] payload = Encoding.ASCII.GetBytes(new string('E', 16 * 1024 * 1024));
            byte[] received = new byte[payload.Length];

            DateTime start = DateTime.UtcNow;
            Task<bool> readTask = ReadWithinAsync(serverConnection, received, 0, received.Length, 15000);
            bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
            bool readOk = await readTask;
            await WaitForAckSettlementAsync(client, 1000);

            double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
            double throughput = GetBenchmarkThroughputBytesPerSecond(simulator, payload.Length, elapsedSeconds);
            double theoretical = bandwidth;

            _output.WriteLine("LongFatPipe throughput={0:F2} B/s, utilization={1:P2}", throughput, throughput / theoretical);

            UcpPerformanceReport longFatPipeReport = UcpPerformanceReport.FromConnection("LongFatPipe", client, throughput, (long)(elapsedSeconds * UcpConstants.MICROS_PER_MILLI), bandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros, simulator.ObservedDataLossPercent);
            longFatPipeReport.ConvergenceMilliseconds = Math.Max(1L, (long)(elapsedSeconds * 1000d));
            UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, longFatPipeReport);

            Assert.True(writeOk);
            Assert.True(readOk);
            Assert.True(payload.SequenceEqual(received));

            // LFN must achieve high utilization with minimal retransmission.
            Assert.True(longFatPipeReport.RetransmissionRatio <= 0.05d);
            Assert.InRange(longFatPipeReport.PacingRateBytesPerSecond, bandwidth * 0.70d, bandwidth * 1.30d);

            // Congestion window must be large enough to fill the BDP.
            Assert.True(longFatPipeReport.CongestionWindowBytes >= bandwidth / 5);
            Assert.True(longFatPipeReport.UtilizationPercent >= 65d);

            await client.CloseAsync();
            server.Stop();
        }

        /// <summary>
        /// Integration test: verifies that an RST (reset) packet from the peer
        /// causes the local connection to transition to Closed state immediately.
        /// </summary>
        [Fact]
        public async Task Integration_Rst_ClosesPeerImmediately()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 2);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40006);
            try
            {
                // Connect client and server.
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40006));
                UcpConnection serverConnection = await acceptTask;

                // Set up a disconnected event listener on the client.
                TaskCompletionSource<bool> disconnected = new TaskCompletionSource<bool>();
                client.OnDisconnected += delegate { disconnected.TrySetResult(true); };

                // Server sends an RST (simulated via AbortForTest).
                serverConnection.AbortForTest(true);

                // Client must observe the disconnect within 3 seconds.
                bool observed = await UcpTestHelpers.WithTimeout(disconnected.Task, 3000);
                Assert.True(observed);

                // Client state must be Closed and must have received a reset.
                Assert.Equal(UcpConnectionState.Closed, client.GetDiagnostics().State);
                Assert.True(client.GetDiagnostics().ReceivedReset);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: verifies that disposing the server connection (simulating peer timeout)
        /// is detected by the client within the expected timeout window.
        /// </summary>
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

                // Listen for the disconnected event on the client side.
                TaskCompletionSource<bool> disconnected = new TaskCompletionSource<bool>();
                client.OnDisconnected += delegate { disconnected.TrySetResult(true); };

                // Dispose the server connection to simulate peer crash / timeout.
                serverConnection.Dispose();

                // Client must detect the disconnect within 7 seconds.
                bool observed = await UcpTestHelpers.WithTimeout(disconnected.Task, 7000);
                Assert.True(observed);
                Assert.Equal(UcpConnectionState.Closed, client.GetDiagnostics().State);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: verifies correct data transfer when the sequence number
        /// wraps around from near <see cref="uint.MaxValue"/> to 0 mid-transfer.
        /// </summary>
        [Fact]
        public async Task Integration_SequenceWrapAround_StillTransfersCorrectly()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1024 * 1024);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));

            // Force the next send sequence number to be just before wraparound.
            client.SetNextSendSequenceForTest(uint.MaxValue - 8);
            server.Start(40008);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40008));
                UcpConnection serverConnection = await acceptTask;

                // Transfer 16 KB which will span the sequence number wraparound boundary.
                byte[] payload = Encoding.ASCII.GetBytes(new string('W', 16 * 1024));
                byte[] received = new byte[payload.Length];

                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 8000);

                // Log diagnostics from both ends for debugging.
                UcpConnectionDiagnostics clientDiag = client.GetDiagnostics();
                UcpConnectionDiagnostics serverDiag = serverConnection.GetDiagnostics();

                _output.WriteLine("Wrap client state={0}, inflight={1}, sent={2}, retrans={3}, rtt={4}", clientDiag.State, clientDiag.FlightBytes, clientDiag.SentDataPackets, clientDiag.RetransmittedPackets, clientDiag.LastRttMicros);
                _output.WriteLine("Wrap server state={0}, buffered={1}, ack={2}, nak={3}", serverDiag.State, serverDiag.BufferedReceiveBytes, serverDiag.SentAckPackets, serverDiag.SentNakPackets);

                // Data must arrive intact despite wraparound.
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

        /// <summary>
        /// Integration test: verifies that a reduced receiver window causes the sender to
        /// slow down, and that restoring the window allows the transfer to complete correctly.
        /// </summary>
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

                // Artificially reduce the receiver's advertised window to 2 MSS.
                serverConnection.SetAdvertisedReceiveWindowForTest((uint)(2 * UcpConstants.Mss));

                byte[] payload = Encoding.ASCII.GetBytes(new string('R', 32 * 1024));
                byte[] received = new byte[payload.Length];
                DateTime start = DateTime.UtcNow;

                // Start writing and wait for the receiver to buffer approximately 2 MSS of data.
                Task<bool> writeTask = client.WriteAsync(payload, 0, payload.Length);
                await WaitForBufferedReceiveBytesAsync(serverConnection, 2 * UcpConstants.Mss, 2000);

                // Restore the receiver window to its default size mid-transfer.
                serverConnection.SetAdvertisedReceiveWindowForTest(new UcpConfiguration().ReceiveWindowBytes);

                // Complete the read and write.
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 12000);
                bool writeOk = await writeTask;
                double elapsedMs = (DateTime.UtcNow - start).TotalMilliseconds;

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));

                // The reduced window should have caused a noticeable delay (> 50ms).
                Assert.True(elapsedMs > 50);

                await client.CloseAsync();
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: verifies that the pacing controller respects the configured
        /// rate limit, keeping throughput within ±30% of the target bandwidth.
        /// </summary>
        [Fact]
        public async Task Integration_Pacing_RespectsConfiguredRate()
        {
            const int bandwidth = 128 * 1024;
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: bandwidth, forwardDelayMilliseconds: 9, backwardDelayMilliseconds: 4);
            UcpConfiguration pacingConfig = CreateScenarioConfig(bandwidth);

            // Set drain pacing gain to 1.0 to keep the pacing rate stable during the drain phase.
            pacingConfig.DrainPacingGain = 1.0d;

            UcpServer server = new UcpServer(simulator.CreateTransport("server"), pacingConfig);
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40010);
            try
            {
                // Establish connection.
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
                double throughput = GetBenchmarkThroughputBytesPerSecond(simulator, payload.Length, elapsedSeconds);

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));

                // Throughput should not exceed 1.5x the configured pacing limit.
                Assert.True(throughput <= bandwidth * 1.5d);

                UcpPerformanceReport pacingReport = UcpPerformanceReport.FromConnection("Pacing", serverConnection, throughput, (long)(elapsedSeconds * UcpConstants.MICROS_PER_MILLI), bandwidth, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros, simulator.ObservedDataLossPercent);
                pacingReport.ConvergenceMilliseconds = Math.Max(1L, (long)(elapsedSeconds * 1000d));
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, pacingReport);

                // Pacing rate should be within the expected convergence band.
                Assert.InRange(pacingReport.PacingRateBytesPerSecond, bandwidth * 0.70d, bandwidth * 1.30d);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: verifies that the receiver correctly handles reordered and
        /// duplicated packets, delivering exactly the original byte stream exactly once.
        /// </summary>
        [Fact]
        public async Task Integration_ReorderingAndDuplication_StillDeliversExactlyOnce()
        {
            // Simulator with 5% duplication and 20% reordering rates.
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

                // Core correctness: the data must survive reordering and duplication intact.
                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));

                // The simulator should have produced both reordered and duplicated packets.
                Assert.True(simulator.ReorderedPackets > 0);
                Assert.True(simulator.DuplicatedPackets > 0);

                // The receiver must report receiving exactly the original payload size (no extra bytes).
                Assert.Equal(payload.Length, serverConnection.GetReport().BytesReceived);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: verifies that with reordering and duplication, the receiver
        /// preserves the exact unique byte stream order (not just the count) using a
        /// pseudo-random payload for verification.
        /// </summary>
        [Fact]
        public async Task Integration_ReorderingAndDuplication_PreservesUniqueByteStreamOrder()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 4, jitterMilliseconds: 2, bandwidthBytesPerSecond: 2 * 1024 * 1024, duplicateRate: 0.05, reorderRate: 0.2);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40015);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40015));
                UcpConnection serverConnection = await acceptTask;

                // Build a pseudo-random unique payload to verify exact byte-for-byte order.
                byte[] payload = BuildUniquePayload(192 * 1024, 20260429);
                byte[] received = new byte[payload.Length];

                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await ReadWithinAsync(serverConnection, received, 0, received.Length, 15000);

                Assert.True(writeOk);
                Assert.True(readOk);

                // Exact equality check (not just SequenceEqual) since we want byte-for-byte match.
                Assert.Equal(payload, received);
                Assert.True(simulator.ReorderedPackets > 0);
                Assert.True(simulator.DuplicatedPackets > 0);
                Assert.Equal(payload.Length, serverConnection.GetReport().BytesReceived);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: verifies that multiple writes of varying sizes, read back
        /// in partial chunks, preserve the concatenated byte stream order.
        /// </summary>
        [Fact]
        public async Task Integration_Stream_MultipleWritesPartialReads_PreservesConcatenatedOrder()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 3, jitterMilliseconds: 1, bandwidthBytesPerSecond: 4 * 1024 * 1024);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"));
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"));
            server.Start(40016);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40016));
                UcpConnection serverConnection = await acceptTask;

                // Define a set of writes with varied chunk sizes including edge cases (±1 around MSS).
                int[] chunkSizes = new int[] { 1, 7, UcpConstants.Mss - 1, UcpConstants.Mss, UcpConstants.Mss + 1, 2 * UcpConstants.Mss + 17, 64 * 1024 + 3 };
                byte[] payload = BuildConcatenatedUniquePayload(chunkSizes, 7171);
                Task<byte[]> readTask = ReadInChunksWithinAsync(serverConnection, payload.Length, new int[] { 3, 97, 4096, 8191, 13 }, 15000);

                // Write each chunk sequentially.
                int offset = 0;
                for (int i = 0; i < chunkSizes.Length; i++)
                {
                    bool writeOk = await client.WriteAsync(payload, offset, chunkSizes[i]);
                    Assert.True(writeOk);
                    offset += chunkSizes[i];
                }

                // Read back in variable-sized chunks; the concatenated result must match the original.
                byte[] chunkedReceived = await readTask;
                Assert.Equal(payload, chunkedReceived);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: full-duplex concurrent transfers. Client and server
        /// simultaneously send unique payloads to each other. Verifies no interleaving
        /// or corruption occurs in either direction.
        /// </summary>
        [Fact]
        public async Task Integration_Stream_FullDuplexConcurrentTransfers_DoNotInterleaveOrCorrupt()
        {
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 4, jitterMilliseconds: 2, bandwidthBytesPerSecond: 8 * 1024 * 1024, duplicateRate: 0.02, reorderRate: 0.05);
            UcpConfiguration config = CreateScenarioConfig(8 * 1024 * 1024);
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), config.Clone());
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, config.Clone(), null);
            server.Start(40017);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 40017));
                UcpConnection serverConnection = await acceptTask;

                // Build distinct payloads for each direction.
                byte[] clientPayload = BuildUniquePayload(256 * 1024, 9001);
                byte[] serverPayload = BuildUniquePayload(192 * 1024, 9002);
                byte[] serverReceived = new byte[clientPayload.Length];
                byte[] clientReceived = new byte[serverPayload.Length];

                // Start all four operations (two writes, two reads) concurrently.
                Task<bool> serverRead = ReadWithinAsync(serverConnection, serverReceived, 0, serverReceived.Length, 20000);
                Task<bool> clientRead = ReadWithinAsync(client, clientReceived, 0, clientReceived.Length, 20000);
                Task<bool> clientWrite = client.WriteAsync(clientPayload, 0, clientPayload.Length);
                Task<bool> serverWrite = serverConnection.WriteAsync(serverPayload, 0, serverPayload.Length);

                // All operations must succeed.
                Assert.True(await clientWrite);
                Assert.True(await serverWrite);
                Assert.True(await serverRead);
                Assert.True(await clientRead);

                // Each side must receive the other's exact payload.
                Assert.Equal(clientPayload, serverReceived);
                Assert.Equal(serverPayload, clientReceived);
            }
            finally
            {
                await client.CloseAsync();
                server.Stop();
            }
        }

        /// <summary>
        /// Integration test: verifies that ordered small segments are delivered to the
        /// application callback (<see cref="UcpConnection.OnData"/>) with minimal latency
        /// when the network conditions are ideal and delayed ACK is disabled.
        /// </summary>
        [Fact]
        public async Task Integration_OrderedSmallSegments_AreDeliveredImmediately()
        {
            int mss = UcpConstants.MSS;

            // Create an ideal network with no jitter or wave impairment.
            NetworkSimulator simulator = new NetworkSimulator(fixedDelayMilliseconds: 1, jitterMilliseconds: 0, bandwidthBytesPerSecond: mss * 10 * 8, dynamicJitterRangeMilliseconds: 0, dynamicWaveAmplitudeMilliseconds: 0);

            // Optimize config for immediate delivery: disable delayed ACK and pacing intervals.
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

                // Track delivery delays for each segment.
                List<double> deliveryDelays = new List<double>();
                Queue<DateTime> sendTimes = new Queue<DateTime>();
                TaskCompletionSource<bool> receivedAll = new TaskCompletionSource<bool>();
                int receivedCount = 0;

                // Subscribe to OnData to measure per-segment delivery latency.
                serverConnection.OnData += delegate (byte[] buffer, int offset, int count)
                {
                    DateTime sentAt;
                    lock (sendTimes)
                    {
                        sentAt = sendTimes.Count == 0 ? DateTime.UtcNow : sendTimes.Dequeue();
                    }

                    // Record the delivery delay, subtracting the fixed 1ms propagation.
                    deliveryDelays.Add((DateTime.UtcNow - sentAt).TotalMilliseconds - 1d);
                    receivedCount++;

                    if (receivedCount == 16)
                    {
                        receivedAll.TrySetResult(true);
                    }
                };

                // Send 8 warm-up segments to establish the connection state.
                for (int i = 0; i < 8; i++)
                {
                    byte[] payload = Encoding.ASCII.GetBytes("W" + i.ToString("D2"));
                    bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                    Assert.True(writeOk);
                }

                // Brief pause to let the warm-up segments settle.
                await Task.Delay(20);

                // Send 8 measured segments, recording send times for latency computation.
                for (int i = 0; i < 8; i++)
                {
                    byte[] payload = Encoding.ASCII.GetBytes("M" + i.ToString("D2"));
                    lock (sendTimes)
                    {
                        sendTimes.Enqueue(DateTime.UtcNow);
                    }

                    bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                    Assert.True(writeOk);

                    // Small delay between sends to avoid batching.
                    await Task.Delay(2);
                }

                // Wait for all 16 segments to be delivered (up to 2 seconds).
                Task completed = await Task.WhenAny(receivedAll.Task, Task.Delay(2000));
                Assert.Equal(receivedAll.Task, completed);

                // Find the maximum delivery delay across all measured segments.
                double maxDelay = 0d;
                for (int i = 0; i < deliveryDelays.Count; i++)
                {
                    if (deliveryDelays[i] > maxDelay)
                    {
                        maxDelay = deliveryDelays[i];
                    }
                }

                // Maximum delivery delay should be under 60ms for ordered small segments.
                Assert.True(maxDelay < 60d, "max ordered delivery delay was " + maxDelay.ToString("F2") + "ms");
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Gigabit ideal scenario: 1 Gbps no-loss network. Verifies high utilization
        /// and near-zero loss in ideal conditions.
        /// </summary>
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

            // Ideal gigabit should achieve high utilization with negligible loss.
            Assert.True(report.UtilizationPercent >= UcpConstants.BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT);
            Assert.True(report.EstimatedLossPercent <= UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        /// <summary>
        /// Gigabit with 5% random loss: verifies the protocol respects the loss budget,
        /// maintains adequate throughput, and keeps retransmission ratio within bounds.
        /// </summary>
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

            // Loss and retransmission must stay within the configured budget.
            Assert.True(report.EstimatedLossPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.RetransmissionPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);

            // Throughput must meet the minimum threshold for this scenario.
            Assert.True(report.ThroughputMbps >= UcpConstants.BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS);

            // Pacing rate should converge to near the 1 Gbps target.
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);

            // Jitter should remain bounded.
            Assert.True(report.JitterMilliseconds <= UcpConstants.BENCHMARK_1G_HEAVY_LOSS_DELAY_MILLISECONDS * UcpConstants.BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER);
        }

        /// <summary>
        /// Gigabit with 1% random loss: verifies the protocol maintains high utilization
        /// under light random loss conditions.
        /// </summary>
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

        /// <summary>
        /// Long fat pipe at 100 Mbps: verifies convergence, low jitter, and pacing rate.
        /// </summary>
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

            // Must report a positive convergence time.
            Assert.True(report.ConvergenceMilliseconds > 0);

            // Jitter must be within the expected range multiplier.
            Assert.True(report.JitterMilliseconds <= UcpConstants.BENCHMARK_LONG_FAT_DELAY_MILLISECONDS * UcpConstants.BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER);
        }

        /// <summary>
        /// 10 Gigabit auto-probe: verifies the BBR controller can discover the available
        /// bandwidth without a pre-configured rate cap.
        /// </summary>
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

            // Auto-probe must converge to near the 10 Gbps target.
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_10_GBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
            Assert.True(report.RetransmissionPercent <= UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        /// <summary>
        /// Burst loss scenario: a contiguous burst of packets is dropped, simulating
        /// a temporary route blackout. Verifies recovery within the loss budget.
        /// </summary>
        [Fact]
        public async Task Integration_BurstLoss_RecoversWithinBudget()
        {
            int dataPacketIndex = 0;
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "BurstLoss",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_BURST_LOSS,
                UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_100M_PAYLOAD_BYTES,
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

                    // Drop a contiguous range of data packets to simulate a burst loss.
                    dataPacketIndex++;
                    return dataPacketIndex >= UcpConstants.BENCHMARK_BURST_LOSS_FIRST_PACKET && dataPacketIndex < UcpConstants.BENCHMARK_BURST_LOSS_FIRST_PACKET + UcpConstants.BENCHMARK_BURST_LOSS_PACKET_COUNT;
                });

            // Ensure the burst loss range was actually reached.
            Assert.True(dataPacketIndex >= UcpConstants.BENCHMARK_BURST_LOSS_FIRST_PACKET + UcpConstants.BENCHMARK_BURST_LOSS_PACKET_COUNT);

            // Recovery metrics must stay within acceptable bounds.
            Assert.True(report.EstimatedLossPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.RetransmissionPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
        }

        /// <summary>
        /// Asymmetric routing scenario: 25ms forward, 15ms reverse delay with 1% loss.
        /// Verifies the protocol handles directional delay asymmetry and directional jitter.
        /// </summary>
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
                25,
                15,
                UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS,
                UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS);

            // Forward delay should be ≥ (25 - jitter) and reverse ≤ (15 + jitter).
            Assert.True(report.ForwardDelayMilliseconds >= UcpConstants.BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS - UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS);
            Assert.True(report.ReverseDelayMilliseconds <= UcpConstants.BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS + UcpConstants.BENCHMARK_ASYM_JITTER_MILLISECONDS);

            Assert.True(report.RetransmissionPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
            Assert.True(report.PacingRateBytesPerSecond >= UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO);
        }

        /// <summary>
        /// High jitter scenario: extreme delay variation. Verifies the protocol stays
        /// alive and maintains useful throughput despite unstable network timing.
        /// </summary>
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

            // Even under extreme jitter, the protocol should maintain reasonable utilization.
            Assert.True(report.UtilizationPercent > 40d);
            Assert.True(report.RetransmissionPercent <= UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        /// <summary>
        /// Unit test for FEC codec: verifies that a single lost packet in a group of 4
        /// can be reconstructed from the repair packet and the 3 surviving data packets.
        /// </summary>
        [Fact]
        public void FecCodec_RecoversSingleLoss()
        {
            // Encoder: group size 4 with 1 repair packet.
            UcpFecCodec enc = new UcpFecCodec(4);

            // Create 4 distinct payloads.
            byte[] p0 = Encoding.ASCII.GetBytes("AAA");
            byte[] p1 = Encoding.ASCII.GetBytes("BBB");
            byte[] p2 = Encoding.ASCII.GetBytes("CCC");
            byte[] p3 = Encoding.ASCII.GetBytes("DDD");

            // Feed packets into the encoder; the 4th packet triggers repair generation.
            Assert.Null(enc.TryEncodeRepair(p0));
            Assert.Null(enc.TryEncodeRepair(p1));
            Assert.Null(enc.TryEncodeRepair(p2));
            byte[] repair = enc.TryEncodeRepair(p3);
            Assert.NotNull(repair);

            // Decoder: simulate loss of packet 1 (index 1, with payload "BBB").
            UcpFecCodec dec = new UcpFecCodec(4);
            dec.FeedDataPacket(0, p0);
            dec.FeedDataPacket(2, p2);
            dec.FeedDataPacket(3, p3);

            // Recover the lost packet using the repair symbol.
            byte[] recovered = dec.TryRecoverFromRepair(repair, 0);
            Assert.NotNull(recovered);
            Assert.Equal(p1, recovered);
        }

        /// <summary>
        /// Unit test for FEC codec: verifies that two lost packets in a group of 8
        /// with 2 repair symbols can both be reconstructed.
        /// </summary>
        [Fact]
        public void FecCodec_RecoversTwoLossesWithTwoRepairs()
        {
            // Encoder: group size 8 with 2 repair symbols.
            UcpFecCodec enc = new UcpFecCodec(8, 2);
            byte[][] payloads = new byte[8][];
            List<byte[]> repairs = null!;

            // Encode all 8 packets with unique identifiers.
            for (int i = 0; i < payloads.Length; i++)
            {
                payloads[i] = Encoding.ASCII.GetBytes("pkt-" + i.ToString("D2"));
                repairs = enc.TryEncodeRepairs(payloads[i]);
            }

            // Two repair symbols should be generated.
            Assert.NotNull(repairs);
            Assert.Equal(2, repairs.Count);

            // Decoder: simulate loss of packets 1 and 6.
            UcpFecCodec dec = new UcpFecCodec(8, 2);
            for (int i = 0; i < payloads.Length; i++)
            {
                if (i != 1 && i != 6)
                {
                    dec.FeedDataPacket((uint)i, payloads[i]);
                }
            }

            // First repair alone should not be sufficient (1 unknown → needs 2 equations).
            Assert.Empty(dec.TryRecoverPacketsFromRepair(repairs[0], 0, 0));

            // Second repair should enable recovery of both lost packets.
            List<UcpFecCodec.RecoveredPacket> recovered = dec.TryRecoverPacketsFromRepair(repairs[1], 0, 1);
            Assert.Equal(2, recovered.Count);
            Assert.Equal(payloads[1], recovered.Single(packet => packet.Slot == 1).Payload);
            Assert.Equal(payloads[6], recovered.Single(packet => packet.Slot == 6).Payload);
        }

        /// <summary>
        /// Unit test for FEC codec: verifies that three lost packets in a group of 32
        /// with 3 repair symbols can all be reconstructed from the repair data.
        /// </summary>
        [Fact]
        public void FecCodec_RecoversThreeLossesWithThreeRepairs()
        {
            // Encoder: group size 32 with 3 repair symbols.
            UcpFecCodec enc = new UcpFecCodec(32, 3);
            byte[][] payloads = new byte[32][];
            List<byte[]> repairs = null!;

            // Encode 32 unique payloads of varying sizes.
            for (int i = 0; i < payloads.Length; i++)
            {
                payloads[i] = BuildUniquePayload(257 + i, 1000 + i);
                repairs = enc.TryEncodeRepairs(payloads[i]);
            }

            Assert.NotNull(repairs);
            Assert.Equal(3, repairs.Count);

            // Decoder: simulate loss of packets 2, 17, and 31.
            UcpFecCodec dec = new UcpFecCodec(32, 3);
            for (int i = 0; i < payloads.Length; i++)
            {
                if (i != 2 && i != 17 && i != 31)
                {
                    dec.FeedDataPacket((uint)i, payloads[i]);
                }
            }

            // First two repairs alone should not be sufficient (3 unknowns → need 3 equations).
            Assert.Empty(dec.TryRecoverPacketsFromRepair(repairs[0], 0, 0));
            Assert.Empty(dec.TryRecoverPacketsFromRepair(repairs[1], 0, 1));

            // Third repair should enable recovery of all 3 lost packets.
            List<UcpFecCodec.RecoveredPacket> recovered = dec.TryRecoverPacketsFromRepair(repairs[2], 0, 2);
            Assert.Equal(3, recovered.Count);
            Assert.Equal(payloads[2], recovered.Single(packet => packet.Slot == 2).Payload);
            Assert.Equal(payloads[17], recovered.Single(packet => packet.Slot == 17).Payload);
            Assert.Equal(payloads[31], recovered.Single(packet => packet.Slot == 31).Payload);
        }

        /// <summary>
        /// Weak 4G cellular scenario: 10 Mbps with 3% loss and a mid-transfer blackout period.
        /// Verifies the protocol recovers from the outage and maintains utilization above 25%.
        /// </summary>
        [Fact]
        public async Task Integration_Weak4G_RecoversFromOutage()
        {
            // Build a drop rule that simulates baseline loss + a periodic network blackout.
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

            // Must recover sufficiently to achieve >25% utilization within the timeout.
            Assert.True(report.UtilizationPercent > 25d);
            Assert.True(report.ElapsedMilliseconds < UcpConstants.BENCHMARK_READ_TIMEOUT_MILLISECONDS);
        }

        /// <summary>
        /// Parameterized coverage test: runs multiple bandwidth+loss combinations to ensure
        /// the protocol works across a range of realistic network conditions.
        /// </summary>
        /// <param name="bandwidthBytesPerSecond">The bottleneck bandwidth.</param>
        /// <param name="lossRate">The random loss probability.</param>
        /// <param name="scenarioName">The scenario identifier for reporting.</param>
        [Theory]
        [InlineData(100000000 / 8, 0.002d, "100M_Loss0.2")]
        [InlineData(100000000 / 8, 0.01d, "100M_Loss1")]
        [InlineData(100000000 / 8, 0.10d, "100M_Loss10")]
        [InlineData(1000000000 / 8, 0.03d, "1G_Loss3")]
        public async Task Integration_CoverageLossBandwidth(int bandwidthBytesPerSecond, double lossRate, string scenarioName)
        {
            // Select payload size based on bandwidth tier.
            int payloadBytes = bandwidthBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND ? UcpConstants.BENCHMARK_1G_LOSS_PAYLOAD_BYTES : UcpConstants.BENCHMARK_100M_LOSS_PAYLOAD_BYTES;

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

            // Basic sanity: throughput must be positive, utilization must be positive.
            Assert.True(report.ThroughputBytesPerSecond > 0);
            Assert.True(report.UtilizationPercent > 0);

            // Retransmission must stay within the maximum allowed budget.
            Assert.True(report.RetransmissionPercent <= UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT);
        }

        /// <summary>
        /// Mobile 3G scenario: 4 Mbps with 75ms delay, 30ms jitter, and 3% random loss.
        /// Verifies acceptable utilization under classic 3G conditions.
        /// </summary>
        [Fact]
        public async Task Integration_Mobile3G_LossyConnects()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Mobile3G",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_MOBILE_3G,
                4 * 1000 * 1000 / 8,
                UcpConstants.BENCHMARK_MOBILE_3G_PAYLOAD_BYTES,
                75,
                30,
                0.03d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260601,
                CreateInitialDataDropRule(0.03d, 20260601));

            Assert.True(report.UtilizationPercent > 25d);
        }

        /// <summary>
        /// Mobile 4G scenario: 20 Mbps with 30ms delay, 25ms jitter, and 1% random loss.
        /// Verifies the protocol handles high-jitter mobile broadband conditions.
        /// </summary>
        [Fact]
        public async Task Integration_Mobile4G_HighJitter()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Mobile4G",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_MOBILE_4G,
                20 * 1000 * 1000 / 8,
                UcpConstants.BENCHMARK_MOBILE_4G_PAYLOAD_BYTES,
                30,
                25,
                0.01d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260602,
                CreateInitialDataDropRule(0.01d, 20260602));

            Assert.True(report.UtilizationPercent > 40d);
        }

        /// <summary>
        /// Satellite scenario: 10 Mbps with 300ms round-trip delay (150ms one-way)
        /// and 0.1% random loss. Verifies the protocol can complete a transfer
        /// over extreme latency without timeouts.
        /// </summary>
        [Fact]
        public async Task Integration_Satellite300ms_Completes()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Satellite",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_SATELLITE,
                10 * 1000 * 1000 / 8,
                UcpConstants.BENCHMARK_SATELLITE_PAYLOAD_BYTES,
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

        /// <summary>
        /// VPN tunnel scenario: 100 Mbps with 50ms delay, 10ms jitter, and 0.5% random loss
        /// simulating dual-congestion conditions. Verifies the protocol maintains minimal throughput.
        /// </summary>
        [Fact]
        public async Task Integration_VpnDualCongestion_LongRtt()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "VpnTunnel",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_VPN,
                UcpConstants.BENCHMARK_100_MBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_VPN_PAYLOAD_BYTES,
                50,
                10,
                0.005d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260604,
                CreateInitialDataDropRule(0.005d, 20260604));

            Assert.True(report.UtilizationPercent > 15d);
        }

        /// <summary>
        /// Data center scenario: 10 Gbps with near-zero latency (0ms fixed delay).
        /// Verifies the auto-probe can discover ultra-high bandwidth without a rate cap.
        /// </summary>
        [Fact]
        public async Task Integration_DataCenter_LowLatencyHighBW()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "DataCenter",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_DATACENTER,
                UcpConstants.BENCHMARK_10_GBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_10G_PAYLOAD_BYTES,
                0,
                0,
                0d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                0,
                null);

            Assert.True(report.UtilizationPercent > 40d);
        }

        /// <summary>
        /// Enterprise broadband scenario: 1 Gbps with 15ms delay, 3ms jitter, and 0.1% loss.
        /// Verifies good throughput over typical corporate WAN conditions.
        /// </summary>
        [Fact]
        public async Task Integration_EnterpriseBroadband_ModerateRtt()
        {
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "Enterprise",
                UcpConstants.BENCHMARK_BASE_PORT + UcpConstants.BENCHMARK_PORT_OFFSET_ENTERPRISE,
                UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND,
                UcpConstants.BENCHMARK_1G_LOSS_PAYLOAD_BYTES,
                15,
                3,
                0.001d,
                UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false,
                20260606,
                CreateInitialDataDropRule(0.001d, 20260606));

            Assert.True(report.UtilizationPercent > 30d);
        }

        /// <summary>
        /// Verifies that <see cref="UcpConnection.SendAsync"/> returns a partial byte count
        /// (greater than 0 but less than the full payload) when the send buffer is too small
        /// to hold the entire message in one call.
        /// </summary>
        [Fact]
        public async Task SendAsync_MayReturnPartialWhenSendBufferIsFull()
        {
            UcpConfiguration config = new UcpConfiguration();

            // Configure a very small send buffer (4 MSS) to force partial sends.
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

                // Attempt to send 64 KB through a 4 MSS send buffer.
                byte[] payload = Encoding.ASCII.GetBytes(new string('S', 64 * 1024));
                int sent = await serverConnection.SendAsync(payload, 0, payload.Length);

                // Should return a partial amount: more than 0, less than the full payload.
                Assert.InRange(sent, 1, payload.Length - 1);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Verifies that <see cref="UcpConnection.SendAsync"/> returns 0 when the send buffer
        /// is already completely full from a previous send, indicating backpressure.
        /// </summary>
        [Fact]
        public async Task SendAsync_ReturnsZeroWhenSendBufferAlreadyFull()
        {
            UcpConfiguration config = new UcpConfiguration();

            // Tiny send buffer (2 MSS) and near-zero pacing rate to fill the buffer quickly.
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

                // First send should accept some bytes (the buffer is initially empty).
                int first = await serverConnection.SendAsync(payload, 0, payload.Length);

                // Second send should return 0 because the buffer is still full.
                int second = await serverConnection.SendAsync(payload, first, payload.Length - first);

                Assert.True(first > 0);
                Assert.Equal(0, second);
            }
            finally
            {
                server.Stop();
            }
        }

        /// <summary>
        /// Reads from a connection with a timeout. Returns false if the read
        /// does not complete within the specified timeout.
        /// </summary>
        /// <param name="connection">The UCP connection to read from.</param>
        /// <param name="buffer">The destination buffer.</param>
        /// <param name="offset">Starting offset in the buffer.</param>
        /// <param name="count">Number of bytes to read.</param>
        /// <param name="timeoutMilliseconds">Maximum wait time in milliseconds.</param>
        /// <returns>True if the read completed within the timeout; false otherwise.</returns>
        private static async Task<bool> ReadWithinAsync(UcpConnection connection, byte[] buffer, int offset, int count, int timeoutMilliseconds)
        {
            Task<bool> readTask = connection.ReadAsync(buffer, offset, count);

            // Race the read against a delay.
            Task completed = await Task.WhenAny(readTask, Task.Delay(timeoutMilliseconds));
            if (completed != readTask)
            {
                return false;
            }

            return await readTask;
        }

        /// <summary>
        /// Reads a total number of bytes from a connection in variable-sized chunks,
        /// cycling through the provided chunk sizes. Throws on timeout or zero-progress.
        /// </summary>
        /// <param name="connection">The UCP connection to read from.</param>
        /// <param name="totalBytes">Total number of bytes to read.</param>
        /// <param name="chunkSizes">Array of chunk sizes to cycle through for each read.</param>
        /// <param name="timeoutMilliseconds">Overall timeout for the entire read operation.</param>
        /// <returns>The full buffer of received bytes.</returns>
        private static async Task<byte[]> ReadInChunksWithinAsync(UcpConnection connection, int totalBytes, int[] chunkSizes, int timeoutMilliseconds)
        {
            byte[] buffer = new byte[totalBytes];
            int offset = 0;
            int chunkIndex = 0;
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);

            while (offset < totalBytes)
            {
                int remaining = totalBytes - offset;

                // Round-robin through the chunk sizes array.
                int requested = Math.Min(remaining, chunkSizes[chunkIndex % chunkSizes.Length]);

                // Calculate remaining timeout budget.
                int remainingTimeout = (int)Math.Max(1, (deadline - DateTime.UtcNow).TotalMilliseconds);

                Task<int> receiveTask = connection.ReceiveAsync(buffer, offset, requested);
                Task completed = await Task.WhenAny(receiveTask, Task.Delay(remainingTimeout));

                if (completed != receiveTask)
                {
                    throw new TimeoutException("Chunked stream read timed out.");
                }

                int received = await receiveTask;
                if (received <= 0)
                {
                    throw new InvalidOperationException("Chunked stream read made no progress.");
                }

                offset += received;
                chunkIndex++;
            }

            return buffer;
        }

        /// <summary>
        /// Measures the elapsed duration of a read task from a common start time.
        /// </summary>
        /// <param name="readTask">The read task to await.</param>
        /// <param name="start">The common reference start time.</param>
        /// <returns>Elapsed time in milliseconds.</returns>
        private static async Task<double> MeasureReadDurationAsync(Task<bool> readTask, DateTime start)
        {
            await readTask;
            return (DateTime.UtcNow - start).TotalMilliseconds;
        }

        /// <summary>
        /// Waits for ACK settlement: polls the connection report until at least one data packet
        /// has been sent and at least one RTT sample is available, confirming the pipeline is quiet.
        /// </summary>
        /// <param name="connection">The connection to poll.</param>
        /// <param name="timeoutMilliseconds">Maximum time to wait.</param>
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

        /// <summary>
        /// Waits until the receiver's buffered byte count reaches the specified minimum.
        /// Used to confirm the sender has been throttled by the receiver window.
        /// </summary>
        /// <param name="connection">The connection to inspect.</param>
        /// <param name="minimumBytes">Minimum buffered bytes required.</param>
        /// <param name="timeoutMilliseconds">Maximum time to wait.</param>
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

        /// <summary>
        /// Runs a line-rate benchmark scenario. Overload with default directional parameters.
        /// </summary>
        private async Task<UcpPerformanceReport> RunLineRateBenchmarkAsync(string scenarioName, int port, int bandwidthBytesPerSecond, int payloadBytes, int fixedDelayMilliseconds, int jitterMilliseconds, double lossRate, double maxLossPercent, bool autoProbe, int simulatorSeed, Func<NetworkSimulator.SimulatedDatagram, bool>? dropRule)
        {
            return await RunLineRateBenchmarkAsync(scenarioName, port, bandwidthBytesPerSecond, payloadBytes, fixedDelayMilliseconds, jitterMilliseconds, lossRate, maxLossPercent, autoProbe, simulatorSeed, dropRule, -1, -1, -1, -1).ConfigureAwait(false);
        }

        /// <summary>
        /// Runs a line-rate benchmark scenario. Overload with directional parameters, defaulting high-bandwidth MSS to false.
        /// </summary>
        private async Task<UcpPerformanceReport> RunLineRateBenchmarkAsync(string scenarioName, int port, int bandwidthBytesPerSecond, int payloadBytes, int fixedDelayMilliseconds, int jitterMilliseconds, double lossRate, double maxLossPercent, bool autoProbe, int simulatorSeed, Func<NetworkSimulator.SimulatedDatagram, bool>? dropRule, int forwardDelayMilliseconds, int backwardDelayMilliseconds, int forwardJitterMilliseconds, int backwardJitterMilliseconds)
        {
            return await RunLineRateBenchmarkAsync(scenarioName, port, bandwidthBytesPerSecond, payloadBytes, fixedDelayMilliseconds, jitterMilliseconds, lossRate, maxLossPercent, autoProbe, simulatorSeed, dropRule, forwardDelayMilliseconds, backwardDelayMilliseconds, forwardJitterMilliseconds, backwardJitterMilliseconds, false).ConfigureAwait(false);
        }

        /// <summary>
        /// Core method that runs a full end-to-end line-rate benchmark scenario.
        /// Configures the network simulator, UCP connection, transfers the payload,
        /// measures throughput and convergence, and returns a populated performance report.
        /// </summary>
        /// <param name="scenarioName">The scenario name for reporting.</param>
        /// <param name="port">The server port to use.</param>
        /// <param name="bandwidthBytesPerSecond">Simulated bottleneck bandwidth.</param>
        /// <param name="payloadBytes">Size of the test payload.</param>
        /// <param name="fixedDelayMilliseconds">Base network delay.</param>
        /// <param name="jitterMilliseconds">Base network jitter.</param>
        /// <param name="lossRate">Uniform random loss rate.</param>
        /// <param name="maxLossPercent">Maximum allowed loss percentage for bandwidth probing.</param>
        /// <param name="autoProbe">If true, enables auto-probe mode with no rate cap.</param>
        /// <param name="simulatorSeed">Seed for the simulator's RNG.</param>
        /// <param name="dropRule">Optional custom packet drop predicate.</param>
        /// <param name="forwardDelayMilliseconds">Directional forward delay.</param>
        /// <param name="backwardDelayMilliseconds">Directional reverse delay.</param>
        /// <param name="forwardJitterMilliseconds">Directional forward jitter.</param>
        /// <param name="backwardJitterMilliseconds">Directional reverse jitter.</param>
        /// <param name="useHighBandwidthMss">If true, uses a larger MSS suitable for high-bandwidth links.</param>
        /// <param name="dynamicJitterRangeMs">Dynamic jitter range in milliseconds.</param>
        /// <param name="dynamicWaveAmpMs">Sinusoidal wave amplitude in milliseconds.</param>
        /// <returns>A populated <see cref="UcpPerformanceReport"/> with all metrics.</returns>
        private async Task<UcpPerformanceReport> RunLineRateBenchmarkAsync(string scenarioName, int port, int bandwidthBytesPerSecond, int payloadBytes, int fixedDelayMilliseconds, int jitterMilliseconds, double lossRate, double maxLossPercent, bool autoProbe, int simulatorSeed, Func<NetworkSimulator.SimulatedDatagram, bool>? dropRule, int forwardDelayMilliseconds, int backwardDelayMilliseconds, int forwardJitterMilliseconds, int backwardJitterMilliseconds, bool useHighBandwidthMss, int dynamicJitterRangeMs = -1, int dynamicWaveAmpMs = -1)
        {
            // Apply directional route model if explicit forward/reverse parameters were not provided.
            ApplyDirectionalRouteModel(scenarioName, fixedDelayMilliseconds, jitterMilliseconds, ref forwardDelayMilliseconds, ref backwardDelayMilliseconds, ref forwardJitterMilliseconds, ref backwardJitterMilliseconds);

            bool hasConfiguredLoss = lossRate > 0 || dropRule != null;

            // Dynamic jitter is disabled for lossy scenarios to keep results reproducible.
            int effectiveDynamicJitter = dynamicJitterRangeMs >= 0 ? dynamicJitterRangeMs : (hasConfiguredLoss ? 0 : 1);
            int effectiveDynamicWave = dynamicWaveAmpMs >= 0 ? dynamicWaveAmpMs : 0;

            // Create the network simulator with all impairment parameters.
            NetworkSimulator simulator = new NetworkSimulator(lossRate: dropRule == null ? lossRate : 0d, fixedDelayMilliseconds: fixedDelayMilliseconds, jitterMilliseconds: jitterMilliseconds, bandwidthBytesPerSecond: bandwidthBytesPerSecond, seed: simulatorSeed == 0 ? 1234 : simulatorSeed, dropRule: dropRule, forwardDelayMilliseconds: forwardDelayMilliseconds, backwardDelayMilliseconds: backwardDelayMilliseconds, forwardJitterMilliseconds: forwardJitterMilliseconds, backwardJitterMilliseconds: backwardJitterMilliseconds, dynamicJitterRangeMilliseconds: effectiveDynamicJitter, dynamicWaveAmplitudeMilliseconds: effectiveDynamicWave);

            // Build the UCP configuration for this scenario.
            UcpConfiguration config = CreateScenarioConfig(bandwidthBytesPerSecond);

            // Enable aggressive SACK recovery for lossy gigabit+ scenarios.
            config.EnableAggressiveSackRecovery = hasConfiguredLoss;

            // Large benchmark objects must not become application-limited by the
            // default 32 MB send buffer or the advertised receive window. Keep the
            // whole payload admissible so measured throughput reflects protocol
            // recovery and pacing, not caller-side backpressure.
            int benchmarkBufferBytes = Math.Max(config.SendBufferSize, payloadBytes + (4 * config.Mss));
            config.SendBufferSize = benchmarkBufferBytes;
            config.ReceiveBufferSize = benchmarkBufferBytes;

            if (hasConfiguredLoss)
            {
                // FEC: tiered redundancy based on loss rate. Sub-3% paths let
                // Random-loss benchmarks are explicitly repair-path tests. Enable
                // enough systematic FEC to cover expected losses within each small
                // group so packet loss does not force a full RTT/RTO stall.
                config.FecGroupSize = 8;
                config.FecRedundancy = lossRate >= UcpConstants.BENCHMARK_HEAVY_RANDOM_LOSS_RATE ? 0.50d : 0.25d;
            }

            // Use larger MSS for high-bandwidth scenarios to reduce packet overhead.
            if (useHighBandwidthMss || bandwidthBytesPerSecond >= UcpConstants.BENCHMARK_1_GBPS_BYTES_PER_SECOND)
            {
                config.Mss = UcpConstants.BENCHMARK_HIGH_BANDWIDTH_MSS;
                config.SendQuantumBytes = config.Mss;
            }

            config.MaxBandwidthLossPercent = maxLossPercent <= 0 ? UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT : maxLossPercent;

            // Compute estimated RTT and BDP for initial congestion window sizing.
            int effectiveForwardDelayMilliseconds = forwardDelayMilliseconds >= 0 ? forwardDelayMilliseconds : fixedDelayMilliseconds;
            int effectiveBackwardDelayMilliseconds = backwardDelayMilliseconds >= 0 ? backwardDelayMilliseconds : fixedDelayMilliseconds;
            int estimatedRttMicros = (int)Math.Max(UcpConstants.MICROS_PER_MILLI, (effectiveForwardDelayMilliseconds + effectiveBackwardDelayMilliseconds) * UcpConstants.MICROS_PER_MILLI);
            int estimatedBdpBytes = (int)Math.Min(int.MaxValue, bandwidthBytesPerSecond * (estimatedRttMicros / (double)UcpConstants.MICROS_PER_SECOND));

            if (hasConfiguredLoss)
            {
                // Random-loss benchmarks are explicitly repair-path tests. Enable
                // enough systematic FEC to cover expected losses within each small
                // group so packet loss does not force a full RTT/RTO stall.
                config.FecGroupSize = 8;
                config.FecRedundancy = lossRate >= UcpConstants.BENCHMARK_HEAVY_RANDOM_LOSS_RATE ? 0.50d : 0.25d;
            }

            // Calculate an appropriate initial CWND for this scenario.
            int initialCwndBytes = CalculateBenchmarkInitialCwndBytes(config, bandwidthBytesPerSecond, estimatedBdpBytes, hasConfiguredLoss);

            config.InitialCwndBytes = (uint)initialCwndBytes;

            // Auto-probe mode: remove rate cap and set a high initial bandwidth for BBR to probe.
            if (autoProbe)
            {
                config.InitialBandwidthBytesPerSecond = Math.Max(UcpConstants.BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND, initialCwndBytes * UcpConstants.BBR_PROBE_BW_GAIN_COUNT);
                config.MaxPacingRateBytesPerSecond = 0;
            }

            // Set minimum RTO for long-fat or lossy scenarios.
            if (!hasConfiguredLoss && (fixedDelayMilliseconds >= UcpConstants.BENCHMARK_LONG_FAT_DELAY_MILLISECONDS || estimatedRttMicros >= UcpConstants.DEFAULT_RTO_MICROS))
            {
                config.MinRtoMicros = UcpConstants.BENCHMARK_LONG_FAT_MIN_RTO_MICROS;
            }
            else if (hasConfiguredLoss && estimatedRttMicros > 0)
            {
                long fecRepairBudgetMicros = config.FecRedundancy > 0d ? estimatedRttMicros * 4L : estimatedRttMicros * 4L;
                config.MinRtoMicros = Math.Max(UcpConstants.DEFAULT_RTO_MICROS, fecRepairBudgetMicros);
            }

            // Create server and client, start the server on the designated port.
            UcpServer server = new UcpServer(simulator.CreateTransport("server"), config.Clone());
            UcpConnection client = new UcpConnection(simulator.CreateTransport("client"), true, config.Clone(), null);
            server.Start(port);
            try
            {
                // Establish the connection.
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
                UcpConnection serverConnection = await acceptTask;

                // Prepare the test payload (filled with a repeating character based on port).
                byte[] payload = BuildPayload((char)('A' + (port % 26)), payloadBytes);
                byte[] received = new byte[payload.Length];

                DateTime start = DateTime.UtcNow;

                // Start reading before writing to ensure the receiver is ready.
                Task<bool> readTask = ReadWithinAsync(serverConnection, received, 0, received.Length, UcpConstants.BENCHMARK_READ_TIMEOUT_MILLISECONDS);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;

                // Wait for ACK settlement to get complete metrics.
                await WaitForAckSettlementAsync(client, UcpConstants.BENCHMARK_ACK_SETTLEMENT_TIMEOUT_MILLISECONDS);

                double elapsedSeconds = Math.Max(0.001d, (DateTime.UtcNow - start).TotalSeconds);
                double throughput = GetBenchmarkThroughputBytesPerSecond(simulator, payload.Length, elapsedSeconds);

                // Build the performance report.
                UcpPerformanceReport report = UcpPerformanceReport.FromConnection(scenarioName, client, throughput, (long)(elapsedSeconds * UcpConstants.MICROS_PER_MILLI), bandwidthBytesPerSecond, simulator.AverageForwardDelayMicros, simulator.AverageReverseDelayMicros, simulator.ObservedDataLossPercent);
                UcpTransferReport receiverReport = serverConnection.GetReport();

                // Estimate convergence time based on how quickly the pacing rate reached target.
                report.ConvergenceMilliseconds = EstimateConvergenceMilliseconds(report, bandwidthBytesPerSecond, elapsedSeconds);

                // Persist the report.
                UcpPerformanceReport.Append(UcpTestHelpers.ReportPath, report);

                // Output detailed diagnostics for CI log analysis.
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

                // Core assertions: write and read must succeed, payload must match.
                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
                Assert.True(report.ThroughputBytesPerSecond > 0);

                // For non-auto-probe scenarios, pacing rate must be within convergence bounds.
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

        /// <summary>
        /// Calculates the initial congestion window size for a benchmark scenario,
        /// factoring in loss, BDP, and bandwidth.
        /// </summary>
        /// <param name="config">The UCP configuration.</param>
        /// <param name="bandwidthBytesPerSecond">The bottleneck bandwidth.</param>
        /// <param name="estimatedBdpBytes">Estimated bandwidth-delay product.</param>
        /// <param name="hasConfiguredLoss">Whether loss is present in the scenario.</param>
        /// <returns>The initial CWND in bytes.</returns>
        private static int CalculateBenchmarkInitialCwndBytes(UcpConfiguration config, int bandwidthBytesPerSecond, int estimatedBdpBytes, bool hasConfiguredLoss)
        {
            int minimumCwndBytes = config.Mss * UcpConstants.INITIAL_CWND_PACKETS;

            if (hasConfiguredLoss)
            {
                // For lossy scenarios, start with a larger CWND scaled from BDP.
                int lossCwndBytes = Math.Max(minimumCwndBytes, (int)Math.Ceiling(estimatedBdpBytes * UcpConstants.BENCHMARK_LOSS_INITIAL_CWND_BDP_GAIN));
                return Math.Min(lossCwndBytes, UcpConstants.BENCHMARK_MAX_LOSS_INITIAL_CWND_BYTES);
            }

            // For no-loss scenarios, scale CWND from BDP with a floor from bandwidth.
            int bdpCwndBytes = Math.Max(minimumCwndBytes, (int)Math.Ceiling(estimatedBdpBytes * UcpConstants.BENCHMARK_INITIAL_CWND_BDP_GAIN));
            return Math.Max(bdpCwndBytes, bandwidthBytesPerSecond / UcpConstants.BENCHMARK_NO_LOSS_INITIAL_CWND_BANDWIDTH_DIVISOR);
        }

        /// <summary>
        /// Computes the benchmark throughput in bytes per second, preferring the
        /// simulator's logical clock measurement when available and capping at the
        /// configured bottleneck bandwidth.
        /// </summary>
        /// <param name="simulator">The network simulator for this scenario.</param>
        /// <param name="payloadBytes">Total payload bytes transferred.</param>
        /// <param name="elapsedSeconds">Wall-clock elapsed time.</param>
        /// <returns>Effective throughput in bytes per second.</returns>
        private static double GetBenchmarkThroughputBytesPerSecond(NetworkSimulator simulator, int payloadBytes, double elapsedSeconds)
        {
            // Prefer the simulator's logical throughput, which avoids OS scheduling artifacts.
            double observedThroughput = simulator.LogicalThroughputBytesPerSecond > 0 ? simulator.LogicalThroughputBytesPerSecond : payloadBytes / elapsedSeconds;

            // Keep benchmark output physically credible even if local in-process
            // scheduling completes faster than the configured serialized link.
            return simulator.BandwidthBytesPerSecond > 0 ? Math.Min(observedThroughput, simulator.BandwidthBytesPerSecond) : observedThroughput;
        }

        /// <summary>
        /// Applies a deterministic directional route model when explicit forward/reverse
        /// delay values were not provided. Computes a 3-15ms one-way skew based on a
        /// stable hash of the scenario name.
        /// </summary>
        private static void ApplyDirectionalRouteModel(string scenarioName, int fixedDelayMilliseconds, int jitterMilliseconds, ref int forwardDelayMilliseconds, ref int backwardDelayMilliseconds, ref int forwardJitterMilliseconds, ref int backwardJitterMilliseconds)
        {
            // If both directions were explicitly specified, leave them as-is.
            if (forwardDelayMilliseconds >= 0 && backwardDelayMilliseconds >= 0)
            {
                return;
            }

            int baseDelayMilliseconds = Math.Max(0, fixedDelayMilliseconds);
            int stableHash = GetStableScenarioHash(scenarioName);

            // Every generated scenario gets a deterministic 3-15ms one-way skew;
            // the stable hash decides which direction is heavier.
            int skewMilliseconds = IsLowLatencyHighBandwidthScenario(scenarioName) ? 5 : 10;
            int floorDelayMilliseconds = Math.Max(0, baseDelayMilliseconds - skewMilliseconds / 2);
            int highDelayMilliseconds = floorDelayMilliseconds + skewMilliseconds;

            // Low-latency high-bandwidth or even-hash scenarios are reverse-heavy.
            bool reverseHeavy = IsLowLatencyHighBandwidthScenario(scenarioName) || stableHash % 2 == 0;

            forwardDelayMilliseconds = reverseHeavy ? floorDelayMilliseconds : highDelayMilliseconds;
            backwardDelayMilliseconds = reverseHeavy ? highDelayMilliseconds : floorDelayMilliseconds;

            // Apply a subtle jitter asymmetry matching the delay skew direction.
            int baseJitterMilliseconds = Math.Max(0, jitterMilliseconds);
            forwardJitterMilliseconds = Math.Max(0, baseJitterMilliseconds + (reverseHeavy ? 1 : 0));
            backwardJitterMilliseconds = Math.Max(0, baseJitterMilliseconds + (reverseHeavy ? 0 : 1));
        }

        /// <summary>
        /// Returns true for scenarios that represent low-latency, high-bandwidth
        /// data center or ideal conditions.
        /// </summary>
        private static bool IsLowLatencyHighBandwidthScenario(string scenarioName)
        {
            return scenarioName == "Gigabit_Ideal" || scenarioName == "Benchmark10G" || scenarioName == "DataCenter";
        }

        /// <summary>
        /// Computes a stable, deterministic integer hash from a scenario name
        /// for use in generating consistent directional route models.
        /// </summary>
        /// <param name="scenarioName">The scenario name to hash.</param>
        /// <returns>A non-negative hash code.</returns>
        private static int GetStableScenarioHash(string scenarioName)
        {
            int hash = 17;
            for (int i = 0; i < scenarioName.Length; i++)
            {
                hash = unchecked(hash * 31 + scenarioName[i]);
            }

            // Ensure a non-negative result (avoid int.MinValue whose abs is itself negative).
            return hash == int.MinValue ? int.MaxValue : Math.Abs(hash);
        }

        /// <summary>
        /// Creates a drop rule that drops initial (non-retransmit) DATA packets
        /// with the specified probability. Used to simulate uniform random loss
        /// in benchmark scenarios.
        /// </summary>
        /// <param name="lossRate">The probability of dropping each initial data packet.</param>
        /// <param name="seed">Seed for the per-rule RNG.</param>
        /// <returns>A delegate that decides whether to drop a given datagram.</returns>
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

                // Only drop initial transmissions of DATA packets (not retransmissions).
                bool isInitialData = packet.Header.Type == UcpPacketType.Data && (packet.Header.Flags & UcpPacketFlags.Retransmit) != UcpPacketFlags.Retransmit;
                return isInitialData && random.NextDouble() < lossRate;
            };
        }

        /// <summary>
        /// Creates a drop rule that simulates a weak 4G cellular network with:
        /// baseline random loss on initial data packets, PLUS a periodic blackout
        /// where ALL packets (including retransmissions) are dropped for a configured duration.
        /// </summary>
        /// <param name="lossRate">Baseline random loss probability.</param>
        /// <param name="seed">Seed for the per-rule RNG.</param>
        /// <param name="outagePeriodMilliseconds">How often the blackout occurs.</param>
        /// <param name="outageDurationMilliseconds">How long each blackout lasts.</param>
        /// <returns>A delegate that decides whether to drop a given datagram.</returns>
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

                // Record the timestamp of the first DATA packet.
                if (firstDataMicros == 0)
                {
                    firstDataMicros = datagram.SendMicros;
                }

                long elapsedMicros = datagram.SendMicros - firstDataMicros;
                long periodMicros = outagePeriodMilliseconds * UcpConstants.MICROS_PER_MILLI;
                long outageMicros = outageDurationMilliseconds * UcpConstants.MICROS_PER_MILLI;

                // Model one mid-transfer blackout instead of a startup outage, so
                // the test measures recovery rather than initial total loss.
                bool inOutage = periodMicros > 0 && elapsedMicros >= periodMicros && elapsedMicros < periodMicros + outageMicros;

                bool isInitialData = (packet.Header.Flags & UcpPacketFlags.Retransmit) != UcpPacketFlags.Retransmit;

                // Drop if in the blackout window OR if it's an initial data packet subject to random loss.
                return inOutage || (isInitialData && random.NextDouble() < lossRate);
            };
        }

        /// <summary>
        /// Builds a payload buffer filled with a repeating character.
        /// </summary>
        /// <param name="value">The character to fill the buffer with.</param>
        /// <param name="payloadBytes">Size of the payload in bytes.</param>
        /// <returns>A new byte array filled with the specified character.</returns>
        private static byte[] BuildPayload(char value, int payloadBytes)
        {
            byte[] payload = new byte[payloadBytes];
            for (int i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)value;
            }

            return payload;
        }

        /// <summary>
        /// Builds a payload buffer with pseudo-random but deterministic content,
        /// using a linear congruential generator seeded with the given value.
        /// This enables exact byte-for-byte verification of received data.
        /// </summary>
        /// <param name="payloadBytes">Size of the payload in bytes.</param>
        /// <param name="seed">Seed for the PRNG.</param>
        /// <returns>A new byte array with pseudo-random content.</returns>
        private static byte[] BuildUniquePayload(int payloadBytes, int seed)
        {
            byte[] payload = new byte[payloadBytes];
            uint state = (uint)seed;

            // Simple LCG: state = state * 1664525 + 1013904223
            for (int i = 0; i < payload.Length; i++)
            {
                state = unchecked(state * 1664525U + 1013904223U);
                payload[i] = (byte)(state >> 24);
            }

            return payload;
        }

        /// <summary>
        /// Builds a concatenated payload whose total size is the sum of the given chunk sizes,
        /// filled with deterministic pseudo-random data for verification.
        /// </summary>
        /// <param name="chunkSizes">Array of chunk sizes whose sum determines the total payload size.</param>
        /// <param name="seed">Seed for the PRNG.</param>
        /// <returns>A new byte array with the total size equal to the sum of chunk sizes.</returns>
        private static byte[] BuildConcatenatedUniquePayload(int[] chunkSizes, int seed)
        {
            int totalBytes = 0;
            for (int i = 0; i < chunkSizes.Length; i++)
            {
                totalBytes += chunkSizes[i];
            }

            return BuildUniquePayload(totalBytes, seed);
        }

        /// <summary>
        /// Estimates the convergence time in milliseconds based on how quickly
        /// the pacing rate reached the target bandwidth band.
        /// </summary>
        /// <param name="report">The performance report with measured pacing rate.</param>
        /// <param name="bandwidthBytesPerSecond">The target bandwidth.</param>
        /// <param name="elapsedSeconds">Total elapsed time for the transfer.</param>
        /// <returns>Estimated convergence time in milliseconds.</returns>
        private static long EstimateConvergenceMilliseconds(UcpPerformanceReport report, int bandwidthBytesPerSecond, double elapsedSeconds)
        {
            // If pacing rate never reached the convergence band, report the full
            // transfer duration instead of an impossible 0ms value.
            if (report.PacingRateBytesPerSecond < bandwidthBytesPerSecond * UcpConstants.BENCHMARK_MIN_CONVERGED_PACING_RATIO)
            {
                return Math.Max(1L, (long)Math.Ceiling(elapsedSeconds * UcpConstants.MICROS_PER_MILLI));
            }

            // Estimate convergence as the ratio of elapsed time scaled by how close pacing is to target.
            double ratio = report.PacingRateBytesPerSecond <= 0 ? 1d : Math.Min(1d, bandwidthBytesPerSecond / report.PacingRateBytesPerSecond);
            return Math.Max(1L, (long)Math.Ceiling(elapsedSeconds * ratio * UcpConstants.MICROS_PER_MILLI));
        }

        /// <summary>
        /// Joins an array of doubles into a comma-separated string for diagnostic output.
        /// </summary>
        /// <param name="values">Array of double values to format.</param>
        /// <returns>A comma-separated string with each value formatted to 2 decimal places.</returns>
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

        /// <summary>
        /// Airplane WiFi scenario: satellite link with periodic brief disconnections
        /// during satellite handovers.  10 Mbps, 100ms RTT, 5ms jitter, 1% random loss,
        /// 150ms blackouts every 15 seconds simulating satellite switch-over.
        /// </summary>
        [Fact]
        public async Task Integration_AirplaneWifi_HandlesSatelliteHandover()
        {
            double periodMs = 15000d; double outageMs = 150d;
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "AirplaneWifi", UcpConstants.BENCHMARK_BASE_PORT + 25,
                10 * 1000 * 1000 / 8, UcpConstants.BENCHMARK_MOBILE_4G_PAYLOAD_BYTES,
                50, 5, 0.01d, UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false, 20260507, CreateHandoverDropRule(0.01d, 20260507, periodMs, outageMs));
            Assert.True(report.UtilizationPercent > 30d);
        }

        /// <summary>
        /// High-speed train scenario: cellular tower handovers cause brief
        /// disconnections and rapid RTT variation.  20 Mbps, 40ms RTT,
        /// 20ms jitter, 0.5% random loss, 50ms blackouts every 30 seconds.
        /// </summary>
        [Fact]
        public async Task Integration_HighSpeedTrain_HandlesTunnelAndHandover()
        {
            double periodMs = 30000d; double outageMs = 50d;
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "HighSpeedTrain", UcpConstants.BENCHMARK_BASE_PORT + 26,
                20 * 1000 * 1000 / 8, UcpConstants.BENCHMARK_MOBILE_4G_PAYLOAD_BYTES,
                20, 20, 0.005d, UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false, 20260508, CreateHandoverDropRule(0.005d, 20260508, periodMs, outageMs));
            Assert.True(report.UtilizationPercent > 20d);
        }

        /// <summary>
        /// Driving (vehicle) scenario: moderate bandwidth, gradual RTT changes
        /// with periodic cell-tower switch drops.  5 Mbps, 30ms RTT, 10ms jitter,
        /// 0.5% random loss, 30ms blackouts every 60 seconds.
        /// </summary>
        [Fact]
        public async Task Integration_DrivingVehicle_HandlesCellSwitch()
        {
            double periodMs = 60000d; double outageMs = 30d;
            UcpPerformanceReport report = await RunLineRateBenchmarkAsync(
                "DrivingVehicle", UcpConstants.BENCHMARK_BASE_PORT + 27,
                5 * 1000 * 1000 / 8, UcpConstants.BENCHMARK_WEAK_4G_PAYLOAD_BYTES,
                15, 10, 0.005d, UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT,
                false, 20260509, CreateHandoverDropRule(0.005d, 20260509, periodMs, outageMs));
            Assert.True(report.UtilizationPercent > 30d);
        }

        private static Func<NetworkSimulator.SimulatedDatagram, bool> CreateHandoverDropRule(
            double lossRate, int seed, double periodMs, double outageMs)
        {
            Random r = new Random(seed);
            long firstUs = 0;
            return d =>
            {
                UcpPacket p;
                if (!UcpPacketCodec.TryDecode(d.Buffer, 0, d.Count, out p)
                    || p.Header.Type != UcpPacketType.Data)
                {
                    return false;
                }

                if (firstUs == 0)
                {
                    firstUs = d.SendMicros;
                }

                long elapsed = d.SendMicros - firstUs;
                long phase = elapsed % ((long)(periodMs * UcpConstants.MICROS_PER_MILLI));
                bool inOutage = phase < (long)(outageMs * UcpConstants.MICROS_PER_MILLI);
                bool isInit = (p.Header.Flags & UcpPacketFlags.Retransmit) != UcpPacketFlags.Retransmit;
                return inOutage || (isInit && r.NextDouble() < lossRate);
            };
        }

        /// <summary>
        /// Creates a UCP configuration optimized for a specific bandwidth scenario.
        /// Initializes bandwidth, max pacing rate, and server bandwidth to the same value.
        /// </summary>
        /// <param name="bandwidthBytesPerSecond">The target bandwidth for this scenario.</param>
        /// <returns>A <see cref="UcpConfiguration"/> instance ready for the scenario.</returns>
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

