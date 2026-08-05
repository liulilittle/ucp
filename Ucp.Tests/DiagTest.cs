using System;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ucp;
using UcpTest.TestTransport;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class DiagTest
    {
        private readonly ITestOutputHelper _output;
        public DiagTest(ITestOutputHelper output) { _output = output; }

        [Fact]
        public async Task Diag_SimpleSendReceive()
        {
            var listener = new ForwardingTraceListener(_output);
            Trace.Listeners.Add(listener);
            try { await RunDiag("1M_noLoss", 1000000, 64 * 1024, 5, 0, _output); }
            finally { Trace.Listeners.Remove(listener); listener.Dispose(); }
        }

        [Fact]
        public async Task Diag_HighBandwidthNoLoss()
        {
            var listener = new ForwardingTraceListener(_output);
            Trace.Listeners.Add(listener);
            try { await RunDiag("125M_noLoss", 125000000, 512 * 1024, 5, 0, _output); }
            finally { Trace.Listeners.Remove(listener); listener.Dispose(); }
        }

        [Fact]
        public async Task Diag_HighBandwidthWithLoss()
        {
            var listener = new ForwardingTraceListener(_output);
            Trace.Listeners.Add(listener);
            try { await RunDiag("125M_loss3", 125000000, 256 * 1024, 5, 0.03d, _output); }
            finally { Trace.Listeners.Remove(listener); listener.Dispose(); }
        }

        private static int _nextPort = 41000;

        private static async Task RunDiag(string name, int bandwidth, int payloadSize, int delayMs, double lossRate, ITestOutputHelper output)
        {
            UcpConfiguration config = UcpConfiguration.GetOptimizedConfig();
            config.InitialBandwidthBytesPerSecond = bandwidth;
            config.MaxPacingRateBytesPerSecond = bandwidth;
            config.ServerBandwidthBytesPerSecond = bandwidth;
            config.EnableDebugLog = lossRate <= 0.01d;
            if (lossRate > 0)
            {
                config.FecGroupSize = 8;
                config.FecRedundancy = 0.25d;
            }

            int port = Interlocked.Increment(ref _nextPort);
            var simulator = new NetworkSimulator(fixedDelayMilliseconds: delayMs, bandwidthBytesPerSecond: bandwidth, lossRate: lossRate);
            var server = new UcpServer(simulator.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(simulator.CreateTransport("client"), true, config.Clone(), null);
            server.Start(port);

            UcpConnection? serverConn = null;
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
                serverConn = await acceptTask;

                var clientDiag = client.GetDiagnostics();
                var serverDiag = serverConn.GetDiagnostics();
                output.WriteLine($"[{name}] Client state={clientDiag.State} Server state={serverDiag.State}");

                byte[] payload = Encoding.ASCII.GetBytes(new string('M', payloadSize));
                byte[] received = new byte[payload.Length];

                int timeoutMs = 30000;
                Task<bool> readTask = ReadWithinAsync(serverConn, received, 0, received.Length, timeoutMs);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                output.WriteLine($"[{name}] Write completed: {writeOk}");

                bool readOk = await readTask;
                output.WriteLine($"[{name}] Read completed: {readOk}");

                // The simulator scheduler thread delivers ACKs asynchronously;
                // the read completing does not guarantee the final ACK's RTT
                // sample has been recorded yet.  Poll briefly for it.
                var report = client.GetReport();
                int pollMs = 5000;
                while (report.RttSamplesMicros.Count == 0 && pollMs > 0)
                {
                    await Task.Delay(25);
                    report = client.GetReport();
                    pollMs -= 25;
                }
                output.WriteLine($"[{name}] Client report: dataPkts={report.DataPacketsSent} retrans={report.RetransmittedPackets} ack={report.AckPacketsSent} rtt={report.RttSamplesMicros.Count} pacing={report.PacingRateBytesPerSecond}");

                var serverReport = serverConn.GetReport();
                output.WriteLine($"[{name}] Server report: ack={serverReport.AckPacketsSent} nak={serverReport.NakPacketsSent} bytes={serverReport.BytesReceived} rtt={serverReport.RttSamplesMicros.Count}");

                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.Equal(payload, received);
                double throughputBps = simulator.LogicalThroughputBytesPerSecond;
                Assert.True(throughputBps > 0,
                    $"Throughput should be positive: {throughputBps}");
                Assert.True(report.RttSamplesMicros.Count > 0,
                    $"RTT sample count should be > 0: {report.RttSamplesMicros.Count}");

                double minThroughputRatio;
                if (name == "1M_noLoss")
                    minThroughputRatio = 0.20;
                else if (name == "125M_noLoss")
                    minThroughputRatio = 0.05;
                else if (name == "125M_loss3")
                    minThroughputRatio = 0.01;
                else
                    minThroughputRatio = 0.01;

                double minBps = bandwidth * minThroughputRatio;
                Assert.True(throughputBps >= minBps,
                    $"[{name}] Throughput {throughputBps:F0}B/s should be >= {minBps:F0}B/s ({minThroughputRatio * 100:F1}% of {bandwidth}B/s)");
            }
            finally
            {
                if (serverConn != null)
                    await UcpTestHelpers.CloseWithTimeout(serverConn);
                await UcpTestHelpers.CloseWithTimeout(client);
                server.Stop();
            }
        }

        private static async Task<bool> ReadWithinAsync(UcpConnection connection, byte[] buffer, int offset, int count, int timeoutMs)
        {
            Task<bool> readTask = connection.ReadAsync(buffer, offset, count);
            Task completed = await Task.WhenAny(readTask, Task.Delay(timeoutMs));
            if (completed != readTask) return false;
            return await readTask;
        }
    }

    internal sealed class ForwardingTraceListener : TraceListener
    {
        private readonly ITestOutputHelper _output;
        public ForwardingTraceListener(ITestOutputHelper output) { _output = output; }
        public override void Write(string? message)
        {
            try { _output.WriteLine(message ?? ""); } catch (InvalidOperationException) { }
        }
        public override void WriteLine(string? message)
        {
            try { _output.WriteLine(message ?? ""); } catch (InvalidOperationException) { }
        }
    }
}
