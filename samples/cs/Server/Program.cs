using System.Net;
using Ucp;

const int DefaultPort = 9000;
const int DefaultBandwidthMbps = 100;

int port = DefaultPort;
int bandwidthMbps = DefaultBandwidthMbps;

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--port" && i + 1 < args.Length)
    {
        port = int.Parse(args[++i]);
    }
    else if (args[i] == "--bandwidth" && i + 1 < args.Length)
    {
        bandwidthMbps = int.Parse(args[++i]);
    }
    else if (args[i] == "--help" || args[i] == "-h")
    {
        Console.WriteLine("Usage: Server [--port <port>] [--bandwidth <Mbps>] [--help]");
        Console.WriteLine($"  --port       Listen port (default: {DefaultPort})");
        Console.WriteLine($"  --bandwidth  Server bandwidth limit in Mbps (default: {DefaultBandwidthMbps})");
        return;
    }
}

int bandwidthBytesPerSec = bandwidthMbps * 1000000 / 8;

var config = UcpConfiguration.GetOptimizedConfig();
config.ServerBandwidthBytesPerSecond = bandwidthBytesPerSec;
config.InitialBandwidthBytesPerSecond = bandwidthBytesPerSec;
config.MaxPacingRateBytesPerSecond = bandwidthBytesPerSec;
config.SendBufferSize = 64 * 1024 * 1024;
config.ReceiveBufferSize = 64 * 1024 * 1024;

using var server = new UcpServer(config);
server.Start(port);
Console.WriteLine($"UCP Echo Server listening on port {port} ({bandwidthMbps} Mbps)");
Console.WriteLine("Press Ctrl+C to stop.");

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
    Console.WriteLine("\nShutting down...");
};

try
{
    while (!cts.IsCancellationRequested)
    {
        using var ctsAccept = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
        var acceptTask = server.AcceptAsync();
        var completed = await Task.WhenAny(acceptTask, Task.Delay(Timeout.Infinite, ctsAccept.Token));

        if (completed == acceptTask)
        {
            var conn = await acceptTask;
            string remoteStr = conn.RemoteEndPoint?.ToString() ?? "";
            if (string.IsNullOrEmpty(remoteStr) || remoteStr == "0.0.0.0:0" || remoteStr.Contains("unknown"))
                remoteStr = $"<cid:{conn.ConnectionId:X8}>";
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Accepted connection {conn.ConnectionId:X8} from {remoteStr}");
            _ = HandleConnectionAsync(conn).ContinueWith(t => {
                if (t.IsFaulted) Console.Error.WriteLine($"Unhandled connection error: {t.Exception?.InnerException?.Message}");
            });
        }
    }
}
catch (OperationCanceledException)
{

}

Console.WriteLine("Server stopped.");

static async Task HandleConnectionAsync(UcpConnection conn)
{
    try
    {
        long totalBytes = 0;
        var buf = new byte[65536];
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var lastPrint = stopwatch.Elapsed;

        while (true)
        {
            int n = await conn.ReceiveAsync(buf, 0, buf.Length);
            if (n <= 0)
            {
                break;
            }

            totalBytes += n;

            bool sent = await conn.WriteAsync(buf, 0, n);
            if (!sent)
            {
                break;
            }

            if (stopwatch.Elapsed - lastPrint > TimeSpan.FromSeconds(5))
            {
                lastPrint = stopwatch.Elapsed;
                var report = conn.GetReport();
                double elapsedSec = stopwatch.Elapsed.TotalSeconds;
                double throughputMbps = totalBytes * 8.0 / elapsedSec / 1000000.0;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Conn {conn.ConnectionId:X8}: {totalBytes / 1024.0 / 1024.0:F2} MB transferred, " +
                    $"{throughputMbps:F2} Mbps, last RTT {report.LastRttMicros / 1000.0:F2} ms, " +
                    $"CWND {report.CongestionWindowBytes} B, Retrans {report.RetransmissionRatio:P1}");
            }
        }

        stopwatch.Stop();
        var finalReport = conn.GetReport();
        double elapsedTotal = stopwatch.Elapsed.TotalSeconds;
        double avgThroughput = elapsedTotal > 0 ? totalBytes * 8.0 / elapsedTotal / 1000000.0 : 0;
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Conn {conn.ConnectionId:X8} closed: {totalBytes / 1024.0 / 1024.0:F2} MB in {elapsedTotal:F2}s, " +
            $"{avgThroughput:F2} Mbps, last RTT {finalReport.LastRttMicros / 1000.0:F2} ms, " +
            $"Retrans {finalReport.RetransmissionRatio:P1}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Conn {conn.ConnectionId:X8} error: {ex.Message}");
    }
    finally
    {
        try { await conn.CloseAsync(); } catch (Exception ex) { Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Conn close error: {ex.Message}"); }
    }
}
