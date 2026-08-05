using System.Net;
using Ucp;

const int DefaultPort = 9000;
const long DefaultDataBytes = 256 * 1024;
const int DefaultDataMb = 1;
const int MaxDataMb = 100;
const int DefaultBandwidthMbps = 100;
const string DefaultHost = "127.0.0.1";

string host = DefaultHost;
int port = DefaultPort;
int dataMb = DefaultDataMb;
int bandwidthMbps = DefaultBandwidthMbps;

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--host" && i + 1 < args.Length)
    {
        host = args[++i];
    }
    else if (args[i] == "--port" && i + 1 < args.Length)
    {
        port = int.Parse(args[++i]);
    }
    else if (args[i] == "--size" && i + 1 < args.Length)
    {
        dataMb = int.Parse(args[++i]);
    }
    else if (args[i] == "--bandwidth" && i + 1 < args.Length)
    {
        bandwidthMbps = int.Parse(args[++i]);
    }
    else if (args[i] == "--help" || args[i] == "-h")
    {
        Console.WriteLine("Usage: Client [--host <host>] [--port <port>] [--size <MB>] [--bandwidth <Mbps>] [--help]");
        Console.WriteLine($"  --host      Server host (default: {DefaultHost})");
        Console.WriteLine($"  --port      Server port (default: {DefaultPort})");
        Console.WriteLine($"  --size      Data size in MB to send (default: {DefaultDataBytes / 1024} KB, max: {MaxDataMb} MB)");
        Console.WriteLine($"  --bandwidth Expected bandwidth in Mbps (default: {DefaultBandwidthMbps})");
        return;
    }
}

if (dataMb > MaxDataMb)
{
    Console.WriteLine($"Warning: --size capped at {MaxDataMb} MB (requested {dataMb} MB)");
    dataMb = MaxDataMb;
}

int bandwidthBytesPerSec = bandwidthMbps * 1000000 / 8;
long totalBytes = dataMb > 0 ? (long)dataMb * 1024 * 1024 : DefaultDataBytes;

var config = UcpConfiguration.GetOptimizedConfig();
config.ServerBandwidthBytesPerSecond = bandwidthBytesPerSec;
config.InitialBandwidthBytesPerSecond = bandwidthBytesPerSec;
config.MaxPacingRateBytesPerSecond = bandwidthBytesPerSec;
config.SendBufferSize = (int)Math.Max(64 * 1024 * 1024, totalBytes * 2);
config.ReceiveBufferSize = (int)Math.Max(64 * 1024 * 1024, totalBytes * 2);

Console.WriteLine($"Connecting to {host}:{port}...");

using var client = new UcpConnection(config);
var remote = new IPEndPoint(IPAddress.Parse(host), port);

var stopwatch = System.Diagnostics.Stopwatch.StartNew();

await client.ConnectAsync(remote);
Console.WriteLine($"Connected (ConnId={client.ConnectionId:X8}), sending {totalBytes / 1024.0 / 1024.0:F2} MB ({totalBytes} bytes)...");

var sendData = new byte[(int)totalBytes];
new Random(42).NextBytes(sendData);
var recvBuf = new byte[(int)totalBytes];

var sendTask = client.WriteAsync(sendData, 0, sendData.Length);

int totalReceived = 0;
var recvStopwatch = System.Diagnostics.Stopwatch.StartNew();
var nextProgressTick = TimeSpan.Zero;
var recvOverallDeadline = TimeSpan.FromSeconds(60);

while (totalReceived < totalBytes)
{

    if (recvStopwatch.Elapsed - nextProgressTick > TimeSpan.FromSeconds(5))
    {
        nextProgressTick = recvStopwatch.Elapsed;
        double pct = 100.0 * totalReceived / totalBytes;
        Console.WriteLine($"  Progress: {totalReceived} / {totalBytes} bytes ({pct:F1}%)");
    }

    if (recvStopwatch.Elapsed > recvOverallDeadline)
    {
        Console.WriteLine($"ERROR: Receive overall deadline exceeded after {totalReceived} of {totalBytes} bytes");
        return;
    }

    using var receiveCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    int n = await client.ReceiveAsync(recvBuf, totalReceived, (int)(totalBytes - totalReceived))
        .WaitAsync(receiveCts.Token);
    if (n <= 0)
    {
        break;
    }
    totalReceived += n;
}

await sendTask;
stopwatch.Stop();

if (totalReceived != totalBytes)
{
    Console.WriteLine($"ERROR: Received {totalReceived} bytes, expected {totalBytes}");
    return;
}

bool verified = sendData.AsSpan().SequenceEqual(recvBuf.AsSpan());
Console.WriteLine(verified ? "Data verification: PASS" : "Data verification: FAIL");

double elapsedSec = stopwatch.Elapsed.TotalSeconds;
double throughputMbps = totalBytes * 8.0 / elapsedSec / 1000000.0;
var report = client.GetReport();

Console.WriteLine();
Console.WriteLine("=== Transfer Statistics ===");
Console.WriteLine($"  Data sent:     {totalBytes / 1024.0 / 1024.0:F2} MB");
Console.WriteLine($"  Data received: {totalReceived / 1024.0 / 1024.0:F2} MB");
Console.WriteLine($"  Elapsed:       {elapsedSec:F3} s");
Console.WriteLine($"  Throughput:    {throughputMbps:F2} Mbps");
Console.WriteLine($"  RTT:           {report.LastRttMicros / 1000.0:F2} ms (last), {GetAverageRtt(report):F2} ms (avg)");
Console.WriteLine($"  CWND:          {report.CongestionWindowBytes} B");
Console.WriteLine($"  Current rate:  {report.MeasuredBandwidthBytesPerSecond * 8.0 / 1000000.0:F2} Mbps");
Console.WriteLine($"  Pacing rate:   {report.PacingRateBytesPerSecond * 8.0 / 1000000.0:F2} Mbps");
Console.WriteLine($"  Retrans:       {report.RetransmissionRatio:P1} ({report.RetransmittedPackets}/{report.DataPacketsSent} packets)");
Console.WriteLine($"  Fast retrans:  {report.FastRetransmissions}");
Console.WriteLine($"  Timeout retrans: {report.TimeoutRetransmissions}");

await client.CloseAsync();
Console.WriteLine("Connection closed.");

static double GetAverageRtt(UcpTransferReport report)
{
    if (report.RttSamplesMicros.Count == 0)
    {
        return 0;
    }

    long sum = 0;
    foreach (long s in report.RttSamplesMicros)
    {
        sum += s;
    }

    return (double)sum / report.RttSamplesMicros.Count / 1000.0;
}
