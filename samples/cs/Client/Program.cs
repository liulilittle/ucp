using System.Net;
using System.Text;
using Ucp;

const int DefaultPort = 9000;
const int DefaultDataMb = 1;
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
        Console.WriteLine($"  --size      Data size in MB to send (default: {DefaultDataMb})");
        Console.WriteLine($"  --bandwidth Expected bandwidth in Mbps (default: {DefaultBandwidthMbps})");
        return;
    }
}

int bandwidthBytesPerSec = bandwidthMbps * 1000000 / 8;
int totalBytes = dataMb * 1024 * 1024;

var config = UcpConfiguration.GetOptimizedConfig();
config.ServerBandwidthBytesPerSecond = bandwidthBytesPerSec;
config.InitialBandwidthBytesPerSecond = bandwidthBytesPerSec;
config.MaxPacingRateBytesPerSecond = bandwidthBytesPerSec;
config.SendBufferSize = Math.Max(64 * 1024 * 1024, totalBytes * 2);
config.ReceiveBufferSize = Math.Max(64 * 1024 * 1024, totalBytes * 2);

Console.WriteLine($"Connecting to {host}:{port}...");

using var client = new UcpConnection(config);
var remote = new IPEndPoint(IPAddress.Parse(host), port);

var stopwatch = System.Diagnostics.Stopwatch.StartNew();

await client.ConnectAsync(remote);
Console.WriteLine($"Connected (ConnId={client.ConnectionId:X8}), sending {totalBytes / 1024.0 / 1024.0:F2} MB...");

var sendData = new byte[totalBytes];
new Random(42).NextBytes(sendData);
var recvBuf = new byte[totalBytes];

var sendTask = client.WriteAsync(sendData, 0, sendData.Length);

int totalReceived = 0;
while (totalReceived < totalBytes)
{
    int n = await client.ReceiveAsync(recvBuf, totalReceived, totalBytes - totalReceived);
    if (n <= 0)
        break;
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
Console.WriteLine($"  Pacing rate:   {report.PacingRateBytesPerSecond * 8.0 / 1000000.0:F2} Mbps");
Console.WriteLine($"  Retrans:       {report.RetransmissionRatio:P1} ({report.RetransmittedPackets}/{report.DataPacketsSent} packets)");
Console.WriteLine($"  Fast retrans:  {report.FastRetransmissions}");
Console.WriteLine($"  Timeout retrans: {report.TimeoutRetransmissions}");

await client.CloseAsync();
Console.WriteLine("Connection closed.");

static double GetAverageRtt(UcpTransferReport report)
{
    if (report.RttSamplesMicros.Count == 0)
        return 0;
    long sum = 0;
    foreach (long s in report.RttSamplesMicros)
        sum += s;
    return (double)sum / report.RttSamplesMicros.Count / 1000.0;
}
