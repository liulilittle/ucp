using System.Net;
using Ucp;

var scenarios = new[]
{
    new { Name = "NoLoss",      Loss = 0.00, DelayMs = 5,  JitterMs = 0,  BwBps = 100_000_000 / 8, PayloadMB = 4,  TargetUtilMin = 90.0, TargetRetransMax = 0.5 },
    new { Name = "Lossy_1%",    Loss = 0.01, DelayMs = 10, JitterMs = 2,  BwBps = 100_000_000 / 8, PayloadMB = 4,  TargetUtilMin = 85.0, TargetRetransMax = 2.0 },
    new { Name = "Lossy_5%",    Loss = 0.05, DelayMs = 10, JitterMs = 2,  BwBps = 100_000_000 / 8, PayloadMB = 8,  TargetUtilMin = 70.0, TargetRetransMax = 7.0 },
    new { Name = "LongFatPipe", Loss = 0.00, DelayMs = 50, JitterMs = 2,  BwBps = 100_000_000 / 8, PayloadMB = 4,  TargetUtilMin = 80.0, TargetRetransMax = 0.5 },
    new { Name = "HighJitter",  Loss = 0.005,DelayMs = 50, JitterMs = 25, BwBps = 100_000_000 / 8, PayloadMB = 4,  TargetUtilMin = 65.0, TargetRetransMax = 2.0 },
};

var readmeTargets = new Dictionary<string, (double minMbps, double maxMbps)>
{
    ["NoLoss"]      = (95, 100),
    ["Lossy_1%"]    = (90,  99),
    ["Lossy_5%"]    = (75,  95),
    ["LongFatPipe"] = (85,  99),
    ["HighJitter"]  = (70,  99),
};

Console.WriteLine("UCP Performance Benchmark");
Console.WriteLine(new string('=', 85));

var allResults = new List<(string Name, double ActualMbps, double Util, string Status)>();

foreach (var scenario in scenarios)
{
    Console.WriteLine($"\n--- {scenario.Name} ---");
    Console.WriteLine($"  Config: {scenario.Loss * 100:F1}% loss, {scenario.DelayMs}ms delay, {scenario.JitterMs}ms jitter, {scenario.BwBps / 125000.0:F1} Mbps, {scenario.PayloadMB} MB");

    var report = await RunScenarioAsync(scenario.Name, scenario.BwBps, scenario.PayloadMB * 1024 * 1024,
        scenario.DelayMs, scenario.JitterMs, scenario.Loss, 12345 + Array.IndexOf(scenarios, scenario));

    if (report == null)
    {
        Console.WriteLine("  FAILED");
        continue;
    }

    double throughputMbps = report.ThroughputBytesPerSec * 8.0 / 1000000.0;
    double targetMbps = scenario.BwBps * 8.0 / 1000000.0;
    double util = targetMbps > 0 ? throughputMbps * 100.0 / targetMbps : 0;

    Console.WriteLine($"  Throughput:     {throughputMbps:F2} Mbps ({util:F1}% util)");
    Console.WriteLine($"  Avg RTT:        {report.AvgRttMicros / 1000.0:F2} ms");
    Console.WriteLine($"  Retransmission: {report.RetransmissionRatio * 100:F2}%");
    Console.WriteLine($"  Observed loss:  {report.ObservedLossPercent:F2}%");
    Console.WriteLine($"  CWND:           {report.CwndBytes} B");
    Console.WriteLine($"  Elapsed:        {report.ElapsedMs} ms");

    bool utilOk = util >= scenario.TargetUtilMin;
    bool retransOk = report.RetransmissionRatio * 100 <= scenario.TargetRetransMax;
    Console.WriteLine($"  Utilization:    {(utilOk ? "PASS" : "FAIL")} (>= {scenario.TargetUtilMin}%)");
    Console.WriteLine($"  Retransmission: {(retransOk ? "PASS" : "FAIL")} (<= {scenario.TargetRetransMax}%)");

    string readmeStatus = "N/A";
    if (readmeTargets.TryGetValue(scenario.Name, out var range))
    {
        bool withinTarget = throughputMbps >= range.minMbps;
        readmeStatus = withinTarget ? "PASS" : "FAIL";
        Console.WriteLine($"  vs README ({range.minMbps}-{range.maxMbps} Mbps): {readmeStatus} (>= {range.minMbps})");
    }

    allResults.Add((scenario.Name, throughputMbps, util, readmeStatus));
}

Console.WriteLine();
Console.WriteLine(new string('=', 85));
Console.WriteLine($"{"Scenario",-16} {"Target (Mbps)",-18} {"Actual (Mbps)",-16} {"Util%",-8} {"vs README"}");
Console.WriteLine(new string('-', 80));

foreach (var result in allResults)
{
    string target = readmeTargets.TryGetValue(result.Name, out var r) ? $"{r.minMbps}-{r.maxMbps}" : "N/A";
    Console.WriteLine($"{result.Name,-16} {target,-18} {result.ActualMbps,-16:F2} {result.Util,-8:F1} {result.Status}");
}

static async Task<ScenarioReport?> RunScenarioAsync(string name, int bandwidthBps, int payloadBytes,
    int delayMs, int jitterMs, double lossRate, int seed)
{
    try
    {
        var config = UcpConfiguration.GetOptimizedConfig();
        config.InitialBandwidthBytesPerSecond = bandwidthBps;
        config.MaxPacingRateBytesPerSecond = bandwidthBps;
        config.ServerBandwidthBytesPerSecond = bandwidthBps;
        config.SendBufferSize = Math.Max(64 * 1024 * 1024, payloadBytes * 2);
        config.ReceiveBufferSize = Math.Max(64 * 1024 * 1024, payloadBytes * 2);

        if (lossRate > 0)
        {
            config.FecRedundancy = lossRate >= 0.05 ? 0.50 : 0.25;
            config.FecGroupSize = 8;
        }

        using var cts = new CancellationTokenSource();
        var peers = new Dictionary<int, SimPeer>();

        var serverPeer = new SimPeer(peers, config.Clone(), delayMs, jitterMs, lossRate, bandwidthBps, seed + 1);
        var clientPeer = new SimPeer(peers, config.Clone(), delayMs, jitterMs, lossRate, bandwidthBps, seed + 2);

        serverPeer.Start(9000);
        clientPeer.Start(0);

        var pumpTask = Task.Run(() => EventPumpLoop(new[] { serverPeer, clientPeer }, cts.Token));

        var server = serverPeer.CreateServer(9000);
        var client = clientPeer.CreateConnection(config);

        var acceptTask = server.AcceptAsync();
        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));
        var serverConn = await acceptTask;

        var payload = new byte[payloadBytes];
        new Random(42).NextBytes(payload);
        var received = new byte[payloadBytes];

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var readTask = ReadWithTimeoutAsync(serverConn, received, 0, received.Length, 180000);
        var writeOk = await client.WriteAsync(payload, 0, payload.Length);
        var readOk = await readTask;
        sw.Stop();

        cts.Cancel();
        try { await pumpTask; } catch (OperationCanceledException) { }

        if (!writeOk || !readOk)
            return null;

        bool verified = payload.AsSpan().SequenceEqual(received);
        if (!verified)
            return null;

        await Task.Delay(200);

        var transferReport = client.GetReport();
        double throughputBps = payloadBytes / Math.Max(0.001, sw.Elapsed.TotalSeconds);
        if (bandwidthBps > 0)
            throughputBps = Math.Min(throughputBps, bandwidthBps);

        long obsDrop = serverPeer.PacketsDropped + clientPeer.PacketsDropped;
        long obsSent = serverPeer.PacketsSent + clientPeer.PacketsSent;
        double obsLoss = obsSent > 0 ? obsDrop * 100.0 / obsSent : 0;

        return new ScenarioReport
        {
            ThroughputBytesPerSec = throughputBps,
            AvgRttMicros = transferReport.LastRttMicros,
            RetransmissionRatio = transferReport.RetransmissionRatio,
            ElapsedMs = sw.ElapsedMilliseconds,
            CwndBytes = transferReport.CongestionWindowBytes,
            ObservedLossPercent = obsLoss,
        };
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Error: {ex.Message}");
        return null;
    }
}

static void EventPumpLoop(SimPeer[] peers, CancellationToken ct)
{
    while (!ct.IsCancellationRequested)
    {
        int work = 0;
        foreach (var peer in peers)
            work += peer.DoEvents();
        if (work == 0)
            Thread.Sleep(1);
    }
}

static async Task<bool> ReadWithTimeoutAsync(UcpConnection conn, byte[] buf, int off, int count, int timeoutMs)
{
    using var cts = new CancellationTokenSource(timeoutMs);
    try
    {
        var task = conn.ReadAsync(buf, off, count);
        await task.WaitAsync(cts.Token);
        return task.Result;
    }
    catch (OperationCanceledException)
    {
        return false;
    }
}

sealed class ScenarioReport
{
    public double ThroughputBytesPerSec;
    public long AvgRttMicros;
    public double RetransmissionRatio;
    public long ElapsedMs;
    public int CwndBytes;
    public double ObservedLossPercent;
}

sealed class SimPeer : UcpNetwork
{
    private readonly Dictionary<int, SimPeer> _peers;
    private readonly int _delayMs;
    private readonly int _jitterMs;
    private readonly double _lossRate;
    private readonly int _bandwidthBps;
    private readonly Random _rng;
    private IPEndPoint? _localEndPoint;
    private readonly object _sync = new();
    private readonly Queue<(byte[] Data, IPEndPoint Source)> _inbox = new();

    public long PacketsSent { get; private set; }
    public long PacketsDropped { get; private set; }

    public SimPeer(Dictionary<int, SimPeer> peers, UcpConfiguration config,
        int delayMs, int jitterMs, double lossRate, int bandwidthBps, int seed)
        : base(config)
    {
        _peers = peers;
        _delayMs = delayMs;
        _jitterMs = jitterMs;
        _lossRate = lossRate;
        _bandwidthBps = bandwidthBps;
        _rng = new Random(seed);
    }

    public override EndPoint? LocalEndPoint => _localEndPoint;

    public override void Start(int port)
    {
        if (_localEndPoint != null) return;
        if (port == 0) port = 50000 + _peers.Count;
        _localEndPoint = new IPEndPoint(IPAddress.Loopback, port);
        lock (_peers) { _peers[port] = this; }
    }

    public override void Stop()
    {
        if (_localEndPoint != null)
        {
            lock (_peers) { _peers.Remove(_localEndPoint.Port); }
        }
    }

    public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject? sender)
    {
        if (_localEndPoint == null) Start(0);

        var copy = new byte[datagram.Length];
        Array.Copy(datagram, copy, datagram.Length);

        lock (_sync)
        {
            PacketsSent++;
            if (_rng.NextDouble() < _lossRate)
            {
                PacketsDropped++;
                return;
            }
        }

        int varJitter = _jitterMs > 0 ? _rng.Next(-_jitterMs, _jitterMs + 1) : 0;
        long delayUs = (long)(Math.Max(0, _delayMs + varJitter)) * 1000L;

        if (_bandwidthBps > 0)
        {
            long bwSerialUs = (long)Math.Ceiling(copy.Length * 1000000.0 / _bandwidthBps);
            delayUs += bwSerialUs;
        }

        _ = DeliverAfterAsync(copy, remote, delayUs);
    }

    private async Task DeliverAfterAsync(byte[] data, IPEndPoint remote, long delayUs)
    {
        if (delayUs > 1000)
            await Task.Delay(TimeSpan.FromMilliseconds(delayUs / 1000.0));
        else if (delayUs > 0)
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(1, delayUs / 1000.0)));

        SimPeer? target = null;
        lock (_peers)
        {
            _peers.TryGetValue(remote.Port, out target);
        }

        if (target != null && _localEndPoint != null)
        {
            target.Enqueue(data, _localEndPoint);
        }
    }

    private void Enqueue(byte[] data, IPEndPoint source)
    {
        lock (_inbox)
        {
            _inbox.Enqueue((data, source));
        }
    }

    public override int DoEvents()
    {
        while (true)
        {
            (byte[] Data, IPEndPoint Source) item;
            lock (_inbox)
            {
                if (_inbox.Count == 0) break;
                item = _inbox.Dequeue();
            }
            Input(item.Data, item.Source);
        }

        return base.DoEvents();
    }
}
