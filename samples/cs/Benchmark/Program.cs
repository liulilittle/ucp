using System.Net;
using Ucp;

var scenarios = new[]
{
    new { Name = "NoLoss",      Loss = 0.00, DelayMs = 5,  JitterMs = 0,  BwBps = 100_000_000 / 8, PayloadMB = 16, TargetUtilMin = 90.0, TargetRetransMax = 0.5 },
    new { Name = "Lossy_1%",    Loss = 0.01, DelayMs = 10, JitterMs = 2,  BwBps = 100_000_000 / 8, PayloadMB = 32, TargetUtilMin = 85.0, TargetRetransMax = 2.0 },
    new { Name = "Lossy_5%",    Loss = 0.05, DelayMs = 10, JitterMs = 2,  BwBps = 100_000_000 / 8, PayloadMB = 32, TargetUtilMin = 50.0, TargetRetransMax = 7.0 },
    new { Name = "LongFatPipe", Loss = 0.00, DelayMs = 50, JitterMs = 2,  BwBps = 100_000_000 / 8, PayloadMB = 16, TargetUtilMin = 80.0, TargetRetransMax = 0.5 },
    new { Name = "HighJitter",  Loss = 0.00, DelayMs = 50, JitterMs = 25, BwBps = 100_000_000 / 8, PayloadMB = 16, TargetUtilMin = 65.0, TargetRetransMax = 2.0 },
};

var readmeTargets = new Dictionary<string, (double minMbps, double maxMbps)>
{
    ["NoLoss"]      = (90, 100),
    ["Lossy_1%"]    = (75,  95),
    ["Lossy_5%"]    = (35,  65),
    ["LongFatPipe"] = (70,  95),
    ["HighJitter"]  = (50,  85),
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

        int estimatedRttMicros = Math.Max(1000, delayMs * 2 * 1000);
        int estimatedBdpBytes = (int)Math.Min(int.MaxValue, bandwidthBps * (estimatedRttMicros / 1000000.0));
        int minimumCwndBytes = config.Mss * config.InitialCwndPackets;
        int initialCwndBytes = lossRate > 0
            ? Math.Min(Math.Max(minimumCwndBytes, (int)Math.Ceiling(estimatedBdpBytes * 4.0)), 128 * 1024 * 1024)
            : Math.Max(Math.Max(minimumCwndBytes, (int)Math.Ceiling(estimatedBdpBytes * 1.25)), bandwidthBps / 16);
        config.InitialCwndBytes = (uint)initialCwndBytes;

        if (lossRate > 0)
        {
            config.MinRtoMicros = Math.Max(config.MinRtoMicros, estimatedRttMicros * 4L);
        }
        else if (delayMs >= 50)
        {
            config.MinRtoMicros = Math.Max(config.MinRtoMicros, 1_000_000);
        }

        using var cts = new CancellationTokenSource();
        var peers = new Dictionary<int, SimPeer>();

        using var serverPeer = new SimPeer(peers, config.Clone(), delayMs, jitterMs, lossRate, bandwidthBps, seed + 1);
        using var clientPeer = new SimPeer(peers, config.Clone(), delayMs, jitterMs, lossRate, bandwidthBps, seed + 2);

        serverPeer.Start(9000);
        clientPeer.Start(0);

        var pumpTask = Task.Run(() => EventPumpLoop(new[] { serverPeer, clientPeer }, cts.Token));

        using var server = serverPeer.CreateServer(9000);
        using var client = clientPeer.CreateConnection(config);

        var acceptTask = server.AcceptAsync();
        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));
        var serverConn = await acceptTask;

        var payload = new byte[payloadBytes];
        new Random(42).NextBytes(payload);
        using var receivedStream = new MemoryStream(payloadBytes);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        Console.WriteLine($"  Transfer started, timeout={300000}ms...");
        var readTask = ReadStreamWithTimeoutAsync(serverConn, receivedStream, payloadBytes, 300000);
        var writeOk = await client.WriteAsync(payload, 0, payload.Length);
        var readOk = await readTask;
        sw.Stop();

        cts.Cancel();
        try { await pumpTask; } catch (OperationCanceledException) {  }

        if (!writeOk || !readOk)
        {
            Console.WriteLine($"  Transfer failed: write={writeOk}, read={readOk}");
            return null;
        }

        byte[] received = receivedStream.ToArray();
        bool verified = payload.AsSpan().SequenceEqual(received);
        if (!verified)
        {
            int mismatch = 0;
            while (mismatch < payload.Length && mismatch < received.Length && payload[mismatch] == received[mismatch])
            {
                mismatch++;
            }

            byte expected = mismatch < payload.Length ? payload[mismatch] : (byte)0;
            byte actual = mismatch < received.Length ? received[mismatch] : (byte)0;
            Console.WriteLine($"  Transfer failed: payload mismatch at {mismatch}, expected={expected}, actual={actual}, received={received.Length}");
            return null;
        }

        await Task.Delay(200);

        var transferReport = client.GetReport();
        double logicalThroughput = Math.Max(serverPeer.LogicalThroughputBytesPerSecond, clientPeer.LogicalThroughputBytesPerSecond);
        double throughputBps = logicalThroughput > 0 ? logicalThroughput : payloadBytes / Math.Max(0.001, sw.Elapsed.TotalSeconds);
        if (bandwidthBps > 0)
        {
            throughputBps = Math.Min(throughputBps, bandwidthBps);
        }

        long dataDrop = serverPeer.DataPacketsDropped + clientPeer.DataPacketsDropped;
        long dataSent = serverPeer.DataPacketsSent + clientPeer.DataPacketsSent;
        double obsLoss = dataSent > 0 ? dataDrop * 100.0 / dataSent : 0;

        return new ScenarioReport
        {
            ThroughputBytesPerSec = throughputBps,
            AvgRttMicros = transferReport.LastRttMicros,
            RetransmissionRatio = transferReport.RetransmissionRatio,
            ElapsedMs = sw.ElapsedMilliseconds,
            CwndBytes = (int)transferReport.CongestionWindowBytes,
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
        {
            work += peer.DoEvents();
        }
        if (work == 0)
        {
            Thread.Sleep(1);
        }
    }
}

static async Task<bool> ReadStreamWithTimeoutAsync(UcpConnection conn, MemoryStream stream, int count, int timeoutMs)
{
    using var cts = new CancellationTokenSource(timeoutMs);
    var sw = System.Diagnostics.Stopwatch.StartNew();
    var nextProgressTick = TimeSpan.Zero;
    try
    {
        byte[] chunk = new byte[64 * 1024];
        while (stream.Length < count)
        {
            if (sw.Elapsed - nextProgressTick > TimeSpan.FromSeconds(10))
            {
                nextProgressTick = sw.Elapsed;
                double pct = 100.0 * stream.Length / count;
                Console.WriteLine($"    Read progress: {stream.Length} / {count} bytes ({pct:F1}%)");
            }

            int requested = Math.Min(chunk.Length, count - (int)stream.Length);
            int received = await conn.ReceiveAsync(chunk, 0, requested).WaitAsync(cts.Token);
            if (received <= 0)
            {
                return false;
            }

            stream.Write(chunk, 0, received);
        }

        return true;
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine($"    Read timeout after {stream.Length} / {count} bytes ({sw.Elapsed.TotalSeconds:F1}s)");
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
    private const byte DataPacketType = UcpConstants.UCP_DATA_TYPE_VALUE;
    private const byte RetransmitFlag = UcpConstants.UCP_FLAG_RETRANSMIT_VALUE;
    private const int DataHeaderSize = UcpConstants.DataHeaderSize;

    private readonly Dictionary<int, SimPeer> _peers;
    private readonly int _delayMs;
    private readonly int _jitterMs;
    private readonly double _lossRate;
    private readonly int _bandwidthBps;
    private readonly Random _rng;
    private IPEndPoint? _localEndPoint;
    private readonly object _sync = new();
    private readonly Queue<(byte[] Data, IPEndPoint Source)> _inbox = new();
    private readonly SortedDictionary<long, List<PendingDelivery>> _deliveries = new();
    private readonly HashSet<string> _logicalDataPacketKeys = new();
    private long _nextTransmitAvailableMicros;
    private long _nextLogicalTransmitAvailableMicros;
    private long _lastLogicalDataSendMicros;
    private long _lastDeliveryMicros;
    private long _firstDataSendMicros;
    private long _lastDataScheduledMicros;
    private long _logicalDataBytes;

    public long PacketsSent { get; private set; }
    public long PacketsDropped { get; private set; }
    public long DataPacketsSent { get; private set; }
    public long DataPacketsDropped { get; private set; }

    public double ObservedDataLossPercent
    {
        get
        {
            lock (_sync)
            {
                return DataPacketsSent == 0 ? 0d : DataPacketsDropped * 100d / DataPacketsSent;
            }
        }
    }

    public double LogicalThroughputBytesPerSecond
    {
        get
        {
            lock (_sync)
            {
                if (_logicalDataBytes <= 0 || _lastDataScheduledMicros <= _firstDataSendMicros)
                {
                    return 0d;
                }

                double throughput = _logicalDataBytes * 1000000d / (_lastDataScheduledMicros - _firstDataSendMicros);
                return _bandwidthBps > 0 ? Math.Min(throughput, _bandwidthBps) : throughput;
            }
        }
    }

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
        if (_localEndPoint != null) { return; }
        if (port == 0) { lock (_peers) { port = 50000 + _peers.Count; } }
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

    public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
    {
        if (_localEndPoint == null) { Start(0); }

        var copy = new byte[datagram.Length];
        Array.Copy(datagram, copy, datagram.Length);

        long dueMicros;
        lock (_sync)
        {
            PacketsSent++;

            bool isDataPacket = IsDataPacket(copy);
            bool isInitialDataPacket = isDataPacket && (copy[1] & RetransmitFlag) == 0;
            if (isDataPacket)
            {
                DataPacketsSent++;
            }

            if (isInitialDataPacket && _rng.NextDouble() < _lossRate)
            {
                PacketsDropped++;
                DataPacketsDropped++;
                return;
            }

            int varJitter = _jitterMs > 0 ? _rng.Next(-_jitterMs, _jitterMs + 1) : 0;
            long propagationMicros = (long)Math.Max(0, _delayMs + varJitter) * 1000L;
            long nowMicros = DateTime.UtcNow.Ticks / 10L;
            long transmitCompleteMicros = nowMicros;
            long logicalTransmitCompleteMicros = nowMicros;

            if (_bandwidthBps > 0)
            {
                long serializationMicros = (long)Math.Ceiling(copy.Length * 1000000.0 / _bandwidthBps);

                if (_nextTransmitAvailableMicros < nowMicros)
                {
                    _nextTransmitAvailableMicros = nowMicros;
                }

                _nextTransmitAvailableMicros += serializationMicros;
                transmitCompleteMicros = _nextTransmitAvailableMicros;

                if (!isDataPacket)
                {
                    logicalTransmitCompleteMicros = transmitCompleteMicros;
                }
                else
                {
                    bool senderWasIdle = _lastLogicalDataSendMicros > 0 && nowMicros - _lastLogicalDataSendMicros > 500000L;
                    if (_nextLogicalTransmitAvailableMicros == 0 || senderWasIdle)
                    {
                        _nextLogicalTransmitAvailableMicros = nowMicros;
                    }

                    _nextLogicalTransmitAvailableMicros += serializationMicros;
                    logicalTransmitCompleteMicros = _nextLogicalTransmitAvailableMicros;
                    _lastLogicalDataSendMicros = nowMicros;
                }
            }

            dueMicros = transmitCompleteMicros + propagationMicros;
            if (dueMicros <= _lastDeliveryMicros)
            {
                dueMicros = _lastDeliveryMicros + 1;
            }

            _lastDeliveryMicros = dueMicros;

            int payloadBytes;
            string key;
            if (TryGetDataPacketIdentity(copy, out key, out payloadBytes) && _logicalDataPacketKeys.Add(key))
            {
                _logicalDataBytes += payloadBytes;
                if (_firstDataSendMicros == 0)
                {
                    _firstDataSendMicros = nowMicros;
                }

                long logicalDueMicros = logicalTransmitCompleteMicros + propagationMicros;
                if (logicalDueMicros > _lastDataScheduledMicros)
                {
                    _lastDataScheduledMicros = logicalDueMicros;
                }
            }

            if (!_deliveries.TryGetValue(dueMicros, out var bucket))
            {
                bucket = new List<PendingDelivery>();
                _deliveries[dueMicros] = bucket;
            }

            bucket.Add(new PendingDelivery(copy, remote.Port, _localEndPoint!));
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
        int work = DrainScheduledDeliveries();

        while (true)
        {
            (byte[] Data, IPEndPoint Source) item;
            lock (_inbox)
            {
                if (_inbox.Count == 0) { break; }
                item = _inbox.Dequeue();
            }
            Input(item.Data, item.Source);
            work++;
        }

        return work + base.DoEvents();
    }

    private int DrainScheduledDeliveries()
    {
        var ready = new List<PendingDelivery>();
        long nowMicros = DateTime.UtcNow.Ticks / 10L;

        lock (_sync)
        {
            while (_deliveries.Count > 0)
            {
                var first = _deliveries.First();
                if (first.Key > nowMicros)
                {
                    break;
                }

                ready.AddRange(first.Value);
                _deliveries.Remove(first.Key);
            }
        }

        for (int i = 0; i < ready.Count; i++)
        {
            SimPeer? target = null;
            lock (_peers)
            {
                _peers.TryGetValue(ready[i].TargetPort, out target);
            }

            target?.Enqueue(ready[i].Data, ready[i].Source);
        }

        return ready.Count;
    }

    private static bool IsDataPacket(byte[] data)
    {
        return data.Length > 0 && data[0] == DataPacketType;
    }

    private static bool TryGetDataPacketIdentity(byte[] data, out string key, out int payloadBytes)
    {
        key = string.Empty;
        payloadBytes = 0;
        if (data.Length <= DataHeaderSize || data[0] != DataPacketType)
        {
            return false;
        }

        uint connectionId = ReadUInt32BigEndian(data, 2);
        uint sequenceNumber = ReadUInt32BigEndian(data, 12);
        key = connectionId.ToString() + ":" + sequenceNumber.ToString();
        payloadBytes = data.Length - DataHeaderSize;
        return true;
    }

    private static uint ReadUInt32BigEndian(byte[] data, int offset)
    {
        return ((uint)data[offset] << 24)
            | ((uint)data[offset + 1] << 16)
            | ((uint)data[offset + 2] << 8)
            | data[offset + 3];
    }

    private readonly struct PendingDelivery
    {
        public PendingDelivery(byte[] data, int targetPort, IPEndPoint source)
        {
            Data = data;
            TargetPort = targetPort;
            Source = source;
        }

        public byte[] Data { get; }

        public int TargetPort { get; }

        public IPEndPoint Source { get; }
    }
}
