using System.Net;
using Ucp;

async Task<bool> RunEcho(int port, int dataSize, int bwBps, int timeoutSec) {
    GlobalKfEstimator.Reset();
    var srvCfg = UcpConfiguration.GetOptimizedConfig();
    srvCfg.ServerBandwidthBytesPerSecond = bwBps;
    srvCfg.InitialBandwidthBytesPerSecond = bwBps;
    srvCfg.MaxPacingRateBytesPerSecond = bwBps;

    using var server = new UcpServer(srvCfg);
    server.Start(port);

    var cliCfg = UcpConfiguration.GetOptimizedConfig();
    cliCfg.ServerBandwidthBytesPerSecond = bwBps;
    cliCfg.InitialBandwidthBytesPerSecond = bwBps;
    cliCfg.MaxPacingRateBytesPerSecond = bwBps;

    using var client = new UcpConnection(cliCfg);

    var acceptTask = server.AcceptAsync();
    await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
    using var accepted = await acceptTask.WaitAsync(TimeSpan.FromSeconds(10));

    var tx = new byte[dataSize];
    new Random(42).NextBytes(tx);
    var serverRx = new byte[dataSize];
    var clientRx = new byte[dataSize];

    bool writeOk;
    try { writeOk = await client.WriteAsync(tx, 0, tx.Length).WaitAsync(TimeSpan.FromSeconds(timeoutSec)); }
    catch (TimeoutException) { return false; }
    if (!writeOk) return false;

    int off = 0;
    while (off < dataSize) {
        int n;
        try { n = await accepted.ReceiveAsync(serverRx, off, dataSize - off).WaitAsync(TimeSpan.FromSeconds(timeoutSec)); }
        catch (TimeoutException) { return false; }
        if (n <= 0) return false;
        off += n;
    }

    bool echoOk;
    try { echoOk = await accepted.WriteAsync(serverRx, 0, serverRx.Length).WaitAsync(TimeSpan.FromSeconds(timeoutSec)); }
    catch (TimeoutException) { return false; }
    if (!echoOk) return false;

    off = 0;
    while (off < dataSize) {
        int n;
        try { n = await client.ReceiveAsync(clientRx, off, dataSize - off).WaitAsync(TimeSpan.FromSeconds(timeoutSec)); }
        catch (TimeoutException) { return false; }
        if (n <= 0) return false;
        off += n;
    }

    await client.CloseAsync();
    await accepted.CloseAsync();
    server.Stop();

    return tx.AsSpan().SequenceEqual(clientRx.AsSpan());
}

int totalPassed = 0;
int totalFailed = 0;

async Task Test(string name, int dataSize, int bwBps, int timeoutSec = 30) {
    bool ok = await RunEcho(9300 + totalPassed + totalFailed, dataSize, bwBps, timeoutSec);
    if (ok) { Console.WriteLine($"[PASS] {name}: {dataSize / 1024} KB"); totalPassed++; }
    else { Console.WriteLine($"[FAIL] {name}"); totalFailed++; }
}

Console.WriteLine("=== UCP SelfTest (Real UDP) ===");
await Test("Echo_64K_100M",    64 * 1024,       100_000_000 / 8);
await Task.Delay(500);
await Test("Echo_256K_100M",   256 * 1024,      100_000_000 / 8);
await Task.Delay(500);
await Test("Echo_1M_100M",     1024 * 1024,     100_000_000 / 8, 60);
await Task.Delay(500);
await Test("Echo_64K_1G",      64 * 1024,       1_000_000_000 / 8);
await Task.Delay(500);
await Test("Echo_256K_1G",     256 * 1024,      1_000_000_000 / 8);

Console.WriteLine($"\n=== Results: {totalPassed} passed, {totalFailed} failed ===");
if (totalFailed > 0) Environment.Exit(1);
