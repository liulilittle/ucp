# PPP PRIVATE NETWORK™ X -- Universal Communication Protocol (UCP) -- API Reference

[Chinese](api_CN.md) | [Documentation Index](index.md)

This document provides the complete public API reference for the UCP library. All file paths referenced are relative to the [Ucp/](../Ucp/) source directory.

---

## Table of Contents

- [UcpConfiguration (Configuration Factory)](#ucpconfiguration-configuration-factory)
- [UcpServer (Server API)](#ucpserver-server-api)
- [UcpConnection (Connection API)](#ucpconnection-connection-api)
- [UcpNetwork (Event Loop Driver)](#ucpnetwork-event-loop-driver)
- [UcpDatagramNetwork (UDP Network)](#ucpdatagramnetwork-udp-network)
- [IUcpObject Interface](#iucpobject-interface)
- [ITransport / IBindableTransport / UdpSocketTransport](#itransport--ibindabletransport--udpsockettransport)
- [UcpTransferReport (Diagnostics)](#ucptransferreport-diagnostics)
- [UcpFecCodec (FEC Configuration)](#ucpfeccodec-fec-configuration)
- [UcpPriority Enum](#ucppriority-enum)
- [C++ Cross-Reference](#c-cross-reference)
- [Error Handling](#error-handling)
- [End-to-End Example](#end-to-end-example)

---

## UcpConfiguration (Configuration Factory)

**Source:** [Ucp/UcpConfiguration.cs](../Ucp/UcpConfiguration.cs)

```csharp
public class UcpConfiguration
```

The master configuration object. Use `GetOptimizedConfig()` to obtain a production-tuned default, then override individual properties. All timers use microsecond resolution; interval defaults suit mobile/WiFi links.

### Static Factory

```csharp
public static UcpConfiguration GetOptimizedConfig()
```

Returns a production-tuned instance with sensible defaults for RTO (50 ms min / 15 s max), MinRTT filter (automatic via geodesic G1/G3), backoff factor (1.2x), initial CWND (configurable, not a fixed 10-packet cap), ProbeBW 8-phase gain cycle (1.25, 0.75, 1.0x6), SACK block limit (2), loss ceiling (25%), and loss control enabled. KCC congestion control (Geodesic Congestion Control, KF component from tcp_kcc.c v2.0) includes geodesic RTT estimation and FEC/NAK delivery samples feeding into the CC engine. MinRTT tracking is handled automatically by geodesic G1/G3.

### Clone

```csharp
public UcpConfiguration Clone()
```

Deep-copies the configuration. Used internally to isolate per-connection settings from server-level defaults.

### Protocol Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| Mss | int | 1220 | 200-9000 | Maximum segment size in bytes. 1220 fits IPv6 min-MTU without fragmentation |
| MaxRetransmissions | int | 10 | 3-100 | Max retransmit attempts per segment before disconnect |
| SendBufferSize | int | 32 MB | 1-256 MB | Outbound buffer capacity. WriteAsync blocks when full |
| ReceiveBufferSize | int | ~5 MB | auto (MSS * RecvWindowPackets) | Receive buffer in bytes. Setter converts to RecvWindowPackets |
| InitialCwndPackets | int | 10 | 4-200 | KCC congestion control initial congestion window in packet units |
| MaxCongestionWindowBytes | int | 64 MB | 64 KB-256 MB | UCP CWND hard cap. 64 MB covers typical BDP below 10 Gbps at 100 ms RTT |
| SendQuantumBytes | int | MSS | MSS-MSSx4 | Pacing token consumption granularity |
| AckSackBlockLimit | int | 2 | 1-255 | Max SACK blocks per ACK packet |
| RecvWindowPackets | int | 4096 | >= 1 | Receive window in packet count for flow control advertisement |
| FecRedundancy | double | 0.0 | 0.0-1.0 | RS-GF(256) redundancy ratio. 0.0 disables FEC; 0.125 = 1 repair per 8 data |
| FecGroupSize | int | 8 | 2-64 | Data packets per FEC group |
| LossControlEnable | bool | true | - | Enable loss-aware pacing adaptation |
| EcnEnabled | bool | false | - | Enable ECN CE-mark feedback (KCC 2.0 default: disabled) |
| EnableDebugLog | bool | false | - | Debug trace logging for congestion decisions |
| EnableMtuDiscovery | bool | true | - | Enable DPLPMTUD path MTU probing |
| MtuProbeMax | int | 1500 | - | Max MTU to probe (Ethernet ceiling) |
| MtuProbeTimeoutMicros | long | 10,000,000 (10 s) | - | Timeout for in-flight MTU probe |
| MtuProbeIntervalMicros | long | 600,000,000 (10 min) | - | Re-probe interval after MTU convergence |
| EnableAggressiveSackRecovery | bool | true (internal) | - | Short-grace SACK recovery (QUIC-like, lowers retransmit threshold) |

### RTO and Timers

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| MinRtoMicros | long | 50,000 (50 ms) | 50,000-1,000,000 | Minimum retransmission timeout |
| MaxRtoMicros | long | 15,000,000 (15 s) | 1,000,000-60,000,000 | Maximum retransmission timeout |
| RetransmitBackoffFactor | double | 1.2 | 1.1-2.0 | RTO backoff multiplier per timeout |
| KeepAliveIntervalMicros | long | 1,000,000 (1 s) | 100,000-30,000,000 | Keep-alive interval (NAT binding refresh) |
| DisconnectTimeoutMicros | long | 4,000,000 (4 s) | 500,000-60,000,000 | Idle disconnect timeout |
| TimerIntervalMilliseconds | int | 1 | 1-100 | DoEvents timer tick interval |
| FairQueueRoundMilliseconds | int | 10 | 1-100 | Fair-queue scheduling round interval |
| ConnectTimeoutMilliseconds | int | 5000 | - | Connect handshake timeout |
| DelayedAckTimeoutMicros | long | 100 | 0-10,000 | Delayed ACK timeout (fires when no outbound data for piggybacking) |

**KCC 2.0 Note**: MinRTT tracking is handled automatically by the geodesic estimator G1/G3; no manual min_rtt filter sampling configuration is required.

### Alias Properties

| Property | Delegates To |
|----------|--------------|
| MinRtoUs | MinRtoMicros |
| MaxRtoUs | MaxRtoMicros |
| RtoBackoffFactor | RetransmitBackoffFactor |
| KeepAliveIntervalUs | KeepAliveIntervalMicros |
| DisconnectTimeoutUs | DisconnectTimeoutMicros |
| UCPMinRttWindowMicros | Removed in KCC 2.0 (min_rtt tracking handled automatically by geodesic G1/G3) |
| InitialCwndBytes | InitialCwndPackets (get/set in bytes) |

### Effective (Clamped) Properties

| Property | Description |
|----------|-------------|
| EffectiveMinRtoMicros | MinRtoMicros floored at protocol constant (50 ms) |
| EffectiveMaxRtoMicros | MaxRtoMicros, never below EffectiveMinRtoMicros |
| EffectiveRetransmitBackoffFactor | Clamped to >= 1.0 |
| EffectiveMaxBandwidthLossPercent | Clamped to [15%, 35%] |
| MaxPayloadSize | Mss - DataHeaderSize (20 bytes) |
| MaxAckSackBlocks | Physical limit based on MSS vs configured AckSackBlockLimit |
| ReceiveWindowBytes | RecvWindowPackets * Mss as uint |
| InitialCongestionWindowBytes | Max(Mss, InitialCwndPackets * Mss) |

### Pacing and KCC Congestion Control Gains

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| MinPacingIntervalMicros | long | 0 | 0-10,000 | Minimum inter-packet gap (0 = no floor) |
| PacingBucketDurationMicros | long | 10,000 (10 ms) | 1,000-100,000 | Token bucket capacity window |

The KCC pacing/CWND gains (Startup 2.887x, Drain 0.344x, ProbeBW 1.25/0.75) are fixed constants in UcpCongestionControl and are not configurable via UcpConfiguration.

**Flow control boundary**: During STARTUP (before full bandwidth is reached), the sendable upper limit is the peer-declared receive window — the initial cwnd does NOT cap the first burst. Once full bandwidth is reached, the upper limit is min(cwnd, peer-declared receive window) (standard TCP/QUIC flow control). `InitialCwndPackets` sets the starting congestion window value only; the peer-advertised `WindowSize` is the authoritative hard cap on bytes in flight during STARTUP.

### Bandwidth and Loss Control

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| InitialBandwidthBytesPerSecond | long | 12,500,000 (100 Mbps) | 125,000-1,250,000,000 | Initial bandwidth estimate for UCP Startup |
| MaxPacingRateBytesPerSecond | long | 12,500,000 | 0-unlimited | Pacing rate ceiling (0 = off) |
| ServerBandwidthBytesPerSecond | int | 12,500,000 | 125,000-1,250,000,000 | Server aggregate egress bandwidth for fair-queue |
| MaxBandwidthWastePercent | double | 0.25 | 0-1 | Retransmit waste ceiling (ratio) |
| MaxBandwidthLossPercent | double | 25% | 15-35 (clamped) | Loss tolerance budget |

### Code Example

```csharp
var config = UcpConfiguration.GetOptimizedConfig();
config.Mss = 9000;                          // Jumbo frames for high-BDP paths
config.FecRedundancy = 0.125;               // 1 repair per 8 data packets
config.ServerBandwidthBytesPerSecond = 1_000_000_000 / 8; // 1 Gbps
config.InitialCwndPackets = 40;             // More aggressive initial window
config.TimerIntervalMilliseconds = 5;       // Finer-grained timer tick
```

---

## UcpServer (Server API)

**Source:** [Ucp/UcpServer.cs](../Ucp/UcpServer.cs)

```csharp
public class UcpServer : IUcpObject, IDisposable
```

Listens for incoming connections on a UDP port. Manages fair-queue scheduling across all active connections.

### Constructors

```csharp
public UcpServer()                                    // Default config, creates own UDP transport
public UcpServer(UcpConfiguration config)             // Custom config, creates own UDP transport
internal UcpServer(ITransport transport)              // Custom transport, default config
internal UcpServer(ITransport transport, int bandwidthLimitBytesPerSecond)
internal UcpServer(ITransport transport, UcpConfiguration config)
```

### Start

```csharp
public void Start(int port)                                              // Bind to port on all interfaces
public void Start(UcpNetwork network, int port, UcpConfiguration configuration) // Start within a UcpNetwork
```

`Start(port)` binds a dual-stack IPv6/UDP socket, subscribes to transport datagrams, and starts the fair-queue timer. When called without a network, a .NET Timer drives fair-queue rounds; otherwise the network's timer system is used.

### AcceptAsync

```csharp
public async Task<UcpConnection> AcceptAsync()
```

Blocks until a new client completes the three-way handshake. Returns a fully established `UcpConnection`. Connections are delivered in FIFO order. Thread-safe; multiple consumers can await simultaneously.

### Stop

```csharp
public void Stop()
```

Unsubscribes from transport events, stops the fair-queue timer, disposes all managed PCBs (sending RST to each peer), stops and optionally disposes the transport. Idempotent.

### Dispose

```csharp
public void Dispose()
```

Calls `Stop()`.

### IUcpObject Members

```csharp
public uint ConnectionId { get; }    // Always 0 (server is not a single connection)
public UcpNetwork Network { get; }   // Owning network, or null when standalone
```

### Fair-Queue Scheduling

The server distributes bandwidth credit to active connections every `FairQueueRoundMilliseconds` (default 10 ms). Credit is proportional to each connection's KCC congestion control pacing rate, capped at equal fair share. Connections are flushed in rotated round-robin order to prevent starvation. The server bandwidth limit is derived from `ServerBandwidthBytesPerSecond`.

### Code Example

```csharp
var config = UcpConfiguration.GetOptimizedConfig();
using var server = new UcpServer(config);
server.Start(9000);
Console.WriteLine($"Listening on port 9000");

// Accept one connection
UcpConnection conn = await server.AcceptAsync();
Console.WriteLine($"Accepted: {conn.RemoteEndPoint}");

// Echo received data back
byte[] buf = new byte[65536];
int n = await conn.ReadAsync(buf, 0, buf.Length);
await conn.WriteAsync(buf, 0, n);

server.Stop();
```

---

## UcpConnection (Connection API)

**Source:** [Ucp/UcpConnection.cs](../Ucp/UcpConnection.cs)

```csharp
public class UcpConnection : IUcpObject, IDisposable
```

Bidirectional data stream over the UCP protocol. Supports both active (outgoing) and passive (accepted from server) connections.

### Constructors

```csharp
public UcpConnection()                                              // Default config, own UDP transport
public UcpConnection(UcpConfiguration config)                        // Custom config, own UDP transport
internal UcpConnection(ITransport transport, ...)                    // Custom transport (internal)
internal UcpConnection(UcpPcb pcb, ITransport transport, UcpConfiguration config) // Server-accept path
internal UcpConnection(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
```

### ConnectAsync

```csharp
public async Task<UcpConnection> ConnectAsync(IPEndPoint remote)
```

Initiates the three-way handshake (SYN / SYN-ACK / ACK) to the specified remote endpoint. Binds the transport to an OS-assigned ephemeral port if not already bound. Returns `this` for fluent chaining. Throws `ArgumentNullException` for null endpoint; throws `InvalidOperationException` if already connected.

```csharp
public async Task<UcpConnection> ConnectAsync(UcpNetwork network, IPEndPoint remote)
```

Connects through a shared `UcpNetwork`, swapping the transport to the network's adapter for multiplexed I/O. The network owns the transport; the connection does not dispose it.

Supports both IPv4 and IPv6 endpoints via dual-stack UDP socket.

### Send / SendAsync (Non-blocking)

```csharp
public int Send(byte[] buf, int offset, int count)
public int Send(byte[] buf, int offset, int count, UcpPriority priority)
public async Task<int> SendAsync(byte[] buf, int offset, int count)
public async Task<int> SendAsync(byte[] buf, int offset, int count, UcpPriority priority)
```

Returns bytes accepted (may be less than `count`), or -1 on error. `Send` wraps `SendAsync` with a 5-second timeout. Data is enqueued on the connection's serial queue for ordered, non-concurrent PCB access. The `priority` parameter (default `Normal`) controls QoS ordering.

### Write / WriteAsync (Reliable)

```csharp
public bool Write(byte[] buf, int off, int count)
public bool Write(byte[] buf, int off, int count, UcpPriority priority)
public async Task<bool> WriteAsync(byte[] buf, int off, int count)
public async Task<bool> WriteAsync(byte[] buf, int off, int count, UcpPriority priority)
```

Loops `SendAsync` internally until all `count` bytes are accepted or the connection fails. Returns `true` on success, `false` on error or timeout. Recommended for production use. Never throws.

### Receive / ReceiveAsync

```csharp
public int Receive(byte[] buf, int offset, int count)
public async Task<int> ReceiveAsync(byte[] buf, int offset, int count)
```

Returns at least 1 byte of in-order data, up to `count`. Returns 0 if the connection is closed, -1 on error. `Receive` wraps `ReceiveAsync` with a 5-second timeout.

### Read / ReadAsync (Exact Byte Count)

```csharp
public bool Read(byte[] buf, int off, int count)
public async Task<bool> ReadAsync(byte[] buf, int off, int count)
```

Reads exactly `count` bytes, looping `ReceiveAsync` internally. Returns `true` on success, `false` if the connection closed before all bytes arrived. Never throws.

### Close / CloseAsync

```csharp
public void Close()
public async Task CloseAsync()
```

Initiates graceful FIN handshake: drains the send buffer, sends FIN, waits for the peer's FIN-ACK, then cleans up transport resources. `Close` wraps with a 5-second timeout; on timeout, forces cleanup.

### Dispose

```csharp
public void Dispose()
```

Calls `Close()`. Never throws.

### MigrateRemote (CID Migration)

```csharp
public void MigrateRemote(IPEndPoint newEndPoint)
```

Explicitly migrates the connection to a new remote endpoint. Triggers path-change logic in the PCB and resets KCC congestion control state (marking path as changed). No-op if PCB is null.

### Events

```csharp
public event Action<byte[], int, int> OnData           // In-order payload arrives (buffer, offset, count)
public event Action<byte[], int, int> OnDataReceived    // Alias for OnData (backward compat)
public event Action OnConnected                        // Handshake completes
public event Action OnDisconnected                     // Connection closes (graceful or error)
```

Events fire on the connection's serial queue (SerialQueue strand). Calling connection methods from event handlers is safe.

### Diagnostics

```csharp
public UcpTransferReport GetReport()                    // Full transfer statistics snapshot
internal UcpConnectionDiagnostics GetDiagnostics()      // Internal diagnostics snapshot
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| ConnectionId | uint | 32-bit random connection identifier |
| RemoteEndPoint | IPEndPoint | Remote peer endpoint |
| Network | UcpNetwork | Owning network engine (null when standalone) |

### Error Handling

All public sync methods (`Send`, `Receive`, `Read`, `Write`, `Close`) catch exceptions internally and return error codes or `false`. Async methods catch `OperationCanceledException` and `ObjectDisposedException`. The connection will fire `OnDisconnected` on protocol-level failures (max retransmissions, handshake timeout, etc.).

### Code Example (Client)

```csharp
var config = UcpConfiguration.GetOptimizedConfig();
using var conn = new UcpConnection(config);

conn.OnConnected += () => Console.WriteLine("Connected!");
conn.OnDisconnected += () => Console.WriteLine("Disconnected");

await conn.ConnectAsync(new IPEndPoint(IPAddress.Parse("192.168.1.100"), 9000));

byte[] request = Encoding.UTF8.GetBytes("Hello UCP!");
await conn.WriteAsync(request, 0, request.Length);

byte[] response = new byte[1024];
int n = await conn.ReceiveAsync(response, 0, response.Length);
Console.WriteLine($"Received: {Encoding.UTF8.GetString(response, 0, n)}");

var report = conn.GetReport();
Console.WriteLine($"RTT: {report.LastRttMicros / 1000.0:F2} ms");
Console.WriteLine($"Throughput: {report.MeasuredBandwidthBytesPerSecond * 8 / 1_000_000:F2} Mbps");

await conn.CloseAsync();
```

---

## UcpNetwork (Event Loop Driver)

**Source:** [Ucp/UcpNetwork.cs](../Ucp/UcpNetwork.cs)

```csharp
public abstract class UcpNetwork : IDisposable
```

Abstract event-loop network driver. Manages timers, PCB routing/registration, and a cached monotonic clock. Call `DoEvents()` in a loop to drive protocol progress.

### Concrete Implementation

Use `UcpDatagramNetwork` for real UDP I/O, or subclass `UcpNetwork` for custom transports.

### DoEvents

```csharp
public virtual int DoEvents()
```

Heartbeat of the network layer. Processes due timers, ticks all active PCBs (RTO checks, delayed flushes, KCC sample updates), and yields when idle (calls `Thread.Yield()` for imminent timers, `Thread.Sleep(0)` otherwise). Returns count of work items processed. Must be called periodically (recommended: every `TimerIntervalMilliseconds`).

### Input / Output

```csharp
public void Input(byte[] datagram, IPEndPoint remote)
public void Output(byte[] datagram, IPEndPoint remote)
public abstract void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
```

`Input` injects a received datagram: decodes the packet, routes to the matching PCB by connection ID (fast path), or falls back to the transport adapter for SYN packets (server/connection accept). `Output` sends an encoded packet; the abstract overload accepts an `IUcpObject` sender for tracing.

### Timer API

```csharp
public uint AddTimer(long expireUs, Action callback)
public bool CancelTimer(uint timerId)
```

`AddTimer` registers a one-shot timer at the given absolute microsecond time. Returns a timer ID for cancellation. The wrapped callback checks cancellation before executing. `CancelTimer` returns `true` if the timer was found and cancelled.

### Factory Methods

```csharp
public UcpServer CreateServer(int port)
public UcpConnection CreateConnection()
public UcpConnection CreateConnection(UcpConfiguration configuration)
```

Create server or connection instances bound to this network's transport adapter. The adapter is shared (multiplexed I/O).

### Properties

| Property | Type | Description |
|----------|------|-------------|
| Configuration | UcpConfiguration | Protocol configuration (cloned at construction) |
| CurrentTimeUs | long | Cached network clock in microseconds (consistent within a DoEvents tick) |
| NowMicroseconds | long | Raw stopwatch time (may be stale up to ~1 ms) |
| LocalEndPoint | EndPoint | Bound socket endpoint (override in derived classes; null in base) |

### Start / Stop / Dispose

```csharp
public virtual void Start(int port)    // Base is no-op; derived classes bind socket
public virtual void Stop()             // Base is no-op; derived classes close socket
public virtual void Dispose()          // Stops network, clears all timers
```

---

## UcpDatagramNetwork (UDP Network)

**Source:** [Ucp/UcpDatagramNetwork.cs](../Ucp/UcpDatagramNetwork.cs)

```csharp
public sealed class UcpDatagramNetwork : UcpNetwork
```

Concrete UDP socket network implementation. Runs a background receive loop via `Task.Run` that injects datagrams via `Input()`.

### Constructors

```csharp
public UcpDatagramNetwork()                                          // Default config, unstarted
public UcpDatagramNetwork(int port)                                  // Default config, starts on port
public UcpDatagramNetwork(IPAddress localAddress, int port)          // Default config, binds to address + port
public UcpDatagramNetwork(UcpConfiguration configuration)            // Custom config, unstarted
public UcpDatagramNetwork(IPAddress localAddress, int port, UcpConfiguration configuration) // Full
```

### Start

```csharp
public override void Start(int port)                            // Delegates to Start(IPAddress.IPv6Any, port)
public void Start(IPAddress localAddress, int port)
```

Creates a dual-stack IPv6 UDP socket with `DualMode = true` so both IPv4 and IPv6 traffic share one socket. Falls back to IPv4-only when IPv6 is unavailable. The receive loop runs on a ThreadPool task.

### Output

```csharp
public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
```

Sends via `UdpClient.SendAsync`. Lazily starts the socket with an OS-assigned port if not yet bound. Send failures are observed and silently ignored (transient UDP errors are expected).

### Properties

```csharp
public override EndPoint LocalEndPoint  // Bound UDP socket's local endpoint
```

### Code Example

```csharp
var network = new UcpDatagramNetwork(9000);  // Start listening on port 9000

// Create a managed server on the network
var server = network.CreateServer(9000);

// Create a connection on the same network (multiplexed)
var conn = network.CreateConnection();
await conn.ConnectAsync(network, new IPEndPoint(IPAddress.Loopback, 9000));

// Drive the event loop
while (true)
{
    int work = network.DoEvents();
    if (work == 0) await Task.Delay(1);
}
```

---

## IUcpObject Interface

**Source:** [Ucp/IUcpObject.cs](../Ucp/IUcpObject.cs)

```csharp
public interface IUcpObject
{
    uint ConnectionId { get; }
    UcpNetwork Network { get; }
}
```

Common contract for UCP-aware senders. `ConnectionId` enables transport-layer demultiplexing. `Network` provides access to the owning event loop for coordinated scheduling. Both `UcpConnection` and `UcpServer` implement this interface.

---

## ITransport / IBindableTransport / UdpSocketTransport

**Source:** [Ucp/Transport/ITransport.cs](../Ucp/Transport/ITransport.cs), [Ucp/Transport/IBindableTransport.cs](../Ucp/Transport/IBindableTransport.cs), [Ucp/Transport/UdpSocketTransport.cs](../Ucp/Transport/UdpSocketTransport.cs)

### ITransport

```csharp
public interface ITransport : IDisposable
{
    event Action<byte[], IPEndPoint> OnDatagram;
    void Send(byte[] data, IPEndPoint remote);
}
```

The network I/O abstraction. Implement this interface to integrate UCP with non-UDP transports (WebRTC DataChannel, in-process simulation, encrypted tunnels, etc.). `OnDatagram` fires for each received datagram. `Send` transmits an encoded packet to the destination.

### IBindableTransport (internal)

```csharp
internal interface IBindableTransport : ITransport
{
    EndPoint LocalEndPoint { get; }
    void Start(int port);
    void Stop();
}
```

Extends `ITransport` with bind lifecycle. `Start(int port)` binds to a port (0 = OS-assigned). `Stop()` signals the receive loop to exit. `LocalEndPoint` exposes the bound address.

### UdpSocketTransport (internal)

```csharp
internal sealed class UdpSocketTransport : IBindableTransport
```

Default UDP transport. Creates a dual-stack IPv6 socket with `DualMode = true` for IPv4/IPv6. Configures OS socket buffers to `UcpConstants.UDP_SOCKET_BUFFER_BYTES`. Runs a background receive loop via `Task.Run`. Lazy-starts with port 0 on first `Send` if not explicitly started.

### Custom Transport Example

```csharp
public class LoopbackTransport : ITransport
{
    public event Action<byte[], IPEndPoint> OnDatagram;

    public void Send(byte[] data, IPEndPoint remote)
    {
        // Simulate immediate loopback
        OnDatagram?.Invoke(data, remote);
    }

    public void Dispose() { }
}

// Use with UcpConnection
var transport = new LoopbackTransport();
var conn = new UcpConnection(transport); // internal constructor
```

---

## UcpTransferReport (Diagnostics)

**Source:** [Ucp/UcpTransferReport.cs](../Ucp/UcpTransferReport.cs)

```csharp
public sealed class UcpTransferReport
```

Populated by `UcpConnection.GetReport()`. All fields are public.

| Field | Type | Description |
|-------|------|-------------|
| BytesSent | long | Total user payload bytes accepted for sending |
| BytesReceived | long | Total user payload bytes delivered in order |
| DataPacketsSent | int | Original DATA packets transmitted |
| RetransmittedPackets | int | DATA packets re-sent to repair loss |
| AckPacketsSent | int | ACK packets emitted |
| NakPacketsSent | int | NAK packets emitted (explicit loss reports) |
| FastRetransmissions | int | Retransmits triggered by SACK/NAK/dup-ACK (before RTO) |
| TimeoutRetransmissions | int | Retransmits triggered by RTO expiry |
| LastRttMicros | long | Most recent RTT sample in microseconds |
| RttSamplesMicros | List\<long\> | Historical RTT samples |
| CongestionWindowBytes | long | Current KCC congestion control congestion window |
| PacingRateBytesPerSecond | double | Current UCP pacing rate |
| MeasuredBandwidthBytesPerSecond | double | True throughput (ACK-confirmed payload bytes / time window) |
| EstimatedLossPercent | double | Estimated packet loss (0-100 scale) |
| RemoteWindowBytes | uint | Peer-advertised receive window |

### Computed Property

```csharp
public double RetransmissionRatio  // RetransmittedPackets / DataPacketsSent (0 if no data)
```

---

## UcpFecCodec (FEC Configuration)

**Source:** [Ucp/UcpFecCodec.cs](../Ucp/UcpFecCodec.cs)

```csharp
internal sealed class UcpFecCodec
```

RS-GF(256) Forward Error Correction encoder/decoder. Configurable via `UcpConfiguration` fields `FecRedundancy` and `FecGroupSize`.

### Constructor (internal)

```csharp
public UcpFecCodec(int groupSize)                // Single repair packet per group
public UcpFecCodec(int groupSize, int repairCount) // Custom repair count
```

`groupSize` clamped to [2, 64]; `repairCount` clamped to [1, groupSize].

### Key Methods (internal)

| Method | Description |
|--------|-------------|
| TryEncodeRepair(byte[] payload) / TryEncodeRepair(uint seq, byte[] payload) | Feed payload into send buffer; returns first repair payload when group is full |
| TryEncodeRepairs(byte[] payload) / TryEncodeRepairs(uint seq, byte[] payload) | Feed payload into send buffer; returns all repair payloads when group is full |
| FeedDataPacket(uint seq, byte[] payload) | Store received data in receive buffer |
| TryRecoverFromRepair(byte[] repair, uint groupBase, ...) | Attempt single-packet recovery from a repair |
| TryRecoverPacketsFromRepair(byte[] repair, uint groupBase, int repairIndex) | Attempt full group recovery with Gaussian elimination |

### FEC Configuration via UcpConfiguration

```csharp
config.FecRedundancy = 0.125;   // 1 repair per 8 data packets (12.5% overhead)
config.FecGroupSize = 8;        // 8 data packets per FEC group
```

---

## UcpPriority Enum

**Source:** [Ucp/UcpEnums.cs](../Ucp/UcpEnums.cs) (line 106)

```csharp
public enum UcpPriority : byte
{
    Background  = 0,   // Lowest priority, background data
    Normal      = 1,   // Default bulk transfer (default when unspecified)
    Interactive = 2,   // Low-latency data (chat, gaming)
    Urgent      = 3    // Highest priority (control, retransmissions)
}
```

Used with `Send`, `SendAsync`, `Write`, `WriteAsync` to control QoS ordering within a single connection's send buffer.

---

## C++ Cross-Reference

The C++ implementation under [cpp/](../cpp/) mirrors the C# public API surface and wire format exactly.

| C# API | C++ Equivalent | Notes |
|--------|----------------|-------|
| UcpConfiguration.GetOptimizedConfig() | `UcpConfiguration::GetOptimizedConfig()` | Same parameter set, same defaults |
| UcpServer.Start/Stop/AcceptAsync | `UcpServer::Start/Stop/AcceptAsync` | C++ uses callback-based accept; no Task\<T\> |
| UcpConnection.ConnectAsync | `UcpConnection::ConnectAsync` | C++ is callback-based (ConnectAsyncCallback) |
| UcpConnection.Send/Write | `UcpConnection::SendAsync` / `UcpConnection::Write` | Identical semantics |
| UcpConnection.Receive/Read | `UcpConnection::Receive` / `UcpConnection::Read` | Identical semantics |
| UcpConnection.SetOnData | `UcpConnection::SetOnData` callback | Same (buffer, offset, count) signature |
| UcpConnection.GetReport | `UcpConnection::GetReport()` | Same UcpTransferReport fields |
| UcpNetwork.DoEvents | `UcpNetwork::DoEvents()` | Event loop driver |
| ITransport | `transport::ITransport` interface | Same abstraction |
| UcpFecCodec | `UcpFecCodec` | Same RS-GF(256) |
| UcpPriority.Normal | `UcpPriority::Normal` | Same 4-tier QoS |

For full details, see [cpp/README_EN.md](../cpp/README_EN.md) and [cpp/docs/api_EN.md](../cpp/docs/api_EN.md).

---

## Error Handling

| Exception Type | When Thrown | Recovery |
|----------------|-------------|----------|
| ObjectDisposedException | Operations on disposed object | Use `using` statements |
| InvalidOperationException | ConnectAsync called twice; Write before connect | Await the handshake before data operations |
| ArgumentNullException | Null endpoint, buffer, or config passed | Validate arguments before calling |
| SocketException | UDP socket bind/send errors | Change port, check firewall, verify network config |
| OperationCanceledException | Operation cancelled during Close/Dispose | Expected during normal shutdown; handled internally |
| ObjectDisposedException (internal) | PCB or transport disposed | Handled internally; propagated as -1 or false |

All synchronous public API methods (`Send`, `Receive`, `Read`, `Write`, `Close`) catch exceptions internally and return error codes or `false` to avoid unhandled exceptions in application code. Async methods propagate exceptions via the returned `Task`.

`OnDisconnected` fires for both graceful and error closures. Event handlers execute on the connection's serial queue; calling connection methods from within event handlers is safe.

---

## End-to-End Example

```csharp
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Ucp;

class Program
{
    static async Task Main()
    {
        var config = UcpConfiguration.GetOptimizedConfig();
        config.ServerBandwidthBytesPerSecond = 100_000_000 / 8; // 100 Mbps
        config.FecRedundancy = 0.125;
        config.Mss = 9000;

        using var server = new UcpServer(config);
        server.Start(9000);
        Console.WriteLine($"Server on port {9000}");

        Task<UcpConnection> acceptTask = server.AcceptAsync();

        using var client = new UcpConnection(config);
        client.OnConnected += () => Console.WriteLine("[Client] Connected");
        client.OnDisconnected += () => Console.WriteLine("[Client] Disconnected");

        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));
        UcpConnection serverConn = await acceptTask;

        // Client sends
        byte[] msg = Encoding.UTF8.GetBytes("Hello from UCP!");
        await client.WriteAsync(msg, 0, msg.Length);

        // Server receives exact bytes
        byte[] buf = new byte[msg.Length];
        await serverConn.ReadAsync(buf, 0, buf.Length);
        Console.WriteLine($"Server got: {Encoding.UTF8.GetString(buf)}");

        // Server replies
        byte[] reply = Encoding.UTF8.GetBytes("ACK: received!");
        await serverConn.WriteAsync(reply, 0, reply.Length);

        // Client reads reply
        byte[] replyBuf = new byte[reply.Length];
        await client.ReadAsync(replyBuf, 0, replyBuf.Length);
        Console.WriteLine($"Client got: {Encoding.UTF8.GetString(replyBuf)}");

        // Diagnostics
        var r = client.GetReport();
        Console.WriteLine($"Throughput:  {r.MeasuredBandwidthBytesPerSecond * 8 / 1e6:F2} Mbps");
        Console.WriteLine($"RTT:         {r.LastRttMicros / 1000.0:F2} ms");
        Console.WriteLine($"Retransmissions: {r.RetransmittedPackets}");

        await client.CloseAsync();
        await serverConn.CloseAsync();
        server.Stop();
    }
}
```

---

## IPv6 Support

UCP has native IPv6 support at every layer:

- **UdpSocketTransport** (Ucp/Transport/UdpSocketTransport.cs:166-176) creates a dual-stack IPv6 socket with `DualMode = true`, accepting both IPv4 and IPv6 traffic on a single socket. Falls back to IPv4-only when the host does not support IPv6.
- **UcpDatagramNetwork** (Ucp/UcpDatagramNetwork.cs:207-216) uses the same dual-stack strategy, binding to `IPAddress.IPv6Any` by default.
- **UcpConnection.ConnectAsync** accepts `IPEndPoint` with any address family (IPv4 or IPv6). The dual-stack socket automatically maps IPv4 addresses for transmission.
- **MSS default** (1220 bytes) fits IPv6 minimum MTU (1280 bytes) minus headers, ensuring no IP fragmentation.
- Explicit IPv6 binding is supported: `UcpDatagramNetwork(IPAddress.Parse("::1"), 9000)` binds to a specific IPv6 address.

[^kcc_gain]: The startup pacing gain is defined in UcpCongestionControl and expressed as 739/256 ≈ 2.887x in BBR_UNIT (256) space, derived from `ceil(2885 × 256 / 1000) = 739`.

[^kcc_drain]: The drain pacing gain is defined in UcpCongestionControl and expressed as 88/256 ≈ 0.344x in BBR_UNIT (256) space, derived from `256 × 1000 / 2885 = 88` (integer division).

---

## License and Trademark

MIT License. See [LICENSE](../LICENSE) for full text.

Copyright (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ is a trademark of PPP PRIVATE NETWORK.
