# UCP — Universal Communication Protocol

A production-grade, QUIC-inspired reliable transport protocol implemented in C# on top of UDP, featuring BBRv1 congestion control, token-bucket pacing, selective ACK (SACK), negative ACK (NAK), forward error correction (FEC), adaptive network classification, and a deterministic event-loop driver.

## Quick Start

```csharp
using Ucp;

// Server
var config = UcpConfiguration.GetOptimizedConfig();
config.ServerBandwidthBytesPerSecond = 100_000_000 / 8; // 100 Mbps
using var server = new UcpServer(config);
server.Start(9000);

// Client
using var client = new UcpConnection(config);
await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));

// Reliable stream transfer
byte[] data = Encoding.UTF8.GetBytes("Hello, UCP!");
await client.WriteAsync(data, 0, data.Length);
```

## Features

| Layer | Capability |
|---|---|
| **Reliability** | Cumulative ACK + SACK blocks + NAK retransmission, fast retransmit, RTO timeout recovery, tail-loss probe |
| **Congestion Control** | BBRv1 with Startup → Drain → ProbeBW → ProbeRTT state machine, loss classifier (random vs congestion), adaptive pacing gain |
| **Pacing** | Token-bucket rate limiter, configurable bucket duration, urgent-send bypass for dying connections |
| **Network Classification** | Real-time `NetworkClass` detection (LowLatencyLAN, MobileUnstable, LossyLongFat, CongestedBottleneck, SymmetricVPN) wired into BBR gain decisions |
| **Forward Error Correction** | XOR-FEC with configurable group size and redundancy, repair packet type `FecRepair (0x08)` |
| **Fair Queue** | Per-connection credit-based scheduling on the server side |
| **Strand Model** | Per-connection `SerialQueue` for lock-free serial protocol state mutation |
| **Event Loop Driver** | `UcpNetwork.DoEvents()` drives timers, RTO, pacing delayed flushes, and FQ rounds deterministically |
| **Simulation** | `NetworkSimulator` with configurable delay, jitter, dynamic wave skew, bandwidth serialization, selective drop rules |

## Architecture

```
Application                 UcpConnection / UcpServer
    │
Protocol Core               UcpPcb
    │
Congestion & Pacing         BbrCongestionControl + PacingController + UcpRtoEstimator
    │
Reliability                 UcpSackGenerator, NAK state machine, FEC codec
    │
Serialization               UcpPacketCodec (big-endian wire format)
    │
Network Driver              UcpNetwork / UcpDatagramNetwork
    │
Transport                   UDP Socket
```

## Key Design Decisions

- **Loss is not congestion.** Random packet loss triggers retransmission only — pacing gain and congestion window are NOT reduced unless RTT inflation, delivery-rate drop, and sustained elevated loss are all confirmed.
- **QUIC-style loss detection.** SACK-based: first missing sequence requires 2 observations and RTT/2 age. Distance confirmation: 20+ SACKed packets beyond the hole confirm it as lost. Time-based: 9/8 × smoothedRTT threshold for tail loss.
- **BBR over loss-based CC.** BBR probes bandwidth via delivery rate estimation rather than reacting to loss events. The loss classifier distinguishes random from congestion loss using deduplicated sliding windows and RTT median analysis.
- **Jumbo MSS for high-bandwidth paths.** Benchmark scenarios ≥ 1 Gbps use 9000-byte MSS to avoid control-plane packet amplification (3500+ packets for 4 MB at 1220-byte MSS vs. ~470 at 9000-byte).

## Configuration Reference

All tuning parameters live in `UcpConfiguration`. Call `UcpConfiguration.GetOptimizedConfig()` for sensible defaults.

### Protocol Tuning

| Parameter | Default | Description |
|---|---|---|
| `Mss` | 1220 | Maximum Segment Size in bytes. Set to 9000 for jumbo-frame paths. |
| `MaxRetransmissions` | 10 | Maximum retransmission attempts per outbound segment before connection abort. |
| `SendBufferSize` | 32 MB | Send buffer capacity in bytes. Limits outstanding unsent data. |
| `ReceiveBufferSize` | ~20 MB | Receive buffer capacity (derived from RecvWindowPackets × Mss). |
| `InitialCwndPackets` | 20 | Initial congestion window in packets. Multiplied by Mss for byte count. |
| `InitialCwndBytes` | — | Convenience setter: initial congestion window in bytes. |
| `MaxCongestionWindowBytes` | 64 MB | Hard cap on congestion window. |
| `SendQuantumBytes` | Mss | Minimum send quantum for pacing token consumption. |
| `AckSackBlockLimit` | 149 | Maximum SACK blocks per ACK packet (MSS-dependent upper bound). |

### RTO & Timers

| Parameter | Default | Description |
|---|---|---|
| `MinRtoMicros` | 200,000 μs | Minimum retransmission timeout. |
| `MaxRtoMicros` | 15,000,000 μs | Maximum retransmission timeout. |
| `RetransmitBackoffFactor` | 1.2 | Multiplicative RTO backoff factor per timeout. |
| `ProbeRttIntervalMicros` | 30,000,000 μs | BBR ProbeRTT interval (30 seconds). |
| `ProbeRttDurationMicros` | 100,000 μs | BBR ProbeRTT minimum duration. |
| `KeepAliveIntervalMicros` | 1,000,000 μs | Keep-alive interval (1 second). |
| `DisconnectTimeoutMicros` | 4,000,000 μs | Idle disconnect timeout. |
| `TimerIntervalMilliseconds` | 20 ms | Internal timer tick interval. |
| `DelayedAckTimeoutMicros` | 2,000 μs | Delayed ACK coalescing timeout. Set to 0 to disable. |

### Pacing

| Parameter | Default | Description |
|---|---|---|
| `MinPacingIntervalMicros` | 1,000 μs | Minimum inter-packet pacing gap. |
| `PacingBucketDurationMicros` | 10,000 μs | Token bucket refill window duration. |

### BBR Gains

| Parameter | Default | Description |
|---|---|---|
| `StartupPacingGain` | 2.0 | BBR Startup pacing gain multiplier. |
| `StartupCwndGain` | 2.0 | BBR Startup congestion window gain. |
| `DrainPacingGain` | 0.75 | BBR Drain pacing gain (reverts to 1.0 if no loss detected). |
| `ProbeBwHighGain` | 1.25 | BBR ProbeBW up-phase gain. |
| `ProbeBwLowGain` | 0.85 | BBR ProbeBW down-phase gain. |
| `ProbeBwCwndGain` | 2.0 | BBR ProbeBW congestion window gain. |
| `BbrWindowRtRounds` | 10 | BBR bandwidth filter window length in RTT rounds. |

### Bandwidth & Loss Control

| Parameter | Default | Description |
|---|---|---|
| `InitialBandwidthBytesPerSecond` | 12.5 MB/s | Initial bottleneck bandwidth estimate. |
| `MaxPacingRateBytesPerSecond` | 12.5 MB/s | Maximum pacing rate ceiling. Set to 0 to disable. |
| `ServerBandwidthBytesPerSecond` | 12.5 MB/s | Server egress bandwidth for FQ scheduling. |
| `LossControlEnable` | true | Enable loss-aware pacing/cwnd reduction. |
| `MaxBandwidthLossPercent` | 25% | Loss budget ceiling (clamped to 15%–35%). Only triggers when network is classified as congested. |

### FEC (Forward Error Correction)

| Parameter | Default | Description |
|---|---|---|
| `FecRedundancy` | 0.0 | FEC redundancy ratio (0.0 = off, 0.125 = 1 repair per 8 packets). |
| `FecGroupSize` | 8 | Number of data packets per FEC group. |

### Internal Flags

| Parameter | Default | Description |
|---|---|---|
| `EnableDebugLog` | false | Enable per-packet trace logging. |
| `FairQueueRoundMilliseconds` | 10 ms | Fair queue credit distribution interval. |

## Benchmark Report

Run `.\run-tests.ps1` to execute all 48 test scenarios and generate `reports/test_report.txt`.

Coverage:
- **Bandwidths**: 4 Mbps → 10 Gbps
- **Loss rates**: 0% → 10%
- **RTT**: 0.5 ms → 300 ms
- **Scenarios**: LAN, data center, enterprise broadband, asymmetric routing, long fat pipe, mobile 3G/4G, satellite, VPN tunnel, burst loss, weak network, high jitter, dual congestion

## License

MIT
