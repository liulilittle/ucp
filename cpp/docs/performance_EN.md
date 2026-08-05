# UCP C++ Performance Characteristics

[Chinese](performance_CN.md)

This document describes the performance characteristics of the UCP C++ implementation, including the KCC (Geodesic Congestion Control) mechanism with geodesic estimator (G1/G2/G3) RTT estimation, RTO estimator, Pacing controller, FEC codec performance, benchmark results, and comparison with TCP/QUIC.

## KCC Congestion Control Kernel

UCP's KCC congestion control engine uses real-time delivery rate rather than loss as the primary congestion signal. The KCC algorithm cycles through three modes: Startup uses a 2.887x Pacing gain to rapidly probe available bandwidth, Drain purges the in-flight queue, and ProbeBW dynamically probes and adapts to bandwidth changes through an 8-phase gain cycle [1.25, 0.75, 1.0x6]. MinRTT tracking is handled automatically by the geodesic estimator G1/G3.

KCC (Geodesic Congestion Control) is the congestion control algorithm used by UCP, combining the KCC 3-mode state machine (Startup/Drain/ProbeBW) with a geodesic estimator (G1/G2/G3) for propagation delay estimation (KF component from tcp_kcc.c v2.0; fixed structural parameters: p_est_init=1000, scale=1024). MinRTT tracking is handled automatically by geodesic G1/G3. The geodesic estimator replaces the window-min filter used in traditional model-based approaches with three structural branches (G1 instant downward absorption, G2 bounded 12.2%-per-RTT growth, G3 dual-threshold path-increase detection: fast 6 consecutive events at 1.10x, slow 7 consecutive events at 1.05x). There is no covariance matrix, no process model, and no adaptive gain. Key features include fixed per-mode gains (no gain decay), ECN-aware graduated backoff (disabled by default), long-term bandwidth EWMA with consistency checks, ACK aggregation compensation (dual-window 5-RTT rotation), and the optional cross-connection Kalman filter (KF). FEC provides recovered-bytes samples (improving bandwidth/RTT estimation) and NAK provides loss-sample data (improving long-term bandwidth estimation) to the congestion control engine for more accurate bandwidth/delay estimation under packet loss.

### UcpConfiguration Structure

```cpp
class UcpConfiguration {
    int     Mss                          = 1220;
    int     MaxRetransmissions           = 10;
    int64_t MinRtoMicros                 = 50000;
    int64_t MaxRtoMicros                 = 15000000;
    double  RetransmitBackoffFactor      = 1.2;
    int64_t KeepAliveIntervalMicros      = 1000000;
    int64_t DisconnectTimeoutMicros      = 4000000;
    int     TimerIntervalMilliseconds    = 1;
    int     FairQueueRoundMilliseconds   = 10;
    int64_t InitialBandwidthBytesPerSecond = 12500000;
    int64_t MaxPacingRateBytesPerSecond    = 12500000;
    int     MaxCongestionWindowBytes       = 64 * 1024 * 1024;
    int     InitialCwndPackets             = 10;
    int     RecvWindowPackets              = 4096;
    int     SendQuantumBytes               = 1220;
    bool    LossControlEnable              = true;
    double  FecRedundancy                  = 0.0;
    int     FecGroupSize                   = 8;
    bool    EnableMtuDiscovery             = true;
};
```

Congestion control gains are fixed constants (matching tcp_kcc.c): Startup pacing/cwnd 2.887x (739/256), Drain pacing 0.344x (88/256), ProbeBW cycle [1.25, 0.75, 1.0x6] with cwnd gain 2.0x. They are not configurable.

### KCC Modes and Gains

| Mode | Pacing Gain | CWND Gain | Duration | Exit Condition |
|---|---|---|---|---|
| Startup | 2.887 (739/256) | 2.887 | ~3-5 RTT | 3 consecutive RTT growth < 25% |
| Drain | 0.344 (88/256) | 2.887 | ~1 RTT | In-flight <= BDP AND 1 RTT elapsed (or 4x min_rtt timeout) |
| ProbeBW | Cycle [1.25, 0.75, 1.0x6] | 2.0 | Steady state | 8-phase cycle |

C++ and C# use identical gain values: Startup=2.887 (739/256), Drain=0.344 (88/256).

## Pacing Controller Performance

| Operation | Method | Behavior |
|---|---|---|
| Normal send | TryConsume(bytes, now) | Refill -> check token balance |
| Urgent retransmit | ForceConsume(bytes, now) | Refill -> send directly (token balance zeroed, no negative debt) |
| Wait time | GetWaitTimeMicros(bytes, now) | Returns (bytes - _tokens) * 1e6 / rate |
| Rate change | SetRate(rate, now) | Set new rate, reset bucket capacity |

## RTO Estimator Performance

### RTO Core Constants

| Constant | C++ Value | C# Value |
|---|---|---|
| INITIAL_RTO_MICROS | 50ms | 50ms |
| MIN_RTO_MICROS | 50ms | 50ms |
| DEFAULT_RTO_MICROS | 50ms | 50ms |
| MAX_RTO_MICROS | 60s | 60s |
| RTO_BACKOFF_FACTOR | 1.2 | 1.2 |

### RTO Formula

```
Initial: SRTT = sample, RTTVAR = sample / 2, RTO = clamp(SRTT + 4*RTTVAR, MIN, MAX)
Per RTT sample: SRTT = 7/8*SRTT + 1/8*sample
                RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - sample|
                RTO = clamp(SRTT + 4*RTTVAR, MIN, MAX)
Timeout backoff: RTO = clamp(RTO * 1.2, MIN, MAX)
```

### Key Differences vs TCP RTO

| Feature | TCP | UCP C++ | Reason |
|---|---|---|---|
| Initial RTO | 1s | 50ms | NAK/FEC handles most loss |
| Minimum RTO | 200ms | 50ms | Faster dead-path detection on LAN |
| Backoff factor | 2.0 | 1.2 | UCP does not reduce CWND |

## FEC Codec Performance

| Operation | Complexity | CPU |
|---|---|---|
| Addition | O(1) | XOR |
| Multiplication | O(1) | 2 lookups + 1 add + 1 mod |
| Division | O(1) | 2 lookups + 1 sub |
| Inversion | O(1) | 1 lookup + 1 sub |

### Codec Complexity

```
Encoding: O(R * N * L) GF256 multiplications, R=repair packets, N=group size, L=payload length
Decoding: O(N^3 * L / slot_length) GF256 operations (Gaussian elimination)
```

| Configuration | Redundancy Overhead | Recoverable Loss |
|---|---|---|
| group_size=8, repair_count=1 | 12.5% | Up to 1 packet per group |
| group_size=8, repair_count=2 | 25% | Up to 2 packets per group |
| group_size=16, repair_count=4 | 25% | Up to 4 packets per group |
| FEC disabled | 0% | 0 |

## Benchmark Results

### C++ Implementation Benchmarks

| Scenario | Target Mbps | RTT | Loss | Throughput Mbps | Utilization |
|---|---|---|---|---|---|
| NoLoss | 83.89 | 9ms | 0% | 35.54 | 42.37% |
| LongFatPipe | 100 | 102ms | 0% | 64.35 | 64.35% |
| Gigabit_Loss1 | 1000 | 40ms | 2.06% | 288.03 | 28.80% |
| Gigabit_Loss5 | 1000 | 60ms | 10.64% | 200.55 | 20.05% |
| Benchmark10G | 10000 | 2ms | 0% | 8528.43 | 85.28% |
| DataCenter | 10000 | 0ms | 0% | 10000.00 | 100.00% |
| Enterprise | 1000 | 30ms | 0% | 339.97 | 34.00% |
| AsymRoute | 100 | 40ms | 0% | 45.62 | 45.62% |
| HighJitter | 100 | 100ms | 0% | 22.93 | 22.93% |
| Weak4G | 10 | 160ms | 10.91% | 3.63 | 36.32% |

C++ implementation achieves highest utilization on long RTT paths, benefiting from the 1ms Pacing timer.

### Performance Projections

| Scenario | Target Mbps | RTT | Loss | Expected Throughput | Expected Retrans% |
|---|---|---|---|---|---|
| NoLoss | 100 | 0.5ms | 0% | 95-100 Mbps | 0% |
| Lossy 1% | 100 | 10ms | 1% | 90-99 Mbps | ~1.2% |
| Lossy 5% | 100 | 10ms | 5% | 75-95 Mbps | ~6% |
| Satellite | 10 | 300ms | 0% | 8.5-9.9 Mbps | 0% |
| Mobile 4G | 20 | 50ms | 1% | 18-19.8 Mbps | ~1.2% |
| VPN Tunnel | 50 | 15ms | 1% | 45-49.5 Mbps | ~1.3% |

### Timer Granularity Impact on Pacing Precision

| Timer Period | Pacing Frame Rate | Max Token per Frame | Utilization Loss |
|---|---|---|---|
| 1ms (C++) | 1000 Hz | 12.5 KB | < 1% |
| 1ms (C#) | 1000 Hz | 12.5 KB | < 1% |

## Convergence Characteristics

No-loss convergence:

| Path | RTT | Startup + Drain | Actual Convergence |
|---|---|---|---|
| LAN | 0.5ms | 2.5ms | < 50ms |
| Broadband | 10ms | 50ms | < 500ms |
| Satellite | 300ms | 1.5s | < 30s |

## Comparison with TCP / QUIC

### UCP vs TCP

| Feature | TCP (CUBIC) | UCP C++ |
|---|---|---|
| Loss response | CWND halved (50%) | Packet-conservation recovery + LT-BW EMA (no multiplicative cwnd cut) |
| Congestion detection | Loss-based | RTT + delivery-rate based |
| Minimum RTO | 200ms | 50ms |
| 5% loss throughput | 30-50% utilization | 20.05% utilization (measured, see benchmark table above) |
| FEC | None | RS-GF(256) |
| Recovery paths | DupACK + RTO | SACK/NAK/FEC/DupACK/RTO (five paths) |

### UCP vs QUIC

| Feature | QUIC | UCP C++ |
|---|---|---|
| Connection migration | Optional | Enabled by default |
| Congestion control | Pluggable (default NewReno) | UCP (built-in) |
| ACK model | ACK frames | Piggybacked ACK (all types) |
| NAK | None | Three-tier confidence NAK |
| FEC | None | RS-GF(256) |
| Multiplexing | Built-in streams | Per-connection independent |

## Performance Tuning Guide

### MSS Tuning

| Path Type | Recommended MSS | Reason |
|---|---|---|
| Low bandwidth (< 1 Mbps) | 536-1220 | Avoid IP fragmentation |
| Broadband (1-100 Mbps) | 1220 (default) | Optimal balance |
| Gigabit LAN (1-10 Gbps) | 9000 (jumbo) | Reduce ~85% per-packet overhead |
| Satellite (high RTT) | 1220-9000 | Reduce ACK packet count |

### Common Pitfalls

| Pitfall | Symptom | Solution |
|---|---|---|
| MSS too small | Gigabit only ~500Mbps | Mss = 9000 |
| SendBuffer too small | WriteAsync frequently blocks | SetSendBufferSize(BDP * 1.5) |
| MaxPacingRate ceiling | Throughput stuck at 100Mbps | MaxPacingRateBytesPerSecond = 0 |
| FEC misconfigured | Retrans% >> Loss% | FecRedundancy = 0.25 |

## Related Documents

- [architecture_EN.md](architecture_EN.md) — Runtime layer structure
- [protocol_EN.md](protocol_EN.md) — Protocol specification
- [api_EN.md](api_EN.md) — API reference
- [constants_EN.md](constants_EN.md) — Protocol constants
- [README_EN.md](../README_EN.md) — Project overview
- [Linux Kernel Module](../../linux/README.md) — KCC Geodesic Congestion Control module (tcp_kcc.c v2.0, with KCC Forwarding (KF) for cross-connection bandwidth sharing)

---

## License and Trademark

MIT License. See [LICENSE](../../LICENSE) for full text.

Copyright (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ is a trademark of PPP PRIVATE NETWORK.
