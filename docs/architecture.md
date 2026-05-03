# PPP PRIVATE NETWORK™ X — Universal Communication Protocol (UCP) — Architecture

[中文](architecture_CN.md) | [Documentation Index](index.md)

**Protocol designation: `ppp+ucp`** — This document provides a deep dive into UCP's internal runtime architecture, covering the six-layer design, per-connection UcpPcb state management, Connection-ID-driven IP-agnostic session tracking, SerialQueue strand-based execution, fair-queue server scheduling, PacingController token bucket design, BBRv2 congestion control internals, FEC Reed-Solomon GF(256) codec, complete inbound/outbound packet flow through the protocol stack, deterministic network simulator architecture, and test/validation flow.

---

## Runtime Layered Architecture

UCP is organized in six layers from application-facing APIs down to UDP Socket:

```mermaid
flowchart TD
    App["Application"] --> Public["UcpConnection / UcpServer"]
    Public --> Pcb["UcpPcb — Protocol Control Block"]
    Pcb --> Bbr["BbrCongestionControl"]
    Pcb --> Pacing["PacingController"]
    Pcb --> Rto["UcpRtoEstimator"]
    Pcb --> Sack["UcpSackGenerator"]
    Pcb --> Nak["NAK State Machine"]
    Pcb --> Fec["UcpFecCodec"]
    Pcb --> ConnId["ConnectionIdTracker"]
    Pcb --> Codec["UcpPacketCodec"]
    Codec --> Network["UcpNetwork / UcpDatagramNetwork"]
    ConnId --> Network
    Network --> Transport["ITransport / UDP Socket"]
    Transport --> Wire["Network Wire"]
    
    subgraph Strand["Per-Connection Strand (SerialQueue lock-free)"]
        Pcb
        Bbr
        Pacing
        Rto
        Sack
        Nak
        Fec
    end
```

### Layer Responsibilities

| Layer | Key Components | Responsibility |
|---|---|---|
| **Application** | `UcpServer`, `UcpConnection` | Public API. `UcpServer` manages passive accept, fair-queue scheduler, accept queue. `UcpConnection` provides async send/receive with backpressure, event-based data notification, diagnostics. |
| **Protocol Control** | `UcpPcb` (Protocol Control Block) | Complete per-connection state machine: send buffer with retransmit tracking, receive reorder buffer (O(log n) insert), ACK/SACK/NAK pipeline, timers, BBR, pacing, fair-queue credit, optional FEC. All state transitions serialized via SerialQueue. |
| **Congestion & Pacing** | `BbrCongestionControl`, `PacingController`, `UcpRtoEstimator` | BBRv2 computes pacing rate and CWND from delivery-rate samples (circular buffer EWMA). `PacingController` byte token bucket with bounded negative balance. `UcpRtoEstimator` provides smoothed RTT with 95th/99th percentile tracking. |
| **Reliability Engine** | `UcpSackGenerator`, NAK state machine, `UcpFecCodec` | SACK block generation (max 2 sends per range). NAK state machine tracks per-sequence gap observations with three-tier confidence guards. `UcpFecCodec` uses precomputed GF(256) log/antilog tables for O(1) RS encode/decode. |
| **Serialization** | `UcpPacketCodec` | Big-endian wire format for all 8 packet types, including piggybacked ACK field extraction. Validates packet integrity before protocol layer delivery. |
| **Network Driver** | `UcpNetwork`, `UcpDatagramNetwork` | Decouples engine from socket I/O. Connection-ID datagram demultiplexing, `DoEvents()` driver for timer dispatch and fair-queue rounds, SerialQueue strand coordination. |
| **Transport** | `UdpSocketTransport` (implements `IBindableTransport`) | UDP send/receive with dynamic port binding (port=0 for OS-assigned ephemeral). In-process `NetworkSimulator` implements same interface with virtual logical clock. |

### Layered Data Flow

```mermaid
sequenceDiagram
    participant App as "Application"
    participant Conn as "UcpConnection"
    participant PCB as "UcpPcb"
    participant BBR as "BbrCongestionControl"
    participant Pace as "PacingController"
    participant FQ as "FairQueue"
    participant Codec as "UcpPacketCodec"
    participant Net as "UcpNetwork"
    participant Sock as "UDP Socket"
    
    Note over App,Sock: "=== Outbound Path ==="
    App->>Conn: "WriteAsync(data)"
    Conn->>PCB: "Enqueue to _sendBuffer"
    PCB->>BBR: "Check CWND (flight < CWND?)"
    BBR-->>PCB: "CWND allows"
    PCB->>Pace: "Request pacing token"
    Pace-->>PCB: "Token available"
    PCB->>FQ: "Request fair-queue credit (server only)"
    FQ-->>PCB: "Credit granted"
    PCB->>Codec: "Encode DATA packet (with piggybacked ACK)"
    Codec->>Net: "Queue datagram"
    Net->>Sock: "UDP Send"
    
    Note over App,Sock: "=== Inbound Path ==="
    Sock->>Net: "Receive datagram"
    Net->>Net: "Extract ConnId from header"
    Net->>PCB: "Dispatch to SerialQueue"
    PCB->>Codec: "Decode + HasAckNumber check"
    Codec-->>PCB: "Parsed packet"
    PCB->>PCB: "ProcessPiggybackedAck"
    PCB->>PCB: "Update cumulative ACK, release send buffer"
    PCB->>PCB: "Process SACK blocks → fast retransmit check"
    PCB->>PCB: "Update RTT sample → BBR + RTO"
    PCB->>PCB: "Handle payload (DATA→recvBuffer, etc.)"
    PCB->>App: "Ordered data delivery → OnData event"
```

---

## UcpPcb — Protocol Control Block

`UcpPcb` is the central hub of UCP architecture. Each active connection has an independent PCB instance managing all dimensions of the protocol state machine. Unlike traditional kernel control blocks bound to IP:port tuples, UCP's PCB is keyed by a random 32-bit Connection ID, making it immune to IP address changes during a session.

### PCB Component Relationship Diagram

```mermaid
flowchart TD
    PCB["UcpPcb"] --> Sender["Sender State"]
    PCB --> Receiver["Receiver State"]
    PCB --> Timers["Timer Management"]
    PCB --> Recovery["Recovery System"]
    PCB --> Config["Configuration Reference"]
    
    Sender --> SendBuf["_sendBuffer<br/>SortedDictionary"]
    Sender --> Flight["_flightBytes<br/>in-flight counter"]
    Sender --> NextSeq["_nextSendSequence<br/>next sequence"]
    Sender --> SackDedup["_sackFastRetransmitNotified<br/>SACK dedup"]
    Sender --> SackCount["_sackSendCount<br/>per-range count"]
    Sender --> UrgentBudget["_urgentRecoveryPacketsInWindow<br/>urgent budget"]
    Sender --> AckPiggy["_ackPiggybackQueue<br/>pending ACK"]
    
    Receiver --> RecvBuf["_recvBuffer<br/>reorder buffer"]
    Receiver --> NextExp["_nextExpectedSequence<br/>expected next seq"]
    Receiver --> RecvQueue["_receiveQueue<br/>ordered delivery queue"]
    Receiver --> MissCounts["_missingSequenceCounts<br/>gap observation counts"]
    Receiver --> NakTier["_nakConfidenceTier<br/>NAK tier"]
    Receiver --> LastNak["_lastNakIssuedMicros<br/>NAK suppression timestamps"]
    Receiver --> FecMeta["_fecFragmentMetadata<br/>FEC metadata"]
    
    Timers --> RtoTimer["RTO Timer"]
    Timers --> KeepAlive["KeepAlive Timer"]
    Timers --> Disconnect["Disconnect Timer"]
    Timers --> DelayedAck["Delayed ACK Timer"]
    Timers --> ProbeRTT["ProbeRTT Timer"]
    
    Recovery --> BBR["BbrCongestionControl<br/>BBRv2"]
    Recovery --> SACK["UcpSackGenerator<br/>SACK generator"]
    Recovery --> NAK["NAK StateMachine<br/>NAK state machine"]
    Recovery --> FEC["UcpFecCodec<br/>FEC codec"]
    Recovery --> RTO["UcpRtoEstimator<br/>RTO estimator"]
```

### Sender State Details

| Data Structure | Type | Purpose |
|---|---|---|
| `_sendBuffer` | `SortedDictionary<uint, OutboundSegment>` | Sequence-sorted outbound segments awaiting ACK. Each segment tracks original send timestamp, retransmission count, urgent recovery flag, and FEC group affiliation. |
| `_flightBytes` | `long` | Total payload bytes currently in flight. BBRv2 uses this to compute delivery rate and enforce CWND in-flight cap. |
| `_nextSendSequence` | `uint` | Next 32-bit sequence number, incrementing monotonically modulo 2^32. Unsigned comparison with 2^31 window for wrap handling. |
| `_sackFastRetransmitNotified` | `HashSet<uint>` | Deduplicates SACK-triggered fast retransmit decisions per sequence. |
| `_sackSendCount` | `Dictionary<(uint,uint), int>` | Per-block-range send counter. Blocks reaching `SACK_BLOCK_MAX_SENDS`(2) are suppressed. |
| `_urgentRecoveryPacketsInWindow` | `int` | Urgent retransmit packets used in current RTT window (capped at 16). Resets at each new RTT estimate. |
| `_ackPiggybackQueue` | `uint?` | Pending cumulative ACK number to be carried on next outbound packet of any type. |

### Receiver State Details

| Data Structure | Type | Purpose |
|---|---|---|
| `_recvBuffer` | `SortedDictionary<uint, InboundSegment>` | Out-of-order inbound segments sorted by sequence with O(log n) insertion. |
| `_nextExpectedSequence` | `uint` | Next sequence needed for in-order delivery. Advances as contiguous segments drain. |
| `_receiveQueue` | `Queue<byte[]>` | Ordered payload chunks ready for application consumption via `ReadAsync`/`ReceiveAsync`. |
| `_missingSequenceCounts` | `Dictionary<uint, int>` | Per-sequence gap observation counter for NAK tier determination. |
| `_nakConfidenceTier` | `enum {Low, Medium, High}` | Current NAK tier: Low (1-2 obs, RTTx2 guard), Medium (3-4 obs, RTT guard), High (5+ obs, 5ms guard). |
| `_lastNakIssuedMicros` | `Dictionary<uint, long>` | Per-sequence NAK suppression timestamps (250ms repeat interval). |
| `_fecFragmentMetadata` | `Dictionary<uint, FragmentMeta>` | Original fragment metadata for FEC-recovered DATA packets preserving sequence numbers and fragment boundaries. |

---

## SerialQueue Per-Connection Strand Execution

UCP's core concurrency model is the **Strand**. Each `UcpConnection` processes all protocol events through its dedicated `SerialQueue`:

```mermaid
flowchart TD
    Main["Main Thread / Event Loop"] --> DoEvents["UcpNetwork.DoEvents()"]
    DoEvents -->|"Iterate all active PCBs"| Dispatch["Per-Connection Dispatch"]
    
    Dispatch --> SQ1["SerialQueue #1 (ConnId=0x0001)"]
    Dispatch --> SQ2["SerialQueue #2 (ConnId=0x0002)"]
    Dispatch --> SQN["SerialQueue #N (ConnId=0xNNNN)"]
    
    subgraph Strand1["Strand Processing (Conn #1)"]
        SQ1 --> T1A["Process Timers"]
        SQ1 --> T1B["Process Inbound Packets"]
        SQ1 --> T1C["Flush Pacing Queue"]
        SQ1 --> T1D["Update BBRv2 Samples"]
        SQ1 --> T1E["Process Application Calls"]
    end
    
    subgraph IO["I/O Thread (off-strand)"]
        IOThread["UDP Socket Thread"] --> Recv["Receive Datagrams"]
        IOThread --> Send["Send Datagrams"]
    end
    
    Recv --> Dispatch
    Outbound["Outbound Queue"] --> Send
```

### Strand Model Properties

| Property | Description |
|---|---|
| **Lock-free** | PCB state is never accessed concurrently from multiple threads. All mutations occur sequentially on the same strand. |
| **Predictable ordering** | Packets processed in receipt order; application calls queued and executed sequentially. |
| **Zero deadlock risk** | Strand model eliminates lock-ordering problems and ABBA deadlocks inherent in multi-lock designs. |
| **I/O offloading** | Only actual UDP Socket `Send()` and `Receive()` execute outside the strand. FEC decoding runs on-strand since GF(256) operations are computationally lightweight. |
| **Deterministic testing** | `NetworkSimulator` uses the same strand model with a virtual logical clock, producing fully reproducible results across different CPUs and OSes. |

```mermaid
flowchart LR
    Inbound["Inbound Datagram"] --> Dispatch["Network Dispatch<br/>by ConnId"]
    Dispatch --> SQ["SerialQueue<br/>for ConnId=X"]
    SQ --> Process["Process Packet<br/>on Strand"]
    Process --> State["Update PCB State"]
    State --> OutboundQ["Enqueue Outbound"]
    Timer["Timer Tick"] --> SQ
    AppCall["Application Call"] --> SQ
    
    subgraph StrandBox["Per-Connection Strand (lock-free)"]
        SQ
        Process
        State
    end
    
    OutboundQ --> Socket["UDP Socket Send<br/>off-strand I/O"]
```

---

## Fair-Queue Server Scheduling

```mermaid
flowchart TD
    Server["UcpServer"] --> FQ["Fair-Queue Scheduler"]
    FQ --> Round["Round Timer: 10ms"]
    Round --> Calc["roundCredit = BW x 10ms / ActiveCount"]
    Calc --> Conn1["Connection 1 +roundCredit"]
    Calc --> Conn2["Connection 2 +roundCredit"]
    Calc --> Conn3["Connection N +roundCredit"]
    
    Conn1 --> Cap1{"Credit > 2-round limit?"}
    Conn2 --> Cap2{"Credit > 2-round limit?"}
    Conn3 --> Cap3{"Credit > 2-round limit?"}
    
    Cap1 -->|"Yes"| Discard1["Cap at 2x roundCredit"]
    Cap2 -->|"Yes"| Discard2["Cap at 2x roundCredit"]
    Cap3 -->|"Yes"| Discard3["Cap at 2x roundCredit"]
    
    Cap1 -->|"No"| Dequeue["Per-connection dequeue"]
    Discard1 --> Dequeue
    Cap2 -->|"No"| Dequeue
    Discard2 --> Dequeue
    Cap3 -->|"No"| Dequeue
    Discard3 --> Dequeue
    
    Dequeue --> Pacing["PacingController Token Bucket"]
    Pacing --> Socket["UDP Socket Send"]
```

| Parameter | Value | Meaning |
|---|---|---|
| `FAIR_QUEUE_ROUND_MILLISECONDS` | 10ms | Round duration. Driven by Timer or `UcpNetwork.DoEvents()`. |
| `MAX_BUFFERED_FAIR_QUEUE_ROUNDS` | 2 rounds | Maximum credit accumulation. Long-idle connections cannot burst beyond 2 rounds of credit. |

---

## PacingController Token Bucket

```mermaid
sequenceDiagram
    participant S as "Sender PCB"
    participant P as "PacingController"
    participant FQ as "Fair Queue (server only)"
    participant Net as "UDP Socket"
    
    Note over S,Net: "=== Normal Send Path ==="
    S->>P: "Request normal send (1400B)"
    P->>P: "Check token balance"
    alt "Tokens >= 1400"
        P->>FQ: "Acquire fair-queue credit"
        FQ-->>P: "Credit granted"
        P->>Net: "Send datagram"
        P->>P: "Tokens -= 1400"
    else "Tokens < 1400"
        P->>S: "Defer; retry next timer tick"
    end
    
    Note over S,Net: "=== Urgent Retransmit Path ==="
    S->>P: "ForceConsume(1400)"
    P->>P: "Tokens -= 1400 (may go negative)"
    P->>Net: "Send datagram (bypass FQ)"
    Note over P: "Negative cap: 50% of bucket capacity<br/>Future normal sends repay debt"
```

---

## BBRv2 Congestion Control Internals

### Core Estimate Pipeline

```mermaid
flowchart LR
    RateSamples["Delivery Rate Samples"] --> MaxFilter["Max over RTT Window<br/>(BbrWindowRtRounds)"]
    MaxFilter --> BtlBw["BtlBw Estimate<br/>bottleneck bandwidth"]
    RTTSamples["RTT Samples"] --> MinFilter["Min over 30s Window"]
    MinFilter --> MinRtt["MinRtt Estimate"]
    
    BtlBw --> BDP["BDP = BtlBw x MinRtt"]
    MinRtt --> BDP
    
    BtlBw --> PacingRate["PacingRate = BtlBw x Gain"]
    BDP --> CWND["CWND = BDP x CWNDGain"]
    
    LossClass["Loss Classification"] --> AdaptiveGain{"Adaptive Gain"}
    AdaptiveGain -->|"Random Loss"| FastRec["Fast Recovery x1.25"]
    AdaptiveGain -->|"Congestion Loss"| Congestion["Gentle Reduce x0.98"]
    FastRec --> PacingRate
    Congestion --> PacingRate
```

### BBRv2 Mode Behavior

| Mode | Pacing Gain | CWND Gain | Duration | Purpose |
|---|---|---|---|---|
| **Startup** | 2.5 | 2.0 | Until bandwidth plateau (3 RTT rounds w/o growth) | Exponentially probe bottleneck bandwidth |
| **Drain** | 0.75 | — | ~1 BBR cycle (~1 RTT) | Drain excess queue accumulated during Startup |
| **ProbeBW** | Cycled [1.25, 0.85, 1.0*6] | 2.0 | Steady state | Eight-phase gain cycling around BtlBw |
| **ProbeRTT** | 1.0 | 4 packets | 100ms (every 30s) | Refresh MinRTT. Auto-skipped on lossy long-fat paths |

### Network Path Classification

BBRv2 uses 200ms sliding windows of RTT, jitter, loss rate, and throughput ratio:

| Network Type | Characteristics | BBR Adaptive Behavior |
|---|---|---|
| `LowLatencyLAN` | RTT < 1ms, zero loss | Aggressive initial probing, high Startup gain |
| `MobileUnstable` | High jitter, variable RTT | Wider reorder grace, skip ProbeRTT |
| `LossyLongFat` | High BDP, sustained random loss | Preserve CWND, skip ProbeRTT |
| `CongestedBottleneck` | Elevated RTT + delivery-rate drop | Enable loss-aware pacing reduction |
| `SymmetricVPN` | Stable RTT, symmetric bandwidth | Standard BBR probing cycles |

---

## Connection-ID-Driven Session Tracking

```mermaid
sequenceDiagram
    participant C as "Client (Wi-Fi→Cellular)"
    participant N as "NAT/Network"
    participant S as "UcpServer"
    
    C->>N: "SYN ConnId=0xABCD1234 src=10.0.0.1:50000"
    N->>S: "SYN ConnId=0xABCD1234 src=1.2.3.4:30000 (NAT mapped)"
    S->>S: "ConnId lookup: none → create PCB<br/>ConnId=0xABCD1234<br/>Generate random ISN=0x7F000001"
    S->>N: "SYNACK ConnId=0xABCD1234<br/>Seq=0x3E000001 HasAck=1 Ack=0x7F000002"
    N->>C: "SYNACK ConnId=0xABCD1234"
    
    C->>N: "ACK ConnId=0xABCD1234 AckNumber=0x3E000002"
    N->>S: "ACK ConnId=0xABCD1234"
    S->>S: "Handshake complete → Established"
    
    Note over C: "=== Network Switch: Wi-Fi → Cellular ==="
    
    C->>N: "DATA ConnId=0xABCD1234 src=10.0.1.1:60000 (new interface)"
    N->>S: "DATA ConnId=0xABCD1234 src=1.2.3.4:40000 (new NAT mapping)"
    S->>S: "ConnId lookup: found PCB ✓<br/>ValidateRemoteEndPoint: accept new IP:port"
    S->>N: "DATA ConnId=0xABCD1234 → 1.2.3.4:40000"
    N->>C: "DATA ConnId=0xABCD1234"
    
    Note over C,S: "Session continues uninterrupted!<br/>IP and port changes are fully transparent"
```

This design enables:
- **NAT rebinding resilience**: Server continues routing to the correct PCB
- **IP mobility**: Client migrates Wi-Fi→Cellular retaining the same Connection ID
- **Multipath readiness**: Same Connection ID can route from multiple interfaces to one PCB (future)

---

## FEC — Reed-Solomon GF(256) Codec

### Mathematical Foundation

**Field parameters:**
- Irreducible polynomial: `x^8 + x^4 + x^3 + x + 1` = `0x11B`
- Primitive element α = 0x02
- Addition: XOR (byte-level, hardware native)
- Multiplication: `antilog[(log[a] + log[b]) mod 255]` — O(1) table lookup
- Division: `antilog[(log[a] - log[b] + 255) mod 255]` — O(1) table lookup
- Log table: 256 entries, Antilog table: 512 entries

### Encode/Decode Flow

```mermaid
sequenceDiagram
    participant Enc as "Sender FEC Encoder"
    participant Net as "Network"
    participant Dec as "Receiver FEC Decoder"
    
    Enc->>Enc: "Group N=8 DATA, Seq 100-107"
    Enc->>Enc: "For each byte position j: 0..L-1<br/>Build vector v = [data[0][j],...,data[7][j]]"
    Enc->>Enc: "Generate R=2 repair bytes per position:<br/>repair[i][j] = SUM(k=0..7)(data[k][j] * alpha^(i*k))"
    
    Enc->>Net: "DATA Seq 100..107"
    Enc->>Net: "FecRepair Group=100 Idx=0,1"
    
    Net--xNet: "DROP DATA Seq 102, 105"
    
    Dec->>Dec: "Received: 6 DATA + 2 Repair = 8 entities"
    Dec->>Dec: "Detect missing: Seq 102, Seq 105"
    Dec->>Dec: "For each byte position j:<br/>Build GF256 Vandermonde system"
    Dec->>Dec: "Gaussian elimination → recover missing bytes"
    Dec->>Dec: "Assemble complete DATA with original SeqNums"
    Dec->>Dec: "Insert into _recvBuffer, advance cumulative ACK"
```

### Adaptive Redundancy Tiers

| Observed Loss Rate | Adaptive Behavior | Effective Redundancy |
|---|---|---|
| < 0.5% | Minimum (base config, typically 0.0–0.125) | Base value |
| 0.5% – 2% | Slight increase 1.25x | Base × 1.25 |
| 2% – 5% | Moderate increase 1.5x, reduce group size | Base × 1.5, min group 4 |
| 5% – 10% | Maximum adaptive 2.0x | Base × 2.0, min group 4 |
| > 10% | FEC alone insufficient; retransmission primary | FEC auxiliary role |

---

## Deterministic Network Simulator

`NetworkSimulator` provides the infrastructure for reproducible deterministic testing:

- **Virtual logical clock**: Independent of system wall clock, byte-precise serialization through bottleneck queue. Eliminates OS scheduling jitter.
- **Independent bidirectional delays**: Per-direction configurable propagation delay and jitter for asymmetric route modeling.
- **Configurable impairments**: Random or deterministic packet loss, duplication, and reordering (independently controllable).
- **Mid-transfer outage**: Configurable trigger time and duration (e.g., Weak4G: 900ms trigger, 80ms full blackout).
- **Packet integrity tracking**: Per-packet forward/return timestamps for precise one-way delay and convergence measurement.

---

## Test Architecture

| Test Area | Examples | Validates |
|---|---|---|
| **Core Protocol** | SequenceWrapAround, CodecRoundTrip, RtoConvergence, PacingTokenArithmetic | Wire format correctness, sequence arithmetic, RTO convergence, token bucket math |
| **Connection Mgmt** | ConnIdDemux, RandomISNUniqueness, DynamicIPRebind, SerialQueueOrdering | Connection-ID demux, ISN uniqueness, IP rebinding, strand ordering |
| **Reliability** | LossyTransfer, BurstLoss, Sack2SendLimit, NakTieredConfidence, FecRecovery | Recovery correctness under all loss patterns |
| **Stream Integrity** | Reordering, Duplication, PartialRead, FullDuplex, PiggybackedAckAllTypes | Application data integrity under all impairments |
| **Performance** | 14+ scenarios 4Mbps-10Gbps | Throughput, convergence, Retrans%/Loss% independence |
| **Report Validation** | ReportPrinter.ValidateReportFile | Physical plausibility of all metrics |

---

## Validation Flow

```mermaid
flowchart TD
    Build["dotnet build"] --> Tests["dotnet test (54 test cases)"]
    Tests --> Report["ReportPrinter.ValidateReportFile"]
    Report --> Metrics{"Zero report-error lines?"}
    Metrics -->|"Yes"| Done["Accept Run"]
    Metrics -->|"No"| Fix["Fix Protocol or Tests"]
    Fix --> Build
    
    Report --> C1["Throughput <= Target x 1.01"]
    Report --> C2["Retrans% in 0%-100%"]
    Report --> C3["Directional Delta 3-15ms"]
    Report --> C4["Loss% Independent Retrans%"]
    Report --> C5["No-loss Util >= 70%"]
    Report --> C6["Pacing Ratio 0.70-3.0"]
    Report --> C7["Jitter <= 4 x Config Delay"]
```
