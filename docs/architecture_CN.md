# PPP PRIVATE NETWORK™ X — 通用通信协议 (UCP) — 架构

[English](architecture.md) | [文档索引](index_CN.md)

**协议标识: `ppp+ucp`** — 本文档描述 UCP 协议引擎的内部运行时架构，涵盖分层设计、每连接状态管理、会话追踪、串行执行、公平队列调度、拥塞控制内核、FEC 编解码器设计以及确定性网络模拟器。

---

## 运行时分层

UCP 按分层架构组织，从面向应用的 API 一直下沉到传输层 socket。每层封装一个明确定义的职责：

```mermaid
flowchart TD
    App[应用程序] --> Public[UcpConnection / UcpServer]
    Public --> Pcb[UcpPcb — 协议控制块]
    Pcb --> Bbr[Bbrv2CongestionControl]
    Pcb --> Pacing[PacingController]
    Pcb --> Rto[UcpRtoEstimator]
    Pcb --> Sack[UcpSackGenerator]
    Pcb --> Nak[UcpNakProcessor]
    Pcb --> Fec[UcpFecCodec]
    Pcb --> ConnId[ConnectionIdTracker]
    Pcb --> Codec[UcpPacketCodec]
    Codec --> Net[UcpNetwork / UcpDatagramNetwork]
    ConnId --> Net
    Net --> Transport[ITransport / UDP Socket]
    Transport --> Wire[网络线路]

    subgraph "每连接串行环境 (SerialQueue)"
        Pcb
        Bbr
        Pacing
        Rto
        Sack
        Nak
        Fec
    end
```

### 各层职责

| 层级 | 组件 | 作用 |
|---|---|---|
| **公共 API** | `UcpServer`, `UcpConnection` | 面向应用的连接生命周期、发送/接收、事件模型。 |
| **协议控制** | `UcpPcb` | 每连接状态机、定时器管理、发送/接收缓冲协调。 |
| **拥塞控制** | `Bbrv2CongestionControl` | BBRv2 状态机配自适应 pacing 增益、投递率估计、丢包分类。 |
| **Pacing** | `PacingController` | 字节级 token bucket，支持有界负余额紧急恢复突发。 |
| **定时器** | `UcpRtoEstimator` | RTT 采样、RTO 退避计算、PTO 守卫逻辑。 |
| **恢复** | `UcpSackGenerator`, `UcpNakProcessor` | SACK 块生成（每块范围最多 2 次发送）；分级置信度 NAK 发送与处理。 |
| **FEC** | `UcpFecCodec` | Reed-Solomon GF(256) 编解码，基于观测丢包率自适应冗余。 |
| **编解码** | `UcpPacketCodec` | 序列化/反序列化含捎带 ACK 字段提取（所有包类型）。 |
| **会话** | `ConnectionIdTracker` | 基于连接 ID 的多路分解、随机 ISN 分配、IP 无关绑定。 |
| **网络** | `UcpNetwork` | 数据报分发、`DoEvents()` 驱动循环、公平队列轮次协调。 |

---

## UcpPcb — 协议控制块

`UcpPcb` 是每连接的核心状态容器。每个活跃连接拥有一个 PCB 实例，管理协议状态机的所有方面。与传统基于 IP:port 元组绑定的 socket 控制不同，PCB 以随机 32 位连接 ID 为键，在会话期间不受 IP 地址变更的影响。

### 连接状态机

```mermaid
stateDiagram-v2
    [*] --> Init
    Init --> HandshakeSynSent: 主动打开 / SYN
    Init --> HandshakeSynReceived: 被动收到 SYN / SYNACK
    HandshakeSynSent --> Established: 收到 SYNACK
    HandshakeSynReceived --> Established: 对端 ACK
    Established --> ClosingFinSent: 本端关闭 / FIN
    Established --> ClosingFinReceived: 对端 FIN
    ClosingFinSent --> Closed: FIN 已确认
    ClosingFinReceived --> Closed: FIN 已确认
    Closed --> [*]
    HandshakeSynSent --> Closed: 超时/RST
    HandshakeSynReceived --> Closed: 超时/RST
    Established --> Closed: 超时/RST

    note right of HandshakeSynSent: 生成随机 ISN<br>分配随机 ConnId
    note left of HandshakeSynReceived: 从 SYN 提取 ConnId<br>验证 ISN
```

### 基于连接 ID 的会话追踪（IP 无关）

每个 UCP 连接通过 SYN 时生成的加密级随机 32 位连接 ID 进行标识。`UcpNetwork` 中的 `ConnectionIdTracker` 维护从连接 ID 到 PCB 实例的字典映射。

```mermaid
sequenceDiagram
    participant C as 客户端（Wi-Fi → 蜂窝）
    participant N as NAT/网络
    participant S as UcpServer

    C->>N: SYN ConnId=0xABCD, src=10.0.0.1:50000
    N->>S: SYN ConnId=0xABCD, src=1.2.3.4:30000
    S->>S: ConnId 查找：无 → 创建 PCB
    S->>N: SYNACK ConnId=0xABCD → 1.2.3.4:30000

    Note over C: 网络切换：Wi-Fi → 蜂窝
    C->>N: DATA ConnId=0xABCD, src=10.0.1.1:60000
    N->>S: DATA ConnId=0xABCD, src=1.2.3.4:40000（新映射）
    S->>S: ConnId 查找：找到 PCB<br>ValidateRemoteEndPoint：接受
    S->>N: DATA ConnId=0xABCD → 1.2.3.4:40000
    Note over C,S: 会话幸存 NAT 重绑定和 IP 变更
```

此设计支持：
- **NAT 重绑定韧性**：客户端 NAT 映射在会话中途变化时，服务端仍能将包路由到正确的 PCB。
- **IP 移动性**：客户端从 Wi-Fi 切换到蜂窝时，保持相同的连接 ID 和会话状态。
- **多路径就绪**：同一连接 ID 可将来自多个接口的包路由到同一 PCB（未来功能）。

### PCB 组件关系

```mermaid
flowchart TD
    PCB[UcpPcb] --> Sender[发送端状态]
    PCB --> Receiver[接收端状态]
    PCB --> Timers[定时器管理]
    PCB --> Recovery[恢复系统]

    Sender --> SendBuf[_sendBuffer: SortedDictionary]
    Sender --> Flight[_flightBytes 计数器]
    Sender --> NextSeq[_nextSendSequence]
    Sender --> SackDedup[_sackFastRetransmitNotified]
    Sender --> SackCount[_sackSendCount 每范围]
    Sender --> UrgentBudget[_urgentRecoveryPacketsInWindow]
    Sender --> AckPiggy[_ackPiggybackQueue]

    Receiver --> RecvBuf[_recvBuffer: SortedDictionary]
    Receiver --> NextExp[_nextExpectedSequence]
    Receiver --> RecvQueue[_receiveQueue 供应用读取]
    Receiver --> MissCounts[_missingSequenceCounts]
    Receiver --> NakTier[_nakConfidenceTier]
    Receiver --> LastNak[_lastNakIssuedMicros]
    Receiver --> FecMeta[_fecFragmentMetadata]

    Timers --> RtoTimer[RTO 定时器]
    Timers --> KeepAlive[保活定时器]
    Timers --> Disconnect[断连定时器]
    Timers --> DelayedAck[延迟 ACK 定时器]
    Timers --> ProbeRTT[ProbeRTT 定时器]

    Recovery --> BBR[Bbrv2CongestionControl]
    Recovery --> SACK[UcpSackGenerator]
    Recovery --> NAK[UcpNakProcessor]
    Recovery --> FEC[UcpFecCodec]
    Recovery --> RTO[UcpRtoEstimator]
```

### 发送端状态

| 结构 | 作用 |
|---|---|
| `_sendBuffer` | 按序号排序、等待 ACK 的发送分段。每分段记录原始发送时间戳、重传次数和紧急恢复状态。 |
| `_flightBytes` | 当前在途 payload 字节数。BBRv2 用于计算投递率并执行 CWND 在途上限。 |
| `_nextSendSequence` | 支持 32 位环绕比较的下一个序号，按 2^32 取模单调递增。 |
| `_sackFastRetransmitNotified` | 去重 SACK 触发快重传决策。一旦缺口经 SACK 修复，不会再次重传直到新 SACK 证据确认新一轮丢包。 |
| `_sackSendCount` | 每个块范围的计数，将 SACK 通告限制在每范围 2 次发送。 |
| `_urgentRecoveryPacketsInWindow` | 每 RTT 限流器，控制 pacing/FQ 绕过的恢复包数。 |
| `_ackPiggybackQueue` | 待捎带的累积 ACK 号，挂载到下一个任意类型的出站包上。 |

### 接收端状态

| 结构 | 作用 |
|---|---|
| `_recvBuffer` | 按序号排序的乱序入站分段。使用类红黑树插入实现 O(log n) 有序访问。 |
| `_nextExpectedSequence` | 下一个可有序交付的序号。连续分段被取出时前移。 |
| `_receiveQueue` | 已有序、可供应用通过 `Receive()` / `ReceiveAsync()` 读取的 payload chunk。 |
| `_missingSequenceCounts` | 每序号缺口观测计数，用于分级置信度 NAK 生成。 |
| `_nakConfidenceTier` | 当前 NAK 置信层级：`低`（1-2 次观测，RTT×2 守卫）、`中`（3-4 次观测，RTT 守卫）、`高`（5+ 次观测，5ms 守卫）。 |
| `_lastNakIssuedMicros` | 每序号 NAK 重复抑制时间戳。 |
| `_fecFragmentMetadata` | FEC 恢复 DATA 包的原始分片元数据。 |

---

## SerialQueue 每连接串行执行

每个 `UcpConnection` 通过专用的 `SerialQueue` 处理所有协议事件 —— 单线程执行上下文（strand）。此设计完全消除锁竞争：

```mermaid
flowchart LR
    Inbound[入站数据报] --> Dispatch[按 ConnId 网络分发]
    Dispatch --> SQ[ConnId=0xABCD 的 SerialQueue]
    SQ --> Process[串行处理包]
    Process --> State[更新 PCB 状态]
    State --> Outbound[入列出站响应]
    Timer[定时器刻度] --> SQ
    AppCall[应用调用] --> SQ

    subgraph Strand[每连接串行环境]
        SQ
        Process
        State
    end

    Outbound --> Socket[UDP Socket 发送 - 串行环境外 I/O]
    Socket --> Wire[网络线路]
```

### 线程模型

```mermaid
flowchart TD
    Main[主线程 / 事件循环] --> DoEvents[UcpNetwork.DoEvents]
    DoEvents -->|遍历所有 PCB| Dispatch[每连接分发]

    Dispatch --> SQ1[SerialQueue #1 (Conn 0x0001)]
    Dispatch --> SQ2[SerialQueue #2 (Conn 0x0002)]
    Dispatch --> SQN[SerialQueue #N (Conn 0xNNNN)]

    subgraph "串行处理（每连接）"
        SQ1 --> T1A[处理定时器]
        SQ1 --> T1B[处理入站包]
        SQ1 --> T1C[刷新 Pacing 队列]
        SQ1 --> T1D[更新 BBRv2 样本]
        SQ1 --> T1E[处理应用调用]
    end

    subgraph "I/O 线程（串行环境外）"
        IO[UDP Socket 线程] --> Recv[接收数据报]
        IO --> Send[发送数据报]
    end

    Recv --> Dispatch
    Outbound[出站队列] --> Send
```

关键属性：
- **无锁**：PCB 状态永远不会被多线程并发访问。
- **可预测的顺序**：包按接收顺序处理；应用调用按序排队执行。
- **无死锁**：串行模型消除了多锁设计中固有的锁顺序问题。
- **I/O 卸载**：仅实际 UDP socket 发送/接收在串行环境外执行。

---

## 服务端公平队列调度

```mermaid
flowchart TD
    Server[UcpServer] --> FQ[公平队列调度器]
    FQ --> Round[轮次定时器：10ms]
    Round --> Calc[roundCredit = BW * 10ms / 活跃数]
    Calc --> Conn1[连接 1 +roundCredit]
    Calc --> Conn2[连接 2 +roundCredit]
    Calc --> Conn3[连接 N +roundCredit]

    Conn1 --> Cap1{Credit > 2 轮限制?}
    Conn2 --> Cap2{Credit > 2 轮限制?}
    Conn3 --> Cap3{Credit > 2 轮限制?}

    Cap1 -->|是| Discard1[封顶至 2x roundCredit]
    Cap2 -->|是| Discard2[封顶至 2x roundCredit]
    Cap3 -->|是| Discard3[封顶至 2x roundCredit]

    Discard1 --> Dequeue[每连接出列]
    Discard2 --> Dequeue
    Discard3 --> Dequeue
    Dequeue --> Pacing[PacingController]
    Pacing --> Socket[UDP Socket 发送]
```

---

## Pacing 与 Token Bucket

`PacingController` 实现字节级 token bucket，语义如下：

- **Token 填充速率**：`BBRv2.PacingRate` 字节/秒。
- **Bucket 容量**：`PacingRate * PacingBucketDurationMicros` —— 通常为 10ms 字节量。
- **普通发送**：消耗 `SendQuantumBytes`（默认 = MSS）个 token。若不足则推迟到下一 tick。
- **紧急发送（`ForceConsume()`）**：即使 token 不足也立即记账字节开销，bucket 可变为负值，负余额上限为 bucket 容量 50%。

```mermaid
sequenceDiagram
    participant S as 发送端 PCB
    participant P as PacingController
    participant FQ as 公平队列（服务端）
    participant Net as UDP Socket

    S->>P: 请求普通发送 (1400B)
    P->>P: Token 是否充足？
    alt Token >= 1400
        P->>FQ: 获取公平队列 credit
        FQ-->>P: Credit 授予
        P->>Net: 发送数据报
        P->>P: Token -= 1400
    else Token < 1400
        P->>S: 推迟；下一 tick 重试
    end

    Note over S,P: 紧急重传路径
    S->>P: ForceConsume(1400)
    P->>P: Token -= 1400（可能变负）
    P->>Net: 发送数据报（绕过 FQ）
    Note over P: 债务由后续普通发送偿还<br>负值上限：bucket 容量 50%
```

---

## BBRv2 拥塞控制与自适应 Pacing 增益

### BBRv2 状态机

```mermaid
stateDiagram-v2
    [*] --> Startup
    Startup --> Drain: 检测带宽平台
    Drain --> ProbeBW: 在途排空至 BDP 以下
    ProbeBW --> ProbeRTT: 需刷新 MinRTT（30s）
    ProbeRTT --> ProbeBW: MinRTT 已刷新
    ProbeBW --> ProbeBW: 循环增益（8 阶段）
    ProbeRTT --> ProbeBW: 丢包长肥路径 — 跳过 ProbeRTT

    note right of Startup: pacing_gain: 2.5<br>指数探测
    note right of Drain: pacing_gain: 0.75<br>排空队列
    note right of ProbeBW: 8 阶段循环<br>[1.35, 0.85, 1.0*6]
    note right of ProbeRTT: CWND: 4 包<br>100ms 持续时间
```

### 核心估计量

```mermaid
flowchart LR
    RateSamples[投递率样本] --> MaxFilter[取 RTT 窗口内最大值]
    MaxFilter --> BtlBw[BtlBw 估计]
    RTTSamples[RTT 样本] --> MinFilter[取 30s 窗口内最小值]
    MinFilter --> MinRtt[MinRtt 估计]

    BtlBw --> BDP[BDP = BtlBw * MinRtt]
    MinRtt --> BDP

    BtlBw --> PacingRate[PacingRate = BtlBw * Gain]
    BDP --> CWND[CWND = BDP * CWNDGain]

    LossClass[丢包分类] --> AdaptiveGain{自适应增益}
    AdaptiveGain -->|随机丢包| PacingRate
    AdaptiveGain -->|拥塞丢包| ReducedRate[PacingRate * 0.98]
```

---

## 协议栈数据包流

### 出站数据包流

```mermaid
sequenceDiagram
    participant App as 应用程序
    participant Conn as UcpConnection
    participant PCB as UcpPcb
    participant BBR as Bbrv2CongestionControl
    participant Pace as PacingController
    participant FQ as 公平队列
    participant Codec as UcpPacketCodec
    participant Net as UcpNetwork
    participant Sock as UDP Socket

    App->>Conn: WriteAsync(data)
    Conn->>PCB: 入列至 _sendBuffer
    PCB->>BBR: 检查 CWND（flightBytes < CWND?）
    BBR-->>PCB: CWND 允许
    PCB->>Pace: 请求 pacing token
    Pace-->>PCB: Token 可用
    PCB->>FQ: 请求公平队列 credit（仅服务端）
    FQ-->>PCB: Credit 授予
    PCB->>Codec: 编码 DATA 包
    Codec->>Net: 排队数据报
    Net->>Sock: UDP 发送
    Sock-->>Net: 线路传输
```

### 入站数据包流

```mermaid
sequenceDiagram
    participant Sock as UDP Socket
    participant Net as UcpNetwork
    participant Demux as ConnId 多路分解
    participant SQ as SerialQueue
    participant PCB as UcpPcb
    participant Codec as UcpPacketCodec
    participant Ack as ACK 处理器
    participant App as 应用程序

    Sock->>Net: 接收数据报
    Net->>Demux: 从公共头提取 ConnId
    Demux->>SQ: 入列至连接的 SerialQueue
    SQ->>PCB: 投递到串行环境
    PCB->>Codec: 解码包
    Codec-->>PCB: 解析包 + HasAckNumber 检查
    PCB->>Ack: ProcessPiggybackedAck（若 HasAckNumber 置位）
    Ack-->>PCB: 更新 _largestCumulativeAck，释放 _sendBuffer
    Ack-->>PCB: 处理 SACK 块 → 快重传检查
    Ack-->>PCB: 更新 RTT 样本 → BBR + RTO 估计器
    PCB-->>PCB: 处理包体（DATA→recvBuffer, NAK→重传 等）
    PCB->>App: 交付有序数据到 _receiveQueue → OnData 事件
```

---

## FEC — Reed-Solomon GF(256) 自适应传输

```mermaid
sequenceDiagram
    participant S as 发送端 FEC 编码器
    participant Net as 网络
    participant R as 接收端 FEC 解码器

    S->>S: N 个 DATA 包编组 (Seq 100-107)
    S->>S: 通过 GF(256) RS 编码生成 R 个修复包
    Note over S: repair[i][byte_j] = Σ(data[k][byte_j] * α^i^k)
    S->>Net: 发送全部 N 个 DATA 包
    S->>Net: 发送 R 个 FecRepair 包
    Net--xNet: 丢弃 DATA Seq 102, 105
    R->>R: 收到 DATA: 6/8 + Repair: 2 = 8 个包
    R->>R: 构建 Vandermonde 矩阵（GF(256)）
    R->>R: 高斯消元：恢复 Seq 102, 105
    R->>R: 以原始 SeqNum 插入 _recvBuffer
    R->>R: 取出连续分段到 _receiveQueue
```

---

## 网络模拟器

`NetworkSimulator` 是确定性进程内网络仿真器，支持：
- 独立去程/回程传播延迟及每方向抖动。
- 通过虚拟逻辑时钟进行带宽序列化，避免 OS 调度在吞吐计算中引入抖动。
- 可配的随机或确定性丢包、重复和乱序。
- 中途 outage 模拟（如 Weak4G 80ms 断网）。
- 显式去程/回程延迟对的非对称路由模型。

---

## 测试架构

| 测试领域 | 示例 |
|---|---|
| **核心协议** | 序号环绕、包编解码往返、RTO 估计器收敛、pacing controller token 记账。 |
| **连接管理** | 连接 ID 多路分解、随机 ISN 唯一性、服务端动态 IP 重绑定、串行队列顺序性。 |
| **可靠性** | 丢包传输、突发丢包、SACK 每范围 2 次发送限制、NAK 分级置信度、FEC 多丢包修复。 |
| **流完整性** | 乱序/重复、部分读取、全双工不交错、捎带 ACK 正确性。 |
| **性能** | 4 Mbps 到 10 Gbps、0-10% 丢包、移动、卫星、VPN、长肥管 BBRv2 收敛验证。 |
| **报告** | 吞吐封顶强制、丢包/重传独立性、方向不对称校验。 |

## 验证流程

```mermaid
flowchart TD
    Build[dotnet build] --> Tests[dotnet test]
    Tests --> Report[ReportPrinter.ValidateReportFile]
    Report --> Metrics{无 report-error?}
    Metrics -->|是| Done[接受本轮]
    Metrics -->|否| Fix[修复协议或报告口径]
    Fix --> Build

    Report --> C1[Throughput <= Target x 1.01]
    Report --> C2[Retrans% 在 0-100%]
    Report --> C3[方向延迟 3-15ms]
    Report --> C4[Loss% 独立 Retrans%]
    Report --> C5[无丢包利用率 >= 70%]
    Report --> C6[Pacing 比率 0.70-3.0]
```
