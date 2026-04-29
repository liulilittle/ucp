# UCP API 完全参考手册

## 概述

UCP 提供三类主要 API 入口：`UcpServer`（服务端）、`UcpConnection`（客户端）、`UcpNetwork`（网络驱动）。所有配置集中在 `UcpConfiguration` 一个类型中。

---

## UcpConfiguration — 完整配置参数

`UcpConfiguration` 是所有协议行为的唯一配置入口。调用 `UcpConfiguration.GetOptimizedConfig()` 获取推荐默认值。

### 1. 基础协议参数

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `Mss` | int | 1220 | **最大分段大小（字节）**。控制每个数据包的最大 payload 长度。高带宽路径（≥1 Gbps）建议设为 9000 以减少包数量 |
| `MaxRetransmissions` | int | 10 | **最大重传次数**。单个分段超过此次数则连接中止 |
| `SendBufferSize` | int | 32 MB | **发送缓冲区大小（字节）**。限制待发送数据的最大缓冲量。WriteAsync 在此缓冲区满时会阻塞等待 |
| `ReceiveBufferSize` | int | ~20 MB | **接收缓冲区大小（字节）**。派生自 `RecvWindowPackets * Mss`，决定接收端能缓存的乱序数据量 |
| `InitialCwndPackets` | int | 20 | **初始拥塞窗口（包数）**。连接建立后的首个 CWND，实际字节数 = `InitialCwndPackets * Mss` |
| `InitialCwndBytes` | uint | — | **初始拥塞窗口（字节）便捷设置器**。设置时会自动换算为包数 |
| `MaxCongestionWindowBytes` | int | 64 MB | **拥塞窗口硬上限（字节）**。CWND 不会超过此值 |
| `SendQuantumBytes` | int | Mss | **最小发送量（字节）**。Pacing 令牌消费的最小粒度 |
| `AckSackBlockLimit` | int | 149 | **ACK 包中最大 SACK 块数量**。受 MSS 限制（更大的 SACK 块数需要更大的 ACK 包） |

### 2. RTO 与定时器

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `MinRtoMicros` | long | 200,000 μs | **最小 RTO（微秒）**。重传超时的下限。高延迟路径应适当增大 |
| `MaxRtoMicros` | long | 15,000,000 μs | **最大 RTO（微秒）**。重传超时的上限，防止过度退避 |
| `RetransmitBackoffFactor` | double | 1.2 | **RTO 退避因子**。每次超时后 RTO 乘以此值 |
| `ProbeRttIntervalMicros` | long | 30,000,000 μs | **BBR ProbeRTT 周期（微秒）**。默认 30 秒刷新一次最小 RTT 估计 |
| `ProbeRttDurationMicros` | long | 100,000 μs | **BBR ProbeRTT 最短持续时间（微秒）**。进入 ProbeRTT 后至少维持此时间 |
| `KeepAliveIntervalMicros` | long | 1,000,000 μs | **Keep-Alive 间隔（微秒）**。空闲时发送保活确认的周期 |
| `DisconnectTimeoutMicros` | long | 4,000,000 μs | **断开超时（微秒）**。无活动超过此时间则判定连接断开 |
| `TimerIntervalMilliseconds` | int | 20 ms | **内部定时器粒度（毫秒）**。PCB 周期检查的间隔 |
| `DelayedAckTimeoutMicros` | long | 2,000 μs | **延迟 ACK 超时（微秒）**。接收端累计数据后延迟发送 ACK 的上限。设为 0 禁用延迟 ACK |

### 3. Pacing（发送节奏控制）

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `MinPacingIntervalMicros` | long | 1,000 μs | **最小 Pacing 间隔（微秒）**。两个包之间的最小发送间隔 |
| `PacingBucketDurationMicros` | long | 10,000 μs | **Pacing 令牌桶窗口（微秒）**。令牌桶的容量 = `PacingRate * BucketDuration / 1s` |

### 4. BBR 增益参数

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `StartupPacingGain` | double | 2.0 | **BBR Startup 阶段 pacing 增益**。Startup 期间 pacing = btl_bw * 2.0 |
| `StartupCwndGain` | double | 2.0 | **BBR Startup 阶段 CWND 增益**。CWND = BDP * 2.0 |
| `DrainPacingGain` | double | 0.75 | **BBR Drain 阶段 pacing 增益**。若无丢包则实际使用 1.0 |
| `ProbeBwHighGain` | double | 1.25 | **BBR ProbeBW 上探增益**。周期性地用 1.25× 探测更多带宽 |
| `ProbeBwLowGain` | double | 0.85 | **BBR ProbeBW 下探增益**。周期性地用 0.85× 排空队列 |
| `ProbeBwCwndGain` | double | 2.0 | **BBR ProbeBW CWND 增益**。CWND 上限 = BDP * 2.0 |
| `BbrWindowRtRounds` | int | 10 | **BBR 带宽滤波窗口（RTT 轮数）**。最近 N 个 RTT 窗口内的最大 delivery rate |

### 5. 带宽与 Loss-Control

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `InitialBandwidthBytesPerSecond` | long | 12.5 MB/s | **初始瓶颈带宽估计**。连接建立时的 btl_bw 初始值 |
| `MaxPacingRateBytesPerSecond` | long | 12.5 MB/s | **最大 pacing 速率硬上限**。设为 0 表示不限制（BBR 自探测） |
| `ServerBandwidthBytesPerSecond` | int | 12.5 MB/s | **服务器出口带宽**。FQ 公平调度使用的总带宽 |
| `LossControlEnable` | bool | true | **是否启用丢包控制**。关闭后协议不会因丢包而降速，极度激进 |
| `MaxBandwidthLossPercent` | double | 25% | **最大容忍丢包率（百分比）**。会被限制在 15%–35% 范围。只有网络被判定为拥塞时才触发降速 |
| `MaxBandwidthWastePercent` | double | 25% | **最大容忍带宽浪费率**。用于限制 CWND 增长上限 |

### 6. FEC（前向纠错）

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `FecRedundancy` | double | 0.0 | **FEC 冗余比例**。0.0=关闭；0.125=每 8 个数据包发送 1 个 XOR 修复包 |
| `FecGroupSize` | int | 8 | **FEC 组大小**。每组 N 个数据包生成 1 个修复包 |

### 7. 内部标志

| 参数 | 类型 | 默认值 | 作用 |
|---|---|---|---|
| `EnableDebugLog` | bool | false | **调试日志开关**。开启后输出所有包的收发和处理日志 |
| `FairQueueRoundMilliseconds` | int | 10 ms | **FQ 调度轮次间隔（毫秒）** |

---

## UcpNetwork — 网络驱动抽象

```csharp
public abstract class UcpNetwork : IDisposable
```

`UcpNetwork` 将协议引擎从具体 Socket 实现中解耦。核心方法：

| 方法 | 作用 |
|---|---|
| `Input(byte[] datagram, IPEndPoint remote)` | 注入一个收到的 UDP 数据报到协议栈 |
| `abstract Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)` | 派生类实现，负责将编码后的包发送到网络 |
| `DoEvents()` | 驱动所有到期计时器、延迟 flush、RTO 检查和 FQ 轮次。无事件时会让出线程 |
| `AddTimer(long expireUs, Action callback)` | 注册微秒级到期回调 |
| `CreateServer(int port)` / `CreateConnection()` | 工厂方法，创建绑定到此网络的服务端/客户端连接 |

`IUcpObject` 接口暴露 `ConnectionId` 和 `Network`，使网络层能读取发送方元数据。

---

## UcpServer — 服务端

```csharp
public class UcpServer : IUcpObject, IDisposable
```

| 方法 | 作用 |
|---|---|
| `Start(int port)` | 开始监听指定 UDP 端口 |
| `AcceptAsync()` | 异步等待新客户端连接，返回 `UcpConnection` |
| `Stop()` | 停止监听并关闭所有连接 |

---

## UcpConnection — 客户端连接

```csharp
public class UcpConnection : IUcpObject, IDisposable
```

### 连接管理

| 方法 | 作用 |
|---|---|
| `ConnectAsync(IPEndPoint remote)` | 异步连接到远程端点 |
| `Close()` / `CloseAsync()` | 关闭连接（优雅 FIN） |

### 数据发送

| 方法 | 作用 |
|---|---|
| `Send(byte[], offset, count)` | 同步发送（先进 send buffer，不等 ACK） |
| `SendAsync(byte[], offset, count)` | 异步发送 |
| `Write(byte[], offset, count)` | **同步可靠写入**（阻塞直到所有数据被 send buffer 接受，不等到对端确认） |
| `WriteAsync(byte[], offset, count)` | **异步可靠写入**（返回 true 表示全部数据已被 send buffer 接受） |

> **注意**：`Write`/`WriteAsync` 不保证对端已收到，只保证数据已进入发送缓冲区。

### 数据接收

| 方法 | 作用 |
|---|---|
| `Receive(byte[], offset, count)` | 同步接收（从有序交付队列读取） |
| `ReceiveAsync(byte[], offset, count)` | 异步接收 |
| `Read(byte[], offset, count)` | 同步读取指定字节数（内部循环 Receive） |
| `ReadAsync(byte[], offset, count)` | 异步读取指定字节数 |

### 事件

| 事件 | 触发时机 |
|---|---|
| `OnData(byte[], offset, count)` / `OnDataReceived` | 有序数据分段到达应用层时立即触发 |
| `OnConnected` | 连接建立（握手完成） |
| `OnDisconnected` | 连接断开 |

### 诊断

| 方法 | 作用 |
|---|---|
| `GetReport()` | 返回 `UcpTransferReport`，包含发送/接收字节数、包数、重传统计、RTT、CWND、Pacing 速率等 |

---

## UcpDatagramNetwork — UDP 默认实现

```csharp
public sealed class UcpDatagramNetwork : UcpNetwork
```

使用单个 UDP Socket 承载所有连接。收到数据报后按 `ConnectionId` 分发到对应 PCB。这是最简单的使用方式。

---

## 使用示例

### 基本服务器/客户端

```csharp
// 服务端
var config = UcpConfiguration.GetOptimizedConfig();
config.ServerBandwidthBytesPerSecond = 100_000_000 / 8;
using var server = new UcpServer(config);
server.Start(9000);

var acceptTask = server.AcceptAsync();

// 客户端
using var client = new UcpConnection(config);
await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));
var serverConn = await acceptTask;

// 数据传输
byte[] data = Encoding.UTF8.GetBytes("Hello UCP!");
await client.WriteAsync(data, 0, data.Length);
byte[] buf = new byte[data.Length];
await serverConn.ReadAsync(buf, 0, buf.Length);
```

### 使用 UcpNetwork 驱动模型

```csharp
using var network = new UcpDatagramNetwork();
network.Start(0);

var server = network.CreateServer(9000);
var client = network.CreateConnection();
var connTask = client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));

while (!connTask.IsCompleted) network.DoEvents();
```

### 开启 FEC

```csharp
var config = UcpConfiguration.GetOptimizedConfig();
config.FecRedundancy = 0.125;  // 每 8 包 1 修复包
config.FecGroupSize = 8;
```

### 开启调试日志

```csharp
config.EnableDebugLog = true;
```
