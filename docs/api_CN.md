# PPP PRIVATE NETWORK™ X -- 通用通信协议 (UCP) -- API 参考

[English](api.md) | [文档索引](index_CN.md)

本文档详尽描述 UCP 库的公开 API 接口。所有文件路径均相对于 [Ucp/](../Ucp/) 源码目录。

---

## 目录

- [UcpConfiguration（配置工厂）](#ucpconfiguration配置工厂)
- [UcpServer（服务端 API）](#ucpserver服务端-api)
- [UcpConnection（连接 API）](#ucpconnection连接-api)
- [UcpNetwork（事件循环驱动）](#ucpnetwork事件循环驱动)
- [UcpDatagramNetwork（UDP 网络）](#ucpdatagramnetworkudp-网络)
- [IUcpObject 接口](#iucpobject-接口)
- [ITransport / IBindableTransport / UdpSocketTransport](#itransport--ibindabletransport--udpsockettransport)
- [UcpTransferReport（诊断报告）](#ucptransferreport诊断报告)
- [UcpFecCodec（FEC 配置）](#ucpfeccodecfec-配置)
- [UcpPriority 枚举](#ucppriority-枚举)
- [C++ 交叉参考](#c-交叉参考)
- [错误处理](#错误处理)
- [端到端示例](#端到端示例)

---

## UcpConfiguration（配置工厂）

**源文件:** [Ucp/UcpConfiguration.cs](../Ucp/UcpConfiguration.cs)

```csharp
public class UcpConfiguration
```

主配置对象。使用 `GetOptimizedConfig()` 获取生产调优默认值，然后按需覆盖各属性。所有定时器使用微秒级精度。

### 静态工厂方法

```csharp
public static UcpConfiguration GetOptimizedConfig()
```

返回生产调优实例，包含合理的默认值：RTO（50 ms 最小 / 15 s 最大）、MinRTT 过滤器（由 Geodesic G1/G3 自动处理）、退避因子（1.2x）、初始 CWND（可配置，非固定 10 包上限）、ProbeBW 8 阶段增益循环（1.25, 0.75, 1.0x6）、SACK 块限制（2）、丢包上限（25%），以及启用丢包控制。KCC（Geodesic Congestion Control，KF 组件源于 tcp_kcc.c v2.0）拥塞控制使用 Geodesic 估计器 RTT 估计，FEC/NAK 投递样本馈入 CC 引擎。MinRTT 跟踪由 Geodesic G1/G3 自动处理。

### Clone

```csharp
public UcpConfiguration Clone()
```

深拷贝配置。内部用于隔离每个连接的设置与服务器级默认值。

### 协议参数

| 参数 | 类型 | 默认值 | 范围 | 说明 |
|------|------|--------|------|------|
| Mss | int | 1220 | 200-9000 | 最大分段大小（字节）。1220 适配 IPv6 最小 MTU，无需 IP 分片 |
| MaxRetransmissions | int | 10 | 3-100 | 每段最大重传次数，超限后断开 |
| SendBufferSize | int | 32 MB | 1-256 MB | 出站缓冲区上限，WriteAsync 满时阻塞 |
| ReceiveBufferSize | int | ~5 MB | 自动（MSS * RecvWindowPackets） | 接收缓冲区（字节）。setter 转换为 RecvWindowPackets |
| InitialCwndPackets | int | 10 | 4-200 | KCC 拥塞控制初始拥塞窗口（包数） |
| MaxCongestionWindowBytes | int | 64 MB | 64 KB-256 MB | UCP CWND 硬上限。64 MB 覆盖 10 Gbps / 100 ms RTT 的典型 BDP |
| SendQuantumBytes | int | MSS | MSS-MSSx4 | Pacing Token 单次消费粒度 |
| AckSackBlockLimit | int | 2 | 1-255 | 每 ACK 最大 SACK 块数 |
| RecvWindowPackets | int | 4096 | >= 1 | 接收窗口（包数），用于流量控制通告 |
| FecRedundancy | double | 0.0 | 0.0-1.0 | RS-GF(256) 冗余比例。0.0=禁用；0.125=每 8 数据包 1 修复包 |
| FecGroupSize | int | 8 | 2-64 | 每 FEC 组数据包数 |
| LossControlEnable | bool | true | - | 启用丢包感知 pacing 自适应 |
| EcnEnabled | bool | false | - | 启用 ECN CE 标记反馈（KCC 2.0 默认禁用） |
| EnableDebugLog | bool | false | - | 拥塞控制决策调试日志 |
| EnableMtuDiscovery | bool | true | - | 启用 DPLPMTUD 路径 MTU 探测 |
| MtuProbeMax | int | 1500 | - | MTU 探测上限（以太网极限） |
| MtuProbeTimeoutMicros | long | 10,000,000 (10 s) | - | 飞行中 MTU 探测超时 |
| MtuProbeIntervalMicros | long | 600,000,000 (10 min) | - | MTU 收敛后重新探测间隔 |

### RTO 与定时器

| 参数 | 类型 | 默认值 | 范围 | 说明 |
|------|------|--------|------|------|
| MinRtoMicros | long | 50,000 (50 ms) | 50,000-1,000,000 | 最小重传超时 |
| MaxRtoMicros | long | 15,000,000 (15 s) | 1,000,000-60,000,000 | 最大重传超时 |
| RetransmitBackoffFactor | double | 1.2 | 1.1-2.0 | RTO 退避乘数 |
| KeepAliveIntervalMicros | long | 1,000,000 (1 s) | 100,000-30,000,000 | 保活间隔（NAT 绑定刷新） |
| DisconnectTimeoutMicros | long | 4,000,000 (4 s) | 500,000-60,000,000 | 空闲断连超时 |
| TimerIntervalMilliseconds | int | 1 | 1-100 | DoEvents 定时器滴答间隔 |
| FairQueueRoundMilliseconds | int | 10 | 1-100 | 公平队列调度轮次间隔 |
| ConnectTimeoutMilliseconds | int | 5000 | - | 连接握手超时 |
| DelayedAckTimeoutMicros | long | 100 | 0-10,000 | 延迟 ACK 超时（无捎带数据时触发） |

**KCC 2.0 说明**：MinRTT 跟踪由 Geodesic 估计器 G1/G3 自动处理，无需手动 min_rtt 过滤器采样配置。

### 别名属性

| 属性 | 委托至 |
|------|--------|
| MinRtoUs | MinRtoMicros |
| MaxRtoUs | MaxRtoMicros |
| RtoBackoffFactor | RetransmitBackoffFactor |
| KeepAliveIntervalUs | KeepAliveIntervalMicros |
| DisconnectTimeoutUs | DisconnectTimeoutMicros |
| UCPMinRttWindowMicros | 已在 KCC 2.0 中移除（min_rtt 跟踪由 Geodesic G1/G3 自动处理） |
| InitialCwndBytes | InitialCwndPackets（字节模式 get/set） |

### 有效（钳位）属性

| 属性 | 说明 |
|------|------|
| EffectiveMinRtoMicros | MinRtoMicros 下限为协议常量（50 ms） |
| EffectiveMaxRtoMicros | MaxRtoMicros，不低于 EffectiveMinRtoMicros |
| EffectiveRetransmitBackoffFactor | 钳位至 >= 1.0 |
| EffectiveMaxBandwidthLossPercent | 钳位至 [15%, 35%] |
| MaxPayloadSize | Mss - DataHeaderSize（20 字节） |
| MaxAckSackBlocks | 基于 MSS 的物理上限与 AckSackBlockLimit 的取小值 |
| ReceiveWindowBytes | RecvWindowPackets * Mss（uint 类型） |
| InitialCongestionWindowBytes | Max(Mss, InitialCwndPackets * Mss) |

### Pacing 与 KCC 拥塞控制增益

| 参数 | 类型 | 默认值 | 范围 | 说明 |
|------|------|--------|------|------|
| MinPacingIntervalMicros | long | 0 | 0-10,000 | 最小包间隔（0=无下限） |
| PacingBucketDurationMicros | long | 10,000 (10 ms) | 1,000-100,000 | Token Bucket 容量窗口 |

KCC pacing/CWND 增益（Startup 2.887x、Drain 0.344x、ProbeBW 1.25/0.75）是 UcpCongestionControl 中的固定常量，不通过 UcpConfiguration 配置。

**流量控制边界**：STARTUP 阶段（达到满带宽前），可发送上限为对端宣告的接收窗口——初始 cwnd 不限制首次突发。达到满带宽后，上限为 min(cwnd, 对端宣告的接收窗口)（标准 TCP/QUIC 流量控制）。`InitialCwndPackets` 仅设定起始拥塞窗口值；STARTUP 阶段对端宣告的 `WindowSize` 才是在途字节的权威硬上限。

### 带宽与丢包控制

| 参数 | 类型 | 默认值 | 范围 | 说明 |
|------|------|--------|------|------|
| InitialBandwidthBytesPerSecond | long | 12,500,000 (100 Mbps) | 125,000-1,250,000,000 | UCP Startup 初始带宽估计 |
| MaxPacingRateBytesPerSecond | long | 12,500,000 | 0-无上限 | Pacing 速率天花板（0=关闭） |
| ServerBandwidthBytesPerSecond | int | 12,500,000 | 125,000-1,250,000,000 | 服务端出口总带宽（公平队列用） |
| MaxBandwidthWastePercent | double | 0.25 | 0-1 | 重传浪费上限（比例） |
| MaxBandwidthLossPercent | double | 25% | 15-35（钳位） | 丢包容忍预算 |

### 代码示例

```csharp
var config = UcpConfiguration.GetOptimizedConfig();
config.Mss = 9000;                              // 高 BDP 路径使用巨型帧
config.FecRedundancy = 0.125;                   // 每 8 数据包 1 修复包
config.ServerBandwidthBytesPerSecond = 1_000_000_000 / 8; // 1 Gbps
config.InitialCwndPackets = 40;                 // 更激进的初始窗口
config.TimerIntervalMilliseconds = 5;           // 更细粒度的定时器滴答
```

---

## UcpServer（服务端 API）

**源文件:** [Ucp/UcpServer.cs](../Ucp/UcpServer.cs)

```csharp
public class UcpServer : IUcpObject, IDisposable
```

在 UDP 端口监听入站连接。管理所有活跃连接的公平队列调度。

### 构造函数

```csharp
public UcpServer()                                    // 默认配置，创建自己的 UDP 传输
public UcpServer(UcpConfiguration config)             // 自定义配置，创建自己的 UDP 传输
internal UcpServer(ITransport transport)               // 自定义传输，默认配置
internal UcpServer(ITransport transport, int bandwidthLimitBytesPerSecond)
internal UcpServer(ITransport transport, UcpConfiguration config)
```

### Start

```csharp
public void Start(int port)                                              // 绑定端口（所有接口）
public void Start(UcpNetwork network, int port, UcpConfiguration configuration) // 在 UcpNetwork 内启动
```

`Start(port)` 创建双栈 IPv6/UDP 套接字，订阅传输数据报事件，启动公平队列定时器。无网络时使用 .NET Timer 驱动公平队列；否则使用网络的定时器系统。

### AcceptAsync

```csharp
public async Task<UcpConnection> AcceptAsync()
```

阻塞直到新客户端完成三次握手。返回完全建立的 `UcpConnection`。连接按 FIFO 顺序交付。线程安全；可多消费者同时等待。

### Stop

```csharp
public void Stop()
```

取消订阅传输事件，停止公平队列定时器，释放所有管理的 PCB（向各对端发送 RST），停止并可选释放传输。幂等。

### Dispose

```csharp
public void Dispose()
```

调用 `Stop()`。

### IUcpObject 成员

```csharp
public uint ConnectionId { get; }    // 恒为 0（服务器非单一连接）
public UcpNetwork Network { get; }   // 所属网络（独立模式为 null）
```

### 公平队列调度

服务器每 `FairQueueRoundMilliseconds`（默认 10 ms）向活跃连接分配带宽信用。信用比例基于各连接的 UCP pacing 速率，上限为均分公平份额。按轮转顺序刷新连接以防饿死。带宽上限来自 `ServerBandwidthBytesPerSecond`。

### 代码示例

```csharp
var config = UcpConfiguration.GetOptimizedConfig();
using var server = new UcpServer(config);
server.Start(9000);
Console.WriteLine($"端口 9000 监听中");

// 接受一个连接
UcpConnection conn = await server.AcceptAsync();
Console.WriteLine($"已接受: {conn.RemoteEndPoint}");

// 回显接收的数据
byte[] buf = new byte[65536];
int n = await conn.ReadAsync(buf, 0, buf.Length);
await conn.WriteAsync(buf, 0, n);

server.Stop();
```

---

## UcpConnection（连接 API）

**源文件:** [Ucp/UcpConnection.cs](../Ucp/UcpConnection.cs)

```csharp
public class UcpConnection : IUcpObject, IDisposable
```

基于 UCP 协议的双向数据流。支持主动（出站）和被動（从服务器接受）连接。

### 构造函数

```csharp
public UcpConnection()                                              // 默认配置，自有 UDP 传输
public UcpConnection(UcpConfiguration config)                        // 自定义配置，自有 UDP 传输
internal UcpConnection(ITransport transport, ...)                    // 自定义传输（内部）
internal UcpConnection(UcpPcb pcb, ITransport transport, UcpConfiguration config) // 服务端接受路径
internal UcpConnection(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
```

### ConnectAsync

```csharp
public async Task<UcpConnection> ConnectAsync(IPEndPoint remote)
```

向指定远端发起三次握手（SYN / SYN-ACK / ACK）。若传输未绑定，则绑定到 OS 分配的临时端口。返回 `this` 以便链式调用。远端为 null 时抛出 `ArgumentNullException`；已连接时抛出 `InvalidOperationException`。

```csharp
public async Task<UcpConnection> ConnectAsync(UcpNetwork network, IPEndPoint remote)
```

通过共享 `UcpNetwork` 连接，将传输切换为网络适配器以实现多路复用 I/O。网络拥有传输，连接不负责释放。

支持 IPv4 和 IPv6 端点（通过双栈 UDP 套接字）。

### Send / SendAsync（非阻塞）

```csharp
public int Send(byte[] buf, int offset, int count)
public int Send(byte[] buf, int offset, int count, UcpPriority priority)
public async Task<int> SendAsync(byte[] buf, int offset, int count)
public async Task<int> SendAsync(byte[] buf, int offset, int count, UcpPriority priority)
```

返回已接受字节数（可能少于 `count`），出错返回 -1。`Send` 包装 `SendAsync` 带 5 秒超时。数据加入连接串行队列以保证有序的 PCB 访问。`priority` 参数（默认 `Normal`）控制 QoS 排序。

### Write / WriteAsync（可靠）

```csharp
public bool Write(byte[] buf, int off, int count)
public bool Write(byte[] buf, int off, int count, UcpPriority priority)
public async Task<bool> WriteAsync(byte[] buf, int off, int count)
public async Task<bool> WriteAsync(byte[] buf, int off, int count, UcpPriority priority)
```

内部循环调用 `SendAsync`，直到所有 `count` 字节被接受或连接失败。成功返回 `true`，失败或超时返回 `false`。推荐生产使用。永不抛出异常。

### Receive / ReceiveAsync

```csharp
public int Receive(byte[] buf, int offset, int count)
public async Task<int> ReceiveAsync(byte[] buf, int offset, int count)
```

返回至少 1 字节有序数据，最多 `count`。连接关闭返回 0，出错返回 -1。`Receive` 包装 `ReceiveAsync` 带 5 秒超时。

### Read / ReadAsync（精确字节数）

```csharp
public bool Read(byte[] buf, int off, int count)
public async Task<bool> ReadAsync(byte[] buf, int off, int count)
```

精确读取 `count` 字节，内部循环调用 `ReceiveAsync`。成功返回 `true`，连接在读完前关闭返回 `false`。永不抛出异常。

### Close / CloseAsync

```csharp
public void Close()
public async Task CloseAsync()
```

发起优雅 FIN 握手：排空发送缓冲、发送 FIN、等待对端 FIN-ACK，然后清理传输资源。`Close` 包装有 5 秒超时；超时则强制清理。

### Dispose

```csharp
public void Dispose()
```

调用 `Close()`。永不抛出异常。

### MigrateRemote（CID 迁移）

```csharp
public void MigrateRemote(IPEndPoint newEndPoint)
```

显式将连接迁移到新的远端端点。触发 PCB 的路径变更逻辑并重置 KCC 拥塞控制状态。PCB 为 null 时无操作。

### 事件

```csharp
public event Action<byte[], int, int> OnData           // 有序负载到达（buffer, offset, count）
public event Action<byte[], int, int> OnDataReceived    // OnData 的别名（向后兼容）
public event Action OnConnected                        // 握手完成
public event Action OnDisconnected                     // 连接关闭（优雅或错误）
```

事件在连接的串行队列（SerialQueue）上触发。在事件处理器中调用连接方法是安全的。

### 诊断

```csharp
public UcpTransferReport GetReport()                    // 完整传输统计快照
internal UcpConnectionDiagnostics GetDiagnostics()      // 内部诊断快照
```

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| ConnectionId | uint | 32 位随机连接标识符 |
| RemoteEndPoint | IPEndPoint | 远端端点 |
| Network | UcpNetwork | 所属网络引擎（独立模式为 null） |

### 错误处理

所有公共同步方法（`Send`, `Receive`, `Read`, `Write`, `Close`）内部捕获异常并返回错误码或 `false`。异步方法捕获 `OperationCanceledException` 和 `ObjectDisposedException`。协议级故障（最大重传、握手超时等）会触发 `OnDisconnected`。

### 代码示例（客户端）

```csharp
var config = UcpConfiguration.GetOptimizedConfig();
using var conn = new UcpConnection(config);

conn.OnConnected += () => Console.WriteLine("已连接!");
conn.OnDisconnected += () => Console.WriteLine("已断开");

await conn.ConnectAsync(new IPEndPoint(IPAddress.Parse("192.168.1.100"), 9000));

byte[] request = Encoding.UTF8.GetBytes("Hello UCP!");
await conn.WriteAsync(request, 0, request.Length);

byte[] response = new byte[1024];
int n = await conn.ReceiveAsync(response, 0, response.Length);
Console.WriteLine($"收到: {Encoding.UTF8.GetString(response, 0, n)}");

var report = conn.GetReport();
Console.WriteLine($"RTT: {report.LastRttMicros / 1000.0:F2} ms");
Console.WriteLine($"吞吐: {report.MeasuredBandwidthBytesPerSecond * 8 / 1_000_000:F2} Mbps");

await conn.CloseAsync();
```

---

## UcpNetwork（事件循环驱动）

**源文件:** [Ucp/UcpNetwork.cs](../Ucp/UcpNetwork.cs)

```csharp
public abstract class UcpNetwork : IDisposable
```

抽象事件循环网络驱动。管理定时器、PCB 路由/注册、以及缓存单调时钟。周期性调用 `DoEvents()` 驱动协议运行。

### 具体实现

使用 `UcpDatagramNetwork` 实现真实 UDP I/O，或继承 `UcpNetwork` 实现自定义传输。

### DoEvents

```csharp
public virtual int DoEvents()
```

网络层心跳。处理到期定时器、滴答所有活跃 PCB（RTO 检查、延迟刷新、KCC 样本更新），空闲时让出 CPU（即将到期用 `Thread.Yield()`，否则 `Thread.Sleep(0)`）。返回已处理工作项数。必须周期性调用（推荐每 `TimerIntervalMilliseconds`）。

### Input / Output

```csharp
public void Input(byte[] datagram, IPEndPoint remote)
public void Output(byte[] datagram, IPEndPoint remote)
public abstract void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
```

`Input` 注入接收的数据报：解码数据包，按连接 ID 路由到匹配 PCB（快速路径），或对 SYN 包回退到传输适配器（服务端/连接接受）。`Output` 发送编码后的数据包；抽象重载接受 `IUcpObject` 发送者引用用于追踪。

### 定时器 API

```csharp
public uint AddTimer(long expireUs, Action callback)
public bool CancelTimer(uint timerId)
```

`AddTimer` 在指定绝对微秒时间注册一次性定时器。返回定时器 ID 用于取消。包装回调在执行前检查取消状态。`CancelTimer` 找到并取消时返回 `true`。

### 工厂方法

```csharp
public UcpServer CreateServer(int port)
public UcpConnection CreateConnection()
public UcpConnection CreateConnection(UcpConfiguration configuration)
```

创建绑定到该网络传输适配器的服务端或连接实例。适配器是共享的（多路复用 I/O）。

### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| Configuration | UcpConfiguration | 协议配置（构造时克隆） |
| CurrentTimeUs | long | 缓存网络时钟（微秒，同一 DoEvents 滴答内一致） |
| NowMicroseconds | long | 原始计时器时间（可能滞后约 1 ms） |
| LocalEndPoint | EndPoint | 绑定的套接字端点（派生类重写；基类返回 null） |

### Start / Stop / Dispose

```csharp
public virtual void Start(int port)    // 基类空操作；派生类绑定套接字
public virtual void Stop()             // 基类空操作；派生类关闭套接字
public virtual void Dispose()          // 停止网络，清除所有定时器
```

---

## UcpDatagramNetwork（UDP 网络）

**源文件:** [Ucp/UcpDatagramNetwork.cs](../Ucp/UcpDatagramNetwork.cs)

```csharp
public sealed class UcpDatagramNetwork : UcpNetwork
```

具体的 UDP 套接字网络实现。通过 `Task.Run` 运行后台接收循环，通过 `Input()` 注入数据报。

### 构造函数

```csharp
public UcpDatagramNetwork()                                          // 默认配置，未启动
public UcpDatagramNetwork(int port)                                  // 默认配置，在端口启动
public UcpDatagramNetwork(IPAddress localAddress, int port)          // 默认配置，绑定到地址+端口
public UcpDatagramNetwork(UcpConfiguration configuration)            // 自定义配置，未启动
public UcpDatagramNetwork(IPAddress localAddress, int port, UcpConfiguration configuration) // 完整
```

### Start

```csharp
public override void Start(int port)                            // 委托至 Start(IPAddress.IPv6Any, port)
public void Start(IPAddress localAddress, int port)
```

创建双栈 IPv6 UDP 套接字（`DualMode = true`），使 IPv4 和 IPv6 流量共享同一套接字。不支持 IPv6 时回退到 IPv4 only。接收循环在 ThreadPool 任务上运行。

### Output

```csharp
public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
```

通过 `UdpClient.SendAsync` 发送。未绑定时惰性启动（OS 分配端口）。发送失败被观察并静默忽略（瞬态 UDP 错误属正常）。

### 属性

```csharp
public override EndPoint LocalEndPoint  // 绑定的 UDP 套接字本地端点
```

### 代码示例

```csharp
var network = new UcpDatagramNetwork(9000);  // 在端口 9000 监听

// 在网络上创建托管服务器
var server = network.CreateServer(9000);

// 在同一网络上创建连接（多路复用）
var conn = network.CreateConnection();
await conn.ConnectAsync(network, new IPEndPoint(IPAddress.Loopback, 9000));

// 驱动事件循环
while (true)
{
    int work = network.DoEvents();
    if (work == 0) await Task.Delay(1);
}
```

---

## IUcpObject 接口

**源文件:** [Ucp/IUcpObject.cs](../Ucp/IUcpObject.cs)

```csharp
public interface IUcpObject
{
    uint ConnectionId { get; }
    UcpNetwork Network { get; }
}
```

UCP 感知发送者的公共契约。`ConnectionId` 用于传输层解复用。`Network` 提供对所属事件循环的访问以协调调度。`UcpConnection` 和 `UcpServer` 均实现此接口。

---

## ITransport / IBindableTransport / UdpSocketTransport

**源文件:** [Ucp/Transport/ITransport.cs](../Ucp/Transport/ITransport.cs), [Ucp/Transport/IBindableTransport.cs](../Ucp/Transport/IBindableTransport.cs), [Ucp/Transport/UdpSocketTransport.cs](../Ucp/Transport/UdpSocketTransport.cs)

### ITransport

```csharp
public interface ITransport : IDisposable
{
    event Action<byte[], IPEndPoint> OnDatagram;
    void Send(byte[] data, IPEndPoint remote);
}
```

网络 I/O 抽象接口。实现此接口可将 UCP 集成到非 UDP 传输层（WebRTC DataChannel、进程内模拟、加密隧道等）。`OnDatagram` 在每个接收数据报时触发。`Send` 向目标传输编码后的数据包。

### IBindableTransport（内部）

```csharp
internal interface IBindableTransport : ITransport
{
    EndPoint LocalEndPoint { get; }
    void Start(int port);
    void Stop();
}
```

扩展 `ITransport` 增加绑定生命周期。`Start(int port)` 绑定端口（0=OS 分配）。`Stop()` 通知接收循环退出。`LocalEndPoint` 暴露绑定地址。

### UdpSocketTransport（内部）

```csharp
internal sealed class UdpSocketTransport : IBindableTransport
```

默认 UDP 传输。创建双栈 IPv6 套接字（`DualMode = true`）支持 IPv4/IPv6。配置 OS 套接字缓冲区为 `UcpConstants.UDP_SOCKET_BUFFER_BYTES`。通过 `Task.Run` 运行后台接收循环。首次 `Send` 时惰性启动（port 0）若未显式启动。

### 自定义传输示例

```csharp
public class LoopbackTransport : ITransport
{
    public event Action<byte[], IPEndPoint> OnDatagram;

    public void Send(byte[] data, IPEndPoint remote)
    {
        // 模拟即时回环
        OnDatagram?.Invoke(data, remote);
    }

    public void Dispose() { }
}

// 与 UcpConnection 配合使用
var transport = new LoopbackTransport();
var conn = new UcpConnection(transport); // 内部构造函数
```

---

## UcpTransferReport（诊断报告）

**源文件:** [Ucp/UcpTransferReport.cs](../Ucp/UcpTransferReport.cs)

```csharp
public sealed class UcpTransferReport
```

由 `UcpConnection.GetReport()` 填充。所有字段均为公开。

| 字段 | 类型 | 说明 |
|------|------|------|
| BytesSent | long | 已接受发送的用户负载总字节 |
| BytesReceived | long | 有序交付的用户负载总字节 |
| DataPacketsSent | int | 已传输的原始 DATA 包数 |
| RetransmittedPackets | int | 为修复丢包重新发送的 DATA 包数 |
| AckPacketsSent | int | 已发出的 ACK 包数 |
| NakPacketsSent | int | 已发出的 NAK 包数（显式丢包报告） |
| FastRetransmissions | int | 由 SACK/NAK/重复 ACK 触发的重传（RTO 前） |
| TimeoutRetransmissions | int | 由 RTO 超时触发的重传 |
| LastRttMicros | long | 最近 RTT 样本（微秒） |
| RttSamplesMicros | List\<long\> | 历史 RTT 样本 |
| CongestionWindowBytes | int | 当前 KCC 拥塞控制拥塞窗口 |
| PacingRateBytesPerSecond | double | 当前 UCP pacing 速率 |
| MeasuredBandwidthBytesPerSecond | double | 真实吞吐量（ACK 确认的负载字节 / 时间窗口） |
| EstimatedLossPercent | double | UCP 估计丢包率（0-100 标度） |
| RemoteWindowBytes | uint | 对端通告的接收窗口 |

### 计算属性

```csharp
public double RetransmissionRatio  // RetransmittedPackets / DataPacketsSent（无数据时返回 0）
```

---

## UcpFecCodec（FEC 配置）

**源文件:** [Ucp/UcpFecCodec.cs](../Ucp/UcpFecCodec.cs)

```csharp
internal sealed class UcpFecCodec
```

RS-GF(256) 前向纠错编码器/解码器。通过 `UcpConfiguration` 的 `FecRedundancy` 和 `FecGroupSize` 字段配置。

### 构造函数（内部）

```csharp
public UcpFecCodec(int groupSize)                // 每组单修复包
public UcpFecCodec(int groupSize, int repairCount) // 自定义修复包数
```

`groupSize` 钳位至 [2, 64]；`repairCount` 钳位至 [1, groupSize]。

### 关键方法（内部）

| 方法 | 说明 |
|------|------|
| TryEncodeRepair(byte[] payload) / TryEncodeRepair(uint seq, byte[] payload) | 将负载送入发送缓冲；组满时返回首个修复包负载 |
| TryEncodeRepairs(byte[] payload) / TryEncodeRepairs(uint seq, byte[] payload) | 将负载送入发送缓冲；组满时返回所有修复包负载 |
| FeedDataPacket(uint seq, byte[] payload) | 将接收数据存入接收缓冲 |
| TryRecoverFromRepair(byte[] repair, uint groupBase, ...) | 尝试从修复包恢复单数据包 |
| TryRecoverPacketsFromRepair(byte[] repair, uint groupBase, int repairIndex) | 尝试完整组恢复（高斯消元） |

### 通过 UcpConfiguration 配置 FEC

```csharp
config.FecRedundancy = 0.125;   // 每 8 数据包 1 修复包（12.5% 开销）
config.FecGroupSize = 8;        // 每 FEC 组 8 数据包
```

---

## UcpPriority 枚举

**源文件:** [Ucp/UcpEnums.cs](../Ucp/UcpEnums.cs)（第 106 行）

```csharp
public enum UcpPriority : byte
{
    Background  = 0,   // 最低优先级，后台数据
    Normal      = 1,   // 默认批量传输（未指定时的默认值）
    Interactive = 2,   // 低延迟数据（聊天、游戏输入）
    Urgent      = 3    // 最高优先级（控制消息、重传）
}
```

配合 `Send`、`SendAsync`、`Write`、`WriteAsync` 使用，控制同一连接发送缓冲内的 QoS 顺序。

---

## C++ 交叉参考

[cpp/](../cpp/) 目录下的 C++ 实现与 C# 公开 API 接口和线格式完全一致。

| C# API | C++ 等价 | 说明 |
|--------|----------|------|
| UcpConfiguration.GetOptimizedConfig() | `ucp_config::get_optimized()` | 相同参数集，相同默认值 |
| UcpServer.Start/Stop/AcceptAsync | `ucp_server::start/stop/accept` | C++ 使用回调式 accept；无 Task\<T\> |
| UcpConnection.ConnectAsync | `ucp_connection::connect` | C++ 版为同步；通过事件循环实现异步 |
| UcpConnection.Send/Write | `ucp_connection::send/write` | 语义一致 |
| UcpConnection.Receive/Read | `ucp_connection::receive/read` | 语义一致 |
| UcpConnection.OnData | `ucp_connection::on_data` 回调 | 相同（buffer, offset, count）签名 |
| UcpConnection.GetReport | `ucp_connection::get_report()` | 相同 UcpTransferReport 字段 |
| UcpNetwork.DoEvents | `ucp_network::poll()` | 事件循环驱动 |
| ITransport | `ucp_transport` 接口 | 相同抽象 |
| UcpFecCodec | `ucp_fec_codec` | 相同 RS-GF(256) |
| UcpPriority::Normal | `ucp_priority::normal` | 相同 4 级 QoS |

详情见 [cpp/README_CN.md](../cpp/README_CN.md) 和 [cpp/docs/api_CN.md](../cpp/docs/api_CN.md)。

---

## 错误处理

| 异常类型 | 触发条件 | 恢复建议 |
|----------|----------|----------|
| ObjectDisposedException | 已释放对象上调用方法 | 使用 `using` 语句管理生命周期 |
| InvalidOperationException | ConnectAsync 调用两次；连接前 Write | 等待握手完成后再进行数据操作 |
| ArgumentNullException | 传入 null 端点/缓冲/配置 | 调用前验证参数 |
| SocketException | UDP 套接字绑定/发送错误 | 更换端口、检查防火墙、验证网络配置 |
| OperationCanceledException | Close/Dispose 过程中取消操作 | 正常关闭过程中的预期行为；内部处理 |
| ObjectDisposedException（内部） | PCB 或传输已释放 | 内部处理；以 -1 或 false 传播 |

所有同步公共 API 方法（`Send`, `Receive`, `Read`, `Write`, `Close`）内部捕获异常并返回错误码或 `false`，避免应用程序代码出现未处理异常。异步方法通过返回的 `Task` 传播异常。

`OnDisconnected` 对优雅关闭和错误关闭均触发。事件在连接串行队列上执行；事件处理器中调用连接方法安全。

---

## 端到端示例

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
        Console.WriteLine($"服务端端口 {9000}");

        Task<UcpConnection> acceptTask = server.AcceptAsync();

        using var client = new UcpConnection(config);
        client.OnConnected += () => Console.WriteLine("[客户端] 已连接");
        client.OnDisconnected += () => Console.WriteLine("[客户端] 已断开");

        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));
        UcpConnection serverConn = await acceptTask;

        // 客户端发送
        byte[] msg = Encoding.UTF8.GetBytes("Hello from UCP!");
        await client.WriteAsync(msg, 0, msg.Length);

        // 服务端接收精确字节
        byte[] buf = new byte[msg.Length];
        await serverConn.ReadAsync(buf, 0, buf.Length);
        Console.WriteLine($"服务端收到: {Encoding.UTF8.GetString(buf)}");

        // 服务端回复
        byte[] reply = Encoding.UTF8.GetBytes("ACK: received!");
        await serverConn.WriteAsync(reply, 0, reply.Length);

        // 客户端读取回复
        byte[] replyBuf = new byte[reply.Length];
        await client.ReadAsync(replyBuf, 0, replyBuf.Length);
        Console.WriteLine($"客户端收到: {Encoding.UTF8.GetString(replyBuf)}");

        // 诊断
        var r = client.GetReport();
        Console.WriteLine($"吞吐:  {r.MeasuredBandwidthBytesPerSecond * 8 / 1e6:F2} Mbps");
        Console.WriteLine($"RTT:   {r.LastRttMicros / 1000.0:F2} ms");
        Console.WriteLine($"重传:  {r.RetransmittedPackets}");

        await client.CloseAsync();
        await serverConn.CloseAsync();
        server.Stop();
    }
}
```

---

## IPv6 支持

UCP 在每层均有原生 IPv6 支持：

- **UdpSocketTransport**（Ucp/Transport/UdpSocketTransport.cs:166-176）创建双栈 IPv6 套接字（`DualMode = true`），单套接字同时接收 IPv4 和 IPv6 流量。不支持 IPv6 的主机回退到 IPv4 only。
- **UcpDatagramNetwork**（Ucp/UcpDatagramNetwork.cs:207-216）使用相同双栈策略，默认绑定 `IPAddress.IPv6Any`。
- **UcpConnection.ConnectAsync** 接受任意地址族（IPv4 或 IPv6）的 `IPEndPoint`。双栈套接字自动映射 IPv4 地址进行传输。
- **MSS 默认值**（1220 字节）适配 IPv6 最小 MTU（1280 字节）减去头部，确保无 IP 分片。
- 支持显式 IPv6 绑定：`UcpDatagramNetwork(IPAddress.Parse("::1"), 9000)` 绑定到指定 IPv6 地址。

[^kcc_gain]: Startup pacing gain 定义于 UcpCongestionControl，在 BBR_UNIT (256) 空间中表示为 739/256 ≈ 2.887x，由 `ceil(2885 × 256 / 1000) = 739` 导出。

[^kcc_drain]: Drain pacing gain 定义于 UcpCongestionControl，在 BBR_UNIT (256) 空间中表示为 88/256 ≈ 0.344x，由 `256 × 1000 / 2885 = 88`（整数除法）导出。

---

## 许可证与商标

MIT 许可证。完整文本见 [LICENSE](../LICENSE)。

版权所有 (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ 是 PPP PRIVATE NETWORK 的商标。
