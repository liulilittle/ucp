# UCP API 说明

## UcpConfiguration

```csharp
public class UcpConfiguration
```

主要配置项：

- `Mss`
- `MaxRetransmissions`
- `MinRtoMicros`
- `MaxRtoMicros`
- `RetransmitBackoffFactor`
- `InitialBandwidthBytesPerSecond`
- `MaxPacingRateBytesPerSecond`
- `InitialCwndPackets`
- `RecvWindowPackets`
- `ServerBandwidthBytesPerSecond`
- `KeepAliveIntervalMicros`
- `DisconnectTimeoutMicros`
- `SendBufferSize`
- `ReceiveBufferSize`
- `InitialCwndBytes`
- `DrainPacingGain`
- `ProbeBwHighGain`
- `ProbeBwLowGain`
- `ProbeBwCwndGain`
- `AckSackBlockLimit`

配置 API 只有 `UcpConfiguration` 一个类型，公开成员采用 .NET PascalCase 命名。
`UcpConfiguration.GetOptimizedConfig()` 返回面向高延迟/高丢包场景的推荐配置，包含 200ms 最小 RTO、30s ProbeRTT 周期、100ms ProbeRTT 持续时间、1.2 RTO 退避和 20 包初始拥塞窗口。

## UcpNetwork

```csharp
public abstract class UcpNetwork : IDisposable
{
    public UcpConfiguration Configuration { get; }
    public long NowMicroseconds { get; }
    public virtual EndPoint LocalEndPoint { get; }

    public UcpServer CreateServer(int port);
    public UcpConnection CreateConnection();
    public UcpConnection CreateConnection(UcpConfiguration configuration);

    public virtual void Start(int port);
    public virtual void Stop();
    public void Input(byte[] datagram, IPEndPoint remote);
    public abstract void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender);
    public uint AddTimer(long expireUs, Action callback);
    public bool CancelTimer(uint timerId);
    public virtual int DoEvents();
}
```

`Input()` 用于把 UDP 数据报注入协议栈，`Output()` 由派生类实现具体发送，并通过 `IUcpObject sender` 获取发送方 `ConnectionId` 与 `Network` 元数据。`DoEvents()` 驱动计时器、pacing 延迟 flush、重传检查和服务端 FQ 轮次；无到期事件时会让出线程。

## IUcpObject

```csharp
public interface IUcpObject
{
    uint ConnectionId { get; }
    UcpNetwork Network { get; }
}
```

## UcpDatagramNetwork

```csharp
public sealed class UcpDatagramNetwork : UcpNetwork
{
    public UcpDatagramNetwork();
    public UcpDatagramNetwork(UcpConfiguration configuration);
}
```

`UcpDatagramNetwork` 使用单个 UDP Socket 承载同一网络对象上的所有连接，通过包头 `ConnectionId` 分发到对应连接。

## UcpServer

```csharp
public class UcpServer
{
    public UcpServer();
    public UcpServer(UcpConfiguration config);
    public uint ConnectionId { get; }
    public UcpNetwork Network { get; }
    public void Start(int port);
    public Task<UcpConnection> AcceptAsync();
    public void Stop();
}
```

## UcpConnection

```csharp
public class UcpConnection
{
    public UcpConnection();
    public UcpConnection(UcpConfiguration config);
    public uint ConnectionId { get; }
    public UcpNetwork Network { get; }

    public Task ConnectAsync(IPEndPoint remote);
    public int Send(byte[] buf, int off, int len);
    public Task<int> SendAsync(byte[] buf, int off, int len);
    public int Receive(byte[] buf, int off, int len);
    public Task<int> ReceiveAsync(byte[] buf, int off, int len);
    public bool Read(byte[] buf, int off, int count);
    public Task<bool> ReadAsync(byte[] buf, int off, int count);
    public bool Write(byte[] buf, int off, int count);
    public Task<bool> WriteAsync(byte[] buf, int off, int count);
    public void Close();
    public Task CloseAsync();

    public UcpTransferReport GetReport();

    public event Action<byte[], int, int> OnData;
    public event Action OnConnected;
    public event Action OnDisconnected;
}
```

## 使用示例

```csharp
UcpConfiguration config = new UcpConfiguration();
config.ServerBandwidthBytesPerSecond = 10 * 1024 * 1024;

using (UcpDatagramNetwork serverNetwork = new UcpDatagramNetwork(config))
using (UcpDatagramNetwork clientNetwork = new UcpDatagramNetwork(config))
{
    UcpServer server = serverNetwork.CreateServer(9000);
    UcpConnection client = clientNetwork.CreateConnection();

    Task connect = client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 9000));
    while (!connect.IsCompleted)
    {
        serverNetwork.DoEvents();
        clientNetwork.DoEvents();
    }
    await connect;

    byte[] payload = Encoding.UTF8.GetBytes("hello");
    await client.WriteAsync(payload, 0, payload.Length);

    UcpTransferReport report = client.GetReport();
    Console.WriteLine(report.LastRttMicros);
}
```

旧式直接创建 `UcpServer` / `UcpConnection` 的 API 仍可使用，内部会使用默认 UDP 传输和后台定时器。

## 性能报告单位

内部带宽字段仍以 bytes/second 保存，便于窗口和 pacing 计算。测试报告和控制台表格面向用户展示时使用 Mbps，重传率、利用率和浪费率使用百分比。
