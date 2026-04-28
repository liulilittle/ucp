# UCP 架构说明

## 分层

- 用户层：`UcpServer`、`UcpConnection`
- 协议层：`UcpPcb`
- 执行层：`SerialQueue`
- 网络驱动层：`UcpNetwork`、`UcpDatagramNetwork`
- 兼容传输层：`ITransport`

## UcpNetwork 驱动模型

`UcpNetwork` 是新的协议栈入口：

- `Input(byte[] datagram, IPEndPoint remote)` 注入收到的 UDP 数据报。
- `Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)` 由派生类实现实际发送，并可读取发送方连接元数据。
- `DoEvents()` 驱动到期计时器、延迟 flush、RTO 检查和服务端 FQ 调度。
- `AddTimer()` 使用 `SortedDictionary<long, List<Action>>` 按微秒时间维护计时器堆。
- `NowMicroseconds` 使用全局 1ms 缓存单调时钟，减少高频时间查询成本。

`IUcpObject` 是网络层可见的发送方契约，公开 `ConnectionId` 与 `Network`。`UcpServer`、`UcpConnection` 和内部 transport adapter 均实现该契约，避免网络派生类依赖未类型化的 `object sender`。

`UcpDatagramNetwork` 是默认 UDP 派生类。它使用一个 UDP Socket 接收和发送数据报，同一网络对象上的多个连接通过公共头 `ConnectionId` 区分，不会为每个连接创建独立 Socket。

## Strand 模型

每个连接拥有自己的 `SerialQueue`：

- 用户 API 调用先进入 strand
- 入站数据报解析后也投递到同一 strand
- 这样同一连接无锁串行，不同连接仍可并行

通过 `UcpNetwork` 创建连接时，网络层只负责按数据报注入，实际包处理仍投递到对应连接的 strand，避免同一连接的 API 调用、ACK、DATA、重传检查并发修改 PCB 状态。

## 拥塞控制与调度

- `BbrCongestionControl` 负责测量带宽、最小 RTT、模式转换
- `PacingController` 负责令牌桶节奏控制
- `UcpServer` 负责面向多连接的 FQ 调度

在新驱动模型下，Pacing 延迟 flush、PCB 周期检查和 FQ 轮次都注册到 `UcpNetwork` 计时器，只有调用 `DoEvents()` 时才推进。旧式 `ITransport` API 仍保留后台 `System.Threading.Timer`，用于兼容已有调用方式。

## 统计系统

`UcpPcb` 内部实时统计：

- 发送字节数
- 接收字节数
- ACK / NAK / 重传包数
- 最后 RTT
- 当前 CWND
- 当前 pacing rate

这些统计通过 `UcpConnection.GetReport()` 暴露给上层和测试。

## 测试项目

`UcpTest` 使用 `NetworkSimulator` 模拟：

- 丢包
- 延迟
- 抖动
- 带宽瓶颈
- 规则型选择性丢包

测试过程中会把性能快照写入 `reports/summary.txt`，并生成对齐纯文本表格 `reports/test_report.txt`。`run-tests.ps1` 会在测试结束后读取并校验报告，报告缺失或关键指标异常会导致脚本失败。
