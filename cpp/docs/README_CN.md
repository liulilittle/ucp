# UCP C++ 文档概览

[English](README_EN.md)

UCP（Universal Communication Protocol）是基于 UDP 的纯控制协议 C++ 实现。UCP 在丢包恢复、确认机制、拥塞控制和前向纠错方面做出了独立的技术选择。UCP 提供 CID 轮换切换、FEC 前向纠错和 SACK/NAK 恢复——所有这些机制为 KCC 拥塞控制提供投递样本。实现使用 C++17 标准，依赖 Boost.Asio（头文件）和平台 Socket API，跨平台支持 Windows、Linux、macOS。

UCP 是纯控制协议：拥塞控制、CID 轮换切换和 FEC/NAK 恢复通过独立子系统运行。拥塞控制使用 KCC 状态机和测地线估计器进行传播延迟估计。FEC 和 NAK 为拥塞控制提供投递样本，以实现更精确的带宽/延迟估计。

UCP 运行在 UDP 之上，采用 KCC 拥塞控制算法，以投递率而非丢包作为主要拥塞信号。协议层面提供五条独立丢包恢复路径：前向纠错零延迟恢复、SACK 选择性确认、NAK 三级置信度否定确认、重复 ACK 快速重传以及 RTO 超时重传。每条路径针对不同丢失模式，确保在各种网络条件下均能找到最优恢复策略。

本目录包含 UCP C++ 实现的全部技术文档，覆盖运行时架构、协议规范、API 参考、性能特征和协议常量五大专题。每份文档均提供中英文双语版本，可通过顶部链接相互切换。架构文档详述六层分层结构和 Worker Thread 串行模型，协议文档规范线格式和状态机，API 参考覆盖全部公开接口，性能文档解析 UCP 增益表和基准测试数据，常量文档按子系统整理全部 77 个以上的协议常量。

文档编写遵循统一的约定：多字节整数使用网络大端序编码，时间值统一以微秒为单位，内存大小以字节为单位，协议常量命名采用大写加下划线风格，UCP 内部常量采用小驼峰加 k 前缀风格。所有代码示例均为 C++17 标准，可跨平台编译运行。测试数据基于 NetworkSimulator 虚拟时钟环境获得，确保结果的可复现性和一致性。若需了解 UCP 协议在 Linux 内核中的移植实现，请参阅 Linux 内核模块相关文档。

## 文档列表

| 文档 | 说明 |
|---|---|
| [index_CN.md](index_CN.md) | 文档总索引，核心概念速查，源文件清单、性能参考和构建命令 |
| [architecture_CN.md](architecture_CN.md) | 六层运行时架构，UcpPcb 协议控制块，Worker Thread 串行模型 |
| [protocol_CN.md](protocol_CN.md) | 线格式规范，8 种包类型，Flags 位布局，连接状态机 |
| [api_CN.md](api_CN.md) | 公开 API 参考，UcpConfiguration/UcpServer/UcpConnection 全部接口 |
| [performance_CN.md](performance_CN.md) | 拥塞控制，基准测试结果和调优指南 |
| [constants_CN.md](constants_CN.md) | 77 个以上协议常量，按包编码、定时器、Pacing、UCP、FEC、会话等子系统分类 |

## 快速导航

| 目标 | 文档 |
|---|---|
| 了解分层架构和线程模型 | [architecture_CN.md](architecture_CN.md) |
| 查看包格式和编解码规范 | [protocol_CN.md](protocol_CN.md) |
| 编写使用 UCP 的应用程序 | [api_CN.md](api_CN.md) |
| 调优 UCP 参数和性能 | [performance_CN.md](performance_CN.md) |
| 查询常量默认值和含义 | [constants_CN.md](constants_CN.md) |
| 浏览全部文档索引 | [index_CN.md](index_CN.md) |

架构文档涵盖了从应用层到 UDP Socket 的六层分层结构，详述每个 UcpConnection 通过专属 std::thread 串行处理全部协议事件的无锁并发模型。协议文档规范了 12 字节公共头、8 种包类型和 Flags 位布局，以及连接状态机的完整状态转换表。API 参考提供了 UcpConfiguration、UcpServer 和 UcpConnection 的全部公开方法签名和线程安全保证。性能文档解析了 UCP 的四模式增益表和拥塞控制机制。常量文档按包编码、定时器、Pacing、UCP、FEC 和会话管理等子系统分类整理全部协议常量及其默认值。

## 相关文档

- [项目根 README (中文)](../README_CN.md) — C++ 实现整体介绍
- [Linux 内核模块](../../linux/README.md) — KCC Geodesic Congestion Control 内核模块（tcp_kcc.c v2.0，含 KCC Forwarding (KF) 跨连接带宽共享组件）

## 文档约定

所有文档遵循以下约定：

- 多字节整数使用网络字节序（大端序）
- 时间值以微秒为单位
- 大小以字节为单位
- 常量名采用 UPPER_CASE（协议常量）或 kCamelCase（UCP 内部常量）
- 所有代码示例为 C++17 标准，可在 Windows、Linux、macOS 上跨平台编译运行

---

## 许可证与商标

MIT 许可证。完整文本见 [LICENSE](../../LICENSE)。

版权所有 (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ 是 PPP PRIVATE NETWORK 的商标。
