# UCP C++ 性能特征

[English](performance_EN.md)

本文档详述 UCP C++ 实现的性能特征，包括 KCC（Geodesic Congestion Control）拥塞控制机制（KF 组件源于 tcp_kcc.c v2.0）、测地线估计器 RTT 估计、RTO 估计器、Pacing 控制器、FEC 编解码性能、基准测试结果以及与 TCP/QUIC 的对比。

## KCC 拥塞控制内核

UCP 使用的 KCC 拥塞控制引擎以实时投递率而非丢包作为主要拥塞信号。KCC 算法在三个模式间切换：Startup 阶段使用 2.887 倍 Pacing 增益快速探测可用带宽，Drain 阶段清空在途队列，ProbeBW 阶段通过 8 阶段增益循环 [1.25, 0.75, 1.0×6] 动态探测并适应带宽变化。MinRTT 跟踪由测地线估计器 G1/G3 自动处理。

KCC（Geodesic Congestion Control）是 UCP 使用的拥塞控制算法，结合 KCC 3 模式状态机（Startup/Drain/ProbeBW）与测地线估计器（G1/G2/G3）进行传播延迟估计（KF 组件源于 tcp_kcc.c v2.0；固定结构参数：p_est_init=1000, scale=1024）。测地线估计器替代了传统基于模型方法中的窗口最小值滤波器，使用三个结构分支（G1 瞬时向下吸收、G2 每 RTT 12.2% 有界增长、G3 双阈值路径增长检测：快路径 6 次连续事件 ≥1.10×、慢路径 7 次连续事件 ≥1.05×）。不存在协方差矩阵、过程模型或自适应增益。关键特性包括各模式固定增益（无增益衰减）、ECN 感知退避（默认禁用）、长期带宽 EWMA 一致性检查、ACK 聚合补偿（双窗口 5-RTT 轮换）和可选跨连接卡尔曼滤波器（KF）。FEC 提供恢复字节样本（改善带宽/RTT 估计），NAK 提供丢包样本数据（改善长期带宽估计），为拥塞控制引擎提供更精确的带宽/延迟估计。

### UcpConfiguration 结构

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

拥塞控制增益是固定常量（与 tcp_kcc.c 一致）：Startup pacing/cwnd 2.887x（739/256）、Drain pacing 0.344x（88/256）、ProbeBW 循环 [1.25, 0.75, 1.0×6] 且 cwnd 增益 2.0x。不可配置。

### KCC 模式与增益

| 模式 | Pacing 增益 | CWND 增益 | 持续时间 | 退出条件 |
|---|---|---|---|---|
| Startup | 2.887 (739/256) | 2.887 | 约 3-5 RTT | 连续 3 RTT 增长 < 25% |
| Drain | 0.344 (88/256) | 2.887 | 约 1 RTT | 在途 ≤ BDP 且 1 RTT 已过（或 4×min_rtt 超时） |
| ProbeBW | 循环 [1.25, 0.75, 1.0x6] | 2.0 | 稳态 | 8 阶段循环 |

C++ 和 C# 使用相同的增益值：Startup=2.887 (739/256)、Drain=0.344 (88/256)。

### 测地线估计器传播延迟估计

UCP 使用测地线估计器（G1/G2/G3）进行传播延迟估计，替代了基于窗口最小值的滤波器。测地线估计器采用三分量行为模型（T_prop / T_queue / T_noise），固定结构参数：p_est_init=1000, p_est_floor=10, scale=1024。不存在协方差矩阵、过程模型或自适应增益。

## Pacing Controller 性能

| 操作 | 方法 | 行为 |
|---|---|---|
| 普通发送 | TryConsume(bytes, now) | Refill → 检查令牌余额 |
| 紧急重传 | ForceConsume(bytes, now) | Refill → 直接发送（令牌清零，不产生负债务） |
| 等待时间 | GetWaitTimeMicros(bytes, now) | 返回 (bytes - _tokens) * 1e6 / rate |
| 速率变更 | SetRate(rate, now) | 设置新速率，重置桶容量 |

## RTO 估计器性能

### RTO 核心常量

| 常量 | C++ 值 | C# 值 |
|---|---|---|
| INITIAL_RTO_MICROS | 50ms | 50ms |
| MIN_RTO_MICROS | 50ms | 50ms |
| DEFAULT_RTO_MICROS | 50ms | 50ms |
| MAX_RTO_MICROS | 60s | 60s |
| RTO_BACKOFF_FACTOR | 1.2 | 1.2 |

### RTO 计算公式

```
初始化: SRTT = sample, RTTVAR = sample / 2, RTO = clamp(SRTT + 4*RTTVAR, MIN, MAX)
每 RTT 样本: SRTT = 7/8*SRTT + 1/8*sample
             RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - sample|
             RTO = clamp(SRTT + 4*RTTVAR, MIN, MAX)
超时退避: RTO = clamp(RTO * 1.2, MIN, MAX)
```

### 与 TCP RTO 差异

| 特性 | TCP | UCP C++ | 原因 |
|---|---|---|---|
| 初始 RTO | 1s | 50ms | NAK/FEC 已处理大部分丢包 |
| 最小 RTO | 200ms | 50ms | LAN 上更快检测死路径 |
| 退避因子 | 2.0 | 1.2 | UCP 不降低 CWND |

## FEC 编解码性能

| 运算 | 复杂度 | CPU 操作 |
|---|---|---|
| 加法 | O(1) | XOR |
| 乘法 | O(1) | 2 查表 + 1 加法 + 1 取模 |
| 除法 | O(1) | 2 查表 + 1 减法 |
| 求逆 | O(1) | 1 查表 + 1 减法 |

### 编解码复杂度

```
编码: O(R * N * L) 次 GF256 乘法，R=修复包数, N=组大小, L=负载长度
解码: O(N^3 * L / slot_length) 次 GF256 运算 (高斯消元)
```

| 配置 | 冗余开销 | 可恢复丢包 |
|---|---|---|
| group_size=8, repair_count=1 | 12.5% | 每组最多 1 包 |
| group_size=8, repair_count=2 | 25% | 每组最多 2 包 |
| group_size=16, repair_count=4 | 25% | 每组最多 4 包 |
| 禁用 FEC | 0% | 0 |

## 基准测试结果

### C++ 实现基准数据

| 场景 | 目标 Mbps | RTT | 丢包率 | 吞吐 Mbps | 利用率 |
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

C++ 实现在长 RTT 路径上达成最高利用率，得益于 1ms Pacing 定时器。

### 性能预期表

| 场景 | 目标 Mbps | RTT | 丢包率 | 预期吞吐 | 预期重传率 |
|---|---|---|---|---|---|
| NoLoss | 100 | 0.5ms | 0% | 95-100 Mbps | 0% |
| Lossy 1% | 100 | 10ms | 1% | 90-99 Mbps | ~1.2% |
| Lossy 5% | 100 | 10ms | 5% | 75-95 Mbps | ~6% |
| Satellite | 10 | 300ms | 0% | 8.5-9.9 Mbps | 0% |
| Mobile 4G | 20 | 50ms | 1% | 18-19.8 Mbps | ~1.2% |
| VPN Tunnel | 50 | 15ms | 1% | 45-49.5 Mbps | ~1.3% |

### 定时器粒度对 Pacing 精度的影响

| 定时器周期 | Pacing 帧率 | 每帧最大 Token | 利用率损失 |
|---|---|---|---|
| 1ms (C++) | 1000 Hz | 12.5 KB | < 1% |
| 1ms (C#) | 1000 Hz | 12.5 KB | < 1% |

## 收敛特性

无丢包收敛时间：

| 路径 | RTT | Startup + Drain | 实际收敛 |
|---|---|---|---|
| LAN | 0.5ms | 2.5ms | < 50ms |
| 宽带 | 10ms | 50ms | < 500ms |
| 卫星 | 300ms | 1.5s | < 30s |

## 与 TCP / QUIC 对比

### UCP 对比 TCP

| 特性 | TCP (CUBIC) | UCP C++ |
|---|---|---|
| 丢包响应 | CWND 减半 (50%) | 包守恒恢复 + LT-BW EMA（无乘性 cwnd 削减） |
| 拥塞检测 | 基于丢包 | 基于 RTT + 投递率 |
| 最小 RTO | 200ms | 50ms |
| 5% 丢包吞吐 | 30-50% 利用率 | 20.05% 利用率（实测，见上文基准结果表） |
| FEC | 无 | RS-GF(256) |
| 恢复路径 | DupACK + RTO | SACK/NAK/FEC/DupACK/RTO 五条 |

### UCP 对比 QUIC

| 特性 | QUIC | UCP C++ |
|---|---|---|
| 连接迁移 | 可选 | 默认启用 |
| 拥塞控制 | 可插拔 (默认 NewReno) | UCP (内置) |
| ACK 模型 | ACK 帧 | 捎带 ACK (所有包类型) |
| NAK | 无 | 三级置信度 NAK |
| FEC | 无 | RS-GF(256) |
| 多路复用 | 内置流多路复用 | 每连接独立 |

## 性能调优指南

### MSS 调优

| 路径类型 | 推荐 MSS | 原因 |
|---|---|---|
| 低带宽 (< 1 Mbps) | 536-1220 | 避免 IP 分片 |
| 宽带/4G (1-100 Mbps) | 1220 (默认) | 最佳平衡 |
| 千兆 LAN (1-10 Gbps) | 9000 (巨型帧) | 减少 ~85% 每包开销 |
| 卫星 (高 RTT) | 1220-9000 | 减少 ACK 包数量 |

### 常见性能陷阱

| 陷阱 | 症状 | 解决方案 |
|---|---|---|
| MSS 过小 | 千兆仅 ~500Mbps | Mss = 9000 |
| SendBuffer 过小 | WriteAsync 频繁阻塞 | SetSendBufferSize(BDP * 1.5) |
| MaxPacingRate 天花板 | 吞吐停滞 100Mbps | MaxPacingRateBytesPerSecond = 0 |
| FEC 配置不当 | Retrans% >> Loss% | FecRedundancy = 0.25 |

## 相关文档

- [architecture_CN.md](architecture_CN.md) — 运行时层次结构
- [protocol_CN.md](protocol_CN.md) — 协议规范
- [api_CN.md](api_CN.md) — API 参考
- [constants_CN.md](constants_CN.md) — 协议常量
- [README_CN.md](../README_CN.md) — 项目介绍
- [Linux 内核模块](../../linux/README.md) — KCC Geodesic Congestion Control 内核模块（tcp_kcc.c v2.0，含 KCC Forwarding (KF) 跨连接带宽共享组件）

---

## 许可证与商标

MIT 许可证。完整文本见 [LICENSE](../../LICENSE)。

版权所有 (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ 是 PPP PRIVATE NETWORK 的商标。

