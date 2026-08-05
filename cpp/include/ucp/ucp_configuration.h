#pragma once

/**
 * MIT License
 *
 * Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file ucp_configuration.h
 *  @brief Per-connection configuration object -- mirrors C# Ucp.UcpConfiguration.
 *
 *  Encapsulates all tunable parameters for a UCP connection:  MSS, RTO bounds,
 *  retransmit limits, pacing and UCP congestion control settings, FEC parameters, buffer sizes,
 *  and debugging flags.  Provides getter/setter methods that clamp values to
 *  safe ranges and derive computed properties (EffectiveMinRto, ReceiveWindowBytes, etc.).
 *
 *  An instance can be cloned (copy-constructed) and shared across multiple
 *  connections.  The static GetOptimizedConfig() returns a tuned configuration
 *  suitable for the current platform.
 */

#include <algorithm>
#include <cstdint>
#include <cmath>
#include "ucp/ucp_constants.h"

namespace ucp {

/** @brief Immutable-like configuration bag (mutable via setters) for a UCP connection.
 *
 *  All public fields have sensible defaults matching the C# UcpConfiguration
 *  class.  Most values are exposed directly (public fields); a few have getter/
 *  setter pairs that enforce clamping or maintain invariants.
 */
class UcpConfiguration {
  public:
    int Mss = 1220;
    int MaxRetransmissions = 10;
    int64_t MinRtoMicros = 50000LL;
    int64_t MaxRtoMicros = 15000000LL;
    double RetransmitBackoffFactor = 1.2;

    int64_t KeepAliveIntervalMicros = 1000000LL;
    int64_t DisconnectTimeoutMicros = 4000000LL;
    int TimerIntervalMilliseconds = 1;
    int FairQueueRoundMilliseconds = 10;
    int ServerBandwidthBytesPerSecond = 12500000;
    int ConnectTimeoutMilliseconds = 5000;

    int64_t InitialBandwidthBytesPerSecond = Constants::kInitialBandwidthBps;
    int64_t MaxPacingRateBytesPerSecond = Constants::kInitialBandwidthBps;
    int MaxCongestionWindowBytes = 64 * 1024 * 1024;
    int InitialCwndPackets = 10;
    int RecvWindowPackets = 4096;
    int SendQuantumBytes = 1220;
    int AckSackBlockLimit = 2;
    bool LossControlEnable = true;
    bool EnableDebugLog = false;
    bool EnableAggressiveSackRecovery = true;
    // C# parity; C++ ECN is compile-time gated by KCC_ECN_ENABLED (ucp_constants.h).
    bool EcnEnabled = false;

    double FecRedundancy = 0.0;
    int FecGroupSize = 8;

    bool EnableMtuDiscovery = true;
    int MtuProbeMax = 1500;
    int64_t MtuProbeTimeoutMicros = 10000000;
    int64_t MtuProbeIntervalMicros = 600000000;

    int SendBufferSize() const noexcept { return m_send_buffer_size; }
    /** @brief Sets send buffer capacity.
     *  @param v  Capacity in bytes. */
    void SetSendBufferSize(int v) noexcept { m_send_buffer_size = v; }

    int ReceiveBufferSize() const noexcept;
    /** @brief Converts user-supplied bytes to packet count with ceiling division.
     *  @param v  Buffer size in bytes. */
    void SetReceiveBufferSize(int v) noexcept;

    uint32_t InitialCwndBytes() const noexcept;
    /** @brief Converts user-supplied bytes to packet count with ceiling division.
     *  @param v  CWND in bytes. */
    void SetInitialCwndBytes(uint32_t v) noexcept;

    int64_t MinRtoUs() const noexcept { return MinRtoMicros; }
    /** @brief Sets minimum RTO in microseconds -- delegates to MinRtoMicros.
     *  @param v  RTO in microseconds. */
    void SetMinRtoUs(int64_t v) noexcept { MinRtoMicros = v; }

    int64_t MaxRtoUs() const noexcept { return MaxRtoMicros; }
    /** @brief Sets maximum RTO in microseconds -- delegates to MaxRtoMicros.
     *  @param v  Max RTO in microseconds. */
    void SetMaxRtoUs(int64_t v) noexcept { MaxRtoMicros = v; }

    double RtoBackoffFactor() const noexcept { return RetransmitBackoffFactor; }
    /** @brief Sets RTO backoff factor -- delegates to RetransmitBackoffFactor.
     *  @param v  Backoff multiplier. */
    void SetRtoBackoffFactor(double v) noexcept { RetransmitBackoffFactor = v; }

    int64_t DelayedAckTimeoutMicros() const noexcept { return m_delayed_ack_timeout_micros; }
    /** @brief Sets delayed ACK timeout in microseconds.
     *  @param v  Timeout in microseconds. */
    void SetDelayedAckTimeoutMicros(int64_t v) noexcept { m_delayed_ack_timeout_micros = v; }

    double MaxBandwidthWastePercent() const noexcept { return m_max_bandwidth_waste_percent; }
    /** @brief Sets max bandwidth waste ratio.
     *  @param v  Waste ratio (0.0-1.0). */
    void SetMaxBandwidthWastePercent(double v) noexcept { m_max_bandwidth_waste_percent = v; }

    double MaxBandwidthLossPercent() const noexcept { return m_max_bandwidth_loss_percent; }
    /** @brief Sets max bandwidth loss percent.
     *  @param v  Loss percent. */
    void SetMaxBandwidthLossPercent(double v) noexcept { m_max_bandwidth_loss_percent = v; }

    int64_t MinPacingIntervalMicros() const noexcept { return m_min_pacing_interval_micros; }
    /** @brief Sets minimum inter-packet pacing gap in microseconds.
     *  @param v  Interval in microseconds. */
    void SetMinPacingIntervalMicros(int64_t v) noexcept { m_min_pacing_interval_micros = v; }

    int64_t PacingBucketDurationMicros() const noexcept { return m_pacing_bucket_duration_micros; }
    /** @brief Sets token-bucket refill window in microseconds.
     *  @param v  Duration in microseconds. */
    void SetPacingBucketDurationMicros(int64_t v) noexcept { m_pacing_bucket_duration_micros = v; }

    int64_t KeepAliveIntervalUs() const noexcept { return KeepAliveIntervalMicros; }
    /** @brief Sets keep-alive interval -- delegates to KeepAliveIntervalMicros.
     *  @param v  Interval in microseconds. */
    void SetKeepAliveIntervalUs(int64_t v) noexcept { KeepAliveIntervalMicros = v; }

    int64_t DisconnectTimeoutUs() const noexcept { return DisconnectTimeoutMicros; }
    /** @brief Sets disconnect timeout -- delegates to DisconnectTimeoutMicros.
     *  @param v  Timeout in microseconds. */
    void SetDisconnectTimeoutUs(int64_t v) noexcept { DisconnectTimeoutMicros = v; }

    /** @brief Effective minimum RTO: Max(MinRtoMicros, protocol floor).
     *  @return Clamped minimum RTO in microseconds. */
    int64_t EffectiveMinRtoMicros() const noexcept;

    /** @brief Effective maximum RTO: Max(effective-min, effective-max).
     *  @return Clamped maximum RTO in microseconds. */
    int64_t EffectiveMaxRtoMicros() const noexcept;

    /** @brief Effective backoff factor: Max(RetransmitBackoffFactor, 1.0).
     *  @return Clamped backoff factor. */
    double EffectiveRetransmitBackoffFactor() const noexcept;

    /** @brief Clamped loss percent to [15%, 35%].
     *  @return Clamped loss percent. */
    double EffectiveMaxBandwidthLossPercent() const noexcept;

    /** @brief Maximum application payload size = MSS - 20 bytes reserved for the data-packet header.
     *  @return Usable payload capacity per data packet (1200 bytes at default MSS). */
    int MaxPayloadSize() const noexcept { return Mss - Constants::DATA_HEADER_SIZE; }

    /** @brief Max SACK blocks fitting in one ACK packet, bounded by both physical space and configured limit.
     *  @return Maximum SACK block count. */
    int MaxAckSackBlocks() const noexcept;

    /** @brief Advertised receive window in bytes: RecvWindowPackets * Mss.
     *  @return Receive window in bytes. */
    uint32_t ReceiveWindowBytes() const noexcept;

    /** @brief Initial CWND in bytes: Max(Mss, InitialCwndPackets * Mss).
     *  @return Initial CWND in bytes. */
    int InitialCongestionWindowBytes() const noexcept;

    /** @brief Deep-copy this configuration.
     *  @return A new UcpConfiguration with the same field values (no shared references). */
    UcpConfiguration Clone() const noexcept;

    /** @brief Get a configuration optimized for the current platform (network type, MTU, etc.).
     *  @return A UcpConfiguration with platform-tuned defaults. */
    static UcpConfiguration GetOptimizedConfig() noexcept;

    /** @brief Copy all field values from this instance into @p target.
     *  @param target  Destination configuration to overwrite (must be a valid reference). */
    void CopyTo(UcpConfiguration& target) const noexcept;

  private:
    int m_send_buffer_size = 32 * 1024 * 1024;
    int64_t m_delayed_ack_timeout_micros = 100LL;
    double m_max_bandwidth_waste_percent = 0.25;
    double m_max_bandwidth_loss_percent = 25.0;
    int64_t m_min_pacing_interval_micros = 0LL;
    int64_t m_pacing_bucket_duration_micros = 10000LL;
};

} // namespace ucp
