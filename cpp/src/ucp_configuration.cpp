/** @file ucp_configuration.cpp
 *  @brief Out-of-line method definitions for UcpConfiguration -- mirrors C# Ucp.UcpConfiguration computed properties and lifecycle methods.
 *
 *  Contains implementations for:
 *    - ReceiveBufferSize getter/setter      (bytes <-> packets conversion)
 *    - InitialCwndBytes getter/setter        (bytes <-> packets conversion)
 *    - EffectiveMinRtoMicros / EffectiveMaxRtoMicros
 *    - EffectiveRetransmitBackoffFactor
 *    - EffectiveMaxBandwidthLossPercent       (clamped to [15%, 35%])
 *    - MaxAckSackBlocks                      (physical limit vs configured limit)
 *    - ReceiveWindowBytes                    (packet-based window -> bytes)
 *    - InitialCongestionWindowBytes          (packet-based CWND -> bytes)
 *    - Clone()                               (deep copy via CopyTo)
 *    - CopyTo()                              (field-by-field assignment)
 *    - GetOptimizedConfig()                  (production-tuned defaults)
 *
 *  Every method maps directly to its C# counterpart in Ucp.UcpConfiguration.cs.
 */

#include "ucp/ucp_configuration.h"
#include "ucp/ucp_constants.h"

namespace ucp {

int UcpConfiguration::ReceiveBufferSize() const noexcept {
    return RecvWindowPackets * Mss;
}

void UcpConfiguration::SetReceiveBufferSize(int v) noexcept {

    RecvWindowPackets = std::max(1, static_cast<int>(std::ceil(v / static_cast<double>(std::max(1, Mss)))));
}

uint32_t UcpConfiguration::InitialCwndBytes() const noexcept {
    return static_cast<uint32_t>(InitialCongestionWindowBytes());
}

void UcpConfiguration::SetInitialCwndBytes(uint32_t v) noexcept {

    InitialCwndPackets = std::max(1, static_cast<int>(std::ceil(v / static_cast<double>(std::max(1, Mss)))));
}

int64_t UcpConfiguration::EffectiveMinRtoMicros() const noexcept {

    return 0 >= MinRtoMicros ? Constants::MIN_RTO_MICROS : MinRtoMicros;
}

int64_t UcpConfiguration::EffectiveMaxRtoMicros() const noexcept {
    int64_t minRto = EffectiveMinRtoMicros();

    int64_t maxRto = 0 >= MaxRtoMicros ? Constants::MAX_RTO_MICROS : MaxRtoMicros;

    return minRto > maxRto ? minRto : maxRto;
}

double UcpConfiguration::EffectiveRetransmitBackoffFactor() const noexcept {

    return 1.0 > RetransmitBackoffFactor ? 1.0 : RetransmitBackoffFactor;
}

double UcpConfiguration::EffectiveMaxBandwidthLossPercent() const noexcept {
    double configured = MaxBandwidthLossPercent();

    if (Constants::MIN_MAX_BANDWIDTH_LOSS_PERCENT > configured) {
        return Constants::MIN_MAX_BANDWIDTH_LOSS_PERCENT;
    }

    if (Constants::MAX_MAX_BANDWIDTH_LOSS_PERCENT < configured) {
        return Constants::MAX_MAX_BANDWIDTH_LOSS_PERCENT;
    }

    return configured;
}

int UcpConfiguration::MaxAckSackBlocks() const noexcept {

    int encodedLimit = std::max(1, (Mss - Constants::ACK_FIXED_SIZE) / Constants::SACK_BLOCK_SIZE);

    int configuredLimit = 0 >= AckSackBlockLimit ? encodedLimit : AckSackBlockLimit;

    return std::max(1, std::min(configuredLimit, encodedLimit));
}

uint32_t UcpConfiguration::ReceiveWindowBytes() const noexcept {

    return static_cast<uint32_t>(RecvWindowPackets * Mss);
}

int UcpConfiguration::InitialCongestionWindowBytes() const noexcept {

    return std::max(Mss, InitialCwndPackets * Mss);
}

UcpConfiguration UcpConfiguration::Clone() const noexcept {
    UcpConfiguration copy;
    CopyTo(copy);
    return copy;
}

UcpConfiguration UcpConfiguration::GetOptimizedConfig() noexcept {
    UcpConfiguration config;

    config.MinRtoMicros = Constants::DEFAULT_RTO_MICROS;
    config.MaxRtoMicros = Constants::DEFAULT_MAX_RTO_MICROS;

    config.RetransmitBackoffFactor = Constants::RTO_BACKOFF_FACTOR;
    config.InitialCwndPackets = Constants::INITIAL_CWND_PACKETS;
    config.AckSackBlockLimit = Constants::DEFAULT_ACK_SACK_BLOCK_LIMIT;
    config.SetMaxBandwidthLossPercent(Constants::DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT);
    config.LossControlEnable = true;
    config.EnableAggressiveSackRecovery = true;

    return config;
}

void UcpConfiguration::CopyTo(UcpConfiguration& target) const noexcept {

    target.Mss = Mss;
    target.MaxRetransmissions = MaxRetransmissions;
    target.MinRtoMicros = MinRtoMicros;
    target.MaxRtoMicros = MaxRtoMicros;
    target.RetransmitBackoffFactor = RetransmitBackoffFactor;

    target.KeepAliveIntervalMicros = KeepAliveIntervalMicros;
    target.DisconnectTimeoutMicros = DisconnectTimeoutMicros;
    target.TimerIntervalMilliseconds = TimerIntervalMilliseconds;
    target.FairQueueRoundMilliseconds = FairQueueRoundMilliseconds;
    target.ServerBandwidthBytesPerSecond = ServerBandwidthBytesPerSecond;
    target.ConnectTimeoutMilliseconds = ConnectTimeoutMilliseconds;
    target.InitialBandwidthBytesPerSecond = InitialBandwidthBytesPerSecond;
    target.MaxPacingRateBytesPerSecond = MaxPacingRateBytesPerSecond;
    target.MaxCongestionWindowBytes = MaxCongestionWindowBytes;
    target.InitialCwndPackets = InitialCwndPackets;
    target.RecvWindowPackets = RecvWindowPackets;
    target.SendQuantumBytes = SendQuantumBytes;
    target.AckSackBlockLimit = AckSackBlockLimit;
    target.LossControlEnable = LossControlEnable;
    target.EnableDebugLog = EnableDebugLog;
    target.EnableAggressiveSackRecovery = EnableAggressiveSackRecovery;
    target.EcnEnabled = EcnEnabled;
    target.FecRedundancy = FecRedundancy;
    target.FecGroupSize = FecGroupSize;
    target.EnableMtuDiscovery = EnableMtuDiscovery;
    target.MtuProbeMax = MtuProbeMax;
    target.MtuProbeTimeoutMicros = MtuProbeTimeoutMicros;
    target.MtuProbeIntervalMicros = MtuProbeIntervalMicros;

    target.m_send_buffer_size = m_send_buffer_size;
    target.m_delayed_ack_timeout_micros = m_delayed_ack_timeout_micros;
    target.m_max_bandwidth_waste_percent = m_max_bandwidth_waste_percent;
    target.m_max_bandwidth_loss_percent = m_max_bandwidth_loss_percent;
    target.m_min_pacing_interval_micros = m_min_pacing_interval_micros;
    target.m_pacing_bucket_duration_micros = m_pacing_bucket_duration_micros;
}

} // namespace ucp
