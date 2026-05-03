/** @file ucp_configuration.cpp
 *  @brief Out-of-line method definitions for UcpConfiguration — mirrors C# Ucp.UcpConfiguration computed properties and lifecycle methods.
 *
 *  Contains implementations for:
 *    - ReceiveBufferSize getter/setter      (bytes ↔ packets conversion)
 *    - InitialCwndBytes getter/setter        (bytes ↔ packets conversion)
 *    - EffectiveMinRtoMicros / EffectiveMaxRtoMicros
 *    - EffectiveRetransmitBackoffFactor
 *    - EffectiveMaxBandwidthLossPercent       (clamped to [15%, 35%])
 *    - MaxAckSackBlocks                      (physical limit vs configured limit)
 *    - ReceiveWindowBytes                    (packet-based window → bytes)
 *    - InitialCongestionWindowBytes          (packet-based CWND → bytes)
 *    - Clone()                               (deep copy via CopyTo)
 *    - CopyTo()                              (field-by-field assignment)
 *    - GetOptimizedConfig()                  (production-tuned defaults)
 *
 *  Every method maps directly to its C# counterpart in Ucp.UcpConfiguration.cs.
 */

#include "ucp/ucp_configuration.h" // Provides the UcpConfiguration class declaration
#include "ucp/ucp_constants.h"     // Provides Constants::MSS, ACK_FIXED_SIZE, SACK_BLOCK_SIZE, RTO/BBR constants, etc.

namespace ucp { // Opens the UCP protocol library namespace — matches the header

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ReceiveBufferSize — converts between bytes and packet-based receive window
//  Mirrors C#: public int ReceiveBufferSize { get; set; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

int UcpConfiguration::ReceiveBufferSize() const { // Returns receive buffer size in bytes — mirrors C# ReceiveBufferSize.get => RecvWindowPackets * Mss
    return RecvWindowPackets * Mss; // Converts the packet-based window to user-friendly byte count, ex: 16384 * 1220 = ~20 MB
}

void UcpConfiguration::SetReceiveBufferSize(int v) { // Sets receive buffer from user-supplied bytes — mirrors C# ReceiveBufferSize.set
    // C# equivalent: RecvWindowPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss)));
    RecvWindowPackets = std::max(1, // Floor of 1 packet ensures at least one segment fits in the window
        static_cast<int>(std::ceil( // Ceiling division: round up to ensure the byte budget is fully covered
            v / static_cast<double>(std::max(1, Mss)) // Divide bytes by MSS (guarded against zero-MSS) to get packet count
        ))
    );
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  InitialCwndBytes — converts between bytes and packet-based initial CWND
//  Mirrors C#: public uint InitialCwndBytes { get; set; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

uint32_t UcpConfiguration::InitialCwndBytes() const { // Returns initial CWND in bytes — mirrors C# InitialCwndBytes.get => (uint)InitialCongestionWindowBytes
    return static_cast<uint32_t>(InitialCongestionWindowBytes()); // Delegates to InitialCongestionWindowBytes() and casts to uint32_t for wire compatibility
}

void UcpConfiguration::SetInitialCwndBytes(uint32_t v) { // Sets initial CWND from user-supplied bytes — mirrors C# InitialCwndBytes.set
    // C# equivalent: InitialCwndPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss)));
    InitialCwndPackets = std::max(1, // Floor of 1 packet prevents a zero-CWND edge case
        static_cast<int>(std::ceil( // Ceiling division: round up so the byte count fits within the packet budget
            v / static_cast<double>(std::max(1, Mss)) // Divide bytes by MSS (guarded against zero) to get initial packet count
        ))
    );
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  EffectiveMinRtoMicros — floor-protected minimum RTO
//  Mirrors C#: public long EffectiveMinRtoMicros { get; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

int64_t UcpConfiguration::EffectiveMinRtoMicros() const { // Computes the effective minimum RTO — mirrors C# EffectiveMinRtoMicros.get
    // C# equivalent: return MinRtoMicros <= 0 ? UcpConstants.MinRtoMicros : MinRtoMicros;
    return MinRtoMicros <= 0 // If the user configured a non-positive (invalid) RTO...
        ? Constants::MIN_RTO_MICROS  // ...fall back to the 20 ms protocol floor to prevent zero/negative RTO
        : MinRtoMicros;             // ...otherwise use the user-configured value as-is
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  EffectiveMaxRtoMicros — floor-protected maximum RTO, never below effective min
//  Mirrors C#: public long EffectiveMaxRtoMicros { get; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

int64_t UcpConfiguration::EffectiveMaxRtoMicros() const { // Computes the effective maximum RTO — mirrors C# EffectiveMaxRtoMicros.get
    int64_t minRto = EffectiveMinRtoMicros(); // Capture the effective minimum RTO as the floor for max — mirrors C#: long minRtoMicros = EffectiveMinRtoMicros;

    // C# equivalent: long maxRtoMicros = MaxRtoMicros <= 0 ? UcpConstants.MaxRtoMicros : MaxRtoMicros;
    int64_t maxRto = MaxRtoMicros <= 0 // If the user configured a non-positive (invalid) max RTO...
        ? Constants::MAX_RTO_MICROS  // ...fall back to the 60 s absolute maximum to prevent zero/negative RTO range
        : MaxRtoMicros;              // ...otherwise use the user-configured value as-is

    // C# equivalent: return maxRtoMicros < minRtoMicros ? minRtoMicros : maxRtoMicros;
    return maxRto < minRto // If the effective maximum would be below the effective minimum (inverted range)...
        ? minRto            // ...enforce maxRto ≥ minRto, preventing inverted RTO range that would break timer logic
        : maxRto;           // ...otherwise return the configured max RTO (correctly ordered)
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  EffectiveRetransmitBackoffFactor — clamped to at least 1.0
//  Mirrors C#: public double EffectiveRetransmitBackoffFactor { get; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

double UcpConfiguration::EffectiveRetransmitBackoffFactor() const { // Computes the effective backoff factor — mirrors C# EffectiveRetransmitBackoffFactor.get
    // C# equivalent: return RetransmitBackoffFactor < 1.0d ? 1.0d : RetransmitBackoffFactor;
    return RetransmitBackoffFactor < 1.0 // A backoff factor below 1.0 would shrink RTO on each timeout — never correct
        ? 1.0                          // Clamp to the 1.0 floor — RTO should stay constant at minimum (no expansion, no contraction)
        : RetransmitBackoffFactor;     // Use the configured factor as-is when ≥ 1.0 (e.g. 1.2 = +20% per timeout)
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  EffectiveMaxBandwidthLossPercent — clamped to [15%, 35%]
//  Mirrors C#: public double EffectiveMaxBandwidthLossPercent { get; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

double UcpConfiguration::EffectiveMaxBandwidthLossPercent() const { // Computes the clamped loss ceiling — mirrors C# EffectiveMaxBandwidthLossPercent.get
    double configured = MaxBandwidthLossPercent(); // Read user-configured value via getter (backing field) — mirrors C#: double configuredValue = MaxBandwidthLossPercent;

    if (configured < Constants::MIN_MAX_BANDWIDTH_LOSS_PERCENT) { // Below 15% would throttle too aggressively on routine random-loss paths (WiFi, 4G)
        return Constants::MIN_MAX_BANDWIDTH_LOSS_PERCENT; // Return the 15% floor — prevents over-throttling on paths with natural packet loss
    }

    if (configured > Constants::MAX_MAX_BANDWIDTH_LOSS_PERCENT) { // Above 35% would tolerate loss rates where throughput collapses regardless
        return Constants::MAX_MAX_BANDWIDTH_LOSS_PERCENT; // Return the 35% ceiling — prevents the sender from operating at unusable loss rates
    }

    return configured; // Value is within the safe range [15%, 35%] — return as-is with no clamping needed
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  MaxAckSackBlocks — SACK blocks bounded by physical capacity
//  Mirrors C#: public int MaxAckSackBlocks { get; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

int UcpConfiguration::MaxAckSackBlocks() const { // Computes max SACK blocks per ACK — mirrors C# MaxAckSackBlocks.get
    // C# equivalent: int encodedLimit = Math.Max(1, (Mss - UcpConstants.AckFixedSize) / UcpConstants.SACK_BLOCK_SIZE);
    int encodedLimit = std::max(1, // Floor of 1 SACK block — every ACK can report at least one range
        (Mss - Constants::ACK_FIXED_SIZE) // Available bytes after the fixed ACK header: 1220 - 28 = 1192
        / Constants::SACK_BLOCK_SIZE // Divide by 8 bytes per SACK block (2× uint32): 1192 / 8 = 149 blocks max
    );

    // C# equivalent: int configuredLimit = AckSackBlockLimit <= 0 ? encodedLimit : AckSackBlockLimit;
    int configuredLimit = AckSackBlockLimit <= 0 // If the user left the limit at zero or negative (meaning "use physical max")...
        ? encodedLimit                          // ...default to the physical limit computed above
        : AckSackBlockLimit;                    // ...otherwise use the explicitly configured limit

    // C# equivalent: return Math.Max(1, Math.Min(configuredLimit, encodedLimit));
    return std::max(1, // Never return less than 1 — safety floor
        std::min(configuredLimit, encodedLimit) // Take the tighter of the user's setting and the physical space budget
    );
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ReceiveWindowBytes — packet-based window converted to bytes
//  Mirrors C#: public uint ReceiveWindowBytes { get; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

uint32_t UcpConfiguration::ReceiveWindowBytes() const { // Advertised receive window in bytes — mirrors C# ReceiveWindowBytes.get
    // C# equivalent: return (uint)(RecvWindowPackets * Mss);
    return static_cast<uint32_t>( // Cast to uint32_t for wire advertisement in ACK packets
        RecvWindowPackets * Mss   // Packet count × segment size: e.g. 16384 × 1220 = ~20 MB window
    );
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  InitialCongestionWindowBytes — at least one MSS worth of initial CWND
//  Mirrors C#: public int InitialCongestionWindowBytes { get; }
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

int UcpConfiguration::InitialCongestionWindowBytes() const { // Computes initial CWND in bytes — mirrors C# InitialCongestionWindowBytes.get
    // C# equivalent: return Math.Max(Mss, InitialCwndPackets * Mss);
    return std::max( // Return the larger of the two — prevents a zero-CWND edge case
        Mss,                     // At least one MSS worth of bytes: 1220 — absolute floor
        InitialCwndPackets * Mss // Configured packet count × MSS: e.g. 20 × 1220 = 24400 bytes
    );
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Clone — deep copy via CopyTo
//  Mirrors C#: public UcpConfiguration Clone()
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

UcpConfiguration UcpConfiguration::Clone() const { // Creates an independent deep copy — mirrors C# Clone()
    UcpConfiguration copy; // Default-construct a fresh config with all field defaults — mirrors C#: new UcpConfiguration()
    CopyTo(copy);          // Copy every field from *this into the new instance — mirrors C#: CopyTo(clone)
    return copy;           // Return the independent copy by value — no shared mutable state between original and clone
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  GetOptimizedConfig — production-tuned defaults
//  Mirrors C#: public static UcpConfiguration GetOptimizedConfig()
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

UcpConfiguration UcpConfiguration::GetOptimizedConfig() { // Returns a production-tuned configuration — mirrors C# GetOptimizedConfig()
    UcpConfiguration config; // Start with a default-constructed config (all default values) — mirrors C#: new UcpConfiguration()

    config.MinRtoMicros = Constants::DEFAULT_RTO_MICROS; // 50 ms — long enough for transient jitter, short enough for fast tail-loss recovery
    config.MaxRtoMicros = Constants::DEFAULT_MAX_RTO_MICROS; // 15 s — connection is likely dead beyond this point
    config.ProbeRttIntervalMicros = Constants::BBR_PROBE_RTT_INTERVAL_MICROS; // 30 s between ProbeRTT phases — amortizes throughput dip to <1%
    config.ProbeRttDurationMicros = Constants::BBR_PROBE_RTT_DURATION_MICROS; // 100 ms minimum ProbeRTT duration — ensures one clean RTT sample
    config.RetransmitBackoffFactor = Constants::RTO_BACKOFF_FACTOR; // 1.2× gentle backoff — avoids multi-second stalls on bursty-loss paths
    config.InitialCwndPackets = Constants::INITIAL_CWND_PACKETS; // 20 packets initial CWND — aggressive but safe with BBR pacing
    config.SetProbeBwLowGain(Constants::BBR_PROBE_BW_LOW_GAIN); // 0.85× drain-phase gain — empties queue accumulated during high-gain phase
    config.AckSackBlockLimit = Constants::DEFAULT_ACK_SACK_BLOCK_LIMIT; // 2 SACK blocks per ACK — matches QUIC default for efficient loss reporting
    config.SetMaxBandwidthLossPercent(Constants::DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT); // 25% loss ceiling — balanced for mobile/WiFi paths with routine packet loss
    config.LossControlEnable = true; // Enable loss-aware pacing — prevents the sender from overdriving lossy paths
    config.EnableAggressiveSackRecovery = true; // Enable short-grace SACK recovery — reduces tail latency on reordering paths (mirrors QUIC)

    return config; // Return the fully tuned configuration by value — mirrors C#: return config;
}

//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CopyTo — field-by-field copy into a target
//  Mirrors C#: internal void CopyTo(UcpConfiguration target)
//━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

void UcpConfiguration::CopyTo(UcpConfiguration& target) const { // Copies every field from this into target — mirrors C# CopyTo(target)
    // C# has a null guard here: if (target == null) throw new ArgumentNullException(...);
    // In C++ the reference cannot be null — no guard needed.

    // --- Public fields (direct assignment, no backing field) ---
    target.Mss = Mss; // Copy MSS — affects all packet-size derived calculations (MaxPayloadSize, MaxAckSackBlocks, etc.)
    target.MaxRetransmissions = MaxRetransmissions; // Copy max retransmissions — connection teardown threshold after repeated RTO timeouts
    target.MinRtoMicros = MinRtoMicros; // Copy minimum RTO — floor for the RTO timer computation
    target.MaxRtoMicros = MaxRtoMicros; // Copy maximum RTO — ceiling for the RTO timer computation
    target.RetransmitBackoffFactor = RetransmitBackoffFactor; // Copy RTO backoff multiplier — controls exponential growth on repeated timeouts
    target.ProbeRttIntervalMicros = ProbeRttIntervalMicros; // Copy ProbeRTT interval — how often BBR re-measures RTprop
    target.ProbeRttDurationMicros = ProbeRttDurationMicros; // Copy ProbeRTT duration — minimum time spent in ProbeRTT state
    target.KeepAliveIntervalMicros = KeepAliveIntervalMicros; // Copy keep-alive interval — NAT binding refresh frequency
    target.DisconnectTimeoutMicros = DisconnectTimeoutMicros; // Copy disconnect timeout — idle time before dead-peer detection
    target.TimerIntervalMilliseconds = TimerIntervalMilliseconds; // Copy timer tick granularity — affects pacing precision
    target.FairQueueRoundMilliseconds = FairQueueRoundMilliseconds; // Copy fair-queue round interval — credit distribution frequency
    target.ServerBandwidthBytesPerSecond = ServerBandwidthBytesPerSecond; // Copy server bandwidth — total egress capacity for fair-queue pool
    target.ConnectTimeoutMilliseconds = ConnectTimeoutMilliseconds; // Copy connect timeout — SYN handshake deadline
    target.InitialBandwidthBytesPerSecond = InitialBandwidthBytesPerSecond; // Copy initial bandwidth estimate — BBR Startup starting point
    target.MaxPacingRateBytesPerSecond = MaxPacingRateBytesPerSecond; // Copy max pacing rate — absolute ceiling on send rate
    target.MaxCongestionWindowBytes = MaxCongestionWindowBytes; // Copy max CWND — absolute ceiling on bytes in flight
    target.InitialCwndPackets = InitialCwndPackets; // Copy initial CWND packets — starting inflight budget in packet units
    target.RecvWindowPackets = RecvWindowPackets; // Copy receive window packets — flow-control advertisement size
    target.SendQuantumBytes = SendQuantumBytes; // Copy send quantum — minimum bytes sent per scheduling round
    target.AckSackBlockLimit = AckSackBlockLimit; // Copy SACK block limit — max SACK ranges per ACK packet
    target.LossControlEnable = LossControlEnable; // Copy loss control toggle — enables loss-budgeted pacing
    target.EnableDebugLog = EnableDebugLog; // Copy debug log toggle — enables trace logging for congestion-control decisions
    target.EnableAggressiveSackRecovery = EnableAggressiveSackRecovery; // Copy aggressive SACK toggle — lowers retransmit threshold for fast recovery
    target.FecRedundancy = FecRedundancy; // Copy FEC redundancy ratio — controls forward error correction overhead
    target.FecGroupSize = FecGroupSize; // Copy FEC group size — data packets per repair group

    // --- Private backing fields (copied via members, accessible within the same class) ---
    target.m_send_buffer_size = m_send_buffer_size; // Copy send buffer capacity — controls blocking behavior of SendAsync
    target.m_delayed_ack_timeout_micros = m_delayed_ack_timeout_micros; // Copy delayed ACK timeout — affects ACK responsiveness vs. overhead
    target.m_max_bandwidth_waste_percent = m_max_bandwidth_waste_percent; // Copy retransmit waste ceiling — controls when sender throttles
    target.m_max_bandwidth_loss_percent = m_max_bandwidth_loss_percent; // Copy loss tolerance ceiling — clamped to [15%, 35%] at consumption
    target.m_min_pacing_interval_micros = m_min_pacing_interval_micros; // Copy minimum pacing gap — 0 μs allows line-rate bursts
    target.m_pacing_bucket_duration_micros = m_pacing_bucket_duration_micros; // Copy token bucket window — controls burst elasticity
    target.m_bbr_window_rt_rounds = m_bbr_window_rt_rounds; // Copy BBR filter window size — longer windows produce stabler estimates
    target.m_startup_pacing_gain = m_startup_pacing_gain; // Copy Startup pacing gain — controls fill aggressiveness
    target.m_startup_cwnd_gain = m_startup_cwnd_gain; // Copy Startup CWND gain — inflight headroom during initial ramp
    target.m_drain_pacing_gain = m_drain_pacing_gain; // Copy Drain pacing gain — queue drain rate after Startup
    target.m_probe_bw_high_gain = m_probe_bw_high_gain; // Copy ProbeBW high gain — bandwidth probe aggressiveness
    target.m_probe_bw_low_gain = m_probe_bw_low_gain; // Copy ProbeBW low gain — queue drain rate during ProbeBW cycle
    target.m_probe_bw_cwnd_gain = m_probe_bw_cwnd_gain; // Copy CWND gain during ProbeBW — steady-state inflight headroom
}

} // namespace ucp — closes the UCP protocol library namespace
