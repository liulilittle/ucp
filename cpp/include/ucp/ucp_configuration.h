#pragma once // Prevents multiple inclusions of this header within a single translation unit

/** @file ucp_configuration.h
 *  @brief Per-connection configuration object — mirrors C# Ucp.UcpConfiguration.
 *
 *  Encapsulates all tunable parameters for a UCP connection:  MSS, RTO bounds,
 *  retransmit limits, pacing and BBR settings, FEC parameters, buffer sizes,
 *  and debugging flags.  Provides getter/setter methods that clamp values to
 *  safe ranges and derive computed properties (EffectiveMinRto, ReceiveWindowBytes, etc.).
 *
 *  An instance can be cloned (copy-constructed) and shared across multiple
 *  connections.  The static GetOptimizedConfig() returns a tuned configuration
 *  suitable for the current platform.
 */

#include <algorithm> // Provides std::max, std::min, std::ceil — used in computed-property implementations
#include <cstdint>   // Provides fixed-width integer types: int64_t, uint32_t, uint16_t
#include <cmath>     // Provides std::ceil for ceiling-division in SetReceiveBufferSize / SetInitialCwndBytes

namespace ucp { // Opens the UCP protocol library namespace — mirrors C# namespace Ucp

/** @brief Immutable-like configuration bag (mutable via setters) for a UCP connection.
 *
 *  All public fields have sensible defaults matching the C# UcpConfiguration
 *  class.  Most values are exposed directly (public fields); a few have getter/
 *  setter pairs that enforce clamping or maintain invariants.
 */
class UcpConfiguration { // Mirrors C# public class UcpConfiguration — per-connection tuning bag
public: // All configuration fields and methods are publicly accessible

    // === Core protocol parameters ===
    // These mirror the C# public fields of the same names in Ucp.UcpConfiguration.

    int  Mss                              = 1220;          //< Maximum segment size — payload bytes per data packet (MSS, mirrors C# UcpConstants.MSS = 1220)
    int  MaxRetransmissions               = 10;            //< Max retransmissions before declaring connection lost (mirrors C# UcpConstants.MAX_RETRANSMISSIONS = 10)
    int64_t MinRtoMicros                  = 50000LL;       //< Lower bound on RTO calculation, 50 ms default (mirrors C# UcpConstants.DEFAULT_RTO_MICROS = 50000L)
    int64_t MaxRtoMicros                  = 15000000LL;    //< Upper bound on RTO calculation, 15 s default (mirrors C# UcpConstants.DEFAULT_MAX_RTO_MICROS = 15000000L)
    double RetransmitBackoffFactor        = 1.2;           //< Multiplier applied on each RTO backoff: 1.2 = +20% per timeout (mirrors C# UcpConstants.RTO_BACKOFF_FACTOR = 1.2)
    int64_t ProbeRttIntervalMicros        = 30000000LL;    //< BBR ProbeRtt entry interval, 30 s (mirrors C# UcpConstants.BBR_PROBE_RTT_INTERVAL_MICROS = 30000000L)
    int64_t ProbeRttDurationMicros        = 100000LL;      //< Minimum duration BBR stays in ProbeRtt, 100 ms (mirrors C# UcpConstants.BBR_PROBE_RTT_DURATION_MICROS = 100000L)

    // === Connection lifecycle ===
    // These match C# public fields controlling keepalive, disconnect, timers and fair-queue scheduling.

    int64_t KeepAliveIntervalMicros       = 1000000LL;     //< Interval between keep-alive sends when idle, 1 s (mirrors C# UcpConstants.KEEP_ALIVE_INTERVAL_MICROS = 1000000L)
    int64_t DisconnectTimeoutMicros       = 4000000LL;     //< Inactivity timeout before disconnecting, 4 s (mirrors C# UcpConstants.DISCONNECT_TIMEOUT_MICROS = 4000000L)
    int  TimerIntervalMilliseconds        = 1;             //< Per-connection timer tick interval, 1 ms (mirrors C# UcpConstants.TIMER_INTERVAL_MILLISECONDS = 1)
    int  FairQueueRoundMilliseconds       = 10;            //< Fair-queue scheduling round interval, 10 ms (mirrors C# UcpConstants.FAIR_QUEUE_ROUND_MILLISECONDS = 10)
    int  ServerBandwidthBytesPerSecond    = 12500000;      //< Total server bandwidth cap for fair-queue, 12.5 MB/s ≈100 Mbps (mirrors C# UcpConstants.DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND)
    int  ConnectTimeoutMilliseconds       = 5000;          //< Connection handshake timeout, 5 s (mirrors C# UcpConstants.CONNECT_TIMEOUT_MILLISECONDS = 5000)

    // === Congestion control ===
    // Mirror C# public fields for bandwidth, pacing rate, congestion window, and loss-detection flags.

    int64_t InitialBandwidthBytesPerSecond = 12500000LL;   //< Initial BBR bandwidth estimate, 12.5 MB/s (mirrors C# UcpConstants.DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND = 12500000L)
    int64_t MaxPacingRateBytesPerSecond    = 12500000LL;   //< Maximum allowed pacing rate, 12.5 MB/s (mirrors C# UcpConstants.DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND = 12500000L)
    int  MaxCongestionWindowBytes         = 64 * 1024 * 1024; //< Hard ceiling on cwnd, 64 MiB (mirrors C# UcpConstants.DEFAULT_MAX_CONGESTION_WINDOW_BYTES = 64*1024*1024)
    int  InitialCwndPackets               = 20;            //< Initial cwnd in MSS-equivalent packets, ~24 KB (mirrors C# UcpConstants.INITIAL_CWND_PACKETS = 20)
    int  RecvWindowPackets                = 16384;         //< Receive window in MSS-equivalent packets, ~20 MB (mirrors C# public int RecvWindowPackets = 16384)
    int  SendQuantumBytes                 = 1220;          //< Minimum bytes per send quantum, = MSS (mirrors C# UcpConstants.MSS = 1220)
    int  AckSackBlockLimit                = 2;             //< Max SACK blocks per ACK packet (mirrors C# UcpConstants.DEFAULT_ACK_SACK_BLOCK_LIMIT = 2)
    bool LossControlEnable                = true;          //< Whether BBR should treat loss as a congestion signal (mirrors C# public bool LossControlEnable = true)
    bool EnableDebugLog                   = false;         //< Enable verbose per-packet debug logging to stderr (mirrors C# public bool EnableDebugLog = false)
    bool EnableAggressiveSackRecovery     = true;          //< Whether to use aggressive SACK-based fast retransmit (mirrors C# internal bool EnableAggressiveSackRecovery = true)

    // === Forward Error Correction ===
    // Mirror C# public FEC fields — disabled by default (redundancy = 0.0).

    double FecRedundancy                  = 0.0;           //< FEC redundancy ratio: 0.0 = FEC disabled; 0.5 = one repair per 2 data packets (mirrors C# public double FecRedundancy = 0.0)
    int  FecGroupSize                     = 8;             //< Number of data packets grouped for FEC encoding (mirrors C# public int FecGroupSize = 8)

    // === Getters/setters with clamping ===
    // Mirror C# property accessors.  Simple fields have inline get/set;
    // computed values (ReceiveBufferSize, InitialCwndBytes) and effective
    // properties are defined out-of-line in ucp_configuration.cpp.

    int   SendBufferSize()             const { return m_send_buffer_size; } // Returns send buffer capacity in bytes — mirrors C# SendBufferSize.get => _sendBufferSize
    void  SetSendBufferSize(int v)           { m_send_buffer_size = v; } // Sets send buffer capacity — mirrors C# SendBufferSize.set => _sendBufferSize = value

    int   ReceiveBufferSize()          const; // Returns receive buffer size in bytes: RecvWindowPackets * Mss — defined out-of-line
    void  SetReceiveBufferSize(int v); // Converts user-supplied bytes to packet count with ceiling division — defined out-of-line

    uint32_t InitialCwndBytes()         const; // Returns initial CWND in bytes: InitialCwndPackets * Mss — defined out-of-line
    void  SetInitialCwndBytes(uint32_t v); // Converts user-supplied bytes to packet count with ceiling division — defined out-of-line

    int64_t MinRtoUs()                 const { return MinRtoMicros; } // Returns minimum RTO in microseconds — alias for MinRtoMicros (mirrors C# MinRtoUs.get)
    void  SetMinRtoUs(int64_t v)             { MinRtoMicros = v; } // Sets minimum RTO in microseconds — delegates to MinRtoMicros (mirrors C# MinRtoUs.set)

    int64_t MaxRtoUs()                 const { return MaxRtoMicros; } // Returns maximum RTO in microseconds — alias for MaxRtoMicros (mirrors C# MaxRtoUs.get)
    void  SetMaxRtoUs(int64_t v)             { MaxRtoMicros = v; } // Sets maximum RTO in microseconds — delegates to MaxRtoMicros (mirrors C# MaxRtoUs.set)

    double RtoBackoffFactor()          const { return RetransmitBackoffFactor; } // Returns RTO backoff factor — alias for RetransmitBackoffFactor (mirrors C# RtoBackoffFactor.get)
    void  SetRtoBackoffFactor(double v)      { RetransmitBackoffFactor = v; } // Sets RTO backoff factor — delegates to RetransmitBackoffFactor (mirrors C# RtoBackoffFactor.set)

    int64_t DelayedAckTimeoutMicros()  const { return m_delayed_ack_timeout_micros; } // Returns delayed ACK timeout in μs — mirrors C# DelayedAckTimeoutMicros.get
    void  SetDelayedAckTimeoutMicros(int64_t v) { m_delayed_ack_timeout_micros = v; } // Sets delayed ACK timeout in μs — mirrors C# DelayedAckTimeoutMicros.set

    double MaxBandwidthWastePercent()  const { return m_max_bandwidth_waste_percent; } // Returns max bandwidth waste ratio — mirrors C# MaxBandwidthWastePercent.get
    void  SetMaxBandwidthWastePercent(double v) { m_max_bandwidth_waste_percent = v; } // Sets max bandwidth waste ratio — mirrors C# MaxBandwidthWastePercent.set

    double MaxBandwidthLossPercent()   const { return m_max_bandwidth_loss_percent; } // Returns max bandwidth loss percent — mirrors C# MaxBandwidthLossPercent.get
    void  SetMaxBandwidthLossPercent(double v) { m_max_bandwidth_loss_percent = v; } // Sets max bandwidth loss percent — mirrors C# MaxBandwidthLossPercent.set

    int64_t MinPacingIntervalMicros()  const { return m_min_pacing_interval_micros; } // Returns minimum inter-packet pacing gap in μs — mirrors C# MinPacingIntervalMicros.get
    void  SetMinPacingIntervalMicros(int64_t v) { m_min_pacing_interval_micros = v; } // Sets minimum inter-packet pacing gap in μs — mirrors C# MinPacingIntervalMicros.set

    int64_t PacingBucketDurationMicros() const { return m_pacing_bucket_duration_micros; } // Returns token-bucket refill window in μs — mirrors C# PacingBucketDurationMicros.get
    void  SetPacingBucketDurationMicros(int64_t v) { m_pacing_bucket_duration_micros = v; } // Sets token-bucket refill window in μs — mirrors C# PacingBucketDurationMicros.set

    int   BbrWindowRtRounds()          const { return m_bbr_window_rt_rounds; } // Returns BBR filter window size in RTT rounds — mirrors C# BbrWindowRtRounds.get
    void  SetBbrWindowRtRounds(int v)        { m_bbr_window_rt_rounds = v; } // Sets BBR filter window size in RTT rounds — mirrors C# BbrWindowRtRounds.set

    int64_t BbrMinRttWindowMicros()    const { return ProbeRttIntervalMicros; } // Returns ProbeRTT interval — alias for ProbeRttIntervalMicros (mirrors C# BbrMinRttWindowMicros.get)
    void  SetBbrMinRttWindowMicros(int64_t v) { ProbeRttIntervalMicros = v; } // Sets ProbeRTT interval — delegates to ProbeRttIntervalMicros (mirrors C# BbrMinRttWindowMicros.set)

    // === BBR gain parameters ===
    // Each getter/setter pair mirrors a C# property backed by a private field.

    double StartupPacingGain()         const { return m_startup_pacing_gain; } // Returns BBR Startup pacing gain — mirrors C# StartupPacingGain.get
    void  SetStartupPacingGain(double v)     { m_startup_pacing_gain = v; } // Sets BBR Startup pacing gain — mirrors C# StartupPacingGain.set

    double StartupCwndGain()           const { return m_startup_cwnd_gain; } // Returns BBR Startup CWND gain — mirrors C# StartupCwndGain.get
    void  SetStartupCwndGain(double v)       { m_startup_cwnd_gain = v; } // Sets BBR Startup CWND gain — mirrors C# StartupCwndGain.set

    double DrainPacingGain()           const { return m_drain_pacing_gain; } // Returns BBR Drain pacing gain — mirrors C# DrainPacingGain.get
    void  SetDrainPacingGain(double v)       { m_drain_pacing_gain = v; } // Sets BBR Drain pacing gain — mirrors C# DrainPacingGain.set

    double ProbeBwHighGain()           const { return m_probe_bw_high_gain; } // Returns BBR ProbeBW high gain — mirrors C# ProbeBwHighGain.get
    void  SetProbeBwHighGain(double v)       { m_probe_bw_high_gain = v; } // Sets BBR ProbeBW high gain — mirrors C# ProbeBwHighGain.set

    double ProbeBwLowGain()            const { return m_probe_bw_low_gain; } // Returns BBR ProbeBW low gain — mirrors C# ProbeBwLowGain.get
    void  SetProbeBwLowGain(double v)        { m_probe_bw_low_gain = v; } // Sets BBR ProbeBW low gain — mirrors C# ProbeBwLowGain.set

    double ProbeBwCwndGain()           const { return m_probe_bw_cwnd_gain; } // Returns BBR ProbeBW CWND gain — mirrors C# ProbeBwCwndGain.get
    void  SetProbeBwCwndGain(double v)       { m_probe_bw_cwnd_gain = v; } // Sets BBR ProbeBW CWND gain — mirrors C# ProbeBwCwndGain.set

    // === Lifecycle aliases ===
    // Microsecond-precision aliases matching C# KeepAliveIntervalUs / DisconnectTimeoutUs properties.

    int64_t KeepAliveIntervalUs()      const { return KeepAliveIntervalMicros; } // Returns keep-alive interval — alias for KeepAliveIntervalMicros (mirrors C# KeepAliveIntervalUs.get)
    void  SetKeepAliveIntervalUs(int64_t v)  { KeepAliveIntervalMicros = v; } // Sets keep-alive interval — delegates to KeepAliveIntervalMicros (mirrors C# KeepAliveIntervalUs.set)

    int64_t DisconnectTimeoutUs()      const { return DisconnectTimeoutMicros; } // Returns disconnect timeout — alias for DisconnectTimeoutMicros (mirrors C# DisconnectTimeoutUs.get)
    void  SetDisconnectTimeoutUs(int64_t v)  { DisconnectTimeoutMicros = v; } // Sets disconnect timeout — delegates to DisconnectTimeoutMicros (mirrors C# DisconnectTimeoutUs.set)

    // === Effective/computed properties ===
    // These mirror C# computed properties that clamp or derive values.
    // All are defined out-of-line in ucp_configuration.cpp.

    int64_t EffectiveMinRtoMicros()    const; // Effective minimum RTO: Max(MinRtoMicros, protocol floor) — mirrors C# EffectiveMinRtoMicros.get
    int64_t EffectiveMaxRtoMicros()    const; // Effective maximum RTO: Max(effective-min, effective-max) — mirrors C# EffectiveMaxRtoMicros.get
    double  EffectiveRetransmitBackoffFactor() const; // Effective backoff factor: Max(RetransmitBackoffFactor, 1.0) — mirrors C# EffectiveRetransmitBackoffFactor.get
    double  EffectiveMaxBandwidthLossPercent() const; // Clamped loss percent to [15%, 35%] — mirrors C# EffectiveMaxBandwidthLossPercent.get

    /** @brief Maximum application payload size = MSS - 20 bytes reserved for the data-packet header.
     *  @return Usable payload capacity per data packet (1200 bytes at default MSS).
     *  Mirrors C# MaxPayloadSize => Mss - UcpConstants.DataHeaderSize. */
    int   MaxPayloadSize()             const { return Mss - 20; } // Returns MSS minus data-header overhead — mirrors C# MaxPayloadSize.get => Mss - DataHeaderSize (=1220-20=1200)

    int   MaxAckSackBlocks()           const; // Max SACK blocks fitting in one ACK packet, bounded by both physical space and configured limit — defined out-of-line
    uint32_t ReceiveWindowBytes()      const; // Advertised receive window in bytes: RecvWindowPackets * Mss — defined out-of-line, mirrors C# ReceiveWindowBytes.get
    int   InitialCongestionWindowBytes() const; // Initial CWND in bytes: Max(Mss, InitialCwndPackets * Mss) — defined out-of-line, mirrors C# InitialCongestionWindowBytes.get

    /** @brief Deep-copy this configuration.
     *  @return A new UcpConfiguration with the same field values (no shared references).
     *  Mirrors C# UcpConfiguration.Clone(). */
    UcpConfiguration Clone() const; // Creates a fresh default-constructed config then copies all fields from *this — defined out-of-line

    /** @brief Get a configuration optimized for the current platform (network type, MTU, etc.).
     *  @return A UcpConfiguration with platform-tuned defaults.
     *  Mirrors C# UcpConfiguration.GetOptimizedConfig(). */
    static UcpConfiguration GetOptimizedConfig(); // Returns a production-tuned config with optimized RTO, CWND, and loss-control settings — defined out-of-line

    /** @brief Copy all field values from this instance into @p target.
     *  @param target  Destination configuration to overwrite (must be a valid reference).
     *  Mirrors C# UcpConfiguration.CopyTo(UcpConfiguration target). */
    void CopyTo(UcpConfiguration& target) const; // Shallow-field copy of all configuration parameters — defined out-of-line

private: // Backing fields — not directly accessible; manipulated through getter/setter pairs
    int m_send_buffer_size                = 32 * 1024 * 1024;   //< Backing field for SendBufferSize, 32 MiB default (mirrors C# _sendBufferSize = 32*1024*1024)
    int64_t m_delayed_ack_timeout_micros   = 100LL;              //< Backing field for DelayedAckTimeoutMicros, 100 μs default (mirrors C# _delayedAckTimeoutMicros = 100L)
    double  m_max_bandwidth_waste_percent  = 0.25;               //< Backing field for MaxBandwidthWastePercent, 25% default (mirrors C# _maxBandwidthWastePercent = 0.25)
    double  m_max_bandwidth_loss_percent   = 25.0;               //< Backing field for MaxBandwidthLossPercent, 25% default (mirrors C# _maxBandwidthLossPercent = 25.0)
    int64_t m_min_pacing_interval_micros   = 0LL;                //< Backing field for MinPacingIntervalMicros, 0 = no minimum (mirrors C# _minPacingIntervalMicros = 0L)
    int64_t m_pacing_bucket_duration_micros = 10000LL;           //< Backing field for PacingBucketDurationMicros, 10 ms default (mirrors C# _pacingBucketDurationMicros = 10000L)
    int   m_bbr_window_rt_rounds           = 10;                 //< Backing field for BbrWindowRtRounds, 10 RTT rounds (mirrors C# _bbrWindowRtRounds = 10)
    double  m_startup_pacing_gain          = 2.89;               //< Backing field for StartupPacingGain, ≈2.89 = 2/ln(2) (mirrors C# _startupPacingGain = 2.89)
    double  m_startup_cwnd_gain            = 2.0;                //< Backing field for StartupCwndGain, 2.0× BDP (mirrors C# _startupCwndGain = 2.0)
    double  m_drain_pacing_gain            = 1.0;                //< Backing field for DrainPacingGain, 1.0× = exactly estimated rate (mirrors C# _drainPacingGain = 1.0)
    double  m_probe_bw_high_gain           = 1.35;               //< Backing field for ProbeBwHighGain, 1.35× for up-probe (mirrors C# _probeBwHighGain = 1.35)
    double  m_probe_bw_low_gain            = 0.85;               //< Backing field for ProbeBwLowGain, 0.85× for down-probe (mirrors C# _probeBwLowGain = 0.85)
    double  m_probe_bw_cwnd_gain           = 2.0;                //< Backing field for ProbeBwCwndGain, 2.0× BDP (mirrors C# _probeBwCwndGain = 2.0)
};

} // namespace ucp — closes the UCP protocol library namespace
