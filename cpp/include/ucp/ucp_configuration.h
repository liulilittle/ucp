#pragma once

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

#include <algorithm>
#include <cstdint>
#include <cmath>

namespace ucp {

/** @brief Immutable-like configuration bag (mutable via setters) for a UCP connection.
 *
 *  All public fields have sensible defaults matching the C# UcpConfiguration
 *  class.  Most values are exposed directly (public fields); a few have getter/
 *  setter pairs that enforce clamping or maintain invariants.
 */
class UcpConfiguration {
public:
    // === Core protocol parameters ===

    int  Mss                              = 1220;          //< Maximum segment size — payload bytes per data packet.
    int  MaxRetransmissions               = 10;            //< Max retransmissions before declaring connection lost.
    int64_t MinRtoMicros                  = 50000LL;       //< Lower bound on RTO calculation (50 ms default).
    int64_t MaxRtoMicros                  = 15000000LL;    //< Upper bound on RTO calculation (15 s default).
    double RetransmitBackoffFactor        = 1.2;           //< Multiplier applied on each RTO backoff (1.2 = +20%).
    int64_t ProbeRttIntervalMicros        = 30000000LL;    //< BBR ProbeRtt entry interval (30 s).
    int64_t ProbeRttDurationMicros        = 100000LL;      //< Minimum duration BBR stays in ProbeRtt (100 ms).

    // === Connection lifecycle ===

    int64_t KeepAliveIntervalMicros       = 1000000LL;     //< Interval between keep-alive sends when idle (1 s).
    int64_t DisconnectTimeoutMicros       = 4000000LL;     //< Inactivity timeout before disconnecting (4 s).
    int  TimerIntervalMilliseconds        = 1;             //< Per-connection timer tick interval (1 ms).
    int  FairQueueRoundMilliseconds       = 10;            //< Fair-queue scheduling round interval (10 ms).
    int  ServerBandwidthBytesPerSecond    = 12500000;      //< Total server bandwidth cap for fair-queue (12.5 MB/s).
    int  ConnectTimeoutMilliseconds       = 5000;          //< Connection handshake timeout (5 s).

    // === Congestion control ===

    int64_t InitialBandwidthBytesPerSecond = 12500000LL;   //< Initial BBR bandwidth estimate (12.5 MB/s).
    int64_t MaxPacingRateBytesPerSecond    = 12500000LL;   //< Maximum allowed pacing rate (12.5 MB/s).
    int  MaxCongestionWindowBytes         = 64 * 1024 * 1024; //< Hard ceiling on cwnd (64 MiB).
    int  InitialCwndPackets               = 20;            //< Initial cwnd in MSS-equivalent packets (~24 KB).
    int  RecvWindowPackets                = 16384;         //< Receive window in MSS-equivalent units (~20 MB).
    int  SendQuantumBytes                 = 1220;          //< Minimum bytes per send quantum (= MSS).
    int  AckSackBlockLimit                = 2;             //< Max SACK blocks per ACK packet.
    bool LossControlEnable                = true;          //< Whether BBR should treat loss as a congestion signal.
    bool EnableDebugLog                   = false;         //< Enable verbose per-packet debug logging to stderr.
    bool EnableAggressiveSackRecovery     = true;          //< Whether to use aggressive SACK-based fast retransmit.

    // === Forward Error Correction ===

    double FecRedundancy                  = 0.0;           //< FEC redundancy ratio (0.0 = FEC disabled; 0.5 = one repair per 2 data packets).
    int  FecGroupSize                     = 8;             //< Number of data packets grouped for FEC encoding.

    // === Getters/setters with clamping ===

    int   SendBufferSize()             const { return m_send_buffer_size; }
    void  SetSendBufferSize(int v)           { m_send_buffer_size = v; }

    int   ReceiveBufferSize()          const;
    void  SetReceiveBufferSize(int v);

    uint32_t InitialCwndBytes()         const;
    void  SetInitialCwndBytes(uint32_t v);

    int64_t MinRtoUs()                 const { return MinRtoMicros; }
    void  SetMinRtoUs(int64_t v)             { MinRtoMicros = v; }

    int64_t MaxRtoUs()                 const { return MaxRtoMicros; }
    void  SetMaxRtoUs(int64_t v)             { MaxRtoMicros = v; }

    double RtoBackoffFactor()          const { return RetransmitBackoffFactor; }
    void  SetRtoBackoffFactor(double v)      { RetransmitBackoffFactor = v; }

    int64_t DelayedAckTimeoutMicros()  const { return m_delayed_ack_timeout_micros; }
    void  SetDelayedAckTimeoutMicros(int64_t v) { m_delayed_ack_timeout_micros = v; }

    double MaxBandwidthWastePercent()  const { return m_max_bandwidth_waste_percent; }
    void  SetMaxBandwidthWastePercent(double v) { m_max_bandwidth_waste_percent = v; }

    double MaxBandwidthLossPercent()   const { return m_max_bandwidth_loss_percent; }
    void  SetMaxBandwidthLossPercent(double v) { m_max_bandwidth_loss_percent = v; }

    int64_t MinPacingIntervalMicros()  const { return m_min_pacing_interval_micros; }
    void  SetMinPacingIntervalMicros(int64_t v) { m_min_pacing_interval_micros = v; }

    int64_t PacingBucketDurationMicros() const { return m_pacing_bucket_duration_micros; }
    void  SetPacingBucketDurationMicros(int64_t v) { m_pacing_bucket_duration_micros = v; }

    int   BbrWindowRtRounds()          const { return m_bbr_window_rt_rounds; }
    void  SetBbrWindowRtRounds(int v)        { m_bbr_window_rt_rounds = v; }

    int64_t BbrMinRttWindowMicros()    const { return ProbeRttIntervalMicros; }
    void  SetBbrMinRttWindowMicros(int64_t v) { ProbeRttIntervalMicros = v; }

    // === BBR gain parameters ===

    double StartupPacingGain()         const { return m_startup_pacing_gain; }
    void  SetStartupPacingGain(double v)     { m_startup_pacing_gain = v; }

    double StartupCwndGain()           const { return m_startup_cwnd_gain; }
    void  SetStartupCwndGain(double v)       { m_startup_cwnd_gain = v; }

    double DrainPacingGain()           const { return m_drain_pacing_gain; }
    void  SetDrainPacingGain(double v)       { m_drain_pacing_gain = v; }

    double ProbeBwHighGain()           const { return m_probe_bw_high_gain; }
    void  SetProbeBwHighGain(double v)       { m_probe_bw_high_gain = v; }

    double ProbeBwLowGain()            const { return m_probe_bw_low_gain; }
    void  SetProbeBwLowGain(double v)        { m_probe_bw_low_gain = v; }

    double ProbeBwCwndGain()           const { return m_probe_bw_cwnd_gain; }
    void  SetProbeBwCwndGain(double v)       { m_probe_bw_cwnd_gain = v; }

    // === Lifecycle aliases ===

    int64_t KeepAliveIntervalUs()      const { return KeepAliveIntervalMicros; }
    void  SetKeepAliveIntervalUs(int64_t v)  { KeepAliveIntervalMicros = v; }

    int64_t DisconnectTimeoutUs()      const { return DisconnectTimeoutMicros; }
    void  SetDisconnectTimeoutUs(int64_t v)  { DisconnectTimeoutMicros = v; }

    // === Effective/computed properties ===

    int64_t EffectiveMinRtoMicros()    const;
    int64_t EffectiveMaxRtoMicros()    const;
    double  EffectiveRetransmitBackoffFactor() const;
    double  EffectiveMaxBandwidthLossPercent() const;

    /** @brief Maximum application payload size = MSS - 20 bytes reserved for future extensions.
     *  @return Usable payload capacity per data packet. */
    int   MaxPayloadSize()             const { return Mss - 20; }

    int   MaxAckSackBlocks()           const;
    uint32_t ReceiveWindowBytes()      const;
    int   InitialCongestionWindowBytes() const;

    /** @brief Deep-copy this configuration.
     *  @return A new UcpConfiguration with the same field values. */
    UcpConfiguration Clone() const;

    /** @brief Get a configuration optimized for the current platform (network type, MTU, etc.).
     *  @return A UcpConfiguration with platform-tuned defaults. */
    static UcpConfiguration GetOptimizedConfig();

    /** @brief Copy all field values from this instance into @p target.
     *  @param target  Destination configuration to overwrite. */
    void CopyTo(UcpConfiguration& target) const;

private:
    int m_send_buffer_size                = 32 * 1024 * 1024;   //< Backing field for SendBufferSize (32 MiB default).
    int64_t m_delayed_ack_timeout_micros   = 100LL;              //< Backing field for DelayedAckTimeoutMicros (100 us default).
    double  m_max_bandwidth_waste_percent  = 0.25;               //< Backing field for MaxBandwidthWastePercent (25% default).
    double  m_max_bandwidth_loss_percent   = 25.0;               //< Backing field for MaxBandwidthLossPercent (25% default).
    int64_t m_min_pacing_interval_micros   = 0LL;                //< Backing field for MinPacingIntervalMicros (0 = no minimum).
    int64_t m_pacing_bucket_duration_micros = 10000LL;           //< Backing field for PacingBucketDurationMicros (10 ms default).
    int   m_bbr_window_rt_rounds           = 10;                 //< Backing field for BbrWindowRtRounds.
    double  m_startup_pacing_gain          = 2.89;               //< Backing field for StartupPacingGain (≈ 2.89).
    double  m_startup_cwnd_gain            = 2.0;                //< Backing field for StartupCwndGain.
    double  m_drain_pacing_gain            = 1.0;                //< Backing field for DrainPacingGain.
    double  m_probe_bw_high_gain           = 1.35;               //< Backing field for ProbeBwHighGain.
    double  m_probe_bw_low_gain            = 0.85;               //< Backing field for ProbeBwLowGain.
    double  m_probe_bw_cwnd_gain           = 2.0;                //< Backing field for ProbeBwCwndGain.
};

} // namespace ucp
