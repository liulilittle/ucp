#pragma once

/** @file ucp_constants.h
 *  @brief Protocol-wide constants and the SackBlock helper — mirrors C# Ucp.Internal.Constants and Ucp.PacketConstants.
 *
 *  Contains wire-format fixed sizes (header sizes, field widths), timing
 *  parameters (RTO initial/min/max), BBR tuning knobs (gain values, window
 *  sizes), pacing defaults, and limits used throughout the protocol stack.
 */

#include <cstdint>

namespace ucp {

/** @brief A single SACK (Selective ACK) block representing a contiguous range [Start, End] of received sequences. */
struct SackBlock {
    uint32_t Start;  //< First sequence number in the acknowledged range.
    uint32_t End;    //< Last sequence number in the acknowledged range.
};

/** @brief Namespace containing all compile-time constants for the UCP protocol.
 *
 *  Grouped in a namespace (rather than a class) to match the C# static-class
 *  pattern and to allow clean 'using namespace Constants;' blocks in .cpp files.
 */
namespace Constants {

// === Wire-format sizes (bytes) ===

constexpr int MSS = 1220;                       //< Maximum segment size — payload capacity per data packet.
constexpr int COMMON_HEADER_SIZE = 12;          //< Size of UcpCommonHeader: type(1) + flags(1) + connection_id(4) + timestamp(6).
constexpr int DATA_HEADER_SIZE   = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);  //< Data header without piggybacked ACK fields.
constexpr int DATA_HEADER_SIZE_WITH_ACK = DATA_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + 6; //< Data header with piggybacked ACK fields.
constexpr int ACK_FIXED_SIZE     = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + 6; //< Fixed portion of an ACK packet (excl. SACK blocks).
constexpr int SACK_BLOCK_SIZE    = sizeof(uint32_t) + sizeof(uint32_t);  //< Size of one SACK block (start + end).

// === Pacing defaults ===

constexpr int DEFAULT_PACING_WAIT_MICROS = 1000;  //< Default wait time (us) returned when tokens are insufficient.

// === Time-unit conversions ===

constexpr long long MICROS_PER_MILLI  = 1000LL;        //< Microseconds per millisecond.
constexpr long long MICROS_PER_SECOND = 1000000LL;      //< Microseconds per second.

// === RTO (Retransmission Time-Out) parameters ===

constexpr long long INITIAL_RTO_MICROS               = 100000LL;    //< Initial RTO before any RTT sample (100 ms).
constexpr long long MIN_RTO_MICROS                   = 20000LL;     //< Absolute lower bound for RTO (20 ms).
constexpr long long DEFAULT_RTO_MICROS               = 50000LL;     //< Default RTO used when configuration is absent (50 ms).
constexpr long long DEFAULT_MAX_RTO_MICROS           = 15000000LL;  //< Default upper bound for RTO (15 s).
constexpr long long MAX_RTO_MICROS                   = 60000000LL;  //< Hard maximum RTO (60 s).
constexpr int     MAX_RETRANSMISSIONS                = 10;          //< Maximum retransmissions before declaring connection lost.
constexpr double  RTO_BACKOFF_FACTOR                 = 1.2;         //< Multiplier applied on each RTO backoff event.
constexpr int     RTT_VAR_DENOM                      = 4;           //< Denominator in RTTVAR EWMA update (power-of-2 shift friendly).
constexpr int     RTT_SMOOTHING_DENOM                = 8;           //< Denominator in SRTT EWMA update.
constexpr int     RTT_SMOOTHING_PREVIOUS_WEIGHT      = 7;           //< Weight of previous SRTT in EWMA (7/8).
constexpr int     RTT_VAR_PREVIOUS_WEIGHT            = 3;           //< Weight of previous RTTVAR in EWMA (3/4).
constexpr int     RTO_GAIN_MULTIPLIER                = 4;           //< Multiplier on RTTVAR in RTO = SRTT + 4 * RTTVAR.
constexpr int     RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER = 2;           //< Max RTO after backoff = max(current*backoff, min_rto*2).

// === Buffer sizing ===

constexpr int     DEFAULT_SEND_BUFFER_BYTES              = 32 * 1024 * 1024;  //< Default send buffer size (32 MiB).
constexpr long long DEFAULT_DELAYED_ACK_TIMEOUT_MICROS   = 100LL;            //< Default interval before sending a standalone ACK (100 us).
constexpr double  DEFAULT_MAX_BANDWIDTH_WASTE_RATIO      = 0.25;             //< Max fraction of bandwidth allowed as waste in cwnd calculation.
constexpr double  DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT     = 25.0;             //< Default loss threshold for triggering aggressive cwnd reduction.
constexpr long long DEFAULT_MIN_PACING_INTERVAL_MICROS   = 0LL;              //< Minimum interval between paced sends (0 = no min).
constexpr long long DEFAULT_PACING_BUCKET_DURATION_MICROS = 10000LL;         //< Default token-bucket refill window (10 ms).

// === BBR gain constants ===

constexpr int     BBR_WINDOW_RTT_ROUNDS       = 10;   //< Number of RTTs used for max-bandwidth windowing.
constexpr double  BBR_STARTUP_PACING_GAIN     = 2.89; //< Pacing gain during BBR Startup (≈ 2.89× — 2/ln(2)).
constexpr double  BBR_STARTUP_CWND_GAIN       = 2.0;  //< Cwnd gain during BBR Startup.
constexpr double  BBR_DRAIN_PACING_GAIN       = 1.0;  //< Default pacing gain during BBR Drain phase.
constexpr double  BBR_PROBE_BW_HIGH_GAIN      = 1.35; //< High pacing gain used for 1 out of 8 ProbeBw cycles.
constexpr double  BBR_PROBE_BW_LOW_GAIN       = 0.85; //< Low pacing gain used for 7 out of 8 ProbeBw cycles.
constexpr double  BBR_PROBE_BW_CWND_GAIN      = 2.0;  //< Cwnd gain during ProbeBw to accommodate bursts.

// === BBR ProbeRtt timing ===

constexpr long long BBR_PROBE_RTT_INTERVAL_MICROS  = 30000000LL;  //< How often ProbeRtt is entered (30 s).
constexpr long long BBR_PROBE_RTT_DURATION_MICROS  = 100000LL;    //< Minimum time spent in ProbeRtt (100 ms).

// === Connection lifecycle timers ===

constexpr long long KEEP_ALIVE_INTERVAL_MICROS   = 1000000LL;  //< Interval for sending keep-alive probes (1 s).
constexpr long long DISCONNECT_TIMEOUT_MICROS    = 4000000LL;  //< Time without activity before declaring disconnect (4 s).
constexpr int  TIMER_INTERVAL_MILLISECONDS       = 1;          //< Per-connection timer tick granularity (1 ms).
constexpr int  FAIR_QUEUE_ROUND_MILLISECONDS     = 10;         //< Fair-queue round scheduling interval (10 ms).
constexpr int  CONNECT_TIMEOUT_MILLISECONDS      = 5000;       //< Connect handshake timeout (5 s).

// === Bandwidth and congestion window defaults ===

constexpr int DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND      = 12500000;   //< Default fair-queue server bandwidth cap (12.5 MB/s).
constexpr long long DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND = 12500000LL; //< Initial BBR bandwidth estimate (12.5 MB/s).
constexpr long long DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND  = 12500000LL; //< Default max pacing rate (12.5 MB/s).
constexpr int DEFAULT_MAX_CONGESTION_WINDOW_BYTES  = 64 * 1024 * 1024;       //< Default max cwnd (64 MiB).
constexpr int INITIAL_CWND_PACKETS                 = 20;                      //< Initial cwnd in MSS-equivalent packets (≈ 24 KB).
constexpr int DEFAULT_ACK_SACK_BLOCK_LIMIT         = 2;                       //< Default max SACK blocks per ACK packet.

// === BBR loss thresholds ===

constexpr double  MIN_MAX_BANDWIDTH_LOSS_PERCENT   = 15.0;  //< Minimum allowed value for MaxBandwidthLossPercent.
constexpr double  MAX_MAX_BANDWIDTH_LOSS_PERCENT   = 35.0;  //< Maximum allowed value for MaxBandwidthLossPercent.

// === Sequence-space arithmetic ===

constexpr uint32_t HALF_SEQUENCE_SPACE            = 0x80000000U;  //< Half of 2^32 — used for modulo-32 comparison (RFC 793/1323).

} // namespace Constants
} // namespace ucp
