#pragma once //< Header guard — prevents multiple inclusion in a single translation unit.

/** @file ucp_constants.h
 *  @brief Protocol-wide constants and the SackBlock helper — mirrors C# Ucp.Internal.Constants and Ucp.PacketConstants.
 *
 *  Contains wire-format fixed sizes (header sizes, field widths), timing
 *  parameters (RTO initial/min/max), BBR tuning knobs (gain values, window
 *  sizes), pacing defaults, and limits used throughout the protocol stack.
 */

#include <cstdint> //< Provides uint32_t, uint16_t, and other fixed-width integer types used by SackBlock and constant expressions.

namespace ucp { //< Top-level namespace for the Universal Communication Protocol (UCP) library.

/** @brief A single SACK (Selective ACK) block representing a contiguous range [Start, End] of received sequences.
 *
 *  Mirrors the C# SackBlock struct in UcpPackets.cs (two public uint fields: Start, End).
 *  Each SACK block encodes an inclusive range of acknowledged sequence numbers,
 *  matching QUIC's SACK frame encoding.  Both Start and End are 32-bit unsigned
 *  integers — sequence numbers wrap modulo 2^32 (RFC 793/1323 semantics).
 */
struct SackBlock {
    uint32_t Start;  //< First sequence number in the acknowledged range (inclusive).  Enables the sender to identify which segments arrived out-of-order.
    uint32_t End;    //< Last sequence number in the acknowledged range (inclusive).  Together with Start, delimits a contiguous block of successfully received data.
}; //< End of SackBlock struct definition — used by ACK/NAK packets, SACK generation, and loss detection.

/** @brief Namespace containing all compile-time constants for the UCP protocol.
 *
 *  Grouped in a namespace (rather than a class) to match the C# static-class
 *  pattern and to allow clean 'using namespace Constants;' blocks in .cpp files.
 */
namespace Constants {

// === Wire-format sizes (bytes) ===
// Every constant in this section defines the encoded byte count of a protocol field or packet header.
// These values are derived from the fixed-width types on the wire, not from platform-specific sizeof().

constexpr int MSS = 1220;                       //< Maximum segment size — payload capacity per data packet (bytes).  1220 avoids IPv6/IPv4 fragmentation on all common MTU sizes (1280–1500).
constexpr int COMMON_HEADER_SIZE = 12;          //< Size of UcpCommonHeader: type(1) + flags(1) + connection_id(4) + timestamp(6) = 12 bytes.  Every UCP packet begins with this fixed prefix.
constexpr int DATA_HEADER_SIZE   = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);  //< Data header without piggybacked ACK fields: 12 + 4(seq) + 2(fragTotal) + 2(fragIndex) = 20 bytes.  Subtracted from MSS to compute per-packet payload budget.
constexpr int DATA_HEADER_SIZE_WITH_ACK = DATA_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + 6; //< Data header with piggybacked ACK fields: 20 + 4(ackNum) + 2(sackCount) + 4(window) + 6(echoTs) = 36 bytes.  Used when the HasAckNumber flag is set.
constexpr int ACK_FIXED_SIZE     = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + 6; //< Fixed portion of an ACK packet (excl. SACK blocks): 12 + 4(ackNum) + 2(sackCount) + 4(window) + 6(echoTs) = 28 bytes.  Variable-length SACK blocks are appended after this.
constexpr int SACK_BLOCK_SIZE    = sizeof(uint32_t) + sizeof(uint32_t);  //< Size of one SACK block on the wire: 4 bytes Start + 4 bytes End = 8 bytes.  Used as the stride when iterating over SACK blocks during parsing.

// === Pacing defaults ===
// Pacing prevents line-rate bursts by spacing packets evenly over time.
// These constants govern the token-bucket pacer's behavior when no per-connection rate estimate is available.

constexpr int DEFAULT_PACING_WAIT_MICROS = 1000;  //< Default wait time (1 ms = 1000 µs) returned when the token bucket has insufficient credit.  Safe floor that prevents unbounded bursts on unknown paths.

// === Time-unit conversions ===
// UCP uses microseconds internally because RTTs on LAN paths can be sub-millisecond,
// BBR pacing intervals are often 100–1000 µs, and the wire-format 48-bit timestamp
// stores µs since epoch.  These constants prevent accidental scale-factor bugs.

constexpr long long MICROS_PER_MILLI  = 1000LL;        //< Microseconds per millisecond (10^3).  Standard SI conversion — used when translating ms-based timers to the µs domain.
constexpr long long MICROS_PER_SECOND = 1000000LL;      //< Microseconds per second (10^6).  Denominator when converting bytes-per-second pacing rates to bytes-per-µs inter-packet gaps.

// === RTO (Retransmission Time-Out) parameters ===
// RFC 6298-style RTO computation with UCP-specific tuning for modern low-latency paths.
// RTO = SRTT + K * RTTVAR (K = 4).  Backoff multiplies RTO by 1.2 per timeout (gentler than TCP's 2×).

constexpr long long INITIAL_RTO_MICROS               = 100000LL;    //< Initial RTO before any RTT sample arrives (100 ms).  Covers most WAN paths including trans-Pacific (~80 ms) without premature SYN retransmission.
constexpr long long MIN_RTO_MICROS                   = 20000LL;     //< Absolute lower bound for RTO (20 ms).  UCP can use a lower floor than TCP's 200 ms because NAK-based loss detection recovers most losses in <5 ms.
constexpr long long DEFAULT_RTO_MICROS               = 50000LL;     //< Default RTO when configuration provides no explicit value (50 ms).  Long enough to ride through transient WiFi/4G jitter bursts.
constexpr long long DEFAULT_MAX_RTO_MICROS           = 15000000LL;  //< Default upper bound for the computed RTO during normal operation (15 s).  Paths that exceed this are likely dead, not merely delayed.
constexpr long long MAX_RTO_MICROS                   = 60000000LL;  //< Hard maximum RTO (60 s).  Catch-all for extreme satellite links (GEO at ~600 ms RTT).  After 60 s without progress, the connection is declared dead unconditionally.
constexpr int     MAX_RETRANSMISSIONS                = 10;          //< Maximum consecutive RTO timeouts before declaring the connection lost.  With 1.2× backoff, 10 timeouts span roughly 2–3 seconds total.
constexpr double  RTO_BACKOFF_FACTOR                 = 1.2;         //< Multiplier applied on each RTO backoff event.  1.2× per timeout is gentler than TCP's 2× — NAK handles most losses, so the RTO is a last resort.
constexpr int     RTT_VAR_DENOM                      = 4;           //< Denominator in RTTVAR EWMA update (β = 1/4 per RFC 6298).  RTTVAR incorporates 25% of each new deviation sample.
constexpr int     RTT_SMOOTHING_DENOM                = 8;           //< Denominator in SRTT EWMA update (α = 1/8 per RFC 6298).  SRTT incorporates 12.5% of each new RTT sample.
constexpr int     RTT_SMOOTHING_PREVIOUS_WEIGHT      = 7;           //< Weight of previous SRTT in EWMA: (1 − α) = 7/8.  Multiplied against historical SRTT before blending the new sample.
constexpr int     RTT_VAR_PREVIOUS_WEIGHT            = 3;           //< Weight of previous RTTVAR in EWMA: (1 − β) = 3/4.  Multiplied against historical RTTVAR before blending the deviation.
constexpr int     RTO_GAIN_MULTIPLIER                = 4;           //< Multiplier K in RTO = SRTT + K × RTTVAR.  RFC 6298 specifies K = 4, providing a conservative RTO that NAK-based recovery supplements.
constexpr int     RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER = 2;           //< Max RTO after backoff = max(current × 1.2, MIN_RTO × 2).  Prevents RTO from collapsing to near-zero on stable paths and then spiking unreasonably after one loss.

// === Buffer sizing ===
// These constants control per-connection memory allocation, ACK timing, and bandwidth accounting.

constexpr int     DEFAULT_SEND_BUFFER_BYTES              = 32 * 1024 * 1024;  //< Default send buffer capacity (32 MiB).  Large enough for 10 Gbps at typical WAN RTTs without blocking the application.
constexpr long long DEFAULT_DELAYED_ACK_TIMEOUT_MICROS   = 100LL;            //< Default interval before sending a standalone ACK when no outbound data is queued (100 µs).  Piggybacked ACKs eliminate most standalone ACK overhead.
constexpr double  DEFAULT_MAX_BANDWIDTH_WASTE_RATIO      = 0.25;             //< Max fraction of total throughput allowed as retransmission waste (25%).  Caps how much link capacity is "wasted" before the sender throttles.
constexpr double  DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT     = 25.0;             //< Default loss threshold for triggering aggressive cwnd reduction (25%).  Above this, the sender interprets loss as congestion and reduces pacing.
constexpr long long DEFAULT_MIN_PACING_INTERVAL_MICROS   = 0LL;              //< Minimum interval between paced sends (0 µs = no floor).  Allows sub-µs gaps at 10 Gbps rates without capping throughput.
constexpr long long DEFAULT_PACING_BUCKET_DURATION_MICROS = 10000LL;         //< Default token-bucket refill window (10 ms).  Long enough to smooth bursts at WAN rates, short enough to prevent seconds-long bursts overflowing router buffers.

// === BBR gain constants ===
// BBR (Bottleneck Bandwidth and Round-trip propagation time) congestion control parameters.
// BBR models the path as a pipe and paces at the estimated bottleneck bandwidth.
// Gains are multipliers applied to the estimated bandwidth or BDP to produce pacing rate and cwnd.

constexpr int     BBR_WINDOW_RTT_ROUNDS       = 10;   //< Number of RTT rounds used for the max-bandwidth filter window.  BBR keeps a max-filter over the last 10 delivery-rate rounds to smooth out transient spikes.
constexpr double  BBR_STARTUP_PACING_GAIN     = 2.89; //< Pacing gain during BBR Startup phase (2/ln(2) ≈ 2.885, rounded to 2.89).  The sender paces at 2.89× estimated bandwidth to rapidly fill the pipe.
constexpr double  BBR_STARTUP_CWND_GAIN       = 2.0;  //< Cwnd gain during BBR Startup.  Inflight cap = 2.0 × BDP — provides enough headroom for the pacing gain to take effect without cwnd being the bottleneck.
constexpr double  BBR_DRAIN_PACING_GAIN       = 1.0;  //< Pacing gain during BBR Drain phase.  Paces at exactly 1.0× estimated bandwidth to drain the inflated queue created during Startup.
constexpr double  BBR_PROBE_BW_HIGH_GAIN      = 1.35; //< High pacing gain in ProbeBw phase — used for 1 out of every 8 ProbeBw cycles.  35% above estimated bandwidth probes for newly available capacity.
constexpr double  BBR_PROBE_BW_LOW_GAIN       = 0.85; //< Low pacing gain in ProbeBw phase — used for 7 out of every 8 ProbeBw cycles.  15% below estimated bandwidth drains any accumulated standing queue.
constexpr double  BBR_PROBE_BW_CWND_GAIN      = 2.0;  //< Cwnd gain during ProbeBw.  Inflight cap = 2.0 × BDP — same headroom as Startup for consistent behavior across phases.

// === BBR ProbeRtt timing ===
// ProbeRtt periodically (every 30 s) reduces inflight to re-measure the true minimum RTT.
// This prevents the RTT estimate from drifting upward due to persistent queuing.

constexpr long long BBR_PROBE_RTT_INTERVAL_MICROS  = 30000000LL;  //< Minimum interval between ProbeRtt entries (30 s).  Matches QUIC's ProbeRTT interval — long enough that the throughput impact amortizes to <1%.
constexpr long long BBR_PROBE_RTT_DURATION_MICROS  = 100000LL;    //< Minimum time the sender stays in ProbeRtt mode (100 ms).  Ensures at least one clean RTT sample is collected even on sub-millisecond paths.

// === Connection lifecycle timers ===
// Timeout and scheduling intervals that govern when keep-alives fire, when idle connections are torn down,
// and at what granularity the event loop ticks.

constexpr long long KEEP_ALIVE_INTERVAL_MICROS   = 1000000LL;  //< Interval between keep-alive probes (1 s = 1,000,000 µs).  Keeps NAT/stateful-firewall UDP bindings from expiring (typical timeout is 30–120 s).
constexpr long long DISCONNECT_TIMEOUT_MICROS    = 4000000LL;  //< Time without any received packet before declaring the connection dead (4 s).  Much shorter than TCP's keep-alive — UCP targets real-time use cases.
constexpr int  TIMER_INTERVAL_MILLISECONDS       = 1;          //< Per-connection timer tick granularity (1 ms).  Aggressive compared to TCP stacks (10–200 ms) — needed for µs-precision pacing and delayed-ACK timers.
constexpr int  FAIR_QUEUE_ROUND_MILLISECONDS     = 10;         //< Fair-queue round scheduling interval (10 ms).  Multiple connections share bandwidth via credits distributed every 10 ms.
constexpr int  CONNECT_TIMEOUT_MILLISECONDS      = 5000;       //< Connect handshake timeout (5 s = 5000 ms).  The SYN/SYN-ACK handshake must complete within this window; allows ~5 retries with 1.2× backoff.

// === Bandwidth and congestion window defaults ===
// Initial estimates and caps for bandwidth, pacing rate, congestion window, and SACK reporting.

constexpr int DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND      = 12500000;   //< Default fair-queue server bandwidth cap (12.5 MB/s = 100 Mbps).  Conservative default; individual connections share this pool.
constexpr long long DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND = 12500000LL; //< Initial BBR bandwidth estimate (12.5 MB/s).  Starts at the server bandwidth cap; BBR adjusts from this baseline.
constexpr long long DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND  = 12500000LL; //< Default max pacing rate (12.5 MB/s).  The pacer will not exceed this rate unless BBR discovers more bandwidth.
constexpr int DEFAULT_MAX_CONGESTION_WINDOW_BYTES  = 64 * 1024 * 1024;       //< Default max cwnd (64 MiB = 67,108,864 bytes).  Hard cap on bytes in flight for any single connection — covers all practical BDPs at sub-10 Gbps.
constexpr int INITIAL_CWND_PACKETS                 = 20;                      //< Initial cwnd in MSS-equivalent packets (20 packets × 1220 bytes ≈ 24 KB).  More aggressive than TCP's IW10, but BBR pacing prevents line-rate bursts.
constexpr int DEFAULT_ACK_SACK_BLOCK_LIMIT         = 2;                       //< Default max SACK blocks per ACK packet (2 blocks).  Matches QUIC's default — sufficient for most loss patterns (one hole being filled plus one opening).

// === BBR loss thresholds ===
// Bounds on the MaxBandwidthLossPercent configuration parameter, which controls how much loss
// the sender tolerates before reducing pacing.

constexpr double  MIN_MAX_BANDWIDTH_LOSS_PERCENT   = 15.0;  //< Minimum allowed value for MaxBandwidthLossPercent (15%).  Below this, the sender would throttle too aggressively on paths with routine random loss (Wi-Fi, 4G).
constexpr double  MAX_MAX_BANDWIDTH_LOSS_PERCENT   = 35.0;  //< Maximum allowed value for MaxBandwidthLossPercent (35%).  Above this, the sender would tolerate loss rates where throughput collapses regardless.

// === Sequence-space arithmetic ===
// 32-bit sequence numbers wrap modulo 2^32.  The half-space constant enables unambiguous comparison
// per RFC 793/1323: any distance less than half the sequence space is considered "forward."

constexpr uint32_t HALF_SEQUENCE_SPACE            = 0x80000000U;  //< Half of 2^32 (2^31 = 2,147,483,648).  Used by UcpSequenceComparer for modulo-32 sequence comparison — distances < 0x80000000 are considered in the forward direction.

} // namespace Constants — end of all compile-time constant definitions.

} // namespace ucp — end of the top-level UCP namespace.
