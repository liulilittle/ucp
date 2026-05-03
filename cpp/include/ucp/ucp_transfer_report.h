#pragma once  //< Include guard: ensures this header is processed only once per translation unit.

/** @file ucp_transfer_report.h
 *  @brief Connection-level transfer statistics — mirrors C# Ucp.UcpTransferReport exactly.
 *
 *  Snapshot of per-connection counters returned by UcpConnection::GetReport().
 *  Provides applications with visibility into bytes sent/received, packet
 *  counts, retransmission ratios, congestion window size, pacing rate, and
 *  estimated loss percentage.  Subset of the richer UcpConnectionDiagnostics.
 */

#include <cstdint>            //< Standard fixed-width integer types: int32_t, int64_t, uint32_t, etc.
#include "ucp/ucp_vector.h"   //< Custom ucp::vector<T> replacement for std::vector<T>.

namespace ucp {  //< Root namespace for the UCP reliable-transport protocol library.

/** @brief Public transfer statistics for a single UCP connection.
 *
 *  Field names, types, and default values match C# Ucp.UcpTransferReport
 *  exactly.  Populated periodically during connection operation and served
 *  as the public-facing diagnostics output (e.g. for throughput benchmarks,
 *  loss analysis, and congestion-control tuning). */
struct UcpTransferReport {  //< Diagnostics snapshot aggregating connection statistics for external reporting.
    int64_t BytesSent              = 0;  //< Cumulative application payload bytes pushed into the send pipeline.
    int64_t BytesReceived          = 0;  //< Cumulative application payload bytes successfully delivered to the receiver.
    int32_t DataPacketsSent        = 0;  //< Count of unique data segments transmitted at least once (excludes retransmits).
    int32_t RetransmittedPackets   = 0;  //< Count of data packets retransmitted for any reason (RTO, SACK, NAK, DUPACK).
    int32_t AckPacketsSent         = 0;  //< Cumulative standalone ACK packets emitted by the connection.
    int32_t NakPacketsSent         = 0;  //< NAK (negative acknowledgement) packets sent to trigger fast retransmission.
    int32_t FastRetransmissions    = 0;  //< Packets retransmitted via fast retransmit (DUPACK or SACK hole), before RTO.
    int32_t TimeoutRetransmissions = 0;  //< Packets retransmitted after the retransmission timer (RTO) expired.
    int64_t LastRttMicros          = 0;  //< Most recent round-trip-time measurement in microseconds.
    ucp::vector<int64_t> RttSamplesMicros;  //< Recent RTT samples for latency diagnostics and trend analysis.
    int32_t CongestionWindowBytes      = 0;  //< BBR congestion window in bytes at the time of the snapshot.
    double  PacingRateBytesPerSecond   = 0.0; //< BBR pacing rate in bytes/second at snapshot time.
    double  EstimatedLossPercent       = 0.0; //< BBR estimated loss percentage on a 0..100 scale.
    uint32_t RemoteWindowBytes         = 0;   //< Peer's advertised receive window in bytes for flow-control enforcement.

    /** @brief Ratio of retransmitted data packets to total unique data packets sent.
     *  @return RetransmissionRatio in [0.0 .. 1.0]; 0.0 if no data packets have been sent. */
    double RetransmissionRatio() const {  //< Public property-style accessor matching C# getter.
        return DataPacketsSent == 0 ? 0.0  //< Guard against division by zero; return 0 if nothing was sent.
            : static_cast<double>(RetransmittedPackets) / static_cast<double>(DataPacketsSent);  //< Compute retransmission overhead ratio.
    }
};

} // namespace ucp  //< Close the ucp namespace scope.
