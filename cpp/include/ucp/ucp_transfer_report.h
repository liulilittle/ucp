#pragma once

/** @file ucp_transfer_report.h
 *  @brief Connection-level transfer statistics — mirrors C# Ucp.TransferReport.
 *
 *  Snapshot of per-connection counters returned by UcpConnection::GetReport().
 *  Provides applications with visibility into bytes sent/received, packet
 *  counts, retransmission ratios, congestion window size, pacing rate, and
 *  estimated loss percentage.  Subset of the richer UcpConnectionDiagnostics.
 */

#include <cstdint>
#include <vector>

namespace ucp {

/** @brief Public transfer statistics for a single UCP connection. */
struct UcpTransferReport {
    int64_t BytesSent              = 0;  //< Total application payload bytes sent.
    int64_t BytesReceived          = 0;  //< Total application payload bytes received.
    int     DataPacketsSent        = 0;  //< Number of unique data packets transmitted (excludes retransmits).
    int     RetransmittedPackets   = 0;  //< Number of data packets retransmitted (any reason: RTO, SACK, NAK, DUPACK).
    int     AckPacketsSent         = 0;  //< Standalone ACK packets sent.
    int     NakPacketsSent         = 0;  //< NAK (negative acknowledgement) packets sent.
    int     FastRetransmissions    = 0;  //< Packets retransmitted via fast retransmit (DUPACK or SACK hole).
    int     TimeoutRetransmissions = 0;  //< Packets retransmitted after RTO expiration.
    int64_t LastRttMicros          = 0;  //< Most recent measured RTT sample (microseconds).
    std::vector<int64_t> RttSamplesMicros;  //< Collection of recent RTT samples (ring buffer, max 256).
    int     CongestionWindowBytes     = 0;  //< BBR congestion window in bytes at the time of the snapshot.
    double  PacingRateBytesPerSecond  = 0.0; //< BBR pacing rate in bytes/second at snapshot time.
    double  EstimatedLossPercent      = 0.0; //< BBR estimated loss percentage (0..100).
    uint32_t RemoteWindowBytes        = 0;   //< Peer's advertised receive window in bytes.

    /** @brief Ratio of retransmitted data packets to total unique data packets sent.
     *  @return RetransmissionRatio in [0.0 .. 1.0]; 0 if no data packets have been sent. */
    double RetransmissionRatio() const {
        return DataPacketsSent == 0 ? 0.0 : static_cast<double>(RetransmittedPackets) / static_cast<double>(DataPacketsSent);
    }
};

} // namespace ucp
