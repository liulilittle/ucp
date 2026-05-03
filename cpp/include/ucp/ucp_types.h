#pragma once

/** @file ucp_types.h
 *  @brief Common data types for UCP endpoints, diagnostics, and transfer reports.
 *
 *  Defines the Endpoint abstraction (address + port), a lightweight public
 *  UcpTransferReport, and the richer UcpConnectionDiagnostics struct used
 *  internally for connection health snapshots.  Mirrors types scattered across
 *  C# Ucp.Types and Ucp.TransferReport.
 */

#include <cstdint>
#include <string>
#include <vector>

namespace ucp {

/** @brief Network endpoint consisting of an IP address and a UDP port. */
struct Endpoint {
    std::string address;  //< IPv4 address string (e.g. "127.0.0.1").
    uint16_t port;        //< UDP port number (e.g. 9000).

    Endpoint() : port(0) {}
    Endpoint(const std::string& addr, uint16_t p) : address(addr), port(p) {}

    /** @brief Parse an "address:port" string into an Endpoint.
     *  @param str  String in "ip:port" or "host:port" format.
     *  @return Parsed Endpoint; port defaults to 0 if not present. */
    static Endpoint Parse(const std::string& str);

    /** @brief Serialize this endpoint to "address:port".
     *  @return String representation. */
    std::string ToString() const;
};

/** @brief Lightweight per-connection statistics snapshot (public API). */
struct UcpTransferReport {
    int64_t BytesSent = 0;               //< Total bytes transmitted.
    int64_t BytesReceived = 0;           //< Total bytes received.
    int32_t DataPacketsSent = 0;         //< Unique data packets sent.
    int32_t RetransmittedPackets = 0;    //< Data packets retransmitted.
    int32_t AckPacketsSent = 0;          //< Standalone ACK packets sent.
    int32_t NakPacketsSent = 0;          //< NAK packets sent.
    int32_t FastRetransmissions = 0;     //< Fast retransmit events.
    int32_t TimeoutRetransmissions = 0;  //< RTO-based retransmissions.
    int64_t LastRttMicros = 0;           //< Most recent RTT sample (us).
    std::vector<int64_t> RttSamplesMicros;  //< Recent RTT samples.
    int32_t CongestionWindowBytes = 0;    //< BBR cwnd in bytes.
    double PacingRateBytesPerSecond = 0.0; //< BBR pacing rate.
    double EstimatedLossPercent = 0.0;     //< Estimated loss % (0..100).
    uint32_t RemoteWindowBytes = 0;       //< Peer's receive window.

    /** @brief Compute the retransmission ratio.
     *  @return Ratio of retransmitted to unique sent packets; 0 if none sent. */
    double RetransmissionRatio() const {
        return DataPacketsSent == 0 ? 0.0
            : static_cast<double>(RetransmittedPackets) / DataPacketsSent;
    }
};

/** @brief Detailed per-connection diagnostics snapshot for internal monitoring. */
struct UcpConnectionDiagnostics {
    int State = 0;                       //< UcpConnectionState as int.
    int32_t FlightBytes = 0;             //< Bytes currently in flight (sent, not acked).
    uint32_t RemoteWindowBytes = 0;      //< Peer's advertised receive window.
    int32_t BufferedReceiveBytes = 0;    //< Bytes in receive queue waiting for app consumption.
    int64_t BytesSent = 0;               //< Total bytes sent.
    int64_t BytesReceived = 0;           //< Total bytes received.
    int32_t SentDataPackets = 0;         //< Unique data packets sent.
    int32_t RetransmittedPackets = 0;    //< Retransmitted data packets.
    int32_t SentAckPackets = 0;          //< ACK packets sent.
    int32_t SentNakPackets = 0;          //< NAK packets sent.
    int32_t SentRstPackets = 0;          //< RST packets sent.
    int32_t FastRetransmissions = 0;     //< Fast retransmit events.
    int32_t TimeoutRetransmissions = 0;  //< RTO retransmissions.
    int32_t CongestionWindowBytes = 0;   //< BBR cwnd (bytes).
    double PacingRateBytesPerSecond = 0.0; //< BBR pacing rate.
    double EstimatedLossPercent = 0.0;    //< Estimated loss %.
    int64_t LastRttMicros = 0;           //< Most recent RTT (us).
    std::vector<int64_t> RttSamplesMicros; //< Recent RTT samples.
    bool ReceivedReset = false;          //< Whether peer sent an RST.
    int32_t CurrentNetworkClass = 0;     //< Current BBR NetworkClass classification.
};

} // namespace ucp
