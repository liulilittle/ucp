#pragma once  //< Include guard: ensures this header is processed only once per translation unit.

/** @file ucp_types.h
 *  @brief Common data types for UCP endpoints, diagnostics, and transfer reports.
 *
 *  Defines the Endpoint abstraction (address + port), a lightweight public
 *  UcpTransferReport matching C# Ucp.UcpTransferReport field-for-field, and the
 *  richer UcpConnectionDiagnostics struct used internally for connection health
 *  snapshots.  Mirrors types scattered across C# Ucp.Types and Ucp.TransferReport.
 */

#include <cstdint>            //< Standard fixed-width integer types: int32_t, int64_t, uint32_t, etc.
#include "ucp/ucp_vector.h"   //< Custom ucp::vector<T> replacement for std::vector<T>.
#include "ucp/ucp_memory.h"   //< Custom ucp::string and memory allocation utilities.

namespace ucp {  //< Root namespace for the UCP reliable-transport protocol library.

/** @brief Network endpoint consisting of an IP address and a UDP port. */
struct Endpoint {  //< Lightweight value-type representing a remote host:port pair.
    ucp::string address;  //< IPv4 address string (e.g. "127.0.0.1").
    uint16_t port;        //< UDP port number (e.g. 9000).

    Endpoint() : port(0) {}  //< Default constructor: empty address, port zero.
    Endpoint(const ucp::string& addr, uint16_t p) : address(addr), port(p) {}  //< Parameterized constructor: binds address and port.

    /** @brief Parse an "address:port" string into an Endpoint.
     *  @param str  String in "ip:port" or "host:port" format.
     *  @return Parsed Endpoint; port defaults to 0 if not present. */
    static Endpoint Parse(const ucp::string& str);  //< Factory method: parses "127.0.0.1:9000" into an Endpoint.

    /** @brief Serialize this endpoint to "address:port".
     *  @return String representation. */
    ucp::string ToString() const;  //< Formats as "address:port" string for logging and display.
};

/** @brief Lightweight per-connection statistics snapshot matching C# Ucp.UcpTransferReport exactly.
 *
 *  Field names, types, and default values mirror the C# public API.
 *  Provides applications with visibility into bytes sent/received, packet
 *  counts, retransmission ratios, congestion window size, pacing rate,
 *  estimated loss percentage, and remote window size. */
struct UcpTransferReport {  //< Public transfer statistics for a single UCP connection.
    int64_t BytesSent = 0;              //< Cumulative application payload bytes pushed into the send pipeline.
    int64_t BytesReceived = 0;          //< Cumulative application payload bytes successfully delivered to the receiver.
    int32_t DataPacketsSent = 0;        //< Count of unique data segments transmitted at least once (excludes retransmits).
    int32_t RetransmittedPackets = 0;   //< Count of data packets retransmitted for any reason (RTO, SACK, NAK, DUPACK).
    int32_t AckPacketsSent = 0;         //< Cumulative standalone ACK packets emitted by the connection.
    int32_t NakPacketsSent = 0;         //< NAK (negative acknowledgement) packets sent to trigger fast retransmission.
    int32_t FastRetransmissions = 0;    //< Packets retransmitted via fast retransmit (DUPACK or SACK hole), before RTO.
    int32_t TimeoutRetransmissions = 0; //< Packets retransmitted after the retransmission timer (RTO) expired.
    int64_t LastRttMicros = 0;          //< Most recent round-trip-time measurement in microseconds.
    ucp::vector<int64_t> RttSamplesMicros; //< Recent RTT samples for latency diagnostics and trend analysis.
    int32_t CongestionWindowBytes = 0;  //< BBR congestion window in bytes at the time of the snapshot.
    double PacingRateBytesPerSecond = 0.0;  //< BBR pacing rate in bytes/second at snapshot time.
    double EstimatedLossPercent = 0.0;      //< BBR estimated loss percentage on a 0..100 scale.
    uint32_t RemoteWindowBytes = 0;         //< Peer's advertised receive window in bytes for flow-control enforcement.

    /** @brief Compute the retransmission ratio.
     *  @return Ratio of retransmitted to unique sent packets; 0.0 if no data packets have been sent. */
    double RetransmissionRatio() const {  //< Public property-style accessor matching C# getter.
        return DataPacketsSent == 0 ? 0.0  //< Guard against division by zero; return 0 if nothing was sent.
            : static_cast<double>(RetransmittedPackets) / static_cast<double>(DataPacketsSent);  //< Compute retransmission overhead ratio.
    }
};

/** @brief Detailed per-connection diagnostics snapshot for internal monitoring.
 *
 *  Extends UcpTransferReport with additional fields used by the engine
 *  and diagnostic tools: flight size, buffered receive bytes, RST counters,
 *  connection state, BBR network class, and the ReceivedReset flag. */
struct UcpConnectionDiagnostics {  //< Internal diagnostics struct consumed by monitoring and logging subsystems.
    int32_t State = 0;                  //< Current connection state cast to int (see UcpConnectionState enum).
    int32_t FlightBytes = 0;            //< Bytes currently in flight (sent but not yet acknowledged by the peer).
    uint32_t RemoteWindowBytes = 0;     //< Peer's advertised receive window in bytes.
    int32_t BufferedReceiveBytes = 0;   //< Bytes in the receive queue waiting for application consumption.
    int64_t BytesSent = 0;              //< Total application payload bytes pushed into the send pipeline.
    int64_t BytesReceived = 0;          //< Total application payload bytes delivered to the receiver.
    int32_t SentDataPackets = 0;        //< Unique data packets transmitted at least once.
    int32_t RetransmittedPackets = 0;   //< Data packets retransmitted for any reason.
    int32_t SentAckPackets = 0;         //< Standalone ACK packets emitted by the connection.
    int32_t SentNakPackets = 0;         //< NAK packets sent to request retransmission of missing sequences.
    int32_t SentRstPackets = 0;         //< RST (reset) packets sent to abruptly terminate the connection.
    int32_t FastRetransmissions = 0;    //< Packets retransmitted via fast retransmit before RTO expiration.
    int32_t TimeoutRetransmissions = 0; //< Packets retransmitted after RTO timer expiration.
    int32_t CongestionWindowBytes = 0;  //< BBR congestion window in bytes at snapshot time.
    double PacingRateBytesPerSecond = 0.0;  //< BBR pacing rate in bytes/second at snapshot time.
    double EstimatedLossPercent = 0.0;      //< BBR estimated loss percentage on a 0..100 scale.
    int64_t LastRttMicros = 0;              //< Most recent round-trip-time measurement in microseconds.
    ucp::vector<int64_t> RttSamplesMicros;  //< Recent RTT samples for latency diagnostics.
    bool ReceivedReset = false;             //< True if the peer sent an RST packet, indicating a remote-initiated reset.
    int32_t CurrentNetworkClass = 0;        //< Current BBR NetworkClass classification (e.g. gain cycle phase).
};

} // namespace ucp  //< Close the ucp namespace scope.
