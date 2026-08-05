#pragma once

/** @file ucp_types.h
 *  @brief Common data types for UCP endpoints, diagnostics, transfer reports, and async callbacks.
 *
 *  Defines the Endpoint abstraction (address + port), error codes for async operations,
 *  callback function types for all async APIs (Proactor pattern), a lightweight public
 *  UcpTransferReport matching C# Ucp.UcpTransferReport field-for-field, and the
 *  richer UcpConnectionDiagnostics struct used internally for connection health
 *  snapshots.  Mirrors types scattered across C# Ucp.Types and Ucp.TransferReport.
 *
 *  MIT License -- Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 */

#include <cstdint>
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

namespace ucp {

/**
 * @brief Error codes for UCP async operations.
 * @note Mirrors C# UcpError enum for cross-language consistency.
 */
enum class UcpError : int {
    None = 0,
    NotConnected = 1,
    InternalError = 2,
    Closed = 3,
    Timeout = 4,
    InvalidArgument = 5,
    OutOfMemory = 6,
    WouldBlock = 7,
    NotSupported = 8,
    ConnectionReset = 9,
    ConnectionRefused = 10,
    AddressInUse = 11,
    AddressNotAvailable = 12,
    NetworkUnreachable = 13,
    BufferTooSmall = 14,
    MessageTooLarge = 15,
    InvalidState = 16,
    ShuttingDown = 17,
    AlreadyExists = 18,
    NotFound = 19,
    AccessDenied = 20,
    ProtocolError = 21,
    HandshakeFailed = 22,
    Disconnected = 23
};

/** @brief Callback type for ConnectAsync operation.
 *  @param error UcpError::None on success, error code on failure.
 *  @param connectionId Valid only if error is None; the assigned connection ID. */
using ConnectAsyncCallback = ucp::function<void(UcpError error, uint32_t connectionId)>;

/** @brief Callback type for SendAsync operation.
 *  @param error UcpError::None on success, error code on failure.
 *  @param bytesSent Number of bytes accepted for sending (always equals requested count on success). */
using SendAsyncCallback = ucp::function<void(UcpError error, int32_t bytesSent)>;

/** @brief Callback type for ReceiveAsync operation.
 *  @param error UcpError::None on success, UcpError::Closed if connection closed gracefully.
 *  @param bytesReceived Number of bytes received (1 to requested count), 0 on close. */
using ReceiveAsyncCallback = ucp::function<void(UcpError error, int32_t bytesReceived)>;

/** @brief Callback type for WriteAsync operation (reliable exact-byte write).
 *  @param error UcpError::None on success, error code on failure.
 *  @param success True if all bytes were accepted for sending. */
using WriteAsyncCallback = ucp::function<void(UcpError error, bool success)>;

/** @brief Callback type for ReadAsync operation (reliable exact-byte read).
 *  @param error UcpError::None on success, UcpError::Closed if connection closed before full read.
 *  @param success True if all requested bytes were received. */
using ReadAsyncCallback = ucp::function<void(UcpError error, bool success)>;

/** @brief Callback type for CloseAsync operation.
 *  @param error UcpError::None on success, error code on failure. */
using CloseAsyncCallback = ucp::function<void(UcpError error)>;

/** @brief Callback type for AcceptAsync operation (server-side).
 *  @param error UcpError::None on success, error code on failure.
 *  @param connection Pointer to accepted connection, valid only if error is None. */
using AcceptAsyncCallback = ucp::function<void(UcpError error, class UcpConnection* connection)>;

struct Endpoint {
    ucp::string address;
    uint16_t port;

    Endpoint() noexcept : port(0) {}

    /** @brief Parameterized constructor: binds address and port.
     *  @param addr  IPv4 or IPv6 address string.
     *  @param p     UDP port number. */
    Endpoint(const ucp::string& addr, uint16_t p) noexcept : address(addr), port(p) {}

    /** @brief Parse an "address:port" string into an Endpoint.
     *  @param str  String in "ip:port" or "host:port" format.
     *  @return Parsed Endpoint; port defaults to 0 if not present. */
    static Endpoint Parse(const ucp::string& str) noexcept;

    /** @brief Serialize this endpoint to "address:port".
     *  @return String representation. */
    ucp::string ToString() const noexcept;
};

/** @brief Lightweight per-connection statistics snapshot matching C# Ucp.UcpTransferReport exactly.
 *
 *  Field names, types, and default values mirror the C# public API.
 *  Provides applications with visibility into bytes sent/received, packet
 *  counts, retransmission ratios, congestion window size, pacing rate,
 *  estimated loss percentage, and remote window size. */
struct UcpTransferReport {
    int64_t BytesSent = 0;
    int64_t BytesReceived = 0;
    int32_t DataPacketsSent = 0;
    int32_t RetransmittedPackets = 0;
    int32_t AckPacketsSent = 0;
    int32_t NakPacketsSent = 0;
    int32_t FastRetransmissions = 0;
    int32_t TimeoutRetransmissions = 0;
    int64_t LastRttMicros = 0;
    ucp::vector<int64_t> RttSamplesMicros;
    int32_t CongestionWindowBytes = 0;
    double PacingRateBytesPerSecond = 0.0;
    double MeasuredBandwidthBytesPerSecond = 0.0;
    double EstimatedLossPercent = 0.0;
    uint32_t RemoteWindowBytes = 0;

    /** @brief Compute the retransmission ratio.
     *  @return Ratio of retransmitted to unique sent packets; 0.0 if no data packets have been sent. */
    double RetransmissionRatio() const noexcept {
        return 0 == DataPacketsSent ? 0.0 : static_cast<double>(RetransmittedPackets) / static_cast<double>(DataPacketsSent);
    }
};

/** @brief Detailed per-connection diagnostics snapshot for internal monitoring.
 *
 *  Extends UcpTransferReport with additional fields used by the engine
 *  and diagnostic tools: flight size, buffered receive bytes, RST counters,
 *  connection state, UCP network class, and the ReceivedReset flag. */
struct UcpConnectionDiagnostics {
    int32_t State = 0;
    int64_t FlightBytes = 0;
    uint32_t RemoteWindowBytes = 0;
    int32_t BufferedReceiveBytes = 0;
    int64_t BytesSent = 0;
    int64_t BytesReceived = 0;
    int32_t SentDataPackets = 0;
    int32_t RetransmittedPackets = 0;
    int32_t SentAckPackets = 0;
    int32_t SentNakPackets = 0;
    int32_t SentRstPackets = 0;
    int32_t FastRetransmissions = 0;
    int32_t TimeoutRetransmissions = 0;
    int32_t CongestionWindowBytes = 0;
    double PacingRateBytesPerSecond = 0.0;
    double MeasuredBandwidthBytesPerSecond = 0.0;
    double EstimatedLossPercent = 0.0;
    int64_t LastRttMicros = 0;
    ucp::vector<int64_t> RttSamplesMicros;
    bool ReceivedReset = false;
    int32_t CurrentNetworkClass = 0;
    int CurrentMtu = 1200;
    int ProbeMin = 1200;
    int ProbeMax = 1500;
    bool IsMtuProbing = false;

    int64_t GeodesicXEst = 0;
    int64_t GeodesicPEst = 0;
    uint32_t GeodesicSampleCnt = 0;
    int64_t GeodesicQDelayAvg = 0;
    int64_t GeodesicJitterEwma = 0;
    int PacingGain = 0;
    int CwndGain = 0;
    int64_t MinRttMicros = 0;
    int64_t BtlBwBytesPerSecond = 0;
    int64_t MaxBwBytesPerSecond = 0;
    int64_t TotalDelivered = 0;
};

/** @brief Enable or disable UCP_TRACE runtime tracing.
 *  Only available when compiled with UCP_TRACE defined.
 *  When enabled, protocol events are logged to stderr.
 *  @param enabled  true to enable tracing, false to disable. */
void UcpSetTraceEnabled(bool enabled) noexcept;

} // namespace ucp
