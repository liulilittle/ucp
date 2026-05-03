#pragma once

/** @file ucp_enums.h
 *  @brief Core enumeration types for the UCP protocol — mirrors C# Ucp.Enums and Ucp.Internal enums.
 *
 *  Defines the on-wire packet types, flag bits, connection state machine states,
 *  QoS priority levels, BBR mode enumeration, and network condition/classification
 *  categories used by the BBR congestion controller.
 */

#include <cstdint>

namespace ucp {

/** @brief Type tag in every UCP packet header (byte 0).
 *
 *  The type field occupies the lower nibble of byte 0 at the start of each
 *  UCP datagram.  The decoder uses this tag to determine which concrete packet
 *  class to instantiate.
 */
enum class UcpPacketType : uint8_t {
    Syn       = 0x01,  //< Connection open request (3-way handshake step 1).
    SynAck    = 0x02,  //< Combined SYN+ACK (server-side response, step 2).
    Ack       = 0x03,  //< Standalone acknowledgement packet.
    Nak       = 0x04,  //< Negative acknowledgement (lists missing sequences).
    Data      = 0x05,  //< Data packet carrying application payload.
    Fin       = 0x06,  //< Connection close request.
    Rst       = 0x07,  //< Connection reset / abort.
    FecRepair = 0x08,  //< Forward Error Correction repair packet.
};

/** @brief Bitfield flags stored in byte 1 of the common header.
 *
 *  Flags control piggybacked-ack presence, retransmit marking, handshake
 *  completion signalling, and priority levels embedded in the header.
 */
enum UcpPacketFlags : uint8_t {
    None          = 0x00,  //< No flags set.
    NeedAck       = 0x01,  //< Request immediate acknowledgement from receiver.
    Retransmit    = 0x02,  //< Packet is a retransmission (not the original send).
    FinAck        = 0x04,  //< ACK of a FIN packet (connection close acknowledged).
    HasAckNumber  = 0x08,  //< Packet carries a piggybacked cumulative ack_number field.
    PriorityMask  = 0x30,  //< Bits [5:4] encode UcpPriority level (0..3).
};

/** @brief State machine states for a UCP connection.
 *
 *  Follows TCP-style transition diagram:
 *  Init -> HandshakeSynSent/SynReceived -> Established -> ClosingFinSent/Received -> Closed.
 */
enum class UcpConnectionState {
    Init,                   //< Initial state before any handshake activity.
    HandshakeSynSent,       //< Client has sent SYN, awaiting SYN-ACK.
    HandshakeSynReceived,   //< Server has received SYN, sent SYN-ACK, awaiting ACK.
    Established,            //< Connection is fully open for data transfer.
    ClosingFinSent,         //< Local side has sent FIN, connection is half-closed.
    ClosingFinReceived,     //< Remote side has sent FIN, waiting for our own FIN to complete.
    Closed,                 //< Connection is fully closed and resources may be released.
};

/** @brief Quality-of-service priority level for outbound segments.
 *
 *  Higher priorities are transmitted first during flush, regardless of
 *  sequence number order (head-of-line-inflight suppression applies).
 */
enum class UcpPriority : uint8_t {
    Background  = 0,  //< Bulk data, no latency sensitivity.
    Normal      = 1,  //< Default priority for application data.
    Interactive = 2,  //< Latency-sensitive data (e.g. chat, RPC).
    Urgent      = 3,  //< Time-critical data (retransmits may use this implicitly).
};

/** @brief BBR congestion-control operating mode.
 *
 *  BBR cycles through four modes:  Startup (exponential probing), Drain
 *  (drain the queue built during Startup), ProbeBw (steady-state cycling
 *  with periodic gain pulses), and ProbeRtt (periodic dip to probe minimum
 *  RTT).  Mirrors the BBRv1 state machine from the IETF draft.
 */
enum class BbrMode {
    Startup,   //< Exponential bandwidth probing with StartupPacingGain (~2.89×).
    Drain,     //< Drain excess queue after Startup (pacing_gain ≈ 1.0 or lower).
    ProbeBw,   //< Steady-state mode cycling through 8 gain phases (mostly 1.35× pulses).
    ProbeRtt,  //< Periodically (every 30 s) reduce inflight to 4 pkts to re-measure min RTT.
};

/** @brief Classification of current network conditions used by BBR loss/congestion decisions. */
enum class NetworkCondition {
    Idle,        //< Not enough data points to classify; assume benign.
    LightLoad,   //< Low loss and low RTT inflation — network is underutilised.
    Congested,   //< High loss or high RTT increase — bottleneck is saturated.
    RandomLoss,  //< Loss without RTT inflation — likely due to random bit errors, not congestion.
};

/** @brief Long-term network path classification derived from observation windows.
 *
 *  BBR adjusts its gain, cwnd, and inflight bounds based on the path class.
 *  Mirrors C# Ucp.Internal.NetworkClass enum.
 */
enum class NetworkClass {
    Default,               //< Unclassified / generic Internet path.
    LowLatencyLAN,         //< Sub-5 ms RTT, low jitter — aggressive probing is safe.
    LossyLongFat,          //< High BDP path with background loss (e.g. transcontinental).
    MobileUnstable,        //< High jitter and moderate loss (cellular / Wi-Fi handover).
    CongestedBottleneck,   //< Sustained throughput degradation and RTT growth.
    SymmetricVPN,          //< Moderate-high RTT through corporate VPN tunnels.
};

} // namespace ucp
