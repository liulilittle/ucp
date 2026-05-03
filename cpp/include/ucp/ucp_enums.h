#pragma once //< Header guard — prevents multiple inclusion in a single translation unit.

/** @file ucp_enums.h
 *  @brief Core enumeration types for the UCP protocol — mirrors C# Ucp.Enums and Ucp.Internal enums.
 *
 *  Defines the on-wire packet types, flag bits, connection state machine states,
 *  QoS priority levels, BBR mode enumeration, and network condition/classification
 *  categories used by the BBR congestion controller.
 */

#include <cstdint> //< Provides uint8_t for specifying the underlying type of enum class values.

namespace ucp { //< Top-level namespace for the Universal Communication Protocol (UCP) library.

/** @brief Type tag stored in the first byte (byte 0) of every UCP packet header.
 *
 *  The type field occupies the full first byte.  The decoder uses this tag
 *  to determine which concrete packet class to instantiate.  Values are chosen
 *  to leave room for future control types between the assigned codes.
 *
 *  C# equivalent: internal enum UcpPacketType : byte in UcpEnums.cs.
 */
enum class UcpPacketType : uint8_t { //< Scoped enum with uint8_t underlying type — each enumerator is a single byte on the wire.
    Syn       = 0x01,  //< Connection open request (3-way handshake step 1).  Client sends SYN with its initial sequence number to initiate a connection.
    SynAck    = 0x02,  //< Combined SYN+ACK response (server-side, handshake step 2).  Server echoes the client's SYN and piggybacks its own initial sequence.
    Ack       = 0x03,  //< Standalone cumulative acknowledgement packet.  ACKs carry the next expected sequence number and optional SACK blocks for selective acknowledgement.
    Nak       = 0x04,  //< Negative acknowledgement packet.  Explicitly lists missing sequence numbers so the sender can fast-retransmit without waiting for duplicate ACKs.
    Data      = 0x05,  //< Data packet carrying application payload.  May include piggybacked ACK fields when the HasAckNumber flag is set.  Supports fragmentation via FragmentTotal/FragmentIndex.
    Fin       = 0x06,  //< Connection close request.  Initiates graceful teardown — once both sides exchange FIN, the connection enters the Closed state.
    Rst       = 0x07,  //< Connection reset / abort.  Forcibly tears down the connection without negotiation.  All state is discarded immediately.
    FecRepair = 0x08,  //< Forward Error Correction repair packet.  Carries XOR-based parity for a group of data packets, enabling loss recovery without retransmission.
}; //< End of UcpPacketType enum — all 8 valid type values are assigned; values 0x00 and 0x09–0xFF are invalid/reserved.

/** @brief Bitfield flags stored in byte 1 of the common header.
 *
 *  Flags control piggybacked-ACK presence, retransmit marking, handshake
 *  completion signalling, and priority levels embedded in the header.
 *  Multiple flags may be OR'd together (e.g., Retransmit | HasAckNumber).
 *
 *  C# equivalent: [Flags] internal enum UcpPacketFlags : byte in UcpEnums.cs.
 */
enum UcpPacketFlags : uint8_t { //< Unscoped enum (C-style) to allow OR-combining flag values without casting — mirrors C# FlagsAttribute semantics.
    None          = 0x00,  //< No flags set.  The packet carries only its base semantics with no special processing requested from the receiver.
    NeedAck       = 0x01,  //< Bit 0: Request immediate acknowledgement from the receiver.  Bypasses the delayed-ACK timer — used for the last packet in a burst and for handshake packets.
    Retransmit    = 0x02,  //< Bit 1: Packet is a retransmission, not the original send.  Receiver skips RTT sampling for this packet (Karn's algorithm) to avoid retransmission ambiguity.
    FinAck        = 0x04,  //< Bit 2: ACK of a FIN packet.  Used during the connection teardown handshake to distinguish a FIN-ACK from a regular cumulative ACK.
    HasAckNumber  = 0x08,  //< Bit 3: Packet carries a piggybacked cumulative ack_number field in its extended header.  Enables bidirectional ACK within a single wire frame.
    PriorityMask  = 0x30,  //< Bits [5:4]: Mask for extracting the 2-bit UcpPriority field (0=Background, 1=Normal, 2=Interactive, 3=Urgent).  Higher priority segments are transmitted first.
}; //< End of UcpPacketFlags bitmask — flag values are powers of 2 to allow independent OR combinations.

/** @brief State machine states for a UCP connection.
 *
 *  Follows TCP-style transition diagram:
 *  Init → HandshakeSynSent/SynReceived → Established → ClosingFinSent/Received → Closed.
 *  Each connection transitions through these states exactly once in its lifetime
 *  (unless RST short-circuits the state machine).
 *
 *  C# equivalent: internal enum UcpConnectionState in UcpEnums.cs.
 */
enum class UcpConnectionState { //< Scoped enum — each state is mutually exclusive and represents a distinct phase in the connection lifecycle.
    Init,                   //< Initial state before any handshake activity.  Connection object exists but no packets have been exchanged — awaiting Open() or an incoming SYN.
    HandshakeSynSent,       //< Client has sent SYN, awaiting SYN-ACK.  The initiating side enters this state after transmitting the first handshake packet.
    HandshakeSynReceived,   //< Server has received SYN, sent SYN-ACK, awaiting the final ACK.  The responding side enters this state after sending SYN-ACK.
    Established,            //< Connection is fully open for bidirectional data transfer.  Both sides may send and receive application data in this state.
    ClosingFinSent,         //< Local side has sent FIN, connection is half-closed.  The local side may still receive data until the remote side sends its own FIN.
    ClosingFinReceived,     //< Remote side has sent FIN, waiting for our own FIN to complete.  The local side finishes draining its send buffer before responding with FIN.
    Closed,                 //< Connection is fully closed and resources may be released.  Terminal state — no further packet processing occurs for this connection.
}; //< End of UcpConnectionState — 7 states covering the full lifecycle from Init to Closed.

/** @brief Quality-of-service priority level for outbound segments.
 *
 *  Higher-priority segments are transmitted before lower-priority ones when
 *  the send buffer contains segments at multiple priority levels.  The priority
 *  is encoded in bits [5:4] of the Flags byte (extracted via PriorityMask).
 *
 *  C# equivalent: public enum UcpPriority : byte in UcpEnums.cs.
 */
enum class UcpPriority : uint8_t { //< Scoped enum with uint8_t underlying type — each priority level occupies 2 bits on the wire.
    Background  = 0,  //< Bulk data, no latency sensitivity (lowest priority).  Transmitted only when no Normal, Interactive, or Urgent data is queued.
    Normal      = 1,  //< Default priority for typical application data transfers.  The standard send priority when no explicit QoS level is specified.
    Interactive = 2,  //< Latency-sensitive data such as chat messages, game input, or RPC calls.  Transmitted ahead of Background and Normal segments.
    Urgent      = 3,  //< Time-critical data — highest priority.  Retransmissions may use this implicitly to minimize recovery latency.  Preempts all other traffic.
}; //< End of UcpPriority — 4 tiers (0–3) encoded in 2 bits, giving the sender 4 distinct QoS levels.

/** @brief BBR congestion-control operating mode.
 *
 *  BBR cycles through four modes: Startup (exponential probing), Drain
 *  (drain the queue built during Startup), ProbeBw (steady-state cycling
 *  with periodic gain pulses), and ProbeRtt (periodic dip to probe minimum
 *  RTT).  This mirrors the BBRv1 state machine from the IETF draft.
 *
 *  C# equivalent: internal enum BbrMode in UcpEnums.cs (also referenced in BbrCongestionControl.cs).
 */
enum class BbrMode { //< Scoped enum — each value represents a distinct phase in the BBR congestion-control state machine.
    Startup,   //< Exponential bandwidth probing with StartupPacingGain (≈2.89×).  The sender rapidly increases its pacing rate each RTT round until the bottleneck is detected.
    Drain,     //< Drain excess queue after Startup exits.  Pacing gain drops to ≈1.0× (or lower) to purge the standing queue built during Startup, restoring low latency.
    ProbeBw,   //< Steady-state mode cycling through 8 gain phases (one 1.35× pulse followed by one 0.85× drain and six 1.0× cruise phases).  Continuously probes for additional bandwidth.
    ProbeRtt,  //< Periodically (at most once every 30 s) reduce inflight to ~4 packets to re-measure the true minimum RTT (RTprop).  Prevents RTT estimate drift from persistent queuing.
}; //< End of BbrMode — 4-state machine covering the complete BBR lifecycle.

/** @brief Classification of current network conditions used by BBR loss/congestion decisions.
 *
 *  The lightweight classifier inspects recent delivery-rate trends, RTT changes, and
 *  loss observations to categorize the path's instantaneous condition.  This drives
 *  gain selection, CWND adjustments, and fast-recovery decisions.
 *
 *  C# equivalent: private enum NetworkCondition in BbrCongestionControl.cs.
 */
enum class NetworkCondition { //< Scoped enum — mutually exclusive instantaneous network condition states.
    Idle,        //< Not enough data points to classify the network condition.  BBR takes no action — treats the path as benign until sufficient samples accumulate.
    LightLoad,   //< Low loss and low RTT inflation relative to the minimum.  The network appears underutilised — aggressive probing is safe and recommended.
    Congested,   //< High loss or high RTT increase from the minimum.  The bottleneck is likely saturated — BBR applies multiplicative pacing and CWND reductions.
    RandomLoss,  //< Loss is observed but RTT has not increased significantly from its minimum.  Loss is attributed to random bit errors or radio interference, not congestion.
}; //< End of NetworkCondition — 4 classifications providing actionable guidance for congestion-control decisions.

/** @brief Long-term network path classification derived from multi-second observation windows.
 *
 *  BBR adjusts its gain tiers, inflight guardrails, FEC redundancy, and ACK scheduling
 *  based on the path class.  Different path types (LAN, mobile, satellite, VPN) have
 *  fundamentally different loss, jitter, and RTT characteristics.
 *
 *  C# equivalent: public enum NetworkClass in BbrCongestionControl.cs (internal to the BBR module).
 */
enum class NetworkClass { //< Scoped enum — each value represents a distinct long-term network path category.
    Default,               //< Unclassified / generic Internet path.  No special characteristics detected — standard BBR behavior applies.
    LowLatencyLAN,         //< Sub-5 ms RTT with low jitter (<3 ms).  Aggressive probing is safe on these clean, high-speed paths (e.g., datacenter interconnects, switched Ethernet).
    LossyLongFat,          //< High bandwidth-delay product (BDP) path with persistent background loss.  Examples: transcontinental undersea cables, satellite links — requires extra CWND headroom for retransmissions.
    MobileUnstable,        //< High jitter and moderate loss typical of cellular (LTE/5G) or Wi-Fi handover.  Uses extended high-gain cycles and fast recovery for non-congestion radio loss.
    CongestedBottleneck,   //< Sustained throughput degradation combined with RTT growth.  A bottleneck link is persistently oversubscribed — conservative pacing gains and tight CWND limits are applied.
    SymmetricVPN,          //< Moderate-to-high RTT through corporate VPN tunnels.  CWND is capped conservatively to avoid tunnel bufferbloat caused by the VPN's own queuing.
}; //< End of NetworkClass — 6 categories covering the spectrum from low-latency LAN to congested VPN tunnels.

} // namespace ucp — end of the top-level UCP namespace.
