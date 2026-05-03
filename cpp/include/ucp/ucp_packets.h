#pragma once // Prevent multiple inclusions of this header file within a single translation unit.

/** @file ucp_packets.h // Doxygen @file tag identifying this header for documentation generation.
 *  @brief Packet type hierarchy for UCP — mirrors C# Ucp.Internal.Packets. // Doxygen @brief summarizing the purpose: packet type class definitions.
 *
 *  Defines the common on-wire header and the five concrete packet types // Lists the fixed 12-byte common header and all derived packet subclasses.
 *  (Data, Ack, Nak, Control, FecRepair).  All packets derive from UcpPacket // Enumerates the five concrete packet types by name.
 *  which holds the mandatory UcpCommonHeader.  Packet encoding/decoding is // Notes that every packet owns a common header instance.
 *  handled by UcpPacketCodec. // References the codec class responsible for wire-format serialization/deserialization.
 */

#include "ucp_constants.h" // Include protocol constants (MSS, SackBlock struct, timer values) shared across the stack.
#include "ucp_enums.h"     // Include enumeration types (UcpPacketType, UcpPacketFlags) used in the common header.
#include <cstdint>         // Include fixed-width integer types: int64_t, uint32_t, uint16_t, uint8_t.
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

namespace ucp { // Open the UCP protocol namespace; all packet types are defined within this scope.

/** @brief Fixed 12-byte header present at the start of every UCP packet. // Doxygen @brief: describes the immutable 12-byte prefix common to all packets. */
struct UcpCommonHeader { // Fixed-size prefix (12 bytes) enabling routing and early parsing before the full packet is decoded.
    UcpPacketType  type;          //< Packet type tag in byte 0 low nibble (Syn/Ack/Data/Fin/Rst); determines which subclass to instantiate.
    UcpPacketFlags flags;         //< Bitfield of OR'd flags in byte 1 (NeedAck, Retransmit, HasAckNumber, FinAck); controls receiver processing.
    uint32_t       connection_id; //< Connection identifier in bytes 2–5 (big-endian); used by the transport layer for datagram demultiplexing.
    int64_t        timestamp;     //< 48-bit monotonic microsecond timestamp in bytes 6–11; mirrored back by the peer in EchoTimestamp for per-packet RTT measurement.
};

/** @brief Abstract base class for all UCP packet types. // Doxygen @brief: polymorphic base enabling a single reference type for all packet kinds.
 *
 *  Every concrete packet holds a UcpCommonHeader and optionally additional // Describes the core structure: a mandatory header plus optional typed fields per subclass.
 *  typed fields.  Use dynamic_cast or the type tag to determine the concrete // Recommends two runtime dispatch mechanisms: header type tag switching or dynamic_cast.
 *  packet class after decoding. // Guides the decode pipeline to select the correct concrete type before accessing subclass fields.
 */
class UcpPacket { // Abstract base class for polymorphic handling of Data, Ack, Nak, Control, and FecRepair packets through a single pointer type.
public: // Public interface of UcpPacket — constructors, destructor, and the shared header instance.
    UcpPacket() = default; // Default constructor: zero-initializes the common header fields via their in-class defaults.
    virtual ~UcpPacket() = default; // Virtual destructor: ensures correct destruction of derived-class resources when deleted through a UcpPacket pointer.

    UcpPacket(const UcpPacket&) = default; // Default copy constructor: performs memberwise copy of the UcpCommonHeader field.
    UcpPacket& operator=(const UcpPacket&) = default; // Default copy assignment: memberwise assignment of the common header.
    UcpPacket(UcpPacket&&) = default; // Default move constructor: transfers ownership of the common header without allocation.
    UcpPacket& operator=(UcpPacket&&) = default; // Default move assignment: transfers header ownership without allocation.

    UcpCommonHeader header;  //< 12-byte common header shared by every packet type; always the first field decoded on the wire.
};

/** @brief Control packet for handshake (Syn, SynAck) and connection teardown (Fin, Rst). // Doxygen @brief: connection-lifecycle management packet.
 *
 *  Optionally carries a sequence number (for Syn/SynAck) and a piggybacked // Describes optional sequence number presence and piggybacked ACK behavior.
 *  cumulative ack number (when HasAckNumber flag is set). // States the condition (HasAckNumber flag) under which AckNumber carries meaningful data.
 */
class UcpControlPacket final : public UcpPacket { // Sealed (final) control packet for SYN, SYN-ACK, FIN, and RST connection management operations.
public: // Public interface of UcpControlPacket — optional handshake fields.
    bool     has_sequence_number = false;  //< Indicates whether SequenceNumber is present in the encoded packet; true for Syn/SynAck carrying a sequence.
    uint32_t sequence_number     = 0;      //< Optional sequence number sent in handshake packets to establish the initial sequence space for the connection.
    uint32_t ack_number          = 0;      //< Cumulative acknowledgment number piggybacked when the header's HasAckNumber flag is set; informs peer of delivered data.
};

/** @brief Data packet carrying application payload and potentially piggybacked ACK info. // Doxygen @brief: application-data carrier with optional ACK metadata fused in. */
class UcpDataPacket final : public UcpPacket { // Sealed (final) data packet: transports fragmented application payload with piggybacked ACK, SACK, window, and echo.
public: // Public interface of UcpDataPacket — payload, fragmentation metadata, and piggybacked ACK fields.
    uint32_t              sequence_number = 0;   //< Sequence number of the first payload byte in this segment; monotonically assigned for in-order reassembly and loss detection.
    uint16_t              fragment_total  = 0;   //< Total number of fragments comprising the logical message (1 = unfragmented single-packet message).
    uint16_t              fragment_index  = 0;   //< Zero-based index of this fragment within the logical message (0 = first fragment); used for reassembly ordering.
    ucp::vector<uint8_t>  payload;                //< Application payload bytes carried by this packet; size bounded by the negotiated MSS (up to 1220 bytes).
    uint32_t              ack_number     = 0;     //< Cumulative acknowledgment number piggybacked on this data packet; avoids sending a separate ACK during bidirectional flows.
    ucp::vector<SackBlock> sack_blocks;            //< Selective ACK blocks describing out-of-order received ranges; enables fast retransmission without standalone ACK packets.
    uint32_t              window_size     = 0;    //< Advertised receive window size in bytes piggybacked for flow control; tells the sender how much buffer space remains.
    int64_t               echo_timestamp  = 0;    //< 48-bit echo of the peer's last Header.Timestamp; the delta between send time and echo gives the current per-packet RTT sample.
};

/** @brief Standalone acknowledgement packet carrying cumulative ACK and optional SACK blocks. // Doxygen @brief: standalone cumulative ACK with flow-control and echo metadata. */
class UcpAckPacket final : public UcpPacket { // Sealed (final) ACK packet: sent when no reverse data is flowing to ensure timely delivery confirmation.
public: // Public interface of UcpAckPacket — cumulative ACK, SACK blocks, window advertisement, and echo timestamp.
    uint32_t              ack_number = 0;       //< Cumulative acknowledgment number: all sequence numbers before this value are acknowledged as delivered in order.
    ucp::vector<SackBlock> sack_blocks;          //< Selective ACK blocks describing out-of-order received ranges beyond the cumulative ACK point.
    uint32_t              window_size    = 0;   //< Advertised receive window size in bytes; the sender must not allow inflight data to exceed this limit.
    int64_t               echo_timestamp = 0;   //< 48-bit echo of the last peer timestamp; the computed delta between original send time and this echo yields the measured RTT.
};

/** @brief Negative acknowledgement packet reporting missing sequence numbers to the sender. // Doxygen @brief: explicit loss-reporting packet for fast retransmission. */
class UcpNakPacket final : public UcpPacket { // Sealed (final) NAK packet: lists specific missing sequences so the sender can retransmit immediately without waiting for the RTO timer.
public: // Public interface of UcpNakPacket — cumulative ACK for context plus the list of missing sequences.
    uint32_t              ack_number = 0;  //< Latest cumulative acknowledgment number providing context for which gap this NAK is reporting against.
    ucp::vector<uint32_t> missing_sequences; //< List of specific sequence numbers believed lost by the receiver; each entry triggers an immediate retransmission.
};

/** @brief Forward Error Correction repair packet carrying XOR'd data for one FEC group. // Doxygen @brief: XOR-parity repair packet for single-packet loss reconstruction. */
class UcpFecRepairPacket final : public UcpPacket { // Sealed (final) FEC repair packet: carries XOR parity enabling the receiver to recover any single lost packet in a group without retransmission.
public: // Public interface of UcpFecRepairPacket — FEC group identifier, repair index, and the XOR-encoded parity payload.
    uint32_t              group_id    = 0;  //< Base sequence number identifying the FEC group this repair packet belongs to; all data packets in the group share this identifier.
    uint8_t               group_index = 0;  //< Zero-based index of this repair packet within the FEC group; supports multiple repair packets per group for higher loss tolerance.
    ucp::vector<uint8_t>  payload;           //< XOR-coded parity payload computed as the XOR of all data packet payloads in the group; any single lost packet can be recovered from this and the surviving group members.
};

} // namespace ucp // Close the UCP protocol namespace.
