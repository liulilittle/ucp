#pragma once

/** @file ucp_packets.h
 *  @brief Packet type hierarchy for UCP — mirrors C# Ucp.Internal.Packets.
 *
 *  Defines the common on-wire header and the five concrete packet types
 *  (Data, Ack, Nak, Control, FecRepair).  All packets derive from UcpPacket
 *  which holds the mandatory UcpCommonHeader.  Packet encoding/decoding is
 *  handled by UcpPacketCodec.
 */

#include "ucp_constants.h"
#include "ucp_enums.h"
#include <cstdint>
#include <vector>

namespace ucp {

/** @brief Fixed 12-byte header present at the start of every UCP packet. */
struct UcpCommonHeader {
    UcpPacketType  type;          //< Packet type tag (byte 0, low nibble).
    UcpPacketFlags flags;         //< Flag bitfield (byte 1).
    uint32_t       connection_id; //< Connection identifier (bytes 2-5, big-endian).
    uint64_t       timestamp;     //< 48-bit microsecond timestamp (bytes 6-11, for echo/PAWS).
};

/** @brief Abstract base class for all UCP packet types.
 *
 *  Every concrete packet holds a UcpCommonHeader and optionally additional
 *  typed fields.  Use dynamic_cast or the type tag to determine the concrete
 *  packet class after decoding.
 */
class UcpPacket {
public:
    UcpPacket() = default;
    virtual ~UcpPacket() = default;

    UcpPacket(const UcpPacket&) = default;
    UcpPacket& operator=(const UcpPacket&) = default;
    UcpPacket(UcpPacket&&) = default;
    UcpPacket& operator=(UcpPacket&&) = default;

    UcpCommonHeader header;  //< 12-byte common header shared by all packet types.
};

/** @brief Control packet for handshake (Syn, SynAck) and connection teardown (Fin, Rst).
 *
 *  Optionally carries a sequence number (for Syn/SynAck) and a piggybacked
 *  cumulative ack number (when HasAckNumber flag is set).
 */
class UcpControlPacket final : public UcpPacket {
public:
    bool     has_sequence_number = false;  //< Whether sequence_number field is present (true for Syn, SynAck, Fin).
    uint32_t sequence_number     = 0;      //< Own sequence number for handshake/timing purposes.
    uint32_t ack_number          = 0;      //< Cumulative ack number (set when HasAckNumber flag is present).
};

/** @brief Data packet carrying application payload and potentially piggybacked ACK info. */
class UcpDataPacket final : public UcpPacket {
public:
    uint32_t              sequence_number = 0;   //< Sequence number of the first byte in this packet.
    uint16_t              fragment_total  = 0;   //< Total number of fragments in the logical message (1 = single).
    uint16_t              fragment_index  = 0;   //< Zero-based index of this fragment within the message.
    std::vector<uint8_t>  payload;                //< Application payload bytes (up to MSS).
    uint32_t              ack_number     = 0;     //< Cumulative ack (when HasAckNumber flag is set).
    std::vector<SackBlock> sack_blocks;            //< SACK blocks (piggybacked when HasAckNumber flag is set).
    uint32_t              window_size     = 0;    //< Advertised receive window (when has piggybacked ACK).
    uint64_t              echo_timestamp  = 0;    //< 48-bit echo of the peer's last timestamp (RTT measurement).
};

/** @brief Standalone acknowledgement packet carrying cumulative ACK and optional SACK blocks. */
class UcpAckPacket final : public UcpPacket {
public:
    uint32_t              ack_number = 0;       //< Cumulative acknowledgement number.
    std::vector<SackBlock> sack_blocks;          //< Selective ACK blocks for out-of-order received data.
    uint32_t              window_size    = 0;   //< Advertised receive window in bytes.
    uint64_t              echo_timestamp = 0;   //< 48-bit echo of the last peer timestamp (RTT measurement).
};

/** @brief Negative acknowledgement packet reporting missing sequence numbers to the sender. */
class UcpNakPacket final : public UcpPacket {
public:
    uint32_t              ack_number = 0;  //< Latest cumulative ack number (for context on which gap is reported).
    std::vector<uint32_t> missing_sequences; //< List of specific sequence numbers believed to be lost.
};

/** @brief Forward Error Correction repair packet carrying XOR'd data for one FEC group. */
class UcpFecRepairPacket final : public UcpPacket {
public:
    uint32_t              group_id    = 0;  //< Base sequence number of the FEC group this repair covers.
    uint8_t               group_index = 0;  //< Index of this repair packet within the FEC group.
    std::vector<uint8_t>  payload;           //< XOR-coded repair payload (max 1200 bytes per FEC slot).
};

} // namespace ucp
