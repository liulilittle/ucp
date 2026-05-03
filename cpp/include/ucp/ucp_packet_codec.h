#pragma once

/** @file ucp_packet_codec.h
 *  @brief Wire-protocol encoder/decoder for UCP packets — mirrors C# Ucp.Internal.PacketCodec.
 *
 *  Handles big-endian serialization of all UCP packet types to and from
 *  byte buffers.  Uses a static interface (no instance state) because
 *  encoding/decoding is purely algorithmic over byte buffers.
 *
 *  All multi-byte integers are encoded in big-endian (network byte order).
 *  The 48-bit timestamp field is read/written as a uint64_t with upper
 *  16 bits masked to zero.
 */

#include "ucp_packets.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace ucp {

// === Field-size constants (network endian) ===

constexpr size_t COMMON_HEADER_SIZE        = 12;  //< Total bytes in UcpCommonHeader.
constexpr size_t SEQUENCE_NUMBER_SIZE      = 4;   //< uint32_t sequence number field width.
constexpr size_t ACK_NUMBER_SIZE           = 4;   //< uint32_t ack number field width.
constexpr size_t CONNECTION_ID_SIZE        = 4;   //< uint32_t connection_id field width.
constexpr size_t ACK_TIMESTAMP_FIELD_SIZE  = 6;   //< 48-bit echo timestamp field width.
constexpr size_t PACKET_TYPE_FIELD_SIZE    = 1;   //< type field width (uint8_t).
constexpr size_t PACKET_FLAGS_FIELD_SIZE   = 1;   //< flags field width (uint8_t).
constexpr size_t SACK_BLOCK_SIZE           = 8;   //< One SACK block: start(4) + end(4).
constexpr size_t MSS                       = 1220; //< Maximum segment size (payload capacity).

// === Derived header sizes ===

constexpr size_t DATA_HEADER_SIZE          = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);     //< Data header without piggybacked ACK.
constexpr size_t DATA_HEADER_SIZE_WITH_ACK = DATA_HEADER_SIZE + ACK_NUMBER_SIZE + sizeof(uint16_t) + sizeof(uint32_t) + ACK_TIMESTAMP_FIELD_SIZE; //< Data header with piggybacked ACK.
constexpr size_t ACK_FIXED_SIZE            = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + ACK_TIMESTAMP_FIELD_SIZE; //< ACK header (excl. SACK blocks).
constexpr size_t NAK_FIXED_SIZE            = COMMON_HEADER_SIZE + ACK_NUMBER_SIZE + sizeof(uint16_t);  //< NAK header (excl. missing sequences).

// === Bit-width constants for shift operations ===

constexpr int BYTE_BITS    = 8;   //< Bits per byte.
constexpr int UINT16_BITS  = 16;  //< Bits in uint16_t.
constexpr int UINT24_BITS  = 24;  //< Bits in 3 bytes.
constexpr int UINT32_BITS  = 32;  //< Bits in uint32_t.
constexpr int UINT40_BITS  = 40;  //< Bits in 5 bytes.

constexpr uint64_t UINT48_MASK = 0x0000FFFFFFFFFFFFULL;  //< Mask to extract lower 48 bits of a uint64_t.

/** @brief Maximum number of SACK blocks that fit in one ACK packet given MSS. */
constexpr int MAX_ACK_SACK_BLOCKS = static_cast<int>((MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE);

/** @brief Static packet encoder/decoder for big-endian UCP wire format.
 *
 *  All methods are static because encoding requires no mutable state.
 *  Decoded packets are returned via std::unique_ptr<UcpPacket>; the caller
 *  should dynamic_cast to the concrete type based on header.type.
 */
class UcpPacketCodec {
public:
    /** @brief Encode a concrete UcpPacket into a wire-format byte buffer.
     *  @param packet  The typed packet to encode (Data, Ack, Nak, FecRepair, or Control).
     *  @return Big-endian byte buffer ready for transmission. */
    static std::vector<uint8_t> Encode(const UcpPacket& packet);

    /** @brief Attempt to decode a byte buffer into a UcpPacket.
     *  @param buffer      Pointer to the start of the datagram.
     *  @param offset      Byte offset within buffer where the packet begins (typically 0).
     *  @param count       Number of bytes available from offset.
     *  @param out_packet  On success, set to a unique_ptr<UcpPacket>; caller should dynamic_cast.
     *  @return true if decoding succeeded, false if the buffer is incomplete or invalid. */
    static bool TryDecode(const uint8_t* buffer, size_t offset, size_t count, std::unique_ptr<UcpPacket>& out_packet);

private:
    // === Primitive big-endian read/write helpers ===

    /** @brief Read a big-endian uint16_t from buffer at offset. */
    static uint16_t ReadUInt16(const uint8_t* buffer, size_t offset);
    /** @brief Write a uint16_t in big-endian to buffer at offset. */
    static void     WriteUInt16(uint16_t value, uint8_t* buffer, size_t offset);
    /** @brief Read a big-endian uint32_t from buffer at offset. */
    static uint32_t ReadUInt32(const uint8_t* buffer, size_t offset);
    /** @brief Write a uint32_t in big-endian to buffer at offset. */
    static void     WriteUInt32(uint32_t value, uint8_t* buffer, size_t offset);
    /** @brief Read a 48-bit big-endian value from buffer at offset (returns uint64_t with upper 16 bits zero). */
    static uint64_t ReadUInt48(const uint8_t* buffer, size_t offset);
    /** @brief Write a 48-bit value in big-endian to buffer at offset (only lower 48 bits of uint64_t are used). */
    static void     WriteUInt48(uint64_t value, uint8_t* buffer, size_t offset);

    /** @brief Decode the 12-byte common header from the buffer.
     *  @return true if count >= 12 and parsing succeeded. */
    static bool TryReadCommonHeader(const uint8_t* buffer, size_t offset, size_t count, UcpCommonHeader& header);
    /** @brief Write the 12-byte common header into the buffer at offset. */
    static void WriteCommonHeader(const UcpCommonHeader& header, uint8_t* buffer, size_t offset);

    // === Per-type encode helpers ===

    static std::vector<uint8_t> EncodeData(const UcpDataPacket& packet);
    static std::vector<uint8_t> EncodeAck(const UcpAckPacket& packet);
    static std::vector<uint8_t> EncodeNak(const UcpNakPacket& packet);
    static std::vector<uint8_t> EncodeFecRepair(const UcpFecRepairPacket& packet);
    static std::vector<uint8_t> EncodeControl(const UcpControlPacket& packet);

    // === Per-type decode helpers ===

    static bool TryDecodeData(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet);
    static bool TryDecodeAck(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet);
    static bool TryDecodeNak(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet);
    static bool TryDecodeFecRepair(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet);
};

} // namespace ucp
