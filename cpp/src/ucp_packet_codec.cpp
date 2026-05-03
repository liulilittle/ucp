/** @file ucp_packet_codec.cpp
 *  @brief Big-endian packet encoding/decoding implementation — mirrors C# Ucp.Internal.PacketCodec.
 *
 *  All multi-byte integers are serialized in big-endian (network byte order).
 *  The 48-bit timestamp field occupies 6 bytes (lower 48 bits of a uint64_t).
 *  Packets are decoded into the appropriate concrete UcpPacket subclass via
 *  tag dispatch on the header.type field.
 */

#include "ucp/ucp_packet_codec.h"

#include <algorithm>
#include <cstring>

namespace ucp {

// ====================================================================================================
// Primitive big-endian read/write helpers
// ====================================================================================================

uint16_t UcpPacketCodec::ReadUInt16(const uint8_t* buffer, size_t offset)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(buffer[offset]) << BYTE_BITS) | buffer[offset + 1]);
}

void UcpPacketCodec::WriteUInt16(uint16_t value, uint8_t* buffer, size_t offset)
{
    buffer[offset]     = static_cast<uint8_t>(value >> BYTE_BITS);
    buffer[offset + 1] = static_cast<uint8_t>(value);
}

uint32_t UcpPacketCodec::ReadUInt32(const uint8_t* buffer, size_t offset)
{
    return (static_cast<uint32_t>(buffer[offset])     << UINT24_BITS)
         | (static_cast<uint32_t>(buffer[offset + 1]) << UINT16_BITS)
         | (static_cast<uint32_t>(buffer[offset + 2]) << BYTE_BITS)
         |  buffer[offset + 3];
}

void UcpPacketCodec::WriteUInt32(uint32_t value, uint8_t* buffer, size_t offset)
{
    buffer[offset]     = static_cast<uint8_t>(value >> UINT24_BITS);
    buffer[offset + 1] = static_cast<uint8_t>(value >> UINT16_BITS);
    buffer[offset + 2] = static_cast<uint8_t>(value >> BYTE_BITS);
    buffer[offset + 3] = static_cast<uint8_t>(value);
}

uint64_t UcpPacketCodec::ReadUInt48(const uint8_t* buffer, size_t offset)
{
    // Read 6 bytes in big-endian into lower 48 bits of a uint64_t
    uint64_t value = (static_cast<uint64_t>(buffer[offset])     << UINT40_BITS)
                   | (static_cast<uint64_t>(buffer[offset + 1]) << UINT32_BITS)
                   | (static_cast<uint64_t>(buffer[offset + 2]) << UINT24_BITS)
                   | (static_cast<uint64_t>(buffer[offset + 3]) << UINT16_BITS)
                   | (static_cast<uint64_t>(buffer[offset + 4]) << BYTE_BITS)
                   |  buffer[offset + 5];
    return value;
}

void UcpPacketCodec::WriteUInt48(uint64_t value, uint8_t* buffer, size_t offset)
{
    // Only lower 48 bits are serialized (upper 16 bits masked to 0)
    uint64_t normalized = value & UINT48_MASK;
    buffer[offset]     = static_cast<uint8_t>(normalized >> UINT40_BITS);
    buffer[offset + 1] = static_cast<uint8_t>(normalized >> UINT32_BITS);
    buffer[offset + 2] = static_cast<uint8_t>(normalized >> UINT24_BITS);
    buffer[offset + 3] = static_cast<uint8_t>(normalized >> UINT16_BITS);
    buffer[offset + 4] = static_cast<uint8_t>(normalized >> BYTE_BITS);
    buffer[offset + 5] = static_cast<uint8_t>(normalized);
}

// ====================================================================================================
// Common header encode/decode
// ====================================================================================================

bool UcpPacketCodec::TryReadCommonHeader(const uint8_t* buffer, size_t offset, size_t count,
                                         UcpCommonHeader& header)
{
    if (count < COMMON_HEADER_SIZE) {
        return false;
    }
    header.type         = static_cast<UcpPacketType>(buffer[offset]);
    header.flags        = static_cast<UcpPacketFlags>(buffer[offset + 1]);
    header.connection_id = ReadUInt32(buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE);
    header.timestamp    = ReadUInt48(buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE + CONNECTION_ID_SIZE);
    return true;
}

void UcpPacketCodec::WriteCommonHeader(const UcpCommonHeader& header, uint8_t* buffer, size_t offset)
{
    buffer[offset]     = static_cast<uint8_t>(header.type);
    buffer[offset + 1] = header.flags;
    WriteUInt32(header.connection_id, buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE);
    WriteUInt48(header.timestamp, buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE + CONNECTION_ID_SIZE);
}

// ====================================================================================================
// Top-level encode/decode (tag dispatch by packet type)
// ====================================================================================================

std::vector<uint8_t> UcpPacketCodec::Encode(const UcpPacket& packet)
{
    // Dispatch to the correct encoder based on the concrete type
    if (auto* data = dynamic_cast<const UcpDataPacket*>(&packet)) {
        return EncodeData(*data);
    }
    if (auto* ack = dynamic_cast<const UcpAckPacket*>(&packet)) {
        return EncodeAck(*ack);
    }
    if (auto* nak = dynamic_cast<const UcpNakPacket*>(&packet)) {
        return EncodeNak(*nak);
    }
    if (auto* fec = dynamic_cast<const UcpFecRepairPacket*>(&packet)) {
        return EncodeFecRepair(*fec);
    }
    if (auto* ctrl = dynamic_cast<const UcpControlPacket*>(&packet)) {
        return EncodeControl(*ctrl);
    }
    return {};
}

bool UcpPacketCodec::TryDecode(const uint8_t* buffer, size_t offset, size_t count,
                               std::unique_ptr<UcpPacket>& out_packet)
{
    out_packet = nullptr;
    if (buffer == nullptr || count < COMMON_HEADER_SIZE) {
        return false;
    }

    UcpCommonHeader header;
    if (!TryReadCommonHeader(buffer, offset, count, header)) {
        return false;
    }

    // Tag dispatch by packet type in the header
    switch (header.type) {
        case UcpPacketType::Data:
            return TryDecodeData(buffer, offset, count, header, out_packet);
        case UcpPacketType::Ack:
            return TryDecodeAck(buffer, offset, count, header, out_packet);
        case UcpPacketType::FecRepair:
            return TryDecodeFecRepair(buffer, offset, count, header, out_packet);
        case UcpPacketType::Nak:
            return TryDecodeNak(buffer, offset, count, header, out_packet);
        case UcpPacketType::Syn:
        case UcpPacketType::SynAck:
        case UcpPacketType::Fin:
        case UcpPacketType::Rst: {
            // Control packets: optional sequence number + optional ack number
            auto control = std::make_unique<UcpControlPacket>();
            control->header = header;

            size_t controlIndex = offset + COMMON_HEADER_SIZE;
            bool hasAck = (header.flags & HasAckNumber) == HasAckNumber;
            if (hasAck && count >= controlIndex + ACK_NUMBER_SIZE) {
                control->ack_number = ReadUInt32(buffer, controlIndex);
                controlIndex += ACK_NUMBER_SIZE;
            }

            if (count >= controlIndex + SEQUENCE_NUMBER_SIZE) {
                control->has_sequence_number = true;
                control->sequence_number = ReadUInt32(buffer, controlIndex);
            }

            out_packet = std::move(control);
            return true;
        }
        default:
            return false;
    }
}

// ====================================================================================================
// Per-type encode implementations
// ====================================================================================================

std::vector<uint8_t> UcpPacketCodec::EncodeData(const UcpDataPacket& packet)
{
    size_t payloadLength = packet.payload.size();
    bool hasAck = (packet.header.flags & HasAckNumber) == HasAckNumber;
    size_t blockCount = 0;
    if (hasAck && !packet.sack_blocks.empty()) {
        blockCount = std::min(packet.sack_blocks.size(), static_cast<size_t>(MAX_ACK_SACK_BLOCKS));
    }

    // Allocate: header + optional piggybacked ACK + SACK blocks + payload
    size_t baseHeaderSize = hasAck ? DATA_HEADER_SIZE_WITH_ACK : DATA_HEADER_SIZE;
    std::vector<uint8_t> bytes(baseHeaderSize + blockCount * SACK_BLOCK_SIZE + payloadLength);
    size_t index = 0;

    // === Data packet layout ===
    WriteCommonHeader(packet.header, bytes.data(), index);
    index += COMMON_HEADER_SIZE;
    WriteUInt32(packet.sequence_number, bytes.data(), index);
    index += SEQUENCE_NUMBER_SIZE;
    WriteUInt16(packet.fragment_total, bytes.data(), index);
    index += sizeof(uint16_t);
    WriteUInt16(packet.fragment_index, bytes.data(), index);
    index += sizeof(uint16_t);

    // Optional piggybacked ACK / SACK / window / echo
    if (hasAck) {
        WriteUInt32(packet.ack_number, bytes.data(), index);
        index += ACK_NUMBER_SIZE;
        WriteUInt16(static_cast<uint16_t>(blockCount), bytes.data(), index);
        index += sizeof(uint16_t);

        for (size_t i = 0; i < blockCount; i++) {
            const SackBlock& block = packet.sack_blocks[i];
            WriteUInt32(block.Start, bytes.data(), index);
            index += SEQUENCE_NUMBER_SIZE;
            WriteUInt32(block.End, bytes.data(), index);
            index += SEQUENCE_NUMBER_SIZE;
        }

        WriteUInt32(packet.window_size, bytes.data(), index);
        index += sizeof(uint32_t);
        WriteUInt48(packet.echo_timestamp, bytes.data(), index);
        index += ACK_TIMESTAMP_FIELD_SIZE;
    }

    // Payload (unsafe copy for performance — caller guarantees alignment)
    if (payloadLength > 0) {
        std::memcpy(bytes.data() + index, packet.payload.data(), payloadLength);
    }

    return bytes;
}

// ====================================================================================================
// Per-type decode implementations
// ====================================================================================================

bool UcpPacketCodec::TryDecodeData(const uint8_t* buffer, size_t offset, size_t count,
                                   const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet)
{
    out_packet = nullptr;
    bool hasAck = (header.flags & HasAckNumber) == HasAckNumber;
    size_t minHeaderSize = hasAck ? DATA_HEADER_SIZE_WITH_ACK : DATA_HEADER_SIZE;
    if (count < minHeaderSize) {
        return false;
    }

    size_t index = offset + COMMON_HEADER_SIZE;
    auto data = std::make_unique<UcpDataPacket>();
    data->header = header;
    data->sequence_number = ReadUInt32(buffer, index);
    index += SEQUENCE_NUMBER_SIZE;
    data->fragment_total = ReadUInt16(buffer, index);
    index += sizeof(uint16_t);
    data->fragment_index = ReadUInt16(buffer, index);
    index += sizeof(uint16_t);

    // Decode piggybacked ACK fields if present
    if (hasAck) {
        data->ack_number = ReadUInt32(buffer, index);
        index += ACK_NUMBER_SIZE;
        uint16_t blockCount = ReadUInt16(buffer, index);
        index += sizeof(uint16_t);

        size_t expectedSize = minHeaderSize + static_cast<size_t>(blockCount) * SACK_BLOCK_SIZE;
        if (count < expectedSize) {
            return false;
        }

        for (uint16_t i = 0; i < blockCount; i++) {
            SackBlock block;
            block.Start = ReadUInt32(buffer, index);
            index += SEQUENCE_NUMBER_SIZE;
            block.End = ReadUInt32(buffer, index);
            index += SEQUENCE_NUMBER_SIZE;
            data->sack_blocks.push_back(block);
        }

        data->window_size = ReadUInt32(buffer, index);
        index += sizeof(uint32_t);
        data->echo_timestamp = ReadUInt48(buffer, index);
        index += ACK_TIMESTAMP_FIELD_SIZE;
    }

    // Remaining bytes are payload
    size_t consumed = index - offset;
    if (consumed > count) {
        return false;
    }
    size_t payloadLength = count - consumed;

    if (payloadLength > 0) {
        data->payload.resize(payloadLength);
        std::memcpy(data->payload.data(), buffer + index, payloadLength);
    }

    out_packet = std::move(data);
    return true;
}

// ====================================================================================================
// ACK packet encode/decode
// ====================================================================================================

std::vector<uint8_t> UcpPacketCodec::EncodeAck(const UcpAckPacket& packet)
{
    size_t blockCount = packet.sack_blocks.size();
    if (blockCount > static_cast<size_t>(MAX_ACK_SACK_BLOCKS)) {
        blockCount = static_cast<size_t>(MAX_ACK_SACK_BLOCKS);
    }

    std::vector<uint8_t> bytes(ACK_FIXED_SIZE + blockCount * SACK_BLOCK_SIZE);
    size_t index = 0;

    WriteCommonHeader(packet.header, bytes.data(), index);
    index += COMMON_HEADER_SIZE;
    WriteUInt32(packet.ack_number, bytes.data(), index);
    index += SEQUENCE_NUMBER_SIZE;
    WriteUInt16(static_cast<uint16_t>(blockCount), bytes.data(), index);
    index += sizeof(uint16_t);

    for (size_t i = 0; i < blockCount; i++) {
        const SackBlock& block = packet.sack_blocks[i];
        WriteUInt32(block.Start, bytes.data(), index);
        index += SEQUENCE_NUMBER_SIZE;
        WriteUInt32(block.End, bytes.data(), index);
        index += SEQUENCE_NUMBER_SIZE;
    }

    WriteUInt32(packet.window_size, bytes.data(), index);
    index += sizeof(uint32_t);
    WriteUInt48(packet.echo_timestamp, bytes.data(), index);

    return bytes;
}

bool UcpPacketCodec::TryDecodeAck(const uint8_t* buffer, size_t offset, size_t count,
                                  const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet)
{
    out_packet = nullptr;
    if (count < ACK_FIXED_SIZE) {
        return false;
    }

    size_t index = offset + COMMON_HEADER_SIZE;
    auto ack = std::make_unique<UcpAckPacket>();
    ack->header = header;
    ack->ack_number = ReadUInt32(buffer, index);
    index += SEQUENCE_NUMBER_SIZE;
    uint16_t blockCount = ReadUInt16(buffer, index);
    index += sizeof(uint16_t);

    size_t expectedSize = ACK_FIXED_SIZE + static_cast<size_t>(blockCount) * SACK_BLOCK_SIZE;
    if (count < expectedSize) {
        return false;
    }

    for (uint16_t i = 0; i < blockCount; i++) {
        SackBlock block;
        block.Start = ReadUInt32(buffer, index);
        index += SEQUENCE_NUMBER_SIZE;
        block.End = ReadUInt32(buffer, index);
        index += SEQUENCE_NUMBER_SIZE;
        ack->sack_blocks.push_back(block);
    }

    ack->window_size = ReadUInt32(buffer, index);
    index += sizeof(uint32_t);
    ack->echo_timestamp = ReadUInt48(buffer, index);

    out_packet = std::move(ack);
    return true;
}

// ====================================================================================================
// NAK packet encode/decode
// ====================================================================================================

std::vector<uint8_t> UcpPacketCodec::EncodeNak(const UcpNakPacket& packet)
{
    size_t count = packet.missing_sequences.size();
    std::vector<uint8_t> bytes(NAK_FIXED_SIZE + count * SEQUENCE_NUMBER_SIZE);
    size_t index = 0;

    WriteCommonHeader(packet.header, bytes.data(), index);
    index += COMMON_HEADER_SIZE;
    WriteUInt32(packet.ack_number, bytes.data(), index);
    index += ACK_NUMBER_SIZE;
    WriteUInt16(static_cast<uint16_t>(count), bytes.data(), index);
    index += sizeof(uint16_t);

    for (size_t i = 0; i < count; i++) {
        WriteUInt32(packet.missing_sequences[i], bytes.data(), index);
        index += SEQUENCE_NUMBER_SIZE;
    }

    return bytes;
}

bool UcpPacketCodec::TryDecodeNak(const uint8_t* buffer, size_t offset, size_t count,
                                  const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet)
{
    out_packet = nullptr;
    if (count < NAK_FIXED_SIZE) {
        return false;
    }

    size_t index = offset + COMMON_HEADER_SIZE;
    auto nak = std::make_unique<UcpNakPacket>();
    nak->header = header;
    nak->ack_number = ReadUInt32(buffer, index);
    index += ACK_NUMBER_SIZE;
    uint16_t missingCount = ReadUInt16(buffer, index);
    index += sizeof(uint16_t);

    size_t expectedSize = NAK_FIXED_SIZE + static_cast<size_t>(missingCount) * SEQUENCE_NUMBER_SIZE;
    if (count < expectedSize) {
        return false;
    }

    for (uint16_t i = 0; i < missingCount; i++) {
        nak->missing_sequences.push_back(ReadUInt32(buffer, index));
        index += SEQUENCE_NUMBER_SIZE;
    }

    out_packet = std::move(nak);
    return true;
}

// ====================================================================================================
// FEC Repair packet encode/decode
// ====================================================================================================

std::vector<uint8_t> UcpPacketCodec::EncodeFecRepair(const UcpFecRepairPacket& packet)
{
    size_t payloadLen = packet.payload.size();
    std::vector<uint8_t> bytes(COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint8_t) + payloadLen);

    WriteCommonHeader(packet.header, bytes.data(), 0);
    WriteUInt32(packet.group_id, bytes.data(), COMMON_HEADER_SIZE);
    bytes[COMMON_HEADER_SIZE + sizeof(uint32_t)] = packet.group_index;

    if (payloadLen > 0) {
        std::memcpy(bytes.data() + COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint8_t),
                    packet.payload.data(), payloadLen);
    }

    return bytes;
}

bool UcpPacketCodec::TryDecodeFecRepair(const uint8_t* buffer, size_t offset, size_t count,
                                        const UcpCommonHeader& header, std::unique_ptr<UcpPacket>& out_packet)
{
    out_packet = nullptr;
    constexpr size_t fecFixedSize = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint8_t);
    if (count < fecFixedSize) {
        return false;
    }

    auto repair = std::make_unique<UcpFecRepairPacket>();
    repair->header = header;
    repair->group_id = ReadUInt32(buffer, offset + COMMON_HEADER_SIZE);
    repair->group_index = buffer[offset + COMMON_HEADER_SIZE + sizeof(uint32_t)];

    size_t payloadLen = count - fecFixedSize;

    if (payloadLen > 0) {
        repair->payload.resize(payloadLen);
        std::memcpy(repair->payload.data(),
                    buffer + offset + fecFixedSize,
                    payloadLen);
    }

    out_packet = std::move(repair);
    return true;
}

// ====================================================================================================
// Control packet encode (Syn / SynAck / Fin / Rst)
// ====================================================================================================

std::vector<uint8_t> UcpPacketCodec::EncodeControl(const UcpControlPacket& packet)
{
    bool hasAck = (packet.header.flags & HasAckNumber) == HasAckNumber;
    size_t size = COMMON_HEADER_SIZE;
    if (hasAck) {
        size += ACK_NUMBER_SIZE;
    }
    if (packet.has_sequence_number) {
        size += SEQUENCE_NUMBER_SIZE;
    }

    std::vector<uint8_t> bytes(size);
    size_t index = 0;
    WriteCommonHeader(packet.header, bytes.data(), index);
    index += COMMON_HEADER_SIZE;

    if (hasAck) {
        WriteUInt32(packet.ack_number, bytes.data(), index);
        index += ACK_NUMBER_SIZE;
    }
    if (packet.has_sequence_number) {
        WriteUInt32(packet.sequence_number, bytes.data(), index);
    }

    return bytes;
}

} // namespace ucp
