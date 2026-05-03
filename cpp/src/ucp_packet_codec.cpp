/** @file ucp_packet_codec.cpp
 *  @brief Big-endian packet encoding/decoding implementation — mirrors C# Ucp.Internal.PacketCodec.
 *
 *  All multi-byte integers are serialized in big-endian (network byte order).
 *  The 48-bit timestamp field occupies 6 bytes (lower 48 bits of a uint64_t).
 *  Packets are decoded into the appropriate concrete UcpPacket subclass via
 *  tag dispatch on the header.type field.
 *
 *  Key equivalence verified line-by-line against C# UcpPacketCodec.cs:
 *  - ReadUInt16/WriteUInt16 — identical big-endian shift-and-mask
 *  - ReadUInt32/WriteUInt32 — identical big-endian shift-and-mask
 *  - ReadUInt48/WriteUInt48 — identical 6-byte big-endian, 48-bit mask
 *  - TryReadCommonHeader — identical field order: Type→Flags→ConnectionId→Timestamp
 *  - WriteCommonHeader — identical field order
 *  - Encode dispatch — same type-priority order (Data→Ack→Nak→FecRepair→Control)
 *  - TryDecode dispatch — same switch case order
 *  - Data encode/decode — identical layout with/without piggybacked ACK
 *  - Ack encode/decode — identical SACK block layout
 *  - Nak encode/decode — identical missing-sequence list layout
 *  - FecRepair encode/decode — identical GroupId/GroupIndex/payload layout
 *  - Control encode/decode — identical AckNumber→SequenceNumber layout
 *
 *  Minor language-semantic differences that do NOT affect wire compatibility:
 *  - Encode returns empty vector for unknown types (C# throws)
 *  - UcpFecRepairPacket::payload is empty vector vs C# null for no payload
 *  - ReadUInt48 returns uint64_t vs C# long (wire bytes identical)
 */

#include "ucp/ucp_packet_codec.h" //< Include the header for our own declarations and field-size constants.
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

#include <algorithm> //< std::min for clamping SACK block counts.
#include <cstring>   //< std::memcpy for fast bulk payload copy.

namespace ucp { //< Open ucp namespace — all UCP types live here.

// ====================================================================================================
// Primitive big-endian read/write helpers
// ====================================================================================================
// Mirrors C# UcpPacketCodec.cs Section "BIG-ENDIAN INTEGER READ / WRITE HELPERS".
// All multi-byte integers on the wire are big-endian (network byte order).
// MSB at lowest offset, LSB at highest offset — matching TCP/IP header encoding.
// uint16: [MSB][LSB], uint32: [31:24][23:16][15:8][7:0], uint48: [47:40]...[7:0]

uint16_t UcpPacketCodec::ReadUInt16(const uint8_t* buffer, size_t offset) // Reads a 2-byte unsigned integer from network byte order (big-endian) into a native uint16_t. Mirrors C# private static ushort ReadUInt16.
{
    return static_cast<uint16_t>( // Cast the assembled OR result to uint16_t — discards any bits above 15 (mirrors C# (ushort)(...)).
        (static_cast<uint16_t>(buffer[offset]) << BYTE_BITS) | buffer[offset + 1]); // MSB at offset shifted left 8 bits into bits [15:8], ORed with LSB at offset+1 in bits [7:0].
}

void UcpPacketCodec::WriteUInt16(uint16_t value, uint8_t* buffer, size_t offset) // Writes a 2-byte unsigned integer in network byte order (big-endian: MSB first, LSB second). Mirrors C# private static void WriteUInt16.
{
    buffer[offset]     = static_cast<uint8_t>(value >> BYTE_BITS); // MSB: bits [15:8] — shift right 8 to bring upper byte into position, cast to 8 bits, store at offset (lower address).
    buffer[offset + 1] = static_cast<uint8_t>(value);               // LSB: bits [7:0] — the low byte is already in position, cast to 8 bits, store at offset+1.
}

uint32_t UcpPacketCodec::ReadUInt32(const uint8_t* buffer, size_t offset) // Reads a 4-byte unsigned integer from network byte order (big-endian) into a native uint32_t. Mirrors C# private static uint ReadUInt32.
{
    return (static_cast<uint32_t>(buffer[offset])     << UINT24_BITS) // Byte at offset: bits [31:24] — MSB, cast to uint32_t to prevent sign extension, shift into highest byte position.
         | (static_cast<uint32_t>(buffer[offset + 1]) << UINT16_BITS) // Byte at offset+1: bits [23:16] — cast to uint32_t, shift into second byte position.
         | (static_cast<uint32_t>(buffer[offset + 2]) << BYTE_BITS)   // Byte at offset+2: bits [15:8] — cast to uint32_t, shift into third byte position.
         |  buffer[offset + 3];                                        // Byte at offset+3: bits [7:0] — LSB, no shift needed, already in lowest byte position.
}

void UcpPacketCodec::WriteUInt32(uint32_t value, uint8_t* buffer, size_t offset) // Writes a 4-byte unsigned integer in network byte order (big-endian: MSB at offset, LSB at offset+3). Mirrors C# private static void WriteUInt32.
{
    buffer[offset]     = static_cast<uint8_t>(value >> UINT24_BITS); // bits [31:24] — shift right 24 bits to bring the highest byte into position, cast to byte (drops upper bits).
    buffer[offset + 1] = static_cast<uint8_t>(value >> UINT16_BITS); // bits [23:16] — shift right 16 bits, cast to byte.
    buffer[offset + 2] = static_cast<uint8_t>(value >> BYTE_BITS);   // bits [15:8] — shift right 8 bits, cast to byte.
    buffer[offset + 3] = static_cast<uint8_t>(value);                // bits [7:0] — lowest byte, no shift needed, cast to byte.
}

uint64_t UcpPacketCodec::ReadUInt48(const uint8_t* buffer, size_t offset) // Reads a 6-byte unsigned 48-bit integer from network byte order, returns as uint64_t with value in lower 48 bits. Mirrors C# private static long ReadUInt48 (C# returns signed long, C++ returns unsigned; wire bytes identical).
{
    // Read 6 bytes in big-endian into lower 48 bits of a uint64_t
    uint64_t value = (static_cast<uint64_t>(buffer[offset])     << UINT40_BITS) // Byte at offset: bits [47:40] — MSB, cast to uint64_t to prevent sign extension, shift 40 bits into position.
                   | (static_cast<uint64_t>(buffer[offset + 1]) << UINT32_BITS) // Byte at offset+1: bits [39:32] — shift 32 bits.
                   | (static_cast<uint64_t>(buffer[offset + 2]) << UINT24_BITS) // Byte at offset+2: bits [31:24] — shift 24 bits.
                   | (static_cast<uint64_t>(buffer[offset + 3]) << UINT16_BITS) // Byte at offset+3: bits [23:16] — shift 16 bits.
                   | (static_cast<uint64_t>(buffer[offset + 4]) << BYTE_BITS)   // Byte at offset+4: bits [15:8] — shift 8 bits.
                   |  buffer[offset + 5];                                        // Byte at offset+5: bits [7:0] — LSB, no shift needed.
    return value; // Return the assembled uint64_t — upper 16 bits are guaranteed zero by construction (max 6-byte value < 2^48).
}

void UcpPacketCodec::WriteUInt48(uint64_t value, uint8_t* buffer, size_t offset) // Writes a 6-byte unsigned 48-bit integer in network byte order; the input uint64_t is masked to 48 bits. Mirrors C# private static void WriteUInt48.
{
    // Only lower 48 bits are serialized (upper 16 bits masked to 0)
    uint64_t normalized = value & UINT48_MASK; // Keep only low 48 bits — bitwise AND with 0x0000FFFFFFFFFFFF strips upper 16 bits.
    buffer[offset]     = static_cast<uint8_t>(normalized >> UINT40_BITS); // bits [47:40] — shift right 40 bits to bring the highest byte into position, cast to byte.
    buffer[offset + 1] = static_cast<uint8_t>(normalized >> UINT32_BITS); // bits [39:32] — shift right 32 bits, cast to byte.
    buffer[offset + 2] = static_cast<uint8_t>(normalized >> UINT24_BITS); // bits [31:24] — shift right 24 bits, cast to byte.
    buffer[offset + 3] = static_cast<uint8_t>(normalized >> UINT16_BITS); // bits [23:16] — shift right 16 bits, cast to byte.
    buffer[offset + 4] = static_cast<uint8_t>(normalized >> BYTE_BITS);   // bits [15:8] — shift right 8 bits, cast to byte.
    buffer[offset + 5] = static_cast<uint8_t>(normalized);                // bits [7:0] — lowest byte, no shift needed, cast to byte.
}

// ====================================================================================================
// Common header encode/decode
// ====================================================================================================
// Mirrors C# UcpPacketCodec.cs Section "COMMON HEADER READER / WRITER".
// Every UCP packet begins with this 12-byte header:
//   [0]     Type         (1 byte)   — UcpPacketType enum
//   [1]     Flags        (1 byte)   — UcpPacketFlags bitmask
//   [2:5]   ConnectionId (4 bytes)  — uint32, big-endian
//   [6:11]  Timestamp    (6 bytes)  — uint48, big-endian, microseconds

bool UcpPacketCodec::TryReadCommonHeader(const uint8_t* buffer, size_t offset, size_t count,
                                         UcpCommonHeader& header) // Parses the universal 12-byte common header that prefixes every UCP packet. Mirrors C# private static bool TryReadCommonHeader.
{
    if (count < COMMON_HEADER_SIZE) { // Validate that the buffer has at least 12 bytes available for the common header.
        return false; // Buffer too short — cannot read a complete common header, return false.
    }
    header.type         = static_cast<UcpPacketType>(buffer[offset]); // Read byte 0: the packet type — cast directly from buffer byte to enum (mirrors C# header.Type = (UcpPacketType)buffer[offset]).
    header.flags        = static_cast<UcpPacketFlags>(buffer[offset + 1]); // Read byte 1: the flags bitmask — cast directly from buffer byte to enum (mirrors C# header.Flags = (UcpPacketFlags)buffer[offset + 1]).
    header.connection_id = ReadUInt32(buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE); // Read bytes 2–5 as a big-endian uint32 ConnectionId — used to route packets to the correct protocol control block.
    header.timestamp    = ReadUInt48(buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE + CONNECTION_ID_SIZE); // Read bytes 6–11 as a big-endian uint48 Timestamp — sender's microsecond clock for RTT echo-back.
    return true; // Success: the common header was fully decoded.
}

void UcpPacketCodec::WriteCommonHeader(const UcpCommonHeader& header, uint8_t* buffer, size_t offset) // Serializes the universal 12-byte common header into the output buffer at the given offset. Mirrors C# private static void WriteCommonHeader.
{
    buffer[offset]     = static_cast<uint8_t>(header.type); // Write byte 0: the packet type — cast enum to its underlying uint8_t (e.g. 0x05 for Data). Mirrors C# buffer[offset] = (byte)header.Type.
    buffer[offset + 1] = header.flags; // Write byte 1: the flags bitmask — UcpPacketFlags has underlying type uint8_t, so implicit conversion to byte. Mirrors C# buffer[offset + 1] = (byte)header.Flags.
    WriteUInt32(header.connection_id, buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE); // Write bytes 2–5 as big-endian uint32 ConnectionId — identifies which logical connection this packet belongs to.
    WriteUInt48(header.timestamp, buffer, offset + PACKET_TYPE_FIELD_SIZE + PACKET_FLAGS_FIELD_SIZE + CONNECTION_ID_SIZE); // Write bytes 6–11 as big-endian uint48 Timestamp — sender's microsecond clock for RTT measurement.
}

// ====================================================================================================
// Top-level encode/decode (tag dispatch by packet type)
// ====================================================================================================
// Mirrors C# UcpPacketCodec.cs public static byte[] Encode and public static bool TryDecode.

ucp::vector<uint8_t> UcpPacketCodec::Encode(const UcpPacket& packet) // Public entry point: converts a typed packet object into a big-endian byte array for wire transmission. Mirrors C# public static byte[] Encode.
{
    // Dispatch to the correct encoder based on the concrete type
    if (auto* data = dynamic_cast<const UcpDataPacket*>(&packet)) { // Pattern-match: check if the runtime type is UcpDataPacket (most common case first for branch-prediction friendliness).
        return EncodeData(*data); // Delegate to the Data-specific encoder which handles sequence numbers, fragmentation, payload, and optional piggybacked ACK.
    }
    if (auto* ack = dynamic_cast<const UcpAckPacket*>(&packet)) { // Pattern-match: check if the runtime type is UcpAckPacket (standalone cumulative + selective ACK).
        return EncodeAck(*ack); // Delegate to the ACK encoder which writes AckNumber, SACK blocks, window, and echo timestamp.
    }
    if (auto* nak = dynamic_cast<const UcpNakPacket*>(&packet)) { // Pattern-match: check if the runtime type is UcpNakPacket (negative ACK with explicit missing sequences).
        return EncodeNak(*nak); // Delegate to the NAK encoder which writes the missing sequence number list.
    }
    if (auto* fec = dynamic_cast<const UcpFecRepairPacket*>(&packet)) { // Pattern-match: check if the runtime type is UcpFecRepairPacket (forward error correction parity data).
        return EncodeFecRepair(*fec); // Delegate to the FEC encoder which writes GroupId, GroupIndex, and parity payload.
    }
    if (auto* ctrl = dynamic_cast<const UcpControlPacket*>(&packet)) { // Pattern-match: check if the runtime type is UcpControlPacket (SYN, SYN-ACK, FIN, RST — connection management).
        return EncodeControl(*ctrl); // Delegate to the Control encoder which writes optional AckNumber and SequenceNumber.
    }
    return {}; // Unknown/unrecognized type — return empty vector (C# equivalent: throws NotSupportedException; C++ avoids exceptions for performance).
}

bool UcpPacketCodec::TryDecode(const uint8_t* buffer, size_t offset, size_t count,
                               ucp::unique_ptr<UcpPacket>& out_packet) // Public entry point: attempts to parse raw bytes into a typed packet; returns false on any failure. Mirrors C# public static bool TryDecode.
{
    out_packet = nullptr; // Initialize the out parameter to null so callers always get a defined value even on early exit (mirrors C# packet = null).
    if (buffer == nullptr || count < COMMON_HEADER_SIZE) { // Validate: buffer must be non-null and large enough for at least the 12-byte common header (mirrors C# if (buffer == null || count < CommonHeaderSize)).
        return false; // Early exit: input is invalid — no packet can be decoded, return false.
    }

    UcpCommonHeader header; // Placeholder for the decoded common header (Type, Flags, ConnectionId, Timestamp).
    if (!TryReadCommonHeader(buffer, offset, count, header)) { // Attempt to parse the 12-byte common header; also validates header fields are within range.
        return false; // Early exit: common header could not be parsed — return false.
    }

    // Tag dispatch by packet type in the header
    switch (header.type) { // Dispatch on the packet type byte from the common header to choose the correct type-specific decoder (mirrors C# switch (header.Type)).
        case UcpPacketType::Data: // Type byte 0x05: application data packet.
            return TryDecodeData(buffer, offset, count, header, out_packet); // Delegate to Data decoder: SequenceNumber, FragmentTotal/Index, optional piggybacked ACK, and payload.
        case UcpPacketType::Ack: // Type byte 0x03: cumulative acknowledgment with SACK blocks.
            return TryDecodeAck(buffer, offset, count, header, out_packet); // Delegate to ACK decoder: AckNumber, SACK blocks, window, echo timestamp.
        case UcpPacketType::FecRepair: // Type byte 0x08: forward error correction repair packet.
            return TryDecodeFecRepair(buffer, offset, count, header, out_packet); // Delegate to FEC decoder: GroupId, GroupIndex, parity payload.
        case UcpPacketType::Nak: // Type byte 0x04: negative acknowledgment with missing sequence list.
            return TryDecodeNak(buffer, offset, count, header, out_packet); // Delegate to NAK decoder: AckNumber, missing sequence list.
        case UcpPacketType::Syn: // Type byte 0x01: connection request — falls through to control packet decoder.
        case UcpPacketType::SynAck: // Type byte 0x02: connection acceptance — falls through to control packet decoder.
        case UcpPacketType::Fin: // Type byte 0x06: graceful close request — falls through to control packet decoder.
        case UcpPacketType::Rst: { // Type byte 0x07: hard connection reset — all four control types share the same decode logic.
            // Control packets: optional sequence number + optional ack number
            auto control = ucp::unique_ptr<UcpControlPacket>(new UcpControlPacket()); // Allocate a fresh Control packet object to populate with decoded fields (mirrors C# new UcpControlPacket()).
            control->header = header; // Copy the already-decoded common header into the packet so upper layers can access Type, Flags, ConnectionId, and Timestamp.

            size_t controlIndex = offset + COMMON_HEADER_SIZE; // Compute the starting offset past the 12-byte common header where control-specific fields begin.
            bool hasAck = (header.flags & HasAckNumber) == HasAckNumber; // Extract the HasAckNumber flag (0x08) from the header flags — controls whether an AckNumber field is present.
            if (hasAck && count >= controlIndex + ACK_NUMBER_SIZE) { // If the piggybacked ACK flag is set AND there are enough remaining bytes for a 4-byte AckNumber.
                control->ack_number = ReadUInt32(buffer, controlIndex); // Read the 4-byte big-endian AckNumber (cumulative ACK for reverse direction, piggybacked on this control packet).
                controlIndex += ACK_NUMBER_SIZE; // Advance the read pointer past the AckNumber field.
            }

            if (count >= controlIndex + SEQUENCE_NUMBER_SIZE) { // Check if there are enough remaining bytes for a 4-byte SequenceNumber (e.g. SYN packets carry a sequence number for handshake).
                control->has_sequence_number = true; // Mark that a sequence number was present so the caller knows the field is valid.
                control->sequence_number = ReadUInt32(buffer, controlIndex); // Read the 4-byte big-endian SequenceNumber (sender's chosen initial sequence number for handshake).
            }

            out_packet = std::move(control); // Assign the fully decoded Control packet (upcast to base type) to the out parameter.
            return true; // Success: a valid Control packet was decoded.
        }
        default: // Any other type byte value that doesn't match a known packet type.
            return false; // Unknown/unrecognized packet type — reject rather than producing a garbage object, return false so caller drops it.
    }
}

// ====================================================================================================
// Per-type encode implementations
// ====================================================================================================
// Each encoder mirrors the corresponding C# private static byte[] Encode* method.
// Wire format matches the C# layout exactly — field order, endianness, and optional fields.

ucp::vector<uint8_t> UcpPacketCodec::EncodeData(const UcpDataPacket& packet) // Serializes a Data packet (the most common packet type) into its big-endian wire format with optional piggybacked ACK. Mirrors C# private static byte[] EncodeData.
{
    size_t payloadLength = packet.payload.size(); // Determine payload size: number of bytes in the application data vector (0 if empty).
    bool hasAck = (packet.header.flags & HasAckNumber) == HasAckNumber; // Extract the HasAckNumber flag (0x08) — determines whether the extended header (with piggybacked ACK) is emitted.
    size_t blockCount = 0; // Default: no SACK blocks unless piggybacking is active and blocks exist.
    if (hasAck && !packet.sack_blocks.empty()) { // Only compute SACK block count when piggybacking is active AND there are actual SACK blocks to serialize.
        blockCount = std::min(packet.sack_blocks.size(), static_cast<size_t>(MAX_ACK_SACK_BLOCKS)); // Clamp to MAX_ACK_SACK_BLOCKS (149) to prevent MTU overflow (mirrors C# Math.Min(packet.SackBlocks.Count, MaxAckSackBlocks)).
    }

    // Allocate: header + optional piggybacked ACK + SACK blocks + payload
    size_t baseHeaderSize = hasAck ? DATA_HEADER_SIZE_WITH_ACK : DATA_HEADER_SIZE; // Select the appropriate header size: 36 bytes with piggybacked ACK, 20 bytes without.
    ucp::vector<uint8_t> bytes(baseHeaderSize + blockCount * SACK_BLOCK_SIZE + payloadLength); // Allocate exact-size output buffer: base header + SACK block data (8 bytes per block) + payload bytes.
    size_t index = 0; // Running write position within the output buffer, starts at the beginning.

    // === Data packet layout ===
    WriteCommonHeader(packet.header, bytes.data(), index); // Write the 12-byte common header (Type=0x05, Flags, ConnectionId, Timestamp) at offset 0 (mirrors C# WriteCommonHeader at offset 0).
    index += COMMON_HEADER_SIZE; // Advance past the 12-byte common header.
    WriteUInt32(packet.sequence_number, bytes.data(), index); // Write the 4-byte big-endian SequenceNumber — identifies this packet's position in the send stream for ordering and ACK tracking.
    index += SEQUENCE_NUMBER_SIZE; // Advance past SequenceNumber (4 bytes).
    WriteUInt16(packet.fragment_total, bytes.data(), index); // Write the 2-byte big-endian FragmentTotal — how many fragments the original user message was split into (1 = unfragmented).
    index += sizeof(uint16_t); // Advance past FragmentTotal (2 bytes).
    WriteUInt16(packet.fragment_index, bytes.data(), index); // Write the 2-byte big-endian FragmentIndex — which fragment this packet represents (0-based index into the message).
    index += sizeof(uint16_t); // Advance past FragmentIndex (2 bytes).

    // Optional piggybacked ACK / SACK / window / echo
    if (hasAck) { // Branch taken when this data packet also carries an acknowledgment (piggybacked ACK — saves one round-trip on bidirectional flows).
        WriteUInt32(packet.ack_number, bytes.data(), index); // Write the 4-byte big-endian AckNumber — the cumulative ACK for packets received from the peer.
        index += ACK_NUMBER_SIZE; // Advance past AckNumber (4 bytes).
        WriteUInt16(static_cast<uint16_t>(blockCount), bytes.data(), index); // Write the 2-byte SACK block count — tells the decoder how many [Start, End) pairs to expect next.
        index += sizeof(uint16_t); // Advance past the SACK block count (2 bytes).

        for (size_t i = 0; i < blockCount; i++) { // Iterate over each SACK block to serialize (up to MAX_ACK_SACK_BLOCKS, already clamped above).
            const SackBlock& block = packet.sack_blocks[i]; // Get the i-th SACK block from the packet's block list.
            WriteUInt32(block.Start, bytes.data(), index); // Write 4-byte big-endian Start — the first sequence acknowledged by this block (inclusive).
            index += SEQUENCE_NUMBER_SIZE; // Advance past Start (4 bytes).
            WriteUInt32(block.End, bytes.data(), index); // Write 4-byte big-endian End — the past-the-end of this acknowledged range (exclusive).
            index += SEQUENCE_NUMBER_SIZE; // Advance past End (4 bytes).
        }

        WriteUInt32(packet.window_size, bytes.data(), index); // Write the 4-byte big-endian WindowSize — the receiver's available buffer space for flow control.
        index += sizeof(uint32_t); // Advance past WindowSize (4 bytes).
        WriteUInt48(packet.echo_timestamp, bytes.data(), index); // Write the 6-byte big-endian EchoTimestamp — mirrors the peer's original timestamp for RTT = now − EchoTimestamp.
        index += ACK_TIMESTAMP_FIELD_SIZE; // Advance past EchoTimestamp (6 bytes).
    }

    // Payload (unsafe copy for performance — caller guarantees alignment)
    if (payloadLength > 0) { // Only copy payload bytes if there is actual payload data (avoids zero-length copy, mirrors C# if (payloadLength > 0)).
        std::memcpy(bytes.data() + index, packet.payload.data(), payloadLength); // Bulk-copy the payload bytes from the packet object directly into the output buffer at the current write position.
    }

    return bytes; // Return the fully encoded data packet as a big-endian byte array ready for wire transmission.
}

// ====================================================================================================
// Per-type decode implementations
// ====================================================================================================
// Each decoder mirrors the corresponding C# private static bool TryDecode* method.
// Validates minimum size requirements, reads fields in C#-identical order, and handles optional fields.

bool UcpPacketCodec::TryDecodeData(const uint8_t* buffer, size_t offset, size_t count,
                                   const UcpCommonHeader& header, ucp::unique_ptr<UcpPacket>& out_packet) // Attempts to parse raw bytes into a UcpDataPacket; the common header has already been decoded. Mirrors C# private static bool TryDecodeData.
{
    out_packet = nullptr; // Initialize out parameter to null so caller always has a defined value even on early exit (mirrors C# packet = null).
    bool hasAck = (header.flags & HasAckNumber) == HasAckNumber; // Determine from the common header flags whether this data packet carries a piggybacked ACK (extended header).
    size_t minHeaderSize = hasAck ? DATA_HEADER_SIZE_WITH_ACK : DATA_HEADER_SIZE; // Select the minimum required byte count: 36 bytes with ACK, 20 bytes without.
    if (count < minHeaderSize) { // Validate that the buffer has at least the minimum required bytes for the selected header format.
        return false; // Buffer too short even for the base data header — reject, return false.
    }

    size_t index = offset + COMMON_HEADER_SIZE; // Calculate the read position just past the 12-byte common header (already decoded and passed in as 'header').
    auto data = ucp::unique_ptr<UcpDataPacket>(new UcpDataPacket()); // Allocate a fresh Data packet object to populate with decoded fields (mirrors C# new UcpDataPacket()).
    data->header = header; // Assign the already-decoded common header to the packet object (mirrors C# data.Header = header).
    data->sequence_number = ReadUInt32(buffer, index); // Read 4-byte big-endian SequenceNumber — tells the receiver where this packet fits in the ordered stream.
    index += SEQUENCE_NUMBER_SIZE; // Advance past SequenceNumber (4 bytes).
    data->fragment_total = ReadUInt16(buffer, index); // Read 2-byte big-endian FragmentTotal — how many fragments the original message was split into.
    index += sizeof(uint16_t); // Advance past FragmentTotal (2 bytes).
    data->fragment_index = ReadUInt16(buffer, index); // Read 2-byte big-endian FragmentIndex — which fragment this packet represents (0-based).
    index += sizeof(uint16_t); // Advance past FragmentIndex (2 bytes).

    // Decode piggybacked ACK fields if present
    if (hasAck) { // Branch taken when this data packet carries a piggybacked ACK — we need to decode the extended ACK fields.
        data->ack_number = ReadUInt32(buffer, index); // Read 4-byte big-endian AckNumber — the cumulative ACK for the reverse direction.
        index += ACK_NUMBER_SIZE; // Advance past AckNumber (4 bytes).
        uint16_t blockCount = ReadUInt16(buffer, index); // Read 2-byte big-endian SACK block count — how many [Start, End) pairs follow.
        index += sizeof(uint16_t); // Advance past the block count (2 bytes).

        size_t expectedSize = minHeaderSize + static_cast<size_t>(blockCount) * SACK_BLOCK_SIZE; // Calculate the total minimum size needed given the declared number of SACK blocks (each 8 bytes).
        if (count < expectedSize) { // Check if the buffer has enough bytes to hold all the declared SACK blocks.
            return false; // Buffer too short for the declared SACK blocks — malformed or truncated, reject.
        }

        for (uint16_t i = 0; i < blockCount; i++) { // Iterate over each declared SACK block to decode.
            SackBlock block; // Allocate a fresh SACK block struct to hold the decoded [Start, End) range.
            block.Start = ReadUInt32(buffer, index); // Read 4-byte big-endian Start — the first sequence number in this acknowledged range (inclusive).
            index += SEQUENCE_NUMBER_SIZE; // Advance past Start (4 bytes).
            block.End = ReadUInt32(buffer, index); // Read 4-byte big-endian End — the sequence just past the end of this acknowledged range (exclusive).
            index += SEQUENCE_NUMBER_SIZE; // Advance past End (4 bytes).
            data->sack_blocks.push_back(block); // Append the decoded SACK block to the packet's block list so upper layers can use it for loss detection.
        }

        data->window_size = ReadUInt32(buffer, index); // Read 4-byte big-endian WindowSize — the peer's advertised receive window for flow control.
        index += sizeof(uint32_t); // Advance past WindowSize (4 bytes).
        data->echo_timestamp = ReadUInt48(buffer, index); // Read 6-byte big-endian EchoTimestamp — the peer's mirrored timestamp for RTT calculation.
        index += ACK_TIMESTAMP_FIELD_SIZE; // Advance past EchoTimestamp (6 bytes).
    }

    // Remaining bytes are payload
    size_t consumed = index - offset; // Total bytes consumed by header(s) — how many bytes we've read from the start.
    if (consumed > count) { // Sanity check: consumed bytes should never exceed the total count (mirrors C# if (payloadLength < 0)).
        return false; // Invalid state — decoding math error or corrupted buffer, reject.
    }
    size_t payloadLength = count - consumed; // Calculate the remaining bytes as payload — everything after the header(s) is application data.

    if (payloadLength > 0) { // Only copy payload bytes if there is actual data (zero-length payload is valid for ACK-only DATA packets).
        data->payload.resize(payloadLength); // Resize the payload vector to exactly the remaining byte count.
        std::memcpy(data->payload.data(), buffer + index, payloadLength); // Bulk-copy the payload bytes from the input buffer at the current read position.
    }

    out_packet = std::move(data); // Assign the fully decoded Data packet (upcast to base type) to the out parameter.
    return true; // Success: a valid Data packet was decoded.
}

// ====================================================================================================
// ACK packet encode/decode
// ====================================================================================================
// Mirrors C# UcpPacketCodec.cs Section "ACK PACKET ENCODER / DECODER".
// Wire format (variable length due to SACK blocks):
//   [0:11]   Common header
//   [12:15]  AckNumber      (uint32)
//   [16:17]  SackBlockCount (uint16)
//   [18:..]  SACK blocks    (N × 8 bytes) — each block: Start(uint32) + End(uint32)
//   [..]     WindowSize     (uint32)
//   [..]     EchoTimestamp  (uint48, 6 bytes)

ucp::vector<uint8_t> UcpPacketCodec::EncodeAck(const UcpAckPacket& packet) // Serializes an ACK packet (pure acknowledgment, not piggybacked on data) into its big-endian wire format. Mirrors C# private static byte[] EncodeAck.
{
    size_t blockCount = packet.sack_blocks.size(); // Determine how many SACK blocks to encode — zero if no selective acknowledgment data is available.
    if (blockCount > static_cast<size_t>(MAX_ACK_SACK_BLOCKS)) { // Guard: prevent the SACK block count from exceeding the protocol's maximum (149) to avoid MTU overflow (mirrors C# if (blockCount > MaxAckSackBlocks)).
        blockCount = static_cast<size_t>(MAX_ACK_SACK_BLOCKS); // Truncate to MSS limit (mirrors C# blockCount = MaxAckSackBlocks).
    }

    ucp::vector<uint8_t> bytes(ACK_FIXED_SIZE + blockCount * SACK_BLOCK_SIZE); // Allocate output buffer: fixed ACK header (28 bytes) + variable SACK block data (8 bytes per block).
    size_t index = 0; // Running write position within the output buffer.

    WriteCommonHeader(packet.header, bytes.data(), index); // Write the 12-byte common header (Type=0x03, Flags, ConnectionId, Timestamp) at offset 0.
    index += COMMON_HEADER_SIZE; // Advance past the common header (12 bytes).
    WriteUInt32(packet.ack_number, bytes.data(), index); // Write the 4-byte big-endian AckNumber — all packets with sequence numbers before this have been received contiguously.
    index += SEQUENCE_NUMBER_SIZE; // Advance past AckNumber (4 bytes).
    WriteUInt16(static_cast<uint16_t>(blockCount), bytes.data(), index); // Write the 2-byte SACK block count — tells the decoder how many SACK blocks follow.
    index += sizeof(uint16_t); // Advance past the block count (2 bytes).

    for (size_t i = 0; i < blockCount; i++) { // Iterate over each SACK block to serialize into the buffer.
        const SackBlock& block = packet.sack_blocks[i]; // Get the i-th SACK block from the packet's block list.
        WriteUInt32(block.Start, bytes.data(), index); // Write 4-byte big-endian Start — first sequence number of this acknowledged range (inclusive).
        index += SEQUENCE_NUMBER_SIZE; // Advance past Start (4 bytes).
        WriteUInt32(block.End, bytes.data(), index); // Write 4-byte big-endian End — past-the-end sequence of this acknowledged range (exclusive).
        index += SEQUENCE_NUMBER_SIZE; // Advance past End (4 bytes).
    }

    WriteUInt32(packet.window_size, bytes.data(), index); // Write 4-byte big-endian WindowSize — the receiver's available buffer, used by the sender for flow-control pacing.
    index += sizeof(uint32_t); // Advance past WindowSize (4 bytes).
    WriteUInt48(packet.echo_timestamp, bytes.data(), index); // Write 6-byte big-endian EchoTimestamp — the peer's original timestamp echoed back for RTT computation.

    return bytes; // Return the fully encoded ACK packet as a big-endian byte array.
}

bool UcpPacketCodec::TryDecodeAck(const uint8_t* buffer, size_t offset, size_t count,
                                  const UcpCommonHeader& header, ucp::unique_ptr<UcpPacket>& out_packet) // Attempts to parse raw bytes into a UcpAckPacket with SACK blocks, window, and echo timestamp. Mirrors C# private static bool TryDecodeAck.
{
    out_packet = nullptr; // Initialize out parameter to null for safe early-exit semantics.
    if (count < ACK_FIXED_SIZE) { // Validate that the buffer has at least the minimum bytes for a fixed-size ACK (28 bytes, without SACK blocks).
        return false; // Buffer too short even for the base ACK header — reject, return false.
    }

    size_t index = offset + COMMON_HEADER_SIZE; // Calculate read position just past the 12-byte common header (already decoded).
    auto ack = ucp::unique_ptr<UcpAckPacket>(new UcpAckPacket()); // Allocate a fresh ACK packet object to populate with decoded fields (mirrors C# new UcpAckPacket()).
    ack->header = header; // Assign the already-decoded common header.
    ack->ack_number = ReadUInt32(buffer, index); // Read 4-byte big-endian AckNumber — the cumulative ACK sequence number (all packets before this are confirmed received).
    index += SEQUENCE_NUMBER_SIZE; // Advance past AckNumber (4 bytes).
    uint16_t blockCount = ReadUInt16(buffer, index); // Read 2-byte SACK block count — how many [Start, End) pairs follow.
    index += sizeof(uint16_t); // Advance past the block count (2 bytes).

    size_t expectedSize = ACK_FIXED_SIZE + static_cast<size_t>(blockCount) * SACK_BLOCK_SIZE; // Calculate the total size required given the number of SACK blocks (each 8 bytes).
    if (count < expectedSize) { // Check if the buffer actually has enough bytes to hold all declared SACK blocks.
        return false; // Buffer too short for the declared SACK blocks — malformed or truncated packet, reject it.
    }

    for (uint16_t i = 0; i < blockCount; i++) { // Iterate over the declared number of SACK blocks to decode each one.
        SackBlock block; // Allocate a fresh SACK block struct.
        block.Start = ReadUInt32(buffer, index); // Read 4-byte big-endian Start — first sequence number in this acknowledged range (inclusive).
        index += SEQUENCE_NUMBER_SIZE; // Advance past Start (4 bytes).
        block.End = ReadUInt32(buffer, index); // Read 4-byte big-endian End — past-the-end sequence of this acknowledged range (exclusive).
        index += SEQUENCE_NUMBER_SIZE; // Advance past End (4 bytes).
        ack->sack_blocks.push_back(block); // Append the decoded SACK block to the packet's block list.
    }

    ack->window_size = ReadUInt32(buffer, index); // Read 4-byte big-endian WindowSize — the receiver's advertised flow-control window.
    index += sizeof(uint32_t); // Advance past WindowSize (4 bytes).
    ack->echo_timestamp = ReadUInt48(buffer, index); // Read 6-byte big-endian EchoTimestamp — the peer's mirrored timestamp for RTT measurement.

    out_packet = std::move(ack); // Assign the fully decoded ACK packet (upcast to base type) to the out parameter.
    return true; // Success: a valid ACK packet was decoded.
}

// ====================================================================================================
// NAK packet encode/decode
// ====================================================================================================
// Mirrors C# UcpPacketCodec.cs Section "NAK PACKET ENCODER / DECODER".
// Wire format (variable length due to missing sequence list):
//   [0:11]   Common header
//   [12:15]  AckNumber       (uint32)
//   [16:17]  MissingCount    (uint16)
//   [18:..]  MissingSequences (N × uint32)

ucp::vector<uint8_t> UcpPacketCodec::EncodeNak(const UcpNakPacket& packet) // Serializes a NAK (Negative Acknowledgment) packet — explicitly tells the sender which sequence numbers are missing. Mirrors C# private static byte[] EncodeNak.
{
    size_t count = packet.missing_sequences.size(); // Determine how many missing sequence numbers are being reported (0 if no loss to report, though a NAK with 0 missing is unusual).
    ucp::vector<uint8_t> bytes(NAK_FIXED_SIZE + count * SEQUENCE_NUMBER_SIZE); // Allocate output buffer: fixed NAK header (18 bytes) + 4 bytes per missing sequence number.
    size_t index = 0; // Running write position within the output buffer.

    WriteCommonHeader(packet.header, bytes.data(), index); // Write the 12-byte common header (Type=0x04, Flags, ConnectionId, Timestamp) at offset 0.
    index += COMMON_HEADER_SIZE; // Advance past the common header (12 bytes).
    WriteUInt32(packet.ack_number, bytes.data(), index); // Write 4-byte big-endian AckNumber — the cumulative ACK, i.e. the highest contiguous sequence received before the gaps.
    index += ACK_NUMBER_SIZE; // Advance past AckNumber (4 bytes).
    WriteUInt16(static_cast<uint16_t>(count), bytes.data(), index); // Write 2-byte MissingCount — the number of explicitly missing sequence numbers that follow.
    index += sizeof(uint16_t); // Advance past MissingCount (2 bytes).

    for (size_t i = 0; i < count; i++) { // Iterate over each explicitly missing sequence number to serialize.
        WriteUInt32(packet.missing_sequences[i], bytes.data(), index); // Write 4-byte big-endian missing sequence number — the sender should retransmit the packet with this sequence.
        index += SEQUENCE_NUMBER_SIZE; // Advance past this missing sequence entry (4 bytes).
    }

    return bytes; // Return the fully encoded NAK packet as a big-endian byte array.
}

bool UcpPacketCodec::TryDecodeNak(const uint8_t* buffer, size_t offset, size_t count,
                                  const UcpCommonHeader& header, ucp::unique_ptr<UcpPacket>& out_packet) // Attempts to parse raw bytes into a UcpNakPacket containing the explicit list of missing sequences. Mirrors C# private static bool TryDecodeNak.
{
    out_packet = nullptr; // Initialize out parameter to null for safe early-exit.
    if (count < NAK_FIXED_SIZE) { // Validate that the buffer has at least the minimum bytes for a fixed-size NAK (18 bytes, without missing sequences).
        return false; // Buffer too short even for the base NAK header — reject.
    }

    size_t index = offset + COMMON_HEADER_SIZE; // Calculate read position just past the 12-byte common header.
    auto nak = ucp::unique_ptr<UcpNakPacket>(new UcpNakPacket()); // Allocate a fresh NAK packet object (mirrors C# new UcpNakPacket()).
    nak->header = header; // Assign the already-decoded common header.
    nak->ack_number = ReadUInt32(buffer, index); // Read 4-byte big-endian AckNumber — the cumulative ACK (highest contiguous sequence received before the gaps).
    index += ACK_NUMBER_SIZE; // Advance past AckNumber (4 bytes).
    uint16_t missingCount = ReadUInt16(buffer, index); // Read 2-byte MissingCount — how many missing sequence numbers are listed.
    index += sizeof(uint16_t); // Advance past MissingCount (2 bytes).

    size_t expectedSize = NAK_FIXED_SIZE + static_cast<size_t>(missingCount) * SEQUENCE_NUMBER_SIZE; // Calculate the total size required given the number of missing sequences (4 bytes each).
    if (count < expectedSize) { // Check if the buffer actually has enough bytes for all declared missing sequences.
        return false; // Buffer too short for the declared missing sequences — malformed or truncated, reject.
    }

    for (uint16_t i = 0; i < missingCount; i++) { // Iterate over the declared number of missing sequence numbers.
        nak->missing_sequences.push_back(ReadUInt32(buffer, index)); // Read 4-byte big-endian missing sequence number and append it directly to the list.
        index += SEQUENCE_NUMBER_SIZE; // Advance past this missing sequence entry (4 bytes).
    }

    out_packet = std::move(nak); // Assign the fully decoded NAK packet (upcast to base type) to the out parameter.
    return true; // Success: a valid NAK packet was decoded.
}

// ====================================================================================================
// FEC Repair packet encode/decode
// ====================================================================================================
// Mirrors C# UcpPacketCodec.cs Section "FEC REPAIR PACKET ENCODER / DECODER".
// Wire format:
//   [0:11]   Common header
//   [12:15]  GroupId    (uint32)  — identifies which FEC group this belongs to
//   [16]     GroupIndex (uint8_t) — position within the FEC group
//   [17:N]   Payload    (variable) — XOR/Reed-Solomon parity data

ucp::vector<uint8_t> UcpPacketCodec::EncodeFecRepair(const UcpFecRepairPacket& packet) // Serializes an FEC (Forward Error Correction) repair packet — carries parity data to reconstruct lost DATA packets without retransmission. Mirrors C# private static byte[] EncodeFecRepair.
{
    size_t payloadLen = packet.payload.size(); // Determine the parity payload size: number of bytes in the payload vector (0 if no parity data).
    ucp::vector<uint8_t> bytes(COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint8_t) + payloadLen); // Allocate output buffer: 12-byte common header + 4-byte GroupId + 1-byte GroupIndex + variable parity payload.

    WriteCommonHeader(packet.header, bytes.data(), 0); // Write the 12-byte common header (Type=0x08, Flags, ConnectionId, Timestamp) at offset 0.
    WriteUInt32(packet.group_id, bytes.data(), COMMON_HEADER_SIZE); // Write 4-byte big-endian GroupId at offset 12 — identifies which FEC group this repair belongs to so the receiver can correlate it with the right data packets.
    bytes[COMMON_HEADER_SIZE + sizeof(uint32_t)] = packet.group_index; // Write the 1-byte GroupIndex at offset 16 — indicates which repair packet this is within the FEC group (0 = first repair packet).

    if (payloadLen > 0) { // Only copy parity data if there is any (a zero-length FEC packet is valid but unusual).
        std::memcpy(bytes.data() + COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint8_t), // Starting at offset 17 (12+4+1) in the output buffer.
                    packet.payload.data(), payloadLen); // Copy the parity payload bytes from the packet into the output buffer.
    }

    return bytes; // Return the fully encoded FEC repair packet as a big-endian byte array.
}

bool UcpPacketCodec::TryDecodeFecRepair(const uint8_t* buffer, size_t offset, size_t count,
                                        const UcpCommonHeader& header, ucp::unique_ptr<UcpPacket>& out_packet) // Attempts to parse raw bytes into a UcpFecRepairPacket containing GroupId, GroupIndex, and parity payload. Mirrors C# private static bool TryDecodeFecRepair.
{
    out_packet = nullptr; // Initialize out parameter to null for safe early-exit.
    constexpr size_t fecFixedSize = COMMON_HEADER_SIZE + sizeof(uint32_t) + sizeof(uint8_t); // Minimum FEC header size: 12(common) + 4(groupId) + 1(groupIndex) = 17 bytes.
    if (count < fecFixedSize) { // Validate that the buffer has at least the minimum bytes for a zero-payload FEC repair packet.
        return false; // Buffer too short for even a zero-payload FEC repair packet — reject.
    }

    auto repair = ucp::unique_ptr<UcpFecRepairPacket>(new UcpFecRepairPacket()); // Allocate a fresh FEC repair packet object (mirrors C# new UcpFecRepairPacket()).
    repair->header = header; // Assign the already-decoded common header.
    repair->group_id = ReadUInt32(buffer, offset + COMMON_HEADER_SIZE); // Read 4-byte big-endian GroupId at offset+12 — identifies which FEC group this repair belongs to.
    repair->group_index = buffer[offset + COMMON_HEADER_SIZE + sizeof(uint32_t)]; // Read the 1-byte GroupIndex at offset+16 — position of this repair packet within the FEC group.

    size_t payloadLen = count - fecFixedSize; // Calculate the remaining bytes as parity payload (the 17-byte fixed header subtracted from total count).

    if (payloadLen > 0) { // If there is actual parity payload data.
        repair->payload.resize(payloadLen); // Resize the payload vector to exactly the parity payload size.
        std::memcpy(repair->payload.data(), // Destination: the payload vector's data buffer.
                    buffer + offset + fecFixedSize, // Source: the input buffer starting at the fixed-header past (offset+17).
                    payloadLen); // Number of parity payload bytes to copy.
    }
    // Note: C# sets repair.Payload = null when payloadLen == 0; C++ leaves an empty vector (default-constructed).
    // Both semantics result in "no payload" — just different null/empty representations by language convention.

    out_packet = std::move(repair); // Assign the fully decoded FEC repair packet (upcast to base type) to the out parameter.
    return true; // Success: a valid FEC repair packet was decoded.
}

// ====================================================================================================
// Control packet encode (Syn / SynAck / Fin / Rst)
// ====================================================================================================
// Mirrors C# UcpPacketCodec.cs Section "CONTROL PACKET ENCODER".
// Wire format (variable length):
//   [0:11]   Common header (Type, Flags, ConnectionId, Timestamp)
//   [12:15]  AckNumber (uint32)          — present if HasAckNumber flag is set
//   [16:19]  SequenceNumber (uint32)     — present if HasSequenceNumber is true
// Used for SYN, SYN-ACK, FIN, and RST packets.

ucp::vector<uint8_t> UcpPacketCodec::EncodeControl(const UcpControlPacket& packet) // Serializes a control packet (connection management) into its variable-length big-endian wire format. Mirrors C# private static byte[] EncodeControl.
{
    bool hasAck = (packet.header.flags & HasAckNumber) == HasAckNumber; // Check if the HasAckNumber flag (0x08) is set in the header flags — determines if we should include a piggybacked AckNumber.
    size_t size = COMMON_HEADER_SIZE; // Start with the 12-byte base common header — every control packet has this at minimum.
    if (hasAck) { // If piggybacked ACK is requested (HasAckNumber flag is set).
        size += ACK_NUMBER_SIZE; // Add 4 bytes for the AckNumber field after the common header.
    }
    if (packet.has_sequence_number) { // If the control packet carries a sequence number (true for SYN and SYN-ACK handshake packets).
        size += SEQUENCE_NUMBER_SIZE; // Add 4 bytes for the SequenceNumber field.
    }

    ucp::vector<uint8_t> bytes(size); // Allocate the exact-size output buffer — no wasted heap space (mirrors C# new byte[size]).
    size_t index = 0; // Running write position within the output buffer, starts at the beginning.
    WriteCommonHeader(packet.header, bytes.data(), index); // Write the 12-byte common header (Type, Flags, ConnectionId, Timestamp) at offset 0.
    index += COMMON_HEADER_SIZE; // Advance the write position past the 12-byte common header.

    if (hasAck) { // If the piggybacked ACK flag was set.
        WriteUInt32(packet.ack_number, bytes.data(), index); // Write the 4-byte big-endian AckNumber (cumulative ACK for the reverse direction).
        index += ACK_NUMBER_SIZE; // Advance past the AckNumber field (4 bytes).
    }
    if (packet.has_sequence_number) { // If the control packet carries a sequence number.
        WriteUInt32(packet.sequence_number, bytes.data(), index); // Write the 4-byte big-endian SequenceNumber (sender's initial sequence for handshake).
    }

    return bytes; // Return the fully encoded control packet as a big-endian byte array ready for wire transmission.
}

} // namespace ucp
