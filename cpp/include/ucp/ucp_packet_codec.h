#pragma once

/**
 * MIT License
 *
 * Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file ucp_packet_codec.h
 *  @brief Wire-protocol encoder/decoder for UCP packets -- mirrors C# Ucp.Internal.PacketCodec.
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
#include "ucp/ucp_constants.h"
#include <cstdint>
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

namespace ucp {

constexpr size_t SESSION_KEY_SIZE = 8;

/** @brief Static packet encoder/decoder for big-endian UCP wire format.
 *
 *  All methods are static because encoding requires no mutable state.
 *  Decoded packets are returned via ucp::shared_ptr<UcpPacket>; the caller
 *  should dynamic_cast to the concrete type based on header.type.
 *
 *  Mirrors the internal static class UcpPacketCodec in C# UcpPacketCodec.cs.
 */
class UcpPacketCodec {
  public:
    UcpPacketCodec() = delete;

    /** @brief Encode a concrete UcpPacket into a wire-format byte buffer.
     *  @param  packet  The typed packet to encode (Data, Ack, Nak, FecRepair, or Control).
     *  @return Big-endian byte buffer ready for transmission. */
    static ucp::vector<uint8_t> Encode(const UcpPacket& packet) noexcept;

    /** @brief Attempt to decode a byte buffer into a UcpPacket.
     *  @param      buffer      Pointer to the start of the datagram.
     *  @param      offset      Byte offset within buffer where the packet begins (typically 0).
     *  @param      count       Number of bytes available from offset.
     *  @param[out] out_packet  On success, set to a shared_ptr<UcpPacket>; caller should dynamic_cast.
     *  @return True if decoding succeeded, false if the buffer is incomplete or invalid. */
    static bool TryDecode(const uint8_t* buffer, size_t offset, size_t count, ucp::shared_ptr<UcpPacket>& out_packet) noexcept;

  private:
    /** @brief Read a big-endian uint16_t from buffer at offset.
     *  @param buffer  Source buffer.
     *  @param offset  Byte offset into buffer.
     *  @return Decoded uint16_t in host byte order. */
    static uint16_t ReadUInt16(const uint8_t* buffer, size_t offset) noexcept;
    /** @brief Write a big-endian uint16_t to buffer at offset.
     *  @param value   Value to encode.
     *  @param buffer  Destination buffer.
     *  @param offset  Byte offset into buffer. */
    static void WriteUInt16(uint16_t value, uint8_t* buffer, size_t offset) noexcept;
    /** @brief Read a big-endian uint32_t from buffer at offset.
     *  @param buffer  Source buffer.
     *  @param offset  Byte offset into buffer.
     *  @return Decoded uint32_t in host byte order. */
    static uint32_t ReadUInt32(const uint8_t* buffer, size_t offset) noexcept;
    /** @brief Write a big-endian uint32_t to buffer at offset.
     *  @param value   Value to encode.
     *  @param buffer  Destination buffer.
     *  @param offset  Byte offset into buffer. */
    static void WriteUInt32(uint32_t value, uint8_t* buffer, size_t offset) noexcept;
    /** @brief Read a big-endian uint48 from buffer at offset (stored as uint64_t with upper 16 bits zeroed).
     *  @param buffer  Source buffer.
     *  @param offset  Byte offset into buffer.
     *  @return Decoded uint48 in host byte order, masked to 48 bits. */
    static uint64_t ReadUInt48(const uint8_t* buffer, size_t offset) noexcept;
    /** @brief Write the lower 48 bits of a uint64_t in big-endian to buffer at offset.
     *  @param value   Value to encode (upper 16 bits ignored).
     *  @param buffer  Destination buffer.
     *  @param offset  Byte offset into buffer. */
    static void WriteUInt48(uint64_t value, uint8_t* buffer, size_t offset) noexcept;
    /** @brief Read a big-endian uint64_t from buffer at offset.
     *  @param buffer  Source buffer.
     *  @param offset  Byte offset into buffer.
     *  @return Decoded uint64_t in host byte order. */
    static uint64_t ReadUInt64(const uint8_t* buffer, size_t offset) noexcept;
    /** @brief Write a big-endian uint64_t to buffer at offset.
     *  @param value   Value to encode.
     *  @param buffer  Destination buffer.
     *  @param offset  Byte offset into buffer. */
    static void WriteUInt64(uint64_t value, uint8_t* buffer, size_t offset) noexcept;

    /** @brief Decode the 12-byte common header from the buffer.
     *  @return True if count >= 12 and parsing succeeded. */
    static bool TryReadCommonHeader(const uint8_t* buffer, size_t offset, size_t count, UcpCommonHeader& header) noexcept;

    static void WriteCommonHeader(const UcpCommonHeader& header, uint8_t* buffer, size_t offset) noexcept;

    static ucp::vector<uint8_t> EncodeData(const UcpDataPacket& packet) noexcept;
    static ucp::vector<uint8_t> EncodeAck(const UcpAckPacket& packet) noexcept;
    static ucp::vector<uint8_t> EncodeNak(const UcpNakPacket& packet) noexcept;
    static ucp::vector<uint8_t> EncodeFecRepair(const UcpFecRepairPacket& packet) noexcept;
    static ucp::vector<uint8_t> EncodeControl(const UcpControlPacket& packet) noexcept;

    static bool TryDecodeData(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header,
                              ucp::shared_ptr<UcpPacket>& out_packet) noexcept;
    static bool TryDecodeAck(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header,
                             ucp::shared_ptr<UcpPacket>& out_packet) noexcept;
    static bool TryDecodeNak(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header,
                             ucp::shared_ptr<UcpPacket>& out_packet) noexcept;
    static bool TryDecodeFecRepair(const uint8_t* buffer, size_t offset, size_t count, const UcpCommonHeader& header,
                                   ucp::shared_ptr<UcpPacket>& out_packet) noexcept;
};

} // namespace ucp
