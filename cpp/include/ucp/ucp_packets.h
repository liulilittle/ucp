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

/** @file ucp_packets.h
 *  @brief Packet type hierarchy for UCP -- mirrors C# Ucp.Internal.Packets.
 *
 *  Defines the common on-wire header and the five concrete packet types
 *  (Data, Ack, Nak, Control, FecRepair).  All packets derive from UcpPacket
 *  which holds the mandatory UcpCommonHeader.  Packet encoding/decoding is
 *  handled by UcpPacketCodec.
 */

#include "ucp_constants.h"
#include "ucp_enums.h"
#include <cstdint>
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

namespace ucp {

struct SackBlock {
    uint32_t Start;
    uint32_t End;
};

struct UcpCommonHeader {
    UcpPacketType type;
    UcpPacketFlags flags;
    uint32_t connection_id;
    int64_t timestamp;
};

/** @brief Abstract base class for all UCP packet types.
 *
 *  Every concrete packet holds a UcpCommonHeader and optionally additional
 *  typed fields.  Use dynamic_cast or the type tag to determine the concrete
 *  packet class after decoding.
 */
class UcpPacket {
  public:
    UcpPacket() noexcept = default;

    virtual ~UcpPacket() noexcept = default;

    UcpPacket(const UcpPacket&) noexcept = default;
    UcpPacket& operator=(const UcpPacket&) noexcept = default;
    UcpPacket(UcpPacket&&) noexcept = default;
    UcpPacket& operator=(UcpPacket&&) noexcept = default;

    UcpCommonHeader header;
};

/** @brief Control packet for handshake (Syn, SynAck) and connection teardown (Fin, Rst).
 *
 *  Optionally carries a sequence number (for Syn/SynAck) and a piggybacked
 *  cumulative ack number (when HasAckNumber flag is set).
 */
class UcpControlPacket final : public UcpPacket {
  public:
    bool has_sequence_number = false;
    uint32_t sequence_number = 0;
    uint32_t ack_number = 0;
    uint64_t session_key = 0;
};

class UcpDataPacket final : public UcpPacket {
  public:
    uint32_t sequence_number = 0;
    uint16_t fragment_total = 0;
    uint16_t fragment_index = 0;
    ucp::vector<uint8_t> payload;
    uint32_t ack_number = 0;
    ucp::vector<SackBlock> sack_blocks;
    uint32_t window_size = 0;
    int64_t echo_timestamp = 0;
};

class UcpAckPacket final : public UcpPacket {
  public:
    uint32_t ack_number = 0;
    ucp::vector<SackBlock> sack_blocks;
    uint32_t window_size = 0;
    int64_t echo_timestamp = 0;
};

class UcpNakPacket final : public UcpPacket {
  public:
    uint32_t ack_number = 0;
    ucp::vector<uint32_t> missing_sequences;
};

class UcpFecRepairPacket final : public UcpPacket {
  public:
    uint32_t group_id = 0;
    uint8_t group_index = 0;
    ucp::vector<uint8_t> payload;
};

} // namespace ucp
