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

/** @file ucp_fec_codec.h
 *  @brief Forward Error Correction (FEC) encoder/decoder over GF(256) -- mirrors C# Ucp.Internal.FecCodec.
 *
 *  Implements XOR-based FEC using Vandermonde matrices over GF(2^8).  The
 *  codec groups outbound data packets into fixed-size groups, computes one
 *  or more repair packets per group, and uses Gaussian elimination to recover
 *  up to repair_count missing data packets per group.
 *
 *  Galois field operations use pre-computed exponent and logarithm tables
 *  with the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
 */

#include <cstdint>
#include "ucp/ucp_vector.h"

namespace ucp {

/** @brief Reed-Solomon-inspired FEC codec operating over GF(256).
 *
 *  Data packets are partitioned into groups of group_size_ packets.  When a
 *  group is full, repair_count_ repair packets are generated (each is an XOR
 *  of all data slots weighted by coefficients from a Vandermonde matrix).
 *  On the receiver side, up to repair_count_ missing packets in a group can
 *  be recovered via Gaussian elimination when enough repair and data packets
 *  have arrived.
 */
class UcpFecCodec {
  public:
    struct RecoveredPacket {
        int slot = 0;
        uint32_t sequence_number = 0;
        ucp::vector<uint8_t> payload;
    };

    /** @brief Construct with a group size and a single repair packet per group (default FEC redundancy of 1).
     *  @param group_size  Number of data packets per FEC group (2..64, clamped). */
    explicit UcpFecCodec(int group_size) noexcept;

    /** @brief Construct with a group size and explicit repair count.
     *  @param group_size    Number of data packets per FEC group (2..64, clamped).
     *  @param repair_count  Number of repair packets to generate per group (1..group_size, clamped). */
    UcpFecCodec(int group_size, int repair_count) noexcept;

    UcpFecCodec(const UcpFecCodec&) = delete;

    UcpFecCodec& operator=(const UcpFecCodec&) = delete;
    UcpFecCodec(UcpFecCodec&&) = delete;
    UcpFecCodec& operator=(UcpFecCodec&&) = delete;

    /** @brief Number of repair packets generated per group.
     *  @return repair_count_ */
    int repair_count() const noexcept { return repair_count_; }

    /** @brief Try to add payload to the send buffer and generate one repair when the group is full.
     *  @param  payload  Payload bytes of the next data packet in the group.
     *  @return The repair packet if the group is now full; nullopt otherwise. */
    ucp::optional<ucp::vector<uint8_t>> TryEncodeRepair(const ucp::vector<uint8_t>& payload) noexcept;

    /** @brief Try to add a sequence-numbered payload and generate one repair when the group is full.
     *  @param  sequence_number  Data packet sequence number.
     *  @param  payload          Payload bytes of the data packet.
     *  @return The repair packet if the group is now full; nullopt otherwise. */
    ucp::optional<ucp::vector<uint8_t>> TryEncodeRepair(uint32_t sequence_number, const ucp::vector<uint8_t>& payload) noexcept;

    /** @brief Try to add payload and generate all repair packets when the group is full.
     *  @param  payload  Payload bytes of the next data packet in the group.
     *  @return Vector of repair packets (one per repair_count_) if group is full; nullopt otherwise. */
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> TryEncodeRepairs(const ucp::vector<uint8_t>& payload) noexcept;

    /** @brief Try to add a sequence-numbered payload and generate all repair packets when the group is full.
     *  @param  sequence_number  Data packet sequence number.
     *  @param  payload          Payload bytes of the data packet.
     *  @return Vector of repair packets if group is full; nullopt otherwise. */
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> TryEncodeRepairs(uint32_t sequence_number,
                                                                      const ucp::vector<uint8_t>& payload) noexcept;

    /** @brief Which slot (0..group_size-1) a given sequence number maps to.
     *  @param  sequence_number  Full sequence number.
     *  @return Slot index = sequence_number % group_size_. */
    int GetSlot(uint32_t sequence_number) const noexcept;

    /** @brief Base sequence number of the FEC group that contains the given sequence.
     *  @param  sequence_number  Any sequence number within the group.
     *  @return Round-down to the nearest multiple of group_size_. */
    uint32_t GetGroupBase(uint32_t sequence_number) const noexcept;

    /** @brief Feed a received data packet into the appropriate receive group buffer.
     *  @param sequence_number  Sequence number of the received packet.
     *  @param payload          Payload bytes of the received packet. */
    void FeedDataPacket(uint32_t sequence_number, const ucp::vector<uint8_t>& payload) noexcept;

    /** @brief Attempt to recover one missing packet from a single repair (default repair index 0).
     *  @param  repair      Received repair packet bytes.
     *  @param  group_base  Base sequence number of the FEC group.
     *  @return Recovered payload if successful; nullopt otherwise. */
    ucp::optional<ucp::vector<uint8_t>> TryRecoverFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base) noexcept;

    /** @brief Attempt to recover one missing packet, reporting which slot was recovered.
     *  @param  repair        Received repair packet bytes.
     *  @param  group_base    Base sequence number of the FEC group.
     *  @param  missing_slot  Output: the slot index that was recovered (-1 if none).
     *  @return Recovered payload if successful; nullopt otherwise. */
    ucp::optional<ucp::vector<uint8_t>> TryRecoverFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base,
                                                             int& missing_slot) noexcept;

    /** @brief Attempt to recover one missing packet from a specific repair index.
     *  @param  repair        Received repair packet bytes.
     *  @param  group_base    Base sequence number of the FEC group.
     *  @param  repair_index  Which repair index within the group was received.
     *  @param  missing_slot  Output: the slot index that was recovered (-1 if none).
     *  @return Recovered payload if successful; nullopt otherwise. */
    ucp::optional<ucp::vector<uint8_t>> TryRecoverFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base, int repair_index,
                                                             int& missing_slot) noexcept;

    /** @brief Attempt to recover one missing packet using previously stored repairs.
     *  @param  sequence_number  Any sequence number within the target group.
     *  @param  missing_slot     Output: the slot index that was recovered (-1 if none).
     *  @return Recovered payload if successful; nullopt otherwise. */
    ucp::optional<ucp::vector<uint8_t>> TryRecoverFromStoredRepair(uint32_t sequence_number, int& missing_slot) noexcept;

    /** @brief Attempt to recover all possible missing packets within a group.
     *  @param  repair        Received repair packet bytes.
     *  @param  group_base    Base sequence number of the FEC group.
     *  @param  repair_index  Which repair index was received.
     *  @return Vector of all recovered packets (may be empty). */
    ucp::vector<RecoveredPacket> TryRecoverPacketsFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base,
                                                             int repair_index) noexcept;

    /** @brief Attempt to recover all possible missing packets using stored repairs.
     *  @param  sequence_number  Any sequence number within the target group.
     *  @return Vector of all recovered packets (may be empty). */
    ucp::vector<RecoveredPacket> TryRecoverPacketsFromStoredRepair(uint32_t sequence_number) noexcept;

  private:
    static constexpr int MAX_FEC_SLOT_LENGTH = 1200;
    static constexpr int GF_EXP_SIZE = 512;

    static uint8_t gf_exp_[GF_EXP_SIZE];
    static uint8_t gf_log_[256];
    static bool tables_initialized_;

    /** @brief Multiply two elements in GF(2^8) using log/exp tables.
     *  @param  left   First element.
     *  @param  right  Second element.
     *  @return left * right in GF(2^8). */
    static uint8_t GfMultiply(uint8_t left, uint8_t right) noexcept;

    /** @brief Compute the multiplicative inverse in GF(2^8).
     *  This function is noexcept -- it performs only table lookups and
     *  arithmetic on precomputed GF(2^8) exponent/log tables.
     *  @param  value  Element to invert.
     *  @return Multiplicative inverse. */
    static uint8_t GfInverse(uint8_t value) noexcept;

    /** @brief Raise a GF element to an integer power.
     *  @param  value     Base element.
     *  @param  exponent  Integer exponent.
     *  @return value^exponent in GF(2^8). */
    static uint8_t GfPower(uint8_t value, int exponent) noexcept;

    /** @brief Get the Vandermonde coefficient for (repair_index, slot).
     *  @param  repair_index  Repair index.
     *  @param  slot          Data slot index.
     *  @return (repair_index + 1)^slot in GF(2^8). */
    static uint8_t GetCoefficient(int repair_index, int slot) noexcept;

    /** @brief Write a uint16_t in big-endian to buffer at offset.
     *  @param value   Value to write.
     *  @param buffer  Destination buffer.
     *  @param offset  Byte offset. */
    static void WriteUInt16(uint16_t value, uint8_t* buffer, int offset) noexcept;

    /** @brief Read a big-endian uint16_t from buffer at offset.
     *  @param  buffer  Source buffer.
     *  @param  offset  Byte offset.
     *  @return Decoded uint16_t. */
    static uint16_t ReadUInt16(const uint8_t* buffer, int offset) noexcept;

    /** @brief Solve the linear system matrix * x = rhs over GF(2^8) using Gauss-Jordan elimination.
     *  @param      matrix  Square coefficient matrix (modified in place to identity).
     *  @param      rhs     Right-hand-side vectors (modified in place -- becomes solution x).
     *  @param      size    Dimension of the square system.
     *  @return True if a unique solution was found; false if singular. */
    static bool TrySolve(ucp::vector<ucp::vector<uint8_t>>& matrix, ucp::vector<ucp::vector<uint8_t>>& rhs, int size) noexcept;

    /** @brief Swap two rows in the coefficient matrix and RHS.
     *  @param matrix  Coefficient matrix.
     *  @param rhs     Right-hand-side vectors.
     *  @param left    First row index.
     *  @param right   Second row index.
     *  @param size    System dimension. */
    static void SwapRows(ucp::vector<ucp::vector<uint8_t>>& matrix, ucp::vector<ucp::vector<uint8_t>>& rhs, int left, int right,
                         int size) noexcept;

    /** @brief Multiply every element in a row by a constant coefficient in GF(2^8).
     *  @param row           Row vector.
     *  @param coefficient   Multiplier. */
    static void MultiplyRow(ucp::vector<uint8_t>& row, uint8_t coefficient) noexcept;

    /** @brief Add (coefficient * source_row) to target_row using GF XOR.
     *  @param target       Target row (modified).
     *  @param source       Source row.
     *  @param coefficient  Scalar multiplier. */
    static void AddScaledRow(ucp::vector<uint8_t>& target, const ucp::vector<uint8_t>& source, uint8_t coefficient) noexcept;

    /** @brief Attempt to recover all missing packets in a given FEC group.
     *  @param  group_base  Base sequence number of the group.
     *  @return List of all packets recovered during this attempt. */
    ucp::vector<RecoveredPacket> TryRecoverGroup(uint32_t group_base) noexcept;

    /** @brief Get or create the receive buffer for an FEC group.
     *  @param  group_base  Base sequence number of the group.
     *  @return Reference to the vector of optional data slots for that group. */
    ucp::vector<ucp::optional<ucp::vector<uint8_t>>>& GetOrCreateReceiveGroup(uint32_t group_base) noexcept;

    /** @brief Get or create the repair buffer for an FEC group.
     *  @param  group_base  Base sequence number of the group.
     *  @return Reference to the map of repair_index -> repair_payload for that group. */
    ucp::map<int, ucp::vector<uint8_t>>& GetOrCreateRepairGroup(uint32_t group_base) noexcept;

    /** @brief Store a payload at an explicit FEC slot and emit repairs when full.
     *  @param slot Slot index in the current FEC group.
     *  @param payload Payload bytes to protect.
     *  @return Repair packets if the group is full; nullopt otherwise. */
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> TryEncodeRepairsAtSlot(int slot, const ucp::vector<uint8_t>& payload) noexcept;

    /** @brief Generate repair packets from a complete FEC data group.
     *  @param group Data slots for one sequence-aligned FEC group.
     *  @return Repair packets if the group has payload data; nullopt otherwise. */
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>>
    EncodeRepairsFromGroup(const ucp::vector<ucp::optional<ucp::vector<uint8_t>>>& group) noexcept;

    void ClearSendBuffer() noexcept;

    void PruneSendState() noexcept;

    void PruneReceiveState() noexcept;

    int group_size_;
    int repair_count_;

    ucp::vector<ucp::optional<ucp::vector<uint8_t>>> send_buffer_;
    int send_count_ = 0;

    ucp::unordered_map<uint32_t, ucp::vector<ucp::optional<ucp::vector<uint8_t>>>> send_groups_;
    ucp::unordered_map<uint32_t, int> send_group_counts_;

    ucp::unordered_map<uint32_t, ucp::vector<ucp::optional<ucp::vector<uint8_t>>>> recv_groups_;
    ucp::unordered_map<uint32_t, ucp::map<int, ucp::vector<uint8_t>>> recv_repairs_;
};

} // namespace ucp
