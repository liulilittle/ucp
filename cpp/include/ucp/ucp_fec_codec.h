#pragma once

/** @file ucp_fec_codec.h
 *  @brief Forward Error Correction (FEC) encoder/decoder over GF(256) — mirrors C# Ucp.Internal.FecCodec.
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
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

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
    /** @brief Result of a single packet recovery from an FEC repair operation. */
    struct RecoveredPacket {
        int slot = 0;                          //< Slot index within the FEC group (0..group_size-1).
        uint32_t sequence_number = 0;           //< Full 32-bit sequence number of the recovered packet.
        std::vector<uint8_t> payload;           //< Recovered payload bytes.
    };

    /** @brief Construct with a group size and a single repair packet per group.
     *  @param group_size  Number of data packets per FEC group (2..64, clamped). */
    explicit UcpFecCodec(int group_size);

    /** @brief Construct with a group size and explicit repair count.
     *  @param group_size    Number of data packets per FEC group (2..64, clamped).
     *  @param repair_count  Number of repair packets to generate per group (1..group_size, clamped). */
    UcpFecCodec(int group_size, int repair_count);

    /** @brief Number of repair packets generated per group.
     *  @return repair_count_ */
    int repair_count() const { return repair_count_; }

    /** @brief Try to add payload to the send buffer and generate one repair when the group is full.
     *  @param payload  Payload bytes of the next data packet in the group.
     *  @return The repair packet if the group is now full; std::nullopt otherwise. */
    std::optional<std::vector<uint8_t>> TryEncodeRepair(const std::vector<uint8_t>& payload);

    /** @brief Try to add payload and generate all repair packets when the group is full.
     *  @param payload  Payload bytes of the next data packet in the group.
     *  @return Vector of repair packets (one per repair_count_) if group is full; std::nullopt otherwise. */
    std::optional<std::vector<std::vector<uint8_t>>> TryEncodeRepairs(const std::vector<uint8_t>& payload);

    /** @brief Which slot (0..group_size-1) a given sequence number maps to.
     *  @param sequence_number  Full sequence number.
     *  @return Slot index = sequence_number % group_size_. */
    int GetSlot(uint32_t sequence_number) const;

    /** @brief Base sequence number of the FEC group that contains the given sequence.
     *  @param sequence_number  Any sequence number within the group.
     *  @return Round-down to the nearest multiple of group_size_. */
    uint32_t GetGroupBase(uint32_t sequence_number) const;

    /** @brief Feed a received data packet into the appropriate receive group buffer.
     *  @param sequence_number  Sequence number of the received packet.
     *  @param payload          Payload bytes of the received packet. */
    void FeedDataPacket(uint32_t sequence_number, const std::vector<uint8_t>& payload);

    /** @brief Attempt to recover one missing packet from a single repair (default repair index 0).
     *  @param repair     Received repair packet bytes.
     *  @param group_base Base sequence number of the FEC group.
     *  @return Recovered payload if successful; std::nullopt otherwise. */
    std::optional<std::vector<uint8_t>> TryRecoverFromRepair(const std::vector<uint8_t>& repair, uint32_t group_base);

    /** @brief Attempt to recover one missing packet, reporting which slot was recovered.
     *  @param repair       Received repair packet bytes.
     *  @param group_base   Base sequence number of the FEC group.
     *  @param missing_slot Output: the slot index that was recovered (-1 if none).
     *  @return Recovered payload if successful; std::nullopt otherwise. */
    std::optional<std::vector<uint8_t>> TryRecoverFromRepair(const std::vector<uint8_t>& repair, uint32_t group_base, int& missing_slot);

    /** @brief Attempt to recover one missing packet from a specific repair index.
     *  @param repair       Received repair packet bytes.
     *  @param group_base   Base sequence number of the FEC group.
     *  @param repair_index Which repair index within the group was received.
     *  @param missing_slot Output: the slot index that was recovered (-1 if none).
     *  @return Recovered payload if successful; std::nullopt otherwise. */
    std::optional<std::vector<uint8_t>> TryRecoverFromRepair(const std::vector<uint8_t>& repair, uint32_t group_base, int repair_index, int& missing_slot);

    /** @brief Attempt to recover one missing packet using previously stored repairs.
     *  @param sequence_number  Any sequence number within the target group.
     *  @param missing_slot     Output: the slot index that was recovered (-1 if none).
     *  @return Recovered payload if successful; std::nullopt otherwise. */
    std::optional<std::vector<uint8_t>> TryRecoverFromStoredRepair(uint32_t sequence_number, int& missing_slot);

    /** @brief Attempt to recover all possible missing packets within a group.
     *  @param repair       Received repair packet bytes.
     *  @param group_base   Base sequence number of the FEC group.
     *  @param repair_index Which repair index was received.
     *  @return Vector of all recovered packets (may be empty). */
    std::vector<RecoveredPacket> TryRecoverPacketsFromRepair(const std::vector<uint8_t>& repair, uint32_t group_base, int repair_index);

    /** @brief Attempt to recover all possible missing packets using stored repairs.
     *  @param sequence_number  Any sequence number within the target group.
     *  @return Vector of all recovered packets (may be empty). */
    std::vector<RecoveredPacket> TryRecoverPacketsFromStoredRepair(uint32_t sequence_number);

private:
    static constexpr int MAX_FEC_SLOT_LENGTH = 1200;  //< Maximum length of a single FEC data slot in bytes.
    static constexpr int GF_EXP_SIZE = 512;           //< Size of the pre-computed GF(2^8) exponent table (2*256 for safe indexing).

    // === GF(2^8) lookup tables (static, initialized at program start) ===

    static uint8_t gf_exp_[GF_EXP_SIZE];  //< GF(2^8) exponentiation table: gf_exp_[i] = a^i.
    static uint8_t gf_log_[256];          //< GF(2^8) logarithm table: gf_log_[x] = i where a^i = x.
    static bool tables_initialized_;      //< Set to true by static initializer lambda.

    // === GF(2^8) arithmetic helpers ===

    /** @brief Multiply two elements in GF(2^8) using log/exp tables. */
    static uint8_t GfMultiply(uint8_t left, uint8_t right);
    /** @brief Compute the multiplicative inverse in GF(2^8). */
    static uint8_t GfInverse(uint8_t value);
    /** @brief Raise a GF element to an integer power. */
    static uint8_t GfPower(uint8_t value, int exponent);
    /** @brief Get the Vandermonde coefficient for (repair_index, slot):
     *         coefficient = (repair_index + 1)^slot. */
    static uint8_t GetCoefficient(int repair_index, int slot);
    /** @brief Write a uint16_t in big-endian to buffer at offset. */
    static void WriteUInt16(uint16_t value, uint8_t* buffer, int offset);
    /** @brief Read a big-endian uint16_t from buffer at offset. */
    static uint16_t ReadUInt16(const uint8_t* buffer, int offset);

    // === Gaussian elimination over GF(2^8) ===

    /** @brief Solve the linear system matrix * x = rhs over GF(2^8) using Gauss-Jordan elimination.
     *  @param matrix  Square coefficient matrix (modified in place).
     *  @param rhs     Right-hand-side vectors (modified in place — becomes solution).
     *  @param size    Dimension of the square system.
     *  @return true if a unique solution was found; false if singular. */
    static bool TrySolve(std::vector<std::vector<uint8_t>>& matrix, std::vector<std::vector<uint8_t>>& rhs, int size);
    /** @brief Swap two rows in the coefficient matrix and RHS. */
    static void SwapRows(std::vector<std::vector<uint8_t>>& matrix, std::vector<std::vector<uint8_t>>& rhs, int left, int right, int size);
    /** @brief Multiply every element in a row by a constant coefficient. */
    static void MultiplyRow(std::vector<uint8_t>& row, uint8_t coefficient);
    /** @brief Add (coefficient * source_row) to target_row using GF XOR. */
    static void AddScaledRow(std::vector<uint8_t>& target, const std::vector<uint8_t>& source, uint8_t coefficient);

    // === Recovery logic ===

    /** @brief Attempt to recover all missing packets in a given FEC group.
     *  @param group_base  Base sequence number of the group.
     *  @return List of all packets recovered during this attempt. */
    std::vector<RecoveredPacket> TryRecoverGroup(uint32_t group_base);

    /** @brief Get or create the receive buffer for an FEC group.
     *  @param group_base  Base sequence number of the group.
     *  @return Reference to the vector of optional data slots for that group. */
    std::vector<std::optional<std::vector<uint8_t>>>& GetOrCreateReceiveGroup(uint32_t group_base);

    /** @brief Get or create the repair buffer for an FEC group.
     *  @param group_base  Base sequence number of the group.
     *  @return Reference to the map of repair_index -> repair_payload for that group. */
    std::map<int, std::vector<uint8_t>>& GetOrCreateRepairGroup(uint32_t group_base);

    /** @brief Clear the send buffer (reset all slots after a group is flushed). */
    void ClearSendBuffer();

    /** @brief Prune old receive groups to bound memory (keep at most 16 groups). */
    void PruneReceiveState();

    int group_size_;     //< Number of data packets per FEC group.
    int repair_count_;   //< Number of repair packets to generate per group.

    std::vector<std::optional<std::vector<uint8_t>>> send_buffer_;  //< Outbound data slots for the current group being built.
    int send_index_ = 0;  //< Next slot to fill in send_buffer_ (0..group_size_-1).

    std::unordered_map<uint32_t, std::vector<std::optional<std::vector<uint8_t>>>> recv_groups_;  //< Receive buffers keyed by group base sequence.
    std::unordered_map<uint32_t, std::map<int, std::vector<uint8_t>>> recv_repairs_;              //< Received repair packets keyed by group base sequence.
};

} // namespace ucp
