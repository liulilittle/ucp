/** @file ucp_fec_codec.cpp
 *  @brief Forward Error Correction encoder/decoder implementation — mirrors C# Ucp.Internal.FecCodec.
 *
 *  Uses a Vandermonde matrix over GF(2^8) with primitive polynomial
 *  x^8 + x^4 + x^3 + x^2 + 1 (0x11D).  Repair packets are XOR-linear
 *  combinations of data packets weighted by GF coefficients.  Missing
 *  packets are recovered via Gaussian elimination when enough repair
 *  and data packets are available for a given FEC group.
 */

#include "ucp/ucp_fec_codec.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace ucp {

// ====================================================================================================
// GF(2^8) lookup table initialization (static, runs at program start)
// ====================================================================================================

uint8_t UcpFecCodec::gf_exp_[UcpFecCodec::GF_EXP_SIZE] = {};
uint8_t UcpFecCodec::gf_log_[256] = {};
bool UcpFecCodec::tables_initialized_ = []() {
    // Build exponent and logarithm tables using generator a = 2
    int value = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp_[i] = static_cast<uint8_t>(value);
        gf_log_[value] = static_cast<uint8_t>(i);
        value <<= 1;
        if (value & 0x100) {
            value ^= 0x11d;  // Reduce modulo primitive polynomial x^8+x^4+x^3+x^2+1
        }
    }
    // Extend exponent table for safe double-indexing (i+j may be up to 510)
    for (int i = 255; i < GF_EXP_SIZE; i++) {
        gf_exp_[i] = gf_exp_[i - 255];
    }
    return true;
}();

// ====================================================================================================
// GF(2^8) arithmetic
// ====================================================================================================

uint8_t UcpFecCodec::GfMultiply(uint8_t left, uint8_t right) {
    if (left == 0 || right == 0) {
        return 0;
    }
    // a^(log(left) + log(right)) = left * right
    return gf_exp_[gf_log_[left] + gf_log_[right]];
}

uint8_t UcpFecCodec::GfInverse(uint8_t value) {
    if (value == 0) {
        throw std::invalid_argument("Cannot invert zero in GF(256).");
    }
    // a^(255) = 1, so inverse(a^k) = a^(255-k)
    return gf_exp_[255 - gf_log_[value]];
}

uint8_t UcpFecCodec::GfPower(uint8_t value, int exponent) {
    if (exponent == 0) {
        return 1;
    }
    if (value == 0) {
        return 0;
    }
    return gf_exp_[(gf_log_[value] * exponent) % 255];
}

uint8_t UcpFecCodec::GetCoefficient(int repair_index, int slot) {
    // Vandermonde coefficient: a_{repair,slot} = (repair_index+1)^slot
    return GfPower(static_cast<uint8_t>(repair_index + 1), slot);
}

void UcpFecCodec::WriteUInt16(uint16_t value, uint8_t* buffer, int offset) {
    buffer[offset] = static_cast<uint8_t>(value >> 8);
    buffer[offset + 1] = static_cast<uint8_t>(value);
}

uint16_t UcpFecCodec::ReadUInt16(const uint8_t* buffer, int offset) {
    return static_cast<uint16_t>((buffer[offset] << 8) | buffer[offset + 1]);
}

// ====================================================================================================
// Construction
// ====================================================================================================

UcpFecCodec::UcpFecCodec(int group_size)
    : UcpFecCodec(group_size, 1) {}

UcpFecCodec::UcpFecCodec(int group_size, int repair_count)
    : group_size_(std::max(2, std::min(group_size, 64))),
      repair_count_(std::max(1, std::min(repair_count, group_size_))),
      send_buffer_(static_cast<size_t>(group_size_)),
      send_index_(0) {}

// ====================================================================================================
// Slot/Group mapping
// ====================================================================================================

int UcpFecCodec::GetSlot(uint32_t sequence_number) const {
    return static_cast<int>(sequence_number % static_cast<uint32_t>(group_size_));
}

uint32_t UcpFecCodec::GetGroupBase(uint32_t sequence_number) const {
    return sequence_number / static_cast<uint32_t>(group_size_) * static_cast<uint32_t>(group_size_);
}

// ====================================================================================================
// Encoding
// ====================================================================================================

std::optional<std::vector<uint8_t>> UcpFecCodec::TryEncodeRepair(const std::vector<uint8_t>& payload) {
    auto repairs = TryEncodeRepairs(payload);
    if (!repairs || repairs->empty()) {
        return std::nullopt;
    }
    return (*repairs)[0];
}

std::optional<std::vector<std::vector<uint8_t>>> UcpFecCodec::TryEncodeRepairs(const std::vector<uint8_t>& payload) {
    // Add this payload to the send buffer ring
    send_buffer_[send_index_] = payload;
    send_index_++;
    if (send_index_ < group_size_) {
        return std::nullopt;  // Group not yet full
    }
    send_index_ = 0;  // Reset for next group

    // Find the maximum slot length (padded slots are treated as having length 0 and skipped)
    int max_len = 0;
    for (int i = 0; i < group_size_; i++) {
        const auto& p = send_buffer_[i];
        if (p && static_cast<int>(p->size()) > max_len) {
            max_len = static_cast<int>(p->size());
        }
    }

    if (max_len == 0) {
        ClearSendBuffer();
        return std::nullopt;
    }

    // Build length table (2 bytes per slot) followed by XOR'd payload
    int length_table_bytes = group_size_ * 2;
    std::vector<std::vector<uint8_t>> repairs;
    repairs.reserve(static_cast<size_t>(repair_count_));

    for (int repair_index = 0; repair_index < repair_count_; repair_index++) {
        std::vector<uint8_t> repair(static_cast<size_t>(length_table_bytes + max_len), 0);
        for (int slot = 0; slot < group_size_; slot++) {
            const auto& p = send_buffer_[slot];
            if (!p) {
                continue;
            }
            WriteUInt16(static_cast<uint16_t>(p->size()), repair.data(), slot * 2);
            uint8_t coefficient = GetCoefficient(repair_index, slot);
            int len = std::min(static_cast<int>(p->size()), max_len);
            for (int j = 0; j < len; j++) {
                repair[length_table_bytes + j] ^= GfMultiply(coefficient, (*p)[j]);
            }
        }
        repairs.push_back(std::move(repair));
    }

    ClearSendBuffer();
    return repairs;
}

// ====================================================================================================
// Receive side
// ====================================================================================================

void UcpFecCodec::FeedDataPacket(uint32_t sequence_number, const std::vector<uint8_t>& payload) {
    uint32_t group_base = GetGroupBase(sequence_number);
    auto& group = GetOrCreateReceiveGroup(group_base);
    int slot = GetSlot(sequence_number);
    if (slot >= 0 && slot < group_size_) {
        group[slot] = payload;
    }
    PruneReceiveState();
}

// ====================================================================================================
// Recovery from repair (public overloads)
// ====================================================================================================

std::optional<std::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(
        const std::vector<uint8_t>& repair, uint32_t group_base) {
    int missing_slot;
    return TryRecoverFromRepair(repair, group_base, missing_slot);
}

std::optional<std::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(
        const std::vector<uint8_t>& repair, uint32_t group_base, int& missing_slot) {
    return TryRecoverFromRepair(repair, group_base, 0, missing_slot);
}

std::optional<std::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(
        const std::vector<uint8_t>& repair, uint32_t group_base, int repair_index, int& missing_slot) {
    missing_slot = -1;
    auto recovered = TryRecoverPacketsFromRepair(repair, group_base, repair_index);
    if (recovered.empty()) {
        return std::nullopt;
    }
    missing_slot = recovered[0].slot;
    return recovered[0].payload;
}

std::optional<std::vector<uint8_t>> UcpFecCodec::TryRecoverFromStoredRepair(
        uint32_t sequence_number, int& missing_slot) {
    missing_slot = -1;
    auto recovered = TryRecoverPacketsFromStoredRepair(sequence_number);
    if (recovered.empty()) {
        return std::nullopt;
    }
    missing_slot = recovered[0].slot;
    return recovered[0].payload;
}

std::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverPacketsFromRepair(
        const std::vector<uint8_t>& repair, uint32_t group_base, int repair_index) {
    if (repair.empty()) {
        return {};
    }
    // Store this repair in the per-group repair map, then attempt recovery
    auto& repairs = GetOrCreateRepairGroup(group_base);
    repairs[repair_index] = repair;
    auto recovered = TryRecoverGroup(group_base);
    PruneReceiveState();
    return recovered;
}

std::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverPacketsFromStoredRepair(
        uint32_t sequence_number) {
    uint32_t group_base = GetGroupBase(sequence_number);
    if (recv_repairs_.count(group_base) == 0) {
        return {};
    }
    return TryRecoverGroup(group_base);
}

// ====================================================================================================
// Core recovery via Gaussian elimination
// ====================================================================================================

std::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverGroup(uint32_t group_base) {
    std::vector<RecoveredPacket> recovered_packets;
    auto& group = GetOrCreateReceiveGroup(group_base);

    // Need enough repair packets
    auto repair_it = recv_repairs_.find(group_base);
    if (repair_it == recv_repairs_.end() || repair_it->second.empty()) {
        return recovered_packets;
    }
    auto& repairs = repair_it->second;

    // === Identify missing slots ===
    std::vector<int> missing_slots;
    for (int i = 0; i < group_size_; i++) {
        if (!group[i]) {
            missing_slots.push_back(i);
        }
    }

    if (missing_slots.empty()) {
        // All slots already received — no recovery needed, clean up repairs
        recv_repairs_.erase(group_base);
        return recovered_packets;
    }

    // Need at least as many repairs as missing slots
    if (static_cast<int>(repairs.size()) < static_cast<int>(missing_slots.size())) {
        return recovered_packets;
    }

    // === Build the linear system (matrix * x = rhs) ===
    int length_table_bytes = group_size_ * 2;
    int missing_count = static_cast<int>(missing_slots.size());

    // Select enough repairs that look complete (size >= length_table_bytes)
    std::vector<std::pair<int, const std::vector<uint8_t>*>> selected_repairs;
    selected_repairs.reserve(static_cast<size_t>(missing_count));
    for (const auto& pair : repairs) {
        if (static_cast<int>(pair.second.size()) >= length_table_bytes &&
                static_cast<int>(selected_repairs.size()) < missing_count) {
            selected_repairs.emplace_back(pair.first, &pair.second);
        }
    }

    if (static_cast<int>(selected_repairs.size()) < missing_count) {
        return recovered_packets;
    }

    // Determine max data length from selected repairs
    int max_len = static_cast<int>(selected_repairs[0].second->size()) - length_table_bytes;
    for (size_t i = 1; i < selected_repairs.size(); i++) {
        max_len = std::min(max_len,
                static_cast<int>(selected_repairs[i].second->size()) - length_table_bytes);
    }

    // Allocate coefficient matrix and RHS vectors
    std::vector<std::vector<uint8_t>> matrix(static_cast<size_t>(missing_count),
            std::vector<uint8_t>(static_cast<size_t>(missing_count), 0));
    std::vector<std::vector<uint8_t>> rhs(static_cast<size_t>(missing_count));

    // === Subtract known packets from each repair to get RHS ===
    for (int row = 0; row < missing_count; row++) {
        int repair_index = selected_repairs[row].first;
        const auto& repair = *selected_repairs[row].second;

        // RHS starts as the repair payload
        rhs[row].assign(repair.begin() + length_table_bytes,
                repair.begin() + length_table_bytes + max_len);

        // Subtract known (non-missing) slots:  rhs -= coefficient * known_payload
        for (int known_slot = 0; known_slot < group_size_; known_slot++) {
            const auto& known = group[known_slot];
            if (!known) {
                continue;
            }
            uint8_t coefficient = GetCoefficient(repair_index, known_slot);
            int len = std::min(static_cast<int>(known->size()), max_len);
            for (int j = 0; j < len; j++) {
                rhs[row][j] ^= GfMultiply(coefficient, (*known)[j]);
            }
        }

        // Fill coefficient matrix row with Vandermonde coefficients for missing slots
        for (int col = 0; col < missing_count; col++) {
            matrix[row][col] = GetCoefficient(repair_index, missing_slots[col]);
        }
    }

    // === Solve using Gauss-Jordan elimination over GF(2^8) ===
    if (!TrySolve(matrix, rhs, missing_count)) {
        return recovered_packets;
    }

    // === Extract recovered payloads using the length table ===
    const auto& length_table = *selected_repairs[0].second;

    int total_slot_lengths = 0;
    for (int slot = 0; slot < group_size_; slot++) {
        int slot_length = ReadUInt16(length_table.data(), slot * 2);
        if (slot_length < 0 || slot_length > MAX_FEC_SLOT_LENGTH) {
            return recovered_packets;
        }
        total_slot_lengths += slot_length;
    }
    if (total_slot_lengths > group_size_ * MAX_FEC_SLOT_LENGTH) {
        return recovered_packets;
    }

    for (int i = 0; i < missing_count; i++) {
        int slot = missing_slots[i];
        int missing_length = ReadUInt16(length_table.data(), slot * 2);
        if (missing_length < 0 || missing_length > max_len) {
            continue;
        }

        std::vector<uint8_t> payload(rhs[i].begin(), rhs[i].begin() + missing_length);
        group[slot] = payload;  // Store recovered packet in the receive buffer
        recovered_packets.push_back(
                {slot, group_base + static_cast<uint32_t>(slot), std::move(payload)});
    }

    // Clean up repairs if we recovered something
    if (!recovered_packets.empty()) {
        recv_repairs_.erase(group_base);
    }

    return recovered_packets;
}

// ====================================================================================================
// Gaussian elimination helpers
// ====================================================================================================

bool UcpFecCodec::TrySolve(std::vector<std::vector<uint8_t>>& matrix,
        std::vector<std::vector<uint8_t>>& rhs, int size) {
    for (int col = 0; col < size; col++) {
        // === Find pivot row ===
        int pivot = col;
        while (pivot < size && matrix[pivot][col] == 0) {
            pivot++;
        }

        if (pivot == size) {
            return false;  // Singular matrix — no unique solution
        }

        if (pivot != col) {
            SwapRows(matrix, rhs, pivot, col, size);
        }

        // === Normalize pivot row ===
        uint8_t inverse = GfInverse(matrix[col][col]);
        if (inverse != 1) {
            for (int c = col; c < size; c++) {
                matrix[col][c] = GfMultiply(matrix[col][c], inverse);
            }
            MultiplyRow(rhs[col], inverse);
        }

        // === Eliminate all other rows ===
        for (int row = 0; row < size; row++) {
            if (row == col) {
                continue;
            }
            uint8_t factor = matrix[row][col];
            if (factor == 0) {
                continue;
            }
            for (int c = col; c < size; c++) {
                matrix[row][c] ^= GfMultiply(factor, matrix[col][c]);
            }
            AddScaledRow(rhs[row], rhs[col], factor);
        }
    }

    return true;
}

void UcpFecCodec::SwapRows(std::vector<std::vector<uint8_t>>& matrix,
        std::vector<std::vector<uint8_t>>& rhs, int left, int right, int size) {
    for (int col = 0; col < size; col++) {
        std::swap(matrix[left][col], matrix[right][col]);
    }
    std::swap(rhs[left], rhs[right]);
}

void UcpFecCodec::MultiplyRow(std::vector<uint8_t>& row, uint8_t coefficient) {
    for (size_t i = 0; i < row.size(); i++) {
        row[i] = GfMultiply(row[i], coefficient);
    }
}

void UcpFecCodec::AddScaledRow(std::vector<uint8_t>& target, const std::vector<uint8_t>& source,
        uint8_t coefficient) {
    for (size_t i = 0; i < target.size(); i++) {
        target[i] ^= GfMultiply(coefficient, source[i]);
    }
}

// ====================================================================================================
// Buffer management
// ====================================================================================================

std::vector<std::optional<std::vector<uint8_t>>>& UcpFecCodec::GetOrCreateReceiveGroup(
        uint32_t group_base) {
    auto [it, inserted] = recv_groups_.try_emplace(group_base);
    if (inserted) {
        it->second.resize(static_cast<size_t>(group_size_));
    }
    return it->second;
}

std::map<int, std::vector<uint8_t>>& UcpFecCodec::GetOrCreateRepairGroup(uint32_t group_base) {
    return recv_repairs_.try_emplace(group_base).first->second;
}

void UcpFecCodec::ClearSendBuffer() {
    for (int i = 0; i < group_size_; i++) {
        send_buffer_[i].reset();
    }
}

void UcpFecCodec::PruneReceiveState() {
    // Limit receive groups to 16 (drop oldest)
    while (recv_groups_.size() > 16) {
        uint32_t oldest = std::numeric_limits<uint32_t>::max();
        for (const auto& pair : recv_groups_) {
            if (pair.first < oldest) {
                oldest = pair.first;
            }
        }
        recv_groups_.erase(oldest);
        recv_repairs_.erase(oldest);
    }

    // Also limit stray repairs
    while (recv_repairs_.size() > 16) {
        uint32_t oldest = std::numeric_limits<uint32_t>::max();
        for (const auto& pair : recv_repairs_) {
            if (pair.first < oldest) {
                oldest = pair.first;
            }
        }
        recv_repairs_.erase(oldest);
    }
}

} // namespace ucp
