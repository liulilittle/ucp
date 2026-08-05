/** @file ucp_fec_codec.cpp
 *  @brief Forward Error Correction encoder/decoder implementation -- mirrors C# Ucp.Internal.FecCodec.
 *
 *  Uses a Vandermonde matrix over GF(2^8) with primitive polynomial
 *  x^8 + x^4 + x^3 + x^2 + 1 (0x11D).  Repair packets are XOR-linear
 *  combinations of data packets weighted by GF coefficients.  Missing
 *  packets are recovered via Gaussian elimination when enough repair
 *  and data packets are available for a given FEC group.
 */

#include "ucp/ucp_fec_codec.h"

#include "ucp/ucp_constants.h"
#include "ucp/ucp_vector.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace ucp {

namespace {

/** @brief Lightweight pair-like struct for (repair_index, payload_pointer) storage in TryRecoverGroup.
 *  Replaces std::pair to keep all container-like types within the ucp namespace convention. */
struct RepairSelection {
    int repair_index;
    const ucp::vector<uint8_t>* payload;
};

} // namespace

uint8_t UcpFecCodec::gf_exp_[UcpFecCodec::GF_EXP_SIZE] = {};
uint8_t UcpFecCodec::gf_log_[256] = {};
bool UcpFecCodec::tables_initialized_ = []() noexcept {
    int value = 1;
    for (int i = 0; 255 > i; i++) {
        gf_exp_[i] = static_cast<uint8_t>(value);
        gf_log_[value] = static_cast<uint8_t>(i);
        value <<= 1;
        if (value & 0x100) {
            value ^= 0x11d;
        }
    }

    for (int i = 255; i < GF_EXP_SIZE; i++) {
        gf_exp_[i] = gf_exp_[i - 255];
    }
    return true;
}();

uint8_t UcpFecCodec::GfMultiply(uint8_t left, uint8_t right) noexcept {
    if (0 == left || 0 == right) {
        return 0;
    }

    return gf_exp_[gf_log_[left] + gf_log_[right]];
}

uint8_t UcpFecCodec::GfInverse(uint8_t value) noexcept {
    if (0 == value) {
        return 0;
    }

    return gf_exp_[255 - gf_log_[value]];
}

uint8_t UcpFecCodec::GfPower(uint8_t value, int exponent) noexcept {
    if (0 == exponent) {
        return 1;
    }
    if (0 == value) {
        return 0;
    }

    return gf_exp_[(gf_log_[value] * exponent) % 255];
}

uint8_t UcpFecCodec::GetCoefficient(int repair_index, int slot) noexcept {

    return GfPower(static_cast<uint8_t>(repair_index + 1), slot);
}

void UcpFecCodec::WriteUInt16(uint16_t value, uint8_t* buffer, int offset) noexcept {
    buffer[offset] = static_cast<uint8_t>(value >> 8);
    buffer[offset + 1] = static_cast<uint8_t>(value);
}

uint16_t UcpFecCodec::ReadUInt16(const uint8_t* buffer, int offset) noexcept {

    return static_cast<uint16_t>((buffer[offset] << 8) | buffer[offset + 1]);
}

UcpFecCodec::UcpFecCodec(int group_size) noexcept : UcpFecCodec(group_size, 1) {}

UcpFecCodec::UcpFecCodec(int group_size, int repair_count) noexcept
    : group_size_(std::max(2, std::min(group_size, 64))), repair_count_(std::max(1, std::min(repair_count, group_size_))),
      send_buffer_(static_cast<size_t>(group_size_)), send_count_(0) {}

int UcpFecCodec::GetSlot(uint32_t sequence_number) const noexcept {

    return static_cast<int>(sequence_number % static_cast<uint32_t>(group_size_));
}

uint32_t UcpFecCodec::GetGroupBase(uint32_t sequence_number) const noexcept {

    return sequence_number / static_cast<uint32_t>(group_size_) * static_cast<uint32_t>(group_size_);
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryEncodeRepair(const ucp::vector<uint8_t>& payload) noexcept {
    auto repairs = TryEncodeRepairs(payload);
    if (!repairs || repairs->empty()) {
        return ucp::nullopt;
    }
    return (*repairs)[0];
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryEncodeRepair(uint32_t sequence_number, const ucp::vector<uint8_t>& payload) noexcept {
    auto repairs = TryEncodeRepairs(sequence_number, payload);
    if (!repairs || repairs->empty()) {
        return ucp::nullopt;
    }
    return (*repairs)[0];
}

ucp::optional<ucp::vector<ucp::vector<uint8_t>>> UcpFecCodec::TryEncodeRepairs(const ucp::vector<uint8_t>& payload) noexcept {
    int slot = send_count_;
    return TryEncodeRepairsAtSlot(slot, payload);
}

ucp::optional<ucp::vector<ucp::vector<uint8_t>>> UcpFecCodec::TryEncodeRepairs(uint32_t sequence_number,
                                                                               const ucp::vector<uint8_t>& payload) noexcept {
    if (payload.empty()) {
        return ucp::nullopt;
    }

    uint32_t group_base = GetGroupBase(sequence_number);
    auto it = send_groups_.find(group_base);
    if (it == send_groups_.end()) {
        send_groups_[group_base] = ucp::vector<ucp::optional<ucp::vector<uint8_t>>>(static_cast<size_t>(group_size_));
        send_group_counts_[group_base] = 0;
        it = send_groups_.find(group_base);
    }

    int slot = GetSlot(sequence_number);
    if (!it->second[static_cast<size_t>(slot)].has_value()) {
        send_group_counts_[group_base] = send_group_counts_[group_base] + 1;
    }

    it->second[static_cast<size_t>(slot)] = payload;
    if (send_group_counts_[group_base] < group_size_) {
        PruneSendState();
        return ucp::nullopt;
    }

    auto repairs = EncodeRepairsFromGroup(it->second);
    send_groups_.erase(group_base);
    send_group_counts_.erase(group_base);
    return repairs;
}

ucp::optional<ucp::vector<ucp::vector<uint8_t>>> UcpFecCodec::TryEncodeRepairsAtSlot(int slot,
                                                                                     const ucp::vector<uint8_t>& payload) noexcept {
    if (0 > slot || slot >= group_size_ || payload.empty()) {
        return ucp::nullopt;
    }

    if (!send_buffer_[static_cast<size_t>(slot)].has_value()) {
        send_count_++;
    }

    send_buffer_[static_cast<size_t>(slot)] = payload;
    if (send_count_ < group_size_) {
        return ucp::nullopt;
    }
    send_count_ = 0;

    auto repairs = EncodeRepairsFromGroup(send_buffer_);
    ClearSendBuffer();
    return repairs;
}

ucp::optional<ucp::vector<ucp::vector<uint8_t>>>
UcpFecCodec::EncodeRepairsFromGroup(const ucp::vector<ucp::optional<ucp::vector<uint8_t>>>& group) noexcept {

    int max_len = 0;
    for (int i = 0; i < group_size_; i++) {
        const auto& p = group[i];
        if (p && static_cast<int>(p->size()) > max_len) {
            max_len = static_cast<int>(p->size());
        }
    }

    if (0 == max_len) {
        return ucp::nullopt;
    }

    int length_table_bytes = group_size_ * 2;
    ucp::vector<ucp::vector<uint8_t>> repairs;
    repairs.reserve(static_cast<size_t>(repair_count_));

    for (int repair_index = 0; repair_index < repair_count_; repair_index++) {

        ucp::vector<uint8_t> repair(static_cast<size_t>(length_table_bytes + max_len), 0);

        for (int slot = 0; slot < group_size_; slot++) {
            const auto& p = group[slot];
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

    return repairs;
}

void UcpFecCodec::FeedDataPacket(uint32_t sequence_number, const ucp::vector<uint8_t>& payload) noexcept {
    uint32_t group_base = GetGroupBase(sequence_number);
    auto& group = GetOrCreateReceiveGroup(group_base);
    int slot = GetSlot(sequence_number);
    if (0 <= slot && slot < group_size_) {
        group[slot] = payload;
    }
    PruneReceiveState();
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base) noexcept {
    int missing_slot;
    return TryRecoverFromRepair(repair, group_base, missing_slot);
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base,
                                                                      int& missing_slot) noexcept {
    return TryRecoverFromRepair(repair, group_base, 0, missing_slot);
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base,
                                                                      int repair_index, int& missing_slot) noexcept {
    missing_slot = -1;
    auto recovered = TryRecoverPacketsFromRepair(repair, group_base, repair_index);
    if (recovered.empty()) {
        return ucp::nullopt;
    }
    missing_slot = recovered[0].slot;
    return recovered[0].payload;
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromStoredRepair(uint32_t sequence_number, int& missing_slot) noexcept {
    missing_slot = -1;
    auto recovered = TryRecoverPacketsFromStoredRepair(sequence_number);
    if (recovered.empty()) {
        return ucp::nullopt;
    }
    missing_slot = recovered[0].slot;
    return recovered[0].payload;
}

ucp::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverPacketsFromRepair(const ucp::vector<uint8_t>& repair, uint32_t group_base,
                                                                                   int repair_index) noexcept {
    if (repair.empty()) {
        return {};
    }

    auto& repairs = GetOrCreateRepairGroup(group_base);
    repairs[repair_index] = repair;
    auto recovered = TryRecoverGroup(group_base);
    PruneReceiveState();
    return recovered;
}

ucp::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverPacketsFromStoredRepair(uint32_t sequence_number) noexcept {
    uint32_t group_base = GetGroupBase(sequence_number);
    if (recv_repairs_.count(group_base) == 0) {
        return {};
    }
    return TryRecoverGroup(group_base);
}

ucp::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverGroup(uint32_t group_base) noexcept {
    ucp::vector<RecoveredPacket> recovered_packets;
    auto& group = GetOrCreateReceiveGroup(group_base);

    auto repair_it = recv_repairs_.find(group_base);
    if (repair_it == recv_repairs_.end() || repair_it->second.empty()) {
        return recovered_packets;
    }
    auto& repairs = repair_it->second;

    ucp::vector<int> missing_slots;
    for (int i = 0; i < group_size_; i++) {
        if (!group[i]) {
            missing_slots.push_back(i);
        }
    }

    if (missing_slots.empty()) {
        recv_repairs_.erase(group_base);
        return recovered_packets;
    }

    if (static_cast<int>(repairs.size()) < static_cast<int>(missing_slots.size())) {
        return recovered_packets;
    }

    int length_table_bytes = group_size_ * 2;
    int missing_count = static_cast<int>(missing_slots.size());

    ucp::vector<RepairSelection> selected_repairs;
    selected_repairs.reserve(static_cast<size_t>(missing_count));
    for (const auto& pair : repairs) {
        if (static_cast<int>(pair.second.size()) >= length_table_bytes && static_cast<int>(selected_repairs.size()) < missing_count) {
            selected_repairs.push_back({pair.first, &pair.second});
        }
    }

    if (static_cast<int>(selected_repairs.size()) < missing_count) {
        return recovered_packets;
    }

    int max_len = static_cast<int>(selected_repairs[0].payload->size()) - length_table_bytes;
    for (size_t i = 1; i < selected_repairs.size(); i++) {
        max_len = std::min(max_len, static_cast<int>(selected_repairs[i].payload->size()) - length_table_bytes);
    }

    ucp::vector<ucp::vector<uint8_t>> matrix(static_cast<size_t>(missing_count),
                                             ucp::vector<uint8_t>(static_cast<size_t>(missing_count), 0));
    ucp::vector<ucp::vector<uint8_t>> rhs(static_cast<size_t>(missing_count));

    for (int row = 0; row < missing_count; row++) {
        int repair_index = selected_repairs[row].repair_index;
        const auto& repair = *selected_repairs[row].payload;

        rhs[row].assign(repair.begin() + length_table_bytes, repair.begin() + length_table_bytes + max_len);

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

        for (int col = 0; col < missing_count; col++) {
            matrix[row][col] = GetCoefficient(repair_index, missing_slots[col]);
        }
    }

    if (!TrySolve(matrix, rhs, missing_count)) {
        return recovered_packets;
    }

    const auto& length_table = *selected_repairs[0].payload;

    int total_slot_lengths = 0;
    for (int slot = 0; slot < group_size_; slot++) {
        int slot_length = ReadUInt16(length_table.data(), slot * 2);
        if (0 > slot_length || slot_length > MAX_FEC_SLOT_LENGTH) {
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
        if (0 > missing_length || missing_length > max_len) {
            continue;
        }

        ucp::vector<uint8_t> payload(rhs[i].begin(), rhs[i].begin() + missing_length);
        group[slot] = payload;
        {
            UcpFecCodec::RecoveredPacket rp;
            rp.slot = slot;
            rp.sequence_number = group_base + static_cast<uint32_t>(slot);
            rp.payload = std::move(payload);
            recovered_packets.push_back(std::move(rp));
        }
    }

    if (!recovered_packets.empty()) {
        recv_repairs_.erase(group_base);
    }

    return recovered_packets;
}

bool UcpFecCodec::TrySolve(ucp::vector<ucp::vector<uint8_t>>& matrix, ucp::vector<ucp::vector<uint8_t>>& rhs, int size) noexcept {
    for (int col = 0; col < size; col++) {

        int pivot = col;
        while (pivot < size && matrix[pivot][col] == 0) {
            pivot++;
        }

        if (pivot == size) {
            return false;
        }

        if (pivot != col) {
            SwapRows(matrix, rhs, pivot, col, size);
        }

        uint8_t inverse = GfInverse(matrix[col][col]);
        if (1 != inverse) {
            for (int c = col; c < size; c++) {
                matrix[col][c] = GfMultiply(matrix[col][c], inverse);
            }
            MultiplyRow(rhs[col], inverse);
        }

        for (int row = 0; row < size; row++) {
            if (row == col) {
                continue;
            }
            uint8_t factor = matrix[row][col];
            if (0 == factor) {
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

void UcpFecCodec::SwapRows(ucp::vector<ucp::vector<uint8_t>>& matrix, ucp::vector<ucp::vector<uint8_t>>& rhs, int left, int right,
                           int size) noexcept {
    for (int col = 0; col < size; col++) {
        std::swap(matrix[left][col], matrix[right][col]);
    }
    std::swap(rhs[left], rhs[right]);
}

void UcpFecCodec::MultiplyRow(ucp::vector<uint8_t>& row, uint8_t coefficient) noexcept {
    for (size_t i = 0; i < row.size(); i++) {
        row[i] = GfMultiply(row[i], coefficient);
    }
}

void UcpFecCodec::AddScaledRow(ucp::vector<uint8_t>& target, const ucp::vector<uint8_t>& source, uint8_t coefficient) noexcept {
    for (size_t i = 0; i < target.size(); i++) {
        target[i] ^= GfMultiply(coefficient, source[i]);
    }
}

ucp::vector<ucp::optional<ucp::vector<uint8_t>>>& UcpFecCodec::GetOrCreateReceiveGroup(uint32_t group_base) noexcept {
    auto it = recv_groups_.find(group_base);
    if (it == recv_groups_.end()) {
        recv_groups_[group_base] = ucp::vector<ucp::optional<ucp::vector<uint8_t>>>(static_cast<size_t>(group_size_));
        it = recv_groups_.find(group_base);
    }
    return it->second;
}

ucp::map<int, ucp::vector<uint8_t>>& UcpFecCodec::GetOrCreateRepairGroup(uint32_t group_base) noexcept {
    auto it = recv_repairs_.find(group_base);
    if (it == recv_repairs_.end()) {
        recv_repairs_[group_base] = ucp::map<int, ucp::vector<uint8_t>>();
        it = recv_repairs_.find(group_base);
    }
    return it->second;
}

void UcpFecCodec::ClearSendBuffer() noexcept {
    for (int i = 0; i < group_size_; i++) {
        send_buffer_[i] = ucp::nullopt;
    }
    send_count_ = 0;
}

void UcpFecCodec::PruneSendState() noexcept {
    while (send_groups_.size() > Constants::FEC_MAX_SEND_GROUPS) {
        uint32_t oldest = std::numeric_limits<uint32_t>::max();
        for (const auto& pair : send_groups_) {
            if (pair.first < oldest) {
                oldest = pair.first;
            }
        }

        send_groups_.erase(oldest);
        send_group_counts_.erase(oldest);
    }
}

void UcpFecCodec::PruneReceiveState() noexcept {

    while (recv_groups_.size() > Constants::FEC_MAX_RECV_GROUPS) {
        uint32_t oldest = std::numeric_limits<uint32_t>::max();
        for (const auto& pair : recv_groups_) {
            if (pair.first < oldest) {
                oldest = pair.first;
            }
        }
        recv_groups_.erase(oldest);
        recv_repairs_.erase(oldest);
    }

    while (recv_repairs_.size() > Constants::FEC_MAX_REPAIR_GROUPS) {
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
