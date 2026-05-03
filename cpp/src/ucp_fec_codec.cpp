/** @file ucp_fec_codec.cpp
 *  @brief Forward Error Correction encoder/decoder implementation — mirrors C# Ucp.Internal.FecCodec.
 *
 *  Uses a Vandermonde matrix over GF(2^8) with primitive polynomial
 *  x^8 + x^4 + x^3 + x^2 + 1 (0x11D).  Repair packets are XOR-linear
 *  combinations of data packets weighted by GF coefficients.  Missing
 *  packets are recovered via Gaussian elimination when enough repair
 *  and data packets are available for a given FEC group.
 */

#include "ucp/ucp_fec_codec.h"  // Own header — declaration of the UcpFecCodec class.

#include "ucp/ucp_vector.h"

#include <algorithm>  // std::max, std::min, std::swap — clamping values and row swapping.
#include <cstring>    // (included for completeness; not directly used but available for mem* operations if needed).
#include <limits>     // std::numeric_limits<uint32_t>::max() — used to find oldest group key during pruning.
#include <stdexcept>  // std::invalid_argument — thrown by GfInverse when inverting zero.
#include <utility>    // std::pair, std::move — used for selected repairs storage and move semantics.

namespace ucp {  // All UCP library code lives in the ucp namespace, matching C# namespace Ucp.

// ====================================================================================================
// GF(2^8) lookup table initialization (static, runs at program start)
// ====================================================================================================
// These tables are built once before main() runs, using a static lambda initializer.
// This is the C++ equivalent of the C# static constructor (static UcpFecCodec() { ... }).

uint8_t UcpFecCodec::gf_exp_[UcpFecCodec::GF_EXP_SIZE] = {};  // Zero-initialize the 512-entry exponent table.  Mirrors C# GfExp[512].
uint8_t UcpFecCodec::gf_log_[256] = {};                       // Zero-initialize the 256-entry logarithm table.  Mirrors C# GfLog[256].
bool UcpFecCodec::tables_initialized_ = []() {                 // Static lambda invoked at program startup to populate GF(2^8) tables.  Mirrors C# static constructor.
    // Build exponent and logarithm tables using generator a = 2 (the primitive element x = 0x02).
    int value = 1;                                     // Start with a^0 = 1.  Mirrors C# int value = 1.
    for (int i = 0; i < 255; i++) {                    // Iterate through all 255 non-zero elements of GF(2^8).  Mirrors C# for (int i = 0; i < 255; i++).
        gf_exp_[i] = static_cast<uint8_t>(value);      // Store a^i = value at index i in the exponent table.  Mirrors C# GfExp[i] = (byte)value.
        gf_log_[value] = static_cast<uint8_t>(i);      // Store the discrete logarithm: log(value) = i.  Mirrors C# GfLog[value] = (byte)i.
        value <<= 1;                                   // Multiply by the primitive element a = x = 0x02 via left shift.  Mirrors C# value <<= 1.
        if (value & 0x100) {                           // Check if the product exceeded 8 bits (bit 8 is set).  Mirrors C# if ((value & 0x100) != 0).
            value ^= 0x11d;                            // Reduce modulo the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 = 0x11D.  Mirrors C# value ^= 0x11d.
        }
    }
    // Extend exponent table for safe double-indexing (i+j may be up to 510 when adding log values).
    for (int i = 255; i < GF_EXP_SIZE; i++) {          // Fill indices 255..511 by wrapping around modulo 255.  Mirrors C# for (int i = 255; i < GfExp.Length; i++).
        gf_exp_[i] = gf_exp_[i - 255];                 // Copy entries from the first 255: gf_exp_[i] = gf_exp_[i - 255] = a^(i mod 255).  Mirrors C# GfExp[i] = GfExp[i - 255].
    }
    return true;                                       // Signal that tables have been initialized (value assigned to tables_initialized_).  No direct C# equivalent since static ctor runs unconditionally.
}();

// ====================================================================================================
// GF(2^8) arithmetic
// ====================================================================================================
// All GF(256) arithmetic uses the precomputed exponent/log tables for O(1) operations.
// GF(256) contains 256 elements, with 255 non-zero elements forming a cyclic group.
// The primitive element a = 2 generates all non-zero elements: {a^0=1, a^1=2, a^2=4, ..., a^254}.

uint8_t UcpFecCodec::GfMultiply(uint8_t left, uint8_t right) {  // Mirrors C# GfMultiply(byte left, byte right).
    if (left == 0 || right == 0) {  // Zero times any element is zero in any field.  Mirrors C# if (left == 0 || right == 0).
        return 0;                    // Early exit for zero operands (avoids log-of-zero error).  Mirrors C# return 0.
    }
    // left * right = a^(log(left) + log(right)) using precomputed tables.  The sum may exceed 255 but the exp table is 512 entries long for safe wrap-free lookup.
    return gf_exp_[gf_log_[left] + gf_log_[right]];  // Mirrors C# return GfExp[GfLog[left] + GfLog[right]].
}

uint8_t UcpFecCodec::GfInverse(uint8_t value) {  // Mirrors C# GfInverse(byte value).
    if (value == 0) {  // Zero has no multiplicative inverse in any field.  Mirrors C# if (value == 0).
        throw std::invalid_argument("Cannot invert zero in GF(256).");  // Throws an exception — C# throws InvalidOperationException.  Same semantic but different exception type.
    }
    // Since a^255 = 1 in GF(256), the inverse of a^k is a^(255 - k).
    // inverse(value) = a^(255 - log(value)).
    return gf_exp_[255 - gf_log_[value]];  // Mirrors C# return GfExp[255 - GfLog[value]].
}

uint8_t UcpFecCodec::GfPower(uint8_t value, int exponent) {  // Mirrors C# GfPower(byte value, int exponent).
    if (exponent == 0) {  // Any non-zero element raised to the 0th power equals 1.  Mirrors C# if (exponent == 0).
        return 1;          // Return multiplicative identity.  Mirrors C# return 1.
    }
    if (value == 0) {  // 0 raised to any positive power is still 0.  Mirrors C# if (value == 0).
        return 0;       // Return additive identity.  Mirrors C# return 0.
    }
    // value^exponent = a^(log(value) * exponent).  Take modulo 255 because a^255 = 1 (the group order is 255).
    // The expression (gf_log_[value] * exponent) % 255 computes the log of the result.
    return gf_exp_[(gf_log_[value] * exponent) % 255];  // Mirrors C# return GfExp[(GfLog[value] * exponent) % 255].
}

uint8_t UcpFecCodec::GetCoefficient(int repair_index, int slot) {  // Mirrors C# GetCoefficient(int repairIndex, int slot).
    // Vandermonde-style coefficient: a_{repair,slot} = (repair_index + 1)^slot in GF(256).
    // Using (repair_index + 1) instead of repair_index ensures the first repair row
    // uses the generator (a^1 = 2) rather than a^0 = 1, producing non-trivial coefficients.
    // This guarantees distinct rows in the Vandermonde matrix for each repair index.
    return GfPower(static_cast<uint8_t>(repair_index + 1), slot);  // Mirrors C# return GfPower((byte)(repairIndex + 1), slot).
}

void UcpFecCodec::WriteUInt16(uint16_t value, uint8_t* buffer, int offset) {  // Mirrors C# WriteUInt16(ushort value, byte[] buffer, int offset).
    buffer[offset] = static_cast<uint8_t>(value >> 8);      // Write the high byte (most significant) in big-endian order.  Mirrors C# buffer[offset] = (byte)(value >> 8).
    buffer[offset + 1] = static_cast<uint8_t>(value);         // Write the low byte (least significant).  Mirrors C# buffer[offset + 1] = (byte)value.
}

uint16_t UcpFecCodec::ReadUInt16(const uint8_t* buffer, int offset) {  // Mirrors C# ReadUInt16(byte[] buffer, int offset).
    // Reconstruct a 16-bit unsigned integer from two big-endian bytes.
    // High byte is shifted left by 8 bits, then OR'd with the low byte.
    return static_cast<uint16_t>((buffer[offset] << 8) | buffer[offset + 1]);  // Mirrors C# return (ushort)((buffer[offset] << 8) | buffer[offset + 1]).
}

// ====================================================================================================
// Construction
// ====================================================================================================

UcpFecCodec::UcpFecCodec(int group_size)                    // Single-argument constructor.  Mirrors C# public UcpFecCodec(int groupSize).
    : UcpFecCodec(group_size, 1) {}                          // Delegate to the two-argument constructor with repair_count = 1.  Mirrors C# : this(groupSize, 1).

UcpFecCodec::UcpFecCodec(int group_size, int repair_count)  // Two-argument constructor.  Mirrors C# public UcpFecCodec(int groupSize, int repairCount).
    : group_size_(std::max(2, std::min(group_size, 64))),   // Clamp group size to [2, 64] for safety.  Mirrors C# _groupSize = Math.Max(2, Math.Min(groupSize, 64)).
      repair_count_(std::max(1, std::min(repair_count, group_size_))),  // Clamp repair count to [1, group_size_] — need at least 1 repair.  Mirrors C# _repairCount = Math.Max(1, Math.Min(repairCount, _groupSize)).
      send_buffer_(static_cast<size_t>(group_size_)),        // Allocate circular send buffer with one slot per group member (all nullopt initially).  Mirrors C# _sendBuffer = new byte[_groupSize][].
      send_index_(0) {}                                       // Initialize write position to the first slot.  Mirrors C# _sendIndex default = 0.

// ====================================================================================================
// Slot/Group mapping
// ====================================================================================================

int UcpFecCodec::GetSlot(uint32_t sequence_number) const {  // Mirrors C# GetSlot(uint sequenceNumber).
    // Slot index within a group = sequence number modulo group size.  This determines which position
    // in the circular buffer this packet belongs to.
    return static_cast<int>(sequence_number % static_cast<uint32_t>(group_size_));  // Mirrors C# return (int)(sequenceNumber % (uint)_groupSize).
}

uint32_t UcpFecCodec::GetGroupBase(uint32_t sequence_number) const {  // Mirrors C# GetGroupBase(uint sequenceNumber).
    // The base sequence number is the first sequence in the group.  Integer division truncates, then
    // multiply by group size to get the round-down value.
    return sequence_number / static_cast<uint32_t>(group_size_) * static_cast<uint32_t>(group_size_);  // Mirrors C# return sequenceNumber / (uint)_groupSize * (uint)_groupSize.
}

// ====================================================================================================
// Encoding
// ====================================================================================================
// The encoder accumulates data packets in a circular send buffer.  When group_size_ packets
// have been collected, it generates repair_count_ repair packets.  Each repair is a linear
// combination of all data packets weighted by Vandermonde coefficients over GF(256).

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryEncodeRepair(const ucp::vector<uint8_t>& payload) {  // Mirrors C# TryEncodeRepair(byte[] payload).
    auto repairs = TryEncodeRepairs(payload);  // Delegate to the multi-repair method for full encoding logic.  Mirrors C# List<byte[]> repairs = TryEncodeRepairs(payload).
    if (!repairs || repairs->empty()) {        // If group was not full or encoding produced no output...  Mirrors C# repairs == null || repairs.Count == 0.
        return ucp::nullopt;                   // Return null-equivalent (group not yet complete or empty).  Mirrors C# return null.
    }
    return (*repairs)[0];  // Return only the first repair packet (used for single-repair FEC).  Mirrors C# return repairs[0].
}

ucp::optional<ucp::vector<ucp::vector<uint8_t>>> UcpFecCodec::TryEncodeRepairs(const ucp::vector<uint8_t>& payload) {  // Mirrors C# TryEncodeRepairs(byte[] payload).
    // Store this payload at the current write position in the circular send buffer.
    send_buffer_[send_index_] = payload;  // Copy payload into the next available slot.  Mirrors C# _sendBuffer[_sendIndex] = payload.
    send_index_++;                        // Advance the write position for the next call.  Mirrors C# _sendIndex++.
    if (send_index_ < group_size_) {      // Group is not yet full — need more data packets.  Mirrors C# if (_sendIndex < _groupSize).
        return ucp::nullopt;              // Return null equivalent (not enough data to encode yet).  Mirrors C# return null.
    }
    send_index_ = 0;  // Reset write position for the next group.  Mirrors C# _sendIndex = 0.

    // Find the maximum payload length across all slots in this group.
    int max_len = 0;                                             // Track the longest payload to determine repair packet size.  Mirrors C# int maxLen = 0.
    for (int i = 0; i < group_size_; i++) {                      // Scan all slots in the current group.  Mirrors C# for (int i = 0; i < _groupSize; i++).
        const auto& p = send_buffer_[i];                         // Retrieve the payload at slot i (may be nullopt).  Mirrors C# byte[] p = _sendBuffer[i].
        if (p && static_cast<int>(p->size()) > max_len) {        // If slot is non-null and longer than current max...  Mirrors C# if (p != null && p.Length > maxLen).
            max_len = static_cast<int>(p->size());               // Update the maximum length.  Mirrors C# maxLen = p.Length.
        }
    }

    if (max_len == 0) {     // All slots are null/empty — nothing to protect with FEC.  Mirrors C# if (maxLen == 0).
        ClearSendBuffer();  // Reset the send buffer to clean state.  Mirrors C# ClearSendBuffer().
        return ucp::nullopt;
    }

    // Each repair packet contains a length table header (2 bytes per slot, big-endian uint16)
    // followed by the parity payload (XOR-linear combination of data weighted by GF coefficients).
    int length_table_bytes = group_size_ * 2;               // Header size = group_size * sizeof(uint16_t).  Mirrors C# int lengthTableBytes = _groupSize * sizeof(ushort).
    ucp::vector<ucp::vector<uint8_t>> repairs;               // Result container for all repair packets.  Mirrors C# List<byte[]> repairs = new List<byte[]>(_repairCount).
    repairs.reserve(static_cast<size_t>(repair_count_));    // Pre-allocate to avoid reallocation during push_back.  Mirrors C# list constructor with capacity.

    for (int repair_index = 0; repair_index < repair_count_; repair_index++) {  // Generate one repair packet per redundancy unit.  Mirrors C# for (int repairIndex = 0; repairIndex < _repairCount; repairIndex++).
        // Allocate the repair packet buffer (header + parity body), initialized to zero.
        // Initial zeros are important: parity starts at 0 and XOR accumulates.
        ucp::vector<uint8_t> repair(static_cast<size_t>(length_table_bytes + max_len), 0);  // Mirrors C# byte[] repair = new byte[lengthTableBytes + maxLen].

        for (int slot = 0; slot < group_size_; slot++) {    // Process each data slot's contribution to this repair.  Mirrors C# for (int slot = 0; slot < _groupSize; slot++).
            const auto& p = send_buffer_[slot];              // Get the payload from this slot (may be nullopt).  Mirrors C# byte[] p = _sendBuffer[slot].
            if (!p) {                                        // Skip empty slots — they contribute nothing to the repair.  Mirrors C# if (p == null).
                continue;                                    // Mirrors C# continue.
            }
            // Write this slot's payload length into the length table header (big-endian uint16).
            WriteUInt16(static_cast<uint16_t>(p->size()), repair.data(), slot * 2);  // Mirrors C# WriteUInt16((ushort)p.Length, repair, slot * sizeof(ushort)).
            // Get the Vandermonde coefficient for this (repair_index, slot) pair.
            uint8_t coefficient = GetCoefficient(repair_index, slot);  // coefficient = (repair_index + 1)^slot in GF(256).  Mirrors C# byte coefficient = GetCoefficient(repairIndex, slot).
            int len = std::min(static_cast<int>(p->size()), max_len);  // Process only up to the known payload length (should equal p->size()).  Mirrors C# int len = Math.Min(p.Length, maxLen).
            // XOR this slot's payload (scaled by the coefficient) into the parity region of the repair.
            // This is the core encoding operation: repair[j] += coefficient * data[slot][j] over GF(256).
            for (int j = 0; j < len; j++) {                                         // Mirrors C# for (int j = 0; j < len; j++).
                repair[length_table_bytes + j] ^= GfMultiply(coefficient, (*p)[j]);  // XOR accumulation: repair[offset+j] = repair[offset+j] XOR (coeff * data[j]).  Mirrors C# repair[lengthTableBytes + j] ^= GfMultiply(coefficient, p[j]).
            }
        }
        repairs.push_back(std::move(repair));  // Append this completed repair packet to the output list.  Mirrors C# repairs.Add(repair).
    }

    ClearSendBuffer();  // Release slot references so they can be reused for the next group.  Mirrors C# ClearSendBuffer().
    return repairs;     // Return the complete set of repair packets for this group.  Mirrors C# return repairs.
}

// ====================================================================================================
// Receive side
// ====================================================================================================
// Received data packets are stored in a per-group receive buffer.  When enough repairs
// are also available, missing data packets can be recovered via Gaussian elimination.

void UcpFecCodec::FeedDataPacket(uint32_t sequence_number, const ucp::vector<uint8_t>& payload) {  // Mirrors C# FeedDataPacket(uint sequenceNumber, byte[] payload).
    uint32_t group_base = GetGroupBase(sequence_number);  // Determine which FEC group this packet belongs to.  Mirrors C# uint groupBase = GetGroupBase(sequenceNumber).
    auto& group = GetOrCreateReceiveGroup(group_base);    // Get or allocate the data slot array for this group.  Mirrors C# byte[][] group = GetOrCreateReceiveGroup(groupBase).
    int slot = GetSlot(sequence_number);                  // Compute the slot index within the group.  Mirrors C# int slot = GetSlot(sequenceNumber).
    if (slot >= 0 && slot < group_size_) {                // Bounds check: slot must be within [0, group_size_).  Mirrors C# if (slot >= 0 && slot < _groupSize).
        group[slot] = payload;                            // Store the payload at the correct slot for later reconstruction.  Mirrors C# group[slot] = payload.
    }
    PruneReceiveState();  // Evict old groups to bound memory usage (keep at most 16).  Mirrors C# PruneReceiveState().
}

// ====================================================================================================
// Recovery from repair (public overloads)
// ====================================================================================================
// These public overloads provide progressively more specific recovery interfaces.
// They all ultimately delegate to TryRecoverPacketsFromRepair or TryRecoverGroup.

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(  // Mirrors C# TryRecoverFromRepair(byte[] repair, uint groupBase).
        const ucp::vector<uint8_t>& repair, uint32_t group_base) {      // repair: the repair packet bytes.  group_base: base sequence of the target group.
    int missing_slot;                                                    // Declared but value is ignored by this caller.  Mirrors C# int missingSlot (out param).
    return TryRecoverFromRepair(repair, group_base, missing_slot);       // Delegate to the version that reports the slot.  Mirrors C# return TryRecoverFromRepair(repair, groupBase, out missingSlot).
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(  // Mirrors C# TryRecoverFromRepair(byte[] repair, uint groupBase, out int missingSlot).
        const ucp::vector<uint8_t>& repair, uint32_t group_base, int& missing_slot) {  // missing_slot is an output parameter — will hold the recovered slot index or -1.
    return TryRecoverFromRepair(repair, group_base, 0, missing_slot);   // Default repair index to 0 (single-repair case).  Mirrors C# return TryRecoverFromRepair(repair, groupBase, 0, out missingSlot).
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromRepair(  // Mirrors C# TryRecoverFromRepair(byte[] repair, uint groupBase, int repairIndex, out int missingSlot).
        const ucp::vector<uint8_t>& repair, uint32_t group_base, int repair_index, int& missing_slot) {
    missing_slot = -1;  // Initialize to "not found" sentinel value.  Mirrors C# missingSlot = -1.
    auto recovered = TryRecoverPacketsFromRepair(repair, group_base, repair_index);  // Run full recovery logic.  Mirrors C# List<RecoveredPacket> recovered = TryRecoverPacketsFromRepair(repair, groupBase, repairIndex).
    if (recovered.empty()) {  // No packets were recovered from this operation.  Mirrors C# if (recovered.Count == 0).
        return ucp::nullopt;  // Return null-equivalent (recovery failed or not yet possible).  Mirrors C# return null.
    }
    missing_slot = recovered[0].slot;  // Report which slot index was recovered (first result).  Mirrors C# missingSlot = recovered[0].Slot.
    return recovered[0].payload;       // Return the first recovered payload bytes.  Mirrors C# return recovered[0].Payload.
}

ucp::optional<ucp::vector<uint8_t>> UcpFecCodec::TryRecoverFromStoredRepair(  // Mirrors C# TryRecoverFromStoredRepair(uint sequenceNumber, out int missingSlot).
        uint32_t sequence_number, int& missing_slot) {                          // sequence_number: any seq within the target group.  missing_slot: output parameter.
    missing_slot = -1;  // Initialize to "not found".  Mirrors C# missingSlot = -1.
    auto recovered = TryRecoverPacketsFromStoredRepair(sequence_number);  // Attempt recovery from previously buffered repairs.  Mirrors C# List<RecoveredPacket> recovered = TryRecoverPacketsFromStoredRepair(sequenceNumber).
    if (recovered.empty()) {  // Recovery produced no results.  Mirrors C# if (recovered.Count == 0).
        return ucp::nullopt;  // Mirrors C# return null.
    }
    missing_slot = recovered[0].slot;  // Report the first recovered slot.  Mirrors C# missingSlot = recovered[0].Slot.
    return recovered[0].payload;       // Return the first recovered payload.  Mirrors C# return recovered[0].Payload.
}

ucp::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverPacketsFromRepair(  // Mirrors C# TryRecoverPacketsFromRepair(byte[] repair, uint groupBase, int repairIndex).
        const ucp::vector<uint8_t>& repair, uint32_t group_base, int repair_index) {
    if (repair.empty()) {  // Guard against empty repair input (since we can't store/recover from nothing).  Mirrors C# if (repair == null).
        return {};          // Return empty result list.  Mirrors C# return new List<RecoveredPacket>().
    }
    // Store this repair packet in the per-group repair map, keyed by repair index.
    // std::map is used (sorted by key) to match C# SortedDictionary behavior.
    auto& repairs = GetOrCreateRepairGroup(group_base);  // Get or allocate repair storage for this group.  Mirrors C# SortedDictionary<int, byte[]> repairs = GetOrCreateRepairGroup(groupBase).
    repairs[repair_index] = repair;                       // Store the repair payload at its repair index (overwrites if already present).  Mirrors C# repairs[repairIndex] = repair.
    auto recovered = TryRecoverGroup(group_base);         // Now attempt Gaussian elimination to recover any missing packets.  Mirrors C# List<RecoveredPacket> recovered = TryRecoverGroup(groupBase).
    PruneReceiveState();                                  // Bound memory by evicting old groups.  Mirrors C# PruneReceiveState().
    return recovered;                                     // Return the list of all recovered packets (may be empty).  Mirrors C# return recovered.
}

ucp::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverPacketsFromStoredRepair(  // Mirrors C# TryRecoverPacketsFromStoredRepair(uint sequenceNumber).
        uint32_t sequence_number) {
    uint32_t group_base = GetGroupBase(sequence_number);  // Find the group base for this sequence number.  Mirrors C# uint groupBase = GetGroupBase(sequenceNumber).
    if (recv_repairs_.count(group_base) == 0) {            // No stored repairs at all for this group — cannot recover.  Mirrors C# if (!_recvRepairs.ContainsKey(groupBase)).
        return {};                                          // Return empty list.  Mirrors C# return new List<RecoveredPacket>().
    }
    return TryRecoverGroup(group_base);  // Attempt recovery using existing buffered data and stored repairs.  Mirrors C# return TryRecoverGroup(groupBase).
}

// ====================================================================================================
// Core recovery via Gaussian elimination
// ====================================================================================================
// This is the heart of the FEC decoder.  For a given group, it:
//   1. Identifies which data slots are missing.
//   2. Selects enough repair packets to form a square linear system.
//   3. Subtracts known (received) data contributions from each repair to isolate unknowns.
//   4. Builds a Vandermonde coefficient matrix over the missing slots.
//   5. Solves the system using Gauss-Jordan elimination over GF(256).
//   6. Extracts recovered payloads using the length table header from the repair.

ucp::vector<UcpFecCodec::RecoveredPacket> UcpFecCodec::TryRecoverGroup(uint32_t group_base) {  // Mirrors C# private List<RecoveredPacket> TryRecoverGroup(uint groupBase).
    ucp::vector<RecoveredPacket> recovered_packets;  // Accumulator for successfully recovered packets.  Mirrors C# List<RecoveredPacket> recoveredPackets = new List<RecoveredPacket>().
    auto& group = GetOrCreateReceiveGroup(group_base);  // Get the data slot array for this group.  Mirrors C# byte[][] group = GetOrCreateReceiveGroup(groupBase).

    // Check if we have any repair packets stored for this group.
    auto repair_it = recv_repairs_.find(group_base);          // Look up repair data for this group.  Mirrors C# _recvRepairs.TryGetValue(groupBase, out repairs).
    if (repair_it == recv_repairs_.end() || repair_it->second.empty()) {  // No repairs or empty repair map — cannot recover.  Mirrors C# if (!_recvRepairs.TryGetValue(groupBase, out repairs) || repairs.Count == 0).
        return recovered_packets;  // Return empty list.  Mirrors C# return recoveredPackets.
    }
    auto& repairs = repair_it->second;  // Reference to the sorted map of repair_index -> repair_payload.  Mirrors C# repairs local variable.

    // === Identify missing slots ===
    // Scan every slot in the group to find which positions have not yet been received.
    ucp::vector<int> missing_slots;                        // Collect indices of null (missing) data slots.  Mirrors C# List<int> missingSlots = new List<int>().
    for (int i = 0; i < group_size_; i++) {                // Scan every slot in the group.  Mirrors C# for (int i = 0; i < _groupSize; i++).
        if (!group[i]) {                                    // This slot has no payload (nullopt) — it is missing.  Mirrors C# if (group[i] == null).
            missing_slots.push_back(i);                     // Record the slot index as missing.  Mirrors C# missingSlots.Add(i).
        }
    }

    if (missing_slots.empty()) {           // All data packets have arrived — the group is complete.  Mirrors C# if (missingSlots.Count == 0).
        recv_repairs_.erase(group_base);   // Clean up: we no longer need the repair data for this group.  Mirrors C# _recvRepairs.Remove(groupBase).
        return recovered_packets;          // Return empty (nothing to recover).  Mirrors C# return recoveredPackets.
    }

    // Need at least as many repair packets as there are missing data slots for the linear system.
    if (static_cast<int>(repairs.size()) < static_cast<int>(missing_slots.size())) {  // Not enough repairs.  Mirrors C# if (repairs.Count < missingSlots.Count).
        return recovered_packets;  // Return empty — wait for more repairs to arrive.  Mirrors C# return recoveredPackets.
    }

    // === Build the linear system (matrix * x = rhs) ===
    int length_table_bytes = group_size_ * 2;  // Size of the length table header (2 bytes per slot).  Mirrors C# int lengthTableBytes = _groupSize * sizeof(ushort).
    int missing_count = static_cast<int>(missing_slots.size());  // Number of unknowns to solve for.  Mirrors C# int missingCount = missingSlots.Count.

    // Select enough valid repair packets to form the square system.
    // A repair is valid if its payload is at least as large as the length table header.
    ucp::vector<std::pair<int, const ucp::vector<uint8_t>*>> selected_repairs;  // Store (repair_index, pointer-to-payload).  Mirrors C# List<KeyValuePair<int, byte[]>> selectedRepairs.
    selected_repairs.reserve(static_cast<size_t>(missing_count));                // Pre-allocate for the needed count.  Mirrors C# new List<KeyValuePair<int, byte[]>>(missingSlots.Count).
    for (const auto& pair : repairs) {                                           // Iterate stored repairs (sorted by repair index).  Mirrors C# foreach (KeyValuePair<int, byte[]> pair in repairs).
        if (static_cast<int>(pair.second.size()) >= length_table_bytes &&        // Repair is large enough to contain a full header.  Mirrors C# pair.Value.Length >= lengthTableBytes.
                static_cast<int>(selected_repairs.size()) < missing_count) {     // Still need more repairs for the square system.  Mirrors C# selectedRepairs.Count < missingSlots.Count.
            selected_repairs.emplace_back(pair.first, &pair.second);             // Store (repair_index, pointer to payload).  Mirrors C# selectedRepairs.Add(pair).
        }
    }

    if (static_cast<int>(selected_repairs.size()) < missing_count) {  // Not enough valid repairs after filtering.  Mirrors C# if (selectedRepairs.Count < missingSlots.Count).
        return recovered_packets;  // Return empty — insufficient valid repair data.  Mirrors C# return recoveredPackets.
    }

    // Determine the maximum data length from the selected repairs.
    // All repairs should have the same max_len (the encoder uses a single max_len value).
    // We take the minimum to be safe against truncated or inconsistent repair sizes.
    int max_len = static_cast<int>(selected_repairs[0].second->size()) - length_table_bytes;  // Start with first repair's data length.  Mirrors C# int maxLen = selectedRepairs[0].Value.Length - lengthTableBytes.
    for (size_t i = 1; i < selected_repairs.size(); i++) {                                    // Check remaining repairs.  Mirrors C# for (int i = 1; i < selectedRepairs.Count; i++).
        max_len = std::min(max_len,                                                             // Use the smallest common length for consistency.  Mirrors C# maxLen = Math.Min(...).
                static_cast<int>(selected_repairs[i].second->size()) - length_table_bytes);
    }

    // Allocate the coefficient matrix (square, missing_count × missing_count) and RHS vectors.
    // Matrix A[row][col] = Vandermonde coefficient for (repair_index, missing_slot[col]).
    // RHS[row] = repair payload minus known data contributions, i.e., the unknown part.
    ucp::vector<ucp::vector<uint8_t>> matrix(static_cast<size_t>(missing_count),            // Missing_count rows.  Mirrors C# byte[,] matrix = new byte[missingCount, missingCount].
            ucp::vector<uint8_t>(static_cast<size_t>(missing_count), 0));                     // Missing_count columns, initialized to 0.  Mirrors C# (defaults to 0 in C#).
    ucp::vector<ucp::vector<uint8_t>> rhs(static_cast<size_t>(missing_count));               // One RHS vector per selected repair row.  Mirrors C# byte[][] rhs = new byte[missingCount][].

    // === Subtract known packets from each repair to isolate the unknown (RHS) ===
    // For each selected repair row, we:
    //   1. Copy the parity payload into RHS (the known part: repair data after the header).
    //   2. Subtract the contributions of all received (non-missing) data slots.
    //   3. Fill the coefficient matrix row with Vandermonde entries for the missing slots.
    for (int row = 0; row < missing_count; row++) {                        // Build one row per selected repair.  Mirrors C# for (int row = 0; row < missingCount; row++).
        int repair_index = selected_repairs[row].first;                    // Which repair packet index this row represents.  Mirrors C# int repairIndex = selectedRepairs[row].Key.
        const auto& repair = *selected_repairs[row].second;                // The raw repair packet bytes.  Mirrors C# byte[] repair = selectedRepairs[row].Value.

        // Initialize RHS: copy the parity payload from the repair (bytes after the length table header).
        // This is the "observed" value: parity = Σ(coefficient * data[slot]) for all slots.
        rhs[row].assign(repair.begin() + length_table_bytes,               // Start at offset length_table_bytes (past the header).  Mirrors C# Buffer.BlockCopy(repair, lengthTableBytes, rhs[row], 0, maxLen).
                repair.begin() + length_table_bytes + max_len);            // Copy exactly max_len bytes.  Mirrors C# copy count = maxLen.

        // Subtract the known (received) data contributions from the parity.
        // For each known slot k: rhs -= coefficient(repair_index, k) * data[k].
        // After subtracting all known contributions, the RHS contains only the unknown part.
        for (int known_slot = 0; known_slot < group_size_; known_slot++) {  // Scan every data slot position.  Mirrors C# for (int knownSlot = 0; knownSlot < _groupSize; knownSlot++).
            const auto& known = group[known_slot];                           // Get the payload at this slot (nullopt if not received).  Mirrors C# byte[] known = group[knownSlot].
            if (!known) {                                                    // This slot was not received — its contribution stays in RHS (it's unknown).  Mirrors C# if (known == null).
                continue;                                                     // Mirrors C# continue.
            }
            uint8_t coefficient = GetCoefficient(repair_index, known_slot);  // Vandermonde coefficient for this (repair, slot) pair.  Mirrors C# byte coefficient = GetCoefficient(repairIndex, knownSlot).
            int len = std::min(static_cast<int>(known->size()), max_len);   // Process only within the common payload length.  Mirrors C# int len = Math.Min(known.Length, maxLen).
            for (int j = 0; j < len; j++) {                                  // For each byte in the known payload...  Mirrors C# for (int j = 0; j < len; j++).
                rhs[row][j] ^= GfMultiply(coefficient, (*known)[j]);         // Subtract (XOR) the known contribution: rhs[j] -= coeff * known_data[j].  Mirrors C# rhs[row][j] ^= GfMultiply(coefficient, known[j]).
            }
        }

        // Fill the coefficient matrix row with Vandermonde coefficients for the missing slots.
        // Matrix element A[row][col] = (repair_index + 1)^(missing_slot[col]) in GF(256).
        for (int col = 0; col < missing_count; col++) {                      // One column per missing slot.  Mirrors C# for (int col = 0; col < missingCount; col++).
            matrix[row][col] = GetCoefficient(repair_index, missing_slots[col]);  // Vandermonde entry — ensures distinct rows for each repair index.  Mirrors C# matrix[row, col] = GetCoefficient(repairIndex, missingSlots[col]).
        }
    }

    // === Solve the linear system using Gauss-Jordan elimination over GF(2^8) ===
    // TrySolve modifies matrix into identity and rhs into the solution vector x.
    // If the matrix is singular (e.g., duplicate repair indices), solve fails.
    if (!TrySolve(matrix, rhs, missing_count)) {  // Run Gaussian elimination over GF(256).  Mirrors C# if (!TrySolve(matrix, rhs, missingCount)).
        return recovered_packets;  // Singular or underdetermined system — cannot recover uniquely.  Mirrors C# return recoveredPackets.
    }

    // === Extract recovered payloads using the length table header ===
    // The length table comes from untrusted network input — validate before using.
    // Each repair carries the same length table, so we use the first selected repair.
    const auto& length_table = *selected_repairs[0].second;  // Use the first repair's length table to get original payload sizes.  Mirrors C# byte[] lengthTable = selectedRepairs[0].Value.

    // Validate all slot lengths against known bounds to guard against corrupt or malicious data.
    int total_slot_lengths = 0;                                    // Accumulator for sum of all slot lengths.  Mirrors C# int totalSlotLengths = 0.
    for (int slot = 0; slot < group_size_; slot++) {               // Validate every slot length entry.  Mirrors C# for (int slot = 0; slot < _groupSize; slot++).
        int slot_length = ReadUInt16(length_table.data(), slot * 2);  // Read big-endian uint16 from the header.  Mirrors C# int slotLength = ReadUInt16(lengthTable, slot * sizeof(ushort)).
        if (slot_length < 0 || slot_length > MAX_FEC_SLOT_LENGTH) {   // Individual slot length exceeds max allowed (1200 bytes).  Mirrors C# if (slotLength < 0 || slotLength > UcpConstants.MAX_FEC_SLOT_LENGTH).
            return recovered_packets;                                  // Length table appears corrupt — abort recovery.  Mirrors C# return recoveredPackets.
        }
        total_slot_lengths += slot_length;  // Accumulate for the group-wide sum check.  Mirrors C# totalSlotLengths += slotLength.
    }
    if (total_slot_lengths > group_size_ * MAX_FEC_SLOT_LENGTH) {  // Total sum exceeds group_size * 1200 (implausible).  Mirrors C# if (totalSlotLengths > _groupSize * UcpConstants.MAX_FEC_SLOT_LENGTH).
        return recovered_packets;                                   // Total length implausible — reject untrusted input.  Mirrors C# return recoveredPackets.
    }

    // For each missing slot, extract the recovered payload from the solved RHS.
    for (int i = 0; i < missing_count; i++) {                                      // Process each recovered unknown.  Mirrors C# for (int i = 0; i < missingCount; i++).
        int slot = missing_slots[i];                                                // Original slot index of this recovered packet.  Mirrors C# int slot = missingSlots[i].
        int missing_length = ReadUInt16(length_table.data(), slot * 2);             // Read the original payload length from the length table.  Mirrors C# int missingLength = ReadUInt16(lengthTable, slot * sizeof(ushort)).
        if (missing_length < 0 || missing_length > max_len) {                       // Validate the length against the computed max payload length.  Mirrors C# if (missingLength < 0 || missingLength > maxLen).
            continue;                                                                // Invalid length — skip this slot (don't produce a corrupt recovery).  Mirrors C# continue.
        }

        // Extract the recovered payload from the RHS solution vector.
        // rhs[i] now contains the pure unknown data for missing_slots[i] after Gaussian elimination.
        ucp::vector<uint8_t> payload(rhs[i].begin(), rhs[i].begin() + missing_length);  // Copy exactly missing_length bytes from the solution.  Mirrors C# Buffer.BlockCopy(rhs[i], 0, payload, 0, missingLength).
        group[slot] = payload;  // Store the recovered packet back into the receive buffer.  Mirrors C# group[slot] = payload.
        {
            UcpFecCodec::RecoveredPacket rp;
            rp.slot = slot;
            rp.sequence_number = group_base + static_cast<uint32_t>(slot);
            rp.payload = std::move(payload);
            recovered_packets.push_back(std::move(rp));
        }
    }

    // Clean up repair data if we recovered at least one packet.
    if (!recovered_packets.empty()) {  // At least one packet was successfully recovered.  Mirrors C# if (recoveredPackets.Count > 0).
        recv_repairs_.erase(group_base);  // Remove repair data — no longer needed for this group.  Mirrors C# _recvRepairs.Remove(groupBase).
    }

    return recovered_packets;  // Return the complete list of recovered packets (may be empty).  Mirrors C# return recoveredPackets.
}

// ====================================================================================================
// Gaussian elimination helpers
// ====================================================================================================
// Gauss-Jordan elimination over GF(2^8) with partial pivoting.
// The algorithm:
//   For each column (pivot column):
//     1. Find a row with a non-zero entry in this column (pivot row).
//     2. Swap the pivot row to the diagonal position.
//     3. Normalize the pivot row so the diagonal element becomes 1.
//     4. Eliminate (zero out) this column from all other rows.
// After processing all columns, the matrix is identity and rhs is the solution.

bool UcpFecCodec::TrySolve(ucp::vector<ucp::vector<uint8_t>>& matrix,       // Coefficient matrix — modified to identity in place.  Mirrors C# byte[,] matrix.
        ucp::vector<ucp::vector<uint8_t>>& rhs, int size) {                  // Right-hand side — modified to solution in place.  Mirrors C# byte[][] rhs.  size = dimension of the square system.
    for (int col = 0; col < size; col++) {                                  // Process each column as the pivot column (forward elimination).  Mirrors C# for (int col = 0; col < size; col++).
        // === Find pivot row ===
        // Search for the first row at or below the diagonal with a non-zero entry in this column.
        int pivot = col;                                                    // Start searching from the diagonal.  Mirrors C# int pivot = col.
        while (pivot < size && matrix[pivot][col] == 0) {                   // Skip rows where the pivot column entry is zero.  Mirrors C# while (pivot < size && matrix[pivot, col] == 0).
            pivot++;                                                         // Try the next row.  Mirrors C# pivot++.
        }

        if (pivot == size) {                                                // No non-zero entry found in this column at all.  Mirrors C# if (pivot == size).
            return false;                                                    // Singular matrix — no unique solution exists.  Mirrors C# return false.
        }

        if (pivot != col) {                                                 // Pivot is not on the diagonal — need to swap rows.  Mirrors C# if (pivot != col).
            SwapRows(matrix, rhs, pivot, col, size);                        // Bring the pivot row to the current diagonal position.  Mirrors C# SwapRows(matrix, rhs, pivot, col, size).
        }

        // === Normalize the pivot row ===
        // Divide the pivot row by its diagonal element to make the diagonal entry 1.
        uint8_t inverse = GfInverse(matrix[col][col]);                      // Compute multiplicative inverse of the pivot element.  Mirrors C# byte inverse = GfInverse(matrix[col, col]).
        if (inverse != 1) {                                                 // Optimization: skip if pivot is already 1.  Mirrors C# if (inverse != 1).
            for (int c = col; c < size; c++) {                              // Scale every element in the pivot row from column col onward.  Mirrors C# for (int c = col; c < size; c++).
                matrix[col][c] = GfMultiply(matrix[col][c], inverse);       // Multiply by inverse: matrix[col][c] = matrix[col][c] * inverse.  Mirrors C# matrix[col, c] = GfMultiply(matrix[col, c], inverse).
            }
            MultiplyRow(rhs[col], inverse);                                 // Apply the same scaling to the RHS vector.  Mirrors C# MultiplyRow(rhs[col], inverse).
        }

        // === Eliminate this column from all other rows ===
        // For each row r ≠ pivot: row[r] = row[r] - factor * row[pivot], where factor = matrix[r][col].
        for (int row = 0; row < size; row++) {                              // Process every row in the matrix.  Mirrors C# for (int row = 0; row < size; row++).
            if (row == col) {                                                // Skip the pivot row itself.  Mirrors C# if (row == col).
                continue;                                                    // Mirrors C# continue.
            }
            uint8_t factor = matrix[row][col];                              // The value at this row's pivot column — the element to eliminate.  Mirrors C# byte factor = matrix[row, col].
            if (factor == 0) {                                              // Already zero — nothing to eliminate in this row.  Mirrors C# if (factor == 0).
                continue;                                                    // Mirrors C# continue.
            }
            for (int c = col; c < size; c++) {                              // For each column from col onward in this row...  Mirrors C# for (int c = col; c < size; c++).
                matrix[row][c] ^= GfMultiply(factor, matrix[col][c]);       // Subtract (XOR with) factor * pivot_row[c]: row = row - factor * pivot_row.  Mirrors C# matrix[row, c] ^= GfMultiply(factor, matrix[col, c]).
            }
            AddScaledRow(rhs[row], rhs[col], factor);                       // Apply same elimination to the RHS: rhs[row] -= factor * rhs[col].  Mirrors C# AddScaledRow(rhs[row], rhs[col], factor).
        }
    }

    return true;  // System solved successfully — matrix is now identity, rhs is the solution vector x.  Mirrors C# return true.
}

void UcpFecCodec::SwapRows(ucp::vector<ucp::vector<uint8_t>>& matrix,       // Mirrors C# SwapRows(byte[,] matrix, byte[][] rhs, int left, int right, int size).
        ucp::vector<ucp::vector<uint8_t>>& rhs, int left, int right, int size) {  // left, right: row indices to swap.  size: number of columns in the matrix.
    for (int col = 0; col < size; col++) {                                  // Swap every element in both matrix rows column by column.  Mirrors C# for (int col = 0; col < size; col++).
        std::swap(matrix[left][col], matrix[right][col]);                   // std::swap exchanges the two elements in place.  Mirrors C# three-line swap with temp variable.
    }
    std::swap(rhs[left], rhs[right]);                                       // Swap the RHS row references — O(1) since vectors support efficient swap.  Mirrors C# three-line swap of RHS references.
}

void UcpFecCodec::MultiplyRow(ucp::vector<uint8_t>& row, uint8_t coefficient) {  // Mirrors C# MultiplyRow(byte[] row, byte coefficient).
    for (size_t i = 0; i < row.size(); i++) {                                    // Scale every element in the row.  Mirrors C# for (int i = 0; i < row.Length; i++).
        row[i] = GfMultiply(row[i], coefficient);                                // Multiply each byte by the coefficient in GF(256).  Mirrors C# row[i] = GfMultiply(row[i], coefficient).
    }
}

void UcpFecCodec::AddScaledRow(ucp::vector<uint8_t>& target, const ucp::vector<uint8_t>& source,  // Mirrors C# AddScaledRow(byte[] target, byte[] source, byte coefficient).
        uint8_t coefficient) {                                                                     // target: the row being modified.  source: the row being added.  coefficient: scale factor.
    for (size_t i = 0; i < target.size(); i++) {                                                   // Process each byte in the row.  Mirrors C# for (int i = 0; i < target.Length; i++).
        target[i] ^= GfMultiply(coefficient, source[i]);                                           // target += coefficient * source using GF(256): XOR with scaled source byte.  Mirrors C# target[i] ^= GfMultiply(coefficient, source[i]).
    }
}

// ====================================================================================================
// Buffer management
// ====================================================================================================

ucp::vector<ucp::optional<ucp::vector<uint8_t>>>& UcpFecCodec::GetOrCreateReceiveGroup(  // Mirrors C# GetOrCreateReceiveGroup(uint groupBase).
        uint32_t group_base) {                                                              // group_base: base sequence number identifying the FEC group.
    auto it = recv_groups_.find(group_base);
    if (it == recv_groups_.end()) {
        recv_groups_[group_base] = ucp::vector<ucp::optional<ucp::vector<uint8_t>>>(
            static_cast<size_t>(group_size_));
        it = recv_groups_.find(group_base);
    }
    return it->second;  // Return a reference to the data slot array for this group.  Mirrors C# return group.
}

std::map<int, ucp::vector<uint8_t>>& UcpFecCodec::GetOrCreateRepairGroup(uint32_t group_base) {  // Mirrors C# GetOrCreateRepairGroup(uint groupBase).
    auto it = recv_repairs_.find(group_base);
    if (it == recv_repairs_.end()) {
        recv_repairs_[group_base] = std::map<int, ucp::vector<uint8_t>>();
        it = recv_repairs_.find(group_base);
    }
    return it->second;  // Mirrors C# _recvRepairs.TryGetValue then new SortedDictionary.
}

void UcpFecCodec::ClearSendBuffer() {             // Mirrors C# ClearSendBuffer().
    for (int i = 0; i < group_size_; i++) {       // Iterate all slots in the send buffer.  Mirrors C# for (int i = 0; i < _groupSize; i++).
        send_buffer_[i] = ucp::nullopt;           // Reset the optional to nullopt (equivalent to setting to null).  Mirrors C# _sendBuffer[i] = null.
    }
}

void UcpFecCodec::PruneReceiveState() {           // Mirrors C# PruneReceiveState().
    // Limit receive data groups to at most 16 to bound memory usage.
    // Evict the oldest group (smallest group base key) when exceeding the limit.
    while (recv_groups_.size() > 16) {                            // Keep at most 16 recent groups.  Mirrors C# while (_recvGroups.Count > 16).
        uint32_t oldest = std::numeric_limits<uint32_t>::max();   // Initialize to maximum possible value (sentinel).  Mirrors C# uint oldest = uint.MaxValue.
        for (const auto& pair : recv_groups_) {                   // Scan all group keys to find the smallest (oldest).  Mirrors C# foreach (uint key in _recvGroups.Keys).
            if (pair.first < oldest) {                            // Found a key smaller than the current oldest.  Mirrors C# if (key < oldest).
                oldest = pair.first;                              // Update the current oldest candidate.  Mirrors C# oldest = key.
            }
        }
        recv_groups_.erase(oldest);   // Evict the oldest (smallest key) data group.  Mirrors C# _recvGroups.Remove(oldest).
        recv_repairs_.erase(oldest);  // Also evict its associated repair data to keep maps in sync.  Mirrors C# _recvRepairs.Remove(oldest).
    }

    // Also limit orphaned repair groups (repairs without corresponding data groups) to 16.
    while (recv_repairs_.size() > 16) {                           // Keep at most 16 orphaned repair groups.  Mirrors C# while (_recvRepairs.Count > 16).
        uint32_t oldest = std::numeric_limits<uint32_t>::max();   // Initialize sentinel.  Mirrors C# uint oldest = uint.MaxValue.
        for (const auto& pair : recv_repairs_) {                   // Scan all repair group keys.  Mirrors C# foreach (uint key in _recvRepairs.Keys).
            if (pair.first < oldest) {                             // Found a smaller (older) key.  Mirrors C# if (key < oldest).
                oldest = pair.first;                               // Update oldest candidate.  Mirrors C# oldest = key.
            }
        }
        recv_repairs_.erase(oldest);  // Evict the oldest orphaned repair group.  Mirrors C# _recvRepairs.Remove(oldest).
    }
}

} // namespace ucp
