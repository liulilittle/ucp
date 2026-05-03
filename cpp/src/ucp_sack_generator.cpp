/** @file ucp_sack_generator.cpp
 *  @brief SACK block generation from unordered received sequences — mirrors C# Ucp.Internal.SackGenerator.
 *
 *  Walks an unordered set of out-of-order received sequence numbers, sorts
 *  them in circular sequence order, and produces contiguous SACK blocks up
 *  to the maximum block limit.  Only sequences >= next_expected_sequence
 *  are considered (earlier ones are already cumulatively acknowledged).
 */

#include "ucp/ucp_sack_generator.h"
#include "ucp/ucp_sequence_comparer.h"

#include <algorithm>

namespace ucp {

std::vector<SackBlock> UcpSackGenerator::Generate(
        uint32_t next_expected_sequence,
        const std::vector<uint32_t>& received_sequences,
        int max_blocks) {

    // === Filter: only include sequences >= next_expected_sequence ===
    std::vector<uint32_t> ordered;
    ordered.reserve(received_sequences.size());
    for (uint32_t seq : received_sequences) {
        if (!UcpSequenceComparer::IsBefore(seq, next_expected_sequence)) {
            ordered.push_back(seq);
        }
    }

    // === Sort in circular sequence-number order using half-space comparison ===
    std::sort(ordered.begin(), ordered.end(),
              [](uint32_t a, uint32_t b) { return UcpSequenceComparer::Compare(a, b) < 0; });

    std::vector<SackBlock> result;
    if (ordered.empty() || max_blocks <= 0) {
        return result;
    }

    // === Coalesce consecutive sequences into contiguous SACK blocks ===
    uint32_t start    = ordered[0];
    uint32_t previous = ordered[0];
    for (size_t i = 1; i < ordered.size(); ++i) {
        uint32_t current = ordered[i];
        if (current == UcpSequenceComparer::Increment(previous)) {
            // Still within the same contiguous range
            previous = current;
            continue;
        }

        // Gap detected — emit the current block
        result.push_back({start, previous});
        if (static_cast<int>(result.size()) >= max_blocks) {
            return result;
        }

        // Start a new block
        start    = current;
        previous = current;
    }

    // === Emit the final block ===
    result.push_back({start, previous});
    if (static_cast<int>(result.size()) > max_blocks) {
        result.erase(result.begin() + max_blocks, result.end());
    }

    return result;
}

} // namespace ucp
