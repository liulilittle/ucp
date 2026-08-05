/** @file ucp_sack_generator.cpp
 *  @brief SACK block generation from unordered received sequences -- mirrors C# UcpSackGenerator.Generate().
 *
 *  Walks an unordered collection of out-of-order received sequence numbers,
 *  filters out those already cumulative-ACKed, sorts the remainder in
 *  wrap-around-aware circular order, coalesces consecutive numbers into
 *  contiguous SACK blocks, and trims the result to respect the max_blocks
 *  limit.  Only sequences >= next_expected_sequence are considered.
 */

#include "ucp/ucp_sack_generator.h"
#include "ucp/ucp_sequence_comparer.h"
#include "ucp/ucp_vector.h"

#include <algorithm>

namespace ucp {

ucp::vector<SackBlock> UcpSackGenerator::Generate(uint32_t next_expected_sequence, const ucp::vector<uint32_t>& received_sequences,
                                                  int max_blocks) noexcept {

    ucp::vector<uint32_t> ordered;
    ordered.reserve(received_sequences.size());
    for (uint32_t seq : received_sequences) {
        if (!UcpSequenceComparer::IsBefore(seq, next_expected_sequence)) {
            ordered.push_back(seq);
        }
    }

    // The common call path feeds std::map keys (already in wrap-around order);
    // only sort when the input is actually out of order.
    bool alreadyOrdered = true;
    for (size_t i = 1; i < ordered.size(); ++i) {
        if (UcpSequenceComparer::Compare(ordered[i - 1], ordered[i]) >= 0) {
            alreadyOrdered = false;
            break;
        }
    }
    if (!alreadyOrdered) {
        std::sort(ordered.begin(), ordered.end(), [](uint32_t a, uint32_t b) noexcept { return UcpSequenceComparer::Compare(a, b) < 0; });
    }

    ucp::vector<SackBlock> result;
    if (ordered.empty() || 0 >= max_blocks) {
        return result;
    }

    uint32_t start = ordered[0];
    uint32_t previous = ordered[0];
    for (size_t i = 1; i < ordered.size(); ++i) {
        uint32_t current = ordered[i];
        if (current == UcpSequenceComparer::Increment(previous)) {

            previous = current;
            continue;
        }

        result.push_back({start, previous});
        if (static_cast<int>(result.size()) >= max_blocks) {
            return result;
        }

        start = current;
        previous = current;
    }

    result.push_back({start, previous});
    if (static_cast<int>(result.size()) > max_blocks) {
        result.erase(result.begin() + max_blocks, result.end());
    }

    return result;
}

} // namespace ucp
