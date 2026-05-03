/** @file ucp_sack_generator.cpp
 *  @brief SACK block generation from unordered received sequences — mirrors C# UcpSackGenerator.Generate().
 *
 *  Walks an unordered collection of out-of-order received sequence numbers,
 *  filters out those already cumulative-ACKed, sorts the remainder in
 *  wrap-around-aware circular order, coalesces consecutive numbers into
 *  contiguous SACK blocks, and trims the result to respect the max_blocks
 *  limit.  Only sequences >= next_expected_sequence are considered.
 */

#include "ucp/ucp_sack_generator.h" // Class declaration for UcpSackGenerator — stateless SACK block builder
#include "ucp/ucp_sequence_comparer.h" // Wrap-around-aware sequence comparison helpers: IsBefore, Compare, Increment
#include "ucp/ucp_vector.h"

#include <algorithm> // std::sort for ordering the filtered sequences in circular sequence order

namespace ucp { // Root namespace for the UCP reliable-transport protocol library — mirrors C# namespace Ucp

ucp::vector<SackBlock> UcpSackGenerator::Generate( // Produces bounded merged SACK blocks for piggybacking on ACK/Data packets (equiv C# line 26)
        uint32_t next_expected_sequence, // The next in-order sequence the receiver expects; sequences before this are already delivered (equiv C# line 26)
        const ucp::vector<uint32_t>& received_sequences, // The set of out-of-order sequence numbers held in the receive buffer (equiv C# line 26)
        int max_blocks) { // Maximum number of SACK blocks to produce, constrained by ACK packet space (equiv C# line 26)

    // === Filter: only include sequences >= next_expected_sequence ===
    ucp::vector<uint32_t> ordered; // Working list that will be filtered and sorted (equiv C# line 29: new List<uint>())
    ordered.reserve(received_sequences.size()); // Pre-allocate capacity to avoid reallocations during push_back — optimization not present in C#
    for (uint32_t seq : received_sequences) { // Iterate all buffered out-of-order sequences (equiv C# line 30: foreach)
        if (!UcpSequenceComparer::IsBefore(seq, next_expected_sequence)) { // Exclude sequences that are already cumulative-ACKed: seq >= next_expected_sequence (equiv C# line 32)
            ordered.push_back(seq); // Include this sequence for potential SACK block generation (equiv C# line 34: ordered.Add())
        } // (equiv C# line 35)
    } // (equiv C# line 36)

    // === Sort in circular sequence-number order using half-space comparison ===
    std::sort(ordered.begin(), ordered.end(), // Sort filtered sequences in ascending order accounting for 32-bit wrap-around (equiv C# line 38: ordered.Sort())
              [](uint32_t a, uint32_t b) { return UcpSequenceComparer::Compare(a, b) < 0; }); // Lambda: a sorts before b when Compare returns -1 (a is "before" b in half-space order) (equiv C# Compare implementation)

    ucp::vector<SackBlock> result; // Accumulator for the final merged SACK blocks (equiv C# line 39: new List<SackBlock>())
    if (ordered.empty() || max_blocks <= 0) { // If nothing to report or the caller forbids any blocks, return empty (equiv C# line 40)
        return result; // Empty result: no eligible out-of-order data (equiv C# line 42)
    } // (equiv C# line 43)

    // === Coalesce consecutive sequences into contiguous SACK blocks ===
    uint32_t start    = ordered[0]; // First sequence of the current contiguous run (equiv C# line 46)
    uint32_t previous = ordered[0]; // Tracks the last sequence seen in the current run, used to detect gaps (equiv C# line 47)
    for (size_t i = 1; i < ordered.size(); ++i) { // Scan remaining sequences from index 1 onward (equiv C# line 48: for (int i = 1; i < ordered.Count; i++))
        uint32_t current = ordered[i]; // The next sequence to check for contiguity (equiv C# line 50)
        if (current == UcpSequenceComparer::Increment(previous)) { // If this sequence immediately follows the previous one (previous + 1 with natural uint overflow) (equiv C# line 51)
            // Consecutive: extend the current run. (equiv C# line 52)
            previous = current; // Advance the run head to include this consecutive sequence (equiv C# line 54)
            continue; // Keep scanning for more consecutive sequences (equiv C# line 55)
        } // (equiv C# line 56)

        // Gap detected: close the current block and start a new one. (equiv C# line 57-58)
        result.push_back({start, previous}); // Emit the contiguous range we just finished (equiv C# line 59: new SackBlock { Start = start, End = previous })
        if (static_cast<int>(result.size()) >= max_blocks) { // If we've reached (or exceeded) the caller's limit on blocks (equiv C# line 60)
            return result; // Stop early: no more blocks allowed. (equiv C# line 62)
        } // (equiv C# line 63)

        // Start a new block (equiv C# line 64)
        start    = current; // Begin a new contiguous run starting at the gapped sequence (equiv C# line 65)
        previous = current; // Reset the run head for the new block (equiv C# line 66)
    } // (equiv C# line 67)

    // === Emit the final block ===
    result.push_back({start, previous}); // Add the trailing run after the loop terminates (equiv C# line 70: new SackBlock { Start = start, End = previous })
    if (static_cast<int>(result.size()) > max_blocks) { // If the final block pushed us over the limit (equiv C# line 71: result.Count > maxBlocks)
        result.erase(result.begin() + max_blocks, result.end()); // Trim excess blocks from the end to respect maxBlocks (equiv C# line 73: result.RemoveRange(maxBlocks, result.Count - maxBlocks))
    } // (equiv C# line 74)

    return result; // Return the merged SACK blocks sorted by Start, bounded by maxBlocks (equiv C# line 76)
} // (equiv C# line 77)

} // namespace ucp
