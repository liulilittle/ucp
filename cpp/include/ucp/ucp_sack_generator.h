#pragma once

/** @file ucp_sack_generator.h
 *  @brief SACK (Selective Acknowledgement) block generation — mirrors C# Ucp.Internal.SackGenerator.
 *
 *  Given a set of out-of-order received sequence numbers, this utility
 *  produces the minimal set of contiguous SACK blocks to report to the peer.
 *  SACK blocks are used in both standalone ACK packets and piggybacked on
 *  outgoing data packets, following QUIC-style range encoding.
 */

#include "ucp_constants.h"

#include <cstdint>
#include <vector>

namespace ucp {

/** @brief Generates contiguous SACK (Selective ACK) blocks from a set of received sequence numbers. */
class UcpSackGenerator {
public:
    UcpSackGenerator() = default;

    /** @brief Build an ordered list of SACK blocks covering non-contiguous received ranges.
     *  @param next_expected_sequence  The next in-order sequence expected (all earlier are cumulatively acked).
     *  @param received_sequences     Unordered set of out-of-order sequence numbers that have been received.
     *  @param max_blocks             Maximum number of SACK blocks to produce.
     *  @return Vector of SackBlock entries sorted by Start (ascending). */
    std::vector<SackBlock> Generate(uint32_t next_expected_sequence,
                                    const std::vector<uint32_t>& received_sequences,
                                    int max_blocks);
};

} // namespace ucp
