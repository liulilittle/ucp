#pragma once //< Include guard: prevents multiple inclusion of this header file

#include "ucp_constants.h" // Provides the SackBlock struct definition and Constants namespace

#include <cstdint> // Fixed-width integer types: uint32_t
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

namespace ucp { // Root namespace for the UCP reliable-transport protocol library — mirrors C# namespace Ucp

/** @brief Generates contiguous SACK (Selective ACK) blocks from a set of received sequence numbers.
 *         Mirrors C# internal sealed class UcpSackGenerator exactly. */
class UcpSackGenerator { // Builds merged SACK blocks from out-of-order received sequences for ACK/Data piggybacking
public:
    UcpSackGenerator() = default; //< Default constructor — stateless generator, no member state required

    /** @brief Build an ordered list of SACK blocks covering non-contiguous received ranges.
     *  @param next_expected_sequence  The next in-order sequence expected (all earlier are cumulatively acked).
     *  @param received_sequences     Unordered set of out-of-order sequence numbers that have been received.
     *  @param max_blocks             Maximum number of SACK blocks to produce.
     *  @return Vector of SackBlock entries sorted by Start (ascending) in circular sequence order. */
    ucp::vector<SackBlock> Generate(uint32_t next_expected_sequence, // The next in-order sequence the receiver expects; sequences before this are already delivered
                                    const ucp::vector<uint32_t>& received_sequences, // The set of out-of-order sequence numbers held in the receive buffer
                                    int max_blocks); // Maximum number of SACK blocks to produce, constrained by ACK packet space (type int matching C#)
};

} // namespace ucp
