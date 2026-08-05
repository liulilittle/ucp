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

/** @file ucp_sack_generator.h
 *  @brief Contiguous SACK block generator for UCP -- mirrors C# Ucp.Internal.UcpSackGenerator.
 *
 *  Merges a set of out-of-order received sequence numbers into a bounded
 *  number of contiguous SACK (Selective ACK) blocks.  The resulting blocks
 *  are emitted in ascending Start order.  The generator is stateless.
 */

#include "ucp_constants.h"
#include "ucp/ucp_packets.h"
#include <cstdint>
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

namespace ucp {

/** @brief Generates contiguous SACK (Selective ACK) blocks from a set of received sequence numbers.
 *         Mirrors C# internal sealed class UcpSackGenerator exactly. */
class UcpSackGenerator {
  public:
    UcpSackGenerator() noexcept = default;

    /** @brief Build an ordered list of SACK blocks covering non-contiguous received ranges.
     *  @param  next_expected_sequence  The next in-order sequence expected (all earlier are cumulatively acked).
     *  @param  received_sequences      Unordered set of out-of-order sequence numbers that have been received.
     *  @param  max_blocks              Maximum number of SACK blocks to produce.
     *  @return Vector of SackBlock entries sorted by Start (ascending) in circular sequence order. */
    ucp::vector<SackBlock> Generate(uint32_t next_expected_sequence, const ucp::vector<uint32_t>& received_sequences,
                                    int max_blocks) noexcept;
};

} // namespace ucp
