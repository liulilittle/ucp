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

/** @file ucp_sequence_comparer.h
 *  @brief 32-bit circular sequence-number arithmetic -- mirrors C# UcpSequenceComparer.
 *
 *  UCP uses 32-bit unsigned sequence numbers that wrap at 2^32. Standard
 *  integer comparison would break near the wrap boundary, so this utility
 *  class implements modulo-2^32 ordering using the "half-sequence-space" rule:
 *  a value is "after" another if their unsigned difference is less than 2^31,
 *  and "before" otherwise. This is identical to the method used by TCP
 *  (RFC 793 Section 3.3) and QUIC, and mirrors the C# implementation in
 *  UcpSequenceComparer.cs exactly.
 */

#include "ucp_constants.h"
#include <cstdint>

namespace ucp {

/** @brief Wrap-around aware 32-bit sequence number comparer.
 *
 *  Assumes active windows stay below 2^31 (half the sequence space).
 *  Provides static helpers: IsAfter, IsBefore, IsBeforeOrEqual,
 *  IsAfterOrEqual, Increment, IsInForwardRange, IsForwardDistanceAtMost.
 *  This is essential for correct ordering of uint sequence numbers that
 *  naturally wrap from 0xFFFFFFFF back to 0, a behavior analogous to TCP.
 */
class UcpSequenceComparer {
  public:
    UcpSequenceComparer() = delete;

    /** @brief Compares two sequence numbers accounting for 32-bit wrap-around.
     *  @param  x  Left sequence number.
     *  @param  y  Right sequence number.
     *  @return 0 if equal, 1 if x is after y, -1 if x is before y. */
    static int Compare(uint32_t x, uint32_t y) noexcept {
        if (x == y) {
            return 0;
        }
        uint32_t diff = x - y;
        return diff < Constants::HALF_SEQUENCE_SPACE ? 1 : -1;
    }

    /** @brief Returns true if left is strictly after right.
     *  @param  left   Sequence to test.
     *  @param  right  Reference sequence.
     *  @return True if left is newer than right. */
    static bool IsAfter(uint32_t left, uint32_t right) noexcept {
        if (left == right) {
            return false;
        }
        return (left - right) < Constants::HALF_SEQUENCE_SPACE;
    }

    /** @brief Returns true if left is strictly before right.
     *  @param  left   Sequence to test.
     *  @param  right  Reference sequence.
     *  @return True if left is older than right. */
    static bool IsBefore(uint32_t left, uint32_t right) noexcept { return left != right && !IsAfter(left, right); }

    /** @brief Returns true if left is before or equal to right.
     *  @param  left   Sequence to test.
     *  @param  right  Reference sequence.
     *  @return True if left <= right in circular order. */
    static bool IsBeforeOrEqual(uint32_t left, uint32_t right) noexcept { return left == right || IsBefore(left, right); }

    /** @brief Returns true if left is after or equal to right.
     *  @param  left   Sequence to test.
     *  @param  right  Reference sequence.
     *  @return True if left >= right in circular order. */
    static bool IsAfterOrEqual(uint32_t left, uint32_t right) noexcept { return left == right || IsAfter(left, right); }

    /** @brief Increments a sequence number with wrap-around support.
     *  @param  value  Sequence to increment.
     *  @return value + 1, wrapping from 0xFFFFFFFF to 0. */
    static uint32_t Increment(uint32_t value) noexcept { return value + 1U; }

    /** @brief Checks whether value falls within the forward range [start, end] inclusive.
     *  @param  value  Sequence to test.
     *  @param  start  Range start (inclusive).
     *  @param  end    Range end (inclusive).
     *  @return True if value is in range. */
    static bool IsInForwardRange(uint32_t value, uint32_t start, uint32_t end) noexcept {
        uint32_t valueDistance = value - start;
        uint32_t endDistance = end - start;
        return endDistance < Constants::HALF_SEQUENCE_SPACE && valueDistance <= endDistance;
    }

    /** @brief Checks whether the forward distance from earlier to later is at most maxDistance.
     *  @param  later       Newer sequence number.
     *  @param  earlier     Older sequence number.
     *  @param  maxDistance Maximum allowed distance.
     *  @return True if the forward distance is at most maxDistance. */
    static bool IsForwardDistanceAtMost(uint32_t later, uint32_t earlier, uint32_t maxDistance) noexcept {
        uint32_t distance = later - earlier;
        return distance <= maxDistance && distance < Constants::HALF_SEQUENCE_SPACE;
    }
};

} // namespace ucp
