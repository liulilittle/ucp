#pragma once

/** @file ucp_sequence_comparer.h
 *  @brief 32-bit circular sequence-number arithmetic — mirrors C# Ucp.Internal.SeqCompare.
 *
 *  UCP uses 32-bit unsigned sequence numbers that wrap at 2^32.  Standard
 *  integer comparison would break near the wrap boundary, so this utility
 *  class implements modulo-2^32 ordering using the "half-sequence-space" rule:
 *  a value is "after" another if their unsigned difference falls in
 *  [1 .. 0x80000000-1], and "before" otherwise.  This is identical to the
 *  method used by TCP (RFC 793 Section 3.3) and QUIC.
 */

#include "ucp_constants.h"
#include <cstdint>

namespace ucp {

/** @brief Static helpers for comparing 32-bit sequence numbers under half-space wrap semantics. */
class UcpSequenceComparer {
public:
    UcpSequenceComparer() = delete;

    /** @brief Three-way comparison of two sequence numbers under half-space ordering.
     *  @param x  First sequence number.
     *  @param y  Second sequence number.
     *  @return 0 if equal, +1 if x is "after" y, -1 if x is "before" y. */
    static int Compare(uint32_t x, uint32_t y) {
        if (x == y) {
            return 0;
        }
        uint32_t diff = x - y;
        return diff < Constants::HALF_SEQUENCE_SPACE ? 1 : -1;
    }

    /** @brief Test whether @p left is strictly after @p right in sequence space.
     *  @param left   Candidate later sequence number.
     *  @param right  Candidate earlier sequence number.
     *  @return true if left > right under half-space ordering. */
    static bool IsAfter(uint32_t left, uint32_t right) {
        if (left == right) {
            return false;
        }
        return (left - right) < Constants::HALF_SEQUENCE_SPACE;
    }

    /** @brief Test whether @p left is strictly before @p right in sequence space.
     *  @param left   Candidate earlier sequence number.
     *  @param right  Candidate later sequence number.
     *  @return true if left < right under half-space ordering. */
    static bool IsBefore(uint32_t left, uint32_t right) {
        return left != right && !IsAfter(left, right);
    }

    /** @brief Check left <= right under half-space ordering.
     *  @param left   Candidate sequence number.
     *  @param right  Candidate sequence number.
     *  @return true if left is not after right. */
    static bool IsBeforeOrEqual(uint32_t left, uint32_t right) {
        return left == right || IsBefore(left, right);
    }

    /** @brief Check left >= right under half-space ordering.
     *  @param left   Candidate sequence number.
     *  @param right  Candidate sequence number.
     *  @return true if left is not before right. */
    static bool IsAfterOrEqual(uint32_t left, uint32_t right) {
        return left == right || IsAfter(left, right);
    }

    /** @brief Return the next sequence number (simple increment, wraps naturally).
     *  @param value  Current sequence number.
     *  @return value + 1 modulo 2^32. */
    static uint32_t Increment(uint32_t value) {
        return value + 1U;
    }

    /** @brief Test whether @p value falls within the forward range [start, end].
     *  @param value  The sequence number to test.
     *  @param start  Inclusive start of the forward range.
     *  @param end    Inclusive end of the forward range.
     *  @return true if start <= value <= end under half-space ordering. */
    static bool IsInForwardRange(uint32_t value, uint32_t start, uint32_t end) {
        uint32_t valueDistance = value - start;
        uint32_t endDistance = end - start;
        return endDistance < Constants::HALF_SEQUENCE_SPACE && valueDistance <= endDistance;
    }

    /** @brief Check that @p later is at most @p maxDistance ahead of @p earlier.
     *  @param later        Candidate later sequence number.
     *  @param earlier      Candidate earlier sequence number.
     *  @param maxDistance  Maximum allowed forward gap.
     *  @return true if 0 <= (later - earlier) <= maxDistance and the range does not wrap. */
    static bool IsForwardDistanceAtMost(uint32_t later, uint32_t earlier, uint32_t maxDistance) {
        uint32_t distance = later - earlier;
        return distance <= maxDistance && distance < Constants::HALF_SEQUENCE_SPACE;
    }
};

} // namespace ucp
