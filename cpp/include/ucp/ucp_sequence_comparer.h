#pragma once //< Include guard: prevents multiple inclusions of this header in a single translation unit

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

#include "ucp_constants.h" //< Provides Constants::HALF_SEQUENCE_SPACE (0x80000000U) used for half-space wrap comparisons
#include <cstdint> //< Provides uint32_t and other fixed-width integer types for deterministic cross-platform arithmetic

namespace ucp { //< All UCP library types live under the ucp namespace to avoid global name collisions

/** @brief Static helpers for comparing 32-bit sequence numbers under half-space wrap semantics. */
class UcpSequenceComparer { //< Stateless utility class: mirrors C# UcpSequenceComparer with identical half-space arithmetic
public:
    UcpSequenceComparer() = delete; //< Deleted constructor: this is a pure static utility class, no instances allowed (C# equivalent uses a private ctor + singleton)

    /** @brief Three-way comparison of two sequence numbers under half-space ordering.
     *  @param x  First sequence number.
     *  @param y  Second sequence number.
     *  @return 0 if equal, +1 if x is "after" y, -1 if x is "before" y. */
    static int Compare(uint32_t x, uint32_t y) { //< Mirrors C# public int Compare(uint x, uint y): three-way half-space comparison
        if (x == y) { //< Equality shortcut: identical sequence numbers are neither after nor before
            return 0; //< Zero: x and y represent the same sequence number (no wrap ambiguity)
        }
        uint32_t diff = x - y; //< Unsigned subtraction naturally wraps; diff encodes the forward distance from y to x in modulo-2^32 space
        return diff < Constants::HALF_SEQUENCE_SPACE ? 1 : -1; //< Distance < 0x80000000 → x is after y (+1); otherwise y has wrapped ahead of x (-1)
    }

    /** @brief Test whether @p left is strictly after @p right in sequence space.
     *  @param left   Candidate later sequence number.
     *  @param right  Candidate earlier sequence number.
     *  @return true if left > right under half-space ordering. */
    static bool IsAfter(uint32_t left, uint32_t right) { //< Mirrors C# public static bool IsAfter(uint left, uint right): wrap-aware strict-after test
        if (left == right) { //< Equal values: left cannot be strictly after right
            return false; //< Identical sequence numbers are equal, not after
        }
        return (left - right) < Constants::HALF_SEQUENCE_SPACE; //< Forward distance < 0x80000000 confirms left is strictly later; C# uses unchecked(left - right)
    }

    /** @brief Test whether @p left is strictly before @p right in sequence space.
     *  @param left   Candidate earlier sequence number.
     *  @param right  Candidate later sequence number.
     *  @return true if left < right under half-space ordering. */
    static bool IsBefore(uint32_t left, uint32_t right) { //< Mirrors C# public static bool IsBefore(uint left, uint right): wrap-aware strict-before test
        return left != right && !IsAfter(left, right); //< Not equal AND not after implies strictly before (C# identical: left != right && !IsAfter(left, right))
    }

    /** @brief Check left <= right under half-space ordering.
     *  @param left   Candidate sequence number.
     *  @param right  Candidate sequence number.
     *  @return true if left is not after right. */
    static bool IsBeforeOrEqual(uint32_t left, uint32_t right) { //< Mirrors C# public static bool IsBeforeOrEqual(uint left, uint right): inclusive-before check
        return left == right || IsBefore(left, right); //< Equal counts as before-or-equal; C# identical: left == right || IsBefore(left, right)
    }

    /** @brief Check left >= right under half-space ordering.
     *  @param left   Candidate sequence number.
     *  @param right  Candidate sequence number.
     *  @return true if left is not before right. */
    static bool IsAfterOrEqual(uint32_t left, uint32_t right) { //< Mirrors C# public static bool IsAfterOrEqual(uint left, uint right): inclusive-after check
        return left == right || IsAfter(left, right); //< Equal counts as after-or-equal; C# identical: left == right || IsAfter(left, right)
    }

    /** @brief Return the next sequence number (simple increment, wraps naturally).
     *  @param value  Current sequence number.
     *  @return value + 1 modulo 2^32. */
    static uint32_t Increment(uint32_t value) { //< Mirrors C# public static uint Increment(uint value): advance by 1 with natural uint overflow
        return value + 1U; //< Unsigned addition wraps automatically at 2^32 (0xFFFFFFFF + 1 = 0); C# uses unchecked(value + 1U) for identical behavior
    }

    /** @brief Test whether @p value falls within the forward range [start, end].
     *  @param value  The sequence number to test.
     *  @param start  Inclusive start of the forward range.
     *  @param end    Inclusive end of the forward range.
     *  @return true if start <= value <= end under half-space ordering. */
    static bool IsInForwardRange(uint32_t value, uint32_t start, uint32_t end) { //< Mirrors C# public static bool IsInForwardRange(uint value, uint start, uint end)
        uint32_t valueDistance = value - start; //< Forward distance from start to value; unsigned subtraction handles wrap naturally (C#: unchecked(value - start))
        uint32_t endDistance = end - start; //< Total span of the forward range from start to end; unsigned subtraction handles wrap (C#: unchecked(end - start))
        return endDistance < Constants::HALF_SEQUENCE_SPACE && valueDistance <= endDistance; //< Range must be < half-space AND value must not exceed the range span; C# identical: endDistance < 0x80000000U && valueDistance <= endDistance
    }

    /** @brief Check that @p later is at most @p maxDistance ahead of @p earlier.
     *  @param later        Candidate later sequence number.
     *  @param earlier      Candidate earlier sequence number.
     *  @param maxDistance  Maximum allowed forward gap.
     *  @return true if 0 <= (later - earlier) <= maxDistance and the range does not wrap. */
    static bool IsForwardDistanceAtMost(uint32_t later, uint32_t earlier, uint32_t maxDistance) { //< Mirrors C# public static bool IsForwardDistanceAtMost(uint later, uint earlier, uint maxDistance)
        uint32_t distance = later - earlier; //< Unsigned forward distance from earlier to later; wraps naturally in modulo-2^32 space (C#: unchecked(later - earlier))
        return distance <= maxDistance && distance < Constants::HALF_SEQUENCE_SPACE; //< Within max gap AND within half-space to avoid wrap ambiguity; C# identical: distance <= maxDistance && distance < 0x80000000U
    }
};

} // namespace ucp //< Closes the ucp namespace that contains UcpSequenceComparer and all other UCP library symbols
