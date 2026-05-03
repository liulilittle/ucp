using System.Collections.Generic; // Provides IComparer<uint> for sortable sequence-number collections

namespace Ucp // Root namespace for the UCP reliable-transport protocol library
{
    /// <summary>
    /// Wrap-around aware 32-bit sequence number comparer.
    /// Assumes active windows stay below 2^31 (half the sequence space).
    /// Provides static helpers: IsAfter, IsBefore, IsBeforeOrEqual,
    /// IsAfterOrEqual, Increment, IsInForwardRange, IsForwardDistanceAtMost.
    /// This is essential for correct ordering of uint sequence numbers that
    /// naturally wrap from 0xFFFFFFFF back to 0, a behavior analogous to TCP.
    /// </summary>
    internal sealed class UcpSequenceComparer : IComparer<uint> // Wrap-around-aware sequence-number comparison and ordering helpers
    {
        /// <summary>Singleton instance for use as a sort comparer in List.Sort() calls.</summary>
        public static readonly UcpSequenceComparer Instance = new UcpSequenceComparer(); // Single shared instance avoids allocating a comparer per sort

        /// <summary>Private constructor to enforce singleton pattern; no external instantiation needed.</summary>
        private UcpSequenceComparer() // Private ctor enforces singleton access through the Instance field
        {
        }

        /// <summary>
        /// Compares two sequence numbers accounting for 32-bit wrap-around.
        /// Assumes the difference is less than 2^31 (half the space), which is
        /// guaranteed because the connection window is always smaller than 2^31.
        /// When the unsigned distance is less than 2^31, x is considered "after" y;
        /// otherwise x is "before" y (i.e., y has wrapped around and is ahead).
        /// </summary>
        /// <returns>Positive if x is after y, negative if x is before y, zero if equal.</returns>
        public int Compare(uint x, uint y) // IComparer<uint> implementation for wrap-around-aware sorting of sequence numbers
        {
            if (x == y)
            {
                return 0; // Identical sequence numbers are equal
            }

            // If the unsigned difference is less than 2^31, x is ahead of y.
            uint diff = unchecked(x - y); // Unsigned subtraction gives the forward distance assuming x >= y (with wrap)
            return diff < 0x80000000U ? 1 : -1; // Distance < 2^31 means x is after y; otherwise y has wrapped ahead of x
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is strictly after <paramref name="right"/>.
        /// Used extensively for checking whether a received sequence is ahead of the expected
        /// sequence, or whether an ACK advances the cumulative acknowledgment point.
        /// </summary>
        public static bool IsAfter(uint left, uint right) // Wrap-aware check: true when left is later in sequence space than right
        {
            if (left == right)
            {
                return false; // Equal values: left is not strictly after right
            }

            return unchecked(left - right) < 0x80000000U; // Forward distance < half the space confirms left is after right
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is strictly before <paramref name="right"/>.
        /// Used for determining if a sequence is older than a reference point (e.g., whether
        /// a packet's sequence has already been acknowledged and can be discarded).
        /// </summary>
        public static bool IsBefore(uint left, uint right) // Wrap-aware check: true when left is earlier in sequence space than right
        {
            return left != right && !IsAfter(left, right); // Not equal and not after implies strictly before
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is before or equal to <paramref name="right"/>.
        /// Used in range checks where the left bound should be inclusive of the reference point.
        /// </summary>
        public static bool IsBeforeOrEqual(uint left, uint right) // Inclusive-before check for range-inclusion tests
        {
            return left == right || IsBefore(left, right); // Equal counts as "before-or-equal"
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is after or equal to <paramref name="right"/>.
        /// Used in range checks where the right bound should be inclusive of the reference point,
        /// such as checking whether a received packet falls within a valid receive window.
        /// </summary>
        public static bool IsAfterOrEqual(uint left, uint right) // Inclusive-after check for receive-window validation
        {
            return left == right || IsAfter(left, right); // Equal counts as "after-or-equal"
        }

        /// <summary>
        /// Increments a sequence number with wrap-around support, simply adding 1
        /// and allowing the uint to naturally overflow from 0xFFFFFFFF back to 0.
        /// This is the canonical way to advance a sequence number in the protocol.
        /// </summary>
        public static uint Increment(uint value) // Advances a sequence number by 1 with natural uint overflow (wrap-around)
        {
            return unchecked(value + 1U); // Unchecked addition allows natural uint overflow on wrap-around
        }

        /// <summary>
        /// Checks whether <paramref name="value"/> falls within the forward range
        /// [start, end] inclusive, accounting for sequence-number wrap. Both bounds
        /// are inclusive. The range must be less than 2^31 wide; otherwise the
        /// wrap-around ambiguity makes the result unreliable.
        /// </summary>
        public static bool IsInForwardRange(uint value, uint start, uint end) // Tests if value lies within [start, end] under wrap-aware ordering
        {
            uint valueDistance = unchecked(value - start); // Forward distance from start to value (handles wrap)
            uint endDistance = unchecked(end - start); // Total span of the range from start to end (handles wrap)
            return endDistance < 0x80000000U && valueDistance <= endDistance; // Range must be < half-space, and value must not exceed the range span
        }

        /// <summary>
        /// Checks whether the forward distance from <paramref name="earlier"/> to
        /// <paramref name="later"/> is at most <paramref name="maxDistance"/>.
        /// Used for bounded-distance checks, e.g., whether two sequence numbers
        /// are within a connection window or within a retransmission threshold.
        /// </summary>
        public static bool IsForwardDistanceAtMost(uint later, uint earlier, uint maxDistance) // Bounded-distance check with wrap-aware arithmetic
        {
            uint distance = unchecked(later - earlier); // Unsigned forward distance from earlier to later
            return distance <= maxDistance && distance < 0x80000000U; // Within the max cap AND within half-space to avoid wrap confusion
        }
    }
}
