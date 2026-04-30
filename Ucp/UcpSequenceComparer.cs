using System.Collections.Generic;

namespace Ucp
{
    /// <summary>
    /// Wrap-around aware 32-bit sequence number comparer.
    /// Assumes active windows stay below 2^31 (half the sequence space).
    /// Provides static helpers: IsAfter, IsBefore, IsBeforeOrEqual,
    /// IsAfterOrEqual, Increment, IsInForwardRange, IsForwardDistanceAtMost.
    /// </summary>
    internal sealed class UcpSequenceComparer : IComparer<uint>
    {
        /// <summary>Singleton instance for use as a sort comparer.</summary>
        public static readonly UcpSequenceComparer Instance = new UcpSequenceComparer();

        /// <summary>Private constructor to enforce singleton pattern.</summary>
        private UcpSequenceComparer()
        {
        }

        /// <summary>
        /// Compares two sequence numbers accounting for 32-bit wrap-around.
        /// Assumes the difference is less than 2^31 (half the space).
        /// </summary>
        /// <returns>Positive if x is after y, negative if x is before y, zero if equal.</returns>
        public int Compare(uint x, uint y)
        {
            if (x == y)
            {
                return 0;
            }

            // If the unsigned difference is less than 2^31, x is ahead of y.
            uint diff = unchecked(x - y);
            return diff < 0x80000000U ? 1 : -1;
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is strictly after <paramref name="right"/>.
        /// </summary>
        public static bool IsAfter(uint left, uint right)
        {
            if (left == right)
            {
                return false;
            }

            return unchecked(left - right) < 0x80000000U;
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is strictly before <paramref name="right"/>.
        /// </summary>
        public static bool IsBefore(uint left, uint right)
        {
            return left != right && !IsAfter(left, right);
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is before or equal to <paramref name="right"/>.
        /// </summary>
        public static bool IsBeforeOrEqual(uint left, uint right)
        {
            return left == right || IsBefore(left, right);
        }

        /// <summary>
        /// Returns true if <paramref name="left"/> is after or equal to <paramref name="right"/>.
        /// </summary>
        public static bool IsAfterOrEqual(uint left, uint right)
        {
            return left == right || IsAfter(left, right);
        }

        /// <summary>
        /// Increments a sequence number with wrap-around support.
        /// </summary>
        public static uint Increment(uint value)
        {
            return unchecked(value + 1U);
        }

        /// <summary>
        /// Checks whether <paramref name="value"/> falls within the forward range [start, end].
        /// Both start and end are inclusive. The range must be less than 2^31 wide.
        /// </summary>
        public static bool IsInForwardRange(uint value, uint start, uint end)
        {
            uint valueDistance = unchecked(value - start);
            uint endDistance = unchecked(end - start);
            return endDistance < 0x80000000U && valueDistance <= endDistance;
        }

        /// <summary>
        /// Checks whether the forward distance from <paramref name="earlier"/> to
        /// <paramref name="later"/> is at most <paramref name="maxDistance"/>.
        /// </summary>
        public static bool IsForwardDistanceAtMost(uint later, uint earlier, uint maxDistance)
        {
            uint distance = unchecked(later - earlier);
            return distance <= maxDistance && distance < 0x80000000U;
        }
    }
}
