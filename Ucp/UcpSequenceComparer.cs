using System.Collections.Generic;

namespace Ucp
{
    /// <summary>
    /// Wrap-around aware 32-bit sequence comparer. It assumes active windows stay below 2^31.
    /// </summary>
    /// <summary>
    /// Wrap-around aware 32-bit sequence number comparer.
    /// Assumes active windows stay below 2^31 (half the sequence space).
    /// Provides static helpers: IsAfter, IsBefore, IsBeforeOrEqual,
    /// IsAfterOrEqual, Increment, IsInForwardRange, IsForwardDistanceAtMost.
    /// </summary>
    internal sealed class UcpSequenceComparer : IComparer<uint>
    {
        public static readonly UcpSequenceComparer Instance = new UcpSequenceComparer();

        private UcpSequenceComparer()
        {
        }

        public int Compare(uint x, uint y)
        {
            if (x == y)
            {
                return 0;
            }

            uint diff = unchecked(x - y);
            return diff < 0x80000000U ? 1 : -1;
        }

        public static bool IsAfter(uint left, uint right)
        {
            if (left == right)
            {
                return false;
            }

            return unchecked(left - right) < 0x80000000U;
        }

        public static bool IsBefore(uint left, uint right)
        {
            return left != right && !IsAfter(left, right);
        }

        public static bool IsBeforeOrEqual(uint left, uint right)
        {
            return left == right || IsBefore(left, right);
        }

        public static bool IsAfterOrEqual(uint left, uint right)
        {
            return left == right || IsAfter(left, right);
        }

        public static uint Increment(uint value)
        {
            return unchecked(value + 1U);
        }

        public static bool IsInForwardRange(uint value, uint start, uint end)
        {
            uint valueDistance = unchecked(value - start);
            uint endDistance = unchecked(end - start);
            return endDistance < 0x80000000U && valueDistance <= endDistance;
        }

        public static bool IsForwardDistanceAtMost(uint later, uint earlier, uint maxDistance)
        {
            uint distance = unchecked(later - earlier);
            return distance <= maxDistance && distance < 0x80000000U;
        }
    }
}
