using System.Collections.Generic;

namespace Ucp
{

    internal sealed class UcpSackGenerator
    {

        public List<SackBlock> Generate(uint nextExpectedSequence, IEnumerable<uint> receivedSequences, int maxBlocks)
        {
            if (maxBlocks <= 0)
            {
                return new List<SackBlock>();
            }

            List<uint> ordered = new List<uint>();
            foreach (uint sequence in receivedSequences)
            {
                if (!UcpSequenceComparer.IsBefore(sequence, nextExpectedSequence))
                {
                    ordered.Add(sequence);
                }
            }

            // The common call path feeds SortedDictionary.Keys (already in
            // wrap-around order); only sort when the input is out of order
            // (parity with C++ UcpSackGenerator).
            bool alreadyOrdered = true;
            for (int i = 1; i < ordered.Count; i++)
            {
                if (UcpSequenceComparer.Instance.Compare(ordered[i - 1], ordered[i]) >= 0)
                {
                    alreadyOrdered = false;
                    break;
                }
            }
            if (!alreadyOrdered)
            {
                ordered.Sort(UcpSequenceComparer.Instance);
            }
            List<SackBlock> result = new List<SackBlock>();
            if (0 == ordered.Count)
            {
                return result;
            }

            uint start = ordered[0];
            uint previous = ordered[0];
            for (int i = 1; i < ordered.Count; i++)
            {
                uint current = ordered[i];
                if (current == UcpSequenceComparer.Increment(previous))
                {

                    previous = current;
                    continue;
                }

                result.Add(new SackBlock { Start = start, End = previous });
                if (result.Count >= maxBlocks)
                {
                    return result;
                }

                start = current;
                previous = current;
            }

            result.Add(new SackBlock { Start = start, End = previous });
            if (result.Count > maxBlocks)
            {
                result.RemoveRange(maxBlocks, result.Count - maxBlocks);
            }

            return result;
        }
    }
}
