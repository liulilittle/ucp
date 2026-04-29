using System.Collections.Generic;

namespace Ucp
{
    /// <summary>
    /// Builds continuous SACK ranges from the receive buffer.
    /// </summary>
    /// <summary>
    /// Builds contiguous SACK (Selective Acknowledgment) blocks from the
    /// receive buffer. Merges consecutive sequence numbers into Start/End
    /// ranges. Limited to <c>maxBlocks</c> to fit within the MSS-constrained
    /// ACK packet.
    /// </summary>
    internal sealed class UcpSackGenerator
    {
        public List<SackBlock> Generate(uint nextExpectedSequence, IEnumerable<uint> receivedSequences, int maxBlocks)
        {
            List<uint> ordered = new List<uint>();
            foreach (uint sequence in receivedSequences)
            {
                if (!UcpSequenceComparer.IsBefore(sequence, nextExpectedSequence))
                {
                    ordered.Add(sequence);
                }
            }

            ordered.Sort(UcpSequenceComparer.Instance);
            List<SackBlock> result = new List<SackBlock>();
            if (ordered.Count == 0 || maxBlocks <= 0)
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
