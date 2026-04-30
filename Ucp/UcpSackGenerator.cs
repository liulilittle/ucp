using System.Collections.Generic;

namespace Ucp
{
    /// <summary>
    /// Builds contiguous SACK (Selective Acknowledgment) blocks from the
    /// receive buffer. Merges consecutive sequence numbers into Start/End
    /// ranges. Limited to <c>maxBlocks</c> to fit within the MSS-constrained
    /// ACK packet.
    /// </summary>
    internal sealed class UcpSackGenerator
    {
        /// <summary>
        /// Generates up to <paramref name="maxBlocks"/> SACK blocks from a
        /// collection of received sequence numbers. Only sequences at or after
        /// <paramref name="nextExpectedSequence"/> are included (ignoring
        /// already-ACKed data). Consecutive sequences are merged into a single
        /// block.
        /// </summary>
        /// <param name="nextExpectedSequence">The next in-order sequence the receiver expects.</param>
        /// <param name="receivedSequences">The set of out-of-order sequence numbers held in the receive buffer.</param>
        /// <param name="maxBlocks">Maximum number of SACK blocks to produce.</param>
        /// <returns>List of merged SACK blocks, sorted by sequence number.</returns>
        public List<SackBlock> Generate(uint nextExpectedSequence, IEnumerable<uint> receivedSequences, int maxBlocks)
        {
            // Collect sequences at or after the expected sequence, ignoring already-delivered data.
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

            // Walk the sorted list merging consecutive sequences into blocks.
            uint start = ordered[0];
            uint previous = ordered[0];
            for (int i = 1; i < ordered.Count; i++)
            {
                uint current = ordered[i];
                if (current == UcpSequenceComparer.Increment(previous))
                {
                    // Consecutive: extend the current run.
                    previous = current;
                    continue;
                }

                // Gap detected: close the current block and start a new one.
                result.Add(new SackBlock { Start = start, End = previous });
                if (result.Count >= maxBlocks)
                {
                    return result; // Stop early if max blocks reached.
                }

                start = current;
                previous = current;
            }

            // Emit the final block spanning to the last consecutive sequence.
            result.Add(new SackBlock { Start = start, End = previous });
            if (result.Count > maxBlocks)
            {
                result.RemoveRange(maxBlocks, result.Count - maxBlocks);
            }

            return result;
        }
    }
}
