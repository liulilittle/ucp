using System.Collections.Generic; // Provides List<T> for ordered sequence collections and result lists

namespace Ucp // Root namespace for the UCP reliable-transport protocol library
{
    /// <summary>
    /// Builds contiguous SACK (Selective Acknowledgment) blocks from the
    /// receive buffer. Merges consecutive sequence numbers into Start/End
    /// ranges. Limited to <c>maxBlocks</c> to fit within the MSS-constrained
    /// ACK packet. This reduces the byte overhead of SACK information when
    /// many non-consecutive ranges exist by coalescing adjacent holes.
    /// </summary>
    internal sealed class UcpSackGenerator // Builds merged SACK blocks from out-of-order received sequences for ACK piggybacking
    {
        /// <summary>
        /// Generates up to <paramref name="maxBlocks"/> SACK blocks from a
        /// collection of received sequence numbers. Only sequences at or after
        /// <paramref name="nextExpectedSequence"/> are included (ignoring
        /// already-ACKed data). Consecutive sequences are merged into a single
        /// block to minimize the number of SACK entries transmitted in the
        /// limited ACK packet space.
        /// </summary>
        /// <param name="nextExpectedSequence">The next in-order sequence the receiver expects; sequences before this are already delivered.</param>
        /// <param name="receivedSequences">The set of out-of-order sequence numbers held in the receive buffer.</param>
        /// <param name="maxBlocks">Maximum number of SACK blocks to produce, constrained by ACK packet space.</param>
        /// <returns>List of merged SACK blocks, sorted by sequence number.</returns>
        public List<SackBlock> Generate(uint nextExpectedSequence, IEnumerable<uint> receivedSequences, int maxBlocks) // Produces bounded merged SACK blocks for piggybacking on ACK/Data packets
        {
            // Collect sequences at or after the expected sequence, ignoring already-delivered data.
            List<uint> ordered = new List<uint>(); // Working list that will be filtered and sorted
            foreach (uint sequence in receivedSequences) // Iterate all buffered out-of-order sequences
            {
                if (!UcpSequenceComparer.IsBefore(sequence, nextExpectedSequence)) // Exclude sequences that are already cumulative-ACKed
                {
                    ordered.Add(sequence); // Include this sequence for potential SACK block generation
                }
            }

            ordered.Sort(UcpSequenceComparer.Instance); // Sort filtered sequences in ascending order accounting for wrap-around
            List<SackBlock> result = new List<SackBlock>(); // Accumulator for the final merged SACK blocks
            if (ordered.Count == 0 || maxBlocks <= 0) // If nothing to report or the caller forbids any blocks, return empty
            {
                return result; // Empty result: no eligible out-of-order data
            }

            // Walk the sorted list merging consecutive sequences into blocks.
            uint start = ordered[0]; // First sequence of the current contiguous run
            uint previous = ordered[0]; // Tracks the last sequence seen to detect gaps
            for (int i = 1; i < ordered.Count; i++) // Scan remaining sequences from index 1 onward
            {
                uint current = ordered[i]; // The next sequence to check for contiguity
                if (current == UcpSequenceComparer.Increment(previous)) // If this sequence immediately follows the previous one
                {
                    // Consecutive: extend the current run.
                    previous = current; // Advance the run head to include this sequence
                    continue; // Keep scanning for more consecutive sequences
                }

                // Gap detected: close the current block and start a new one.
                result.Add(new SackBlock { Start = start, End = previous }); // Emit the contiguous range we just finished
                if (result.Count >= maxBlocks) // If we've reached the caller's limit on blocks
                {
                    return result; // Stop early if max blocks reached.
                }

                start = current; // Begin a new contiguous run starting at the gapped sequence
                previous = current; // Reset the run head for the new block
            }

            // Emit the final block spanning to the last consecutive sequence.
            result.Add(new SackBlock { Start = start, End = previous }); // Add the trailing run after the loop terminates
            if (result.Count > maxBlocks) // If the final block pushed us over the limit
            {
                result.RemoveRange(maxBlocks, result.Count - maxBlocks); // Trim excess blocks from the end to respect maxBlocks
            }

            return result; // Return the merged SACK blocks (bounded by maxBlocks)
        }
    }
}
