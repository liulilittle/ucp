using System;
using System.Collections.Generic;

namespace Ucp
{
    /// <summary>
    /// Systematic Reed-Solomon-style Forward Error Correction encoder/decoder
    /// over GF(256).
    ///
    /// Encoder buffers N data payloads and generates one or more parity repair
    /// packets over GF(256). Decoder buffers received data and repairs by group
    /// base sequence number, then reconstructs up to R missing DATA packets when
    /// at least R independent repair packets are available.
    ///
    /// Group size is configurable via <see cref="UcpConfiguration.FecGroupSize"/>.
    /// Repair count is derived from <see cref="UcpConfiguration.FecRedundancy"/>.
    /// </summary>
    internal sealed class UcpFecCodec
    {
        /// <summary>
        /// Represents a packet recovered via FEC repair.
        /// </summary>
        internal sealed class RecoveredPacket
        {
            /// <summary>Slot index within the FEC group.</summary>
            public int Slot;

            /// <summary>Sequence number of the original recovered data packet.</summary>
            public uint SequenceNumber;

            /// <summary>Recovered payload bytes.</summary>
            public byte[] Payload;
        }

        /// <summary>Precomputed GF(256) exponentiation table (512 entries for wrap-around).</summary>
        private static readonly byte[] GfExp = new byte[512];

        /// <summary>Precomputed GF(256) logarithm table.</summary>
        private static readonly byte[] GfLog = new byte[256];

        /// <summary>Number of data packets per FEC group.</summary>
        private readonly int _groupSize;

        /// <summary>Number of repair packets generated per group.</summary>
        private readonly int _repairCount;

        /// <summary>Circular send buffer accumulating data payloads for a group.</summary>
        private readonly byte[][] _sendBuffer;

        /// <summary>Current write position in the send buffer.</summary>
        private int _sendIndex;

        /// <summary>Receive buffer: maps group base sequence to data slots.</summary>
        private readonly Dictionary<uint, byte[][]> _recvGroups = new Dictionary<uint, byte[][]>();

        /// <summary>Maps group base sequence to received repair packets indexed by repair index.</summary>
        private readonly Dictionary<uint, SortedDictionary<int, byte[]>> _recvRepairs = new Dictionary<uint, SortedDictionary<int, byte[]>>();

        /// <summary>
        /// Initializes the GF(256) exp/log tables used for fast multiply/divide.
        /// Generator polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11d).
        /// </summary>
        static UcpFecCodec()
        {
            int value = 1;
            for (int i = 0; i < 255; i++)
            {
                GfExp[i] = (byte)value;
                GfLog[value] = (byte)i;
                value <<= 1;
                if ((value & 0x100) != 0)
                {
                    value ^= 0x11d; // Reduce modulo generator polynomial.
                }
            }

            // Double the table for fast wrap-around in multiplication.
            for (int i = 255; i < GfExp.Length; i++)
            {
                GfExp[i] = GfExp[i - 255];
            }
        }

        /// <summary>
        /// Creates an FEC codec with a single repair packet per group.
        /// </summary>
        /// <param name="groupSize">Number of data packets per group.</param>
        public UcpFecCodec(int groupSize)
            : this(groupSize, 1)
        {
        }

        /// <summary>
        /// Creates an FEC codec with the given group size and repair count.
        /// Both are clamped to valid ranges.
        /// </summary>
        /// <param name="groupSize">Number of data packets per group (2..64).</param>
        /// <param name="repairCount">Number of repair packets per group (1..groupSize).</param>
        public UcpFecCodec(int groupSize, int repairCount)
        {
            _groupSize = Math.Max(2, Math.Min(groupSize, 64));
            _repairCount = Math.Max(1, Math.Min(repairCount, _groupSize));
            _sendBuffer = new byte[_groupSize][];
        }

        /// <summary>Number of repair packets generated per group.</summary>
        public int RepairCount
        {
            get { return _repairCount; }
        }

        /// <summary>
        /// Feeds a payload into the send buffer. When the group is full, generates
        /// repair packets and returns only the first one (for single-repair use).
        /// </summary>
        /// <param name="payload">The data payload to encode.</param>
        /// <returns>The first repair payload, or null if group not yet full.</returns>
        public byte[] TryEncodeRepair(byte[] payload)
        {
            List<byte[]> repairs = TryEncodeRepairs(payload);
            return repairs == null || repairs.Count == 0 ? null : repairs[0];
        }

        /// <summary>
        /// Feeds a payload into the send buffer. When the group is full, generates
        /// and returns all repair packets for this group.
        /// </summary>
        /// <param name="payload">The data payload to encode.</param>
        /// <returns>List of repair payloads, or null if the group is not yet full.</returns>
        public List<byte[]> TryEncodeRepairs(byte[] payload)
        {
            _sendBuffer[_sendIndex] = payload;
            _sendIndex++;
            if (_sendIndex < _groupSize)
            {
                return null; // Group not yet complete.
            }

            _sendIndex = 0;

            // Determine the maximum payload length across all slots.
            int maxLen = 0;
            for (int i = 0; i < _groupSize; i++)
            {
                byte[] p = _sendBuffer[i];
                if (p != null && p.Length > maxLen)
                {
                    maxLen = p.Length;
                }
            }

            if (maxLen == 0)
            {
                ClearSendBuffer();
                return null;
            }

            // Each repair carries a length table (2 bytes per slot) followed by parity.
            int lengthTableBytes = _groupSize * sizeof(ushort);
            List<byte[]> repairs = new List<byte[]>(_repairCount);
            for (int repairIndex = 0; repairIndex < _repairCount; repairIndex++)
            {
                byte[] repair = new byte[lengthTableBytes + maxLen];
                for (int slot = 0; slot < _groupSize; slot++)
                {
                    byte[] p = _sendBuffer[slot];
                    if (p == null)
                    {
                        continue;
                    }

                    // Write this slot's length into the length table.
                    WriteUInt16((ushort)p.Length, repair, slot * sizeof(ushort));
                    byte coefficient = GetCoefficient(repairIndex, slot);
                    int len = Math.Min(p.Length, maxLen);
                    // XOR this slot's payload into the parity (scaled by coefficient).
                    for (int j = 0; j < len; j++)
                    {
                        repair[lengthTableBytes + j] ^= GfMultiply(coefficient, p[j]);
                    }
                }

                repairs.Add(repair);
            }

            ClearSendBuffer();
            return repairs;
        }

        /// <summary>
        /// Returns the slot index within a group for the given sequence number.
        /// </summary>
        /// <param name="sequenceNumber">The data packet sequence number.</param>
        /// <returns>Zero-based slot index.</returns>
        public int GetSlot(uint sequenceNumber)
        {
            return (int)(sequenceNumber % (uint)_groupSize);
        }

        /// <summary>
        /// Returns the base sequence number (first slot) of the group containing
        /// the given sequence number.
        /// </summary>
        /// <param name="sequenceNumber">A sequence number within the group.</param>
        /// <returns>The group's base sequence number.</returns>
        public uint GetGroupBase(uint sequenceNumber)
        {
            return sequenceNumber / (uint)_groupSize * (uint)_groupSize;
        }

        /// <summary>
        /// Stores a received data packet in the receive buffer for its group.
        /// </summary>
        /// <param name="sequenceNumber">The packet's sequence number.</param>
        /// <param name="payload">The packet's payload.</param>
        public void FeedDataPacket(uint sequenceNumber, byte[] payload)
        {
            if (payload == null)
            {
                return;
            }

            uint groupBase = GetGroupBase(sequenceNumber);
            byte[][] group = GetOrCreateReceiveGroup(groupBase);
            int slot = GetSlot(sequenceNumber);
            if (slot >= 0 && slot < _groupSize)
            {
                group[slot] = payload;
            }

            PruneReceiveState();
        }

        /// <summary>
        /// Attempts to recover a single missing packet using the given repair
        /// payload for a specific group.
        /// </summary>
        /// <param name="repair">The repair packet payload.</param>
        /// <param name="groupBase">The base sequence number of the group.</param>
        /// <returns>The recovered payload, or null if recovery failed.</returns>
        public byte[] TryRecoverFromRepair(byte[] repair, uint groupBase)
        {
            int missingSlot;
            return TryRecoverFromRepair(repair, groupBase, out missingSlot);
        }

        /// <summary>
        /// Attempts to recover a single missing packet and reports the slot index.
        /// </summary>
        /// <param name="repair">The repair packet payload.</param>
        /// <param name="groupBase">The base sequence number of the group.</param>
        /// <param name="missingSlot">The recovered slot index.</param>
        /// <returns>The recovered payload, or null.</returns>
        public byte[] TryRecoverFromRepair(byte[] repair, uint groupBase, out int missingSlot)
        {
            return TryRecoverFromRepair(repair, groupBase, 0, out missingSlot);
        }

        /// <summary>
        /// Attempts to recover a single missing packet with known repair index.
        /// </summary>
        /// <param name="repair">The repair packet payload.</param>
        /// <param name="groupBase">The base sequence number of the group.</param>
        /// <param name="repairIndex">The index of this repair within the group.</param>
        /// <param name="missingSlot">The recovered slot index.</param>
        /// <returns>The recovered payload, or null.</returns>
        public byte[] TryRecoverFromRepair(byte[] repair, uint groupBase, int repairIndex, out int missingSlot)
        {
            missingSlot = -1;
            List<RecoveredPacket> recovered = TryRecoverPacketsFromRepair(repair, groupBase, repairIndex);
            if (recovered.Count == 0)
            {
                return null;
            }

            missingSlot = recovered[0].Slot;
            return recovered[0].Payload;
        }

        /// <summary>
        /// Attempts to recover a missing packet using previously stored repair data
        /// for the group containing the given sequence number.
        /// </summary>
        /// <param name="sequenceNumber">A sequence number identifying the group.</param>
        /// <param name="missingSlot">The recovered slot index.</param>
        /// <returns>The recovered payload, or null.</returns>
        public byte[] TryRecoverFromStoredRepair(uint sequenceNumber, out int missingSlot)
        {
            missingSlot = -1;
            List<RecoveredPacket> recovered = TryRecoverPacketsFromStoredRepair(sequenceNumber);
            if (recovered.Count == 0)
            {
                return null;
            }

            missingSlot = recovered[0].Slot;
            return recovered[0].Payload;
        }

        /// <summary>
        /// Stores a repair packet and attempts to recover all missing packets
        /// in its group.
        /// </summary>
        /// <param name="repair">The repair packet payload.</param>
        /// <param name="groupBase">The base sequence number of the group.</param>
        /// <param name="repairIndex">The index of this repair.</param>
        /// <returns>List of recovered packets.</returns>
        public List<RecoveredPacket> TryRecoverPacketsFromRepair(byte[] repair, uint groupBase, int repairIndex)
        {
            if (repair == null)
            {
                return new List<RecoveredPacket>();
            }

            SortedDictionary<int, byte[]> repairs = GetOrCreateRepairGroup(groupBase);
            repairs[repairIndex] = repair;
            List<RecoveredPacket> recovered = TryRecoverGroup(groupBase);
            PruneReceiveState();
            return recovered;
        }

        /// <summary>
        /// Attempts to recover missing packets in the group containing the given
        /// sequence number using previously stored repair data.
        /// </summary>
        /// <param name="sequenceNumber">A sequence number identifying the group.</param>
        /// <returns>List of recovered packets.</returns>
        public List<RecoveredPacket> TryRecoverPacketsFromStoredRepair(uint sequenceNumber)
        {
            uint groupBase = GetGroupBase(sequenceNumber);
            if (!_recvRepairs.ContainsKey(groupBase))
            {
                return new List<RecoveredPacket>();
            }

            return TryRecoverGroup(groupBase);
        }

        /// <summary>
        /// Attempts Gaussian elimination to recover all missing packets in a group.
        /// Requires at least as many independent repair packets as missing data slots.
        /// </summary>
        /// <param name="groupBase">The base sequence number of the group.</param>
        /// <returns>List of successfully recovered packets.</returns>
        private List<RecoveredPacket> TryRecoverGroup(uint groupBase)
        {
            List<RecoveredPacket> recoveredPackets = new List<RecoveredPacket>();
            byte[][] group = GetOrCreateReceiveGroup(groupBase);

            SortedDictionary<int, byte[]> repairs;
            if (!_recvRepairs.TryGetValue(groupBase, out repairs) || repairs.Count == 0)
            {
                return recoveredPackets;
            }

            // Identify which slots are missing.
            List<int> missingSlots = new List<int>();
            for (int i = 0; i < _groupSize; i++)
            {
                if (group[i] == null)
                {
                    missingSlots.Add(i);
                }
            }

            if (missingSlots.Count == 0)
            {
                _recvRepairs.Remove(groupBase); // Group complete; clean up.
                return recoveredPackets;
            }

            if (repairs.Count < missingSlots.Count)
            {
                return recoveredPackets; // Not enough repair packets yet.
            }

            int lengthTableBytes = _groupSize * sizeof(ushort);
            // Select the required number of valid repairs.
            List<KeyValuePair<int, byte[]>> selectedRepairs = new List<KeyValuePair<int, byte[]>>(missingSlots.Count);
            foreach (KeyValuePair<int, byte[]> pair in repairs)
            {
                if (pair.Value != null && pair.Value.Length >= lengthTableBytes && selectedRepairs.Count < missingSlots.Count)
                {
                    selectedRepairs.Add(pair);
                }
            }

            if (selectedRepairs.Count < missingSlots.Count)
            {
                return recoveredPackets;
            }

            // Compute the minimum repair payload length (after the length table).
            int maxLen = selectedRepairs[0].Value.Length - lengthTableBytes;
            for (int i = 1; i < selectedRepairs.Count; i++)
            {
                maxLen = Math.Min(maxLen, selectedRepairs[i].Value.Length - lengthTableBytes);
            }

            int missingCount = missingSlots.Count;
            // Build the coefficient matrix and RHS vector for GF(256) linear system.
            byte[,] matrix = new byte[missingCount, missingCount];
            byte[][] rhs = new byte[missingCount][];
            for (int row = 0; row < missingCount; row++)
            {
                int repairIndex = selectedRepairs[row].Key;
                byte[] repair = selectedRepairs[row].Value;
                rhs[row] = new byte[maxLen];
                Buffer.BlockCopy(repair, lengthTableBytes, rhs[row], 0, maxLen);

                // Subtract known data contributions from the parity.
                for (int knownSlot = 0; knownSlot < _groupSize; knownSlot++)
                {
                    byte[] known = group[knownSlot];
                    if (known == null)
                    {
                        continue;
                    }

                    byte coefficient = GetCoefficient(repairIndex, knownSlot);
                    int len = Math.Min(known.Length, maxLen);
                    for (int j = 0; j < len; j++)
                    {
                        rhs[row][j] ^= GfMultiply(coefficient, known[j]);
                    }
                }

                // Build the Vandermonde-style matrix for the missing slots.
                for (int col = 0; col < missingCount; col++)
                {
                    matrix[row, col] = GetCoefficient(repairIndex, missingSlots[col]);
                }
            }

            if (!TrySolve(matrix, rhs, missingCount))
            {
                return recoveredPackets; // Matrix is singular or under-determined.
            }

            // Extract recovered payloads using the length table from the first repair.
            byte[] lengthTable = selectedRepairs[0].Value;
            for (int i = 0; i < missingCount; i++)
            {
                int slot = missingSlots[i];
                int missingLength = ReadUInt16(lengthTable, slot * sizeof(ushort));
                if (missingLength <= 0 || missingLength > rhs[i].Length)
                {
                    continue;
                }

                byte[] payload = new byte[missingLength];
                Buffer.BlockCopy(rhs[i], 0, payload, 0, missingLength);
                group[slot] = payload;
                recoveredPackets.Add(new RecoveredPacket { Slot = slot, SequenceNumber = groupBase + (uint)slot, Payload = payload });
            }

            if (recoveredPackets.Count > 0)
            {
                _recvRepairs.Remove(groupBase); // Clean up after successful recovery.
            }

            return recoveredPackets;
        }

        /// <summary>
        /// Gets or creates the data buffer array for a receive group.
        /// </summary>
        private byte[][] GetOrCreateReceiveGroup(uint groupBase)
        {
            byte[][] group;
            if (!_recvGroups.TryGetValue(groupBase, out group))
            {
                group = new byte[_groupSize][];
                _recvGroups[groupBase] = group;
            }

            return group;
        }

        /// <summary>
        /// Gets or creates the repair storage for a receive group.
        /// </summary>
        private SortedDictionary<int, byte[]> GetOrCreateRepairGroup(uint groupBase)
        {
            SortedDictionary<int, byte[]> repairs;
            if (!_recvRepairs.TryGetValue(groupBase, out repairs))
            {
                repairs = new SortedDictionary<int, byte[]>();
                _recvRepairs[groupBase] = repairs;
            }

            return repairs;
        }

        /// <summary>
        /// Clears all send buffer slots after a group has been flushed.
        /// </summary>
        private void ClearSendBuffer()
        {
            for (int i = 0; i < _groupSize; i++)
            {
                _sendBuffer[i] = null;
            }
        }

        /// <summary>
        /// Prunes old receive groups and repair data to bound memory usage.
        /// Retains at most the 16 most recent groups.
        /// </summary>
        private void PruneReceiveState()
        {
            // Prune data groups.
            while (_recvGroups.Count > 16)
            {
                uint oldest = uint.MaxValue;
                foreach (uint key in _recvGroups.Keys)
                {
                    if (key < oldest)
                    {
                        oldest = key;
                    }
                }

                _recvGroups.Remove(oldest);
                _recvRepairs.Remove(oldest);
            }

            // Prune orphaned repair groups.
            while (_recvRepairs.Count > 16)
            {
                uint oldest = uint.MaxValue;
                foreach (uint key in _recvRepairs.Keys)
                {
                    if (key < oldest)
                    {
                        oldest = key;
                    }
                }

                _recvRepairs.Remove(oldest);
            }
        }

        /// <summary>
        /// Solves a linear system Ax = b over GF(256) using Gaussian elimination
        /// with partial pivoting. Both A and b are modified in place.
        /// </summary>
        /// <param name="matrix">The coefficient matrix (size × size), modified in place.</param>
        /// <param name="rhs">The right-hand side vector, modified in place.</param>
        /// <param name="size">The dimension of the square system.</param>
        /// <returns>True if the system was solved successfully; false if singular.</returns>
        private static bool TrySolve(byte[,] matrix, byte[][] rhs, int size)
        {
            for (int col = 0; col < size; col++)
            {
                // Find a pivot row with a non-zero entry in this column.
                int pivot = col;
                while (pivot < size && matrix[pivot, col] == 0)
                {
                    pivot++;
                }

                if (pivot == size)
                {
                    return false; // Singular matrix.
                }

                if (pivot != col)
                {
                    SwapRows(matrix, rhs, pivot, col, size);
                }

                // Normalize the pivot row.
                byte inverse = GfInverse(matrix[col, col]);
                if (inverse != 1)
                {
                    for (int c = col; c < size; c++)
                    {
                        matrix[col, c] = GfMultiply(matrix[col, c], inverse);
                    }

                    MultiplyRow(rhs[col], inverse);
                }

                // Eliminate this column from all other rows.
                for (int row = 0; row < size; row++)
                {
                    if (row == col)
                    {
                        continue;
                    }

                    byte factor = matrix[row, col];
                    if (factor == 0)
                    {
                        continue;
                    }

                    for (int c = col; c < size; c++)
                    {
                        matrix[row, c] ^= GfMultiply(factor, matrix[col, c]);
                    }

                    AddScaledRow(rhs[row], rhs[col], factor);
                }
            }

            return true;
        }

        /// <summary>
        /// Swaps two rows of the matrix and RHS vector.
        /// </summary>
        private static void SwapRows(byte[,] matrix, byte[][] rhs, int left, int right, int size)
        {
            for (int col = 0; col < size; col++)
            {
                byte value = matrix[left, col];
                matrix[left, col] = matrix[right, col];
                matrix[right, col] = value;
            }

            byte[] row = rhs[left];
            rhs[left] = rhs[right];
            rhs[right] = row;
        }

        /// <summary>
        /// Multiplies every element of a row by a coefficient over GF(256).
        /// </summary>
        private static void MultiplyRow(byte[] row, byte coefficient)
        {
            for (int i = 0; i < row.Length; i++)
            {
                row[i] = GfMultiply(row[i], coefficient);
            }
        }

        /// <summary>
        /// Adds a scaled source row to the target row over GF(256): target += coefficient * source.
        /// </summary>
        private static void AddScaledRow(byte[] target, byte[] source, byte coefficient)
        {
            for (int i = 0; i < target.Length; i++)
            {
                target[i] ^= GfMultiply(coefficient, source[i]);
            }
        }

        /// <summary>
        /// Returns the Vandermonde-style coefficient for a given repair index and data slot.
        /// Coefficient = (repairIndex + 1)^slot in GF(256).
        /// </summary>
        private static byte GetCoefficient(int repairIndex, int slot)
        {
            return GfPower((byte)(repairIndex + 1), slot);
        }

        /// <summary>
        /// Multiplies two elements in GF(256) using precomputed exp/log tables.
        /// </summary>
        private static byte GfMultiply(byte left, byte right)
        {
            if (left == 0 || right == 0)
            {
                return 0;
            }

            return GfExp[GfLog[left] + GfLog[right]];
        }

        /// <summary>
        /// Computes the multiplicative inverse in GF(256).
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if attempting to invert zero.</exception>
        private static byte GfInverse(byte value)
        {
            if (value == 0)
            {
                throw new InvalidOperationException("Cannot invert zero in GF(256).");
            }

            return GfExp[255 - GfLog[value]];
        }

        /// <summary>
        /// Raises a GF(256) element to the given integer exponent.
        /// </summary>
        private static byte GfPower(byte value, int exponent)
        {
            if (exponent == 0)
            {
                return 1;
            }

            if (value == 0)
            {
                return 0;
            }

            return GfExp[(GfLog[value] * exponent) % 255];
        }

        /// <summary>
        /// Writes a big-endian 16-bit unsigned integer into a buffer.
        /// </summary>
        private static void WriteUInt16(ushort value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> 8);
            buffer[offset + 1] = (byte)value;
        }

        /// <summary>
        /// Reads a big-endian 16-bit unsigned integer from a buffer.
        /// </summary>
        private static ushort ReadUInt16(byte[] buffer, int offset)
        {
            return (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
        }
    }
}
