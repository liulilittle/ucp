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
            int value = 1; // Start with the primitive element α^0 = 1 in GF(256)
            for (int i = 0; i < 255; i++) // Iterate through all 255 non-zero field elements
            {
                GfExp[i] = (byte)value; // Store α^i in the exponentiation table at index i
                GfLog[value] = (byte)i; // Store the discrete logarithm of α^i as i
                value <<= 1; // Multiply by α (which is x, the polynomial 0x02) via left shift
                if ((value & 0x100) != 0) // Check if result exceeds GF(256) — bit 8 is set
                {
                    value ^= 0x11d; // Reduce modulo generator polynomial: x^8 + x^4 + x^3 + x^2 + 1
                }
            }

            // Double the table for fast wrap-around in multiplication.
            for (int i = 255; i < GfExp.Length; i++) // Fill indices 255..511 for wrap-free lookup
            {
                GfExp[i] = GfExp[i - 255]; // Copy first 255 entries — mimics α^(i mod 255)
            }
        }

        /// <summary>
        /// Creates an FEC codec with a single repair packet per group.
        /// </summary>
        /// <param name="groupSize">Number of data packets per group.</param>
        public UcpFecCodec(int groupSize)
            : this(groupSize, 1) // Default to a single repair packet per group
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
            _groupSize = Math.Max(2, Math.Min(groupSize, 64)); // Clamp group size to [2, 64] for safety
            _repairCount = Math.Max(1, Math.Min(repairCount, _groupSize)); // Clamp repair count to [1, groupSize] — must have at least 1
            _sendBuffer = new byte[_groupSize][]; // Allocate circular send buffer with one slot per group member
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
            List<byte[]> repairs = TryEncodeRepairs(payload); // Delegate to multi-repair method
            return repairs == null || repairs.Count == 0 ? null : repairs[0]; // Return first repair or null if group not full
        }

        /// <summary>
        /// Feeds a payload into the send buffer. When the group is full, generates
        /// and returns all repair packets for this group.
        /// </summary>
        /// <param name="payload">The data payload to encode.</param>
        /// <returns>List of repair payloads, or null if the group is not yet full.</returns>
        public List<byte[]> TryEncodeRepairs(byte[] payload)
        {
            _sendBuffer[_sendIndex] = payload; // Store this payload at the current circular buffer position
            _sendIndex++; // Advance write position for next call
            if (_sendIndex < _groupSize) // Group is not yet complete — wait for more data packets
            {
                return null; // Group not yet complete.
            }

            _sendIndex = 0; // Reset write position for the next group

            // Determine the maximum payload length across all slots.
            int maxLen = 0; // Track the longest payload to size parity data
            for (int i = 0; i < _groupSize; i++) // Scan all slots in the group
            {
                byte[] p = _sendBuffer[i]; // Retrieve payload at slot i
                if (p != null && p.Length > maxLen) // Found a longer valid payload
                {
                    maxLen = p.Length; // Update maximum length
                }
            }

            if (maxLen == 0) // All slots are null or empty — nothing to protect
            {
                ClearSendBuffer(); // Reset buffer state
                return null;
            }

            // Each repair carries a length table (2 bytes per slot) followed by parity.
            int lengthTableBytes = _groupSize * sizeof(ushort); // Header size: 2 bytes per slot (big-endian lengths)
            List<byte[]> repairs = new List<byte[]>(_repairCount); // Pre-allocate list for all repair packets
            for (int repairIndex = 0; repairIndex < _repairCount; repairIndex++) // Generate one repair per redundancy unit
            {
                byte[] repair = new byte[lengthTableBytes + maxLen]; // Allocate header + parity body
                for (int slot = 0; slot < _groupSize; slot++) // Process each data slot for this repair
                {
                    byte[] p = _sendBuffer[slot]; // Get the payload from this slot
                    if (p == null) // Slot is empty in this group — skip it
                    {
                        continue;
                    }

                    // Write this slot's length into the length table.
                    WriteUInt16((ushort)p.Length, repair, slot * sizeof(ushort)); // Store payload length so decoder knows original size
                    byte coefficient = GetCoefficient(repairIndex, slot); // Vandermonde coefficient α^slot for this repair row
                    int len = Math.Min(p.Length, maxLen); // Process only up to known payload bytes (should equal p.Length)
                    // XOR this slot's payload into the parity (scaled by coefficient).
                    for (int j = 0; j < len; j++) // Mix each byte with GF(256) scaling
                    {
                        repair[lengthTableBytes + j] ^= GfMultiply(coefficient, p[j]); // Encode: parity[j] += coeff * data[slot][j]
                    }
                }

                repairs.Add(repair); // Append this completed repair packet to the output list
            }

            ClearSendBuffer(); // Free references to allow GC of consumed payloads
            return repairs;
        }

        /// <summary>
        /// Returns the slot index within a group for the given sequence number.
        /// </summary>
        /// <param name="sequenceNumber">The data packet sequence number.</param>
        /// <returns>Zero-based slot index.</returns>
        public int GetSlot(uint sequenceNumber)
        {
            return (int)(sequenceNumber % (uint)_groupSize); // Slot index = sequence mod group size (circular wrapping)
        }

        /// <summary>
        /// Returns the base sequence number (first slot) of the group containing
        /// the given sequence number.
        /// </summary>
        /// <param name="sequenceNumber">A sequence number within the group.</param>
        /// <returns>The group's base sequence number.</returns>
        public uint GetGroupBase(uint sequenceNumber)
        {
            return sequenceNumber / (uint)_groupSize * (uint)_groupSize; // Integer division truncates, then multiply gives base
        }

        /// <summary>
        /// Stores a received data packet in the receive buffer for its group.
        /// </summary>
        /// <param name="sequenceNumber">The packet's sequence number.</param>
        /// <param name="payload">The packet's payload.</param>
        public void FeedDataPacket(uint sequenceNumber, byte[] payload)
        {
            if (payload == null) // Null payload means nothing to store
            {
                return;
            }

            uint groupBase = GetGroupBase(sequenceNumber); // Determine which group this packet belongs to
            byte[][] group = GetOrCreateReceiveGroup(groupBase); // Get or allocate the group's data slot array
            int slot = GetSlot(sequenceNumber); // Compute the slot index within the group
            if (slot >= 0 && slot < _groupSize) // Safety check on slot bounds
            {
                group[slot] = payload; // Store payload at the correct slot for later reconstruction
            }

            PruneReceiveState(); // Limit memory usage by evicting old groups
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
            int missingSlot; // Declared for out param — value ignored by this overload
            return TryRecoverFromRepair(repair, groupBase, out missingSlot); // Delegate to out-parameter version
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
            return TryRecoverFromRepair(repair, groupBase, 0, out missingSlot); // Default repair index 0 (single-repair case)
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
            missingSlot = -1; // Initialize to "not found" before attempting recovery
            List<RecoveredPacket> recovered = TryRecoverPacketsFromRepair(repair, groupBase, repairIndex); // Run full recovery
            if (recovered.Count == 0) // No packets were recovered
            {
                return null;
            }

            missingSlot = recovered[0].Slot; // Report which slot was recovered
            return recovered[0].Payload; // Return the recovered payload bytes
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
            missingSlot = -1; // Initialize to "not found"
            List<RecoveredPacket> recovered = TryRecoverPacketsFromStoredRepair(sequenceNumber); // Attempt recovery from buffered repairs
            if (recovered.Count == 0) // Recovery produced no results
            {
                return null;
            }

            missingSlot = recovered[0].Slot; // Report the first recovered slot index
            return recovered[0].Payload; // Return the first recovered payload
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
            if (repair == null) // Nothing to process
            {
                return new List<RecoveredPacket>();
            }

            SortedDictionary<int, byte[]> repairs = GetOrCreateRepairGroup(groupBase); // Get or allocate repair storage for this group
            repairs[repairIndex] = repair; // Store this repair indexed by its repair index
            List<RecoveredPacket> recovered = TryRecoverGroup(groupBase); // Attempt Gaussian elimination on the group
            PruneReceiveState(); // Bound memory usage after processing
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
            uint groupBase = GetGroupBase(sequenceNumber); // Find the group for this sequence number
            if (!_recvRepairs.ContainsKey(groupBase)) // No stored repairs for this group — cannot recover
            {
                return new List<RecoveredPacket>();
            }

            return TryRecoverGroup(groupBase); // Attempt recovery with existing buffered data and repairs
        }

        /// <summary>
        /// Attempts Gaussian elimination to recover all missing packets in a group.
        /// Requires at least as many independent repair packets as missing data slots.
        /// </summary>
        /// <param name="groupBase">The base sequence number of the group.</param>
        /// <returns>List of successfully recovered packets.</returns>
        private List<RecoveredPacket> TryRecoverGroup(uint groupBase)
        {
            List<RecoveredPacket> recoveredPackets = new List<RecoveredPacket>(); // Accumulator for successfully recovered packets
            byte[][] group = GetOrCreateReceiveGroup(groupBase); // Get the data slot array for this group

            SortedDictionary<int, byte[]> repairs;
            if (!_recvRepairs.TryGetValue(groupBase, out repairs) || repairs.Count == 0) // No repair data available — cannot recover
            {
                return recoveredPackets;
            }

            // Identify which slots are missing.
            List<int> missingSlots = new List<int>(); // Collect indices of null (missing) data slots
            for (int i = 0; i < _groupSize; i++) // Scan every slot in the group
            {
                if (group[i] == null) // This slot has not been received
                {
                    missingSlots.Add(i); // Record as missing
                }
            }

            if (missingSlots.Count == 0) // All data packets have arrived — group is complete
            {
                _recvRepairs.Remove(groupBase); // Group complete; clean up.
                return recoveredPackets;
            }

            if (repairs.Count < missingSlots.Count) // Need at least one repair per missing slot for Gaussian elimination
            {
                return recoveredPackets; // Not enough repair packets yet.
            }

            int lengthTableBytes = _groupSize * sizeof(ushort); // Size of the length table header in repair packets
            // Select the required number of valid repairs.
            List<KeyValuePair<int, byte[]>> selectedRepairs = new List<KeyValuePair<int, byte[]>>(missingSlots.Count); // Pre-size for needed count
            foreach (KeyValuePair<int, byte[]> pair in repairs) // Iterate stored repairs sorted by repair index
            {
                if (pair.Value != null && pair.Value.Length >= lengthTableBytes && selectedRepairs.Count < missingSlots.Count) // Valid and still need more
                {
                    selectedRepairs.Add(pair); // Pick this repair for the linear system
                }
            }

            if (selectedRepairs.Count < missingSlots.Count) // Still not enough after filtering invalid ones
            {
                return recoveredPackets;
            }

            // Compute the minimum repair payload length (after the length table).
            int maxLen = selectedRepairs[0].Value.Length - lengthTableBytes; // Start with first repair's data length
            for (int i = 1; i < selectedRepairs.Count; i++) // Check remaining repairs
            {
                maxLen = Math.Min(maxLen, selectedRepairs[i].Value.Length - lengthTableBytes); // Use the smallest common length for consistency
            }

            int missingCount = missingSlots.Count; // Number of unknowns to solve for
            // Build the coefficient matrix and RHS vector for GF(256) linear system.
            byte[,] matrix = new byte[missingCount, missingCount]; // Square coefficient matrix A (Vandermonde over GF(256))
            byte[][] rhs = new byte[missingCount][]; // Right-hand side vector: one row per selected repair
            for (int row = 0; row < missingCount; row++) // Build one row of the linear system per repair
            {
                int repairIndex = selectedRepairs[row].Key; // Which repair packet (0-based index) this row represents
                byte[] repair = selectedRepairs[row].Value; // The raw repair packet bytes
                rhs[row] = new byte[maxLen]; // Allocate RHS buffer sized to common payload length
                Buffer.BlockCopy(repair, lengthTableBytes, rhs[row], 0, maxLen); // Copy parity bytes after length table into RHS

                // Subtract known data contributions from the parity.
                for (int knownSlot = 0; knownSlot < _groupSize; knownSlot++) // For each data slot in the group
                {
                    byte[] known = group[knownSlot]; // Get the payload at this slot (may be null)
                    if (known == null) // This slot was not received — its contribution is unknown and stays in RHS
                    {
                        continue;
                    }

                    byte coefficient = GetCoefficient(repairIndex, knownSlot); // Vandermonde coefficient for this (repair, slot) pair
                    int len = Math.Min(known.Length, maxLen); // Process only within the common payload length
                    for (int j = 0; j < len; j++) // Mix each byte: subtract (XOR) the known contribution
                    {
                        rhs[row][j] ^= GfMultiply(coefficient, known[j]); // RHS -= coeff * data[slot][j] in GF(256)
                    }
                }

                // Build the Vandermonde-style matrix for the missing slots.
                for (int col = 0; col < missingCount; col++) // Populate one matrix column per missing slot
                {
                    matrix[row, col] = GetCoefficient(repairIndex, missingSlots[col]); // A[row,col] = α^{(repairIndex+1)*missingSlot} in GF(256)
                }
            }

            if (!TrySolve(matrix, rhs, missingCount)) // Run Gaussian elimination over GF(256) — returns false if singular
            {
                return recoveredPackets; // Matrix is singular or under-determined.
            }

            // Extract recovered payloads using the length table from the first repair.
            // The length table comes from untrusted network input — validate before use.
            byte[] lengthTable = selectedRepairs[0].Value; // Use first repair's length table to get original payload sizes
            // Validate all slot lengths in the length table against known bounds.
            int totalSlotLengths = 0; // Accumulator for sum check
            for (int slot = 0; slot < _groupSize; slot++) // Validate every slot length entry
            {
                int slotLength = ReadUInt16(lengthTable, slot * sizeof(ushort)); // Read big-endian 16-bit length from header
                if (slotLength < 0 || slotLength > UcpConstants.MAX_FEC_SLOT_LENGTH) // Individual slot exceeds max payload
                {
                    return recoveredPackets; // Corrupt or malicious length table — abort recovery
                }
                totalSlotLengths += slotLength; // Accumulate for group-wide sum check
            }
            if (totalSlotLengths > _groupSize * UcpConstants.MAX_FEC_SLOT_LENGTH) // Sum exceeds reasonable maximum
            {
                return recoveredPackets; // Total length implausible — reject untrusted input
            }
            for (int i = 0; i < missingCount; i++) // Extract each recovered payload from the solved system
            {
                int slot = missingSlots[i]; // Original slot index of this recovered packet
                int missingLength = ReadUInt16(lengthTable, slot * sizeof(ushort)); // Original payload length from length table
                if (missingLength < 0 || missingLength > maxLen) // Validate against computed max payload length
                {
                    continue; // Invalid length for this slot — skip recovery for this sequence
                }

                byte[] payload = new byte[missingLength]; // Allocate buffer for the recovered payload
                Buffer.BlockCopy(rhs[i], 0, payload, 0, missingLength); // Copy solved unknown vector into payload
                group[slot] = payload; // Store recovered payload in the group (may help future recoveries)
                recoveredPackets.Add(new RecoveredPacket { Slot = slot, SequenceNumber = groupBase + (uint)slot, Payload = payload }); // Build result record
            }

            if (recoveredPackets.Count > 0) // At least one packet was recovered
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
            if (!_recvGroups.TryGetValue(groupBase, out group)) // Group not yet allocated for this base sequence
            {
                group = new byte[_groupSize][]; // Allocate array with one slot per group member
                _recvGroups[groupBase] = group; // Register in the dictionary for future lookups
            }

            return group;
        }

        /// <summary>
        /// Gets or creates the repair storage for a receive group.
        /// </summary>
        private SortedDictionary<int, byte[]> GetOrCreateRepairGroup(uint groupBase)
        {
            SortedDictionary<int, byte[]> repairs;
            if (!_recvRepairs.TryGetValue(groupBase, out repairs)) // No repair storage yet for this group
            {
                repairs = new SortedDictionary<int, byte[]>(); // Create sorted dictionary keyed by repair index
                _recvRepairs[groupBase] = repairs; // Register for future access
            }

            return repairs;
        }

        /// <summary>
        /// Clears all send buffer slots after a group has been flushed.
        /// </summary>
        private void ClearSendBuffer()
        {
            for (int i = 0; i < _groupSize; i++) // Iterate all slots in the send buffer
            {
                _sendBuffer[i] = null; // Release reference to allow GC of consumed payload data
            }
        }

        /// <summary>
        /// Prunes old receive groups and repair data to bound memory usage.
        /// Retains at most the 16 most recent groups.
        /// </summary>
        private void PruneReceiveState()
        {
            // Prune data groups.
            while (_recvGroups.Count > 16) // Keep at most 16 recent groups to bound memory
            {
                uint oldest = uint.MaxValue; // Track the smallest (oldest) group base key
                foreach (uint key in _recvGroups.Keys) // Scan all group keys
                {
                    if (key < oldest) // Found an older group
                    {
                        oldest = key; // Update current oldest
                    }
                }

                _recvGroups.Remove(oldest); // Evict the oldest data group
                _recvRepairs.Remove(oldest); // Also evict its associated repair data
            }

            // Prune orphaned repair groups.
            while (_recvRepairs.Count > 16) // Also limit orphaned repair groups to 16
            {
                uint oldest = uint.MaxValue; // Track the smallest repair group key
                foreach (uint key in _recvRepairs.Keys) // Scan all repair group keys
                {
                    if (key < oldest) // Found an older repair group
                    {
                        oldest = key; // Update current oldest
                    }
                }

                _recvRepairs.Remove(oldest); // Evict the oldest orphaned repair group
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
            for (int col = 0; col < size; col++) // Forward elimination: process each column as pivot column
            {
                // Find a pivot row with a non-zero entry in this column.
                int pivot = col; // Start searching from the diagonal position
                while (pivot < size && matrix[pivot, col] == 0) // Skip rows with zero in this column
                {
                    pivot++; // Try the next row down
                }

                if (pivot == size) // No non-zero entry found in this column — matrix is singular
                {
                    return false; // Singular matrix.
                }

                if (pivot != col) // Pivot is not on the diagonal — need to swap rows
                {
                    SwapRows(matrix, rhs, pivot, col, size); // Bring the pivot row to the current diagonal position
                }

                // Normalize the pivot row.
                byte inverse = GfInverse(matrix[col, col]); // Compute multiplicative inverse of the pivot element
                if (inverse != 1) // Skip identity multiplication if pivot is already 1
                {
                    for (int c = col; c < size; c++) // Scale every element in the pivot row from column 'col' onward
                    {
                        matrix[col, c] = GfMultiply(matrix[col, c], inverse); // Normalize: row[col] becomes 1
                    }

                    MultiplyRow(rhs[col], inverse); // Apply same scaling to the RHS vector
                }

                // Eliminate this column from all other rows.
                for (int row = 0; row < size; row++) // Process every row in the matrix
                {
                    if (row == col) // Skip the pivot row itself
                    {
                        continue;
                    }

                    byte factor = matrix[row, col]; // The value to eliminate in this row
                    if (factor == 0) // Already zero — nothing to do
                    {
                        continue;
                    }

                    for (int c = col; c < size; c++) // Eliminate column 'col' from this row using XOR with scaled pivot row
                    {
                        matrix[row, c] ^= GfMultiply(factor, matrix[col, c]); // In GF(256): row = row + factor * pivot_row
                    }

                    AddScaledRow(rhs[row], rhs[col], factor); // Apply same elimination to RHS vector
                }
            }

            return true; // System solved successfully — matrix is now identity, RHS is solution
        }

        /// <summary>
        /// Swaps two rows of the matrix and RHS vector.
        /// </summary>
        private static void SwapRows(byte[,] matrix, byte[][] rhs, int left, int right, int size)
        {
            for (int col = 0; col < size; col++) // Swap every element in both matrix rows
            {
                byte value = matrix[left, col]; // Temporarily hold left row element
                matrix[left, col] = matrix[right, col]; // Copy right into left
                matrix[right, col] = value; // Copy saved left into right
            }

            byte[] row = rhs[left]; // Temporarily hold left RHS row reference
            rhs[left] = rhs[right]; // Copy right RHS to left
            rhs[right] = row; // Copy saved left RHS to right
        }

        /// <summary>
        /// Multiplies every element of a row by a coefficient over GF(256).
        /// </summary>
        private static void MultiplyRow(byte[] row, byte coefficient)
        {
            for (int i = 0; i < row.Length; i++) // Scale every element in the row
            {
                row[i] = GfMultiply(row[i], coefficient); // Multiply each byte by coefficient in GF(256)
            }
        }

        /// <summary>
        /// Adds a scaled source row to the target row over GF(256): target += coefficient * source.
        /// </summary>
        private static void AddScaledRow(byte[] target, byte[] source, byte coefficient)
        {
            for (int i = 0; i < target.Length; i++) // Process each byte in the row
            {
                target[i] ^= GfMultiply(coefficient, source[i]); // target += coefficient * source using GF(256) arithmetic
            }
        }

        /// <summary>
        /// Returns the Vandermonde-style coefficient for a given repair index and data slot.
        /// Coefficient = (repairIndex + 1)^slot in GF(256).
        /// </summary>
        private static byte GetCoefficient(int repairIndex, int slot)
        {
            return GfPower((byte)(repairIndex + 1), slot); // Vandermonde coefficient α^{(repairIndex+1)*slot} — ensures distinct rows
        }

        /// <summary>
        /// Multiplies two elements in GF(256) using precomputed exp/log tables.
        /// </summary>
        private static byte GfMultiply(byte left, byte right)
        {
            if (left == 0 || right == 0) // Anything times zero is zero in any field
            {
                return 0;
            }

            return GfExp[GfLog[left] + GfLog[right]]; // a * b = α^{log(a) + log(b)} using precomputed tables
        }

        /// <summary>
        /// Computes the multiplicative inverse in GF(256).
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if attempting to invert zero.</exception>
        private static byte GfInverse(byte value)
        {
            if (value == 0) // Zero has no multiplicative inverse — caller must ensure this never happens
            {
                throw new InvalidOperationException("Cannot invert zero in GF(256).");
            }

            return GfExp[255 - GfLog[value]]; // α^{-log(value)} = α^{255 - log(value)} since α^{255} = 1
        }

        /// <summary>
        /// Raises a GF(256) element to the given integer exponent.
        /// </summary>
        private static byte GfPower(byte value, int exponent)
        {
            if (exponent == 0) // Any non-zero element to the 0th power is 1
            {
                return 1;
            }

            if (value == 0) // 0 to any positive power is 0
            {
                return 0;
            }

            return GfExp[(GfLog[value] * exponent) % 255]; // α^{(log(value) * exponent) mod 255} since order is 255
        }

        /// <summary>
        /// Writes a big-endian 16-bit unsigned integer into a buffer.
        /// </summary>
        private static void WriteUInt16(ushort value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> 8); // Write high byte (big-endian: most significant byte first)
            buffer[offset + 1] = (byte)value; // Write low byte (least significant byte)
        }

        /// <summary>
        /// Reads a big-endian 16-bit unsigned integer from a buffer.
        /// </summary>
        private static ushort ReadUInt16(byte[] buffer, int offset)
        {
            return (ushort)((buffer[offset] << 8) | buffer[offset + 1]); // Big-endian: high byte shifted 8 bits, OR with low byte
        }
    }
}
