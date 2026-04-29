using System;
using System.Collections.Generic;

namespace Ucp
{
    /// <summary>
    /// Systematic Reed-Solomon-style Forward Error Correction encoder/decoder.
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
        internal sealed class RecoveredPacket
        {
            public int Slot;
            public byte[] Payload;
        }

        private static readonly byte[] GfExp = new byte[512];
        private static readonly byte[] GfLog = new byte[256];
        private readonly int _groupSize;
        private readonly int _repairCount;
        private readonly byte[][] _sendBuffer;
        private int _sendIndex;
        private readonly Dictionary<uint, byte[][]> _recvGroups = new Dictionary<uint, byte[][]>();
        private readonly Dictionary<uint, SortedDictionary<int, byte[]>> _recvRepairs = new Dictionary<uint, SortedDictionary<int, byte[]>>();

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
                    value ^= 0x11d;
                }
            }

            for (int i = 255; i < GfExp.Length; i++)
            {
                GfExp[i] = GfExp[i - 255];
            }
        }

        public UcpFecCodec(int groupSize)
            : this(groupSize, 1)
        {
        }

        public UcpFecCodec(int groupSize, int repairCount)
        {
            _groupSize = Math.Max(2, Math.Min(groupSize, 64));
            _repairCount = Math.Max(1, Math.Min(repairCount, _groupSize));
            _sendBuffer = new byte[_groupSize][];
        }

        public int RepairCount
        {
            get { return _repairCount; }
        }

        public byte[] TryEncodeRepair(byte[] payload)
        {
            List<byte[]> repairs = TryEncodeRepairs(payload);
            return repairs == null || repairs.Count == 0 ? null : repairs[0];
        }

        public List<byte[]> TryEncodeRepairs(byte[] payload)
        {
            _sendBuffer[_sendIndex] = payload;
            _sendIndex++;
            if (_sendIndex < _groupSize)
            {
                return null;
            }

            _sendIndex = 0;
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

                    WriteUInt16((ushort)p.Length, repair, slot * sizeof(ushort));
                    byte coefficient = GetCoefficient(repairIndex, slot);
                    int len = Math.Min(p.Length, maxLen);
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

        public int GetSlot(uint sequenceNumber)
        {
            return (int)(sequenceNumber % (uint)_groupSize);
        }

        public uint GetGroupBase(uint sequenceNumber)
        {
            return sequenceNumber / (uint)_groupSize * (uint)_groupSize;
        }

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

        public byte[] TryRecoverFromRepair(byte[] repair, uint groupBase)
        {
            int missingSlot;
            return TryRecoverFromRepair(repair, groupBase, out missingSlot);
        }

        public byte[] TryRecoverFromRepair(byte[] repair, uint groupBase, out int missingSlot)
        {
            return TryRecoverFromRepair(repair, groupBase, 0, out missingSlot);
        }

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

        public List<RecoveredPacket> TryRecoverPacketsFromStoredRepair(uint sequenceNumber)
        {
            uint groupBase = GetGroupBase(sequenceNumber);
            if (!_recvRepairs.ContainsKey(groupBase))
            {
                return new List<RecoveredPacket>();
            }

            return TryRecoverGroup(groupBase);
        }

        private List<RecoveredPacket> TryRecoverGroup(uint groupBase)
        {
            List<RecoveredPacket> recoveredPackets = new List<RecoveredPacket>();
            byte[][] group = GetOrCreateReceiveGroup(groupBase);

            SortedDictionary<int, byte[]> repairs;
            if (!_recvRepairs.TryGetValue(groupBase, out repairs) || repairs.Count == 0)
            {
                return recoveredPackets;
            }

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
                _recvRepairs.Remove(groupBase);
                return recoveredPackets;
            }

            if (repairs.Count < missingSlots.Count)
            {
                return recoveredPackets;
            }

            int lengthTableBytes = _groupSize * sizeof(ushort);
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

            int maxLen = selectedRepairs[0].Value.Length - lengthTableBytes;
            for (int i = 1; i < selectedRepairs.Count; i++)
            {
                maxLen = Math.Min(maxLen, selectedRepairs[i].Value.Length - lengthTableBytes);
            }

            int missingCount = missingSlots.Count;
            byte[,] matrix = new byte[missingCount, missingCount];
            byte[][] rhs = new byte[missingCount][];
            for (int row = 0; row < missingCount; row++)
            {
                int repairIndex = selectedRepairs[row].Key;
                byte[] repair = selectedRepairs[row].Value;
                rhs[row] = new byte[maxLen];
                Buffer.BlockCopy(repair, lengthTableBytes, rhs[row], 0, maxLen);

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

                for (int col = 0; col < missingCount; col++)
                {
                    matrix[row, col] = GetCoefficient(repairIndex, missingSlots[col]);
                }
            }

            if (!TrySolve(matrix, rhs, missingCount))
            {
                return recoveredPackets;
            }

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
                recoveredPackets.Add(new RecoveredPacket { Slot = slot, Payload = payload });
            }

            if (recoveredPackets.Count > 0)
            {
                _recvRepairs.Remove(groupBase);
            }

            return recoveredPackets;
        }

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

        private void ClearSendBuffer()
        {
            for (int i = 0; i < _groupSize; i++)
            {
                _sendBuffer[i] = null;
            }
        }

        private void PruneReceiveState()
        {
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

        private static bool TrySolve(byte[,] matrix, byte[][] rhs, int size)
        {
            for (int col = 0; col < size; col++)
            {
                int pivot = col;
                while (pivot < size && matrix[pivot, col] == 0)
                {
                    pivot++;
                }

                if (pivot == size)
                {
                    return false;
                }

                if (pivot != col)
                {
                    SwapRows(matrix, rhs, pivot, col, size);
                }

                byte inverse = GfInverse(matrix[col, col]);
                if (inverse != 1)
                {
                    for (int c = col; c < size; c++)
                    {
                        matrix[col, c] = GfMultiply(matrix[col, c], inverse);
                    }

                    MultiplyRow(rhs[col], inverse);
                }

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

        private static void MultiplyRow(byte[] row, byte coefficient)
        {
            for (int i = 0; i < row.Length; i++)
            {
                row[i] = GfMultiply(row[i], coefficient);
            }
        }

        private static void AddScaledRow(byte[] target, byte[] source, byte coefficient)
        {
            for (int i = 0; i < target.Length; i++)
            {
                target[i] ^= GfMultiply(coefficient, source[i]);
            }
        }

        private static byte GetCoefficient(int repairIndex, int slot)
        {
            return GfPower((byte)(repairIndex + 1), slot);
        }

        private static byte GfMultiply(byte left, byte right)
        {
            if (left == 0 || right == 0)
            {
                return 0;
            }

            return GfExp[GfLog[left] + GfLog[right]];
        }

        private static byte GfInverse(byte value)
        {
            if (value == 0)
            {
                throw new InvalidOperationException("Cannot invert zero in GF(256).");
            }

            return GfExp[255 - GfLog[value]];
        }

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

        private static void WriteUInt16(ushort value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> 8);
            buffer[offset + 1] = (byte)value;
        }

        private static ushort ReadUInt16(byte[] buffer, int offset)
        {
            return (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
        }
    }
}
