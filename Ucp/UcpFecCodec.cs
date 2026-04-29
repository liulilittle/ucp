using System;
using System.Collections.Generic;

namespace Ucp
{
    internal sealed class UcpFecCodec
    {
        private readonly int _groupSize;
        private readonly byte[][] _sendBuffer;
        private int _sendIndex;
        private readonly Dictionary<uint, byte[][]> _recvGroups = new Dictionary<uint, byte[][]>();

        public UcpFecCodec(int groupSize)
        {
            _groupSize = Math.Max(2, Math.Min(groupSize, 64));
            _sendBuffer = new byte[_groupSize][];
        }

        public byte[] TryEncodeRepair(byte[] payload)
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
                for (int i = 0; i < _groupSize; i++)
                {
                    _sendBuffer[i] = null;
                }

                return null;
            }

            byte[] repair = new byte[maxLen];
            for (int i = 0; i < _groupSize; i++)
            {
                byte[] p = _sendBuffer[i];
                if (p == null)
                {
                    continue;
                }

                int len = Math.Min(p.Length, repair.Length);
                for (int j = 0; j < len; j++)
                {
                    repair[j] ^= p[j];
                }
            }

            for (int i = 0; i < _groupSize; i++)
            {
                _sendBuffer[i] = null;
            }

            return repair;
        }

        public void FeedDataPacket(uint sequenceNumber, byte[] payload)
        {
            if (payload == null)
            {
                return;
            }

            uint groupBase = sequenceNumber / (uint)_groupSize * (uint)_groupSize;
            byte[][] group;
            if (!_recvGroups.TryGetValue(groupBase, out group))
            {
                group = new byte[_groupSize][];
                _recvGroups[groupBase] = group;
            }

            int slot = (int)(sequenceNumber % (uint)_groupSize);
            if (slot >= 0 && slot < _groupSize)
            {
                group[slot] = payload;
            }

            while (_recvGroups.Count > 16)
            {
                uint oldest = uint.MaxValue;
                foreach (uint k in _recvGroups.Keys)
                {
                    if (k < oldest)
                    {
                        oldest = k;
                    }
                }

                _recvGroups.Remove(oldest);
            }
        }

        public byte[] TryRecoverFromRepair(byte[] repair, uint groupBase)
        {
            if (repair == null)
            {
                return null;
            }

            byte[][] group;
            if (!_recvGroups.TryGetValue(groupBase, out group))
            {
                group = new byte[_groupSize][];
                _recvGroups[groupBase] = group;
            }

            int missingCount = 0;
            int missingSlot = -1;
            for (int i = 0; i < _groupSize; i++)
            {
                if (group[i] == null)
                {
                    missingCount++;
                    missingSlot = i;
                }
            }

            if (missingCount != 1 || missingSlot < 0)
            {
                return null;
            }

            byte[] recovered = new byte[repair.Length];
            Buffer.BlockCopy(repair, 0, recovered, 0, repair.Length);

            for (int i = 0; i < _groupSize; i++)
            {
                if (i == missingSlot)
                {
                    continue;
                }

                byte[] p = group[i];
                if (p == null)
                {
                    continue;
                }

                int len = Math.Min(p.Length, recovered.Length);
                for (int j = 0; j < len; j++)
                {
                    recovered[j] ^= p[j];
                }
            }

            group[missingSlot] = recovered;
            return recovered;
        }
    }
}
