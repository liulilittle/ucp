using System;

namespace Ucp
{
    internal sealed class UcpFecCodec
    {
        private readonly int _groupSize;
        private readonly byte[][] _sendBuffer;
        private int _sendIndex;

        private readonly byte[][] _recvBuffer;
        private readonly bool[] _received;
        private readonly bool[] _groupsSealed;
        private int _recvGroupIndex;

        public UcpFecCodec(int groupSize)
        {
            _groupSize = Math.Max(2, groupSize);
            _sendBuffer = new byte[_groupSize][];
            _recvBuffer = new byte[_groupSize][];
            _received = new bool[_groupSize];
            _groupsSealed = new bool[2];
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

        public byte[] TryRecoverFromRepair(byte[] repair, uint sequenceInGroup, byte[] dataPayload)
        {
            int index = (int)(sequenceInGroup % (uint)_groupSize);
            if (dataPayload != null)
            {
                _recvBuffer[index] = dataPayload;
                _received[index] = true;
            }

            if (_recvGroupIndex != (int)(sequenceInGroup / (uint)_groupSize))
            {
                _recvGroupIndex = (int)(sequenceInGroup / (uint)_groupSize);
                for (int i = 0; i < _groupSize; i++)
                {
                    _recvBuffer[i] = null;
                    _received[i] = false;
                }

                _groupsSealed[0] = false;
                _groupsSealed[1] = false;
                if (dataPayload != null)
                {
                    _recvBuffer[index] = dataPayload;
                    _received[index] = true;
                }
            }

            if (repair == null)
            {
                return null;
            }

            int missingCount = 0;
            int missingIndex = -1;
            for (int i = 0; i < _groupSize; i++)
            {
                if (!_received[i])
                {
                    missingCount++;
                    missingIndex = i;
                }
            }

            if (missingCount != 1 || missingIndex < 0)
            {
                return null;
            }

            byte[] recovered = new byte[repair.Length];
            Buffer.BlockCopy(repair, 0, recovered, 0, repair.Length);

            for (int i = 0; i < _groupSize; i++)
            {
                if (i == missingIndex)
                {
                    continue;
                }

                byte[] p = _recvBuffer[i];
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

            _recvBuffer[missingIndex] = recovered;
            _received[missingIndex] = true;

            return recovered;
        }
    }
}
