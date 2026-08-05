using System;

namespace Ucp
{

    internal static class UcpPacketCodec
    {

        public static byte[] Encode(UcpPacket packet)
        {
            if (null == packet)
            {
                throw new ArgumentNullException(nameof(packet));
            }

            if (packet is UcpDataPacket)
            {
                return EncodeData((UcpDataPacket)packet);
            }

            if (packet is UcpAckPacket)
            {
                return EncodeAck((UcpAckPacket)packet);
            }

            if (packet is UcpNakPacket)
            {
                return EncodeNak((UcpNakPacket)packet);
            }

            if (packet is UcpFecRepairPacket)
            {
                return EncodeFecRepair((UcpFecRepairPacket)packet);
            }

            if (packet is UcpControlPacket)
            {
                return EncodeControl((UcpControlPacket)packet);
            }

            throw new NotSupportedException("Unknown UCP packet type.");
        }

        public static bool TryDecode(byte[] buffer, int offset, int count, out UcpPacket packet)
        {
            packet = null;
            if (null == buffer || count < UcpConstants.CommonHeaderSize || offset < 0 || count < 0 || offset + count > buffer.Length)
            {
                return false;
            }

            UcpCommonHeader header;
            if (!TryReadCommonHeader(buffer, offset, count, out header))
            {
                return false;
            }

            switch (header.Type)
            {
                case UcpPacketType.Data:
                    return TryDecodeData(buffer, offset, count, header, out packet);
                case UcpPacketType.Ack:
                    return TryDecodeAck(buffer, offset, count, header, out packet);
                case UcpPacketType.FecRepair:
                    return TryDecodeFecRepair(buffer, offset, count, header, out packet);
                case UcpPacketType.Nak:
                    return TryDecodeNak(buffer, offset, count, header, out packet);
                case UcpPacketType.Syn:
                case UcpPacketType.SynAck:
                case UcpPacketType.Fin:
                case UcpPacketType.Rst:

                    UcpControlPacket control = new UcpControlPacket();
                    control.Header = header;

                    int controlIndex = offset + UcpConstants.CommonHeaderSize;
                    bool hasAck = (header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
                    if (hasAck && count >= controlIndex + UcpConstants.ACK_NUMBER_SIZE)
                    {
                        control.AckNumber = ReadUInt32(buffer, controlIndex);
                        controlIndex += UcpConstants.ACK_NUMBER_SIZE;
                    }

                    if (count >= controlIndex + UcpConstants.SEQUENCE_NUMBER_SIZE)
                    {
                        control.HasSequenceNumber = true;
                        control.SequenceNumber = ReadUInt32(buffer, controlIndex);
                        controlIndex += UcpConstants.SEQUENCE_NUMBER_SIZE;
                    }

                    if (count >= controlIndex + UcpConstants.SESSION_KEY_SIZE)
                    {
                        control.SessionKey = ReadUInt64(buffer, controlIndex);
                    }

                    packet = control;
                    return true;
                default:
                    return false;
            }
        }

        private static byte[] EncodeControl(UcpControlPacket packet)
        {
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            int size = UcpConstants.CommonHeaderSize;
            if (hasAck)
            {
                size += UcpConstants.ACK_NUMBER_SIZE;
            }

            if (packet.HasSequenceNumber)
            {
                size += UcpConstants.SEQUENCE_NUMBER_SIZE;
            }

            if (0 != packet.SessionKey)
            {
                size += UcpConstants.SESSION_KEY_SIZE;
            }

            byte[] bytes = new byte[size];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);

            index += UcpConstants.CommonHeaderSize;
            if (hasAck)
            {
                WriteUInt32(packet.AckNumber, bytes, index);
                index += UcpConstants.ACK_NUMBER_SIZE;
            }

            if (packet.HasSequenceNumber)
            {
                WriteUInt32(packet.SequenceNumber, bytes, index);
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            }

            if (0 != packet.SessionKey)
            {
                WriteUInt64(packet.SessionKey, bytes, index);
            }

            return bytes;
        }

        private static byte[] EncodeData(UcpDataPacket packet)
        {
            int payloadLength = null == packet.Payload ? 0 : packet.Payload.Length;
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            int blockCount = hasAck && null != packet.SackBlocks ? Math.Min(packet.SackBlocks.Count, UcpConstants.MaxAckSackBlocks) : 0;

            int baseHeaderSize = hasAck ? UcpConstants.DATA_HEADER_SIZE_WITH_ACK : UcpConstants.DataHeaderSize;
            byte[] bytes = new byte[baseHeaderSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE) + payloadLength];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;
            WriteUInt32(packet.SequenceNumber, bytes, index);
            index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            WriteUInt16(packet.FragmentTotal, bytes, index);
            index += sizeof(ushort);
            WriteUInt16(packet.FragmentIndex, bytes, index);
            index += sizeof(ushort);

            if (hasAck)
            {

                WriteUInt32(packet.AckNumber, bytes, index);
                index += UcpConstants.ACK_NUMBER_SIZE;

                WriteUInt16((ushort)blockCount, bytes, index);
                index += sizeof(ushort);

                for (int i = 0; i < blockCount; i++)
                {
                    SackBlock block = packet.SackBlocks[i];
                    WriteUInt32(block.Start, bytes, index);
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                    WriteUInt32(block.End, bytes, index);
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                }

                WriteUInt32(packet.WindowSize, bytes, index);
                index += sizeof(uint);

                WriteUInt48(packet.EchoTimestamp, bytes, index);
                index += UcpConstants.ACK_TIMESTAMP_FIELD_SIZE;
            }

            if (payloadLength > 0)
            {
                Buffer.BlockCopy(packet.Payload, 0, bytes, index, payloadLength);
            }

            return bytes;
        }

        private static bool TryDecodeData(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet)
        {
            packet = null;
            bool hasAck = (header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            int minHeaderSize = hasAck ? UcpConstants.DATA_HEADER_SIZE_WITH_ACK : UcpConstants.DataHeaderSize;
            if (count < minHeaderSize)
            {
                return false;
            }

            int index = offset + UcpConstants.CommonHeaderSize;
            UcpDataPacket data = new UcpDataPacket();
            data.Header = header;
            data.SequenceNumber = ReadUInt32(buffer, index);
            index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            data.FragmentTotal = ReadUInt16(buffer, index);
            index += sizeof(ushort);
            data.FragmentIndex = ReadUInt16(buffer, index);
            index += sizeof(ushort);

            if (hasAck)
            {

                data.AckNumber = ReadUInt32(buffer, index);
                index += UcpConstants.ACK_NUMBER_SIZE;
                ushort blockCount = ReadUInt16(buffer, index);
                index += sizeof(ushort);

                int expectedSize = minHeaderSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE);
                if (count < expectedSize || blockCount > UcpConstants.MaxAckSackBlocks)
                {
                    return false;
                }

                for (int i = 0; i < blockCount; i++)
                {
                    SackBlock block = new SackBlock();
                    block.Start = ReadUInt32(buffer, index);
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                    block.End = ReadUInt32(buffer, index);
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                    data.SackBlocks.Add(block);
                }

                data.WindowSize = ReadUInt32(buffer, index);
                index += sizeof(uint);
                data.EchoTimestamp = ReadUInt48(buffer, index);
                index += UcpConstants.ACK_TIMESTAMP_FIELD_SIZE;
            }

            int payloadLength = count - (index - offset);
            if (payloadLength < 0)
            {
                return false;
            }

            data.Payload = new byte[payloadLength];
            if (payloadLength > 0)
            {
                Buffer.BlockCopy(buffer, index, data.Payload, 0, payloadLength);
            }

            packet = data;
            return true;
        }

        private static byte[] EncodeAck(UcpAckPacket packet)
        {
            int blockCount = null == packet.SackBlocks ? 0 : packet.SackBlocks.Count;
            if (blockCount > UcpConstants.MaxAckSackBlocks)
            {
                blockCount = UcpConstants.MaxAckSackBlocks;
            }

            byte[] bytes = new byte[UcpConstants.AckFixedSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE)];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;

            WriteUInt32(packet.AckNumber, bytes, index);
            index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            WriteUInt16((ushort)blockCount, bytes, index);
            index += sizeof(ushort);

            for (int i = 0; i < blockCount; i++)
            {
                SackBlock block = packet.SackBlocks[i];
                WriteUInt32(block.Start, bytes, index);
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                WriteUInt32(block.End, bytes, index);
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            }

            WriteUInt32(packet.WindowSize, bytes, index);
            index += sizeof(uint);

            WriteUInt48(packet.EchoTimestamp, bytes, index);
            return bytes;
        }

        private static bool TryDecodeAck(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet)
        {
            packet = null;
            if (count < UcpConstants.AckFixedSize)
            {
                return false;
            }

            int index = offset + UcpConstants.CommonHeaderSize;
            UcpAckPacket ack = new UcpAckPacket();
            ack.Header = header;
            ack.AckNumber = ReadUInt32(buffer, index);
            index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            ushort blockCount = ReadUInt16(buffer, index);
            index += sizeof(ushort);
            if (blockCount > UcpConstants.MaxAckSackBlocks)
            {
                blockCount = (ushort)UcpConstants.MaxAckSackBlocks;
            }

            int expectedSize = UcpConstants.AckFixedSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE);
            if (count < expectedSize)
            {
                return false;
            }

            for (int i = 0; i < blockCount; i++)
            {
                SackBlock block = new SackBlock();
                block.Start = ReadUInt32(buffer, index);
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                block.End = ReadUInt32(buffer, index);
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                ack.SackBlocks.Add(block);
            }

            ack.WindowSize = ReadUInt32(buffer, index);
            index += sizeof(uint);
            ack.EchoTimestamp = ReadUInt48(buffer, index);
            packet = ack;
            return true;
        }

        private static byte[] EncodeNak(UcpNakPacket packet)
        {
            int count = null == packet.MissingSequences ? 0 : packet.MissingSequences.Count;
            if (count > UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET)
            {
                count = UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET;
            }
            byte[] bytes = new byte[UcpConstants.NakFixedSize + (count * UcpConstants.SEQUENCE_NUMBER_SIZE)];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;

            WriteUInt32(packet.AckNumber, bytes, index);
            index += UcpConstants.ACK_NUMBER_SIZE;

            WriteUInt16((ushort)count, bytes, index);
            index += sizeof(ushort);

            for (int i = 0; i < count; i++)
            {
                WriteUInt32(packet.MissingSequences[i], bytes, index);
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            }

            return bytes;
        }

        private static bool TryDecodeNak(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet)
        {
            packet = null;
            if (count < UcpConstants.NakFixedSize)
            {
                return false;
            }

            int index = offset + UcpConstants.CommonHeaderSize;
            UcpNakPacket nak = new UcpNakPacket();
            nak.Header = header;
            nak.AckNumber = ReadUInt32(buffer, index);
            index += UcpConstants.ACK_NUMBER_SIZE;

            ushort missingCount = ReadUInt16(buffer, index);
            index += sizeof(ushort);

            int expectedSize = UcpConstants.NakFixedSize + (missingCount * UcpConstants.SEQUENCE_NUMBER_SIZE);
            if (count < expectedSize || missingCount > UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET)
            {
                return false;
            }

            for (int i = 0; i < missingCount; i++)
            {
                nak.MissingSequences.Add(ReadUInt32(buffer, index));
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            }

            packet = nak;
            return true;
        }

        private static bool TryReadCommonHeader(byte[] buffer, int offset, int count, out UcpCommonHeader header)
        {
            header = new UcpCommonHeader();
            if (count < UcpConstants.CommonHeaderSize)
            {
                return false;
            }

            header.Type = (UcpPacketType)buffer[offset];
            header.Flags = (UcpPacketFlags)buffer[offset + 1];

            header.ConnectionId = ReadUInt32(buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE);

            header.Timestamp = ReadUInt48(buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE + UcpConstants.CONNECTION_ID_SIZE);
            return true;
        }

        private static void WriteCommonHeader(UcpCommonHeader header, byte[] buffer, int offset)
        {

            buffer[offset] = (byte)header.Type;
            buffer[offset + 1] = (byte)header.Flags;

            WriteUInt32(header.ConnectionId, buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE);

            WriteUInt48(header.Timestamp, buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE + UcpConstants.CONNECTION_ID_SIZE);
        }

        private static void WriteUInt16(ushort value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> UcpConstants.BYTE_BITS);
            buffer[offset + 1] = (byte)value;
        }

        private static ushort ReadUInt16(byte[] buffer, int offset)
        {
            return (ushort)((buffer[offset] << UcpConstants.BYTE_BITS) | buffer[offset + 1]);
        }

        private static void WriteUInt32(uint value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> UcpConstants.UINT24_BITS);
            buffer[offset + 1] = (byte)(value >> UcpConstants.UINT16_BITS);
            buffer[offset + 2] = (byte)(value >> UcpConstants.BYTE_BITS);
            buffer[offset + 3] = (byte)value;
        }

        private static uint ReadUInt32(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset] << UcpConstants.UINT24_BITS)
                | ((uint)buffer[offset + 1] << UcpConstants.UINT16_BITS)
                | ((uint)buffer[offset + 2] << UcpConstants.BYTE_BITS)
                | buffer[offset + 3];
        }

        private static void WriteUInt48(long value, byte[] buffer, int offset)
        {
            ulong normalized = (ulong)value & UcpConstants.UINT48_MASK;
            buffer[offset] = (byte)(normalized >> UcpConstants.UINT40_BITS);
            buffer[offset + 1] = (byte)(normalized >> UcpConstants.UINT32_BITS);
            buffer[offset + 2] = (byte)(normalized >> UcpConstants.UINT24_BITS);
            buffer[offset + 3] = (byte)(normalized >> UcpConstants.UINT16_BITS);
            buffer[offset + 4] = (byte)(normalized >> UcpConstants.BYTE_BITS);
            buffer[offset + 5] = (byte)normalized;
        }

        private static long ReadUInt48(byte[] buffer, int offset)
        {
            ulong value = ((ulong)buffer[offset] << UcpConstants.UINT40_BITS)
                | ((ulong)buffer[offset + 1] << UcpConstants.UINT32_BITS)
                | ((ulong)buffer[offset + 2] << UcpConstants.UINT24_BITS)
                | ((ulong)buffer[offset + 3] << UcpConstants.UINT16_BITS)
                | ((ulong)buffer[offset + 4] << UcpConstants.BYTE_BITS)
                | buffer[offset + 5];
            return (long)value;
        }

        private static void WriteUInt64(ulong value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> 56);
            buffer[offset + 1] = (byte)(value >> 48);
            buffer[offset + 2] = (byte)(value >> 40);
            buffer[offset + 3] = (byte)(value >> 32);
            buffer[offset + 4] = (byte)(value >> 24);
            buffer[offset + 5] = (byte)(value >> 16);
            buffer[offset + 6] = (byte)(value >> 8);
            buffer[offset + 7] = (byte)value;
        }

        private static ulong ReadUInt64(byte[] buffer, int offset)
        {
            return ((ulong)buffer[offset] << 56)
                | ((ulong)buffer[offset + 1] << 48)
                | ((ulong)buffer[offset + 2] << 40)
                | ((ulong)buffer[offset + 3] << 32)
                | ((ulong)buffer[offset + 4] << 24)
                | ((ulong)buffer[offset + 5] << 16)
                | ((ulong)buffer[offset + 6] << 8)
                | buffer[offset + 7];
        }

        private static byte[] EncodeFecRepair(UcpFecRepairPacket packet)
        {
            int payloadLen = null == packet.Payload ? 0 : packet.Payload.Length;
            int totalSize = UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte) + payloadLen;
            if (totalSize < payloadLen || totalSize < UcpConstants.CommonHeaderSize)
            {
                throw new ArgumentOutOfRangeException(nameof(packet), "FEC repair packet size would overflow.");
            }
            byte[] bytes = new byte[totalSize];
            WriteCommonHeader(packet.Header, bytes, 0);

            WriteUInt32(packet.GroupId, bytes, UcpConstants.CommonHeaderSize);

            bytes[UcpConstants.CommonHeaderSize + sizeof(uint)] = packet.GroupIndex;
            if (payloadLen > 0)
            {
                Buffer.BlockCopy(packet.Payload, 0, bytes, UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte), payloadLen);
            }

            return bytes;
        }

        private static bool TryDecodeFecRepair(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet)
        {
            packet = null;
            if (count < UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte))
            {
                return false;
            }

            UcpFecRepairPacket repair = new UcpFecRepairPacket();
            repair.Header = header;
            repair.GroupId = ReadUInt32(buffer, offset + UcpConstants.CommonHeaderSize);
            repair.GroupIndex = buffer[offset + UcpConstants.CommonHeaderSize + sizeof(uint)];
            int payloadLen = count - (UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte));
            if (payloadLen < 0)
            {
                return false;
            }

            if (payloadLen > 0)
            {
                repair.Payload = new byte[payloadLen];
                Buffer.BlockCopy(buffer, offset + UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte), repair.Payload, 0, payloadLen);
            }
            else
            {
                repair.Payload = null;
            }

            packet = repair;
            return true;
        }
    }
}
