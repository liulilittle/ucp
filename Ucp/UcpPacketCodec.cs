using System;

namespace Ucp
{
    /// <summary>
    /// Encodes and decodes protocol packets in big-endian byte order.
    /// </summary>
    internal static class UcpPacketCodec
    {
        public static byte[] Encode(UcpPacket packet)
        {
            if (packet == null)
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
            if (buffer == null || count < UcpConstants.CommonHeaderSize || offset < 0 || count < 0 || offset + count > buffer.Length)
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
                    if (count >= UcpConstants.CommonHeaderSize + UcpConstants.SEQUENCE_NUMBER_SIZE)
                    {
                        control.HasSequenceNumber = true;
                        control.SequenceNumber = ReadUInt32(buffer, offset + UcpConstants.CommonHeaderSize);
                    }

                    packet = control;
                    return true;
                default:
                    return false;
            }
        }

        private static byte[] EncodeControl(UcpControlPacket packet)
        {
            int size = packet.HasSequenceNumber ? UcpConstants.CommonHeaderSize + UcpConstants.SEQUENCE_NUMBER_SIZE : UcpConstants.CommonHeaderSize;
            byte[] bytes = new byte[size];
            WriteCommonHeader(packet.Header, bytes, 0);
            if (packet.HasSequenceNumber)
            {
                WriteUInt32(packet.SequenceNumber, bytes, UcpConstants.CommonHeaderSize);
            }

            return bytes;
        }

        private static byte[] EncodeData(UcpDataPacket packet)
        {
            int payloadLength = packet.Payload == null ? 0 : packet.Payload.Length;
            byte[] bytes = new byte[UcpConstants.DataHeaderSize + payloadLength];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;
            WriteUInt32(packet.SequenceNumber, bytes, index);
            index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            WriteUInt16(packet.FragmentTotal, bytes, index);
            index += sizeof(ushort);
            WriteUInt16(packet.FragmentIndex, bytes, index);
            index += sizeof(ushort);

            if (payloadLength > 0)
            {
                Buffer.BlockCopy(packet.Payload, 0, bytes, index, payloadLength);
            }

            return bytes;
        }

        private static byte[] EncodeAck(UcpAckPacket packet)
        {
            int blockCount = packet.SackBlocks == null ? 0 : packet.SackBlocks.Count;
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

        private static byte[] EncodeNak(UcpNakPacket packet)
        {
            int count = packet.MissingSequences == null ? 0 : packet.MissingSequences.Count;
            byte[] bytes = new byte[UcpConstants.NakFixedSize + (count * UcpConstants.SEQUENCE_NUMBER_SIZE)];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;
            WriteUInt16((ushort)count, bytes, index);
            index += sizeof(ushort);

            for (int i = 0; i < count; i++)
            {
                WriteUInt32(packet.MissingSequences[i], bytes, index);
                index += UcpConstants.SEQUENCE_NUMBER_SIZE;
            }

            return bytes;
        }

        private static bool TryDecodeData(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet)
        {
            packet = null;
            if (count < UcpConstants.DataHeaderSize)
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

            int payloadLength = count - UcpConstants.DataHeaderSize;
            data.Payload = new byte[payloadLength];
            if (payloadLength > 0)
            {
                Buffer.BlockCopy(buffer, index, data.Payload, 0, payloadLength);
            }

            packet = data;
            return true;
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

        private static bool TryDecodeNak(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet)
        {
            packet = null;
            if (count < UcpConstants.NakFixedSize)
            {
                return false;
            }

            int index = offset + UcpConstants.CommonHeaderSize;
            ushort missingCount = ReadUInt16(buffer, index);
            index += sizeof(ushort);
            int expectedSize = UcpConstants.NakFixedSize + (missingCount * UcpConstants.SEQUENCE_NUMBER_SIZE);
            if (count < expectedSize)
            {
                return false;
            }

            UcpNakPacket nak = new UcpNakPacket();
            nak.Header = header;
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

        private static byte[] EncodeFecRepair(UcpFecRepairPacket packet)
        {
            int payloadLen = packet.Payload == null ? 0 : packet.Payload.Length;
            byte[] bytes = new byte[UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte) + payloadLen];
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
