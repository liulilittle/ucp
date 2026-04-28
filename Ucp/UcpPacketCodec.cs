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
                case UcpPacketType.Nak:
                    return TryDecodeNak(buffer, offset, count, header, out packet);
                case UcpPacketType.Syn:
                case UcpPacketType.SynAck:
                case UcpPacketType.Fin:
                case UcpPacketType.Rst:
                    UcpControlPacket control = new UcpControlPacket();
                    control.Header = header;
                    if (count >= UcpConstants.CommonHeaderSize + 4)
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
            int size = packet.HasSequenceNumber ? UcpConstants.CommonHeaderSize + 4 : UcpConstants.CommonHeaderSize;
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
            index += 4;
            WriteUInt16(packet.FragmentTotal, bytes, index);
            index += 2;
            WriteUInt16(packet.FragmentIndex, bytes, index);
            index += 2;

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

            byte[] bytes = new byte[UcpConstants.AckFixedSize + (blockCount * 8)];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;
            WriteUInt32(packet.AckNumber, bytes, index);
            index += 4;
            WriteUInt16((ushort)blockCount, bytes, index);
            index += 2;

            for (int i = 0; i < blockCount; i++)
            {
                SackBlock block = packet.SackBlocks[i];
                WriteUInt32(block.Start, bytes, index);
                index += 4;
                WriteUInt32(block.End, bytes, index);
                index += 4;
            }

            WriteUInt32(packet.WindowSize, bytes, index);
            index += 4;
            WriteUInt48(packet.EchoTimestamp, bytes, index);
            return bytes;
        }

        private static byte[] EncodeNak(UcpNakPacket packet)
        {
            int count = packet.MissingSequences == null ? 0 : packet.MissingSequences.Count;
            byte[] bytes = new byte[UcpConstants.NakFixedSize + (count * 4)];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;
            WriteUInt16((ushort)count, bytes, index);
            index += 2;

            for (int i = 0; i < count; i++)
            {
                WriteUInt32(packet.MissingSequences[i], bytes, index);
                index += 4;
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
            index += 4;
            data.FragmentTotal = ReadUInt16(buffer, index);
            index += 2;
            data.FragmentIndex = ReadUInt16(buffer, index);
            index += 2;

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
            index += 4;
            ushort blockCount = ReadUInt16(buffer, index);
            index += 2;

            int expectedSize = UcpConstants.AckFixedSize + (blockCount * 8);
            if (count < expectedSize)
            {
                return false;
            }

            for (int i = 0; i < blockCount; i++)
            {
                SackBlock block = new SackBlock();
                block.Start = ReadUInt32(buffer, index);
                index += 4;
                block.End = ReadUInt32(buffer, index);
                index += 4;
                ack.SackBlocks.Add(block);
            }

            ack.WindowSize = ReadUInt32(buffer, index);
            index += 4;
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
            index += 2;
            int expectedSize = UcpConstants.NakFixedSize + (missingCount * 4);
            if (count < expectedSize)
            {
                return false;
            }

            UcpNakPacket nak = new UcpNakPacket();
            nak.Header = header;
            for (int i = 0; i < missingCount; i++)
            {
                nak.MissingSequences.Add(ReadUInt32(buffer, index));
                index += 4;
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
            header.ConnectionId = ReadUInt32(buffer, offset + 2);
            header.Timestamp = ReadUInt48(buffer, offset + 6);
            return true;
        }

        private static void WriteCommonHeader(UcpCommonHeader header, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)header.Type;
            buffer[offset + 1] = (byte)header.Flags;
            WriteUInt32(header.ConnectionId, buffer, offset + 2);
            WriteUInt48(header.Timestamp, buffer, offset + 6);
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

        private static void WriteUInt32(uint value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        private static uint ReadUInt32(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset] << 24)
                | ((uint)buffer[offset + 1] << 16)
                | ((uint)buffer[offset + 2] << 8)
                | buffer[offset + 3];
        }

        private static void WriteUInt48(long value, byte[] buffer, int offset)
        {
            ulong normalized = (ulong)value & 0x0000FFFFFFFFFFFFUL;
            buffer[offset] = (byte)(normalized >> 40);
            buffer[offset + 1] = (byte)(normalized >> 32);
            buffer[offset + 2] = (byte)(normalized >> 24);
            buffer[offset + 3] = (byte)(normalized >> 16);
            buffer[offset + 4] = (byte)(normalized >> 8);
            buffer[offset + 5] = (byte)normalized;
        }

        private static long ReadUInt48(byte[] buffer, int offset)
        {
            ulong value = ((ulong)buffer[offset] << 40)
                | ((ulong)buffer[offset + 1] << 32)
                | ((ulong)buffer[offset + 2] << 24)
                | ((ulong)buffer[offset + 3] << 16)
                | ((ulong)buffer[offset + 4] << 8)
                | buffer[offset + 5];
            return (long)value;
        }
    }
}
