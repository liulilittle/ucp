using System.Collections.Generic;

namespace Ucp
{
    internal struct UcpCommonHeader
    {
        public UcpPacketType Type;
        public UcpPacketFlags Flags;
        public uint ConnectionId;
        public long Timestamp;
    }

    internal struct SackBlock
    {
        public uint Start;
        public uint End;
    }

    internal abstract class UcpPacket
    {
        public UcpCommonHeader Header;
    }

    internal sealed class UcpControlPacket : UcpPacket
    {
        public bool HasSequenceNumber;
        public uint SequenceNumber;
    }

    internal sealed class UcpDataPacket : UcpPacket
    {
        public uint SequenceNumber;
        public ushort FragmentTotal;
        public ushort FragmentIndex;
        public byte[] Payload;
    }

    internal sealed class UcpAckPacket : UcpPacket
    {
        public uint AckNumber;
        public List<SackBlock> SackBlocks = new List<SackBlock>();
        public uint WindowSize;
        public long EchoTimestamp;
    }

    internal sealed class UcpNakPacket : UcpPacket
    {
        public List<uint> MissingSequences = new List<uint>();
    }
}
