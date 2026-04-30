using System.Collections.Generic;

namespace Ucp
{
    /// <summary>
    /// Common header fields present in every UCP packet. Includes type, flags,
    /// connection ID, and a microsecond-resolution timestamp.
    /// </summary>
    internal struct UcpCommonHeader
    {
        /// <summary>Packet type indicating how to interpret the payload.</summary>
        public UcpPacketType Type;

        /// <summary>Bitfield of flags modifying packet handling.</summary>
        public UcpPacketFlags Flags;

        /// <summary>Identifies the logical connection this packet belongs to.</summary>
        public uint ConnectionId;

        /// <summary>Sender's monotonic timestamp in microseconds, used for RTT echo.</summary>
        public long Timestamp;
    }

    /// <summary>
    /// A Selective Acknowledgment block spanning a contiguous range of
    /// sequence numbers [Start, End] (inclusive).
    /// </summary>
    internal struct SackBlock
    {
        /// <summary>First sequence number in this acknowledged range (inclusive).</summary>
        public uint Start;

        /// <summary>Last sequence number in this acknowledged range (inclusive).</summary>
        public uint End;
    }

    /// <summary>
    /// Abstract base class for all UCP packet types.
    /// </summary>
    internal abstract class UcpPacket
    {
        /// <summary>Common header fields shared by all packet types.</summary>
        public UcpCommonHeader Header;
    }

    /// <summary>
    /// Represents a control packet: Syn, SynAck, Fin, or Rst.
    /// May optionally carry a sequence number for handshake packets.
    /// </summary>
    internal sealed class UcpControlPacket : UcpPacket
    {
        /// <summary>Whether a SequenceNumber is present in the encoded packet.</summary>
        public bool HasSequenceNumber;

        /// <summary>Optional sequence number carried in Syn/SynAck packets.</summary>
        public uint SequenceNumber;
    }

    /// <summary>
    /// Represents a data packet carrying a fragmented or whole application payload.
    /// Supports multi-fragment delivery through FragmentTotal and FragmentIndex.
    /// </summary>
    internal sealed class UcpDataPacket : UcpPacket
    {
        /// <summary>Sequence number of this data segment.</summary>
        public uint SequenceNumber;

        /// <summary>Total number of fragments in the logical message (1 = unfragmented).</summary>
        public ushort FragmentTotal;

        /// <summary>Zero-based index of this fragment within the logical message.</summary>
        public ushort FragmentIndex;

        /// <summary>The application payload bytes carried by this packet.</summary>
        public byte[] Payload;
    }

    /// <summary>
    /// Represents an acknowledgment packet with cumulative ACK number,
    /// optional SACK blocks, flow control window, and echo timestamp.
    /// </summary>
    internal sealed class UcpAckPacket : UcpPacket
    {
        /// <summary>Cumulative acknowledgment number: all sequences before this are received.</summary>
        public uint AckNumber;

        /// <summary>Selective acknowledgment blocks for out-of-order received ranges.</summary>
        public List<SackBlock> SackBlocks = new List<SackBlock>();

        /// <summary>Advertised receive window size in bytes for flow control.</summary>
        public uint WindowSize;

        /// <summary>Echoed timestamp from the packet being acknowledged (for RTT measurement).</summary>
        public long EchoTimestamp;
    }

    /// <summary>
    /// Represents a negative acknowledgment packet listing missing sequence
    /// numbers that the receiver has detected as lost.
    /// </summary>
    internal sealed class UcpNakPacket : UcpPacket
    {
        /// <summary>List of sequence numbers reported as missing by the receiver.</summary>
        public List<uint> MissingSequences = new List<uint>();
    }

    /// <summary>
    /// Represents a Forward Error Correction repair packet carrying parity
    /// data for a specific group of data packets.
    /// </summary>
    internal sealed class UcpFecRepairPacket : UcpPacket
    {
        /// <summary>Base sequence number identifying the FEC group.</summary>
        public uint GroupId;

        /// <summary>Index of this repair within the group (0-based).</summary>
        public byte GroupIndex;

        /// <summary>Parity repair payload computed over the group's data packets.</summary>
        public byte[] Payload;
    }
}
