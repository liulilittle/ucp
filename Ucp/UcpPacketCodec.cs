// ┌───────────────────────────────────────────────────────────────────────────┐
// │  PPP PRIVATE NETWORK™ X — Universal Communication Protocol (UCP)         │
// │  UcpPacketCodec.cs — Big-endian packet encoder / decoder                  │
// │                                                                          │
// │  All UCP wire-format serialization lives here.  Every multi-byte field   │
// │  is written and read in network byte order (big-endian) to guarantee     │
// │  interoperability across CPU architectures (x86, ARM, RISC-V, etc.).    │
// │                                                                          │
// │  Packet type dispatch:                                                   │
// │   • DATA  (0x05)  — application payload with optional piggybacked ACK   │
// │   • ACK   (0x03)  — cumulative ACK + QUIC-style SACK blocks            │
// │   • NAK   (0x04)  — negative ACK with explicit missing sequence list    │
// │   • FEC   (0x08)  — forward error correction repair (parity) packet     │
// │   • SYN   (0x01)  — connection request                                  │
// │   • SYN-ACK (0x02)— connection acceptance                               │
// │   • FIN   (0x06)  — graceful close request                              │
// │   • RST   (0x07)  — hard connection reset                               │
// │                                                                          │
// │  Piggybacked ACK: Data packets can carry an ACK in the same wire frame  │
// │  when the HasAckNumber flag (0x08) is set in the common header flags.   │
// │  This saves round-trips on bidirectional flows by acknowledging the     │
// │  reverse direction inline with forward data.  The piggybacked ACK       │
// │  includes: AckNumber (uint32), SACK block count + blocks, advertised    │
// │  window (uint32), and echo timestamp (uint48).                          │
// └───────────────────────────────────────────────────────────────────────────┘

using System;

namespace Ucp
{
    /// <summary>
    /// Encodes and decodes UCP protocol packets in big-endian byte order.
    /// Supports all packet types: Data, Ack, Nak, FecRepair, Control (Syn/SynAck/Fin/Rst).
    /// </summary>
    /// <remarks>
    /// <para><b>Big-endian rationale:</b> Network byte order is always big-endian,
    /// regardless of host CPU endianness.  This guarantees that a packet encoded
    /// on an x86 machine (little-endian) is decoded identically on an ARM device
    /// (which may be big-endian).  The Read/Write helpers use explicit shift-and-mask
    /// operations rather than <c>BitConverter</c> to avoid runtime endianness checks.</para>
    ///
    /// <para><b>Packet dispatch:</b> <see cref="Encode(UcpPacket)"/> and
    /// <see cref="TryDecode"/> use type-based dispatch.  The common header's
    /// <c>Type</c> field determines which type-specific encoder/decoder is invoked.
    /// Unknown types are rejected at decode time rather than producing garbage.</para>
    ///
    /// <para><b>Piggybacked ACK:</b> Both DATA and CONTROL packets support
    /// an optional piggybacked ACK.  When the <c>HasAckNumber</c> flag (0x08) is set
    /// in the common header flags, the type-specific header is followed by:
    ///   • AckNumber (uint32, 4 bytes) — cumulative ACK for the reverse direction
    ///   • For DATA packets: SACK block count + blocks, Window, EchoTimestamp
    ///   • For CONTROL packets: just the AckNumber (no SACK/window/echo needed)</para>
    ///
    /// <para><b>SACK blocks (QUIC-style):</b> Selective Acknowledgment blocks
    /// encode acknowledged ranges beyond the cumulative ACK number.  Each block
    /// is a [start, end) pair of uint32 sequence numbers where all packets in
    /// [start, end) have been received.  This is identical to QUIC's ACK frame
    /// SACK encoding and allows the sender to identify exactly which packets need
    /// retransmission.</para>
    /// </remarks>
    internal static class UcpPacketCodec
    {
        /// <summary>
        /// Encodes a UcpPacket into its big-endian wire format.
        /// Dispatches to the appropriate type-specific encoder.
        /// </summary>
        /// <param name="packet">The packet to encode.</param>
        /// <returns>Big-endian encoded byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown if packet is null.</exception>
        /// <exception cref="NotSupportedException">Thrown if packet type is unknown.</exception>
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

        /// <summary>
        /// Attempts to decode a buffer into a typed UcpPacket.
        /// Returns false if the buffer is too short, the common header is invalid,
        /// or the packet type is unrecognized.
        /// </summary>
        /// <param name="buffer">The byte buffer containing encoded packet data.</param>
        /// <param name="offset">Offset into the buffer where packet data starts.</param>
        /// <param name="count">Number of bytes available from offset.</param>
        /// <param name="packet">The decoded packet, or null if decoding failed.</param>
        /// <returns>True if a packet was successfully decoded.</returns>
        /// <remarks>
        /// <para>The common header (12 bytes) is decoded first via
        /// <see cref="TryReadCommonHeader"/>.  Then the <c>Type</c> field
        /// selects the type-specific decoder.  Each decoder validates minimum
        /// size requirements for its packet type before reading fields.</para>
        /// </remarks>
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
                    // Control packets: decode AckNumber if HasAckNumber flag is set,
                    // then optional SequenceNumber.
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
                    }

                    packet = control;
                    return true;
                default:
                    return false;
            }
        }

        // ────────────────────────────────────────────────────────────────────
        //  CONTROL PACKET ENCODER
        //
        //  Wire format (variable length):
        //    [0:11]   Common header (Type, Flags, ConnectionId, Timestamp)
        //    [12:15]  AckNumber (uint32)          — present if HasAckNumber flag
        //    [16:19]  SequenceNumber (uint32)      — present if HasSequenceNumber
        //
        //  Used for SYN, SYN-ACK, FIN, and RST packets.
        //  The HasAckNumber flag enables piggybacked ACK on control packets.
        // ────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Encodes a control packet (Syn, SynAck, Fin, Rst).
        /// Includes AckNumber when HasAckNumber flag is set, and optional sequence number
        /// for handshake packets.
        /// </summary>
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
            }

            return bytes;
        }

        // ────────────────────────────────────────────────────────────────────
        //  DATA PACKET ENCODER / DECODER
        //
        //  Wire format — basic (no piggybacked ACK):
        //    [0:11]   Common header
        //    [12:15]  SequenceNumber (uint32)
        //    [16:17]  FragmentTotal  (uint16)   — total fragments in message
        //    [18:19]  FragmentIndex  (uint16)   — this fragment's position
        //    [20:N]   Payload bytes
        //
        //  Wire format — with piggybacked ACK (HasAckNumber flag = 0x08):
        //    [0:11]   Common header
        //    [12:15]  SequenceNumber (uint32)
        //    [16:17]  FragmentTotal  (uint16)
        //    [18:19]  FragmentIndex  (uint16)
        //    [20:23]  AckNumber      (uint32)   — cumulative ACK for reverse dir
        //    [24:25]  SackBlockCount (uint16)   — number of SACK blocks
        //    [26:..]  SACK blocks    (N × 8 bytes)
        //             Each block: Start (uint32) + End (uint32)  [start, end)
        //    [..]     WindowSize     (uint32)   — receiver's advertised window
        //    [..]     EchoTimestamp  (uint48, 6 bytes) — peer's timestamp mirrored
        //    [..:N]   Payload bytes
        //
        //  The piggybacked ACK saves a round-trip on bidirectional flows.
        //  FragmentTotal/FragmentIndex support user-message fragmentation
        //  across multiple DATA packets when the message exceeds the per-packet
        //  payload budget (MAX_PAYLOAD_SIZE, 1200 bytes at default MSS).
        // ────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Encodes a data packet: common header, sequence number, fragment info,
        /// optional piggybacked ACK (AckNumber, SACK blocks, window, echo timestamp),
        /// and payload.
        /// </summary>
        /// <remarks>
        /// <para><b>Piggybacked ACK encoding:</b> When the HasAckNumber flag is set,
        /// the data header is extended with full ACK information.  The SACK block
        /// count is written as a uint16, followed by that many [Start, End] pairs.
        /// The total number of SACK blocks is clamped to <see cref="UcpConstants.MaxAckSackBlocks"/>
        /// to prevent the packet from exceeding MSS.</para>
        /// </remarks>
        private static byte[] EncodeData(UcpDataPacket packet)
        {
            int payloadLength = packet.Payload == null ? 0 : packet.Payload.Length;
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            int blockCount = hasAck && packet.SackBlocks != null ? Math.Min(packet.SackBlocks.Count, UcpConstants.MaxAckSackBlocks) : 0;

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
                // ── Piggybacked ACK fields ──
                // AckNumber: the highest contiguous sequence received on the reverse path
                WriteUInt32(packet.AckNumber, bytes, index);
                index += UcpConstants.ACK_NUMBER_SIZE;
                // Number of QUIC-style SACK blocks that follow
                WriteUInt16((ushort)blockCount, bytes, index);
                index += sizeof(ushort);
                // Each SACK block: [Start, End) — both inclusive of the range
                for (int i = 0; i < blockCount; i++)
                {
                    SackBlock block = packet.SackBlocks[i];
                    WriteUInt32(block.Start, bytes, index);
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                    WriteUInt32(block.End, bytes, index);
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE;
                }

                // Receiver's advertised window (flow control, in bytes)
                WriteUInt32(packet.WindowSize, bytes, index);
                index += sizeof(uint);
                // Echo of the peer's timestamp from the packet being ACKed,
                // enabling one-sided RTT measurement at the sender.
                WriteUInt48(packet.EchoTimestamp, bytes, index);
                index += UcpConstants.ACK_TIMESTAMP_FIELD_SIZE;
            }

            if (payloadLength > 0)
            {
                Buffer.BlockCopy(packet.Payload, 0, bytes, index, payloadLength);
            }

            return bytes;
        }

        /// <summary>
        /// Decodes a buffer into a UcpDataPacket. Supports optional piggybacked ACK
        /// when the HasAckNumber flag is set in the common header.
        /// </summary>
        /// <remarks>
        /// <para><b>Piggybacked ACK decoding:</b> The HasAckNumber flag in the
        /// common header determines whether the extended header format is used.
        /// When set, the decoder reads the AckNumber, SACK block count, each SACK
        /// block (start + end), WindowSize, and EchoTimestamp before the payload.
        /// The payload occupies the remaining bytes in the buffer.  A zero-length
        /// payload is valid (ACK-only DATA packet — no user data, just acknowledgment).</para>
        /// </remarks>
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
                // ── Decode piggybacked ACK fields ──
                data.AckNumber = ReadUInt32(buffer, index);
                index += UcpConstants.ACK_NUMBER_SIZE;
                ushort blockCount = ReadUInt16(buffer, index);
                index += sizeof(ushort);

                // Validate that enough bytes remain for the declared SACK blocks
                int expectedSize = minHeaderSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE);
                if (count < expectedSize)
                {
                    return false;
                }

                // Decode each QUIC-style SACK block [Start, End)
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

        // ────────────────────────────────────────────────────────────────────
        //  ACK PACKET ENCODER / DECODER
        //
        //  Wire format (variable length due to SACK blocks):
        //    [0:11]   Common header
        //    [12:15]  AckNumber      (uint32)   — cumulative ACK (all seq < this acknowledged)
        //    [16:17]  SackBlockCount (uint16)   — number of SACK blocks that follow
        //    [18:..]  SACK blocks    (N × 8 bytes)
        //             Each: Start (uint32) + End (uint32)  — [start, end) range
        //    [..]     WindowSize     (uint32)   — receiver's flow-control window
        //    [..]     EchoTimestamp  (uint48, 6 bytes) — sender's timestamp mirrored back
        //
        //  The AckNumber+1 is the first unacknowledged sequence number (cumulative ACK).
        //  SACK blocks acknowledge ranges beyond the cumulative ACK.
        //  The EchoTimestamp enables the sender to compute RTT as:
        //    RTT = now − EchoTimestamp
        //  without storing per-packet send timestamps.
        // ────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Encodes an ACK packet: common header, ack number, SACK blocks, window size, echo timestamp.
        /// </summary>
        /// <remarks>
        /// <para><b>QUIC-style SACK blocks:</b> Each block records a contiguous range
        /// [start, end) of sequence numbers that have been received beyond the cumulative
        /// ACK number.  Blocks are ordered by increasing start sequence.  The sender uses
        /// these blocks to identify "holes" — sequence ranges that are NOT covered by any
        /// SACK block and therefore may need retransmission.</para>
        /// </remarks>
        private static byte[] EncodeAck(UcpAckPacket packet)
        {
            int blockCount = packet.SackBlocks == null ? 0 : packet.SackBlocks.Count;
            if (blockCount > UcpConstants.MaxAckSackBlocks)
            {
                blockCount = UcpConstants.MaxAckSackBlocks; // Truncate to MSS limit.
            }

            byte[] bytes = new byte[UcpConstants.AckFixedSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE)];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;
            // Cumulative ACK: the sender may free all data up to (but not including) this sequence
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
            // Mirror the peer's timestamp for RTT calculation
            WriteUInt48(packet.EchoTimestamp, bytes, index);
            return bytes;
        }

        /// <summary>
        /// Decodes a buffer into a UcpAckPacket with its SACK blocks, window, and echo timestamp.
        /// </summary>
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

            // Validate that the buffer has enough bytes for the declared SACK blocks
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

        // ────────────────────────────────────────────────────────────────────
        //  NAK PACKET ENCODER / DECODER
        //
        //  Wire format (variable length due to missing sequence list):
        //    [0:11]   Common header
        //    [12:15]  AckNumber       (uint32)  — last contiguous sequence received
        //    [16:17]  MissingCount    (uint16)  — number of missing sequence entries
        //    [18:..]  MissingSequences (N × uint32) — explicitly missing sequence numbers
        //
        //  NAK is the receiver's explicit loss signal.  Unlike SACK (which lists
        //  what WAS received), NAK lists what was NOT received.  This is more
        //  efficient for sparse loss — a single NAK with 3 entries is smaller than
        //  the multiple SACK blocks needed to describe the same holes.
        // ────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Encodes a NAK packet: common header, ack number, count of missing sequences, and the sequence numbers.
        /// </summary>
        private static byte[] EncodeNak(UcpNakPacket packet)
        {
            int count = packet.MissingSequences == null ? 0 : packet.MissingSequences.Count;
            byte[] bytes = new byte[UcpConstants.NakFixedSize + (count * UcpConstants.SEQUENCE_NUMBER_SIZE)];
            int index = 0;
            WriteCommonHeader(packet.Header, bytes, index);
            index += UcpConstants.CommonHeaderSize;

            // Highest contiguous sequence received — all below this are delivered
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

        /// <summary>
        /// Decodes a buffer into a UcpNakPacket with its ack number and missing sequence list.
        /// </summary>
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
            if (count < expectedSize)
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

        // ────────────────────────────────────────────────────────────────────
        //  COMMON HEADER READER / WRITER
        //
        //  Every UCP packet begins with this 12-byte header:
        //    Offset  Size  Field         Encoding
        //    ──────────────────────────────────────────
        //    [0]     1     Type          byte (UcpPacketType enum)
        //    [1]     1     Flags         byte (UcpPacketFlags bitmask)
        //    [2:5]   4     ConnectionId  uint32, big-endian
        //    [6:11]  6     Timestamp     uint48, big-endian, microseconds
        //
        //  The Timestamp is a microsecond-resolution sender timestamp used for
        //  RTT calculation.  The receiver echoes it back in the EchoTimestamp
        //  field of ACK packets, allowing the sender to compute RTT without
        //  per-packet state.
        // ────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Reads the 12-byte common header: Type, Flags, ConnectionId (uint32),
        /// and Timestamp (uint48).
        /// </summary>
        private static bool TryReadCommonHeader(byte[] buffer, int offset, int count, out UcpCommonHeader header)
        {
            header = new UcpCommonHeader();
            if (count < UcpConstants.CommonHeaderSize)
            {
                return false;
            }

            // Type and Flags are single bytes, directly addressable
            header.Type = (UcpPacketType)buffer[offset];
            header.Flags = (UcpPacketFlags)buffer[offset + 1];
            // ConnectionId: offset 2, 4 bytes big-endian
            header.ConnectionId = ReadUInt32(buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE);
            // Timestamp: offset 6, 6 bytes big-endian uint48
            header.Timestamp = ReadUInt48(buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE + UcpConstants.CONNECTION_ID_SIZE);
            return true;
        }

        /// <summary>
        /// Writes the 12-byte common header: Type, Flags, ConnectionId (uint32),
        /// and Timestamp (uint48).
        /// </summary>
        private static void WriteCommonHeader(UcpCommonHeader header, byte[] buffer, int offset)
        {
            // Type (byte 0) and Flags (byte 1) are written directly
            buffer[offset] = (byte)header.Type;
            buffer[offset + 1] = (byte)header.Flags;
            // ConnectionId: bytes 2–5, big-endian uint32
            WriteUInt32(header.ConnectionId, buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE);
            // Timestamp: bytes 6–11, big-endian uint48
            WriteUInt48(header.Timestamp, buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE + UcpConstants.CONNECTION_ID_SIZE);
        }

        // ────────────────────────────────────────────────────────────────────
        //  BIG-ENDIAN INTEGER READ / WRITE HELPERS
        //
        //  All multi-byte integers on the wire are big-endian (network byte
        //  order).  The most significant byte (MSB) appears at the lowest
        //  offset, matching how TCP/IP headers are encoded.
        //
        //  Rather than using System.BitConverter (which depends on the host
        //  CPU's endianness), these helpers use explicit shift-and-mask
        //  operations.  This guarantees identical behavior on x86 (little-
        //  endian), ARM (configurable), and any future platform.
        //
        //  Shift amounts use the named constants from UcpConstants
        //  (UINT16_BITS=16, UINT24_BITS=24, UINT32_BITS=32, UINT40_BITS=40,
        //  BYTE_BITS=8) rather than raw integers for readability and to
        //  prevent off-by-one errors.
        //
        //  uint16 (2 bytes):  [MSB] [LSB]
        //  uint32 (4 bytes):  [31:24] [23:16] [15:8] [7:0]
        //  uint48 (6 bytes):  [47:40] [39:32] [31:24] [23:16] [15:8] [7:0]
        //
        //  Note: The uint48 helpers accept/return Int64 (signed long) because
        //  C# has no native 48-bit integer type.  The Write helper masks the
        //  input to 48 bits; the Read helper preserves the sign bit within
        //  the 48-bit range.
        // ────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Writes a 16-bit unsigned integer in big-endian order.
        /// </summary>
        /// <remarks>
        /// High byte (bits [15:8]) at offset, low byte (bits [7:0]) at offset+1.
        /// The shift by BYTE_BITS (8) extracts the upper 8 bits.
        /// </remarks>
        private static void WriteUInt16(ushort value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> UcpConstants.BYTE_BITS);       // MSB: bits [15:8]
            buffer[offset + 1] = (byte)value;                                // LSB: bits [7:0]
        }

        /// <summary>
        /// Reads a 16-bit unsigned integer in big-endian order.
        /// </summary>
        /// <remarks>
        /// Reconstructs the value by shifting the high byte left by 8 bits
        /// and OR-ing in the low byte.  The cast to ushort discards bits
        /// above bit 15.
        /// </remarks>
        private static ushort ReadUInt16(byte[] buffer, int offset)
        {
            return (ushort)((buffer[offset] << UcpConstants.BYTE_BITS) | buffer[offset + 1]);
        }

        /// <summary>
        /// Writes a 32-bit unsigned integer in big-endian order.
        /// </summary>
        /// <remarks>
        /// Byte order: [31:24] at offset, [23:16] at offset+1,
        /// [15:8] at offset+2, [7:0] at offset+3.
        /// Each byte is extracted by right-shifting the value by the
        /// appropriate amount and casting to byte (which discards bits
        /// above bit 7).
        /// </remarks>
        private static void WriteUInt32(uint value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> UcpConstants.UINT24_BITS);     // bits [31:24]
            buffer[offset + 1] = (byte)(value >> UcpConstants.UINT16_BITS);  // bits [23:16]
            buffer[offset + 2] = (byte)(value >> UcpConstants.BYTE_BITS);    // bits [15:8]
            buffer[offset + 3] = (byte)value;                                // bits [7:0]
        }

        /// <summary>
        /// Reads a 32-bit unsigned integer in big-endian order.
        /// </summary>
        /// <remarks>
        /// Each byte is left-shifted to its position and OR-ed together.
        /// The explicit casts to uint prevent sign-extension from the byte
        /// values (which would set upper bits incorrectly if the high bit
        /// of any byte is 1).
        /// </remarks>
        private static uint ReadUInt32(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset] << UcpConstants.UINT24_BITS)       // bits [31:24]
                | ((uint)buffer[offset + 1] << UcpConstants.UINT16_BITS)    // bits [23:16]
                | ((uint)buffer[offset + 2] << UcpConstants.BYTE_BITS)      // bits [15:8]
                | buffer[offset + 3];                                        // bits [7:0]
        }

        /// <summary>
        /// Writes a 48-bit unsigned integer in big-endian order (stores as 6 bytes).
        /// The value is masked to 48 bits before encoding.
        /// </summary>
        /// <remarks>
        /// <para>The input is a signed Int64 (C# long), which can hold 63 bits of
        /// magnitude.  The value is first masked with <see cref="UcpConstants.UINT48_MASK"/>
        /// (0x0000FFFFFFFFFFFF) to zero out bits [63:48], ensuring only 48 bits
        /// are written.  This is used for microsecond timestamps, which fit in
        /// 48 bits (range: ~8,925 years from epoch).</para>
        ///
        /// <para>Byte order: [47:40] [39:32] [31:24] [23:16] [15:8] [7:0],
        /// written from offset to offset+5.</para>
        /// </remarks>
        private static void WriteUInt48(long value, byte[] buffer, int offset)
        {
            ulong normalized = (ulong)value & UcpConstants.UINT48_MASK;      // keep only low 48 bits
            buffer[offset] = (byte)(normalized >> UcpConstants.UINT40_BITS); // bits [47:40]
            buffer[offset + 1] = (byte)(normalized >> UcpConstants.UINT32_BITS); // bits [39:32]
            buffer[offset + 2] = (byte)(normalized >> UcpConstants.UINT24_BITS); // bits [31:24]
            buffer[offset + 3] = (byte)(normalized >> UcpConstants.UINT16_BITS); // bits [23:16]
            buffer[offset + 4] = (byte)(normalized >> UcpConstants.BYTE_BITS);   // bits [15:8]
            buffer[offset + 5] = (byte)normalized;                               // bits [7:0]
        }

        /// <summary>
        /// Reads a 48-bit unsigned integer in big-endian order.
        /// Returns as a signed long with the value in the low 48 bits.
        /// </summary>
        /// <remarks>
        /// <para>Reconstructs the 48-bit value by shifting each byte to its
        /// position and OR-ing.  The result is returned as Int64 (signed long)
        /// because C# has no native unsigned long (ulong in C# is unsigned 64-bit).
        /// The cast to long at the end preserves the value in the low 48 bits;
        /// bit 47 becomes the sign bit of the Int64, which is fine because
        /// microsecond timestamps won't exceed 48 bits for millennia.</para>
        /// </remarks>
        private static long ReadUInt48(byte[] buffer, int offset)
        {
            ulong value = ((ulong)buffer[offset] << UcpConstants.UINT40_BITS)       // bits [47:40]
                | ((ulong)buffer[offset + 1] << UcpConstants.UINT32_BITS)           // bits [39:32]
                | ((ulong)buffer[offset + 2] << UcpConstants.UINT24_BITS)           // bits [31:24]
                | ((ulong)buffer[offset + 3] << UcpConstants.UINT16_BITS)           // bits [23:16]
                | ((ulong)buffer[offset + 4] << UcpConstants.BYTE_BITS)             // bits [15:8]
                | buffer[offset + 5];                                                // bits [7:0]
            return (long)value;
        }

        // ────────────────────────────────────────────────────────────────────
        //  FEC REPAIR PACKET ENCODER / DECODER
        //
        //  Wire format:
        //    [0:11]   Common header
        //    [12:15]  GroupId    (uint32)  — identifies which FEC group this belongs to
        //    [16]     GroupIndex (byte)    — position within the FEC group
        //    [17:N]   Payload    (variable)— XOR/Reed-Solomon parity data
        //
        //  FEC repair packets carry parity information that allows the receiver
        //  to reconstruct lost DATA packets without retransmission.  Groups are
        //  identified by GroupId (typically a sequence number range), and each
        //  repair packet within a group has a sequential GroupIndex.
        // ────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Encodes a FEC repair packet: common header, group ID, group index, parity payload.
        /// </summary>
        private static byte[] EncodeFecRepair(UcpFecRepairPacket packet)
        {
            int payloadLen = packet.Payload == null ? 0 : packet.Payload.Length;
            byte[] bytes = new byte[UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte) + payloadLen];
            WriteCommonHeader(packet.Header, bytes, 0);
            // FEC group identifier — links this repair packet to a specific group of data packets
            WriteUInt32(packet.GroupId, bytes, UcpConstants.CommonHeaderSize);
            // Position of this repair packet within the group (0-based)
            bytes[UcpConstants.CommonHeaderSize + sizeof(uint)] = packet.GroupIndex;
            if (payloadLen > 0)
            {
                Buffer.BlockCopy(packet.Payload, 0, bytes, UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte), payloadLen);
            }

            return bytes;
        }

        /// <summary>
        /// Decodes a buffer into a UcpFecRepairPacket with its parity payload.
        /// </summary>
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
