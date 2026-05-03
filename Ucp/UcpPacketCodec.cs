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

using System; // Core .NET types (ArgumentNullException, NotSupportedException, Buffer, etc.)

namespace Ucp // Protocol namespace grouping all UCP types together
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
    internal static class UcpPacketCodec // Static utility class — no state, only pure encode/decode functions
    {
        /// <summary>
        /// Encodes a UcpPacket into its big-endian wire format.
        /// Dispatches to the appropriate type-specific encoder.
        /// </summary>
        /// <param name="packet">The packet to encode.</param>
        /// <returns>Big-endian encoded byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown if packet is null.</exception>
        /// <exception cref="NotSupportedException">Thrown if packet type is unknown.</exception>
        public static byte[] Encode(UcpPacket packet) // Public entry point: converts a typed packet object into a big-endian byte array for wire transmission
        {
            if (packet == null) // Guard: reject null input immediately rather than triggering a NullReferenceException deep in dispatch logic
            {
                throw new ArgumentNullException(nameof(packet)); // Fail fast with the parameter name to aid debugging — callers see exactly which argument was null
            }

            if (packet is UcpDataPacket) // Pattern-match: check if the runtime type is a Data packet (most common case first for branch-prediction friendliness)
            {
                return EncodeData((UcpDataPacket)packet); // Delegate to the Data-specific encoder which handles sequence numbers, fragmentation, payload, and optional piggybacked ACK
            }

            if (packet is UcpAckPacket) // Pattern-match: check if the runtime type is an ACK packet (cumulative + selective acknowledgment)
            {
                return EncodeAck((UcpAckPacket)packet); // Delegate to the ACK encoder which writes AckNumber, SACK blocks, window, and echo timestamp
            }

            if (packet is UcpNakPacket) // Pattern-match: check if the runtime type is a NAK packet (explicit negative acknowledgment with missing sequences)
            {
                return EncodeNak((UcpNakPacket)packet); // Delegate to the NAK encoder which writes the missing sequence number list
            }

            if (packet is UcpFecRepairPacket) // Pattern-match: check if the runtime type is an FEC repair packet (forward error correction parity data)
            {
                return EncodeFecRepair((UcpFecRepairPacket)packet); // Delegate to the FEC encoder which writes GroupId, GroupIndex, and parity payload
            }

            if (packet is UcpControlPacket) // Pattern-match: check if the runtime type is a Control packet (SYN, SYN-ACK, FIN, RST — connection management)
            {
                return EncodeControl((UcpControlPacket)packet); // Delegate to the Control encoder which writes optional AckNumber and SequenceNumber
            }

            throw new NotSupportedException("Unknown UCP packet type."); // Defensive: if none of the known types matched, the type is unrecognized and cannot be encoded safely
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
        public static bool TryDecode(byte[] buffer, int offset, int count, out UcpPacket packet) // Public entry point: attempts to parse raw bytes into a typed packet; returns false on any failure rather than throwing
        {
            packet = null; // Initialize the out parameter to null so callers always get a defined value even on early exit
            if (buffer == null || count < UcpConstants.CommonHeaderSize || offset < 0 || count < 0 || offset + count > buffer.Length) // Validate all input parameters: buffer must exist, must be large enough for at least the common header, and must not overflow the buffer bounds
            {
                return false; // Early exit: input is invalid — no packet can be decoded, return false so caller can drop/discard
            }

            UcpCommonHeader header; // Placeholder for the decoded common header (Type, Flags, ConnectionId, Timestamp)
            if (!TryReadCommonHeader(buffer, offset, count, out header)) // Attempt to parse the 12-byte common header; this also validates the header fields are within range
            {
                return false; // Early exit: common header could not be parsed (e.g. invalid packet type byte) — return false
            }

            switch (header.Type) // Dispatch on the packet type byte from the common header to choose the correct type-specific decoder
            {
                case UcpPacketType.Data: // Type byte 0x05: application data packet
                    return TryDecodeData(buffer, offset, count, header, out packet); // Delegate to the Data decoder which reads SequenceNumber, FragmentTotal/Index, optional piggybacked ACK fields, and payload
                case UcpPacketType.Ack: // Type byte 0x03: cumulative acknowledgment with SACK blocks
                    return TryDecodeAck(buffer, offset, count, header, out packet); // Delegate to the ACK decoder which reads AckNumber, SACK blocks, window, and echo timestamp
                case UcpPacketType.FecRepair: // Type byte 0x08: forward error correction repair packet
                    return TryDecodeFecRepair(buffer, offset, count, header, out packet); // Delegate to the FEC decoder which reads GroupId, GroupIndex, and parity payload
                case UcpPacketType.Nak: // Type byte 0x04: negative acknowledgment with missing sequence list
                    return TryDecodeNak(buffer, offset, count, header, out packet); // Delegate to the NAK decoder which reads the missing sequence numbers
                case UcpPacketType.Syn: // Type byte 0x01: connection request
                case UcpPacketType.SynAck: // Type byte 0x02: connection acceptance
                case UcpPacketType.Fin: // Type byte 0x06: graceful close request
                case UcpPacketType.Rst: // Type byte 0x07: hard connection reset
                    // Control packets: decode AckNumber if HasAckNumber flag is set,
                    // then optional SequenceNumber.
                    UcpControlPacket control = new UcpControlPacket(); // Allocate a fresh Control packet object to populate with decoded fields
                    control.Header = header; // Copy the already-decoded common header into the packet so upper layers can access Type, Flags, ConnectionId, and Timestamp
                    
                    int controlIndex = offset + UcpConstants.CommonHeaderSize; // Compute the starting offset past the 12-byte common header where control-specific fields begin
                    bool hasAck = (header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Extract the HasAckNumber flag (0x08) from the header flags byte — controls whether an AckNumber field is present after the common header
                    if (hasAck && count >= controlIndex + UcpConstants.ACK_NUMBER_SIZE) // If the piggybacked ACK flag is set AND there are enough remaining bytes to hold a 4-byte AckNumber
                    {
                        control.AckNumber = ReadUInt32(buffer, controlIndex); // Read the 4-byte big-endian AckNumber (cumulative ACK for reverse direction, piggybacked on this control packet)
                        controlIndex += UcpConstants.ACK_NUMBER_SIZE; // Advance the read pointer past the AckNumber field
                    }

                    if (count >= controlIndex + UcpConstants.SEQUENCE_NUMBER_SIZE) // Check if there are enough remaining bytes for a 4-byte SequenceNumber (e.g. SYN packets carry a sequence number for handshake)
                    {
                        control.HasSequenceNumber = true; // Mark that a sequence number was present so the caller knows the field is valid
                        control.SequenceNumber = ReadUInt32(buffer, controlIndex); // Read the 4-byte big-endian SequenceNumber (sender's chosen initial sequence number for handshake)
                    }

                    packet = control; // Assign the fully decoded Control packet to the out parameter
                    return true; // Success: a valid Control packet was decoded
                default: // Any other type byte value that doesn't match a known packet type
                    return false; // Unknown/unrecognized packet type — reject rather than producing a garbage object, return false so caller drops it
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
        private static byte[] EncodeControl(UcpControlPacket packet) // Serializes a control packet (connection management) into its variable-length big-endian wire format
        {
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Check if the HasAckNumber flag (0x08) is set in the header flags — determines if we should include a piggybacked AckNumber
            int size = UcpConstants.CommonHeaderSize; // Start with the 12-byte base common header — every control packet has this at minimum
            if (hasAck) // If piggybacked ACK is requested (HasAckNumber flag is set)
            {
                size += UcpConstants.ACK_NUMBER_SIZE; // Add 4 bytes for the AckNumber field after the common header
            }

            if (packet.HasSequenceNumber) // If the control packet carries a sequence number (true for SYN and SYN-ACK handshake packets)
            {
                size += UcpConstants.SEQUENCE_NUMBER_SIZE; // Add 4 bytes for the SequenceNumber field
            }

            byte[] bytes = new byte[size]; // Allocate the exact-size output buffer — no wasted heap space
            int index = 0; // Running write position within the output buffer, starts at the beginning
            WriteCommonHeader(packet.Header, bytes, index); // Write the 12-byte common header (Type, Flags, ConnectionId, Timestamp) at offset 0

            index += UcpConstants.CommonHeaderSize; // Advance the write position past the 12-byte common header
            if (hasAck) // If the piggybacked ACK flag was set
            {
                WriteUInt32(packet.AckNumber, bytes, index); // Write the 4-byte big-endian AckNumber (cumulative ACK for the reverse direction)
                index += UcpConstants.ACK_NUMBER_SIZE; // Advance past the AckNumber field
            }

            if (packet.HasSequenceNumber) // If the control packet carries a sequence number
            {
                WriteUInt32(packet.SequenceNumber, bytes, index); // Write the 4-byte big-endian SequenceNumber (sender's initial sequence for handshake)
            }

            return bytes; // Return the fully encoded control packet as a big-endian byte array ready for wire transmission
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
        private static byte[] EncodeData(UcpDataPacket packet) // Serializes a Data packet (the most common packet type) into its big-endian wire format with optional piggybacked ACK
        {
            int payloadLength = packet.Payload == null ? 0 : packet.Payload.Length; // Determine payload size: 0 if no payload, otherwise the actual byte count — needed before allocating the output buffer
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Extract the HasAckNumber flag (0x08) from the common header — determines whether the extended header (with piggybacked ACK) is emitted
            int blockCount = hasAck && packet.SackBlocks != null ? Math.Min(packet.SackBlocks.Count, UcpConstants.MaxAckSackBlocks) : 0; // Compute the number of SACK blocks to write: only when piggybacking is active and blocks exist, clamped to MaxAckSackBlocks to prevent MTU overflow

            int baseHeaderSize = hasAck ? UcpConstants.DATA_HEADER_SIZE_WITH_ACK : UcpConstants.DataHeaderSize; // Select the appropriate header size: the extended header includes AckNumber + SACK count + Window + EchoTimestamp fields
            byte[] bytes = new byte[baseHeaderSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE) + payloadLength]; // Allocate the exact-size output buffer: base header + SACK block data (8 bytes per block) + payload bytes
            int index = 0; // Running write position within the output buffer
            WriteCommonHeader(packet.Header, bytes, index); // Write the 12-byte common header (Type=0x05, Flags, ConnectionId, Timestamp) at offset 0
            index += UcpConstants.CommonHeaderSize; // Advance past the 12-byte common header
            WriteUInt32(packet.SequenceNumber, bytes, index); // Write the 4-byte big-endian SequenceNumber — identifies this packet's position in the send stream for ordering and ACK tracking
            index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past the SequenceNumber
            WriteUInt16(packet.FragmentTotal, bytes, index); // Write the 2-byte big-endian FragmentTotal — how many fragments the original user message was split into (1 = unfragmented)
            index += sizeof(ushort); // Advance past FragmentTotal (2 bytes)
            WriteUInt16(packet.FragmentIndex, bytes, index); // Write the 2-byte big-endian FragmentIndex — which fragment this packet represents (0-based index into the message)
            index += sizeof(ushort); // Advance past FragmentIndex (2 bytes)

            if (hasAck) // Branch taken when this data packet also carries an acknowledgment (piggybacked ACK, saves one round-trip on bidirectional flows)
            {
                // ── Piggybacked ACK fields ──
                // AckNumber: the highest contiguous sequence received on the reverse path
                WriteUInt32(packet.AckNumber, bytes, index); // Write the 4-byte big-endian AckNumber — the cumulative ACK for packets received from the peer, allowing the peer to free its send buffer
                index += UcpConstants.ACK_NUMBER_SIZE; // Advance past AckNumber (4 bytes)
                // Number of QUIC-style SACK blocks that follow
                WriteUInt16((ushort)blockCount, bytes, index); // Write the 2-byte SACK block count — tells the decoder how many [Start, End) pairs to expect next
                index += sizeof(ushort); // Advance past the SACK block count (2 bytes)
                // Each SACK block: [Start, End) — both inclusive of the range
                for (int i = 0; i < blockCount; i++) // Iterate over each SACK block to serialize (up to MaxAckSackBlocks, already clamped above)
                {
                    SackBlock block = packet.SackBlocks[i]; // Get the i-th SACK block from the packet's block list
                    WriteUInt32(block.Start, bytes, index); // Write the 4-byte big-endian Start sequence number — the first sequence acknowledged by this block (inclusive)
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past Start (4 bytes)
                    WriteUInt32(block.End, bytes, index); // Write the 4-byte big-endian End sequence number — the past-the-end of this acknowledged range (exclusive)
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past End (4 bytes)
                }

                // Receiver's advertised window (flow control, in bytes)
                WriteUInt32(packet.WindowSize, bytes, index); // Write the 4-byte big-endian WindowSize — the receiver's available buffer space, used for flow control (sender must not exceed this)
                index += sizeof(uint); // Advance past WindowSize (4 bytes)
                // Echo of the peer's timestamp from the packet being ACKed,
                // enabling one-sided RTT measurement at the sender.
                WriteUInt48(packet.EchoTimestamp, bytes, index); // Write the 6-byte big-endian EchoTimestamp — mirrors the peer's original timestamp so they can compute RTT = now - EchoTimestamp
                index += UcpConstants.ACK_TIMESTAMP_FIELD_SIZE; // Advance past EchoTimestamp (6 bytes)
            }

            if (payloadLength > 0) // Only copy payload bytes if there is actual payload data (avoids a zero-length BlockCopy which is valid but unnecessary)
            {
                Buffer.BlockCopy(packet.Payload, 0, bytes, index, payloadLength); // Copy the payload bytes from the packet object directly into the output buffer at the current write position — faster than a manual loop
            }

            return bytes; // Return the fully encoded data packet as a big-endian byte array ready for wire transmission
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
        private static bool TryDecodeData(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet) // Attempts to parse raw bytes into a UcpDataPacket; the common header has already been decoded by TryDecode
        {
            packet = null; // Initialize out parameter to null so caller always has a defined value even on early exit
            bool hasAck = (header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Determine from the common header flags whether this data packet carries a piggybacked ACK (extended header)
            int minHeaderSize = hasAck ? UcpConstants.DATA_HEADER_SIZE_WITH_ACK : UcpConstants.DataHeaderSize; // Select the minimum required byte count: the extended header is larger due to AckNumber + SACK count + Window + EchoTimestamp fields
            if (count < minHeaderSize) // Validate that the buffer has at least the minimum required bytes for the selected header format
            {
                return false; // Buffer too short even for the base data header — reject, return false so caller knows decoding failed
            }

            int index = offset + UcpConstants.CommonHeaderSize; // Calculate the read position just past the 12-byte common header (already decoded and passed in as 'header')
            UcpDataPacket data = new UcpDataPacket(); // Allocate a fresh Data packet object to populate with decoded fields
            data.Header = header; // Assign the already-decoded common header to the packet object
            data.SequenceNumber = ReadUInt32(buffer, index); // Read 4-byte big-endian SequenceNumber — tells the receiver where this packet fits in the ordered stream
            index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past SequenceNumber
            data.FragmentTotal = ReadUInt16(buffer, index); // Read 2-byte big-endian FragmentTotal — how many fragments the original message was split into
            index += sizeof(ushort); // Advance past FragmentTotal
            data.FragmentIndex = ReadUInt16(buffer, index); // Read 2-byte big-endian FragmentIndex — which fragment this packet represents (0-based)
            index += sizeof(ushort); // Advance past FragmentIndex

            if (hasAck) // Branch taken when this data packet carries a piggybacked ACK — we need to decode the extended ACK fields
            {
                // ── Decode piggybacked ACK fields ──
                data.AckNumber = ReadUInt32(buffer, index); // Read 4-byte big-endian AckNumber — the cumulative ACK for the reverse direction, telling us which packets the peer has received
                index += UcpConstants.ACK_NUMBER_SIZE; // Advance past AckNumber
                ushort blockCount = ReadUInt16(buffer, index); // Read 2-byte big-endian SACK block count — tells us how many [Start, End) pairs follow
                index += sizeof(ushort); // Advance past the block count

                // Validate that enough bytes remain for the declared SACK blocks
                int expectedSize = minHeaderSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE); // Calculate the total minimum size needed given the declared number of SACK blocks (each 8 bytes)
                if (count < expectedSize) // Check if the buffer has enough bytes to hold all the declared SACK blocks
                {
                    return false; // Buffer is too short for the declared SACK blocks — the packet is malformed or truncated, reject it
                }

                // Decode each QUIC-style SACK block [Start, End)
                for (int i = 0; i < blockCount; i++) // Iterate over the declared number of SACK blocks
                {
                    SackBlock block = new SackBlock(); // Allocate a fresh SACK block struct to hold the decoded range
                    block.Start = ReadUInt32(buffer, index); // Read 4-byte big-endian Start — the first sequence number in this acknowledged range (inclusive)
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past Start
                    block.End = ReadUInt32(buffer, index); // Read 4-byte big-endian End — the sequence just past the end of this acknowledged range (exclusive)
                    index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past End
                    data.SackBlocks.Add(block); // Append the decoded SACK block to the packet's block list so upper layers can use it for loss detection
                }

                data.WindowSize = ReadUInt32(buffer, index); // Read 4-byte big-endian WindowSize — the peer's advertised receive window for flow control
                index += sizeof(uint); // Advance past WindowSize
                data.EchoTimestamp = ReadUInt48(buffer, index); // Read 6-byte big-endian EchoTimestamp — the peer's mirrored timestamp for RTT calculation
                index += UcpConstants.ACK_TIMESTAMP_FIELD_SIZE; // Advance past EchoTimestamp
            }

            int payloadLength = count - (index - offset); // Calculate the remaining bytes as payload — everything after the header(s) is user data
            if (payloadLength < 0) // Sanity check: negative payload means the decoding math is wrong or the buffer is corrupted
            {
                return false; // Invalid state — reject the packet rather than attempting to allocate a negative-size array
            }

            data.Payload = new byte[payloadLength]; // Allocate a byte array of exactly the payload size — may be zero-length for ACK-only DATA packets
            if (payloadLength > 0) // Only perform the copy if there is actual payload data
            {
                Buffer.BlockCopy(buffer, index, data.Payload, 0, payloadLength); // Copy the payload bytes from the input buffer into the packet's Payload array — faster than a manual byte-by-byte loop
            }

            packet = data; // Assign the fully decoded Data packet (upcast to the base type) to the out parameter
            return true; // Success: a valid Data packet was decoded
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
        private static byte[] EncodeAck(UcpAckPacket packet) // Serializes an ACK packet (pure acknowledgment, not piggybacked on data) into its big-endian wire format
        {
            int blockCount = packet.SackBlocks == null ? 0 : packet.SackBlocks.Count; // Determine how many SACK blocks to encode — zero if no selective acknowledgment data is available
            if (blockCount > UcpConstants.MaxAckSackBlocks) // Guard: prevent the SACK block count from exceeding the protocol's maximum to avoid MTU overflow
            {
                blockCount = UcpConstants.MaxAckSackBlocks; // Truncate to MSS limit.
            }

            byte[] bytes = new byte[UcpConstants.AckFixedSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE)]; // Allocate the output buffer: fixed ACK header size + variable SACK block data (8 bytes per block)
            int index = 0; // Running write position within the output buffer
            WriteCommonHeader(packet.Header, bytes, index); // Write the 12-byte common header (Type=0x03, Flags, ConnectionId, Timestamp) at offset 0
            index += UcpConstants.CommonHeaderSize; // Advance past the common header
            // Cumulative ACK: the sender may free all data up to (but not including) this sequence
            WriteUInt32(packet.AckNumber, bytes, index); // Write the 4-byte big-endian AckNumber — all packets with sequence numbers before this have been received contiguously
            index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past AckNumber
            WriteUInt16((ushort)blockCount, bytes, index); // Write the 2-byte SACK block count — tells the decoder how many SACK blocks follow
            index += sizeof(ushort); // Advance past the block count

            for (int i = 0; i < blockCount; i++) // Iterate over each SACK block to serialize into the buffer
            {
                SackBlock block = packet.SackBlocks[i]; // Get the i-th SACK block from the packet's block list
                WriteUInt32(block.Start, bytes, index); // Write 4-byte big-endian Start — first sequence number of this acknowledged range (inclusive)
                index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past Start
                WriteUInt32(block.End, bytes, index); // Write 4-byte big-endian End — past-the-end sequence of this acknowledged range (exclusive)
                index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past End
            }

            WriteUInt32(packet.WindowSize, bytes, index); // Write 4-byte big-endian WindowSize — the receiver's available buffer, used by the sender for flow-control pacing
            index += sizeof(uint); // Advance past WindowSize
            // Mirror the peer's timestamp for RTT calculation
            WriteUInt48(packet.EchoTimestamp, bytes, index); // Write 6-byte big-endian EchoTimestamp — the peer's original timestamp echoed back so they can compute round-trip time
            return bytes; // Return the fully encoded ACK packet as a big-endian byte array
        }

        /// <summary>
        /// Decodes a buffer into a UcpAckPacket with its SACK blocks, window, and echo timestamp.
        /// </summary>
        private static bool TryDecodeAck(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet) // Attempts to parse raw bytes into a UcpAckPacket with SACK blocks, window size, and echo timestamp
        {
            packet = null; // Initialize out parameter to null for safe early-exit semantics
            if (count < UcpConstants.AckFixedSize) // Validate that the buffer has at least the minimum bytes for a fixed-size ACK (without SACK blocks)
            {
                return false; // Buffer too short even for the base ACK header — reject, return false
            }

            int index = offset + UcpConstants.CommonHeaderSize; // Calculate read position just past the 12-byte common header (already decoded)
            UcpAckPacket ack = new UcpAckPacket(); // Allocate a fresh ACK packet object to populate with decoded fields
            ack.Header = header; // Assign the already-decoded common header
            ack.AckNumber = ReadUInt32(buffer, index); // Read 4-byte big-endian AckNumber — the cumulative ACK sequence number (all packets before this are confirmed received)
            index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past AckNumber
            ushort blockCount = ReadUInt16(buffer, index); // Read 2-byte SACK block count — how many [Start, End) pairs follow
            index += sizeof(ushort); // Advance past the block count

            // Validate that the buffer has enough bytes for the declared SACK blocks
            int expectedSize = UcpConstants.AckFixedSize + (blockCount * UcpConstants.SACK_BLOCK_SIZE); // Calculate the total size required given the number of SACK blocks
            if (count < expectedSize) // Check if the buffer actually has enough bytes to hold all declared SACK blocks
            {
                return false; // Buffer too short for the declared SACK blocks — malformed or truncated packet, reject it
            }

            for (int i = 0; i < blockCount; i++) // Iterate over the declared number of SACK blocks to decode each one
            {
                SackBlock block = new SackBlock(); // Allocate a fresh SACK block struct
                block.Start = ReadUInt32(buffer, index); // Read 4-byte big-endian Start — first sequence number in this acknowledged range (inclusive)
                index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past Start
                block.End = ReadUInt32(buffer, index); // Read 4-byte big-endian End — past-the-end sequence of this acknowledged range (exclusive)
                index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past End
                ack.SackBlocks.Add(block); // Append the decoded SACK block to the packet's block list
            }

            ack.WindowSize = ReadUInt32(buffer, index); // Read 4-byte big-endian WindowSize — the receiver's advertised flow-control window
            index += sizeof(uint); // Advance past WindowSize
            ack.EchoTimestamp = ReadUInt48(buffer, index); // Read 6-byte big-endian EchoTimestamp — the peer's mirrored timestamp for RTT measurement
            packet = ack; // Assign the fully decoded ACK packet to the out parameter
            return true; // Success: a valid ACK packet was decoded
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
        private static byte[] EncodeNak(UcpNakPacket packet) // Serializes a NAK (Negative Acknowledgment) packet — explicitly tells the sender which sequence numbers are missing
        {
            int count = packet.MissingSequences == null ? 0 : packet.MissingSequences.Count; // Determine how many missing sequence numbers are being reported (0 if no loss to report, though a NAK with 0 missing is unusual)
            byte[] bytes = new byte[UcpConstants.NakFixedSize + (count * UcpConstants.SEQUENCE_NUMBER_SIZE)]; // Allocate the output buffer: fixed NAK header + 4 bytes per missing sequence number
            int index = 0; // Running write position within the output buffer
            WriteCommonHeader(packet.Header, bytes, index); // Write the 12-byte common header (Type=0x04, Flags, ConnectionId, Timestamp) at offset 0
            index += UcpConstants.CommonHeaderSize; // Advance past the common header

            // Highest contiguous sequence received — all below this are delivered
            WriteUInt32(packet.AckNumber, bytes, index); // Write 4-byte big-endian AckNumber — the cumulative ACK, i.e. the highest contiguous sequence received before the gaps
            index += UcpConstants.ACK_NUMBER_SIZE; // Advance past AckNumber

            WriteUInt16((ushort)count, bytes, index); // Write 2-byte MissingCount — the number of explicitly missing sequence numbers that follow
            index += sizeof(ushort); // Advance past MissingCount

            for (int i = 0; i < count; i++) // Iterate over each explicitly missing sequence number to serialize
            {
                WriteUInt32(packet.MissingSequences[i], bytes, index); // Write 4-byte big-endian missing sequence number — the sender should retransmit the packet with this sequence
                index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past this missing sequence entry
            }

            return bytes; // Return the fully encoded NAK packet as a big-endian byte array
        }

        /// <summary>
        /// Decodes a buffer into a UcpNakPacket with its ack number and missing sequence list.
        /// </summary>
        private static bool TryDecodeNak(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet) // Attempts to parse raw bytes into a UcpNakPacket containing the explicit list of missing sequences
        {
            packet = null; // Initialize out parameter to null for safe early-exit
            if (count < UcpConstants.NakFixedSize) // Validate that the buffer has at least the minimum bytes for a fixed-size NAK (without missing sequences)
            {
                return false; // Buffer too short even for the base NAK header — reject
            }

            int index = offset + UcpConstants.CommonHeaderSize; // Calculate read position just past the 12-byte common header
            UcpNakPacket nak = new UcpNakPacket(); // Allocate a fresh NAK packet object
            nak.Header = header; // Assign the already-decoded common header
            nak.AckNumber = ReadUInt32(buffer, index); // Read 4-byte big-endian AckNumber — the cumulative ACK (highest contiguous sequence received before the gaps)
            index += UcpConstants.ACK_NUMBER_SIZE; // Advance past AckNumber

            ushort missingCount = ReadUInt16(buffer, index); // Read 2-byte MissingCount — how many missing sequence numbers are listed
            index += sizeof(ushort); // Advance past MissingCount
            
            int expectedSize = UcpConstants.NakFixedSize + (missingCount * UcpConstants.SEQUENCE_NUMBER_SIZE); // Calculate the total size required given the number of missing sequences
            if (count < expectedSize) // Check if the buffer actually has enough bytes for all declared missing sequences
            {
                return false; // Buffer too short for the declared missing sequences — malformed or truncated, reject
            }

            for (int i = 0; i < missingCount; i++) // Iterate over the declared number of missing sequence numbers
            {
                nak.MissingSequences.Add(ReadUInt32(buffer, index)); // Read 4-byte big-endian missing sequence number and add it directly to the list
                index += UcpConstants.SEQUENCE_NUMBER_SIZE; // Advance past this missing sequence entry
            }

            packet = nak; // Assign the fully decoded NAK packet to the out parameter
            return true; // Success: a valid NAK packet was decoded
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
        private static bool TryReadCommonHeader(byte[] buffer, int offset, int count, out UcpCommonHeader header) // Parses the universal 12-byte common header that prefixes every UCP packet — validates minimum size before reading
        {
            header = new UcpCommonHeader(); // Initialize the out parameter to a fresh object (fields will be overwritten, but this ensures it's never null)
            if (count < UcpConstants.CommonHeaderSize) // Validate that the buffer has at least 12 bytes available for the common header
            {
                return false; // Buffer too short — cannot read a complete common header, return false
            }

            // Type and Flags are single bytes, directly addressable
            header.Type = (UcpPacketType)buffer[offset]; // Read byte 0: the packet type — cast directly from the buffer byte to the enum (safe because unknown values will be caught by the switch in TryDecode)
            header.Flags = (UcpPacketFlags)buffer[offset + 1]; // Read byte 1: the flags bitmask — cast directly, individual bits are tested by upper layers
            // ConnectionId: offset 2, 4 bytes big-endian
            header.ConnectionId = ReadUInt32(buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE); // Read bytes 2–5 as a big-endian uint32 ConnectionId — used to route packets to the correct protocol control block
            // Timestamp: offset 6, 6 bytes big-endian uint48
            header.Timestamp = ReadUInt48(buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE + UcpConstants.CONNECTION_ID_SIZE); // Read bytes 6–11 as a big-endian uint48 Timestamp — sent by the peer for RTT echo-back
            return true; // Success: the common header was fully decoded
        }

        /// <summary>
        /// Writes the 12-byte common header: Type, Flags, ConnectionId (uint32),
        /// and Timestamp (uint48).
        /// </summary>
        private static void WriteCommonHeader(UcpCommonHeader header, byte[] buffer, int offset) // Serializes the universal 12-byte common header into the output buffer at the given offset
        {
            // Type (byte 0) and Flags (byte 1) are written directly
            buffer[offset] = (byte)header.Type; // Write byte 0: the packet type — cast the enum value to its underlying byte (e.g. 0x05 for Data)
            buffer[offset + 1] = (byte)header.Flags; // Write byte 1: the flags bitmask — cast the flags enum to its underlying byte value
            // ConnectionId: bytes 2–5, big-endian uint32
            WriteUInt32(header.ConnectionId, buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE); // Write bytes 2–5 as a big-endian uint32 ConnectionId — identifies which logical connection this packet belongs to
            // Timestamp: bytes 6–11, big-endian uint48
            WriteUInt48(header.Timestamp, buffer, offset + UcpConstants.PACKET_TYPE_FIELD_SIZE + UcpConstants.PACKET_FLAGS_FIELD_SIZE + UcpConstants.CONNECTION_ID_SIZE); // Write bytes 6–11 as a big-endian uint48 Timestamp — the sender's microsecond clock for RTT measurement
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
        private static void WriteUInt16(ushort value, byte[] buffer, int offset) // Writes a 2-byte unsigned integer in network byte order (big-endian: MSB first, LSB second)
        {
            buffer[offset] = (byte)(value >> UcpConstants.BYTE_BITS);       // MSB: bits [15:8] — shift the upper 8 bits down to the low byte position, then mask to 8 bits via byte cast, storing at the lower offset (big-endian: MSB at lowest address)
            buffer[offset + 1] = (byte)value;                                // LSB: bits [7:0] — the low 8 bits are already in position, just cast to byte, storing at offset+1
        }

        /// <summary>
        /// Reads a 16-bit unsigned integer in big-endian order.
        /// </summary>
        /// <remarks>
        /// Reconstructs the value by shifting the high byte left by 8 bits
        /// and OR-ing in the low byte.  The cast to ushort discards bits
        /// above bit 15.
        /// </remarks>
        private static ushort ReadUInt16(byte[] buffer, int offset) // Reads a 2-byte unsigned integer from network byte order (big-endian) into a native ushort
        {
            return (ushort)((buffer[offset] << UcpConstants.BYTE_BITS) | buffer[offset + 1]); // Shift the MSB (at offset) left 8 bits into position, OR in the LSB (at offset+1), cast to ushort to discard any bits above 15
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
        private static void WriteUInt32(uint value, byte[] buffer, int offset) // Writes a 4-byte unsigned integer in network byte order (big-endian: MSB at offset, LSB at offset+3)
        {
            buffer[offset] = (byte)(value >> UcpConstants.UINT24_BITS);     // bits [31:24] — shift right 24 bits to bring the highest byte into position, cast to byte (drops upper bits)
            buffer[offset + 1] = (byte)(value >> UcpConstants.UINT16_BITS);  // bits [23:16] — shift right 16 bits, cast to byte
            buffer[offset + 2] = (byte)(value >> UcpConstants.BYTE_BITS);    // bits [15:8] — shift right 8 bits, cast to byte
            buffer[offset + 3] = (byte)value;                                // bits [7:0] — no shift needed, the lowest byte is already in position, cast to byte
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
        private static uint ReadUInt32(byte[] buffer, int offset) // Reads a 4-byte unsigned integer from network byte order (big-endian) into a native uint
        {
            return ((uint)buffer[offset] << UcpConstants.UINT24_BITS)       // bits [31:24] — MSB at offset, cast to uint (prevents sign extension), shift into highest byte position
                | ((uint)buffer[offset + 1] << UcpConstants.UINT16_BITS)    // bits [23:16] — byte at offset+1, cast to uint, shift into second-highest byte position
                | ((uint)buffer[offset + 2] << UcpConstants.BYTE_BITS)      // bits [15:8] — byte at offset+2, cast to uint, shift into third byte position
                | buffer[offset + 3];                                        // bits [7:0] — LSB at offset+3, no shift needed, already in the lowest byte position
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
        private static void WriteUInt48(long value, byte[] buffer, int offset) // Writes a 6-byte unsigned 48-bit integer in network byte order; the input long is masked to 48 bits to prevent garbage in bits 48–63
        {
            ulong normalized = (ulong)value & UcpConstants.UINT48_MASK;      // keep only low 48 bits — bitwise AND with 0x0000FFFFFFFFFFFF strips any upper bits from the Int64 sign extension or stray high values
            buffer[offset] = (byte)(normalized >> UcpConstants.UINT40_BITS); // bits [47:40] — shift right 40 bits to bring the highest byte into position, cast to byte
            buffer[offset + 1] = (byte)(normalized >> UcpConstants.UINT32_BITS); // bits [39:32] — shift right 32 bits, cast to byte
            buffer[offset + 2] = (byte)(normalized >> UcpConstants.UINT24_BITS); // bits [31:24] — shift right 24 bits, cast to byte
            buffer[offset + 3] = (byte)(normalized >> UcpConstants.UINT16_BITS); // bits [23:16] — shift right 16 bits, cast to byte
            buffer[offset + 4] = (byte)(normalized >> UcpConstants.BYTE_BITS);   // bits [15:8] — shift right 8 bits, cast to byte
            buffer[offset + 5] = (byte)normalized;                               // bits [7:0] — the lowest byte, no shift needed, cast to byte
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
        private static long ReadUInt48(byte[] buffer, int offset) // Reads a 6-byte unsigned 48-bit integer from network byte order, returns as Int64 (signed long) with the value in the lower 48 bits
        {
            ulong value = ((ulong)buffer[offset] << UcpConstants.UINT40_BITS)       // bits [47:40] — MSB at offset, cast to ulong to prevent sign extension, shift 40 bits into position
                | ((ulong)buffer[offset + 1] << UcpConstants.UINT32_BITS)           // bits [39:32] — byte at offset+1, shift 32 bits
                | ((ulong)buffer[offset + 2] << UcpConstants.UINT24_BITS)           // bits [31:24] — byte at offset+2, shift 24 bits
                | ((ulong)buffer[offset + 3] << UcpConstants.UINT16_BITS)           // bits [23:16] — byte at offset+3, shift 16 bits
                | ((ulong)buffer[offset + 4] << UcpConstants.BYTE_BITS)             // bits [15:8] — byte at offset+4, shift 8 bits
                | buffer[offset + 5];                                                // bits [7:0] — LSB at offset+5, no shift needed
            return (long)value; // Cast the assembled ulong to long (Int64) — the value in bits 0–47 is preserved; bit 47 may become the sign bit, which is acceptable for timestamps
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
        private static byte[] EncodeFecRepair(UcpFecRepairPacket packet) // Serializes an FEC (Forward Error Correction) repair packet — carries parity data to reconstruct lost DATA packets without retransmission
        {
            int payloadLen = packet.Payload == null ? 0 : packet.Payload.Length; // Determine the parity payload size: 0 if null, otherwise the actual byte length
            byte[] bytes = new byte[UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte) + payloadLen]; // Allocate the output buffer: 12-byte common header + 4-byte GroupId + 1-byte GroupIndex + variable parity payload
            WriteCommonHeader(packet.Header, bytes, 0); // Write the 12-byte common header (Type=0x08, Flags, ConnectionId, Timestamp) at offset 0
            // FEC group identifier — links this repair packet to a specific group of data packets
            WriteUInt32(packet.GroupId, bytes, UcpConstants.CommonHeaderSize); // Write 4-byte big-endian GroupId at offset 12 — identifies which FEC group this repair belongs to so the receiver can correlate it with the right data packets
            // Position of this repair packet within the group (0-based)
            bytes[UcpConstants.CommonHeaderSize + sizeof(uint)] = packet.GroupIndex; // Write the 1-byte GroupIndex at offset 16 — indicates which repair packet this is within the FEC group (0 = first repair packet)
            if (payloadLen > 0) // Only copy parity data if there is any (a zero-length FEC packet is valid but useless)
            {
                Buffer.BlockCopy(packet.Payload, 0, bytes, UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte), payloadLen); // Copy the parity payload bytes into the output buffer starting at offset 17 (12 + 4 + 1)
            }

            return bytes; // Return the fully encoded FEC repair packet as a big-endian byte array
        }

        /// <summary>
        /// Decodes a buffer into a UcpFecRepairPacket with its parity payload.
        /// </summary>
        private static bool TryDecodeFecRepair(byte[] buffer, int offset, int count, UcpCommonHeader header, out UcpPacket packet) // Attempts to parse raw bytes into a UcpFecRepairPacket containing GroupId, GroupIndex, and parity payload
        {
            packet = null; // Initialize out parameter to null for safe early-exit
            if (count < UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte)) // Validate that the buffer has at least the minimum bytes: 12 (header) + 4 (GroupId) + 1 (GroupIndex) = 17 bytes
            {
                return false; // Buffer too short for even a zero-payload FEC repair packet — reject
            }

            UcpFecRepairPacket repair = new UcpFecRepairPacket(); // Allocate a fresh FEC repair packet object
            repair.Header = header; // Assign the already-decoded common header
            repair.GroupId = ReadUInt32(buffer, offset + UcpConstants.CommonHeaderSize); // Read 4-byte big-endian GroupId at offset+12 — identifies which FEC group this repair belongs to
            repair.GroupIndex = buffer[offset + UcpConstants.CommonHeaderSize + sizeof(uint)]; // Read the 1-byte GroupIndex at offset+16 — position of this repair packet within the FEC group
            int payloadLen = count - (UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte)); // Calculate the remaining bytes as parity payload (the 17-byte fixed header subtracted from total count)
            if (payloadLen < 0) // Sanity check: negative payload means the decoding math is wrong or the buffer claims a smaller size than the fixed header
            {
                return false; // Invalid state — reject
            }

            if (payloadLen > 0) // If there is actual parity payload data
            {
                repair.Payload = new byte[payloadLen]; // Allocate a byte array sized exactly to the parity payload
                Buffer.BlockCopy(buffer, offset + UcpConstants.CommonHeaderSize + sizeof(uint) + sizeof(byte), repair.Payload, 0, payloadLen); // Copy the parity payload bytes from the buffer starting at the payload offset (17 bytes into the packet)
            }
            else // Zero-length payload — the FEC repair packet has no parity data (valid but unusual, perhaps a header-only signaling packet)
            {
                repair.Payload = null; // Explicitly set Payload to null rather than leaving an empty array — callers can distinguish "no payload" from "zero-length payload"
            }

            packet = repair; // Assign the fully decoded FEC repair packet to the out parameter
            return true; // Success: a valid FEC repair packet was decoded
        }
    }
}
