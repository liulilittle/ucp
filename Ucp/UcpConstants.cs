// ┌───────────────────────────────────────────────────────────────────────────┐
// │  PPP PRIVATE NETWORK™ X — Universal Communication Protocol (UCP)         │
// │  UcpConstants.cs — Protocol constants and magic numbers                   │
// │                                                                          │
// │  All protocol-level constants live here so the same numeric choices      │
// │  compile to the same values across C#, Rust, and C++.  Every constant    │
// │  documents WHY a particular value was selected — not just what it is.    │
// │                                                                          │
// │  Design decisions encoded here:                                          │
// │   • Microsecond-precision timing (the wire format uses μs timestamps)    │
// │   • 1220-byte MSS avoids IP fragmentation on all common link layers      │
// │   • KCC 2.0 (Geodesic Congestion Control) with geodesic G1/G2/G3 RTT est.     │
// │   • QUIC-inspired SACK blocks for precise loss reporting                 │
// │   • NAK-based receiver-side loss detection with confidence tiers         │
// │   • Benchmark constants covering 100M→10G, mobile, satellite, VPN       │
// │                                                                          │
// │  Conventions:                                                            │
// │   • UPPER_SNAKE_CASE  — internal protocol constants (C++/Rust-style)    │
// │   • PascalCase         — public aliases for external C# consumers        │
// │   • MICROS suffix      — value is in microseconds                        │
// │   • _FIELD_SIZE suffix — encoded field width on the wire in bytes        │
// └───────────────────────────────────────────────────────────────────────────┘

/// <summary>
/// All protocol-level constants, magic numbers, timing conversions, and
/// configuration defaults used throughout the UCP protocol stack.  Every
/// numeric value includes WHY it was chosen, not just what it is.
/// </summary>
namespace Ucp
{
    /// <summary>
    /// Central protocol constants kept in one place for future C++ portability.
    /// Time values use microseconds unless the constant name states another unit.
    /// </summary>
    public static class UcpConstants
    {
        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 1 — TIME UNIT CONVERSIONS
        //
        //  UCP uses microseconds everywhere internally because:
        //    • RTTs on LAN paths are sub-millisecond (need μs precision)
        //    • UCP pacing intervals are often 100–1000 μs
        //    • The wire-format 48-bit timestamp field stores μs since epoch
        //  These constants prevent accidental scale-factor bugs when
        //  converting between C# timer primitives and protocol units.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Number of microseconds in one millisecond.</summary>
        /// <remarks>
        /// Standard SI conversion (1 ms = 1000 μs).  Chosen over 1024
        /// because all OS timers and the wire-format timestamp field
        /// use decimal microseconds, not binary subdivisions.
        /// </remarks>
        public const long MICROS_PER_MILLI = 1000L; // Runtime: denominator when converting ms→μs for delayed-ACK timers and pacing interval checks.

        /// <summary>Number of microseconds in one second.</summary>
        /// <remarks>
        /// Standard SI conversion.  Used as the denominator when
        /// converting from bytes-per-second pacing rates to
        /// bytes-per-microsecond inter-packet gaps.
        /// </remarks>
        public const long MICROS_PER_SECOND = 1000000L; // Runtime: denominator in UCP pacing-gap calculations (bytes/sec → bytes/μs).



        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 2 — PACKET FORMAT CONSTANTS
        //
        //  Every UCP packet shares a 12-byte common header, then appends
        //  type-specific fields.  The MSS is the absolute upper bound a
        //  packet may occupy on the wire before IP fragmentation risk.
        //  These constants let encoders/decoders pre-allocate buffers and
        //  validate sizes without recomputing field offsets.
        //
        //  Common header layout (12 bytes):
        //    [0]     Type        (1 byte)   — UcpPacketType enum
        //    [1]     Flags       (1 byte)   — UcpPacketFlags bitmask
        //    [2:5]   ConnectionId (4 bytes) — uint32, big-endian
        //    [6:11]  Timestamp   (6 bytes)  — uint48, big-endian, μs
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Protocol maximum segment size in bytes.</summary>
        /// <remarks>
        /// Chosen as 1220 because it fits within:
        ///   • IPv6 minimum MTU (1280) minus 40-byte IPv6 header
        ///     and 8-byte UDP header, leaving 1232 bytes; 1220 gives
        ///     a 12-byte safety margin for IP options and tunnels.
        ///   • 1500-byte Ethernet MTU — 1220 + 20 (IPv4) + 8 (UDP) + 40
        ///     (encapsulation headroom) = 1288, still well under 1500.
        /// Avoiding IP fragmentation is critical for UDP-based transports
        /// because a single lost fragment discards the entire datagram.
        /// </remarks>
        public const int MSS = 1220; // Runtime: caps every outbound packet to 1220 bytes; larger values risk IP fragmentation and datagram loss.

        /// <summary>Common packet header size in bytes (Type + Flags + ConnectionId + Timestamp).</summary>
        /// <remarks>
        /// 1 byte Type + 1 byte Flags + 4 byte ConnectionId + 6 byte Timestamp = 12 bytes.
        /// The timestamp uses 48 bits (6 bytes) — a range of 2^48 microseconds
        /// ≈ 8.9 years before wrap-around.
        /// </remarks>
        public const int COMMON_HEADER_SIZE = 12; // Runtime: offset for data payload in every packet; pre-allocated buffer size for header parsing.

        /// <summary>Minimum Data packet-specific header size in bytes (without piggybacked ACK).</summary>
        /// <remarks>
        /// Common header (12) + SequenceNumber (4) + FragmentTotal (2) + FragmentIndex (2) = 20 bytes.
        /// FragmentTotal/FragmentIndex support message fragmentation for payloads
        /// exceeding the per-packet data budget.
        /// </remarks>
        public const int DATA_HEADER_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(ushort); // Runtime: per-packet overhead subtracted from MSS to determine payload budget.

        /// <summary>Data packet header size when piggybacked ACK (HasAckNumber flag) is present, in bytes (excludes variable SACK blocks).</summary>
        /// <remarks>
        /// Base data header (20) + AckNumber (4) + SackBlockCount (2) + WindowSize (4) + EchoTimestamp (6) = 36 bytes.
        /// Piggybacked ACKs save a round-trip by acknowledging the reverse
        /// direction within the same wire frame as forward data.  The sender
        /// sets the HasAckNumber flag in the common header to signal that the
        /// extended header format is in use.
        /// </remarks>
        public const int DATA_HEADER_SIZE_WITH_ACK = DATA_HEADER_SIZE + ACK_NUMBER_SIZE + sizeof(ushort) + sizeof(uint) + ACK_TIMESTAMP_FIELD_SIZE; // Runtime: expanded header layout used when HasAckNumber flag is set on a data packet.

        /// <summary>Fixed ACK packet size in bytes before variable SACK blocks.</summary>
        /// <remarks>
        /// Common header (12) + AckNumber (4) + SackBlockCount (2) + WindowSize (4) + EchoTimestamp (6) = 28 bytes.
        /// The echo timestamp is the sender's original timestamp reflected
        /// back by the receiver, enabling one-sided RTT measurement without
        /// per-packet state at the sender.
        /// </remarks>
        public const int ACK_FIXED_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(uint) + ACK_TIMESTAMP_FIELD_SIZE; // Runtime: baseline ACK serialization length; variable SACK blocks are appended after this.

        /// <summary>Fixed NAK packet size in bytes before variable missing sequence entries (includes AckNumber).</summary>
        /// <remarks>
        /// Common header (12) + AckNumber (4) + MissingCount (2) = 18 bytes.
        /// NAKs carry an AckNumber (the last contiguous sequence received)
        /// followed by a list of explicitly missing sequence numbers.
        /// </remarks>
        public const int NAK_FIXED_SIZE = COMMON_HEADER_SIZE + ACK_NUMBER_SIZE + sizeof(ushort); // Runtime: minimum size of a NAK before missing-sequence entries; bounds-checked during decode.

        /// <summary>Maximum data payload size in one packet, in bytes.</summary>
        /// <remarks>
        /// MSS (1220) − DATA_HEADER_SIZE (20) = 1200 bytes.
        /// This is the per-packet application-data budget.  Larger messages
        /// must be fragmented across multiple packets using FragmentTotal
        /// and FragmentIndex.
        /// </remarks>
        public const int MAX_PAYLOAD_SIZE = MSS - DATA_HEADER_SIZE; // Runtime: per-packet application-data ceiling; larger messages are fragmented across multiple packets.

        /// <summary>Encoded SACK block size in bytes (2 × uint32).</summary>
        /// <remarks>
        /// Each SACK block encodes a [start, end] range of acknowledged
        /// sequence numbers (both endpoints inclusive).
        /// 4 bytes start + 4 bytes end = 8 bytes per block.
        /// </remarks>
        public const int SACK_BLOCK_SIZE = sizeof(uint) + sizeof(uint); // Runtime: stride used when iterating over SACK blocks inside an ACK packet during loss detection.

        /// <summary>Encoded sequence number size in bytes (uint32).</summary>
        /// <remarks>
        /// 32-bit sequence numbers provide 4 billion packets of range.
        /// At 1200 bytes/packet and 10 Gbps, that is ~4,123 seconds
        /// before wrap-around — well above any practical connection
        /// lifetime at those rates.
        /// </remarks>
        public const int SEQUENCE_NUMBER_SIZE = sizeof(uint); // Runtime: byte count read/written for every sequence number in packet encode/decode.

        /// <summary>Half the uint32 sequence space (2^31) for wrap-around comparison.</summary>
        public const uint HALF_SEQUENCE_SPACE = 2147483648U; // Runtime: used for sequence number wrap-around arithmetic (seq < other ? diff < half).

        /// <summary>Encoded ACK number field size in bytes (uint32).</summary>
        public const int ACK_NUMBER_SIZE = sizeof(uint); // Runtime: byte count for ACK/NAK serialization; referenced by header-size calculations above.

        /// <summary>Encoded session key field size in bytes (uint64).</summary>
        public const int SESSION_KEY_SIZE = sizeof(ulong); // Runtime: byte count for session_key in SYN/SYN-ACK control packets.

        /// <summary>Encoded connection identifier size in bytes (uint32).</summary>
        /// <remarks>
        /// 32-bit connection IDs support up to ~4 billion simultaneous
        /// connections per endpoint pair, far exceeding any practical
        /// deployment.
        /// </remarks>
        public const int CONNECTION_ID_SIZE = sizeof(uint); // Runtime: byte count for connection demux key; read from every packet's common header.

        // =====================================================================
        // CID ROTATION (Dynamic CID Migration)
        // =====================================================================

        /// <summary>CID rotation interval in microseconds (60 seconds).</summary>
        public const long CID_ROTATE_INTERVAL_MICROS = 60000000L;

        /// <summary>Age at which an extra CID is retired (120 seconds).</summary>
        public const long CID_RETIRE_AGE_MICROS = 120000000L;

        /// <summary>Reserved sequence number marking CID-rotation DATA packets.</summary>
        public const uint CID_ROTATE_SEQUENCE_MARKER = 0xFFFFFFFFU;

        /// <summary>CID rotation ACK timeout in microseconds (5 seconds). If no ACK within this time, reset _cidRotatePending to allow future rotations.</summary>
        public const long CID_ROTATE_ACK_TIMEOUT_MICROS = 5_000_000L;

        /// <summary>ACK timestamp field size in bytes (uint48).</summary>
        /// <remarks>
        /// 48 bits = 6 bytes.  Microsecond timestamps fit in 48 bits for
        /// ~8.9 years (2^48 microseconds).  Using 6 bytes instead of 8 saves
        /// 2 bytes per ACK packet without sacrificing range.
        /// </remarks>
        public const int ACK_TIMESTAMP_FIELD_SIZE = 6; // Runtime: byte count written/read for echo timestamps in ACK and piggybacked-ACK headers.

        /// <summary>Encoded packet type field size in bytes.</summary>
        public const int PACKET_TYPE_FIELD_SIZE = sizeof(byte); // Runtime: used by UcpPacketCodec as the read/write width for the Type byte in the common header.

        /// <summary>Encoded packet flags field size in bytes.</summary>
        public const int PACKET_FLAGS_FIELD_SIZE = sizeof(byte); // Runtime: used by UcpPacketCodec as the read/write width for the Flags byte in the common header.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 2b — BIT COUNTS FOR SERIALIZATION
        //
        //  Named shift constants used by the big-endian Read/Write helpers
        //  in UcpPacketCodec.cs.  Named constants prevent magic-number bugs
        //  and make the shift arithmetic self-documenting.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Bit count in a 16-bit integer.</summary>
        public const int UINT16_BITS = 16; // Runtime: shift amount when packing/unpacking 16-bit big-endian fields (seq frag counts, SackBlockCount).

        /// <summary>Bit count in a 24-bit field.</summary>
        /// <remarks>
        /// 24-bit shifts are used for the third byte of uint32 and uint48
        /// serialization (byte at offset 2 in big-endian: bits [23:16]).
        /// </remarks>
        public const int UINT24_BITS = 24; // Runtime: shift amount for byte 2 of multi-byte integer serialization in big-endian encoding.

        /// <summary>Bit count in a 32-bit field.</summary>
        public const int UINT32_BITS = 32; // Runtime: shift amount for the most-significant byte (byte 3) of uint32 serialization.

        /// <summary>Bit count in a 40-bit field.</summary>
        /// <remarks>
        /// 40-bit shifts are used for the most-significant byte of uint48
        /// serialization (byte at offset 0 in big-endian: bits [47:40]).
        /// </remarks>
        public const int UINT40_BITS = 40; // Runtime: shift amount for the MSB of uint48 timestamp serialization (bits [47:40]).

        /// <summary>Bit count in one byte.</summary>
        public const int BYTE_BITS = 8; // Runtime: used in bit-shift calculations throughout the codec (e.g., byte×8 → bit index).

        /// <summary>Mask used to keep only the low 48 bits of an ACK timestamp.</summary>
        /// <remarks>
        /// Applied when writing a C# Int64 into a 6-byte uint48 field.
        /// Discards bits [63:48] so they don't leak into adjacent fields.
        /// 0x0000FFFFFFFFFFFF = 2^48 − 1.
        /// </remarks>
        public const ulong UINT48_MASK = 0x0000FFFFFFFFFFFFUL; // Runtime: bitwise-AND applied to every long→uint48 write; prevents upper-byte corruption.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 3 — WINDOW AND BUFFER SIZES
        //
        //  Receive window, congestion window, send buffer, and pacing
        //  configuration.  These govern how much data can be in-flight
        //  before the sender must pause for an ACK.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Default receive window size measured in packets.</summary>
        /// <remarks>
        /// 4096 packets × 1220 bytes/packet = ~5 MB receive window.
        /// Powers of 2 work well with sequence-number arithmetic.
        /// This window supports 1 Gbps at ~40 ms RTT (BDP ≈ 5 MB),
        /// and 100 Mbps at latencies up to 400 ms.
        /// </remarks>
        public const int DEFAULT_RECV_WINDOW_PACKETS = 4096; // Runtime: receive-window capacity in packets; advertised to the sender to cap flights.

        /// <summary>Default receive window size measured in bytes.</summary>
        public const uint DEFAULT_RECV_WINDOW_BYTES = (uint)(DEFAULT_RECV_WINDOW_PACKETS * MSS); // Runtime: receive-window in bytes (~5 MB); overflow-safe uint used in window comparisons.



        /// <summary>Initial congestion window packet count (matches TCP IW10).</summary>
        /// <remarks>
        /// 10 packets (~12 KB) initial window.  Matches TCP's IW10
        /// (RFC 6928) and the kernel's TCP_INIT_CWND.  UCP's pacing
        /// spreads these across one RTT to avoid bursts.
        /// </remarks>
        public const int INITIAL_CWND_PACKETS = 10; // Runtime: UCP Startup initial inflight allowance; spread by the pacer across one RTT.

        /// <summary>Default send buffer capacity in bytes.</summary>
        /// <remarks>
        /// 32 MB send buffer.  Large enough for 10 Gbps at typical WAN
        /// RTTs without blocking the application.  The send buffer absorbs
        /// application writes while the congestion controller drains them
        /// at the pacing rate.
        /// </remarks>
        public const int DEFAULT_SEND_BUFFER_BYTES = 32 * 1024 * 1024; // Runtime: pre-allocates 32 MB of send-buffer memory per UCP connection.

        /// <summary>Default delayed ACK timeout in microseconds.</summary>
        /// <remarks>
        /// 100 μs.  UCP piggybacks ACKs on data packets, eliminating standalone
        /// ACK overhead.  Delayed ACKs only fire when no outbound data is available.
        /// 100 μs is sufficient for sub-RTT batching without inflating RTT.
        /// </remarks>
        public const long DEFAULT_DELAYED_ACK_TIMEOUT_MICROS = 100L; // Runtime: max wait before sending a standalone ACK when no outbound data is queued.

        /// <summary>Default maximum tolerated bandwidth waste ratio, where 0.25 means 25%.</summary>
        /// <remarks>
        /// 25% overhead ceiling.  Retransmissions consume bandwidth, and
        /// this ratio caps how much of the link capacity may be "wasted"
        /// before the sender backs off.  25% matches empirical observations
        /// on lossy 4G/5G mobile paths (1–5% random loss generates ~20–25%
        /// retransmit overhead with efficient SACK-based recovery).
        /// </remarks>
        public const double DEFAULT_MAX_BANDWIDTH_WASTE_RATIO = 0.25d; // Runtime: if retransmit overhead exceeds 25% of total throughput the sender throttles.

        /// <summary>Default maximum tolerated bandwidth loss percentage exposed to users.</summary>
        public const double DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT = 25d; // Runtime: user-facing loss ceiling (25%); derived from the waste ratio above.

        /// <summary>Minimum allowed configured bandwidth loss percentage.</summary>
        /// <remarks>
        /// 15% floor.  Below this, the sender would throttle too
        /// aggressively on paths with routine random loss (Wi-Fi, 4G).
        /// </remarks>
        public const double MIN_MAX_BANDWIDTH_LOSS_PERCENT = 15d; // Runtime: lower-bound validation on user-provided loss-percent settings.

        /// <summary>Maximum allowed configured bandwidth loss percentage.</summary>
        /// <remarks>
        /// 35% ceiling.  Above this, the sender would tolerate loss
        /// rates where throughput collapses regardless.
        /// </remarks>
        public const double MAX_MAX_BANDWIDTH_LOSS_PERCENT = 35d; // Runtime: upper-bound validation on user-provided loss-percent settings.

        /// <summary>No minimum pacing interval — allows sub-μs inter-packet spacing at 10 Gbps
        /// line rate.  The pacing token bucket provides burst elasticity; enforcing
        /// a minimum gap would cap peak throughput.  At rates below ~100 Mbps the
        /// computed inter-packet gap is naturally large enough to avoid excessive CPU.</summary>
        /// <remarks>
        /// 0 μs = no artificial inter-packet gap floor.  When the pacing
        /// rate is very high (e.g. 10 Gbps), the computed gap can be
        /// sub-microsecond.  Forcing a minimum would cap throughput below
        /// line rate on fast links.
        /// </remarks>
        public const long DEFAULT_MIN_PACING_INTERVAL_MICROS = 0L; // Runtime: no floor on inter-packet spacing; allows sub-μs gaps at 10 Gbps rates.

        /// <summary>Default pacing token bucket duration in microseconds.</summary>
        /// <remarks>
        /// 10,000 μs = 10 ms.  The token bucket refills over a 10 ms window.
        /// This is long enough to smooth bursts at typical WAN rates but short
        /// enough that the bucket doesn't allow seconds-long bursts that
        /// overwhelm shallow router buffers.
        /// </remarks>
        public const long DEFAULT_PACING_BUCKET_DURATION_MICROS = 10000L; // Runtime: token-bucket refill window; burst size is pacing_rate × 10 ms.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 4 — RTO (RETRANSMISSION TIMEOUT)
        //
        //  RFC 6298-style RTO computation with UCP-specific tuning for
        //  modern low-latency paths.  The RTO backoff is multiplicative
        //  (like TCP) but the base values and backoff factor are lower
        //  because UCP uses NAK + SACK fast retransmit to recover most
        //  loss without waiting for the RTO timer.
        //
        //  RFC 6298 formula:
        //    SRTT   = (1 − α) × SRTT   + α × RTT_sample    (α = 1/8)
        //    RTTVAR = (1 − β) × RTTVAR + β × |SRTT − RTT_sample|  (β = 1/4)
        //    RTO    = SRTT + K × RTTVAR  (K = 4)
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>50 ms floor — significantly smaller than TCP's typical 200 ms minimum RTO.
        /// UCP's loss detection uses NAK-based fast recovery + UCP's rate-based
        /// detection, so a small MIN_RTO serves only as a last-resort safety net for
        /// complete SILENCE detection (no data, no ACK, no NAK for 50 ms).  This
        /// aggressive lower bound is safe because UCP does not rely on RTO expiry for
        /// ordinary loss recovery.</summary>
        /// <remarks>
        /// 50 ms.  TCP's minimum RTO is typically 200 ms, but UCP can
        /// safely use 50 ms because NAK-based loss detection recovers
        /// most packets in &lt;5 ms.  The RTO is only a last resort when
        /// both SACK and NAK fail.
        /// </remarks>
        public const long MIN_RTO_MICROS = 50000L; // Runtime: config validation floor; any user RTO below 50 ms is rejected.

        /// <summary>Default optimized minimum RTO, in microseconds.</summary>
        /// <remarks>
        /// 50 ms.  Long enough to ride through transient WiFi/4G jitter
        /// bursts without spurious retransmits, short enough that a true
        /// tail loss is recovered quickly.
        /// </remarks>
        public const long DEFAULT_RTO_MICROS = 50000L; // Runtime: the RTO timer fires at 50 ms by default; used until a measured SRTT is available.

        /// <summary>Initial RTO used before a measured RTT is available, in microseconds.</summary>
        /// <remarks>
        /// 50 ms.  Matches the default MIN_RTO so the first SYN timer
        /// fires at the same floor as the steady-state timer.  Modern
        /// WAN paths rarely exceed 50 ms, so this is safe.
        /// </remarks>
        public const long INITIAL_RTO_MICROS = 50000L; // Runtime: used for the first SYN retransmission timer before any RTT sample exists.

        /// <summary>Maximum RTO accepted by the optimized default configuration, in microseconds.</summary>
        /// <remarks>
        /// 15 s.  Above this, the connection is likely dead rather than
        /// just delayed.  Most paths recover or fail within this window.
        /// </remarks>
        public const long DEFAULT_MAX_RTO_MICROS = 15000000L; // Runtime: upper cap on the computed RTO timer during normal operation.

        /// <summary>Absolute fallback maximum RTO, in microseconds.</summary>
        /// <remarks>
        /// 60 s.  Catch-all for extreme satellite links (GEO at ~600 ms
        /// RTT with deep buffering).  After 60 seconds without progress,
        /// the connection is declared dead unconditionally.
        /// </remarks>
        public const long MAX_RTO_MICROS = 60000000L; // Runtime: hard ceiling on RTO; exceeded triggers unconditional connection teardown.

        /// <summary>Default RTO backoff multiplier.</summary>
        /// <remarks>
        /// 1.2× per timeout, not TCP's 2.0×.  UCP's gentler backoff avoids
        /// multi-second stalls on paths with occasional loss bursts.
        /// NAK-based recovery handles most losses, so the RTO fires only
        /// when the path is genuinely unresponsive, making aggressive
        /// backoff counterproductive.
        /// </remarks>
        public const double RTO_BACKOFF_FACTOR = 1.2d; // Runtime: RTO ← RTO × 1.2 after each timeout; gentler than TCP's 2× doubling.

        /// <summary>Maximum number of retransmission attempts per outbound segment.</summary>
        /// <remarks>
        /// 10 attempts.  After 10 consecutive RTO timeouts (roughly
        /// 10 × 100 ms × 1.2^n, ~2–3 seconds total), the connection
        /// is torn down.
        /// </remarks>
        public const int MAX_RETRANSMISSIONS = 10; // Runtime: max RTO timeouts per segment before connection teardown (~2–3 s total).

        /// <summary>Initial RTTVAR bootstrap divisor (first RTT sample / 2, RFC 6298 section 2.2).</summary>
        public const int UCP_INITIAL_RTTVAR_DIVISOR = 2; // Runtime: initial RTTVAR = first RTT sample / 2.

        /// <summary>State-machine evaluation floor in microseconds before the first RTT sample.</summary>
        public const long UCP_MIN_ROUND_DURATION_MICROS = MICROS_PER_MILLI; // Runtime: 1 ms floor for round-window math before any RTT sample exists.

        /// <summary>RTT threshold above which the delayed-ACK cap is shortened (30 ms).</summary>
        public const long HIGH_LATENCY_THRESHOLD_MICROS = 30000L; // Runtime: RTT >30 ms triggers the shorter delayed-ACK cap.

        /// <summary>Maximum timeout retransmits armed by one timer tick.</summary>
        /// <remarks>
        /// 4 segments per tick.  Prevents a single timer tick from
        /// dumping hundreds of retransmissions onto the wire after a
        /// long outage.  Spreads the retransmit load across multiple
        /// ticks to avoid self-inflicted congestion.
        /// </remarks>
        public const int RTO_RETRANSMIT_BUDGET_PER_TICK = 4; // Runtime: each 1 ms timer tick retransmits at most 4 RTO-timed-out segments.

        /// <summary>Maximum urgent retransmits allowed to bypass pacing in one RTT window.</summary>
        /// <remarks>
        /// 8192 segments per RTT.  Urgent retransmits (tail-loss probes,
        /// fast-retransmit triggers) bypass the pacer to minimize latency.
        /// The budget prevents an unbounded urgent flood on very lossy
        /// paths while still covering high-BDP tail-loss scenarios.
        /// </remarks>
        public const int URGENT_RETRANSMIT_BUDGET_PER_RTT = 8192; // Runtime: max urgent (pace-bypassing) retransmits per RTT window; prevents unbounded floods.

        /// <summary>Idle-time percentage after which a tail-loss probe may be urgent.</summary>
        /// <remarks>
        /// 75%.  If the sender has been idle for >75% of an RTT, the next
        /// transmission may be treated as urgent (bypass pacing).  This
        /// prevents the pacer from adding unnecessary latency when the
        /// application produces data after a quiet period.
        /// </remarks>
        public const int URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT = 75; // Runtime: sender-idle threshold that lets the next batch bypass the pacer.

        /// <summary>RTT variance EWMA denominator for RFC6298-style smoothing.</summary>
        /// <remarks>
        /// β = 1/4, the standard RFC 6298 value.  RTTVAR reacts to 25%
        /// of each new deviation sample, providing a balance between
        /// responsiveness and stability.
        /// </remarks>
        public const int RTT_VAR_DENOM = 4; // Runtime: RTTVAR ← (3×RTTVAR + deviation) / 4 per RTT sample (RFC 6298 β=1/4).

        /// <summary>RTT sample weight denominator for smoothed RTT EWMA.</summary>
        /// <remarks>
        /// α = 1/8, the standard RFC 6298 value.  SRTT incorporates 12.5%
        /// of each new RTT sample, giving stable estimates on paths with
        /// moderate jitter.
        /// </remarks>
        public const int RTT_SMOOTHING_DENOM = 8; // Runtime: SRTT ← (7×SRTT + sample) / 8 per sample (RFC 6298 α=1/8).

        /// <summary>Previous smoothed RTT numerator when using a 1/8 sample weight.</summary>
        /// <remarks>
        /// 7/8 weight on the previous SRTT value.  (1 − α) = 7/8.
        /// </remarks>
        public const int RTT_SMOOTHING_PREVIOUS_WEIGHT = RTT_SMOOTHING_DENOM - 1; // Runtime: multiplier on historical SRTT before blending the new sample.

        /// <summary>Previous RTT variance numerator when using a 1/4 sample weight.</summary>
        /// <remarks>
        /// 3/4 weight on the previous RTTVAR value.  (1 − β) = 3/4.
        /// </remarks>
        public const int RTT_VAR_PREVIOUS_WEIGHT = RTT_VAR_DENOM - 1; // Runtime: multiplier on historical RTTVAR before blending the deviation.

        /// <summary>RTT variance multiplier used when calculating RTO (SRTT + 4*RTTVAR, K = 4).</summary>
        /// <remarks>
        /// K = 4.  RTO = SRTT + 4 × RTTVAR.  RFC 6298 specifies K=4.
        /// UCP keeps K=4 always, trusting NAK to catch what
        /// the slightly looser RTO might miss.
        /// </remarks>
        public const int RTO_GAIN_MULTIPLIER = 4; // Runtime: RTO = SRTT + K × RTTVAR; the per-sample RTO computation used by the timer.

        /// <summary>Maximum accepted RTT sample multiplier relative to the current RTO during recovery.</summary>
        /// <remarks>
        /// 4.0×.  During loss recovery, RTT samples can spike due to
        /// retransmission ambiguity.  Samples exceeding 4× the current
        /// RTO are discarded as likely measuring a retransmitted packet
        /// rather than a genuine RTT (Karn's algorithm).
        /// </remarks>
        public const double RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER = 4.0d; // Runtime: RTT samples >4× RTO during recovery are discarded (Karn's algorithm).

        /// <summary>Backoff floor multiple relative to the minimum RTO.</summary>
        /// <remarks>
        /// The backed-off RTO is floored at 2 × MIN_RTO_MICROS (100 ms).  This
        /// keeps recovery prompt on very stable
        /// paths (where SRTT is tiny), keeping the retransmission interval
        /// prompt.
        /// </remarks>
        public const int RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER = 2; // Runtime: backed-off RTO is floored at 2 x MIN_RTO_MICROS (100 ms) to keep recovery prompt.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 5 — KCC 2.0 CONGESTION CONTROL (tcp_kcc.c v2.0 compatible)
        //
        //  KCC models the path as a pipe with a bottleneck bandwidth
        //  (BtlBw) and round-trip propagation delay (RTprop).  It paces
        //  at the estimated BtlBw and caps inflight at BDP × gain.
        //
        //  State machine (3-mode, no PROBE_RTT):
        //    Startup  → Drain  → ProbeBW
        //
        //  Propagation-delay estimation uses the geodesic G1/G2/G3
        //  estimator; the cross-connection Kalman filter (KF) provides
        //  a fair-share bandwidth floor for fast start.  All parameters
        //  follow the tcp_kcc.c v2.0 kernel implementation.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>UCP bandwidth RT cycle length in RTT rounds.</summary>
        /// <remarks>
        /// 10 RTT rounds.  UCP maintains a max-filter over the last 10
        /// delivery-rate samples.  Matches the tcp_kcc.c UCP_BW_RT_CYCLE_LEN.
        /// </remarks>
        public const int UCP_BW_RT_CYCLE_LEN = 10; // Runtime: UCP max-filter holds up to 10 RTT rounds.

        /// <summary>Number of consecutive sub-threshold rounds required to exit Startup.</summary>
        /// <remarks>
        /// 3 rounds.  Startup must see 3 consecutive rounds where the
        /// bandwidth growth is below UCP_KCC_FULL_BW_THRESH (1.25x)
        /// before exiting to Drain.  Matches tcp_kcc.c UCP_FULL_BW_CNT.
        /// </remarks>
        public const int UCP_FULL_BW_CNT = 3; // Runtime: Startup exits to Drain after 3 consecutive rounds of sub-25% growth.

        /// <summary>Startup pacing gain (739/256 ≈ 2.88671875, matches C++ tcp_kcc.c).</summary>
        /// <remarks>
        /// C++ defines kcc_high_gain_val = 739 (in BBR_UNIT=256 units), giving
        /// 739/256 ≈ 2.88671875.  During Startup the sender paces at this rate
        /// to rapidly fill the pipe and discover the bottleneck bandwidth.
        /// </remarks>
        public const double UCP_STARTUP_PACING_GAIN = 739.0 / 256.0; // Runtime: Startup phases pace data at 739/256 × BtlBw (aligned with tcp_kcc.c).

        /// <summary>Startup congestion window gain (739/256 ≈ 2.88671875, matches C++ tcp_kcc.c).</summary>
        /// <remarks>
        /// Inflight cap = 739/256 × BDP during Startup.  Matches the pacing gain
        /// during Startup (both use the same multiplier).  KCC (tcp_kcc.c)
        /// sets cwnd_gain = STARTUP_HIGH_GAIN in Startup mode.
        /// </remarks>
        public const double UCP_STARTUP_CWND_GAIN = 739.0 / 256.0; // Runtime: Startup inflight cap = 739/256 × BDP (aligned with tcp_kcc.c).

        /// <summary>Drain pacing gain (88/256 ≈ 0.34375×, matches C++ DRAIN_GAIN).</summary>
        /// <remarks>
        /// After Startup, Drain paces at 88/256 ≈ 0.34375× estimated bandwidth to
        /// rapidly drain the standing queue that Startup created.
        /// Matches the C++ DRAIN_GAIN (kcc_drain_gain_val = 88/256).
        /// </remarks>
        public const double UCP_DRAIN_PACING_GAIN = 88.0 / 256.0; // Runtime: Drain phase pacing = 0.34375× estimated BtlBw; matches C++ DRAIN_GAIN.

        /// <summary>High probing pacing gain (1.25x).</summary>
        /// <remarks>
        /// Probes at 25% above estimated bandwidth to find newly
        /// available capacity.  Matches tcp_kcc.c ProbeBw high gain.
        /// </remarks>
        public const double UCP_PROBE_BW_HIGH_GAIN = 1.25d; // Runtime: ProbeBW high phase paces 25% above BtlBw.

        /// <summary>Low probing pacing gain (0.75x).</summary>
        /// <remarks>
        /// Drains at 25% below estimated bandwidth to empty queues
        /// accumulated during high-gain phase.  Matches tcp_kcc.c.
        /// </remarks>
        public const double UCP_PROBE_BW_LOW_GAIN = 0.75d; // Runtime: ProbeBW low phase paces 25% below BtlBw to drain queues.

        /// <summary>ProbeBW congestion window gain (2.0x).</summary>
        /// <remarks>
        /// During ProbeBW, the inflight cap is 2.0 × BDP.  This matches
        /// the Startup CWND gain, providing consistent headroom across
        /// phases.
        /// </remarks>
        public const double UCP_PROBE_BW_CWND_GAIN = 2.0d; // Runtime: ProbeBW inflight cap = 2.0 × BDP.

        /// <summary>KCC 2.0 scale constants (aligned with tcp_kcc.c).</summary>
        public const int UCP_BW_SCALE = 24;
        public const long UCP_BW_UNIT = 1L << UCP_BW_SCALE;
        public const int UCP_GAIN_SCALE = 8;
        public const int UCP_GAIN_UNIT = 1 << UCP_GAIN_SCALE;
        public const int UCP_KCC_SCALE_SHIFT = 10;

        /// <summary>KCC 2.0 geodesic estimator constants.</summary>
        public const int UCP_G2_GROWTH_NUM = 122;
        public const int UCP_G2_GROWTH_DEN = 1000;
        public const int UCP_G3_FAST_TH_NUM = 11;
        public const int UCP_G3_FAST_TH_DEN = 10;
        public const int UCP_G3_SLOW_TH_NUM = 21;
        public const int UCP_G3_SLOW_TH_DEN = 20;
        public const int UCP_G3_FAST_CNT = 6;
        public const int UCP_G3_SLOW_CNT = 7;
        public const int UCP_LOCK_THRESH_US = 5000;
        public const int UCP_FAST_ONLY_THRESH_US = 7500;
        public const int UCP_STALENESS_RNDS = 128;
        public const int UCP_PD_NOISE_GATE_NUM = 95;
        public const int UCP_PD_NOISE_GATE_DEN = 100;
        public const long UCP_P_EST_INIT = 1000;
        public const long UCP_P_EST_FLOOR = 10;
        public const int UCP_P_EST_DECAY_SHIFT = 4;
        public const int UCP_P_EST_GROWTH_SHIFT = 3;
        public const long UCP_P_EST_MAX = 1000000;
        public const int UCP_MIN_SAMPLES = 5;
        public const long UCP_RTT_SAMPLE_MAX_US = 500000;
        public const long UCP_INNOV_SQ_CAP = 3000000000L;
        public const int UCP_EWMA_JITTER_NUM = 7;
        public const int UCP_EWMA_JITTER_DEN = 8;
        public const int UCP_EWMA_QDELAY_NUM = 7;
        public const int UCP_EWMA_QDELAY_DEN = 8;
        public const int UCP_JITTER_SEED_SHIFT = 2;
        public const int UCP_MINRTT_FAST_FALL_CNT = 5;
        public const int UCP_MINRTT_FAST_FALL_DIV = 4;
        public const int UCP_MINRTT_STICKY_NUM = 75;
        public const int UCP_MINRTT_STICKY_DEN = 100;
        public const int UCP_MINRTT_SRTT_GUARD_NUM = 90;
        public const int UCP_MINRTT_SRTT_GUARD_DEN = 100;
        public const int UCP_QDELAY_CLEAN_BP = 1000;
        public const int UCP_QDELAY_CONG_BP = 2500;
        public const long UCP_QDELAY_FLOOR_US = 500;
        public const int UCP_QDELAY_BP_BASE = 10000;
        public const int UCP_BITFIELD_3BIT_MAX = 7;

        /// <summary>KCC 2.0 FSM gains.</summary>
        public const int UCP_HIGH_GAIN = (256 * 2885 / 1000 + 1); // 739
        public const int UCP_DRAIN_GAIN = (256 * 1000 / 2885); // 88
        public const int UCP_CWND_GAIN = 512; // 2.0x
        public const int UCP_PACING_INIT_GAIN = 739;
        public const int UCP_KCC_FULL_BW_THRESH = 320; // 1.25x growth threshold (tcp_kcc.c FULL_BW_THRESH)
        public const int UCP_KCC_FULL_BW_CNT = 3; // rounds without 1.25x growth before exiting Startup
        public const int UCP_PROBE_BW_CYCLE_RAND = 7;

        /// <summary>KCC 2.0 PROBE_BW cycle length (8 phases, tcp_kcc.c CYCLE_LEN).</summary>
        public const int UCP_PROBE_BW_CYCLE_LEN = 8;

        /// <summary>KCC 2.0 precomputed gain-table slot count (tcp_kcc.c gain slots).</summary>
        public const int UCP_GAIN_SLOTS = 256;

        /// <summary>KCC 2.0 maximum gain in 1/256 units (tcp_kcc.c GAIN_MAX=1023).</summary>
        public const int UCP_GAIN_MAX = 1023;

        /// <summary>Alias of UCP_GAIN_MAX, matching the C++ KCC_GAIN_MAX name.</summary>
        public const int UCP_KCC_GAIN_MAX = UCP_GAIN_MAX;

        /// <summary>KCC 2.0 percentage base (tcp_kcc.c PCT_BASE=100).</summary>
        public const int UCP_PCT_BASE = 100;

        /// <summary>KCC 2.0 gain-phase fractions for the 8-slot cycle: {1.25, 0.75, 1.0 x6}.</summary>
        public const int UCP_GAIN_PROBE_PHASE_NUM = 5;
        public const int UCP_GAIN_PROBE_PHASE_DEN = 4;
        public const int UCP_GAIN_DRAIN_PHASE_NUM = 3;
        public const int UCP_GAIN_DRAIN_PHASE_DEN = 4;
        public const int UCP_GAIN_CRUISE_PHASE_NUM = 1;
        public const int UCP_GAIN_CRUISE_PHASE_DEN = 1;

        /// <summary>KCC 2.0 misc fixed-point constants (tcp_kcc.c).</summary>
        public const int UCP_SRTT_SHIFT = 3; // srtt stored << 3 (kernel tcp semantics)
        public const int UCP_RTT_MIN_FLOOR_US = 1; // minimum accepted RTT sample
        public const int UCP_GAIN_FLOOR = 1; // minimum cwnd gain after ECN backoff
        public const int UCP_CWND_MIN_TARGET = 4; // cwnd floor in segments (CWND_MIN_TARGET)
        public const int UCP_PROBE_CWND_BONUS = 2; // probe-phase cwnd bonus in segments
        public const long UCP_BDP_MIN_RTT_US = 1; // pre-convergence model-RTT floor
        public const long UCP_MIN_RTT_UNINIT = 0xFFFFFFFFL; // min_rtt sentinel before the first sample

        /// <summary>KCC 2.0 CA states (matches tcp_kcc.c bbr_ca_state).</summary>
        public const int UCP_CA_OPEN = 0;
        public const int UCP_CA_RECOVERY = 2;
        public const int UCP_CA_LOSS = 3;

        /// <summary>KCC 2.0 LT-BW (policer detection) constants.</summary>
        public const int UCP_LT_LOSS_THRESH = 50; // 50/256 ~ 20% loss gate for a policer candidate
        public const int UCP_LT_BW_RATIO_NUM = 1;
        public const int UCP_LT_BW_RATIO_DEN = 8;
        public const int UCP_LT_BW_RATIO = (256 * UCP_LT_BW_RATIO_NUM) / UCP_LT_BW_RATIO_DEN;
        public const int UCP_LT_BW_DIFF = 500;
        public const int UCP_LT_BW_EMA_NUM = 1;
        public const int UCP_LT_BW_EMA_DEN = 2;
        public const long UCP_LT_BW_ITHRESH = 5000;
        public const int UCP_LT_INTVL_MIN_RTTS = 4; // minimum sampling interval in RTT rounds
        public const int UCP_LT_INTVL_MAX_MULT = 4; // interval timeout = MIN_RTTS * MAX_MULT
        public const int UCP_LT_BW_MAX_RTTS = 48; // lt_bw expires after 48 active RTT rounds
        public const int UCP_LT_RTT_CNT_MAX = 4095; // lt_rtt_cnt saturates at 4095 (12-bit field)

        /// <summary>KCC 2.0 ACK aggregation constants.</summary>
        public const int UCP_EXTRA_ACKED_GAIN_NUM = 1;
        public const int UCP_EXTRA_ACKED_GAIN_DEN = 1;
        public const long UCP_EXTRA_ACKED_MAX_MS_RATIO = 100;
        public const int UCP_EXTRA_ACKED_WIN_RTTS_MAX = 31;
        public const int UCP_AGG_WINDOW_ROTATION_RTTS = 5;
        public const long UCP_ACK_EPOCH_MAX = 0x100000;

        /// <summary>KCC 2.0 KF (cross-connection Kalman filter) constants.</summary>
        public const int UCP_KF_CHI2_NUM = 384;
        public const int UCP_KF_CHI2_DEN = 100;
        public const int UCP_KF_Q_SHIFT = 20;
        public const int UCP_KF_STEADY_R_PCT = 5;
        public const int UCP_KF_STARTUP_R_PCT = 15;
        public const long UCP_KF_OVERFLOW_GUARD = 1L << 31;
        public const int UCP_KF_INNOV_SHIFT = 10;
        public const int UCP_KF_VAR_SHIFT = 20;
        public const int UCP_KF_CWND_SEGS_MAX = 20000;
        public const int UCP_KF_DISCOUNT_NUM = 50;
        public const int UCP_KF_DISCOUNT_DEN = 100;

        /// <summary>KCC 2.0 TSO constants.</summary>
        public const int UCP_TSO_HEADROOM_MULT = 3;
        public const int UCP_TSO_DIV_CEIL = 32;
        public const int UCP_TSO_DIV_DOUBLE_SHIFT = 1;
        public const int UCP_TSO_HIGH_JITTER_THRESH_US = 4000;
        public const int UCP_TSO_MAX_SEGS = 127;
        public const int UCP_TSO_SEGS_DEFAULT = 2;
        public const int UCP_TSO_SEGS_LOW = 1;
        public const long UCP_TSO_RATE_DIV_2 = UCP_MIN_TSO_RATE_DIV; // alias of UCP_MIN_TSO_RATE_DIV (8)
        public const long UCP_MIN_TSO_RATE_BPS = UCP_MIN_TSO_RATE; // alias of UCP_MIN_TSO_RATE (1200000)

        /// <summary>KCC 2.0 misc constants.</summary>
        public const int UCP_CWND_ABSOLUTE_MIN = 1;
        public const int UCP_DRAIN_AND_OR_MODE = 1;
        public const int UCP_DEFAULT_RTT_US = 1000;
        public const int UCP_SNDBUF_EXPAND_FACTOR = 3;
        public const long UCP_EDT_NEAR_NOW_NS = 1000;
        public const int UCP_ECN_EWMA_FLOOR = 4;
        public const int UCP_ECN_IDLE_DECAY_NUM = 31;
        public const int UCP_ECN_IDLE_DECAY_DEN = 32;

        /// <summary>KCC 2.0 ECN (runtime-gated via UcpConfiguration.EcnEnabled, default off).</summary>
        public const int UCP_ECN_BACKOFF_NUM = 20; // 20/100 ECN backoff fraction
        public const int UCP_ECN_BACKOFF_DEN = 100;
        public const int UCP_ECN_EWMA_RETAINED = 3; // 3/4 retained weight in the ECN EWMA
        public const int UCP_ECN_EWMA_TOTAL = 4;

        /// <summary>Minimum TSO rate and divisor used by kcc_min_tso_segs.</summary>
        public const int UCP_MIN_TSO_RATE = 1200000;
        public const int UCP_MIN_TSO_RATE_DIV = 8;
        public const int MAX_FEC_SLOT_LENGTH = 1200; // Runtime: validates FEC repair payloads ≤ 1200 bytes; larger values indicate corruption.

        /// <summary>Minimum estimated loss percent to enable adaptive FEC encoding (2%).</summary>
        /// <remarks>
        /// 2%.  Below 2% estimated loss, the bandwidth cost of FEC
        /// exceeds the benefit.  The 2% threshold prevents FEC from
        /// activating on near-perfect paths where occasional single-
        /// packet drops are cheaper to retransmit than to FEC-protect.
        /// </remarks>
        public const double FEC_ADAPTIVE_MIN_LOSS_PERCENT = 2d; // Runtime: adaptive FEC activates at ≥2% estimated loss; ≤2% → cheaper to retransmit.

        /// <summary>Alias of FEC_ADAPTIVE_MIN_LOSS_PERCENT used by the PCB adaptive-FEC gate.</summary>
        public const double ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT = FEC_ADAPTIVE_MIN_LOSS_PERCENT; // Runtime: PCB compares EstimatedLossPercent against this before emitting FEC repairs.



        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 8 — LOSS DETECTION, NAK, AND SACK
        //
        //  UCP uses a three-tier loss detection strategy:
        //   1. SACK-based fast retransmit — sender detects holes from the
        //      SACK blocks carried in ACK packets.  A hole must be observed
        //      in 2 SACK blocks and the ACK must have advanced 48 sequences
        //      past it before retransmission.
        //   2. NAK-based receiver push — the receiver explicitly signals
        //      missing packets via NAK packets when it observes gaps in the
        //      sequence space after a grace period.
        //   3. RTO timeout — last resort when both SACK and NAK fail.
        //
        //  The confidence-tiered NAK system prevents false positives from
        //  packet reordering (which is common on WiFi and multipath routes):
        //
        //    Tier              Obs.   Grace    Use case
        //    ──────────────────────────────────────────────
        //    Standard NAK        2   2000 μs   Normal loss suspicion
        //    Medium confidence   32   1000 μs   Likely loss, low reorder risk
        //    High confidence    128   1000 μs   Almost certain loss
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Maximum number of NAK packets emitted during one RTT interval.</summary>
        /// <remarks>
        /// 1024.  Prevents a NAK storm on very lossy paths where every
        /// other packet triggers a NAK.  1024 NAKs/RTT is still ~1 NAK
        /// per ms at 1 Gbps, which is manageable.
        /// </remarks>
        public const int MAX_NAKS_PER_RTT = 1024; // Runtime: per-RTT ceiling on NAK emission; prevents NAK storms on very lossy paths.

        /// <summary>Threshold in payload-sized segments below which early retransmit is allowed.</summary>
        /// <remarks>
        /// 4 segments.  RFC 5827 Early Retransmit: if inflight is below
        /// 4 segments and a duplicate ACK arrives, retransmit immediately
        /// because there aren't enough packets in flight to generate the
        /// standard 3 duplicate ACKs needed for fast retransmit.
        /// </remarks>
        public const int EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS = 4; // Runtime: if inflight ≤ 4, retransmit on first dup ACK (RFC 5827 Early Retransmit).

        /// <summary>Tail-loss probe threshold in payload-sized segments.</summary>
        /// <remarks>
        /// 2 segments.  If inflight drops to ≤2 segments after the last
        /// ACK, arm a tail-loss probe timer.  When the timer fires,
        /// retransmit the last unacknowledged packet to provoke an ACK
        /// (which either confirms delivery or reveals more loss).
        /// </remarks>
        public const int TLP_MAX_INFLIGHT_SEGMENTS = 2; // Runtime: if inflight ≤ 2 and no ACK, arm a TLP timer to probe tail loss.

        /// <summary>Tail-loss probe timer ratio relative to the smoothed RTT.</summary>
        /// <remarks>
        /// 1.5 × SRTT.  The TLP fires at 1.5× the smoothed RTT after
        /// the last ACK.  This is long enough to avoid spurious probes
        /// from jitter, short enough to recover tail loss before the RTO.
        /// </remarks>
        public const double TLP_TIMEOUT_RTT_RATIO = 1.5d; // Runtime: TLP timer = 1.5 × SRTT; fires before RTO for tail-loss recovery.

        /// <summary>Duplicate ACK count needed to trigger fast retransmit.</summary>
        /// <remarks>
        /// 3 duplicate ACKs.  Standard TCP behavior.  The first ACK
        /// after a gap is the "hole notification"; the next 3 confirm
        /// the gap is real loss, not reordering.
        /// </remarks>
        public const int DUPLICATE_ACK_THRESHOLD = 3; // Runtime: 3 duplicate ACKs trigger fast retransmit (standard TCP behavior).

        /// <summary>SACK observations needed before a missing hole is retransmitted without waiting for RTO.</summary>
        /// <remarks>
        /// 2 SACK blocks.  Matching QUIC's default SACK threshold.
        /// A missing sequence range must appear in 2 separate SACK blocks
        /// before the sender retransmits.  This filters transient holes
        /// caused by reordering while minimizing recovery latency.
        /// </remarks>
        public const int SACK_FAST_RETRANSMIT_THRESHOLD = 2; // Runtime: hole must appear in 2 SACK blocks before fast retransmit fires.

        /// <summary>Minimum SACK distance past a missing sequence before treating the hole as real loss.</summary>
        /// <remarks>
        /// 48 sequences.  The ACK must have progressed at least 48
        /// sequence numbers beyond the start of the hole.  A gap of
        /// <48 packets could be reordering (packets taking a different
        /// path and arriving slightly out of order).  At 1200 bytes/pkt,
        /// 48 packets = ~57 KB — a reasonable reorder window on WAN paths.
        /// </remarks>
        public const int SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD = 48; // Runtime: ACK must advance 48 seq numbers past hole before fast retransmit.

        /// <summary>Lower bound for SACK-based reorder grace before fast retransmit, in microseconds.
        /// Reduced to 5ms for faster hole recovery on low-latency paths.</summary>
        /// <remarks>
        /// 5 ms.  The gap must have persisted for at least 5 ms before
        /// retransmission.  With 2-block SACK threshold and 5ms grace,
        /// UCP achieves QUIC-comparable recovery latency.
        /// </remarks>
        public const long SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS = 5000L; // Runtime: 5 ms minimum delay before SACK-based fast retransmit fires.

        /// <summary>Missing observation count needed before the receiver sends a NAK.</summary>
        /// <remarks>
        /// 2 observations.  After seeing 2 subsequent packets arrive
        /// past a gap, the receiver considers the missing packet
        /// potentially lost and may send a NAK (subject to reorder grace).
        /// </remarks>
        public const int NAK_MISSING_THRESHOLD = 2; // Runtime: 2 subsequent arrivals beyond a gap → receiver may NAK the missing packet.

        /// <summary>Minimum packet-age delay before receiver NAKs a missing sequence, in microseconds.
        /// Reduced to 2ms for faster loss detection on low-latency paths.</summary>
        /// <remarks>
        /// 2 ms.  A packet must have been missing for at least 2 ms
        /// before the receiver will NAK it.  On modern networks, 2 ms
        /// is sufficient to distinguish reordering from true loss.
        /// </remarks>
        public const long NAK_REORDER_GRACE_MICROS = 2000L; // Runtime: 2 ms minimum delay before standard-confidence NAK is sent.

        /// <summary>Missing observation count that makes a gap high-confidence despite reorder grace.</summary>
        /// <remarks>
        /// 128 subsequent arrivals beyond the gap → near-certain loss.
        /// The probability that 128 packets all reordered around a single
        /// gap is astronomically low.  Use minimal grace (1 ms).
        /// </remarks>
        public const int NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD = 128; // Runtime: ≥128 arrivals past a gap → high-confidence loss; 1 ms grace.

        /// <summary>Minimum packet-age delay for high-confidence missing gaps, in microseconds.</summary>
        public const long NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS = 1000L; // Runtime: 1 ms reorder grace for high-confidence NAK gaps.

        /// <summary>Missing observation count that makes a gap more likely to be real loss than jitter.</summary>
        /// <remarks>
        /// 32 observations → moderate confidence.  There is still a
        /// small chance of reordering, but it's unlikely.  Use 1 ms grace.
        /// </remarks>
        public const int NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD = 32; // Runtime: ≥32 arrivals past a gap → medium-confidence loss; 1 ms grace.

        /// <summary>Minimum packet-age delay for medium-confidence missing gaps, in microseconds.</summary>
        public const long NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS = 1000L; // Runtime: 1 ms reorder grace for medium-confidence NAK gaps.

        /// <summary>Minimum interval before the receiver may re-emit a NAK for the same missing sequence.</summary>
        /// <remarks>
        /// 5 ms between repeated NAKs for the same gap.  Prevents NAK
        /// flooding while still providing timely re-notification if the
        /// sender's retransmission is itself lost.
        /// </remarks>
        public const long NAK_REPEAT_INTERVAL_MICROS = 5000L; // Runtime: min 5 ms between re-NAKs for same gap; prevents NAK flooding.

        /// <summary>Maximum number of sequence slots scanned while building NAK state.</summary>
        /// <remarks>
        /// 16384 slots.  Caps the per-cycle NAK scan to prevent O(n)
        /// behavior on connections with millions of sequences in flight.
        /// At 1200 B/pkt, 16K packets = ~19 MB of data — enough to cover
        /// typical receive windows.
        /// </remarks>
        public const int MAX_NAK_MISSING_SCAN = 16384; // Runtime: per-cycle NAK scan ceiling of 16K slots; prevents unbounded scan time.

        /// <summary>Maximum missing sequences included in one NAK packet.</summary>
        /// <remarks>
        /// 256 entries.  At 4 bytes each = 1024 bytes of missing-sequence
        /// data.  Combined with the fixed NAK header (18 bytes) = 1042
        /// bytes total, safely under the 1220-byte MSS.
        /// </remarks>
        public const int MAX_NAK_SEQUENCES_PER_PACKET = 256; // Runtime: max 256 missing entries/NAK; total packet ≤ 1042 bytes < 1220 MSS.

        /// <summary>Maximum SACK blocks emitted by default (QUIC uses 2).</summary>
        /// <remarks>
        /// 2 blocks.  Matching QUIC's default.  More blocks provide
        /// finer loss reporting but increase ACK packet size.  2 blocks
        /// is sufficient for most loss patterns (one hole being filled
        /// plus one new hole opening).
        /// </remarks>
        public const int DEFAULT_ACK_SACK_BLOCK_LIMIT = 2; // Runtime: each ACK carries at most 2 SACK blocks (QUIC standard).

        /// <summary>Maximum number of times each SACK block range can be sent (QUIC standard: 2).</summary>
        public const int MAX_SACK_SEND_COUNT = 2; // Runtime: SACK ranges are capped at 2 sends; beyond that the information is stale.

        /// <summary>Receive-buffer occupancy that forces an immediate ACK, measured in packets.</summary>
        /// <remarks>
        /// 4 packets.  When 4 reordered packets accumulate in the
        /// receive buffer (waiting for a missing predecessor), send an
        /// immediate ACK to signal the gap to the sender via SACK.
        /// This accelerates fast retransmit on reordering paths.
        /// </remarks>
        public const int IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD = 4; // Runtime: ≥4 reordered packets buffered → send immediate ACK (SACK gap signal).

        /// <summary>Minimum spacing between immediate reordered-data ACKs, in microseconds.</summary>
        /// <remarks>
        /// 250 μs.  Prevents the receiver from sending a flood of
        /// immediate ACKs when many packets arrive out of order in
        /// quick succession (common after WiFi interference clears).
        /// </remarks>
        public const long REORDERED_ACK_MIN_INTERVAL_MICROS = 250L; // Runtime: at least 250 μs between reordered-data immediate ACKs to prevent floods.

        /// <summary>Threshold at which the SACK block send-count dictionary is purged to prevent unbounded growth.</summary>
        /// <remarks>
        /// 1024 entries.  When the dictionary tracking per-SACK-block send
        /// counts exceeds this size, the entire dictionary is cleared.
        /// Stale counts are harmless — this is a simple memory-safety fence.
        /// </remarks>
        public const int SACK_SEND_COUNT_PURGE_THRESHOLD = 1024; // Runtime: clear _sackBlockSendCounts when entry count exceeds 1024.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 9 — CONNECTION MANAGEMENT CONSTANTS
        //
        //  Keep-alive, disconnect timeout, timer granularity, fair-queue
        //  scheduling, and default bandwidth/pacing limits.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Default keep-alive interval in microseconds (1 second).</summary>
        /// <remarks>
        /// 1 s.  If no data has been sent for 1 second, the sender emits
        /// a keep-alive packet to refresh NAT/stateful-firewall bindings
        /// and detect dead peers.  1 second is frequent enough to keep
        /// most NAT bindings alive (typical UDP timeout is 30–120 s).
        /// </remarks>
        public const long KEEP_ALIVE_INTERVAL_MICROS = MICROS_PER_SECOND; // Runtime: 1 s between keep-alive packets; keeps NAT/stateful-firewall bindings alive.

        /// <summary>Default disconnect timeout in microseconds (4 seconds).</summary>
        /// <remarks>
        /// 4 s.  If no packet is received for 4 seconds, the connection
        /// is considered dead.  This is much shorter than TCP's typical
        /// 2+ hour keep-alive timeout, reflecting UCP's use case as a
        /// real-time transport where stale connections should be detected
        /// quickly.
        /// </remarks>
        public const long DISCONNECT_TIMEOUT_MICROS = 4000000L; // Runtime: 4 s without a packet → connection declared dead and torn down.

        /// <summary>Timer tick at 1 ms granularity, inspired by Cloudflare's approach of using
        /// very small scheduling quanta (&lt; typical OS timer slice of ~15 ms) to achieve
        /// μs-level pacing precision at high data rates.  At 10 Gbps with 1200 B packets,
        /// inter-packet spacing is ~0.96 μs — a coarse timer would introduce artificial
        /// gaps or burstiness.  1 ms tick combined with microsecond-precision pacing
        /// tokens allows the sender to smooth bursts without waiting for the next OS
        /// timer interrupt.  See: https://blog.cloudflare.com/how-to-receive-a-million-pa/</summary>
        /// <remarks>
        /// 1 ms.  The main event loop ticks every millisecond.  This is
        /// aggressive compared to typical TCP stacks (which use 10–200 ms
        /// timers), but necessary for accurate pacing at high data rates
        /// and for sub-millisecond delayed-ACK timers.
        /// </remarks>
        public const int TIMER_INTERVAL_MILLISECONDS = 1; // Runtime: event loop runs every 1 ms; enables μs-precision pacing and ACK timers.

        /// <summary>Fair queue scheduling round in milliseconds.</summary>
        /// <remarks>
        /// 10 ms.  Multiple connections to the same destination share
        /// bandwidth via fair queuing, with credits distributed every
        /// 10 ms.  This balances responsiveness (frequent scheduling)
        /// against overhead (scheduling 100×/second per connection).
        /// </remarks>
        public const int FAIR_QUEUE_ROUND_MILLISECONDS = 10; // Runtime: fair-queue credit distribution cycle is 10 ms.

        /// <summary>Default server bandwidth in bytes per second (~100 Mbps).</summary>
        /// <remarks>
        /// 12.5 MB/s.  Conservative default for the server's total
        /// egress capacity.  Individual connections are paced to share
        /// this pool via fair queuing.
        /// </remarks>
        public const int DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND = 100000000 / 8; // Runtime: 12.5 MB/s default server egress cap; shared across connections via fair queuing.

        /// <summary>Default initial bandwidth estimate in bytes per second.</summary>
        /// <remarks>
        /// Starts at the server's configured bandwidth.  UCP will adjust
        /// upward or downward based on measured delivery rates.
        /// </remarks>
        public const int DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND; // Runtime: initial UCP bandwidth estimate equals server bandwidth cap.

        /// <summary>UDP socket send/receive buffer size in bytes to absorb paced UCP bursts.</summary>
        /// <remarks>
        /// 4 MiB.  Large enough to absorb paced UCP bursts before the
        /// receive loop drains them.  Applied to both send and receive
        /// socket buffers via Socket.ReceiveBufferSize/SendBufferSize.
        /// </remarks>
        public const int UDP_SOCKET_BUFFER_BYTES = 4 * 1024 * 1024; // Runtime: 4 MiB socket buffer; absorbs paced UCP bursts before recv loop drain.

        /// <summary>Default maximum pacing rate in bytes per second.</summary>
        /// <remarks>
        /// Initially set to the server bandwidth.  The pacer will not
        /// exceed this rate unless the UCP bandwidth estimate grows
        /// beyond it.
        /// </remarks>
        public const int DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND; // Runtime: max pacing rate starts at server bandwidth; grows with UCP.

        /// <summary>Maximum congestion window in bytes (64 MB).</summary>
        /// <remarks>
        /// 64 MB.  Absolute upper bound on bytes in flight.  At 1200 B/pkt
        /// and 10 Gbps, 64 MB = ~53 ms of data — enough BDP headroom for
        /// all practical paths.  Even trans-Pacific at 10 Gbps (BDP ≈ 125 MB
        /// at 100 ms RTT) doesn't exceed this because UCP targets sub-10 Gbps.
        /// </remarks>
        public const int DEFAULT_MAX_CONGESTION_WINDOW_BYTES = 64 * 1024 * 1024; // Runtime: 64 MB hard cap on bytes in flight for any single connection.

        /// <summary>Default connect timeout in milliseconds.</summary>
        /// <remarks>
        /// 5 s.  The initial SYN/SYN-ACK handshake must complete within
        /// 5 seconds.  This allows for several retransmissions at the
        /// initial RTO (100 ms) with backoff.
        /// </remarks>
        public const int CONNECT_TIMEOUT_MILLISECONDS = 5000; // Runtime: 5 s limit for SYN/SYN-ACK handshake completion; allows ~5 retries with backoff.

        /// <summary>Maximum RTT samples retained in diagnostics.</summary>
        /// <remarks>
        /// 1024 samples.  Ring buffer for RTT diagnostics and logging.
        /// At one sample per RTT on a 10 ms path, this holds ~10 seconds
        /// of history.
        /// </remarks>
        public const int MAX_RTT_SAMPLES = 1024; // Runtime: RTT diagnostic ring buffer holds 1024 samples (~10 s at 10 ms RTT).

        /// <summary>Maximum fair-queue credit retained across rounds.</summary>
        /// <remarks>
        /// 4 rounds.  A connection can accumulate at most 4 rounds of
        /// unused fair-queue credit.  Matches C++ value of 4.
        /// </remarks>
        public const int MAX_BUFFERED_FAIR_QUEUE_ROUNDS = 4; // Runtime: max 4 rounds of saved fair-queue credit; matches C++.

        /// <summary>Minimum wait floor for timer sleeps.  Values below 1 ms would cause
        /// busy-spinning on most OS schedulers.  Combined with the 1 ms timer tick,
        /// this ensures the protocol can maintain sub-millisecond pacing resolution
        /// without consuming excessive CPU on spin-wait.</summary>
        public const int MIN_TIMER_WAIT_MILLISECONDS = 1; // Runtime: 1 ms floor for timer sleep calls; prevents busy-spinning.

        /// <summary>Handshake retry lower bound in milliseconds.</summary>
        /// <remarks>
        /// 100 ms.  The SYN retransmission timer bottoms out at 100 ms,
        /// preventing SYN floods on lossy access links while still
        /// retrying promptly.
        /// </remarks>
        public const int MIN_HANDSHAKE_WAIT_MILLISECONDS = 100; // Runtime: 100 ms minimum between SYN retransmissions.

        /// <summary>Close wait timeout in milliseconds.</summary>
        /// <remarks>
        /// 1 s.  After sending FIN, wait up to 1 second for the final
        /// ACK before forcibly closing.  This matches the TIME_WAIT
        /// concept but is much shorter because UCP uses connection IDs
        /// for demultiplexing, not 4-tuples.
        /// </remarks>
        public const int CLOSE_WAIT_TIMEOUT_MILLISECONDS = 1000; // Runtime: 1 s wait for final FIN-ACK before forced close.

        /// <summary>PAWS (Protection Against Wrapped Sequences) timestamp rejection threshold in microseconds.</summary>
        /// <remarks>
        /// 60 seconds.  Incoming packets with a timestamp more than 60 seconds
        /// behind the largest timestamp seen from this peer are rejected as stale.
        /// At 100 Gbps, 32-bit sequence numbers wrap in ~3 seconds; the 60-second
        /// PAWS window provides a 20× safety margin while still allowing for
        /// extreme clock skew and path delays (e.g. satellite at ~600 ms RTT).
        /// </remarks>
        public const long PAWS_TIMEOUT_MICROS = 60000000L; // Runtime: 60 s PAWS window; stale packets with timestamp delta >60 s are dropped.

        /// <summary>Fallback pacing wait in microseconds when no pacing rate is available.</summary>
        /// <remarks>
        /// 1 ms.  When the pacer has no rate estimate (e.g. right after
        /// connection establishment), it defaults to a 1 ms inter-packet
        /// gap.  This is a safe floor that prevents line-rate bursts
        /// onto unknown paths.
        /// </remarks>
        public const long DEFAULT_PACING_WAIT_MICROS = MICROS_PER_MILLI; // Runtime: 1 ms per-packet gap floor when pacing rate is unknown.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 9b — DPLPMTUD (Datagram PLPMTUD) PATH MTU DISCOVERY
        //
        //  Binary-search-based path MTU discovery that sends padded probe
        //  data packets.  Probes carry ACK blocks and window updates so the
        //  peer benefits from them even if the probe is dropped.  Probing
        //  is triggered by MarkPathChanged() and runs every MTU_PROBE_-
        //  INTERVAL_MICROS until the binary search converges.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Minimum MTU value for DPLPMTUD binary search (IPv6 minimum).</summary>
        public const int MTU_PROBE_BASE = 1200;

        /// <summary>Maximum MTU value for DPLPMTUD binary search (Ethernet frame minus headers).</summary>
        public const int MTU_PROBE_MAX = 1500;

        /// <summary>Interval between successive MTU probe transmissions (10 minutes).</summary>
        public const long MTU_PROBE_INTERVAL_MICROS = 600_000_000L;

        /// <summary>Timeout for an in-flight MTU probe awaiting ACK (10 seconds).</summary>
        public const long MTU_PROBE_TIMEOUT_MICROS = 10_000_000L;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 10 — WIRE-FORMAT TYPE AND FLAG VALUES
        //
        //  These byte values are written directly into the Type and Flags
        //  fields of the common header.  They are defined here (rather
        //  than only in the enum definitions) so that protocol test code,
        //  simulators, and cross-language ports can reference the exact
        //  wire values without depending on C# enum-to-int casting.
        //
        //  Packet type values (1 byte):
        //   0x01 = SYN      — connection request
        //   0x02 = SYN-ACK  — connection acceptance
        //   0x03 = ACK      — cumulative acknowledgment + SACK blocks
        //   0x04 = NAK      — negative acknowledgment (missing sequences)
        //   0x05 = DATA     — application data (with optional piggybacked ACK)
        //   0x06 = FIN      — graceful close request
        //   0x07 = RST      — hard reset (connection refused or error)
        //   0x08 = FEC      — forward error correction repair packet
        //
        //  Flag values (bitmask, 1 byte):
        //   0x01 = NeedAck       — receiver should ACK immediately
        //   0x02 = Retransmit    — this packet is a retransmission
        //   0x04 = FinAck        — FIN has been acknowledged (FIN-ACK)
        //   0x08 = HasAckNumber  — packet carries piggybacked ACK fields
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Encoded UCP data packet type value used by the test simulator.</summary>
        /// <remarks>
        /// 0x05.  The value 5 was chosen to leave room for future
        /// control types (0x01–0x04, 0x06–0x07) while keeping DATA
        /// in the middle of the range.  This is arbitrary but stable.
        /// </remarks>
        public const byte UCP_DATA_TYPE_VALUE = 0x05; // Runtime: data packet wire byte; written into the Type field of every data packet.

        /// <summary>Encoded UCP SYN packet type value.</summary>
        public const byte UCP_SYN_TYPE_VALUE = 0x01; // Runtime: SYN wire byte; marks connection-request packets.

        /// <summary>Encoded UCP SYN-ACK packet type value.</summary>
        public const byte UCP_SYN_ACK_TYPE_VALUE = 0x02; // Runtime: SYN-ACK wire byte; marks connection-acceptance packets.

        /// <summary>Encoded UCP ACK packet type value.</summary>
        public const byte UCP_ACK_TYPE_VALUE = 0x03; // Runtime: ACK wire byte; marks cumulative acknowledgment packets.

        /// <summary>Encoded UCP NAK packet type value.</summary>
        public const byte UCP_NAK_TYPE_VALUE = 0x04; // Runtime: NAK wire byte; marks negative acknowledgment (missing sequence) packets.

        /// <summary>Encoded UCP FIN packet type value.</summary>
        public const byte UCP_FIN_TYPE_VALUE = 0x06; // Runtime: FIN wire byte; marks graceful close request packets.

        /// <summary>Encoded UCP FEC repair packet type value.</summary>
        public const byte UCP_FEC_REPAIR_TYPE_VALUE = 0x08; // Runtime: FEC repair wire byte; marks parity-repair packets.

        /// <summary>Encoded UCP RST packet type value.</summary>
        public const byte UCP_RST_TYPE_VALUE = 0x07; // Runtime: RST wire byte; marks hard-reset connection rejection/error packets.

        /// <summary>Encoded empty flags value.</summary>
        public const byte UCP_FLAGS_NONE_VALUE = 0x00; // Runtime: empty flags byte; no special processing requested.

        /// <summary>Encoded NeedAck packet flag value.</summary>
        /// <remarks>
        /// 0x01 (bit 0).  When set, the receiver should send an ACK
        /// immediately rather than waiting for the delayed-ACK timer.
        /// Used for the last packet in a burst and for handshake packets.
        /// </remarks>
        public const byte UCP_FLAG_NEED_ACK_VALUE = 0x01; // Runtime: bit 0 set → receiver sends immediate ACK (bypass delayed-ACK timer).

        /// <summary>Encoded Retransmit packet flag value.</summary>
        /// <remarks>
        /// 0x02 (bit 1).  Marks a retransmitted packet, enabling the
        /// receiver to avoid ambiguity when measuring RTT (Karn's algorithm)
        /// and to correctly account for retransmission overhead.
        /// </remarks>
        public const byte UCP_FLAG_RETRANSMIT_VALUE = 0x02; // Runtime: bit 1 set → packet is retransmission; RTT not sampled from this (Karn's algo).

        /// <summary>Encoded FinAck packet flag value.</summary>
        /// <remarks>
        /// 0x04 (bit 2).  Indicates that a FIN has been acknowledged.
        /// Used during the connection teardown handshake to distinguish
        /// a FIN-ACK from a regular ACK.
        /// </remarks>
        public const byte UCP_FLAG_FIN_ACK_VALUE = 0x04; // Runtime: bit 2 set → FIN acknowledged; used in connection teardown handshake.

        /// <summary>Encoded HasAckNumber packet flag value.</summary>
        /// <remarks>
        /// 0x08 (bit 3).  When set, the packet carries piggybacked ACK
        /// fields after its type-specific header.  This is the mechanism
        /// that enables bidirectional acknowledgment within a single
        /// wire frame — DATA and CONTROL packets can both carry ACK info
        /// when this flag is set.  Bits are spaced by powers of 2 to
        /// allow independent flag combinations.
        /// </remarks>
        public const byte UCP_FLAG_HAS_ACK_VALUE = 0x08; // Runtime: bit 3 set → packet carries piggybacked ACK; header extended accordingly.

        /// <summary>Encoded MtuProbe packet flag value.</summary>
        /// <remarks>
        /// 0x40 (bit 6).  Marks a data packet as an MTU probe for DPLPMTUD
        /// path MTU discovery.  The receiver acknowledges the probe to
        /// confirm MTU viability but does not deliver the padded payload.
        /// </remarks>
        public const byte UCP_FLAG_MTU_PROBE_VALUE = 0x40; // Runtime: bit 6 set → packet is a DPLPMTUD MTU probe; receiver ACKs but discards payload.

        /// <summary>Bitmask for extracting the 2-bit priority field from packet flags.</summary>
        /// <remarks>
        /// 0x30 (bits 4-5).  The priority field encodes the UcpPriority
        /// of the packet's payload, allowing the receiver to dispatch
        /// high-priority data before lower-priority data and the sender
        /// to reorder segments by priority during transmission.
        /// </remarks>
        public const byte UCP_FLAG_PRIORITY_MASK = 0x30; // Runtime: binary AND with flags byte → extract 2-bit priority field (bits 4–5).

        /// <summary>Encoded PathChallenge packet flag value (used for both challenge and response).</summary>
        /// <remarks>
        /// 0x80 (bit 7).  When set on a DATA packet, the payload contains a random
        /// 8-byte challenge. The receiver echoes back the same flag+payload as a response.
        /// This enables migration security by verifying the new endpoint before accepting it.
        /// </remarks>
        public const byte UCP_FLAG_PATH_CHALLENGE_VALUE = 0x80; // Runtime: bit 7 set → packet carries path challenge/response for migration verification.

        /// <summary>Path challenge timeout in microseconds (2 seconds).</summary>
        public const long PATH_CHALLENGE_TIMEOUT_MICROS = 2_000_000L;

        /// <summary>Path challenge rate-limit interval in microseconds (5 seconds).</summary>
        public const long PATH_CHALLENGE_RATE_LIMIT_MICROS = 5_000_000L;

        /// <summary>Maximum consecutive PATH_CHALLENGE attempts before accepting migration unconditionally.</summary>
        public const int PATH_CHALLENGE_MAX_ATTEMPTS = 3;

        /// <summary>GF(256) generator polynomial for FEC: x^8 + x^4 + x^3 + x^2 + 1.</summary>
        public const int GF256_GENERATOR_POLY = 0x11d; // Runtime: GF(256) modulo polynomial for Reed-Solomon FEC operations.

        /// <summary>Maximum number of FEC send groups retained in memory (16).</summary>
        public const int FEC_MAX_SEND_GROUPS = 16; // Runtime: max 16 outbound FEC sequence-groups retained.

        /// <summary>Maximum number of FEC receive groups retained in memory (16).</summary>
        public const int FEC_MAX_RECV_GROUPS = 16; // Runtime: max 16 inbound FEC data-groups retained.

        /// <summary>Maximum number of FEC repair groups retained in memory (16).</summary>
        public const int FEC_MAX_REPAIR_GROUPS = 16; // Runtime: max 16 orphaned FEC repair-groups retained.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 10b — EVICTION POLICIES FOR UNBOUNDED DICTIONARIES
        //
        //  These caps prevent unbounded memory growth on connections
        //  where ACKs never arrive or gaps never fill (dead connections).
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Max entries in _sackTracking before oldest is evicted.</summary>
        public const int MAX_SACK_TRACKING_ENTRIES = 10000;

        /// <summary>Max entries in _sackFastRetransmitNotified before oldest is evicted.</summary>
        public const int MAX_SACK_NOTIFIED_ENTRIES = 10000;

        /// <summary>Max entries in _missingSequenceCounts / _missingFirstSeenMicros / _lastNakIssuedMicros before oldest is evicted.</summary>
        public const int MAX_MISSING_TRACKING_ENTRIES = 10000;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 11 — COMPUTED CONSTANTS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Maximum ACK SACK blocks that fit inside one MSS-sized ACK packet.</summary>
        /// <remarks>
        /// Computed as (MSS − ACK_FIXED_SIZE) / SACK_BLOCK_SIZE.
        /// At 1220 MSS: (1220 − 28) / 8 = 149 blocks.  In practice,
        /// DEFAULT_ACK_SACK_BLOCK_LIMIT (2) is used, but this computed
        /// maximum prevents buffer overflow if a peer sends more.
        /// </remarks>
        public static readonly int MAX_ACK_SACK_BLOCKS = (MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE; // Runtime: computed max (149 blocks); used as buffer-overflow guard when parsing ACK packets.

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 12 — PASCALCASE PUBLIC ALIASES
        //
        //  These provide a C#-idiomatic public surface for external
        //  consumers that prefer PascalCase over UPPER_SNAKE_CASE.
        //  Each alias maps directly to its snake_case counterpart.
        //  Internal code uses the snake_case originals for consistency
        //  with the C++/Rust ports.
        // ═══════════════════════════════════════════════════════════════════

        public const int Mss = MSS; // Runtime alias: delegates to MSS; identical value at all compile sites.
        public const int CommonHeaderSize = COMMON_HEADER_SIZE; // Runtime alias: delegates to COMMON_HEADER_SIZE.
        public const int DataHeaderSize = DATA_HEADER_SIZE; // Runtime alias: delegates to DATA_HEADER_SIZE.
        public const int AckFixedSize = ACK_FIXED_SIZE; // Runtime alias: delegates to ACK_FIXED_SIZE.
        public const int NakFixedSize = NAK_FIXED_SIZE; // Runtime alias: delegates to NAK_FIXED_SIZE.
        public const int MaxPayloadSize = MAX_PAYLOAD_SIZE; // Runtime alias: delegates to MAX_PAYLOAD_SIZE.
        public const int DefaultReceiveWindowPackets = DEFAULT_RECV_WINDOW_PACKETS; // Runtime alias: delegates to DEFAULT_RECV_WINDOW_PACKETS.
        public const uint DefaultReceiveWindowBytes = DEFAULT_RECV_WINDOW_BYTES; // Runtime alias: delegates to DEFAULT_RECV_WINDOW_BYTES.
        public const int DefaultInitialBandwidthBytesPerSecond = DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND; // Runtime alias: delegates to DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND.
        public const long MinRtoMicros = MIN_RTO_MICROS; // Runtime alias: delegates to MIN_RTO_MICROS.
        public const long MaxRtoMicros = MAX_RTO_MICROS; // Runtime alias: delegates to MAX_RTO_MICROS.
        public const long KeepAliveIntervalMicros = KEEP_ALIVE_INTERVAL_MICROS; // Runtime alias: delegates to KEEP_ALIVE_INTERVAL_MICROS.
        public const long DisconnectTimeoutMicros = DISCONNECT_TIMEOUT_MICROS; // Runtime alias: delegates to DISCONNECT_TIMEOUT_MICROS.
        public const long TimerIntervalMilliseconds = TIMER_INTERVAL_MILLISECONDS; // Runtime alias: delegates to TIMER_INTERVAL_MILLISECONDS.
        public const int FairQueueRoundMilliseconds = FAIR_QUEUE_ROUND_MILLISECONDS; // Runtime alias: delegates to FAIR_QUEUE_ROUND_MILLISECONDS.
        public const int DefaultServerBandwidthBytesPerSecond = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND; // Runtime alias: delegates to DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND.
        public const int ConnectTimeoutMilliseconds = CONNECT_TIMEOUT_MILLISECONDS; // Runtime alias: delegates to CONNECT_TIMEOUT_MILLISECONDS.
        public const int MaxRttSamples = MAX_RTT_SAMPLES; // Runtime alias: delegates to MAX_RTT_SAMPLES.
        public const int MaxBufferedFairQueueRounds = MAX_BUFFERED_FAIR_QUEUE_ROUNDS; // Runtime alias: delegates to MAX_BUFFERED_FAIR_QUEUE_ROUNDS.
        public const int BwRtCycleLen = UCP_BW_RT_CYCLE_LEN; // Runtime alias: delegates to UCP_BW_RT_CYCLE_LEN.
        public const int FullBwCnt = UCP_FULL_BW_CNT; // Runtime alias: delegates to UCP_FULL_BW_CNT.
        public const int ProbeCwndBonus = UCP_PROBE_CWND_BONUS; // Runtime alias: delegates to UCP_PROBE_CWND_BONUS.
        public const int CwndMinTarget = UCP_CWND_MIN_TARGET; // Runtime alias: delegates to UCP_CWND_MIN_TARGET.

        public static readonly int MaxAckSackBlocks = MAX_ACK_SACK_BLOCKS; // Runtime alias: delegates to MAX_ACK_SACK_BLOCKS; same computed max.
    }
}
