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
// │   • BBRv3-style congestion control with mobile/jitter-aware gains        │
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

namespace Ucp
{
    /// <summary>
    /// Central protocol constants kept in one place for future C++ portability.
    /// Time values use microseconds unless the constant name states another unit.
    /// </summary>
    internal static class UcpConstants
    {
        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 1 — TIME UNIT CONVERSIONS
        //
        //  UCP uses microseconds everywhere internally because:
        //    • RTTs on LAN paths are sub-millisecond (need μs precision)
        //    • BBR pacing intervals are often 100–1000 μs
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
        public const long MICROS_PER_MILLI = 1000L;

        /// <summary>Number of microseconds in one second.</summary>
        /// <remarks>
        /// Standard SI conversion.  Used as the denominator when
        /// converting from bytes-per-second pacing rates to
        /// bytes-per-microsecond inter-packet gaps.
        /// </remarks>
        public const long MICROS_PER_SECOND = 1000000L;

        /// <summary>Number of nanoseconds in one microsecond.</summary>
        /// <remarks>
        /// Standard SI conversion.  Used to bridge between .NET
        /// <see cref="System.Diagnostics.Stopwatch"/> (which returns
        /// nanoseconds on most platforms) and UCP's microsecond domain.
        /// </remarks>
        public const long NANOS_PER_MICRO = 1000L;

        /// <summary>Number of bits in one byte, used for Mbps presentation.</summary>
        /// <remarks>
        /// Used when converting byte-rate throughput to user-facing
        /// megabits-per-second (Mbps) metrics.  Stored as double to
        /// avoid integer truncation in division-heavy UI code.
        /// </remarks>
        public const double BITS_PER_BYTE = 8d;

        /// <summary>Number of bits per second in one megabit per second.</summary>
        /// <remarks>
        /// Networking convention uses decimal mega (10^6), not binary
        /// (2^20).  This matches how ISPs and link layers report bandwidth,
        /// so the user sees consistent numbers.
        /// </remarks>
        public const double BITS_PER_MEGABIT = 1000000d;

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
        public const int MSS = 1220;

        /// <summary>Common packet header size in bytes (Type + Flags + ConnectionId + Timestamp).</summary>
        /// <remarks>
        /// 1 byte Type + 1 byte Flags + 4 byte ConnectionId + 6 byte Timestamp = 12 bytes.
        /// The timestamp uses 48 bits (6 bytes) — sufficient range for
        /// ~8,925 years of microsecond ticks, eliminating year-2038 concerns.
        /// </remarks>
        public const int COMMON_HEADER_SIZE = 12;

        /// <summary>Minimum Data packet-specific header size in bytes (without piggybacked ACK).</summary>
        /// <remarks>
        /// Common header (12) + SequenceNumber (4) + FragmentTotal (2) + FragmentIndex (2) = 20 bytes.
        /// FragmentTotal/FragmentIndex support message fragmentation for payloads
        /// exceeding the per-packet data budget.
        /// </remarks>
        public const int DATA_HEADER_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(ushort);

        /// <summary>Data packet header size when piggybacked ACK (HasAckNumber flag) is present, in bytes (excludes variable SACK blocks).</summary>
        /// <remarks>
        /// Base data header (20) + AckNumber (4) + SackBlockCount (2) + WindowSize (4) + EchoTimestamp (6) = 36 bytes.
        /// Piggybacked ACKs save a round-trip by acknowledging the reverse
        /// direction within the same wire frame as forward data.  The sender
        /// sets the HasAckNumber flag in the common header to signal that the
        /// extended header format is in use.
        /// </remarks>
        public const int DATA_HEADER_SIZE_WITH_ACK = DATA_HEADER_SIZE + ACK_NUMBER_SIZE + sizeof(ushort) + sizeof(uint) + ACK_TIMESTAMP_FIELD_SIZE;

        /// <summary>Fixed ACK packet size in bytes before variable SACK blocks.</summary>
        /// <remarks>
        /// Common header (12) + AckNumber (4) + SackBlockCount (2) + WindowSize (4) + EchoTimestamp (6) = 28 bytes.
        /// The echo timestamp is the sender's original timestamp reflected
        /// back by the receiver, enabling one-sided RTT measurement without
        /// per-packet state at the sender.
        /// </remarks>
        public const int ACK_FIXED_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(uint) + ACK_TIMESTAMP_FIELD_SIZE;

        /// <summary>Fixed NAK packet size in bytes before variable missing sequence entries (includes AckNumber).</summary>
        /// <remarks>
        /// Common header (12) + AckNumber (4) + MissingCount (2) = 18 bytes.
        /// NAKs carry an AckNumber (the last contiguous sequence received)
        /// followed by a list of explicitly missing sequence numbers.
        /// </remarks>
        public const int NAK_FIXED_SIZE = COMMON_HEADER_SIZE + ACK_NUMBER_SIZE + sizeof(ushort);

        /// <summary>Maximum data payload size in one packet, in bytes.</summary>
        /// <remarks>
        /// MSS (1220) − DATA_HEADER_SIZE (20) = 1200 bytes.
        /// This is the per-packet application-data budget.  Larger messages
        /// must be fragmented across multiple packets using FragmentTotal
        /// and FragmentIndex.
        /// </remarks>
        public const int MAX_PAYLOAD_SIZE = MSS - DATA_HEADER_SIZE;

        /// <summary>Encoded SACK block size in bytes (2 × uint32).</summary>
        /// <remarks>
        /// Each SACK block encodes a [start, end) range of acknowledged
        /// sequence numbers, matching QUIC's SACK frame encoding.
        /// 4 bytes start + 4 bytes end = 8 bytes per block.
        /// </remarks>
        public const int SACK_BLOCK_SIZE = sizeof(uint) + sizeof(uint);

        /// <summary>Encoded sequence number size in bytes (uint32).</summary>
        /// <remarks>
        /// 32-bit sequence numbers provide 4 billion packets of range.
        /// At 1200 bytes/packet and 10 Gbps, that is ~3,840 seconds
        /// before wrap-around — well above any practical connection
        /// lifetime at those rates.
        /// </remarks>
        public const int SEQUENCE_NUMBER_SIZE = sizeof(uint);

        /// <summary>Encoded ACK number field size in bytes (uint32).</summary>
        public const int ACK_NUMBER_SIZE = sizeof(uint);

        /// <summary>Encoded connection identifier size in bytes (uint32).</summary>
        /// <remarks>
        /// 32-bit connection IDs support up to ~4 billion simultaneous
        /// connections per endpoint pair, far exceeding any practical
        /// deployment.
        /// </remarks>
        public const int CONNECTION_ID_SIZE = sizeof(uint);

        /// <summary>ACK timestamp field size in bytes (uint48).</summary>
        /// <remarks>
        /// 48 bits = 6 bytes.  Microsecond timestamps fit in 48 bits for
        /// ~8,925 years.  Using 6 bytes instead of 8 saves 2 bytes per
        /// ACK packet without sacrificing range.
        /// </remarks>
        public const int ACK_TIMESTAMP_FIELD_SIZE = 6;

        /// <summary>Encoded packet type field size in bytes.</summary>
        public const int PACKET_TYPE_FIELD_SIZE = sizeof(byte);

        /// <summary>Encoded packet flags field size in bytes.</summary>
        public const int PACKET_FLAGS_FIELD_SIZE = sizeof(byte);

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 2b — BIT COUNTS FOR SERIALIZATION
        //
        //  Named shift constants used by the big-endian Read/Write helpers
        //  in UcpPacketCodec.cs.  Named constants prevent magic-number bugs
        //  and make the shift arithmetic self-documenting.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Bit count in a 16-bit integer.</summary>
        public const int UINT16_BITS = 16;

        /// <summary>Bit count in a 24-bit field.</summary>
        /// <remarks>
        /// 24-bit shifts are used for the third byte of uint32 and uint48
        /// serialization (byte at offset 2 in big-endian: bits [23:16]).
        /// </remarks>
        public const int UINT24_BITS = 24;

        /// <summary>Bit count in a 32-bit field.</summary>
        public const int UINT32_BITS = 32;

        /// <summary>Bit count in a 40-bit field.</summary>
        /// <remarks>
        /// 40-bit shifts are used for the most-significant byte of uint48
        /// serialization (byte at offset 0 in big-endian: bits [47:40]).
        /// </remarks>
        public const int UINT40_BITS = 40;

        /// <summary>Bit count in one byte.</summary>
        public const int BYTE_BITS = 8;

        /// <summary>Mask used to keep only the low 48 bits of an ACK timestamp.</summary>
        /// <remarks>
        /// Applied when writing a C# Int64 into a 6-byte uint48 field.
        /// Discards bits [63:48] so they don't leak into adjacent fields.
        /// 0x0000FFFFFFFFFFFF = 2^48 − 1.
        /// </remarks>
        public const ulong UINT48_MASK = 0x0000FFFFFFFFFFFFUL;

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
        public const int DEFAULT_RECV_WINDOW_PACKETS = 4096;

        /// <summary>Default receive window size measured in bytes.</summary>
        public const uint DEFAULT_RECV_WINDOW_BYTES = (uint)(DEFAULT_RECV_WINDOW_PACKETS * MSS);

        /// <summary>Initial congestion window packet count used by the optimized default configuration.</summary>
        /// <remarks>
        /// 20 packets (~24 KB) initial window.  More aggressive than TCP's
        /// IW10, but safe because BBR's pacing prevents line-rate bursts.
        /// These 20 packets are spread over one RTT by the pacer, so the
        /// instantaneous burst is never more than a few packets.
        /// </remarks>
        public const int INITIAL_CWND_PACKETS = 20;

        /// <summary>Legacy initial congestion window in bytes retained for old tests and callers.</summary>
        /// <remarks>
        /// 4 × 1220 = 4880 bytes (~4 packets).  Conservative value used
        /// by older test harnesses and provides a backward-compatible
        /// floor that no configuration should drop below.
        /// </remarks>
        public const int DEFAULT_INITIAL_CONGESTION_WINDOW = 4 * MSS;

        /// <summary>Default send buffer capacity in bytes.</summary>
        /// <remarks>
        /// 32 MB send buffer.  Large enough for 10 Gbps at typical WAN
        /// RTTs without blocking the application.  The send buffer absorbs
        /// application writes while the congestion controller drains them
        /// at the pacing rate.
        /// </remarks>
        public const int DEFAULT_SEND_BUFFER_BYTES = 32 * 1024 * 1024;

        /// <summary>Default delayed ACK timeout in microseconds.</summary>
        /// <remarks>
        /// 100 μs.  UCP piggybacks ACKs on data packets, eliminating standalone
        /// ACK overhead.  Delayed ACKs only fire when no outbound data is available.
        /// 100 μs is sufficient for sub-RTT batching without inflating RTT.
        /// </remarks>
        public const long DEFAULT_DELAYED_ACK_TIMEOUT_MICROS = 100L;

        /// <summary>Default maximum tolerated bandwidth waste ratio, where 0.25 means 25%.</summary>
        /// <remarks>
        /// 25% overhead ceiling.  Retransmissions consume bandwidth, and
        /// this ratio caps how much of the link capacity may be "wasted"
        /// before the sender backs off.  25% matches empirical observations
        /// on lossy 4G/5G mobile paths (1–5% random loss generates ~20–25%
        /// retransmit overhead with efficient SACK-based recovery).
        /// </remarks>
        public const double DEFAULT_MAX_BANDWIDTH_WASTE_RATIO = 0.25d;

        /// <summary>Default maximum tolerated bandwidth loss percentage exposed to users.</summary>
        public const double DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT = 25d;

        /// <summary>Minimum allowed configured bandwidth loss percentage.</summary>
        /// <remarks>
        /// 15% floor.  Below this, the sender would throttle too
        /// aggressively on paths with routine random loss (Wi-Fi, 4G).
        /// </remarks>
        public const double MIN_MAX_BANDWIDTH_LOSS_PERCENT = 15d;

        /// <summary>Maximum allowed configured bandwidth loss percentage.</summary>
        /// <remarks>
        /// 35% ceiling.  Above this, the sender would tolerate loss
        /// rates where throughput collapses regardless.
        /// </remarks>
        public const double MAX_MAX_BANDWIDTH_LOSS_PERCENT = 35d;

        /// <summary>Default minimum pacing interval in microseconds.</summary>
        /// <remarks>
        /// 0 μs = no artificial inter-packet gap floor.  When the pacing
        /// rate is very high (e.g. 10 Gbps), the computed gap can be
        /// sub-microsecond.  Forcing a minimum would cap throughput below
        /// line rate on fast links.
        /// </remarks>
        public const long DEFAULT_MIN_PACING_INTERVAL_MICROS = 0L;

        /// <summary>Default pacing token bucket duration in microseconds.</summary>
        /// <remarks>
        /// 10,000 μs = 10 ms.  The token bucket refills over a 10 ms window.
        /// This is long enough to smooth bursts at typical WAN rates but short
        /// enough that the bucket doesn't allow seconds-long bursts that
        /// overwhelm shallow router buffers.
        /// </remarks>
        public const long DEFAULT_PACING_BUCKET_DURATION_MICROS = 10000L;

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

        /// <summary>Minimum RTO accepted by configuration validation, in microseconds.</summary>
        /// <remarks>
        /// 20 ms.  TCP's minimum RTO is typically 200 ms, but UCP can
        /// safely use 20 ms because NAK-based loss detection recovers
        /// most packets in <5 ms.  The RTO is only a last resort when
        /// both SACK and NAK fail.
        /// </remarks>
        public const long MIN_RTO_MICROS = 20000L;

        /// <summary>Default optimized minimum RTO, in microseconds.</summary>
        /// <remarks>
        /// 50 ms.  Long enough to ride through transient WiFi/4G jitter
        /// bursts without spurious retransmits, short enough that a true
        /// tail loss is recovered quickly.
        /// </remarks>
        public const long DEFAULT_RTO_MICROS = 50000L;

        /// <summary>Initial RTO used before a measured RTT is available, in microseconds.</summary>
        /// <remarks>
        /// 100 ms.  Conservative initial value before the first RTT
        /// sample arrives.  100 ms covers most WAN paths (including
        /// trans-Pacific at ~80 ms), so the initial handshake won't
        /// timeout prematurely.
        /// </remarks>
        public const long INITIAL_RTO_MICROS = 100000L;

        /// <summary>Maximum RTO accepted by the optimized default configuration, in microseconds.</summary>
        /// <remarks>
        /// 15 s.  Above this, the connection is likely dead rather than
        /// just delayed.  Most paths recover or fail within this window.
        /// </remarks>
        public const long DEFAULT_MAX_RTO_MICROS = 15000000L;

        /// <summary>Absolute fallback maximum RTO, in microseconds.</summary>
        /// <remarks>
        /// 60 s.  Catch-all for extreme satellite links (GEO at ~600 ms
        /// RTT with deep buffering).  After 60 seconds without progress,
        /// the connection is declared dead unconditionally.
        /// </remarks>
        public const long MAX_RTO_MICROS = 60000000L;

        /// <summary>Default RTO backoff multiplier.</summary>
        /// <remarks>
        /// 1.2× per timeout, not TCP's 2.0×.  UCP's gentler backoff avoids
        /// multi-second stalls on paths with occasional loss bursts.
        /// NAK-based recovery handles most losses, so the RTO fires only
        /// when the path is genuinely unresponsive, making aggressive
        /// backoff counterproductive.
        /// </remarks>
        public const double RTO_BACKOFF_FACTOR = 1.2d;

        /// <summary>Maximum retransmission attempts per outbound segment.</summary>
        /// <remarks>
        /// 10 attempts.  After 10 consecutive RTO timeouts (roughly
        /// 10 × 100 ms × 1.2^n, ~2–3 seconds total), the connection
        /// is torn down.
        /// </remarks>
        public const int MAX_RETRANSMISSIONS = 10;

        /// <summary>Maximum timeout retransmits armed by one timer tick.</summary>
        /// <remarks>
        /// 4 segments per tick.  Prevents a single timer tick from
        /// dumping hundreds of retransmissions onto the wire after a
        /// long outage.  Spreads the retransmit load across multiple
        /// ticks to avoid self-inflicted congestion.
        /// </remarks>
        public const int RTO_RETRANSMIT_BUDGET_PER_TICK = 4;

        /// <summary>ACK-progress window in which bulk RTO retransmission is suppressed.</summary>
        /// <remarks>
        /// 2 ms.  If an ACK arrived within the last 2 ms, the sender is
        /// still making forward progress.  Suppress bulk RTO in this
        /// window to avoid redundant retransmissions that waste bandwidth.
        /// </remarks>
        public const long RTO_ACK_PROGRESS_SUPPRESSION_MICROS = 2 * MICROS_PER_MILLI;

        /// <summary>Maximum urgent retransmits allowed to bypass pacing in one RTT window.</summary>
        /// <remarks>
        /// 8192 segments per RTT.  Urgent retransmits (tail-loss probes,
        /// fast-retransmit triggers) bypass the pacer to minimize latency.
        /// The budget prevents an unbounded urgent flood on very lossy
        /// paths while still covering high-BDP tail-loss scenarios.
        /// </remarks>
        public const int URGENT_RETRANSMIT_BUDGET_PER_RTT = 8192;

        /// <summary>Idle-time percentage after which a tail-loss probe may be urgent.</summary>
        /// <remarks>
        /// 75%.  If the sender has been idle for >75% of an RTT, the next
        /// transmission may be treated as urgent (bypass pacing).  This
        /// prevents the pacer from adding unnecessary latency when the
        /// application produces data after a quiet period.
        /// </remarks>
        public const int URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT = 75;

        /// <summary>RTT variance EWMA denominator for RFC6298-style smoothing.</summary>
        /// <remarks>
        /// β = 1/4, the standard RFC 6298 value.  RTTVAR reacts to 25%
        /// of each new deviation sample, providing a balance between
        /// responsiveness and stability.
        /// </remarks>
        public const int RTT_VAR_DENOM = 4;

        /// <summary>RTT sample weight denominator for smoothed RTT EWMA.</summary>
        /// <remarks>
        /// α = 1/8, the standard RFC 6298 value.  SRTT incorporates 12.5%
        /// of each new RTT sample, giving stable estimates on paths with
        /// moderate jitter.
        /// </remarks>
        public const int RTT_SMOOTHING_DENOM = 8;

        /// <summary>Previous smoothed RTT numerator when using a 1/8 sample weight.</summary>
        /// <remarks>
        /// 7/8 weight on the previous SRTT value.  (1 − α) = 7/8.
        /// </remarks>
        public const int RTT_SMOOTHING_PREVIOUS_WEIGHT = RTT_SMOOTHING_DENOM - 1;

        /// <summary>Previous RTT variance numerator when using a 1/4 sample weight.</summary>
        /// <remarks>
        /// 3/4 weight on the previous RTTVAR value.  (1 − β) = 3/4.
        /// </remarks>
        public const int RTT_VAR_PREVIOUS_WEIGHT = RTT_VAR_DENOM - 1;

        /// <summary>RTT variance multiplier used when calculating RTO (SRTT + 2*RTTVAR for tighter recovery).</summary>
        /// <remarks>
        /// K = 4.  RTO = SRTT + 4 × RTTVAR.  RFC 6298 specifies K=4,
        /// which gives tighter RTO than earlier RFCs that used K=2 or K=4
        /// piecewise.  UCP keeps K=4 always, trusting NAK to catch what
        /// the slightly looser RTO might miss.
        /// </remarks>
        public const int RTO_GAIN_MULTIPLIER = 4;

        /// <summary>Maximum accepted RTT sample multiplier relative to the current RTO during recovery.</summary>
        /// <remarks>
        /// 4.0×.  During loss recovery, RTT samples can spike due to
        /// retransmission ambiguity.  Samples exceeding 4× the current
        /// RTO are discarded as likely measuring a retransmitted packet
        /// rather than a genuine RTT (Karn's algorithm).
        /// </remarks>
        public const double RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER = 4.0d;

        /// <summary>Maximum backoff multiple relative to the minimum RTO.</summary>
        /// <remarks>
        /// The backed-off RTO is capped at 2 × MIN_RTO_MICROS.  This
        /// prevents RTO from collapsing to near-zero on very stable
        /// paths (where SRTT is tiny) and then spiking to unreasonable
        /// values after a single loss event.
        /// </remarks>
        public const int RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER = 2;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 5 — BBR CONGESTION CONTROL
        //
        //  BBRv3-style congestion control parameters.  BBR models the path
        //  as a pipe with a bottleneck bandwidth (BtlBw) and round-trip
        //  propagation delay (RTprop).  It paces at the estimated BtlBw
        //  and caps inflight at BDP × gain.
        //
        //  State machine:
        //    Startup  → Drain  → ProbeBW  ↔ ProbeRTT
        //
        //  Key differences from IETF BBRv3:
        //   • Mobile/jitter-aware gain tiers (light / moderate / heavy loss)
        //   • Aggressive startup pacing (2.5×, not IETF's 2.89×)
        //   • Congestion classifier with composite scoring
        //     (rate drop + RTT growth + loss observation)
        //   • Non-congestion loss detection (random loss ≠ queue overflow)
        //   • Random-loss CWND cushion for lossy non-congested paths
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>BBR bandwidth filter window length measured in RTT rounds.</summary>
        /// <remarks>
        /// 10 RTT rounds.  BBR maintains a max-filter over the last 10
        /// delivery-rate samples.  Ten rounds gives enough statistical
        /// mass to find the true bottleneck rate without holding stale
        /// estimates after a path capacity drop.
        /// </remarks>
        public const int BBR_WINDOW_RTT_ROUNDS = 10;

        /// <summary>Number of BBR delivery-rate samples retained for bandwidth estimation.</summary>
        /// <remarks>
        /// Same as the filter window — one sample per RTT round over the
        /// 10-round window.  Windowed max-filter provides the BtlBw estimate.
        /// </remarks>
        public const int BBR_RECENT_RATE_SAMPLE_COUNT = 10;

        /// <summary>BBR ProbeBW cycle length in gain phases.</summary>
        /// <remarks>
        /// 8 phases: [1.35, 0.85, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0].
        /// The 1.35× phase probes for more bandwidth; the 0.85× phase
        /// drains any standing queue; the six 1.0× phases cruise at the
        /// estimated rate.  This matches the original BBRv2 cycle.
        /// </remarks>
        public const int BBR_PROBE_BW_GAIN_COUNT = 8;

        /// <summary>BBR startup requires this many rounds without sufficient bandwidth growth before draining.</summary>
        /// <remarks>
        /// 3 rounds.  Startup must see 3 consecutive rounds where the
        /// bandwidth growth is below BBR_STARTUP_GROWTH_TARGET (25%)
        /// before exiting to Drain.  Prevents premature exit on bursty
        /// paths where a single round happens to have low growth.
        /// </remarks>
        public const int BBR_MIN_STARTUP_FULL_BANDWIDTH_ROUNDS = 3;

        /// <summary>BBR startup full-bandwidth growth target (25% growth per round).</summary>
        /// <remarks>
        /// 1.25×.  If the latest bandwidth sample is ≥1.25× the previous
        /// max, startup considers bandwidth still growing and stays in
        /// the Startup phase.  Below this threshold for 3 consecutive
        /// rounds triggers the Drain transition.
        /// </remarks>
        public const double BBR_STARTUP_GROWTH_TARGET = 1.25d;

        /// <summary>BBR startup pacing gain (2.5x).</summary>
        /// <remarks>
        /// During Startup, the sender paces at 2.5× the estimated bandwidth
        /// to rapidly fill the pipe and discover the bottleneck rate.
        /// IETF BBR uses 2.89 (2/ln2), but 2.5× avoids excessive queue
        /// buildup on shallow-buffered paths (common on mobile/WiFi)
        /// while still converging to line rate in ~10 RTTs.
        /// </remarks>
        public const double BBR_STARTUP_PACING_GAIN = 2.5d;

        /// <summary>BBR startup congestion window gain (2.0x).</summary>
        /// <remarks>
        /// Inflight cap = 2.0 × BDP during Startup.  Doubling the CWND
        /// relative to BDP provides enough headroom for the pacing gain
        /// to take effect without the inflight cap being the bottleneck.
        /// </remarks>
        public const double BBR_STARTUP_CWND_GAIN = 2.0d;

        /// <summary>BBR drain pacing gain (1.0x, drain the inflated queue).</summary>
        /// <remarks>
        /// After Startup, Drain paces at exactly the estimated bandwidth
        /// (1.0× gain) until inflight drops to BDP.  This drains the
        /// standing queue that Startup created, allowing a clean RTprop
        /// measurement for ProbeBW.
        /// </remarks>
        public const double BBR_DRAIN_PACING_GAIN = 1.0d;

        /// <summary>BBR high probing pacing gain (1.35x).</summary>
        /// <remarks>
        /// One phase per 8-phase ProbeBW cycle sends 35% above the
        /// estimated bandwidth to probe for newly available capacity.
        /// This is the standard BBR "up-probe" gain.
        /// </remarks>
        public const double BBR_PROBE_BW_HIGH_GAIN = 1.35d;

        /// <summary>BBR low probing pacing gain (0.85x).</summary>
        /// <remarks>
        /// One phase per cycle sends 15% below the estimated bandwidth
        /// to drain any queue that accumulated during the high-gain phase.
        /// This is the standard BBR "down-probe" gain.
        /// </remarks>
        public const double BBR_PROBE_BW_LOW_GAIN = 0.85d;

        /// <summary>BBR ProbeBW congestion window gain (2.0x).</summary>
        /// <remarks>
        /// During ProbeBW, the inflight cap is 2.0 × BDP.  This matches
        /// the Startup CWND gain, providing consistent headroom across
        /// phases.  The pacer (not the CWND) is the primary rate control.
        /// </remarks>
        public const double BBR_PROBE_BW_CWND_GAIN = 2.0d;

        /// <summary>BBR ProbeRTT pacing gain used to avoid a full throughput cliff (0.85x).</summary>
        /// <remarks>
        /// During ProbeRTT, the sender paces at 85% of estimated bandwidth
        /// rather than dropping to zero.  This prevents a complete
        /// throughput stall on paths where ProbeRTT is required frequently
        /// (e.g. rapidly changing mobile paths).  85% still drains queues
        /// effectively while maintaining some forward progress.
        /// </remarks>
        public const double BBR_PROBE_RTT_PACING_GAIN = 0.85d;

        /// <summary>BBR ProbeRTT interval in microseconds (30s).</summary>
        /// <remarks>
        /// 30 seconds.  BBR enters ProbeRTT at most once every 30 seconds.
        /// This matches QUIC's ProbeRTT interval and is long enough that
        /// the throughput impact of the brief drain period amortizes to
        /// <1% throughput reduction.
        /// </remarks>
        public const long BBR_PROBE_RTT_INTERVAL_MICROS = 30000000L;

        /// <summary>BBR ProbeRTT minimum duration in microseconds.</summary>
        /// <remarks>
        /// 100 ms.  ProbeRTT stays active for at least 100 ms to ensure
        /// at least one clean RTT sample is collected.  On sub-ms paths
        /// this is far more than one RTT, but avoids timer-granularity
        /// artifacts.
        /// </remarks>
        public const long BBR_PROBE_RTT_DURATION_MICROS = 100000L;

        /// <summary>Maximum ProbeRTT duration multiplier used as a safety valve.</summary>
        /// <remarks>
        /// ProbeRTT exits after 2 × current-RTT at most, even if the
        /// minimum RTT hasn't been refreshed.  This prevents ProbeRTT
        /// from persisting indefinitely on paths with steadily growing
        /// RTT (e.g. cellular congestion).
        /// </remarks>
        public const int BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER = 2;

        /// <summary>BBR minimum RTT freshness multiplier used for early ProbeRTT exit (5% margin).</summary>
        /// <remarks>
        /// 1.05×.  If the latest RTT sample is within 5% of the known
        /// minimum, the queue is considered drained and ProbeRTT exits
        /// early. This prevents ProbeRTT from overstaying when the path
        /// is already empty.
        /// </remarks>
        public const double BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER = 1.05d;

        /// <summary>BBR RTT increase threshold for unconstrained high-gain probing.</summary>
        /// <remarks>
        /// 10%.  If RTT has increased less than 10% from its minimum,
        /// the path is considered uncongested and high-gain probing
        /// (1.35×) is allowed without restrictions.  This is the
        /// "green zone" for aggressive capacity seeking.
        /// </remarks>
        public const double BBR_LOW_RTT_INCREASE_RATIO = 0.10d;

        /// <summary>BBR RTT increase threshold for moderate probing.</summary>
        /// <remarks>
        /// 20%.  If RTT has increased between 10% and 20%, moderate
        /// probing (1.50× under low loss) is allowed.  Above 20%,
        /// probing is restricted to avoid pushing an already-loaded
        /// queue into loss.
        /// </remarks>
        public const double BBR_MODERATE_RTT_INCREASE_RATIO = 0.20d;

        /// <summary>Recent loss ratio below which high-gain probing remains enabled.</summary>
        /// <remarks>
        /// 1%.  Loss below 1% is considered background noise (WiFi
        /// collisions, radio interference).  High-gain probing
        /// continues unimpeded.
        /// </remarks>
        public const double BBR_LOW_LOSS_RATIO = 0.01d;

        /// <summary>Recent loss ratio below which moderate probing is enabled.</summary>
        /// <remarks>
        /// 3%.  Loss between 1% and 3% permits moderate probing gain
        /// (useful for mobile paths with routine low-level loss).
        /// </remarks>
        public const double BBR_MODERATE_LOSS_RATIO = 0.03d;

        /// <summary>Recent loss ratio below which pacing is kept close to target.</summary>
        /// <remarks>
        /// 8%.  Loss below 8% → light pacing gain (1.10×).  The path
        /// is lossy but not congested; a modest gain keeps throughput
        /// close to the estimate without overdriving the loss rate.
        /// </remarks>
        public const double BBR_LIGHT_LOSS_RATIO = 0.08d;

        /// <summary>Recent loss ratio below which pacing is gently reduced.</summary>
        /// <remarks>
        /// 15%.  Loss between 8% and 15% → medium pacing gain (1.05×).
        /// Above 15% → high-loss pacing (1.00×, no gain).
        /// </remarks>
        public const double BBR_MEDIUM_LOSS_RATIO = 0.15d;

        /// <summary>BBR moderate probing gain used under low loss (1.45x for aggressive mobile probing).</summary>
        /// <remarks>
        /// 1.50×.  When loss is low (<1%) but RTT has grown moderately
        /// (10–20%), probe at 1.50× to aggressively recover bandwidth
        /// on mobile paths where RTT inflation is often transient.
        /// This is higher than the standard high-gain (1.35×) because
        /// the RTT headroom exists to absorb the extra flight.
        /// </remarks>
        public const double BBR_MODERATE_PROBE_GAIN = 1.50d;

        /// <summary>BBR target-maintaining gain under light loss (1.10x).</summary>
        /// <remarks>
        /// 1.10×.  Light loss means the path is lossy but not congested.
        /// A small gain compensates for the throughput lost to
        /// retransmissions without increasing the loss rate.
        /// </remarks>
        public const double BBR_LIGHT_LOSS_PACING_GAIN = 1.10d;

        /// <summary>BBR gentle pacing gain under medium loss (1.05x).</summary>
        /// <remarks>
        /// 1.05×.  At medium loss (8–15%), only a minimal gain is
        /// applied — just enough to offset retransmission overhead
        /// without risking a loss-rate spiral.
        /// </remarks>
        public const double BBR_MEDIUM_LOSS_PACING_GAIN = 1.05d;

        /// <summary>BBR severe loss pacing gain (1.00x = no pacing inflation).</summary>
        /// <remarks>
        /// 1.00×.  At high loss (>15%), the pacer sends at exactly the
        /// estimated bandwidth with no gain.  Any inflation would be
        /// self-defeating — the path is already dropping packets; adding
        /// more packets just increases the loss count.
        /// </remarks>
        public const double BBR_HIGH_LOSS_PACING_GAIN = 1.00d;

        /// <summary>BBR fast recovery pacing gain used after non-congestion loss recovery signals.</summary>
        /// <remarks>
        /// 1.25×.  After recovering from a non-congestion loss event
        /// (e.g. WiFi interference burst), temporarily pace at 1.25× to
        /// quickly restore throughput to the pre-loss level.
        /// </remarks>
        public const double BBR_FAST_RECOVERY_PACING_GAIN = 1.25d;

        /// <summary>Minimum BBR pacing gain after a congestion loss signal.</summary>
        /// <remarks>
        /// 0.92×.  When the classifier confirms congestion, the pacing
        /// rate is multiplied by at least 0.92 (8% reduction).  Combined
        /// with CONGESTION_LOSS_REDUCTION (0.98), the effective reduction
        /// is 0.92 × 0.98 ≈ 0.90.
        /// </remarks>
        public const double BBR_MIN_CONGESTION_PACING_GAIN = 0.92d;

        /// <summary>Multiplicative BBR reduction applied on a congestion loss signal (98%).</summary>
        /// <remarks>
        /// 0.98×.  On confirmed congestion, multiply the pacing rate by
        /// 0.98 (2% reduction).  This is gentler than TCP's 0.5× halving
        /// because (a) the classifier is confident it's truly congestion,
        /// not random loss, and (b) BBR targets the optimal operating
        /// point near BDP, so small adjustments suffice.
        /// </remarks>
        public const double BBR_CONGESTION_LOSS_REDUCTION = 0.98d;

        /// <summary>Minimum congestion window gain retained after congestion loss.</summary>
        /// <remarks>
        /// 0.95×.  The CWND gain floor after a congestion event.
        /// Prevents the CWND from collapsing below 0.95× BDP, which
        /// would underutilize the path.
        /// </remarks>
        public const double BBR_MIN_LOSS_CWND_GAIN = 0.95d;

        /// <summary>Congestion window gain recovery step per ACK (standard).</summary>
        /// <remarks>
        /// 0.08 per ACK.  After a congestion reduction, the CWND gain
        /// recovers by 0.08 per ACK (toward its target of 2.0×).  This
        /// provides a gradual ramp back to full throughput over ~12 ACKs.
        /// </remarks>
        public const double BBR_LOSS_CWND_RECOVERY_STEP = 0.08d;

        /// <summary>Congestion window gain recovery step per ACK (accelerated for mobile/outage).</summary>
        /// <remarks>
        /// 0.15 per ACK.  On mobile paths where loss is typically
        /// transient (outage, not congestion), recover CWND gain faster
        /// (~7 ACKs to full) to restore throughput promptly after the
        /// outage ends.
        /// </remarks>
        public const double BBR_LOSS_CWND_RECOVERY_STEP_FAST = 0.15d;

        /// <summary>Loss budget headroom below which probing may become more aggressive again.</summary>
        /// <remarks>
        /// 80%.  When the loss budget is used at ≤80% of its ceiling,
        /// the sender may resume more aggressive probing.  This creates
        /// hysteresis — once probing is restricted due to loss, it stays
        /// restricted until the loss rate drops well below the threshold.
        /// </remarks>
        public const double BBR_LOSS_BUDGET_RECOVERY_RATIO = 0.80d;

        /// <summary>EWMA sample weight used to smooth exported loss estimates.</summary>
        /// <remarks>
        /// 25% weight on the new sample, 75% on the historical estimate.
        /// This is more reactive than the RTT EWMA (12.5%) because loss
        /// patterns change faster than RTT on mobile/wireless paths.
        /// </remarks>
        public const double BBR_LOSS_EWMA_SAMPLE_WEIGHT = 0.25d;

        /// <summary>EWMA retained weight used to smooth exported loss estimates.</summary>
        /// <remarks>
        /// (1 − 0.25) = 0.75 weight on the previous estimate.
        /// </remarks>
        public const double BBR_LOSS_EWMA_RETAINED_WEIGHT = 1d - BBR_LOSS_EWMA_SAMPLE_WEIGHT;

        /// <summary>EWMA decay applied when no recent loss is observed.</summary>
        /// <remarks>
        /// 0.90× per window.  When no loss is observed, the loss EWMA
        /// decays by 10% each window.  This prevents a single lossy
        /// episode from permanently inflating the loss estimate.
        /// </remarks>
        public const double BBR_LOSS_EWMA_IDLE_DECAY = 0.90d;

        /// <summary>Delivery-rate drop ratio that contributes to a congestion classification (15% drop).</summary>
        /// <remarks>
        /// −15%.  If the delivery rate drops ≥15% relative to the recent
        /// max, the congestion classifier gains 1 point.  A 15% drop is
        /// large enough to distinguish genuine congestion from random
        /// throughput variation.
        /// </remarks>
        public const double BBR_CONGESTION_RATE_DROP_RATIO = -0.15d;

        /// <summary>RTT increase ceiling below which loss is treated as random rather than queue congestion.</summary>
        /// <remarks>
        /// 20%.  If the RTT has not increased by more than 20% from its
        /// minimum (despite observed loss), the loss is classified as
        /// random (radio/bit-error), not congestion.  This is a critical
        /// heuristic: congestion loss is always accompanied by RTT
        /// inflation (queue buildup), while random loss is not.
        /// </remarks>
        public const double BBR_RANDOM_LOSS_MAX_RTT_INCREASE_RATIO = 0.20d;

        /// <summary>Classifier score required before loss-control treats a signal as congestion.</summary>
        /// <remarks>
        /// 2 points.  The composite classifier must reach 2 points
        /// (from rate drops, RTT growth, and/or loss observation)
        /// before the loss signal triggers a congestion response.
        /// This two-factor requirement prevents false positives from
        /// any single metric.
        /// </remarks>
        public const int BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD = 2;

        /// <summary>Classifier score assigned to a meaningful delivery-rate drop.</summary>
        public const int BBR_CONGESTION_RATE_DROP_SCORE = 1;

        /// <summary>Classifier score assigned to sustained RTT growth.</summary>
        public const int BBR_CONGESTION_RTT_GROWTH_SCORE = 1;

        /// <summary>Classifier score assigned to moderate recent loss while RTT is also growing.</summary>
        public const int BBR_CONGESTION_LOSS_SCORE = 1;

        /// <summary>Maximum rate-derived loss contribution beyond measured retransmission loss.</summary>
        /// <remarks>
        /// 5%.  When delivery rate drops but retransmission counters
        /// don't fully account for the drop, the classifier infers up
        /// to 5% additional "hidden" loss from the rate gap.
        /// </remarks>
        public const double BBR_RATE_LOSS_HINT_MAX_RATIO = 0.05d;

        /// <summary>Maximum startup delivery-rate sample multiplier relative to the active pacing rate.</summary>
        /// <remarks>
        /// 4.0×.  During Startup, ACK compression can inflate delivery-
        /// rate samples well above the actual pacing rate.  Capping at
        /// 4.0× prevents the bandwidth estimate from being wildly
        /// overestimated during the first few RTTs.
        /// </remarks>
        public const double BBR_STARTUP_ACK_AGGREGATION_RATE_CAP_GAIN = 4.0d;

        /// <summary>Maximum steady-state delivery-rate sample multiplier relative to the active pacing rate.</summary>
        /// <remarks>
        /// 1.50×.  In steady state, ACK aggregation is less pronounced.
        /// Capping at 1.50× prevents transient delivery-rate spikes from
        /// inflating the BtlBw estimate beyond sustainable capacity.
        /// </remarks>
        public const double BBR_STEADY_ACK_AGGREGATION_RATE_CAP_GAIN = 1.50d;

        /// <summary>Maximum bottleneck-bandwidth growth per RTT while in Startup (2.0x).</summary>
        /// <remarks>
        /// 2.0×.  During Startup, the BtlBw estimate can grow at most
        /// 2× per RTT round.  This prevents a single bursty ACK from
        /// instantly doubling the estimate.
        /// </remarks>
        public const double BBR_STARTUP_BANDWIDTH_GROWTH_PER_ROUND = 2.0d;

        /// <summary>Maximum bottleneck-bandwidth growth per RTT after Startup (1.25x).</summary>
        /// <remarks>
        /// 1.25×.  After Startup, bandwidth growth is capped at 25% per
        /// RTT round.  Real path capacity rarely increases faster than
        /// this (capacity changes come from routing changes, which are
        /// infrequent).
        /// </remarks>
        public const double BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND = 1.25d;

        /// <summary>RTT multiplier above which a loss signal is eligible for congestion classification (1.50x to tolerate jitter).</summary>
        /// <remarks>
        /// 1.10×.  Loss signals are only considered for congestion
        /// classification if the current RTT is ≥1.10× the minimum RTT.
        /// This tolerates modest jitter (10%) without triggering false
        /// congestion responses.
        /// </remarks>
        public const double BBR_CONGESTION_LOSS_RTT_MULTIPLIER = 1.10d;

        /// <summary>Deduplicated loss events at or below this count are treated as random in one loss window.</summary>
        /// <remarks>
        /// 2 events.  If ≤2 distinct loss events (after deduplication)
        /// are observed in a loss window, they are treated as random
        /// (likely WiFi collision pairs or radio fading).  A single
        /// packet loss on a wireless link rarely indicates congestion.
        /// </remarks>
        public const int BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS = 2;

        /// <summary>Deduplicated loss events above this count need RTT inflation before congestion response.</summary>
        /// <remarks>
        /// 3 events.  ≥3 loss events in one window cross the threshold
        /// from "random" to "potentially congestion."  However, RTT
        /// must also be elevated for the congestion classifier to
        /// respond.
        /// </remarks>
        public const int BBR_CONGESTION_LOSS_WINDOW_THRESHOLD = 3;

        /// <summary>Minimum missing packet count in one loss report before NAK loss is treated as clustered.</summary>
        /// <remarks>
        /// 3 packets.  If a single NAK reports ≥3 missing sequences,
        /// the loss is classified as a burst (clustered).  Burst losses
        /// are more likely congestion-related than isolated single-packet
        /// drops.
        /// </remarks>
        public const int BBR_CONGESTION_LOSS_BURST_THRESHOLD = 3;

        /// <summary>Fallback bandwidth-growth interval before a valid RTT sample is available.</summary>
        /// <remarks>
        /// 10 ms.  Before the first RTT sample arrives, the bandwidth
        /// estimate is updated every 10 ms.  This provides a responsive
        /// initial ramp without requiring an RTT measurement.
        /// </remarks>
        public const long BBR_BANDWIDTH_GROWTH_FALLBACK_INTERVAL_MICROS = 10000L;

        /// <summary>Maximum ratio used for the lower inflight guardrail relative to BDP (tight to prevent bufferbloat).</summary>
        /// <remarks>
        /// 1.25× BDP.  BBR must keep at least 1.25× BDP in flight.
        /// The 0.25× headroom compensates for ACK compression (multiple
        /// ACKs arriving back-to-back, which would otherwise stall the
        /// sender if inflight dropped to exactly BDP between ACK arrivals).
        /// </remarks>
        public const double BBR_INFLIGHT_LOW_GAIN = 1.25d;

        /// <summary>Maximum ratio used for the upper inflight guardrail relative to BDP (capped at 2.0x to keep queuing delay under one RTT).</summary>
        /// <remarks>
        /// 2.00× BDP.  When inflight exceeds 2.0× BDP, the sender
        /// pauses (CWND-clamped).  This prevents bufferbloat: at 2× BDP,
        /// the standing queue is roughly one BDP, adding at most one
        /// RTT of queuing delay.
        /// </remarks>
        public const double BBR_INFLIGHT_HIGH_GAIN = 2.00d;

        /// <summary>Upper inflight guardrail for mobile/jittery non-congested paths
        /// where extra headroom compensates for retransmission and jitter overhead.</summary>
        /// <remarks>
        /// 2.00× BDP (same as standard).  Mobile paths with high jitter
        /// benefit from the same headroom as wired paths; in practice the
        /// pacer (not the inflight cap) provides the dominant backpressure
        /// on these paths.
        /// </remarks>
        public const double BBR_INFLIGHT_MOBILE_HIGH_GAIN = 2.00d;

        /// <summary>RTT growth required before loss-driven delivery drops are classified as congestion.</summary>
        /// <remarks>
        /// 50%.  The RTT must be elevated by at least 50% above the
        /// minimum before the classifier interprets delivery-rate drops
        /// as congestion-related (rather than random loss).  This is
        /// a high bar, reflecting that random loss dominates on many
        /// real-world paths.
        /// </remarks>
        public const double BBR_CONGESTION_RTT_INCREASE_RATIO = 0.50d;

        /// <summary>Recent loss ratio required before loss-driven delivery drops are classified as congestion.</summary>
        /// <remarks>
        /// 10%.  Loss must exceed 10% before the classifier uses loss
        /// observations as a congestion signal.  Below 10%, loss is too
        /// ambiguous to contribute to the congestion score.
        /// </remarks>
        public const double BBR_CONGESTION_LOSS_RATIO = 0.10d;

        /// <summary>Maximum RTT cushion multiplier used by CWND on non-congested lossy paths.
        /// Kept at 2.0x to prevent bufferbloat while allowing retransmit headroom.</summary>
        /// <remarks>
        /// 2.0× RTT of cushion.  On paths where loss is classified as
        /// random (not congestion), the CWND is allowed to exceed BDP
        /// by up to 2.0× RTT worth of data.  This provides headroom for
        /// retransmissions and SACK-based recovery without stalling.
        /// </remarks>
        public const double BBR_RANDOM_LOSS_CWND_RTT_CUSHION = 2.0d;

        /// <summary>Delivery-rate sample history length used by the lightweight classifier.</summary>
        /// <remarks>
        /// 16 samples.  The classifier keeps a rolling window of the
        /// last 16 delivery-rate samples to detect trends.  16 gives
        /// ~2–3 RTTs of history at typical BBR window sizes — enough
        /// to distinguish a trend from noise without over-smoothing.
        /// </remarks>
        public const int BBR_DELIVERY_RATE_HISTORY_COUNT = 16;

        /// <summary>Number of recent RTT samples used to classify jitter
        /// and compute robust percentiles (P10, P25, P30, P50).
        /// 32 samples balances statistical stability against convergence speed.</summary>
        /// <remarks>
        /// 32 samples.  This provides reliable percentile estimates
        /// (P10, P25, P30, P50) for jitter classification and network
        /// type detection.  On a 50 ms path, 32 samples span 1.6 s —
        /// enough to smooth over short-term variations while still
        /// reacting to path changes within a few seconds.
        /// </remarks>
        public const int BBR_RTT_HISTORY_COUNT = 32;

        /// <summary>Recent loss accounting bucket duration in microseconds.</summary>
        /// <remarks>
        /// 100 ms per bucket.  Loss is tracked in 100 ms intervals,
        /// providing a time-decaying loss-rate estimate that reacts
        /// to changing path conditions.
        /// </remarks>
        public const long BBR_LOSS_BUCKET_MICROS = 100000L;

        /// <summary>Number of recent loss accounting buckets.</summary>
        /// <remarks>
        /// 10 buckets × 100 ms = 1 second of loss history.  One second
        /// is long enough to smooth out bursty loss patterns (WiFi
        /// interference, 4G scheduling gaps) without retaining stale data.
        /// </remarks>
        public const int BBR_LOSS_BUCKET_COUNT = 10;

        /// <summary>Minimum round duration in microseconds when no RTT sample is available.</summary>
        /// <remarks>
        /// 1 ms.  BBR re-evaluates its state at most once per millisecond
        /// before an RTT measurement is available.  This prevents
        /// thrashing on the initial handshake.
        /// </remarks>
        public const long BBR_MIN_ROUND_DURATION_MICROS = MICROS_PER_MILLI;

        /// <summary>Fallback BBR bandwidth filter window before a valid minimum RTT is known.</summary>
        /// <remarks>
        /// 1 second.  Before the first RTT sample, BBR uses a 1-second
        /// bandwidth filter window.  This covers the worst-case first
        /// RTT (satellite at ~600 ms) while still being responsive.
        /// </remarks>
        public const long BBR_DEFAULT_RATE_WINDOW_MICROS = MICROS_PER_SECOND;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 6 — BENCHMARK CONSTANTS
        //
        //  Pre-configured test scenarios covering UCP's target operating
        //  range.  Each benchmark exercises a specific path profile
        //  (bandwidth, delay, jitter, loss) to validate congestion control,
        //  loss recovery, and pacing under controlled conditions.
        //
        //  Coverage matrix:
        //    Bandwidth:  100 Mbps → 1 Gbps → 10 Gbps
        //    Delay:      1 ms (DC) → 50 ms (LFP) → 80 ms (4G)
        //    Loss:       0% (ideal), 0.5% (asym), 1% (light), 5% (heavy)
        //    Jitter:     0 ms → 25ms (high-jitter)
        //    Topology:   symmetric, asymmetric, burst-loss, VPN, satellite
        //
        //  Payload sizes are chosen to be 2–4× BDP at the target rate,
        //  giving BBR enough rounds to converge before the transfer ends.
        //  Deterministic random seeds enable reproducible loss patterns
        //  across test runs on any platform.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Benchmark bandwidth for 100 Mbps line-rate scenarios, in bytes per second.</summary>
        /// <remarks>
        /// 100,000,000 / 8 = 12,500,000 B/s.  Decimal mega (10^6),
        /// matching network-industry convention.
        /// </remarks>
        public const int BENCHMARK_100_MBPS_BYTES_PER_SECOND = 100000000 / 8;

        /// <summary>Benchmark bandwidth for 1 Gbps line-rate scenarios, in bytes per second.</summary>
        /// <remarks>
        /// 1,000,000,000 / 8 = 125,000,000 B/s.
        /// </remarks>
        public const int BENCHMARK_1_GBPS_BYTES_PER_SECOND = 1000000000 / 8;

        /// <summary>Benchmark bandwidth for 10 Gbps line-rate scenarios, in bytes per second.</summary>
        /// <remarks>
        /// 10,000,000,000 / 8 = 1,250,000,000 B/s ≈ 1.16 GB/s.
        /// Capped at int.MaxValue because C# int is 32-bit and the
        /// raw value exceeds 2.1B.
        /// </remarks>
        public const int BENCHMARK_10_GBPS_BYTES_PER_SECOND = 10000000000L / 8 > int.MaxValue ? int.MaxValue : (int)(10000000000L / 8);

        /// <summary>Initial probe bandwidth used by unconstrained benchmark tests, in bytes per second.</summary>
        /// <remarks>
        /// 125,000 B/s (1 Mbps).  Conservative starting point for
        /// auto-probe convergence tests.  The congestion controller
        /// ramps from this floor toward line rate.
        /// </remarks>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND = 1000000 / 8;

        /// <summary>Relative divisor used to choose a practical initial bandwidth probe for large links.</summary>
        /// <remarks>
        /// 1/128 of line rate.  For a 1 Gbps link, this gives 1 Gbps / 128
        /// ≈ 7.8 Mbps as the initial probe rate.  Starting at 1/128th of
        /// the target prevents the first few RTTs from massively
        /// overshooting on high-bandwidth paths.
        /// </remarks>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_DIVISOR = 128;

        /// <summary>Path multiplier used to estimate RTT from one-way simulator delay.</summary>
        /// <remarks>
        /// 2×.  The simulator applies one-way delay; multiplying by 2
        /// gives the round-trip time used for BDP estimation.
        /// </remarks>
        public const int BENCHMARK_RTT_PATH_MULTIPLIER = 2;

        /// <summary>Initial congestion-window gain relative to estimated BDP for line-rate benchmarks.</summary>
        /// <remarks>
        /// 1.25× BDP.  Provides enough inflight headroom for the pacer
        /// to operate at line rate without the CWND being the bottleneck.
        /// </remarks>
        public const double BENCHMARK_INITIAL_CWND_BDP_GAIN = 1.25d;

        /// <summary>Bandwidth divisor used as the no-loss benchmark initial congestion-window floor.</summary>
        /// <remarks>
        /// Line-rate / 16.  For a 1 Gbps link, CWND starts at ~62.5 Mbps
        /// worth of inflight.  Chosen as a safe starting point that BBR
        /// can quickly grow from.
        /// </remarks>
        public const int BENCHMARK_NO_LOSS_INITIAL_CWND_BANDWIDTH_DIVISOR = 16;

        /// <summary>Initial congestion-window gain relative to estimated BDP for lossy benchmarks.</summary>
        /// <remarks>
        /// 4.0× BDP.  Lossy benchmarks start with extra CWND headroom
        /// because retransmissions consume inflight budget.  Without
        /// this, the sender would stall waiting for SACK coverage
        /// before the CWND opens.
        /// </remarks>
        public const double BENCHMARK_LOSS_INITIAL_CWND_BDP_GAIN = 4.0d;

        /// <summary>Initial congestion-window gain for weak/high-latency network benchmarks (8.0x BDP).</summary>
        /// <remarks>
        /// 8.0× BDP.  On very weak networks (high loss, high latency,
        /// low throughput), the sender needs substantial CWND headroom
        /// to maintain even modest throughput.  8× BDP is aggressive
        /// but these paths have little to lose from queue buildup.
        /// </remarks>
        public const double BENCHMARK_WEAK_NETWORK_INITIAL_CWND_BDP_GAIN = 8.0d;

        /// <summary>ProbeRTT interval for weak/high-latency network benchmarks (120s) to avoid premature CWND reduction.</summary>
        /// <remarks>
        /// 120 s.  Weak networks need longer intervals between ProbeRTT
        /// events because the throughput recovery after each ProbeRTT
        /// (which temporarily cuts pacing) takes many RTTs on these paths.
        /// </remarks>
        public const long BENCHMARK_WEAK_NETWORK_PROBE_RTT_INTERVAL_MICROS = 120000000L;

        /// <summary>Serial-time threshold (seconds) above which a benchmark is considered long-running
        /// and the extended ProbeRTT interval is applied.</summary>
        /// <remarks>
        /// 10 s.  Benchmarks running longer than 10 seconds of simulated
        /// time are classified as long-running and get the extended
        /// ProbeRTT interval to avoid repeated throughput dips.
        /// </remarks>
        public const double BENCHMARK_LONG_RUNNING_SERIAL_SECONDS = 10d;

        /// <summary>Maximum initial congestion window used by random-loss benchmarks, in bytes.</summary>
        /// <remarks>
        /// 128 MB.  Upper bound on the initial CWND for lossy benchmark
        /// scenarios.  Prevents the CWND from being initialized to an
        /// absurdly large value on 10 Gbps × 80 ms paths (BDP ≈ 100 MB).
        /// </remarks>
        public const int BENCHMARK_MAX_LOSS_INITIAL_CWND_BYTES = 128 * 1024 * 1024;

        /// <summary>Minimum RTO used by long-fat-pipe benchmarks to avoid simulator serialization false positives.</summary>
        /// <remarks>
        /// 1 s minimum RTO.  On simulated long-fat paths, the RTO must
        /// be at least 1 second to avoid premature timeouts caused by
        /// the simulator's serial event processing rather than real
        /// packet loss.
        /// </remarks>
        public const long BENCHMARK_LONG_FAT_MIN_RTO_MICROS = MICROS_PER_SECOND;

        /// <summary>Deterministic random seed used by light-loss benchmark data drops.</summary>
        /// <remarks>
        /// Date-based seed (2026-05-01) ensures reproducible loss
        /// patterns across test runs and platforms.
        /// </remarks>
        public const int BENCHMARK_LIGHT_RANDOM_LOSS_SEED = 20260501;

        /// <summary>Deterministic random seed used by heavy-loss benchmark data drops.</summary>
        public const int BENCHMARK_HEAVY_RANDOM_LOSS_SEED = 20260502;

        /// <summary>RTT used by controller-only auto-probe convergence benchmarks, in microseconds.</summary>
        /// <remarks>
        /// 10 ms.  Controller-only convergence tests (no network
        /// simulator) assume a 10 ms RTT for BDP calculations.
        /// </remarks>
        public const long BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS = 10000L;

        /// <summary>Maximum BBR rounds allowed for controller-only auto-probe convergence benchmarks.</summary>
        /// <remarks>
        /// 32 rounds.  After 32 BBR rounds (~320 ms at 10 ms RTT),
        /// the test declares convergence failure.  At 10× BBR filter
        /// window, this is over 3 full filter cycles — ample time to
        /// converge in ideal conditions.
        /// </remarks>
        public const int BENCHMARK_CONTROLLER_MAX_CONVERGENCE_ROUNDS = 32;

        /// <summary>Payload size used by 100 Mbps benchmark scenarios, in bytes.</summary>
        /// <remarks>
        /// 16 MB.  At 100 Mbps, this is ~1.3 s of data — enough for
        /// BBR to complete Startup (~10 RTTs) and enter ProbeBW on a
        /// 5 ms RTT path.
        /// </remarks>
        public const int BENCHMARK_100M_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by asymmetric route benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_ASYM_PAYLOAD_BYTES = 8 * 1024 * 1024;

        /// <summary>Payload size used by high-jitter weak-network benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 4G weak-network benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_WEAK_4G_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 100 Mbps random-loss benchmark scenarios, in bytes.</summary>
        /// <remarks>
        /// 32 MB.  Larger payload for lossy benchmarks because
        /// retransmissions reduce effective throughput,
        /// requiring more data to reach steady state.
        /// </remarks>
        public const int BENCHMARK_100M_LOSS_PAYLOAD_BYTES = 32 * 1024 * 1024;

        /// <summary>Payload size used by high-loss high-RTT benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by mobile 3G lossy benchmark scenarios, in bytes.</summary>
        /// <remarks>
        /// 16 MB.  3G paths have low throughput and high latency; 16 MB
        /// provides enough data for convergence without making test
        /// duration excessive.
        /// </remarks>
        public const int BENCHMARK_MOBILE_3G_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by mobile 4G high-jitter benchmark scenarios, in bytes.</summary>
        /// <remarks>
        /// 32 MB.  4G paths have moderate throughput; 32 MB ensures
        /// multiple ProbeBW cycles complete.
        /// </remarks>
        public const int BENCHMARK_MOBILE_4G_PAYLOAD_BYTES = 32 * 1024 * 1024;

        /// <summary>Payload size used by satellite benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_SATELLITE_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by VPN benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_VPN_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by the 100 Mbps long-fat-pipe benchmark, in bytes.</summary>
        public const int BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 1 Gbps benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_1G_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 1 Gbps random-loss benchmark scenarios, in bytes.</summary>
        /// <remarks>
        /// 64 MB.  At 1 Gbps with 5% loss, the effective throughput
        /// can be well below line rate; 64 MB ensures enough data
        /// transfers that BBR reaches steady state.
        /// </remarks>
        public const int BENCHMARK_1G_LOSS_PAYLOAD_BYTES = 64 * 1024 * 1024;

        /// <summary>Jumbo MSS used by high-bandwidth benchmark paths to avoid control-plane packet amplification.</summary>
        /// <remarks>
        /// 9000 bytes (jumbo frame).  On 10 Gbps paths, the default
        /// 1220-byte MSS would generate ~1 million packets/second,
        /// overwhelming the control plane.  9000-byte MSS reduces
        /// packet rate by 7.4×.
        /// </remarks>
        public const int BENCHMARK_HIGH_BANDWIDTH_MSS = 9000;

        /// <summary>Payload size used by 10 Gbps benchmark scenarios, in bytes.</summary>
        /// <remarks>
        /// 32 MB.  At 10 Gbps with 9000-byte packets, this is ~28 ms
        /// of data — just ~3 RTTs on a typical WAN path.  BBR needs
        /// more RTTs to converge, so the test verifies startup ramp
        /// rather than steady-state throughput.
        /// </remarks>
        public const int BENCHMARK_10G_PAYLOAD_BYTES = 32 * 1024 * 1024;

        /// <summary>Payload size used by burst-loss recovery benchmark scenarios, in bytes.</summary>
        /// <remarks>
        /// 2 MB.  Small payload to keep test duration short; the
        /// benchmark focuses on recovery speed after a burst, not
        /// steady-state throughput.
        /// </remarks>
        public const int BENCHMARK_BURST_LOSS_PAYLOAD_BYTES = 2 * 1024 * 1024;

        /// <summary>Default benchmark read timeout in milliseconds.</summary>
        /// <remarks>
        /// 180 s (3 minutes).  Long enough for any benchmark to complete
        /// even on the slowest simulated path (satellite at 600 ms RTT,
        /// 16 MB payload ≈ 215 s at 600 kbps).
        /// </remarks>
        public const int BENCHMARK_READ_TIMEOUT_MILLISECONDS = 180000;

        /// <summary>Default ACK settlement timeout in milliseconds.</summary>
        /// <remarks>
        /// 1 s.  After the data transfer completes, the test waits up to
        /// 1 second for final ACKs to settle before computing metrics.
        /// </remarks>
        public const int BENCHMARK_ACK_SETTLEMENT_TIMEOUT_MILLISECONDS = 1000;

        /// <summary>First logical port used by dynamically allocated benchmark tests.</summary>
        /// <remarks>
        /// 40100.  Chosen to avoid conflicts with ephemeral port ranges
        /// (typically 32768–60999 on Linux, 49152–65535 on Windows) and
        /// well-known services.  Each benchmark scenario gets a unique
        /// offset from this base.
        /// </remarks>
        public const int BENCHMARK_BASE_PORT = 40100;

        /// <summary>Port offset for the 1 Gbps ideal benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_IDEAL = 0;

        /// <summary>Port offset for the 1 Gbps heavy-loss benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS5 = 1;

        /// <summary>Port offset for the 1 Gbps light-loss benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS1 = 2;

        /// <summary>Port offset for the 100 Mbps long-fat-pipe benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_LONG_FAT_100M = 3;

        /// <summary>Port offset for the 10 Gbps benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_10G = 4;

        /// <summary>Port offset for the burst-loss benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_BURST_LOSS = 5;

        /// <summary>Port offset for the asymmetric route benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_ASYM_ROUTE = 6;

        /// <summary>Port offset for the high-jitter benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_HIGH_JITTER = 7;

        /// <summary>Port offset for the weak 4G benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_WEAK_4G = 8;

        /// <summary>Fixed one-way delay for the 100 Mbps benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 5 ms.  Represents a typical metro-area or inter-datacenter
        /// link — fast enough that line rate is reachable, slow enough
        /// that the congestion controller must manage a non-trivial BDP.
        /// </remarks>
        public const int BENCHMARK_100M_DELAY_MILLISECONDS = 5;

        /// <summary>Fixed one-way delay for the 1 Gbps ideal benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 1 ms.  Ideal datacenter path with negligible propagation
        /// delay.  Tests throughput in near-zero-RTT conditions.
        /// </remarks>
        public const int BENCHMARK_1G_IDEAL_DELAY_MILLISECONDS = 1;

        /// <summary>Fixed one-way delay for the 1 Gbps light-loss benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 20 ms.  Typical cross-continent WAN RTT/2.  At 1 Gbps,
        /// BDP = 2.5 MB, which fits comfortably within the default
        /// receive window.
        /// </remarks>
        public const int BENCHMARK_1G_LIGHT_LOSS_DELAY_MILLISECONDS = 20;

        /// <summary>Jitter for the 1 Gbps light-loss benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 3 ms.  Modest jitter typical of a well-provisioned WAN link.
        /// </remarks>
        public const int BENCHMARK_1G_LIGHT_LOSS_JITTER_MILLISECONDS = 3;

        /// <summary>Fixed one-way delay for the 1 Gbps heavy-loss benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 30 ms.  Longer WAN delay combined with 5% loss stresses the
        /// congestion classifier's ability to distinguish congestion
        /// loss from random loss.
        /// </remarks>
        public const int BENCHMARK_1G_HEAVY_LOSS_DELAY_MILLISECONDS = 30;

        /// <summary>Jitter for the 1 Gbps heavy-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_1G_HEAVY_LOSS_JITTER_MILLISECONDS = 5;

        /// <summary>Fixed one-way delay for the 100 Mbps long-fat-pipe benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 50 ms.  Represents a trans-oceanic link.  BDP = 100 Mbps ×
        /// 100 ms = 1.25 MB, a classic "long fat pipe" scenario.
        /// </remarks>
        public const int BENCHMARK_LONG_FAT_DELAY_MILLISECONDS = 50;

        /// <summary>Jitter for the 100 Mbps long-fat-pipe benchmark, in milliseconds.</summary>
        public const int BENCHMARK_LONG_FAT_JITTER_MILLISECONDS = 2;

        /// <summary>Fixed one-way delay for the 10 Gbps probe benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 1 ms.  Datacenter-like low latency to test raw throughput
        /// without RTT as the bottleneck.
        /// </remarks>
        public const int BENCHMARK_10G_DELAY_MILLISECONDS = 1;

        /// <summary>Fixed one-way delay for the burst-loss benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 25 ms.  Moderate WAN delay where burst-loss recovery must
        /// compete with the BDP × RTT time constant.
        /// </remarks>
        public const int BENCHMARK_BURST_LOSS_DELAY_MILLISECONDS = 25;

        /// <summary>Jitter for the burst-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_BURST_LOSS_JITTER_MILLISECONDS = 4;

        /// <summary>Forward one-way delay for the asymmetric route benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 25 ms forward.  Asymmetric routing (common on the Internet)
        /// where the forward and return paths have different latencies.
        /// This breaks RTT-based estimators that assume symmetry.
        /// </remarks>
        public const int BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS = 25;

        /// <summary>Backward one-way delay for the asymmetric route benchmark, in milliseconds.</summary>
        public const int BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS = 15;

        /// <summary>Per-direction jitter for the asymmetric route benchmark, in milliseconds.</summary>
        /// <remarks>
        /// 8 ms jitter on an already asymmetric path adds significant
        /// measurement noise to RTT samples.
        /// </remarks>
        public const int BENCHMARK_ASYM_JITTER_MILLISECONDS = 8;

        /// <summary>Random data loss rate used by the asymmetric route benchmark.</summary>
        /// <remarks>
        /// 0.5% random loss.  Modest loss typical of a well-maintained
        /// but long-distance Internet path.
        /// </remarks>
        public const double BENCHMARK_ASYM_RANDOM_LOSS_RATE = 0.005d;

        /// <summary>Random data loss rate used by the high-jitter benchmark.</summary>
        public const double BENCHMARK_HIGH_JITTER_LOSS_RATE = 0.005d;

        /// <summary>Random data loss rate used by the weak 4G benchmark.</summary>
        /// <remarks>
        /// 5% loss.  Realistic for a congested or weak-signal 4G cell.
        /// Combined with 80 ms delay and periodic outages, this
        /// represents a worst-case mobile scenario.
        /// </remarks>
        public const double BENCHMARK_WEAK_4G_LOSS_RATE = 0.05d;

        /// <summary>Deterministic random seed used by asymmetric route benchmark data drops.</summary>
        public const int BENCHMARK_ASYM_RANDOM_LOSS_SEED = 20260503;

        /// <summary>Deterministic random seed used by high-jitter benchmark data drops.</summary>
        public const int BENCHMARK_HIGH_JITTER_LOSS_SEED = 20260504;

        /// <summary>Deterministic random seed used by weak 4G benchmark data drops.</summary>
        public const int BENCHMARK_WEAK_4G_LOSS_SEED = 20260505;

        /// <summary>Fixed one-way delay for high-jitter benchmark scenarios, in milliseconds.</summary>
        /// <remarks>
        /// 50 ms RTT/2 with 25 ms jitter creates extreme RTT variance.
        /// Tests the RTT estimator's stability under maximum noise.
        /// </remarks>
        public const int BENCHMARK_HIGH_JITTER_DELAY_MILLISECONDS = 50;

        /// <summary>Per-direction jitter for high-jitter benchmark scenarios, in milliseconds.</summary>
        /// <remarks>
        /// 25 ms jitter (50% of the fixed delay).  This is deliberately
        /// extreme — real paths rarely exceed 20% jitter/delay ratio.
        /// Tests the robustness boundary.
        /// </remarks>
        public const int BENCHMARK_HIGH_JITTER_JITTER_MILLISECONDS = 25;

        /// <summary>Fixed one-way delay for weak 4G benchmark scenarios, in milliseconds.</summary>
        /// <remarks>
        /// 80 ms.  Typical worst-case 4G latency including scheduling
        /// and queueing delays.
        /// </remarks>
        public const int BENCHMARK_WEAK_4G_DELAY_MILLISECONDS = 80;

        /// <summary>Weak 4G outage period, in milliseconds.</summary>
        /// <remarks>
        /// 900 ms.  The path drops ALL packets for 80 ms every 900 ms.
        /// This simulates 4G scheduling outages and handover gaps.
        /// The sender must survive and recover from periodic total
        /// blackouts.
        /// </remarks>
        public const int BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS = 900;

        /// <summary>Weak 4G outage duration, in milliseconds.</summary>
        /// <remarks>
        /// 80 ms.  Each outage lasts 80 ms — well over one RTT, so
        /// the sender experiences multiple consecutive RTO events.
        /// </remarks>
        public const int BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS = 80;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 7 — NETWORK CLASSIFIER CONSTANTS
        //
        //  Lightweight online classifier that identifies the path type from
        //  observed RTT, jitter, and loss statistics.  The classification
        //  result tunes BBR gain tiers, FEC redundancy, and ACK scheduling
        //  to match the path characteristics.
        //
        //  Categories:
        //   • LAN        — RTT < 5 ms, jitter < 3 ms
        //   • Long-fat   — RTT ≥ 80 ms
        //   • Mobile     — loss > 3% OR jitter > 20 ms
        //   • Default    — everything else (typical WAN/broadband)
        //
        //  Statistics are collected in rolling 200 ms windows (8 windows
        //  = 1.6 s of history), providing fast adaptation to path changes
        //  (e.g. WiFi → cellular handover).
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Number of recent statistics windows retained for network classification.</summary>
        /// <remarks>
        /// 8 windows × 200 ms = 1.6 s of history.  Long enough to
        /// average out transient noise, short enough to detect a
        /// network change within ~2 seconds.
        /// </remarks>
        public const int NETWORK_CLASSIFIER_WINDOW_COUNT = 8;

        /// <summary>Duration of each classification statistics window, in microseconds.</summary>
        /// <remarks>
        /// 200 ms.  Chosen because most path properties (RTT, jitter,
        /// loss rate) are stable over 200 ms intervals but can change
        /// at second granularity (e.g. cellular scheduling).
        /// </remarks>
        public const long NETWORK_CLASSIFIER_WINDOW_DURATION_MICROS = 200000L;

        /// <summary>RTT threshold (ms) for classifying long-fat networks.</summary>
        /// <remarks>
        /// 80 ms.  Paths with RTT ≥ 80 ms are classified as long-fat.
        /// At typical broadband speeds (10–100 Mbps), BDP exceeds 100 KB,
        /// requiring larger CWND and longer BBR filter windows.
        /// </remarks>
        public const double NETWORK_CLASSIFIER_LONG_FAT_RTT_MS = 80d;

        /// <summary>Loss threshold for classifying mobile/unstable networks.</summary>
        /// <remarks>
        /// 3%.  Paths with sustained loss ≥3% are classified as mobile
        /// or unstable.  3% is the threshold above which random loss
        /// (WiFi, cellular) dominates over occasional congestion drops.
        /// </remarks>
        public const double NETWORK_CLASSIFIER_MOBILE_LOSS_RATE = 0.03d;

        /// <summary>Jitter threshold (ms) for classifying mobile/unstable networks.</summary>
        /// <remarks>
        /// 20 ms.  Sustained jitter ≥20 ms indicates a shared or
        /// wireless medium.  Wired WAN paths typically have jitter
        /// well below 5 ms.
        /// </remarks>
        public const double NETWORK_CLASSIFIER_MOBILE_JITTER_MS = 20d;

        /// <summary>RTT threshold (ms) for classifying low-latency LAN.</summary>
        /// <remarks>
        /// 5 ms.  Sub-5ms RTT is typical of switched Ethernet LANs
        /// and same-region datacenter interconnects.  LAN paths get
        /// aggressive delayed-ACK timers and minimal reorder grace.
        /// </remarks>
        public const double NETWORK_CLASSIFIER_LAN_RTT_MS = 5d;

        /// <summary>Jitter threshold (ms) for classifying low-latency LAN.</summary>
        /// <remarks>
        /// 3 ms.  LAN paths have near-zero jitter (<1 ms typical).
        /// 3 ms provides headroom for virtualized/containerized
        /// environments where hypervisor scheduling adds modest jitter.
        /// </remarks>
        public const double NETWORK_CLASSIFIER_LAN_JITTER_MS = 3d;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 7b — FEC AND LOSS-RATE CONSTANTS
        //
        //  Forward Error Correction (FEC) is applied adaptively based on
        //  the estimated loss rate and path characteristics (RTT, jitter).
        //  FEC trades bandwidth overhead for reduced retransmission latency
        //  — critical on high-RTT paths where a single retransmit costs
        //  an entire RTT of delay.
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Light random data loss rate used by benchmark scenarios.</summary>
        /// <remarks>
        /// 1%.  Represents a well-maintained path with occasional
        /// bit-error or collision drops.
        /// </remarks>
        public const double BENCHMARK_LIGHT_RANDOM_LOSS_RATE = 0.01d;

        /// <summary>Heavy random data loss rate used by benchmark scenarios.</summary>
        /// <remarks>
        /// 5%.  Represents a congested or weak-signal path where
        /// 1 in 20 packets is dropped.
        /// </remarks>
        public const double BENCHMARK_HEAVY_RANDOM_LOSS_RATE = 0.05d;

        /// <summary>Very heavy random data loss rate (>=10%) used by benchmark scenarios.</summary>
        /// <remarks>
        /// 10%.  Extreme loss scenario (e.g. satellite during rain fade,
        /// severely overloaded cellular cell).  At this loss rate,
        /// aggressive FEC is required to maintain any throughput.
        /// </remarks>
        public const double BENCHMARK_VERY_HEAVY_RANDOM_LOSS_RATE = 0.10d;

        /// <summary>FEC redundancy ratio for very heavy loss (>=10%) benchmark scenarios.</summary>
        /// <remarks>
        /// 50% redundancy.  For every 2 data packets, send 1 FEC repair
        /// packet.  This can recover from up to 33% loss in ideal
        /// conditions.  50% is the maximum practical overhead.
        /// </remarks>
        public const double BENCHMARK_VERY_HEAVY_LOSS_FEC_REDUNDANCY = 0.50d;

        /// <summary>Medium random loss rate (>=3%) threshold for increased FEC redundancy.</summary>
        public const double BENCHMARK_MEDIUM_RANDOM_LOSS_RATE = 0.03d;

        /// <summary>FEC redundancy ratio for medium loss (3-10%) benchmark scenarios.</summary>
        public const double BENCHMARK_MEDIUM_LOSS_FEC_REDUNDANCY = 0.50d;

        /// <summary>Minimum estimated loss percent to enable adaptive FEC encoding (1%).</summary>
        /// <remarks>
        /// 2%.  Below 2% estimated loss, the bandwidth cost of FEC
        /// exceeds the benefit.  The 2% threshold prevents FEC from
        /// activating on near-perfect paths where occasional single-
        /// packet drops are cheaper to retransmit than to FEC-protect.
        /// </remarks>
        public const double FEC_ADAPTIVE_MIN_LOSS_PERCENT = 2d;

        /// <summary>RTT threshold above which heavy FEC (0.50) is always used for lossy benchmarks.</summary>
        /// <remarks>
        /// 80 ms.  On high-RTT paths, the latency cost of retransmission
        /// is substantial (80 ms per lost packet).  Heavy FEC at 50%
        /// redundancy is justified to avoid cumulative retransmission
        /// delays.
        /// </remarks>
        public const long BENCHMARK_HIGH_RTT_FEC_THRESHOLD_MICROS = 80000L;

        /// <summary>Jitter threshold (ms) above which FEC is enabled to suppress SACK storms on reordering paths.</summary>
        /// <remarks>
        /// 15 ms.  High jitter causes packet reordering, which triggers
        /// SACK-based retransmissions even when no packets are lost.
        /// Enabling FEC on high-jitter paths reduces false SACK triggers.
        /// </remarks>
        public const int BENCHMARK_HIGH_JITTER_FEC_THRESHOLD_MS = 15;

        /// <summary>First data packet index included in the burst-loss benchmark.</summary>
        /// <remarks>
        /// Packet 16.  The benchmark drops packets 16–23, allowing
        /// the first 15 packets to establish the connection before
        /// the burst loss hits.  This tests recovery from mid-transfer
        /// loss bursts, not startup behavior.
        /// </remarks>
        public const int BENCHMARK_BURST_LOSS_FIRST_PACKET = 16;

        /// <summary>Number of consecutive data packets dropped in the burst-loss benchmark.</summary>
        /// <remarks>
        /// 8 consecutive packets.  A burst of 8 losses far exceeds
        /// typical FEC protection and forces RTO-based recovery.
        /// Tests the sender's ability to detect and recover from a
        /// sustained loss burst.
        /// </remarks>
        public const int BENCHMARK_BURST_LOSS_PACKET_COUNT = 8;

        /// <summary>Minimum line-rate utilization target for no-loss benchmark scenarios.</summary>
        /// <remarks>
        /// 70%.  On ideal (no-loss) paths, UCP should achieve ≥70% line
        /// rate.  The 30% gap accounts for protocol overhead (headers,
        /// ACK traffic, BBR's non-100%-duty-cycle pacing).
        /// </remarks>
        public const double BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT = 70d;

        /// <summary>Minimum line-rate utilization target for controlled-loss benchmark scenarios.</summary>
        /// <remarks>
        /// 45%.  With controlled loss (0.5–5%), the protocol should still
        /// achieve ≥45% line rate after accounting for retransmission
        /// overhead and congestion-control backoff.
        /// </remarks>
        public const double BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT = 45d;

        /// <summary>Minimum throughput target for the 5% random-loss 1 Gbps benchmark, in Mbps.</summary>
        /// <remarks>
        /// 145 Mbps on a 1 Gbps link with 5% loss.  At 5% random loss,
        /// throughput is dominated by the loss rate × RTT product;
        /// 145 Mbps represents ≈15% utilization, realistic for a
        /// lossy WAN path without FEC.
        /// </remarks>
        public const double BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS = 145d;

        /// <summary>Maximum acceptable RTT jitter multiplier relative to the configured one-way delay.</summary>
        /// <remarks>
        /// 4×.  The worst-case jitter must not exceed 4× the configured
        /// delay.  This prevents the benchmark from accepting results
        /// where jitter overwhelms the signal.
        /// </remarks>
        public const double BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER = 4d;

        /// <summary>Minimum pacing ratio accepted after auto-probing converges.</summary>
        /// <remarks>
        /// 0.70×.  After auto-probe convergence, the pacing rate must
        /// be at least 70% of the target.  Lower means the controller
        /// failed to find the path's capacity.
        /// </remarks>
        public const double BENCHMARK_MIN_CONVERGED_PACING_RATIO = 0.70d;

        /// <summary>Maximum pacing ratio accepted after auto-probing converges (1000× for aggressive mode).</summary>
        /// <remarks>
        /// 3.0×.  After convergence, the pacing rate must not exceed 3×
        /// the target.  Above 3× indicates the controller is over-
        /// estimating bandwidth, which would cause excessive loss in
        /// production.
        /// </remarks>
        public const double BENCHMARK_MAX_CONVERGED_PACING_RATIO = 3.0d;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 7c — ADDITIONAL BENCHMARK PORT OFFSETS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Port offset for the mobile 3G benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_MOBILE_3G = 14;

        /// <summary>Port offset for the mobile 4G high-jitter benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_MOBILE_4G = 15;

        /// <summary>Port offset for the satellite benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_SATELLITE = 16;

        /// <summary>Port offset for the VPN dual-congestion benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_VPN = 17;

        /// <summary>Port offset for the datacenter benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_DATACENTER = 18;

        /// <summary>Port offset for the enterprise benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_ENTERPRISE = 19;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 8 — LOSS DETECTION, NAK, AND SACK
        //
        //  UCP uses a three-tier loss detection strategy:
        //   1. SACK-based fast retransmit — sender detects holes from the
        //      SACK blocks carried in ACK packets.  A hole must be observed
        //      in 3 SACK blocks and the ACK must have advanced 48 sequences
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
        //    Standard NAK        2   5000 μs   Normal loss suspicion
        //    Medium confidence   32   1000 μs   Likely loss, low reorder risk
        //    High confidence    128   1000 μs   Almost certain loss
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Maximum number of NAK packets emitted during one RTT interval.</summary>
        /// <remarks>
        /// 1024.  Prevents a NAK storm on very lossy paths where every
        /// other packet triggers a NAK.  1024 NAKs/RTT is still ~1 NAK
        /// per ms at 1 Gbps, which is manageable.
        /// </remarks>
        public const int MAX_NAKS_PER_RTT = 1024;

        /// <summary>Threshold in payload-sized segments below which early retransmit is allowed.</summary>
        /// <remarks>
        /// 4 segments.  RFC 5827 Early Retransmit: if inflight is below
        /// 4 segments and a duplicate ACK arrives, retransmit immediately
        /// because there aren't enough packets in flight to generate the
        /// standard 3 duplicate ACKs needed for fast retransmit.
        /// </remarks>
        public const int EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS = 4;

        /// <summary>Tail-loss probe threshold in payload-sized segments.</summary>
        /// <remarks>
        /// 2 segments.  If inflight drops to ≤2 segments after the last
        /// ACK, arm a tail-loss probe timer.  When the timer fires,
        /// retransmit the last unacknowledged packet to provoke an ACK
        /// (which either confirms delivery or reveals more loss).
        /// </remarks>
        public const int TLP_MAX_INFLIGHT_SEGMENTS = 2;

        /// <summary>Tail-loss probe timer ratio relative to the smoothed RTT.</summary>
        /// <remarks>
        /// 1.5 × SRTT.  The TLP fires at 1.5× the smoothed RTT after
        /// the last ACK.  This is long enough to avoid spurious probes
        /// from jitter, short enough to recover tail loss before the RTO.
        /// </remarks>
        public const double TLP_TIMEOUT_RTT_RATIO = 1.5d;

        /// <summary>Number of congestion loss events needed before entering ProbeRTT.</summary>
        /// <remarks>
        /// 5 events.  After 5 classified congestion loss events, BBR
        /// enters ProbeRTT to re-measure the true RTprop.  This prevents
        /// the RTT estimate from drifting upward due to persistent queueing.
        /// </remarks>
        public const int BBR_PROBE_RTT_CONGESTION_LOSS_THRESHOLD = 5;

        /// <summary>Duplicate ACK count needed to trigger fast retransmit.</summary>
        /// <remarks>
        /// 3 duplicate ACKs.  Standard TCP behavior.  The first ACK
        /// after a gap is the "hole notification"; the next 3 confirm
        /// the gap is real loss, not reordering.
        /// </remarks>
        public const int DUPLICATE_ACK_THRESHOLD = 3;

        /// <summary>SACK observations needed before a missing hole is retransmitted without waiting for RTO.</summary>
        /// <remarks>
        /// 2 SACK blocks.  Matching QUIC's default SACK threshold.
        /// A missing sequence range must appear in 2 separate SACK blocks
        /// before the sender retransmits.  This filters transient holes
        /// caused by reordering while minimizing recovery latency.
        /// </remarks>
        public const int SACK_FAST_RETRANSMIT_THRESHOLD = 2;

        /// <summary>Minimum SACK distance past a missing sequence before treating the hole as real loss.</summary>
        /// <remarks>
        /// 48 sequences.  The ACK must have progressed at least 48
        /// sequence numbers beyond the start of the hole.  A gap of
        /// <48 packets could be reordering (packets taking a different
        /// path and arriving slightly out of order).  At 1200 bytes/pkt,
        /// 48 packets = ~57 KB — a reasonable reorder window on WAN paths.
        /// </remarks>
        public const int SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD = 48;

        /// <summary>Lower bound for SACK-based reorder grace before fast retransmit, in microseconds.
        /// Reduced to 5ms for faster hole recovery on low-latency paths.</summary>
        /// <remarks>
        /// 5 ms.  The gap must have persisted for at least 5 ms before
        /// retransmission.  With 2-block SACK threshold and 5ms grace,
        /// UCP achieves QUIC-comparable recovery latency.
        /// </remarks>
        public const long SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS = 5000L;

        /// <summary>Missing observation count needed before the receiver sends a NAK.</summary>
        /// <remarks>
        /// 2 observations.  After seeing 2 subsequent packets arrive
        /// past a gap, the receiver considers the missing packet
        /// potentially lost and may send a NAK (subject to reorder grace).
        /// </remarks>
        public const int NAK_MISSING_THRESHOLD = 2;

        /// <summary>Minimum packet-age delay before receiver NAKs a missing sequence, in microseconds.
        /// Reduced to 2ms for faster loss detection on low-latency paths.</summary>
        /// <remarks>
        /// 2 ms.  A packet must have been missing for at least 2 ms
        /// before the receiver will NAK it.  On modern networks, 2 ms
        /// is sufficient to distinguish reordering from true loss.
        /// </remarks>
        public const long NAK_REORDER_GRACE_MICROS = 2000L;

        /// <summary>Missing observation count that makes a gap high-confidence despite reorder grace.</summary>
        /// <remarks>
        /// 128 subsequent arrivals beyond the gap → near-certain loss.
        /// The probability that 128 packets all reordered around a single
        /// gap is astronomically low.  Use minimal grace (1 ms).
        /// </remarks>
        public const int NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD = 128;

        /// <summary>Minimum packet-age delay for high-confidence missing gaps, in microseconds.</summary>
        public const long NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS = 1000L;

        /// <summary>Missing observation count that makes a gap more likely to be real loss than jitter.</summary>
        /// <remarks>
        /// 32 observations → moderate confidence.  There is still a
        /// small chance of reordering, but it's unlikely.  Use 1 ms grace.
        /// </remarks>
        public const int NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD = 32;

        /// <summary>Minimum packet-age delay for medium-confidence missing gaps, in microseconds.</summary>
        public const long NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS = 1000L;

        /// <summary>Minimum interval before the receiver may re-emit a NAK for the same missing sequence.</summary>
        /// <remarks>
        /// 5 ms between repeated NAKs for the same gap.  Prevents NAK
        /// flooding while still providing timely re-notification if the
        /// sender's retransmission is itself lost.
        /// </remarks>
        public const long NAK_REPEAT_INTERVAL_MICROS = 5000L;

        /// <summary>Maximum number of sequence slots scanned while building NAK state.</summary>
        /// <remarks>
        /// 16384 slots.  Caps the per-cycle NAK scan to prevent O(n)
        /// behavior on connections with millions of sequences in flight.
        /// At 1200 B/pkt, 16K packets = ~19 MB of data — enough to cover
        /// typical receive windows.
        /// </remarks>
        public const int MAX_NAK_MISSING_SCAN = 16384;

        /// <summary>Maximum missing sequences included in one NAK packet.</summary>
        /// <remarks>
        /// 256 entries.  At 4 bytes each = 1024 bytes of missing-sequence
        /// data.  Combined with the fixed NAK header (18 bytes) = 1042
        /// bytes total, safely under the 1220-byte MSS.
        /// </remarks>
        public const int MAX_NAK_SEQUENCES_PER_PACKET = 256;

        /// <summary>Maximum SACK blocks emitted by default (QUIC uses 2).</summary>
        /// <remarks>
        /// 2 blocks.  Matching QUIC's default.  More blocks provide
        /// finer loss reporting but increase ACK packet size.  2 blocks
        /// is sufficient for most loss patterns (one hole being filled
        /// plus one new hole opening).
        /// </remarks>
        public const int DEFAULT_ACK_SACK_BLOCK_LIMIT = 2;

        /// <summary>Receive-buffer occupancy that forces an immediate ACK, measured in packets.</summary>
        /// <remarks>
        /// 4 packets.  When 4 reordered packets accumulate in the
        /// receive buffer (waiting for a missing predecessor), send an
        /// immediate ACK to signal the gap to the sender via SACK.
        /// This accelerates fast retransmit on reordering paths.
        /// </remarks>
        public const int IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD = 4;

        /// <summary>Minimum spacing between immediate reordered-data ACKs, in microseconds.</summary>
        /// <remarks>
        /// 250 μs.  Prevents the receiver from sending a flood of
        /// immediate ACKs when many packets arrive out of order in
        /// quick succession (common after WiFi interference clears).
        /// </remarks>
        public const long REORDERED_ACK_MIN_INTERVAL_MICROS = 250L;

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
        public const long KEEP_ALIVE_INTERVAL_MICROS = MICROS_PER_SECOND;

        /// <summary>Default disconnect timeout in microseconds (4 seconds).</summary>
        /// <remarks>
        /// 4 s.  If no packet is received for 4 seconds, the connection
        /// is considered dead.  This is much shorter than TCP's typical
        /// 2+ hour keep-alive timeout, reflecting UCP's use case as a
        /// real-time transport where stale connections should be detected
        /// quickly.
        /// </remarks>
        public const long DISCONNECT_TIMEOUT_MICROS = 4000000L;

        /// <summary>Default timer interval in milliseconds.</summary>
        /// <remarks>
        /// 1 ms.  The main event loop ticks every millisecond.  This is
        /// aggressive compared to typical TCP stacks (which use 10–200 ms
        /// timers), but necessary for accurate pacing at high data rates
        /// and for sub-millisecond delayed-ACK timers.
        /// </remarks>
        public const int TIMER_INTERVAL_MILLISECONDS = 1;

        /// <summary>Fair queue scheduling round in milliseconds.</summary>
        /// <remarks>
        /// 10 ms.  Multiple connections to the same destination share
        /// bandwidth via fair queuing, with credits distributed every
        /// 10 ms.  This balances responsiveness (frequent scheduling)
        /// against overhead (scheduling 100×/second per connection).
        /// </remarks>
        public const int FAIR_QUEUE_ROUND_MILLISECONDS = 10;

        /// <summary>Default server bandwidth in bytes per second (~100 Mbps).</summary>
        /// <remarks>
        /// 12.5 MB/s.  Conservative default for the server's total
        /// egress capacity.  Individual connections are paced to share
        /// this pool via fair queuing.
        /// </remarks>
        public const int DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND = 100000000 / 8;

        /// <summary>Default initial bandwidth estimate in bytes per second.</summary>
        /// <remarks>
        /// Starts at the server's configured bandwidth.  BBR will adjust
        /// upward or downward based on measured delivery rates.
        /// </remarks>
        public const int DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Default maximum pacing rate in bytes per second.</summary>
        /// <remarks>
        /// Initially set to the server bandwidth.  The pacer will not
        /// exceed this rate unless the BBR bandwidth estimate grows
        /// beyond it.
        /// </remarks>
        public const int DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Maximum congestion window in bytes (64 MB).</summary>
        /// <remarks>
        /// 64 MB.  Absolute upper bound on bytes in flight.  At 1200 B/pkt
        /// and 10 Gbps, 64 MB = ~53 ms of data — enough BDP headroom for
        /// all practical paths.  Even trans-Pacific at 10 Gbps (BDP ≈ 125 MB
        /// at 100 ms RTT) doesn't exceed this because UCP targets sub-10 Gbps.
        /// </remarks>
        public const int DEFAULT_MAX_CONGESTION_WINDOW_BYTES = 64 * 1024 * 1024;

        /// <summary>Default connect timeout in milliseconds.</summary>
        /// <remarks>
        /// 5 s.  The initial SYN/SYN-ACK handshake must complete within
        /// 5 seconds.  This allows for several retransmissions at the
        /// initial RTO (100 ms) with backoff.
        /// </remarks>
        public const int CONNECT_TIMEOUT_MILLISECONDS = 5000;

        /// <summary>Maximum RTT samples retained in diagnostics.</summary>
        /// <remarks>
        /// 1024 samples.  Ring buffer for RTT diagnostics and logging.
        /// At one sample per RTT on a 10 ms path, this holds ~10 seconds
        /// of history.
        /// </remarks>
        public const int MAX_RTT_SAMPLES = 1024;

        /// <summary>Maximum fair-queue credit retained across rounds.</summary>
        /// <remarks>
        /// 2 rounds.  A connection can accumulate at most 2 rounds of
        /// unused fair-queue credit.  This prevents a quiescent connection
        /// from bursting for many seconds when it suddenly becomes active.
        /// </remarks>
        public const int MAX_BUFFERED_FAIR_QUEUE_ROUNDS = 2;

        /// <summary>Minimum sleep interval used by timers and waits in milliseconds.</summary>
        public const int MIN_TIMER_WAIT_MILLISECONDS = 1;

        /// <summary>Handshake retry lower bound in milliseconds.</summary>
        /// <remarks>
        /// 100 ms.  The SYN retransmission timer bottoms out at 100 ms,
        /// preventing SYN floods on lossy access links while still
        /// retrying promptly.
        /// </remarks>
        public const int MIN_HANDSHAKE_WAIT_MILLISECONDS = 100;

        /// <summary>Close wait timeout in milliseconds.</summary>
        /// <remarks>
        /// 1 s.  After sending FIN, wait up to 1 second for the final
        /// ACK before forcibly closing.  This matches the TIME_WAIT
        /// concept but is much shorter because UCP uses connection IDs
        /// for demultiplexing, not 4-tuples.
        /// </remarks>
        public const int CLOSE_WAIT_TIMEOUT_MILLISECONDS = 1000;

        /// <summary>Fallback pacing wait in microseconds when no pacing rate is available.</summary>
        /// <remarks>
        /// 1 ms.  When the pacer has no rate estimate (e.g. right after
        /// connection establishment), it defaults to a 1 ms inter-packet
        /// gap.  This is a safe floor that prevents line-rate bursts
        /// onto unknown paths.
        /// </remarks>
        public const long DEFAULT_PACING_WAIT_MICROS = MICROS_PER_MILLI;

        /// <summary>Logical simulator base port used by tests.</summary>
        public const int SIMULATOR_BASE_PORT = 30000;

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
        public const byte UCP_DATA_TYPE_VALUE = 0x05;

        /// <summary>Encoded UCP SYN packet type value.</summary>
        public const byte UCP_SYN_TYPE_VALUE = 0x01;

        /// <summary>Encoded UCP SYN-ACK packet type value.</summary>
        public const byte UCP_SYN_ACK_TYPE_VALUE = 0x02;

        /// <summary>Encoded UCP ACK packet type value.</summary>
        public const byte UCP_ACK_TYPE_VALUE = 0x03;

        /// <summary>Encoded UCP NAK packet type value.</summary>
        public const byte UCP_NAK_TYPE_VALUE = 0x04;

        /// <summary>Encoded UCP FIN packet type value.</summary>
        public const byte UCP_FIN_TYPE_VALUE = 0x06;

        /// <summary>Encoded UCP FEC repair packet type value.</summary>
        /// <remarks>
        /// 0x08.  FEC is a special data-like packet that carries parity
        /// rather than application payload.  Positioned at 0x08 to group
        /// with data-plane types while remaining distinguishable.
        /// </remarks>
        public const byte UCP_FEC_REPAIR_TYPE_VALUE = 0x08;

        /// <summary>Estimated loss percent threshold for adaptive FEC repair transmission.</summary>
        /// <remarks>
        /// 2%.  When the estimated loss rate reaches 2%, the sender begins
        /// injecting FEC repair packets.  Below 2%, the bandwidth cost of
        /// FEC exceeds the retransmission savings.
        /// </remarks>
        public const double ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT = 2d;

        /// <summary>Encoded UCP RST packet type value.</summary>
        public const byte UCP_RST_TYPE_VALUE = 0x07;

        /// <summary>Encoded empty flags value.</summary>
        public const byte UCP_FLAGS_NONE_VALUE = 0x00;

        /// <summary>Encoded NeedAck packet flag value.</summary>
        /// <remarks>
        /// 0x01 (bit 0).  When set, the receiver should send an ACK
        /// immediately rather than waiting for the delayed-ACK timer.
        /// Used for the last packet in a burst and for handshake packets.
        /// </remarks>
        public const byte UCP_FLAG_NEED_ACK_VALUE = 0x01;

        /// <summary>Encoded Retransmit packet flag value.</summary>
        /// <remarks>
        /// 0x02 (bit 1).  Marks a retransmitted packet, enabling the
        /// receiver to avoid ambiguity when measuring RTT (Karn's algorithm)
        /// and to correctly account for retransmission overhead.
        /// </remarks>
        public const byte UCP_FLAG_RETRANSMIT_VALUE = 0x02;

        /// <summary>Encoded FinAck packet flag value.</summary>
        /// <remarks>
        /// 0x04 (bit 2).  Indicates that a FIN has been acknowledged.
        /// Used during the connection teardown handshake to distinguish
        /// a FIN-ACK from a regular ACK.
        /// </remarks>
        public const byte UCP_FLAG_FIN_ACK_VALUE = 0x04;

        /// <summary>Encoded HasAckNumber packet flag value.</summary>
        /// <remarks>
        /// 0x08 (bit 3).  When set, the packet carries piggybacked ACK
        /// fields after its type-specific header.  This is the mechanism
        /// that enables bidirectional acknowledgment within a single
        /// wire frame — DATA and CONTROL packets can both carry ACK info
        /// when this flag is set.  Bits are spaced by powers of 2 to
        /// allow independent flag combinations.
        /// </remarks>
        public const byte UCP_FLAG_HAS_ACK_VALUE = 0x08;

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
        public static readonly int MAX_ACK_SACK_BLOCKS = (MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 12 — PASCALCASE PUBLIC ALIASES
        //
        //  These provide a C#-idiomatic public surface for external
        //  consumers that prefer PascalCase over UPPER_SNAKE_CASE.
        //  Each alias maps directly to its snake_case counterpart.
        //  Internal code uses the snake_case originals for consistency
        //  with the C++/Rust ports.
        // ═══════════════════════════════════════════════════════════════════

        public const int Mss = MSS;
        public const int CommonHeaderSize = COMMON_HEADER_SIZE;
        public const int DataHeaderSize = DATA_HEADER_SIZE;
        public const int AckFixedSize = ACK_FIXED_SIZE;
        public const int NakFixedSize = NAK_FIXED_SIZE;
        public const int MaxPayloadSize = MAX_PAYLOAD_SIZE;
        public const int DefaultReceiveWindowPackets = DEFAULT_RECV_WINDOW_PACKETS;
        public const uint DefaultReceiveWindowBytes = DEFAULT_RECV_WINDOW_BYTES;
        public const int DefaultInitialCongestionWindow = DEFAULT_INITIAL_CONGESTION_WINDOW;
        public const int DefaultInitialBandwidthBytesPerSecond = DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND;
        public const long MinRtoMicros = MIN_RTO_MICROS;
        public const long MaxRtoMicros = MAX_RTO_MICROS;
        public const long ProbeRttIntervalMicros = BBR_PROBE_RTT_INTERVAL_MICROS;
        public const long ProbeRttDurationMicros = BBR_PROBE_RTT_DURATION_MICROS;
        public const long KeepAliveIntervalMicros = KEEP_ALIVE_INTERVAL_MICROS;
        public const long DisconnectTimeoutMicros = DISCONNECT_TIMEOUT_MICROS;
        public const long TimerIntervalMilliseconds = TIMER_INTERVAL_MILLISECONDS;
        public const int FairQueueRoundMilliseconds = FAIR_QUEUE_ROUND_MILLISECONDS;
        public const int DefaultServerBandwidthBytesPerSecond = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;
        public const int ConnectTimeoutMilliseconds = CONNECT_TIMEOUT_MILLISECONDS;
        public const int MaxRttSamples = MAX_RTT_SAMPLES;
        public const int BbrProbeBwGainCount = BBR_PROBE_BW_GAIN_COUNT;
        public const int MinBbrStartupFullBandwidthRounds = BBR_MIN_STARTUP_FULL_BANDWIDTH_ROUNDS;
        public const double BbrStartupGrowthTarget = BBR_STARTUP_GROWTH_TARGET;
        public const int MaxBufferedFairQueueRounds = MAX_BUFFERED_FAIR_QUEUE_ROUNDS;

        public static readonly int MaxAckSackBlocks = MAX_ACK_SACK_BLOCKS;
    }
}
