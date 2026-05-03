// ====================================================================================================
// PPP PRIVATE NETWORK™ X — Universal Communication Protocol (UCP) / ppp+ucp
// Protocol Control Block (PCB) — Per-connection state machine and protocol engine.
// ====================================================================================================
// UCP is a reliable, in-order, stream-oriented transport protocol operating over
// unreliable datagram transports (UDP).  It combines:
//   - A TCP-style 3-way handshake with cryptographically random Initial Sequence Numbers (ISN)
//   - Cumulative ACK with QUIC-style SACK blocks (each range sent at most 2 times)
//   - NAK-based gap reporting for immediate loss signaling
//   - Duplicate-ACK-triggered fast retransmit (3 DUPACKs → infer loss)
//   - SACK-based fast retransmit for non-leading holes
//   - RTO-based timeout recovery with exponential backoff
//   - Tail-Loss Probe (TLP) for low-inflight scenarios
//   - Silence Probe to detect path blackout faster than full RTO
//   - BBRv1 congestion control (bandwidth estimation, pacing, gain-cycling)
//   - Token-bucket pacing (smooth sends, no bursts)
//   - Optional Fair-Queue credit scheduling (per-connection bandwidth isolation)
//   - Optional Forward Error Correction (FEC) with adaptive repair-send threshold
//   - Piggybacked ACK on data packets to eliminate standalone ACK overhead
//   - Deduplicated loss classification (congestion vs. random) via RTT-inflation detection
//
// Protocol state is protected by <c>_sync</c> — all methods suffixed "Unsafe" MUST be
// called while holding <c>_sync</c>.  Inbound packet dispatch runs on the per-connection
// SerialQueue to avoid lock contention between application API calls and network events.
// ====================================================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Ucp.Transport;

namespace Ucp.Internal
{
    /// <summary>
    /// UCP Protocol Control Block — the per-connection state machine.
    ///
    /// Manages the send buffer (sorted by sequence number), receive reorder buffer,
    /// NAK gap tracking, SACK-based fast retransmit, RTO timer recovery, BBR
    /// congestion control, token-bucket pacing, fair-queue credit, and FEC encoding.
    ///
    /// All protocol state mutation happens under <c>_sync</c> lock.
    /// Inbound packet processing is dispatched through the per-connection
    /// SerialQueue to avoid lock contention between API calls and network events.
    ///
    /// Data delivery to the application fires the DataReceived event when
    /// consecutive in-order segments become available (no batching delay).
    /// </summary>
    internal sealed class UcpPcb : IDisposable
    {
        // ============================================================================================
        // Inner data structures — each models one aspect of the protocol state machine.
        // ============================================================================================

        /// <summary>
        /// Tracks a single outbound data segment in the send buffer (sorted by sequence number).
        ///
        /// Each segment transitions through these states:
        ///   1. Created (InFlight=false, Acked=false) — stored in _sendBuffer, not yet transmitted
        ///   2. InFlight (InFlight=true) — sent to network, consuming _flightBytes budget
        ///   3. NeedsRetransmit — detected as lost via SACK/NAK/DUPACK/RTO, awaiting retransmission
        ///   4. Acked — confirmed received by peer, eligible for garbage collection
        ///
        /// Cold-path fields (SACK tracking) are stored in the separate <see cref="SackTrackingState"/>
        /// class to reduce memory overhead on the hot path — only segments observed as missing in
        /// SACK blocks require this extra state.  See <c>_sackTracking</c>.
        /// </summary>
        private sealed class OutboundSegment
        {
            /// <summary>Sequence number assigned to this segment.</summary>
            public uint SequenceNumber;

            /// <summary>Total fragments in the logical message (1 = single-fragment).</summary>
            public ushort FragmentTotal;

            /// <summary>Zero-based index of this fragment within the message.</summary>
            public ushort FragmentIndex;

            /// <summary>Application payload bytes.</summary>
            public byte[] Payload;

            /// <summary>Whether this segment is currently in flight (sent but not acked).</summary>
            public bool InFlight;

            /// <summary>Whether this segment has been acknowledged by the peer.</summary>
            public bool Acked;

            /// <summary>Whether this segment is marked for retransmission.</summary>
            public bool NeedsRetransmit;

            /// <summary>Number of times transmitted (0 = never sent).</summary>
            public int SendCount;

            /// <summary>Microsecond timestamp of the most recent send.</summary>
            public long LastSendMicros;

            /// <summary>QoS priority level for this segment (Background, Normal, Interactive, Urgent).</summary>
            public UcpPriority Priority;
        }

        /// <summary>
        /// Cold-path state for SACK-based fast retransmit tracking.  Only segments
        /// that are observed as missing in SACK blocks get entries in <c>_sackTracking</c>.
        /// This avoids wasting memory on outbound segments that are never reported as holes.
        /// </summary>
        private sealed class SackTrackingState
        {
            /// <summary>Count of times this segment was seen as missing in SACK blocks.</summary>
            public int MissingAckCount;

            /// <summary>Microsecond timestamp of the first SACK observation for this hole.</summary>
            public long FirstMissingAckMicros;

            /// <summary>True when recovery must bypass smooth pacing to avoid connection death.</summary>
            public bool UrgentRetransmit;
        }

        /// <summary>
        /// Original fragment metadata retained with each FEC-encoded payload.
        /// When a FEC repair packet reconstructs a missing fragment, the codec
        /// needs the original FragmentTotal/FragmentIndex to properly reassemble
        /// the logical message.  This metadata is stored per-sequence when the
        /// original DATA packet is received (even out-of-order), so that FEC
        /// recovery can reconstruct the complete message correctly.
        /// </summary>
        private sealed class FecFragmentMetadata
        {
            /// <summary>Total fragments in the original application message.</summary>
            public ushort FragmentTotal;

            /// <summary>Zero-based fragment index within the original message.</summary>
            public ushort FragmentIndex;
        }

        /// <summary>
        /// Deduplicated loss event tracked for congestion classification.
        ///
        /// The loss classifier distinguishes congestion loss (buffer overrun → RTT inflation)
        /// from random loss (wire corruption, burst interference).  It does this by:
        ///   1. Deduplicating loss events by sequence number within a time window
        ///   2. Measuring the median RTT across all recent loss events
        ///   3. Comparing median RTT to the minimum-observed RTT
        /// If median RTT significantly exceeds min RTT, the loss is classified as congestion.
        /// </summary>
        private sealed class LossEvent
        {
            /// <summary>Sequence number of the lost segment.</summary>
            public uint SequenceNumber;

            /// <summary>Microsecond timestamp of the loss detection.</summary>
            public long TimestampMicros;

            /// <summary>RTT at the time the loss was detected.</summary>
            public long RttMicros;
        }

        /// <summary>
        /// Tracks a received (possibly out-of-order) data segment in the receive buffer.
        ///
        /// Inbound segments are stored in a sorted dictionary keyed by sequence number.
        /// When the next-expected sequence arrives, contiguous segments are drained
        /// in order and delivered to the application via the _receiveQueue.
        /// </summary>
        private sealed class InboundSegment
        {
            /// <summary>Sequence number of this received segment.</summary>
            public uint SequenceNumber;

            /// <summary>Total fragments in the logical message.</summary>
            public ushort FragmentTotal;

            /// <summary>Zero-based index of this fragment.</summary>
            public ushort FragmentIndex;

            /// <summary>Payload bytes received.</summary>
            public byte[] Payload;
        }

        /// <summary>
        /// Chunk of contiguous in-order data ready for application delivery.
        /// The application reads from these chunks via ReceiveAsync(), advancing
        /// Offset until the chunk is exhausted, then dequeuing it.
        /// </summary>
        private sealed class ReceiveChunk
        {
            /// <summary>Buffer containing the data.</summary>
            public byte[] Buffer;

            /// <summary>Current read offset within the buffer.</summary>
            public int Offset;

            /// <summary>Total number of bytes in the buffer.</summary>
            public int Count;
        }

        // ---- Static protocol entropy sources ----

        /// <summary>
        /// Cryptographically secure RNG for connection ID generation.
        /// Connection IDs are 32-bit values (UcpConstants.CONNECTION_ID_SIZE = 4 bytes).
        /// Zero is reserved (never assigned), ensuring every valid connection has a non-zero ID.
        /// </summary>
        private static readonly RandomNumberGenerator ConnectionIdGenerator = RandomNumberGenerator.Create();

        /// <summary>
        /// Cryptographically secure RNG for initial sequence number (ISN) generation.
        /// Like TCP's ISN, UCP starts each connection from a random 32-bit sequence number
        /// to prevent off-path injection attacks against stale connections (RFC 6528).
        /// </summary>
        private static readonly RandomNumberGenerator SequenceRng = RandomNumberGenerator.Create();

        // ---- Core dependencies ----

        /// <summary>
        /// Lock protecting all protocol state mutation.  Every field below this line
        /// that is not readonly must be accessed while holding this lock.  Methods
        /// suffixed "Unsafe" document this contract — callers must hold _sync.
        /// </summary>
        private readonly object _sync = new object();

        /// <summary>Underlying transport for I/O operations (UDP socket wrapper).</summary>
        private readonly ITransport _transport;

        /// <summary>
        /// Whether fair-queue scheduling is enabled for this connection.
        /// Fair-queue credit (_fairQueueCreditBytes) is replenished externally
        /// via AddFairQueueCredit() and consumed per-packet during flush.
        /// </summary>
        private readonly bool _useFairQueue;

        /// <summary>Whether this connection was created server-side (accepted, not initiated).</summary>
        private readonly bool _isServerSide;

        /// <summary>Protocol configuration (cloned from the source to avoid external mutation).</summary>
        private readonly UcpConfiguration _config;

        /// <summary>
        /// Callback invoked when this PCB transitions to Closed state.
        /// Used by UcpNetwork to remove the PCB from its connection table.
        /// </summary>
        private readonly Action<UcpPcb> _closedCallback;

        // ---- Send/receive data structures ----

        /// <summary>
        /// Outbound data segments keyed by sequence number, sorted by the UCP 32-bit
        /// wraparound-aware comparator.  The sorted order enables efficient range scans
        /// for cumulative ACK processing and SACK-based hole detection.
        /// </summary>
        private readonly SortedDictionary<uint, OutboundSegment> _sendBuffer = new SortedDictionary<uint, OutboundSegment>(UcpSequenceComparer.Instance);

        /// <summary>
        /// Received out-of-order data segments keyed by sequence number.
        /// Sorted by UcpSequenceComparer so the receive loop can efficiently locate
        /// the next-expected sequence and drain contiguous in-order data.
        /// </summary>
        private readonly SortedDictionary<uint, InboundSegment> _recvBuffer = new SortedDictionary<uint, InboundSegment>(UcpSequenceComparer.Instance);

        /// <summary>
        /// Queue of in-order data chunks ready for application read.
        /// Each chunk is a byte buffer with an offset pointer; the application
        /// can read a partial chunk, and the remainder stays for the next read.
        /// </summary>
        private readonly Queue<ReceiveChunk> _receiveQueue = new Queue<ReceiveChunk>();

        // ---- NAK and loss tracking ----

        // NAKs (Negative AcKnowledgements) are sent by the receiver to the sender
        // when a gap is detected in the received sequence space.  Unlike SACK (which
        // reports received ranges), NAK explicitly names missing sequences.  The
        // sender uses NAK to trigger retransmission without waiting for RTO.

        /// <summary>
        /// Set of sequence numbers for which a NAK has already been issued.
        /// This suppresses duplicate NAKs within the same RTT window — once a NAK
        /// is sent, the receiver waits for retransmission before re-reporting the gap.
        /// </summary>
        private readonly HashSet<uint> _nakIssued = new HashSet<uint>();

        /// <summary>
        /// Counts how many times each sequence was observed as missing (not in _recvBuffer).
        /// Each packet that creates/extends a gap increments this counter.  The NAK
        /// emission threshold (NAK_MISSING_THRESHOLD) must be reached before a NAK is sent.
        /// </summary>
        private readonly Dictionary<uint, int> _missingSequenceCounts = new Dictionary<uint, int>();

        /// <summary>
        /// First-seen timestamp for each missing sequence (microseconds).
        /// Used to enforce the reorder-grace period — a gap must persist for at
        /// least the adaptive grace interval before it's considered a true loss.
        /// </summary>
        private readonly Dictionary<uint, long> _missingFirstSeenMicros = new Dictionary<uint, long>();

        /// <summary>
        /// Last-NAK-issued timestamp for each sequence (microseconds).
        /// Rate-limits NAK emission: a sequence cannot be NAKed more than once
        /// per RTT regardless of _nakIssued state.
        /// </summary>
        private readonly Dictionary<uint, long> _lastNakIssuedMicros = new Dictionary<uint, long>();

        /// <summary>
        /// Sequences for which SACK-based fast retransmit has already been triggered.
        /// Prevents duplicate fast-retransmit notifications for the same loss event.
        /// </summary>
        private readonly HashSet<uint> _sackFastRetransmitNotified = new HashSet<uint>();

        /// <summary>
        /// QUIC-style SACK send count tracking per block range.  Each SACK range
        /// (identified by a packed (start<<32|end) key) is sent at most 2 times
        /// (MAX_SACK_SEND_COUNT).  After 2 sends, the range is dropped from future
        /// ACKs — the peer should have acted on it by then.  This bounds memory
        /// usage and prevents stale SACK accumulation.
        /// </summary>
        private readonly Dictionary<ulong, int> _sackBlockSendCounts = new Dictionary<ulong, int>();

        /// <summary>
        /// Cold-path SACK tracking state keyed by sequence number.  Only segments observed
        /// as SACK holes receive entries here — avoids allocating MissingAckCount,
        /// FirstMissingAckMicros, and UrgentRetransmit on the hot-path OutboundSegment.
        /// </summary>
        private readonly Dictionary<uint, SackTrackingState> _sackTracking = new Dictionary<uint, SackTrackingState>();

        /// <summary>Maximum number of times each SACK block range can be sent (QUIC standard: 2).</summary>
        private const int MAX_SACK_SEND_COUNT = 2;

        /// <summary>
        /// FEC groups for which repair packets have been sent.  Once a group's
        /// repair packets are transmitted, SACK-based fast retransmit for that
        /// group is suppressed during the FEC repair grace period, giving FEC
        /// a chance to recover without redundant retransmission.
        /// </summary>
        private readonly HashSet<uint> _fecRepairSentGroups = new HashSet<uint>();

        /// <summary>
        /// Fragment metadata for DATA packets whose payloads are covered by FEC repair.
        /// Keyed by the original data sequence number; needed so that FEC-recovered
        /// payloads can be associated with the correct FragmentTotal/FragmentIndex
        /// for message reassembly.
        /// </summary>
        private readonly Dictionary<uint, FecFragmentMetadata> _fecFragmentMetadata = new Dictionary<uint, FecFragmentMetadata>();

        // ---- FEC ----

        /// <summary>
        /// Forward Error Correction (FEC) encoder/decoder.  Null if FEC is disabled
        /// (FecRedundancy <= 0 or FecGroupSize <= 1 in configuration).
        ///
        /// FEC operates on groups of FecGroupSize consecutive data packets.  When the
        /// group is complete, FecRedundancy * FecGroupSize repair packets are generated
        /// and (if loss exceeds the adaptive threshold) transmitted.  The receiver can
        /// reconstruct any missing original from any combination of data + repair packets.
        /// </summary>
        private UcpFecCodec _fecCodec;

        /// <summary>Base sequence number of the current FEC group being built.</summary>
        private uint _fecGroupBaseSeq;

        /// <summary>Number of data packets sent in the current FEC group (resets each group).</summary>
        private int _fecGroupSendCount;

        // ---- Async coordination ----

        /// <summary>
        /// Signal released when new data is available for ReceiveAsync.  The semaphore
        /// count mirrors the number of ReceiveChunks available in _receiveQueue.
        /// This avoids polling and enables efficient async waiting.
        /// </summary>
        private readonly SemaphoreSlim _receiveSignal = new SemaphoreSlim(0, int.MaxValue);

        /// <summary>
        /// Signal released when send buffer space frees up (segments are ACKed and
        /// removed).  WriteAsync() callers wait on this when the buffer is full.
        /// </summary>
        private readonly SemaphoreSlim _sendSpaceSignal = new SemaphoreSlim(0, int.MaxValue);

        /// <summary>
        /// Lock ensuring only one flush operation runs at a time.  Multiple concurrent
        /// FlushSendQueueAsync() calls are serialized by this semaphore, preventing
        /// duplicate transmission of the same segments.
        /// </summary>
        private readonly SemaphoreSlim _flushLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Cancellation token for all async operations on this PCB.
        /// Canceled on Dispose() or TransitionToClosed(), unblocking all waiters.
        /// </summary>
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        /// <summary>
        /// Completes when the connection handshake succeeds (true) or fails (false).
        /// ConnectAsync() awaits this TCS to determine handshake outcome.
        /// </summary>
        private readonly TaskCompletionSource<bool> _connectedTcs = new TaskCompletionSource<bool>();

        /// <summary>
        /// Completes when the connection is fully closed.  CloseAsync() awaits
        /// this TCS to know when the peer has acknowledged the FIN.
        /// </summary>
        private readonly TaskCompletionSource<bool> _closedTcs = new TaskCompletionSource<bool>();

        // ---- Protocol engines ----

        /// <summary>
        /// Generates SACK blocks from the receive buffer.  When the receive buffer
        /// contains holes (gaps), the SACK generator produces a compact list of
        /// [Start, End] ranges describing the received segments beyond the cumulative
        /// ACK point.  This is analogous to TCP SACK (RFC 2018) / QUIC ACK ranges.
        /// </summary>
        private readonly UcpSackGenerator _sackGenerator = new UcpSackGenerator();

        /// <summary>
        /// RTO estimator (RFC 6298 style).  Maintains SmoothedRTT (SRTT), RTT
        /// variation (RTTVAR), and computes the Retransmission Timeout (RTO).
        /// Supports exponential backoff on RTO-triggered loss events.
        /// </summary>
        private readonly UcpRtoEstimator _rtoEstimator;

        /// <summary>
        /// BBRv1 congestion control engine.  Cycles through probing bandwidth,
        /// draining the queue, and probing RTT floor.  Computes pacing rate,
        /// congestion window, and estimated loss percent.  Receives notifications
        /// for ACKs, packet sends, losses, and fast retransmits.
        /// </summary>
        private readonly BbrCongestionControl _bbr;

        /// <summary>
        /// Token-bucket pacing controller.  Enforces the BBR-computed pacing rate
        /// by maintaining a token bucket.  Each packet sent consumes tokens equal
        /// to the packet size.  When tokens are insufficient, FlushSendQueueAsync
        /// schedules a delayed flush for when tokens will be available.
        /// </summary>
        private readonly PacingController _pacing;

        /// <summary>
        /// Optional .NET Timer for standalone mode (null when using UcpNetwork).
        /// In standalone mode, the timer fires at TimerIntervalMilliseconds to
        /// drive RTO checks, keep-alive, and NAK collection.
        /// </summary>
        private readonly Timer _timer;

        /// <summary>Network engine reference (null in standalone mode), used for timer scheduling.</summary>
        private readonly UcpNetwork _network;

        // ---- Connection state ----

        /// <summary>
        /// Current connection state machine state.  Transitions follow:
        ///   Init → HandshakeSynSent (client) or HandshakeSynReceived (server)
        ///        → Established → ClosingFinSent / ClosingFinReceived → Closed
        /// </summary>
        private UcpConnectionState _state;

        /// <summary>Remote endpoint of this connection (IP + port).</summary>
        private IPEndPoint _remoteEndPoint;

        /// <summary>
        /// Unique connection identifier assigned by cryptographically secure RNG.
        /// All packets on this connection carry this ID in the header.
        /// </summary>
        private uint _connectionId;

        /// <summary>
        /// Next sequence number to assign to an outbound data segment.
        /// Starts from a cryptographically random ISN (NextSequence()) and
        /// increments monotonically (with 32-bit wraparound).
        /// </summary>
        private uint _nextSendSequence;

        /// <summary>
        /// Next in-order sequence number expected from the peer (the "rcv_nxt").
        /// Packets with sequence < _nextExpectedSequence are duplicates;
        /// packets with sequence > _nextExpectedSequence create a gap.
        /// </summary>
        private uint _nextExpectedSequence;

        /// <summary>
        /// Peer-advertised receive window in bytes.  Controls the maximum amount
        /// of unacknowledged data the sender may have in flight.  Updated by ACKs
        /// and piggybacked window advertisements.
        /// </summary>
        private uint _remoteWindowBytes = UcpConstants.DefaultReceiveWindowBytes;

        /// <summary>
        /// Current bytes in flight (sent but not yet acknowledged).  The sender
        /// must respect min(_bbr.CongestionWindowBytes, _remoteWindowBytes).
        /// Decremented when segments are ACKed; incremented when new/retransmitted
        /// segments are sent.
        /// </summary>
        private int _flightBytes;

        /// <summary>
        /// Accumulated fair-queue credit in bytes; consumed during sends.
        /// Replenished externally by the network scheduler (AddFairQueueCredit).
        /// When credit is exhausted and no urgent retransmit is pending, the
        /// send loop breaks until more credit arrives.
        /// </summary>
        private double _fairQueueCreditBytes;

        /// <summary>Last echo timestamp received from the peer (for echo-based RTT measurement).</summary>
        private long _lastEchoTimestamp;

        /// <summary>
        /// Timestamp of the last protocol activity (send or receive), in microseconds.
        /// Used for keep-alive and disconnect timeout detection.
        /// </summary>
        private long _lastActivityMicros;

        /// <summary>Timestamp of the last ACK packet sent (microseconds).</summary>
        private long _lastAckSentMicros;

        /// <summary>Most recent accepted RTT sample in microseconds.</summary>
        private long _lastRttMicros;

        // ---- Handshake / close flags ----

        /// <summary>
        /// Whether a SYN has been sent.  The UCP 3-way handshake:
        ///   1. Client → Server: SYN(ISN_c)
        ///   2. Server → Client: SYN-ACK(ISN_s, ACK=ISN_c)
        ///   3. Client → Server: ACK(ISN_s)
        /// After step 3, both sides transition to Established.
        /// </summary>
        private bool _synSent;

        /// <summary>Whether a SYN-ACK has been sent (server side, step 2 of handshake).</summary>
        private bool _synAckSent;

        /// <summary>Timestamp of the most recent SYN-ACK send (for RTO-driven retransmission).</summary>
        private long _synAckSentMicros;

        /// <summary>Whether a FIN has been sent (graceful close initiated).</summary>
        private bool _finSent;

        /// <summary>Whether the FIN has been acknowledged by the peer (FIN-ACK received).</summary>
        private bool _finAcked;

        /// <summary>Whether a FIN was received from the peer.</summary>
        private bool _peerFinReceived;

        /// <summary>Whether a RST was received from the peer (abrupt close).</summary>
        private bool _rstReceived;

        // ---- Lifecycle ----

        /// <summary>Whether this PCB has been disposed (prevents double-dispose).</summary>
        private bool _disposed;

        /// <summary>Largest microsecond timestamp seen from the peer across all valid packets, used for PAWS (Protection Against Wrapped Sequences).</summary>
        private long _largestTimestampSeen; // Tracks most recent packet timestamp for PAWS validation

        /// <summary>Whether PAWS timestamp validation is active (default true).  Disabled only for testing.</summary>
        private bool _pawsEnabled = true; // Protection Against Wrapped Sequences — rejects stale packets >60s behind largest seen timestamp

        /// <summary>Whether a delayed flush has been scheduled (avoids duplicate scheduling).</summary>
        private bool _flushDelayed;

        /// <summary>Whether a delayed ACK has been scheduled (avoids duplicate ACK timers).</summary>
        private bool _ackDelayed;

        /// <summary>Timer ID from the network engine (0 if not scheduled).</summary>
        private uint _timerId;

        /// <summary>Timer ID for the delayed flush (0 if not scheduled).</summary>
        private uint _flushTimerId;

        /// <summary>
        /// Whether the Connected event has been raised.  Ensures the event fires
        /// exactly once per connection lifetime, even if multiple packets trigger
        /// the Established transition.
        /// </summary>
        private bool _connectedRaised;

        /// <summary>
        /// Whether the Disconnected event has been raised.  Ensures the event fires
        /// exactly once per connection lifetime.
        /// </summary>
        private bool _disconnectedRaised;

        /// <summary>Whether cleanup resources (network registration, timers) have been released.</summary>
        private bool _closedResourcesReleased;

        /// <summary>Whether the underlying network path has changed (e.g., NAT rebinding, mobile handover).</summary>
        private bool _pathChanged;

        // ---- Duplicate ACK tracking ----

        // UCP's fast retransmit algorithm uses duplicate ACK counting (like TCP):
        //   1. The first ACK for a sequence is normal
        //   2. If the same cumulative ACK number arrives again (duplicate), it means
        //      a later packet arrived but the expected one is missing
        //   3. After DUPLICATE_ACK_THRESHOLD (3) duplicate ACKs, the next sequence
        //      after the cumulative ACK is inferred lost and fast-retransmitted

        /// <summary>Largest cumulative ACK number seen so far (monotonic, never recedes).</summary>
        private uint _largestCumulativeAckNumber;

        /// <summary>Whether _largestCumulativeAckNumber has been set.</summary>
        private bool _hasLargestCumulativeAckNumber;

        /// <summary>Last ACK number received (for duplicate ACK detection).</summary>
        private uint _lastAckNumber;

        /// <summary>Whether _lastAckNumber has been set.</summary>
        private bool _hasLastAckNumber;

        /// <summary>
        /// Count of consecutive duplicate ACKs received.
        /// Reset to 0 when a non-duplicate ACK arrives (cumulative ACK advances).
        /// When this reaches DUPLICATE_ACK_THRESHOLD, fast retransmit triggers.
        /// </summary>
        private int _duplicateAckCount;

        /// <summary>
        /// Whether fast recovery is currently active.  During fast recovery, further
        /// duplicate ACKs do not trigger additional fast retransmits for the same loss.
        /// Exits when a non-duplicate ACK arrives.
        /// </summary>
        private bool _fastRecoveryActive;

        // ---- Receive window ----

        /// <summary>Local receive window size in bytes advertised to the peer.</summary>
        private uint _localReceiveWindowBytes = UcpConstants.DefaultReceiveWindowBytes;

        /// <summary>Bytes currently queued for application delivery (in _receiveQueue).</summary>
        private int _queuedReceiveBytes;

        // ---- Counters ----

        /// <summary>Cumulative user payload bytes sent.</summary>
        private long _bytesSent;

        /// <summary>Cumulative user payload bytes received.</summary>
        private long _bytesReceived;

        /// <summary>Count of original (first-transmission) data packets transmitted.</summary>
        private int _sentDataPackets;

        /// <summary>Count of retransmitted data packets.</summary>
        private int _retransmittedPackets;

        /// <summary>Count of ACK packets transmitted.</summary>
        private int _sentAckPackets;

        /// <summary>Count of NAK packets transmitted.</summary>
        private int _sentNakPackets;

        /// <summary>Count of RST packets transmitted.</summary>
        private int _sentRstPackets;

        /// <summary>Count of fast retransmissions (SACK or DUPACK triggered).</summary>
        private int _fastRetransmissions;

        /// <summary>Count of RTO-triggered retransmissions.</summary>
        private int _timeoutRetransmissions;

        // ---- RTT sample history ----

        /// <summary>
        /// Retained RTT samples for diagnostics and minimum-RTT computation.
        /// Bounded at MaxRttSamples entries (oldest dropped first).
        /// The minimum value in this list is used by the loss classifier
        /// as the baseline propagation RTT to detect congestion inflation.
        /// </summary>
        private readonly List<long> _rttSamplesMicros = new List<long>();

        // ---- NAK rate limiting ----

        /// <summary>
        /// Start timestamp of the current NAK rate-limit window.  Within each
        /// SRTT-duration window, at most MAX_NAKS_PER_RTT NAK packets may be sent.
        /// This prevents NAK storms during sustained loss events.
        /// </summary>
        private long _lastNakWindowMicros;

        /// <summary>Number of NAKs sent in the current RTT window.</summary>
        private int _naksSentThisRttWindow;

        // ---- Delayed ACK / reordering ----

        /// <summary>Timestamp of the last ACK received (for tail-loss probe detection).</summary>
        private long _lastAckReceivedMicros;

        /// <summary>Timestamp of the last reordered-data ACK sent (throttles immediate ACKs).</summary>
        private long _lastReorderedAckSentMicros;

        /// <summary>
        /// Whether a tail-loss probe has been armed (but not yet retransmitted).
        /// TLP fires when inflight is low and no ACK arrives within TLP_TIMEOUT_RTT_RATIO * SRTT.
        /// Once armed, only one retransmit occurs until an ACK arrives.
        /// </summary>
        private bool _tailLossProbePending;

        // ---- Loss classification ----

        /// <summary>
        /// Queue of recent deduplicated loss events for congestion classification.
        /// Each loss event records the sequence number, timestamp, and RTT at time of
        /// detection.  Events are pruned when they fall outside the classification window.
        /// </summary>
        private readonly Queue<LossEvent> _recentLossEvents = new Queue<LossEvent>();

        /// <summary>
        /// Hash set of recent loss sequence numbers for fast O(1) deduplication.
        /// A loss is only counted once within the classification window.
        /// </summary>
        private readonly HashSet<uint> _recentLossSequences = new HashSet<uint>();

        /// <summary>
        /// Start timestamp of the current urgent recovery budget window.
        /// Within each SRTT window, at most URGENT_RETRANSMIT_BUDGET_PER_RTT
        /// urgent retransmits (bypassing pacing) are allowed.
        /// </summary>
        private long _urgentRecoveryWindowMicros;

        /// <summary>Number of urgent recovery packets sent in the current RTT window.</summary>
        private int _urgentRecoveryPacketsInWindow;

        // ---- Constructors ----

        /// <summary>
        /// Creates a PCB with an optional connection ID and null network (standalone mode).
        /// Delegates to the full constructor with network=null.
        /// </summary>
        /// <param name="transport">Underlying ITransport for I/O.</param>
        /// <param name="remoteEndPoint">Remote endpoint.</param>
        /// <param name="isServerSide">Whether this is an accepted server-side connection.</param>
        /// <param name="useFairQueue">Whether fair-queue scheduling is enabled.</param>
        /// <param name="closedCallback">Callback invoked on transition to Closed.</param>
        /// <param name="connectionId">Optional explicit connection ID (null = generate random).</param>
        /// <param name="config">Protocol configuration.</param>
        public UcpPcb(ITransport transport, IPEndPoint remoteEndPoint, bool isServerSide, bool useFairQueue, Action<UcpPcb> closedCallback, uint? connectionId, UcpConfiguration config)
            : this(transport, remoteEndPoint, isServerSide, useFairQueue, closedCallback, connectionId, config, null) // Delegate to full constructor with network=null (standalone mode)
        {
        }

        /// <summary>
        /// Full constructor: initializes all sub-components and schedules the first timer.
        ///
        /// Sub-component initialization:
        ///   - UcpRtoEstimator: RFC 6298 RTO computation (SRTT + 4*RTTVAR, with backoff)
        ///   - BbrCongestionControl: BBRv1 state machine (Startup/Drain/ProbeBW/ProbeRTT)
        ///   - PacingController: Token-bucket rate enforcement at BBR-computed pacing rate
        ///   - UcpFecCodec: Reed-Solomon-style FEC codec (initialized iff FecRedundancy > 0
        ///     and FecGroupSize > 1)
        ///
        /// Timer strategy:
        ///   - Standalone mode (network == null): Creates a .NET Timer firing at
        ///     TimerIntervalMilliseconds.  Each tick runs OnTimerAsync to check RTO,
        ///     keep-alive, and NAK collection.
        ///   - Network-managed mode: Registers with UcpNetwork which drives all
        ///     PCB timers from its own event loop, avoiding per-connection .NET timers.
        ///
        /// Initial state:
        ///   - _state = Init (pre-handshake)
        ///   - _nextSendSequence = cryptographically random ISN (prevents off-path injection)
        ///   - _lastActivityMicros / _lastAckSentMicros = current time
        ///   - Windows initialized from configuration
        /// </summary>
        /// <param name="transport">Underlying transport.</param>
        /// <param name="remoteEndPoint">Remote endpoint.</param>
        /// <param name="isServerSide">Whether server-side.</param>
        /// <param name="useFairQueue">Whether fair-queue enabled.</param>
        /// <param name="closedCallback">Closed-state callback.</param>
        /// <param name="connectionId">Optional connection ID.</param>
        /// <param name="config">Protocol configuration.</param>
        /// <param name="network">Network engine (null = standalone).</param>
        public UcpPcb(ITransport transport, IPEndPoint remoteEndPoint, bool isServerSide, bool useFairQueue, Action<UcpPcb> closedCallback, uint? connectionId, UcpConfiguration config, UcpNetwork network)
        {
            _transport = transport; // Store the underlying UDP transport for I/O
            _remoteEndPoint = remoteEndPoint; // Record the peer's IP address and port
            _isServerSide = isServerSide; // True if this is an accepted (server) connection
            _useFairQueue = useFairQueue; // True if fair-queue credit scheduling is active
            _config = config ?? new UcpConfiguration(); // Clone or default: prevent external config mutation
            _network = network; // Network engine reference (null = standalone mode)
            _closedCallback = closedCallback; // Callback invoked when this PCB transitions to Closed state
            // Generate a cryptographically random connection ID (zero is reserved — retry until non-zero).
            _connectionId = connectionId ?? NextConnectionId(); // Use provided ID or generate cryptographically random one
            _rtoEstimator = new UcpRtoEstimator(_config); // RFC 6298 RTO computation: SRTT + 4*RTTVAR with exponential backoff
            _bbr = new BbrCongestionControl(_config); // BBRv1 congestion control: Startup/Drain/ProbeBW/ProbeRTT states
            // Start pacing at the configured initial bandwidth so early sends are not blocked.
            _pacing = new PacingController(_config, _config.InitialBandwidthBytesPerSecond); // Token-bucket pacer seeded with initial bandwidth
            if (_config.FecRedundancy > 0d && _config.FecGroupSize > 1) // FEC is enabled only when redundancy > 0 and group size > 1
            {
                int fecRepairCount = Math.Max(1, (int)Math.Ceiling(_config.FecGroupSize * _config.FecRedundancy)); // Compute number of repair packets per group: ceil(groupSize * redundancy)
                _fecCodec = new UcpFecCodec(_config.FecGroupSize, fecRepairCount); // Reed-Solomon-style FEC encoder/decoder
            }

            // Initialize state: pre-handshake, random ISN, snapshot current time.
            _state = UcpConnectionState.Init; // All connections start in Init (pre-handshake) state
            _nextSendSequence = NextSequence(); // Generate cryptographically random ISN (RFC 6528 anti-injection protection)
            _lastActivityMicros = NowMicros(); // Seed activity timestamp to start of connection (prevents premature disconnect timeout)
            _lastAckSentMicros = _lastActivityMicros; // Sync ACK sent timestamp with activity start
            _remoteWindowBytes = _config.ReceiveWindowBytes; // Initialize peer's advertised receive window from config
            _localReceiveWindowBytes = _config.ReceiveWindowBytes; // Initialize local receive window from config
            if (_network == null) // Standalone mode: no UcpNetwork engine available
            {
                // Standalone mode: use a .NET Timer.
                _timer = new Timer(OnTimer, null, _config.TimerIntervalMilliseconds, _config.TimerIntervalMilliseconds); // Create repeating .NET Timer for RTO, keep-alive, NAK
            }
            else // Network-managed mode: UcpNetwork drives all PCB timers
            {
                // Network-managed mode: register with the network and schedule via network timers.
                _network.RegisterPcb(this); // Register this PCB so network can dispatch packets and timer events to it
                ScheduleTimer(); // Schedule the first timer tick through the network engine
            }
        }

        // ---- Events ----

        /// <summary>
        /// Raised when new in-order data is available for application delivery.
        /// Fired synchronously during EnqueuePayload() — the handler receives
        /// (buffer, offset, count) for each contiguous data chunk.
        /// </summary>
        public event Action<byte[], int, int> DataReceived;

        /// <summary>
        /// Raised when the connection handshake completes successfully (both
        /// sides have acknowledged each other's SYN).  The connection is now
        /// Established and data can be sent/received.
        /// </summary>
        public event Action Connected;

        /// <summary>
        /// Raised when the connection is fully closed (FIN exchanged and acknowledged,
        /// or RST received, or timeout).  After this fires, the PCB must not be used.
        /// </summary>
        public event Action Disconnected;

        // ---- Public properties ----

        /// <summary>Unique connection identifier (cryptographically random 32-bit value).</summary>
        public uint ConnectionId
        {
            get { return _connectionId; } // Return the cryptographically random 32-bit connection ID
        }

        /// <summary>Remote endpoint of this connection (IP address + UDP port).</summary>
        public IPEndPoint RemoteEndPoint
        {
            get { return _remoteEndPoint; } // Return the peer's IP address and port
        }

        /// <summary>Current connection state, thread-safe (acquires _sync lock on read).</summary>
        public UcpConnectionState State
        {
            get { lock (_sync) { return _state; } } // Thread-safe read: acquire protocol lock, return current state atomically
        }

        /// <summary>Current pacing rate from the BBR controller in bytes/sec, thread-safe.</summary>
        public double CurrentPacingRateBytesPerSecond
        {
            get { lock (_sync) { return _bbr.PacingRateBytesPerSecond; } } // Thread-safe: return BBR pacing rate under protocol lock
        }

        /// <summary>Whether the send buffer contains unsent segments, thread-safe.</summary>
        public bool HasPendingSendData
        {
            get { lock (_sync) { return _sendBuffer.Count > 0; } } // Thread-safe: check if any segments remain in send buffer
        }

        /// <summary>
        /// Creates a snapshot of all diagnostic counters and state for reporting.
        /// Captured under _sync lock for consistency — all counters are read atomically
        /// within a single critical section so the snapshot is self-consistent.
        /// </summary>
        /// <returns>An immutable snapshot of the current diagnostics.</returns>
        public UcpConnectionDiagnostics GetDiagnosticsSnapshot()
        {
            lock (_sync) // Acquire protocol lock for consistent snapshot of all counters
            {
                UcpConnectionDiagnostics diagnostics = new UcpConnectionDiagnostics(); // Create new immutable snapshot container
                diagnostics.State = _state; // Current connection state machine state
                diagnostics.FlightBytes = _flightBytes; // Bytes in flight (sent but not yet ACKed)
                diagnostics.RemoteWindowBytes = _remoteWindowBytes; // Peer's advertised receive window
                diagnostics.BytesSent = _bytesSent; // Cumulative user payload bytes sent over connection lifetime
                diagnostics.BytesReceived = _bytesReceived; // Cumulative user payload bytes received over connection lifetime
                diagnostics.SentDataPackets = _sentDataPackets; // Count of original (non-retransmit) data packets
                diagnostics.RetransmittedPackets = _retransmittedPackets; // Count of retransmitted data packets
                diagnostics.SentAckPackets = _sentAckPackets; // Count of standalone ACK packets sent
                diagnostics.SentNakPackets = _sentNakPackets; // Count of NAK packets sent
                diagnostics.SentRstPackets = _sentRstPackets; // Count of RST (reset) packets sent
                diagnostics.FastRetransmissions = _fastRetransmissions; // Count of SACK/DUPACK-triggered fast retransmissions
                diagnostics.TimeoutRetransmissions = _timeoutRetransmissions; // Count of RTO-triggered retransmissions
                diagnostics.CongestionWindowBytes = _bbr.CongestionWindowBytes; // Current BBR congestion window in bytes
                diagnostics.PacingRateBytesPerSecond = _bbr.PacingRateBytesPerSecond; // Current BBR-computed pacing rate
                diagnostics.EstimatedLossPercent = _bbr.EstimatedLossPercent; // BBR estimated loss percentage
                diagnostics.LastRttMicros = _lastRttMicros; // Most recently measured RTT in microseconds
                // Copy RTT samples to avoid exposing mutable list.
                diagnostics.RttSamplesMicros.AddRange(_rttSamplesMicros); // Shallow-copy RTT sample history into snapshot
                diagnostics.ReceivedReset = _rstReceived; // Whether a RST was received from the peer
                diagnostics.CurrentNetworkClass = (int)_bbr.CurrentNetworkClass; // BBR network path classification (e.g., cellular, ethernet)

                int bufferedBytes = 0; // Accumulator for buffered receive bytes across all chunks
                foreach (ReceiveChunk chunk in _receiveQueue) // Iterate receive queue to sum unread bytes
                {
                    bufferedBytes += chunk.Count - chunk.Offset; // Unread bytes remaining in each chunk
                }

                diagnostics.BufferedReceiveBytes = bufferedBytes; // Total bytes buffered awaiting application read
                return diagnostics; // Return the self-consistent snapshot
            }
        }

        /// <summary>
        /// Aborts the connection immediately.  Optionally sends a RST (reset) packet
        /// to the peer before closing, allowing the peer to clean up resources
        /// rather than waiting for a timeout.
        /// </summary>
        /// <param name="sendReset">If true, sends a RST packet to the peer before closing.</param>
        public void Abort(bool sendReset)
        {
            if (sendReset && _remoteEndPoint != null) // Only send RST if requested and we have a known remote endpoint
            {
                // RST with no flags — peer can distinguish from graceful FIN close.
                SendControl(UcpPacketType.Rst, UcpPacketFlags.None); // Fire-and-forget RST packet to notify peer of abrupt close
            }

            TransitionToClosed(); // Immediately transition to Closed state (tears down all resources)
        }

        /// <summary>
        /// Test hook: overrides the next send sequence number.
        /// Used by unit tests to control sequence number assignment for deterministic testing.
        /// </summary>
        public void SetNextSendSequenceForTest(uint nextSendSequence)
        {
            lock (_sync) // Acquire protocol lock since _nextSendSequence is protocol state
            {
                _nextSendSequence = nextSendSequence; // Override next send sequence number for deterministic testing
            }
        }

        /// <summary>
        /// Test hook: overrides the advertised receive window.
        /// Used by unit tests to simulate constrained receiver scenarios.
        /// </summary>
        public void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            lock (_sync) // Acquire protocol lock for safe write to receive window
            {
                _localReceiveWindowBytes = windowBytes; // Override local receive window for constrained receiver test scenarios
            }
        }

        /// <summary>
        /// Sets or updates the remote endpoint for this connection.
        /// Must be called under _sync lock to prevent race conditions.
        /// </summary>
        public void SetRemoteEndPoint(IPEndPoint remoteEndPoint)
        {
            lock (_sync) // Acquire protocol lock for safe write to remote endpoint
            {
                _remoteEndPoint = remoteEndPoint; // Update the peer's IP and port (used for IP-agnostic rebinding)
            }
        }

        /// <summary>
        /// Validates that the given remote endpoint matches the current one.
        /// If the current endpoint is null, accepts the new one (first packet).
        /// For IP-agnostic connections, accepts and updates to new endpoints
        /// (supports NAT rebinding and client IP changes).
        ///
        /// This enables UCP's IP-agnostic connection model: after the initial
        /// handshake, subsequent packets may arrive from a different IP/port
        /// (e.g., mobile device switching between WiFi and cellular).  UCP
        /// validates the connection ID, not the IP address.
        /// </summary>
        /// <returns>True if the endpoint is valid for this connection.</returns>
        public bool ValidateRemoteEndPoint(IPEndPoint remoteEndPoint)
        {
            if (remoteEndPoint == null) // Null endpoint is never valid
            {
                return false; // Reject null immediately — caller error
            }

            lock (_sync) // Acquire protocol lock for safe access to _remoteEndPoint
            {
                if (_remoteEndPoint == null) // No endpoint set yet (first packet arriving)
                {
                    // First packet — accept unconditionally.
                    _remoteEndPoint = remoteEndPoint; // Record the first observed endpoint as the peer
                    return true; // Accept unconditionally (no prior endpoint to compare against)
                }

                if (_remoteEndPoint.Equals(remoteEndPoint)) // Address and port match exactly
                {
                    return true; // Same endpoint — no rebinding needed
                }

                // IP-agnostic: accept new endpoint (client changed port/IP).
                // The connection ID in the packet header is the true identity.
                _remoteEndPoint = remoteEndPoint; // Update to new endpoint (NAT rebinding, WiFi→cellular handoff)
                // Signal to the congestion controller that the path may have changed.
                if (_state == UcpConnectionState.Established)
                {
                    _pathChanged = true; // Mark path as changed; CC adapts on next ACK/timer tick
                }
                return true; // Accept the new endpoint under IP-agnostic model
            }
        }

        /// <summary>
        /// Performs the UCP SYN handshake: sends SYN, waits for SYN-ACK with
        /// exponential backoff, up to the configured connect timeout.
        ///
        /// UCP 3-way handshake with random ISN:
        ///   1. Client generates a cryptographically random ISN_c via NextSequence()
        ///      and sends SYN(seq=ISN_c) to the server.  The ISN is stored in
        ///      _nextSendSequence.
        ///   2. Server receives SYN, records the client's sequence, generates its own
        ///      random ISN_s, and replies SYN-ACK(seq=ISN_s, ack=ISN_c).
        ///   3. Client receives SYN-ACK, processes the piggybacked ACK, sends an ACK
        ///      for ISN_s, and transitions to Established.
        ///
        /// The random ISN prevents blind off-path injection attacks (RFC 6528).
        /// An attacker who cannot observe the ISN cannot inject valid data packets
        /// because all sequence numbers must be within the receiver's window.
        ///
        /// Retransmission strategy:
        ///   - SYN is retransmitted at RTO intervals (minimum MinRto)
        ///   - After each send, waits max(RTO_min, current_RTO) before resending
        ///   - Continues until _connectedTcs completes or deadline expires
        /// </summary>
        /// <param name="remoteEndPoint">The remote endpoint to connect to.</param>
        /// <exception cref="TimeoutException">If handshake does not complete within ConnectTimeoutMilliseconds.</exception>
        public async Task ConnectAsync(IPEndPoint remoteEndPoint)
        {
            SetRemoteEndPoint(remoteEndPoint); // Record the target server endpoint (IP + port)
            lock (_sync) // Acquire protocol lock for safe state transition
            {
                if (_state == UcpConnectionState.Established) // Check if already connected (idempotent)
                {
                    return; // Already connected — idempotent.
                }

                _state = UcpConnectionState.HandshakeSynSent; // Transition to SYN-sent state (step 1 of 3-way handshake)
                _synSent = true; // Mark SYN as sent so HandleSynAck knows we initiated
            }

            long deadlineMicros = NowMicros() + (_config.ConnectTimeoutMilliseconds * UcpConstants.MICROS_PER_MILLI); // Compute absolute deadline for handshake timeout
            while (NowMicros() < deadlineMicros) // Loop until deadline or handshake completes
            {
                // Send SYN carrying our ISN (_nextSendSequence).
                SendControl(UcpPacketType.Syn, UcpPacketFlags.None); // Transmit SYN with our randomly generated ISN
                int waitMilliseconds; // Time to wait before retransmitting SYN
                lock (_sync) // Acquire protocol lock to read current RTO
                {
                    // Wait at least MIN_HANDSHAKE_WAIT_MILLISECONDS, otherwise the
                    // current RTO (which may be very small before any samples).
                    waitMilliseconds = (int)Math.Max(UcpConstants.MIN_HANDSHAKE_WAIT_MILLISECONDS, _rtoEstimator.CurrentRtoMicros / UcpConstants.MICROS_PER_MILLI); // Use max of minimum wait and current RTO for backoff
                }

                Task completed = await Task.WhenAny(_connectedTcs.Task, Task.Delay(waitMilliseconds, _cts.Token)).ConfigureAwait(false); // Race: completion vs timeout — whichever finishes first
                if (completed == _connectedTcs.Task) // _connectedTcs completed first (handshake result arrived)
                {
                    if (await _connectedTcs.Task.ConfigureAwait(false)) // Await the result to see if handshake succeeded
                    {
                        return; // Connection established — SYN-ACK received and processed.
                    }

                    break; // _connectedTcs completed with false — handshake failed.
                }
                // Timeout expired — resend SYN with backoff (RTO grows).
            }

            throw new TimeoutException("UCP connection handshake timed out."); // Deadline expired without handshake completion
        }

        /// <summary>
        /// Enqueues data for sending.  Accepts up to MaxPayloadSize * ushort.MaxValue bytes,
        /// fragmenting into MSS-sized (MaxPayloadSize) segments.  Each segment is assigned
        /// a monotonically increasing sequence number from _nextSendSequence.
        ///
        /// Fragmentation: If count > MaxPayloadSize, the message is split into fragments.
        /// Each fragment carries FragmentTotal (total fragments in message) and FragmentIndex
        /// (zero-based position).  The receiver reassembles messages using these fields.
        ///
        /// Flow control: If the send buffer is full (count >= SendBufferSize / MaxPayloadSize),
        /// the caller should retry.  The _sendSpaceSignal is released when ACKs free buffer slots.
        ///
        /// After enqueueing, FlushSendQueueAsync() is called to attempt immediate transmission.
        /// </summary>
        /// <param name="buffer">Source buffer.</param>
        /// <param name="offset">Offset into the source buffer.</param>
        /// <param name="count">Number of bytes to send.</param>
        /// <returns>Number of bytes accepted, or -1 if the connection is not sendable.</returns>
        public async Task<int> SendAsync(byte[] buffer, int offset, int count)
        {
            return await SendAsync(buffer, offset, count, UcpPriority.Normal).ConfigureAwait(false);
        }

        /// <summary>
        /// Enqueues data for sending with the specified QoS priority.
        /// Higher-priority segments are transmitted before lower-priority ones
        /// when FlushSendQueueAsync collects segments to send.
        ///
        /// Fragmentation: If count > MaxPayloadSize, the message is split into fragments.
        /// Each fragment carries FragmentTotal (total fragments in message) and FragmentIndex
        /// (zero-based position).  The receiver reassembles messages using these fields.
        /// </summary>
        /// <param name="buffer">Source buffer.</param>
        /// <param name="offset">Offset into the source buffer.</param>
        /// <param name="count">Number of bytes to send.</param>
        /// <param name="priority">QoS priority for this data (Background, Normal, Interactive, Urgent).</param>
        /// <returns>Number of bytes accepted, or -1 if the connection is not sendable.</returns>
        internal async Task<int> SendAsync(byte[] buffer, int offset, int count, UcpPriority priority)
        {
            ValidateBuffer(buffer, offset, count); // Validate buffer arguments (null, range check) — throws on invalid
            lock (_sync) // Acquire protocol lock to check connection state
            {
                // Only accept data in Established, ClosingFinSent, or ClosingFinReceived.
                // Reject in Init, Handshake*, Closed, or after RST.
                if (_state != UcpConnectionState.Established && _state != UcpConnectionState.ClosingFinSent && _state != UcpConnectionState.ClosingFinReceived) // Not in a sendable state
                {
                    return -1; // Connection not ready for sending
                }

            }

            int acceptedBytes = 0; // Running total of bytes accepted into send buffer
            int remaining = count; // Bytes still to fragment and enqueue
            int currentOffset = offset; // Source buffer read cursor
            // Cap to max message size: MaxPayloadSize (MSS) * ushort.MaxValue (max fragments).
            if (count > _config.MaxPayloadSize * ushort.MaxValue) // Message exceeds max fragments * MSS limit
            {
                count = _config.MaxPayloadSize * ushort.MaxValue; // Cap message to maximum allowed size
                remaining = count; // Update remaining to reflect capped size
            }

            // Calculate total fragments needed for this message.
            ushort fragmentTotal = (ushort)((count + _config.MaxPayloadSize - 1) / _config.MaxPayloadSize); // Ceiling division: how many MSS-sized chunks
            ushort fragmentIndex = 0; // Zero-based fragment counter within this message
            int maxBufferedSegments = Math.Max(1, _config.SendBufferSize / Math.Max(1, _config.MaxPayloadSize)); // Maximum number of segments allowed in send buffer

            while (remaining > 0) // Loop until all data is fragmented and enqueued
            {
                int chunk = remaining > _config.MaxPayloadSize ? _config.MaxPayloadSize : remaining; // Size of this fragment: min(MSS, remaining bytes)
                lock (_sync) // Acquire protocol lock for safe send buffer access
                {
                    // Flow control: don't exceed send buffer capacity.
                    if (_sendBuffer.Count >= maxBufferedSegments) // Send buffer is full (max capacity reached)
                    {
                        break; // Send buffer full; caller should retry via WriteAsync.
                    }
                }

                byte[] payload = new byte[chunk]; // Allocate buffer for this fragment's payload
                Buffer.BlockCopy(buffer, currentOffset, payload, 0, chunk); // Copy fragment bytes from source buffer

                lock (_sync) // Acquire protocol lock for safe sequence number assignment and buffer insert
                {
                    OutboundSegment segment = new OutboundSegment(); // Create new outbound segment metadata
                    segment.SequenceNumber = _nextSendSequence; // Assign the next available sequence number
                    segment.FragmentTotal = fragmentTotal; // Total fragments in this logical message
                    segment.FragmentIndex = fragmentIndex; // Zero-based position of this fragment
                    segment.Payload = payload; // Attach the payload bytes
                    segment.Priority = priority; // Store QoS priority for send ordering
                    // Insert into sorted dictionary; UcpSequenceComparer maintains 32-bit wraparound order.
                    _sendBuffer[segment.SequenceNumber] = segment; // Store segment keyed by sequence number (sorted insertion)
                    _nextSendSequence = UcpSequenceComparer.Increment(_nextSendSequence); // Advance ISN to next available sequence (32-bit wraparound)
                }

                currentOffset += chunk; // Advance source read cursor past consumed bytes
                remaining -= chunk; // Decrement bytes still to fragment
                acceptedBytes += chunk; // Increment accepted byte counter
                fragmentIndex++; // Advance fragment index for next chunk
            }

            await FlushSendQueueAsync().ConfigureAwait(false); // Trigger asynchronous send loop to transmit buffered segments
            return acceptedBytes; // Return number of bytes accepted (may be less than requested if buffer full)
        }

        /// <summary>
        /// Copies up to <paramref name="count"/> bytes from the receive queue into
        /// the provided buffer.  Blocks until data is available or the connection closes.
        ///
        /// Uses a producer-consumer pattern: data producers call EnqueuePayload() which
        /// adds a ReceiveChunk to _receiveQueue and releases _receiveSignal.  This method
        /// waits on _receiveSignal when the queue is empty.
        ///
        /// Partial reads are supported: if a chunk has more data than requested, only
        /// the requested amount is copied and the chunk's Offset advances.  The remaining
        /// data stays in the chunk for the next read.
        /// </summary>
        /// <returns>Number of bytes copied, 0 if closed, or -1 on error.</returns>
        public async Task<int> ReceiveAsync(byte[] buffer, int offset, int count)
        {
            ValidateBuffer(buffer, offset, count); // Validate buffer arguments (null, range check) — throws on invalid
            while (true) // Loop until data available or connection closed
            {
                ReceiveChunk chunk = null; // Pending chunk of contiguous in-order data
                lock (_sync) // Acquire protocol lock for safe queue access
                {
                    if (_receiveQueue.Count > 0) // There is at least one chunk waiting
                    {
                        chunk = _receiveQueue.Peek(); // Peek at first chunk without removing (supports partial reads)
                    }
                    else if (_state == UcpConnectionState.Closed) // Connection is closed with no data remaining
                    {
                        return 0; // Connection closed, no more data.
                    }
                }

                if (chunk != null) // A chunk is available for reading
                {
                    lock (_sync) // Acquire protocol lock for safe data copy and state mutation
                    {
                        ReceiveChunk current = _receiveQueue.Peek(); // Re-peek under lock (guarantees consistency)
                        int available = current.Count - current.Offset; // Unread bytes remaining in this chunk
                        int toCopy = available > count ? count : available; // Copy min(requested, available)
                        Buffer.BlockCopy(current.Buffer, current.Offset, buffer, offset, toCopy); // Copy payload bytes to caller's buffer
                        current.Offset += toCopy; // Advance the chunk's read cursor
                        _queuedReceiveBytes -= toCopy; // Decrement total queued receive bytes tracker
                        if (_queuedReceiveBytes < 0) // Safety: clamp to zero if tracking underflows
                        {
                            _queuedReceiveBytes = 0; // Clamp to zero
                        }
                        if (current.Offset >= current.Count) // All bytes in this chunk have been consumed
                        {
                            // Chunk fully consumed — remove from queue.
                            _receiveQueue.Dequeue(); // Remove the fully-consumed chunk
                        }

                        // Schedule an ACK since we freed receive window space.
                        ScheduleAck(); // Let sender know we have more receive window capacity

                        return toCopy; // Return number of bytes copied to caller
                    }
                }

                // Wait for data to arrive (signaled by EnqueuePayload).
                await _receiveSignal.WaitAsync(_cts.Token).ConfigureAwait(false); // Block until new data arrives or connection closes
            }
        }

        /// <summary>
        /// Reads exactly <paramref name="count"/> bytes into the buffer.
        /// Loops calling ReceiveAsync() until the requested count is satisfied or
        /// the connection closes.  Returns false if the connection closed before
        /// all bytes were received.
        /// </summary>
        public async Task<bool> ReadAsync(byte[] buffer, int offset, int count)
        {
            ValidateBuffer(buffer, offset, count);
            int completed = 0;
            while (completed < count)
            {
                int received = await ReceiveAsync(buffer, offset + completed, count - completed).ConfigureAwait(false);
                if (received <= 0)
                {
                    return false;
                }

                completed += received;
            }

            return true;
        }

        /// <summary>
        /// Writes exactly <paramref name="count"/> bytes, retrying via SendAsync()
        /// until all data is accepted or the connection closes.  When SendAsync
        /// returns 0 (buffer full), waits on _sendSpaceSignal for ACKs to free buffer slots.
        /// Returns false on error or close.
        /// </summary>
        public async Task<bool> WriteAsync(byte[] buffer, int offset, int count)
        {
            return await WriteAsync(buffer, offset, count, UcpPriority.Normal).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes exactly <paramref name="count"/> bytes with the specified QoS priority,
        /// retrying via SendAsync() until all data is accepted or the connection closes.
        /// Returns false on error or close.
        /// </summary>
        internal async Task<bool> WriteAsync(byte[] buffer, int offset, int count, UcpPriority priority)
        {
            ValidateBuffer(buffer, offset, count); // Validate buffer arguments (null, range check) — throws on invalid
            int totalWritten = 0; // Running total of bytes successfully accepted and sent
            while (totalWritten < count) // Loop until all requested bytes are written
            {
                int written = await SendAsync(buffer, offset + totalWritten, count - totalWritten, priority).ConfigureAwait(false); // Attempt to send remaining bytes
                if (written < 0) // Connection is no longer in a sendable state
                {
                    return false; // Connection not in sendable state.
                }

                if (written == 0) // Send buffer full — zero bytes accepted this round
                {
                    // Send buffer full — wait for ACKs to free space.
                    await _sendSpaceSignal.WaitAsync(_cts.Token).ConfigureAwait(false); // Block until ACKs free send buffer slots
                    continue; // Retry the write loop
                }

                totalWritten += written; // Accumulate successfully written bytes
            }

            return true; // All bytes written successfully
        }

        /// <summary>
        /// Gracefully closes the connection via a FIN exchange:
        ///   1. Drain the send buffer (wait for all data to be ACKed)
        ///   2. Send FIN to the peer
        ///   3. Wait for the peer to acknowledge the FIN
        ///   4. Transition to Closed
        ///
        /// UCP's graceful close is a 2-way FIN handshake (simpler than TCP's 4-way):
        ///   A → B: FIN (seq=a)
        ///   B → A: FIN-ACK (ack=a+1, fin-ack flag set)
        ///
        /// Either side can initiate close.  When both FINs are acknowledged,
        /// the connection transitions to Closed.
        ///
        /// Timeout: If the send buffer doesn't drain within DisconnectTimeoutMicros,
        /// proceeds with the FIN anyway.  If the close doesn't complete within
        /// CLOSE_WAIT_TIMEOUT_MILLISECONDS, forces transition to Closed.
        /// </summary>
        public async Task CloseAsync()
        {
            bool needSendFin = false; // True if we need to send a FIN packet (not already sent)
            long deadlineMicros = NowMicros() + _config.DisconnectTimeoutMicros; // Absolute deadline for send buffer drain
            // Step 1: Drain the send buffer (wait for in-flight data to be ACKed).
            while (NowMicros() < deadlineMicros) // Loop until drain deadline expires
            {
                lock (_sync) // Acquire protocol lock to check buffer state
                {
                    if (_sendBuffer.Count == 0 || _state == UcpConnectionState.Closed) // Buffer drained or already closed
                    {
                        break; // Exit drain loop
                    }
                }

                await _sendSpaceSignal.WaitAsync(10, _cts.Token).ConfigureAwait(false); // Wait up to 10ms for buffer to free, then recheck
            }

            // Step 2: Send FIN if not already sent.
            lock (_sync) // Acquire protocol lock for state transition
            {
                if (_state == UcpConnectionState.Closed) // Already closed (race with another close)
                {
                    return; // Nothing to do — already closed
                }

                if (!_finSent) // FIN has not been sent yet
                {
                    _state = UcpConnectionState.ClosingFinSent; // Transition to FIN-sent closing state
                    _finSent = true; // Mark FIN as sent
                    needSendFin = true; // Signal that we need to transmit the FIN packet
                }
            }

            if (needSendFin) // FIN needs to be sent to the peer
            {
                SendControl(UcpPacketType.Fin, UcpPacketFlags.None); // Transmit FIN packet to initiate graceful close
            }

            // Step 3-4: Wait for peer FIN-ACK, then transition to Closed.
            await WaitWithTimeoutAsync(_closedTcs.Task, UcpConstants.CLOSE_WAIT_TIMEOUT_MILLISECONDS).ConfigureAwait(false); // Wait for peer to acknowledge FIN with timeout
            TransitionToClosed(); // Perform final state transition to Closed
        }

        /// <summary>
        /// Dispatches an inbound packet to the appropriate handler based on type.
        /// Records activity timestamp on every received packet (even control packets)
        /// so that keep-alive and disconnect timeout detection work correctly.
        ///
        /// Packet dispatch by type:
        ///   SYN      → HandleSyn        (handshake step 1)
        ///   SYNACK   → HandleSynAck     (handshake step 2)
        ///   ACK      → HandleAckAsync   (cumulative ACK + SACK processing)
        ///   NAK      → HandleNakAsync   (explicit loss notification)
        ///   DATA     → HandleData       (payload + piggybacked ACK + NAK)
        ///   FECREPAIR→ HandleFecRepair  (FEC reconstruction)
        ///   FIN      → HandleFin        (graceful close)
        ///   RST      → Immediate close  (abrupt reset)
        /// </summary>
        /// <param name="packet">The decoded UCP packet.</param>
        public async Task HandleInboundAsync(UcpPacket packet)
        {
            if (packet == null) // Null guard — caller may pass null for unknown packets
            {
                return; // Nothing to handle
            }

            lock (_sync) // Acquire protocol lock for PAWS validation and timestamp update
            {
                _lastActivityMicros = NowMicros(); // Record activity timestamp for keep-alive and disconnect timeout

                // PAWS (Protection Against Wrapped Sequences): reject packets with timestamps
                // too far behind the largest seen.  At 100 Gbps, 32-bit sequence numbers wrap
                // in ~3 seconds; a stale duplicate from before the wrap must be detected by
                // its old timestamp, not by sequence number alone.
                if (_pawsEnabled && _largestTimestampSeen > 0 && // At least one packet seen and PAWS active
                    _largestTimestampSeen - packet.Header.Timestamp > UcpConstants.PAWS_TIMEOUT_MICROS) // Timestamp is >60s behind largest seen
                {
                    return; // Reject as too old — likely wrapped duplicate or replay
                }

                // Update largest timestamp seen for future PAWS comparisons.
                if (packet.Header.Timestamp > _largestTimestampSeen) // New record timestamp from peer
                {
                    _largestTimestampSeen = packet.Header.Timestamp; // Advance the PAWS window
                }
            }

            if (packet.Header.Type == UcpPacketType.Syn) // Incoming SYN: handshake step 1 (or re-SYN)
            {
                HandleSyn((UcpControlPacket)packet); // Process SYN packet synchronously
                return; // Done — SYN handler does not need async completion
            }

            if (packet.Header.Type == UcpPacketType.SynAck) // Incoming SYN-ACK: handshake step 2 (client perspective)
            {
                HandleSynAck((UcpControlPacket)packet); // Process SYN-ACK synchronously
                return; // Done
            }

            if (packet.Header.Type == UcpPacketType.Ack) // Incoming ACK: cumulative acknowledgment
            {
                await HandleAckAsync((UcpAckPacket)packet).ConfigureAwait(false); // Process ACK asynchronously (may trigger flush)
                return; // Done
            }

            if (packet.Header.Type == UcpPacketType.Nak) // Incoming NAK: negative acknowledgment (explicit loss report)
            {
                await HandleNakAsync((UcpNakPacket)packet).ConfigureAwait(false); // Process NAK asynchronously (may trigger retransmit)
                return; // Done
            }

            if (packet.Header.Type == UcpPacketType.Data) // Incoming DATA: application payload
            {
                HandleData((UcpDataPacket)packet); // Process data packet synchronously (may queue ACK/NAK)
                return; // Done
            }

            if (packet.Header.Type == UcpPacketType.FecRepair) // Incoming FEC repair packet
            {
                HandleFecRepair((UcpFecRepairPacket)packet); // Process FEC repair synchronously (may recover lost data)
                return; // Done
            }

            if (packet.Header.Type == UcpPacketType.Fin) // Incoming FIN: graceful close initiation
            {
                HandleFin((UcpControlPacket)packet); // Process FIN synchronously (reply with FIN-ACK and possibly our own FIN)
                return; // Done
            }

            if (packet.Header.Type == UcpPacketType.Rst) // Incoming RST: abrupt connection reset
            {
                _rstReceived = true; // Record that a reset was received (for diagnostics)
                TransitionToClosed(); // Immediately transition to Closed without graceful FIN exchange
            }
        }

        /// <summary>
        /// Adds fair-queue credit bytes to this PCB.  Called by the network scheduler
        /// to grant bandwidth to this connection.  Credit is consumed during
        /// FlushSendQueueAsync — each packet sent deducts its size from the credit.
        ///
        /// Credit is capped at MaxBufferedFairQueueRounds * max(SendQuantum, MSS) to
        /// prevent any single connection from hoarding credit during idle periods.
        /// </summary>
        /// <param name="bytes">Credit bytes to add.</param>
        public void AddFairQueueCredit(double bytes)
        {
            if (!_useFairQueue || bytes <= 0) // Fair queue disabled or no credit to add
            {
                return; // Nothing to do
            }

            lock (_sync) // Acquire protocol lock for safe credit update
            {
                _fairQueueCreditBytes += bytes; // Add credit bytes to this connection's budget
                double maxCreditBytes = Math.Max(_config.SendQuantumBytes, _config.Mss) * UcpConstants.MaxBufferedFairQueueRounds; // Cap: prevent idle connections from hoarding credit
                if (_fairQueueCreditBytes > maxCreditBytes) // Credit exceeds maximum cap
                {
                    _fairQueueCreditBytes = maxCreditBytes; // Clamp to max
                }
            }
        }

        /// <summary>
        /// Requests an immediate flush of the send buffer.  Fire-and-forget:
        /// the actual flush runs asynchronously on the thread pool.
        /// </summary>
        public void RequestFlush()
        {
            _ = FlushSendQueueAsync(); // Fire-and-forget: trigger asynchronous send loop
        }

        /// <summary>
        /// Performs one tick of timer processing (used by UcpNetwork.DoEvents).
        /// Returns 1 if work was done, 0 if idle.  The network engine calls this
        /// synchronously from its event loop, so heavy work is deferred to async.
        /// </summary>
        /// <param name="nowMicros">Current network time in microseconds.</param>
        /// <returns>Number of work items processed.</returns>
        public int OnTick(long nowMicros)
        {
            if (_disposed) // PCB has been disposed — no work to do
            {
                return 0; // Return zero work items
            }

            int work = 0; // Counter for work items processed
            Task timerTask = OnTimerAsync(nowMicros); // Run the timer heartbeat (RTO, TLP, NAK, keep-alive)
            if (timerTask.IsCompleted) // Timer task completed synchronously (no async wait needed)
            {
                work++; // Count as one work item
            }

            if (HasPendingSendData) // Send buffer has data waiting to be transmitted
            {
                RequestFlush(); // Fire-and-forget a send queue flush
                work++; // Count as one work item
            }

            return work; // Return total work items processed this tick
        }

        /// <summary>
        /// Dispatches a decoded packet from the network directly to this PCB
        /// (used by UcpNetwork.Input for known connections).  Validates the
        /// remote endpoint (IP-agnostic) before dispatching.
        /// </summary>
        /// <param name="packet">The decoded UCP packet.</param>
        /// <param name="remoteEndPoint">The source endpoint.</param>
        public void DispatchFromNetwork(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (ValidateRemoteEndPoint(remoteEndPoint)) // Endpoint matches (or first packet — accepted)
            {
                _ = HandleInboundAsync(packet); // Fire-and-forget: dispatch packet to the inbound handler
            }
        }

        /// <summary>
        /// Disposes the PCB: cancels all async operations, disposes timers and
        /// semaphores, unregisters from the network, and transitions to Closed.
        /// Safe to call multiple times (idempotent via _disposed flag).
        /// </summary>
        public void Dispose()
        {
            if (_disposed) // Already disposed — idempotent guard
            {
                return; // Nothing to clean up
            }

            _disposed = true; // Set disposed flag first to prevent re-entrancy
            _cts.Cancel(); // Cancel all async operations and unblock waiters
            if (_timer != null) // Standalone mode: .NET Timer was created
            {
                _timer.Dispose(); // Dispose the timer (stops repeating ticks)
            }

            ReleaseNetworkRegistrations(); // Unregister from UcpNetwork and cancel timers
            TransitionToClosed(); // Transition to Closed state (fires Disconnected event, releases semaphores)
            _cts.Dispose(); // Dispose the cancellation token source
            _receiveSignal.Dispose(); // Dispose the receive semaphore
            _sendSpaceSignal.Dispose(); // Dispose the send space semaphore
            _flushLock.Dispose(); // Dispose the flush lock semaphore
        }

        // ---- Packet handler: SYN ----

        /// <summary>
        /// Processes a cumulative ACK piggybacked on a non-ACK packet (DATA, NAK,
        /// SYN-ACK, FIN, RST).  This is a fundamental UCP optimization: instead of
        /// sending a separate ACK packet, every outbound data and control packet
        /// carries the receiver's cumulative ACK number, SACK blocks, and window.
        ///
        /// Algorithm:
        ///   1. Validate ACK plausibility: must be non-zero and not receding (ACK
        ///      must be >= the largest previously seen cumulative ACK).
        ///   2. Iterate the send buffer in sequence order.  For each segment whose
        ///      sequence <= ackNumber, mark it as acknowledged.
        ///   3. If the segment was in flight, decrement _flightBytes.  If it was
        ///      a first-transmission packet, record the RTT sample for the RTO
        ///      estimator and BBR.
        ///   4. Remove ACKed segments from the send buffer and the SACK fast-retransmit
        ///      tracking set.
        ///   5. Signal _sendSpaceSignal so blocked writers can resume.
        ///   6. Update BBR and pacing rate with the new delivery information.
        ///
        /// Critical invariants:
        ///   - _flightBytes must never go negative (clamped to 0)
        ///   - RTT samples use only first-transmission packets (SendCount == 1) to
        ///     avoid retransmission ambiguity (Karn's algorithm)
        ///   - The ACK must not recede (monotonic) — prevents replay attacks
        ///
        /// Does NOT trigger a flush — callers should do that themselves after
        /// processing the packet's other payload.
        /// </summary>
        /// <param name="ackNumber">The cumulative ACK number (next expected sequence - 1).</param>
        /// <param name="echoTimestamp">Echo timestamp from the packet header.</param>
        /// <param name="nowMicros">Current time in microseconds.</param>
        /// <returns>Number of bytes delivered (ACKed) by this piggybacked ACK.</returns>
        private int ProcessPiggybackedAck(uint ackNumber, long echoTimestamp, long nowMicros)
        {
            List<uint> removeKeys = new List<uint>(); // Collect keys of ACKed segments for deferred removal
            int deliveredBytes = 0; // Accumulator for total payload bytes acknowledged
            lock (_sync) // Acquire protocol lock for safe send buffer mutation
            {
                // Validate: ACK must be non-zero and non-receding.
                if (ackNumber == 0) // Zero ACK is invalid (no data can be cumulatively ACKed at seq 0)
                {
                    return 0; // No bytes delivered
                }

                // Reject receding ACKs (must be monotonic).
                if (_hasLargestCumulativeAckNumber && UcpSequenceComparer.IsBefore(ackNumber, _largestCumulativeAckNumber)) // New ACK is behind the largest we've seen
                {
                    return 0; // Reject receding ACK — possible replay
                }

                // Update largest cumulative ACK seen.
                if (!_hasLargestCumulativeAckNumber || UcpSequenceComparer.IsAfter(ackNumber, _largestCumulativeAckNumber)) // New ACK advances our largest-seen
                {
                    _largestCumulativeAckNumber = ackNumber; // Record new largest cumulative ACK
                    _hasLargestCumulativeAckNumber = true; // Mark that we have a baseline
                }

                // Any ACK (even duplicate) proves the path is alive — update timestamps.
                _lastAckReceivedMicros = nowMicros; // Record when we last heard from the peer
                _tailLossProbePending = false; // ACK arrived — cancel any pending tail-loss probe

                // Walk the send buffer in sequence order to find ACKed segments.
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer) // Iterate send buffer in sorted sequence order
                {
                    OutboundSegment segment = pair.Value; // Get the outbound segment metadata
                    if (segment.Acked) continue; // Skip already-acknowledged segments

                    if (UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackNumber)) // Segment is cumulatively ACKed
                    {
                        segment.Acked = true; // Mark segment as acknowledged by peer
                        if (segment.InFlight) // Segment was in flight (sent but not yet acked)
                        {
                            _flightBytes -= segment.Payload.Length; // Decrement flight bytes by payload size
                            if (_flightBytes < 0) _flightBytes = 0; // Safety clamp.
                        }

                        deliveredBytes += segment.Payload.Length; // Accumulate delivered bytes for BBR/congestion update
                        // Karn's algorithm: use only first-transmission packets for RTT
                        // estimation.  Retransmitted packets have ambiguous timing
                        // (did the ACK refer to the original or the retransmit?).
                        if (segment.SendCount == 1 && segment.LastSendMicros > 0) // Only first-transmission packets with known send time
                        {
                            long segmentRtt = nowMicros - segment.LastSendMicros; // Compute RTT for this specific segment
                            if (segmentRtt > 0) // Positive RTT (i.e., not a reordered measurement)
                            {
                                _lastRttMicros = segmentRtt; // Store as most recent RTT sample
                                AddRttSampleUnsafe(segmentRtt); // Add to bounded RTT sample history
                                _rtoEstimator.Update(segmentRtt); // Update RFC 6298 RTO estimator (SRTT and RTTVAR)
                            }
                        }

                        removeKeys.Add(pair.Key); // Schedule this segment for removal after iteration
                    }
                    else if (UcpSequenceComparer.IsAfter(segment.SequenceNumber, ackNumber)) // Past the cumulative ACK point
                    {
                        // Sorted dictionary means we've passed all ACK-eligible segments.
                        break; // Stop scanning — remaining segments are beyond the cumulative ACK
                    }
                }

                // Remove acknowledged segments and their tracking state.
                for (int i = 0; i < removeKeys.Count; i++) // Iterate collected keys for removal
                {
                    _sackFastRetransmitNotified.Remove(removeKeys[i]); // Clean up fast-retransmit notification flag
                    _sackTracking.Remove(removeKeys[i]); // Clean up cold-path SACK tracking state
                    _sendBuffer.Remove(removeKeys[i]); // Remove segment from send buffer
                }

                // Signal writers that buffer space has freed up.
                if (removeKeys.Count > 0) // At least one segment was ACKed
                {
                    try { 
                        _sendSpaceSignal.Release(removeKeys.Count); // Release semaphore for each freed buffer slot
                    } 
                    catch (SemaphoreFullException)
                    {
                        // Semaphore full — benign, just means many ACKs have already
                        // released more capacity than writers can consume.
                    }
                }

                // Reset fair-queue credit when buffer empties (no data to pace).
                if (_sendBuffer.Count == 0) // Send buffer is completely empty
                {
                    _fairQueueCreditBytes = 0; // Reset credit — no pending data needs pacing budget
                }

                // Update congestion control with delivery information.
                if (deliveredBytes > 0) // At least one segment was delivered/ACKed
                {
                    _bbr.OnAck(nowMicros, deliveredBytes, _lastRttMicros, _flightBytes); // Feed delivery information to BBR congestion control
                    _pacing.SetRate(_bbr.PacingRateBytesPerSecond, nowMicros); // Update pacing rate to BBR's new computed rate
                }
            }

            // Note: Callers handle flushing when needed (e.g., if fast retransmit was triggered).
            return deliveredBytes; // Return total bytes acknowledged by this piggybacked ACK
        }

        /// <summary>
        /// Handles an incoming SYN packet (step 1 of the 3-way handshake from the
        /// server's perspective, or a re-SYN from the client).
        ///
        /// Processing:
        ///   1. Accept the peer's connection ID (the SYN carries the client-chosen ID).
        ///   2. Record the peer's initial sequence number as _nextExpectedSequence.
        ///   3. Transition from Init → HandshakeSynReceived.
        ///   4. If the SYN carries a piggybacked ACK (re-SYN from client that already
        ///      has data to acknowledge), process it via ProcessPiggybackedAck.
        ///   5. Reply with SYN-ACK: carries our ISN (_nextSendSequence) and
        ///      acknowledges the peer's ISN.
        ///
        /// The handshake establishes three things:
        ///   - Sequence number synchronization (both sides learn each other's ISN)
        ///   - Connection ID agreement (packets are identified by the client-chosen ID)
        ///   - State transition to allow data flow
        /// </summary>
        private void HandleSyn(UcpControlPacket packet)
        {
            bool shouldReply = false; // Whether to reply with SYN-ACK
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Check if SYN carries piggybacked ACK (re-SYN)
            lock (_sync) // Acquire protocol lock for connection state mutation
            {
                _connectionId = packet.Header.ConnectionId; // Accept the client-chosen connection ID
                if (_network != null) // Network-managed mode
                {
                    _network.UpdatePcbConnectionId(this, 0, _connectionId); // Update network's connection-id-to-PCB mapping
                }
                if (packet.HasSequenceNumber) // SYN carries the peer's ISN
                {
                    _nextExpectedSequence = packet.SequenceNumber; // Record peer's initial sequence number
                }

                if (_state == UcpConnectionState.Init) // Server side: first contact from client
                {
                    _state = UcpConnectionState.HandshakeSynReceived; // Transition to SYN-received state
                }

                if (_state != UcpConnectionState.Closed) // Connection is not closed
                {
                    _synAckSent = true; // Mark that we will send (or already sent) SYN-ACK
                    _synAckSentMicros = NowMicros(); // Record timestamp for RTO-driven retransmission
                    shouldReply = true; // Signal that we should send SYN-ACK
                }
            }

            // Process piggybacked ACK from re-SYN before replying.
            if (hasAck && packet.AckNumber > 0) // SYN carries a valid piggybacked ACK
            {
                ProcessPiggybackedAck(packet.AckNumber, packet.Header.Timestamp, NowMicros()); // Process the piggybacked ACK to clean up send buffer
            }

            if (shouldReply) // We should send a SYN-ACK response
            {
                SendControl(UcpPacketType.SynAck, UcpPacketFlags.None); // Transmit SYN-ACK with our ISN and ACK of peer's ISN
            }
        }

        // ---- Packet handler: SYN-ACK ----

        /// <summary>
        /// Handles an incoming SYN-ACK (step 2 of the 3-way handshake from the
        /// client's perspective).
        ///
        /// Processing:
        ///   1. Record the peer's initial sequence number from the SYN-ACK.
        ///   2. Process the piggybacked ACK — this acknowledges our SYN and any
        ///      early data we may have sent.
        ///   3. Send a pure ACK to acknowledge the peer's ISN (step 3).
        ///   4. If we sent the SYN (client side), transition to Established.
        ///
        /// The SYN-ACK carries the server's ISN in the SequenceNumber field and
        /// the client's ISN in the AckNumber field.  After processing, both sides
        /// can send and receive data.
        /// </summary>
        private void HandleSynAck(UcpControlPacket packet)
        {
            bool shouldEstablish = false; // Whether to transition to Established
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Check if SYN-ACK carries piggybacked ACK
            lock (_sync) // Acquire protocol lock for state mutation
            {
                if (packet.HasSequenceNumber) // SYN-ACK carries the server's ISN
                {
                    _nextExpectedSequence = packet.SequenceNumber; // Record peer's (server's) initial sequence number
                }

                if (_synSent && _state != UcpConnectionState.Closed) // We sent the SYN and connection is not closed
                {
                    // Only transition to Established if we initiated the SYN.
                    shouldEstablish = _state == UcpConnectionState.HandshakeSynSent; // We are in SYN-sent state — handshake ready to complete
                }
            }

            if (hasAck && packet.AckNumber > 0) // SYN-ACK carries valid piggybacked ACK
            {
                ProcessPiggybackedAck(packet.AckNumber, packet.Header.Timestamp, NowMicros()); // Process the ACK which acknowledges our SYN
            }

            // Send ACK for the server's ISN (step 3 of handshake).
            SendAckPacket(UcpPacketFlags.None, 0); // Transmit pure ACK to acknowledge server's ISN

            if (shouldEstablish) // Handshake is complete
            {
                TransitionToEstablished(); // Transition to Established state (fires Connected event)
            }
        }

        // ---- Packet handler: ACK ----

        /// <summary>
        /// Handles an incoming ACK packet — the core acknowledgment processing engine.
        ///
        /// Processing stages:
        ///
        /// A. Plausibility check (IsAckPlausibleUnsafe):
        ///    - Connection ID must match
        ///    - Cumulative ACK must not recede (monotonic)
        ///    - SACK block ranges must be valid (start <= end)
        ///
        /// B. Cumulative ACK + SACK processing:
        ///    - Mark all segments with sequence <= AckNumber as ACKed (cumulative ACK)
        ///    - Scan SACK blocks for selectively acknowledged segments beyond the
        ///      cumulative ACK point
        ///    - For each newly ACKed segment: decrement flight bytes, record bytes
        ///      delivered, and sample the RTT (Karn's algorithm: first-transmission only)
        ///
        /// C. SACK-based fast retransmit detection:
        ///    - For segments NOT ACKed but whose sequence is below the highest SACK end:
        ///      increment MissingAckCount (in cold-path _sackTracking) and check
        ///      fast-retransmit eligibility
        ///    - A segment is eligible if it's been observed as missing enough times,
        ///      the reorder grace period has expired, and it's a reported SACK hole
        ///      (bracketed by lower and higher SACK ranges)
        ///
        /// D. Duplicate ACK fast retransmit:
        ///    - If the cumulative ACK hasn't advanced (same as _lastAckNumber),
        ///      increment _duplicateAckCount
        ///    - When _duplicateAckCount >= DUPLICATE_ACK_THRESHOLD (3), infer the
        ///      next expected sequence as lost and fast-retransmit it
        ///
        /// E. RTT estimation:
        ///    - Prefer segment-level RTT (time since last send)
        ///    - Fall back to echo-based RTT if no segment-level samples
        ///    - Only accept samples within RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER * RTO
        ///    - Update SRTT and RTTVAR via RFC 6298 algorithm
        ///
        /// F. Congestion control update:
        ///    - Feed delivery information to BBR (bytes delivered, RTT, flight size)
        ///    - Update pacing rate
        ///
        /// G. Post-processing:
        ///    - If a handshake ACK was received, transition to Established
        ///    - If FIN-ACK received and both FINs exchanged, transition to Closed
        ///    - If fast retransmit triggered or data was delivered, flush the send queue
        /// </summary>
        /// <param name="ackPacket">The decoded ACK packet.</param>
        private async Task HandleAckAsync(UcpAckPacket ackPacket)
        {
            bool establishByHandshake = false; // Whether this ACK completes the server-side handshake
            List<uint> removeKeys = new List<uint>(); // Collect keys of ACKed segments for deferred removal
            int deliveredBytes = 0; // Accumulator for total bytes newly acknowledged
            int remainingFlight; // Flight bytes remaining after processing (drives post-processing flush decision)
            long sampleRtt = 0; // Best RTT sample from this ACK (prefer segment-level over echo)
            long echoRtt = 0; // Echo-based RTT as fallback
            long nowMicros = NowMicros(); // Snapshot current time for consistent timestamps within this handler
            bool fastRetransmitTriggered = false; // Whether duplicate-ACK fast retransmit was triggered

            lock (_sync) // Acquire protocol lock for all ACK processing stages A–F
            {
                // ---- Stage A: Plausibility check ----
                if (!IsAckPlausibleUnsafe(ackPacket)) // ACK fails validation (ID mismatch, receding ACK, malformed SACK)
                {
                    remainingFlight = _flightBytes; // Capture flight bytes for post-processing
                    return; // Reject implausible ACK — do not process
                }

                // Update peer's advertised receive window.
                _remoteWindowBytes = ackPacket.WindowSize; // Update flow-control window from peer's advertisement
                // Sort SACK blocks for efficient linear scanning.
                SortSackBlocksUnsafe(ackPacket.SackBlocks); // Sort SACK blocks by start sequence for two-pointer walk

                // Check if this ACK completes the handshake (server side).
                if (_state == UcpConnectionState.HandshakeSynReceived && _synAckSent) // Server side: we sent SYN-ACK, now received client ACK
                {
                    establishByHandshake = true; // Handshake complete from server perspective
                }

                // Check for FIN-ACK flag (peer acknowledges our FIN).
                if ((ackPacket.Header.Flags & UcpPacketFlags.FinAck) == UcpPacketFlags.FinAck) // Peer set FinAck flag
                {
                    _finAcked = true; // Our FIN has been acknowledged by the peer
                }

                // Compute echo-based RTT for fallback.
                if (ackPacket.EchoTimestamp > 0) // Peer echoed back a timestamp we sent earlier
                {
                    echoRtt = nowMicros - ackPacket.EchoTimestamp; // Compute round-trip time from echo
                }

                // Any ACK proves the path is alive — update receive timestamp.
                _lastAckReceivedMicros = nowMicros; // Record ACK receipt time for TLP/silence probe detection
                _tailLossProbePending = false; // Cancel any pending tail-loss probe

                // ---- Stage D: Duplicate ACK fast retransmit detection ----
                UpdateDuplicateAckStateUnsafe(ackPacket, nowMicros, out fastRetransmitTriggered); // Check for duplicate ACKs and trigger fast retransmit if threshold met

                // ---- Stage B: Cumulative ACK + SACK processing ----
                int sackIndex = 0; // Current position in the sorted SACK blocks list
                List<SackBlock> sackBlocks = ackPacket.SackBlocks; // Peer's selectivelly acknowledged ranges
                bool hasSackBlocks = sackBlocks != null && sackBlocks.Count > 0; // Whether peer sent any SACK blocks
                uint highestSack = hasSackBlocks ? GetHighestSackEnd(sackBlocks) : 0U; // Highest sequence number covered by any SACK block
                // The first sequence NOT covered by the cumulative ACK — this is the
                // leading edge of the ACK hole, the most likely candidate for loss.
                uint firstMissingSequence = UcpSequenceComparer.Increment(ackPacket.AckNumber); // Sequence immediately after cumulative ACK
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer) // Walk send buffer in sorted sequence order
                {
                    OutboundSegment segment = pair.Value; // Current segment metadata
                    if (segment.Acked) // Segment already acknowledged
                    {
                        continue; // Skip — no processing needed
                    }

                    // Check cumulative ACK coverage.
                    bool acked = UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackPacket.AckNumber); // Covered by cumulative ACK
                    if (!acked && sackBlocks != null) // Not cumulatively ACKed, check SACK blocks
                    {
                        // Scan SACK blocks to check if this segment is selectively ACKed.
                        // SACK blocks are sorted by start, so we advance the index as we go.
                        while (sackIndex < sackBlocks.Count && UcpSequenceComparer.IsBefore(sackBlocks[sackIndex].End, segment.SequenceNumber)) // Advance past SACK blocks that end before this segment
                        {
                            sackIndex++; // Move to next SACK block
                        }

                        if (sackIndex < sackBlocks.Count) // There is a SACK block that could cover this segment
                        {
                            SackBlock block = sackBlocks[sackIndex]; // Get the current SACK block
                            acked = UcpSequenceComparer.IsInForwardRange(segment.SequenceNumber, block.Start, block.End); // Check if segment falls within this SACK block
                        }
                    }

                    if (acked) // Segment is acknowledged (cumulative or selective)
                    {
                if (!_hasLargestCumulativeAckNumber || UcpSequenceComparer.IsAfter(ackPacket.AckNumber, _largestCumulativeAckNumber)) // ACK advances our largest-seen cumulative ACK
                {
                    _largestCumulativeAckNumber = ackPacket.AckNumber; // Update largest cumulative ACK
                    _hasLargestCumulativeAckNumber = true; // Mark that we have a baseline
                }

                        segment.Acked = true; // Mark segment as acknowledged
                        if (segment.InFlight) // Segment was in flight (sent but not yet acked)
                        {
                            _flightBytes -= segment.Payload.Length; // Decrement flight bytes
                            if (_flightBytes < 0) // Safety: clamp to zero
                            {
                                _flightBytes = 0; // Clamp to zero
                            }
                        }

                        deliveredBytes += segment.Payload.Length; // Accumulate delivered bytes
                        // Karn's algorithm: only first-transmission packets for RTT.
                        if (segment.SendCount == 1 && segment.LastSendMicros > 0) // First transmission with known send time
                        {
                            long segmentRtt = nowMicros - segment.LastSendMicros; // Compute RTT for this segment
                            // Keep the smallest (most recent) RTT sample within this ACK.
                            if (sampleRtt == 0 || segmentRtt < sampleRtt) // No sample yet, or this one is smaller
                            {
                                sampleRtt = segmentRtt; // Record as best RTT sample from this ACK
                            }
                        }

                        _bytesSent += segment.Payload.Length; // Accumulate sent bytes counter for diagnostics
                        removeKeys.Add(pair.Key); // Schedule this segment for removal
                        continue; // Move to next segment (no need for loss detection on ACKed segments)
                    }

                    // ---- Stage C: SACK-based fast retransmit detection ----
                    if (hasSackBlocks) // Peer sent SACK blocks — we can detect holes
                    {
                        // Only consider segments whose sequence is below the highest
                        // SACK end — the peer has acknowledged data beyond this point,
                        // so any un-ACKed segment in between is a candidate for loss.
                        if (UcpSequenceComparer.IsBefore(segment.SequenceNumber, highestSack)) // Segment is below highest SACK frontier
                        {
                            if (!_sackFastRetransmitNotified.Contains(segment.SequenceNumber)) // Not yet notified for fast retransmit
                            {
                                // Lazy-create SACK tracking state for this segment if not already tracked.
                                SackTrackingState sackState = GetOrCreateSackTrackingUnsafe(segment.SequenceNumber); // Get or create cold-path tracking state
                                if (sackState.MissingAckCount == 0) // First observation of this hole
                                {
                                    sackState.FirstMissingAckMicros = nowMicros; // Record when the hole was first detected
                                }

                                sackState.MissingAckCount++; // Increment missing-observation counter
                            }

                            // Only non-leading holes bracketed by reported SACK ranges are
                            // repaired in parallel; this avoids treating a truncated SACK
                            // list as proof that every omitted sequence was lost.
                            bool reportedSackHole = IsReportedSackHoleUnsafe(segment.SequenceNumber, ackPacket.AckNumber, sackBlocks); // Check if this hole is bracketed by SACK ranges
                            if (segment.SendCount == 1 && !segment.NeedsRetransmit && ShouldFastRetransmitSackHoleUnsafe(segment, firstMissingSequence, highestSack, reportedSackHole, nowMicros)) // First send, not already marked, and meets SACK fast retransmit criteria
                            {
                                segment.NeedsRetransmit = true; // Mark for retransmission
                                // Mark as urgent in the cold-path SACK tracking state to bypass pacing.
                                SackTrackingState sackState = GetOrCreateSackTrackingUnsafe(segment.SequenceNumber); // Get existing tracking state
                                sackState.UrgentRetransmit = true; // Bypass pacing for urgent recovery
                                _fastRetransmissions++; // Increment fast retransmit counter
                                _sackFastRetransmitNotified.Add(segment.SequenceNumber); // Record that we've notified this sequence
                                bool isCongestionLoss = IsCongestionLossUnsafe(segment.SequenceNumber, sampleRtt, nowMicros, 1); // Classify loss: congestion or random
                                _bbr.OnFastRetransmit(nowMicros, isCongestionLoss); // Notify BBR of fast retransmit event
                                TraceLogUnsafe("FastRetransmit sequence=" + segment.SequenceNumber + " sack=true congestion=" + isCongestionLoss); // Debug trace
                            }
                        }
                    }
                }

                // Remove ACKed segments from the send buffer and clean up tracking state.
                for (int i = 0; i < removeKeys.Count; i++) // Iterate all ACKed keys
                {
                    _sackFastRetransmitNotified.Remove(removeKeys[i]); // Clean up fast-retransmit notification flag
                    _sendBuffer.Remove(removeKeys[i]); // Remove segment from send buffer
                }

                if (removeKeys.Count > 0) // At least one segment was removed
                {
                    try
                    {
                        _sendSpaceSignal.Release(removeKeys.Count); // Release semaphore for each freed buffer slot
                    }
                    catch (SemaphoreFullException) // Semaphore is at max count
                    {
                    }
                }

                // Reset fair-queue credit when buffer empties.
                if (_sendBuffer.Count == 0) // No segments remaining in send buffer
                {
                    _fairQueueCreditBytes = 0; // Reset credit — no pending data needs pacing budget
                }

                remainingFlight = _flightBytes; // Snapshot for post-processing flush decision

                // ---- Stage E: RTT estimation ----
                // Fall back to echo-based RTT if no segment-level sample is available.
                if (deliveredBytes > 0 && sampleRtt == 0 && echoRtt > 0 && echoRtt <= _rtoEstimator.CurrentRtoMicros) // Data delivered but no segment RTT, echo is plausible
                {
                    sampleRtt = echoRtt; // Fall back to echo-based RTT.
                }

                // Filter implausible RTT samples (protect RTO estimator from noise).
                bool acceptableRttSample = sampleRtt > 0 && sampleRtt <= (long)(_rtoEstimator.CurrentRtoMicros * UcpConstants.RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER); // RTT is positive and within acceptable multiplier of current RTO
                if (deliveredBytes > 0 && acceptableRttSample) // Data delivered with a valid RTT sample
                {
                    _lastRttMicros = sampleRtt; // Update most recent RTT
                    AddRttSampleUnsafe(sampleRtt); // Add to bounded RTT history for min-RTT tracking
                    _rtoEstimator.Update(sampleRtt); // Update SRTT and RTTVAR (RFC 6298)
                }

                // ---- Stage F: Congestion control update ----
                _bbr.OnAck(nowMicros, deliveredBytes, sampleRtt, _flightBytes); // Feed delivery info to BBR congestion control
                _pacing.SetRate(_bbr.PacingRateBytesPerSecond, nowMicros); // Update token-bucket pacing rate
            }

            // ---- Stage G: Post-processing ----
            if (establishByHandshake) // This ACK completed the server-side handshake
            {
                TransitionToEstablished(); // Transition to Established state
            }

            // Both FINs exchanged and acknowledged → clean close.
            if (_finSent && _finAcked && _peerFinReceived) // Our FIN acknowledged, peer's FIN received
            {
                TransitionToClosed(); // Clean close complete
            }

            // Trigger a flush if: fast retransmit was triggered, data was delivered
            // (which means we have new window space), or there's remaining flight
            // (we should try to fill the window).
            if (fastRetransmitTriggered || deliveredBytes > 0 || remainingFlight > 0) // Need to flush the send queue
            {
                await FlushSendQueueAsync().ConfigureAwait(false); // Trigger asynchronous send loop
            }
        }

        // ---- Packet handler: NAK ----

        /// <summary>
        /// Handles an incoming NAK (Negative Acknowledgment) packet.
        ///
        /// NAKs are sent by the receiver when it detects gaps in the sequence space
        /// that have persisted beyond the reorder-grace period.  Unlike SACK (which
        /// says "I have these ranges"), NAK says "I'm missing these exact sequences."
        ///
        /// Processing:
        ///   1. First, process any piggybacked cumulative ACK (the NAK always carries
        ///      the receiver's current ACK state).
        ///   2. For each missing sequence in the NAK list, look up the corresponding
        ///      OutboundSegment.  If the segment is not yet marked for retransmit,
        ///      not already ACKed, and the retransmit cooldown has expired, mark it
        ///      for retransmission.
        ///   3. Classify the loss (congestion vs. random) and notify BBR.
        ///   4. Flush the send queue to retransmit the NAKed segments.
        ///
        /// Retransmit acceptance guard (ShouldAcceptRetransmitRequestUnsafe):
        ///   A segment that has already been retransmitted must wait at least one
        ///   SRTT before being retransmitted again — this prevents NAK amplification
        ///   where repeated NAKs cause duplicate retransmissions.
        /// </summary>
        /// <param name="nakPacket">The decoded NAK packet.</param>
        private async Task HandleNakAsync(UcpNakPacket nakPacket)
        {
            bool notifiedLoss = false; // Whether any loss was notified to BBR
            long nowMicros = NowMicros(); // Snapshot current time

            // Process piggybacked cumulative ACK from NAK.
            if (nakPacket.AckNumber > 0) // NAK carries a valid piggybacked cumulative ACK
            {
                ProcessPiggybackedAck(nakPacket.AckNumber, nakPacket.Header.Timestamp, nowMicros); // Process ACK to acknowledge delivered data before handling NAK gaps
            }

            lock (_sync) // Acquire protocol lock for safe send buffer access
            {
                for (int i = 0; i < nakPacket.MissingSequences.Count; i++) // Iterate peer's reported missing sequences
                {
                    uint sequence = nakPacket.MissingSequences[i]; // Current missing sequence number
                    OutboundSegment segment; // Look up corresponding outbound segment
                    if (_sendBuffer.TryGetValue(sequence, out segment)) // Segment exists in our send buffer
                    {
                        // Only retransmit if: not already marked, not already ACKed,
                        // and retransmit cooldown has expired.
                        if (!segment.NeedsRetransmit && !segment.Acked && ShouldAcceptRetransmitRequestUnsafe(segment, nowMicros)) // Eligible for retransmission
                        {
                            segment.NeedsRetransmit = true; // Mark for retransmission
                            // Mark as urgent in cold-path SACK tracking state to bypass pacing.
                            SackTrackingState nakSackState = GetOrCreateSackTrackingUnsafe(segment.SequenceNumber); // Lazy-create if needed
                            nakSackState.UrgentRetransmit = true; // Bypass pacing for NAK-triggered recovery
                            _tailLossProbePending = false; // NAK proves the path is alive.
                            notifiedLoss = true; // Signal that we detected a loss
                        }
                    }
                }

                if (notifiedLoss) // At least one NAKed segment was marked for retransmit
                {
                    bool isCongestionLoss = ClassifyLossesUnsafe(nakPacket.MissingSequences, nowMicros, 0); // Classify batch of NAKed losses
                    _bbr.OnPacketLoss(nowMicros, GetRetransmissionRatioUnsafe(), isCongestionLoss); // Notify BBR of packet loss
                    TraceLogUnsafe("NAK loss congestion=" + isCongestionLoss + " count=" + nakPacket.MissingSequences.Count); // Debug trace
                }
            }

            await FlushSendQueueAsync().ConfigureAwait(false); // Trigger send loop to retransmit NAKed segments
        }

        // ---- ACK validation ----

        /// <summary>
        /// Validates that the ACK packet is plausible — must be called under _sync lock.
        ///
        /// Checks:
        ///   1. Non-null packet
        ///   2. Connection ID matches (prevent cross-connection injection)
        ///   3. Cumulative ACK does not recede (monotonic: newest ACK >= previous largest)
        ///   4. SACK blocks are well-formed (Start <= End for each block)
        ///
        /// The non-receding ACK check is a critical security property: it prevents an
        /// attacker from replaying an old ACK to make the sender think data was lost.
        /// </summary>
        private bool IsAckPlausibleUnsafe(UcpAckPacket ackPacket)
        {
            if (ackPacket == null) // Null packet is never plausible
            {
                return false; // Reject null
            }

            if (ackPacket.Header.ConnectionId != _connectionId) // Connection ID mismatch
            {
                return false; // Wrong connection — prevent cross-connection injection
            }

            // PAWS timestamp check as additional defense layer: reject ACK packets whose
            // timestamps are too far behind the largest timestamp seen from this peer.
            // This catches stale ACKs that would otherwise pass the sequence-number checks
            // after a 32-bit sequence number wrap.
            if (_pawsEnabled && _largestTimestampSeen > 0 && // PAWS active and at least one packet seen
                _largestTimestampSeen - ackPacket.Header.Timestamp > UcpConstants.PAWS_TIMEOUT_MICROS) // Timestamp >60s behind
            {
                return false; // Stale ACK — reject via PAWS
            }

            // ACK must not recede — the cumulative ACK number is monotonic.
            if (_hasLargestCumulativeAckNumber && UcpSequenceComparer.IsBefore(ackPacket.AckNumber, _largestCumulativeAckNumber)) // ACK number is behind the largest we've seen
            {
                return false; // ACK cannot recede.
            }

            // Validate SACK block structural integrity.
            if (ackPacket.SackBlocks != null) // SACK blocks are present
            {
                for (int i = 0; i < ackPacket.SackBlocks.Count; i++) // Iterate each SACK block
                {
                    SackBlock block = ackPacket.SackBlocks[i]; // Current SACK block
                    if (UcpSequenceComparer.IsAfter(block.Start, block.End)) // Start > End: malformed
                    {
                        return false; // Malformed SACK block.
                    }
                }
            }

            return true; // Packet passes all plausibility checks
        }

        /// <summary>
        /// Returns the highest End value across all SACK blocks.  Used to determine
        /// the upper bound of the sequence space that the peer has received.
        /// Segments with sequence numbers below this bound that are NOT in any SACK
        /// block are candidates for loss detection.
        /// </summary>
        private static uint GetHighestSackEnd(List<SackBlock> blocks)
        {
            uint highest = 0; // Current highest end value
            bool hasValue = false; // Whether we've set a value yet
            for (int i = 0; i < blocks.Count; i++) // Iterate all SACK blocks
            {
                if (!hasValue || UcpSequenceComparer.IsAfter(blocks[i].End, highest)) // First value or current block ends higher
                {
                    highest = blocks[i].End; // Update highest end value
                    hasValue = true; // Mark that we have a value
                }
            }

            return highest; // Return highest SACK end (or 0 if list was empty)
        }

        /// <summary>
        /// Sorts SACK blocks by their Start sequence number for efficient linear
        /// scanning in HandleAckAsync.  Sorting enables the two-pointer walk where
        /// both the segment iterator and SACK block index advance monotonically
        /// through their respective sorted sequences.
        ///
        /// Must be called under _sync — the blocks list is mutated in-place.
        /// </summary>
        private static void SortSackBlocksUnsafe(List<SackBlock> blocks)
        {
            if (blocks == null || blocks.Count <= 1)
            {
                return;
            }

            blocks.Sort(delegate (SackBlock left, SackBlock right)
            {
                return UcpSequenceComparer.Instance.Compare(left.Start, right.Start);
            });
        }

        // ---- SACK-based fast retransmit ----

        /// <summary>
        /// Gets or creates a SackTrackingState entry for the given sequence number.
        /// Lazy-allocation ensures only segments observed as SACK holes consume
        /// this memory — the common case (immediately-ACKed segments) has no entry.
        ///
        /// Must be called under _sync.
        /// </summary>
        private SackTrackingState GetOrCreateSackTrackingUnsafe(uint sequenceNumber)
        {
            SackTrackingState state;
            if (!_sackTracking.TryGetValue(sequenceNumber, out state)) // Check for existing entry
            {
                state = new SackTrackingState(); // Lazy-create cold-path tracking state
                _sackTracking[sequenceNumber] = state; // Store keyed by sequence number
            }
            return state; // Return existing or newly-created state
        }

        /// <summary>
        /// Determines whether a segment identified as missing via SACK should be
        /// fast-retransmitted (without waiting for RTO).
        ///
        /// SACK-based fast retransmit works differently from duplicate-ACK fast
        /// retransmit.  Instead of counting identical ACKs, it observes that SACK
        /// blocks have "bracketed" a sequence number — lower and higher data was
        /// received, but this specific sequence was not.  When that observation is
        /// repeated enough times and enough time has passed (reorder grace), the
        /// segment is presumed lost.
        ///
        /// Decision criteria:
        ///   1. Segment must have been sent at least once
        ///   2. Not already notified for fast retransmit (deduplication)
        ///   3. EnableAggressiveSackRecovery must be enabled in config
        ///   4. Reorder grace period must have expired (time since last send >= SRTT)
        ///   5. FEC repair must not be pending for this segment's group
        ///   6. MissingAckCount (in cold-path _sackTracking) must meet the threshold:
        ///      - First missing sequence (leading hole): SACK_FAST_RETRANSMIT_THRESHOLD
        ///      - Non-leading holes: +1 additional observation, unless the hole is
        ///        explicitly reported and the distance past the hole is large enough
        ///   7. Non-leading holes must be confirmed as "reported SACK holes"
        ///      (bracketed by lower and higher SACK ranges)
        /// </summary>
        private bool ShouldFastRetransmitSackHoleUnsafe(OutboundSegment segment, uint firstMissingSequence, uint highestSack, bool reportedSackHole, long nowMicros)
        {
            if (segment == null || segment.LastSendMicros <= 0)
            {
                return false;
            }

            if (_sackFastRetransmitNotified.Contains(segment.SequenceNumber))
            {
                return false; // Already notified — prevent duplicate fast retransmit.
            }

            if (!_config.EnableAggressiveSackRecovery)
            {
                return false;
            }

            // Reorder grace: a packet must be missing for at least one SRTT before
            // we assume it was lost.  Below this threshold, we might just be seeing
            // reordering on the network.
            long reorderGraceMicros = GetSackFastRetransmitReorderGraceMicrosUnsafe();
            if (nowMicros - segment.LastSendMicros < reorderGraceMicros)
            {
                return false; // Still within reorder grace period.
            }

            // If FEC repair packets have been sent for this group, give FEC time
            // to recover before triggering retransmission.
            if (HasPendingFecRepairUnsafe(segment, nowMicros))
            {
                return false; // FEC might still recover this.
            }

            bool firstMissing = segment.SequenceNumber == firstMissingSequence;
            // Non-leading holes require an extra observation for safety.
            int requiredObservations = firstMissing ? UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD : UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD + 1;
            uint distancePastHole = unchecked(highestSack - segment.SequenceNumber);
            // Reduce required observations when the hole is far behind the ACK frontier
            // AND it's a confirmed reported hole — the evidence is strong enough.
            if (!firstMissing && reportedSackHole && distancePastHole >= (uint)Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD, _config.FecGroupSize))
            {
                requiredObservations = UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD;
            }

            // Retrieve cold-path SACK tracking state for MissingAckCount (defaults to 0 if no entry).
            SackTrackingState sackState;
            int missingAckCount = _sackTracking.TryGetValue(segment.SequenceNumber, out sackState) ? sackState.MissingAckCount : 0; // Default to 0 if never tracked
            if (missingAckCount < requiredObservations)
            {
                return false;
            }

            // First missing sequence (leading hole): always fast-retransmit when threshold met.
            if (firstMissing)
            {
                return true;
            }

            // Non-leading holes require the "reported" confirmation (bracketed).
            if (!reportedSackHole)
            {
                return false;
            }

            // Far-past holes with strong evidence: fast-retransmit.
            if (distancePastHole >= UcpConstants.SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks whether FEC repair for this segment's group is still pending.
        /// If yes, SACK-based fast retransmit should wait — FEC may recover the
        /// segment without needing a retransmission.  The grace period is the
        /// time during which the repair packets could plausibly arrive.
        ///
        /// This prevents the wasteful scenario where both FEC repair and SACK
        /// retransmit are triggered simultaneously, doubling the recovery overhead.
        /// </summary>
        private bool HasPendingFecRepairUnsafe(OutboundSegment segment, long nowMicros)
        {
            if (_fecCodec == null || segment == null)
            {
                return false;
            }

            // Check cold-path SACK tracking state for the first observation timestamp.
            SackTrackingState sackState;
            if (!_sackTracking.TryGetValue(segment.SequenceNumber, out sackState) || sackState.FirstMissingAckMicros <= 0) // No tracking or no observation yet
            {
                return false; // This segment has never been observed as a SACK hole
            }

            uint groupBase = _fecCodec.GetGroupBase(segment.SequenceNumber);
            if (!_fecRepairSentGroups.Contains(groupBase))
            {
                return false; // No repair sent for this group — no FEC to wait for.
            }

            long graceMicros = GetFecFastRetransmitGraceMicrosUnsafe();
            return nowMicros - sackState.FirstMissingAckMicros < graceMicros; // Check if within FEC repair grace period
        }

        /// <summary>
        /// Returns the grace period during which FEC repair is expected before
        /// SACK fast retransmit triggers.  Scaled to SRTT/16, bounded between
        /// SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS and 4× that value.
        /// </summary>
        private long GetFecFastRetransmitGraceMicrosUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            if (rttMicros <= 0)
            {
                rttMicros = _config.MinRtoMicros;
            }

            if (rttMicros <= 0)
            {
                return UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS;
            }

            // FEC repair packets travel through the same path, so they should arrive
            // within ~RTT/16 after the SACK observation if they were sent.
            long adaptiveGraceMicros = rttMicros / 16;
            long maxGraceMicros = UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS * 4;
            return Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, Math.Min(adaptiveGraceMicros, maxGraceMicros));
        }

        /// <summary>
        /// Determines whether a non-leading hole is "reported" by SACK blocks.
        ///
        /// A non-leading hole is trustworthy only when:
        ///   - Lower data was cumulatively ACKed or SACKed (hasLowerAck)
        ///   - A later SACK block proves the receiver has moved past this exact
        ///     sequence (hasHigherSack)
        ///
        /// This bracketing is critical: without it, a truncated SACK list (limited
        /// by MaxAckSackBlocks) could omit a segment simply because the list didn't
        /// have room, not because the segment was actually lost.
        ///
        /// Must be called under _sync.
        /// </summary>
        private static bool IsReportedSackHoleUnsafe(uint sequenceNumber, uint cumulativeAckNumber, List<SackBlock> sackBlocks)
        {
            if (sackBlocks == null || sackBlocks.Count == 0)
            {
                return false;
            }

            bool hasLowerAck = UcpSequenceComparer.IsBeforeOrEqual(cumulativeAckNumber, sequenceNumber);
            bool hasHigherSack = false;
            for (int i = 0; i < sackBlocks.Count; i++)
            {
                SackBlock block = sackBlocks[i];
                if (UcpSequenceComparer.IsInForwardRange(sequenceNumber, block.Start, block.End))
                {
                    return false; // Sequence is inside a SACK block — not a hole at all.
                }

                if (UcpSequenceComparer.IsBefore(block.End, sequenceNumber))
                {
                    hasLowerAck = true;
                    continue;
                }

                if (UcpSequenceComparer.IsAfter(block.Start, sequenceNumber))
                {
                    hasHigherSack = true;
                    break; // Found a range beyond our sequence — proven hole.
                }
            }

            return hasLowerAck && hasHigherSack;
        }

        /// <summary>
        /// Returns the minimum time a segment must wait before SACK fast retransmit
        /// triggers.  Set to one full SRTT — a reordered packet takes at most one RTT
        /// (forward direction) to arrive, so waiting one RTT prevents spurious fast
        /// retransmits of merely reordered (not lost) packets.
        ///
        /// Must be called under _sync.
        /// </summary>
        private long GetSackFastRetransmitReorderGraceMicrosUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            if (rttMicros <= 0)
            {
                long fallbackRttMicros = _config.MinRtoMicros > 0 ? _config.MinRtoMicros : UcpConstants.DEFAULT_RTO_MICROS;
                return Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, fallbackRttMicros * 2);
            }

            return Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros);
        }

        // ---- Duplicate ACK handling ----

        /// <summary>
        /// Updates duplicate ACK counters and triggers fast retransmit if the
        /// threshold is reached.
        ///
        /// Duplicate ACK fast retransmit (RFC 5681):
        ///   - When the same cumulative ACK number arrives multiple times in a row,
        ///     each new packet after the first must be an out-of-order arrival at
        ///     the receiver, implying that the expected sequence was lost.
        ///   - After DUPLICATE_ACK_THRESHOLD (3) duplicate ACKs, the next sequence
        ///     number after the cumulative ACK is inferred lost and fast-retransmitted.
        ///
        /// Fast recovery:
        ///   - Once fast retransmit triggers, _fastRecoveryActive is set to prevent
        ///     further fast retransmits for the same loss event.
        ///   - Recovery exits when a non-duplicate ACK arrives (cumulative ACK advances).
        ///
        /// Must be called under _sync.
        /// </summary>
        private void UpdateDuplicateAckStateUnsafe(UcpAckPacket ackPacket, long nowMicros, out bool fastRetransmitTriggered)
        {
            fastRetransmitTriggered = false; // Default: no fast retransmit triggered
            bool hasSack = ackPacket.SackBlocks != null && ackPacket.SackBlocks.Count > 0; // SACK blocks present (informational)
            bool duplicateAck = _hasLastAckNumber && ackPacket.AckNumber == _lastAckNumber; // Same cumulative ACK as previous = duplicate
            if (duplicateAck) // This is a duplicate ACK
            {
                _duplicateAckCount++; // Increment duplicate ACK counter
                if (_duplicateAckCount >= UcpConstants.DUPLICATE_ACK_THRESHOLD && !_fastRecoveryActive) // Threshold reached and not already in recovery
                {
                    // Infer the next sequence after cumulative ACK as lost.
                    uint lostSeq = UcpSequenceComparer.Increment(ackPacket.AckNumber); // The first un-ACKed sequence (leading hole)
                    OutboundSegment lostSegment; // Look up corresponding segment
                    if (_sendBuffer.TryGetValue(lostSeq, out lostSegment) && !lostSegment.Acked && lostSegment.SendCount == 1 && !lostSegment.NeedsRetransmit) // Segment exists, not yet ACKed, first transmission, not already marked
                    {
                        long rttForFastRetransmit = GetFastRetransmitAgeThresholdUnsafe(); // Age threshold for DUPACK fast retransmit
                        if (ShouldTriggerEarlyRetransmitUnsafe() || rttForFastRetransmit <= 0 || nowMicros - lostSegment.LastSendMicros >= rttForFastRetransmit) // Early retransmit condition or age threshold met
                        {
                            lostSegment.NeedsRetransmit = true; // Mark for retransmission
                            // Mark as urgent in cold-path SACK tracking state to bypass pacing.
                            SackTrackingState dupAckSackState = GetOrCreateSackTrackingUnsafe(lostSeq); // Lazy-create if needed
                            dupAckSackState.UrgentRetransmit = true; // Bypass pacing for duplicate-ACK fast retransmit
                            _fastRecoveryActive = true; // Enter fast recovery mode (prevent further triggers)
                            _fastRetransmissions++; // Increment fast retransmit counter
                            fastRetransmitTriggered = true; // Signal to caller that retransmit was triggered
                            bool isCongestionLoss = IsCongestionLossUnsafe(lostSeq, 0, nowMicros, 1); // Classify loss: congestion or random
                            _bbr.OnFastRetransmit(nowMicros, isCongestionLoss); // Notify BBR of fast retransmit event
                            TraceLogUnsafe("FastRetransmit sequence=" + lostSeq + " dupAck=true congestion=" + isCongestionLoss); // Debug trace
                        }
                    }
                }
            }
            else // Non-duplicate ACK (cumulative ACK advanced)
            {
                // Non-duplicate ACK: reset counters and exit fast recovery.
                _duplicateAckCount = 0; // Reset duplicate ACK counter
                _fastRecoveryActive = false; // Exit fast recovery mode
            }

            _lastAckNumber = ackPacket.AckNumber; // Store this ACK number for next duplicate detection
            _hasLastAckNumber = true; // Mark that we have a baseline ACK number
        }

        // ---- Loss classification ----

        /// <summary>
        /// Classifies whether a single sequence loss is congestion-related (vs. random).
        /// Convenience overload that wraps the sequence in a single-element list.
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool IsCongestionLossUnsafe(uint sequenceNumber, long sampleRttMicros, long nowMicros, int contiguousLossCount)
        {
            List<uint> sequences = new List<uint>(1); // Create single-element list for uniform interface
            sequences.Add(sequenceNumber); // Add the sequence number to the list
            return ClassifyLossesUnsafe(sequences, nowMicros, sampleRttMicros, contiguousLossCount); // Delegate to multi-sequence classifier
        }

        /// <summary>
        /// Classifies multiple sequence losses as congestion or random.
        /// Computes the maximum contiguous loss run from the input list.
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool ClassifyLossesUnsafe(IList<uint> sequenceNumbers, long nowMicros, long sampleRttMicros)
        {
            return ClassifyLossesUnsafe(sequenceNumbers, nowMicros, sampleRttMicros, GetMaxContiguousLossRun(sequenceNumbers));
        }

        /// <summary>
        /// Classifies losses as congestion based on deduplicated loss event count,
        /// contiguous loss run length, and RTT inflation relative to the minimum.
        ///
        /// Core algorithm for distinguishing congestion loss from random loss:
        ///
        /// A. Deduplication:
        ///    Each loss sequence is added to _recentLossSequences (hash set) and
        ///    _recentLossEvents (queue with timestamp).  Duplicates are skipped,
        ///    and expired events (older than the classification window) are pruned.
        ///
        /// B. Congestion indicators:
        ///    1. Deduplicated loss count > BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS: many
        ///       different sequences lost — likely congestion, not random corruption.
        ///    2. Max contiguous loss run >= BBR_CONGESTION_LOSS_BURST_THRESHOLD: a
        ///       burst of consecutive losses indicates a queue overflow.
        ///    3. Median RTT > min_rtt * BBR_CONGESTION_LOSS_RTT_MULTIPLIER: RTT has
        ///       increased beyond baseline propagation delay — queues are building.
        ///
        /// C. RTT-inflation detection:
        ///    The loss classifier compares the median RTT from recent loss events
        ///    against the minimum observed RTT (from all collected samples).  A
        ///    sustained increase indicates bufferbloat-induced loss rather than
        ///    transient random corruption.
        ///
        /// Must be called under _sync.
        /// </summary>
        /// <returns>True if losses are classified as congestion.</returns>
        private bool ClassifyLossesUnsafe(IList<uint> sequenceNumbers, long nowMicros, long sampleRttMicros, int contiguousLossCount)
        {
            long windowMicros = GetLossClassifierWindowMicrosUnsafe();
            PruneLossEventsUnsafe(nowMicros, windowMicros);
            long rttMicros = sampleRttMicros > 0 ? sampleRttMicros : _lastRttMicros;
            bool addedLoss = false;
            if (sequenceNumbers != null)
            {
                for (int i = 0; i < sequenceNumbers.Count; i++)
                {
                    uint sequenceNumber = sequenceNumbers[i];
                    // Deduplication: a sequence is only recorded once per window.
                    if (_recentLossSequences.Add(sequenceNumber))
                    {
                        _recentLossEvents.Enqueue(new LossEvent { SequenceNumber = sequenceNumber, TimestampMicros = nowMicros, RttMicros = rttMicros });
                        addedLoss = true;
                    }
                }
            }

            if (addedLoss)
            {
                // Re-prune in case we added events that push the window boundary.
                PruneLossEventsUnsafe(nowMicros, windowMicros);
            }

            int dedupedLossCount = _recentLossEvents.Count;
            if (dedupedLossCount == 0)
            {
                return false; // No deduplicated loss events to classify.
            }

            int maxContiguousLossCount = Math.Max(contiguousLossCount, GetMaxContiguousRecentLossRunUnsafe());
            // Too few losses and no burst → random loss, not congestion.
            if (dedupedLossCount <= UcpConstants.BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS && maxContiguousLossCount < UcpConstants.BBR_CONGESTION_LOSS_BURST_THRESHOLD)
            {
                return false;
            }

            // Check for clustered loss (many deduped events or burst).
            bool clusteredLoss = maxContiguousLossCount >= UcpConstants.BBR_CONGESTION_LOSS_BURST_THRESHOLD || dedupedLossCount > UcpConstants.BBR_CONGESTION_LOSS_WINDOW_THRESHOLD;
            if (!clusteredLoss)
            {
                return false;
            }

            // RTT-inflation check: is RTT elevated above the baseline?
            long medianRttMicros = GetLossWindowMedianRttMicrosUnsafe();
            long minRttMicros = GetMinimumObservedRttMicrosUnsafe();
            if (medianRttMicros <= 0 || minRttMicros <= 0)
            {
                return false;
            }

            // Congestion requires RTT inflation (queue buildup).
            return medianRttMicros > (long)(minRttMicros * UcpConstants.BBR_CONGESTION_LOSS_RTT_MULTIPLIER);
        }

        /// <summary>
        /// Returns the time window for recent loss classification: max(1ms, 2*minRTT).
        /// Events older than this are pruned.
        ///
        /// Must be called under _sync.
        /// </summary>
        private long GetLossClassifierWindowMicrosUnsafe()
        {
            long minRttMicros = GetMinimumObservedRttMicrosUnsafe(); // Get minimum observed RTT (baseline propagation delay)
            if (minRttMicros <= 0) // No minimum RTT available
            {
                minRttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros; // Fall back to SRTT or configured minimum RTO
            }

            return Math.Max(UcpConstants.MICROS_PER_MILLI, minRttMicros * 2); // Window = max(1ms, 2 * min_RTT)
        }

        /// <summary>
        /// Removes loss events older than the classification window.
        /// Called before each classification to keep the queue bounded.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void PruneLossEventsUnsafe(long nowMicros, long windowMicros)
        {
            while (_recentLossEvents.Count > 0 && nowMicros - _recentLossEvents.Peek().TimestampMicros > windowMicros) // Oldest event is outside the classification window
            {
                LossEvent expired = _recentLossEvents.Dequeue(); // Remove expired event from front of queue
                _recentLossSequences.Remove(expired.SequenceNumber); // Also remove from dedup hash set
            }
        }

        /// <summary>
        /// Returns the median RTT across recent loss events, used as the congestion
        /// RTT for comparison against the minimum baseline.  Median is used instead
        /// of average to be robust against outlier RTT spikes.
        ///
        /// Must be called under _sync.
        /// </summary>
        private long GetLossWindowMedianRttMicrosUnsafe()
        {
            List<long> samples = new List<long>(); // Collect RTT samples from loss events
            foreach (LossEvent lossEvent in _recentLossEvents) // Iterate all recent loss events
            {
                if (lossEvent.RttMicros > 0) // Loss event has a valid RTT
                {
                    samples.Add(lossEvent.RttMicros); // Add to sample list
                }
            }

            // Fall back to the most recent RTT sample if no loss-event RTTs recorded.
            if (samples.Count == 0 && _lastRttMicros > 0) // No loss-event samples but we have a recent RTT
            {
                samples.Add(_lastRttMicros); // Use most recent RTT as fallback
            }

            if (samples.Count == 0) // No samples available at all
            {
                return 0; // Cannot compute median
            }

            samples.Sort(); // Sort samples for median computation
            return samples[samples.Count / 2]; // Median.
        }

        /// <summary>
        /// Returns the minimum observed RTT from all collected RTT samples.
        /// This represents the baseline propagation delay (no queuing) and
        /// is used by the loss classifier as the "floor" for RTT-inflation detection.
        ///
        /// Must be called under _sync.
        /// </summary>
        private long GetMinimumObservedRttMicrosUnsafe()
        {
            long minRttMicros = 0; // Minimum RTT found so far
            for (int i = 0; i < _rttSamplesMicros.Count; i++) // Scan all collected RTT samples
            {
                long sample = _rttSamplesMicros[i]; // Current RTT sample
                if (sample > 0 && (minRttMicros == 0 || sample < minRttMicros)) // Valid positive sample and (first found or lower than current min)
                {
                    minRttMicros = sample; // Update minimum
                }
            }

            if (minRttMicros == 0 && _lastRttMicros > 0) // No samples in history but we have a recent RTT
            {
                minRttMicros = _lastRttMicros; // Use most recent RTT as fallback
            }

            return minRttMicros; // Return minimum observed RTT
        }

        /// <summary>
        /// Returns the maximum contiguous loss run among recent loss events.
        /// Contiguous losses (consecutive sequence numbers) strongly indicate
        /// a queue overflow event (congestion) rather than random loss.
        ///
        /// Must be called under _sync.
        /// </summary>
        private int GetMaxContiguousRecentLossRunUnsafe()
        {
            if (_recentLossEvents.Count == 0) // No loss events recorded
            {
                return 0; // No contiguous run
            }

            List<uint> sequenceNumbers = new List<uint>(_recentLossEvents.Count); // Pre-allocate for known count
            foreach (LossEvent lossEvent in _recentLossEvents) // Iterate recent loss events
            {
                sequenceNumbers.Add(lossEvent.SequenceNumber); // Collect sequence numbers
            }

            return GetMaxContiguousLossRun(sequenceNumbers); // Compute longest contiguous run
        }

        /// <summary>
        /// Computes the longest run of consecutive sequence numbers in a list
        /// (wraparound-aware via UcpSequenceComparer).  Sorts input, counts
        /// consecutive runs skipping duplicates.
        /// </summary>
        private static int GetMaxContiguousLossRun(IList<uint> sequenceNumbers)
        {
            if (sequenceNumbers == null || sequenceNumbers.Count == 0) // Null or empty input
            {
                return 0; // No contiguous run
            }

            List<uint> sorted = new List<uint>(sequenceNumbers); // Copy into mutable list
            sorted.Sort(UcpSequenceComparer.Instance); // Sort by sequence number (wraparound-aware)
            int maxRun = 1; // Longest run found so far (default: 1)
            int currentRun = 1; // Current consecutive run length
            for (int i = 1; i < sorted.Count; i++) // Scan sorted list for consecutive runs
            {
                if (sorted[i] == sorted[i - 1]) // Duplicate sequence (already counted)
                {
                    continue; // Skip duplicates (deduplication happens at higher level).
                }

                if (unchecked(sorted[i] - sorted[i - 1]) == 1U) // Consecutive (difference of exactly 1)
                {
                    currentRun++; // Extend current run
                    if (currentRun > maxRun) // New longest run
                    {
                        maxRun = currentRun; // Update max
                    }
                }
                else // Non-consecutive — gap found
                {
                    currentRun = 1; // Gap found — reset contiguous run.
                }
            }

            return maxRun; // Return longest contiguous run length
        }

        /// <summary>
        /// Returns the minimum age before a segment is eligible for duplicate-ACK
        /// fast retransmit: max(reorder_grace_min, SRTT/8).  This is shorter than
        /// the SACK reorder grace (1*SRTT) because duplicate ACKs provide stronger
        /// evidence of loss — three identical ACKs means three later packets have
        /// arrived, so reordering is unlikely to explain the gap.
        /// </summary>
        private long GetFastRetransmitAgeThresholdUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros; // Best available RTT estimate
            return rttMicros <= 0 ? 0 : Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros / 8); // Grace = max(min_grace, SRTT/8); 0 if no RTT
        }

        /// <summary>
        /// Returns true if early retransmit should trigger (when inflight is
        /// too small for the normal duplicate ACK mechanism to produce 3 DUPACKs).
        /// With only 1-2 packets in flight, the receiver can only emit 1-2 DUPACKs,
        /// so waiting for 3 would cause a head-of-line timeout.  Early retransmit
        /// triggers for small inflight sizes without requiring full DUPACK count.
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool ShouldTriggerEarlyRetransmitUnsafe()
        {
            int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize)); // Estimate number of segments in flight
            return inflightSegments > 0 && inflightSegments <= UcpConstants.EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS; // Low inflight — early retransmit should trigger
        }

        /// <summary>
        /// Guards against redundant retransmits: a segment that has already been
        /// retransmitted (SendCount > 1) must wait at least one SRTT (or current RTO)
        /// before accepting another retransmit request.  This prevents NAK amplification
        /// where repeated NAKs cause the same segment to be retransmitted multiple times
        /// before the first retransmission can reach the receiver.
        ///
        /// First retransmission (SendCount <= 1) is always accepted — the segment
        /// hasn't been retransmitted yet.
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool ShouldAcceptRetransmitRequestUnsafe(OutboundSegment segment, long nowMicros)
        {
            if (segment == null || segment.SendCount <= 1 || segment.LastSendMicros <= 0) // First retransmit or no send history
            {
                return true; // First retransmit is always accepted.
            }

            long graceMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _rtoEstimator.CurrentRtoMicros; // SRTT or current RTO as grace period
            if (graceMicros <= 0) // No valid RTT estimate
            {
                return true; // No RTT estimate — accept to avoid stall.
            }

            return nowMicros - segment.LastSendMicros >= graceMicros; // Cooldown has expired — accept retransmit request
        }

        /// <summary>
        /// Returns the ACK-progress grace window used to suppress bulk RTO scans.
        /// If ACKs are arriving recently (within this window), the path is alive
        /// and recovery should be driven by SACK/NAK/FEC instead of retransmitting
        /// the entire outstanding pipe on RTO.  This avoids RTO amplification
        /// during partial loss events.
        ///
        /// Must be called under _sync.
        /// </summary>
        private long GetRtoAckProgressSuppressionMicrosUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            if (rttMicros <= 0)
            {
                rttMicros = _config.MinRtoMicros;
            }

            if (rttMicros <= 0)
            {
                return UcpConstants.RTO_ACK_PROGRESS_SUPPRESSION_MICROS;
            }

            return Math.Max(UcpConstants.RTO_ACK_PROGRESS_SUPPRESSION_MICROS, rttMicros / 4);
        }

        /// <summary>
        /// Returns the overall retransmission ratio (retransmitted / total sent).
        /// Used by BBR for bandwidth estimation adjustment during loss events.
        ///
        /// Must be called under _sync.
        /// </summary>
        private double GetRetransmissionRatioUnsafe()
        {
            int total = _sentDataPackets + _retransmittedPackets;
            return total == 0 ? 0d : _retransmittedPackets / (double)total;
        }

        /// <summary>
        /// Conditionally writes a debug trace message for this PCB when
        /// EnableDebugLog is configured.
        ///
        /// Must be called under _sync (accesses _config).
        /// </summary>
        private void TraceLogUnsafe(string message)
        {
            if (_config.EnableDebugLog)
            {
                Trace.WriteLine("[UCP PCB] " + message);
            }
        }

        // ---- Packet handler: DATA ----

        /// <summary>
        /// Handles an incoming DATA packet — the primary data reception pipeline.
        ///
        /// Processing stages:
        ///
        /// A. Piggybacked ACK processing:
        ///    Before processing the data payload, any piggybacked cumulative ACK
        ///    on the data packet is processed via ProcessPiggybackedAck.  This
        ///    is one of UCP's key optimizations: every DATA packet carries the
        ///    receiver's ACK state, eliminating standalone ACK packets during
        ///    bidirectional data flow.
        ///
        /// B. Packet validation:
        ///    Payload must be non-null, within MaxPayloadSize, and have valid
        ///    fragment metadata (FragmentTotal > 0, FragmentIndex < FragmentTotal).
        ///
        /// C. Receive window check:
        ///    If the segment falls within the receive window (used bytes + payload
        ///    length <= local window), it is stored in _recvBuffer (sorted by
        ///    sequence number via UcpSequenceComparer).
        ///
        /// D. FEC feed:
        ///    If FEC is enabled, the payload is fed to the FEC codec for real-time
        ///    encoding/decoding.  Fragment metadata is stored for later reassembly.
        ///    The codec may immediately recover missing packets from its accumulated
        ///    data + repair data.
        ///
        /// E. Gap detection and NAK collection (NAK gap detection):
        ///    If the received sequence > _nextExpectedSequence, there's a gap.
        ///    The receiver scans from _nextExpectedSequence up to the received
        ///    sequence, and for each missing sequence, increments its missing
        ///    counter.  If the counter reaches NAK_MISSING_THRESHOLD and the
        ///    reorder-grace period has expired, a NAK entry is queued.
        ///
        ///    NAK rate limiting: each sequence can only be NAKed once (tracked
        ///    by _nakIssued).  MAX_NAK_SEQUENCES_PER_PACKET entries per NAK
        ///    packet.  MAX_NAK_MISSING_SCAN limits how far ahead we scan.
        ///
        /// F. In-order delivery:
        ///    After storing and NAK-gap processing, the receive loop drains
        ///    contiguous in-order segments from _recvBuffer into readyPayloads.
        ///    Each drained segment advances _nextExpectedSequence.
        ///
        /// G. Immediate ACK scheduling:
        ///    If reordering is detected (gaps in buffer), an immediate ACK may
        ///    be sent so the sender gets SACK information promptly.  Otherwise,
        ///    a delayed ACK is scheduled (which may be piggybacked on an outbound
        ///    data packet, canceling the timer).
        ///
        /// H. NAK emission:
        ///    If any gaps were collected, a NAK packet is sent immediately.
        /// </summary>
        /// <param name="dataPacket">The decoded data packet.</param>
        private void HandleData(UcpDataPacket dataPacket)
        {
            List<uint> missing = new List<uint>(); // Sequences to be NAKed (reported as missing to sender)
            List<byte[]> readyPayloads = new List<byte[]>(); // Contiguous in-order payloads ready for application delivery
            bool shouldEstablish = false; // Whether this data packet completes the handshake
            bool shouldStore = false; // Whether the payload fits in our receive window
            bool sendImmediateAck = false; // Whether to send an immediate ACK (vs delayed)
            bool hasPiggybackedAck = (dataPacket.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Check if DATA packet carries piggybacked ACK

            // Stage A: Process piggybacked ACK from data packet BEFORE handling data payload.
            // This keeps the sender's flight bytes accurate and avoids ACK storms — the
            // peer is already sending data, so piggybacking is free.
            if (hasPiggybackedAck && dataPacket.AckNumber > 0) // Data packet carries a valid piggybacked ACK
            {
                ProcessPiggybackedAck(dataPacket.AckNumber, dataPacket.Header.Timestamp, NowMicros()); // Process the piggybacked cumulative ACK

                if (dataPacket.WindowSize > 0) // Data packet also advertises a window
                {
                    lock (_sync) // Acquire protocol lock for safe window update
                    {
                        _remoteWindowBytes = dataPacket.WindowSize; // Update peer's advertised receive window
                    }
                }
            }

            lock (_sync) // Acquire protocol lock for data processing stages B–F
            {
                // Stage B: Validate packet integrity.
                if (dataPacket.Payload == null || dataPacket.Payload.Length > _config.MaxPayloadSize || dataPacket.FragmentTotal == 0 || dataPacket.FragmentIndex >= dataPacket.FragmentTotal) // Invalid payload or fragment metadata
                {
                    return; // Reject malformed data packet
                }

                // Check if this data packet completes the handshake (server side:
                // client sends data after SYN-ACK, which implicitly acknowledges
                // the server's SYN-ACK when a piggybacked ACK is present).
                if (_state == UcpConnectionState.HandshakeSynReceived && _synAckSent) // Server waiting for client ACK to complete handshake
                {
                    shouldEstablish = true; // Mark handshake complete
                }

                _lastEchoTimestamp = dataPacket.Header.Timestamp; // Store timestamp for future ACK echo
                if (UcpSequenceComparer.IsBefore(dataPacket.SequenceNumber, _nextExpectedSequence)) // Sequence is before expected — duplicate or reordering artifact
                {
                    // Old duplicate: sequence < expected.  These packets are ACKed
                    // (we already have this data) but not stored again.  The peer
                    // needs an ACK so it can converge its send state.
                }
                else // Sequence is at or after expected
                {
                    // Stage C: Receive window check.
                    uint usedBytes = GetReceiveWindowUsedBytesUnsafe(); // Compute current receive window usage
                    shouldStore = usedBytes + dataPacket.Payload.Length <= _localReceiveWindowBytes; // Store only if there's room in the receive window
                    if (shouldStore && !_recvBuffer.ContainsKey(dataPacket.SequenceNumber)) // Window has room and not a duplicate
                    {
                        // Store the segment in the sorted receive buffer.
                        InboundSegment inbound = new InboundSegment(); // Create inbound segment metadata
                        inbound.SequenceNumber = dataPacket.SequenceNumber; // Assign the packet's sequence number
                        inbound.FragmentTotal = dataPacket.FragmentTotal; // Total fragments in the message
                        inbound.FragmentIndex = dataPacket.FragmentIndex; // Position of this fragment
                        inbound.Payload = dataPacket.Payload; // Attach the payload bytes
                        _recvBuffer[dataPacket.SequenceNumber] = inbound; // Insert into sorted receive buffer
                        // Clear NAK/gap tracking state for this sequence — we got it.
                        _nakIssued.Remove(dataPacket.SequenceNumber); // Clear NAK-issued flag
                        _missingSequenceCounts.Remove(dataPacket.SequenceNumber); // Clear missing observation counter
                        _missingFirstSeenMicros.Remove(dataPacket.SequenceNumber); // Clear first-seen timestamp
                        _lastNakIssuedMicros.Remove(dataPacket.SequenceNumber); // Clear last-NAK timestamp

                        // Stage D: Feed FEC codec with newly arrived data.
                        if (_fecCodec != null) // FEC is enabled
                        {
                            _fecFragmentMetadata[dataPacket.SequenceNumber] = new FecFragmentMetadata { FragmentTotal = dataPacket.FragmentTotal, FragmentIndex = dataPacket.FragmentIndex }; // Store fragment metadata for FEC recovery
                            _fecCodec.FeedDataPacket(dataPacket.SequenceNumber, dataPacket.Payload); // Feed raw data to FEC encoder/decoder
                            // Attempt FEC recovery: the new data packet might enable
                            // reconstruction of previously missing packets in the same group.
                            TryRecoverFecAroundUnsafe(dataPacket.SequenceNumber, readyPayloads); // Try to recover missing packets using FEC
                        }
                    }

                    // Stage E: Gap detection and NAK collection.
                    if (shouldStore && UcpSequenceComparer.IsAfter(dataPacket.SequenceNumber, _nextExpectedSequence)) // Received packet is ahead of expected — gap exists
                    {
                        // Gap detected — the peer sent us a packet with a higher sequence
                        // than we expected, meaning some packets in between are missing.
                        sendImmediateAck = ShouldSendImmediateReorderedAckUnsafe(NowMicros()); // Determine if we should send an immediate ACK (vs throttled)
                        uint current = _nextExpectedSequence; // Start scanning from the expected sequence
                        int remainingNakSlots = UcpConstants.MAX_NAK_MISSING_SCAN; // Budget for how far to scan for NAK candidates
                        // Scan from expected sequence up to (but not including) the received
                        // packet, collecting NAK-eligible sequences.
                        while (current != dataPacket.SequenceNumber && remainingNakSlots > 0) // Not reached received seq and still within scan budget
                        {
                            if (!_recvBuffer.ContainsKey(current)) // This sequence is truly missing (not in buffer)
                            {
                                int missingCount; // How many times this sequence has been observed missing
                                _missingSequenceCounts.TryGetValue(current, out missingCount); // Get current count
                                missingCount++; // Increment missing observation
                                _missingSequenceCounts[current] = missingCount; // Store updated count
                                long firstSeenMicros = GetMissingFirstSeenMicrosUnsafe(current); // Get or record first observation time
                                bool missingAgeExpired = HasNakReorderGraceExpiredUnsafe(missingCount, firstSeenMicros, NowMicros()); // Check if reorder grace period has expired
                                bool missingRepeatedEnough = missingCount >= UcpConstants.NAK_MISSING_THRESHOLD; // Enough observations to consider a real loss
                                // Emit NAK only when: enough observations, reorder grace expired,
                                // NAK not already issued, and we have room in the NAK list.
                                if (missing.Count < UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET && missingRepeatedEnough && missingAgeExpired && ShouldIssueNakUnsafe(current)) // NAK slot available and all criteria met
                                {
                                    MarkNakIssuedUnsafe(current); // Mark that NAK was issued for this sequence
                                    missing.Add(current); // Add to the list of sequences to NAK
                                }
                            }

                            current = UcpSequenceComparer.Increment(current); // Advance to next expected sequence
                            remainingNakSlots--; // Decrement scan budget
                        }
                    }

                    // Stage F: Drain contiguous in-order segments for delivery.
                    while (_recvBuffer.Count > 0) // There are buffered segments to check
                    {
                        InboundSegment next; // Next expected segment
                        if (!_recvBuffer.TryGetValue(_nextExpectedSequence, out next)) // Next expected sequence is not yet in buffer
                        {
                            break; // Gap at expected — stop draining
                        }

                        _recvBuffer.Remove(_nextExpectedSequence); // Remove from receive buffer
                        _nakIssued.Remove(_nextExpectedSequence); // Clear NAK tracking
                        _missingSequenceCounts.Remove(_nextExpectedSequence); // Clear missing counter
                        _missingFirstSeenMicros.Remove(_nextExpectedSequence); // Clear first-seen timestamp
                        _lastNakIssuedMicros.Remove(_nextExpectedSequence); // Clear last-NAK timestamp
                        _fecFragmentMetadata.Remove(_nextExpectedSequence); // Clear FEC fragment metadata
                        _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence); // Advance expected sequence
                        readyPayloads.Add(next.Payload); // Add payload to ready list for delivery
                    }

                    // Check if the first gap (immediately after draining) should trigger a NAK.
                    if (_recvBuffer.Count > 0 && !_recvBuffer.ContainsKey(_nextExpectedSequence)) // Buffer has data but expected sequence is missing
                    {
                        if (_recvBuffer.Count >= UcpConstants.IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD && ShouldSendImmediateReorderedAckUnsafe(NowMicros())) // Enough reordered packets and throttle allows
                        {
                            sendImmediateAck = true; // Multiple reordered packets — send ACK now.
                        }

                        int missingCount; // Missing observation counter for expected sequence
                        _missingSequenceCounts.TryGetValue(_nextExpectedSequence, out missingCount); // Get current count
                        long firstSeenMicros = GetMissingFirstSeenMicrosUnsafe(_nextExpectedSequence); // Get first-seen timestamp
                        if (missing.Count < UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET && missingCount >= UcpConstants.NAK_MISSING_THRESHOLD && HasNakReorderGraceExpiredUnsafe(missingCount, firstSeenMicros, NowMicros()) && ShouldIssueNakUnsafe(_nextExpectedSequence)) // All NAK criteria met for the leading gap
                        {
                            MarkNakIssuedUnsafe(_nextExpectedSequence); // Mark NAK issued
                            missing.Add(_nextExpectedSequence); // Add to NAK list
                        }
                    }
                }
            }

            // Deliver ready payloads to the application outside the lock to
            // avoid holding _sync during event handler invocations.
            for (int i = 0; i < readyPayloads.Count; i++) // Iterate all ready payloads
            {
                EnqueuePayload(readyPayloads[i]); // Deliver payload to application (fires DataReceived event)
            }

            if (shouldEstablish) // Data packet completed the handshake
            {
                TransitionToEstablished(); // Transition to Established state
            }

            // Stage H: Emit NAK for collected gaps.
            if (missing.Count > 0) // There are sequences to NAK
            {
                SendNak(missing); // Send NAK packet with missing sequence list
            }

            // Stage G: Schedule or send immediate ACK.
            // Piggybacked ACKs on outbound data packets cancel the delayed ACK timer,
            // so standalone ACKs only fire when no data is flowing.
            if (sendImmediateAck) // Reordering detected — send ACK now
            {
                SendAckPacket(UcpPacketFlags.None, 0); // Transmit immediate ACK with current cumulative state
            }
            else // No reordering — schedule delayed ACK (allows piggybacking)
            {
                ScheduleAck(); // Schedule a delayed ACK for potential piggybacking
            }
        }

        // ---- FEC recovery helpers ----

        /// <summary>
        /// Attempts to recover missing packets around a freshly received sequence
        /// using stored FEC repair data.  Scans all candidate sequences in the
        /// same FEC group, trying the FEC codec reconstructor for each missing one.
        /// If reconstruction succeeds, the recovered packets are stored and any
        /// newly contiguous data is drained.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void TryRecoverFecAroundUnsafe(uint receivedSequenceNumber, List<byte[]> readyPayloads)
        {
            if (_fecCodec == null || readyPayloads == null) // FEC disabled or no output list
            {
                return; // Nothing to recover
            }

            uint groupBase = _fecCodec.GetGroupBase(receivedSequenceNumber); // Get base sequence of the FEC group
            int groupSize = Math.Max(2, _config.FecGroupSize); // FEC group size (minimum 2)
            for (int i = 0; i < groupSize; i++) // Scan all sequences in this FEC group
            {
                uint candidateSeq = groupBase + (uint)i; // Candidate sequence to try recovering
                // Skip sequences that are already received, already delivered, or
                // the one that just arrived (handled by caller).
                if (candidateSeq == receivedSequenceNumber || UcpSequenceComparer.IsBefore(candidateSeq, _nextExpectedSequence) || _recvBuffer.ContainsKey(candidateSeq)) // Skip if already have it
                {
                    continue; // No recovery needed for this candidate
                }

                // Try to reconstruct the candidate from stored repair + data packets.
                if (StoreRecoveredFecPacketsUnsafe(_fecCodec.TryRecoverPacketsFromStoredRepair(candidateSeq), readyPayloads) > 0) // Recovery succeeded
                {
                    return; // Recovery succeeded — stop scanning; drain will do the rest.
                }
            }
        }

        /// <summary>
        /// Stores FEC-recovered packets into the receive buffer and drains any
        /// newly contiguous in-order data.  Each recovered packet is validated
        /// (must not be older than expected, must not already be in buffer) before
        /// insertion via StoreRecoveredFecSegmentUnsafe.
        ///
        /// Must be called under _sync.
        /// </summary>
        /// <returns>Number of recovered packets stored.</returns>
        private int StoreRecoveredFecPacketsUnsafe(List<UcpFecCodec.RecoveredPacket> recoveredPackets, List<byte[]> readyPayloads)
        {
            if (recoveredPackets == null || recoveredPackets.Count == 0) // No recovered packets to store
            {
                return 0; // Nothing stored
            }

            int stored = 0; // Count of successfully stored recovered packets
            for (int i = 0; i < recoveredPackets.Count; i++) // Iterate each recovered packet
            {
                UcpFecCodec.RecoveredPacket recoveredPacket = recoveredPackets[i]; // Current recovered packet
                if (recoveredPacket == null) // Null recovered packet — skip
                {
                    continue; // Skip null entry
                }

                if (StoreRecoveredFecSegmentUnsafe(recoveredPacket.SequenceNumber, recoveredPacket.Payload)) // Store the recovered payload in receive buffer
                {
                    stored++; // Increment stored counter
                }
            }

            if (stored > 0) // At least one packet was stored
            {
                // Drain newly contiguous data resulting from the recovery.
                DrainReadyPayloadsUnsafe(readyPayloads); // Drain any newly contiguous in-order data
            }

            return stored; // Return count of stored recovered packets
        }

        /// <summary>
        /// Stores a single FEC-recovered segment into the receive buffer.
        /// Validates that the sequence is not already received (duplicate check)
        /// and is ahead of the next-expected sequence (not stale).  Retrieves
        /// fragment metadata for proper reassembly.
        ///
        /// Must be called under _sync.
        /// </summary>
        /// <returns>True if the segment was stored successfully.</returns>
        private bool StoreRecoveredFecSegmentUnsafe(uint recoveredSeq, byte[] recovered)
        {
            if (recovered == null || UcpSequenceComparer.IsBefore(recoveredSeq, _nextExpectedSequence) || _recvBuffer.ContainsKey(recoveredSeq)) // Null, stale, or duplicate
            {
                return false; // Cannot store — reject
            }

            FecFragmentMetadata metadata; // Fragment metadata for reassembly
            if (!_fecFragmentMetadata.TryGetValue(recoveredSeq, out metadata)) // No metadata stored for this sequence
            {
                // Fallback: assume single-fragment message.
                metadata = new FecFragmentMetadata { FragmentTotal = 1, FragmentIndex = 0 }; // Default: single-fragment message
            }

            InboundSegment inbound = new InboundSegment(); // Create inbound segment
            inbound.SequenceNumber = recoveredSeq; // Assign recovered sequence number
            inbound.FragmentTotal = metadata.FragmentTotal; // Total fragments from metadata
            inbound.FragmentIndex = metadata.FragmentIndex; // Fragment position from metadata
            inbound.Payload = recovered; // Attach recovered payload

            _recvBuffer[recoveredSeq] = inbound; // Insert into sorted receive buffer
            ClearMissingReceiveStateUnsafe(recoveredSeq); // Clean up gap/NAK tracking for this sequence
            return true; // Successfully stored
        }

        /// <summary>
        /// Drains all contiguous in-order segments from the receive buffer into
        /// the ready payloads list.  Called after FEC recovery or new data arrival
        /// when newly contiguous data may be available.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void DrainReadyPayloadsUnsafe(List<byte[]> readyPayloads)
        {
            while (_recvBuffer.Count > 0) // Buffer has segments to check
            {
                InboundSegment next; // Next expected segment
                if (!_recvBuffer.TryGetValue(_nextExpectedSequence, out next)) // Next expected not present
                {
                    break; // Gap — stop draining
                }

                _recvBuffer.Remove(_nextExpectedSequence); // Remove from buffer
                ClearMissingReceiveStateUnsafe(_nextExpectedSequence); // Clean up tracking state
                _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence); // Advance expected sequence
                readyPayloads.Add(next.Payload); // Add to ready payloads
            }
        }

        /// <summary>
        /// Clears all tracking state for a given sequence number (NAK issued,
        /// missing counts, first-seen timestamps, FEC metadata).  Called when
        /// a sequence is received (normally or via FEC recovery).
        ///
        /// Must be called under _sync.
        /// </summary>
        private void ClearMissingReceiveStateUnsafe(uint sequenceNumber)
        {
            _nakIssued.Remove(sequenceNumber);
            _missingSequenceCounts.Remove(sequenceNumber);
            _missingFirstSeenMicros.Remove(sequenceNumber);
            _lastNakIssuedMicros.Remove(sequenceNumber);
            _fecFragmentMetadata.Remove(sequenceNumber);
        }

        /// <summary>
        /// Returns true if a NAK hasn't already been issued for the given sequence.
        /// Each sequence can be NAKed at most once per receive lifetime — after
        /// that, we wait for the retransmission to arrive.
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool ShouldIssueNakUnsafe(uint sequenceNumber)
        {
            return !_nakIssued.Contains(sequenceNumber);
        }

        /// <summary>
        /// Throttles immediate reordered-data ACKs: allows one ACK per
        /// REORDERED_ACK_MIN_INTERVAL_MICROS.  Without this throttle, every
        /// out-of-order packet would trigger an immediate ACK, potentially
        /// causing ACK implosion on high-reorder paths.
        ///
        /// Must be called under _sync (updates _lastReorderedAckSentMicros).
        /// </summary>
        private bool ShouldSendImmediateReorderedAckUnsafe(long nowMicros)
        {
            if (_lastReorderedAckSentMicros == 0 || nowMicros - _lastReorderedAckSentMicros >= UcpConstants.REORDERED_ACK_MIN_INTERVAL_MICROS)
            {
                _lastReorderedAckSentMicros = nowMicros;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks whether the reorder grace period for a missing sequence has
        /// expired, using tiered confidence levels based on observation count.
        ///
        /// NAK reorder grace is the minimum time a gap must persist before the
        /// receiver concludes it's a true loss (rather than packet reordering).
        /// UCP uses tiered confidence:
        ///   - Base grace (low confidence): adaptive, based on SRTT and jitter
        ///   - Medium confidence (more observations): shorter grace (base / 2)
        ///   - High confidence (many observations): even shorter grace (capped at minimum)
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool HasNakReorderGraceExpiredUnsafe(int missingCount, long firstSeenMicros, long nowMicros)
        {
            long baseGraceMicros = GetAdaptiveNakReorderGraceMicrosUnsafe();
            long graceMicros = missingCount >= UcpConstants.NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD
                ? Math.Max(baseGraceMicros / 2, UcpConstants.NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS)
                : missingCount >= UcpConstants.NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD
                    ? Math.Max(baseGraceMicros / 2, UcpConstants.NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS)
                : baseGraceMicros;
            return nowMicros - firstSeenMicros >= graceMicros;
        }

        /// <summary>
        /// Computes a NAK reorder grace from RTT/jitter evidence.
        /// High-jitter paths get a longer receiver-side gap delay so reordering
        /// is not mistaken for packet loss.  The grace is max(NAK_REORDER_GRACE_MICROS,
        /// min(SRTT/2, MinRto)) to scale with path RTT.
        ///
        /// Must be called under _sync.
        /// </summary>
        private long GetAdaptiveNakReorderGraceMicrosUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            if (rttMicros <= 0)
            {
                rttMicros = _config.MinRtoMicros;
            }

            if (rttMicros <= 0)
            {
                return UcpConstants.NAK_REORDER_GRACE_MICROS;
            }

            return Math.Max(UcpConstants.NAK_REORDER_GRACE_MICROS, Math.Min(rttMicros / 2, _config.MinRtoMicros));
        }

        /// <summary>
        /// Marks a sequence number as having had a NAK issued and records the
        /// timestamp for rate-limiting purposes.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void MarkNakIssuedUnsafe(uint sequenceNumber)
        {
            _nakIssued.Add(sequenceNumber);
            _lastNakIssuedMicros[sequenceNumber] = NowMicros();
        }

        /// <summary>
        /// Returns the first-seen timestamp for a missing sequence.  If this is
        /// the first observation, records the current timestamp.  This marks the
        /// start of the reorder-grace period for NAK emission.
        ///
        /// Must be called under _sync.
        /// </summary>
        private long GetMissingFirstSeenMicrosUnsafe(uint sequenceNumber)
        {
            long firstSeenMicros;
            if (!_missingFirstSeenMicros.TryGetValue(sequenceNumber, out firstSeenMicros))
            {
                firstSeenMicros = NowMicros();
                _missingFirstSeenMicros[sequenceNumber] = firstSeenMicros;
            }

            return firstSeenMicros;
        }

        // ---- Packet handler: FEC repair ----

        /// <summary>
        /// Handles an incoming FEC repair packet.  FEC repair packets are sent
        /// by the peer when a FEC group is complete and loss is above threshold.
        ///
        /// Processing:
        ///   1. Feed the repair payload + group metadata to the FEC codec decoder.
        ///   2. The codec attempts to reconstruct any missing packets in the group.
        ///   3. Store recovered packets in the receive buffer.
        ///   4. Drain newly contiguous data and deliver to the application.
        ///   5. Send an immediate ACK — FEC recovery advances the cumulative ACK
        ///      immediately, so the sender must be notified to release its in-flight
        ///      data and avoid timeout storms.
        /// </summary>
        private void HandleFecRepair(UcpFecRepairPacket packet)
        {
            if (_fecCodec == null || packet.Payload == null) // FEC disabled or null payload
            {
                return; // Cannot process
            }

            uint groupBase = packet.GroupId; // FEC group base sequence
            List<UcpFecCodec.RecoveredPacket> recoveredPackets = _fecCodec.TryRecoverPacketsFromRepair(packet.Payload, groupBase, packet.GroupIndex); // Attempt to reconstruct missing packets from repair
            List<byte[]> fecReadyPayloads = new List<byte[]>(); // Ready payloads from FEC recovery
            int recoveredCount; // Number of packets recovered

            lock (_sync) // Acquire protocol lock for receive buffer mutation
            {
                recoveredCount = StoreRecoveredFecPacketsUnsafe(recoveredPackets, fecReadyPayloads); // Store recovered packets and drain contiguous data
            }

            if (recoveredCount == 0) // No packets were recovered
            {
                return; // Nothing to do
            }

            // Deliver recovered data to the application.
            for (int i = 0; i < fecReadyPayloads.Count; i++) // Iterate all drained ready payloads
            {
                EnqueuePayload(fecReadyPayloads[i]); // Deliver to application
            }

            // Immediate ACK: FEC recovery advances the cumulative ACK, so the
            // sender must know promptly.  Delaying would cause timeout storms.
            SendAckPacket(UcpPacketFlags.None, 0); // Transmit immediate ACK with updated cumulative state
        }

        // ---- Packet handler: FIN ----

        /// <summary>
        /// Handles an incoming FIN: processes piggybacked ACK, acknowledges the
        /// FIN with a FIN-ACK flag, sends our own FIN if not yet sent, and checks
        /// if both FINs are acknowledged for final close.
        ///
        /// UCP FIN exchange:
        ///   1. A → B: FIN (seq=a)
        ///   2. B → A: ACK with FinAck flag (ack=a+1, flags=FinAck)
        ///   3. If B also wants to close: B → A: FIN (seq=b)
        ///   4. A → B: ACK with FinAck flag (ack=b+1)
        ///
        /// When both sides have sent FIN and received FinAck, the connection
        /// transitions to Closed.
        /// </summary>
        private void HandleFin(UcpControlPacket packet)
        {
            bool needSendOwnFin = false; // Whether we need to send our own FIN
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber; // Check for piggybacked ACK
            lock (_sync) // Acquire protocol lock for state transition
            {
                _peerFinReceived = true; // Record that peer sent FIN
                _state = UcpConnectionState.ClosingFinReceived; // Transition to FIN-received closing state
                if (!_finSent) // We haven't sent our FIN yet
                {
                    _finSent = true; // Mark our FIN as sent
                    needSendOwnFin = true; // Signal that we need to transmit our FIN
                }
            }

            if (hasAck && packet.AckNumber > 0) // FIN carries piggybacked ACK
            {
                ProcessPiggybackedAck(packet.AckNumber, packet.Header.Timestamp, NowMicros()); // Process piggybacked ACK
            }

            // Acknowledge the peer's FIN with the FinAck flag.
            SendAckPacket(UcpPacketFlags.FinAck, 0); // Transmit ACK with FinAck flag (acknowledges peer's FIN)
            if (needSendOwnFin) // We need to send our FIN too
            {
                SendControl(UcpPacketType.Fin, UcpPacketFlags.None); // Transmit our FIN (initiate our side of close)
            }

            if (_finAcked) // Our FIN was already acknowledged by a previous ACK
            {
                // Both FINs acknowledged — clean close complete.
                TransitionToClosed(); // Transition to Closed state
            }
        }

        // ---- Packet sending helpers ----

        /// <summary>
        /// Sends a NAK (Negative Acknowledgment) packet with the given list of
        /// missing sequence numbers.
        ///
        /// NAK packets carry:
        ///   - Cumulative ACK number (so the peer doesn't need a separate ACK)
        ///   - List of missing sequence numbers (currently up to MAX_NAK_SEQUENCES_PER_PACKET)
        ///
        /// NAK rate limiting:
        ///   - At most MAX_NAKS_PER_RTT NAK packets can be sent per SRTT-duration window.
        ///   - The window is reset each SRTT to prevent permanent NAK suppression.
        ///   - Rate limiting prevents NAK storms during sustained high-loss periods,
        ///     where flooding the sender with NAKs would waste bandwidth without
        ///     providing new information.
        /// </summary>
        /// <param name="missing">List of missing sequence numbers to report.</param>
        private void SendNak(List<uint> missing)
        {
            if (missing == null || missing.Count == 0) // No sequences to report
            {
                return; // Nothing to send
            }

            uint cumAck; // Cumulative ACK number to include in the NAK
            lock (_sync) // Acquire protocol lock for rate-limit and ACK snapshot
            {
                long nowMicros = NowMicros(); // Snapshot current time
                long rttWindowMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.DelayedAckTimeoutMicros; // Use SRTT or fallback for window duration
                if (rttWindowMicros <= 0) // Still no valid RTT
                {
                    rttWindowMicros = UcpConstants.BBR_MIN_ROUND_DURATION_MICROS; // Use minimum round duration as fallback
                }

                // Reset NAK window if SRTT has elapsed.
                if (_lastNakWindowMicros == 0 || nowMicros - _lastNakWindowMicros >= rttWindowMicros) // Window has expired
                {
                    _lastNakWindowMicros = nowMicros; // Start new NAK window
                    _naksSentThisRttWindow = 0; // Reset send counter for new window
                }

                // Rate limit: at most MAX_NAKS_PER_RTT NAK packets per window.
                if (_naksSentThisRttWindow >= UcpConstants.MAX_NAKS_PER_RTT) // Rate limit reached
                {
                    return; // Suppress NAK — rate limited
                }

                _naksSentThisRttWindow++; // Increment NAK send counter
                // Cumulative ACK is _nextExpectedSequence - 1 (everything before is received).
                cumAck = _nextExpectedSequence > 0 ? unchecked(_nextExpectedSequence - 1U) : 0; // Compute cumulative ACK
                _lastAckSentMicros = nowMicros; // NAK carries ACK, counts as ACK send.
            }

            UcpNakPacket packet = new UcpNakPacket(); // Create NAK packet
            packet.Header = CreateHeader(UcpPacketType.Nak, UcpPacketFlags.None, NowMicros()); // Create common header
            packet.AckNumber = cumAck; // Set cumulative ACK number
            packet.MissingSequences.AddRange(missing); // Add all missing sequence numbers
            
            byte[] encoded = UcpPacketCodec.Encode(packet); // Encode the NAK packet to wire format
            _sentNakPackets++; // Increment NAK counter
            _transport.Send(encoded, _remoteEndPoint); // Transmit NAK via transport
        }

        /// <summary>
        /// Sends a control packet (SYN, SYN-ACK, FIN, RST).
        ///
        /// SYN and SYN-ACK include the current _nextSendSequence as their sequence
        /// number for ISN negotiation during handshake.
        ///
        /// All control packets except the initial outgoing SYN carry the cumulative
        /// ACK number (_nextExpectedSequence - 1).  This means:
        ///   - SYN-ACK carries ACK of client's ISN
        ///   - FIN carries ACK of the last received data
        ///   - RST may carry ACK for the peer to converge on close
        ///
        /// RST packets increment the RST counter for diagnostics.
        /// </summary>
        /// <param name="type">The control packet type (Syn, SynAck, Fin, Rst).</param>
        /// <param name="flags">Packet flags.</param>
        private void SendControl(UcpPacketType type, UcpPacketFlags flags)
        {
            UcpControlPacket packet = new UcpControlPacket(); // Create control packet
            uint cumAck = 0; // Cumulative ACK number (0 = no ACK)
            bool hasAck = false; // Whether this packet carries a cumulative ACK
            lock (_sync) // Acquire protocol lock for state snapshot
            {
                if (type == UcpPacketType.Syn || type == UcpPacketType.SynAck) // SYN or SYN-ACK: carry our ISN as sequence number
                {
                    packet.HasSequenceNumber = true; // Enable sequence number field
                    packet.SequenceNumber = _nextSendSequence; // Our ISN.
                }
                
                // All control packets except the initial outgoing SYN carry cumulative ACK.
                if (type != UcpPacketType.Syn && _nextExpectedSequence > 0) // Not a SYN and we have received at least one packet
                {
                    hasAck = true; // This packet will carry a cumulative ACK
                    cumAck = unchecked(_nextExpectedSequence - 1U); // ACK = last in-order received sequence
                }
            }

            UcpPacketFlags packetFlags = flags; // Start with caller-provided flags
            if (hasAck) // Packet carries a cumulative ACK
            {
                packetFlags |= UcpPacketFlags.HasAckNumber; // Set HasAckNumber flag
                packet.AckNumber = cumAck; // Set ACK number in packet
            }

            packet.Header = CreateHeader(type, packetFlags, NowMicros()); // Create common header with type, flags, and timestamp
            byte[] encoded = UcpPacketCodec.Encode(packet); // Encode to wire format
            if (type == UcpPacketType.Rst) // This is a RST packet
            {
                _sentRstPackets++; // Increment RST counter for diagnostics
            }

            _transport.Send(encoded, _remoteEndPoint); // Transmit via underlying transport
        }

        /// <summary>
        /// Sends an ACK packet with the current cumulative ACK number, SACK blocks
        /// (QUIC-style: each block range sent at most 2 times), advertised receive
        /// window, and optional echo timestamp.
        ///
        /// QUIC-style SACK limitation (MAX_SACK_SEND_COUNT = 2):
        ///   Each SACK range [start, end] is packed into a 64-bit key and tracked in
        ///   _sackBlockSendCounts.  A range is included in ACKs at most twice.  After
        ///   two sends, the range is dropped:
        ///     - The peer should have acted on the SACK information by then
        ///     - Prevents unbounded memory growth from stale SACK ranges
        ///     - Avoids sending redundant information indefinitely
        ///
        /// Window advertisement:
        ///   Advertised window = local_receive_window - used_bytes.  If the window
        ///   would be negative (more data queued than window size), advertises 0
        ///   to pause the sender.
        ///
        /// Echo timestamp:
        ///   If overrideEchoTimestamp > 0: use that value (caller-provided)
        ///   If overrideEchoTimestamp = 0: use stored _lastEchoTimestamp
        ///   If overrideEchoTimestamp = -1: send 0 (keep-alive, no echo)
        /// </summary>
        /// <param name="flags">Packet flags (e.g. FinAck).</param>
        /// <param name="overrideEchoTimestamp">Override echo timestamp (0 = use stored, -1 = send keepalive).</param>
        private void SendAckPacket(UcpPacketFlags flags, long overrideEchoTimestamp)
        {
            UcpAckPacket packet; // The ACK packet to send
            lock (_sync) // Acquire protocol lock for ACK state snapshot
            {
                packet = new UcpAckPacket(); // Create ACK packet
                packet.Header = CreateHeader(UcpPacketType.Ack, flags, NowMicros()); // Create common header
                // Cumulative ACK = next expected - 1 (everything before is ACKed).
                packet.AckNumber = unchecked(_nextExpectedSequence - 1U); // Set cumulative ACK number

                // Generate raw SACK blocks, then apply QUIC-style send-count filter.
                List<SackBlock> rawBlocks = _sackGenerator.Generate(_nextExpectedSequence, _recvBuffer.Keys, _config.MaxAckSackBlocks); // Generate SACK blocks from receive buffer
                List<SackBlock> filteredBlocks = new List<SackBlock>(rawBlocks.Count); // Filtered blocks that haven't been sent max times
                for (int i = 0; i < rawBlocks.Count; i++) // Iterate raw SACK blocks
                {
                    // Pack start/end into 64-bit key for dictionary lookup.
                    ulong key = PackSackBlockKey(rawBlocks[i].Start, rawBlocks[i].End); // Pack into ulong key
                    int sendCount; // How many times this block has been sent
                    _sackBlockSendCounts.TryGetValue(key, out sendCount); // Look up send count
                    if (sendCount < MAX_SACK_SEND_COUNT) // Not yet sent max times (QUIC standard: 2)
                    {
                        filteredBlocks.Add(rawBlocks[i]); // Include this block
                        _sackBlockSendCounts[key] = sendCount + 1; // Increment send count
                    }
                }

                packet.SackBlocks = filteredBlocks; // Set filtered SACK blocks on packet

                // Advertise available receive window to the sender.
                uint usedBytes = GetReceiveWindowUsedBytesUnsafe(); // Compute used receive window bytes
                packet.WindowSize = usedBytes >= _localReceiveWindowBytes ? 0U : _localReceiveWindowBytes - usedBytes; // Advertise available window (0 if full)
                packet.EchoTimestamp = overrideEchoTimestamp < 0 ? 0 : (overrideEchoTimestamp > 0 ? overrideEchoTimestamp : _lastEchoTimestamp); // Determine echo timestamp: keep-alive=0, override, or stored
                _lastAckSentMicros = packet.Header.Timestamp; // Record ACK send time
            }

            byte[] encoded = UcpPacketCodec.Encode(packet); // Encode to wire format
            _sentAckPackets++; // Increment ACK counter
            _transport.Send(encoded, _remoteEndPoint); // Transmit via transport
        }

        /// <summary>
        /// Schedules a delayed ACK to allow potential piggybacking on an outbound
        /// data packet.  If the delayed ACK timeout is zero or the last RTT is very
        /// short (< 30ms), the ACK is sent immediately.
        ///
        /// Delayed ACK strategy:
        ///   - ACKs are intentionally delayed by DelayedAckTimeoutMicros to give
        ///     outbound data a chance to piggyback the ACK for free
        ///   - If an outbound data packet is sent before the timer fires, that
        ///     data packet will include the ACK and the timer is canceled
        ///   - On high-latency paths (> 30ms SRTT), the delay is capped at 1ms
        ///     to avoid inflating RTT further
        ///   - Only one delayed ACK can be scheduled at a time (_ackDelayed flag)
        ///
        /// Scheduling mechanism:
        ///   - Standalone mode: Task.Delay on thread pool
        ///   - Network-managed mode: UcpNetwork timer callback
        /// </summary>
        private void ScheduleAck()
        {
            // Zero timeout → send immediately (no piggyback opportunity expected).
            if (_config.DelayedAckTimeoutMicros <= 0) // Delayed ACK is disabled
            {
                SendAckPacket(UcpPacketFlags.None, 0); // Transmit ACK immediately
                return; // Done
            }

            long ackDelayMicros = _config.DelayedAckTimeoutMicros; // Base delay from configuration
            // On high-latency paths, use shorter delay to avoid RTT inflation.
            if (_lastRttMicros > 30L * UcpConstants.MICROS_PER_MILLI) // High-latency path (>30ms RTT)
            {
                ackDelayMicros = Math.Min(ackDelayMicros, UcpConstants.MICROS_PER_MILLI); // Cap delay at 1ms on high-RTT paths
            }

            lock (_sync) // Acquire protocol lock to check/set _ackDelayed flag
            {
                if (_ackDelayed) // Delayed ACK is already scheduled
                {
                    return; // Already scheduled — piggyback will happen.
                }

                _ackDelayed = true; // Mark that a delayed ACK is pending
            }

            if (_network == null) // Standalone mode: no UcpNetwork available
            {
                // Standalone: use Task.Delay with cancellation support.
                Task.Run(async delegate // Fire-and-forget async task
                {
                    try
                    {
                        await Task.Delay((int)Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, ackDelayMicros / UcpConstants.MICROS_PER_MILLI), _cts.Token).ConfigureAwait(false); // Wait for delay period
                        lock (_sync) // Acquire lock to clear flag
                        {
                            _ackDelayed = false; // Clear delayed flag
                        }

                        SendAckPacket(UcpPacketFlags.None, 0); // Transmit the delayed ACK
                    }
                    catch (OperationCanceledException) // PCB was disposed during delay
                    {
                        // PCB disposed — ignore.
                    }
                });
                return; // Done — async task is running
            }

            // Network-managed: schedule via network timer for precise timing.
            _network.AddTimer(_network.CurrentTimeUs + ackDelayMicros, delegate // Schedule timer at deadline
            {
                lock (_sync) // Acquire lock to clear flag
                {
                    _ackDelayed = false; // Clear delayed flag
                }

                SendAckPacket(UcpPacketFlags.None, 0); // Transmit the delayed ACK
            });
        }

        // ---- Send queue flush ----

        /// <summary>
        /// Flushes the send buffer: collects pending segments, applies pacing and
        /// fair-queue credit, encodes, and sends via the transport.  Reschedules
        /// itself if pacing wait time is needed.
        ///
        /// This is the central send-loop of UCP.  Processing stages:
        ///
        /// A. Collection (inside _sync lock):
        ///    1. Compute effective send window: min(BBR_cwnd, peer_rwnd) - _flightBytes
        ///    2. Walk _sendBuffer in sequence order, collecting eligible segments:
        ///       - Segments already ACKed: skip
        ///       - In-flight and not needing retransmit: skip (already sent)
        ///       - Would exceed window: stop (in-order guarantee — cannot skip ahead)
        ///    3. For each collected segment:
        ///       a. Urgent retransmits bypass pacing tokens (ForceConsume)
        ///       b. Normal sends check pacing tokens (TryConsume) — if insufficient,
        ///          record wait time and stop collecting
        ///       c. Fair-queue credit is deducted per segment (unless urgent recovery)
        ///       d. Segment is marked InFlight, NeedsRetransmit cleared; UrgentRetransmit
        ///          flag in cold-path _sackTracking is reset
        ///       e. SendCount incremented; if first send, _flightBytes increased
        ///    4. Snapshot piggybacked ACK state (cumulative ACK, SACK blocks, window,
        ///       echo timestamp) — these values are included on every outbound data packet
        ///
        /// B. Encoding and sending (outside _sync lock):
        ///    1. Each collected segment is encoded as a UcpDataPacket with:
        ///       - Sequence number, fragment metadata, payload
        ///       - Piggybacked cumulative ACK (_nextExpectedSequence - 1)
        ///       - Piggybacked SACK blocks (peer's loss detection)
        ///       - Advertised receive window (flow control)
        ///       - Echo timestamp (RTT measurement)
        ///
        /// C. FEC encoding (per-segment):
        ///    - If FEC is enabled and this is a first-transmission (not retransmit),
        ///      the payload is fed to the FEC codec
        ///    - When a FEC group is complete, repair packets are generated
        ///    - Repair packets are only sent if estimated loss >= adaptive threshold
        ///      (low-loss paths skip FEC to save bandwidth)
        ///
        /// D. Pacing wait:
        ///    - If no segments were collected but pacing tokens are insufficient,
        ///      a delayed flush is scheduled for when tokens will be available
        ///    - The delayed flush retries FlushSendQueueAsync after the wait
        ///
        /// Piggybacking strategy:
        ///    Every data packet carries the receiver's ACK state.  This eliminates
        ///    standalone ACK packets during bidirectional data flow — the ACK rides
        ///    for free on outbound data.  The delayed ACK timer fires only when
        ///    there's no outbound data to piggyback on.
        ///
        /// Serialization:
        ///    Only one FlushSendQueueAsync runs at a time (_flushLock semaphore).
        ///    This prevents duplicate transmission of segments.
        /// </summary>
        private async Task FlushSendQueueAsync()
        {
            await _flushLock.WaitAsync().ConfigureAwait(false); // Acquire flush semaphore (only one flush at a time)
            try
            {
                while (!_cts.IsCancellationRequested) // Keep flushing while connection is alive
                {
                    List<OutboundSegment> segmentsToSend = new List<OutboundSegment>(); // Segments collected for transmission
                    long nowMicros = NowMicros(); // Snapshot current time for consistent timestamps
                    long waitMicros = 0; // Time to wait for pacing tokens (0 = no wait needed)
                    uint piggyCumAck = 0; // Piggybacked cumulative ACK to include on each data packet
                    List<SackBlock> piggySackBlocks = null; // Piggybacked SACK blocks to include
                    uint piggyWindow = 0; // Piggybacked receive window advertisement
                    long piggyEcho = 0; // Piggybacked echo timestamp for RTT measurement

                    lock (_sync) // Acquire protocol lock for send buffer collection (Stage A)
                    {
                        // Stage A.1: Compute effective send window.
                        int windowBytes = GetSendWindowBytesUnsafe(); // Effective window = min(BBR cwnd, peer rwnd)
                        int piggybackedAckOverhead = UcpConstants.DATA_HEADER_SIZE_WITH_ACK - UcpConstants.DataHeaderSize; // Extra bytes for piggybacked ACK fields
                        foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer) // Walk send buffer in sequence order
                        {
                            OutboundSegment segment = pair.Value; // Current segment
                            if (segment.Acked) // Already acknowledged by peer
                            {
                                continue; // Already acknowledged — will be removed soon.
                            }

                            if (segment.InFlight && !segment.NeedsRetransmit) // Already in flight and not needing retransmit
                            {
                                continue; // Already sent and not marked for retransmit.
                            }

                            // Window check (only for new sends, not retransmits).
                            if (!segment.NeedsRetransmit && !segment.InFlight && _flightBytes + segment.Payload.Length > windowBytes) // New send would exceed congestion/receive window
                            {
                                break; // Window full — stop collecting.
                            }

                            int packetSize = UcpConstants.DataHeaderSize + piggybackedAckOverhead + segment.Payload.Length; // Total wire size of this data packet
                            // Check cold-path SACK tracking state for urgent flag (defaults to false if no entry).
                            SackTrackingState flushSackState; // SACK tracking state for this segment
                            bool hasUrgentFlag = _sackTracking.TryGetValue(segment.SequenceNumber, out flushSackState) && flushSackState.UrgentRetransmit; // Check if urgent retransmit requested
                            bool urgentRecovery = segment.NeedsRetransmit && segment.SendCount > 0 && hasUrgentFlag && CanUseUrgentRecoveryUnsafe(nowMicros); // Urgent recovery: bypass pacing and credit checks

                            // Fair-queue credit check: skip if credit insufficient (unless urgent).
                            if (_useFairQueue && _fairQueueCreditBytes < packetSize && !urgentRecovery) // Fair queue enabled, credit insufficient, not urgent
                            {
                                break; // Stop collecting — no credit left
                            }

            // Stage A.3a: Urgent recovery bypasses pacing (ForceConsume).
            if (urgentRecovery) // This segment is an urgent retransmit (SACK/NAK/DUPACK/RTO-triggered)
            {
                _pacing.ForceConsume(packetSize, nowMicros); // Consume pacing tokens unconditionally (bypass budget)
                _urgentRecoveryPacketsInWindow++; // Increment urgent recovery budget counter
            }
                            // Stage A.3b: Normal sends check pacing token bucket.
                            else if (!_pacing.TryConsume(packetSize, nowMicros)) // Normal send: not enough pacing tokens
                            {
                                // Not enough tokens — record wait time and stop collecting.
                                waitMicros = _pacing.GetWaitTimeMicros(packetSize, nowMicros); // Compute how long until tokens are available
                                break; // Stop collecting — pacing limited
                            }

                            // Stage A.3c: Deduct fair-queue credit.
                            if (_useFairQueue) // Fair queue is enabled
                            {
                                _fairQueueCreditBytes -= packetSize; // Deduct bytes from fair-queue credit
                                if (_fairQueueCreditBytes < 0) // Credit went negative (possible with concurrent replenishment)
                                {
                                    _fairQueueCreditBytes = 0; // Clamp to zero
                                }
                            }

                            // Stage A.3d: Mark segment state.
                            segment.InFlight = true; // Mark as in flight
                            segment.NeedsRetransmit = false; // Clear retransmit flag (we're about to send it)
                            // Clear urgent retransmit flag in cold-path SACK tracking (no-op if not yet tracked).
                            if (_sackTracking.TryGetValue(segment.SequenceNumber, out SackTrackingState clearSackState)) // Entry exists from prior SACK observation
                            {
                                clearSackState.UrgentRetransmit = false; // Clear for this send cycle
                            }
                            if (segment.SendCount == 0) // First transmission (not a retransmit)
                            {
                                _flightBytes += segment.Payload.Length; // Increment flight bytes for first-time sends
                            }

                            // Stage A.3e: Update send count and notify BBR.
                            segment.SendCount++; // Increment send count
                            _bbr.OnPacketSent(nowMicros, segment.SendCount > 1); // Notify BBR of packet send (is retransmit?)
                            segment.LastSendMicros = nowMicros; // Record last send time for RTT computation
                            _lastActivityMicros = nowMicros; // Update activity timestamp
                            segmentsToSend.Add(segment); // Add to collection for encoding/sending
                        }

                        // Stage A.4: Snapshot piggybacked ACK info inside the lock.
                        piggyCumAck = _nextExpectedSequence > 0 ? unchecked(_nextExpectedSequence - 1U) : 0; // Compute cumulative ACK for piggyback
                        piggySackBlocks = piggyCumAck > 0 ? _sackGenerator.Generate(_nextExpectedSequence, _recvBuffer.Keys, _config.MaxAckSackBlocks) : null; // Generate SACK blocks for piggyback
                        piggyWindow = piggyCumAck > 0 // Compute advertised receive window for piggyback
                            ? (_localReceiveWindowBytes > GetReceiveWindowUsedBytesUnsafe() // Window > used bytes
                                ? _localReceiveWindowBytes - GetReceiveWindowUsedBytesUnsafe() // Available = window - used
                                : 0U) // Window is full — advertise 0 to pause sender
                            : _localReceiveWindowBytes; // No ACK needed — advertise full window
                        piggyEcho = _lastEchoTimestamp; // Echo the last timestamp received from peer
                        _lastAckSentMicros = nowMicros; // Piggyback counts as an ACK send.

                        // Sort collected segments by priority: Urgent (3) first, Background (0) last.
                        // Stable sort preserves original send-buffer order within the same priority tier.
                        // Stable sort: higher priority first, then original sequence-number order
                        segmentsToSend.Sort((a, b) => // Sort comparer
                        {
                            int priorityCmp = b.Priority.CompareTo(a.Priority); // Higher priority first
                            if (priorityCmp != 0) return priorityCmp; // Different priority — return comparison result
                            // Same priority: preserve sequence-number order (stable secondary key)
                            return UcpSequenceComparer.Instance.Compare(a.SequenceNumber, b.SequenceNumber); // Sequence-number order
                        });
                    }

                    if (segmentsToSend.Count == 0) // No segments collected for transmission
                    {
                        // Stage D: No segments collected — schedule delayed flush if pacing limited.
                        if (waitMicros > 0) // Pacing limited — tokens will be available after wait
                        {
                            ScheduleDelayedFlush(waitMicros); // Schedule delayed flush for when tokens are available
                        }

                        break; // Exit flush loop
                    }

                    // Stage B: Encode and send all collected segments with piggybacked ACK.
                    for (int i = 0; i < segmentsToSend.Count; i++) // Iterate collected segments
                    {
                        OutboundSegment segment = segmentsToSend[i]; // Current segment to send
                        UcpDataPacket packet = new UcpDataPacket(); // Create data packet

                        // Retransmit packets carry the Retransmit flag so the receiver
                        // can distinguish original from retransmitted data.
                        UcpPacketFlags pktFlags = segment.SendCount > 1 // Retransmission (SendCount > 1 means retransmit)
                            ? UcpPacketFlags.NeedAck | UcpPacketFlags.Retransmit | UcpPacketFlags.HasAckNumber // Retransmit packet: NeedAck + Retransmit flag + ACK
                            : UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber; // Original packet: NeedAck + ACK

                        packet.Header = CreateHeader(UcpPacketType.Data, pktFlags, nowMicros); // Create common header
                        packet.SequenceNumber = segment.SequenceNumber; // Set sequence number
                        packet.FragmentTotal = segment.FragmentTotal; // Set total fragments in message
                        packet.FragmentIndex = segment.FragmentIndex; // Set fragment position
                        packet.Payload = segment.Payload; // Attach payload bytes

                        // Piggyback ACK state on every data packet.
                        packet.AckNumber = piggyCumAck; // Piggyback cumulative ACK
                        if (piggySackBlocks != null && piggySackBlocks.Count > 0) // SACK blocks are available
                        {
                            packet.SackBlocks = piggySackBlocks; // Piggyback SACK blocks
                        }

                        packet.WindowSize = piggyWindow; // Piggyback receive window advertisement
                        packet.EchoTimestamp = piggyEcho; // Piggyback echo timestamp

                        byte[] encoded = UcpPacketCodec.Encode(packet); // Encode to wire format
                        if (segment.SendCount > 1) // This is a retransmission
                        {
                            _retransmittedPackets++; // Increment retransmit counter
                        }
                        else // This is a first-transmission
                        {
                            _sentDataPackets++; // Increment original data packet counter
                        }

                        _bytesSent += segment.Payload.Length; // Accumulate sent bytes counter
                        _transport.Send(encoded, _remoteEndPoint); // Transmit via transport

                        // Stage C: FEC encoding.
                        if (_fecCodec != null && segment.SendCount <= 1) // FEC enabled and this is first-transmission (not retransmit)
                        {
                            lock (_sync) // Acquire lock for FEC metadata storage
                            {
                                _fecFragmentMetadata[segment.SequenceNumber] = new FecFragmentMetadata { FragmentTotal = segment.FragmentTotal, FragmentIndex = segment.FragmentIndex }; // Store fragment metadata for FEC recovery
                            }

                            if (_fecGroupSendCount == 0) // Starting a new FEC group
                            {
                                _fecGroupBaseSeq = _fecCodec.GetGroupBase(segment.SequenceNumber); // Set the group base sequence
                            }

                            List<byte[]> repairs = _fecCodec.TryEncodeRepairs(segment.Payload); // Feed data to FEC encoder; returns repair packets if group is complete
                            _fecGroupSendCount++; // Increment group send counter
                            if (repairs != null && repairs.Count > 0) // FEC group is complete — repair packets generated
                            {
                                // Adaptive FEC: only transmit repair packets when estimated
                                // loss exceeds the adaptive threshold.  The encoder always
                                // runs — we just skip sending repairs on low-loss paths
                                // where SACK is more efficient and repair bandwidth is wasted.
                                if (_bbr.EstimatedLossPercent >= UcpConstants.ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT) // Loss is above adaptive threshold
                                {
                                    for (int repairIndex = 0; repairIndex < repairs.Count; repairIndex++) // Send each repair packet
                                    {
                                        UcpFecRepairPacket repairPacket = new UcpFecRepairPacket(); // Create FEC repair packet
                                        repairPacket.Header = CreateHeader(UcpPacketType.FecRepair, UcpPacketFlags.None, nowMicros); // Create header
                                        repairPacket.GroupId = _fecGroupBaseSeq; // Set group base sequence
                                        repairPacket.GroupIndex = (byte)repairIndex; // Set repair index within group
                                        repairPacket.Payload = repairs[repairIndex]; // Attach repair payload
                                        byte[] encodedRepair = UcpPacketCodec.Encode(repairPacket); // Encode to wire format
                                        _transport.Send(encodedRepair, _remoteEndPoint); // Transmit repair packet
                                    }

                                    _fecRepairSentGroups.Add(_fecGroupBaseSeq); // Record that repairs were sent for this group
                                }

                                _fecGroupSendCount = 0; // Group complete — reset for next group.
                            }
                        }
                    }
                }
            }
            finally // Always release the flush lock
            {
                _flushLock.Release(); // Release flush semaphore
            }
        }

        /// <summary>
        /// Schedules a delayed flush after the given wait time (pacing tokens will
        /// be available then).  Uses the network timer in managed mode or Task.Delay
        /// in standalone mode.  Only one delayed flush is scheduled at a time.
        /// </summary>
        /// <param name="waitMicros">Wait time in microseconds.</param>
        private void ScheduleDelayedFlush(long waitMicros)
        {
            if (_flushDelayed) // Delayed flush is already scheduled
            {
                return; // Already scheduled — avoid duplicate timers.
            }

            _flushDelayed = true; // Set the flag to prevent duplicate scheduling
            int delayMs = (int)Math.Ceiling(waitMicros / (double)UcpConstants.MICROS_PER_MILLI); // Convert microseconds to milliseconds (ceiling)
            if (delayMs < UcpConstants.MIN_TIMER_WAIT_MILLISECONDS) // Delay is below minimum threshold
            {
                delayMs = UcpConstants.MIN_TIMER_WAIT_MILLISECONDS; // Enforce minimum delay
            }

            if (_network == null) // Standalone mode: no UcpNetwork
            {
                // Standalone: use Task.Delay.
                Task.Run(async () => // Fire-and-forget async task
                {
                    try
                    {
                        await Task.Delay(delayMs, _cts.Token).ConfigureAwait(false); // Wait for pacing tokens
                        _flushDelayed = false; // Clear delayed flag
                        await FlushSendQueueAsync().ConfigureAwait(false); // Retry the flush
                    }
                    catch (OperationCanceledException) // PCB was disposed
                    {
                        _flushDelayed = false; // Clear delayed flag on cancellation
                    }
                });
                return; // Done — async task is running
            }

            // Network-managed: use network timer.
            _flushTimerId = _network.AddTimer(_network.NowMicroseconds + (delayMs * UcpConstants.MICROS_PER_MILLI), delegate // Schedule timer at deadline
            {
                _flushDelayed = false; // Clear delayed flag
                _flushTimerId = 0; // Clear timer ID
                _ = FlushSendQueueAsync(); // Fire-and-forget retry the flush
            });
        }

        /// <summary>
        /// Enqueues a received in-order payload for application delivery.
        /// Creates a ReceiveChunk and adds it to _receiveQueue, then fires the
        /// DataReceived event and releases _receiveSignal to unblock any
        /// waiting ReceiveAsync() callers.
        ///
        /// DataReceived event is fired synchronously — the handler executes
        /// on the calling thread (typically the SerialQueue dispatch thread).
        /// </summary>
        /// <param name="payload">The in-order payload bytes.</param>
        private void EnqueuePayload(byte[] payload)
        {
            if (payload == null || payload.Length == 0) // Null or empty payload
            {
                return; // Nothing to deliver
            }

            lock (_sync) // Acquire protocol lock for receive queue mutation
            {
                ReceiveChunk chunk = new ReceiveChunk(); // Create new receive chunk
                chunk.Buffer = payload; // Set payload buffer
                chunk.Count = payload.Length; // Set total byte count
                _receiveQueue.Enqueue(chunk); // Enqueue the chunk for application reading
                _queuedReceiveBytes += payload.Length; // Increment queued bytes counter
                _bytesReceived += payload.Length; // Increment total received bytes counter
            }

            // Fire event outside lock to avoid re-entrancy issues.
            Action<byte[], int, int> dataReceived = DataReceived; // Snapshot event delegate for thread safety
            if (dataReceived != null) // At least one subscriber
            {
                dataReceived(payload, 0, payload.Length); // Fire DataReceived event with (buffer, offset, count)
            }

            _receiveSignal.Release(); // Signal blocked ReceiveAsync callers that data is available
        }

        // ---- Send window management ----

        /// <summary>
        /// Returns the effective send window in bytes: min(BBR_congestion_window,
        /// peer_receive_window).  This is the maximum number of bytes that may be
        /// in flight at any time.  New sends (not retransmits) respect this limit.
        ///
        /// Must be called under _sync.
        /// </summary>
        private int GetSendWindowBytesUnsafe()
        {
            int receiveWindowBytes = (int)_remoteWindowBytes; // Peer's advertised receive window (cast to int for comparison)
            int congestionWindowBytes = _bbr.CongestionWindowBytes; // BBR congestion window in bytes
            int windowBytes = congestionWindowBytes < receiveWindowBytes ? congestionWindowBytes : receiveWindowBytes; // Effective window = min(BBR cwnd, peer rwnd)
            if (windowBytes < 0) // Window is negative (possible with integer overflow)
            {
                windowBytes = 0; // Clamp to zero
            }

            return windowBytes; // Return effective send window in bytes
        }

        /// <summary>
        /// Returns true if the urgent recovery budget hasn't been exhausted in the
        /// current SRTT window.  Urgent retransmits bypass pacing, but are capped
        /// at URGENT_RETRANSMIT_BUDGET_PER_RTT per SRTT window to prevent flooding
        /// during sustained loss.
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool CanUseUrgentRecoveryUnsafe(long nowMicros)
        {
            long windowMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros; // Use SRTT or configured minimum RTO as window size
            if (windowMicros <= 0) // Still no valid RTT estimate
            {
                windowMicros = UcpConstants.DEFAULT_RTO_MICROS; // Use protocol default
            }

            // Reset window budget if SRTT has elapsed.
            if (_urgentRecoveryWindowMicros == 0 || nowMicros - _urgentRecoveryWindowMicros >= windowMicros) // Window has expired
            {
                _urgentRecoveryWindowMicros = nowMicros; // Start new urgent recovery window
                _urgentRecoveryPacketsInWindow = 0; // Reset packet counter
            }

            return _urgentRecoveryPacketsInWindow < UcpConstants.URGENT_RETRANSMIT_BUDGET_PER_RTT; // Budget not yet exhausted
        }

        /// <summary>
        /// Returns true if the connection is nearing the disconnect timeout,
        /// making urgent recovery more critical.  When within the threshold
        /// percentage of DisconnectTimeoutMicros without activity, recovery
        /// packets are sent with increased urgency to save the connection.
        ///
        /// Must be called under _sync.
        /// </summary>
        private bool IsNearDisconnectTimeoutUnsafe(long nowMicros)
        {
            if (_config.DisconnectTimeoutMicros <= 0) // No disconnect timeout configured
            {
                return false; // Cannot be near timeout
            }

            long idleMicros = nowMicros - _lastActivityMicros; // Time since last protocol activity
            return idleMicros >= _config.DisconnectTimeoutMicros * UcpConstants.URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT / 100L; // Idle time exceeds threshold percentage of disconnect timeout
        }

        /// <summary>
        /// Returns the total bytes used in the local receive buffer (queued for
        /// application delivery + out-of-order segments waiting in _recvBuffer).
        /// Used to compute the advertised receive window sent to the peer.
        ///
        /// Must be called under _sync.
        /// </summary>
        private uint GetReceiveWindowUsedBytesUnsafe()
        {
            long usedBytes = _queuedReceiveBytes; // Start with bytes queued for application delivery
            foreach (KeyValuePair<uint, InboundSegment> pair in _recvBuffer) // Add out-of-order buffered segments
            {
                usedBytes += pair.Value.Payload == null ? 0 : pair.Value.Payload.Length; // Add payload size (skip null)
            }

            if (usedBytes <= 0) // No bytes used
            {
                return 0; // Return zero
            }

            if (usedBytes >= uint.MaxValue) // Overflow protection
            {
                return uint.MaxValue; // Return max value
            }

            return (uint)usedBytes; // Cast to uint
        }

        /// <summary>
        /// Creates a common header for outbound packets.  The header carries:
        ///   - Packet type (Data, Ack, Syn, etc.)
        ///   - Flags (NeedAck, Retransmit, HasAckNumber, FinAck, etc.)
        ///   - Connection ID (identifies which PCB owns this packet)
        ///   - Timestamp (microsecond clock, used for RTT computation via echo)
        /// </summary>
        /// <param name="type">The packet type.</param>
        /// <param name="flags">Packet flags.</param>
        /// <param name="timestampMicros">Microsecond timestamp.</param>
        private UcpCommonHeader CreateHeader(UcpPacketType type, UcpPacketFlags flags, long timestampMicros)
        {
            UcpCommonHeader header = new UcpCommonHeader(); // Create new header object
            header.Type = type; // Set packet type (Data, Ack, Syn, etc.)
            header.Flags = flags; // Set packet flags (NeedAck, Retransmit, etc.)
            header.ConnectionId = _connectionId; // Set connection ID for PCB identification
            header.Timestamp = timestampMicros; // Set microsecond timestamp for RTT computation
            return header; // Return the configured header
        }

        // ---- Timer management ----

        /// <summary>
        /// Timer callback invoked when using a .NET Timer (standalone mode).
        /// Delegates to the async timer handler and reschedules for the next tick.
        /// </summary>
        private void OnTimer(object state)
        {
            if (_disposed) // PCB has been disposed
            {
                return; // Nothing to do — stop timer processing
            }

            _ = OnTimerAsync(); // Fire-and-forget the async timer handler
            if (_network != null) // Network-managed mode
            {
                ScheduleTimer(); // Reschedule for network-managed mode.
            }
        }

        /// <summary>
        /// Schedules the next timer tick via the network engine.  Uses the
        /// configured TimerIntervalMilliseconds as the base interval, ensuring
        /// a minimum of MIN_TIMER_WAIT_MILLISECONDS.
        /// </summary>
        private void ScheduleTimer()
        {
            if (_network == null || _disposed) // No network engine or disposed
            {
                return; // Cannot schedule
            }

            long intervalMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.TimerIntervalMilliseconds) * UcpConstants.MICROS_PER_MILLI; // Compute interval in microseconds with minimum enforcement
            _timerId = _network.AddTimer(_network.NowMicroseconds + intervalMicros, delegate { OnTimer(null); }); // Schedule next tick callback at deadline
        }

        /// <summary>Delegates to the microsecond-aware timer handler at current time.</summary>
        private async Task OnTimerAsync()
        {
            await OnTimerAsync(NowMicros()).ConfigureAwait(false); // Delegate to full timer handler with current timestamp
        }

        /// <summary>
        /// Core timer handler: the heartbeat of UCP protocol state machine.
        /// Runs every TimerIntervalMilliseconds (or per UcpNetwork tick).
        ///
        /// Processing stages:
        ///
        /// A. RTO (Retransmission Timeout) — "RTO":
        ///    Iterates all in-flight segments.  For each segment whose time since
        ///    last send exceeds the current RTO, marks it NeedsRetransmit.
        ///    Budget: at most RTO_RETRANSMIT_BUDGET_PER_TICK segments per tick.
        ///    Suppression: if an ACK was received recently (within
        ///      GetRtoAckProgressSuppressionMicros) and inflight > TLP_MAX,
        ///      RTO retransmits are suppressed to avoid bulk RTO amplification
        ///      when the path is still delivering ACKs (SACK/NAK should handle it).
        ///    Max retransmissions: if segment.SendCount >= MaxRetransmissions AND
        ///      the loss is congestion, the connection is aborted (max retransmits
        ///      exceeded — the path is too lossy to sustain the connection).
        ///
        /// B. Tail-Loss Probe (TLP) — "tail-loss probe":
        ///    When inflight is low (<= TLP_MAX_INFLIGHT_SEGMENTS) and no ACK has
        ///    arrived within TLP_TIMEOUT_RTT_RATIO * SRTT, retransmits the last
        ///    un-ACKed segment.  TLP addresses the "tail loss" problem: when the
        ///    last few packets of a transfer are lost, there aren't enough subsequent
        ///    packets to trigger the 3-DUPACK fast retransmit mechanism.
        ///
        /// C. Silence Probe — "silence probe":
        ///    When inflight > TLP_MAX but no ACK for 3 * SRTT, the path may have
        ///    experienced a blackout (e.g., WiFi disassoc, cellular handoff).  In
        ///    this case, retransmits the most-recently-sent segment as a path probe
        ///    — faster than waiting for full RTO on high-RTT paths.
        ///
        /// D. NAK collection (CollectMissingForNakUnsafe):
        ///    Scans the receive buffer for persistent gaps and collects sequences
        ///    for NAK emission.
        ///
        /// E. Keep-alive:
        ///    If Established and no packets sent for KeepAliveIntervalMicros, sends
        ///    an empty ACK (keep-alive probe) to verify path liveness.
        ///
        /// F. SYN-ACK retransmission:
        ///    Server side: if SYN-ACK was sent but acknowledged, retransmit at RTO.
        ///
        /// G. Disconnect timeout:
        ///    If no activity for DisconnectTimeoutMicros, transition to Closed.
        /// </summary>
        /// <param name="nowMicros">Current time in microseconds.</param>
        private async Task OnTimerAsync(long nowMicros)
        {
            bool timedOut = false; // Whether RTO timeout occurred this tick
            bool sendKeepAlive = false; // Whether to send a keep-alive probe
            bool retransmitSynAck = false; // Whether to retransmit SYN-ACK
            bool maxRetransmissionsExceeded = false; // Whether any segment exceeded max retransmit count
            bool timedOutForCongestion = false; // Whether the timeout was classified as congestion
            bool tailLossProbe = false; // Whether a tail-loss probe or silence probe was triggered
            List<uint> missingForNak = new List<uint>(); // Sequences to NAK collected this tick

            lock (_sync) // Acquire protocol lock for timer processing stages A–F
            {
                // ---- Path-change adaptation: reset CC path-specific estimates ----
                if (_pathChanged && _state == UcpConnectionState.Established) // Path changed and connection is active
                {
                    _pathChanged = false; // Clear flag before calling BBR to avoid re-entry
                    _bbr.OnPathChange(nowMicros); // Reset path-specific estimates (MinRtt, RTT history, classifier windows)
                }

                // ---- Stage A: RTO scan ----
                int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize)); // Estimate number of segments in flight
                int rtoRetransmitBudget = UcpConstants.RTO_RETRANSMIT_BUDGET_PER_TICK; // Budget for RTO retransmits per tick
                // Suppress bulk RTO when ACK flow is still active.
                bool ackProgressRecent = _lastAckReceivedMicros > 0 && nowMicros - _lastAckReceivedMicros <= GetRtoAckProgressSuppressionMicrosUnsafe(); // ACK arrived recently — path is alive
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer) // Scan send buffer for timed-out segments
                {
                    OutboundSegment segment = pair.Value; // Current segment
                    if (!segment.InFlight || segment.Acked || segment.NeedsRetransmit) // Not in flight, already ACKed, or already marked
                    {
                        continue; // Skip — nothing to do for this segment
                    }

                    // Segment has been in flight longer than the current RTO → timeout.
                    if (nowMicros - segment.LastSendMicros >= _rtoEstimator.CurrentRtoMicros) // Time since last send exceeds current RTO
                    {
                        // If ACKs are still arriving and inflight is large, skip —
                        // SACK/NAK should recover individual losses without RTO.
                        if (ackProgressRecent && _sendBuffer.Count > UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS) // ACK flow active and inflight above TLP threshold
                        {
                            continue; // ACK flow is alive — avoid bulk RTO amplification.
                        }

                        // Budget exhausted for this tick.
                        if (rtoRetransmitBudget <= 0) // No more RTO retransmits allowed this tick
                        {
                            break; // Stop scanning — budget exhausted
                        }

                        bool segmentTimedOutForCongestion = IsCongestionLossUnsafe(segment.SequenceNumber, 0, nowMicros, 1); // Classify whether this timeout is congestion-related
                        // Max retransmissions check: if exceeded AND it's congestion loss,
                        // abort the connection (the path is too congested for recovery).
                        if (segment.SendCount >= _config.MaxRetransmissions && segmentTimedOutForCongestion) // Max retransmits reached for congestion loss
                        {
                            _timeoutRetransmissions++; // Increment timeout retransmit counter
                            maxRetransmissionsExceeded = true; // Signal to abort connection
                            break; // Max retransmissions exceeded — abort connection.
                        }

                        segment.NeedsRetransmit = true; // Mark for retransmission
                            // Mark as urgent in cold-path SACK tracking state to bypass pacing.
                            GetOrCreateSackTrackingUnsafe(segment.SequenceNumber).UrgentRetransmit = true; // Bypass pacing for RTO recovery
                            timedOut = true; // Mark that timeout occurred
                        rtoRetransmitBudget--; // Decrement RTO budget
                        timedOutForCongestion = timedOutForCongestion || segmentTimedOutForCongestion; // Accumulate congestion classification
                        _timeoutRetransmissions++; // Increment timeout retransmit counter
                    }
                }

                // ---- Stage B: Tail-Loss Probe (TLP) ----
                if (!timedOut && !_tailLossProbePending && inflightSegments > 0 && inflightSegments <= UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS) // No timeout, no pending TLP, low inflight
                {
                    long tlpTimeoutMicros = _rtoEstimator.SmoothedRttMicros > 0 // TLP timeout based on SRTT
                        ? (long)Math.Ceiling(_rtoEstimator.SmoothedRttMicros * UcpConstants.TLP_TIMEOUT_RTT_RATIO) // SRTT-based timeout
                        : _rtoEstimator.CurrentRtoMicros; // Fall back to current RTO
                    if (_lastAckReceivedMicros > 0 && nowMicros - _lastAckReceivedMicros >= tlpTimeoutMicros) // No ACK within TLP timeout
                    {
                        // TLP: retransmit the most-recently-sent un-ACKed segment.
                        foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer) // Scan for the most recent segment to retransmit
                        {
                            OutboundSegment segment = pair.Value; // Current segment
                            if (segment.Acked || !segment.InFlight || segment.NeedsRetransmit) // Already ACKed, not in flight, or already marked
                            {
                                continue; // Skip
                            }

                            if (nowMicros - segment.LastSendMicros < tlpTimeoutMicros) // Not yet beyond TLP timeout
                            {
                                continue; // Still within TLP tolerance
                            }

                        segment.NeedsRetransmit = true; // Mark for retransmission
                            // Mark as urgent in cold-path SACK tracking — only if near disconnect timeout.
                            GetOrCreateSackTrackingUnsafe(segment.SequenceNumber).UrgentRetransmit = IsNearDisconnectTimeoutUnsafe(nowMicros); // Urgent only when connection is at risk
                            _tailLossProbePending = true; // Mark TLP as pending
                            tailLossProbe = true; // Signal for post-processing
                            break; // Only one segment per TLP event.
                        }
                    }
                }

                // ---- Stage C: Silence Probe ----
                if (!timedOut && !_tailLossProbePending && inflightSegments > UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS // No timeout, no TLP, inflight above TLP threshold
                    && _lastAckReceivedMicros > 0 && _rtoEstimator.SmoothedRttMicros > 0 // Have ACK history and SRTT
                    && nowMicros - _lastAckReceivedMicros >= _rtoEstimator.SmoothedRttMicros * 3) // No ACK for 3 * SRTT — potential path blackout
                {
                    // Find the highest-sequence in-flight segment (most recently sent).
                    uint highestSeq = 0; // Track highest sequence number
                    OutboundSegment newest = null; // Track newest in-flight segment
                    foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer) // Scan for newest in-flight segment
                    {
                        if (pair.Value.Acked || !pair.Value.InFlight || pair.Value.NeedsRetransmit) continue; // Skip non-candidates
                        if (newest == null || UcpSequenceComparer.IsAfter(pair.Key, highestSeq)) // First candidate or higher sequence
                        {
                            highestSeq = pair.Key; // Update highest sequence
                            newest = pair.Value; // Update newest segment
                        }
                    }
                    if (newest != null) // Found a valid candidate
                    {
                    newest.NeedsRetransmit = true; // Mark for retransmission as path probe
                        // Mark as urgent in cold-path SACK tracking state for silence probe.
                        GetOrCreateSackTrackingUnsafe(newest.SequenceNumber).UrgentRetransmit = true; // Bypass pacing for path probe
                        _tailLossProbePending = true; // Mark probe as pending
                        tailLossProbe = true; // Signal for post-processing
                    }
                }

                // RTO recovery: notify BBR and apply exponential backoff.
                if (timedOut) // RTO timeout occurred this tick
                {
                    _bbr.OnPacketLoss(nowMicros, GetRetransmissionRatioUnsafe(), timedOutForCongestion); // Notify BBR of packet loss event
                    TraceLogUnsafe("RTO loss congestion=" + timedOutForCongestion + " rto=" + _rtoEstimator.CurrentRtoMicros); // Debug trace
                    if (timedOutForCongestion) // Congestion-classified timeout
                    {
                        _rtoEstimator.Backoff(); // Exponential backoff for congestion timeouts.
                    }
                }

                // ---- Stage D: NAK collection ----
                CollectMissingForNakUnsafe(missingForNak, nowMicros); // Scan receive buffer for persistent gaps to NAK

                // ---- Stage E: Keep-alive ----
                if (_state == UcpConnectionState.Established && nowMicros - _lastAckSentMicros >= _config.KeepAliveIntervalMicros && nowMicros - _lastActivityMicros >= _config.KeepAliveIntervalMicros) // Established and idle for keep-alive interval
                {
                    sendKeepAlive = true; // Signal to send keep-alive probe
                }

                // ---- Stage F: SYN-ACK retransmission ----
                if (_isServerSide && _state == UcpConnectionState.HandshakeSynReceived && _synAckSent && nowMicros - _synAckSentMicros >= _rtoEstimator.CurrentRtoMicros) // Server side, waiting for handshake ACK, RTO elapsed
                {
                    _synAckSentMicros = nowMicros; // Reset SYN-ACK send timestamp
                    retransmitSynAck = true; // Signal to retransmit SYN-ACK
                }
            }

            if (maxRetransmissionsExceeded) // Connection should be aborted
            {
                TransitionToClosed(); // Transition to Closed state (abort connection)
                return; // Stop timer processing
            }

            if (timedOut || tailLossProbe) // Segments need retransmission
            {
                await FlushSendQueueAsync().ConfigureAwait(false); // Trigger flush to retransmit timed-out/probe segments
            }

            if (retransmitSynAck) // SYN-ACK needs retransmission
            {
                SendControl(UcpPacketType.SynAck, UcpPacketFlags.None); // Retransmit SYN-ACK
            }

            if (missingForNak.Count > 0) // Gaps found in receive buffer
            {
                SendNak(missingForNak); // Send NAK packet with missing sequences
            }

            if (sendKeepAlive) // Keep-alive needed
            {
                // -1 echo = keepalive (no echo timestamp, pure liveness check).
                SendAckPacket(UcpPacketFlags.None, -1); // Send keep-alive ACK (echo override -1 = no echo)
            }

            // ---- Stage G: Disconnect timeout ----
            if ((_state == UcpConnectionState.HandshakeSynSent || _state == UcpConnectionState.HandshakeSynReceived || _state == UcpConnectionState.Established || _state == UcpConnectionState.ClosingFinSent || _state == UcpConnectionState.ClosingFinReceived) // In a non-closed state
                && nowMicros - _lastActivityMicros >= _config.DisconnectTimeoutMicros) // No activity for disconnect timeout
            {
                TransitionToClosed(); // Transition to Closed (connection timed out)
                return; // Stop timer processing
            }

            if (_state == UcpConnectionState.Closed) // State is already closed
            {
                TransitionToClosed(); // Ensure cleanup on re-entry.
            }
        }

        /// <summary>
        /// Scans the receive buffer for missing sequences (gaps) and collects up to
        /// MAX_NAK_SEQUENCES_PER_PACKET entries for NAK emission.  Only sequences
        /// that have been observed missing enough times and whose reorder grace has
        /// expired are collected.  Scanning is bounded by MAX_NAK_MISSING_SCAN to
        /// avoid O(n) traversal on large gaps.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void CollectMissingForNakUnsafe(List<uint> missing, long nowMicros)
        {
            if (missing == null || _recvBuffer.Count == 0 || _recvBuffer.ContainsKey(_nextExpectedSequence)) // No buffer, buffer empty, or expected sequence already received
            {
                return; // No gap at the expected sequence — nothing to NAK.
            }

            // Find the highest received sequence to bound the scan range.
            uint highestReceived = _nextExpectedSequence; // Start from expected sequence
            bool hasHighest = false; // Whether we found any received sequence
            foreach (KeyValuePair<uint, InboundSegment> pair in _recvBuffer) // Scan receive buffer for highest received sequence
            {
                if (!hasHighest || UcpSequenceComparer.IsAfter(pair.Key, highestReceived)) // First candidate or higher sequence found
                {
                    highestReceived = pair.Key; // Update highest received
                    hasHighest = true; // Mark that we have a value
                }
            }

            if (!hasHighest) // No received sequences found (should not happen since _recvBuffer.Count > 0)
            {
                return; // Safety: no range to scan
            }

            // Scan from expected to highest received, collecting NAK-eligible gaps.
            uint current = _nextExpectedSequence; // Start scanning from expected sequence
            int remainingScan = UcpConstants.MAX_NAK_MISSING_SCAN; // Bounded scan budget
            while (missing.Count < UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET && current != highestReceived && remainingScan > 0) // Not full, not reached highest, scan budget remains
            {
                if (!_recvBuffer.ContainsKey(current)) // This sequence is missing (gap)
                {
                    long firstSeenMicros = GetMissingFirstSeenMicrosUnsafe(current); // Get or record first observation time
                    int missingCount; // Missing observation counter
                    _missingSequenceCounts.TryGetValue(current, out missingCount); // Get current count
                    missingCount++; // Increment observation count
                    _missingSequenceCounts[current] = missingCount; // Store updated count
                    if (missingCount >= UcpConstants.NAK_MISSING_THRESHOLD && HasNakReorderGraceExpiredUnsafe(missingCount, firstSeenMicros, nowMicros) && ShouldIssueNakUnsafe(current)) // Meets all NAK criteria
                    {
                        MarkNakIssuedUnsafe(current); // Mark that NAK was issued for this sequence
                        missing.Add(current); // Add to NAK list
                    }
                }

                current = UcpSequenceComparer.Increment(current); // Advance to next sequence
                remainingScan--; // Decrement scan budget
            }
        }

        // ---- State transitions ----

        /// <summary>
        /// Transitions the connection to Established state.  Raises the Connected
        /// event (exactly once per lifetime) and signals the _connectedTcs so that
        /// ConnectAsync() can return.  If already Established or Closed, returns
        /// immediately (idempotent).
        ///
        /// The Connected event is fired outside the lock to prevent deadlocks
        /// in user callback code.
        /// </summary>
        private void TransitionToEstablished()
        {
            Action connected = null; // Snapshot of Connected event for raise outside lock
            lock (_sync) // Acquire protocol lock for state transition
            {
                if (_state == UcpConnectionState.Established || _state == UcpConnectionState.Closed) // Already established or closed — idempotent
                {
                    return; // Nothing to do
                }

                _state = UcpConnectionState.Established; // Set state to Established
                if (!_connectedRaised) // Connected event hasn't been raised yet
                {
                    _connectedRaised = true; // Mark as raised (ensures exactly once)
                    connected = Connected; // Snapshot for raise outside lock.
                }
            }

            _connectedTcs.TrySetResult(true); // Signal ConnectAsync that handshake succeeded
            if (connected != null) // At least one subscriber
            {
                connected(); // Fire Connected event outside lock
            }
        }

        /// <summary>
        /// Transitions the connection to Closed state.  Raises the Disconnected
        /// event, signals both TCSes (connected fails, closed completes), releases
        /// the receive signal (unblocks waiting ReceiveAsync callers), releases
        /// network registrations, and invokes the closed callback.
        ///
        /// Idempotent: if _closedResourcesReleased is already true, returns
        /// immediately to avoid double-cleanup.
        ///
        /// The Disconnected event is fired outside the lock to prevent deadlocks.
        /// </summary>
        private void TransitionToClosed()
        {
            Action disconnected = null; // Snapshot of Disconnected event for raise outside lock
            bool shouldCallback = false; // Whether to invoke the _closedCallback
            bool releaseResources = false; // Whether to release network registrations
            lock (_sync) // Acquire protocol lock for state transition
            {
                if (_state == UcpConnectionState.Closed) // Already in Closed state
                {
                    if (_closedResourcesReleased) // Resources already released
                    {
                        return; // Already fully cleaned up.
                    }
                }

                _state = UcpConnectionState.Closed; // Set state to Closed
                if (!_closedResourcesReleased) // Resources not yet released
                {
                    _closedResourcesReleased = true; // Mark as released
                    releaseResources = true; // Signal to release resources outside lock
                }

                if (!_disconnectedRaised) // Disconnected event hasn't been raised yet
                {
                    _disconnectedRaised = true; // Mark as raised (ensures exactly once)
                    disconnected = Disconnected; // Snapshot for raise outside lock.
                }

                shouldCallback = true; // Signal to invoke closed callback
            }

            _connectedTcs.TrySetResult(false); // Connection failed.
            _closedTcs.TrySetResult(true); // Close complete.
            _receiveSignal.Release(); // Unblocks any waiting ReceiveAsync callers.
            if (releaseResources) // Need to release network resources
            {
                ReleaseNetworkRegistrations(); // Unregister from network and cancel timers
            }

            if (disconnected != null) // At least one subscriber
            {
                disconnected(); // Fire Disconnected event outside lock
            }

            if (shouldCallback && _closedCallback != null) // Callback should fire and callback is registered
            {
                _closedCallback(this); // Invoke closed callback (UcpNetwork removes this PCB from its table)
            }
        }

        /// <summary>
        /// Unregisters this PCB from the network engine and cancels all
        /// registered timers.  Called during close/dispose to release
        /// network resources.
        /// </summary>
        private void ReleaseNetworkRegistrations()
        {
            if (_network == null) // No network engine registered
            {
                return; // Nothing to release
            }

            _network.UnregisterPcb(this); // Remove PCB from network's connection table
            if (_timerId != 0) // Periodic timer is active
            {
                _network.CancelTimer(_timerId); // Cancel the periodic timer
                _timerId = 0; // Clear timer ID
            }

            if (_flushTimerId != 0) // Delayed flush timer is active
            {
                _network.CancelTimer(_flushTimerId); // Cancel the delayed flush timer
                _flushTimerId = 0; // Clear timer ID
            }
        }

        // ---- Utility methods ----

        /// <summary>
        /// Waits for a task to complete with a timeout.  Returns true if the task
        /// completed before the timeout; false if timeout expired.
        /// Uses Task.WhenAny for cooperative cancellation.
        /// </summary>
        private static async Task<bool> WaitWithTimeoutAsync(Task task, int timeoutMilliseconds)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMilliseconds)).ConfigureAwait(false); // Race: task vs timeout — whichever finishes first
            if (completed != task) // Timeout finished first
            {
                return false; // Timeout expired
            }

            await task.ConfigureAwait(false); // Await the completed task to propagate any exceptions
            return true; // Task completed before timeout
        }

        /// <summary>
        /// Generates a non-zero cryptographically random connection ID.
        /// Zero is reserved (never assigned).  Uses do-while loop to ensure
        /// the generated ID is non-zero.  ConnectionIdGenerator is a
        /// static RandomNumberGenerator for entropy.
        /// </summary>
        private static uint NextConnectionId()
        {
            byte[] bytes = new byte[UcpConstants.CONNECTION_ID_SIZE]; // Allocate buffer for random bytes
            uint connectionId; // Generated connection ID
            do
            {
                ConnectionIdGenerator.GetBytes(bytes); // Fill buffer with cryptographically random bytes
                connectionId = BitConverter.ToUInt32(bytes, 0); // Convert bytes to uint32
            }
            while (connectionId == 0); // Zero is reserved — retry until non-zero.

            return connectionId; // Return cryptographically random non-zero connection ID
        }

        /// <summary>
        /// Generates a cryptographically random initial sequence number (ISN).
        /// Like TCP's ISN (RFC 6528), UCP starts each connection from a
        /// random 32-bit sequence number to prevent off-path injection attacks.
        /// An attacker who cannot predict the ISN cannot inject valid data
        /// into the connection because sequence numbers must fall within the
        /// receiver's window.
        /// </summary>
        private static uint NextSequence()
        {
            byte[] bytes = new byte[UcpConstants.SEQUENCE_NUMBER_SIZE]; // Allocate buffer for random bytes
            SequenceRng.GetBytes(bytes); // Fill buffer with cryptographically random bytes
            return BitConverter.ToUInt32(bytes, 0); // Convert to uint32 ISN
        }

        /// <summary>
        /// Returns the current protocol time in microseconds, preferring the
        /// network's shared clock (consistent across all PCBs) when available.
        /// In standalone mode, falls back to the system high-resolution timer.
        /// </summary>
        private long NowMicros()
        {
            return _network == null ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs; // Use network clock if available, otherwise system high-resolution timer
        }

        /// <summary>
        /// Adds an RTT sample to the history buffer, bounded at MaxRttSamples.
        /// Oldest samples are dropped when the buffer is full (FIFO eviction).
        /// The minimum value in this buffer is used by the loss classifier for
        /// RTT-inflation detection.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void AddRttSampleUnsafe(long sampleRttMicros)
        {
            if (sampleRttMicros <= 0) // Invalid or zero RTT sample
            {
                return; // Ignore invalid samples
            }

            _rttSamplesMicros.Add(sampleRttMicros); // Append to sample history
            if (_rttSamplesMicros.Count > UcpConstants.MaxRttSamples) // History is at capacity
            {
                _rttSamplesMicros.RemoveAt(0); // Drop oldest sample when at capacity.
            }
        }

        /// <summary>
        /// Packs a SACK block (Start, End) into a single ulong key for send-count
        /// tracking.  Start occupies the upper 32 bits, End occupies the lower 32 bits.
        /// This enables O(1) dictionary lookup to check if a range has been sent
        /// the maximum number of times.
        /// </summary>
        private static ulong PackSackBlockKey(uint start, uint end)
        {
            return ((ulong)start << 32) | end; // Pack start into upper 32 bits, end into lower 32 bits
        }

        /// <summary>
        /// Purges SACK send-count entries when the dictionary grows beyond 1024
        /// entries, preventing unbounded memory growth from stale SACK ranges.
        /// Full clear is safe because stale send-counts are harmless — the
        /// worst case is a range being sent one extra time beyond MAX_SACK_SEND_COUNT.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void PurgeSackSendCountsUnsafe()
        {
            if (_sackBlockSendCounts.Count > 1024) // Dictionary exceeded threshold
            {
                _sackBlockSendCounts.Clear(); // Clear all entries — stale counts are harmless
            }
        }

        /// <summary>
        /// Validates send/receive buffer arguments.  Throws on null buffer,
        /// negative offset/count, or range exceeding buffer length.
        /// </summary>
        private static void ValidateBuffer(byte[] buffer, int offset, int count)
        {
            if (buffer == null) // Null buffer reference
            {
                throw new ArgumentNullException(nameof(buffer)); // Throw on null buffer
            }

            if (offset < 0 || count < 0 || offset + count > buffer.Length) // Negative offset/count or range exceeds buffer
            {
                throw new ArgumentOutOfRangeException("buffer", "Buffer range is invalid."); // Throw on invalid range
            }
        }
    }
}
