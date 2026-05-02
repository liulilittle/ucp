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
        /// The MissingAckCount/FirstMissingAckMicros pair implements SACK-based loss detection:
        /// each time a SACK block omits this sequence (while bracketing it between reported ranges),
        /// MissingAckCount increments.  When it reaches the threshold and reorder-grace expires,
        /// the segment is marked for fast retransmit without waiting for RTO.
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

            /// <summary>True when recovery must bypass smooth pacing to avoid connection death.</summary>
            public bool UrgentRetransmit;

            /// <summary>Count of times this segment was seen as missing in SACK blocks.</summary>
            public int MissingAckCount;

            /// <summary>Microsecond timestamp of the first SACK observation for this hole.</summary>
            public long FirstMissingAckMicros;

            /// <summary>Number of times transmitted (0 = never sent).</summary>
            public int SendCount;

            /// <summary>Microsecond timestamp of the most recent send.</summary>
            public long LastSendMicros;
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
            : this(transport, remoteEndPoint, isServerSide, useFairQueue, closedCallback, connectionId, config, null)
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
            _transport = transport;
            _remoteEndPoint = remoteEndPoint;
            _isServerSide = isServerSide;
            _useFairQueue = useFairQueue;
            _config = config ?? new UcpConfiguration();
            _network = network;
            _closedCallback = closedCallback;
            // Generate a cryptographically random connection ID (zero is reserved — retry until non-zero).
            _connectionId = connectionId ?? NextConnectionId();
            _rtoEstimator = new UcpRtoEstimator(_config);
            _bbr = new BbrCongestionControl(_config);
            // Start pacing at the configured initial bandwidth so early sends are not blocked.
            _pacing = new PacingController(_config, _config.InitialBandwidthBytesPerSecond);
            if (_config.FecRedundancy > 0d && _config.FecGroupSize > 1)
            {
                int fecRepairCount = Math.Max(1, (int)Math.Ceiling(_config.FecGroupSize * _config.FecRedundancy));
                _fecCodec = new UcpFecCodec(_config.FecGroupSize, fecRepairCount);
            }

            // Initialize state: pre-handshake, random ISN, snapshot current time.
            _state = UcpConnectionState.Init;
            _nextSendSequence = NextSequence();
            _lastActivityMicros = NowMicros();
            _lastAckSentMicros = _lastActivityMicros;
            _remoteWindowBytes = _config.ReceiveWindowBytes;
            _localReceiveWindowBytes = _config.ReceiveWindowBytes;
            if (_network == null)
            {
                // Standalone mode: use a .NET Timer.
                _timer = new Timer(OnTimer, null, _config.TimerIntervalMilliseconds, _config.TimerIntervalMilliseconds);
            }
            else
            {
                // Network-managed mode: register with the network and schedule via network timers.
                _network.RegisterPcb(this);
                ScheduleTimer();
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
            get { return _connectionId; }
        }

        /// <summary>Remote endpoint of this connection (IP address + UDP port).</summary>
        public IPEndPoint RemoteEndPoint
        {
            get { return _remoteEndPoint; }
        }

        /// <summary>Current connection state, thread-safe (acquires _sync lock on read).</summary>
        public UcpConnectionState State
        {
            get { lock (_sync) { return _state; } }
        }

        /// <summary>Current pacing rate from the BBR controller in bytes/sec, thread-safe.</summary>
        public double CurrentPacingRateBytesPerSecond
        {
            get { lock (_sync) { return _bbr.PacingRateBytesPerSecond; } }
        }

        /// <summary>Whether the send buffer contains unsent segments, thread-safe.</summary>
        public bool HasPendingSendData
        {
            get { lock (_sync) { return _sendBuffer.Count > 0; } }
        }

        /// <summary>
        /// Creates a snapshot of all diagnostic counters and state for reporting.
        /// Captured under _sync lock for consistency — all counters are read atomically
        /// within a single critical section so the snapshot is self-consistent.
        /// </summary>
        /// <returns>An immutable snapshot of the current diagnostics.</returns>
        public UcpConnectionDiagnostics GetDiagnosticsSnapshot()
        {
            lock (_sync)
            {
                UcpConnectionDiagnostics diagnostics = new UcpConnectionDiagnostics();
                diagnostics.State = _state;
                diagnostics.FlightBytes = _flightBytes;
                diagnostics.RemoteWindowBytes = _remoteWindowBytes;
                diagnostics.BytesSent = _bytesSent;
                diagnostics.BytesReceived = _bytesReceived;
                diagnostics.SentDataPackets = _sentDataPackets;
                diagnostics.RetransmittedPackets = _retransmittedPackets;
                diagnostics.SentAckPackets = _sentAckPackets;
                diagnostics.SentNakPackets = _sentNakPackets;
                diagnostics.SentRstPackets = _sentRstPackets;
                diagnostics.FastRetransmissions = _fastRetransmissions;
                diagnostics.TimeoutRetransmissions = _timeoutRetransmissions;
                diagnostics.CongestionWindowBytes = _bbr.CongestionWindowBytes;
                diagnostics.PacingRateBytesPerSecond = _bbr.PacingRateBytesPerSecond;
                diagnostics.EstimatedLossPercent = _bbr.EstimatedLossPercent;
                diagnostics.LastRttMicros = _lastRttMicros;
                // Copy RTT samples to avoid exposing mutable list.
                diagnostics.RttSamplesMicros.AddRange(_rttSamplesMicros);
                diagnostics.ReceivedReset = _rstReceived;
                diagnostics.CurrentNetworkClass = (int)_bbr.CurrentNetworkClass;

                int bufferedBytes = 0;
                foreach (ReceiveChunk chunk in _receiveQueue)
                {
                    bufferedBytes += chunk.Count - chunk.Offset;
                }

                diagnostics.BufferedReceiveBytes = bufferedBytes;
                return diagnostics;
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
            if (sendReset && _remoteEndPoint != null)
            {
                // RST with no flags — peer can distinguish from graceful FIN close.
                SendControl(UcpPacketType.Rst, UcpPacketFlags.None);
            }

            TransitionToClosed();
        }

        /// <summary>
        /// Test hook: overrides the next send sequence number.
        /// Used by unit tests to control sequence number assignment for deterministic testing.
        /// </summary>
        public void SetNextSendSequenceForTest(uint nextSendSequence)
        {
            lock (_sync)
            {
                _nextSendSequence = nextSendSequence;
            }
        }

        /// <summary>
        /// Test hook: overrides the advertised receive window.
        /// Used by unit tests to simulate constrained receiver scenarios.
        /// </summary>
        public void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            lock (_sync)
            {
                _localReceiveWindowBytes = windowBytes;
            }
        }

        /// <summary>
        /// Sets or updates the remote endpoint for this connection.
        /// Must be called under _sync lock to prevent race conditions.
        /// </summary>
        public void SetRemoteEndPoint(IPEndPoint remoteEndPoint)
        {
            lock (_sync)
            {
                _remoteEndPoint = remoteEndPoint;
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
            if (remoteEndPoint == null)
            {
                return false;
            }

            lock (_sync)
            {
                if (_remoteEndPoint == null)
                {
                    // First packet — accept unconditionally.
                    _remoteEndPoint = remoteEndPoint;
                    return true;
                }

                if (_remoteEndPoint.Equals(remoteEndPoint))
                {
                    return true;
                }

                // IP-agnostic: accept new endpoint (client changed port/IP).
                // The connection ID in the packet header is the true identity.
                _remoteEndPoint = remoteEndPoint;
                return true;
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
            SetRemoteEndPoint(remoteEndPoint);
            lock (_sync)
            {
                if (_state == UcpConnectionState.Established)
                {
                    return; // Already connected — idempotent.
                }

                _state = UcpConnectionState.HandshakeSynSent;
                _synSent = true;
            }

            long deadlineMicros = NowMicros() + (_config.ConnectTimeoutMilliseconds * UcpConstants.MICROS_PER_MILLI);
            while (NowMicros() < deadlineMicros)
            {
                // Send SYN carrying our ISN (_nextSendSequence).
                SendControl(UcpPacketType.Syn, UcpPacketFlags.None);
                int waitMilliseconds;
                lock (_sync)
                {
                    // Wait at least MIN_HANDSHAKE_WAIT_MILLISECONDS, otherwise the
                    // current RTO (which may be very small before any samples).
                    waitMilliseconds = (int)Math.Max(UcpConstants.MIN_HANDSHAKE_WAIT_MILLISECONDS, _rtoEstimator.CurrentRtoMicros / UcpConstants.MICROS_PER_MILLI);
                }

                Task completed = await Task.WhenAny(_connectedTcs.Task, Task.Delay(waitMilliseconds, _cts.Token)).ConfigureAwait(false);
                if (completed == _connectedTcs.Task)
                {
                    if (await _connectedTcs.Task.ConfigureAwait(false))
                    {
                        return; // Connection established — SYN-ACK received and processed.
                    }

                    break; // _connectedTcs completed with false — handshake failed.
                }
                // Timeout expired — resend SYN with backoff (RTO grows).
            }

            throw new TimeoutException("UCP connection handshake timed out.");
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
            ValidateBuffer(buffer, offset, count);
            lock (_sync)
            {
                // Only accept data in Established, ClosingFinSent, or ClosingFinReceived.
                // Reject in Init, Handshake*, Closed, or after RST.
                if (_state != UcpConnectionState.Established && _state != UcpConnectionState.ClosingFinSent && _state != UcpConnectionState.ClosingFinReceived)
                {
                    return -1;
                }

            }

            int acceptedBytes = 0;
            int remaining = count;
            int currentOffset = offset;
            // Cap to max message size: MaxPayloadSize (MSS) * ushort.MaxValue (max fragments).
            if (count > _config.MaxPayloadSize * ushort.MaxValue)
            {
                count = _config.MaxPayloadSize * ushort.MaxValue;
                remaining = count;
            }

            // Calculate total fragments needed for this message.
            ushort fragmentTotal = (ushort)((count + _config.MaxPayloadSize - 1) / _config.MaxPayloadSize);
            ushort fragmentIndex = 0;
            int maxBufferedSegments = Math.Max(1, _config.SendBufferSize / Math.Max(1, _config.MaxPayloadSize));

            while (remaining > 0)
            {
                int chunk = remaining > _config.MaxPayloadSize ? _config.MaxPayloadSize : remaining;
                lock (_sync)
                {
                    // Flow control: don't exceed send buffer capacity.
                    if (_sendBuffer.Count >= maxBufferedSegments)
                    {
                        break; // Send buffer full; caller should retry via WriteAsync.
                    }
                }

                byte[] payload = new byte[chunk];
                Buffer.BlockCopy(buffer, currentOffset, payload, 0, chunk);

                lock (_sync)
                {
                    OutboundSegment segment = new OutboundSegment();
                    segment.SequenceNumber = _nextSendSequence;
                    segment.FragmentTotal = fragmentTotal;
                    segment.FragmentIndex = fragmentIndex;
                    segment.Payload = payload;
                    // Insert into sorted dictionary; UcpSequenceComparer maintains 32-bit wraparound order.
                    _sendBuffer[segment.SequenceNumber] = segment;
                    _nextSendSequence = UcpSequenceComparer.Increment(_nextSendSequence);
                }

                currentOffset += chunk;
                remaining -= chunk;
                acceptedBytes += chunk;
                fragmentIndex++;
            }

            await FlushSendQueueAsync().ConfigureAwait(false);
            return acceptedBytes;
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
            ValidateBuffer(buffer, offset, count);
            while (true)
            {
                ReceiveChunk chunk = null;
                lock (_sync)
                {
                    if (_receiveQueue.Count > 0)
                    {
                        chunk = _receiveQueue.Peek();
                    }
                    else if (_state == UcpConnectionState.Closed)
                    {
                        return 0; // Connection closed, no more data.
                    }
                }

                if (chunk != null)
                {
                    lock (_sync)
                    {
                        ReceiveChunk current = _receiveQueue.Peek();
                        int available = current.Count - current.Offset;
                        int toCopy = available > count ? count : available;
                        Buffer.BlockCopy(current.Buffer, current.Offset, buffer, offset, toCopy);
                        current.Offset += toCopy;
                        _queuedReceiveBytes -= toCopy;
                        if (_queuedReceiveBytes < 0)
                        {
                            _queuedReceiveBytes = 0;
                        }
                        if (current.Offset >= current.Count)
                        {
                            // Chunk fully consumed — remove from queue.
                            _receiveQueue.Dequeue();
                        }

                        // Schedule an ACK since we freed receive window space.
                        ScheduleAck();

                        return toCopy;
                    }
                }

                // Wait for data to arrive (signaled by EnqueuePayload).
                await _receiveSignal.WaitAsync(_cts.Token).ConfigureAwait(false);
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
            ValidateBuffer(buffer, offset, count);
            int totalWritten = 0;
            while (totalWritten < count)
            {
                int written = await SendAsync(buffer, offset + totalWritten, count - totalWritten).ConfigureAwait(false);
                if (written < 0)
                {
                    return false; // Connection not in sendable state.
                }

                if (written == 0)
                {
                    // Send buffer full — wait for ACKs to free space.
                    await _sendSpaceSignal.WaitAsync(_cts.Token).ConfigureAwait(false);
                    continue;
                }

                totalWritten += written;
            }

            return true;
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
            bool needSendFin = false;
            long deadlineMicros = NowMicros() + _config.DisconnectTimeoutMicros;
            // Step 1: Drain the send buffer (wait for in-flight data to be ACKed).
            while (NowMicros() < deadlineMicros)
            {
                lock (_sync)
                {
                    if (_sendBuffer.Count == 0 || _state == UcpConnectionState.Closed)
                    {
                        break;
                    }
                }

                await _sendSpaceSignal.WaitAsync(10, _cts.Token).ConfigureAwait(false);
            }

            // Step 2: Send FIN if not already sent.
            lock (_sync)
            {
                if (_state == UcpConnectionState.Closed)
                {
                    return;
                }

                if (!_finSent)
                {
                    _state = UcpConnectionState.ClosingFinSent;
                    _finSent = true;
                    needSendFin = true;
                }
            }

            if (needSendFin)
            {
                SendControl(UcpPacketType.Fin, UcpPacketFlags.None);
            }

            // Step 3-4: Wait for peer FIN-ACK, then transition to Closed.
            await WaitWithTimeoutAsync(_closedTcs.Task, UcpConstants.CLOSE_WAIT_TIMEOUT_MILLISECONDS).ConfigureAwait(false);
            TransitionToClosed();
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
            if (packet == null)
            {
                return;
            }

            lock (_sync)
            {
                _lastActivityMicros = NowMicros();
            }

            if (packet.Header.Type == UcpPacketType.Syn)
            {
                HandleSyn((UcpControlPacket)packet);
                return;
            }

            if (packet.Header.Type == UcpPacketType.SynAck)
            {
                HandleSynAck((UcpControlPacket)packet);
                return;
            }

            if (packet.Header.Type == UcpPacketType.Ack)
            {
                await HandleAckAsync((UcpAckPacket)packet).ConfigureAwait(false);
                return;
            }

            if (packet.Header.Type == UcpPacketType.Nak)
            {
                await HandleNakAsync((UcpNakPacket)packet).ConfigureAwait(false);
                return;
            }

            if (packet.Header.Type == UcpPacketType.Data)
            {
                HandleData((UcpDataPacket)packet);
                return;
            }

            if (packet.Header.Type == UcpPacketType.FecRepair)
            {
                HandleFecRepair((UcpFecRepairPacket)packet);
                return;
            }

            if (packet.Header.Type == UcpPacketType.Fin)
            {
                HandleFin((UcpControlPacket)packet);
                return;
            }

            if (packet.Header.Type == UcpPacketType.Rst)
            {
                _rstReceived = true;
                TransitionToClosed();
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
            if (!_useFairQueue || bytes <= 0)
            {
                return;
            }

            lock (_sync)
            {
                _fairQueueCreditBytes += bytes;
                double maxCreditBytes = Math.Max(_config.SendQuantumBytes, _config.Mss) * UcpConstants.MaxBufferedFairQueueRounds;
                if (_fairQueueCreditBytes > maxCreditBytes)
                {
                    _fairQueueCreditBytes = maxCreditBytes;
                }
            }
        }

        /// <summary>
        /// Requests an immediate flush of the send buffer.  Fire-and-forget:
        /// the actual flush runs asynchronously on the thread pool.
        /// </summary>
        public void RequestFlush()
        {
            _ = FlushSendQueueAsync();
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
            if (_disposed)
            {
                return 0;
            }

            int work = 0;
            Task timerTask = OnTimerAsync(nowMicros);
            if (timerTask.IsCompleted)
            {
                work++;
            }

            if (HasPendingSendData)
            {
                RequestFlush();
                work++;
            }

            return work;
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
            if (ValidateRemoteEndPoint(remoteEndPoint))
            {
                _ = HandleInboundAsync(packet);
            }
        }

        /// <summary>
        /// Disposes the PCB: cancels all async operations, disposes timers and
        /// semaphores, unregisters from the network, and transitions to Closed.
        /// Safe to call multiple times (idempotent via _disposed flag).
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _cts.Cancel();
            if (_timer != null)
            {
                _timer.Dispose();
            }

            ReleaseNetworkRegistrations();
            TransitionToClosed();
            _cts.Dispose();
            _receiveSignal.Dispose();
            _sendSpaceSignal.Dispose();
            _flushLock.Dispose();
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
            List<uint> removeKeys = new List<uint>();
            int deliveredBytes = 0;
            lock (_sync)
            {
                // Validate: ACK must be non-zero and non-receding.
                if (ackNumber == 0)
                {
                    return 0;
                }

                // Reject receding ACKs (must be monotonic).
                if (_hasLargestCumulativeAckNumber && UcpSequenceComparer.IsBefore(ackNumber, _largestCumulativeAckNumber))
                {
                    return 0;
                }

                // Update largest cumulative ACK seen.
                if (!_hasLargestCumulativeAckNumber || UcpSequenceComparer.IsAfter(ackNumber, _largestCumulativeAckNumber))
                {
                    _largestCumulativeAckNumber = ackNumber;
                    _hasLargestCumulativeAckNumber = true;
                }

                // Any ACK (even duplicate) proves the path is alive — update timestamps.
                _lastAckReceivedMicros = nowMicros;
                _tailLossProbePending = false;

                // Walk the send buffer in sequence order to find ACKed segments.
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (segment.Acked) continue;

                    if (UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackNumber))
                    {
                        segment.Acked = true;
                        if (segment.InFlight)
                        {
                            _flightBytes -= segment.Payload.Length;
                            if (_flightBytes < 0) _flightBytes = 0; // Safety clamp.
                        }

                        deliveredBytes += segment.Payload.Length;
                        // Karn's algorithm: use only first-transmission packets for RTT
                        // estimation.  Retransmitted packets have ambiguous timing
                        // (did the ACK refer to the original or the retransmit?).
                        if (segment.SendCount == 1 && segment.LastSendMicros > 0)
                        {
                            long segmentRtt = nowMicros - segment.LastSendMicros;
                            if (segmentRtt > 0)
                            {
                                _lastRttMicros = segmentRtt;
                                AddRttSampleUnsafe(segmentRtt);
                                _rtoEstimator.Update(segmentRtt);
                            }
                        }

                        removeKeys.Add(pair.Key);
                    }
                    else if (UcpSequenceComparer.IsAfter(segment.SequenceNumber, ackNumber))
                    {
                        // Sorted dictionary means we've passed all ACK-eligible segments.
                        break;
                    }
                }

                // Remove acknowledged segments and their tracking state.
                for (int i = 0; i < removeKeys.Count; i++)
                {
                    _sackFastRetransmitNotified.Remove(removeKeys[i]);
                    _sendBuffer.Remove(removeKeys[i]);
                }

                // Signal writers that buffer space has freed up.
                if (removeKeys.Count > 0)
                {
                    try { 
                        _sendSpaceSignal.Release(removeKeys.Count); 
                    } 
                    catch (SemaphoreFullException)
                    {
                        // Semaphore full — benign, just means many ACKs have already
                        // released more capacity than writers can consume.
                    }
                }

                // Reset fair-queue credit when buffer empties (no data to pace).
                if (_sendBuffer.Count == 0)
                {
                    _fairQueueCreditBytes = 0;
                }

                // Update congestion control with delivery information.
                if (deliveredBytes > 0)
                {
                    _bbr.OnAck(nowMicros, deliveredBytes, _lastRttMicros, _flightBytes);
                    _pacing.SetRate(_bbr.PacingRateBytesPerSecond, nowMicros);
                }
            }

            // Note: Callers handle flushing when needed (e.g., if fast retransmit was triggered).
            return deliveredBytes;
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
            bool shouldReply = false;
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            lock (_sync)
            {
                _connectionId = packet.Header.ConnectionId;
                if (_network != null)
                {
                    _network.UpdatePcbConnectionId(this, 0, _connectionId);
                }
                if (packet.HasSequenceNumber)
                {
                    _nextExpectedSequence = packet.SequenceNumber;
                }

                if (_state == UcpConnectionState.Init)
                {
                    _state = UcpConnectionState.HandshakeSynReceived;
                }

                if (_state != UcpConnectionState.Closed)
                {
                    _synAckSent = true;
                    _synAckSentMicros = NowMicros();
                    shouldReply = true;
                }
            }

            // Process piggybacked ACK from re-SYN before replying.
            if (hasAck && packet.AckNumber > 0)
            {
                ProcessPiggybackedAck(packet.AckNumber, packet.Header.Timestamp, NowMicros());
            }

            if (shouldReply)
            {
                SendControl(UcpPacketType.SynAck, UcpPacketFlags.None);
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
            bool shouldEstablish = false;
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            lock (_sync)
            {
                if (packet.HasSequenceNumber)
                {
                    _nextExpectedSequence = packet.SequenceNumber;
                }

                if (_synSent && _state != UcpConnectionState.Closed)
                {
                    // Only transition to Established if we initiated the SYN.
                    shouldEstablish = _state == UcpConnectionState.HandshakeSynSent;
                }
            }

            if (hasAck && packet.AckNumber > 0)
            {
                ProcessPiggybackedAck(packet.AckNumber, packet.Header.Timestamp, NowMicros());
            }

            // Send ACK for the server's ISN (step 3 of handshake).
            SendAckPacket(UcpPacketFlags.None, 0);

            if (shouldEstablish)
            {
                TransitionToEstablished();
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
        ///      increment MissingAckCount and check fast-retransmit eligibility
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
            bool establishByHandshake = false;
            List<uint> removeKeys = new List<uint>();
            int deliveredBytes = 0;
            int remainingFlight;
            long sampleRtt = 0;
            long echoRtt = 0;
            long nowMicros = NowMicros();
            bool fastRetransmitTriggered = false;

            lock (_sync)
            {
                // ---- Stage A: Plausibility check ----
                if (!IsAckPlausibleUnsafe(ackPacket))
                {
                    remainingFlight = _flightBytes;
                    return;
                }

                // Update peer's advertised receive window.
                _remoteWindowBytes = ackPacket.WindowSize;
                // Sort SACK blocks for efficient linear scanning.
                SortSackBlocksUnsafe(ackPacket.SackBlocks);

                // Check if this ACK completes the handshake (server side).
                if (_state == UcpConnectionState.HandshakeSynReceived && _synAckSent)
                {
                    establishByHandshake = true;
                }

                // Check for FIN-ACK flag (peer acknowledges our FIN).
                if ((ackPacket.Header.Flags & UcpPacketFlags.FinAck) == UcpPacketFlags.FinAck)
                {
                    _finAcked = true;
                }

                // Compute echo-based RTT for fallback.
                if (ackPacket.EchoTimestamp > 0)
                {
                    echoRtt = nowMicros - ackPacket.EchoTimestamp;
                }

                // Any ACK proves the path is alive — update receive timestamp.
                _lastAckReceivedMicros = nowMicros;
                _tailLossProbePending = false;

                // ---- Stage D: Duplicate ACK fast retransmit detection ----
                UpdateDuplicateAckStateUnsafe(ackPacket, nowMicros, out fastRetransmitTriggered);

                // ---- Stage B: Cumulative ACK + SACK processing ----
                int sackIndex = 0;
                List<SackBlock> sackBlocks = ackPacket.SackBlocks;
                bool hasSackBlocks = sackBlocks != null && sackBlocks.Count > 0;
                uint highestSack = hasSackBlocks ? GetHighestSackEnd(sackBlocks) : 0U;
                // The first sequence NOT covered by the cumulative ACK — this is the
                // leading edge of the ACK hole, the most likely candidate for loss.
                uint firstMissingSequence = UcpSequenceComparer.Increment(ackPacket.AckNumber);
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (segment.Acked)
                    {
                        continue;
                    }

                    // Check cumulative ACK coverage.
                    bool acked = UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackPacket.AckNumber);
                    if (!acked && sackBlocks != null)
                    {
                        // Scan SACK blocks to check if this segment is selectively ACKed.
                        // SACK blocks are sorted by start, so we advance the index as we go.
                        while (sackIndex < sackBlocks.Count && UcpSequenceComparer.IsBefore(sackBlocks[sackIndex].End, segment.SequenceNumber))
                        {
                            sackIndex++;
                        }

                        if (sackIndex < sackBlocks.Count)
                        {
                            SackBlock block = sackBlocks[sackIndex];
                            acked = UcpSequenceComparer.IsInForwardRange(segment.SequenceNumber, block.Start, block.End);
                        }
                    }

                    if (acked)
                    {
                if (!_hasLargestCumulativeAckNumber || UcpSequenceComparer.IsAfter(ackPacket.AckNumber, _largestCumulativeAckNumber))
                {
                    _largestCumulativeAckNumber = ackPacket.AckNumber;
                    _hasLargestCumulativeAckNumber = true;
                }

                        segment.Acked = true;
                        if (segment.InFlight)
                        {
                            _flightBytes -= segment.Payload.Length;
                            if (_flightBytes < 0)
                            {
                                _flightBytes = 0;
                            }
                        }

                        deliveredBytes += segment.Payload.Length;
                        // Karn's algorithm: only first-transmission packets for RTT.
                        if (segment.SendCount == 1 && segment.LastSendMicros > 0)
                        {
                            long segmentRtt = nowMicros - segment.LastSendMicros;
                            // Keep the smallest (most recent) RTT sample within this ACK.
                            if (sampleRtt == 0 || segmentRtt < sampleRtt)
                            {
                                sampleRtt = segmentRtt;
                            }
                        }

                        _bytesSent += segment.Payload.Length;
                        removeKeys.Add(pair.Key);
                        continue;
                    }

                    // ---- Stage C: SACK-based fast retransmit detection ----
                    if (hasSackBlocks)
                    {
                        // Only consider segments whose sequence is below the highest
                        // SACK end — the peer has acknowledged data beyond this point,
                        // so any un-ACKed segment in between is a candidate for loss.
                        if (UcpSequenceComparer.IsBefore(segment.SequenceNumber, highestSack))
                        {
                            if (!_sackFastRetransmitNotified.Contains(segment.SequenceNumber))
                            {
                                if (segment.MissingAckCount == 0)
                                {
                                    segment.FirstMissingAckMicros = nowMicros;
                                }

                                segment.MissingAckCount++;
                            }

                            // Only non-leading holes bracketed by reported SACK ranges are
                            // repaired in parallel; this avoids treating a truncated SACK
                            // list as proof that every omitted sequence was lost.
                            bool reportedSackHole = IsReportedSackHoleUnsafe(segment.SequenceNumber, ackPacket.AckNumber, sackBlocks);
                            if (segment.SendCount == 1 && !segment.NeedsRetransmit && ShouldFastRetransmitSackHoleUnsafe(segment, firstMissingSequence, highestSack, reportedSackHole, nowMicros))
                            {
                                segment.NeedsRetransmit = true;
                                segment.UrgentRetransmit = true; // Bypass pacing for urgent recovery.
                                _fastRetransmissions++;
                                _sackFastRetransmitNotified.Add(segment.SequenceNumber);
                                bool isCongestionLoss = IsCongestionLossUnsafe(segment.SequenceNumber, sampleRtt, nowMicros, 1);
                                _bbr.OnFastRetransmit(nowMicros, isCongestionLoss);
                                TraceLogUnsafe("FastRetransmit sequence=" + segment.SequenceNumber + " sack=true congestion=" + isCongestionLoss);
                            }
                        }
                    }
                }

                // Remove ACKed segments from the send buffer and clean up tracking state.
                for (int i = 0; i < removeKeys.Count; i++)
                {
                    _sackFastRetransmitNotified.Remove(removeKeys[i]);
                    _sendBuffer.Remove(removeKeys[i]);
                }

                if (removeKeys.Count > 0)
                {
                    try
                    {
                        _sendSpaceSignal.Release(removeKeys.Count);
                    }
                    catch (SemaphoreFullException)
                    {
                    }
                }

                // Reset fair-queue credit when buffer empties.
                if (_sendBuffer.Count == 0)
                {
                    _fairQueueCreditBytes = 0;
                }

                remainingFlight = _flightBytes;

                // ---- Stage E: RTT estimation ----
                // Fall back to echo-based RTT if no segment-level sample is available.
                if (deliveredBytes > 0 && sampleRtt == 0 && echoRtt > 0 && echoRtt <= _rtoEstimator.CurrentRtoMicros)
                {
                    sampleRtt = echoRtt; // Fall back to echo-based RTT.
                }

                // Filter implausible RTT samples (protect RTO estimator from noise).
                bool acceptableRttSample = sampleRtt > 0 && sampleRtt <= (long)(_rtoEstimator.CurrentRtoMicros * UcpConstants.RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
                if (deliveredBytes > 0 && acceptableRttSample)
                {
                    _lastRttMicros = sampleRtt;
                    AddRttSampleUnsafe(sampleRtt);
                    _rtoEstimator.Update(sampleRtt);
                }

                // ---- Stage F: Congestion control update ----
                _bbr.OnAck(nowMicros, deliveredBytes, sampleRtt, _flightBytes);
                _pacing.SetRate(_bbr.PacingRateBytesPerSecond, nowMicros);
            }

            // ---- Stage G: Post-processing ----
            if (establishByHandshake)
            {
                TransitionToEstablished();
            }

            // Both FINs exchanged and acknowledged → clean close.
            if (_finSent && _finAcked && _peerFinReceived)
            {
                TransitionToClosed();
            }

            // Trigger a flush if: fast retransmit was triggered, data was delivered
            // (which means we have new window space), or there's remaining flight
            // (we should try to fill the window).
            if (fastRetransmitTriggered || deliveredBytes > 0 || remainingFlight > 0)
            {
                await FlushSendQueueAsync().ConfigureAwait(false);
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
            bool notifiedLoss = false;
            long nowMicros = NowMicros();

            // Process piggybacked cumulative ACK from NAK.
            if (nakPacket.AckNumber > 0)
            {
                ProcessPiggybackedAck(nakPacket.AckNumber, nakPacket.Header.Timestamp, nowMicros);
            }

            lock (_sync)
            {
                for (int i = 0; i < nakPacket.MissingSequences.Count; i++)
                {
                    uint sequence = nakPacket.MissingSequences[i];
                    OutboundSegment segment;
                    if (_sendBuffer.TryGetValue(sequence, out segment))
                    {
                        // Only retransmit if: not already marked, not already ACKed,
                        // and retransmit cooldown has expired.
                        if (!segment.NeedsRetransmit && !segment.Acked && ShouldAcceptRetransmitRequestUnsafe(segment, nowMicros))
                        {
                            segment.NeedsRetransmit = true;
                            segment.UrgentRetransmit = true; // Bypass pacing for NAK-triggered recovery.
                            _tailLossProbePending = false; // NAK proves the path is alive.
                            notifiedLoss = true;
                        }
                    }
                }

                if (notifiedLoss)
                {
                    bool isCongestionLoss = ClassifyLossesUnsafe(nakPacket.MissingSequences, nowMicros, 0);
                    _bbr.OnPacketLoss(nowMicros, GetRetransmissionRatioUnsafe(), isCongestionLoss);
                    TraceLogUnsafe("NAK loss congestion=" + isCongestionLoss + " count=" + nakPacket.MissingSequences.Count);
                }
            }

            await FlushSendQueueAsync().ConfigureAwait(false);
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
            if (ackPacket == null)
            {
                return false;
            }

            if (ackPacket.Header.ConnectionId != _connectionId)
            {
                return false;
            }

            // ACK must not recede — the cumulative ACK number is monotonic.
            if (_hasLargestCumulativeAckNumber && UcpSequenceComparer.IsBefore(ackPacket.AckNumber, _largestCumulativeAckNumber))
            {
                return false; // ACK cannot recede.
            }

            // Validate SACK block structural integrity.
            if (ackPacket.SackBlocks != null)
            {
                for (int i = 0; i < ackPacket.SackBlocks.Count; i++)
                {
                    SackBlock block = ackPacket.SackBlocks[i];
                    if (UcpSequenceComparer.IsAfter(block.Start, block.End))
                    {
                        return false; // Malformed SACK block.
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Returns the highest End value across all SACK blocks.  Used to determine
        /// the upper bound of the sequence space that the peer has received.
        /// Segments with sequence numbers below this bound that are NOT in any SACK
        /// block are candidates for loss detection.
        /// </summary>
        private static uint GetHighestSackEnd(List<SackBlock> blocks)
        {
            uint highest = 0;
            bool hasValue = false;
            for (int i = 0; i < blocks.Count; i++)
            {
                if (!hasValue || UcpSequenceComparer.IsAfter(blocks[i].End, highest))
                {
                    highest = blocks[i].End;
                    hasValue = true;
                }
            }

            return highest;
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
        ///   6. MissingAckCount must meet the threshold:
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

            if (segment.MissingAckCount < requiredObservations)
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
            if (_fecCodec == null || segment == null || segment.FirstMissingAckMicros <= 0)
            {
                return false;
            }

            uint groupBase = _fecCodec.GetGroupBase(segment.SequenceNumber);
            if (!_fecRepairSentGroups.Contains(groupBase))
            {
                return false; // No repair sent for this group — no FEC to wait for.
            }

            long graceMicros = GetFecFastRetransmitGraceMicrosUnsafe();
            return nowMicros - segment.FirstMissingAckMicros < graceMicros;
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
            fastRetransmitTriggered = false;
            bool hasSack = ackPacket.SackBlocks != null && ackPacket.SackBlocks.Count > 0;
            bool duplicateAck = _hasLastAckNumber && ackPacket.AckNumber == _lastAckNumber;
            if (duplicateAck)
            {
                _duplicateAckCount++;
                if (_duplicateAckCount >= UcpConstants.DUPLICATE_ACK_THRESHOLD && !_fastRecoveryActive)
                {
                    // Infer the next sequence after cumulative ACK as lost.
                    uint lostSeq = UcpSequenceComparer.Increment(ackPacket.AckNumber);
                    OutboundSegment lostSegment;
                    if (_sendBuffer.TryGetValue(lostSeq, out lostSegment) && !lostSegment.Acked && lostSegment.SendCount == 1 && !lostSegment.NeedsRetransmit)
                    {
                        long rttForFastRetransmit = GetFastRetransmitAgeThresholdUnsafe();
                        if (ShouldTriggerEarlyRetransmitUnsafe() || rttForFastRetransmit <= 0 || nowMicros - lostSegment.LastSendMicros >= rttForFastRetransmit)
                        {
                            lostSegment.NeedsRetransmit = true;
                            lostSegment.UrgentRetransmit = true;
                            _fastRecoveryActive = true;
                            _fastRetransmissions++;
                            fastRetransmitTriggered = true;
                            bool isCongestionLoss = IsCongestionLossUnsafe(lostSeq, 0, nowMicros, 1);
                            _bbr.OnFastRetransmit(nowMicros, isCongestionLoss);
                            TraceLogUnsafe("FastRetransmit sequence=" + lostSeq + " dupAck=true congestion=" + isCongestionLoss);
                        }
                    }
                }
            }
            else
            {
                // Non-duplicate ACK: reset counters and exit fast recovery.
                _duplicateAckCount = 0;
                _fastRecoveryActive = false;
            }

            _lastAckNumber = ackPacket.AckNumber;
            _hasLastAckNumber = true;
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
            List<uint> sequences = new List<uint>(1);
            sequences.Add(sequenceNumber);
            return ClassifyLossesUnsafe(sequences, nowMicros, sampleRttMicros, contiguousLossCount);
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
            long minRttMicros = GetMinimumObservedRttMicrosUnsafe();
            if (minRttMicros <= 0)
            {
                minRttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros;
            }

            return Math.Max(UcpConstants.MICROS_PER_MILLI, minRttMicros * 2);
        }

        /// <summary>
        /// Removes loss events older than the classification window.
        /// Called before each classification to keep the queue bounded.
        ///
        /// Must be called under _sync.
        /// </summary>
        private void PruneLossEventsUnsafe(long nowMicros, long windowMicros)
        {
            while (_recentLossEvents.Count > 0 && nowMicros - _recentLossEvents.Peek().TimestampMicros > windowMicros)
            {
                LossEvent expired = _recentLossEvents.Dequeue();
                _recentLossSequences.Remove(expired.SequenceNumber);
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
            List<long> samples = new List<long>();
            foreach (LossEvent lossEvent in _recentLossEvents)
            {
                if (lossEvent.RttMicros > 0)
                {
                    samples.Add(lossEvent.RttMicros);
                }
            }

            // Fall back to the most recent RTT sample if no loss-event RTTs recorded.
            if (samples.Count == 0 && _lastRttMicros > 0)
            {
                samples.Add(_lastRttMicros);
            }

            if (samples.Count == 0)
            {
                return 0;
            }

            samples.Sort();
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
            long minRttMicros = 0;
            for (int i = 0; i < _rttSamplesMicros.Count; i++)
            {
                long sample = _rttSamplesMicros[i];
                if (sample > 0 && (minRttMicros == 0 || sample < minRttMicros))
                {
                    minRttMicros = sample;
                }
            }

            if (minRttMicros == 0 && _lastRttMicros > 0)
            {
                minRttMicros = _lastRttMicros;
            }

            return minRttMicros;
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
            if (_recentLossEvents.Count == 0)
            {
                return 0;
            }

            List<uint> sequenceNumbers = new List<uint>(_recentLossEvents.Count);
            foreach (LossEvent lossEvent in _recentLossEvents)
            {
                sequenceNumbers.Add(lossEvent.SequenceNumber);
            }

            return GetMaxContiguousLossRun(sequenceNumbers);
        }

        /// <summary>
        /// Computes the longest run of consecutive sequence numbers in a list
        /// (wraparound-aware via UcpSequenceComparer).  Sorts input, counts
        /// consecutive runs skipping duplicates.
        /// </summary>
        private static int GetMaxContiguousLossRun(IList<uint> sequenceNumbers)
        {
            if (sequenceNumbers == null || sequenceNumbers.Count == 0)
            {
                return 0;
            }

            List<uint> sorted = new List<uint>(sequenceNumbers);
            sorted.Sort(UcpSequenceComparer.Instance);
            int maxRun = 1;
            int currentRun = 1;
            for (int i = 1; i < sorted.Count; i++)
            {
                if (sorted[i] == sorted[i - 1])
                {
                    continue; // Skip duplicates (deduplication happens at higher level).
                }

                if (unchecked(sorted[i] - sorted[i - 1]) == 1U)
                {
                    currentRun++;
                    if (currentRun > maxRun)
                    {
                        maxRun = currentRun;
                    }
                }
                else
                {
                    currentRun = 1; // Gap found — reset contiguous run.
                }
            }

            return maxRun;
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
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            return rttMicros <= 0 ? 0 : Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros / 8);
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
            int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize));
            return inflightSegments > 0 && inflightSegments <= UcpConstants.EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS;
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
            if (segment == null || segment.SendCount <= 1 || segment.LastSendMicros <= 0)
            {
                return true; // First retransmit is always accepted.
            }

            long graceMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _rtoEstimator.CurrentRtoMicros;
            if (graceMicros <= 0)
            {
                return true; // No RTT estimate — accept to avoid stall.
            }

            return nowMicros - segment.LastSendMicros >= graceMicros;
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
            List<uint> missing = new List<uint>();
            List<byte[]> readyPayloads = new List<byte[]>();
            bool shouldEstablish = false;
            bool shouldStore = false;
            bool sendImmediateAck = false;
            bool hasPiggybackedAck = (dataPacket.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;

            // Stage A: Process piggybacked ACK from data packet BEFORE handling data payload.
            // This keeps the sender's flight bytes accurate and avoids ACK storms — the
            // peer is already sending data, so piggybacking is free.
            if (hasPiggybackedAck && dataPacket.AckNumber > 0)
            {
                ProcessPiggybackedAck(dataPacket.AckNumber, dataPacket.Header.Timestamp, NowMicros());

                if (dataPacket.WindowSize > 0)
                {
                    lock (_sync)
                    {
                        _remoteWindowBytes = dataPacket.WindowSize;
                    }
                }
            }

            lock (_sync)
            {
                // Stage B: Validate packet integrity.
                if (dataPacket.Payload == null || dataPacket.Payload.Length > _config.MaxPayloadSize || dataPacket.FragmentTotal == 0 || dataPacket.FragmentIndex >= dataPacket.FragmentTotal)
                {
                    return;
                }

                // Check if this data packet completes the handshake (server side:
                // client sends data after SYN-ACK, which implicitly acknowledges
                // the server's SYN-ACK when a piggybacked ACK is present).
                if (_state == UcpConnectionState.HandshakeSynReceived && _synAckSent)
                {
                    shouldEstablish = true;
                }

                _lastEchoTimestamp = dataPacket.Header.Timestamp;
                if (UcpSequenceComparer.IsBefore(dataPacket.SequenceNumber, _nextExpectedSequence))
                {
                    // Old duplicate: sequence < expected.  These packets are ACKed
                    // (we already have this data) but not stored again.  The peer
                    // needs an ACK so it can converge its send state.
                }
                else
                {
                    // Stage C: Receive window check.
                    uint usedBytes = GetReceiveWindowUsedBytesUnsafe();
                    shouldStore = usedBytes + dataPacket.Payload.Length <= _localReceiveWindowBytes;
                    if (shouldStore && !_recvBuffer.ContainsKey(dataPacket.SequenceNumber))
                    {
                        // Store the segment in the sorted receive buffer.
                        InboundSegment inbound = new InboundSegment();
                        inbound.SequenceNumber = dataPacket.SequenceNumber;
                        inbound.FragmentTotal = dataPacket.FragmentTotal;
                        inbound.FragmentIndex = dataPacket.FragmentIndex;
                        inbound.Payload = dataPacket.Payload;
                        _recvBuffer[dataPacket.SequenceNumber] = inbound;
                        // Clear NAK/gap tracking state for this sequence — we got it.
                        _nakIssued.Remove(dataPacket.SequenceNumber);
                        _missingSequenceCounts.Remove(dataPacket.SequenceNumber);
                        _missingFirstSeenMicros.Remove(dataPacket.SequenceNumber);
                        _lastNakIssuedMicros.Remove(dataPacket.SequenceNumber);

                        // Stage D: Feed FEC codec with newly arrived data.
                        if (_fecCodec != null)
                        {
                            _fecFragmentMetadata[dataPacket.SequenceNumber] = new FecFragmentMetadata { FragmentTotal = dataPacket.FragmentTotal, FragmentIndex = dataPacket.FragmentIndex };
                            _fecCodec.FeedDataPacket(dataPacket.SequenceNumber, dataPacket.Payload);
                            // Attempt FEC recovery: the new data packet might enable
                            // reconstruction of previously missing packets in the same group.
                            TryRecoverFecAroundUnsafe(dataPacket.SequenceNumber, readyPayloads);
                        }
                    }

                    // Stage E: Gap detection and NAK collection.
                    if (shouldStore && UcpSequenceComparer.IsAfter(dataPacket.SequenceNumber, _nextExpectedSequence))
                    {
                        // Gap detected — the peer sent us a packet with a higher sequence
                        // than we expected, meaning some packets in between are missing.
                        sendImmediateAck = ShouldSendImmediateReorderedAckUnsafe(NowMicros());
                        uint current = _nextExpectedSequence;
                        int remainingNakSlots = UcpConstants.MAX_NAK_MISSING_SCAN;
                        // Scan from expected sequence up to (but not including) the received
                        // packet, collecting NAK-eligible sequences.
                        while (current != dataPacket.SequenceNumber && remainingNakSlots > 0)
                        {
                            if (!_recvBuffer.ContainsKey(current))
                            {
                                int missingCount;
                                _missingSequenceCounts.TryGetValue(current, out missingCount);
                                missingCount++;
                                _missingSequenceCounts[current] = missingCount;
                                long firstSeenMicros = GetMissingFirstSeenMicrosUnsafe(current);
                                bool missingAgeExpired = HasNakReorderGraceExpiredUnsafe(missingCount, firstSeenMicros, NowMicros());
                                bool missingRepeatedEnough = missingCount >= UcpConstants.NAK_MISSING_THRESHOLD;
                                // Emit NAK only when: enough observations, reorder grace expired,
                                // NAK not already issued, and we have room in the NAK list.
                                if (missing.Count < UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET && missingRepeatedEnough && missingAgeExpired && ShouldIssueNakUnsafe(current))
                                {
                                    MarkNakIssuedUnsafe(current);
                                    missing.Add(current);
                                }
                            }

                            current = UcpSequenceComparer.Increment(current);
                            remainingNakSlots--;
                        }
                    }

                    // Stage F: Drain contiguous in-order segments for delivery.
                    while (_recvBuffer.Count > 0)
                    {
                        InboundSegment next;
                        if (!_recvBuffer.TryGetValue(_nextExpectedSequence, out next))
                        {
                            break;
                        }

                        _recvBuffer.Remove(_nextExpectedSequence);
                        _nakIssued.Remove(_nextExpectedSequence);
                        _missingSequenceCounts.Remove(_nextExpectedSequence);
                        _missingFirstSeenMicros.Remove(_nextExpectedSequence);
                        _lastNakIssuedMicros.Remove(_nextExpectedSequence);
                        _fecFragmentMetadata.Remove(_nextExpectedSequence);
                        _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence);
                        readyPayloads.Add(next.Payload);
                    }

                    // Check if the first gap (immediately after draining) should trigger a NAK.
                    if (_recvBuffer.Count > 0 && !_recvBuffer.ContainsKey(_nextExpectedSequence))
                    {
                        if (_recvBuffer.Count >= UcpConstants.IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD && ShouldSendImmediateReorderedAckUnsafe(NowMicros()))
                        {
                            sendImmediateAck = true; // Multiple reordered packets — send ACK now.
                        }

                        int missingCount;
                        _missingSequenceCounts.TryGetValue(_nextExpectedSequence, out missingCount);
                        long firstSeenMicros = GetMissingFirstSeenMicrosUnsafe(_nextExpectedSequence);
                        if (missing.Count < UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET && missingCount >= UcpConstants.NAK_MISSING_THRESHOLD && HasNakReorderGraceExpiredUnsafe(missingCount, firstSeenMicros, NowMicros()) && ShouldIssueNakUnsafe(_nextExpectedSequence))
                        {
                            MarkNakIssuedUnsafe(_nextExpectedSequence);
                            missing.Add(_nextExpectedSequence);
                        }
                    }
                }
            }

            // Deliver ready payloads to the application outside the lock to
            // avoid holding _sync during event handler invocations.
            for (int i = 0; i < readyPayloads.Count; i++)
            {
                EnqueuePayload(readyPayloads[i]);
            }

            if (shouldEstablish)
            {
                TransitionToEstablished();
            }

            // Stage H: Emit NAK for collected gaps.
            if (missing.Count > 0)
            {
                SendNak(missing);
            }

            // Stage G: Schedule or send immediate ACK.
            // Piggybacked ACKs on outbound data packets cancel the delayed ACK timer,
            // so standalone ACKs only fire when no data is flowing.
            if (sendImmediateAck)
            {
                SendAckPacket(UcpPacketFlags.None, 0);
            }
            else
            {
                ScheduleAck();
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
            if (_fecCodec == null || readyPayloads == null)
            {
                return;
            }

            uint groupBase = _fecCodec.GetGroupBase(receivedSequenceNumber);
            int groupSize = Math.Max(2, _config.FecGroupSize);
            for (int i = 0; i < groupSize; i++)
            {
                uint candidateSeq = groupBase + (uint)i;
                // Skip sequences that are already received, already delivered, or
                // the one that just arrived (handled by caller).
                if (candidateSeq == receivedSequenceNumber || UcpSequenceComparer.IsBefore(candidateSeq, _nextExpectedSequence) || _recvBuffer.ContainsKey(candidateSeq))
                {
                    continue;
                }

                // Try to reconstruct the candidate from stored repair + data packets.
                if (StoreRecoveredFecPacketsUnsafe(_fecCodec.TryRecoverPacketsFromStoredRepair(candidateSeq), readyPayloads) > 0)
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
            if (recoveredPackets == null || recoveredPackets.Count == 0)
            {
                return 0;
            }

            int stored = 0;
            for (int i = 0; i < recoveredPackets.Count; i++)
            {
                UcpFecCodec.RecoveredPacket recoveredPacket = recoveredPackets[i];
                if (recoveredPacket == null)
                {
                    continue;
                }

                if (StoreRecoveredFecSegmentUnsafe(recoveredPacket.SequenceNumber, recoveredPacket.Payload))
                {
                    stored++;
                }
            }

            if (stored > 0)
            {
                // Drain newly contiguous data resulting from the recovery.
                DrainReadyPayloadsUnsafe(readyPayloads);
            }

            return stored;
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
            if (recovered == null || UcpSequenceComparer.IsBefore(recoveredSeq, _nextExpectedSequence) || _recvBuffer.ContainsKey(recoveredSeq))
            {
                return false;
            }

            FecFragmentMetadata metadata;
            if (!_fecFragmentMetadata.TryGetValue(recoveredSeq, out metadata))
            {
                // Fallback: assume single-fragment message.
                metadata = new FecFragmentMetadata { FragmentTotal = 1, FragmentIndex = 0 };
            }

            InboundSegment inbound = new InboundSegment();
            inbound.SequenceNumber = recoveredSeq;
            inbound.FragmentTotal = metadata.FragmentTotal;
            inbound.FragmentIndex = metadata.FragmentIndex;
            inbound.Payload = recovered;

            _recvBuffer[recoveredSeq] = inbound;
            ClearMissingReceiveStateUnsafe(recoveredSeq);
            return true;
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
            while (_recvBuffer.Count > 0)
            {
                InboundSegment next;
                if (!_recvBuffer.TryGetValue(_nextExpectedSequence, out next))
                {
                    break;
                }

                _recvBuffer.Remove(_nextExpectedSequence);
                ClearMissingReceiveStateUnsafe(_nextExpectedSequence);
                _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence);
                readyPayloads.Add(next.Payload);
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
            if (_fecCodec == null || packet.Payload == null)
            {
                return;
            }

            uint groupBase = packet.GroupId;
            List<UcpFecCodec.RecoveredPacket> recoveredPackets = _fecCodec.TryRecoverPacketsFromRepair(packet.Payload, groupBase, packet.GroupIndex);
            List<byte[]> fecReadyPayloads = new List<byte[]>();
            int recoveredCount;

            lock (_sync)
            {
                recoveredCount = StoreRecoveredFecPacketsUnsafe(recoveredPackets, fecReadyPayloads);
            }

            if (recoveredCount == 0)
            {
                return;
            }

            // Deliver recovered data to the application.
            for (int i = 0; i < fecReadyPayloads.Count; i++)
            {
                EnqueuePayload(fecReadyPayloads[i]);
            }

            // Immediate ACK: FEC recovery advances the cumulative ACK, so the
            // sender must know promptly.  Delaying would cause timeout storms.
            SendAckPacket(UcpPacketFlags.None, 0);
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
            bool needSendOwnFin = false;
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            lock (_sync)
            {
                _peerFinReceived = true;
                _state = UcpConnectionState.ClosingFinReceived;
                if (!_finSent)
                {
                    _finSent = true;
                    needSendOwnFin = true;
                }
            }

            if (hasAck && packet.AckNumber > 0)
            {
                ProcessPiggybackedAck(packet.AckNumber, packet.Header.Timestamp, NowMicros());
            }

            // Acknowledge the peer's FIN with the FinAck flag.
            SendAckPacket(UcpPacketFlags.FinAck, 0);
            if (needSendOwnFin)
            {
                SendControl(UcpPacketType.Fin, UcpPacketFlags.None);
            }

            if (_finAcked)
            {
                // Both FINs acknowledged — clean close complete.
                TransitionToClosed();
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
            if (missing == null || missing.Count == 0)
            {
                return;
            }

            uint cumAck;
            lock (_sync)
            {
                long nowMicros = NowMicros();
                long rttWindowMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.DelayedAckTimeoutMicros;
                if (rttWindowMicros <= 0)
                {
                    rttWindowMicros = UcpConstants.BBR_MIN_ROUND_DURATION_MICROS;
                }

                // Reset NAK window if SRTT has elapsed.
                if (_lastNakWindowMicros == 0 || nowMicros - _lastNakWindowMicros >= rttWindowMicros)
                {
                    _lastNakWindowMicros = nowMicros;
                    _naksSentThisRttWindow = 0;
                }

                // Rate limit: at most MAX_NAKS_PER_RTT NAK packets per window.
                if (_naksSentThisRttWindow >= UcpConstants.MAX_NAKS_PER_RTT)
                {
                    return;
                }

                _naksSentThisRttWindow++;
                // Cumulative ACK is _nextExpectedSequence - 1 (everything before is received).
                cumAck = _nextExpectedSequence > 0 ? unchecked(_nextExpectedSequence - 1U) : 0;
                _lastAckSentMicros = nowMicros; // NAK carries ACK, counts as ACK send.
            }

            UcpNakPacket packet = new UcpNakPacket();
            packet.Header = CreateHeader(UcpPacketType.Nak, UcpPacketFlags.None, NowMicros());
            packet.AckNumber = cumAck;
            packet.MissingSequences.AddRange(missing);
            
            byte[] encoded = UcpPacketCodec.Encode(packet);
            _sentNakPackets++;
            _transport.Send(encoded, _remoteEndPoint);
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
            UcpControlPacket packet = new UcpControlPacket();
            uint cumAck = 0;
            bool hasAck = false;
            lock (_sync)
            {
                if (type == UcpPacketType.Syn || type == UcpPacketType.SynAck)
                {
                    packet.HasSequenceNumber = true;
                    packet.SequenceNumber = _nextSendSequence; // Our ISN.
                }
                
                // All control packets except the initial outgoing SYN carry cumulative ACK.
                if (type != UcpPacketType.Syn && _nextExpectedSequence > 0)
                {
                    hasAck = true;
                    cumAck = unchecked(_nextExpectedSequence - 1U);
                }
            }

            UcpPacketFlags packetFlags = flags;
            if (hasAck)
            {
                packetFlags |= UcpPacketFlags.HasAckNumber;
                packet.AckNumber = cumAck;
            }

            packet.Header = CreateHeader(type, packetFlags, NowMicros());
            byte[] encoded = UcpPacketCodec.Encode(packet);
            if (type == UcpPacketType.Rst)
            {
                _sentRstPackets++;
            }

            _transport.Send(encoded, _remoteEndPoint);
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
            UcpAckPacket packet;
            lock (_sync)
            {
                packet = new UcpAckPacket();
                packet.Header = CreateHeader(UcpPacketType.Ack, flags, NowMicros());
                // Cumulative ACK = next expected - 1 (everything before is ACKed).
                packet.AckNumber = unchecked(_nextExpectedSequence - 1U);

                // Generate raw SACK blocks, then apply QUIC-style send-count filter.
                List<SackBlock> rawBlocks = _sackGenerator.Generate(_nextExpectedSequence, _recvBuffer.Keys, _config.MaxAckSackBlocks);
                List<SackBlock> filteredBlocks = new List<SackBlock>(rawBlocks.Count);
                for (int i = 0; i < rawBlocks.Count; i++)
                {
                    // Pack start/end into 64-bit key for dictionary lookup.
                    ulong key = PackSackBlockKey(rawBlocks[i].Start, rawBlocks[i].End);
                    int sendCount;
                    _sackBlockSendCounts.TryGetValue(key, out sendCount);
                    if (sendCount < MAX_SACK_SEND_COUNT)
                    {
                        filteredBlocks.Add(rawBlocks[i]);
                        _sackBlockSendCounts[key] = sendCount + 1;
                    }
                }

                packet.SackBlocks = filteredBlocks;

                // Advertise available receive window to the sender.
                uint usedBytes = GetReceiveWindowUsedBytesUnsafe();
                packet.WindowSize = usedBytes >= _localReceiveWindowBytes ? 0U : _localReceiveWindowBytes - usedBytes;
                packet.EchoTimestamp = overrideEchoTimestamp < 0 ? 0 : (overrideEchoTimestamp > 0 ? overrideEchoTimestamp : _lastEchoTimestamp);
                _lastAckSentMicros = packet.Header.Timestamp;
            }

            byte[] encoded = UcpPacketCodec.Encode(packet);
            _sentAckPackets++;
            _transport.Send(encoded, _remoteEndPoint);
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
            if (_config.DelayedAckTimeoutMicros <= 0)
            {
                SendAckPacket(UcpPacketFlags.None, 0);
                return;
            }

            long ackDelayMicros = _config.DelayedAckTimeoutMicros;
            // On high-latency paths, use shorter delay to avoid RTT inflation.
            if (_lastRttMicros > 30L * UcpConstants.MICROS_PER_MILLI)
            {
                ackDelayMicros = Math.Min(ackDelayMicros, UcpConstants.MICROS_PER_MILLI);
            }

            lock (_sync)
            {
                if (_ackDelayed)
                {
                    return; // Already scheduled — piggyback will happen.
                }

                _ackDelayed = true;
            }

            if (_network == null)
            {
                // Standalone: use Task.Delay with cancellation support.
                Task.Run(async delegate
                {
                    try
                    {
                        await Task.Delay((int)Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, ackDelayMicros / UcpConstants.MICROS_PER_MILLI), _cts.Token).ConfigureAwait(false);
                        lock (_sync)
                        {
                            _ackDelayed = false;
                        }

                        SendAckPacket(UcpPacketFlags.None, 0);
                    }
                    catch (OperationCanceledException)
                    {
                        // PCB disposed — ignore.
                    }
                });
                return;
            }

            // Network-managed: schedule via network timer for precise timing.
            _network.AddTimer(_network.CurrentTimeUs + ackDelayMicros, delegate
            {
                lock (_sync)
                {
                    _ackDelayed = false;
                }

                SendAckPacket(UcpPacketFlags.None, 0);
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
        ///       d. Segment is marked InFlight, NeedsRetransmit/UrgentRetransmit cleared
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
            await _flushLock.WaitAsync().ConfigureAwait(false);
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    List<OutboundSegment> segmentsToSend = new List<OutboundSegment>();
                    long nowMicros = NowMicros();
                    long waitMicros = 0;
                    uint piggyCumAck = 0;
                    List<SackBlock> piggySackBlocks = null;
                    uint piggyWindow = 0;
                    long piggyEcho = 0;

                    lock (_sync)
                    {
                        // Stage A.1: Compute effective send window.
                        int windowBytes = GetSendWindowBytesUnsafe();
                        int piggybackedAckOverhead = UcpConstants.DATA_HEADER_SIZE_WITH_ACK - UcpConstants.DataHeaderSize;
                        foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                        {
                            OutboundSegment segment = pair.Value;
                            if (segment.Acked)
                            {
                                continue; // Already acknowledged — will be removed soon.
                            }

                            if (segment.InFlight && !segment.NeedsRetransmit)
                            {
                                continue; // Already sent and not marked for retransmit.
                            }

                            // Window check (only for new sends, not retransmits).
                            if (!segment.NeedsRetransmit && !segment.InFlight && _flightBytes + segment.Payload.Length > windowBytes)
                            {
                                break; // Window full — stop collecting.
                            }

                            int packetSize = UcpConstants.DataHeaderSize + piggybackedAckOverhead + segment.Payload.Length;
                            bool urgentRecovery = segment.NeedsRetransmit && segment.SendCount > 0 && segment.UrgentRetransmit && CanUseUrgentRecoveryUnsafe(nowMicros);

                            // Fair-queue credit check: skip if credit insufficient (unless urgent).
                            if (_useFairQueue && _fairQueueCreditBytes < packetSize && !urgentRecovery)
                            {
                                break;
                            }

            // Stage A.3a: Urgent recovery bypasses pacing (ForceConsume).
            if (urgentRecovery)
            {
                _pacing.ForceConsume(packetSize, nowMicros);
                _urgentRecoveryPacketsInWindow++;
            }
                            // Stage A.3b: Normal sends check pacing token bucket.
                            else if (!_pacing.TryConsume(packetSize, nowMicros))
                            {
                                // Not enough tokens — record wait time and stop collecting.
                                waitMicros = _pacing.GetWaitTimeMicros(packetSize, nowMicros);
                                break;
                            }

                            // Stage A.3c: Deduct fair-queue credit.
                            if (_useFairQueue)
                            {
                                _fairQueueCreditBytes -= packetSize;
                                if (_fairQueueCreditBytes < 0)
                                {
                                    _fairQueueCreditBytes = 0;
                                }
                            }

                            // Stage A.3d: Mark segment state.
                            segment.InFlight = true;
                            segment.NeedsRetransmit = false;
                            segment.UrgentRetransmit = false;
                            if (segment.SendCount == 0)
                            {
                                _flightBytes += segment.Payload.Length;
                            }

                            // Stage A.3e: Update send count and notify BBR.
                            segment.SendCount++;
                            _bbr.OnPacketSent(nowMicros, segment.SendCount > 1);
                            segment.LastSendMicros = nowMicros;
                            _lastActivityMicros = nowMicros;
                            segmentsToSend.Add(segment);
                        }

                        // Stage A.4: Snapshot piggybacked ACK info inside the lock.
                        piggyCumAck = _nextExpectedSequence > 0 ? unchecked(_nextExpectedSequence - 1U) : 0;
                        piggySackBlocks = piggyCumAck > 0 ? _sackGenerator.Generate(_nextExpectedSequence, _recvBuffer.Keys, _config.MaxAckSackBlocks) : null;
                        piggyWindow = piggyCumAck > 0
                            ? (_localReceiveWindowBytes > GetReceiveWindowUsedBytesUnsafe()
                                ? _localReceiveWindowBytes - GetReceiveWindowUsedBytesUnsafe()
                                : 0U)
                            : _localReceiveWindowBytes;
                        piggyEcho = _lastEchoTimestamp;
                        _lastAckSentMicros = nowMicros; // Piggyback counts as an ACK send.
                    }

                    if (segmentsToSend.Count == 0)
                    {
                        // Stage D: No segments collected — schedule delayed flush if pacing limited.
                        if (waitMicros > 0)
                        {
                            ScheduleDelayedFlush(waitMicros);
                        }

                        break;
                    }

                    // Stage B: Encode and send all collected segments with piggybacked ACK.
                    for (int i = 0; i < segmentsToSend.Count; i++)
                    {
                        OutboundSegment segment = segmentsToSend[i];
                        UcpDataPacket packet = new UcpDataPacket();

                        // Retransmit packets carry the Retransmit flag so the receiver
                        // can distinguish original from retransmitted data.
                        UcpPacketFlags pktFlags = segment.SendCount > 1
                            ? UcpPacketFlags.NeedAck | UcpPacketFlags.Retransmit | UcpPacketFlags.HasAckNumber
                            : UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber;

                        packet.Header = CreateHeader(UcpPacketType.Data, pktFlags, nowMicros);
                        packet.SequenceNumber = segment.SequenceNumber;
                        packet.FragmentTotal = segment.FragmentTotal;
                        packet.FragmentIndex = segment.FragmentIndex;
                        packet.Payload = segment.Payload;

                        // Piggyback ACK state on every data packet.
                        packet.AckNumber = piggyCumAck;
                        if (piggySackBlocks != null && piggySackBlocks.Count > 0)
                        {
                            packet.SackBlocks = piggySackBlocks;
                        }

                        packet.WindowSize = piggyWindow;
                        packet.EchoTimestamp = piggyEcho;

                        byte[] encoded = UcpPacketCodec.Encode(packet);
                        if (segment.SendCount > 1)
                        {
                            _retransmittedPackets++;
                        }
                        else
                        {
                            _sentDataPackets++;
                        }

                        _bytesSent += segment.Payload.Length;
                        _transport.Send(encoded, _remoteEndPoint);

                        // Stage C: FEC encoding.
                        if (_fecCodec != null && segment.SendCount <= 1)
                        {
                            lock (_sync)
                            {
                                _fecFragmentMetadata[segment.SequenceNumber] = new FecFragmentMetadata { FragmentTotal = segment.FragmentTotal, FragmentIndex = segment.FragmentIndex };
                            }

                            if (_fecGroupSendCount == 0)
                            {
                                _fecGroupBaseSeq = _fecCodec.GetGroupBase(segment.SequenceNumber);
                            }

                            List<byte[]> repairs = _fecCodec.TryEncodeRepairs(segment.Payload);
                            _fecGroupSendCount++;
                            if (repairs != null && repairs.Count > 0)
                            {
                                // Adaptive FEC: only transmit repair packets when estimated
                                // loss exceeds the adaptive threshold.  The encoder always
                                // runs — we just skip sending repairs on low-loss paths
                                // where SACK is more efficient and repair bandwidth is wasted.
                                if (_bbr.EstimatedLossPercent >= UcpConstants.ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT)
                                {
                                    for (int repairIndex = 0; repairIndex < repairs.Count; repairIndex++)
                                    {
                                        UcpFecRepairPacket repairPacket = new UcpFecRepairPacket();
                                        repairPacket.Header = CreateHeader(UcpPacketType.FecRepair, UcpPacketFlags.None, nowMicros);
                                        repairPacket.GroupId = _fecGroupBaseSeq;
                                        repairPacket.GroupIndex = (byte)repairIndex;
                                        repairPacket.Payload = repairs[repairIndex];
                                        byte[] encodedRepair = UcpPacketCodec.Encode(repairPacket);
                                        _transport.Send(encodedRepair, _remoteEndPoint);
                                    }

                                    _fecRepairSentGroups.Add(_fecGroupBaseSeq);
                                }

                                _fecGroupSendCount = 0; // Group complete — reset for next group.
                            }
                        }
                    }
                }
            }
            finally
            {
                _flushLock.Release();
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
            if (_flushDelayed)
            {
                return; // Already scheduled — avoid duplicate timers.
            }

            _flushDelayed = true;
            int delayMs = (int)Math.Ceiling(waitMicros / (double)UcpConstants.MICROS_PER_MILLI);
            if (delayMs < UcpConstants.MIN_TIMER_WAIT_MILLISECONDS)
            {
                delayMs = UcpConstants.MIN_TIMER_WAIT_MILLISECONDS;
            }

            if (_network == null)
            {
                // Standalone: use Task.Delay.
                Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(delayMs, _cts.Token).ConfigureAwait(false);
                        _flushDelayed = false;
                        await FlushSendQueueAsync().ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        _flushDelayed = false;
                    }
                });
                return;
            }

            // Network-managed: use network timer.
            _flushTimerId = _network.AddTimer(_network.NowMicroseconds + (delayMs * UcpConstants.MICROS_PER_MILLI), delegate
            {
                _flushDelayed = false;
                _flushTimerId = 0;
                _ = FlushSendQueueAsync();
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
            if (payload == null || payload.Length == 0)
            {
                return;
            }

            lock (_sync)
            {
                ReceiveChunk chunk = new ReceiveChunk();
                chunk.Buffer = payload;
                chunk.Count = payload.Length;
                _receiveQueue.Enqueue(chunk);
                _queuedReceiveBytes += payload.Length;
                _bytesReceived += payload.Length;
            }

            // Fire event outside lock to avoid re-entrancy issues.
            Action<byte[], int, int> dataReceived = DataReceived;
            if (dataReceived != null)
            {
                dataReceived(payload, 0, payload.Length);
            }

            _receiveSignal.Release();
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
            int receiveWindowBytes = (int)_remoteWindowBytes;
            int congestionWindowBytes = _bbr.CongestionWindowBytes;
            int windowBytes = congestionWindowBytes < receiveWindowBytes ? congestionWindowBytes : receiveWindowBytes;
            if (windowBytes < 0)
            {
                windowBytes = 0;
            }

            return windowBytes;
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
            long windowMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros;
            if (windowMicros <= 0)
            {
                windowMicros = UcpConstants.DEFAULT_RTO_MICROS;
            }

            // Reset window budget if SRTT has elapsed.
            if (_urgentRecoveryWindowMicros == 0 || nowMicros - _urgentRecoveryWindowMicros >= windowMicros)
            {
                _urgentRecoveryWindowMicros = nowMicros;
                _urgentRecoveryPacketsInWindow = 0;
            }

            return _urgentRecoveryPacketsInWindow < UcpConstants.URGENT_RETRANSMIT_BUDGET_PER_RTT;
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
            if (_config.DisconnectTimeoutMicros <= 0)
            {
                return false;
            }

            long idleMicros = nowMicros - _lastActivityMicros;
            return idleMicros >= _config.DisconnectTimeoutMicros * UcpConstants.URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT / 100L;
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
            long usedBytes = _queuedReceiveBytes;
            foreach (KeyValuePair<uint, InboundSegment> pair in _recvBuffer)
            {
                usedBytes += pair.Value.Payload == null ? 0 : pair.Value.Payload.Length;
            }

            if (usedBytes <= 0)
            {
                return 0;
            }

            if (usedBytes >= uint.MaxValue)
            {
                return uint.MaxValue;
            }

            return (uint)usedBytes;
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
            UcpCommonHeader header = new UcpCommonHeader();
            header.Type = type;
            header.Flags = flags;
            header.ConnectionId = _connectionId;
            header.Timestamp = timestampMicros;
            return header;
        }

        // ---- Timer management ----

        /// <summary>
        /// Timer callback invoked when using a .NET Timer (standalone mode).
        /// Delegates to the async timer handler and reschedules for the next tick.
        /// </summary>
        private void OnTimer(object state)
        {
            if (_disposed)
            {
                return;
            }

            _ = OnTimerAsync();
            if (_network != null)
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
            if (_network == null || _disposed)
            {
                return;
            }

            long intervalMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.TimerIntervalMilliseconds) * UcpConstants.MICROS_PER_MILLI;
            _timerId = _network.AddTimer(_network.NowMicroseconds + intervalMicros, delegate { OnTimer(null); });
        }

        /// <summary>Delegates to the microsecond-aware timer handler at current time.</summary>
        private async Task OnTimerAsync()
        {
            await OnTimerAsync(NowMicros()).ConfigureAwait(false);
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
            bool timedOut = false;
            bool sendKeepAlive = false;
            bool retransmitSynAck = false;
            bool maxRetransmissionsExceeded = false;
            bool timedOutForCongestion = false;
            bool tailLossProbe = false;
            List<uint> missingForNak = new List<uint>();

            lock (_sync)
            {
                // ---- Stage A: RTO scan ----
                int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize));
                int rtoRetransmitBudget = UcpConstants.RTO_RETRANSMIT_BUDGET_PER_TICK;
                // Suppress bulk RTO when ACK flow is still active.
                bool ackProgressRecent = _lastAckReceivedMicros > 0 && nowMicros - _lastAckReceivedMicros <= GetRtoAckProgressSuppressionMicrosUnsafe();
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (!segment.InFlight || segment.Acked || segment.NeedsRetransmit)
                    {
                        continue;
                    }

                    // Segment has been in flight longer than the current RTO → timeout.
                    if (nowMicros - segment.LastSendMicros >= _rtoEstimator.CurrentRtoMicros)
                    {
                        // If ACKs are still arriving and inflight is large, skip —
                        // SACK/NAK should recover individual losses without RTO.
                        if (ackProgressRecent && _sendBuffer.Count > UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS)
                        {
                            continue; // ACK flow is alive — avoid bulk RTO amplification.
                        }

                        // Budget exhausted for this tick.
                        if (rtoRetransmitBudget <= 0)
                        {
                            break;
                        }

                        bool segmentTimedOutForCongestion = IsCongestionLossUnsafe(segment.SequenceNumber, 0, nowMicros, 1);
                        // Max retransmissions check: if exceeded AND it's congestion loss,
                        // abort the connection (the path is too congested for recovery).
                        if (segment.SendCount >= _config.MaxRetransmissions && segmentTimedOutForCongestion)
                        {
                            _timeoutRetransmissions++;
                            maxRetransmissionsExceeded = true;
                            break; // Max retransmissions exceeded — abort connection.
                        }

                            segment.NeedsRetransmit = true;
                            segment.UrgentRetransmit = true; // Bypass pacing for RTO recovery.
                            timedOut = true;
                        rtoRetransmitBudget--;
                        timedOutForCongestion = timedOutForCongestion || segmentTimedOutForCongestion;
                        _timeoutRetransmissions++;
                    }
                }

                // ---- Stage B: Tail-Loss Probe (TLP) ----
                if (!timedOut && !_tailLossProbePending && inflightSegments > 0 && inflightSegments <= UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS)
                {
                    long tlpTimeoutMicros = _rtoEstimator.SmoothedRttMicros > 0
                        ? (long)Math.Ceiling(_rtoEstimator.SmoothedRttMicros * UcpConstants.TLP_TIMEOUT_RTT_RATIO)
                        : _rtoEstimator.CurrentRtoMicros;
                    if (_lastAckReceivedMicros > 0 && nowMicros - _lastAckReceivedMicros >= tlpTimeoutMicros)
                    {
                        // TLP: retransmit the most-recently-sent un-ACKed segment.
                        foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                        {
                            OutboundSegment segment = pair.Value;
                            if (segment.Acked || !segment.InFlight || segment.NeedsRetransmit)
                            {
                                continue;
                            }

                            if (nowMicros - segment.LastSendMicros < tlpTimeoutMicros)
                            {
                                continue;
                            }

                            segment.NeedsRetransmit = true;
                            segment.UrgentRetransmit = IsNearDisconnectTimeoutUnsafe(nowMicros);
                            _tailLossProbePending = true;
                            tailLossProbe = true;
                            break; // Only one segment per TLP event.
                        }
                    }
                }

                // ---- Stage C: Silence Probe ----
                if (!timedOut && !_tailLossProbePending && inflightSegments > UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS
                    && _lastAckReceivedMicros > 0 && _rtoEstimator.SmoothedRttMicros > 0
                    && nowMicros - _lastAckReceivedMicros >= _rtoEstimator.SmoothedRttMicros * 3)
                {
                    // Find the highest-sequence in-flight segment (most recently sent).
                    uint highestSeq = 0;
                    OutboundSegment newest = null;
                    foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                    {
                        if (pair.Value.Acked || !pair.Value.InFlight || pair.Value.NeedsRetransmit) continue;
                        if (newest == null || UcpSequenceComparer.IsAfter(pair.Key, highestSeq))
                        {
                            highestSeq = pair.Key;
                            newest = pair.Value;
                        }
                    }
                    if (newest != null)
                    {
                        newest.NeedsRetransmit = true;
                        newest.UrgentRetransmit = true;
                        _tailLossProbePending = true;
                        tailLossProbe = true;
                    }
                }

                // RTO recovery: notify BBR and apply exponential backoff.
                if (timedOut)
                {
                    _bbr.OnPacketLoss(nowMicros, GetRetransmissionRatioUnsafe(), timedOutForCongestion);
                    TraceLogUnsafe("RTO loss congestion=" + timedOutForCongestion + " rto=" + _rtoEstimator.CurrentRtoMicros);
                    if (timedOutForCongestion)
                    {
                        _rtoEstimator.Backoff(); // Exponential backoff for congestion timeouts.
                    }
                }

                // ---- Stage D: NAK collection ----
                CollectMissingForNakUnsafe(missingForNak, nowMicros);

                // ---- Stage E: Keep-alive ----
                if (_state == UcpConnectionState.Established && nowMicros - _lastAckSentMicros >= _config.KeepAliveIntervalMicros && nowMicros - _lastActivityMicros >= _config.KeepAliveIntervalMicros)
                {
                    sendKeepAlive = true;
                }

                // ---- Stage F: SYN-ACK retransmission ----
                if (_isServerSide && _state == UcpConnectionState.HandshakeSynReceived && _synAckSent && nowMicros - _synAckSentMicros >= _rtoEstimator.CurrentRtoMicros)
                {
                    _synAckSentMicros = nowMicros;
                    retransmitSynAck = true;
                }
            }

            if (maxRetransmissionsExceeded)
            {
                TransitionToClosed();
                return;
            }

            if (timedOut || tailLossProbe)
            {
                await FlushSendQueueAsync().ConfigureAwait(false);
            }

            if (retransmitSynAck)
            {
                SendControl(UcpPacketType.SynAck, UcpPacketFlags.None);
            }

            if (missingForNak.Count > 0)
            {
                SendNak(missingForNak);
            }

            if (sendKeepAlive)
            {
                // -1 echo = keepalive (no echo timestamp, pure liveness check).
                SendAckPacket(UcpPacketFlags.None, -1);
            }

            // ---- Stage G: Disconnect timeout ----
            if ((_state == UcpConnectionState.HandshakeSynSent || _state == UcpConnectionState.HandshakeSynReceived || _state == UcpConnectionState.Established || _state == UcpConnectionState.ClosingFinSent || _state == UcpConnectionState.ClosingFinReceived)
                && nowMicros - _lastActivityMicros >= _config.DisconnectTimeoutMicros)
            {
                TransitionToClosed();
                return;
            }

            if (_state == UcpConnectionState.Closed)
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
            if (missing == null || _recvBuffer.Count == 0 || _recvBuffer.ContainsKey(_nextExpectedSequence))
            {
                return; // No gap at the expected sequence — nothing to NAK.
            }

            // Find the highest received sequence to bound the scan range.
            uint highestReceived = _nextExpectedSequence;
            bool hasHighest = false;
            foreach (KeyValuePair<uint, InboundSegment> pair in _recvBuffer)
            {
                if (!hasHighest || UcpSequenceComparer.IsAfter(pair.Key, highestReceived))
                {
                    highestReceived = pair.Key;
                    hasHighest = true;
                }
            }

            if (!hasHighest)
            {
                return;
            }

            // Scan from expected to highest received, collecting NAK-eligible gaps.
            uint current = _nextExpectedSequence;
            int remainingScan = UcpConstants.MAX_NAK_MISSING_SCAN;
            while (missing.Count < UcpConstants.MAX_NAK_SEQUENCES_PER_PACKET && current != highestReceived && remainingScan > 0)
            {
                if (!_recvBuffer.ContainsKey(current))
                {
                    long firstSeenMicros = GetMissingFirstSeenMicrosUnsafe(current);
                    int missingCount;
                    _missingSequenceCounts.TryGetValue(current, out missingCount);
                    missingCount++;
                    _missingSequenceCounts[current] = missingCount;
                    if (missingCount >= UcpConstants.NAK_MISSING_THRESHOLD && HasNakReorderGraceExpiredUnsafe(missingCount, firstSeenMicros, nowMicros) && ShouldIssueNakUnsafe(current))
                    {
                        MarkNakIssuedUnsafe(current);
                        missing.Add(current);
                    }
                }

                current = UcpSequenceComparer.Increment(current);
                remainingScan--;
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
            Action connected = null;
            lock (_sync)
            {
                if (_state == UcpConnectionState.Established || _state == UcpConnectionState.Closed)
                {
                    return;
                }

                _state = UcpConnectionState.Established;
                if (!_connectedRaised)
                {
                    _connectedRaised = true;
                    connected = Connected; // Snapshot for raise outside lock.
                }
            }

            _connectedTcs.TrySetResult(true);
            if (connected != null)
            {
                connected();
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
            Action disconnected = null;
            bool shouldCallback = false;
            bool releaseResources = false;
            lock (_sync)
            {
                if (_state == UcpConnectionState.Closed)
                {
                    if (_closedResourcesReleased)
                    {
                        return; // Already fully cleaned up.
                    }
                }

                _state = UcpConnectionState.Closed;
                if (!_closedResourcesReleased)
                {
                    _closedResourcesReleased = true;
                    releaseResources = true;
                }

                if (!_disconnectedRaised)
                {
                    _disconnectedRaised = true;
                    disconnected = Disconnected; // Snapshot for raise outside lock.
                }

                shouldCallback = true;
            }

            _connectedTcs.TrySetResult(false); // Connection failed.
            _closedTcs.TrySetResult(true); // Close complete.
            _receiveSignal.Release(); // Unblocks any waiting ReceiveAsync callers.
            if (releaseResources)
            {
                ReleaseNetworkRegistrations();
            }

            if (disconnected != null)
            {
                disconnected();
            }

            if (shouldCallback && _closedCallback != null)
            {
                _closedCallback(this);
            }
        }

        /// <summary>
        /// Unregisters this PCB from the network engine and cancels all
        /// registered timers.  Called during close/dispose to release
        /// network resources.
        /// </summary>
        private void ReleaseNetworkRegistrations()
        {
            if (_network == null)
            {
                return;
            }

            _network.UnregisterPcb(this);
            if (_timerId != 0)
            {
                _network.CancelTimer(_timerId);
                _timerId = 0;
            }

            if (_flushTimerId != 0)
            {
                _network.CancelTimer(_flushTimerId);
                _flushTimerId = 0;
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
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMilliseconds)).ConfigureAwait(false);
            if (completed != task)
            {
                return false;
            }

            await task.ConfigureAwait(false);
            return true;
        }

        /// <summary>
        /// Generates a non-zero cryptographically random connection ID.
        /// Zero is reserved (never assigned).  Uses do-while loop to ensure
        /// the generated ID is non-zero.  ConnectionIdGenerator is a
        /// static RandomNumberGenerator for entropy.
        /// </summary>
        private static uint NextConnectionId()
        {
            byte[] bytes = new byte[UcpConstants.CONNECTION_ID_SIZE];
            uint connectionId;
            do
            {
                ConnectionIdGenerator.GetBytes(bytes);
                connectionId = BitConverter.ToUInt32(bytes, 0);
            }
            while (connectionId == 0); // Zero is reserved — retry until non-zero.

            return connectionId;
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
            byte[] bytes = new byte[UcpConstants.SEQUENCE_NUMBER_SIZE];
            SequenceRng.GetBytes(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

        /// <summary>
        /// Returns the current protocol time in microseconds, preferring the
        /// network's shared clock (consistent across all PCBs) when available.
        /// In standalone mode, falls back to the system high-resolution timer.
        /// </summary>
        private long NowMicros()
        {
            return _network == null ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs;
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
            if (sampleRttMicros <= 0)
            {
                return;
            }

            _rttSamplesMicros.Add(sampleRttMicros);
            if (_rttSamplesMicros.Count > UcpConstants.MaxRttSamples)
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
            return ((ulong)start << 32) | end;
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
            if (_sackBlockSendCounts.Count > 1024)
            {
                _sackBlockSendCounts.Clear();
            }
        }

        /// <summary>
        /// Validates send/receive buffer arguments.  Throws on null buffer,
        /// negative offset/count, or range exceeding buffer length.
        /// </summary>
        private static void ValidateBuffer(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            if (offset < 0 || count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("buffer", "Buffer range is invalid.");
            }
        }
    }
}
