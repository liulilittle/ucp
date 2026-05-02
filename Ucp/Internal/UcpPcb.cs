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
        /// <summary>Tracks a single outbound data segment in the send buffer.</summary>
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

        /// <summary>Original fragment metadata retained with each FEC-encoded payload.</summary>
        private sealed class FecFragmentMetadata
        {
            /// <summary>Total fragments in the original application message.</summary>
            public ushort FragmentTotal;

            /// <summary>Zero-based fragment index within the original message.</summary>
            public ushort FragmentIndex;
        }

        /// <summary>Deduplicated loss event tracked for congestion classification.</summary>
        private sealed class LossEvent
        {
            /// <summary>Sequence number of the lost segment.</summary>
            public uint SequenceNumber;

            /// <summary>Microsecond timestamp of the loss detection.</summary>
            public long TimestampMicros;

            /// <summary>RTT at the time the loss was detected.</summary>
            public long RttMicros;
        }

        /// <summary>Tracks a received (possibly out-of-order) data segment.</summary>
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

        /// <summary>Chunk of contiguous in-order data ready for application delivery.</summary>
        private sealed class ReceiveChunk
        {
            /// <summary>Buffer containing the data.</summary>
            public byte[] Buffer;

            /// <summary>Current read offset within the buffer.</summary>
            public int Offset;

            /// <summary>Total number of bytes in the buffer.</summary>
            public int Count;
        }

        /// <summary>Cryptographically secure RNG for connection ID generation.</summary>
        private static readonly RandomNumberGenerator ConnectionIdGenerator = RandomNumberGenerator.Create();

        /// <summary>Cryptographically secure RNG for initial sequence number generation.</summary>
        private static readonly RandomNumberGenerator SequenceRng = RandomNumberGenerator.Create();

        // ---- Core dependencies ----

        /// <summary>Lock protecting all protocol state mutation.</summary>
        private readonly object _sync = new object();

        /// <summary>Underlying transport for I/O operations.</summary>
        private readonly ITransport _transport;

        /// <summary>Whether fair-queue scheduling is enabled for this connection.</summary>
        private readonly bool _useFairQueue;

        /// <summary>Whether this connection was created server-side.</summary>
        private readonly bool _isServerSide;

        /// <summary>Protocol configuration (cloned from the source).</summary>
        private readonly UcpConfiguration _config;

        /// <summary>Callback invoked when this PCB transitions to Closed state.</summary>
        private readonly Action<UcpPcb> _closedCallback;

        // ---- Send/receive data structures ----

        /// <summary>Outbound data segments keyed by sequence number (sorted for in-order sending).</summary>
        private readonly SortedDictionary<uint, OutboundSegment> _sendBuffer = new SortedDictionary<uint, OutboundSegment>(UcpSequenceComparer.Instance);

        /// <summary>Received out-of-order data segments keyed by sequence number.</summary>
        private readonly SortedDictionary<uint, InboundSegment> _recvBuffer = new SortedDictionary<uint, InboundSegment>(UcpSequenceComparer.Instance);

        /// <summary>Queue of in-order data chunks ready for application read.</summary>
        private readonly Queue<ReceiveChunk> _receiveQueue = new Queue<ReceiveChunk>();

        // ---- NAK and loss tracking ----

        /// <summary>Set of sequence numbers for which a NAK has already been issued.</summary>
        private readonly HashSet<uint> _nakIssued = new HashSet<uint>();

        /// <summary>Counts how many times each sequence was observed as missing.</summary>
        private readonly Dictionary<uint, int> _missingSequenceCounts = new Dictionary<uint, int>();

        /// <summary>First-seen timestamp for each missing sequence.</summary>
        private readonly Dictionary<uint, long> _missingFirstSeenMicros = new Dictionary<uint, long>();

        /// <summary>Last-NAK-issued timestamp for each sequence.</summary>
        private readonly Dictionary<uint, long> _lastNakIssuedMicros = new Dictionary<uint, long>();

        /// <summary>Sequences for which SACK-based fast retransmit has already been triggered.</summary>
        private readonly HashSet<uint> _sackFastRetransmitNotified = new HashSet<uint>();

        /// <summary>FEC groups for which repair packets have been sent.</summary>
        private readonly HashSet<uint> _fecRepairSentGroups = new HashSet<uint>();

        /// <summary>Fragment metadata for DATA packets whose payloads are covered by FEC repair packets.</summary>
        private readonly Dictionary<uint, FecFragmentMetadata> _fecFragmentMetadata = new Dictionary<uint, FecFragmentMetadata>();

        // ---- FEC ----

        /// <summary>Forward Error Correction encoder/decoder (null if disabled).</summary>
        private UcpFecCodec _fecCodec;

        /// <summary>Base sequence number of the current FEC group being built.</summary>
        private uint _fecGroupBaseSeq;

        /// <summary>Number of data packets sent in the current FEC group.</summary>
        private int _fecGroupSendCount;

        // ---- Async coordination ----

        /// <summary>Signal released when new data is available for ReceiveAsync.</summary>
        private readonly SemaphoreSlim _receiveSignal = new SemaphoreSlim(0, int.MaxValue);

        /// <summary>Signal released when send buffer space frees up.</summary>
        private readonly SemaphoreSlim _sendSpaceSignal = new SemaphoreSlim(0, int.MaxValue);

        /// <summary>Lock ensuring only one flush operation runs at a time.</summary>
        private readonly SemaphoreSlim _flushLock = new SemaphoreSlim(1, 1);

        /// <summary>Cancellation token for all async operations on this PCB.</summary>
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        /// <summary>Completes when the connection handshake succeeds or fails.</summary>
        private readonly TaskCompletionSource<bool> _connectedTcs = new TaskCompletionSource<bool>();

        /// <summary>Completes when the connection is fully closed.</summary>
        private readonly TaskCompletionSource<bool> _closedTcs = new TaskCompletionSource<bool>();

        // ---- Protocol engines ----

        /// <summary>Generates SACK blocks from the receive buffer.</summary>
        private readonly UcpSackGenerator _sackGenerator = new UcpSackGenerator();

        /// <summary>RTO estimator (RFC 6298 style).</summary>
        private readonly UcpRtoEstimator _rtoEstimator;

        /// <summary>BBRv1 congestion control engine.</summary>
        private readonly BbrCongestionControl _bbr;

        /// <summary>Token-bucket pacing controller.</summary>
        private readonly PacingController _pacing;

        /// <summary>Optional .NET timer for standalone mode (null when using UcpNetwork).</summary>
        private readonly Timer _timer;

        /// <summary>Network engine reference (null in standalone mode).</summary>
        private readonly UcpNetwork _network;

        // ---- Connection state ----

        /// <summary>Current connection state machine state.</summary>
        private UcpConnectionState _state;

        /// <summary>Remote endpoint of this connection.</summary>
        private IPEndPoint _remoteEndPoint;

        /// <summary>Unique connection identifier assigned by cryptographically secure RNG.</summary>
        private uint _connectionId;

        /// <summary>Next sequence number to assign to an outbound data segment.</summary>
        private uint _nextSendSequence;

        /// <summary>Next in-order sequence number expected from the peer.</summary>
        private uint _nextExpectedSequence;

        /// <summary>Peer-advertised receive window in bytes.</summary>
        private uint _remoteWindowBytes = UcpConstants.DefaultReceiveWindowBytes;

        /// <summary>Current bytes in flight (sent but not yet acknowledged).</summary>
        private int _flightBytes;

        /// <summary>Accumulated fair-queue credit in bytes; spent on sends.</summary>
        private double _fairQueueCreditBytes;

        /// <summary>Last echo timestamp received from the peer.</summary>
        private long _lastEchoTimestamp;

        /// <summary>Timestamp of the last protocol activity (send or receive).</summary>
        private long _lastActivityMicros;

        /// <summary>Timestamp of the last ACK packet sent.</summary>
        private long _lastAckSentMicros;

        /// <summary>Most recent accepted RTT sample in microseconds.</summary>
        private long _lastRttMicros;

        // ---- Handshake / close flags ----

        /// <summary>Whether a SYN has been sent.</summary>
        private bool _synSent;

        /// <summary>Whether a SYN-ACK has been sent (server side).</summary>
        private bool _synAckSent;

        /// <summary>Timestamp of the most recent SYN-ACK send.</summary>
        private long _synAckSentMicros;

        /// <summary>Whether a FIN has been sent.</summary>
        private bool _finSent;

        /// <summary>Whether the FIN has been acknowledged by the peer.</summary>
        private bool _finAcked;

        /// <summary>Whether a FIN was received from the peer.</summary>
        private bool _peerFinReceived;

        /// <summary>Whether a RST was received from the peer.</summary>
        private bool _rstReceived;

        // ---- Lifecycle ----

        /// <summary>Whether this PCB has been disposed.</summary>
        private bool _disposed;

        /// <summary>Whether a delayed flush has been scheduled.</summary>
        private bool _flushDelayed;

        /// <summary>Whether a delayed ACK has been scheduled.</summary>
        private bool _ackDelayed;

        /// <summary>Timer ID from the network engine (0 if not scheduled).</summary>
        private uint _timerId;

        /// <summary>Timer ID for the delayed flush (0 if not scheduled).</summary>
        private uint _flushTimerId;

        /// <summary>Whether the Connected event has been raised.</summary>
        private bool _connectedRaised;

        /// <summary>Whether the Disconnected event has been raised.</summary>
        private bool _disconnectedRaised;

        /// <summary>Whether cleanup resources have been released.</summary>
        private bool _closedResourcesReleased;

        // ---- Duplicate ACK tracking ----

        /// <summary>Largest cumulative ACK number seen so far.</summary>
        private uint _largestCumulativeAckNumber;

        /// <summary>Whether _largestCumulativeAckNumber has been set.</summary>
        private bool _hasLargestCumulativeAckNumber;

        /// <summary>Last ACK number received (for duplicate ACK detection).</summary>
        private uint _lastAckNumber;

        /// <summary>Whether _lastAckNumber has been set.</summary>
        private bool _hasLastAckNumber;

        /// <summary>Count of consecutive duplicate ACKs received.</summary>
        private int _duplicateAckCount;

        /// <summary>Whether fast recovery is currently active.</summary>
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

        /// <summary>Count of original data packets transmitted.</summary>
        private int _sentDataPackets;

        /// <summary>Count of retransmitted data packets.</summary>
        private int _retransmittedPackets;

        /// <summary>Count of ACK packets transmitted.</summary>
        private int _sentAckPackets;

        /// <summary>Count of NAK packets transmitted.</summary>
        private int _sentNakPackets;

        /// <summary>Count of RST packets transmitted.</summary>
        private int _sentRstPackets;

        /// <summary>Count of fast retransmissions.</summary>
        private int _fastRetransmissions;

        /// <summary>Count of RTO-triggered retransmissions.</summary>
        private int _timeoutRetransmissions;

        // ---- RTT sample history ----

        /// <summary>Retained RTT samples for diagnostics.</summary>
        private readonly List<long> _rttSamplesMicros = new List<long>();

        // ---- NAK rate limiting ----

        /// <summary>Start timestamp of the current NAK rate-limit window.</summary>
        private long _lastNakWindowMicros;

        /// <summary>Number of NAKs sent in the current RTT window.</summary>
        private int _naksSentThisRttWindow;

        // ---- Delayed ACK / reordering ----

        /// <summary>Timestamp of the last ACK received.</summary>
        private long _lastAckReceivedMicros;

        /// <summary>Timestamp of the last reordered-data ACK sent.</summary>
        private long _lastReorderedAckSentMicros;

        /// <summary>Whether a tail-loss probe has been armed (not yet retransmitted).</summary>
        private bool _tailLossProbePending;

        // ---- Loss classification ----

        /// <summary>Queue of recent deduplicated loss events.</summary>
        private readonly Queue<LossEvent> _recentLossEvents = new Queue<LossEvent>();

        /// <summary>Hash set of recent loss sequence numbers for fast deduplication.</summary>
        private readonly HashSet<uint> _recentLossSequences = new HashSet<uint>();

        /// <summary>Start timestamp of the current urgent recovery budget window.</summary>
        private long _urgentRecoveryWindowMicros;

        /// <summary>Number of urgent recovery packets sent in the current RTT window.</summary>
        private int _urgentRecoveryPacketsInWindow;

        // ---- Constructors ----

        /// <summary>
        /// Creates a PCB with an optional connection ID and null network.
        /// </summary>
        public UcpPcb(ITransport transport, IPEndPoint remoteEndPoint, bool isServerSide, bool useFairQueue, Action<UcpPcb> closedCallback, uint? connectionId, UcpConfiguration config)
            : this(transport, remoteEndPoint, isServerSide, useFairQueue, closedCallback, connectionId, config, null)
        {
        }

        /// <summary>
        /// Full constructor: initializes all sub-components (RTO estimator, BBR,
        /// pacing controller, FEC codec if enabled) and schedules the first timer.
        /// </summary>
        public UcpPcb(ITransport transport, IPEndPoint remoteEndPoint, bool isServerSide, bool useFairQueue, Action<UcpPcb> closedCallback, uint? connectionId, UcpConfiguration config, UcpNetwork network)
        {
            _transport = transport;
            _remoteEndPoint = remoteEndPoint;
            _isServerSide = isServerSide;
            _useFairQueue = useFairQueue;
            _config = config ?? new UcpConfiguration();
            _network = network;
            _closedCallback = closedCallback;
            _connectionId = connectionId ?? NextConnectionId();
            _rtoEstimator = new UcpRtoEstimator(_config);
            _bbr = new BbrCongestionControl(_config);
            _pacing = new PacingController(_config, _config.InitialBandwidthBytesPerSecond);
            if (_config.FecRedundancy > 0d && _config.FecGroupSize > 1)
            {
                int fecRepairCount = Math.Max(1, (int)Math.Ceiling(_config.FecGroupSize * _config.FecRedundancy));
                _fecCodec = new UcpFecCodec(_config.FecGroupSize, fecRepairCount);
            }

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

        /// <summary>Raised when new in-order data is available for application delivery.</summary>
        public event Action<byte[], int, int> DataReceived;

        /// <summary>Raised when the connection handshake completes successfully.</summary>
        public event Action Connected;

        /// <summary>Raised when the connection is fully closed.</summary>
        public event Action Disconnected;

        // ---- Public properties ----

        /// <summary>Unique connection identifier.</summary>
        public uint ConnectionId
        {
            get { return _connectionId; }
        }

        /// <summary>Remote endpoint of this connection.</summary>
        public IPEndPoint RemoteEndPoint
        {
            get { return _remoteEndPoint; }
        }

        /// <summary>Current connection state (thread-safe).</summary>
        public UcpConnectionState State
        {
            get { lock (_sync) { return _state; } }
        }

        /// <summary>Current pacing rate from the BBR controller (thread-safe).</summary>
        public double CurrentPacingRateBytesPerSecond
        {
            get { lock (_sync) { return _bbr.PacingRateBytesPerSecond; } }
        }

        /// <summary>Whether the send buffer contains unsent segments (thread-safe).</summary>
        public bool HasPendingSendData
        {
            get { lock (_sync) { return _sendBuffer.Count > 0; } }
        }

        /// <summary>
        /// Creates a snapshot of all diagnostic counters and state for reporting.
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
        /// Aborts the connection immediately. Optionally sends a RST to the peer.
        /// </summary>
        /// <param name="sendReset">If true, sends a RST packet before closing.</param>
        public void Abort(bool sendReset)
        {
            if (sendReset && _remoteEndPoint != null)
            {
                SendControl(UcpPacketType.Rst, UcpPacketFlags.None);
            }

            TransitionToClosed();
        }

        /// <summary>Test hook: overrides the next send sequence number.</summary>
        public void SetNextSendSequenceForTest(uint nextSendSequence)
        {
            lock (_sync)
            {
                _nextSendSequence = nextSendSequence;
            }
        }

        /// <summary>Test hook: overrides the advertised receive window.</summary>
        public void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            lock (_sync)
            {
                _localReceiveWindowBytes = windowBytes;
            }
        }

        /// <summary>Sets or updates the remote endpoint for this connection.</summary>
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
        /// For IP-agnostic connections, accepts and updates to new endpoints.
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
                    _remoteEndPoint = remoteEndPoint;
                    return true;
                }

                if (_remoteEndPoint.Equals(remoteEndPoint))
                {
                    return true;
                }

                // Accept new endpoint (IP-agnostic: client changed port/IP).
                _remoteEndPoint = remoteEndPoint;
                return true;
            }
        }

        /// <summary>
        /// Performs the UCP SYN handshake: sends SYN, waits for SYN-ACK with
        /// exponential backoff, up to the configured connect timeout.
        /// </summary>
        /// <param name="remoteEndPoint">The remote endpoint to connect to.</param>
        public async Task ConnectAsync(IPEndPoint remoteEndPoint)
        {
            SetRemoteEndPoint(remoteEndPoint);
            lock (_sync)
            {
                if (_state == UcpConnectionState.Established)
                {
                    return; // Already connected.
                }

                _state = UcpConnectionState.HandshakeSynSent;
                _synSent = true;
            }

            long deadlineMicros = NowMicros() + (_config.ConnectTimeoutMilliseconds * UcpConstants.MICROS_PER_MILLI);
            while (NowMicros() < deadlineMicros)
            {
                SendControl(UcpPacketType.Syn, UcpPacketFlags.None);
                int waitMilliseconds;
                lock (_sync)
                {
                    waitMilliseconds = (int)Math.Max(UcpConstants.MIN_HANDSHAKE_WAIT_MILLISECONDS, _rtoEstimator.CurrentRtoMicros / UcpConstants.MICROS_PER_MILLI);
                }

                Task completed = await Task.WhenAny(_connectedTcs.Task, Task.Delay(waitMilliseconds, _cts.Token)).ConfigureAwait(false);
                if (completed == _connectedTcs.Task)
                {
                    if (await _connectedTcs.Task.ConfigureAwait(false))
                    {
                        return; // Connection established.
                    }

                    break; // Connection attempt failed.
                }
            }

            throw new TimeoutException("UCP connection handshake timed out.");
        }

        /// <summary>
        /// Enqueues data for sending. Accepts up to the max payload size times
        /// ushort.MaxValue bytes, fragmenting into MSS-sized segments.
        /// Returns the number of bytes accepted.
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
                if (_state != UcpConnectionState.Established && _state != UcpConnectionState.ClosingFinSent && _state != UcpConnectionState.ClosingFinReceived)
                {
                    return -1;
                }

            }

            int acceptedBytes = 0;
            int remaining = count;
            int currentOffset = offset;
            if (count > _config.MaxPayloadSize * ushort.MaxValue)
            {
                count = _config.MaxPayloadSize * ushort.MaxValue;
                remaining = count;
            }

            ushort fragmentTotal = (ushort)((count + _config.MaxPayloadSize - 1) / _config.MaxPayloadSize);
            ushort fragmentIndex = 0;
            int maxBufferedSegments = Math.Max(1, _config.SendBufferSize / Math.Max(1, _config.MaxPayloadSize));

            while (remaining > 0)
            {
                int chunk = remaining > _config.MaxPayloadSize ? _config.MaxPayloadSize : remaining;
                lock (_sync)
                {
                    if (_sendBuffer.Count >= maxBufferedSegments)
                    {
                        break; // Send buffer full; caller should retry.
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
        /// Copies up to <paramref name="count"/> bytes from the receive queue
        /// into the provided buffer. Blocks until data is available or the
        /// connection closes.
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
                        return 0;
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
                            _receiveQueue.Dequeue();
                        }

                        ScheduleAck();

                        return toCopy;
                    }
                }

                await _receiveSignal.WaitAsync(_cts.Token).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Reads exactly <paramref name="count"/> bytes into the buffer.
        /// Returns false if the connection closed before all bytes were received.
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
        /// Writes exactly <paramref name="count"/> bytes, retrying until all data
        /// is accepted or the connection closes. Returns false on error or close.
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
                    return false;
                }

                if (written == 0)
                {
                    await _sendSpaceSignal.WaitAsync(_cts.Token).ConfigureAwait(false);
                    continue;
                }

                totalWritten += written;
            }

            return true;
        }

        /// <summary>
        /// Gracefully closes the connection: drains the send buffer, sends FIN,
        /// and waits for the peer's FIN-ACK before transitioning to Closed.
        /// </summary>
        public async Task CloseAsync()
        {
            bool needSendFin = false;
            long deadlineMicros = NowMicros() + _config.DisconnectTimeoutMicros;
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

            await WaitWithTimeoutAsync(_closedTcs.Task, UcpConstants.CLOSE_WAIT_TIMEOUT_MILLISECONDS).ConfigureAwait(false);
            TransitionToClosed();
        }

        /// <summary>
        /// Dispatches an inbound packet to the appropriate handler based on type.
        /// Records activity timestamp on every received packet.
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
        /// Adds fair-queue credit bytes to this PCB, capped at a maximum buffer.
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

        /// <summary>Requests an immediate flush of the send buffer.</summary>
        public void RequestFlush()
        {
            _ = FlushSendQueueAsync();
        }

        /// <summary>
        /// Performs one tick of timer processing (used by UcpNetwork.DoEvents).
        /// Returns 1 if work was done, 0 if idle.
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
        /// (used by UcpNetwork.Input for known connections).
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
        /// Disposes the PCB: cancels async operations, disposes timers and
        /// semaphores, unregisters from the network, and transitions to Closed.
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
        /// Processes a cumulative ACK piggybacked on a non-ACK packet (DATA, NAK, SYNACK, FIN, RST).
        /// Validates plausibility, removes ACKed segments, and updates flight bytes.
        /// Returns the list of removed keys for the caller to handle cleanup.
        /// Does NOT trigger a flush - callers should do that themselves.
        /// </summary>
        /// <returns>Number of bytes delivered (ACKed) by this piggybacked ACK.</returns>
        private int ProcessPiggybackedAck(uint ackNumber, long echoTimestamp, long nowMicros)
        {
            List<uint> removeKeys = new List<uint>();
            int deliveredBytes = 0;
            lock (_sync)
            {
                if (ackNumber == 0)
                {
                    return 0;
                }

                if (_hasLargestCumulativeAckNumber && UcpSequenceComparer.IsBefore(ackNumber, _largestCumulativeAckNumber))
                {
                    return 0;
                }

                if (!_hasLargestCumulativeAckNumber || UcpSequenceComparer.IsAfter(ackNumber, _largestCumulativeAckNumber))
                {
                    _largestCumulativeAckNumber = ackNumber;
                    _hasLargestCumulativeAckNumber = true;
                }

                _lastAckReceivedMicros = nowMicros;
                _tailLossProbePending = false;

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
                            if (_flightBytes < 0) _flightBytes = 0;
                        }

                        deliveredBytes += segment.Payload.Length;
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
                        break;
                    }
                }

                for (int i = 0; i < removeKeys.Count; i++)
                {
                    _sackFastRetransmitNotified.Remove(removeKeys[i]);
                    _sendBuffer.Remove(removeKeys[i]);
                }

                if (removeKeys.Count > 0)
                {
                    try { 
                        _sendSpaceSignal.Release(removeKeys.Count); 
                    } 
                    catch (SemaphoreFullException)
                    {
                        
                    }
                }

                if (_sendBuffer.Count == 0)
                {
                    _fairQueueCreditBytes = 0;
                }

                if (deliveredBytes > 0)
                {
                    _bbr.OnAck(nowMicros, deliveredBytes, _lastRttMicros, _flightBytes);
                    _pacing.SetRate(_bbr.PacingRateBytesPerSecond, nowMicros);
                }
            }

            // Note: Callers handle flushing when needed.
            return deliveredBytes;
        }

        /// <summary>
        /// Handles an incoming SYN packet. Accepts the connection ID, sets the
        /// initial expected sequence, and replies with SYN-ACK.
        /// If the SYN carries a piggybacked ACK (re-SYN), processes it.
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
        /// Handles an incoming SYN-ACK: sets the expected sequence, processes the
        /// piggybacked ACK, acknowledges it, and transitions to Established.
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
                    shouldEstablish = _state == UcpConnectionState.HandshakeSynSent;
                }
            }

            if (hasAck && packet.AckNumber > 0)
            {
                ProcessPiggybackedAck(packet.AckNumber, packet.Header.Timestamp, NowMicros());
            }

            SendAckPacket(UcpPacketFlags.None, 0);

            if (shouldEstablish)
            {
                TransitionToEstablished();
            }
        }

        // ---- Packet handler: ACK ----

        /// <summary>
        /// Handles an incoming ACK packet: validates plausibility, processes
        /// cumulative ACK and SACK blocks, removes acknowledged segments,
        /// updates RTT and BBR estimates, and triggers fast retransmits.
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
                if (!IsAckPlausibleUnsafe(ackPacket))
                {
                    remainingFlight = _flightBytes;
                    return;
                }

                _remoteWindowBytes = ackPacket.WindowSize;
                SortSackBlocksUnsafe(ackPacket.SackBlocks);
                if (_state == UcpConnectionState.HandshakeSynReceived && _synAckSent)
                {
                    establishByHandshake = true;
                }

                if ((ackPacket.Header.Flags & UcpPacketFlags.FinAck) == UcpPacketFlags.FinAck)
                {
                    _finAcked = true;
                }

                if (ackPacket.EchoTimestamp > 0)
                {
                    echoRtt = nowMicros - ackPacket.EchoTimestamp;
                }

                _lastAckReceivedMicros = nowMicros;
                _tailLossProbePending = false;

                UpdateDuplicateAckStateUnsafe(ackPacket, nowMicros, out fastRetransmitTriggered);

                // Walk the send buffer and mark segments as ACKed (cumulative or SACK).
                int sackIndex = 0;
                List<SackBlock> sackBlocks = ackPacket.SackBlocks;
                bool hasSackBlocks = sackBlocks != null && sackBlocks.Count > 0;
                uint highestSack = hasSackBlocks ? GetHighestSackEnd(sackBlocks) : 0U;
                uint firstMissingSequence = UcpSequenceComparer.Increment(ackPacket.AckNumber);
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (segment.Acked)
                    {
                        continue;
                    }

                    bool acked = UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackPacket.AckNumber);
                    if (!acked && sackBlocks != null)
                    {
                        // Scan SACK blocks to check if this segment is selectively ACKed.
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
                        if (segment.SendCount == 1 && segment.LastSendMicros > 0)
                        {
                            long segmentRtt = nowMicros - segment.LastSendMicros;
                            if (sampleRtt == 0 || segmentRtt < sampleRtt)
                            {
                                sampleRtt = segmentRtt;
                            }
                        }

                        _bytesReceived += 0;
                        removeKeys.Add(pair.Key);
                        continue;
                    }

                    // Check for SACK-based fast retransmit eligibility.
                    if (hasSackBlocks)
                    {
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
                                segment.UrgentRetransmit = true;
                                _fastRetransmissions++;
                                _sackFastRetransmitNotified.Add(segment.SequenceNumber);
                                bool isCongestionLoss = IsCongestionLossUnsafe(segment.SequenceNumber, sampleRtt, nowMicros, 1);
                                _bbr.OnFastRetransmit(nowMicros, isCongestionLoss);
                                TraceLogUnsafe("FastRetransmit sequence=" + segment.SequenceNumber + " sack=true congestion=" + isCongestionLoss);
                            }
                        }
                    }
                }

                // Remove ACKed segments from the send buffer.
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

                if (_sendBuffer.Count == 0)
                {
                    _fairQueueCreditBytes = 0;
                }

                remainingFlight = _flightBytes;
                if (deliveredBytes > 0 && sampleRtt == 0 && echoRtt > 0 && echoRtt <= _rtoEstimator.CurrentRtoMicros)
                {
                    sampleRtt = echoRtt; // Fall back to echo-based RTT.
                }

                bool acceptableRttSample = sampleRtt > 0 && sampleRtt <= (long)(_rtoEstimator.CurrentRtoMicros * UcpConstants.RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
                if (deliveredBytes > 0 && acceptableRttSample)
                {
                    _lastRttMicros = sampleRtt;
                    AddRttSampleUnsafe(sampleRtt);
                    _rtoEstimator.Update(sampleRtt);
                }

                // Update BBR and pacing with the new ACK information.
                _bbr.OnAck(nowMicros, deliveredBytes, sampleRtt, _flightBytes);
                _pacing.SetRate(_bbr.PacingRateBytesPerSecond, nowMicros);
            }

            if (establishByHandshake)
            {
                TransitionToEstablished();
            }

            if (_finSent && _finAcked && _peerFinReceived)
            {
                TransitionToClosed();
            }

            if (fastRetransmitTriggered || deliveredBytes > 0 || remainingFlight > 0)
            {
                await FlushSendQueueAsync().ConfigureAwait(false);
            }
        }

        // ---- Packet handler: NAK ----

        /// <summary>
        /// Handles an incoming NAK packet: processes the piggybacked cumulative ACK,
        /// marks the reported sequences for retransmission if the segment hasn't
        /// already been retransmitted too recently.
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
                        if (!segment.NeedsRetransmit && !segment.Acked && ShouldAcceptRetransmitRequestUnsafe(segment, nowMicros))
                        {
                            segment.NeedsRetransmit = true;
                            segment.UrgentRetransmit = true;
                            _tailLossProbePending = false;
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
        /// Validates that the ACK packet is plausible: correct connection ID,
        /// non-receding cumulative ACK, and valid SACK block ordering.
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

            if (_hasLargestCumulativeAckNumber && UcpSequenceComparer.IsBefore(ackPacket.AckNumber, _largestCumulativeAckNumber))
            {
                return false; // ACK cannot recede.
            }

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
        /// Returns the highest End value across all SACK blocks.
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
        /// Sorts SACK blocks by their Start sequence number for efficient scanning.
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
        /// Determines whether a segment identified as missing via SACK should
        /// be fast-retransmitted. Applies reorder grace, observation thresholds,
        /// and FEC pending-repair checks.
        /// </summary>
        private bool ShouldFastRetransmitSackHoleUnsafe(OutboundSegment segment, uint firstMissingSequence, uint highestSack, bool reportedSackHole, long nowMicros)
        {
            if (segment == null || segment.LastSendMicros <= 0)
            {
                return false;
            }

            if (_sackFastRetransmitNotified.Contains(segment.SequenceNumber))
            {
                return false; // Already notified.
            }

            if (!_config.EnableAggressiveSackRecovery)
            {
                return false;
            }

            long reorderGraceMicros = GetSackFastRetransmitReorderGraceMicrosUnsafe();
            if (nowMicros - segment.LastSendMicros < reorderGraceMicros)
            {
                return false; // Still within reorder grace period.
            }

            if (HasPendingFecRepairUnsafe(segment, nowMicros))
            {
                return false; // FEC might still recover this.
            }

            bool firstMissing = segment.SequenceNumber == firstMissingSequence;
            int requiredObservations = firstMissing ? UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD : UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD + 1;
            uint distancePastHole = unchecked(highestSack - segment.SequenceNumber);
            if (!firstMissing && reportedSackHole && distancePastHole >= (uint)Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD, _config.FecGroupSize))
            {
                requiredObservations = UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD;
            }

            if (segment.MissingAckCount < requiredObservations)
            {
                return false;
            }

            if (firstMissing)
            {
                return true;
            }

            if (!reportedSackHole)
            {
                return false;
            }

            if (distancePastHole >= UcpConstants.SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks whether FEC repair for this segment's group is still pending,
        /// in which case SACK-based fast retransmit should wait.
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
                return false;
            }

            long graceMicros = GetFecFastRetransmitGraceMicrosUnsafe();
            return nowMicros - segment.FirstMissingAckMicros < graceMicros;
        }

        /// <summary>
        /// Returns the grace period in microseconds during which FEC repair is
        /// expected before SACK fast retransmit triggers.
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

            long adaptiveGraceMicros = rttMicros / 16;
            long maxGraceMicros = UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS * 4;
            return Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, Math.Min(adaptiveGraceMicros, maxGraceMicros));
        }

        /// <summary>
        /// Determines whether a non-leading hole is "reported" by SACK blocks:
        /// a lower range has been ACKed and a higher range has been SACKed,
        /// bracketing this sequence as a real hole.
        /// </summary>
        private static bool IsReportedSackHoleUnsafe(uint sequenceNumber, uint cumulativeAckNumber, List<SackBlock> sackBlocks)
        {
            if (sackBlocks == null || sackBlocks.Count == 0)
            {
                return false;
            }

            // A non-leading hole is trustworthy only when lower data was
            // cumulatively ACKed or SACKed and a later SACK block proves the
            // receiver has moved past this exact sequence.
            bool hasLowerAck = UcpSequenceComparer.IsBeforeOrEqual(cumulativeAckNumber, sequenceNumber);
            bool hasHigherSack = false;
            for (int i = 0; i < sackBlocks.Count; i++)
            {
                SackBlock block = sackBlocks[i];
                if (UcpSequenceComparer.IsInForwardRange(sequenceNumber, block.Start, block.End))
                {
                    return false; // Sequence is inside a SACK block, not a hole.
                }

                if (UcpSequenceComparer.IsBefore(block.End, sequenceNumber))
                {
                    hasLowerAck = true;
                    continue;
                }

                if (UcpSequenceComparer.IsAfter(block.Start, sequenceNumber))
                {
                    hasHigherSack = true;
                    break;
                }
            }

            return hasLowerAck && hasHigherSack;
        }

        /// <summary>
        /// Returns the minimum time a segment must wait before SACK fast
        /// retransmit triggers, scaled to a fraction of the RTT.
        /// </summary>
        private long GetSackFastRetransmitReorderGraceMicrosUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            if (rttMicros <= 0)
            {
                long fallbackRttMicros = _config.MinRtoMicros > 0 ? _config.MinRtoMicros : UcpConstants.DEFAULT_RTO_MICROS;
                return Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, fallbackRttMicros * 2);
            }

            // A reordered packet takes up to one RTT (forward) + jitter to
            // arrive, then its confirming ACK takes another half-RTT (reverse)
            // to reach the sender.  The full 2×RTT guard ensures the confirming
            // ACK clears the hole before SACK retransmits, eliminating spurious
            // fast retransmits on high-jitter weak-network paths.
            return Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros * 2);
        }

        // ---- Duplicate ACK handling ----

        /// <summary>
        /// Updates duplicate ACK counters and triggers fast retransmit if the
        /// duplicate ACK threshold is reached for the inferred lost segment.
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
                    // The next sequence after the cumulative ACK is inferred as lost.
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
                _duplicateAckCount = 0;
                _fastRecoveryActive = false;
            }

            _lastAckNumber = ackPacket.AckNumber;
            _hasLastAckNumber = true;
        }

        // ---- Loss classification ----

        /// <summary>
        /// Classifies whether a single sequence loss is congestion-related.
        /// </summary>
        private bool IsCongestionLossUnsafe(uint sequenceNumber, long sampleRttMicros, long nowMicros, int contiguousLossCount)
        {
            List<uint> sequences = new List<uint>(1);
            sequences.Add(sequenceNumber);
            return ClassifyLossesUnsafe(sequences, nowMicros, sampleRttMicros, contiguousLossCount);
        }

        /// <summary>
        /// Classifies multiple sequence losses as congestion or random.
        /// </summary>
        private bool ClassifyLossesUnsafe(IList<uint> sequenceNumbers, long nowMicros, long sampleRttMicros)
        {
            return ClassifyLossesUnsafe(sequenceNumbers, nowMicros, sampleRttMicros, GetMaxContiguousLossRun(sequenceNumbers));
        }

        /// <summary>
        /// Classifies losses as congestion based on deduplicated loss event count,
        /// contiguous loss run length, and RTT inflation relative to the minimum.
        /// </summary>
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
                    if (_recentLossSequences.Add(sequenceNumber))
                    {
                        _recentLossEvents.Enqueue(new LossEvent { SequenceNumber = sequenceNumber, TimestampMicros = nowMicros, RttMicros = rttMicros });
                        addedLoss = true;
                    }
                }
            }

            if (addedLoss)
            {
                PruneLossEventsUnsafe(nowMicros, windowMicros);
            }

            int dedupedLossCount = _recentLossEvents.Count;
            if (dedupedLossCount == 0)
            {
                return false;
            }

            int maxContiguousLossCount = Math.Max(contiguousLossCount, GetMaxContiguousRecentLossRunUnsafe());
            if (dedupedLossCount <= UcpConstants.BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS && maxContiguousLossCount < UcpConstants.BBR_CONGESTION_LOSS_BURST_THRESHOLD)
            {
                return false; // Too few losses to classify as congestion.
            }

            bool clusteredLoss = maxContiguousLossCount >= UcpConstants.BBR_CONGESTION_LOSS_BURST_THRESHOLD || dedupedLossCount > UcpConstants.BBR_CONGESTION_LOSS_WINDOW_THRESHOLD;
            if (!clusteredLoss)
            {
                return false;
            }

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
        /// Returns the time window in microseconds for recent loss classification.
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
        /// Returns the median RTT across recent loss events for congestion detection.
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

            if (samples.Count == 0 && _lastRttMicros > 0)
            {
                samples.Add(_lastRttMicros);
            }

            if (samples.Count == 0)
            {
                return 0;
            }

            samples.Sort();
            return samples[samples.Count / 2];
        }

        /// <summary>
        /// Returns the minimum observed RTT from all collected RTT samples.
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
        /// Computes the longest run of consecutive sequence numbers in a list.
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
                    continue; // Skip duplicates.
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
                    currentRun = 1; // Gap found, reset run.
                }
            }

            return maxRun;
        }

        /// <summary>
        /// Returns the minimum age before a segment is eligible for duplicate-ACK
        /// fast retransmit, scaled to RTT / 8 with a minimum reorder grace.
        /// </summary>
        private long GetFastRetransmitAgeThresholdUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            // Duplicate ACK recovery should repair quickly after two observations
            // without waiting a full RTT on high-BDP paths.
            return rttMicros <= 0 ? 0 : Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros / 8);
        }

        /// <summary>
        /// Returns true if early retransmit should trigger (when inflight is tiny).
        /// </summary>
        private bool ShouldTriggerEarlyRetransmitUnsafe()
        {
            int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize));
            return inflightSegments > 0 && inflightSegments <= UcpConstants.EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS;
        }

        /// <summary>
        /// Guards against redundant retransmits: a segment must wait at least one
        /// RTT (or RTO) before being retransmitted again after the first send.
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
                return true;
            }

            return nowMicros - segment.LastSendMicros >= graceMicros;
        }

        /// <summary>
        /// Returns the ACK-progress grace window used to suppress bulk RTO scans.
        /// If ACKs are arriving, the path is alive and recovery should be driven
        /// by SACK/NAK/FEC instead of retransmitting the entire outstanding pipe.
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
        /// Returns the overall retransmission ratio (retransmits / total sends).
        /// </summary>
        private double GetRetransmissionRatioUnsafe()
        {
            int total = _sentDataPackets + _retransmittedPackets;
            return total == 0 ? 0d : _retransmittedPackets / (double)total;
        }

        /// <summary>
        /// Conditionally writes a debug trace message for the PCB.
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
        /// Handles an incoming DATA packet: processes any piggybacked ACK, stores
        /// it in the receive buffer if within the window, drains consecutive
        /// in-order segments to the receive queue, generates NAK for detected gaps,
        /// and attempts FEC recovery.
        /// </summary>
        /// <param name="dataPacket">The decoded data packet.</param>
        private void HandleData(UcpDataPacket dataPacket)
        {
            List<uint> missing = new List<uint>();
            List<byte[]> readyPayloads = new List<byte[]>();
            bool shouldEstablish = false;
            bool shouldStore = false;
            bool sendImmediateAck = false;

            lock (_sync)
            {
                // Validate packet integrity.
                if (dataPacket.Payload == null || dataPacket.Payload.Length > _config.MaxPayloadSize || dataPacket.FragmentTotal == 0 || dataPacket.FragmentIndex >= dataPacket.FragmentTotal)
                {
                    return;
                }

                if (_state == UcpConnectionState.HandshakeSynReceived && _synAckSent)
                {
                    shouldEstablish = true;
                }

                _lastEchoTimestamp = dataPacket.Header.Timestamp;
                if (UcpSequenceComparer.IsBefore(dataPacket.SequenceNumber, _nextExpectedSequence))
                {
                    // Old duplicate packets only need an ACK so the peer can converge.
                }
                else
                {
                    uint usedBytes = GetReceiveWindowUsedBytesUnsafe();
                    shouldStore = usedBytes + dataPacket.Payload.Length <= _localReceiveWindowBytes;
                    if (shouldStore && !_recvBuffer.ContainsKey(dataPacket.SequenceNumber))
                    {
                        // Store the segment in the receive buffer.
                        InboundSegment inbound = new InboundSegment();
                        inbound.SequenceNumber = dataPacket.SequenceNumber;
                        inbound.FragmentTotal = dataPacket.FragmentTotal;
                        inbound.FragmentIndex = dataPacket.FragmentIndex;
                        inbound.Payload = dataPacket.Payload;
                        _recvBuffer[dataPacket.SequenceNumber] = inbound;
                        _nakIssued.Remove(dataPacket.SequenceNumber);
                        _missingSequenceCounts.Remove(dataPacket.SequenceNumber);
                        _missingFirstSeenMicros.Remove(dataPacket.SequenceNumber);
                        _lastNakIssuedMicros.Remove(dataPacket.SequenceNumber);

                        if (_fecCodec != null)
                        {
                            _fecFragmentMetadata[dataPacket.SequenceNumber] = new FecFragmentMetadata { FragmentTotal = dataPacket.FragmentTotal, FragmentIndex = dataPacket.FragmentIndex };
                            _fecCodec.FeedDataPacket(dataPacket.SequenceNumber, dataPacket.Payload);
                            TryRecoverFecAroundUnsafe(dataPacket.SequenceNumber, readyPayloads);
                        }
                    }

                    if (shouldStore && UcpSequenceComparer.IsAfter(dataPacket.SequenceNumber, _nextExpectedSequence))
                    {
                        // Gap detected: scan and collect NAK-eligible sequences.
                        sendImmediateAck = ShouldSendImmediateReorderedAckUnsafe(NowMicros());
                        uint current = _nextExpectedSequence;
                        int remainingNakSlots = UcpConstants.MAX_NAK_MISSING_SCAN;
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

                    // Drain contiguous in-order segments.
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

                    // Check if the first gap should trigger a NAK.
                    if (_recvBuffer.Count > 0 && !_recvBuffer.ContainsKey(_nextExpectedSequence))
                    {
                        if (_recvBuffer.Count >= UcpConstants.IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD && ShouldSendImmediateReorderedAckUnsafe(NowMicros()))
                        {
                            sendImmediateAck = true;
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

            // Deliver ready payloads to the application outside the lock.
            for (int i = 0; i < readyPayloads.Count; i++)
            {
                EnqueuePayload(readyPayloads[i]);
            }

            if (shouldEstablish)
            {
                TransitionToEstablished();
            }

            if (missing.Count > 0)
            {
                SendNak(missing);
            }

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
        /// using stored FEC repair data.
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
                if (candidateSeq == receivedSequenceNumber || UcpSequenceComparer.IsBefore(candidateSeq, _nextExpectedSequence) || _recvBuffer.ContainsKey(candidateSeq))
                {
                    continue;
                }

                if (StoreRecoveredFecPacketsUnsafe(_fecCodec.TryRecoverPacketsFromStoredRepair(candidateSeq), readyPayloads) > 0)
                {
                    return; // Recovery succeeded; stop scanning.
                }
            }
        }

        /// <summary>
        /// Stores FEC-recovered packets into the receive buffer and drains
        /// any newly contiguous in-order data.
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
                DrainReadyPayloadsUnsafe(readyPayloads);
            }

            return stored;
        }

        /// <summary>
        /// Stores a single FEC-recovered segment into the receive buffer.
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
        /// the ready payloads list.
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
        /// Clears all tracking state for a given sequence number.
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
        /// </summary>
        private bool ShouldIssueNakUnsafe(uint sequenceNumber)
        {
            return !_nakIssued.Contains(sequenceNumber);
        }

        /// <summary>
        /// Throttles immediate reordered-data ACKs: allows one per minimum interval.
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
        /// Checks whether the reorder grace period for a missing sequence has expired,
        /// using tiered confidence levels based on observation count.
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
        /// Computes a NAK reorder grace from RTT/jitter evidence. High-jitter
        /// paths need a longer receiver-side gap delay so reordering is not
        /// mistaken for packet loss and amplified into needless retransmits.
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
        /// Marks a sequence number as having had a NAK issued.
        /// </summary>
        private void MarkNakIssuedUnsafe(uint sequenceNumber)
        {
            _nakIssued.Add(sequenceNumber);
            _lastNakIssuedMicros[sequenceNumber] = NowMicros();
        }

        /// <summary>
        /// Returns the first-seen timestamp for a missing sequence, recording it
        /// if this is the first observation.
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
        /// Handles an incoming FEC repair packet: feeds it to the FEC codec,
        /// stores recovered packets, and delivers them to the application.
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

            for (int i = 0; i < fecReadyPayloads.Count; i++)
            {
                EnqueuePayload(fecReadyPayloads[i]);
            }

            // FEC recovery advances the cumulative ACK immediately; delaying it
            // leaves the sender with stale in-flight data and can create timeout
            // storms even though the receiver already reconstructed the payload.
            SendAckPacket(UcpPacketFlags.None, 0);
        }

        // ---- Packet handler: FIN ----

        /// <summary>
        /// Handles an incoming FIN: processes piggybacked ACK, acknowledges it,
        /// sends our own FIN if not yet sent, and checks if both FINs are
        /// acknowledged for final close.
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

            SendAckPacket(UcpPacketFlags.FinAck, 0);
            if (needSendOwnFin)
            {
                SendControl(UcpPacketType.Fin, UcpPacketFlags.None);
            }

            if (_finAcked)
            {
                TransitionToClosed();
            }
        }

        // ---- Packet sending helpers ----

        /// <summary>
        /// Sends a NAK packet with the given list of missing sequences.
        /// Includes cumulative ACK number so a separate ACK is not needed.
        /// Respects the per-RTT NAK emission rate limit.
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

                if (_lastNakWindowMicros == 0 || nowMicros - _lastNakWindowMicros >= rttWindowMicros)
                {
                    _lastNakWindowMicros = nowMicros;
                    _naksSentThisRttWindow = 0;
                }

                if (_naksSentThisRttWindow >= UcpConstants.MAX_NAKS_PER_RTT)
                {
                    return;
                }

                _naksSentThisRttWindow++;
                cumAck = _nextExpectedSequence > 0 ? unchecked(_nextExpectedSequence - 1U) : 0;
                _lastAckSentMicros = nowMicros;
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
        /// Sends a control packet (Syn, SynAck, Fin, Rst). Syn and SynAck
        /// include the current next-send-sequence for handshake validation.
        /// All control packets except the initial SYN carry the cumulative ACK number.
        /// </summary>
        /// <param name="type">The control packet type.</param>
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
                    packet.SequenceNumber = _nextSendSequence;
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
        /// Sends an ACK packet with the current cumulative ACK number, SACK blocks,
        /// advertised window, and echo timestamp.
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
                packet.AckNumber = unchecked(_nextExpectedSequence - 1U);
                packet.SackBlocks = _sackGenerator.Generate(_nextExpectedSequence, _recvBuffer.Keys, _config.MaxAckSackBlocks);
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
        /// Schedules a delayed ACK to allow potential piggybacking. If the
        /// delayed ACK timeout is zero or the RTT is very short, sends immediately.
        /// </summary>
        private void ScheduleAck()
        {
            if (_config.DelayedAckTimeoutMicros <= 0)
            {
                SendAckPacket(UcpPacketFlags.None, 0);
                return;
            }

            long ackDelayMicros = _config.DelayedAckTimeoutMicros;
            if (_lastRttMicros > 30L * UcpConstants.MICROS_PER_MILLI)
            {
                ackDelayMicros = Math.Min(ackDelayMicros, UcpConstants.MICROS_PER_MILLI); // Shorter delay on high-latency paths.
            }

            lock (_sync)
            {
                if (_ackDelayed)
                {
                    return; // Already scheduled.
                }

                _ackDelayed = true;
            }

            if (_network == null)
            {
                // Standalone: use Task.Delay.
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
                    }
                });
                return;
            }

            // Network-managed: use network timer.
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
        /// Flushes the send buffer: collects pending segments, applies pacing
        /// and fair-queue credit, encodes and sends via the transport.
        /// Reschedules itself if pacing wait time is needed.
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

                    lock (_sync)
                    {
                        int windowBytes = GetSendWindowBytesUnsafe();
                        foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                        {
                            OutboundSegment segment = pair.Value;
                            if (segment.Acked)
                            {
                                continue;
                            }

                            if (segment.InFlight && !segment.NeedsRetransmit)
                            {
                                continue;
                            }

                            if (!segment.NeedsRetransmit && !segment.InFlight && _flightBytes + segment.Payload.Length > windowBytes)
                            {
                                break; // Send window is full.
                            }

                            int packetSize = UcpConstants.DataHeaderSize + segment.Payload.Length;
                            bool urgentRecovery = segment.NeedsRetransmit && segment.SendCount > 0 && segment.UrgentRetransmit && CanUseUrgentRecoveryUnsafe(nowMicros);
                            if (_useFairQueue && _fairQueueCreditBytes < packetSize && !urgentRecovery)
                            {
                                break; // Not enough fair-queue credit.
                            }

            if (urgentRecovery)
            {
                // Urgent recovery bypasses the smooth pacing gate without
                // creating post-recovery token debt that would stall data.
                _pacing.ForceConsume(packetSize, nowMicros);
                _urgentRecoveryPacketsInWindow++;
            }
                            else if (!_pacing.TryConsume(packetSize, nowMicros))
                            {
                                waitMicros = _pacing.GetWaitTimeMicros(packetSize, nowMicros);
                                break; // Pacing gate; cannot send now.
                            }

                            if (_useFairQueue)
                            {
                                _fairQueueCreditBytes -= packetSize;
                                if (_fairQueueCreditBytes < 0)
                                {
                                    _fairQueueCreditBytes = 0;
                                }
                            }

                            segment.InFlight = true;
                            segment.NeedsRetransmit = false;
                            segment.UrgentRetransmit = false;
                            if (segment.SendCount == 0)
                            {
                                _flightBytes += segment.Payload.Length;
                            }
                            else
                            {
                                segment.InFlight = true;
                            }

                            segment.SendCount++;
                            _bbr.OnPacketSent(nowMicros, segment.SendCount > 1);
                            segment.LastSendMicros = nowMicros;
                            _lastActivityMicros = nowMicros;
                            segmentsToSend.Add(segment);
                        }
                    }

                    if (segmentsToSend.Count == 0)
                    {
                        if (waitMicros > 0)
                        {
                            ScheduleDelayedFlush(waitMicros);
                        }

                        break;
                    }

                    // Encode and send all collected segments outside the lock.
                    for (int i = 0; i < segmentsToSend.Count; i++)
                    {
                        OutboundSegment segment = segmentsToSend[i];
                        UcpDataPacket packet = new UcpDataPacket();

                        packet.Header = CreateHeader(UcpPacketType.Data,
                            segment.SendCount > 1 ? UcpPacketFlags.NeedAck | UcpPacketFlags.Retransmit : UcpPacketFlags.NeedAck,
                            nowMicros);
                        packet.SequenceNumber = segment.SequenceNumber;
                        packet.FragmentTotal = segment.FragmentTotal;
                        packet.FragmentIndex = segment.FragmentIndex;
                        packet.Payload = segment.Payload;

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

                        // FEC encoding: generate and send repair packets when a group is complete.
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
                                // Adaptive FEC: only transmit repair packets when
                                // estimated loss exceeds threshold.  The encoder
                                // always runs — we just skip sending repairs on
                                // low-loss paths where SACK is more efficient.
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

                                _fecGroupSendCount = 0;
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
        /// Schedules a delayed flush after the given wait time elapses.
        /// </summary>
        /// <param name="waitMicros">Wait time in microseconds.</param>
        private void ScheduleDelayedFlush(long waitMicros)
        {
            if (_flushDelayed)
            {
                return; // Already scheduled.
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
        /// Enqueues a received payload for application delivery and fires the
        /// DataReceived event.
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

            Action<byte[], int, int> dataReceived = DataReceived;
            if (dataReceived != null)
            {
                dataReceived(payload, 0, payload.Length);
            }

            _receiveSignal.Release();
        }

        // ---- Send window management ----

        /// <summary>
        /// Returns the effective send window in bytes: min(congestion_window, remote_receive_window).
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
        /// Returns true if the urgent recovery budget hasn't been exhausted
        /// in the current RTT window.
        /// </summary>
        private bool CanUseUrgentRecoveryUnsafe(long nowMicros)
        {
            long windowMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros;
            if (windowMicros <= 0)
            {
                windowMicros = UcpConstants.DEFAULT_RTO_MICROS;
            }

            if (_urgentRecoveryWindowMicros == 0 || nowMicros - _urgentRecoveryWindowMicros >= windowMicros)
            {
                _urgentRecoveryWindowMicros = nowMicros;
                _urgentRecoveryPacketsInWindow = 0; // Reset window budget.
            }

            return _urgentRecoveryPacketsInWindow < UcpConstants.URGENT_RETRANSMIT_BUDGET_PER_RTT;
        }

        /// <summary>
        /// Returns true if the connection is nearing the disconnect timeout,
        /// making urgent recovery more critical.
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
        /// Returns the total bytes used in the local receive buffer (queued + out-of-order).
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
        /// Creates a common header for outbound packets.
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

        /// <summary>Timer callback invoked when using a .NET Timer (standalone mode).</summary>
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

        /// <summary>Schedules the next timer tick via the network engine.</summary>
        private void ScheduleTimer()
        {
            if (_network == null || _disposed)
            {
                return;
            }

            long intervalMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.TimerIntervalMilliseconds) * UcpConstants.MICROS_PER_MILLI;
            _timerId = _network.AddTimer(_network.NowMicroseconds + intervalMicros, delegate { OnTimer(null); });
        }

        /// <summary>Delegates to the microsecond-aware timer handler.</summary>
        private async Task OnTimerAsync()
        {
            await OnTimerAsync(NowMicros()).ConfigureAwait(false);
        }

        /// <summary>
        /// Core timer handler: checks for RTO timeouts, tail-loss probes,
        /// keep-alive expiration, disconnection timeouts, and collects NAK gaps.
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
                int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize));
                int rtoRetransmitBudget = UcpConstants.RTO_RETRANSMIT_BUDGET_PER_TICK;
                bool ackProgressRecent = _lastAckReceivedMicros > 0 && nowMicros - _lastAckReceivedMicros <= GetRtoAckProgressSuppressionMicrosUnsafe();
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (!segment.InFlight || segment.Acked || segment.NeedsRetransmit)
                    {
                        continue;
                    }

                    if (nowMicros - segment.LastSendMicros >= _rtoEstimator.CurrentRtoMicros)
                    {
                        if (ackProgressRecent && _sendBuffer.Count > UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS)
                        {
                            continue; // ACK flow is alive; avoid bulk RTO amplification.
                        }

                        if (rtoRetransmitBudget <= 0)
                        {
                            break; // Budget exhausted for this tick.
                        }

                        bool segmentTimedOutForCongestion = IsCongestionLossUnsafe(segment.SequenceNumber, 0, nowMicros, 1);
                        if (segment.SendCount >= _config.MaxRetransmissions && segmentTimedOutForCongestion)
                        {
                            _timeoutRetransmissions++;
                            maxRetransmissionsExceeded = true;
                            break; // Max retransmissions exceeded; abort.
                        }

                            segment.NeedsRetransmit = true;
                            segment.UrgentRetransmit = true;
                            timedOut = true;
                        rtoRetransmitBudget--;
                        timedOutForCongestion = timedOutForCongestion || segmentTimedOutForCongestion;
                        _timeoutRetransmissions++;
                    }
                }

                // Tail-loss probe: when inflight is low and no ACK received recently.
                if (!timedOut && !_tailLossProbePending && inflightSegments > 0 && inflightSegments <= UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS)
                {
                    long tlpTimeoutMicros = _rtoEstimator.SmoothedRttMicros > 0
                        ? (long)Math.Ceiling(_rtoEstimator.SmoothedRttMicros * UcpConstants.TLP_TIMEOUT_RTT_RATIO)
                        : _rtoEstimator.CurrentRtoMicros;
                    if (_lastAckReceivedMicros > 0 && nowMicros - _lastAckReceivedMicros >= tlpTimeoutMicros)
                    {
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
                            break;
                        }
                    }
                }

                // Silence probe: detect path blackout by prolonged ACK silence.
                // When inflight > TLP_MAX but no ACK for 2×SRTT, retransmit the
                // most-recently-sent segment as a path probe — faster than waiting
                // for full RTO on high-RTT paths.
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

                if (timedOut)
                {
                    _bbr.OnPacketLoss(nowMicros, GetRetransmissionRatioUnsafe(), timedOutForCongestion);
                    TraceLogUnsafe("RTO loss congestion=" + timedOutForCongestion + " rto=" + _rtoEstimator.CurrentRtoMicros);
                    if (timedOutForCongestion)
                    {
                        _rtoEstimator.Backoff(); // Exponential backoff for congestion timeouts.
                    }
                }

                if (_state == UcpConnectionState.Established && nowMicros - _lastAckSentMicros >= _config.KeepAliveIntervalMicros && nowMicros - _lastActivityMicros >= _config.KeepAliveIntervalMicros)
                {
                    sendKeepAlive = true;
                }

                CollectMissingForNakUnsafe(missingForNak, nowMicros);

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
                SendAckPacket(UcpPacketFlags.None, -1); // -1 = keepalive (no echo timestamp).
            }

            if ((_state == UcpConnectionState.HandshakeSynSent || _state == UcpConnectionState.HandshakeSynReceived || _state == UcpConnectionState.Established || _state == UcpConnectionState.ClosingFinSent || _state == UcpConnectionState.ClosingFinReceived)
                && nowMicros - _lastActivityMicros >= _config.DisconnectTimeoutMicros)
            {
                TransitionToClosed();
                return;
            }

            if (_state == UcpConnectionState.Closed)
            {
                TransitionToClosed();
            }
        }

        /// <summary>
        /// Scans the receive buffer for missing sequences and collects up to
        /// MAX_NAK_SEQUENCES_PER_PACKET entries for NAK emission.
        /// </summary>
        private void CollectMissingForNakUnsafe(List<uint> missing, long nowMicros)
        {
            if (missing == null || _recvBuffer.Count == 0 || _recvBuffer.ContainsKey(_nextExpectedSequence))
            {
                return;
            }

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
        /// Transitions the connection to Established state. Raises the Connected
        /// event and signals the connection TCS.
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
                    connected = Connected;
                }
            }

            _connectedTcs.TrySetResult(true);
            if (connected != null)
            {
                connected();
            }
        }

        /// <summary>
        /// Transitions the connection to Closed state. Raises the Disconnected
        /// event, signals both TCSes, releases receive signal, and invokes
        /// the closed callback.
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
                    disconnected = Disconnected;
                }

                shouldCallback = true;
            }

            _connectedTcs.TrySetResult(false);
            _closedTcs.TrySetResult(true);
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
        /// registered timers.
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
        /// Waits for a task to complete with a timeout; returns true if completed.
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
            while (connectionId == 0); // Zero is reserved; retry until non-zero.

            return connectionId;
        }

        /// <summary>
        /// Generates a cryptographically random initial sequence number (like TCP ISN).
        /// </summary>
        private static uint NextSequence()
        {
            byte[] bytes = new byte[UcpConstants.SEQUENCE_NUMBER_SIZE];
            SequenceRng.GetBytes(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

        /// <summary>
        /// Returns the current protocol time in microseconds, preferring the
        /// network's shared clock when available.
        /// </summary>
        private long NowMicros()
        {
            return _network == null ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs;
        }

        /// <summary>
        /// Adds an RTT sample to the history buffer, maintaining the maximum
        /// sample count.
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
        /// Validates send/receive buffer arguments.
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
