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

    internal sealed class UcpPcb : IDisposable
    {

        private sealed class OutboundSegment
        {

            public uint SequenceNumber;

            public ushort FragmentTotal;

            public ushort FragmentIndex;

            public byte[] Payload;

            public bool InFlight;

            public bool Acked;

            public bool NeedsRetransmit;

            public int SendCount;

            public long LastSendMicros;

            public UcpPriority Priority;
        }

        private sealed class SackTrackingState
        {

            public int MissingAckCount;

            public long FirstMissingAckMicros;

            public bool UrgentRetransmit;
        }

        private struct LossEvent
        {
            public uint SequenceNumber;
            public long TimestampMicros;
            public long RttMicros;
        }

        private sealed class FecFragmentMetadata
        {

            public ushort FragmentTotal;

            public ushort FragmentIndex;
        }

        private sealed class InboundSegment
        {

            public uint SequenceNumber;

            public ushort FragmentTotal;

            public ushort FragmentIndex;

            public byte[] Payload;
        }

        private sealed class ReceiveChunk
        {

            public byte[] Buffer;

            public int Offset;

            public int Count;
        }

        private static readonly RandomNumberGenerator ConnectionIdGenerator = RandomNumberGenerator.Create();

        private static readonly RandomNumberGenerator SequenceRng = RandomNumberGenerator.Create();

        private readonly object _sync = new object();

        private readonly object _endpointLock = new object();
        private readonly object _sendBufLock = new object();
        private readonly object _recvBufLock = new object();
        private readonly object _rttLock = new object();
        private readonly object _nakLock = new object();
        private readonly object _lossLock = new object();
        private readonly object _fecLock = new object();

        private readonly ITransport _transport;

        private readonly bool _useFairQueue;

        private readonly bool _isServerSide;

        private readonly UcpConfiguration _config;

        private readonly Action<UcpPcb> _closedCallback;

        private readonly SortedDictionary<uint, OutboundSegment> _sendBuffer = new SortedDictionary<uint, OutboundSegment>(UcpSequenceComparer.Instance);

        private readonly SortedDictionary<uint, InboundSegment> _recvBuffer = new SortedDictionary<uint, InboundSegment>(UcpSequenceComparer.Instance);

        private readonly Queue<ReceiveChunk> _receiveQueue = new Queue<ReceiveChunk>();

        private readonly HashSet<uint> _nakIssued = new HashSet<uint>();

        private readonly Dictionary<uint, int> _missingSequenceCounts = new Dictionary<uint, int>();

        private readonly Dictionary<uint, long> _missingFirstSeenMicros = new Dictionary<uint, long>();

        private readonly Dictionary<uint, long> _lastNakIssuedMicros = new Dictionary<uint, long>();

        private readonly HashSet<uint> _sackFastRetransmitNotified = new HashSet<uint>();

        private readonly Dictionary<ulong, int> _sackBlockSendCounts = new Dictionary<ulong, int>();

        private readonly Dictionary<uint, SackTrackingState> _sackTracking = new Dictionary<uint, SackTrackingState>();

        private const int MAX_SACK_SEND_COUNT = UcpConstants.MAX_SACK_SEND_COUNT;

        private readonly HashSet<uint> _fecRepairSentGroups = new HashSet<uint>();

        private readonly Dictionary<uint, FecFragmentMetadata> _fecFragmentMetadata = new Dictionary<uint, FecFragmentMetadata>();

        private UcpFecCodec _fecCodec;

        private readonly SemaphoreSlim _receiveSignal = new SemaphoreSlim(0, int.MaxValue);

        private readonly SemaphoreSlim _sendSpaceSignal = new SemaphoreSlim(0, int.MaxValue);

        private readonly SemaphoreSlim _flushLock = new SemaphoreSlim(1, 1);

        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        private readonly TaskCompletionSource<bool> _connectedTcs = new TaskCompletionSource<bool>();

        private readonly TaskCompletionSource<bool> _closedTcs = new TaskCompletionSource<bool>();

        private readonly UcpSackGenerator _sackGenerator = new UcpSackGenerator();

        private readonly UcpRtoEstimator _rtoEstimator;

        private readonly UcpCongestionControl _congestion;

        private readonly PacingController _pacing;

        private readonly Timer _timer;

        private volatile bool _timerDisposed;

        private readonly UcpNetwork _network;

        private volatile UcpConnectionState _state;

        private volatile IPEndPoint _remoteEndPoint;

        private volatile uint _connectionId;

        private ulong _sessionKey;

        private volatile uint _nextSendSequence;

        private uint _nextExpectedSequence;

        private volatile uint _remoteWindowBytes = UcpConstants.DefaultReceiveWindowBytes;

        private long _flightBytes;

        private double _fairQueueCreditBytes;

        private long _lastEchoTimestamp;

        // Most recent time the remote peer proved it is alive (any inbound packet that passed
        // PAWS validation). This is updated ONLY by the receive path: our own outgoing packets
        // (keepalives, data, ACKs, NAKs) must never refresh it, or an idle connection to a dead
        // peer would indefinitely self-refresh its own disconnect deadline. The disconnect check
        // in OnTimerSync therefore measures how long the peer itself has been silent.
        private long _lastPeerAliveMicros;

        private long _lastAckSentMicros;

        private long _lastRttMicros;

        private bool _synSent;

        private bool _synAckSent;

        private long _synAckSentMicros;

        private bool _finSent;

        private bool _finAcked;

        private bool _peerFinReceived;

        private volatile bool _rstReceived;

        private bool _hasPendingCloseCallback;

        private long _closeStartMicros;

        private long _finSentMicros;

        private int _finRetransmitCount;

        private volatile bool _disposed;

        internal bool Disposed => _disposed;

        private long _largestTimestampSeen;

        internal void ResetLargestTimestampForReconnection()
        {
            Volatile.Write(ref _largestTimestampSeen, 0);
        }

        private volatile bool _flushDelayed;
        private long _flushDeadlineUs;

        private volatile bool _ackDelayed;

        private uint _timerId;

        private uint _flushTimerId;

        private uint _ackTimerId;

        private bool _connectedRaised;

        private bool _disconnectedRaised;

        private bool _closedResourcesReleased;

        private volatile bool _pathChanged;

        private uint _largestCumulativeAckNumber;

        private bool _hasLargestCumulativeAckNumber;

        private uint _lastAckNumber;

        private bool _hasLastAckNumber;

        private int _duplicateAckCount;

        private bool _fastRecoveryActive;

        private volatile uint _localReceiveWindowBytes = UcpConstants.DefaultReceiveWindowBytes;

        private int _queuedReceiveBytes;

        private long _recvBufferBytes;

        private long _bytesSent;

        private long _bytesReceived;

        private readonly long[] _measuredBwSlots = new long[10];

        private readonly long[] _measuredBwSlotStart = new long[10];

        private int _measuredBwSlotIndex;

        private int _sentDataPackets;

        private int _retransmittedPackets;

        private int _sentAckPackets;

        private int _sentNakPackets;

        private int _sentRstPackets;

        private int _fastRetransmissions;

        private int _timeoutRetransmissions;

        private readonly List<long> _rttSamplesMicros = new List<long>();

        private readonly Queue<LossEvent> _recentLossEvents = new Queue<LossEvent>();

        private readonly HashSet<uint> _recentLossSequences = new HashSet<uint>();

        private long _lastNakWindowMicros;

        private int _naksSentThisRttWindow;

        private long _lastAckReceivedMicros;

        private long _lastReorderedAckSentMicros;

        private bool _tailLossProbePending;

        private long _urgentRecoveryWindowMicros;

        private int _urgentRecoveryPacketsInWindow;

        private readonly HashSet<uint> _extraCids = new HashSet<uint>();

        private uint _pendingNewCid;

        private bool _cidRotatePending;

        private long _lastCidRotateMicros;

        private uint _cidRotateMarkerSequence;

        private uint _deferredOldCid;
        private uint _deferredNewCid;
        private uint _deferredOldCid2;
        private uint _deferredNewCid2;

        private IPEndPoint _pathChallengeCandidate;

        private byte[] _pathChallengeData;

        private long _pathChallengeMicros;

        private long _lastPathChallengeMicros;

        private int _pathChallengeAttempts;

        private bool _pathChallengePending;

        private int _probeMin = UcpConstants.MTU_PROBE_BASE;

        private int _probeMax = UcpConstants.MTU_PROBE_MAX;

        private int _probeMtu;

        private int _currentMtu = UcpConstants.MTU_PROBE_BASE;

        private long _lastMtuProbeMicros;

        private long _lastMtuConvergeMicros;

        private uint _mtuProbeSequenceNumber;

        private bool _mtuProbeAcked;

        private bool _mtuProbePending;

        public UcpPcb(ITransport transport, IPEndPoint remoteEndPoint, bool isServerSide, bool useFairQueue, Action<UcpPcb> closedCallback, uint? connectionId, UcpConfiguration config)
            : this(transport, remoteEndPoint, isServerSide, useFairQueue, closedCallback, connectionId, config, null)
        {
        }

        public UcpPcb(ITransport transport, IPEndPoint remoteEndPoint, bool isServerSide, bool useFairQueue, Action<UcpPcb> closedCallback, uint? connectionId, UcpConfiguration config, UcpNetwork network)
        {
            _cts.Token.Register(() => _closedTcs.TrySetResult(false));
            _transport = transport;
            _remoteEndPoint = remoteEndPoint;
            _isServerSide = isServerSide;
            _useFairQueue = useFairQueue;
            _config = config ?? new UcpConfiguration();
            _network = network;
            _closedCallback = closedCallback;

            _connectionId = connectionId ?? NextConnectionId();

            _sessionKey = _isServerSide ? 0UL : NextSessionKey();
            _rtoEstimator = new UcpRtoEstimator(_config);
            _congestion = new UcpCongestionControl(
                _config);

            _pacing = new PacingController(_config, _config.InitialBandwidthBytesPerSecond);
            if (_config.FecRedundancy > 0d && _config.FecGroupSize > 1)
            {
                int fecRepairCount = Math.Max(1, (int)Math.Ceiling(_config.FecGroupSize * _config.FecRedundancy));
                _fecCodec = new UcpFecCodec(_config.FecGroupSize, fecRepairCount);
            }

            _state = UcpConnectionState.Init;
            _nextSendSequence = NextSequence();
            _lastPeerAliveMicros = NowMicros();
            _lastAckSentMicros = _lastPeerAliveMicros;
            _remoteWindowBytes = _config.ReceiveWindowBytes;
            _localReceiveWindowBytes = _config.ReceiveWindowBytes;
            for (int i = 0; i < _measuredBwSlotStart.Length; i++)
            {
                _measuredBwSlotStart[i] = -1L;
            }

            if (null == _network)
            {

                int timerIntervalMs = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.TimerIntervalMilliseconds);
                _timer = new Timer(OnTimer, null, timerIntervalMs, timerIntervalMs);
            }
            else
            {

                _network.RegisterPcb(this);
                ScheduleTimer();
            }
        }

        private bool IsRstFromKnownRemote(IPEndPoint remoteEndPoint)
        {
            if (null == remoteEndPoint)
            {
                return false;
            }

            lock (_endpointLock)
            {
                if (null == _remoteEndPoint)
                {
                    return true;
                }

                return _remoteEndPoint.Equals(remoteEndPoint);
            }
        }

        public event Action<byte[], int, int> DataReceived;

        public event Action Connected;

        public event Action Disconnected;

        public uint ConnectionId
        {
            get { return _connectionId; }
        }

        public ulong SessionKey
        {
            get { return Volatile.Read(ref _sessionKey); }
        }

        public IPEndPoint RemoteEndPoint
        {
            get { return _remoteEndPoint; }
        }

        public UcpConnectionState State
        {
            get { return _state; }
        }

        public double CurrentPacingRateBytesPerSecond
        {
            get { return _congestion.PacingRateBytesPerSecond; }
        }

        public bool HasPendingSendData
        {
            get { lock (_sendBufLock) { return _sendBuffer.Count > 0; } }
        }

        internal bool HasReceiveData
        {
            get { lock (_sync) { return _receiveQueue.Count > 0; } }
        }

        internal bool HasSendSpace
        {
            get
            {
                lock (_sendBufLock)
                {
                    int maxBufferedSegments = Math.Max(1, _config.SendBufferSize / Math.Max(1, _config.MaxPayloadSize));
                    return _sendBuffer.Count < maxBufferedSegments;
                }
            }
        }

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
                diagnostics.CongestionWindowBytes = _congestion.CongestionWindowBytes;
                diagnostics.PacingRateBytesPerSecond = _congestion.PacingRateBytesPerSecond;
                diagnostics.EstimatedLossPercent = _congestion.EstimatedLossPercent;
                diagnostics.LastRttMicros = _lastRttMicros;

                diagnostics.RttSamplesMicros.AddRange(_rttSamplesMicros);

                diagnostics.MeasuredBandwidthBytesPerSecond = ComputeMeasuredBandwidthUnsafe(NowMicros());

                diagnostics.ReceivedReset = _rstReceived;
                diagnostics.CurrentMtu = _currentMtu;
                diagnostics.MtuProbeMin = _probeMin;
                diagnostics.MtuProbeMax = _probeMax;
                diagnostics.MtuProbeValue = _mtuProbePending ? _probeMtu : 0;
                diagnostics.MtuProbePending = _mtuProbePending;

                int bufferedBytes = 0;
                foreach (ReceiveChunk chunk in _receiveQueue)
                {
                    bufferedBytes += chunk.Count - chunk.Offset;
                }

                diagnostics.BufferedReceiveBytes = bufferedBytes;
                return diagnostics;
            }
        }

        public void Abort(bool sendReset)
        {
            IPEndPoint ep = _remoteEndPoint;
            if (sendReset && null != ep)
            {
                try
                {
                    SendControl(UcpPacketType.Rst, UcpPacketFlags.None);
                }
                catch (ObjectDisposedException)
                {
                }
                catch (InvalidOperationException)
                {
                }
            }

            TransitionToClosed();
        }

        public void SetNextSendSequenceForTest(uint nextSendSequence)
        {
            _nextSendSequence = nextSendSequence;
        }

        public void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            _localReceiveWindowBytes = windowBytes;
        }

        public void SetRemoteEndPoint(IPEndPoint remoteEndPoint)
        {
            if (null == remoteEndPoint)
            {
                return;
            }

            _remoteEndPoint = remoteEndPoint;
        }

        public void MarkPathChanged()
        {
            _pathChanged = true;
        }

        internal int GetCurrentMtu() => _currentMtu;

        internal int GetProbeMin() => _probeMin;

        internal int GetProbeMax() => _probeMax;

        internal int GetProbeMtu() => _probeMtu;

        internal bool IsMtuProbePending() => _mtuProbePending;

        internal bool IsMtuProbeAcked() => _mtuProbeAcked;

        internal void SetMtuProbeAckedForTest()
        {

            _mtuProbePending = false; _mtuProbeAcked = true;
        }

        internal void SetLastMtuProbeMicrosForTest(long micros)
        {
            Interlocked.Exchange(ref _lastMtuProbeMicros, micros);
        }

        internal void SetLastMtuConvergeMicrosForTest(long micros)
        {
            Interlocked.Exchange(ref _lastMtuConvergeMicros, micros);
        }

        internal void RunTimerForTest(long nowMicros)
        {
            if (null != _network && nowMicros > _network.CurrentTimeUs)
            {
                _network.AdvanceTimeForTest(nowMicros);
            }
            OnTimerSync(nowMicros);
        }

        public bool IsValidCid(uint cid)
        {
            if (_connectionId == cid) { return true; }
            lock (_endpointLock)
            {
                return _extraCids.Contains(cid);
            }
        }

        public bool AddExtraCid(uint cid)
        {
            if (0 == cid || _connectionId == cid) { return false; }
            lock (_endpointLock)
            {
                return _extraCids.Add(cid);
            }
        }

        public bool RemoveExtraCid(uint cid)
        {
            if (cid == _connectionId) { return false; }
            lock (_endpointLock)
            {
                return _extraCids.Remove(cid);
            }
        }

        public bool ValidateRemoteEndPoint(IPEndPoint remoteEndPoint)
        {
            if (null == remoteEndPoint)
            {
                return false;
            }

            lock (_sync)
            {
                if (null == _remoteEndPoint)
                {

                    _remoteEndPoint = remoteEndPoint;
                    return true;
                }

                if (_remoteEndPoint.Equals(remoteEndPoint))
                {
                    return true;
                }

                if (_state != UcpConnectionState.Established)
                {
                    _remoteEndPoint = remoteEndPoint;
                    return true;
                }

                long nowMicros = NowMicros();
                if (_pathChallengePending)
                {
                    return false;
                }
                if (_lastPathChallengeMicros > 0 && nowMicros - _lastPathChallengeMicros < UcpConstants.PATH_CHALLENGE_RATE_LIMIT_MICROS)
                {
                    return false;
                }

                if (_pathChallengeAttempts >= UcpConstants.PATH_CHALLENGE_MAX_ATTEMPTS)
                {
                    _remoteEndPoint = remoteEndPoint;
                    _pathChanged = true;
                    _pathChallengeAttempts = 0;
                    _pathChallengePending = false;
                    return true;
                }

                _pathChallengeCandidate = remoteEndPoint;
                _pathChallengeData = new byte[8];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(_pathChallengeData);
                }

                _pathChallengeMicros = nowMicros;
                _lastPathChallengeMicros = nowMicros;
                _pathChallengeAttempts++;
                _pathChallengePending = true;
            }

            SendPathChallenge(_pathChallengeCandidate, _pathChallengeData);
            return false;
        }

        public async Task ConnectAsync(IPEndPoint remoteEndPoint)
        {
            SetRemoteEndPoint(remoteEndPoint);
            lock (_sync)
            {
                if (_state == UcpConnectionState.Established)
                {
                    return;
                }

                if (_state == UcpConnectionState.Closed ||
                    _state == UcpConnectionState.ClosingFinSent ||
                    _state == UcpConnectionState.ClosingFinReceived)
                {
                    return;
                }

                _state = UcpConnectionState.HandshakeSynSent;
                _synSent = true;
            }

            long deadlineMicros = NowMicros() + (_config.ConnectTimeoutMilliseconds * UcpConstants.MICROS_PER_MILLI);
            while (NowMicros() < deadlineMicros)
            {
                try
                {

                    SendControl(UcpPacketType.Syn, UcpPacketFlags.None);
                    int waitMilliseconds;
                    lock (_rttLock)
                    {

                        waitMilliseconds = (int)Math.Max(UcpConstants.MIN_HANDSHAKE_WAIT_MILLISECONDS, _rtoEstimator.CurrentRtoMicros / UcpConstants.MICROS_PER_MILLI);
                    }

                    Task completed = await Task.WhenAny(_connectedTcs.Task, Task.Delay(waitMilliseconds, _cts.Token)).ConfigureAwait(false);
                    if (completed == _connectedTcs.Task)
                    {
                        if (await _connectedTcs.Task.ConfigureAwait(false))
                        {
                            return;
                        }

                        break;
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (ObjectDisposedException)
                {
                    throw new OperationCanceledException("UCP connection handshake canceled (disposed).");
                }

            }

            throw new TimeoutException("UCP connection handshake timed out.");
        }

        public async Task<int> SendAsync(byte[] buffer, int offset, int count)
        {
            return await SendAsync(buffer, offset, count, UcpPriority.Normal).ConfigureAwait(false);
        }

        internal async Task<int> SendAsync(byte[] buffer, int offset, int count, UcpPriority priority)
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
            int effectiveMaxPayload = Math.Min(_config.MaxPayloadSize, _currentMtu - UcpConstants.DATA_HEADER_SIZE_WITH_ACK);
            if (effectiveMaxPayload <= 0) effectiveMaxPayload = _config.MaxPayloadSize;
            if (effectiveMaxPayload <= 0) effectiveMaxPayload = UcpConstants.MSS - (int)UcpConstants.DataHeaderSize;

            long maxAllowed = (long)effectiveMaxPayload * ushort.MaxValue;
            if (maxAllowed > int.MaxValue) maxAllowed = int.MaxValue;
            if (count > maxAllowed)
            {
                count = (int)maxAllowed;
                remaining = count;
            }

            ushort fragmentTotal = (ushort)((count + effectiveMaxPayload - 1) / effectiveMaxPayload);
            ushort fragmentIndex = 0;
            int maxBufferedSegments = Math.Max(1, _config.SendBufferSize / Math.Max(1, effectiveMaxPayload));

            while (remaining > 0)
            {
                int chunk = Math.Min(effectiveMaxPayload, remaining);

                byte[] payload = new byte[chunk];
                Buffer.BlockCopy(buffer, currentOffset, payload, 0, chunk);

                lock (_sendBufLock)
                {
                    if (_sendBuffer.Count >= maxBufferedSegments)
                    {
                        break;
                    }

                    OutboundSegment segment = new OutboundSegment();
                    segment.SequenceNumber = _nextSendSequence;
                    segment.FragmentTotal = fragmentTotal;
                    segment.FragmentIndex = fragmentIndex;
                    segment.Payload = payload;
                    segment.Priority = priority;

                    if (_sendBuffer.ContainsKey(segment.SequenceNumber))
                    {
                        break;
                    }

                    _sendBuffer[segment.SequenceNumber] = segment;
                    _nextSendSequence = UcpSequenceComparer.Increment(_nextSendSequence);
                }

                currentOffset += chunk;
                remaining -= chunk;
                acceptedBytes += chunk;
                fragmentIndex++;
            }

            if (acceptedBytes > 0)
            {
                // All other _congestion mutation sites (OnAck, OnPathChange,
                // OnPacketLoss, SetPeerWindow, OnPacketSent) are serialized
                // under _sync. Use the same lock here so the CC state machine
                // has a single critical section — a dedicated _ccLock would
                // create a second, non-excluding critical section (data race).
                lock (_sync) { _congestion.SetAppLimited(false); _congestion.OnIdleRestart(); }
            }

            await FlushSendQueueAsync().ConfigureAwait(false);
            return acceptedBytes;
        }

        public async Task<int> ReceiveAsync(byte[] buffer, int offset, int count)
        {
            return await ReceiveAsync(buffer, offset, count, CancellationToken.None).ConfigureAwait(false);
        }

        public async Task<int> ReceiveAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBuffer(buffer, offset, count);
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bool hasData = false;
                lock (_sync)
                {
                    if (_receiveQueue.Count > 0)
                    {
                        hasData = true;
                    }
                    else if (_state == UcpConnectionState.Closed)
                    {
                        return 0;
                    }
                }

                if (hasData)
                {
                    lock (_sync)
                    {
                        if (_receiveQueue.Count == 0)
                            continue;

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

                try
                {
                    // Link the caller's cancellation so a timed-out synchronous
                    // Receive() can abandon this wait; otherwise a zombie reader
                    // would consume future data into a discarded buffer.
                    if (cancellationToken.CanBeCanceled)
                    {
                        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
                        await _receiveSignal.WaitAsync(linked.Token).ConfigureAwait(false);
                    }
                    else
                    {
                        await _receiveSignal.WaitAsync(_cts.Token).ConfigureAwait(false);
                    }
                }
                catch (ObjectDisposedException)
                {
                    return 0;
                }
                catch (OperationCanceledException)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    return 0;
                }
            }
        }

        public async Task<bool> ReadAsync(byte[] buffer, int offset, int count)
        {
            return await ReadAsync(buffer, offset, count, CancellationToken.None).ConfigureAwait(false);
        }

        public async Task<bool> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBuffer(buffer, offset, count);
            int completed = 0;
            while (completed < count)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int received = await ReceiveAsync(buffer, offset + completed, count - completed, cancellationToken).ConfigureAwait(false);
                if (received <= 0)
                {
                    return false;
                }

                completed += received;
            }

            return true;
        }

        public async Task<bool> WriteAsync(byte[] buffer, int offset, int count)
        {
            return await WriteAsync(buffer, offset, count, UcpPriority.Normal).ConfigureAwait(false);
        }

        internal async Task<bool> WriteAsync(byte[] buffer, int offset, int count, UcpPriority priority)
        {
            ValidateBuffer(buffer, offset, count);
            int totalWritten = 0;
            while (totalWritten < count)
            {
                int written = await SendAsync(buffer, offset + totalWritten, count - totalWritten, priority).ConfigureAwait(false);
                if (written < 0)
                {
                    return false;
                }

                if (0 == written)
                {

                    try
                    {
                        await _sendSpaceSignal.WaitAsync(_cts.Token).ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException)
                    {
                        return false;
                    }
                    continue;
                }

                totalWritten += written;
            }

            return true;
        }

        public async Task CloseAsync()
        {
            lock (_sync)
            {
                if (_state == UcpConnectionState.Closed)
                {
                    return;
                }
                if (!_hasPendingCloseCallback)
                {
                    _state = UcpConnectionState.ClosingFinSent;
                    _hasPendingCloseCallback = true;
                    _closeStartMicros = NowMicros();
                }
            }

            long closeTimeoutMs = Math.Max((_config.DisconnectTimeoutMicros + 5_000_000L) / 1000L, 10_000L);
            await WaitWithTimeoutAsync(_closedTcs.Task, (int)Math.Min(closeTimeoutMs, int.MaxValue)).ConfigureAwait(false);
            TransitionToClosed();
        }

        public async Task HandleInboundAsync(UcpPacket packet)
        {
            if (null == packet)
            {
                return;
            }

            lock (_sync)
            {
                // Any inbound packet is proof the remote peer is alive (PAWS below rejects stale
                // or replayed packets). This is the ONLY site that refreshes _lastPeerAliveMicros;
                // outgoing sends must not count as peer activity or keepalives would self-refresh
                // the disconnect deadline forever (see the keepalive comment in OnTimerSync).
                _lastPeerAliveMicros = NowMicros();

                if (_largestTimestampSeen > 0 &&
                    _largestTimestampSeen - packet.Header.Timestamp > UcpConstants.PAWS_TIMEOUT_MICROS)
                {
                    return;
                }

                if (packet.Header.Timestamp > _largestTimestampSeen)
                {
                    _largestTimestampSeen = packet.Header.Timestamp;
                }
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

        public void AddFairQueueCredit(double bytes)
        {
            if (!_useFairQueue || bytes <= 0)
            {
                return;
            }

            lock (_sendBufLock)
            {
                _fairQueueCreditBytes += bytes;
                double maxCreditBytes = Math.Max(bytes, Math.Max(_config.SendQuantumBytes, _config.Mss) * UcpConstants.MaxBufferedFairQueueRounds * 16);
                if (_fairQueueCreditBytes > maxCreditBytes)
                {
                    _fairQueueCreditBytes = maxCreditBytes;
                }
            }
        }

        public void RequestFlush()
        {
            _ = FlushSendQueueAsync().ContinueWith(static (t, _) =>
            {
                if (t.IsFaulted)
                {
                    Trace.WriteLine("[UCP PCB] FlushSendQueueAsync failed: " + t.Exception?.InnerException?.Message);
                }
            }, null, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        }

        public int OnTick(long nowMicros)
        {
            if (_disposed) return 0;

            int work = 0;
            try
            {
                OnTimerSync(nowMicros);
                work++;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("[UCP PCB] OnTimerSync failed: " + ex.Message);
            }

            if (HasPendingSendData)
            {
                RequestFlush();
                work++;
            }

            return work;
        }

        public void DispatchFromNetwork(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (packet.Header.Type == UcpPacketType.Rst)
            {
                if (!IsRstFromKnownRemote(remoteEndPoint))
                {
                    return;
                }
            }
            if (ValidateRemoteEndPoint(remoteEndPoint))
            {
                _ = HandleInboundAsync(packet).ContinueWith(static (t, _) =>
                {
                    if (t.IsFaulted)
                    {
                        Trace.WriteLine("[UCP PCB] HandleInboundAsync failed: " + t.Exception?.InnerException?.Message);
                    }
                }, null, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                return;
            }

            if (TryVerifyPathChallenge(packet, remoteEndPoint))
            {
                _ = HandleInboundAsync(packet).ContinueWith(static (t, _) =>
                {
                    if (t.IsFaulted)
                    {
                        Trace.WriteLine("[UCP PCB] HandleInboundAsync failed: " + t.Exception?.InnerException?.Message);
                    }
                }, null, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
            }
        }

        public void Dispose()
        {
            lock (_sendBufLock)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
            }
            _cts.Cancel();
            DisposeTimer();

            try
            {
                ReleaseNetworkRegistrations();
            }
            finally
            {
                try
                {
                    TransitionToClosed();
                }
                finally
                {
                    _cts.Dispose();
                    _receiveSignal.Dispose();
                    _sendSpaceSignal.Dispose();
                    _flushLock.Dispose();
                }
            }
        }

        private int ProcessPiggybackedAck(uint ackNumber, long echoTimestamp, long nowMicros)
        {
            List<uint> removeKeys = new List<uint>();
            int deliveredBytes = 0;
            long bestRtt = 0;
            long flightBeforeAck = 0;
            long ackRttForOnAck = 0;
            lock (_sync)
            {

                if (0 == ackNumber)
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

                flightBeforeAck = _flightBytes;
                lock (_sendBufLock)
                {
                    foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                    {
                        OutboundSegment segment = pair.Value;
                        if (segment.Acked) { continue; }

                        if (UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackNumber))
                        {
                            segment.Acked = true;
                            if (segment.InFlight)
                            {
                                _flightBytes -= segment.Payload.Length;
                                if (_flightBytes < 0) { _flightBytes = 0; }
                            }

                            deliveredBytes += segment.Payload.Length;

                            if (segment.SendCount == 1 && segment.LastSendMicros > 0)
                            {
                                long segmentRtt = nowMicros - segment.LastSendMicros;
                                if (segmentRtt < 1) { segmentRtt = 1; }
                                if (segmentRtt > 0)
                                {

                                    long rtoLimit = (long)(_rtoEstimator.CurrentRtoMicros * UcpConstants.RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
                                    if (segmentRtt <= rtoLimit)
                                    {

                                        if (0 == bestRtt || segmentRtt < bestRtt)
                                        {
                                            bestRtt = segmentRtt;
                                        }
                                    }
                                }
                            }

                            removeKeys.Add(pair.Key);
                        }
                        else if (UcpSequenceComparer.IsAfter(segment.SequenceNumber, ackNumber))
                        {

                            break;
                        }
                    }
                }

                for (int i = 0; i < removeKeys.Count; i++)
                {
                    _sackFastRetransmitNotified.Remove(removeKeys[i]);
                    _sackTracking.Remove(removeKeys[i]);
                    lock (_sendBufLock) { _sendBuffer.Remove(removeKeys[i]); }
                }

                PurgeSackSendCountsUnsafe();

                long sampleRtt = bestRtt;
                if (0 < bestRtt)
                {
                    _lastRttMicros = bestRtt;
                    AddRttSampleUnsafe(bestRtt);
                    _rtoEstimator.Update(bestRtt);
                }

                long echoRtt = nowMicros - echoTimestamp;
                if (echoRtt < 1) { echoRtt = 1; }
                if (0 == sampleRtt && echoRtt > 0 && echoRtt <= _rtoEstimator.CurrentRtoMicros)
                {
                    sampleRtt = echoRtt;
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
                    catch (ObjectDisposedException)
                    {

                    }
                }

                bool sendBufferEmpty;
                lock (_sendBufLock) { sendBufferEmpty = 0 == _sendBuffer.Count; }
                if (sendBufferEmpty)
                {
                    _congestion.SetAppLimited(true);
                }

                if (deliveredBytes > 0)
                {
                    AdvanceMeasuredBwSlotUnsafe(nowMicros, deliveredBytes);
                }

                if (_mtuProbePending &&
                    _hasLargestCumulativeAckNumber &&
                    UcpSequenceComparer.IsAfter(_largestCumulativeAckNumber, _mtuProbeSequenceNumber))
                {
                    _mtuProbePending = false;
                    _mtuProbeAcked = true;
                }

                if (deliveredBytes > 0)
                {
                    long edtWstamp = nowMicros + (_pacing?.GetWaitTimeMicros(_config.Mss, nowMicros) ?? 0);
                    _congestion.SetEdtState(nowMicros, edtWstamp);
                    ackRttForOnAck = sampleRtt > 0 ? sampleRtt : _lastRttMicros;
                }

                if (_cidRotatePending &&
                    _hasLargestCumulativeAckNumber &&
                    UcpSequenceComparer.IsAfterOrEqual(_largestCumulativeAckNumber, _cidRotateMarkerSequence))
                {
                    _cidRotatePending = false;
                    _cidRotateMarkerSequence = 0;
                    if (_pendingNewCid != 0)
                    {
                        uint oldCid = _connectionId;
                        _connectionId = _pendingNewCid;
                        _pendingNewCid = 0;
                        lock (_endpointLock) { _extraCids.Add(oldCid); }
                        _deferredOldCid = oldCid;
                        _deferredNewCid = _connectionId;
                    }
                }
            }

            if (_deferredNewCid != 0)
            {
                uint oldCid = _deferredOldCid;
                uint newCid = _deferredNewCid;
                lock (_endpointLock) { _deferredOldCid = 0; _deferredNewCid = 0; }
                if (null != _network)
                {
                    _network.UpdatePcbConnectionId(this, oldCid, newCid);
                }
            }

            if (deliveredBytes > 0)
            {
                lock (_sync)
                {
                    _congestion.OnAck(nowMicros, deliveredBytes, ackRttForOnAck, flightBeforeAck);
                    _pacing.SetRate(_congestion.PacingRateBytesPerSecond, nowMicros);
                }
            }

            return deliveredBytes;
        }

        private void HandleSyn(UcpControlPacket packet)
        {
            bool shouldReply = false;
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            UcpPcb zombiePcb = null;
            bool shouldRegister = false;
            bool shouldCheckCollision = false;
            uint synConnId = 0;
            {
                lock (_sync)
                {

                    _sessionKey = packet.SessionKey;

                    if (_isServerSide && 0 != _sessionKey && null != _network)
                    {
                        shouldRegister = true;
                        synConnId = packet.Header.ConnectionId;
                        if (0 != synConnId)
                        {
                            shouldCheckCollision = true;
                        }
                    }

                    if (packet.HasSequenceNumber)
                    {
                        _nextExpectedSequence = packet.SequenceNumber;
                    }

                    if (_state == UcpConnectionState.Init)
                    {
                        _state = UcpConnectionState.HandshakeSynReceived;
                    }

                    if (null == _remoteEndPoint)
                    {
                        return;
                    }

                    if (_state != UcpConnectionState.Closed)
                    {
                        _synAckSent = true;
                        _synAckSentMicros = NowMicros();
                        shouldReply = true;
                    }
                }
            }

            if (shouldRegister && null != _network)
            {
                UcpPcb existingBySession = _network.TryRegisterSessionKey(_sessionKey, this);
                if (null != existingBySession && existingBySession != this)
                {
                    if (existingBySession.State == UcpConnectionState.Established)
                    {

                        existingBySession.ResetLargestTimestampForReconnection();

                        existingBySession.SetRemoteEndPoint(_remoteEndPoint);
                        existingBySession.DispatchFromNetwork(packet, _remoteEndPoint);
                        return;
                    }
                }

                if (shouldCheckCollision && 0 != synConnId)
                {
                    UcpPcb collidingPcb = _network.LookupByConnectionId(synConnId);
                    if (null != collidingPcb && collidingPcb != this)
                    {
                        zombiePcb = collidingPcb;
                    }
                }
            }

            if (hasAck && packet.AckNumber > 0)
            {
                ProcessPiggybackedAck(packet.AckNumber, 0, NowMicros());
            }

            if (null != zombiePcb)
            {
                try { if (!zombiePcb.Disposed) zombiePcb.Abort(true); } catch { }
            }

            if (shouldReply)
            {
                SendControl(UcpPacketType.SynAck, UcpPacketFlags.None);
            }
        }

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
                ProcessPiggybackedAck(packet.AckNumber, 0, NowMicros());
            }

            SendAckPacket(UcpPacketFlags.None, 0);

            if (shouldEstablish)
            {
                TransitionToEstablished();
            }
        }

        private async Task HandleAckAsync(UcpAckPacket ackPacket)
        {
            bool establishByHandshake = false;
            List<uint> removeKeys = new List<uint>();
            int deliveredBytes = 0;
            long remainingFlight;
            long sampleRtt = 0;
            long echoRtt = 0;
            long nowMicros = NowMicros();
            bool fastRetransmitTriggered = false;

            long flightBeforeAck = 0;

            lock (_sync)
            {

                if (!IsAckPlausibleUnsafe(ackPacket))
                {
                    remainingFlight = _flightBytes;
                    return;
                }

                _remoteWindowBytes = ackPacket.WindowSize;
                _congestion.SetPeerWindow(_remoteWindowBytes);

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
                    if (echoRtt < 1) { echoRtt = 1; }
                }

                _lastAckReceivedMicros = nowMicros;
                _tailLossProbePending = false;

                UpdateDuplicateAckStateUnsafe(ackPacket, nowMicros, out fastRetransmitTriggered);

                int sackIndex = 0;
                List<SackBlock> sackBlocks = ackPacket.SackBlocks;
                bool hasSackBlocks = null != sackBlocks && sackBlocks.Count > 0;
                uint highestSack = hasSackBlocks ? GetHighestSackEnd(sackBlocks) : 0U;

                uint firstMissingSequence = UcpSequenceComparer.Increment(ackPacket.AckNumber);
                flightBeforeAck = _flightBytes;
                lock (_sendBufLock)
                {
                    foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                    {
                        OutboundSegment segment = pair.Value;
                        if (segment.Acked)
                        {
                            continue;
                        }

                        bool acked = UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackPacket.AckNumber);
                        if (!acked && hasSackBlocks)
                        {

                            if (UcpSequenceComparer.IsAfter(segment.SequenceNumber, highestSack))
                            {
                                break;
                            }

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
                        else if (!acked && !hasSackBlocks)
                        {
                            break;
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

                                if (0 == sampleRtt || segmentRtt < sampleRtt)
                                {
                                    sampleRtt = segmentRtt;
                                }
                            }

                            removeKeys.Add(pair.Key);
                            continue;
                        }

                        if (hasSackBlocks)
                        {

                            if (UcpSequenceComparer.IsBefore(segment.SequenceNumber, highestSack))
                            {
                                if (!_sackFastRetransmitNotified.Contains(segment.SequenceNumber))
                                {

                                    SackTrackingState sackState = GetOrCreateSackTrackingUnsafe(segment.SequenceNumber);
                                    if (0 == sackState.MissingAckCount)
                                    {
                                        sackState.FirstMissingAckMicros = nowMicros;
                                    }

                                    sackState.MissingAckCount++;
                                }

                                bool reportedSackHole = IsReportedSackHoleUnsafe(segment.SequenceNumber, ackPacket.AckNumber, sackBlocks);
                                if (segment.SendCount == 1 && !segment.NeedsRetransmit && ShouldFastRetransmitSackHoleUnsafe(segment, firstMissingSequence, highestSack, reportedSackHole, nowMicros))
                                {
                                    segment.NeedsRetransmit = true;

                                    SackTrackingState sackState = GetOrCreateSackTrackingUnsafe(segment.SequenceNumber);
                                    sackState.UrgentRetransmit = true;
                                    _fastRetransmissions++;
                                    _sackFastRetransmitNotified.Add(segment.SequenceNumber);
                                    bool isCongestionLoss = IsCongestionLossUnsafe(segment.SequenceNumber, sampleRtt, nowMicros, 1);
                                    _congestion.OnFastRetransmit(nowMicros, isCongestionLoss, segment.Payload.Length);
                                    TraceLogUnsafe("FastRetransmit sequence=" + segment.SequenceNumber + " sack=true congestion=" + isCongestionLoss);
                                }
                            }
                        }
                    }
                }

                for (int i = 0; i < removeKeys.Count; i++)
                {
                    _sackFastRetransmitNotified.Remove(removeKeys[i]);
                    _sackTracking.Remove(removeKeys[i]);
                    lock (_sendBufLock) { _sendBuffer.Remove(removeKeys[i]); }
                }

                PurgeSackSendCountsUnsafe();

                if (removeKeys.Count > 0)
                {
                    try
                    {
                        _sendSpaceSignal.Release(removeKeys.Count);
                    }
                    catch (SemaphoreFullException)
                    {

                    }
                    catch (ObjectDisposedException)
                    {

                    }
                }

                bool sendBufferEmpty;
                lock (_sendBufLock) { sendBufferEmpty = 0 == _sendBuffer.Count; }
                if (sendBufferEmpty)
                {
                    _congestion.SetAppLimited(true);
                }

                remainingFlight = _flightBytes;

                if (_mtuProbePending &&
                    _hasLargestCumulativeAckNumber &&
                    UcpSequenceComparer.IsAfter(_largestCumulativeAckNumber, _mtuProbeSequenceNumber))
                {
                    _mtuProbePending = false;
                    _mtuProbeAcked = true;
                }

                if (deliveredBytes > 0 && 0 == sampleRtt && echoRtt > 0 && echoRtt <= _rtoEstimator.CurrentRtoMicros)
                {
                    sampleRtt = echoRtt;
                }

                bool acceptableRttSample = sampleRtt > 0 && sampleRtt <= (long)(_rtoEstimator.CurrentRtoMicros * UcpConstants.RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
                if (deliveredBytes > 0 && acceptableRttSample)
                {
                    _lastRttMicros = sampleRtt;
                    AddRttSampleUnsafe(sampleRtt);
                    _rtoEstimator.Update(sampleRtt);
                }

                if (deliveredBytes > 0)
                {
                    AdvanceMeasuredBwSlotUnsafe(nowMicros, deliveredBytes);
                }

                if (_cidRotatePending &&
                    _hasLargestCumulativeAckNumber &&
                    UcpSequenceComparer.IsAfterOrEqual(_largestCumulativeAckNumber, _cidRotateMarkerSequence))
                {
                    _cidRotatePending = false;
                    _cidRotateMarkerSequence = 0;
                    if (_pendingNewCid != 0)
                    {
                        uint oldCid = _connectionId;
                        _connectionId = _pendingNewCid;
                        _pendingNewCid = 0;
                        lock (_endpointLock) { _extraCids.Add(oldCid); }
                        _deferredOldCid2 = oldCid;
                        _deferredNewCid2 = _connectionId;
                    }
                }
            }

            lock (_sync)
            {
                if (deliveredBytes > 0)
                {
                    long edtWstamp = nowMicros + (_pacing?.GetWaitTimeMicros(_config.Mss, nowMicros) ?? 0);
                    _congestion.SetEdtState(nowMicros, edtWstamp);
                    _congestion.OnAck(nowMicros, deliveredBytes, sampleRtt, flightBeforeAck);
                    _pacing.SetRate(_congestion.PacingRateBytesPerSecond, nowMicros);
                }
            }

            if (_deferredNewCid2 != 0)
            {
                uint oldCid = _deferredOldCid2;
                uint newCid = _deferredNewCid2;
                lock (_endpointLock) { _deferredOldCid2 = 0; _deferredNewCid2 = 0; }
                if (null != _network)
                {
                    _network.UpdatePcbConnectionId(this, oldCid, newCid);
                }
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

        private async Task HandleNakAsync(UcpNakPacket nakPacket)
        {
            bool notifiedLoss = false;
            long lostBytes = 0;
            long nowMicros = NowMicros();

            if (nakPacket.AckNumber > 0)
            {
                ProcessPiggybackedAck(nakPacket.AckNumber, 0, nowMicros);
            }

            lock (_sync)
            {
                lock (_sendBufLock)
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
                                SackTrackingState nakSackState = GetOrCreateSackTrackingUnsafe(segment.SequenceNumber);
                                nakSackState.UrgentRetransmit = true;
                                _tailLossProbePending = false;
                                notifiedLoss = true;
                                lostBytes += segment.Payload.Length;
                            }
                        }
                    }
                }

                if (notifiedLoss)
                {
                    bool isCongestionLoss = ClassifyLossesUnsafe(nakPacket.MissingSequences, nowMicros, 0);
                    _congestion.OnNakLoss(nowMicros, lostBytes);
                    TraceLogUnsafe("NAK loss congestion=" + isCongestionLoss + " count=" + nakPacket.MissingSequences.Count);
                }
            }

            await FlushSendQueueAsync().ConfigureAwait(false);
        }

        private bool IsAckPlausibleUnsafe(UcpAckPacket ackPacket)
        {
            if (null == ackPacket)
            {
                return false;
            }

            if (ackPacket.Header.ConnectionId != _connectionId)
            {
                return false;
            }

            if (_largestTimestampSeen > 0 &&
                _largestTimestampSeen - ackPacket.Header.Timestamp > UcpConstants.PAWS_TIMEOUT_MICROS)
            {
                return false;
            }

            if (_hasLargestCumulativeAckNumber && UcpSequenceComparer.IsBefore(ackPacket.AckNumber, _largestCumulativeAckNumber))
            {
                return false;
            }

            if (null != ackPacket.SackBlocks)
            {
                for (int i = 0; i < ackPacket.SackBlocks.Count; i++)
                {
                    SackBlock block = ackPacket.SackBlocks[i];
                    if (UcpSequenceComparer.IsAfter(block.Start, block.End))
                    {
                        return false;
                    }
                }
            }

            return true;
        }

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

        private static void SortSackBlocksUnsafe(List<SackBlock> blocks)
        {
            if (null == blocks || blocks.Count <= 1)
            {
                return;
            }

            // SACK blocks arrive in encoding order (usually already sorted); only sort
            // when they are actually out of order (parity with C++ SortSackBlocks).
            bool alreadyOrdered = true;
            for (int i = 1; i < blocks.Count; ++i)
            {
                if (!UcpSequenceComparer.IsBefore(blocks[i - 1].Start, blocks[i].Start))
                {
                    alreadyOrdered = false;
                    break;
                }
            }
            if (alreadyOrdered)
            {
                return;
            }

            blocks.Sort(delegate (SackBlock left, SackBlock right)
            {
                return UcpSequenceComparer.Instance.Compare(left.Start, right.Start);
            });
        }

        private SackTrackingState GetOrCreateSackTrackingUnsafe(uint sequenceNumber)
        {
            SackTrackingState state;
            if (!_sackTracking.TryGetValue(sequenceNumber, out state))
            {
                PurgeSackTrackingUnsafe();
                state = new SackTrackingState();
                _sackTracking[sequenceNumber] = state;
            }
            return state;
        }

        private bool ShouldFastRetransmitSackHoleUnsafe(OutboundSegment segment, uint firstMissingSequence, uint highestSack, bool reportedSackHole, long nowMicros)
        {
            if (null == segment || segment.LastSendMicros <= 0)
            {
                return false;
            }

            if (_sackFastRetransmitNotified.Contains(segment.SequenceNumber))
            {
                return false;
            }

            if (!_config.EnableAggressiveSackRecovery)
            {
                return false;
            }

            long reorderGraceMicros = GetSackFastRetransmitReorderGraceMicrosUnsafe();
            if (nowMicros - segment.LastSendMicros < reorderGraceMicros)
            {
                return false;
            }

            if (HasPendingFecRepairUnsafe(segment, nowMicros))
            {
                return false;
            }

            bool firstMissing = segment.SequenceNumber == firstMissingSequence;

            int requiredObservations = firstMissing ? UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD : UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD + 1;
            uint distancePastHole = unchecked(highestSack - segment.SequenceNumber);

            if (!firstMissing && reportedSackHole && distancePastHole >= (uint)Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD, _config.FecGroupSize))
            {
                requiredObservations = UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD;
            }

            SackTrackingState sackState;
            int missingAckCount = _sackTracking.TryGetValue(segment.SequenceNumber, out sackState) ? sackState.MissingAckCount : 0;
            if (missingAckCount < requiredObservations)
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

        private bool HasPendingFecRepairUnsafe(OutboundSegment segment, long nowMicros)
        {
            if (null == _fecCodec || null == segment)
            {
                return false;
            }

            SackTrackingState sackState;
            if (!_sackTracking.TryGetValue(segment.SequenceNumber, out sackState) || sackState.FirstMissingAckMicros <= 0)
            {
                return false;
            }

            uint groupBase = _fecCodec.GetGroupBase(segment.SequenceNumber);
            bool repairSent;
            lock (_fecLock) { repairSent = _fecRepairSentGroups.Contains(groupBase); }
            if (!repairSent)
            {
                return false;
            }

            long graceMicros = GetFecFastRetransmitGraceMicrosUnsafe();
            return nowMicros - sackState.FirstMissingAckMicros < graceMicros;
        }

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

        private static bool IsReportedSackHoleUnsafe(uint sequenceNumber, uint cumulativeAckNumber, List<SackBlock> sackBlocks)
        {
            if (null == sackBlocks || 0 == sackBlocks.Count)
            {
                return false;
            }

            bool hasLowerAck = !UcpSequenceComparer.IsBefore(cumulativeAckNumber, sequenceNumber);
            bool hasHigherSack = false;
            for (int i = 0; i < sackBlocks.Count; i++)
            {
                SackBlock block = sackBlocks[i];
                if (UcpSequenceComparer.IsInForwardRange(sequenceNumber, block.Start, block.End))
                {
                    return false;
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

        private void UpdateDuplicateAckStateUnsafe(UcpAckPacket ackPacket, long nowMicros, out bool fastRetransmitTriggered)
        {
            fastRetransmitTriggered = false;
            bool hasSack = null != ackPacket.SackBlocks && ackPacket.SackBlocks.Count > 0;
            bool duplicateAck = _hasLastAckNumber && ackPacket.AckNumber == _lastAckNumber;
            if (duplicateAck)
            {
                _duplicateAckCount++;
                if (_duplicateAckCount >= UcpConstants.DUPLICATE_ACK_THRESHOLD && !_fastRecoveryActive)
                {

                    uint lostSeq = UcpSequenceComparer.Increment(ackPacket.AckNumber);
                    lock (_sendBufLock)
                    {
                        OutboundSegment lostSegment;
                        if (_sendBuffer.TryGetValue(lostSeq, out lostSegment) && !lostSegment.Acked && lostSegment.SendCount == 1 && !lostSegment.NeedsRetransmit)
                        {
                            long rttForFastRetransmit = GetFastRetransmitAgeThresholdUnsafe();
                            if (ShouldTriggerEarlyRetransmitUnsafe() || rttForFastRetransmit <= 0 || nowMicros - lostSegment.LastSendMicros >= rttForFastRetransmit)
                            {
                                lostSegment.NeedsRetransmit = true;

                                SackTrackingState dupAckSackState = GetOrCreateSackTrackingUnsafe(lostSeq);
                                dupAckSackState.UrgentRetransmit = true;
                                _fastRecoveryActive = true;
                                _fastRetransmissions++;
                                fastRetransmitTriggered = true;
                                bool isCongestionLoss = IsCongestionLossUnsafe(lostSeq, 0, nowMicros, 1);
                                _congestion.OnFastRetransmit(nowMicros, isCongestionLoss, lostSegment.Payload.Length);
                                TraceLogUnsafe("FastRetransmit sequence=" + lostSeq + " dupAck=true congestion=" + isCongestionLoss);
                            }
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

        private const double UCP_RANDOM_LOSS_MAX_DEDUPED_EVENTS = 2.0;
        private const int UCP_CONGESTION_LOSS_BURST_THRESHOLD = 3;
        private const int UCP_CONGESTION_LOSS_WINDOW_THRESHOLD = 3;
        private const double UCP_CONGESTION_LOSS_RTT_MULTIPLIER = 1.10;

        private bool IsCongestionLossUnsafe(uint sequenceNumber, long sampleRttMicros, long nowMicros, int contiguousLossCount)
        {
            var sequences = new List<uint>(1) { sequenceNumber };
            return ClassifyLossesUnsafe(sequences, nowMicros, sampleRttMicros, contiguousLossCount);
        }

        private bool ClassifyLossesUnsafe(IList<uint> sequenceNumbers, long nowMicros, long sampleRttMicros)
        {
            return ClassifyLossesUnsafe(sequenceNumbers, nowMicros, sampleRttMicros, GetMaxContiguousLossRunUnsafe(sequenceNumbers));
        }

        private bool ClassifyLossesUnsafe(IList<uint> sequenceNumbers, long nowMicros, long sampleRttMicros, int contiguousLossCount)
        {
            long windowMicros = GetLossClassifierWindowMicrosUnsafe();
            PruneLossEventsUnsafe(nowMicros, windowMicros);

            long rttMicros = sampleRttMicros > 0 ? sampleRttMicros : _lastRttMicros;
            bool addedLoss = false;
            foreach (uint seq in sequenceNumbers)
            {
                if (_recentLossSequences.Add(seq))
                {
                    _recentLossEvents.Enqueue(new LossEvent
                    {
                        SequenceNumber = seq,
                        TimestampMicros = nowMicros,
                        RttMicros = rttMicros
                    });
                    addedLoss = true;
                }
            }

            if (addedLoss)
                PruneLossEventsUnsafe(nowMicros, windowMicros);

            int dedupedLossCount = _recentLossEvents.Count;
            if (dedupedLossCount == 0)
                return false;

            int maxContiguousLossCount = Math.Max(contiguousLossCount, GetMaxContiguousRecentLossRunUnsafe());
            if (dedupedLossCount <= UCP_RANDOM_LOSS_MAX_DEDUPED_EVENTS &&
                maxContiguousLossCount < UCP_CONGESTION_LOSS_BURST_THRESHOLD)
                return false;

            bool clusteredLoss = maxContiguousLossCount >= UCP_CONGESTION_LOSS_BURST_THRESHOLD ||
                dedupedLossCount > UCP_CONGESTION_LOSS_WINDOW_THRESHOLD;
            if (!clusteredLoss)
                return false;

            long medianRtt = GetLossWindowMedianRttMicrosUnsafe();
            long minRtt = GetMinimumObservedRttMicrosUnsafe();
            if (medianRtt <= 0 || minRtt <= 0)
                return false;

            return medianRtt > (long)((double)minRtt * UCP_CONGESTION_LOSS_RTT_MULTIPLIER);
        }

        private long GetLossClassifierWindowMicrosUnsafe()
        {
            long minRtt = GetMinimumObservedRttMicrosUnsafe();
            if (minRtt <= 0)
                minRtt = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros;
            return Math.Max(UcpConstants.MICROS_PER_MILLI, minRtt * 2);
        }

        private void PruneLossEventsUnsafe(long nowMicros, long windowMicros)
        {
            while (_recentLossEvents.Count > 0 &&
                   nowMicros - _recentLossEvents.Peek().TimestampMicros > windowMicros)
            {
                _recentLossSequences.Remove(_recentLossEvents.Dequeue().SequenceNumber);
            }
        }

        private long GetLossWindowMedianRttMicrosUnsafe()
        {
            var samples = new List<long>();
            foreach (var ev in _recentLossEvents)
            {
                if (ev.RttMicros > 0)
                    samples.Add(ev.RttMicros);
            }
            if (samples.Count == 0 && _lastRttMicros > 0)
                samples.Add(_lastRttMicros);
            if (samples.Count == 0)
                return 0;

            samples.Sort();
            return samples[samples.Count / 2];
        }

        private long GetMinimumObservedRttMicrosUnsafe()
        {
            long minRtt = 0;
            foreach (long sample in _rttSamplesMicros)
            {
                if (sample > 0 && (minRtt == 0 || sample < minRtt))
                    minRtt = sample;
            }
            if (minRtt == 0 && _lastRttMicros > 0)
                minRtt = _lastRttMicros;
            return minRtt;
        }

        private int GetMaxContiguousRecentLossRunUnsafe()
        {
            if (_recentLossEvents.Count == 0)
                return 0;

            var seqs = new List<uint>(_recentLossEvents.Count);
            foreach (var ev in _recentLossEvents)
                seqs.Add(ev.SequenceNumber);

            return GetMaxContiguousLossRunUnsafe(seqs);
        }

        private static int GetMaxContiguousLossRunUnsafe(IList<uint> sequenceNumbers)
        {
            if (sequenceNumbers.Count == 0)
                return 0;

            var sorted = new List<uint>(sequenceNumbers);
            sorted.Sort();
            int maxRun = 1;
            int currentRun = 1;
            for (int i = 1; i < sorted.Count; i++)
            {
                if (sorted[i] == sorted[i - 1])
                    continue;
                if (sorted[i] - sorted[i - 1] == 1U)
                {
                    currentRun++;
                    if (currentRun > maxRun)
                        maxRun = currentRun;
                }
                else
                {
                    currentRun = 1;
                }
            }
            return maxRun;
        }

        private long GetFastRetransmitAgeThresholdUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            return rttMicros <= 0 ? 0 : Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros / 8);
        }

        private bool ShouldTriggerEarlyRetransmitUnsafe()
        {
            int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize));
            return inflightSegments > 0 && inflightSegments <= UcpConstants.EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS;
        }

        private bool ShouldAcceptRetransmitRequestUnsafe(OutboundSegment segment, long nowMicros)
        {
            if (null == segment || segment.SendCount <= 1 || segment.LastSendMicros <= 0)
            {
                return true;
            }

            long graceMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _rtoEstimator.CurrentRtoMicros;
            if (graceMicros <= 0)
            {
                return true;
            }

            return nowMicros - segment.LastSendMicros >= graceMicros;
        }

        private double GetRetransmissionRatioUnsafe()
        {
            int total = _sentDataPackets + _retransmittedPackets;
            return 0 == total ? 0d : _retransmittedPackets / (double)total;
        }

        private void TraceLogUnsafe(string message)
        {
            if (_config.EnableDebugLog)
            {
                Trace.WriteLine("[UCP PCB] " + message);
            }
        }

        private void HandleData(UcpDataPacket dataPacket)
        {

            if (UcpConstants.CID_ROTATE_SEQUENCE_MARKER == dataPacket.SequenceNumber)
            {
                HandleCidRotation(dataPacket);
                return;
            }

            if ((dataPacket.Header.Flags & UcpPacketFlags.PathChallenge) == UcpPacketFlags.PathChallenge)
            {
                HandlePathChallenge(dataPacket);
                return;
            }

            List<uint> missing = new List<uint>();
            List<byte[]> readyPayloads = new List<byte[]>();
            bool shouldEstablish = false;
            bool shouldStore = false;
            bool sendImmediateAck = false;
            bool hasPiggybackedAck = (dataPacket.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            bool isMtuProbe = (dataPacket.Header.Flags & UcpPacketFlags.MtuProbe) == UcpPacketFlags.MtuProbe;

            if (hasPiggybackedAck && dataPacket.AckNumber > 0)
            {
                ProcessPiggybackedAck(dataPacket.AckNumber, dataPacket.EchoTimestamp, NowMicros());

                if (dataPacket.WindowSize > 0)
                {
                    _remoteWindowBytes = dataPacket.WindowSize;
                }
            }

            lock (_sync)
            {
                if (dataPacket.WindowSize > 0)
                {
                    _congestion.SetPeerWindow(dataPacket.WindowSize);
                }

                int maxPayloadForPacket = isMtuProbe
                    ? _config.MtuProbeMax - UcpConstants.DATA_HEADER_SIZE_WITH_ACK
                    : _config.MaxPayloadSize;
                if (null == dataPacket.Payload || dataPacket.Payload.Length > maxPayloadForPacket || 0 == dataPacket.FragmentTotal || dataPacket.FragmentIndex >= dataPacket.FragmentTotal)
                {
                    return;
                }

                UcpConnectionState stateLocal = _state;
                if (stateLocal == UcpConnectionState.HandshakeSynReceived && _synAckSent)
                {
                    shouldEstablish = true;
                }

                _lastEchoTimestamp = dataPacket.Header.Timestamp;
                if (UcpSequenceComparer.IsBefore(dataPacket.SequenceNumber, _nextExpectedSequence))
                {

                }
                else
                {

                    int payloadLengthForWindow = isMtuProbe ? 0 : dataPacket.Payload.Length;
                    uint usedBytes = GetReceiveWindowUsedBytesUnsafe();
                    shouldStore = usedBytes + payloadLengthForWindow <= _localReceiveWindowBytes;
                    if (shouldStore && !_recvBuffer.ContainsKey(dataPacket.SequenceNumber))
                    {

                        InboundSegment inbound = new InboundSegment();
                        inbound.SequenceNumber = dataPacket.SequenceNumber;
                        inbound.FragmentTotal = dataPacket.FragmentTotal;
                        inbound.FragmentIndex = dataPacket.FragmentIndex;
                        inbound.Payload = isMtuProbe ? Array.Empty<byte>() : dataPacket.Payload;
                        _recvBuffer[dataPacket.SequenceNumber] = inbound;
                        _recvBufferBytes += inbound.Payload.LongLength;

                        _nakIssued.Remove(dataPacket.SequenceNumber);
                        _missingSequenceCounts.Remove(dataPacket.SequenceNumber);
                        _missingFirstSeenMicros.Remove(dataPacket.SequenceNumber);
                        _lastNakIssuedMicros.Remove(dataPacket.SequenceNumber);

                        if (null != _fecCodec && !isMtuProbe)
                        {
                            _fecFragmentMetadata[dataPacket.SequenceNumber] = new FecFragmentMetadata { FragmentTotal = dataPacket.FragmentTotal, FragmentIndex = dataPacket.FragmentIndex };
                            _fecCodec.FeedDataPacket(dataPacket.SequenceNumber, dataPacket.Payload);

                            TryRecoverFecAroundUnsafe(dataPacket.SequenceNumber, readyPayloads);
                        }
                    }

                    if (shouldStore && UcpSequenceComparer.IsAfter(dataPacket.SequenceNumber, _nextExpectedSequence))
                    {
                        PurgeMissingTrackingUnsafe();
                        // Cache the clock once for the whole gap scan: NowMicros()
                        // is a timer read and the gap can be thousands of slots.
                        long nowMicrosCached = NowMicros();
                        sendImmediateAck = ShouldSendImmediateReorderedAckUnsafe(nowMicrosCached);
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
                                bool missingAgeExpired = HasNakReorderGraceExpiredUnsafe(missingCount, firstSeenMicros, nowMicrosCached);
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

                    while (_recvBuffer.Count > 0)
                    {
                        InboundSegment next;
                        if (!_recvBuffer.TryGetValue(_nextExpectedSequence, out next))
                        {
                            break;
                        }

                        _recvBuffer.Remove(_nextExpectedSequence);
                        _recvBufferBytes -= next.Payload.LongLength;
                        if (_recvBufferBytes < 0) { _recvBufferBytes = 0; }
                        _nakIssued.Remove(_nextExpectedSequence);
                        _missingSequenceCounts.Remove(_nextExpectedSequence);
                        _missingFirstSeenMicros.Remove(_nextExpectedSequence);
                        _lastNakIssuedMicros.Remove(_nextExpectedSequence);
                        _fecFragmentMetadata.Remove(_nextExpectedSequence);
                        _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence);
                        readyPayloads.Add(next.Payload);
                    }

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

        private void TryRecoverFecAroundUnsafe(uint receivedSequenceNumber, List<byte[]> readyPayloads)
        {
            if (null == _fecCodec || null == readyPayloads)
            {
                return;
            }

            long nowMicros = NowMicros();
            uint groupBase = _fecCodec.GetGroupBase(receivedSequenceNumber);
            int groupSize = Math.Max(2, _config.FecGroupSize);
            for (int i = 0; i < groupSize; i++)
            {
                uint candidateSeq = groupBase + (uint)i;
                if (candidateSeq == receivedSequenceNumber || UcpSequenceComparer.IsBefore(candidateSeq, _nextExpectedSequence) || _recvBuffer.ContainsKey(candidateSeq))
                {
                    continue;
                }

                List<UcpFecCodec.RecoveredPacket> recoveredPackets = _fecCodec.TryRecoverPacketsFromStoredRepair(candidateSeq);
                if (null == recoveredPackets || 0 == recoveredPackets.Count)
                {
                    continue;
                }

                long recoveredBytes = 0;
                for (int j = 0; j < recoveredPackets.Count; j++)
                {
                    recoveredBytes += recoveredPackets[j].Payload.Length;
                }

                if (StoreRecoveredFecPacketsUnsafe(recoveredPackets, readyPayloads) > 0)
                {
                    if (recoveredBytes > 0)
                    {
                        lock (_sync)
                        {
                            _congestion.OnFecRecovery(nowMicros, recoveredBytes);
                        }
                    }
                    return;
                }
            }
        }

        private int StoreRecoveredFecPacketsUnsafe(List<UcpFecCodec.RecoveredPacket> recoveredPackets, List<byte[]> readyPayloads)
        {
            if (null == recoveredPackets || 0 == recoveredPackets.Count)
            {
                return 0;
            }

            int stored = 0;
            for (int i = 0; i < recoveredPackets.Count; i++)
            {
                UcpFecCodec.RecoveredPacket recoveredPacket = recoveredPackets[i];
                if (null == recoveredPacket)
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

        private bool StoreRecoveredFecSegmentUnsafe(uint recoveredSeq, byte[] recovered)
        {
            if (null == recovered || UcpSequenceComparer.IsBefore(recoveredSeq, _nextExpectedSequence) || _recvBuffer.ContainsKey(recoveredSeq))
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
            _recvBufferBytes += recovered.LongLength;
            ClearMissingReceiveStateUnsafe(recoveredSeq);
            return true;
        }

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
                _recvBufferBytes -= next.Payload.LongLength;
                if (_recvBufferBytes < 0) { _recvBufferBytes = 0; }
                ClearMissingReceiveStateUnsafe(_nextExpectedSequence);
                _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence);
                readyPayloads.Add(next.Payload);
            }
        }

        private void ClearMissingReceiveStateUnsafe(uint sequenceNumber)
        {
            _nakIssued.Remove(sequenceNumber);
            _missingSequenceCounts.Remove(sequenceNumber);
            _missingFirstSeenMicros.Remove(sequenceNumber);
            _lastNakIssuedMicros.Remove(sequenceNumber);
            _fecFragmentMetadata.Remove(sequenceNumber);
        }

        private bool ShouldIssueNakUnsafe(uint sequenceNumber)
        {
            return !_nakIssued.Contains(sequenceNumber);
        }

        private bool ShouldSendImmediateReorderedAckUnsafe(long nowMicros)
        {
            if (0 == _lastReorderedAckSentMicros || nowMicros - _lastReorderedAckSentMicros >= UcpConstants.REORDERED_ACK_MIN_INTERVAL_MICROS)
            {
                _lastReorderedAckSentMicros = nowMicros;
                return true;
            }

            return false;
        }

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

        private void MarkNakIssuedUnsafe(uint sequenceNumber)
        {
            _nakIssued.Add(sequenceNumber);
            _lastNakIssuedMicros[sequenceNumber] = NowMicros();
        }

        private long GetMissingFirstSeenMicrosUnsafe(uint sequenceNumber)
        {
            long firstSeenMicros;
            if (!_missingFirstSeenMicros.TryGetValue(sequenceNumber, out firstSeenMicros))
            {
                PurgeMissingTrackingUnsafe();
                firstSeenMicros = NowMicros();
                _missingFirstSeenMicros[sequenceNumber] = firstSeenMicros;
            }

            return firstSeenMicros;
        }

        private void HandleFecRepair(UcpFecRepairPacket packet)
        {
            if (null == _fecCodec || null == packet.Payload)
            {
                return;
            }

            long nowMicros = NowMicros();
            uint groupBase = packet.GroupId;
            List<UcpFecCodec.RecoveredPacket> recoveredPackets;
            List<byte[]> fecReadyPayloads = new List<byte[]>();
            int recoveredCount;
            long recoveredBytes = 0;

            lock (_sync)
            {
                // TryRecoverPacketsFromRepair mutates the codec's _recvRepairs /
                // _recvGroups dictionaries (TryRecoverGroup removes groups); it
                // must run under _sync, the same lock FeedDataPacket and
                // TryRecoverFecAroundUnsafe use.  Running it outside the lock
                // (as before) raced with concurrent inbound FEC/data processing
                // in network mode (DispatchFromNetwork is fire-and-forget).
                recoveredPackets = _fecCodec.TryRecoverPacketsFromRepair(packet.Payload, groupBase, packet.GroupIndex);
                for (int i = 0; i < recoveredPackets.Count; i++)
                {
                    recoveredBytes += recoveredPackets[i].Payload.Length;
                }
                recoveredCount = StoreRecoveredFecPacketsUnsafe(recoveredPackets, fecReadyPayloads);
                if (recoveredCount > 0)
                {
                    _congestion.OnFecRecovery(nowMicros, recoveredBytes);
                }
            }

            if (0 == recoveredCount)
            {
                return;
            }

            for (int i = 0; i < fecReadyPayloads.Count; i++)
            {
                EnqueuePayload(fecReadyPayloads[i]);
            }

            SendAckPacket(UcpPacketFlags.None, 0);
        }

        private void HandleFin(UcpControlPacket packet)
        {
            bool needSendOwnFin = false;
            bool hasAck = (packet.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber;
            lock (_sync)
            {
                // A terminal Closed connection must not be resurrected by a late FIN.
                if (_state == UcpConnectionState.Closed)
                {
                    return;
                }
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
                ProcessPiggybackedAck(packet.AckNumber, 0, NowMicros());
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

        private void SendNak(List<uint> missing)
        {
            if (null == missing || 0 == missing.Count)
            {
                return;
            }

            IPEndPoint remoteEndPoint;
            uint cumAck;
            lock (_sync)
            {
                remoteEndPoint = _remoteEndPoint;
                long nowMicros = NowMicros();
                long rttWindowMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.DelayedAckTimeoutMicros;
                if (rttWindowMicros <= 0)
                {
                    rttWindowMicros = UcpConstants.UCP_MIN_ROUND_DURATION_MICROS;
                }

                if (0 == _lastNakWindowMicros || nowMicros - _lastNakWindowMicros >= rttWindowMicros)
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

            if (null == remoteEndPoint) { return; }
            UcpNakPacket packet = new UcpNakPacket();
            packet.Header = CreateHeader(UcpPacketType.Nak, UcpPacketFlags.None, NowMicros());
            packet.AckNumber = cumAck;
            packet.MissingSequences.AddRange(missing);

            byte[] encoded = UcpPacketCodec.Encode(packet);
            _sentNakPackets++;
            _transport.Send(encoded, remoteEndPoint);
        }

        internal void SendControl(UcpPacketType type, UcpPacketFlags flags)
        {
            UcpControlPacket packet = new UcpControlPacket();
            IPEndPoint remoteEndPoint;
            uint cumAck = 0;
            bool hasAck = false;
            ulong sessionKey = 0;
            lock (_sync)
            {
                remoteEndPoint = _remoteEndPoint;
                if (type == UcpPacketType.Syn || type == UcpPacketType.SynAck)
                {
                    packet.HasSequenceNumber = true;
                    lock (_sendBufLock) { packet.SequenceNumber = _nextSendSequence; }
                }

                if (type == UcpPacketType.Syn)
                {
                    sessionKey = _sessionKey;
                }
                else if (type == UcpPacketType.SynAck)
                {
                    sessionKey = _sessionKey;
                }

                if (type != UcpPacketType.Syn && _nextExpectedSequence > 0)
                {
                    hasAck = true;
                    cumAck = unchecked(_nextExpectedSequence - 1U);
                }
            }

            if (null == remoteEndPoint) { return; }
            UcpPacketFlags packetFlags = flags;
            if (hasAck)
            {
                packetFlags |= UcpPacketFlags.HasAckNumber;
                packet.AckNumber = cumAck;
            }

            packet.Header = CreateHeader(type, packetFlags, NowMicros());
            packet.SessionKey = sessionKey;
            byte[] encoded = UcpPacketCodec.Encode(packet);
            if (type == UcpPacketType.Rst)
            {
                _sentRstPackets++;
            }

            _transport.Send(encoded, remoteEndPoint);
        }

        private void SendCidUpdate(uint newCid)
        {
            if (0 == newCid)
            {
                return;
            }

            UcpDataPacket packet = new UcpDataPacket();
            packet.SequenceNumber = UcpConstants.CID_ROTATE_SEQUENCE_MARKER;
            packet.FragmentTotal = 1;
            packet.FragmentIndex = 0;
            packet.Payload = BitConverter.GetBytes(newCid);

            IPEndPoint remoteEndPoint;
            lock (_sync)
            {
                remoteEndPoint = _remoteEndPoint;
                packet.Header = CreateHeader(UcpPacketType.Data,
                    UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber, NowMicros());
                packet.AckNumber = _nextExpectedSequence > 0 ? _nextExpectedSequence - 1U : 0;
                uint usedBytes = GetReceiveWindowUsedBytesUnsafe();
                packet.WindowSize = usedBytes >= _localReceiveWindowBytes ? 0U : _localReceiveWindowBytes - usedBytes;
                packet.EchoTimestamp = _lastEchoTimestamp;
                _sentDataPackets++;
                _bytesSent += sizeof(uint);
            }

            if (null == remoteEndPoint) { return; }
            byte[] encoded = UcpPacketCodec.Encode(packet);
            _transport.Send(encoded, remoteEndPoint);
        }

        private void SendPathChallenge(IPEndPoint target, byte[] challengeData)
        {
            if (null == target || null == challengeData || 8 != challengeData.Length)
            {
                return;
            }

            UcpDataPacket packet = new UcpDataPacket();
            packet.FragmentTotal = 1;
            packet.FragmentIndex = 0;
            packet.Payload = challengeData;

            lock (_sendBufLock)
            {
                packet.Header = CreateHeader(UcpPacketType.Data,
                    UcpPacketFlags.NeedAck | UcpPacketFlags.PathChallenge, NowMicros());
                packet.SequenceNumber = _nextSendSequence;
                _nextSendSequence = UcpSequenceComparer.Increment(_nextSendSequence);
                _sentDataPackets++;
                _bytesSent += challengeData.Length;
            }

            byte[] encoded = UcpPacketCodec.Encode(packet);
            _transport.Send(encoded, target);
        }

        private bool TryVerifyPathChallenge(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (null == packet || null == remoteEndPoint)
            {
                return false;
            }

            if (!(packet is UcpDataPacket dataPacket))
            {
                return false;
            }

            if ((dataPacket.Header.Flags & UcpPacketFlags.PathChallenge) != UcpPacketFlags.PathChallenge)
            {
                return false;
            }

            byte[] payload = dataPacket.Payload;
            if (null == payload || 8 != payload.Length)
            {
                return false;
            }

            lock (_sync)
            {
                if (null == _pathChallengeCandidate || null == _pathChallengeData)
                {
                    return false;
                }

                if (!_pathChallengeCandidate.Equals(remoteEndPoint))
                {
                    return false;
                }

                if (!ByteArrayEquals(_pathChallengeData, payload))
                {
                    return false;
                }

                _remoteEndPoint = _pathChallengeCandidate;
                _pathChanged = true;
                _pathChallengeCandidate = null;
                _pathChallengeData = null;
                _pathChallengeMicros = 0;
                _pathChallengePending = false;
                _pathChallengeAttempts = 0;
                return true;
            }
        }

        private void HandlePathChallenge(UcpDataPacket dataPacket)
        {
            byte[] payload = dataPacket.Payload;
            if (null == payload || 8 != payload.Length)
            {
                return;
            }

            bool isResponse = false;
            byte[] echoPayload = null;
            IPEndPoint targetForEcho = null;

            lock (_sync)
            {
                if (_pathChallengeData != null && ByteArrayEquals(_pathChallengeData, payload))
                {

                    if (_pathChallengeCandidate != null)
                    {
                        _remoteEndPoint = _pathChallengeCandidate;
                        _pathChanged = true;
                    }

                    _pathChallengeCandidate = null;
                    _pathChallengeData = null;
                    _pathChallengeMicros = 0;
                    isResponse = true;
                }
                else
                {

                    echoPayload = payload;
                    targetForEcho = _remoteEndPoint;
                }
            }

            if ((dataPacket.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber && dataPacket.AckNumber > 0)
            {
                ProcessPiggybackedAck(dataPacket.AckNumber, dataPacket.EchoTimestamp, NowMicros());
            }

            if (!isResponse && null != echoPayload && null != targetForEcho)
            {

                UcpDataPacket echo = new UcpDataPacket();
                echo.FragmentTotal = 1;
                echo.FragmentIndex = 0;
                echo.Payload = echoPayload;

                lock (_sendBufLock)
                {
                    echo.Header = CreateHeader(UcpPacketType.Data,
                        UcpPacketFlags.NeedAck | UcpPacketFlags.PathChallenge, NowMicros());
                    echo.SequenceNumber = _nextSendSequence;
                    _nextSendSequence = UcpSequenceComparer.Increment(_nextSendSequence);
                    _sentDataPackets++;
                }

                byte[] encoded = UcpPacketCodec.Encode(echo);
                _transport.Send(encoded, targetForEcho);
            }
        }

        private static bool ByteArrayEquals(byte[] a, byte[] b)
        {
            if (a == b) { return true; }
            if (null == a || null == b) { return false; }
            if (a.Length != b.Length) { return false; }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) { return false; }
            }
            return true;
        }

        private void SendMtuProbe(int probeMtu)
        {
            if (probeMtu <= UcpConstants.MTU_PROBE_BASE || probeMtu > UcpConstants.MTU_PROBE_MAX)
            {
                return;
            }
            UcpDataPacket packet = new UcpDataPacket();
            lock (_sync)
            {
                _mtuProbeSequenceNumber = _nextSendSequence;
                _nextSendSequence = UcpSequenceComparer.Increment(_nextSendSequence);
                packet.Header = CreateHeader(UcpPacketType.Data, UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber | UcpPacketFlags.MtuProbe, NowMicros());
                packet.SequenceNumber = _mtuProbeSequenceNumber;
                packet.FragmentTotal = 1;
                packet.FragmentIndex = 0;
                int payloadBytes = probeMtu - UcpConstants.DATA_HEADER_SIZE_WITH_ACK;
                if (payloadBytes < 1)
                {
                    return;
                }
                packet.Payload = new byte[payloadBytes];
                packet.AckNumber = _nextExpectedSequence > 0 ? _nextExpectedSequence - 1U : 0;
                uint usedBytes = GetReceiveWindowUsedBytesUnsafe();
                packet.WindowSize = usedBytes >= _localReceiveWindowBytes ? 0U : _localReceiveWindowBytes - usedBytes;
                packet.EchoTimestamp = _lastEchoTimestamp;
                _mtuProbePending = true;
                _mtuProbeAcked = false;
                _probeMtu = probeMtu;
            }
            IPEndPoint sendEp = _remoteEndPoint;
            byte[] encoded = UcpPacketCodec.Encode(packet);
            _sentDataPackets++;
            if (null != sendEp)
            {
                _transport.Send(encoded, sendEp);
            }
        }

        private void HandleCidRotation(UcpDataPacket dataPacket)
        {
            if (null == dataPacket.Payload || dataPacket.Payload.Length < sizeof(uint))
            {
                return;
            }
            // CID rotation is authenticated by the established-handshake state:
            // accept rotation only while the connection is Established, so an
            // off-path packet (which cannot be routed to this PCB without the
            // correct ConnId) cannot flip CIDs mid-handshake.
            if (_state != UcpConnectionState.Established)
            {
                return;
            }
            uint newCid = BitConverter.ToUInt32(dataPacket.Payload, 0);
            uint oldCid = dataPacket.Header.ConnectionId;

            lock (_endpointLock)
            {
                if (0 == newCid || newCid == _connectionId)
                {
                    return;
                }
                _extraCids.Add(newCid);
                if (0 != oldCid && oldCid != _connectionId)
                {
                    _extraCids.Remove(oldCid);
                }
            }

            if ((dataPacket.Header.Flags & UcpPacketFlags.HasAckNumber) == UcpPacketFlags.HasAckNumber && dataPacket.AckNumber > 0)
            {
                ProcessPiggybackedAck(dataPacket.AckNumber, dataPacket.EchoTimestamp, NowMicros());

                if (dataPacket.WindowSize > 0)
                {
                    _remoteWindowBytes = dataPacket.WindowSize;
                    lock (_sync)
                    {
                        _congestion.SetPeerWindow(dataPacket.WindowSize);
                    }
                }
            }
        }

        private void SendAckPacket(UcpPacketFlags flags, long overrideEchoTimestamp)
        {
            UcpAckPacket packet;
            IPEndPoint remoteEndPoint;
            lock (_sync)
            {
                remoteEndPoint = _remoteEndPoint;
                packet = new UcpAckPacket();
                packet.Header = CreateHeader(UcpPacketType.Ack, flags, NowMicros());

                packet.AckNumber = _nextExpectedSequence > 0 ? unchecked(_nextExpectedSequence - 1U) : 0;

                List<SackBlock> rawBlocks = _sackGenerator.Generate(_nextExpectedSequence, _recvBuffer.Keys, _config.MaxAckSackBlocks);
                List<SackBlock> filteredBlocks = new List<SackBlock>(rawBlocks.Count);
                for (int i = 0; i < rawBlocks.Count; i++)
                {

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

                uint usedBytes = GetReceiveWindowUsedBytesUnsafe();
                packet.WindowSize = usedBytes >= _localReceiveWindowBytes ? 0U : _localReceiveWindowBytes - usedBytes;
                packet.EchoTimestamp = overrideEchoTimestamp < 0 ? 0 : (overrideEchoTimestamp > 0 ? overrideEchoTimestamp : _lastEchoTimestamp);
                _lastAckSentMicros = packet.Header.Timestamp;
            }

            if (null == remoteEndPoint) { return; }
            byte[] encoded = UcpPacketCodec.Encode(packet);
            _sentAckPackets++;
            _transport.Send(encoded, remoteEndPoint);
        }

        private void ScheduleAck()
        {

            if (_config.DelayedAckTimeoutMicros <= 0)
            {
                SendAckPacket(UcpPacketFlags.None, 0);
                return;
            }

            long ackDelayMicros = _config.DelayedAckTimeoutMicros;

            if (_lastRttMicros > UcpConstants.HIGH_LATENCY_THRESHOLD_MICROS)
            {
                ackDelayMicros = Math.Min(ackDelayMicros, UcpConstants.MICROS_PER_MILLI);
            }

            if (null == _network && _transport is UdpSocketTransport && ackDelayMicros < UcpConstants.MICROS_PER_MILLI)
            {
                SendAckPacket(UcpPacketFlags.None, 0);
                return;
            }

            lock (_sendBufLock) { if (_ackDelayed) return; _ackDelayed = true; }

            if (null == _network)
            {
                Task.Run(async delegate
                {
                    try
                    {
                        await Task.Delay((int)Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, ackDelayMicros / UcpConstants.MICROS_PER_MILLI), _cts.Token).ConfigureAwait(false);
                        _ackDelayed = false;

                        SendAckPacket(UcpPacketFlags.None, 0);
                    }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        Trace.WriteLine("[UCP PCB] ScheduleAck SendAckPacket failed: " + ex.Message);
                    }
                });
                return;
            }

            _ackTimerId = _network.AddTimer(_network.CurrentTimeUs + ackDelayMicros, delegate
            {
                _ackDelayed = false;
                SendAckPacket(UcpPacketFlags.None, 0);
            });
        }

        private async Task FlushSendQueueAsync()
        {
            try
            {
                await _flushLock.WaitAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            try
            {
                const int MaxSegmentsPerBurst = 16;
                List<OutboundSegment> segmentsToSend = new List<OutboundSegment>(MaxSegmentsPerBurst);
                while (!_cts.IsCancellationRequested)
                {
                    segmentsToSend.Clear();
                    long nowMicros = NowMicros();
                    long waitMicros = 0;
                    bool windowLimited = false;
                    uint piggyCumAck = 0;
                    List<SackBlock> piggySackBlocks = null;
                    uint piggyWindow = 0;
                    long piggyEcho = 0;
                    IPEndPoint remoteEpSnapshot = null;

                    lock (_sync)
                    {

                        int windowBytes = GetSendWindowBytesUnsafe();
                        int piggybackedAckOverhead = UcpConstants.DATA_HEADER_SIZE_WITH_ACK - UcpConstants.DataHeaderSize;
                        lock (_sendBufLock)
                        {
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
                                    windowLimited = true;
                                    break;
                                }

                                int packetSize = UcpConstants.DataHeaderSize + piggybackedAckOverhead + segment.Payload.Length;

                                SackTrackingState flushSackState;
                                bool hasUrgentFlag = _sackTracking.TryGetValue(segment.SequenceNumber, out flushSackState) && flushSackState.UrgentRetransmit;
                                bool urgentRecovery = segment.NeedsRetransmit && segment.SendCount > 0 && hasUrgentFlag && CanUseUrgentRecoveryUnsafe(nowMicros);

                                if (_useFairQueue && _fairQueueCreditBytes < packetSize && !urgentRecovery)
                                {
                                    break;
                                }

                                if (urgentRecovery)
                                {
                                    _pacing.ForceConsume(packetSize, nowMicros);
                                    _urgentRecoveryPacketsInWindow++;
                                }

                                else if (!_pacing.TryConsume(packetSize, nowMicros))
                                {

                                    waitMicros = _pacing.GetWaitTimeMicros(packetSize, nowMicros);
                                    break;
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

                                if (_sackTracking.TryGetValue(segment.SequenceNumber, out SackTrackingState clearSackState))
                                {
                                    clearSackState.UrgentRetransmit = false;
                                }
                                if (0 == segment.SendCount)
                                {
                                    _flightBytes += segment.Payload.Length;
                                }

                                segment.SendCount++;
                                _congestion.OnPacketSent(nowMicros, segment.SendCount > 1);
                                segment.LastSendMicros = nowMicros;
                                segmentsToSend.Add(segment);
                                if (segmentsToSend.Count >= MaxSegmentsPerBurst) break;
                            }

                            piggyCumAck = _nextExpectedSequence > 0 ? unchecked(_nextExpectedSequence - 1U) : 0;
                            piggySackBlocks = piggyCumAck > 0 ? _sackGenerator.Generate(_nextExpectedSequence, _recvBuffer.Keys, _config.MaxAckSackBlocks) : null;
                            piggyWindow = piggyCumAck > 0
                                ? (_localReceiveWindowBytes > GetReceiveWindowUsedBytesUnsafe()
                                    ? _localReceiveWindowBytes - GetReceiveWindowUsedBytesUnsafe()
                                    : 0U)
                                : _localReceiveWindowBytes;
                            piggyEcho = _lastEchoTimestamp;
                            _lastAckSentMicros = nowMicros;

                            remoteEpSnapshot = _remoteEndPoint;

                            // Sort only when the burst mixes priorities (parity
                            // with C++ FlushSendQueueAsync); single-priority bursts
                            // are already in sequence order.
                            if (segmentsToSend.Count > 1 &&
                                segmentsToSend[0].Priority != segmentsToSend[segmentsToSend.Count - 1].Priority)
                            {
                                segmentsToSend.Sort((a, b) =>
                                {
                                    int priorityCmp = b.Priority.CompareTo(a.Priority);
                                    if (0 != priorityCmp) { return priorityCmp; }

                                    return UcpSequenceComparer.Instance.Compare(a.SequenceNumber, b.SequenceNumber);
                                });
                            }

                            if (piggyCumAck > 0)
                            {
                                _ackDelayed = false;
                                if (null != _network && 0 != _ackTimerId)
                                {
                                    _network.CancelTimer(_ackTimerId);
                                    _ackTimerId = 0;
                                }
                            }
                        }

                        if (0 == segmentsToSend.Count)
                        {

                            if (piggyCumAck > 0 && _ackDelayed)
                            {
                                _ackDelayed = false;
                                if (null != _network && 0 != _ackTimerId)
                                {
                                    _network.CancelTimer(_ackTimerId);
                                    _ackTimerId = 0;
                                }
                                SendAckPacket(UcpPacketFlags.None, piggyEcho);
                            }

                            if (waitMicros > 0)
                            {
                                ScheduleDelayedFlush(waitMicros);
                            }
                            else if (windowLimited)
                            {
                                // Send window is full but the loop produced nothing to
                                // send this pass (all queued retransmits already in
                                // flight, new segments window-limited). Wait a short
                                // interval for ACKs to free window space instead of
                                // exiting: RequestFlush on ACK will re-enter with a
                                // larger window.
                                ScheduleDelayedFlush(UcpConstants.DEFAULT_PACING_WAIT_MICROS);
                            }

                            break;
                        }

                        for (int i = 0; i < segmentsToSend.Count; i++)
                        {
                            OutboundSegment segment = segmentsToSend[i];
                            UcpDataPacket packet = new UcpDataPacket();

                            UcpPacketFlags pktFlags = segment.SendCount > 1
                                ? UcpPacketFlags.NeedAck | UcpPacketFlags.Retransmit | UcpPacketFlags.HasAckNumber
                                : UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber;

                            packet.Header = CreateHeader(UcpPacketType.Data, pktFlags, nowMicros);
                            packet.SequenceNumber = segment.SequenceNumber;
                            packet.FragmentTotal = segment.FragmentTotal;
                            packet.FragmentIndex = segment.FragmentIndex;
                            packet.Payload = segment.Payload;

                            packet.AckNumber = piggyCumAck;
                            if (null != piggySackBlocks && piggySackBlocks.Count > 0)
                            {
                                // Encode reads SackBlocks only; share the list across
                                // segments in this burst instead of copying per packet.
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
                                _bytesSent += segment.Payload.Length;
                            }
                            var ep = remoteEpSnapshot;
                            if (ep == null) break;
                            _transport.Send(encoded, ep);

                            if (null != _fecCodec && segment.SendCount <= 1)
                            {

                                List<byte[]> repairsToSend = null;
                                uint repairGroupBase = 0;
                                bool shouldSendRepairs = false;
                                lock (_sync)
                                {
                                    uint fecGroupBaseSeq = _fecCodec.GetGroupBase(segment.SequenceNumber);
                                    List<byte[]> repairs = _fecCodec.TryEncodeRepairs(segment.SequenceNumber, segment.Payload);
                                    if (null != repairs && repairs.Count > 0)
                                    {
                                        if (_congestion.EstimatedLossPercent >= UcpConstants.ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT)
                                        {
                                            repairsToSend = repairs;
                                            repairGroupBase = fecGroupBaseSeq;
                                            shouldSendRepairs = true;
                                        }
                                    }
                                }
                                if (shouldSendRepairs && null != repairsToSend)
                                {
                                    for (int repairIndex = 0; repairIndex < repairsToSend.Count; repairIndex++)
                                    {
                                        UcpFecRepairPacket repairPacket = new UcpFecRepairPacket();
                                        repairPacket.Header = CreateHeader(UcpPacketType.FecRepair, UcpPacketFlags.None, nowMicros);
                                        repairPacket.GroupId = repairGroupBase;
                                        repairPacket.GroupIndex = (byte)repairIndex;
                                        repairPacket.Payload = repairsToSend[repairIndex];
                                        byte[] encodedRepair = UcpPacketCodec.Encode(repairPacket);
                                        IPEndPoint repairEp = _remoteEndPoint;
                                        if (repairEp == null) break;
                                        _transport.Send(encodedRepair, repairEp);
                                    }
                                    lock (_fecLock) { _fecRepairSentGroups.Add(repairGroupBase); }
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                try { _flushLock.Release(); } catch (ObjectDisposedException) { }
            }
        }

        private void ScheduleDelayedFlush(long waitMicros)
        {
            int delayMs;
            long flushDeadlineUs = unchecked(NowMicros() + waitMicros);
            lock (_sendBufLock)
            {
                if (_flushDelayed)
                {
                    if (_flushDeadlineUs <= NowMicros() || flushDeadlineUs >= _flushDeadlineUs)
                    {
                        return;
                    }
                    _flushDeadlineUs = flushDeadlineUs;
                }
                else
                {
                    _flushDelayed = true;
                    _flushDeadlineUs = flushDeadlineUs;
                }
                delayMs = (int)Math.Ceiling(waitMicros / (double)UcpConstants.MICROS_PER_MILLI);
            }

            if (delayMs < UcpConstants.MIN_TIMER_WAIT_MILLISECONDS)
            {
                delayMs = UcpConstants.MIN_TIMER_WAIT_MILLISECONDS;
            }

            if (null == _network)
            {

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
                    catch (Exception)
                    {
                        _flushDelayed = false;
                    }
                });
                return;
            }

            var timerId = _network.AddTimer(_network.NowMicroseconds + (delayMs * UcpConstants.MICROS_PER_MILLI), delegate
            {
                lock (_sendBufLock) { _flushDelayed = false; _flushTimerId = 0; }
                _ = FlushSendQueueAsync().ContinueWith(static (t, _) =>
                {
                    if (t.IsFaulted)
                    {
                        Trace.WriteLine("[UCP PCB] Delayed FlushSendQueueAsync failed: " + t.Exception?.InnerException?.Message);
                    }
                }, null, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
            });
            _flushTimerId = timerId;
        }

        private void EnqueuePayload(byte[] payload)
        {
            if (null == payload || 0 == payload.Length)
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
            if (null != dataReceived)
            {
                try { dataReceived(payload, 0, payload.Length); } catch (Exception) { }
            }

            try { _receiveSignal.Release(); } catch (ObjectDisposedException) { }
        }

        private int GetSendWindowBytesUnsafe()
        {
            int receiveWindowBytes = (int)Math.Min(_remoteWindowBytes, int.MaxValue);
            int congestionWindowBytes = (int)_congestion.CongestionWindowBytes;
            int windowBytes;
            if (_congestion.Mode == UcpMode.Startup && !_congestion.FullBwReached)
            {
                windowBytes = receiveWindowBytes;
            }
            else
            {
                windowBytes = congestionWindowBytes < receiveWindowBytes ? congestionWindowBytes : receiveWindowBytes;
            }
            if (windowBytes < 0)
            {
                windowBytes = 0;
            }

            return windowBytes;
        }

        private bool CanUseUrgentRecoveryUnsafe(long nowMicros)
        {
            long windowMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros;
            if (windowMicros <= 0)
            {
                windowMicros = UcpConstants.DEFAULT_RTO_MICROS;
            }

            if (0 == _urgentRecoveryWindowMicros || nowMicros - _urgentRecoveryWindowMicros >= windowMicros)
            {
                _urgentRecoveryWindowMicros = nowMicros;
                _urgentRecoveryPacketsInWindow = 0;
            }

            return _urgentRecoveryPacketsInWindow < UcpConstants.URGENT_RETRANSMIT_BUDGET_PER_RTT;
        }

        private bool IsNearDisconnectTimeoutUnsafe(long nowMicros)
        {
            if (_config.DisconnectTimeoutMicros <= 0)
            {
                return false;
            }

            long idleMicros = nowMicros - _lastPeerAliveMicros;
            return idleMicros >= _config.DisconnectTimeoutMicros * UcpConstants.URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT / 100L;
        }

        private uint GetReceiveWindowUsedBytesUnsafe()
        {
            long usedBytes = _queuedReceiveBytes + _recvBufferBytes;

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

        private UcpCommonHeader CreateHeader(UcpPacketType type, UcpPacketFlags flags, long timestampMicros)
        {
            UcpCommonHeader header = new UcpCommonHeader();
            header.Type = type;
            header.Flags = flags;
            header.ConnectionId = _connectionId;
            header.Timestamp = timestampMicros;
            return header;
        }

        private int _timerRunning;

        private void OnTimer(object state)
        {
            if (_disposed) return;

            if (Interlocked.Exchange(ref _timerRunning, 1) != 0) return;

            try
            {
                OnTimerSync(NowMicros());
            }
            catch (Exception ex)
            {
                Trace.WriteLine("[UCP PCB] OnTimerSync failed: " + ex.Message);
            }
            finally
            {
                _timerRunning = 0;
            }

            if (null != _network)
            {
                ScheduleTimer();
            }
        }

        private void ScheduleTimer()
        {
            if (null == _network || _disposed)
            {
                return;
            }

            long intervalMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.TimerIntervalMilliseconds) * UcpConstants.MICROS_PER_MILLI;
            _timerId = _network.AddTimer(_network.NowMicroseconds + intervalMicros, delegate { OnTimer(null); });
        }

        private void OnTimerSync(long nowMicros)
        {
            bool timedOut = false;
            bool sendKeepAlive = false;
            bool retransmitSynAck = false;
            bool maxRetransmissionsExceeded = false;
            bool timedOutForCongestion = false;
            bool tailLossProbe = false;
            bool closeDrained = false;
            bool closeTimedOut = false;
            List<uint> missingForNak = new List<uint>();

            lock (_sync)
            {
                PurgeSackTrackingUnsafe();
                PurgeMissingTrackingUnsafe();

                if (_pathChanged && _state == UcpConnectionState.Established)
                {
                    _pathChanged = false;
                    _probeMin = UcpConstants.MTU_PROBE_BASE;
                    _probeMax = UcpConstants.MTU_PROBE_MAX;
                    _mtuProbePending = false;
                    _mtuProbeAcked = false;
                    _lastMtuConvergeMicros = 0;
                    _congestion.OnPathChange(nowMicros);
                }

                int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize));
                long rtoLostBytes = 0;
                int rtoRetransmitBudget = UcpConstants.RTO_RETRANSMIT_BUDGET_PER_TICK;

                lock (_sendBufLock)
                {
                    foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                    {
                        OutboundSegment segment = pair.Value;
                        if (!segment.InFlight || segment.Acked || segment.NeedsRetransmit)
                        {
                            continue;
                        }

                        if (nowMicros - segment.LastSendMicros >= _rtoEstimator.CurrentRtoMicros)
                        {
                            // NOTE: previously this suppressed RTO retransmission when
                            // the segment was SACK-reported missing and an ACK had
                            // arrived recently, on the assumption that SACK-based fast
                            // retransmit would cover the gap. On a lossy path the fast
                            // retransmit may never fire (dup-ACK threshold / reorder
                            // grace not met), which deadlocked the flow: the sender
                            // stopped retransmitting (RTO suppressed) while the
                            // receiver waited forever for the missing segment. RTO is
                            // the last-resort recovery and must always be able to fire;
                            // the SACK fast-retransmit path still runs first and is
                            // strictly faster when its conditions are met.
                            if (rtoRetransmitBudget <= 0)
                            {
                                break;
                            }

                            bool segmentTimedOutForCongestion = IsCongestionLossUnsafe(segment.SequenceNumber, 0, nowMicros, 1);

                            if (segment.SendCount >= _config.MaxRetransmissions && segmentTimedOutForCongestion)
                            {
                                _timeoutRetransmissions++;
                                maxRetransmissionsExceeded = true;
                                break;
                            }

                            segment.NeedsRetransmit = true;

                            GetOrCreateSackTrackingUnsafe(segment.SequenceNumber).UrgentRetransmit = true;
                            timedOut = true;
                            rtoLostBytes += segment.Payload.Length;
                            rtoRetransmitBudget--;
                            timedOutForCongestion = timedOutForCongestion || segmentTimedOutForCongestion;
                            _timeoutRetransmissions++;
                        }
                    }
                }

                if (!timedOut && !_tailLossProbePending && inflightSegments > 0 && inflightSegments <= UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS)
                {
                    long tlpTimeoutMicros = _rtoEstimator.SmoothedRttMicros > 0
                        ? (long)Math.Ceiling(_rtoEstimator.SmoothedRttMicros * UcpConstants.TLP_TIMEOUT_RTT_RATIO)
                        : _rtoEstimator.CurrentRtoMicros;
                    if (_lastAckReceivedMicros > 0 && nowMicros - _lastAckReceivedMicros >= tlpTimeoutMicros)
                    {

                        lock (_sendBufLock)
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

                                GetOrCreateSackTrackingUnsafe(segment.SequenceNumber).UrgentRetransmit = IsNearDisconnectTimeoutUnsafe(nowMicros);
                                _tailLossProbePending = true;
                                tailLossProbe = true;
                                break;
                            }
                        }
                    }
                }

                if (!timedOut && !_tailLossProbePending && inflightSegments > UcpConstants.TLP_MAX_INFLIGHT_SEGMENTS
                    && _lastAckReceivedMicros > 0 && _rtoEstimator.SmoothedRttMicros > 0
                    && nowMicros - _lastAckReceivedMicros >= _rtoEstimator.SmoothedRttMicros * 3)
                {

                    uint highestSeq = 0;
                    OutboundSegment newest = null;
                    lock (_sendBufLock)
                    {
                        foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                        {
                            if (pair.Value.Acked || !pair.Value.InFlight || pair.Value.NeedsRetransmit) { continue; }
                            if (null == newest || UcpSequenceComparer.IsAfter(pair.Key, highestSeq))
                            {
                                highestSeq = pair.Key;
                                newest = pair.Value;
                            }
                        }
                    }
                    if (null != newest)
                    {
                        newest.NeedsRetransmit = true;

                        GetOrCreateSackTrackingUnsafe(newest.SequenceNumber).UrgentRetransmit = true;
                        _tailLossProbePending = true;
                        tailLossProbe = true;
                    }
                }

                if (timedOut)
                {
                    _congestion.OnPacketLoss(nowMicros, GetRetransmissionRatioUnsafe(), timedOutForCongestion, rtoLostBytes);
                    TraceLogUnsafe("RTO loss congestion=" + timedOutForCongestion + " rto=" + _rtoEstimator.CurrentRtoMicros);
                    if (timedOutForCongestion)
                    {
                        _rtoEstimator.Backoff();
                    }
                }

                PruneStaleNakTrackingUnsafe();

                CollectMissingForNakUnsafe(missingForNak, nowMicros);

                // Keepalive is driven purely by SEND idle time (_lastAckSentMicros). It MUST NOT
                // depend on receive activity: if it did, a live peer that merely receives our
                // keepalives would have its own receive timestamps refreshed and would never emit
                // its own keepalives, so this side could never observe proof that the peer is
                // alive. With a send-idle-only trigger BOTH peers emit a keepalive every
                // KeepAliveInterval on their own schedule: each side continuously receives
                // keepalives from a live peer and refreshes _lastPeerAliveMicros, while a dead
                // peer stops sending and is torn down by the disconnect check below.
                if (_state == UcpConnectionState.Established && nowMicros - _lastAckSentMicros >= _config.KeepAliveIntervalMicros)
                {
                    sendKeepAlive = true;
                }

                if (_isServerSide && _state == UcpConnectionState.HandshakeSynReceived && _synAckSent && nowMicros - _synAckSentMicros >= _rtoEstimator.CurrentRtoMicros)
                {
                    _synAckSentMicros = nowMicros;
                    retransmitSynAck = true;
                }

                if (_hasPendingCloseCallback && !_finAcked && _state != UcpConnectionState.Closed)
                {
                    long closeDeadlineMicros = _closeStartMicros + _config.DisconnectTimeoutMicros;
                    if (nowMicros >= closeDeadlineMicros)
                    {
                        closeTimedOut = true;
                    }
                    else if (!_finSent)
                    {
                        bool sendBufferEmpty;
                        lock (_sendBufLock) { sendBufferEmpty = 0 == _sendBuffer.Count; }
                        if (sendBufferEmpty)
                        {
                            _finSent = true;
                            _finSentMicros = nowMicros;
                            _finRetransmitCount = 1;
                            _state = UcpConnectionState.ClosingFinSent;
                            closeDrained = true;
                        }
                    }
                    else
                    {
                        if (nowMicros - _finSentMicros >= _rtoEstimator.CurrentRtoMicros)
                        {
                            if (_finRetransmitCount >= _config.MaxRetransmissions)
                            {
                                closeTimedOut = true;
                            }
                            else
                            {
                                _finSentMicros = nowMicros;
                                _finRetransmitCount++;
                                closeDrained = true;
                            }
                        }
                    }
                }
            }

            if (maxRetransmissionsExceeded)
            {
                TransitionToClosed();
                return;
            }

            if (timedOut || tailLossProbe)
            {
                RequestFlush();
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
                SendAckPacket(UcpPacketFlags.None, -1);
            }

            if (closeDrained)
            {
                SendControl(UcpPacketType.Fin, UcpPacketFlags.None);
            }
            if (closeTimedOut)
            {
                if (null != _remoteEndPoint)
                {
                    SendControl(UcpPacketType.Rst, UcpPacketFlags.None);
                }
                TransitionToClosed();
                return;
            }

            bool shouldSendCidUpdate = false;
            uint cidUpdatePayload = 0;

            lock (_sync)
            {
                if (_state == UcpConnectionState.Established && 0 == _lastCidRotateMicros)
                {
                    _lastCidRotateMicros = nowMicros;
                }

                if (_state == UcpConnectionState.Established &&
                    !_cidRotatePending &&
                    _lastCidRotateMicros > 0 &&
                    nowMicros - _lastCidRotateMicros >= UcpConstants.CID_ROTATE_INTERVAL_MICROS &&
                    null != _remoteEndPoint)
                {
                    _pendingNewCid = NextConnectionId();
                    lock (_endpointLock) { _extraCids.Add(_pendingNewCid); }
                    _cidRotatePending = true;
                    _cidRotateMarkerSequence = _nextSendSequence;
                    _lastCidRotateMicros = nowMicros;
                    shouldSendCidUpdate = true;
                    cidUpdatePayload = _pendingNewCid;
                }

                if (_lastCidRotateMicros > 0 &&
                    nowMicros - _lastCidRotateMicros >= UcpConstants.CID_RETIRE_AGE_MICROS)
                {
                    lock (_endpointLock) { _extraCids.Clear(); }
                }

                if (_cidRotatePending && nowMicros - _lastCidRotateMicros >= UcpConstants.CID_ROTATE_ACK_TIMEOUT_MICROS)
                {
                    _cidRotatePending = false;
                    _cidRotateMarkerSequence = 0;
                }

                if (_pathChallengeData != null && nowMicros - _pathChallengeMicros >= UcpConstants.PATH_CHALLENGE_TIMEOUT_MICROS)
                {
                    _pathChallengeCandidate = null;
                    _pathChallengeData = null;
                    _pathChallengeMicros = 0;
                    _pathChallengePending = false;
                }
            }

            if (shouldSendCidUpdate)
            {
                SendCidUpdate(cidUpdatePayload);
            }

            bool shouldSendMtuProbe = false;
            int nextProbeMtu = 0;
            lock (_sync)
            {
                if (_state == UcpConnectionState.Established && _config.EnableMtuDiscovery)
                {
                    if (_mtuProbePending)
                    {
                        if (nowMicros - _lastMtuProbeMicros >= _config.MtuProbeTimeoutMicros)
                        {
                            _mtuProbePending = false;
                            _probeMax = _probeMtu;
                        }
                    }
                    else if (_mtuProbeAcked)
                    {
                        _mtuProbeAcked = false;
                        _probeMin = _probeMtu;
                    }
                    if (!_mtuProbePending && _probeMax - _probeMin > 8)
                    {
                        _probeMtu = (_probeMin + _probeMax) / 2;
                        _lastMtuProbeMicros = nowMicros;
                        shouldSendMtuProbe = true;
                        nextProbeMtu = _probeMtu;
                    }
                    else if (!_mtuProbePending && _probeMax - _probeMin <= 8)
                    {
                        _currentMtu = _probeMin;
                        if (0 == _lastMtuConvergeMicros)
                        {
                            _lastMtuConvergeMicros = nowMicros;
                        }
                        if (nowMicros - _lastMtuConvergeMicros >= _config.MtuProbeIntervalMicros)
                        {
                            _probeMin = UcpConstants.MTU_PROBE_BASE;
                            _probeMax = UcpConstants.MTU_PROBE_MAX;
                            _lastMtuConvergeMicros = 0;
                            _probeMtu = (_probeMin + _probeMax) / 2;
                            _lastMtuProbeMicros = nowMicros;
                            shouldSendMtuProbe = true;
                            nextProbeMtu = _probeMtu;
                        }
                    }
                }
            }
            if (shouldSendMtuProbe)
            {
                SendMtuProbe(nextProbeMtu);
            }

            if ((_state == UcpConnectionState.HandshakeSynSent || _state == UcpConnectionState.HandshakeSynReceived || _state == UcpConnectionState.Established || _state == UcpConnectionState.ClosingFinSent || _state == UcpConnectionState.ClosingFinReceived)
                && nowMicros - _lastPeerAliveMicros >= _config.DisconnectTimeoutMicros)
            {
                TransitionToClosed();
                return;
            }

            if (_state == UcpConnectionState.Closed)
            {
                TransitionToClosed();
            }
        }

        private void CollectMissingForNakUnsafe(List<uint> missing, long nowMicros)
        {
            if (null == missing || 0 == _recvBuffer.Count || _recvBuffer.ContainsKey(_nextExpectedSequence))
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

        private void PruneStaleNakTrackingUnsafe()
        {
            if (_nextExpectedSequence == 0 || (_nakIssued.Count == 0 && _missingSequenceCounts.Count == 0
                && _missingFirstSeenMicros.Count == 0 && _lastNakIssuedMicros.Count == 0))
            {
                return;
            }

            const uint maxStaleDistance = 1000;
            uint threshold = _nextExpectedSequence > maxStaleDistance
                ? _nextExpectedSequence - maxStaleDistance
                : 0;

            PruneStaleHashSetUnsafe(_nakIssued, threshold);
            PruneStaleDictionaryUnsafe(_missingSequenceCounts, threshold);
            PruneStaleDictionaryUnsafe(_missingFirstSeenMicros, threshold);
            PruneStaleDictionaryUnsafe(_lastNakIssuedMicros, threshold);
        }

        private static void PruneStaleDictionaryUnsafe<T>(Dictionary<uint, T> dict, uint threshold)
        {
            if (dict.Count == 0) return;

            List<uint> stale = null;
            foreach (uint key in dict.Keys)
            {
                if (UcpSequenceComparer.IsBefore(key, threshold))
                {
                    if (stale == null) stale = new List<uint>();
                    stale.Add(key);
                }
            }

            if (stale != null)
            {
                for (int i = 0; i < stale.Count; i++)
                {
                    dict.Remove(stale[i]);
                }
            }
        }

        private static void PruneStaleHashSetUnsafe(HashSet<uint> set, uint threshold)
        {
            if (set.Count == 0) return;

            List<uint> stale = null;
            foreach (uint key in set)
            {
                if (UcpSequenceComparer.IsBefore(key, threshold))
                {
                    if (stale == null) stale = new List<uint>();
                    stale.Add(key);
                }
            }

            if (stale != null)
            {
                for (int i = 0; i < stale.Count; i++)
                {
                    set.Remove(stale[i]);
                }
            }
        }

        private void AdvanceMeasuredBwSlotUnsafe(long nowMicros, int deliveredBytes)
        {
            const long slotDuration = 200_000L;
            long slotStart = nowMicros - (nowMicros % slotDuration);
            if (_measuredBwSlotStart[_measuredBwSlotIndex] != slotStart)
            {

                int targetIndex = (int)((nowMicros / slotDuration) % _measuredBwSlots.Length);
                while (_measuredBwSlotIndex != targetIndex)
                {
                    _measuredBwSlotIndex = (_measuredBwSlotIndex + 1) % _measuredBwSlots.Length;
                    _measuredBwSlots[_measuredBwSlotIndex] = 0;
                    _measuredBwSlotStart[_measuredBwSlotIndex] = -1L;
                }

                _measuredBwSlots[_measuredBwSlotIndex] = 0;
                _measuredBwSlotStart[_measuredBwSlotIndex] = slotStart;
            }

            _measuredBwSlots[_measuredBwSlotIndex] += deliveredBytes;
        }

        private double ComputeMeasuredBandwidthUnsafe(long nowMicros)
        {
            const long slotDuration = 200_000L;
            long minSlotStart = nowMicros - (_measuredBwSlots.Length * slotDuration);
            long totalBytes = 0;
            for (int i = 0; i < _measuredBwSlots.Length; i++)
            {
                long slotStart = _measuredBwSlotStart[i];
                if (slotStart >= 0 && slotStart >= minSlotStart && slotStart <= nowMicros)
                {
                    totalBytes += _measuredBwSlots[i];
                }
            }

            long elapsed = _measuredBwSlots.Length * slotDuration;
            if (elapsed <= 0 || totalBytes <= 0)
            {
                return 0d;
            }

            return totalBytes * UcpConstants.MICROS_PER_SECOND / (double)elapsed;
        }

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
            if (null != connected)
            {
                try { connected(); } catch (Exception) { }
            }
        }

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
                        return;
                    }
                }

                _state = UcpConnectionState.Closed;
                if (!_closedResourcesReleased)
                {
                    _closedResourcesReleased = true;
                    _hasPendingCloseCallback = false;
                    releaseResources = true;
                }

                lock (_sendBufLock) { _sendBuffer.Clear(); }
                _recvBuffer.Clear();
                _recvBufferBytes = 0;
                _receiveQueue.Clear();
                lock (_endpointLock) { _extraCids.Clear(); }
                _fecFragmentMetadata.Clear();
                _sackTracking.Clear();
                _sackFastRetransmitNotified.Clear();
                _sackBlockSendCounts.Clear();
                _nakIssued.Clear();
                _missingSequenceCounts.Clear();
                _missingFirstSeenMicros.Clear();
                _lastNakIssuedMicros.Clear();
                _fecRepairSentGroups.Clear();
                _recentLossEvents.Clear();
                _recentLossSequences.Clear();

                if (!_disconnectedRaised)
                {
                    _disconnectedRaised = true;
                    disconnected = Disconnected;
                }

                shouldCallback = true;
            }

            _connectedTcs.TrySetResult(false);
            _closedTcs.TrySetResult(true);
            try { _receiveSignal.Release(int.MaxValue / 2); } catch (ObjectDisposedException) { } catch (SemaphoreFullException) { }
            try { _sendSpaceSignal.Release(int.MaxValue / 2); } catch (ObjectDisposedException) { } catch (SemaphoreFullException) { }
            if (releaseResources)
            {
                DisposeTimer();
                ReleaseNetworkRegistrations();
            }

            try
            {
                if (null != disconnected)
                {
                    disconnected();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError($"[UCP] Disconnected callback threw on conn: {ex}");
            }

            if (shouldCallback && null != _closedCallback)
            {
                try
                {
                    _closedCallback(this);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.TraceError($"[UCP] Closed callback threw on conn: {ex}");
                }
            }
        }

        private void ReleaseNetworkRegistrations()
        {
            if (null == _network)
            {
                return;
            }

            _network.UnregisterPcb(this);
            if (0 != _timerId)
            {
                _network.CancelTimer(_timerId);
                _timerId = 0;
            }

            if (0 != _flushTimerId)
            {
                _network.CancelTimer(_flushTimerId);
                _flushTimerId = 0;
            }

            if (0 != _ackTimerId)
            {
                _network.CancelTimer(_ackTimerId);
                _ackTimerId = 0;
            }
        }

        internal void DetachNetwork()
        {
            lock (_sync)
            {
                ReleaseNetworkRegistrations();
            }
        }

        private void DisposeTimer()
        {
            if (null == _timer)
            {
                return;
            }

            bool shouldDispose = false;
            lock (_sendBufLock) { if (!_timerDisposed) { _timerDisposed = true; shouldDispose = true; } }

            if (shouldDispose)
            {
                _timer.Change(Timeout.Infinite, Timeout.Infinite);
                _timer.Dispose();
            }
        }

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

        private static uint NextConnectionId()
        {
            byte[] bytes = new byte[UcpConstants.CONNECTION_ID_SIZE];
            uint connectionId;
            do
            {
                ConnectionIdGenerator.GetBytes(bytes);
                connectionId = BitConverter.ToUInt32(bytes, 0);
            }
            while (0 == connectionId);

            return connectionId;
        }

        private static ulong NextSessionKey()
        {
            byte[] bytes = new byte[UcpConstants.SESSION_KEY_SIZE];
            ulong sessionKey;
            do
            {
                ConnectionIdGenerator.GetBytes(bytes);
                sessionKey = BitConverter.ToUInt64(bytes, 0);
            }
            while (0 == sessionKey);

            return sessionKey;
        }

        private static uint NextSequence()
        {
            byte[] bytes = new byte[UcpConstants.SEQUENCE_NUMBER_SIZE];
            SequenceRng.GetBytes(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

        private long NowMicros()
        {
            // Standalone connections use the full microsecond-resolution
            // stopwatch read: the millisecond-quantized cached value would
            // collapse sub-ms RTT samples (e.g. loopback ~50us) to 0/1ms and
            // distort the KCC geodesic/RTT estimators.  Network-managed
            // connections use the network's cached logical clock.
            return null == _network ? UcpTime.ReadStopwatchMicroseconds() : _network.CurrentTimeUs;
        }

        private void AddRttSampleUnsafe(long sampleRttMicros)
        {
            if (sampleRttMicros <= 0)
            {
                return;
            }

            _rttSamplesMicros.Add(sampleRttMicros);
            if (_rttSamplesMicros.Count > UcpConstants.MaxRttSamples)
            {
                int excess = _rttSamplesMicros.Count - UcpConstants.MaxRttSamples;
                _rttSamplesMicros.RemoveRange(0, excess);
            }
        }

        private static ulong PackSackBlockKey(uint start, uint end)
        {
            return ((ulong)start << 32) | end;
        }

        private void PurgeSackSendCountsUnsafe()
        {
            if (_sackBlockSendCounts.Count > UcpConstants.SACK_SEND_COUNT_PURGE_THRESHOLD)
            {
                _sackBlockSendCounts.Clear();
            }
        }

        private void PurgeSackTrackingUnsafe()
        {
            if (_sackTracking.Count > UcpConstants.MAX_SACK_TRACKING_ENTRIES)
            {
                _sackTracking.Clear();
            }
            if (_sackFastRetransmitNotified.Count > UcpConstants.MAX_SACK_NOTIFIED_ENTRIES)
            {
                _sackFastRetransmitNotified.Clear();
            }
        }

        private void PurgeMissingTrackingUnsafe()
        {
            if (_missingSequenceCounts.Count > UcpConstants.MAX_MISSING_TRACKING_ENTRIES)
            {
                _missingSequenceCounts.Clear();
                _missingFirstSeenMicros.Clear();
                _lastNakIssuedMicros.Clear();
            }
        }

        private static void ValidateBuffer(byte[] buffer, int offset, int count)
        {
            if (null == buffer)
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
