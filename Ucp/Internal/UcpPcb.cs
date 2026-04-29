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
            public int MissingAckCount;
            public int SendCount;
            public long LastSendMicros;
        }

        private sealed class LossEvent
        {
            public uint SequenceNumber;
            public long TimestampMicros;
            public long RttMicros;
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

        private readonly object _sync = new object();
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
        private UcpFecCodec _fecCodec;
        private readonly SemaphoreSlim _receiveSignal = new SemaphoreSlim(0, int.MaxValue);
        private readonly SemaphoreSlim _sendSpaceSignal = new SemaphoreSlim(0, int.MaxValue);
        private readonly SemaphoreSlim _flushLock = new SemaphoreSlim(1, 1);
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly TaskCompletionSource<bool> _connectedTcs = new TaskCompletionSource<bool>();
        private readonly TaskCompletionSource<bool> _closedTcs = new TaskCompletionSource<bool>();
        private readonly UcpSackGenerator _sackGenerator = new UcpSackGenerator();
        private readonly UcpRtoEstimator _rtoEstimator;
        private readonly BbrCongestionControl _bbr;
        private readonly PacingController _pacing;
        private readonly Timer _timer;
        private readonly UcpNetwork _network;

        private UcpConnectionState _state;
        private IPEndPoint _remoteEndPoint;
        private uint _connectionId;
        private uint _nextSendSequence;
        private uint _nextExpectedSequence;
        private uint _remoteWindowBytes = UcpConstants.DefaultReceiveWindowBytes;
        private int _flightBytes;
        private double _fairQueueCreditBytes;
        private long _lastEchoTimestamp;
        private long _lastActivityMicros;
        private long _lastAckSentMicros;
        private long _lastRttMicros;
        private bool _synSent;
        private bool _synAckSent;
        private long _synAckSentMicros;
        private bool _finSent;
        private bool _finAcked;
        private bool _peerFinReceived;
        private bool _rstReceived;
        private bool _disposed;
        private bool _flushDelayed;
        private bool _ackDelayed;
        private uint _timerId;
        private uint _flushTimerId;
        private bool _connectedRaised;
        private bool _disconnectedRaised;
        private bool _closedResourcesReleased;
        private uint _largestCumulativeAckNumber;
        private bool _hasLargestCumulativeAckNumber;
        private uint _lastAckNumber;
        private bool _hasLastAckNumber;
        private int _duplicateAckCount;
        private bool _fastRecoveryActive;
        private uint _localReceiveWindowBytes = UcpConstants.DefaultReceiveWindowBytes;
        private int _queuedReceiveBytes;
        private long _bytesSent;
        private long _bytesReceived;
        private int _sentDataPackets;
        private int _retransmittedPackets;
        private int _sentAckPackets;
        private int _sentNakPackets;
        private int _sentRstPackets;
        private int _fastRetransmissions;
        private int _timeoutRetransmissions;
        private readonly List<long> _rttSamplesMicros = new List<long>();
        private long _lastNakWindowMicros;
        private int _naksSentThisRttWindow;
        private long _lastAckReceivedMicros;
        private long _lastReorderedAckSentMicros;
        private bool _tailLossProbePending;
        private readonly Queue<LossEvent> _recentLossEvents = new Queue<LossEvent>();
        private readonly HashSet<uint> _recentLossSequences = new HashSet<uint>();

        public UcpPcb(ITransport transport, IPEndPoint remoteEndPoint, bool isServerSide, bool useFairQueue, Action<UcpPcb> closedCallback, uint? connectionId, UcpConfiguration config)
            : this(transport, remoteEndPoint, isServerSide, useFairQueue, closedCallback, connectionId, config, null)
        {
        }

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
                _fecCodec = new UcpFecCodec(_config.FecGroupSize);
            }

            _state = UcpConnectionState.Init;
            _lastActivityMicros = NowMicros();
            _lastAckSentMicros = _lastActivityMicros;
            _remoteWindowBytes = _config.ReceiveWindowBytes;
            _localReceiveWindowBytes = _config.ReceiveWindowBytes;
            if (_network == null)
            {
                _timer = new Timer(OnTimer, null, _config.TimerIntervalMilliseconds, _config.TimerIntervalMilliseconds);
            }
            else
            {
                _network.RegisterPcb(this);
                ScheduleTimer();
            }
        }

        public event Action<byte[], int, int> DataReceived;

        public event Action Connected;

        public event Action Disconnected;

        public uint ConnectionId
        {
            get { return _connectionId; }
        }

        public IPEndPoint RemoteEndPoint
        {
            get { return _remoteEndPoint; }
        }

        public UcpConnectionState State
        {
            get { lock (_sync) { return _state; } }
        }

        public double CurrentPacingRateBytesPerSecond
        {
            get { lock (_sync) { return _bbr.PacingRateBytesPerSecond; } }
        }

        public bool HasPendingSendData
        {
            get { lock (_sync) { return _sendBuffer.Count > 0; } }
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

        public void Abort(bool sendReset)
        {
            if (sendReset && _remoteEndPoint != null)
            {
                SendControl(UcpPacketType.Rst, UcpPacketFlags.None);
            }

            TransitionToClosed();
        }

        public void SetNextSendSequenceForTest(uint nextSendSequence)
        {
            lock (_sync)
            {
                _nextSendSequence = nextSendSequence;
            }
        }

        public void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            lock (_sync)
            {
                _localReceiveWindowBytes = windowBytes;
            }
        }

        public void SetRemoteEndPoint(IPEndPoint remoteEndPoint)
        {
            lock (_sync)
            {
                _remoteEndPoint = remoteEndPoint;
            }
        }

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

                return _remoteEndPoint.Equals(remoteEndPoint);
            }
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
                        return;
                    }

                    break;
                }
            }

            throw new TimeoutException("UCP connection handshake timed out.");
        }

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
                        break;
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

        public void RequestFlush()
        {
            _ = FlushSendQueueAsync();
        }

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

        public void DispatchFromNetwork(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (ValidateRemoteEndPoint(remoteEndPoint))
            {
                _ = HandleInboundAsync(packet);
            }
        }

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

        private void HandleSyn(UcpControlPacket packet)
        {
            bool shouldReply = false;
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

            if (shouldReply)
            {
                SendControl(UcpPacketType.SynAck, UcpPacketFlags.None);
            }
        }

        private void HandleSynAck(UcpControlPacket packet)
        {
            bool shouldAck = false;
            bool shouldEstablish = false;
            lock (_sync)
            {
                if (packet.HasSequenceNumber)
                {
                    _nextExpectedSequence = packet.SequenceNumber;
                }

                if (_synSent && _state != UcpConnectionState.Closed)
                {
                    shouldAck = true;
                    shouldEstablish = _state == UcpConnectionState.HandshakeSynSent;
                }
            }

            if (shouldAck)
            {
                SendAckPacket(UcpPacketFlags.None, 0);
                if (shouldEstablish)
                {
                    TransitionToEstablished();
                }
            }
        }

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

                    if (hasSackBlocks)
                    {
                        if (UcpSequenceComparer.IsBefore(segment.SequenceNumber, highestSack))
                        {
                            if (!_sackFastRetransmitNotified.Contains(segment.SequenceNumber))
                            {
                                segment.MissingAckCount++;
                            }

                            if (segment.SendCount == 1 && !segment.NeedsRetransmit && ShouldFastRetransmitSackHoleUnsafe(segment, firstMissingSequence, highestSack, nowMicros))
                            {
                                segment.NeedsRetransmit = true;
                                _fastRetransmissions++;
                                _sackFastRetransmitNotified.Add(segment.SequenceNumber);
                                bool isCongestionLoss = IsCongestionLossUnsafe(segment.SequenceNumber, sampleRtt, nowMicros, 1);
                                _bbr.OnFastRetransmit(nowMicros, isCongestionLoss);
                                TraceLogUnsafe("FastRetransmit sequence=" + segment.SequenceNumber + " sack=true congestion=" + isCongestionLoss);
                            }
                        }
                    }
                }

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
                    sampleRtt = echoRtt;
                }

                bool acceptableRttSample = sampleRtt > 0 && sampleRtt <= (long)(_rtoEstimator.CurrentRtoMicros * UcpConstants.RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
                if (deliveredBytes > 0 && acceptableRttSample)
                {
                    _lastRttMicros = sampleRtt;
                    AddRttSampleUnsafe(sampleRtt);
                    _rtoEstimator.Update(sampleRtt);
                }

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

        private async Task HandleNakAsync(UcpNakPacket nakPacket)
        {
            bool notifiedLoss = false;
            long nowMicros = NowMicros();
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
                return false;
            }

            if (ackPacket.SackBlocks != null)
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
            if (blocks == null || blocks.Count <= 1)
            {
                return;
            }

            blocks.Sort(delegate (SackBlock left, SackBlock right)
            {
                return UcpSequenceComparer.Instance.Compare(left.Start, right.Start);
            });
        }

        private bool ShouldFastRetransmitSackHoleUnsafe(OutboundSegment segment, uint firstMissingSequence, uint highestSack, long nowMicros)
        {
            if (segment == null || segment.LastSendMicros <= 0)
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

            if (segment.SequenceNumber == firstMissingSequence && segment.MissingAckCount >= UcpConstants.SACK_FAST_RETRANSMIT_THRESHOLD)
            {
                return true;
            }

            return false;
        }

        private long GetSackFastRetransmitReorderGraceMicrosUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            if (rttMicros <= 0)
            {
                return UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS;
            }

            return Math.Max(UcpConstants.SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros / 2);
        }

        private void UpdateDuplicateAckStateUnsafe(UcpAckPacket ackPacket, long nowMicros, out bool fastRetransmitTriggered)
        {
            fastRetransmitTriggered = false;
            bool hasSack = ackPacket.SackBlocks != null && ackPacket.SackBlocks.Count > 0;
            bool duplicateAck = _hasLastAckNumber && ackPacket.AckNumber == _lastAckNumber && !hasSack;
                if (duplicateAck)
                {
                    _duplicateAckCount++;
                if (_duplicateAckCount >= UcpConstants.DUPLICATE_ACK_THRESHOLD && !_fastRecoveryActive)
                {
                    uint lostSeq = UcpSequenceComparer.Increment(ackPacket.AckNumber);
                    OutboundSegment lostSegment;
                    if (_sendBuffer.TryGetValue(lostSeq, out lostSegment) && !lostSegment.Acked && lostSegment.SendCount == 1 && !lostSegment.NeedsRetransmit)
                    {
                        long rttForFastRetransmit = GetFastRetransmitAgeThresholdUnsafe();
                        if (ShouldTriggerEarlyRetransmitUnsafe() || rttForFastRetransmit <= 0 || nowMicros - lostSegment.LastSendMicros >= rttForFastRetransmit)
                        {
                            lostSegment.NeedsRetransmit = true;
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

        private bool IsCongestionLossUnsafe(uint sequenceNumber, long sampleRttMicros, long nowMicros, int contiguousLossCount)
        {
            List<uint> sequences = new List<uint>(1);
            sequences.Add(sequenceNumber);
            return ClassifyLossesUnsafe(sequences, nowMicros, sampleRttMicros, contiguousLossCount);
        }

        private bool ClassifyLossesUnsafe(IList<uint> sequenceNumbers, long nowMicros, long sampleRttMicros)
        {
            return ClassifyLossesUnsafe(sequenceNumbers, nowMicros, sampleRttMicros, GetMaxContiguousLossRun(sequenceNumbers));
        }

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
                return false;
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

            return medianRttMicros > (long)(minRttMicros * UcpConstants.BBR_CONGESTION_LOSS_RTT_MULTIPLIER);
        }

        private long GetLossClassifierWindowMicrosUnsafe()
        {
            long minRttMicros = GetMinimumObservedRttMicrosUnsafe();
            if (minRttMicros <= 0)
            {
                minRttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _config.MinRtoMicros;
            }

            return Math.Max(UcpConstants.MICROS_PER_MILLI, minRttMicros * 2);
        }

        private void PruneLossEventsUnsafe(long nowMicros, long windowMicros)
        {
            while (_recentLossEvents.Count > 0 && nowMicros - _recentLossEvents.Peek().TimestampMicros > windowMicros)
            {
                LossEvent expired = _recentLossEvents.Dequeue();
                _recentLossSequences.Remove(expired.SequenceNumber);
            }
        }

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
                    continue;
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
                    currentRun = 1;
                }
            }

            return maxRun;
        }

        private long GetFastRetransmitAgeThresholdUnsafe()
        {
            long rttMicros = _rtoEstimator.SmoothedRttMicros > 0 ? _rtoEstimator.SmoothedRttMicros : _lastRttMicros;
            return rttMicros <= 0 ? 0 : rttMicros;
        }

        private bool ShouldTriggerEarlyRetransmitUnsafe()
        {
            int inflightSegments = Math.Max(1, _config.MaxPayloadSize) <= 0 ? 0 : (int)Math.Ceiling(_flightBytes / (double)Math.Max(1, _config.MaxPayloadSize));
            return inflightSegments > 0 && inflightSegments <= UcpConstants.EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS;
        }

        private bool ShouldAcceptRetransmitRequestUnsafe(OutboundSegment segment, long nowMicros)
        {
            if (segment == null || segment.SendCount <= 1 || segment.LastSendMicros <= 0)
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
            return total == 0 ? 0d : _retransmittedPackets / (double)total;
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
            List<uint> missing = new List<uint>();
            List<byte[]> readyPayloads = new List<byte[]>();
            bool shouldEstablish = false;
            bool shouldStore = false;
            bool sendImmediateAck = false;

            lock (_sync)
            {
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
                            byte[] recovered = _fecCodec.TryRecoverFromRepair(null, dataPacket.SequenceNumber, dataPacket.Payload);
                            if (recovered != null)
                            {
                                InboundSegment fecInbound = new InboundSegment();
                                fecInbound.SequenceNumber = dataPacket.SequenceNumber - 1;
                                fecInbound.FragmentTotal = 1;
                                fecInbound.FragmentIndex = 0;
                                fecInbound.Payload = recovered;
                                if (!_recvBuffer.ContainsKey(fecInbound.SequenceNumber))
                                {
                                    _recvBuffer[fecInbound.SequenceNumber] = fecInbound;
                                }
                            }
                        }
                    }

                    if (shouldStore && UcpSequenceComparer.IsAfter(dataPacket.SequenceNumber, _nextExpectedSequence))
                    {
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

        private bool ShouldIssueNakUnsafe(uint sequenceNumber)
        {
            return !_nakIssued.Contains(sequenceNumber);
        }

        private bool ShouldSendImmediateReorderedAckUnsafe(long nowMicros)
        {
            if (_lastReorderedAckSentMicros == 0 || nowMicros - _lastReorderedAckSentMicros >= UcpConstants.REORDERED_ACK_MIN_INTERVAL_MICROS)
            {
                _lastReorderedAckSentMicros = nowMicros;
                return true;
            }

            return false;
        }

        private static bool HasNakReorderGraceExpiredUnsafe(int missingCount, long firstSeenMicros, long nowMicros)
        {
            long graceMicros = missingCount >= UcpConstants.NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD
                ? UcpConstants.NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS
                : missingCount >= UcpConstants.NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD
                    ? UcpConstants.NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS
                : UcpConstants.NAK_REORDER_GRACE_MICROS;
            return nowMicros - firstSeenMicros >= graceMicros;
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
                firstSeenMicros = NowMicros();
                _missingFirstSeenMicros[sequenceNumber] = firstSeenMicros;
            }

            return firstSeenMicros;
        }

        private void HandleFecRepair(UcpFecRepairPacket packet)
        {
            if (_fecCodec == null || packet.Payload == null)
            {
                return;
            }

            lock (_sync)
            {
                byte[] recovered = _fecCodec.TryRecoverFromRepair(packet.Payload, packet.GroupId, null);
                if (recovered == null)
                {
                    return;
                }

                InboundSegment inbound = new InboundSegment();
                inbound.SequenceNumber = packet.GroupId;
                inbound.FragmentTotal = 1;
                inbound.FragmentIndex = 0;
                inbound.Payload = recovered;

                if (!_recvBuffer.ContainsKey(packet.GroupId))
                {
                    _recvBuffer[packet.GroupId] = inbound;
                    _nakIssued.Remove(packet.GroupId);
                    _missingSequenceCounts.Remove(packet.GroupId);
                    _missingFirstSeenMicros.Remove(packet.GroupId);
                    _lastNakIssuedMicros.Remove(packet.GroupId);
                }

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
                    _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence);
                }
            }

            ScheduleAck();
        }

        private void HandleFin(UcpControlPacket packet)
        {
            bool needSendOwnFin = false;
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
            if (missing == null || missing.Count == 0)
            {
                return;
            }

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
            }

            UcpNakPacket packet = new UcpNakPacket();
            packet.Header = CreateHeader(UcpPacketType.Nak, UcpPacketFlags.None, NowMicros());
            packet.MissingSequences.AddRange(missing);
            byte[] encoded = UcpPacketCodec.Encode(packet);
            _sentNakPackets++;
            _transport.Send(encoded, _remoteEndPoint);
        }

        private void SendControl(UcpPacketType type, UcpPacketFlags flags)
        {
            UcpControlPacket packet = new UcpControlPacket();
            packet.Header = CreateHeader(type, flags, NowMicros());
            if (type == UcpPacketType.Syn || type == UcpPacketType.SynAck)
            {
                packet.HasSequenceNumber = true;
                packet.SequenceNumber = _nextSendSequence;
            }

            byte[] encoded = UcpPacketCodec.Encode(packet);
            if (type == UcpPacketType.Rst)
            {
                _sentRstPackets++;
            }

            _transport.Send(encoded, _remoteEndPoint);
        }

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
                ackDelayMicros = Math.Min(ackDelayMicros, UcpConstants.MICROS_PER_MILLI);
            }

            lock (_sync)
            {
                if (_ackDelayed)
                {
                    return;
                }

                _ackDelayed = true;
            }

            if (_network == null)
            {
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

            _network.AddTimer(_network.CurrentTimeUs + ackDelayMicros, delegate
            {
                lock (_sync)
                {
                    _ackDelayed = false;
                }

                SendAckPacket(UcpPacketFlags.None, 0);
            });
        }

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
                                break;
                            }

                            int packetSize = UcpConstants.DataHeaderSize + segment.Payload.Length;
                            if (_useFairQueue && _fairQueueCreditBytes < packetSize)
                            {
                                break;
                            }

                            if (!_pacing.TryConsume(packetSize, nowMicros))
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

                    for (int i = 0; i < segmentsToSend.Count; i++)
                    {
                        OutboundSegment segment = segmentsToSend[i];
                        UcpDataPacket packet = new UcpDataPacket();
                        packet.Header = CreateHeader(UcpPacketType.Data, segment.SendCount > 1 ? UcpPacketFlags.NeedAck | UcpPacketFlags.Retransmit : UcpPacketFlags.NeedAck, nowMicros);
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

                        if (_fecCodec != null && segment.SendCount <= 1)
                        {
                            byte[] repair = _fecCodec.TryEncodeRepair(segment.Payload);
                            if (repair != null)
                            {
                                UcpFecRepairPacket repairPacket = new UcpFecRepairPacket();
                                repairPacket.Header = CreateHeader(UcpPacketType.FecRepair, UcpPacketFlags.None, nowMicros);
                                repairPacket.GroupId = segment.SequenceNumber;
                                repairPacket.GroupIndex = 0;
                                repairPacket.Payload = repair;
                                byte[] encodedRepair = UcpPacketCodec.Encode(repairPacket);
                                _transport.Send(encodedRepair, _remoteEndPoint);
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

        private void ScheduleDelayedFlush(long waitMicros)
        {
            if (_flushDelayed)
            {
                return;
            }

            _flushDelayed = true;
            int delayMs = (int)Math.Ceiling(waitMicros / (double)UcpConstants.MICROS_PER_MILLI);
            if (delayMs < UcpConstants.MIN_TIMER_WAIT_MILLISECONDS)
            {
                delayMs = UcpConstants.MIN_TIMER_WAIT_MILLISECONDS;
            }

            if (_network == null)
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
                });
                return;
            }

            _flushTimerId = _network.AddTimer(_network.NowMicroseconds + (delayMs * UcpConstants.MICROS_PER_MILLI), delegate
            {
                _flushDelayed = false;
                _flushTimerId = 0;
                _ = FlushSendQueueAsync();
            });
        }

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

        private UcpCommonHeader CreateHeader(UcpPacketType type, UcpPacketFlags flags, long timestampMicros)
        {
            UcpCommonHeader header = new UcpCommonHeader();
            header.Type = type;
            header.Flags = flags;
            header.ConnectionId = _connectionId;
            header.Timestamp = timestampMicros;
            return header;
        }

        private void OnTimer(object state)
        {
            if (_disposed)
            {
                return;
            }

            _ = OnTimerAsync();
            if (_network != null)
            {
                ScheduleTimer();
            }
        }

        private void ScheduleTimer()
        {
            if (_network == null || _disposed)
            {
                return;
            }

            long intervalMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.TimerIntervalMilliseconds) * UcpConstants.MICROS_PER_MILLI;
            _timerId = _network.AddTimer(_network.NowMicroseconds + intervalMicros, delegate { OnTimer(null); });
        }

        private async Task OnTimerAsync()
        {
            await OnTimerAsync(NowMicros()).ConfigureAwait(false);
        }

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
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (!segment.InFlight || segment.Acked || segment.NeedsRetransmit)
                    {
                        continue;
                    }

                    if (nowMicros - segment.LastSendMicros >= _rtoEstimator.CurrentRtoMicros)
                    {
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
                        timedOut = true;
                        rtoRetransmitBudget--;
                        timedOutForCongestion = timedOutForCongestion || segmentTimedOutForCongestion;
                        _timeoutRetransmissions++;
                    }
                }

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
                            _tailLossProbePending = true;
                            tailLossProbe = true;
                            break;
                        }
                    }
                }

                if (timedOut)
                {
                    _bbr.OnPacketLoss(nowMicros, GetRetransmissionRatioUnsafe(), timedOutForCongestion);
                    TraceLogUnsafe("RTO loss congestion=" + timedOutForCongestion + " rto=" + _rtoEstimator.CurrentRtoMicros);
                    if (timedOutForCongestion)
                    {
                        _rtoEstimator.Backoff();
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
                SendAckPacket(UcpPacketFlags.None, 0);
            }

            if (sendKeepAlive)
            {
                SendAckPacket(UcpPacketFlags.None, -1);
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
            _receiveSignal.Release();
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
            while (connectionId == 0);

            return connectionId;
        }

        private long NowMicros()
        {
            return _network == null ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs;
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
                _rttSamplesMicros.RemoveAt(0);
            }
        }

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
