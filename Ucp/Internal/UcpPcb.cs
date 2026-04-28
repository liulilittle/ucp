using System;
using System.Collections.Generic;
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
                diagnostics.LastRttMicros = _lastRttMicros;
                diagnostics.RttSamplesMicros.AddRange(_rttSamplesMicros);
                diagnostics.ReceivedReset = _rstReceived;

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

            long deadlineMicros = NowMicros() + (_config.ConnectTimeoutMilliseconds * 1000L);
            while (NowMicros() < deadlineMicros)
            {
                SendControl(UcpPacketType.Syn, UcpPacketFlags.None);
                int waitMilliseconds;
                lock (_sync)
                {
                    waitMilliseconds = (int)Math.Max(100L, _rtoEstimator.CurrentRtoMicros / 1000L);
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
                    if (_flightBytes > 0 && remaining < _config.MaxPayloadSize && _sendBuffer.Count > 0)
                    {
                        break;
                    }

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

            await WaitWithTimeoutAsync(_closedTcs.Task, 1000).ConfigureAwait(false);
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
                await HandleSynAsync((UcpControlPacket)packet).ConfigureAwait(false);
                return;
            }

            if (packet.Header.Type == UcpPacketType.SynAck)
            {
                await HandleSynAckAsync((UcpControlPacket)packet).ConfigureAwait(false);
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
                await HandleDataAsync((UcpDataPacket)packet).ConfigureAwait(false);
                return;
            }

            if (packet.Header.Type == UcpPacketType.Fin)
            {
                await HandleFinAsync((UcpControlPacket)packet).ConfigureAwait(false);
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

        private async Task HandleSynAsync(UcpControlPacket packet)
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

        private async Task HandleSynAckAsync(UcpControlPacket packet)
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
            long nowMicros = NowMicros();

            lock (_sync)
            {
                if (!IsAckPlausibleUnsafe(ackPacket))
                {
                    remainingFlight = _flightBytes;
                    return;
                }

                _remoteWindowBytes = ackPacket.WindowSize;
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
                    sampleRtt = nowMicros - ackPacket.EchoTimestamp;
                    _lastRttMicros = sampleRtt;
                    AddRttSampleUnsafe(sampleRtt);
                }

                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (segment.Acked)
                    {
                        continue;
                    }

                    bool acked = UcpSequenceComparer.IsBeforeOrEqual(segment.SequenceNumber, ackPacket.AckNumber);
                    if (!acked && ackPacket.SackBlocks != null)
                    {
                        for (int i = 0; i < ackPacket.SackBlocks.Count; i++)
                        {
                            SackBlock block = ackPacket.SackBlocks[i];
                            if (UcpSequenceComparer.IsInForwardRange(segment.SequenceNumber, block.Start, block.End))
                            {
                                acked = true;
                                break;
                            }
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
                        if (sampleRtt == 0 && segment.SendCount == 1 && segment.LastSendMicros > 0)
                        {
                            sampleRtt = nowMicros - segment.LastSendMicros;
                            _lastRttMicros = sampleRtt;
                            AddRttSampleUnsafe(sampleRtt);
                        }

                        _bytesReceived += 0;
                        removeKeys.Add(pair.Key);
                        continue;
                    }

                    if (ackPacket.SackBlocks != null && ackPacket.SackBlocks.Count > 0)
                    {
                        uint highestSack = GetHighestSackEnd(ackPacket.SackBlocks);
                        if (UcpSequenceComparer.IsBefore(segment.SequenceNumber, highestSack))
                        {
                            segment.MissingAckCount++;
                            if (segment.MissingAckCount == 3 && segment.SendCount == 1 && !segment.NeedsRetransmit)
                            {
                                segment.NeedsRetransmit = true;
                                _fastRetransmissions++;
                            }
                        }
                    }
                }

                for (int i = 0; i < removeKeys.Count; i++)
                {
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
                if (deliveredBytes > 0 && sampleRtt > 0)
                {
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

            if (deliveredBytes > 0 || remainingFlight > 0)
            {
                await FlushSendQueueAsync().ConfigureAwait(false);
            }
        }

        private async Task HandleNakAsync(UcpNakPacket nakPacket)
        {
            lock (_sync)
            {
                for (int i = 0; i < nakPacket.MissingSequences.Count; i++)
                {
                    uint sequence = nakPacket.MissingSequences[i];
                    OutboundSegment segment;
                    if (_sendBuffer.TryGetValue(sequence, out segment))
                    {
                        segment.NeedsRetransmit = true;
                    }
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

        private async Task HandleDataAsync(UcpDataPacket dataPacket)
        {
            List<uint> missing = new List<uint>();
            List<byte[]> readyPayloads = new List<byte[]>();
            bool shouldEstablish = false;
            bool shouldStore = false;

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
                    }

                    if (shouldStore && UcpSequenceComparer.IsAfter(dataPacket.SequenceNumber, _nextExpectedSequence))
                    {
                        uint current = _nextExpectedSequence;
                        int remainingNakSlots = 32;
                        while (current != dataPacket.SequenceNumber && remainingNakSlots > 0)
                        {
                            if (!_nakIssued.Contains(current))
                            {
                                _nakIssued.Add(current);
                                missing.Add(current);
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
                        _nextExpectedSequence = UcpSequenceComparer.Increment(_nextExpectedSequence);
                        readyPayloads.Add(next.Payload);
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

            ScheduleAck();
        }

        private async Task HandleFinAsync(UcpControlPacket packet)
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
                        await Task.Delay((int)Math.Max(1L, _config.DelayedAckTimeoutMicros / 1000L), _cts.Token).ConfigureAwait(false);
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

            _network.AddTimer(_network.CurrentTimeUs + _config.DelayedAckTimeoutMicros, delegate
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
            int delayMs = (int)Math.Ceiling(waitMicros / 1000d);
            if (delayMs < 1)
            {
                delayMs = 1;
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

            _flushTimerId = _network.AddTimer(_network.NowMicroseconds + (delayMs * 1000L), delegate
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

            long intervalMicros = Math.Max(1, _config.TimerIntervalMilliseconds) * 1000L;
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

            lock (_sync)
            {
                foreach (KeyValuePair<uint, OutboundSegment> pair in _sendBuffer)
                {
                    OutboundSegment segment = pair.Value;
                    if (!segment.InFlight || segment.Acked)
                    {
                        continue;
                    }

                    if (nowMicros - segment.LastSendMicros >= _rtoEstimator.CurrentRtoMicros)
                    {
                        if (segment.SendCount >= _config.MaxRetransmissions)
                        {
                            _timeoutRetransmissions++;
                            maxRetransmissionsExceeded = true;
                            break;
                        }

                        segment.NeedsRetransmit = true;
                        timedOut = true;
                        _timeoutRetransmissions++;
                    }
                }

                if (timedOut)
                {
                    _rtoEstimator.Backoff();
                }

                if (_state == UcpConnectionState.Established && nowMicros - _lastAckSentMicros >= _config.KeepAliveIntervalMicros && nowMicros - _lastActivityMicros >= _config.KeepAliveIntervalMicros)
                {
                    sendKeepAlive = true;
                }

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

            if (timedOut)
            {
                await FlushSendQueueAsync().ConfigureAwait(false);
            }

            if (retransmitSynAck)
            {
                SendControl(UcpPacketType.SynAck, UcpPacketFlags.None);
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
            byte[] bytes = new byte[4];
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
