using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Ucp.Internal;
using Ucp.Transport;

namespace Ucp
{

    public class UcpServer : IUcpObject, IDisposable
    {

        private sealed class ConnectionEntry
        {

            public UcpConnection Connection;

            public UcpPcb Pcb;

            public bool Accepted;

            public Action ConnectedHandler;
        }

        private readonly object _sync = new object();

        private ITransport _transport;

        private IBindableTransport _bindableTransport;

        private bool _ownsTransport;

        private int _bandwidthLimitBytesPerSecond;

        private UcpConfiguration _config;

        private UcpNetwork _network;

        private readonly Dictionary<uint, ConnectionEntry> _connections = new Dictionary<uint, ConnectionEntry>();

        private readonly Queue<UcpConnection> _acceptQueue = new Queue<UcpConnection>();

        private readonly SemaphoreSlim _acceptSignal = new SemaphoreSlim(0, int.MaxValue);

        private Timer _fairQueueTimer;

        private uint _fairQueueTimerId;

        private int _fairQueueStartIndex;

        private long _lastFairQueueRoundMicros;

        private bool _started;

        private int _disposed;

        private CancellationTokenSource _stopCts = new CancellationTokenSource();

        public UcpServer()
            : this(new UdpSocketTransport(), true, new UcpConfiguration())
        {
        }

        public UcpServer(UcpConfiguration config)
            : this(new UdpSocketTransport(), true, config ?? new UcpConfiguration())
        {
        }

        internal UcpServer(ITransport transport)
            : this(transport, true, new UcpConfiguration())
        {
        }

        internal UcpServer(ITransport transport, int bandwidthLimitBytesPerSecond)
            : this(transport, true, CreateConfigWithBandwidth(bandwidthLimitBytesPerSecond))
        {
        }

        internal UcpServer(ITransport transport, UcpConfiguration config)
            : this(transport, true, config)
        {
        }

        private UcpServer(ITransport transport, bool ownsTransport, UcpConfiguration config)
            : this(transport, ownsTransport, config, null)
        {
        }

        internal UcpServer(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
        {
            _transport = transport;
            _bindableTransport = transport as IBindableTransport;
            _ownsTransport = ownsTransport;
            _config = config ?? new UcpConfiguration();
            _network = network;
            _bandwidthLimitBytesPerSecond = _config.ServerBandwidthBytesPerSecond > 0 ? _config.ServerBandwidthBytesPerSecond : UcpConstants.DefaultServerBandwidthBytesPerSecond;
        }

        public void Start(int port)
        {
            lock (_sync)
            {
                if (_disposed != 0)
                {
                    return;
                }
                if (_started)
                {
                    return;
                }

                // A previous Stop() cancelled _stopCts: rebuild it so a
                // restarted server can AcceptAsync again (otherwise the
                // cancelled token makes every AcceptAsync fail immediately).
                if (_stopCts.IsCancellationRequested)
                {
                    _stopCts = new CancellationTokenSource();
                }

                if (null != _bindableTransport)
                {
                    _bindableTransport.Start(port);
                }

                _transport.OnDatagram += OnTransportDatagram;
                _started = true;
                if (null == _network)
                {

                    _fairQueueTimer = new Timer(OnFairQueueRound, null, _config.FairQueueRoundMilliseconds, _config.FairQueueRoundMilliseconds);
                }
                else
                {

                    ScheduleFairQueueRound();
                }
            }
        }

        public uint ConnectionId
        {
            get { return 0U; }
        }

        public UcpNetwork Network
        {
            get { return _network; }
        }

        public void Start(UcpNetwork network, int port, UcpConfiguration configuration)
        {
            if (null == network)
            {
                throw new ArgumentNullException(nameof(network));
            }

            lock (_sync)
            {
                if (_started)
                {
                    return;
                }

                _transport = network.TransportAdapter;
                _bindableTransport = network.TransportAdapter;
                _ownsTransport = false;
                _config = null == configuration ? network.Configuration.Clone() : configuration.Clone();
                _network = network;
                _bandwidthLimitBytesPerSecond = _config.ServerBandwidthBytesPerSecond > 0 ? _config.ServerBandwidthBytesPerSecond : UcpConstants.DefaultServerBandwidthBytesPerSecond;
            }

            Start(port);
        }

        public async Task<UcpConnection> AcceptAsync()
        {
            while (true)
            {
                lock (_sync)
                {
                    if (_acceptQueue.Count > 0)
                    {
                        return _acceptQueue.Dequeue();
                    }
                }

                try
                {
                    await _acceptSignal.WaitAsync(_stopCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (ObjectDisposedException)
                {
                    throw new OperationCanceledException("UCP server accepting stopped (disposed).");
                }
            }
        }

        public void Stop()
        {
            List<ConnectionEntry> entries = new List<ConnectionEntry>();
            List<UcpConnection> staleAccept = new List<UcpConnection>();
            lock (_sync)
            {
                if (!_started)
                {
                    return;
                }

                _started = false;
                // Cancel inside the lock AFTER the _started check: Cancel() on a
                // CTS that was already disposed (a second Stop/Dispose) throws
                // ObjectDisposedException, so it must not run when we early-return.
                _stopCts.Cancel();
                _transport.OnDatagram -= OnTransportDatagram;
                if (null != _fairQueueTimer)
                {
                    _fairQueueTimer.Dispose();
                    _fairQueueTimer = null;
                }

                if (null != _network && 0 != _fairQueueTimerId)
                {
                    _network.CancelTimer(_fairQueueTimerId);
                    _fairQueueTimerId = 0;
                }

                foreach (KeyValuePair<uint, ConnectionEntry> pair in _connections)
                {
                    entries.Add(pair.Value);
                }

                _connections.Clear();

                while (_acceptQueue.Count > 0)
                {
                    staleAccept.Add(_acceptQueue.Dequeue());
                }
            }

            foreach (var conn in staleAccept)
                try { conn.Dispose(); } catch { }

            for (int i = 0; i < entries.Count; i++)
            {
                entries[i].Pcb.Dispose();
            }

            if (_ownsTransport && null != _bindableTransport)
            {
                _bindableTransport.Stop();
            }

            if (_ownsTransport)
            {
                _transport.Dispose();
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }
            Stop();
            _stopCts.Dispose();
            _acceptSignal.Dispose();
        }

        private void OnTransportDatagram(byte[] datagram, IPEndPoint remoteEndPoint)
        {
            if (null == datagram || null == remoteEndPoint)
            {
                return;
            }

            UcpPacket packet;
            if (!UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet))
            {
                // Undecodable datagram: nothing to dispatch, drop it.
                return;
            }

            ConnectionEntry entry = GetOrCreateConnection(remoteEndPoint, packet);
            if (null == entry)
            {
                // No connection and none could be created: drop it.
                return;
            }

            entry.Connection.DispatchPacket(packet, remoteEndPoint);
        }

        private ConnectionEntry GetOrCreateConnection(IPEndPoint remoteEndPoint, UcpPacket packet)
        {
            uint key = CreateKey(packet.Header.ConnectionId);
            ConnectionEntry entry;
            lock (_sync)
            {
                if (_connections.TryGetValue(key, out entry))
                {

                    if (packet is UcpControlPacket synPkt && synPkt.Header.Type == UcpPacketType.Syn &&
                        0 != synPkt.SessionKey && 0 != entry.Pcb.SessionKey && entry.Pcb.SessionKey != synPkt.SessionKey)
                    {
                        UcpPcb pcbToAbort = entry.Pcb;
                        _connections.Remove(key);

                        Monitor.Exit(_sync);
                        try { if (!pcbToAbort.Disposed) pcbToAbort.Abort(true); } catch { }
                        Monitor.Enter(_sync);

                        if (!_started) return null;
                        if (_connections.TryGetValue(key, out var recheck) && recheck != null) return recheck;
                        entry = null;
                    }
                    else
                    {

                        entry.Pcb.SetRemoteEndPoint(remoteEndPoint);
                        return entry;
                    }
                }

                if (packet is UcpControlPacket && packet.Header.Type == UcpPacketType.Syn && null != _network)
                {
                    UcpControlPacket synPacket = (UcpControlPacket)packet;
                    if (0 != synPacket.SessionKey)
                    {
                        UcpPcb existingPcb = _network.LookupBySessionKey(synPacket.SessionKey);
                        if (null != existingPcb)
                        {

                            existingPcb.ResetLargestTimestampForReconnection();

                            uint existingKey = CreateKey(existingPcb.ConnectionId);
                            if (_connections.TryGetValue(existingKey, out entry))
                            {
                                entry.Pcb.SetRemoteEndPoint(remoteEndPoint);
                                return entry;
                            }
                        }
                    }
                }

                if (packet.Header.Type != UcpPacketType.Syn)
                {
                    return null;
                }

                if (!_started) return null;

                UcpPcb pcb = new UcpPcb(_transport, remoteEndPoint, true, true, OnPcbClosed, packet.Header.ConnectionId, _config.Clone(), _network);
                UcpConnection connection = new UcpConnection(pcb, _transport, _config.Clone());
                entry = new ConnectionEntry();
                entry.Connection = connection;
                entry.Pcb = pcb;
                // Keep the handler instance so it can be detached when the
                // connection closes (avoids a long-lived closure cycle on the
                // server via the pcb's Connected event).
                entry.ConnectedHandler = delegate { OnPcbConnected(entry); };
                pcb.Connected += entry.ConnectedHandler;
                _connections[key] = entry;
            }

            return entry;
        }

        private void OnPcbConnected(ConnectionEntry entry)
        {
            lock (_sync)
            {
                if (entry.Accepted)
                {
                    return;
                }

                entry.Accepted = true;

                _acceptQueue.Enqueue(entry.Connection);
            }

            _acceptSignal.Release();
        }

        private void OnPcbClosed(UcpPcb pcb)
        {
            if (null == pcb)
            {
                return;
            }

            uint key = CreateKey(pcb.ConnectionId);
            lock (_sync)
            {
                ConnectionEntry entry;
                if (_connections.TryGetValue(key, out entry) && object.ReferenceEquals(entry.Pcb, pcb))
                {
                    if (null != entry.ConnectedHandler)
                    {
                        entry.Pcb.Connected -= entry.ConnectedHandler;
                        entry.ConnectedHandler = null;
                    }

                    _connections.Remove(key);
                }
            }
        }

        private void OnFairQueueRound(object _)
        {
            try
            {
                OnFairQueueRoundCore();
            }
            catch
            {
                if (null != _network)
                {
                    ScheduleFairQueueRound();
                }
                return;
            }
            if (null != _network)
            {
                ScheduleFairQueueRound();
            }
        }

        private void OnFairQueueRoundCore()
        {

            List<UcpConnection> active = new List<UcpConnection>();
            lock (_sync)
            {
                foreach (KeyValuePair<uint, ConnectionEntry> pair in _connections)
                {
                    if ((pair.Value.Connection.State == UcpConnectionState.Established || pair.Value.Connection.State == UcpConnectionState.ClosingFinSent || pair.Value.Connection.State == UcpConnectionState.ClosingFinReceived)
                        && pair.Value.Connection.HasPendingSendData)
                    {
                        active.Add(pair.Value.Connection);
                    }
                }
            }

            if (0 == active.Count)
            {
                return;
            }

            long nowMicros = null == _network ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs;
            long elapsedMicros = 0 == _lastFairQueueRoundMicros ? _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI : nowMicros - _lastFairQueueRoundMicros;
            if (elapsedMicros < UcpConstants.MICROS_PER_MILLI)
            {
                elapsedMicros = UcpConstants.MICROS_PER_MILLI;
            }

            if (elapsedMicros > _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI * UcpConstants.MAX_BUFFERED_FAIR_QUEUE_ROUNDS)
            {
                elapsedMicros = _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI * UcpConstants.MAX_BUFFERED_FAIR_QUEUE_ROUNDS;
            }

            _lastFairQueueRoundMicros = nowMicros;
            double roundBytes = _bandwidthLimitBytesPerSecond * (elapsedMicros / (double)UcpConstants.MICROS_PER_SECOND);
            double fairShareCap = active.Count > 0 ? _bandwidthLimitBytesPerSecond / (double)active.Count : _bandwidthLimitBytesPerSecond;
            double effectiveTotalPacing = 0;
            double[] effectivePacing = new double[active.Count];

            for (int i = 0; i < active.Count; i++)
            {
                double pacing = active[i].CurrentPacingRateBytesPerSecond;
                if (pacing <= 0)
                {
                    pacing = fairShareCap;
                }

                if (pacing > fairShareCap)
                {
                    pacing = fairShareCap;
                }

                effectivePacing[i] = pacing;
                effectiveTotalPacing += pacing;
            }

            if (effectiveTotalPacing <= 0)
            {
                effectiveTotalPacing = active.Count;
            }

            for (int i = 0; i < active.Count; i++)
            {
                double credit = (effectivePacing[i] / effectiveTotalPacing) * roundBytes;
                active[i].AddFairQueueCredit(credit);
            }

            int startIndex = 0;
            lock (_sync)
            {
                if (_fairQueueStartIndex >= active.Count)
                {
                    _fairQueueStartIndex = 0;
                }

                startIndex = _fairQueueStartIndex;
                _fairQueueStartIndex++;
            }

            for (int i = 0; i < active.Count; i++)
            {
                int index = (startIndex + i) % active.Count;
                active[index].RequestFlush();
            }
        }

        private void ScheduleFairQueueRound()
        {
            if (null == _network)
            {
                return;
            }

            lock (_sync)
            {
                if (!_started)
                {
                    return;
                }

                long delayMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.FairQueueRoundMilliseconds) * UcpConstants.MICROS_PER_MILLI;

                _fairQueueTimerId = _network.AddTimer(_network.NowMicroseconds + delayMicros, delegate { OnFairQueueRound(null); });
            }
        }

        private static uint CreateKey(uint connectionId)
        {
            return connectionId;
        }

        private static UcpConfiguration CreateConfigWithBandwidth(int bandwidthLimitBytesPerSecond)
        {
            UcpConfiguration config = new UcpConfiguration();
            if (bandwidthLimitBytesPerSecond > 0)
            {
                config.ServerBandwidthBytesPerSecond = bandwidthLimitBytesPerSecond;
            }

            return config;
        }
    }
}
