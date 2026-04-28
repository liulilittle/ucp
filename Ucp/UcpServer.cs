using System;
using System.Collections.Generic;
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
        }

        private readonly object _sync = new object();
        private ITransport _transport;
        private IBindableTransport _bindableTransport;
        private bool _ownsTransport;
        private int _bandwidthLimitBytesPerSecond;
        private UcpConfiguration _config;
        private UcpNetwork _network;
        private readonly Dictionary<string, ConnectionEntry> _connections = new Dictionary<string, ConnectionEntry>();
        private readonly Queue<UcpConnection> _acceptQueue = new Queue<UcpConnection>();
        private readonly SemaphoreSlim _acceptSignal = new SemaphoreSlim(0, int.MaxValue);

        private Timer _fairQueueTimer;
        private uint _fairQueueTimerId;
        private int _fairQueueStartIndex;
        private long _lastFairQueueRoundMicros;
        private bool _started;

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
                if (_started)
                {
                    return;
                }

                if (_bindableTransport != null)
                {
                    _bindableTransport.Start(port);
                }

                _transport.OnDatagram += OnTransportDatagram;
                _started = true;
                if (_network == null)
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
            if (network == null)
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
                _config = configuration == null ? network.Configuration.Clone() : configuration.Clone();
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

                await _acceptSignal.WaitAsync().ConfigureAwait(false);
            }
        }

        public void Stop()
        {
            List<ConnectionEntry> entries = new List<ConnectionEntry>();
            lock (_sync)
            {
                if (!_started)
                {
                    return;
                }

                _started = false;
                _transport.OnDatagram -= OnTransportDatagram;
                if (_fairQueueTimer != null)
                {
                    _fairQueueTimer.Dispose();
                    _fairQueueTimer = null;
                }

                if (_network != null && _fairQueueTimerId != 0)
                {
                    _network.CancelTimer(_fairQueueTimerId);
                    _fairQueueTimerId = 0;
                }

                foreach (KeyValuePair<string, ConnectionEntry> pair in _connections)
                {
                    entries.Add(pair.Value);
                }

                _connections.Clear();
            }

            for (int i = 0; i < entries.Count; i++)
            {
                entries[i].Pcb.Dispose();
            }

            if (_bindableTransport != null)
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
            Stop();
        }

        private void OnTransportDatagram(byte[] datagram, IPEndPoint remoteEndPoint)
        {
            if (datagram == null || remoteEndPoint == null)
            {
                return;
            }

            UcpPacket packet;
            if (!UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet))
            {
                return;
            }

            ConnectionEntry entry = GetOrCreateConnection(remoteEndPoint, packet);
            if (entry == null)
            {
                return;
            }

            entry.Connection.DispatchPacket(packet, remoteEndPoint);
        }

        private ConnectionEntry GetOrCreateConnection(IPEndPoint remoteEndPoint, UcpPacket packet)
        {
            string key = CreateKey(remoteEndPoint, packet.Header.ConnectionId);
            ConnectionEntry entry;
            lock (_sync)
            {
                if (_connections.TryGetValue(key, out entry))
                {
                    return entry;
                }

                if (packet.Header.Type != UcpPacketType.Syn)
                {
                    return null;
                }

                UcpPcb pcb = new UcpPcb(_transport, remoteEndPoint, true, true, OnPcbClosed, packet.Header.ConnectionId, _config.Clone(), _network);
                UcpConnection connection = new UcpConnection(pcb, _transport, _config.Clone());
                entry = new ConnectionEntry();
                entry.Connection = connection;
                entry.Pcb = pcb;
                pcb.Connected += delegate { OnPcbConnected(entry); };
                _connections[key] = entry;
                return entry;
            }
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
            if (pcb == null || pcb.RemoteEndPoint == null)
            {
                return;
            }

            string key = CreateKey(pcb.RemoteEndPoint, pcb.ConnectionId);
            lock (_sync)
            {
                _connections.Remove(key);
            }
        }

        private void OnFairQueueRound(object state)
        {
            OnFairQueueRoundCore();
            if (_network != null)
            {
                ScheduleFairQueueRound();
            }
        }

        private void OnFairQueueRoundCore()
        {
            List<UcpConnection> active = new List<UcpConnection>();
            lock (_sync)
            {
                foreach (KeyValuePair<string, ConnectionEntry> pair in _connections)
                {
                    if ((pair.Value.Connection.State == UcpConnectionState.Established || pair.Value.Connection.State == UcpConnectionState.ClosingFinSent || pair.Value.Connection.State == UcpConnectionState.ClosingFinReceived)
                        && pair.Value.Connection.HasPendingSendData)
                    {
                        active.Add(pair.Value.Connection);
                    }
                }
            }

            if (active.Count == 0)
            {
                return;
            }

            long nowMicros = _network == null ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs;
            long elapsedMicros = _lastFairQueueRoundMicros == 0 ? _config.FairQueueRoundMilliseconds * 1000L : nowMicros - _lastFairQueueRoundMicros;
            if (elapsedMicros < 1000L)
            {
                elapsedMicros = 1000L;
            }

            if (elapsedMicros > _config.FairQueueRoundMilliseconds * 2000L)
            {
                elapsedMicros = _config.FairQueueRoundMilliseconds * 2000L;
            }

            _lastFairQueueRoundMicros = nowMicros;
            double roundBytes = _bandwidthLimitBytesPerSecond * (elapsedMicros / 1000000d);
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
            if (_network == null)
            {
                return;
            }

            lock (_sync)
            {
                if (!_started)
                {
                    return;
                }

                long delayMicros = Math.Max(1, _config.FairQueueRoundMilliseconds) * 1000L;
                _fairQueueTimerId = _network.AddTimer(_network.NowMicroseconds + delayMicros, delegate { OnFairQueueRound(null); });
            }
        }

        private static string CreateKey(IPEndPoint remoteEndPoint, uint connectionId)
        {
            return remoteEndPoint + "#" + connectionId;
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
