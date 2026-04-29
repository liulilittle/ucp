using System;
using System.Net;
using System.Threading.Tasks;
using Ucp.Internal;
using Ucp.Transport;

namespace Ucp
{
    public class UcpConnection : IUcpObject, IDisposable
    {
        private readonly object _sync = new object();
        private readonly SerialQueue _strand = new SerialQueue();
        private ITransport _transport;
        private IBindableTransport _bindableTransport;
        private bool _ownsTransport;
        private bool _serverManagedDispatch;
        private UcpConfiguration _config;
        private UcpNetwork _network;

        private UcpPcb _pcb;
        private bool _transportSubscribed;
        private bool _hasPendingInitialSendSequence;
        private uint _pendingInitialSendSequence;
        private Action<byte[], int, int> _onData;
        private Action _onConnected;
        private Action _onDisconnected;

        public UcpConnection()
            : this(new UdpSocketTransport(), true, false, new UcpConfiguration())
        {
        }

        public UcpConnection(UcpConfiguration config)
            : this(new UdpSocketTransport(), true, false, config ?? new UcpConfiguration())
        {
        }

        internal UcpConnection(ITransport transport)
            : this(transport, true, false, new UcpConfiguration())
        {
        }

        internal UcpConnection(ITransport transport, bool ownsTransport)
            : this(transport, ownsTransport, false, new UcpConfiguration())
        {
        }

        internal UcpConnection(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
            : this(transport, ownsTransport, false, config, network)
        {
        }

        internal UcpConnection(UcpPcb pcb, ITransport transport, UcpConfiguration config)
            : this(transport, false, true, config)
        {
            AttachPcb(pcb);
        }

        private UcpConnection(ITransport transport, bool ownsTransport, bool serverManagedDispatch, UcpConfiguration config)
            : this(transport, ownsTransport, serverManagedDispatch, config, null)
        {
        }

        private UcpConnection(ITransport transport, bool ownsTransport, bool serverManagedDispatch, UcpConfiguration config, UcpNetwork network)
        {
            _transport = transport;
            _bindableTransport = transport as IBindableTransport;
            _ownsTransport = ownsTransport;
            _serverManagedDispatch = serverManagedDispatch;
            _config = config ?? new UcpConfiguration();
            _network = network;
            if (!_serverManagedDispatch)
            {
                SubscribeTransport();
            }
        }

        public event Action<byte[], int, int> OnData
        {
            add
            {
                _onData += value;
                if (_pcb != null)
                {
                    _pcb.DataReceived += value;
                }
            }
            remove
            {
                _onData -= value;
                if (_pcb != null)
                {
                    _pcb.DataReceived -= value;
                }
            }
        }

        public event Action<byte[], int, int> OnDataReceived
        {
            add { OnData += value; }
            remove { OnData -= value; }
        }

        public event Action OnConnected
        {
            add
            {
                _onConnected += value;
                if (_pcb != null)
                {
                    _pcb.Connected += value;
                }
            }
            remove
            {
                _onConnected -= value;
                if (_pcb != null)
                {
                    _pcb.Connected -= value;
                }
            }
        }

        public event Action OnDisconnected
        {
            add
            {
                _onDisconnected += value;
                if (_pcb != null)
                {
                    _pcb.Disconnected += value;
                }
            }
            remove
            {
                _onDisconnected -= value;
                if (_pcb != null)
                {
                    _pcb.Disconnected -= value;
                }
            }
        }

        public async Task ConnectAsync(IPEndPoint remote)
        {
            if (remote == null)
            {
                throw new ArgumentNullException(nameof(remote));
            }

            lock (_sync)
            {
                if (_pcb != null)
                {
                    throw new InvalidOperationException("Connection is already initialized.");
                }

                if (_bindableTransport != null)
                {
                    _bindableTransport.Start(0);
                }

                UcpPcb pcb = new UcpPcb(_transport, remote, false, false, null, null, _config.Clone(), _network);
                if (_hasPendingInitialSendSequence)
                {
                    pcb.SetNextSendSequenceForTest(_pendingInitialSendSequence);
                }

                AttachPcb(pcb);
            }

            await _pcb.ConnectAsync(remote).ConfigureAwait(false);
        }

        public async Task ConnectAsync(UcpNetwork network, IPEndPoint remote)
        {
            if (network == null)
            {
                throw new ArgumentNullException(nameof(network));
            }

            lock (_sync)
            {
                if (_pcb != null)
                {
                    throw new InvalidOperationException("Connection is already initialized.");
                }

                if (_transportSubscribed)
                {
                    _transport.OnDatagram -= OnTransportDatagram;
                    _transportSubscribed = false;
                }

                if (_ownsTransport && _bindableTransport != null)
                {
                    _bindableTransport.Stop();
                }

                if (_ownsTransport)
                {
                    _transport.Dispose();
                }

                _transport = network.TransportAdapter;
                _bindableTransport = network.TransportAdapter;
                _ownsTransport = false;
                _serverManagedDispatch = false;
                _network = network;
                SubscribeTransport();
                _hasPendingInitialSendSequence = false;
            }

            await ConnectAsync(remote).ConfigureAwait(false);
        }

        public int Send(byte[] buf, int offset, int count)
        {
            try
            {
                return SendAsync(buf, offset, count).GetAwaiter().GetResult();
            }
            catch
            {
                return -1;
            }
        }

        public async Task<int> SendAsync(byte[] buf, int offset, int count)
        {
            if (_pcb == null)
            {
                return -1;
            }

            try
            {
                return await _strand.EnqueueAsync(delegate { return _pcb.SendAsync(buf, offset, count); }).ConfigureAwait(false);
            }
            catch
            {
                return -1;
            }
        }

        public int Receive(byte[] buf, int offset, int count)
        {
            try
            {
                return ReceiveAsync(buf, offset, count).GetAwaiter().GetResult();
            }
            catch
            {
                return -1;
            }
        }

        public async Task<int> ReceiveAsync(byte[] buf, int offset, int count)
        {
            if (_pcb == null)
            {
                return -1;
            }

            try
            {
                return await _pcb.ReceiveAsync(buf, offset, count).ConfigureAwait(false);
            }
            catch
            {
                return -1;
            }
        }

        public bool Read(byte[] buf, int off, int count)
        {
            try
            {
                return ReadAsync(buf, off, count).GetAwaiter().GetResult();
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> ReadAsync(byte[] buf, int off, int count)
        {
            if (_pcb == null)
            {
                return false;
            }

            try
            {
                return await _pcb.ReadAsync(buf, off, count).ConfigureAwait(false);
            }
            catch
            {
                return false;
            }
        }

        public bool Write(byte[] buf, int off, int count)
        {
            try
            {
                return WriteAsync(buf, off, count).GetAwaiter().GetResult();
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> WriteAsync(byte[] buf, int off, int count)
        {
            if (_pcb == null)
            {
                return false;
            }

            try
            {
                return await _pcb.WriteAsync(buf, off, count).ConfigureAwait(false);
            }
            catch
            {
                return false;
            }
        }

        public void Close()
        {
            CloseAsync().GetAwaiter().GetResult();
        }

        public async Task CloseAsync()
        {
            if (_pcb != null)
            {
                await _pcb.CloseAsync().ConfigureAwait(false);
            }

            CleanupTransport();
        }

        public void Dispose()
        {
            try
            {
                Close();
            }
            catch
            {
                CleanupTransport();
            }
        }

        internal void DispatchPacket(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (packet == null || _pcb == null)
            {
                return;
            }

            _strand.Post(async delegate
            {
                _pcb.SetRemoteEndPoint(remoteEndPoint);
                await _pcb.HandleInboundAsync(packet).ConfigureAwait(false);
            });
        }

        internal void AddFairQueueCredit(double bytes)
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.AddFairQueueCredit(bytes); });
        }

        internal void RequestFlush()
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.RequestFlush(); });
        }

        internal double CurrentPacingRateBytesPerSecond
        {
            get { return _pcb == null ? 0 : _pcb.CurrentPacingRateBytesPerSecond; }
        }

        internal bool HasPendingSendData
        {
            get { return _pcb != null && _pcb.HasPendingSendData; }
        }

        internal UcpConnectionState State
        {
            get { return _pcb == null ? UcpConnectionState.Init : _pcb.State; }
        }

        internal UcpConnectionDiagnostics GetDiagnostics()
        {
            return _pcb == null ? new UcpConnectionDiagnostics() : _pcb.GetDiagnosticsSnapshot();
        }

        public IPEndPoint RemoteEndPoint
        {
            get { return _pcb == null ? null : _pcb.RemoteEndPoint; }
        }

        public uint ConnectionId
        {
            get { return _pcb == null ? 0U : _pcb.ConnectionId; }
        }

        public UcpNetwork Network
        {
            get { return _network; }
        }

        public UcpTransferReport GetReport()
        {
            UcpConnectionDiagnostics diagnostics = GetDiagnostics();
            UcpTransferReport report = new UcpTransferReport();
            report.BytesSent = diagnostics.BytesSent;
            report.BytesReceived = diagnostics.BytesReceived;
            report.DataPacketsSent = diagnostics.SentDataPackets;
            report.RetransmittedPackets = diagnostics.RetransmittedPackets;
            report.AckPacketsSent = diagnostics.SentAckPackets;
            report.NakPacketsSent = diagnostics.SentNakPackets;
            report.FastRetransmissions = diagnostics.FastRetransmissions;
            report.TimeoutRetransmissions = diagnostics.TimeoutRetransmissions;
            report.LastRttMicros = diagnostics.LastRttMicros;
            report.RttSamplesMicros.AddRange(diagnostics.RttSamplesMicros);
            report.CongestionWindowBytes = diagnostics.CongestionWindowBytes;
            report.PacingRateBytesPerSecond = diagnostics.PacingRateBytesPerSecond;
            report.EstimatedLossPercent = diagnostics.EstimatedLossPercent;
            report.RemoteWindowBytes = diagnostics.RemoteWindowBytes;
            return report;
        }

        internal void AbortForTest(bool sendReset)
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.Abort(sendReset); });
        }

        internal void SetNextSendSequenceForTest(uint nextSendSequence)
        {
            if (_pcb == null)
            {
                lock (_sync)
                {
                    _hasPendingInitialSendSequence = true;
                    _pendingInitialSendSequence = nextSendSequence;
                }

                return;
            }

            _strand.Post(delegate { _pcb.SetNextSendSequenceForTest(nextSendSequence); });
        }

        internal void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.SetAdvertisedReceiveWindowForTest(windowBytes); });
        }

        private void AttachPcb(UcpPcb pcb)
        {
            _pcb = pcb;
            if (_onData != null)
            {
                _pcb.DataReceived += _onData;
            }

            if (_onConnected != null)
            {
                _pcb.Connected += _onConnected;
            }

            if (_onDisconnected != null)
            {
                _pcb.Disconnected += _onDisconnected;
            }
        }

        private void SubscribeTransport()
        {
            if (_transportSubscribed)
            {
                return;
            }

            _transport.OnDatagram += OnTransportDatagram;
            _transportSubscribed = true;
        }

        private void OnTransportDatagram(byte[] datagram, IPEndPoint remoteEndPoint)
        {
            if (_pcb == null || datagram == null)
            {
                return;
            }

            UcpPacket packet;
            if (!UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet))
            {
                return;
            }

            if (_pcb.ConnectionId != 0 && packet.Header.ConnectionId != _pcb.ConnectionId)
            {
                return;
            }

            if (!_pcb.ValidateRemoteEndPoint(remoteEndPoint))
            {
                return;
            }

            if (packet.Header.Type == UcpPacketType.Nak)
            {
                DispatchPriorityPacket(packet, remoteEndPoint);
                return;
            }

            DispatchPacket(packet, remoteEndPoint);
        }

        private void DispatchPriorityPacket(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (packet == null || _pcb == null)
            {
                return;
            }

            _strand.PostPriority(async delegate
            {
                _pcb.SetRemoteEndPoint(remoteEndPoint);
                await _pcb.HandleInboundAsync(packet).ConfigureAwait(false);
            });
        }

        private void CleanupTransport()
        {
            if (!_serverManagedDispatch && _transportSubscribed)
            {
                _transport.OnDatagram -= OnTransportDatagram;
                _transportSubscribed = false;
            }

            if (_ownsTransport)
            {
                if (_bindableTransport != null)
                {
                    _bindableTransport.Stop();
                }

                _transport.Dispose();
            }
        }
    }
}
