using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
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

        private IPEndPoint _remoteEndPointCache;


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
                lock (_sync)
                {
                    _onData += value;
                    if (null != _pcb)
                    {
                        _pcb.DataReceived += value;
                    }
                }
            }
            remove
            {
                lock (_sync)
                {
                    _onData -= value;
                    if (null != _pcb)
                    {
                        _pcb.DataReceived -= value;
                    }
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
                lock (_sync)
                {
                    _onConnected += value;
                    if (null != _pcb)
                    {
                        _pcb.Connected += value;
                    }
                }
            }
            remove
            {
                lock (_sync)
                {
                    _onConnected -= value;
                    if (null != _pcb)
                    {
                        _pcb.Connected -= value;
                    }
                }
            }
        }

        public event Action OnDisconnected
        {
            add
            {
                lock (_sync)
                {
                    _onDisconnected += value;
                    if (null != _pcb)
                    {
                        _pcb.Disconnected += value;
                    }
                }
            }
            remove
            {
                lock (_sync)
                {
                    _onDisconnected -= value;
                    if (null != _pcb)
                    {
                        _pcb.Disconnected -= value;
                    }
                }
            }
        }

        public async Task<UcpConnection> ConnectAsync(IPEndPoint remote)
        {
            if (null == remote)
            {
                throw new ArgumentNullException(nameof(remote));
            }

            lock (_sync)
            {
                if (null != _pcb)
                {
                    throw new InvalidOperationException("Connection is already initialized.");
                }

                if (null != _bindableTransport)
                {
                    _bindableTransport.Start(0);
                }

                UcpPcb pcb = new UcpPcb(_transport, remote, false, false, null, null, _config.Clone(), _network);

                AttachPcb(pcb);
            }

            await _pcb.ConnectAsync(remote).ConfigureAwait(false);
            return this;
        }

        public async Task<UcpConnection> ConnectAsync(UcpNetwork network, IPEndPoint remote)
        {
            if (null == network)
            {
                throw new ArgumentNullException(nameof(network));
            }

            lock (_sync)
            {
                if (null != _pcb)
                {
                    throw new InvalidOperationException("Connection is already initialized.");
                }

                if (_transportSubscribed)
                {
                    _transport.OnDatagram -= OnTransportDatagram;
                    _transportSubscribed = false;
                }

                if (_ownsTransport && null != _bindableTransport)
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
            }

            await ConnectAsync(remote).ConfigureAwait(false);
            return this;
        }

        public int Send(byte[] buf, int offset, int count)
        {
            return Send(buf, offset, count, UcpPriority.Normal);
        }

        public int Send(byte[] buf, int offset, int count, UcpPriority priority)
        {
            if (_strand.IsCurrentThreadProcessing)
            {
                throw new InvalidOperationException(
                    "Send() called from strand thread would deadlock. Use SendAsync() instead.");
            }

            try
            {
                using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                Task<int> sendTask = Task.Run(() => SendAsync(buf, offset, count, priority), cts.Token);
                if (sendTask.Wait(TimeSpan.FromSeconds(5)))
                {
                    return sendTask.GetAwaiter().GetResult();
                }

                cts.Cancel();
                sendTask.Wait(TimeSpan.FromSeconds(1));
                return -1;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError($"[UCP] Send error on conn {ConnectionId:X8}: {ex}");
                return -1;
            }
        }

        public async Task<int> SendAsync(byte[] buf, int offset, int count)
        {
            return await SendAsync(buf, offset, count, UcpPriority.Normal).ConfigureAwait(false);
        }

        public async Task<int> SendAsync(byte[] buf, int offset, int count, UcpPriority priority)
        {
            if (null == _pcb)
            {
                return -1;
            }

            try
            {
                return await _strand.EnqueueAsync(delegate { return _pcb.SendAsync(buf, offset, count, priority); }).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return -1;
            }
            catch (ObjectDisposedException)
            {
                return -1;
            }
            catch (InvalidOperationException)
            {
                return -1;
            }
        }

        public int Receive(byte[] buf, int offset, int count)
        {
            if (_strand.IsCurrentThreadProcessing)
            {
                throw new InvalidOperationException(
                    "Receive() called from strand thread would deadlock. Use ReceiveAsync() instead.");
            }

            try
            {
                if (null == _pcb)
                {
                    return -1;
                }
                // The inner pcb ReceiveAsync is cancellable via the passed token;
                // run it against a private staging buffer.  On success copy the
                // result into the caller's buffer; on timeout the background task
                // is cancelled so it cannot consume future data into the discarded
                // staging buffer (a zombie reader would otherwise steal data).
                byte[] staging = new byte[count];
                using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                Task<int> recvTask = Task.Run(() => _pcb.ReceiveAsync(staging, 0, count, cts.Token), cts.Token);
                if (recvTask.Wait(TimeSpan.FromSeconds(5)))
                {
                    int got = recvTask.GetAwaiter().GetResult();
                    if (got > 0 && got <= count)
                    {
                        Array.Copy(staging, 0, buf, offset, got);
                    }
                    return got;
                }

                cts.Cancel();
                return -1;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError($"[UCP] Receive error on conn {ConnectionId:X8}: {ex}");
                return -1;
            }
        }

        public async Task<int> ReceiveAsync(byte[] buf, int offset, int count)
        {
            if (null == _pcb)
            {
                return -1;
            }

            try
            {
                return await _pcb.ReceiveAsync(buf, offset, count).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return -1;
            }
            catch (ObjectDisposedException)
            {
                return -1;
            }
        }

        public bool Read(byte[] buf, int off, int count)
        {
            if (_strand.IsCurrentThreadProcessing)
            {
                throw new InvalidOperationException(
                    "Read() called from strand thread would deadlock. Use ReadAsync() instead.");
            }

            try
            {
                if (null == _pcb)
                {
                    return false;
                }
                // The inner pcb ReadAsync is cancellable via the passed token;
                // run it against a private staging buffer.  On success copy the
                // result into the caller's buffer; on timeout the background task
                // is cancelled so it cannot consume future data into the discarded
                // staging buffer (a zombie reader would otherwise steal data).
                byte[] staging = new byte[count];
                using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                Task<bool> readTask = Task.Run(() => _pcb.ReadAsync(staging, 0, count, cts.Token), cts.Token);
                if (readTask.Wait(TimeSpan.FromSeconds(5)))
                {
                    bool ok = readTask.GetAwaiter().GetResult();
                    if (ok)
                    {
                        Array.Copy(staging, 0, buf, off, count);
                    }
                    return ok;
                }

                cts.Cancel();
                return false;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError($"[UCP] Read error on conn {ConnectionId:X8}: {ex}");
                return false;
            }
        }

        public async Task<bool> ReadAsync(byte[] buf, int off, int count)
        {
            UcpPcb pcb = _pcb;
            if (null == pcb)
            {
                return false;
            }

            try
            {
                return await pcb.ReadAsync(buf, off, count).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }

        public bool Write(byte[] buf, int off, int count)
        {
            return Write(buf, off, count, UcpPriority.Normal);
        }

        public bool Write(byte[] buf, int off, int count, UcpPriority priority)
        {
            if (_strand.IsCurrentThreadProcessing)
            {
                throw new InvalidOperationException(
                    "Write() called from strand thread would deadlock. Use WriteAsync() instead.");
            }

            try
            {
                using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                Task<bool> writeTask = Task.Run(() => WriteAsync(buf, off, count, priority), cts.Token);
                if (writeTask.Wait(TimeSpan.FromSeconds(5)))
                {
                    return writeTask.GetAwaiter().GetResult();
                }

                cts.Cancel();
                writeTask.Wait(TimeSpan.FromSeconds(1));
                return false;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError($"[UCP] Write error on conn {ConnectionId:X8}: {ex}");
                return false;
            }
        }

        public async Task<bool> WriteAsync(byte[] buf, int off, int count)
        {
            return await WriteAsync(buf, off, count, UcpPriority.Normal).ConfigureAwait(false);
        }

        public async Task<bool> WriteAsync(byte[] buf, int off, int count, UcpPriority priority)
        {
            if (null == _pcb)
            {
                return false;
            }

            try
            {
                return await _pcb.WriteAsync(buf, off, count, priority).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }

        public void Close()
        {
            if (_strand.IsCurrentThreadProcessing)
            {
                throw new InvalidOperationException(
                    "Close() called from strand thread would deadlock. Use CloseAsync() instead.");
            }

            try
            {
                using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                Task closeTask = Task.Run(() => CloseAsync(), cts.Token);
                if (!closeTask.Wait(TimeSpan.FromSeconds(5)))
                {
                    cts.Cancel();
                    closeTask.Wait(TimeSpan.FromSeconds(1));
                    CleanupTransport();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError($"[UCP] Close error on conn {ConnectionId:X8}: {ex}");
                CleanupTransport();
            }
        }

        public async Task CloseAsync()
        {
            if (null != _pcb)
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
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError($"[UCP] Dispose error on conn {ConnectionId:X8}: {ex}");
                CleanupTransport();
            }

            if (null != _pcb)
            {
                lock (_sync)
                {
                    _pcb.DataReceived -= _onData;
                    _pcb.Connected -= _onConnected;
                    _pcb.Disconnected -= _onDisconnected;
                }
            }

            _strand.Stop();

            _pcb?.Dispose();
        }

        internal void DispatchPacket(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (null == packet || null == _pcb)
            {
                return;
            }

            _strand.Post(async delegate
            {
                try
                {
                    _pcb.SetRemoteEndPoint(remoteEndPoint);
                    await _pcb.HandleInboundAsync(packet).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {

                }
                catch (ObjectDisposedException)
                {

                }
            });
        }

        internal void AddFairQueueCredit(double bytes)
        {
            if (null == _pcb)
            {
                return;
            }

            _strand.Post(delegate { _pcb.AddFairQueueCredit(bytes); });
        }

        internal void RequestFlush()
        {
            if (null == _pcb)
            {
                return;
            }

            _strand.Post(delegate { _pcb.RequestFlush(); });
        }

        internal double CurrentPacingRateBytesPerSecond
        {
            get { return null == _pcb ? 0 : _pcb.CurrentPacingRateBytesPerSecond; }
        }

        internal bool HasPendingSendData
        {
            get { return null != _pcb && _pcb.HasPendingSendData; }
        }

        internal UcpConnectionState State
        {
            get { return null == _pcb ? UcpConnectionState.Init : _pcb.State; }
        }

        internal UcpConnectionDiagnostics GetDiagnostics()
        {
            return null == _pcb ? new UcpConnectionDiagnostics() : _pcb.GetDiagnosticsSnapshot();
        }

        public IPEndPoint RemoteEndPoint
        {
            get
            {
                // The PCB is the authoritative source; it is updated on every
                // inbound datagram (DispatchPacket -> SetRemoteEndPoint), so it
                // reflects peer migration. The cache is only a fallback.
                if (null != _pcb && null != _pcb.RemoteEndPoint) return _pcb.RemoteEndPoint;
                return _remoteEndPointCache;
            }
        }

        public void MigrateRemote(IPEndPoint newEndPoint)
        {
            if (null == newEndPoint || null == _pcb) { return; }
            _pcb.SetRemoteEndPoint(newEndPoint);
            _remoteEndPointCache = newEndPoint;
            _pcb.MarkPathChanged();
        }

        public uint ConnectionId
        {
            get { return null == _pcb ? 0U : _pcb.ConnectionId; }
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
            report.MeasuredBandwidthBytesPerSecond = diagnostics.MeasuredBandwidthBytesPerSecond;
            report.EstimatedLossPercent = diagnostics.EstimatedLossPercent;
            report.RemoteWindowBytes = diagnostics.RemoteWindowBytes;
            return report;
        }

        private void AttachPcb(UcpPcb pcb)
        {
            _pcb = pcb;

            if (null != pcb && null != pcb.RemoteEndPoint)
            {
                _remoteEndPointCache = pcb.RemoteEndPoint;
            }

            if (null == _remoteEndPointCache && null != _pcb)
            {
                _remoteEndPointCache = _pcb.RemoteEndPoint;
            }
            if (null != _onData)
            {
                _pcb.DataReceived += _onData;
            }

            if (null != _onConnected)
            {
                _pcb.Connected += _onConnected;
            }

            if (null != _onDisconnected)
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
            if (null == _pcb || null == datagram)
            {
                return;
            }

            UcpPacket packet;
            if (!UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet))
            {
                return;
            }

            if (0 != _pcb.ConnectionId && packet.Header.ConnectionId != _pcb.ConnectionId && !_pcb.IsValidCid(packet.Header.ConnectionId))
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
            if (null == packet || null == _pcb)
            {
                return;
            }

            _strand.PostPriority(async delegate
            {
                try
                {
                    _pcb.SetRemoteEndPoint(remoteEndPoint);
                    await _pcb.HandleInboundAsync(packet).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {

                }
                catch (ObjectDisposedException)
                {

                }
            });
        }

        private void CleanupTransport()
        {
            ITransport transport;
            IBindableTransport bindableTransport;
            bool ownsTransport;
            lock (_sync)
            {
                if (!_serverManagedDispatch && _transportSubscribed)
                {
                    _transport.OnDatagram -= OnTransportDatagram;
                    _transportSubscribed = false;
                }

                transport = _transport;
                bindableTransport = _bindableTransport;
                ownsTransport = _ownsTransport;

                // Make cleanup idempotent: a second call (e.g. Close timeout
                // followed by CloseAsync completing) must not Dispose the same
                // transport again.
                _transport = null;
                _bindableTransport = null;
                _ownsTransport = false;
            }

            if (ownsTransport)
            {
                if (null != bindableTransport)
                {
                    bindableTransport.Stop();
                }

                transport?.Dispose();
            }
        }
    }
}
