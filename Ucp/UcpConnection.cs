using System;
using System.Net;
using System.Threading.Tasks;
using Ucp.Internal;
using Ucp.Transport;

namespace Ucp
{
    /// <summary>
    /// Client-side UCP connection. Provides connect, send, receive, and close
    /// operations. Internally wraps a <see cref="UcpPcb"/> for protocol logic.
    /// Supports both callback-based (<c>OnData</c> event) and stream-based
    /// (<c>ReadAsync</c>/<c>WriteAsync</c>) APIs.
    /// </summary>
    public class UcpConnection : IUcpObject, IDisposable
    {
        /// <summary>Synchronization lock for connection lifetime state transitions.</summary>
        private readonly object _sync = new object();

        /// <summary>Per-connection serial execution queue to serialize async operations.</summary>
        private readonly SerialQueue _strand = new SerialQueue();

        /// <summary>Underlying transport for sending and receiving datagrams.</summary>
        private ITransport _transport;

        /// <summary>Bindable transport interface, if supported by the underlying transport.</summary>
        private IBindableTransport _bindableTransport;

        /// <summary>Whether this connection owns the transport and should dispose it.</summary>
        private bool _ownsTransport;

        /// <summary>Whether packet dispatch is managed externally (UcpServer path).</summary>
        private bool _serverManagedDispatch;

        /// <summary>Protocol configuration for this connection.</summary>
        private UcpConfiguration _config;

        /// <summary>Reference to the network engine if multiplexed.</summary>
        private UcpNetwork _network;

        /// <summary>The protocol control block managing all low-level state.</summary>
        private UcpPcb _pcb;

        /// <summary>Whether the connection has subscribed to transport datagram events.</summary>
        private bool _transportSubscribed;

        /// <summary>Whether a pending initial send sequence was set before the PCB existed.</summary>
        private bool _hasPendingInitialSendSequence;

        /// <summary>Pending initial send sequence number for test injection.</summary>
        private uint _pendingInitialSendSequence;

        /// <summary>Callback registered via OnData event.</summary>
        private Action<byte[], int, int> _onData;

        /// <summary>Callback registered via OnConnected event.</summary>
        private Action _onConnected;

        /// <summary>Callback registered via OnDisconnected event.</summary>
        private Action _onDisconnected;

        /// <summary>
        /// Creates a connection with a new UdpSocketTransport and default configuration.
        /// </summary>
        public UcpConnection()
            : this(new UdpSocketTransport(), true, false, new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a connection with a new UdpSocketTransport and the given configuration.
        /// </summary>
        /// <param name="config">Protocol configuration.</param>
        public UcpConnection(UcpConfiguration config)
            : this(new UdpSocketTransport(), true, false, config ?? new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a connection wrapping an existing transport with default configuration.
        /// </summary>
        /// <param name="transport">The transport to use.</param>
        internal UcpConnection(ITransport transport)
            : this(transport, true, false, new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a connection with an existing transport and ownership flag.
        /// </summary>
        /// <param name="transport">The transport to use.</param>
        /// <param name="ownsTransport">Whether to dispose the transport on close.</param>
        internal UcpConnection(ITransport transport, bool ownsTransport)
            : this(transport, ownsTransport, false, new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a connection for multiplexed network use.
        /// </summary>
        internal UcpConnection(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
            : this(transport, ownsTransport, false, config, network)
        {
        }

        /// <summary>
        /// Creates a connection around an existing PCB (server-side accept path).
        /// </summary>
        internal UcpConnection(UcpPcb pcb, ITransport transport, UcpConfiguration config)
            : this(transport, false, true, config)
        {
            AttachPcb(pcb);
        }

        /// <summary>
        /// Internal constructor for creating a connection with server-managed dispatch.
        /// </summary>
        private UcpConnection(ITransport transport, bool ownsTransport, bool serverManagedDispatch, UcpConfiguration config)
            : this(transport, ownsTransport, serverManagedDispatch, config, null)
        {
        }

        /// <summary>
        /// Full internal constructor that initializes the connection state.
        /// Subscribes to transport datagrams unless server-managed.
        /// </summary>
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

        /// <summary>
        /// Raised when in-order data is available for delivery. Provides buffer, offset,
        /// and count of the received payload.
        /// </summary>
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

        /// <summary>Alias for OnData for backward compatibility.</summary>
        public event Action<byte[], int, int> OnDataReceived
        {
            add { OnData += value; }
            remove { OnData -= value; }
        }

        /// <summary>Raised when the connection handshake completes and data transfer is possible.</summary>
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

        /// <summary>Raised when the connection is fully closed.</summary>
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

        /// <summary>
        /// Connects to the specified remote endpoint. Binds the transport if needed,
        /// creates a PCB, and performs the SYN handshake.
        /// </summary>
        /// <param name="remote">The remote endpoint to connect to.</param>
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
                    _bindableTransport.Start(0); // Bind to OS-assigned port.
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

        /// <summary>
        /// Connects to a remote endpoint using a shared UcpNetwork for multiplexed I/O.
        /// Swaps the transport to the network's adapter before connecting.
        /// </summary>
        /// <param name="network">The network engine to use.</param>
        /// <param name="remote">The remote endpoint to connect to.</param>
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

                // Unsubscribe from the old transport, stop and dispose it if owned.
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

                // Switch to the network's transport adapter.
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

        /// <summary>
        /// Synchronously sends data. Returns the number of bytes accepted for sending,
        /// or -1 on error.
        /// </summary>
        /// <param name="buf">Buffer containing data to send.</param>
        /// <param name="offset">Offset into the buffer where data starts.</param>
        /// <param name="count">Number of bytes to send.</param>
        /// <returns>Bytes accepted, or -1 on error.</returns>
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

        /// <summary>
        /// Asynchronously sends data through the serial queue. Returns the number
        /// of bytes accepted for sending, or -1 on error.
        /// </summary>
        /// <param name="buf">Buffer containing data to send.</param>
        /// <param name="offset">Offset into the buffer where data starts.</param>
        /// <param name="count">Number of bytes to send.</param>
        /// <returns>Bytes accepted, or -1 on error.</returns>
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

        /// <summary>
        /// Synchronously receives data. Returns bytes copied, 0 if closed, or -1 on error.
        /// </summary>
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

        /// <summary>
        /// Asynchronously receives at most <paramref name="count"/> bytes of in-order data.
        /// Blocks until data is available or the connection closes.
        /// </summary>
        /// <returns>Bytes copied, 0 if closed, or -1 on error.</returns>
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

        /// <summary>
        /// Synchronously reads exactly <paramref name="count"/> bytes. Returns false
        /// if the connection closed before all bytes were received.
        /// </summary>
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

        /// <summary>
        /// Asynchronously reads exactly <paramref name="count"/> bytes of in-order data.
        /// Returns false if the connection closed before all bytes were received.
        /// </summary>
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

        /// <summary>
        /// Synchronously writes exactly <paramref name="count"/> bytes. Returns false on error.
        /// </summary>
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

        /// <summary>
        /// Asynchronously writes exactly <paramref name="count"/> bytes, retrying
        /// until all data is accepted or the connection closes.
        /// </summary>
        /// <returns>True if all bytes were accepted; false on error.</returns>
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

        /// <summary>
        /// Synchronously closes the connection.
        /// </summary>
        public void Close()
        {
            CloseAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Asynchronously closes the connection: drains the send buffer, sends FIN,
        /// and waits for the peer's FIN-ACK before cleaning up.
        /// </summary>
        public async Task CloseAsync()
        {
            if (_pcb != null)
            {
                await _pcb.CloseAsync().ConfigureAwait(false);
            }

            CleanupTransport();
        }

        /// <summary>
        /// Disposes the connection, closing it if still active.
        /// </summary>
        public void Dispose()
        {
            try
            {
                Close();
            }
            catch
            {
                CleanupTransport(); // Best-effort cleanup on error.
            }
        }

        /// <summary>
        /// Internal dispatch: enqueues a decoded packet for handling on the serial queue.
        /// </summary>
        /// <param name="packet">The decoded UCP packet.</param>
        /// <param name="remoteEndPoint">The remote endpoint that sent the packet.</param>
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

        /// <summary>
        /// Adds fair-queue credit bytes to this connection's PCB.
        /// </summary>
        /// <param name="bytes">Credit bytes to add.</param>
        internal void AddFairQueueCredit(double bytes)
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.AddFairQueueCredit(bytes); });
        }

        /// <summary>
        /// Requests an immediate flush of the send queue.
        /// </summary>
        internal void RequestFlush()
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.RequestFlush(); });
        }

        /// <summary>Current pacing rate in bytes per second, or 0 if not connected.</summary>
        internal double CurrentPacingRateBytesPerSecond
        {
            get { return _pcb == null ? 0 : _pcb.CurrentPacingRateBytesPerSecond; }
        }

        /// <summary>Whether the send buffer contains unsent data.</summary>
        internal bool HasPendingSendData
        {
            get { return _pcb != null && _pcb.HasPendingSendData; }
        }

        /// <summary>Current connection state.</summary>
        internal UcpConnectionState State
        {
            get { return _pcb == null ? UcpConnectionState.Init : _pcb.State; }
        }

        /// <summary>
        /// Gets a snapshot of connection diagnostics for reporting.
        /// </summary>
        internal UcpConnectionDiagnostics GetDiagnostics()
        {
            return _pcb == null ? new UcpConnectionDiagnostics() : _pcb.GetDiagnosticsSnapshot();
        }

        /// <summary>The remote endpoint this connection is communicating with.</summary>
        public IPEndPoint RemoteEndPoint
        {
            get { return _pcb == null ? null : _pcb.RemoteEndPoint; }
        }

        /// <summary>The protocol connection ID, or 0 if not yet assigned.</summary>
        public uint ConnectionId
        {
            get { return _pcb == null ? 0U : _pcb.ConnectionId; }
        }

        /// <summary>The network engine that owns this connection (may be null).</summary>
        public UcpNetwork Network
        {
            get { return _network; }
        }

        /// <summary>
        /// Builds a transfer report from the current diagnostics snapshot.
        /// </summary>
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

        /// <summary>Internal test hook: aborts the PCB with an optional RST.</summary>
        internal void AbortForTest(bool sendReset)
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.Abort(sendReset); });
        }

        /// <summary>Internal test hook: sets the next send sequence number.</summary>
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

        /// <summary>Internal test hook: overrides the advertised receive window.</summary>
        internal void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            if (_pcb == null)
            {
                return;
            }

            _strand.Post(delegate { _pcb.SetAdvertisedReceiveWindowForTest(windowBytes); });
        }

        /// <summary>
        /// Attaches a PCB to this connection and wires up event callbacks.
        /// </summary>
        /// <param name="pcb">The protocol control block to attach.</param>
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

        /// <summary>
        /// Subscribes to the transport's OnDatagram event for incoming packet dispatch.
        /// </summary>
        private void SubscribeTransport()
        {
            if (_transportSubscribed)
            {
                return;
            }

            _transport.OnDatagram += OnTransportDatagram;
            _transportSubscribed = true;
        }

        /// <summary>
        /// Handles an incoming datagram from the transport: decodes and dispatches
        /// it to the PCB. NAK packets receive priority queue dispatch.
        /// Filters packets by connection ID and validates the remote endpoint.
        /// </summary>
        private void OnTransportDatagram(byte[] datagram, IPEndPoint remoteEndPoint)
        {
            if (_pcb == null || datagram == null)
            {
                return;
            }

            UcpPacket packet;
            if (!UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet))
            {
                return; // Malformed or unrecognized packet.
            }

            if (_pcb.ConnectionId != 0 && packet.Header.ConnectionId != _pcb.ConnectionId)
            {
                return; // Packet does not belong to this connection.
            }

            if (!_pcb.ValidateRemoteEndPoint(remoteEndPoint))
            {
                return; // Endpoint mismatch.
            }

            if (packet.Header.Type == UcpPacketType.Nak)
            {
                // NAK packets get priority dispatch to trigger retransmits quickly.
                DispatchPriorityPacket(packet, remoteEndPoint);
                return;
            }

            DispatchPacket(packet, remoteEndPoint);
        }

        /// <summary>
        /// Dispatches a packet with priority (inserted at the front of the serial queue).
        /// Used for NAK packets that need immediate attention.
        /// </summary>
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

        /// <summary>
        /// Cleans up the transport: unsubscribes from events, stops and disposes
        /// if owned by this connection.
        /// </summary>
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
