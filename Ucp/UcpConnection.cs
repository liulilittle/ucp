using System; // Provides Action<T>, IDisposable, InvalidOperationException, ArgumentNullException
using System.Net; // Provides IPEndPoint for remote endpoint representation
using System.Threading.Tasks; // Provides Task, Task<T> for async connect/send/receive/close operations
using Ucp.Internal; // Internal protocol types: UcpPcb, UcpPacket, UcpPacketCodec, UcpPacketType, SerialQueue
using Ucp.Transport; // Transport abstractions: ITransport, IBindableTransport

namespace Ucp // Encapsulates the UCP reliable UDP transport protocol library
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
        private readonly object _sync = new object(); // Protects PCB creation, transport subscription, and state flags from concurrent access

        /// <summary>Per-connection serial execution queue to serialize async operations.</summary>
        private readonly SerialQueue _strand = new SerialQueue(); // Ensures all send/receive/event operations on this connection are serialized (no concurrent PCB access)

        /// <summary>Underlying transport for sending and receiving datagrams.</summary>
        private ITransport _transport; // The UDP socket transport used to send and receive raw datagrams

        /// <summary>Bindable transport interface, if supported by the underlying transport.</summary>
        private IBindableTransport _bindableTransport; // Allows binding to a local port; null if transport doesn't support binding

        /// <summary>Whether this connection owns the transport and should dispose it.</summary>
        private bool _ownsTransport; // If true, Dispose() will clean up the transport; false if owned by server/network

        /// <summary>Whether packet dispatch is managed externally (UcpServer path).</summary>
        private bool _serverManagedDispatch; // True when the server subscribes to transport events; we skip our own subscription to avoid duplicate handling

        /// <summary>Protocol configuration for this connection.</summary>
        private UcpConfiguration _config; // Stores settings like timeouts, window sizes, pacing parameters

        /// <summary>Reference to the network engine if multiplexed.</summary>
        private UcpNetwork _network; // Non-null when this connection runs inside a multiplexed UcpNetwork event loop

        /// <summary>The protocol control block managing all low-level state.</summary>
        private UcpPcb _pcb; // The core protocol engine: manages sequence numbers, retransmits, flow control, congestion control

        /// <summary>Whether the connection has subscribed to transport datagram events.</summary>
        private bool _transportSubscribed; // Tracks subscription state to avoid double-subscribe or unsubscribing when not subscribed

        /// <summary>Whether a pending initial send sequence was set before the PCB existed.</summary>
        private bool _hasPendingInitialSendSequence; // True when SetNextSendSequenceForTest was called before ConnectAsync created the PCB

        /// <summary>Pending initial send sequence number for test injection.</summary>
        private uint _pendingInitialSendSequence; // The sequence number to apply once the PCB is created (test hook)

        /// <summary>Callback registered via OnData event.</summary>
        private Action<byte[], int, int> _onData; // Multicast delegate for received data callbacks (buffer, offset, count)

        /// <summary>Callback registered via OnConnected event.</summary>
        private Action _onConnected; // Multicast delegate for handshake-complete notification

        /// <summary>Callback registered via OnDisconnected event.</summary>
        private Action _onDisconnected; // Multicast delegate for connection-closed notification

        /// <summary>
        /// Creates a connection with a new UdpSocketTransport and default configuration.
        /// </summary>
        public UcpConnection()
            : this(new UdpSocketTransport(), true, false, new UcpConfiguration()) // Default: owns a fresh UDP transport, not server-managed, default settings
        {
        }

        /// <summary>
        /// Creates a connection with a new UdpSocketTransport and the given configuration.
        /// </summary>
        /// <param name="config">Protocol configuration.</param>
        public UcpConnection(UcpConfiguration config)
            : this(new UdpSocketTransport(), true, false, config ?? new UcpConfiguration()) // Coalesces null config to default to avoid NullReferenceException
        {
        }

        /// <summary>
        /// Creates a connection wrapping an existing transport with default configuration.
        /// </summary>
        /// <param name="transport">The transport to use.</param>
        internal UcpConnection(ITransport transport)
            : this(transport, true, false, new UcpConfiguration()) // Internal: wraps an existing transport, owns it by default
        {
        }

        /// <summary>
        /// Creates a connection with an existing transport and ownership flag.
        /// </summary>
        /// <param name="transport">The transport to use.</param>
        /// <param name="ownsTransport">Whether to dispose the transport on close.</param>
        internal UcpConnection(ITransport transport, bool ownsTransport)
            : this(transport, ownsTransport, false, new UcpConfiguration()) // Internal: wraps transport with caller-specified ownership, default config
        {
        }

        /// <summary>
        /// Creates a connection for multiplexed network use.
        /// </summary>
        internal UcpConnection(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
            : this(transport, ownsTransport, false, config, network) // Internal: full constructor for network-managed connections
        {
        }

        /// <summary>
        /// Creates a connection around an existing PCB (server-side accept path).
        /// </summary>
        internal UcpConnection(UcpPcb pcb, ITransport transport, UcpConfiguration config)
            : this(transport, false, true, config) // Server path: does not own transport, server handles dispatch, no network context yet
        {
            AttachPcb(pcb); // Wire up the already-created PCB with event callbacks
        }

        /// <summary>
        /// Internal constructor for creating a connection with server-managed dispatch.
        /// </summary>
        private UcpConnection(ITransport transport, bool ownsTransport, bool serverManagedDispatch, UcpConfiguration config)
            : this(transport, ownsTransport, serverManagedDispatch, config, null) // Chains to the full constructor with null network
        {
        }

        /// <summary>
        /// Full internal constructor that initializes the connection state.
        /// Subscribes to transport datagrams unless server-managed.
        /// </summary>
        private UcpConnection(ITransport transport, bool ownsTransport, bool serverManagedDispatch, UcpConfiguration config, UcpNetwork network)
        {
            _transport = transport; // Store the transport reference for sending/receiving datagrams
            _bindableTransport = transport as IBindableTransport; // Attempt to cast to bindable interface; null if transport doesn't support binding
            _ownsTransport = ownsTransport; // Remember whether we're responsible for cleaning up the transport
            _serverManagedDispatch = serverManagedDispatch; // If true, the server subscribes to transport events; we skip our own subscription
            _config = config ?? new UcpConfiguration(); // Guard against null config by falling back to defaults
            _network = network; // May be null for standalone use; non-null when multiplexed
            if (!_serverManagedDispatch) // This connection is responsible for receiving its own datagrams
            {
                SubscribeTransport(); // Hook into the transport's OnDatagram event to receive incoming packets
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
                _onData += value; // Add the subscriber to our local multicast delegate
                if (_pcb != null) // PCB already exists (subscribing after connect)
                {
                    _pcb.DataReceived += value; // Forward directly to the PCB so the callback fires for subsequent data
                }
            }
            remove
            {
                _onData -= value; // Remove the subscriber from our local multicast delegate
                if (_pcb != null) // PCB exists, need to unbind from it too
                {
                    _pcb.DataReceived -= value; // Remove from the PCB to stop forwarding callbacks
                }
            }
        }

        /// <summary>Alias for OnData for backward compatibility.</summary>
        public event Action<byte[], int, int> OnDataReceived
        {
            add { OnData += value; } // Forward subscription to the canonical OnData event
            remove { OnData -= value; } // Forward unsubscription to the canonical OnData event
        }

        /// <summary>Raised when the connection handshake completes and data transfer is possible.</summary>
        public event Action OnConnected
        {
            add
            {
                _onConnected += value; // Add the subscriber to our local multicast delegate
                if (_pcb != null) // PCB already exists (event registered after connect)
                {
                    _pcb.Connected += value; // Forward to PCB so the callback fires when handshake completes
                }
            }
            remove
            {
                _onConnected -= value; // Remove the subscriber from our local multicast delegate
                if (_pcb != null) // PCB exists, need to unbind from it too
                {
                    _pcb.Connected -= value; // Remove from the PCB to stop forwarding callbacks
                }
            }
        }

        /// <summary>Raised when the connection is fully closed.</summary>
        public event Action OnDisconnected
        {
            add
            {
                _onDisconnected += value; // Add the subscriber to our local multicast delegate
                if (_pcb != null) // PCB already exists (event registered after connect)
                {
                    _pcb.Disconnected += value; // Forward to PCB so the callback fires on close
                }
            }
            remove
            {
                _onDisconnected -= value; // Remove the subscriber from our local multicast delegate
                if (_pcb != null) // PCB exists, need to unbind from it too
                {
                    _pcb.Disconnected -= value; // Remove from the PCB to stop forwarding callbacks
                }
            }
        }

        /// <summary>
        /// Connects to the specified remote endpoint. Binds the transport if needed,
        /// creates a PCB, and performs the SYN handshake.
        /// </summary>
        /// <param name="remote">The remote endpoint to connect to.</param>
        public async Task<UcpConnection> ConnectAsync(IPEndPoint remote)
        {
            if (remote == null) // Validate the remote endpoint to avoid errors during PCB creation
            {
                throw new ArgumentNullException(nameof(remote)); // Fail fast with a clear error message
            }

            lock (_sync) // Protect PCB creation and transport binding from concurrent calls
            {
                if (_pcb != null) // A PCB already exists (ConnectAsync was called more than once)
                {
                    throw new InvalidOperationException("Connection is already initialized."); // Reject duplicate connect attempts
                }

                if (_bindableTransport != null) // Transport supports binding to a local port
                {
                    _bindableTransport.Start(0); // Bind to OS-assigned port. (0 means OS picks a free ephemeral port)
                }

                UcpPcb pcb = new UcpPcb(_transport, remote, false, false, null, null, _config.Clone(), _network); // Create a new client-side PCB: server=false, empty connection ID (server assigns), clone config for isolation
                if (_hasPendingInitialSendSequence) // A test hook set a custom send sequence before the PCB existed
                {
                    pcb.SetNextSendSequenceForTest(_pendingInitialSendSequence); // Apply the pending test sequence to the new PCB
                }

                AttachPcb(pcb); // Wire up event callbacks (DataReceived, Connected, Disconnected) on the new PCB
            }

            await _pcb.ConnectAsync(remote).ConfigureAwait(false); // Initiate the SYN/SYN-ACK handshake; awaits until established or failure
            return this; // Return self for fluent chaining (caller can use the same reference to send/receive)
        }

        /// <summary>
        /// Connects to a remote endpoint using a shared UcpNetwork for multiplexed I/O.
        /// Swaps the transport to the network's adapter before connecting.
        /// </summary>
        /// <param name="network">The network engine to use.</param>
        /// <param name="remote">The remote endpoint to connect to.</param>
        public async Task<UcpConnection> ConnectAsync(UcpNetwork network, IPEndPoint remote)
        {
            if (network == null) // Validate the network argument to prevent subsequent NullReferenceException
            {
                throw new ArgumentNullException(nameof(network)); // Fail fast with a clear error
            }

            lock (_sync) // Protect transport swap and state transitions from concurrent access
            {
                if (_pcb != null) // A PCB already exists (ConnectAsync was called more than once)
                {
                    throw new InvalidOperationException("Connection is already initialized."); // Reject duplicate connect attempts
                }

                // Unsubscribe from the old transport, stop and dispose it if owned.
                if (_transportSubscribed) // We are currently subscribed to the old transport's events
                {
                    _transport.OnDatagram -= OnTransportDatagram; // Unsubscribe to stop receiving datagrams from the old transport
                    _transportSubscribed = false; // Mark as unsubscribed so CleanupTransport doesn't try again
                }

                if (_ownsTransport && _bindableTransport != null) // We own the transport and it supports binding
                {
                    _bindableTransport.Stop(); // Stop the old transport to release its bound port
                }

                if (_ownsTransport) // We own the old transport
                {
                    _transport.Dispose(); // Dispose the old transport to free native socket resources
                }

                // Switch to the network's transport adapter.
                _transport = network.TransportAdapter; // Replace transport with the network's shared adapter for multiplexed I/O
                _bindableTransport = network.TransportAdapter; // Network's adapter also implements IBindableTransport
                _ownsTransport = false; // The network owns its transport; we must not dispose it
                _serverManagedDispatch = false; // We manage our own dispatch with the network's transport
                _network = network; // Store the network reference for timer queries and time access
                SubscribeTransport(); // Subscribe to the network transport's OnDatagram for incoming packets
                _hasPendingInitialSendSequence = false; // Clear any pending test sequence since transport was swapped (new PCB will be created)
            }

            await ConnectAsync(remote).ConfigureAwait(false); // Delegate to the core ConnectAsync to create PCB and perform handshake
            return this; // Return self for fluent chaining after the network-swapped connection is established
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
            return Send(buf, offset, count, UcpPriority.Normal); // Delegate to the priority overload with Normal QoS
        }

        /// <summary>
        /// Synchronously sends data with the specified priority.
        /// Returns the number of bytes accepted for sending, or -1 on error.
        /// </summary>
        /// <param name="buf">Buffer containing data to send.</param>
        /// <param name="offset">Offset into the buffer where data starts.</param>
        /// <param name="count">Number of bytes to send.</param>
        /// <param name="priority">QoS priority for this data.</param>
        /// <returns>Bytes accepted, or -1 on error.</returns>
        public int Send(byte[] buf, int offset, int count, UcpPriority priority)
        {
            try
            {
                return SendAsync(buf, offset, count, priority).GetAwaiter().GetResult(); // Block synchronously on the async send; GetAwaiter().GetResult() preserves the original exception stack trace
            }
            catch
            {
                return -1; // Any failure (disposed, closed, buffer full) returns -1 to signal error
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
            return await SendAsync(buf, offset, count, UcpPriority.Normal).ConfigureAwait(false); // Delegate to the priority overload with Normal QoS
        }

        /// <summary>
        /// Asynchronously sends data with the specified QoS priority.
        /// Returns the number of bytes accepted for sending, or -1 on error.
        /// </summary>
        /// <param name="buf">Buffer containing data to send.</param>
        /// <param name="offset">Offset into the buffer where data starts.</param>
        /// <param name="count">Number of bytes to send.</param>
        /// <param name="priority">QoS priority for this data.</param>
        /// <returns>Bytes accepted, or -1 on error.</returns>
        public async Task<int> SendAsync(byte[] buf, int offset, int count, UcpPriority priority)
        {
            if (_pcb == null) // No PCB means the connection hasn't been established yet
            {
                return -1; // Cannot send without an active connection
            }

            try
            {
                return await _strand.EnqueueAsync(delegate { return _pcb.SendAsync(buf, offset, count, priority); }).ConfigureAwait(false); // Enqueue the send on the serial queue to ensure ordered, non-concurrent PCB access
            }
            catch
            {
                return -1; // Any failure (PCB disposed, connection closed) returns -1 to signal error
            }
        }

        /// <summary>
        /// Synchronously receives data. Returns bytes copied, 0 if closed, or -1 on error.
        /// </summary>
        public int Receive(byte[] buf, int offset, int count)
        {
            try
            {
                return ReceiveAsync(buf, offset, count).GetAwaiter().GetResult(); // Block synchronously on the async receive; GetAwaiter().GetResult() preserves the original exception stack trace
            }
            catch
            {
                return -1; // Any failure returns -1 to signal error
            }
        }

        /// <summary>
        /// Asynchronously receives at most <paramref name="count"/> bytes of in-order data.
        /// Blocks until data is available or the connection closes.
        /// </summary>
        /// <returns>Bytes copied, 0 if closed, or -1 on error.</returns>
        public async Task<int> ReceiveAsync(byte[] buf, int offset, int count)
        {
            if (_pcb == null) // No PCB means the connection hasn't been established yet
            {
                return -1; // Cannot receive without an active connection
            }

            try
            {
                return await _pcb.ReceiveAsync(buf, offset, count).ConfigureAwait(false); // Delegate to the PCB which manages in-order delivery and read queue
            }
            catch
            {
                return -1; // Any failure (PCB disposed, connection closed) returns -1 to signal error
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
                return ReadAsync(buf, off, count).GetAwaiter().GetResult(); // Block synchronously on the async read; GetAwaiter().GetResult() preserves the original exception stack trace
            }
            catch
            {
                return false; // Any failure returns false to signal error or incomplete read
            }
        }

        /// <summary>
        /// Asynchronously reads exactly <paramref name="count"/> bytes of in-order data.
        /// Returns false if the connection closed before all bytes were received.
        /// </summary>
        public async Task<bool> ReadAsync(byte[] buf, int off, int count)
        {
            if (_pcb == null) // No PCB means the connection hasn't been established yet
            {
                return false; // Cannot read without an active connection
            }

            try
            {
                return await _pcb.ReadAsync(buf, off, count).ConfigureAwait(false); // Delegate to the PCB which loops ReceiveAsync until count bytes are accumulated
            }
            catch
            {
                return false; // Any failure (PCB disposed, connection closed mid-read) returns false
            }
        }

        /// <summary>
        /// Synchronously writes exactly <paramref name="count"/> bytes. Returns false on error.
        /// </summary>
        public bool Write(byte[] buf, int off, int count)
        {
            return Write(buf, off, count, UcpPriority.Normal); // Delegate to the priority overload with Normal QoS
        }

        /// <summary>
        /// Synchronously writes exactly <paramref name="count"/> bytes with the specified priority.
        /// Returns false on error.
        /// </summary>
        public bool Write(byte[] buf, int off, int count, UcpPriority priority)
        {
            try
            {
                return WriteAsync(buf, off, count, priority).GetAwaiter().GetResult(); // Block synchronously on the async write; GetAwaiter().GetResult() preserves the original exception stack trace
            }
            catch
            {
                return false; // Any failure returns false to signal error
            }
        }

        /// <summary>
        /// Asynchronously writes exactly <paramref name="count"/> bytes, retrying
        /// until all data is accepted or the connection closes.
        /// </summary>
        /// <returns>True if all bytes were accepted; false on error.</returns>
        public async Task<bool> WriteAsync(byte[] buf, int off, int count)
        {
            return await WriteAsync(buf, off, count, UcpPriority.Normal).ConfigureAwait(false); // Delegate to the priority overload with Normal QoS
        }

        /// <summary>
        /// Asynchronously writes exactly <paramref name="count"/> bytes with the specified priority,
        /// retrying until all data is accepted or the connection closes.
        /// </summary>
        /// <returns>True if all bytes were accepted; false on error.</returns>
        public async Task<bool> WriteAsync(byte[] buf, int off, int count, UcpPriority priority)
        {
            if (_pcb == null) // No PCB means the connection hasn't been established yet
            {
                return false; // Cannot write without an active connection
            }

            try
            {
                return await _pcb.WriteAsync(buf, off, count, priority).ConfigureAwait(false); // Delegate to the PCB which loops SendAsync until all bytes are accepted
            }
            catch
            {
                return false; // Any failure (PCB disposed, connection closed mid-write) returns false
            }
        }

        /// <summary>
        /// Synchronously closes the connection.
        /// </summary>
        public void Close()
        {
            CloseAsync().GetAwaiter().GetResult(); // Block synchronously on the async close; GetAwaiter().GetResult() preserves the original exception stack trace
        }

        /// <summary>
        /// Asynchronously closes the connection: drains the send buffer, sends FIN,
        /// and waits for the peer's FIN-ACK before cleaning up.
        /// </summary>
        public async Task CloseAsync()
        {
            if (_pcb != null) // A PCB exists to perform the graceful close handshake
            {
                await _pcb.CloseAsync().ConfigureAwait(false); // Initiate the FIN/FIN-ACK close sequence; drains pending sends
            }

            CleanupTransport(); // Release transport resources after the PCB has finished closing
        }

        /// <summary>
        /// Disposes the connection, closing it if still active.
        /// </summary>
        public void Dispose()
        {
            try
            {
                Close(); // Attempt a normal close (drains buffer, sends FIN)
            }
            catch
            {
                CleanupTransport(); // Best-effort cleanup on error. If close threw, still release transport resources
            }
        }

        /// <summary>
        /// Internal dispatch: enqueues a decoded packet for handling on the serial queue.
        /// </summary>
        /// <param name="packet">The decoded UCP packet.</param>
        /// <param name="remoteEndPoint">The remote endpoint that sent the packet.</param>
        internal void DispatchPacket(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (packet == null || _pcb == null) // Guard against null packet or no PCB (connection not yet established)
            {
                return; // Nothing to dispatch
            }

            _strand.Post(async delegate // Enqueue the packet handling on the serial queue (fire-and-forget)
            {
                _pcb.SetRemoteEndPoint(remoteEndPoint); // Update the remote endpoint in case of NAT rebinding (IP/port change)
                await _pcb.HandleInboundAsync(packet).ConfigureAwait(false); // Let the PCB process the packet (data, ack, nak, close, etc.)
            });
        }

        /// <summary>
        /// Adds fair-queue credit bytes to this connection's PCB.
        /// </summary>
        /// <param name="bytes">Credit bytes to add.</param>
        internal void AddFairQueueCredit(double bytes)
        {
            if (_pcb == null) // No PCB exists (connection not established or already closed)
            {
                return; // Nothing to credit
            }

            _strand.Post(delegate { _pcb.AddFairQueueCredit(bytes); }); // Enqueue the credit addition on the serial queue for safe concurrent access
        }

        /// <summary>
        /// Requests an immediate flush of the send queue.
        /// </summary>
        internal void RequestFlush()
        {
            if (_pcb == null) // No PCB exists (connection not established or already closed)
            {
                return; // Nothing to flush
            }

            _strand.Post(delegate { _pcb.RequestFlush(); }); // Enqueue the flush request on the serial queue (fire-and-forget, non-blocking)
        }

        /// <summary>Current pacing rate in bytes per second, or 0 if not connected.</summary>
        internal double CurrentPacingRateBytesPerSecond
        {
            get { return _pcb == null ? 0 : _pcb.CurrentPacingRateBytesPerSecond; } // Return 0 if no PCB (not connected), otherwise delegate to PCB's congestion-controlled send rate
        }

        /// <summary>Whether the send buffer contains unsent data.</summary>
        internal bool HasPendingSendData
        {
            get { return _pcb != null && _pcb.HasPendingSendData; } // True only if PCB exists and has buffered bytes waiting to be sent
        }

        /// <summary>Current connection state.</summary>
        internal UcpConnectionState State
        {
            get { return _pcb == null ? UcpConnectionState.Init : _pcb.State; } // Return Init state if no PCB yet, otherwise delegate to PCB's current state machine state
        }

        /// <summary>
        /// Gets a snapshot of connection diagnostics for reporting.
        /// </summary>
        internal UcpConnectionDiagnostics GetDiagnostics()
        {
            return _pcb == null ? new UcpConnectionDiagnostics() : _pcb.GetDiagnosticsSnapshot(); // Return empty diagnostics if no PCB, otherwise get a snapshot of runtime stats (RTT, loss, bytes, etc.)
        }

        /// <summary>The remote endpoint this connection is communicating with.</summary>
        public IPEndPoint RemoteEndPoint
        {
            get { return _pcb == null ? null : _pcb.RemoteEndPoint; } // Return null if no PCB, otherwise the remote peer's IP and port
        }

        /// <summary>The protocol connection ID, or 0 if not yet assigned.</summary>
        public uint ConnectionId
        {
            get { return _pcb == null ? 0U : _pcb.ConnectionId; } // Return 0 if no PCB (connection not established), otherwise the assigned connection identifier
        }

        /// <summary>The network engine that owns this connection (may be null).</summary>
        public UcpNetwork Network
        {
            get { return _network; } // Expose the network context; null when standalone
        }

        /// <summary>
        /// Builds a transfer report from the current diagnostics snapshot.
        /// </summary>
        public UcpTransferReport GetReport()
        {
            UcpConnectionDiagnostics diagnostics = GetDiagnostics(); // Obtain the latest statistics snapshot from the PCB
            UcpTransferReport report = new UcpTransferReport(); // Create a fresh report object to populate
            report.BytesSent = diagnostics.BytesSent; // Copy total bytes sent from diagnostics to report
            report.BytesReceived = diagnostics.BytesReceived; // Copy total bytes received from diagnostics to report
            report.DataPacketsSent = diagnostics.SentDataPackets; // Copy count of data packets sent to report
            report.RetransmittedPackets = diagnostics.RetransmittedPackets; // Copy count of retransmitted packets to report
            report.AckPacketsSent = diagnostics.SentAckPackets; // Copy count of ACK packets sent to report
            report.NakPacketsSent = diagnostics.SentNakPackets; // Copy count of NAK packets sent to report
            report.FastRetransmissions = diagnostics.FastRetransmissions; // Copy count of fast (triple-ACK) retransmissions to report
            report.TimeoutRetransmissions = diagnostics.TimeoutRetransmissions; // Copy count of timeout-based retransmissions to report
            report.LastRttMicros = diagnostics.LastRttMicros; // Copy the most recent RTT sample in microseconds to report
            report.RttSamplesMicros.AddRange(diagnostics.RttSamplesMicros); // Copy the full list of RTT samples collected during the connection
            report.CongestionWindowBytes = diagnostics.CongestionWindowBytes; // Copy the current congestion window size to report
            report.PacingRateBytesPerSecond = diagnostics.PacingRateBytesPerSecond; // Copy the current pacing rate to report
            report.EstimatedLossPercent = diagnostics.EstimatedLossPercent; // Copy the estimated packet loss percentage to report
            report.RemoteWindowBytes = diagnostics.RemoteWindowBytes; // Copy the peer's advertised receive window size to report
            return report; // Return the fully populated transfer report
        }

        /// <summary>Internal test hook: aborts the PCB with an optional RST.</summary>
        internal void AbortForTest(bool sendReset)
        {
            if (_pcb == null) // No PCB exists (connection not established or already closed)
            {
                return; // Nothing to abort
            }

            _strand.Post(delegate { _pcb.Abort(sendReset); }); // Enqueue the abort on the serial queue; if sendReset is true, sends a RST packet before tearing down
        }

        /// <summary>Internal test hook: sets the next send sequence number.</summary>
        internal void SetNextSendSequenceForTest(uint nextSendSequence)
        {
            if (_pcb == null) // PCB doesn't exist yet (called before ConnectAsync)
            {
                lock (_sync) // Protect the pending sequence state from concurrent access
                {
                    _hasPendingInitialSendSequence = true; // Flag that a pending sequence is waiting to be applied
                    _pendingInitialSendSequence = nextSendSequence; // Store the sequence number to apply once PCB is created
                }

                return; // Done; the sequence will be applied in ConnectAsync when the PCB is created
            }

            _strand.Post(delegate { _pcb.SetNextSendSequenceForTest(nextSendSequence); }); // PCB exists, apply the sequence directly via the serial queue
        }

        /// <summary>Internal test hook: overrides the advertised receive window.</summary>
        internal void SetAdvertisedReceiveWindowForTest(uint windowBytes)
        {
            if (_pcb == null) // No PCB exists (connection not established or already closed)
            {
                return; // Cannot set window without a PCB
            }

            _strand.Post(delegate { _pcb.SetAdvertisedReceiveWindowForTest(windowBytes); }); // Enqueue the window override on the serial queue for thread-safe access
        }

        /// <summary>
        /// Attaches a PCB to this connection and wires up event callbacks.
        /// </summary>
        /// <param name="pcb">The protocol control block to attach.</param>
        private void AttachPcb(UcpPcb pcb)
        {
            _pcb = pcb; // Store the PCB reference as the active protocol engine for this connection
            if (_onData != null) // There are subscribers to the OnData event
            {
                _pcb.DataReceived += _onData; // Wire up the DataReceived event so existing subscribers receive future data
            }

            if (_onConnected != null) // There are subscribers to the OnConnected event
            {
                _pcb.Connected += _onConnected; // Wire up the Connected event so existing subscribers get notified on handshake completion
            }

            if (_onDisconnected != null) // There are subscribers to the OnDisconnected event
            {
                _pcb.Disconnected += _onDisconnected; // Wire up the Disconnected event so existing subscribers get notified on close
            }
        }

        /// <summary>
        /// Subscribes to the transport's OnDatagram event for incoming packet dispatch.
        /// </summary>
        private void SubscribeTransport()
        {
            if (_transportSubscribed) // Already subscribed (idempotent guard)
            {
                return; // Avoid double subscription which would cause duplicate packet handling
            }

            _transport.OnDatagram += OnTransportDatagram; // Subscribe to the transport's datagram event to receive incoming UDP packets
            _transportSubscribed = true; // Mark as subscribed so we know to unsubscribe during cleanup
        }

        /// <summary>
        /// Handles an incoming datagram from the transport: decodes and dispatches
        /// it to the PCB. NAK packets receive priority queue dispatch.
        /// Filters packets by connection ID and validates the remote endpoint.
        /// </summary>
        private void OnTransportDatagram(byte[] datagram, IPEndPoint remoteEndPoint)
        {
            if (_pcb == null || datagram == null) // Guard against null PCB (connection closed) or null datagram (malformed callback)
            {
                return; // Silently drop; nothing to process
            }

            UcpPacket packet; // Will hold the decoded packet structure
            if (!UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet)) // Attempt to decode the binary datagram into a typed UCP packet
            {
                return; // Malformed or unrecognized packet.
            }

            if (_pcb.ConnectionId != 0 && packet.Header.ConnectionId != _pcb.ConnectionId) // Connection ID mismatch (not the initial SYN where ID is 0)
            {
                return; // Packet does not belong to this connection.
            }

            if (!_pcb.ValidateRemoteEndPoint(remoteEndPoint)) // Remote endpoint verification failed (IP/port mismatch, unless in handshake)
            {
                return; // Endpoint mismatch.
            }

            if (packet.Header.Type == UcpPacketType.Nak) // Packet is a Negative Acknowledgment (NAK) indicating packet loss
            {
                // NAK packets get priority dispatch to trigger retransmits quickly.
                DispatchPriorityPacket(packet, remoteEndPoint); // Insert at the front of the serial queue to minimize retransmission delay
                return; // Handled; don't also dispatch via normal path
            }

            DispatchPacket(packet, remoteEndPoint); // Normal dispatch: enqueue at the back of the serial queue for ordered processing
        }

        /// <summary>
        /// Dispatches a packet with priority (inserted at the front of the serial queue).
        /// Used for NAK packets that need immediate attention.
        /// </summary>
        private void DispatchPriorityPacket(UcpPacket packet, IPEndPoint remoteEndPoint)
        {
            if (packet == null || _pcb == null) // Guard against null packet or no PCB (connection not yet established)
            {
                return; // Nothing to dispatch
            }

            _strand.PostPriority(async delegate // Enqueue the packet handling at the FRONT of the serial queue (priority over normal packets)
            {
                _pcb.SetRemoteEndPoint(remoteEndPoint); // Update the remote endpoint in case of NAT rebinding during the connection
                await _pcb.HandleInboundAsync(packet).ConfigureAwait(false); // Let the PCB process the priority packet (NAK handling triggers retransmits)
            });
        }

        /// <summary>
        /// Cleans up the transport: unsubscribes from events, stops and disposes
        /// if owned by this connection.
        /// </summary>
        private void CleanupTransport()
        {
            if (!_serverManagedDispatch && _transportSubscribed) // We manage our own dispatch and are currently subscribed
            {
                _transport.OnDatagram -= OnTransportDatagram; // Unsubscribe from datagram events to stop receiving packets
                _transportSubscribed = false; // Mark as unsubscribed so we don't attempt to unsubscribe again
            }

            if (_ownsTransport) // This connection owns its transport (created it internally)
            {
                if (_bindableTransport != null) // Transport supports explicit stop
                {
                    _bindableTransport.Stop(); // Stop the transport to release the bound port
                }

                _transport.Dispose(); // Dispose the transport to free native socket resources
            }
        }
    }
}
