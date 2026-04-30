using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Ucp.Internal;
using Ucp.Transport;

namespace Ucp
{
    /// <summary>
    /// Server-side UCP listener. Accepts incoming connections via
    /// <c>AcceptAsync()</c>. Manages fair-queue scheduling across all
    /// active connections on a configurable round interval.
    /// </summary>
    public class UcpServer : IUcpObject, IDisposable
    {
        /// <summary>
        /// Tracks a pending or established connection entry managed by the server.
        /// </summary>
        private sealed class ConnectionEntry
        {
            /// <summary>The UcpConnection wrapper for this peer.</summary>
            public UcpConnection Connection;

            /// <summary>The protocol control block for this peer.</summary>
            public UcpPcb Pcb;

            /// <summary>Whether this connection has been accepted by the application.</summary>
            public bool Accepted;
        }

        /// <summary>Synchronization lock for server state.</summary>
        private readonly object _sync = new object();

        /// <summary>Underlying transport for I/O operations.</summary>
        private ITransport _transport;

        /// <summary>Bindable transport interface, if supported.</summary>
        private IBindableTransport _bindableTransport;

        /// <summary>Whether the server owns the transport and should dispose it.</summary>
        private bool _ownsTransport;

        /// <summary>Server aggregate bandwidth limit in bytes per second.</summary>
        private int _bandwidthLimitBytesPerSecond;

        /// <summary>Protocol configuration for accepted connections.</summary>
        private UcpConfiguration _config;

        /// <summary>Reference to the network engine if multiplexed.</summary>
        private UcpNetwork _network;

        /// <summary>Active connections keyed by "IP:port#connectionId".</summary>
        private readonly Dictionary<string, ConnectionEntry> _connections = new Dictionary<string, ConnectionEntry>();

        /// <summary>Queue of connections waiting to be accepted by the application.</summary>
        private readonly Queue<UcpConnection> _acceptQueue = new Queue<UcpConnection>();

        /// <summary>Semaphore signaled when a new connection is ready for acceptance.</summary>
        private readonly SemaphoreSlim _acceptSignal = new SemaphoreSlim(0, int.MaxValue);

        /// <summary>Timer driving fair-queue credit distribution rounds.</summary>
        private Timer _fairQueueTimer;

        /// <summary>Network timer ID for fair-queue scheduling when using UcpNetwork.</summary>
        private uint _fairQueueTimerId;

        /// <summary>Rotating start index for fair-queue round-robin ordering.</summary>
        private int _fairQueueStartIndex;

        /// <summary>Microsecond timestamp of the last fair-queue round.</summary>
        private long _lastFairQueueRoundMicros;

        /// <summary>Whether the server has been started.</summary>
        private bool _started;

        /// <summary>
        /// Creates a server with a new UdpSocketTransport and default configuration.
        /// </summary>
        public UcpServer()
            : this(new UdpSocketTransport(), true, new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a server with a new UdpSocketTransport and the given configuration.
        /// </summary>
        /// <param name="config">Protocol configuration for accepted connections.</param>
        public UcpServer(UcpConfiguration config)
            : this(new UdpSocketTransport(), true, config ?? new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a server wrapping an existing transport.
        /// </summary>
        internal UcpServer(ITransport transport)
            : this(transport, true, new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a server with a bandwidth limit for fair-queue scheduling.
        /// </summary>
        internal UcpServer(ITransport transport, int bandwidthLimitBytesPerSecond)
            : this(transport, true, CreateConfigWithBandwidth(bandwidthLimitBytesPerSecond))
        {
        }

        /// <summary>
        /// Creates a server wrapping an existing transport with the given configuration.
        /// </summary>
        internal UcpServer(ITransport transport, UcpConfiguration config)
            : this(transport, true, config)
        {
        }

        /// <summary>
        /// Internal constructor with ownership and configuration.
        /// </summary>
        private UcpServer(ITransport transport, bool ownsTransport, UcpConfiguration config)
            : this(transport, ownsTransport, config, null)
        {
        }

        /// <summary>
        /// Full internal constructor for creating a server, optionally within a UcpNetwork.
        /// </summary>
        internal UcpServer(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
        {
            _transport = transport;
            _bindableTransport = transport as IBindableTransport;
            _ownsTransport = ownsTransport;
            _config = config ?? new UcpConfiguration();
            _network = network;
            _bandwidthLimitBytesPerSecond = _config.ServerBandwidthBytesPerSecond > 0 ? _config.ServerBandwidthBytesPerSecond : UcpConstants.DefaultServerBandwidthBytesPerSecond;
        }

        /// <summary>
        /// Binds the transport to the given port and starts accepting connections.
        /// Subscribes to transport datagrams and starts the fair-queue timer.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
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
                    // Standalone mode: use a .NET Timer for fair-queue rounds.
                    _fairQueueTimer = new Timer(OnFairQueueRound, null, _config.FairQueueRoundMilliseconds, _config.FairQueueRoundMilliseconds);
                }
                else
                {
                    // Network-managed mode: schedule fair-queue via network timers.
                    ScheduleFairQueueRound();
                }
            }
        }

        /// <summary>Connection ID is always 0 for servers (not bound to a single connection).</summary>
        public uint ConnectionId
        {
            get { return 0U; }
        }

        /// <summary>The network engine that owns this server (may be null).</summary>
        public UcpNetwork Network
        {
            get { return _network; }
        }

        /// <summary>
        /// Starts the server within a UcpNetwork context, overriding the transport
        /// and configuration.
        /// </summary>
        /// <param name="network">The network engine.</param>
        /// <param name="port">The local port to bind.</param>
        /// <param name="configuration">The configuration to use (cloned internally).</param>
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

        /// <summary>
        /// Asynchronously accepts the next incoming connection. Blocks until a
        /// new client connects and completes the handshake.
        /// </summary>
        /// <returns>The accepted UcpConnection.</returns>
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

        /// <summary>
        /// Stops the server: unsubscribes from transport events, stops the
        /// fair-queue timer, disposes all PCBs, and stops the transport.
        /// </summary>
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

                // Snapshot and clear connections for safe disposal outside lock.
                foreach (KeyValuePair<string, ConnectionEntry> pair in _connections)
                {
                    entries.Add(pair.Value);
                }

                _connections.Clear();
            }

            // Dispose all PCBs outside the lock to avoid deadlock.
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

        /// <summary>
        /// Disposes the server by calling Stop().
        /// </summary>
        public void Dispose()
        {
            Stop();
        }

        /// <summary>
        /// Handles an incoming datagram from the transport. Decodes the packet,
        /// looks up or creates a connection entry, and dispatches it.
        /// </summary>
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
                return; // Non-SYN packet for unknown connection; silently dropped.
            }

            entry.Connection.DispatchPacket(packet, remoteEndPoint);
        }

        /// <summary>
        /// Looks up or creates a connection entry for the given remote endpoint
        /// and packet. Only SYN packets create new entries; other packets on
        /// unknown connections return null.
        /// </summary>
        /// <param name="remoteEndPoint">The source endpoint of the packet.</param>
        /// <param name="packet">The decoded UCP packet.</param>
        /// <returns>The matching or newly created connection entry, or null.</returns>
        private ConnectionEntry GetOrCreateConnection(IPEndPoint remoteEndPoint, UcpPacket packet)
        {
            string key = CreateKey(remoteEndPoint, packet.Header.ConnectionId);
            ConnectionEntry entry;
            lock (_sync)
            {
                if (_connections.TryGetValue(key, out entry))
                {
                    return entry; // Existing connection found.
                }

                if (packet.Header.Type != UcpPacketType.Syn)
                {
                    return null; // Only SYN can create new connections.
                }

                // Create a new PCB and wrap it in a UcpConnection.
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

        /// <summary>
        /// Called when a PCB completes the handshake. Enqueues the connection
        /// for application acceptance and signals the accept semaphore.
        /// </summary>
        /// <param name="entry">The connection entry that became established.</param>
        private void OnPcbConnected(ConnectionEntry entry)
        {
            lock (_sync)
            {
                if (entry.Accepted)
                {
                    return; // Already accepted.
                }

                entry.Accepted = true;
                _acceptQueue.Enqueue(entry.Connection);
            }

            _acceptSignal.Release();
        }

        /// <summary>
        /// Called when a PCB is closed. Removes the connection entry from the
        /// server's connection table.
        /// </summary>
        /// <param name="pcb">The PCB that closed.</param>
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

        /// <summary>
        /// Fair-queue timer callback. Runs the credit distribution round and
        /// reschedules if using a UcpNetwork.
        /// </summary>
        /// <param name="state">Timer state (unused).</param>
        private void OnFairQueueRound(object state)
        {
            OnFairQueueRoundCore();
            if (_network != null)
            {
                ScheduleFairQueueRound();
            }
        }

        /// <summary>
        /// Core fair-queue round: distributes bandwidth credit among active
        /// connections proportional to their pacing rates, then flushes each
        /// in round-robin order.
        /// </summary>
        private void OnFairQueueRoundCore()
        {
            // Collect active connections that have pending send data.
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

            // Calculate elapsed time since the last round to determine credit pool.
            long nowMicros = _network == null ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs;
            long elapsedMicros = _lastFairQueueRoundMicros == 0 ? _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI : nowMicros - _lastFairQueueRoundMicros;
            if (elapsedMicros < UcpConstants.MICROS_PER_MILLI)
            {
                elapsedMicros = UcpConstants.MICROS_PER_MILLI;
            }

            // Cap buffered rounds to prevent credit explosion after stalls.
            if (elapsedMicros > _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI * UcpConstants.MAX_BUFFERED_FAIR_QUEUE_ROUNDS)
            {
                elapsedMicros = _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI * UcpConstants.MAX_BUFFERED_FAIR_QUEUE_ROUNDS;
            }

            _lastFairQueueRoundMicros = nowMicros;
            double roundBytes = _bandwidthLimitBytesPerSecond * (elapsedMicros / (double)UcpConstants.MICROS_PER_SECOND);
            double fairShareCap = active.Count > 0 ? _bandwidthLimitBytesPerSecond / (double)active.Count : _bandwidthLimitBytesPerSecond;
            double effectiveTotalPacing = 0;
            double[] effectivePacing = new double[active.Count];

            // Collect each connection's effective pacing rate, capped at fair share.
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

            // Distribute credit proportional to each connection's effective pacing share.
            for (int i = 0; i < active.Count; i++)
            {
                double credit = (effectivePacing[i] / effectiveTotalPacing) * roundBytes;
                active[i].AddFairQueueCredit(credit);
            }

            // Rotate the start index for round-robin flush ordering.
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

            // Flush each connection in rotated round-robin order.
            for (int i = 0; i < active.Count; i++)
            {
                int index = (startIndex + i) % active.Count;
                active[index].RequestFlush();
            }
        }

        /// <summary>
        /// Schedules the next fair-queue round via the network timer.
        /// </summary>
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

                long delayMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.FairQueueRoundMilliseconds) * UcpConstants.MICROS_PER_MILLI;
                _fairQueueTimerId = _network.AddTimer(_network.NowMicroseconds + delayMicros, delegate { OnFairQueueRound(null); });
            }
        }

        /// <summary>
        /// Creates a connection lookup key from the remote endpoint and connection ID.
        /// </summary>
        private static string CreateKey(IPEndPoint remoteEndPoint, uint connectionId)
        {
            return remoteEndPoint + "#" + connectionId;
        }

        /// <summary>
        /// Creates a configuration with the specified bandwidth limit.
        /// </summary>
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
