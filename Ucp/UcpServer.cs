using System; // Provides core types like Action, IDisposable, Nullable
using System.Collections.Generic; // Provides Dictionary<TKey,TValue>, Queue<T>, List<T>
using System.Net; // Provides IPEndPoint for network endpoint representation
using System.Threading; // Provides Timer, SemaphoreSlim for async coordination
using System.Threading.Tasks; // Provides Task, Task<T> for async operations
using Ucp.Internal; // Internal protocol types: UcpPcb, UcpPacketCodec, UcpConstants, UcpTime
using Ucp.Transport; // Transport abstractions: ITransport, IBindableTransport

namespace Ucp // Encapsulates the UCP reliable UDP transport protocol library
{
    /// <summary>
    /// Server-side UCP listener. Accepts incoming connections via
    /// <c>AcceptAsync()</c>. Manages fair-queue scheduling across all
    /// active connections on a configurable round interval.
    /// </summary>
    public class UcpServer : IUcpObject, IDisposable // Server listener implementing connection identity and cleanup contracts
    {
        /// <summary>
        /// Tracks a pending or established connection entry managed by the server.
        /// </summary>
        private sealed class ConnectionEntry // Internal bookkeeping entry for each active client connection
        {
            /// <summary>The UcpConnection wrapper for this peer.</summary>
            public UcpConnection Connection; // Public API-facing connection object exposed to the application

            /// <summary>The protocol control block for this peer.</summary>
            public UcpPcb Pcb; // Low-level protocol engine managing sequence numbers, acks, retransmits

            /// <summary>Whether this connection has been accepted by the application.</summary>
            public bool Accepted; // Guards against duplicate OnConnected events (if already enqueued for accept)
        }

        /// <summary>Synchronization lock for server state.</summary>
        private readonly object _sync = new object(); // Protects all mutable server state from concurrent access

        /// <summary>Underlying transport for I/O operations.</summary>
        private ITransport _transport; // The UDP socket transport used to send and receive raw datagrams

        /// <summary>Bindable transport interface, if supported.</summary>
        private IBindableTransport _bindableTransport; // Allows binding to a specific port; null if transport doesn't support binding

        /// <summary>Whether the server owns the transport and should dispose it.</summary>
        private bool _ownsTransport; // If true, Dispose() will clean up the transport; false if managed externally

        /// <summary>Server aggregate bandwidth limit in bytes per second.</summary>
        private int _bandwidthLimitBytesPerSecond; // Caps total bytes per second across all connections for fair-queue

        /// <summary>Protocol configuration for accepted connections.</summary>
        private UcpConfiguration _config; // Cloned per-connection for isolation; changes don't affect other connections

        /// <summary>Reference to the network engine if multiplexed.</summary>
        private UcpNetwork _network; // Non-null when server runs inside a multiplexed UcpNetwork event loop

        /// <summary>Active connections keyed by ConnectionId only (IP-agnostic).</summary>
        private readonly Dictionary<uint, ConnectionEntry> _connections = new Dictionary<uint, ConnectionEntry>(); // Lookup table mapping connection IDs to their PCB + wrapper entries

        /// <summary>Queue of connections waiting to be accepted by the application.</summary>
        private readonly Queue<UcpConnection> _acceptQueue = new Queue<UcpConnection>(); // FIFO order so application accepts in connection-establishment order

        /// <summary>Semaphore signaled when a new connection is ready for acceptance.</summary>
        private readonly SemaphoreSlim _acceptSignal = new SemaphoreSlim(0, int.MaxValue); // Released once per new connection; blocks AcceptAsync() until a connection arrives

        /// <summary>Timer driving fair-queue credit distribution rounds.</summary>
        private Timer _fairQueueTimer; // .NET Timer used in standalone mode (non-network); fires at configurable intervals

        /// <summary>Network timer ID for fair-queue scheduling when using UcpNetwork.</summary>
        private uint _fairQueueTimerId; // Non-zero when a fair-queue round is scheduled via the network's timer system

        /// <summary>Rotating start index for fair-queue round-robin ordering.</summary>
        private int _fairQueueStartIndex; // Ensures connections are flushed in a rotated order each round for fairness

        /// <summary>Microsecond timestamp of the last fair-queue round.</summary>
        private long _lastFairQueueRoundMicros; // Used to calculate elapsed time and the credit pool size for the current round

        /// <summary>Whether the server has been started.</summary>
        private bool _started; // Prevents double-start and guards against operations before Start()

        /// <summary>
        /// Creates a server with a new UdpSocketTransport and default configuration.
        /// </summary>
        public UcpServer()
            : this(new UdpSocketTransport(), true, new UcpConfiguration()) // Default: owns a fresh UDP transport with default settings
        {
        }

        /// <summary>
        /// Creates a server with a new UdpSocketTransport and the given configuration.
        /// </summary>
        /// <param name="config">Protocol configuration for accepted connections.</param>
        public UcpServer(UcpConfiguration config)
            : this(new UdpSocketTransport(), true, config ?? new UcpConfiguration()) // Coalesces null config to default to avoid NullReferenceException
        {
        }

        /// <summary>
        /// Creates a server wrapping an existing transport.
        /// </summary>
        internal UcpServer(ITransport transport)
            : this(transport, true, new UcpConfiguration()) // Internal: wraps an existing transport with default config
        {
        }

        /// <summary>
        /// Creates a server with a bandwidth limit for fair-queue scheduling.
        /// </summary>
        internal UcpServer(ITransport transport, int bandwidthLimitBytesPerSecond)
            : this(transport, true, CreateConfigWithBandwidth(bandwidthLimitBytesPerSecond)) // Builds a config with the bandwidth limit baked in
        {
        }

        /// <summary>
        /// Creates a server wrapping an existing transport with the given configuration.
        /// </summary>
        internal UcpServer(ITransport transport, UcpConfiguration config)
            : this(transport, true, config) // Internal: wraps transport with caller-supplied config, server owns transport
        {
        }

        /// <summary>
        /// Internal constructor with ownership and configuration.
        /// </summary>
        private UcpServer(ITransport transport, bool ownsTransport, UcpConfiguration config)
            : this(transport, ownsTransport, config, null) // Chains to the full constructor with no network context
        {
        }

        /// <summary>
        /// Full internal constructor for creating a server, optionally within a UcpNetwork.
        /// </summary>
        internal UcpServer(ITransport transport, bool ownsTransport, UcpConfiguration config, UcpNetwork network)
        {
            _transport = transport; // Store the transport reference for sending/receiving datagrams
            _bindableTransport = transport as IBindableTransport; // Attempt to cast to bindable interface; null if not supported
            _ownsTransport = ownsTransport; // Remember whether we're responsible for disposing the transport
            _config = config ?? new UcpConfiguration(); // Guard against null config by falling back to defaults
            _network = network; // May be null for standalone use; non-null when multiplexed
            _bandwidthLimitBytesPerSecond = _config.ServerBandwidthBytesPerSecond > 0 ? _config.ServerBandwidthBytesPerSecond : UcpConstants.DefaultServerBandwidthBytesPerSecond; // Use configured limit or fall back to default (2.5 MB/s)
        }

        /// <summary>
        /// Binds the transport to the given port and starts accepting connections.
        /// Subscribes to transport datagrams and starts the fair-queue timer.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
        public void Start(int port)
        {
            lock (_sync) // Acquire exclusive access to prevent races with Stop() or concurrent Start()
            {
                if (_started) // Already started — idempotent, avoid double binding
                {
                    return; // No-op: server is already running
                }

                if (_bindableTransport != null) // Check if the transport supports explicit port binding
                {
                    _bindableTransport.Start(port); // Bind the transport to the specified port so OS routes incoming packets here
                }

                _transport.OnDatagram += OnTransportDatagram; // Subscribe to incoming datagram events so we receive all packets
                _started = true; // Mark the server as started so other methods know it's active
                if (_network == null) // Standalone mode (no multiplexed event loop)
                {
                    // Standalone mode: use a .NET Timer for fair-queue rounds.
                    _fairQueueTimer = new Timer(OnFairQueueRound, null, _config.FairQueueRoundMilliseconds, _config.FairQueueRoundMilliseconds); // Create a periodic timer that fires every round interval (default 1ms) to distribute bandwidth
                }
                else
                {
                    // Network-managed mode: schedule fair-queue via network timers.
                    ScheduleFairQueueRound(); // Register the first fair-queue round in the network's timer system (driven by DoEvents)
                }
            }
        }

        /// <summary>Connection ID is always 0 for servers (not bound to a single connection).</summary>
        public uint ConnectionId
        {
            get { return 0U; } // Server is not associated with any single connection ID; always returns 0
        }

        /// <summary>The network engine that owns this server (may be null).</summary>
        public UcpNetwork Network
        {
            get { return _network; } // Expose the network context; null when standalone
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
            if (network == null) // Validate the network argument to prevent subsequent NullReferenceException
            {
                throw new ArgumentNullException(nameof(network)); // Fail fast with a clear error
            }

            lock (_sync) // Protect the state swap from concurrent access
            {
                if (_started) // Already started — idempotent guard
                {
                    return; // No-op: server was already started
                }

                _transport = network.TransportAdapter; // Replace transport with the network's shared adapter (multiplexed I/O)
                _bindableTransport = network.TransportAdapter; // Network's adapter also implements IBindableTransport for port binding
                _ownsTransport = false; // The network owns its transport; we must not dispose it
                _config = configuration == null ? network.Configuration.Clone() : configuration.Clone(); // Clone to isolate per-server config from other objects sharing the network
                _network = network; // Store the network reference for timer scheduling and time queries
                _bandwidthLimitBytesPerSecond = _config.ServerBandwidthBytesPerSecond > 0 ? _config.ServerBandwidthBytesPerSecond : UcpConstants.DefaultServerBandwidthBytesPerSecond; // Recalculate bandwidth limit from the new config
            }

            Start(port); // Delegate the actual binding and subscription to the core Start method
        }

        /// <summary>
        /// Asynchronously accepts the next incoming connection. Blocks until a
        /// new client connects and completes the handshake.
        /// </summary>
        /// <returns>The accepted UcpConnection.</returns>
        public async Task<UcpConnection> AcceptAsync()
        {
            while (true) // Loop to handle spurious wake-ups (unlikely with SemaphoreSlim but defensive)
            {
                lock (_sync) // Check the accept queue under lock to avoid race with OnPcbConnected
                {
                    if (_acceptQueue.Count > 0) // A connection is waiting to be accepted
                    {
                        return _acceptQueue.Dequeue(); // Remove from queue and return to the caller (FIFO order)
                    }
                }

                await _acceptSignal.WaitAsync().ConfigureAwait(false); // Block asynchronously until a new connection is enqueued and signals
            }
        }

        /// <summary>
        /// Stops the server: unsubscribes from transport events, stops the
        /// fair-queue timer, disposes all PCBs, and stops the transport.
        /// </summary>
        public void Stop()
        {
            List<ConnectionEntry> entries = new List<ConnectionEntry>(); // Prepare a local list to hold entries for disposal outside the lock
            lock (_sync) // Acquire lock to snapshot and clear state atomically
            {
                if (!_started) // Server wasn't started or already stopped
                {
                    return; // Nothing to stop
                }

                _started = false; // Immediately mark as not started so no new operations begin
                _transport.OnDatagram -= OnTransportDatagram; // Unsubscribe from transport events to stop receiving packets
                if (_fairQueueTimer != null) // A standalone timer was running
                {
                    _fairQueueTimer.Dispose(); // Release the timer's native resources and stop callbacks
                    _fairQueueTimer = null; // Clear the reference so we don't try to dispose again
                }

                if (_network != null && _fairQueueTimerId != 0) // A network-managed fair-queue round is scheduled
                {
                    _network.CancelTimer(_fairQueueTimerId); // Cancel the pending network timer so it won't fire after we stop
                    _fairQueueTimerId = 0; // Reset the timer ID to guard against double cancellation
                }

                // Snapshot and clear connections for safe disposal outside lock.
                foreach (KeyValuePair<uint, ConnectionEntry> pair in _connections) // Iterate all active connections
                {
                    entries.Add(pair.Value); // Collect each ConnectionEntry for later disposal
                }

                _connections.Clear(); // Empty the dictionary under lock so no new lookups find stale entries
            }

            // Dispose all PCBs outside the lock to avoid deadlock.
            for (int i = 0; i < entries.Count; i++) // Iterate the snapshot we collected
            {
                entries[i].Pcb.Dispose(); // Dispose each PCB, which triggers connection cleanup and packet flushing
            }

            if (_bindableTransport != null) // Transport supports explicit stop (socket close)
            {
                _bindableTransport.Stop(); // Stop the transport to release the bound port
            }

            if (_ownsTransport) // We created this transport internally
            {
                _transport.Dispose(); // Dispose transport to free native socket resources
            }
        }

        /// <summary>
        /// Disposes the server by calling Stop().
        /// </summary>
        public void Dispose()
        {
            Stop(); // Delegate to Stop() which handles all cleanup; idempotent via _started flag
        }

        /// <summary>
        /// Handles an incoming datagram from the transport. Decodes the packet,
        /// looks up or creates a connection entry, and dispatches it.
        /// </summary>
        private void OnTransportDatagram(byte[] datagram, IPEndPoint remoteEndPoint)
        {
            if (datagram == null || remoteEndPoint == null) // Guard against malformed transport callbacks
            {
                return; // Silently drop; nothing we can do with null data
            }

            UcpPacket packet; // Will hold the decoded packet structure
            if (!UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet)) // Attempt to decode the binary datagram into a typed packet
            {
                return; // Packet is malformed or unrecognized protocol; silently drop
            }

            ConnectionEntry entry = GetOrCreateConnection(remoteEndPoint, packet); // Look up existing connection or create a new one from SYN
            if (entry == null) // No entry found and the packet was not a SYN
            {
                return; // Non-SYN packet for unknown connection; silently dropped.
            }

            entry.Connection.DispatchPacket(packet, remoteEndPoint); // Forward the decoded packet to the connection's serial queue for processing
        }

        /// <summary>
        /// Looks up or creates a connection entry for the given remote endpoint
        /// and packet. Keyed by ConnectionId only (IP-agnostic). Only SYN packets
        /// create new entries; other packets on unknown connections return null.
        /// Updates the remote endpoint on existing connections to support IP/port changes.
        /// </summary>
        /// <param name="remoteEndPoint">The source endpoint of the packet.</param>
        /// <param name="packet">The decoded UCP packet.</param>
        /// <returns>The matching or newly created connection entry, or null.</returns>
        private ConnectionEntry GetOrCreateConnection(IPEndPoint remoteEndPoint, UcpPacket packet)
        {
            uint key = CreateKey(packet.Header.ConnectionId); // Derive the lookup key from the packet's connection ID
            ConnectionEntry entry; // Will hold the found or created entry
            lock (_sync) // Protect the connections dictionary from concurrent modification
            {
                if (_connections.TryGetValue(key, out entry)) // An entry already exists for this connection ID
                {
                    // Update the remote endpoint to support IP/port changes.
                    entry.Pcb.SetRemoteEndPoint(remoteEndPoint); // Track the latest remote endpoint in case NAT rebinding occurred
                    return entry; // Return the existing entry
                }

                if (packet.Header.Type != UcpPacketType.Syn) // Packet is not a connection request
                {
                    return null; // Only SYN can create new connections.
                }

                // Create a new PCB and wrap it in a UcpConnection.
                UcpPcb pcb = new UcpPcb(_transport, remoteEndPoint, true, true, OnPcbClosed, packet.Header.ConnectionId, _config.Clone(), _network); // Build a new server-side PCB with the packet's connection ID; server=true means it will respond with SYN-ACK
                UcpConnection connection = new UcpConnection(pcb, _transport, _config.Clone()); // Wrap the PCB in a UcpConnection so the application gets a clean API
                entry = new ConnectionEntry(); // Allocate the bookkeeping entry
                entry.Connection = connection; // Link the UcpConnection wrapper
                entry.Pcb = pcb; // Link the low-level PCB
                pcb.Connected += delegate { OnPcbConnected(entry); }; // Register callback: when handshake completes, enqueue for accept
                _connections[key] = entry; // Insert into the dictionary so subsequent packets find this entry
                return entry; // Return the new entry so the SYN can be dispatched
            }
        }

        /// <summary>
        /// Called when a PCB completes the handshake. Enqueues the connection
        /// for application acceptance and signals the accept semaphore.
        /// </summary>
        /// <param name="entry">The connection entry that became established.</param>
        private void OnPcbConnected(ConnectionEntry entry)
        {
            lock (_sync) // Protect _acceptQueue and Accepted flag from concurrent access
            {
                if (entry.Accepted) // Guard: already enqueued from a prior Connected event (shouldn't happen, but defensive)
                {
                    return; // Already accepted.
                }

                entry.Accepted = true; // Mark as accepted so we don't enqueue it twice
                _acceptQueue.Enqueue(entry.Connection); // Add the established connection to the FIFO accept queue
            }

            _acceptSignal.Release(); // Signal the accept semaphore so AcceptAsync() wakes up and dequeues
        }

        /// <summary>
        /// Called when a PCB is closed. Removes the connection entry from the
        /// server's connection table.
        /// </summary>
        /// <param name="pcb">The PCB that closed.</param>
        private void OnPcbClosed(UcpPcb pcb)
        {
            if (pcb == null) // Guard against null PCB passed by misbehaving callback
            {
                return; // Nothing to clean up
            }

            uint key = CreateKey(pcb.ConnectionId); // Derive the dictionary key from the closing PCB's connection ID
            lock (_sync) // Protect _connections from concurrent modification
            {
                _connections.Remove(key); // Remove the entry so the server forgets this connection
            }
        }

        /// <summary>
        /// Fair-queue timer callback. Runs the credit distribution round and
        /// reschedules if using a UcpNetwork.
        /// </summary>
        /// <param name="state">Timer state (unused).</param>
        private void OnFairQueueRound(object state)
        {
            OnFairQueueRoundCore(); // Execute the core credit distribution logic
            if (_network != null) // We are running inside a multiplexed network
            {
                ScheduleFairQueueRound(); // Re-schedule the next round via the network's timer system
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
            List<UcpConnection> active = new List<UcpConnection>(); // Build a list of connections eligible for credit this round
            lock (_sync) // Protect _connections dictionary during enumeration
            {
                foreach (KeyValuePair<uint, ConnectionEntry> pair in _connections) // Scan all tracked connections
                {
                    if ((pair.Value.Connection.State == UcpConnectionState.Established || pair.Value.Connection.State == UcpConnectionState.ClosingFinSent || pair.Value.Connection.State == UcpConnectionState.ClosingFinReceived) // Connection is in a state that can still send data
                        && pair.Value.Connection.HasPendingSendData) // Connection actually has buffered data waiting to be sent
                    {
                        active.Add(pair.Value.Connection); // Include this connection in the credit distribution round
                    }
                }
            }

            if (active.Count == 0) // No connections need bandwidth
            {
                return; // Nothing to distribute; skip the rest
            }

            // Calculate elapsed time since the last round to determine credit pool.
            long nowMicros = _network == null ? UcpTime.NowMicroseconds() : _network.CurrentTimeUs; // Get current time: use network's virtual clock if multiplexed, otherwise wall clock
            long elapsedMicros = _lastFairQueueRoundMicros == 0 ? _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI : nowMicros - _lastFairQueueRoundMicros; // On first round, assume exactly one interval has passed; otherwise compute actual elapsed time
            if (elapsedMicros < UcpConstants.MICROS_PER_MILLI) // Elapsed time is less than 1 millisecond (can happen with bursty timers)
            {
                elapsedMicros = UcpConstants.MICROS_PER_MILLI; // Clamp to a minimum of 1ms to avoid zero or negative credit
            }

            // Cap buffered rounds to prevent credit explosion after stalls.
            if (elapsedMicros > _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI * UcpConstants.MAX_BUFFERED_FAIR_QUEUE_ROUNDS) // More than MAX_BUFFERED rounds have passed (e.g., after a long GC pause)
            {
                elapsedMicros = _config.FairQueueRoundMilliseconds * UcpConstants.MICROS_PER_MILLI * UcpConstants.MAX_BUFFERED_FAIR_QUEUE_ROUNDS; // Cap at the maximum allowed buffered rounds to prevent overwhelming credit burst
            }

            _lastFairQueueRoundMicros = nowMicros; // Record the current time as the baseline for the next round's elapsed calculation
            double roundBytes = _bandwidthLimitBytesPerSecond * (elapsedMicros / (double)UcpConstants.MICROS_PER_SECOND); // Calculate total bytes allowed this round: bandwidth limit * elapsed time in seconds
            double fairShareCap = active.Count > 0 ? _bandwidthLimitBytesPerSecond / (double)active.Count : _bandwidthLimitBytesPerSecond; // Each connection's maximum fair share per second (bandwidth divided equally)
            double effectiveTotalPacing = 0; // Accumulator for the sum of all effective pacing rates (used for proportional distribution)
            double[] effectivePacing = new double[active.Count]; // Array to hold each connection's effective pacing rate for this round

            // Collect each connection's effective pacing rate, capped at fair share.
            for (int i = 0; i < active.Count; i++) // Iterate all active connections
            {
                double pacing = active[i].CurrentPacingRateBytesPerSecond; // Get the connection's current pacing rate (congestion-controlled send rate)
                if (pacing <= 0) // Connection has no computed pacing rate (e.g., just started, no RTT samples)
                {
                    pacing = fairShareCap; // Default to equal fair share so new connections get a baseline credit
                }

                if (pacing > fairShareCap) // Pacing rate exceeds the equal-share cap
                {
                    pacing = fairShareCap; // Clamp to fair share so no single connection can starve others
                }

                effectivePacing[i] = pacing; // Store the capped pacing rate for this connection
                effectiveTotalPacing += pacing; // Accumulate into the total for proportional distribution denominator
            }

            if (effectiveTotalPacing <= 0) // All connections have zero pacing (edge case, shouldn't happen after clamping)
            {
                effectiveTotalPacing = active.Count; // Fall back to equal weight so each connection gets roundBytes / count
            }

            // Distribute credit proportional to each connection's effective pacing share.
            for (int i = 0; i < active.Count; i++) // Iterate all active connections again
            {
                double credit = (effectivePacing[i] / effectiveTotalPacing) * roundBytes; // Calculate credit: this connection's share of pacing * total round bytes
                active[i].AddFairQueueCredit(credit); // Add the credit to the connection's PCB so it can send more data this round
            }

            // Rotate the start index for round-robin flush ordering.
            int startIndex = 0; // Will hold the starting index into the active list for this round
            lock (_sync) // Protect _fairQueueStartIndex read-modify-write
            {
                if (_fairQueueStartIndex >= active.Count) // Start index has grown past the list size (connections were removed)
                {
                    _fairQueueStartIndex = 0; // Reset to the beginning so we don't index out of bounds
                }

                startIndex = _fairQueueStartIndex; // Capture the current start index for this round
                _fairQueueStartIndex++; // Advance for the next round so different connections get priority each time
            }

            // Flush each connection in rotated round-robin order.
            for (int i = 0; i < active.Count; i++) // Iterate in rotated order
            {
                int index = (startIndex + i) % active.Count; // Compute the index with wrap-around so we start at startIndex and cycle
                active[index].RequestFlush(); // Tell the connection to immediately flush its send buffer (subject to its credit limit)
            }
        }

        /// <summary>
        /// Schedules the next fair-queue round via the network timer.
        /// </summary>
        private void ScheduleFairQueueRound()
        {
            if (_network == null) // Guard: only meaningful when running under a UcpNetwork
            {
                return; // Standalone mode uses .NET Timer, no need to schedule via network
            }

            lock (_sync) // Protect _started and _fairQueueTimerId from concurrent Stop()
            {
                if (!_started) // Server has been stopped
                {
                    return; // Don't schedule if we're shutting down
                }

                long delayMicros = Math.Max(UcpConstants.MIN_TIMER_WAIT_MILLISECONDS, _config.FairQueueRoundMilliseconds) * UcpConstants.MICROS_PER_MILLI; // Calculate the delay in microseconds, clamped to a minimum to avoid busy-waiting
                _fairQueueTimerId = _network.AddTimer(_network.NowMicroseconds + delayMicros, delegate { OnFairQueueRound(null); }); // Register a one-shot timer in the network's event loop that fires after delayMicros
            }
        }

        /// <summary>
        /// Returns the connection ID as the lookup key (IP-agnostic).
        /// </summary>
        private static uint CreateKey(uint connectionId)
        {
            return connectionId; // Direct identity mapping: the connection ID itself is the lookup key
        }

        /// <summary>
        /// Creates a configuration with the specified bandwidth limit.
        /// </summary>
        private static UcpConfiguration CreateConfigWithBandwidth(int bandwidthLimitBytesPerSecond)
        {
            UcpConfiguration config = new UcpConfiguration(); // Create a fresh default configuration instance
            if (bandwidthLimitBytesPerSecond > 0) // A positive bandwidth limit was specified
            {
                config.ServerBandwidthBytesPerSecond = bandwidthLimitBytesPerSecond; // Override the server bandwidth setting
            }

            return config; // Return the configured (or default) configuration
        }
    }
}
