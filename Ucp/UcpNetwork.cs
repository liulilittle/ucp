using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using Ucp.Internal;
using Ucp.Transport;

namespace Ucp
{
    /// <summary>
    /// Abstract event-loop network driver that decouples the UCP protocol engine
    /// from socket I/O. Call <c>DoEvents()</c> in a loop to drive all timers,
    /// delayed flushes, RTO checks, and fair-queue rounds.
    ///
    /// <c>Input(byte[], IPEndPoint)</c> injects received datagrams.
    /// <c>Output(byte[], IPEndPoint, IUcpObject)</c> must be implemented by the
    /// derived class to send encoded packets to the network.
    ///
    /// The default UDP implementation is <see cref="UcpDatagramNetwork"/>.
    /// </summary>
    public abstract class UcpNetwork : IDisposable
    {
        /// <summary>
        /// Represents a single timer registration with a callback and expiration time.
        /// </summary>
        private sealed class TimerRegistration
        {
            /// <summary>Unique timer identifier.</summary>
            public uint Id;

            /// <summary>Absolute expiration time in microseconds.</summary>
            public long ExpireMicros;

            /// <summary>Wrapped callback that handles cancellation checks.</summary>
            public Action Callback;
        }

        /// <summary>
        /// Internal transport adapter that bridges the network's Input/Output with
        /// the transport interface. Implements IBindableTransport and IUcpObject
        /// so the protocol stack can be used transparently.
        /// </summary>
        private sealed class NetworkTransportAdapter : IBindableTransport, IUcpObject
        {
            /// <summary>Reference to the owning UcpNetwork.</summary>
            private readonly UcpNetwork network;

            /// <summary>
            /// Creates a transport adapter linked to the given network.
            /// </summary>
            public NetworkTransportAdapter(UcpNetwork network)
            {
                this.network = network;
            }

            public event Action<byte[], IPEndPoint> OnDatagram;

            /// <summary>Gets the network's local endpoint.</summary>
            public EndPoint LocalEndPoint
            {
                get { return network.LocalEndPoint; }
            }

            /// <summary>Connection ID is always 0 for the network-level transport.</summary>
            public uint ConnectionId
            {
                get { return 0; }
            }

            /// <summary>Returns the owning UcpNetwork.</summary>
            public UcpNetwork Network
            {
                get { return network; }
            }

            /// <summary>Delegates start to the network.</summary>
            public void Start(int port)
            {
                network.Start(port);
            }

            /// <summary>Delegates stop to the network.</summary>
            public void Stop()
            {
                network.Stop();
            }

            /// <summary>Delegates send to the network's Output method.</summary>
            public void Send(byte[] data, IPEndPoint remote)
            {
                network.Output(data, remote, this);
            }

            /// <summary>No-op dispose for the adapter.</summary>
            public void Dispose()
            {
            }

            /// <summary>
            /// Raises the OnDatagram event so the protocol stack receives the datagram.
            /// </summary>
            /// <param name="datagram">The raw datagram bytes.</param>
            /// <param name="remote">The source endpoint.</param>
            public void Raise(byte[] datagram, IPEndPoint remote)
            {
                Action<byte[], IPEndPoint> handler = OnDatagram;
                if (handler != null)
                {
                    handler(datagram, remote);
                }
            }
        }

        /// <summary>Synchronization lock for the timer heap.</summary>
        private readonly object _timerSync = new object();

        /// <summary>Synchronization lock for the PCB registry.</summary>
        private readonly object _pcbSync = new object();

        /// <summary>Timer heap sorted by expiration time, mapping to callback lists.</summary>
        private readonly SortedDictionary<long, List<Action>> _timerHeap = new SortedDictionary<long, List<Action>>();

        /// <summary>Active timer registrations keyed by timer ID for cancellation.</summary>
        private readonly Dictionary<uint, TimerRegistration> _activeTimers = new Dictionary<uint, TimerRegistration>();

        /// <summary>PCB lookup by connection ID for fast packet routing.</summary>
        private readonly Dictionary<uint, UcpPcb> _pcbsByConnectionId = new Dictionary<uint, UcpPcb>();

        /// <summary>List of all active PCBs for DoEvents tick processing.</summary>
        private readonly List<UcpPcb> _activePcbs = new List<UcpPcb>();

        /// <summary>Internal transport adapter used by connections created via this network.</summary>
        private readonly NetworkTransportAdapter _transportAdapter;

        /// <summary>Auto-incrementing counter for unique timer IDs.</summary>
        private int _nextTimerId;

        /// <summary>Cached current time in microseconds for protocol use.</summary>
        private long _currentTimeUs;

        /// <summary>Cached current time in milliseconds for throttling updates.</summary>
        private long _currentTimeMs;

        /// <summary>Whether this network has been disposed.</summary>
        private bool _disposed;

        /// <summary>
        /// Creates a network with default configuration.
        /// </summary>
        protected UcpNetwork()
            : this(new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates a network with the given configuration.
        /// </summary>
        /// <param name="configuration">Protocol configuration (cloned internally).</param>
        protected UcpNetwork(UcpConfiguration configuration)
        {
            Configuration = configuration == null ? new UcpConfiguration() : configuration.Clone();
            _transportAdapter = new NetworkTransportAdapter(this);
            _currentTimeUs = UcpTime.ReadStopwatchMicroseconds();
            _currentTimeMs = _currentTimeUs / UcpConstants.MICROS_PER_MILLI;
        }

        /// <summary>Protocol configuration (read-only after construction).</summary>
        public UcpConfiguration Configuration { get; private set; }

        /// <summary>Internal transport adapter exposed for connection/server creation.</summary>
        internal IBindableTransport TransportAdapter
        {
            get { return _transportAdapter; }
        }

        /// <summary>Returns the raw stopwatch-based microsecond time (not the cached clock).</summary>
        public long NowMicroseconds
        {
            get { return Volatile.Read(ref _currentTimeUs); }
        }

        /// <summary>
        /// Cached network clock in microseconds. Protocol code uses this value so
        /// all timers, RTT samples, and pacing decisions advance from one logical
        /// clock owned by DoEvents rather than from scattered system time reads.
        /// </summary>
        public long CurrentTimeUs
        {
            get { return Volatile.Read(ref _currentTimeUs); }
        }

        /// <summary>Local endpoint of the network (override in derived classes).</summary>
        public virtual EndPoint LocalEndPoint
        {
            get { return null; }
        }

        /// <summary>
        /// Creates a UcpServer using this network's transport adapter and starts
        /// it on the given port.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
        /// <returns>A started UcpServer.</returns>
        public UcpServer CreateServer(int port)
        {
            UcpServer server = new UcpServer(_transportAdapter, false, Configuration.Clone(), this);
            server.Start(port);
            return server;
        }

        /// <summary>
        /// Creates a UcpConnection using this network's transport adapter and
        /// default configuration.
        /// </summary>
        public UcpConnection CreateConnection()
        {
            return CreateConnection(Configuration);
        }

        /// <summary>
        /// Creates a UcpConnection using this network's transport adapter and
        /// the given configuration.
        /// </summary>
        /// <param name="configuration">Protocol configuration (cloned internally).</param>
        public UcpConnection CreateConnection(UcpConfiguration configuration)
        {
            UcpConfiguration config = configuration == null ? Configuration.Clone() : configuration.Clone();
            return new UcpConnection(_transportAdapter, false, config, this);
        }

        /// <summary>Starts the network (override in derived classes for socket binding).</summary>
        public virtual void Start(int port)
        {
        }

        /// <summary>Stops the network (override in derived classes for socket cleanup).</summary>
        public virtual void Stop()
        {
        }

        /// <summary>
        /// Injects a received datagram into the network. Decodes the packet and
        /// routes it to the appropriate PCB, or falls back to the transport adapter
        /// (which triggers server/connection accept logic) for SYN packets.
        /// </summary>
        /// <param name="datagram">The raw datagram bytes.</param>
        /// <param name="remote">The source endpoint.</param>
        public void Input(byte[] datagram, IPEndPoint remote)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }

            if (datagram == null)
            {
                throw new ArgumentNullException(nameof(datagram));
            }

            if (remote == null)
            {
                throw new ArgumentNullException(nameof(remote));
            }

            if (datagram.Length < UcpConstants.CommonHeaderSize)
            {
                return; // Too short to be a valid UCP packet.
            }

            UcpPacket packet;
            if (UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet))
            {
                UcpPcb pcb;
                lock (_pcbSync)
                {
                    _pcbsByConnectionId.TryGetValue(packet.Header.ConnectionId, out pcb);
                }

                if (pcb != null)
                {
                    // Directly dispatch to the known PCB for efficiency.
                    pcb.DispatchFromNetwork(packet, remote);
                    return;
                }

                if (packet.Header.Type != UcpPacketType.Syn)
                {
                    return; // Unknown connection and not a SYN; drop silently.
                }
            }

            // Fallback: raise to transport adapter for server/connection creation.
            _transportAdapter.Raise(datagram, remote);
        }

        /// <summary>
        /// Convenience override for Output without a sender reference.
        /// </summary>
        public void Output(byte[] datagram, IPEndPoint remote)
        {
            Output(datagram, remote, null);
        }

        /// <summary>
        /// Sends an encoded packet to the network. Must be implemented by derived classes.
        /// </summary>
        /// <param name="datagram">The encoded packet bytes.</param>
        /// <param name="remote">The destination endpoint.</param>
        /// <param name="sender">The sending object (connection, server, or null).</param>
        public abstract void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender);

        /// <summary>
        /// Adds a one-shot timer that fires at the given absolute time in microseconds.
        /// The callback is wrapped to check for cancellation before execution.
        /// </summary>
        /// <param name="expireUs">Absolute expiration time in microseconds.</param>
        /// <param name="callback">The callback to invoke.</param>
        /// <returns>A timer ID that can be used with CancelTimer.</returns>
        public uint AddTimer(long expireUs, Action callback)
        {
            if (callback == null)
            {
                throw new ArgumentNullException(nameof(callback));
            }

            uint timerId = unchecked((uint)Interlocked.Increment(ref _nextTimerId));
            TimerRegistration registration = new TimerRegistration();
            registration.Id = timerId;
            registration.ExpireMicros = expireUs;

            // Wrap the callback to check for cancellation before executing.
            Action wrappedCallback = delegate
            {
                bool shouldRun = false;
                lock (_timerSync)
                {
                    TimerRegistration active;
                    if (_activeTimers.TryGetValue(timerId, out active) && object.ReferenceEquals(active, registration))
                    {
                        _activeTimers.Remove(timerId);
                        shouldRun = true;
                    }
                }

                if (shouldRun)
                {
                    callback();
                }
            };

            registration.Callback = wrappedCallback;
            lock (_timerSync)
            {
                _activeTimers[timerId] = registration;
                List<Action> callbacks;
                if (!_timerHeap.TryGetValue(expireUs, out callbacks))
                {
                    callbacks = new List<Action>();
                    _timerHeap[expireUs] = callbacks;
                }

                callbacks.Add(wrappedCallback);
            }

            return timerId;
        }

        /// <summary>
        /// Cancels a pending timer. Returns true if the timer was found and cancelled.
        /// </summary>
        /// <param name="timerId">The timer ID returned by AddTimer.</param>
        public bool CancelTimer(uint timerId)
        {
            lock (_timerSync)
            {
                return _activeTimers.Remove(timerId);
            }
        }

        /// <summary>
        /// Drives one iteration of the event loop: fires due timers and ticks all
        /// active PCBs. Returns the total number of work items processed (callbacks + PCB ticks).
        /// </summary>
        /// <returns>Number of work items processed in this iteration.</returns>
        public virtual int DoEvents()
        {
            if (_disposed)
            {
                return 0;
            }

            UpdateCachedClock();

            // Collect all due callbacks from the timer heap.
            List<Action> dueCallbacks = new List<Action>();
            long nowMicros = CurrentTimeUs;
            lock (_timerSync)
            {
                while (_timerHeap.Count > 0)
                {
                    long firstKey;
                    List<Action> firstCallbacks;
                    GetFirstTimerUnsafe(out firstKey, out firstCallbacks);
                    if (firstKey > nowMicros)
                    {
                        break; // No more expired timers.
                    }

                    _timerHeap.Remove(firstKey);
                    for (int i = 0; i < firstCallbacks.Count; i++)
                    {
                        dueCallbacks.Add(firstCallbacks[i]);
                    }
                }
            }

            // Execute all due callbacks.
            for (int i = 0; i < dueCallbacks.Count; i++)
            {
                dueCallbacks[i]();
            }

            // Tick all active PCBs.
            List<UcpPcb> snapshot = SnapshotPcbs();
            int pcbWork = 0;
            for (int i = 0; i < snapshot.Count; i++)
            {
                pcbWork += snapshot[i].OnTick(CurrentTimeUs);
            }

            // If no work was done, yield to avoid busy-waiting.
            if (dueCallbacks.Count == 0 && pcbWork == 0)
            {
                YieldWhenIdle();
            }

            return dueCallbacks.Count + pcbWork;
        }

        /// <summary>
        /// Registers a PCB with this network for fast packet routing and tick processing.
        /// </summary>
        internal void RegisterPcb(UcpPcb pcb)
        {
            if (pcb == null)
            {
                return;
            }

            lock (_pcbSync)
            {
                if (!_activePcbs.Contains(pcb))
                {
                    _activePcbs.Add(pcb);
                }

                if (pcb.ConnectionId != 0)
                {
                    _pcbsByConnectionId[pcb.ConnectionId] = pcb;
                }
            }
        }

        /// <summary>
        /// Updates a PCB's connection ID in the lookup table after the handshake
        /// assigns a final ID.
        /// </summary>
        internal void UpdatePcbConnectionId(UcpPcb pcb, uint oldConnectionId, uint newConnectionId)
        {
            if (pcb == null || newConnectionId == 0)
            {
                return;
            }

            lock (_pcbSync)
            {
                if (oldConnectionId != 0)
                {
                    UcpPcb existing;
                    if (_pcbsByConnectionId.TryGetValue(oldConnectionId, out existing) && object.ReferenceEquals(existing, pcb))
                    {
                        _pcbsByConnectionId.Remove(oldConnectionId);
                    }
                }

                _pcbsByConnectionId[newConnectionId] = pcb;
                if (!_activePcbs.Contains(pcb))
                {
                    _activePcbs.Add(pcb);
                }
            }
        }

        /// <summary>
        /// Unregisters a PCB from this network's routing and tick lists.
        /// </summary>
        internal void UnregisterPcb(UcpPcb pcb)
        {
            if (pcb == null)
            {
                return;
            }

            lock (_pcbSync)
            {
                _activePcbs.Remove(pcb);
                uint connectionId = pcb.ConnectionId;
                if (connectionId != 0)
                {
                    UcpPcb existing;
                    if (_pcbsByConnectionId.TryGetValue(connectionId, out existing) && object.ReferenceEquals(existing, pcb))
                    {
                        _pcbsByConnectionId.Remove(connectionId);
                    }
                }
            }
        }

        /// <summary>
        /// Disposes the network: stops and clears all timers.
        /// </summary>
        public virtual void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            Stop();
            lock (_timerSync)
            {
                _activeTimers.Clear();
                _timerHeap.Clear();
            }
        }

        /// <summary>
        /// Retrieves the first (earliest) timer entry without removing it.
        /// Must be called under _timerSync lock.
        /// </summary>
        private void GetFirstTimerUnsafe(out long expireUs, out List<Action> callbacks)
        {
            foreach (KeyValuePair<long, List<Action>> pair in _timerHeap)
            {
                expireUs = pair.Key;
                callbacks = pair.Value;
                return;
            }

            expireUs = 0;
            callbacks = null;
        }

        /// <summary>
        /// Yields the calling thread when no work is pending to avoid busy-waiting.
        /// If the next timer is imminent (&lt;= 1ms), uses Thread.Yield() for low
        /// latency; otherwise sleeps for 1ms.
        /// </summary>
        private void YieldWhenIdle()
        {
            long nextExpireUs = 0;
            bool hasTimer = false;
            lock (_timerSync)
            {
                if (_timerHeap.Count > 0)
                {
                    List<Action> ignored;
                    GetFirstTimerUnsafe(out nextExpireUs, out ignored);
                    hasTimer = true;
                }
            }

            if (hasTimer && nextExpireUs - CurrentTimeUs <= UcpConstants.MICROS_PER_MILLI)
            {
                Thread.Yield();
                return;
            }

            Thread.Sleep(1);
        }

        /// <summary>
        /// Updates the cached clock from the high-resolution stopwatch at most
        /// once per millisecond. This avoids the overhead of reading the stopwatch
        /// on every protocol operation.
        /// </summary>
        private void UpdateCachedClock()
        {
            long stopwatchUs = UcpTime.ReadStopwatchMicroseconds();
            long stopwatchMs = stopwatchUs / UcpConstants.MICROS_PER_MILLI;
            long cachedMs = Volatile.Read(ref _currentTimeMs);
            if (stopwatchMs != cachedMs)
            {
                Volatile.Write(ref _currentTimeUs, stopwatchUs);
                Volatile.Write(ref _currentTimeMs, stopwatchMs);
            }
        }

        /// <summary>
        /// Creates a snapshot of all active PCBs for safe iteration outside the lock.
        /// </summary>
        private List<UcpPcb> SnapshotPcbs()
        {
            lock (_pcbSync)
            {
                return new List<UcpPcb>(_activePcbs);
            }
        }
    }
}
