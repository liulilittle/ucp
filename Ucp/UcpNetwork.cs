using System;                       // Brings in core types (Exception, IDisposable, etc.)
using System.Collections.Generic;    // Brings in Dictionary, List, SortedDictionary
using System.Net;                    // Brings in IPEndPoint, EndPoint
using System.Threading;              // Brings in Interlocked, Volatile, Thread
using Ucp.Internal;                  // Internal protocol types: UcpPcb, UcpTime, UcpConstants, etc.
using Ucp.Transport;                 // Transport abstractions: IBindableTransport, IUcpObject

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
    public abstract class UcpNetwork : IDisposable // Abstract so derived classes provide socket I/O; IDisposable for deterministic cleanup
    {
        /// <summary>
        /// Represents a single timer registration with a callback and expiration time.
        /// </summary>
        private sealed class TimerRegistration // sealed — no subclasses needed; stored in dictionaries
        {
            /// <summary>Unique timer identifier.</summary>
            public uint Id; // Monotonically-increasing ID assigned from _nextTimerId

            /// <summary>Absolute expiration time in microseconds.</summary>
            public long ExpireMicros; // Compared against CurrentTimeUs in DoEvents to decide firing

            /// <summary>Wrapped callback that handles cancellation checks.</summary>
            public Action Callback; // Wraps the user callback with a cancellation guard (see AddTimer)
        }

        /// <summary>
        /// Internal transport adapter that bridges the network's Input/Output with
        /// the transport interface. Implements IBindableTransport and IUcpObject
        /// so the protocol stack can be used transparently.
        /// </summary>
        private sealed class NetworkTransportAdapter : IBindableTransport, IUcpObject // Adapter pattern: wraps UcpNetwork as a transport for the protocol stack
        {
            /// <summary>Reference to the owning UcpNetwork.</summary>
            private readonly UcpNetwork network; // Back-reference so Start/Stop/Send delegate to the owning network

            /// <summary>
            /// Creates a transport adapter linked to the given network.
            /// </summary>
            public NetworkTransportAdapter(UcpNetwork network)
            {
                this.network = network; // Store the owning network for delegation throughout adapter lifetime
            }

            public event Action<byte[], IPEndPoint> OnDatagram; // Raised when Input's fallback path receives a datagram for server/connection accept

            /// <summary>Gets the network's local endpoint.</summary>
            public EndPoint LocalEndPoint
            {
                get { return network.LocalEndPoint; } // Delegate to the owning network (derived class provides real endpoint)
            }

            /// <summary>Connection ID is always 0 for the network-level transport.</summary>
            public uint ConnectionId
            {
                get { return 0; } // Network-level adapter is not a connection; always returns 0
            }

            /// <summary>Returns the owning UcpNetwork.</summary>
            public UcpNetwork Network
            {
                get { return network; } // Expose back-reference so UcpServer/UcpConnection can access network-wide state
            }

            /// <summary>Delegates start to the network.</summary>
            public void Start(int port)
            {
                network.Start(port); // Forward to the owning network's socket-bind logic
            }

            /// <summary>Delegates stop to the network.</summary>
            public void Stop()
            {
                network.Stop(); // Forward to the owning network's socket-close logic
            }

            /// <summary>Delegates send to the network's Output method.</summary>
            public void Send(byte[] data, IPEndPoint remote)
            {
                network.Output(data, remote, this); // Pass 'this' as sender so derived Output can trace the source
            }

            /// <summary>No-op dispose for the adapter.</summary>
            public void Dispose()
            {
                // Adapter owns no unmanaged resources; nothing to release
            }

            /// <summary>
            /// Raises the OnDatagram event so the protocol stack receives the datagram.
            /// </summary>
            /// <param name="datagram">The raw datagram bytes.</param>
            /// <param name="remote">The source endpoint.</param>
            public void Raise(byte[] datagram, IPEndPoint remote)
            {
                Action<byte[], IPEndPoint> handler = OnDatagram; // Snapshot delegate to avoid NullReferenceException if unsubscribed between check and invoke
                if (handler != null) // Only invoke if there are subscribers (e.g. server/connection accept handlers)
                {
                    handler(datagram, remote); // Deliver the datagram into the protocol stack for processing
                }
            }
        }

        /// <summary>Synchronization lock for the timer heap.</summary>
        private readonly object _timerSync = new object(); // Dedicated lock object for _timerHeap and _activeTimers (never lock(this))

        /// <summary>Synchronization lock for the PCB registry.</summary>
        private readonly object _pcbSync = new object(); // Dedicated lock object for _activePcbs and _pcbsByConnectionId

        /// <summary>Timer heap sorted by expiration time, mapping to callback lists.</summary>
        private readonly SortedDictionary<long, List<Action>> _timerHeap = new SortedDictionary<long, List<Action>>(); // Min-heap: earliest-expiring timers at lowest key; multiple callbacks per key

        /// <summary>Active timer registrations keyed by timer ID for cancellation.</summary>
        private readonly Dictionary<uint, TimerRegistration> _activeTimers = new Dictionary<uint, TimerRegistration>(); // Fast O(1) lookup by timer ID for CancelTimer

        /// <summary>PCB lookup by connection ID for fast packet routing.</summary>
        private readonly Dictionary<uint, UcpPcb> _pcbsByConnectionId = new Dictionary<uint, UcpPcb>(); // O(1) routing of incoming packets to the owning PCB

        /// <summary>List of all active PCBs for DoEvents tick processing.</summary>
        private readonly List<UcpPcb> _activePcbs = new List<UcpPcb>(); // Iterated each DoEvents to call OnTick on every PCB

        /// <summary>Internal transport adapter used by connections created via this network.</summary>
        private readonly NetworkTransportAdapter _transportAdapter; // Single shared adapter; created in constructor, used by connection/server factories

        /// <summary>Auto-incrementing counter for unique timer IDs.</summary>
        private int _nextTimerId; // Incremented atomically via Interlocked.Increment; starts at 0

        /// <summary>Cached current time in microseconds for protocol use.</summary>
        private long _currentTimeUs; // Updated at most once per millisecond by UpdateCachedClock; read via Volatile

        /// <summary>Cached current time in milliseconds for throttling updates.</summary>
        private long _currentTimeMs; // Used by UpdateCachedClock to decide whether a full clock refresh is needed

        /// <summary>Whether this network has been disposed.</summary>
        private bool _disposed; // Set to true in Dispose; checked in Input and DoEvents to prevent use-after-free

        /// <summary>
        /// Creates a network with default configuration.
        /// </summary>
        protected UcpNetwork()
            : this(new UcpConfiguration()) // Chain to the parameterized constructor with a fresh default configuration
        {
        }

        /// <summary>
        /// Creates a network with the given configuration.
        /// </summary>
        /// <param name="configuration">Protocol configuration (cloned internally).</param>
        protected UcpNetwork(UcpConfiguration configuration)
        {
            Configuration = configuration == null ? new UcpConfiguration() : configuration.Clone(); // Clone to prevent external mutation; default to new if null passed
            _transportAdapter = new NetworkTransportAdapter(this); // Create the adapter that bridges this network instance to the transport layer
            _currentTimeUs = UcpTime.ReadStopwatchMicroseconds(); // Seed the cached clock with the current high-resolution monotonic time
            _currentTimeMs = _currentTimeUs / UcpConstants.MICROS_PER_MILLI; // Derive the millisecond value from the microsecond reading
        }

        /// <summary>Protocol configuration (read-only after construction).</summary>
        public UcpConfiguration Configuration { get; private set; } // Exposed so connections/servers can read tuning parameters

        /// <summary>Internal transport adapter exposed for connection/server creation.</summary>
        internal IBindableTransport TransportAdapter
        {
            get { return _transportAdapter; } // Internal visibility: only the UCP library assembly uses this for factory methods
        }

        /// <summary>Returns the raw stopwatch-based microsecond time (not the cached clock).</summary>
        public long NowMicroseconds
        {
            get { return Volatile.Read(ref _currentTimeUs); } // Volatile read avoids a full fence; value may be stale up to ~1ms
        }

        /// <summary>
        /// Cached network clock in microseconds. Protocol code uses this value so
        /// all timers, RTT samples, and pacing decisions advance from one logical
        /// clock owned by DoEvents rather than from scattered system time reads.
        /// </summary>
        public long CurrentTimeUs
        {
            get { return Volatile.Read(ref _currentTimeUs); } // Same backing field as NowMicroseconds; protocol reads this for consistent time within a tick
        }

        /// <summary>Local endpoint of the network (override in derived classes).</summary>
        public virtual EndPoint LocalEndPoint
        {
            get { return null; } // Base returns null; derived classes (e.g. UdpNetwork) override with the bound socket's local endpoint
        }

        /// <summary>
        /// Creates a UcpServer using this network's transport adapter and starts
        /// it on the given port.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
        /// <returns>A started UcpServer.</returns>
        public UcpServer CreateServer(int port)
        {
            UcpServer server = new UcpServer(_transportAdapter, false, Configuration.Clone(), this); // 'false' = not client-owned; clone config to isolate mutations
            server.Start(port); // Bind to the given port and start the accept loop
            return server; // Return the now-running server to the caller for further use
        }

        /// <summary>
        /// Creates a UcpConnection using this network's transport adapter and
        /// default configuration.
        /// </summary>
        public UcpConnection CreateConnection()
        {
            return CreateConnection(Configuration); // Delegate to the parameterized overload with the network's stored configuration
        }

        /// <summary>
        /// Creates a UcpConnection using this network's transport adapter and
        /// the given configuration.
        /// </summary>
        /// <param name="configuration">Protocol configuration (cloned internally).</param>
        public UcpConnection CreateConnection(UcpConfiguration configuration)
        {
            UcpConfiguration config = configuration == null ? Configuration.Clone() : configuration.Clone(); // Fall back to network config if null; always clone for isolation
            return new UcpConnection(_transportAdapter, false, config, this); // 'false' = client-mode connection (not server-owned)
        }

        /// <summary>Starts the network (override in derived classes for socket binding).</summary>
        public virtual void Start(int port)
        {
            // Base implementation is a no-op; derived classes bind a socket and begin receiving here
        }

        /// <summary>Stops the network (override in derived classes for socket cleanup).</summary>
        public virtual void Stop()
        {
            // Base implementation is a no-op; derived classes close their socket here
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
            if (_disposed) // Guard: reject all input after disposal to prevent accessing cleared data structures
            {
                throw new ObjectDisposedException(GetType().Name); // Fail loudly; caller should not be feeding a disposed network
            }

            if (datagram == null) // Validate the datagram argument
            {
                throw new ArgumentNullException(nameof(datagram)); // Fail fast rather than producing confusing NullReferenceException later
            }

            if (remote == null) // Validate the remote endpoint argument
            {
                throw new ArgumentNullException(nameof(remote)); // Fail fast; routing requires a valid remote address
            }

            if (datagram.Length < UcpConstants.CommonHeaderSize) // Reject packets that cannot contain a valid UCP header
            {
                return; // Too short to be a valid UCP packet. // Drop silently: attacker probing or truncated packet
            }

            UcpPacket packet; // Declare here so it is in scope for both the TryDecode block and the fallback path
            if (UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet)) // Attempt to decode the binary datagram into a structured packet object
            {
                UcpPcb pcb; // Will hold the matching PCB if the connection ID is registered
                lock (_pcbSync) // Acquire PCB lock to safely read from the shared _pcbsByConnectionId dictionary
                {
                    _pcbsByConnectionId.TryGetValue(packet.Header.ConnectionId, out pcb); // O(1) lookup by connection ID; pcb is null for unknown connections
                }

                if (pcb != null) // Found a known PCB — this is an established connection
                {
                    // Directly dispatch to the known PCB for efficiency.
                    pcb.DispatchFromNetwork(packet, remote); // Fast path: deliver the decoded packet straight to the owning PCB
                    return; // Packet handled; no need to fall through to the adapter
                }

                if (packet.Header.Type != UcpPacketType.Syn) // Packet is from an unknown connection AND is not a connection request
                {
                    return; // Unknown connection and not a SYN; drop silently. // Non-SYN from unknown source is noise; drop to avoid wasting CPU
                }
            }

            // Fallback: raise to transport adapter for server/connection creation.
            _transportAdapter.Raise(datagram, remote); // Let the protocol stack process the raw datagram (SYN → new connection, or server accept)
        }

        /// <summary>
        /// Convenience override for Output without a sender reference.
        /// </summary>
        public void Output(byte[] datagram, IPEndPoint remote)
        {
            Output(datagram, remote, null); // Delegate to the abstract Output with null sender (no traceable source)
        }

        /// <summary>
        /// Sends an encoded packet to the network. Must be implemented by derived classes.
        /// </summary>
        /// <param name="datagram">The encoded packet bytes.</param>
        /// <param name="remote">The destination endpoint.</param>
        /// <param name="sender">The sending object (connection, server, or null).</param>
        public abstract void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender); // Abstract: derived class performs the actual socket send (UDP, etc.)

        /// <summary>
        /// Adds a one-shot timer that fires at the given absolute time in microseconds.
        /// The callback is wrapped to check for cancellation before execution.
        /// </summary>
        /// <param name="expireUs">Absolute expiration time in microseconds.</param>
        /// <param name="callback">The callback to invoke.</param>
        /// <returns>A timer ID that can be used with CancelTimer.</returns>
        public uint AddTimer(long expireUs, Action callback)
        {
            if (callback == null) // Validate: callback must be non-null
            {
                throw new ArgumentNullException(nameof(callback)); // Fail fast — a null callback would cause a NullReferenceException at fire time
            }

            uint timerId = unchecked((uint)Interlocked.Increment(ref _nextTimerId)); // Atomically allocate a unique timer ID; wrapping overflow is harmless
            TimerRegistration registration = new TimerRegistration(); // Create the metadata container for this timer
            registration.Id = timerId; // Store the ID so the wrapped callback can match against the active-timers dictionary
            registration.ExpireMicros = expireUs; // Store the absolute expiration time so DoEvents can decide when to fire

            // Wrap the callback to check for cancellation before executing.
            Action wrappedCallback = delegate // Closure: validates the timer registration is still active before invoking the real callback
            {
                bool shouldRun = false; // Guard flag: true if the timer was NOT cancelled between AddTimer and now
                lock (_timerSync) // Synchronize with CancelTimer to ensure atomic check-and-remove
                {
                    TimerRegistration active; // Holds the registration currently stored under this ID
                    if (_activeTimers.TryGetValue(timerId, out active) && object.ReferenceEquals(active, registration)) // This exact registration is still the active one (not cancelled, not replaced)
                    {
                        _activeTimers.Remove(timerId); // Consume the timer: remove from active set so it cannot fire again
                        shouldRun = true; // Mark as safe to invoke the user callback
                    }
                }

                if (shouldRun) // Timer was not cancelled — safe to execute
                {
                    callback(); // Invoke the user's callback now that cancellation has been ruled out
                }
            };

            registration.Callback = wrappedCallback; // Store the wrapped callback so the reference-equality check above works
            lock (_timerSync) // Acquire lock to atomically insert into both timer data structures
            {
                _activeTimers[timerId] = registration; // Insert into the ID-indexed dictionary for fast cancellation
                List<Action> callbacks; // The bucket of callbacks at this expiration time (may already exist)
                if (!_timerHeap.TryGetValue(expireUs, out callbacks)) // Check if a bucket for this expiration time already exists
                {
                    callbacks = new List<Action>(); // Create a new bucket for this microsecond
                    _timerHeap[expireUs] = callbacks; // Insert into the sorted heap; SortedDictionary orders by key
                }

                callbacks.Add(wrappedCallback); // Append this timer's callback to the bucket (multiple timers can share the same expiration)
            }

            return timerId; // Return the ID so the caller can cancel before it fires if needed
        }

        /// <summary>
        /// Cancels a pending timer. Returns true if the timer was found and cancelled.
        /// </summary>
        /// <param name="timerId">The timer ID returned by AddTimer.</param>
        public bool CancelTimer(uint timerId)
        {
            lock (_timerSync) // Synchronize with AddTimer and timer execution to prevent racing with the wrapped callback
            {
                return _activeTimers.Remove(timerId); // Remove returns true if the timer existed (was successfully cancelled)
            }
        }

        /// <summary>
        /// Drives one iteration of the event loop: fires due timers and ticks all
        /// active PCBs. Returns the total number of work items processed (callbacks + PCB ticks).
        /// </summary>
        /// <returns>Number of work items processed in this iteration.</returns>
        public virtual int DoEvents()
        {
            if (_disposed) // Guard: refuse to process events after disposal
            {
                return 0; // Report zero work — nothing was or should be done on a disposed network
            }

            UpdateCachedClock(); // Refresh the cached time so all operations in this tick share a consistent logical clock

            // Collect all due callbacks from the timer heap.
            List<Action> dueCallbacks = new List<Action>(); // Accumulator for all callbacks that have expired this tick
            long nowMicros = CurrentTimeUs; // Snapshot the logical "now" so the while-loop condition is stable across iterations
            lock (_timerSync) // Synchronize timer-heap access with concurrent AddTimer calls
            {
                while (_timerHeap.Count > 0) // Loop while there are timers that could potentially be expired
                {
                    long firstKey; // The expiration time of the earliest timer in the heap
                    List<Action> firstCallbacks; // The callback bucket at that expiration time
                    GetFirstTimerUnsafe(out firstKey, out firstCallbacks); // Peek at the earliest entry without removing
                    if (firstKey > nowMicros) // Earliest timer has NOT yet expired — stop draining
                    {
                        break; // No more expired timers. // All remaining timers are in the future; exit the drain loop
                    }

                    _timerHeap.Remove(firstKey); // Remove the expired bucket from the sorted dictionary
                    for (int i = 0; i < firstCallbacks.Count; i++) // Iterate all callbacks that expired at this microsecond
                    {
                        dueCallbacks.Add(firstCallbacks[i]); // Move each callback to the execution list (outside the lock)
                    }
                }
            }

            // Execute all due callbacks.
            for (int i = 0; i < dueCallbacks.Count; i++) // Iterate all collected expired callbacks
            {
                dueCallbacks[i](); // Invoke each wrapped callback; the wrapper internally handles cancellation checks
            }

            // Tick all active PCBs.
            List<UcpPcb> snapshot = SnapshotPcbs(); // Take a snapshot under lock so we can iterate PCBs safely without holding the lock
            int pcbWork = 0; // Accumulator for work items processed by PCB ticks (used for return value and idle detection)
            for (int i = 0; i < snapshot.Count; i++) // Iterate the snapshot (safe — no lock held during OnTick)
            {
                pcbWork += snapshot[i].OnTick(CurrentTimeUs); // Tick each PCB; each returns how many work items it processed (retransmits, flushes, etc.)
            }

            // If no work was done, yield to avoid busy-waiting.
            if (dueCallbacks.Count == 0 && pcbWork == 0) // Neither timers nor PCBs produced any work this tick
            {
                YieldWhenIdle(); // Yield CPU time to avoid a hot spin-loop when nothing is pending
            }

            return dueCallbacks.Count + pcbWork; // Report total work items so the event-loop driver can track activity
        }

        /// <summary>
        /// Registers a PCB with this network for fast packet routing and tick processing.
        /// </summary>
        internal void RegisterPcb(UcpPcb pcb)
        {
            if (pcb == null) // Defensive: guard against null argument
            {
                return; // Silently ignore; caller should not pass null but we don't want to crash in release
            }

            lock (_pcbSync) // Synchronize with Input, DoEvents, and other PCB mutations
            {
                if (!_activePcbs.Contains(pcb)) // Avoid adding the same PCB twice (idempotent registration)
                {
                    _activePcbs.Add(pcb); // Add to the tick list; OnTick will now be called for this PCB each DoEvents
                }

                if (pcb.ConnectionId != 0) // Connection ID 0 means the handshake hasn't assigned a real ID yet
                {
                    _pcbsByConnectionId[pcb.ConnectionId] = pcb; // Index by connection ID for O(1) routing in Input
                }
            }
        }

        /// <summary>
        /// Updates a PCB's connection ID in the lookup table after the handshake
        /// assigns a final ID.
        /// </summary>
        internal void UpdatePcbConnectionId(UcpPcb pcb, uint oldConnectionId, uint newConnectionId)
        {
            if (pcb == null || newConnectionId == 0) // Guard: need a valid PCB and a non-zero new ID to proceed
            {
                return; // Nothing meaningful to do with null PCB or zero ID
            }

            lock (_pcbSync) // Synchronize with Input and other PCB lookups
            {
                if (oldConnectionId != 0) // If there was a previous non-zero ID, clean up the stale mapping
                {
                    UcpPcb existing; // Holds the PCB currently mapped to the old ID
                    if (_pcbsByConnectionId.TryGetValue(oldConnectionId, out existing) && object.ReferenceEquals(existing, pcb)) // Verify the old mapping still points to THIS PCB (defensive)
                    {
                        _pcbsByConnectionId.Remove(oldConnectionId); // Remove the stale entry so future lookups for this old ID don't misroute
                    }
                }

                _pcbsByConnectionId[newConnectionId] = pcb; // Insert the new mapping so packets with the new connection ID route correctly
                if (!_activePcbs.Contains(pcb)) // Ensure the PCB is in the tick list (belt-and-suspenders; should already be there)
                {
                    _activePcbs.Add(pcb); // Add to tick list if not already present (shouldn't happen in normal flow)
                }
            }
        }

        /// <summary>
        /// Unregisters a PCB from this network's routing and tick lists.
        /// </summary>
        internal void UnregisterPcb(UcpPcb pcb)
        {
            if (pcb == null) // Defensive: guard against null argument
            {
                return; // Silently ignore
            }

            lock (_pcbSync) // Synchronize with Input and other PCB mutations
            {
                _activePcbs.Remove(pcb); // Remove from tick list; OnTick will no longer be called for this PCB
                uint connectionId = pcb.ConnectionId; // Snapshot the connection ID so we can clean up the routing entry
                if (connectionId != 0) // Only clean up the routing table if a non-zero ID was actually assigned
                {
                    UcpPcb existing; // Holds the PCB currently mapped to this connection ID
                    if (_pcbsByConnectionId.TryGetValue(connectionId, out existing) && object.ReferenceEquals(existing, pcb)) // Verify the mapping still points to THIS PCB (not a replacement PCB reusing the same ID)
                    {
                        _pcbsByConnectionId.Remove(connectionId); // Remove the routing entry so stale packets don't get misrouted to a freed PCB
                    }
                }
            }
        }

        /// <summary>
        /// Disposes the network: stops and clears all timers.
        /// </summary>
        public virtual void Dispose()
        {
            if (_disposed) // Idempotent guard: prevent double-disposal from causing errors
            {
                return; // Already disposed; nothing to do
            }

            _disposed = true; // Set flag immediately so concurrent Input/DoEvents calls fail early
            Stop(); // Call derived-class stop to close the underlying socket
            lock (_timerSync) // Synchronize with any in-flight AddTimer or timer execution
            {
                _activeTimers.Clear(); // Clear all active registrations; wrapped callbacks will see they are no longer active and skip execution
                _timerHeap.Clear(); // Clear the heap so DoEvents will find no timers to fire
            }
        }

        /// <summary>
        /// Retrieves the first (earliest) timer entry without removing it.
        /// Must be called under _timerSync lock.
        /// </summary>
        private void GetFirstTimerUnsafe(out long expireUs, out List<Action> callbacks)
        {
            foreach (KeyValuePair<long, List<Action>> pair in _timerHeap) // SortedDictionary enumerates in key order; first iteration yields the earliest timer
            {
                expireUs = pair.Key; // Output the expiration time of the earliest bucket
                callbacks = pair.Value; // Output the callback list at that time
                return; // Exit after the first entry — we only need the earliest
            }

            expireUs = 0; // Sentinel: no timers in the heap
            callbacks = null; // Sentinel: no callbacks
        }

        /// <summary>
        /// Yields the calling thread when no work is pending to avoid busy-waiting.
        /// If the next timer is imminent (&lt;= 1ms), uses Thread.Yield() for low
        /// latency; otherwise sleeps for 1ms.
        /// </summary>
        private void YieldWhenIdle()
        {
            long nextExpireUs = 0; // Will hold the expiration time of the soonest pending timer
            bool hasTimer = false; // Will be true if at least one timer is registered
            lock (_timerSync) // Synchronize with AddTimer so we see the latest timer state
            {
                if (_timerHeap.Count > 0) // Check if any timers exist
                {
                    List<Action> ignored; // We only need the key (expiration time), not the callback list
                    GetFirstTimerUnsafe(out nextExpireUs, out ignored); // Peek at the earliest timer's expiration time
                    hasTimer = true; // Mark that a timer exists so the conditional yield below triggers
                }
            }

            if (hasTimer && nextExpireUs - CurrentTimeUs <= UcpConstants.MICROS_PER_MILLI) // The next timer fires within 1ms — don't sleep, just yield
            {
                Thread.Yield(); // Yield the current time slice; keeps latency low for imminent timers while still being cooperative
                return; // Yield is sufficient; no need to sleep
            }

            Thread.Sleep(1); // No imminent timer: sleep for 1ms to dramatically reduce CPU usage during idle periods
        }

        /// <summary>
        /// Updates the cached clock from the high-resolution stopwatch at most
        /// once per millisecond. This avoids the overhead of reading the stopwatch
        /// on every protocol operation.
        /// </summary>
        private void UpdateCachedClock()
        {
            long stopwatchUs = UcpTime.ReadStopwatchMicroseconds(); // Read the high-resolution monotonic stopwatch in microseconds
            long stopwatchMs = stopwatchUs / UcpConstants.MICROS_PER_MILLI; // Convert to milliseconds for the granularity throttle check
            long cachedMs = Volatile.Read(ref _currentTimeMs); // Read the last cached millisecond value without a full memory barrier
            if (stopwatchMs != cachedMs) // Has at least 1 full millisecond elapsed since the last update?
            {
                Volatile.Write(ref _currentTimeUs, stopwatchUs); // Update the microsecond cache so protocol code sees the freshest time
                Volatile.Write(ref _currentTimeMs, stopwatchMs); // Update the millisecond cache so the next call can compare against the new value
            }
        }

        /// <summary>
        /// Creates a snapshot of all active PCBs for safe iteration outside the lock.
        /// </summary>
        private List<UcpPcb> SnapshotPcbs()
        {
            lock (_pcbSync) // Acquire the PCB lock to get a consistent view of the active PCB list
            {
                return new List<UcpPcb>(_activePcbs); // Shallow-copy the list; caller can iterate (and call OnTick) without holding the lock
            }
        }
    }
}
