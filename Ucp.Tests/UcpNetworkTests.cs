using System; // Import core .NET types (DateTime, etc.)
using System.Collections.Generic; // Import generic collections (Dictionary, Queue)
using System.Net; // Import networking types (IPAddress, IPEndPoint)
using System.Text; // Import text encoding (Encoding.ASCII)
using System.Threading.Tasks; // Import async task types (Task, Task<T>)
using Ucp; // Import UCP core types (UcpNetwork, UcpConfiguration, UcpServer, UcpConnection)
using Xunit; // Import xUnit testing framework (Fact attribute, Assert)

namespace UcpTest // Define the test namespace for the UCP project
{
    /// <summary>
    /// Unit tests for the UCP network abstraction layer (<see cref="UcpNetwork"/>).
    /// Uses an in-memory loopback network to verify timer dispatch, connection
    /// establishment, and data transfer driven entirely by manual <c>DoEvents</c> pumping.
    /// </summary>
    public sealed class UcpNetworkTests // Test class for UcpNetwork event-loop-based integration tests
    {
        /// <summary>
        /// A fully in-process <see cref="UcpNetwork"/> implementation that routes datagrams
        /// through a shared peer dictionary. Enables deterministic integration testing
        /// without real sockets or thread scheduling.
        /// </summary>
        private sealed class LoopbackNetwork : UcpNetwork // In-process network that uses a dictionary-based peer routing instead of sockets
        {
            /// <summary>Shared registry of all peers keyed by port number.</summary>
            private readonly Dictionary<int, LoopbackNetwork> peers; // Shared peer dictionary mapping ports to loopback network instances

            /// <summary>Inbound message queue guarded by <see cref="sync"/>.</summary>
            private readonly Queue<Datagram> inbox = new Queue<Datagram>(); // Thread-safe inbound datagram queue for received messages

            /// <summary>Lock object protecting <see cref="inbox"/> access.</summary>
            private readonly object sync = new object(); // Synchronization object for thread-safe inbox access

            /// <summary>The local endpoint assigned after <see cref="Start"/> is called.</summary>
            private IPEndPoint? localEndPoint; // The bound local endpoint (null before Start), nullable

            /// <summary>
            /// Creates a loopback network instance bound to a shared peer registry.
            /// </summary>
            /// <param name="peers">Shared dictionary mapping port numbers to loopback network instances.</param>
            /// <param name="configuration">The UCP configuration to pass to the base class.</param>
            public LoopbackNetwork(Dictionary<int, LoopbackNetwork> peers, UcpConfiguration configuration) // Constructor: accepts shared peer dictionary and UCP config
                : base(configuration) // Forward the configuration to the UcpNetwork base class
            {
                this.peers = peers; // Store the shared peer registry for message routing
            }

            /// <inheritdoc/>
            public override EndPoint? LocalEndPoint // Expose the bound local endpoint as a read-only property
            {
                get { return localEndPoint; } // Return the currently bound endpoint (null if not started)
            }

            /// <summary>
            /// Binds this peer to a loopback port. If <paramref name="port"/> is 0,
            /// an auto-assigned port starting at 50000 is used.
            /// </summary>
            /// <param name="port">Desired port number, or 0 for automatic assignment.</param>
            public override void Start(int port) // Bind this loopback peer to a port and register it in the peer dictionary
            {
                // Only bind once; ignore subsequent Start calls.
                if (localEndPoint != null) // If already bound, skip re-binding to avoid port conflicts
                {
                    return; // Exit early — already started
                }

                // Auto-assign a port if none was specified, offset from the peer count.
                if (port == 0) // If port 0 was specified, auto-assign a port starting at 50000
                {
                    port = 50000 + peers.Count; // Compute auto-assigned port: 50000 + current peer count
                }

                localEndPoint = new IPEndPoint(IPAddress.Loopback, port); // Create the local loopback endpoint with the chosen port
                peers[port] = this; // Register this instance in the shared peer dictionary for message routing
            }

            /// <summary>
            /// Unbinds this peer from the shared registry.
            /// </summary>
            public override void Stop() // Remove this peer from the shared registry
            {
                if (localEndPoint != null) // Only attempt removal if we were actually bound
                {
                    peers.Remove(localEndPoint.Port); // Remove our port entry from the shared peer dictionary
                }
            }

            /// <summary>
            /// Delivers an outgoing datagram to the target peer by copying the buffer
            /// and enqueuing it into the destination's inbox.
            /// </summary>
            /// <param name="datagram">The raw bytes to transmit.</param>
            /// <param name="remote">The destination endpoint.</param>
            /// <param name="sender">The UCP object that originated the datagram (unused).</param>
            public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender) // Route an outgoing datagram to the destination peer's inbox
            {
                // Auto-bind if Start has not been called yet.
                if (localEndPoint == null) // If this peer has no local endpoint, bind it now
                {
                    Start(0); // Auto-bind to an ephemeral port so we can send
                }

                // Locate the target peer; silently discard if it does not exist.
                LoopbackNetwork? target; // Declare variable for the destination loopback network
                if (!peers.TryGetValue(remote.Port, out target)) // Look up the target peer by destination port in the shared dictionary
                {
                    return; // Silently drop the datagram if the destination peer is unknown
                }

                // Copy the buffer so the sender can reuse it immediately.
                byte[] copy = new byte[datagram.Length]; // Allocate a new buffer for the copy to avoid shared references
                Buffer.BlockCopy(datagram, 0, copy, 0, datagram.Length); // Copy the datagram bytes into the new buffer for safe transfer
                IPEndPoint source = localEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0); // Use our bound endpoint as source, or fallback to loopback:0
                target.Enqueue(copy, source); // Deliver the copied buffer to the target peer's inbox
            }

            /// <summary>
            /// Processes every pending inbound datagram in the inbox, then invokes the base
            /// class event loop. Returns the total number of datagrams processed.
            /// </summary>
            /// <returns>The count of datagrams handled this cycle.</returns>
            public override int DoEvents() // Pump the event loop: process all queued datagrams, then run base class timers
            {
                int processed = 0; // Counter for how many datagrams were processed this cycle
                while (true) // Loop until the inbox is empty
                {
                    Datagram? datagram = null; // Holder for the dequeued datagram (null if inbox is empty)
                    lock (sync) // Acquire the lock to safely access the inbox queue
                    {
                        if (inbox.Count > 0) // Check if there are any pending datagrams in the inbox
                        {
                            datagram = inbox.Dequeue(); // Remove and retrieve the next datagram from the queue
                        }
                    }

                    if (datagram == null) // If no datagram was dequeued, the inbox is empty
                    {
                        break; // Exit the processing loop
                    }

                    // Deliver the datagram through the base class Input pipeline.
                    Input(datagram.Buffer, datagram.Remote); // Route the datagram into UCP's internal packet processing
                    processed++; // Increment the processed datagram counter
                }

                // Also run timer callbacks and other base-class housekeeping.
                return processed + base.DoEvents(); // Return total processed count including base class timer work
            }

            /// <summary>
            /// Enqueues an incoming buffer from a remote peer into the inbox.
            /// </summary>
            /// <param name="buffer">The received data buffer (ownership transfers to this instance).</param>
            /// <param name="remote">The source endpoint.</param>
            private void Enqueue(byte[] buffer, IPEndPoint remote) // Thread-safe method to add an inbound datagram to the processing queue
            {
                lock (sync) // Acquire the lock to safely modify the inbox queue
                {
                    Datagram datagram = new Datagram(); // Create a new datagram wrapper for the buffer and remote
                    datagram.Buffer = buffer; // Assign the received byte buffer to the datagram
                    datagram.Remote = remote; // Record the source endpoint on the datagram
                    inbox.Enqueue(datagram); // Add the datagram to the inbound queue for later DoEvents processing
                }
            }

            /// <summary>
            /// Internal structure representing an in-flight datagram with its source address.
            /// </summary>
            private sealed class Datagram // Simple data holder for an inbound message and its source endpoint
            {
                /// <summary>The raw bytes of the datagram.</summary>
                public byte[] Buffer = Array.Empty<byte>(); // The received byte buffer (defaults to empty array)

                /// <summary>The source endpoint that sent this datagram.</summary>
                public IPEndPoint Remote = new IPEndPoint(IPAddress.Loopback, 0); // The sender's endpoint (defaults to loopback:0)
            }
        }

        /// <summary>
        /// Verifies that network timers fire only when <see cref="UcpNetwork.DoEvents"/>
        /// is explicitly called, not spontaneously.
        /// </summary>
        [Fact] // Mark as an xUnit fact test (no parameters)
        public async Task NetworkTimers_RunOnlyWhenDoEventsIsCalled() // Test: timers are only dispatched during explicit DoEvents calls
        {
            // Set up a single loopback network with one timer callback.
            Dictionary<int, LoopbackNetwork> peers = new Dictionary<int, LoopbackNetwork>(); // Create the shared peer registry for message routing
            UcpConfiguration configuration = new UcpConfiguration(); // Create a default UCP configuration for the network
            LoopbackNetwork network = new LoopbackNetwork(peers, configuration); // Instantiate the loopback network with shared peers
            int fired = 0; // Counter to track how many times the timer callback fires

            // Register a timer set to fire at the current microsecond timestamp.
            network.AddTimer(network.NowMicroseconds, delegate { fired++; }); // Add a timer that schedules immediately and increments the counter

            // The timer should not fire until DoEvents pumps the event loop.
            Assert.Equal(0, fired); // Verify no timer callback fired before any DoEvents call

            // Pump the network for 50ms; the timer should fire exactly once.
            await PumpAsync(network, null, 50); // Run DoEvents for 50ms to allow the timer to dispatch
            Assert.Equal(1, fired); // Verify the timer callback fired exactly once during the pump cycle
        }

        /// <summary>
        /// End-to-end test that connects a client and server using the loopback network,
        /// transfers a 16 KB payload, and verifies the data is received intact.
        /// </summary>
        [Fact] // Mark as an xUnit fact test (no parameters)
        public async Task NetworkApi_CanConnectAndTransferWithDoEvents() // Test: full connect+transfer+verify using loopback network and DoEvents pumping
        {
            // Create shared peer registry and individual network instances for client and server.
            Dictionary<int, LoopbackNetwork> peers = new Dictionary<int, LoopbackNetwork>(); // Create the shared peer dictionary for routing between client and server
            UcpConfiguration configuration = new UcpConfiguration(); // Create a default UCP configuration
            configuration.TimerIntervalMilliseconds = 1; // Set timer interval to 1ms for fast polling in test
            configuration.FairQueueRoundMilliseconds = 1; // Set fair-queue round to 1ms for fast test scheduling
            LoopbackNetwork serverNetwork = new LoopbackNetwork(peers, configuration); // Create the server-side loopback network
            LoopbackNetwork clientNetwork = new LoopbackNetwork(peers, configuration); // Create the client-side loopback network

            // Create UCP server and client bound to the loopback networks.
            UcpServer server = serverNetwork.CreateServer(41001); // Create a UCP server on the server network, listening on port 41001
            UcpConnection client = clientNetwork.CreateConnection(); // Create a UCP client connection on the client network
            Task<UcpConnection> acceptTask = server.AcceptAsync(); // Start accepting a connection on the server (returns the server-side connection)
            Task connectTask = client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41001)); // Initiate connection from the client to the server

            // Pump both networks until connection handshake completes.
            await PumpUntilAsync(serverNetwork, clientNetwork, async delegate // Run DoEvents on both networks until the connect+accept tasks complete
            {
                await connectTask; // Await the client connection task completion
                await acceptTask; // Await the server accept task completion
            }, 5000); // Timeout after 5 seconds if handshake doesn't complete

            UcpConnection serverConnection = await acceptTask; // Extract the server-side connection from the completed accept task

            // Prepare a 16 KB payload for transfer.
            byte[] payload = Encoding.ASCII.GetBytes(new string('N', 16 * 1024)); // Create a 16 KB payload filled with the character 'N'
            byte[] received = new byte[payload.Length]; // Allocate a receive buffer of the same size as the payload
            Task<bool> readTask = serverConnection.ReadAsync(received, 0, received.Length); // Start reading the full payload from the server side
            Task<int> writeTask = client.SendAsync(payload, 0, payload.Length); // Start sending the payload from the client side

            // Pump both networks until the write completes and the read succeeds.
            await PumpUntilAsync(serverNetwork, clientNetwork, async delegate // Run DoEvents on both networks until the write+read tasks complete
            {
                int written = await writeTask; // Await the write task and get the number of bytes sent
                bool readOk = await readTask; // Await the read task and get success/failure
                Assert.Equal(payload.Length, written); // Verify all bytes were written
                Assert.True(readOk); // Verify the read completed successfully
            }, 5000); // Timeout after 5 seconds

            // Verify the received payload matches what was sent.
            Assert.Equal(payload, received); // Verify byte-for-byte equality between sent and received data

            await client.CloseAsync(); // Gracefully close the client connection
            server.Stop(); // Stop the server
        }

        /// <summary>
        /// Continuously pumps one or two networks with <c>DoEvents</c> until the given
        /// async action completes or a timeout is reached.
        /// </summary>
        /// <param name="first">The primary network to pump.</param>
        /// <param name="second">An optional secondary network to pump simultaneously.</param>
        /// <param name="action">The async operation to await for completion.</param>
        /// <param name="timeoutMilliseconds">Maximum time to pump before throwing <see cref="TimeoutException"/>.</param>
        private static async Task PumpUntilAsync(UcpNetwork first, UcpNetwork? second, Func<Task> action, int timeoutMilliseconds) // Helper: pump DoEvents until an async action completes or timeout
        {
            Task task = action(); // Start the async action and capture the returned task
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds); // Calculate the absolute deadline from the timeout

            // Pump both networks until the task finishes or the deadline expires.
            while (!task.IsCompleted && DateTime.UtcNow < deadline) // Loop while the task is not done and time remains
            {
                first.DoEvents(); // Pump the primary network's event loop (process datagrams and timers)
                if (second != null) // If a secondary network is provided, pump it too
                {
                    second.DoEvents(); // Pump the secondary network's event loop
                }

                await Task.Delay(1); // Yield and pause 1ms between polls to avoid busy-waiting
            }

            // If the task never completed, the test infrastructure failed.
            if (!task.IsCompleted) // Check if the task failed to complete within the timeout window
            {
                throw new TimeoutException("Network polling test timed out."); // Throw to signal the test infrastructure failure
            }

            // Await to propagate any exception thrown inside the action.
            await task; // Unwrap the completed task to propagate any exceptions from the action body
        }

        /// <summary>
        /// Pumps the network event loops for a fixed duration, regardless of any task completion.
        /// </summary>
        /// <param name="first">The primary network to pump.</param>
        /// <param name="second">An optional secondary network to pump simultaneously.</param>
        /// <param name="durationMilliseconds">How long to pump before returning.</param>
        private static async Task PumpAsync(UcpNetwork first, UcpNetwork? second, int durationMilliseconds) // Helper: pump DoEvents continuously for a fixed duration
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(durationMilliseconds); // Calculate the absolute deadline for the pumping duration

            // Keep pumping DoEvents until the duration expires.
            while (DateTime.UtcNow < deadline) // Loop until the duration deadline is reached
            {
                first.DoEvents(); // Pump the primary network's event loop (process datagrams and timers)
                if (second != null) // If a secondary network is provided, pump it too
                {
                    second.DoEvents(); // Pump the secondary network's event loop
                }

                await Task.Delay(1); // Yield and pause 1ms to throttle the polling loop
            }
        }
    }
}
