using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Ucp;
using Xunit;

namespace UcpTest
{
    /// <summary>
    /// Unit tests for the UCP network abstraction layer (<see cref="UcpNetwork"/>).
    /// Uses an in-memory loopback network to verify timer dispatch, connection
    /// establishment, and data transfer driven entirely by manual <c>DoEvents</c> pumping.
    /// </summary>
    public sealed class UcpNetworkTests
    {
        /// <summary>
        /// A fully in-process <see cref="UcpNetwork"/> implementation that routes datagrams
        /// through a shared peer dictionary. Enables deterministic integration testing
        /// without real sockets or thread scheduling.
        /// </summary>
        private sealed class LoopbackNetwork : UcpNetwork
        {
            /// <summary>Shared registry of all peers keyed by port number.</summary>
            private readonly Dictionary<int, LoopbackNetwork> peers;

            /// <summary>Inbound message queue guarded by <see cref="sync"/>.</summary>
            private readonly Queue<Datagram> inbox = new Queue<Datagram>();

            /// <summary>Lock object protecting <see cref="inbox"/> access.</summary>
            private readonly object sync = new object();

            /// <summary>The local endpoint assigned after <see cref="Start"/> is called.</summary>
            private IPEndPoint? localEndPoint;

            /// <summary>
            /// Creates a loopback network instance bound to a shared peer registry.
            /// </summary>
            /// <param name="peers">Shared dictionary mapping port numbers to loopback network instances.</param>
            /// <param name="configuration">The UCP configuration to pass to the base class.</param>
            public LoopbackNetwork(Dictionary<int, LoopbackNetwork> peers, UcpConfiguration configuration)
                : base(configuration)
            {
                this.peers = peers;
            }

            /// <inheritdoc/>
            public override EndPoint? LocalEndPoint
            {
                get { return localEndPoint; }
            }

            /// <summary>
            /// Binds this peer to a loopback port. If <paramref name="port"/> is 0,
            /// an auto-assigned port starting at 50000 is used.
            /// </summary>
            /// <param name="port">Desired port number, or 0 for automatic assignment.</param>
            public override void Start(int port)
            {
                // Only bind once; ignore subsequent Start calls.
                if (localEndPoint != null)
                {
                    return;
                }

                // Auto-assign a port if none was specified, offset from the peer count.
                if (port == 0)
                {
                    port = 50000 + peers.Count;
                }

                localEndPoint = new IPEndPoint(IPAddress.Loopback, port);
                peers[port] = this;
            }

            /// <summary>
            /// Unbinds this peer from the shared registry.
            /// </summary>
            public override void Stop()
            {
                if (localEndPoint != null)
                {
                    peers.Remove(localEndPoint.Port);
                }
            }

            /// <summary>
            /// Delivers an outgoing datagram to the target peer by copying the buffer
            /// and enqueuing it into the destination's inbox.
            /// </summary>
            /// <param name="datagram">The raw bytes to transmit.</param>
            /// <param name="remote">The destination endpoint.</param>
            /// <param name="sender">The UCP object that originated the datagram (unused).</param>
            public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
            {
                // Auto-bind if Start has not been called yet.
                if (localEndPoint == null)
                {
                    Start(0);
                }

                // Locate the target peer; silently discard if it does not exist.
                LoopbackNetwork? target;
                if (!peers.TryGetValue(remote.Port, out target))
                {
                    return;
                }

                // Copy the buffer so the sender can reuse it immediately.
                byte[] copy = new byte[datagram.Length];
                Buffer.BlockCopy(datagram, 0, copy, 0, datagram.Length);
                IPEndPoint source = localEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0);
                target.Enqueue(copy, source);
            }

            /// <summary>
            /// Processes every pending inbound datagram in the inbox, then invokes the base
            /// class event loop. Returns the total number of datagrams processed.
            /// </summary>
            /// <returns>The count of datagrams handled this cycle.</returns>
            public override int DoEvents()
            {
                int processed = 0;
                while (true)
                {
                    Datagram? datagram = null;
                    lock (sync)
                    {
                        if (inbox.Count > 0)
                        {
                            datagram = inbox.Dequeue();
                        }
                    }

                    if (datagram == null)
                    {
                        break;
                    }

                    // Deliver the datagram through the base class Input pipeline.
                    Input(datagram.Buffer, datagram.Remote);
                    processed++;
                }

                // Also run timer callbacks and other base-class housekeeping.
                return processed + base.DoEvents();
            }

            /// <summary>
            /// Enqueues an incoming buffer from a remote peer into the inbox.
            /// </summary>
            /// <param name="buffer">The received data buffer (ownership transfers to this instance).</param>
            /// <param name="remote">The source endpoint.</param>
            private void Enqueue(byte[] buffer, IPEndPoint remote)
            {
                lock (sync)
                {
                    Datagram datagram = new Datagram();
                    datagram.Buffer = buffer;
                    datagram.Remote = remote;
                    inbox.Enqueue(datagram);
                }
            }

            /// <summary>
            /// Internal structure representing an in-flight datagram with its source address.
            /// </summary>
            private sealed class Datagram
            {
                /// <summary>The raw bytes of the datagram.</summary>
                public byte[] Buffer = Array.Empty<byte>();

                /// <summary>The source endpoint that sent this datagram.</summary>
                public IPEndPoint Remote = new IPEndPoint(IPAddress.Loopback, 0);
            }
        }

        /// <summary>
        /// Verifies that network timers fire only when <see cref="UcpNetwork.DoEvents"/>
        /// is explicitly called, not spontaneously.
        /// </summary>
        [Fact]
        public async Task NetworkTimers_RunOnlyWhenDoEventsIsCalled()
        {
            // Set up a single loopback network with one timer callback.
            Dictionary<int, LoopbackNetwork> peers = new Dictionary<int, LoopbackNetwork>();
            UcpConfiguration configuration = new UcpConfiguration();
            LoopbackNetwork network = new LoopbackNetwork(peers, configuration);
            int fired = 0;

            // Register a timer set to fire at the current microsecond timestamp.
            network.AddTimer(network.NowMicroseconds, delegate { fired++; });

            // The timer should not fire until DoEvents pumps the event loop.
            Assert.Equal(0, fired);

            // Pump the network for 50ms; the timer should fire exactly once.
            await PumpAsync(network, null, 50);
            Assert.Equal(1, fired);
        }

        /// <summary>
        /// End-to-end test that connects a client and server using the loopback network,
        /// transfers a 16 KB payload, and verifies the data is received intact.
        /// </summary>
        [Fact]
        public async Task NetworkApi_CanConnectAndTransferWithDoEvents()
        {
            // Create shared peer registry and individual network instances for client and server.
            Dictionary<int, LoopbackNetwork> peers = new Dictionary<int, LoopbackNetwork>();
            UcpConfiguration configuration = new UcpConfiguration();
            configuration.TimerIntervalMilliseconds = 1;
            configuration.FairQueueRoundMilliseconds = 1;
            LoopbackNetwork serverNetwork = new LoopbackNetwork(peers, configuration);
            LoopbackNetwork clientNetwork = new LoopbackNetwork(peers, configuration);

            // Create UCP server and client bound to the loopback networks.
            UcpServer server = serverNetwork.CreateServer(41001);
            UcpConnection client = clientNetwork.CreateConnection();
            Task<UcpConnection> acceptTask = server.AcceptAsync();
            Task connectTask = client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41001));

            // Pump both networks until connection handshake completes.
            await PumpUntilAsync(serverNetwork, clientNetwork, async delegate
            {
                await connectTask;
                await acceptTask;
            }, 5000);

            UcpConnection serverConnection = await acceptTask;

            // Prepare a 16 KB payload for transfer.
            byte[] payload = Encoding.ASCII.GetBytes(new string('N', 16 * 1024));
            byte[] received = new byte[payload.Length];
            Task<bool> readTask = serverConnection.ReadAsync(received, 0, received.Length);
            Task<int> writeTask = client.SendAsync(payload, 0, payload.Length);

            // Pump both networks until the write completes and the read succeeds.
            await PumpUntilAsync(serverNetwork, clientNetwork, async delegate
            {
                int written = await writeTask;
                bool readOk = await readTask;
                Assert.Equal(payload.Length, written);
                Assert.True(readOk);
            }, 5000);

            // Verify the received payload matches what was sent.
            Assert.Equal(payload, received);

            await client.CloseAsync();
            server.Stop();
        }

        /// <summary>
        /// Continuously pumps one or two networks with <c>DoEvents</c> until the given
        /// async action completes or a timeout is reached.
        /// </summary>
        /// <param name="first">The primary network to pump.</param>
        /// <param name="second">An optional secondary network to pump simultaneously.</param>
        /// <param name="action">The async operation to await for completion.</param>
        /// <param name="timeoutMilliseconds">Maximum time to pump before throwing <see cref="TimeoutException"/>.</param>
        private static async Task PumpUntilAsync(UcpNetwork first, UcpNetwork? second, Func<Task> action, int timeoutMilliseconds)
        {
            Task task = action();
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);

            // Pump both networks until the task finishes or the deadline expires.
            while (!task.IsCompleted && DateTime.UtcNow < deadline)
            {
                first.DoEvents();
                if (second != null)
                {
                    second.DoEvents();
                }

                await Task.Delay(1);
            }

            // If the task never completed, the test infrastructure failed.
            if (!task.IsCompleted)
            {
                throw new TimeoutException("Network polling test timed out.");
            }

            // Await to propagate any exception thrown inside the action.
            await task;
        }

        /// <summary>
        /// Pumps the network event loops for a fixed duration, regardless of any task completion.
        /// </summary>
        /// <param name="first">The primary network to pump.</param>
        /// <param name="second">An optional secondary network to pump simultaneously.</param>
        /// <param name="durationMilliseconds">How long to pump before returning.</param>
        private static async Task PumpAsync(UcpNetwork first, UcpNetwork? second, int durationMilliseconds)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(durationMilliseconds);

            // Keep pumping DoEvents until the duration expires.
            while (DateTime.UtcNow < deadline)
            {
                first.DoEvents();
                if (second != null)
                {
                    second.DoEvents();
                }

                await Task.Delay(1);
            }
        }
    }
}
