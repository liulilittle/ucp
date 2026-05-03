using System; // Provides Action, IDisposable, ObjectDisposedException, ArgumentNullException
using System.Net; // Provides IPEndPoint, IPAddress, EndPoint, SocketException
using System.Net.Sockets; // Provides UdpClient, UdpReceiveResult for UDP socket operations
using System.Threading; // Provides CancellationTokenSource for cooperative cancellation
using System.Threading.Tasks; // Provides Task, Task.Run for background async operations

namespace Ucp // Encapsulates the UCP reliable UDP transport protocol library
{
    /// <summary>
    /// UDP socket-based network implementation for UCP. Runs a background
    /// receive loop that injects datagrams via <c>Input()</c>, sends encoded
    /// packets via <c>Output()</c>, and delegates protocol progress to the
    /// base <c>DoEvents()</c> event loop.
    /// </summary>
    public sealed class UcpDatagramNetwork : UcpNetwork // Sealed concrete implementation of the abstract UcpNetwork for real UDP sockets
    {
        /// <summary>Synchronization lock for socket lifecycle operations.</summary>
        private readonly object _sync = new object(); // Protects UdpClient creation, disposal, and state access from concurrent threads

        /// <summary>Underlying UDP client socket.</summary>
        private UdpClient _udpClient; // The actual .NET UDP socket used for binding, sending, and receiving datagrams

        /// <summary>Cancellation token to stop the receive loop.</summary>
        private CancellationTokenSource _cts; // Provides a cancellable token to gracefully terminate the background receive loop

        /// <summary>Background receive loop task.</summary>
        private Task _receiveLoopTask; // Holds a reference to the running background receive loop task for diagnostics

        /// <summary>Whether this instance has been disposed.</summary>
        private bool _disposed; // Guards against using the network after disposal and prevents double-dispose

        /// <summary>
        /// Creates an unstarted UcpDatagramNetwork with default configuration.
        /// </summary>
        public UcpDatagramNetwork()
            : base(new UcpConfiguration()) // Initialize the base class with default protocol configuration
        {
        }

        /// <summary>
        /// Creates and immediately starts a UcpDatagramNetwork on the given port.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
        public UcpDatagramNetwork(int port)
            : base(new UcpConfiguration()) // Initialize the base class with default protocol configuration
        {
            Start(port); // Immediately bind the UDP socket and start the receive loop on the specified port
        }

        /// <summary>
        /// Creates and immediately starts a UcpDatagramNetwork on the given
        /// address and port.
        /// </summary>
        /// <param name="localAddress">The local IP address to bind.</param>
        /// <param name="port">The local port to bind.</param>
        public UcpDatagramNetwork(IPAddress localAddress, int port)
            : base(new UcpConfiguration()) // Initialize the base class with default protocol configuration
        {
            Start(localAddress, port); // Immediately bind the UDP socket to the specific IP address and port, then start receive loop
        }

        /// <summary>
        /// Creates an unstarted UcpDatagramNetwork with the given configuration.
        /// </summary>
        /// <param name="configuration">Protocol configuration.</param>
        public UcpDatagramNetwork(UcpConfiguration configuration)
            : base(configuration) // Initialize the base class with the caller-supplied configuration
        {
        }

        /// <summary>
        /// Creates and immediately starts a UcpDatagramNetwork on the given
        /// address and port with the given configuration.
        /// </summary>
        /// <param name="localAddress">The local IP address to bind.</param>
        /// <param name="port">The local port to bind.</param>
        /// <param name="configuration">Protocol configuration.</param>
        public UcpDatagramNetwork(IPAddress localAddress, int port, UcpConfiguration configuration)
            : base(configuration) // Initialize the base class with the caller-supplied configuration
        {
            Start(localAddress, port); // Immediately bind the UDP socket and start the receive loop
        }

        /// <summary>
        /// Gets the local endpoint of the bound UDP socket.
        /// </summary>
        public override EndPoint LocalEndPoint
        {
            get
            {
                lock (_sync) // Protect access to _udpClient which may be nullified during Stop/Dispose
                {
                    return _udpClient == null ? null : _udpClient.Client.LocalEndPoint; // Return null if not started, otherwise return the bound local IPEndPoint (includes OS-assigned port)
                }
            }
        }

        /// <summary>
        /// Starts the UDP socket on the given port, binding to all interfaces.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
        public override void Start(int port)
        {
            Start(IPAddress.Any, port); // Delegate to the full Start method with IPAddress.Any (bind to all available network interfaces)
        }

        /// <summary>
        /// Starts the UDP socket on the given local address and port.
        /// </summary>
        /// <param name="localAddress">The local IP address.</param>
        /// <param name="port">The local port.</param>
        public void Start(IPAddress localAddress, int port)
        {
            lock (_sync) // Protect socket creation and state transition from concurrent access
            {
                if (_disposed) // Object has already been disposed
                {
                    throw new ObjectDisposedException(nameof(UcpDatagramNetwork)); // Throw to fail fast; using a disposed object is a programming error
                }

                if (_udpClient != null) // Socket was already created (Start was called more than once)
                {
                    return; // Already started. Idempotent: no need to create a second socket.
                }

                _udpClient = new UdpClient(new IPEndPoint(localAddress ?? IPAddress.Any, port)); // Create the UDP socket bound to the specified IP and port; null address falls back to Any
                _cts = new CancellationTokenSource(); // Create a new cancellation token source to control the receive loop's lifetime
                _receiveLoopTask = Task.Run(ReceiveLoopAsync); // Start the background receive loop (fire-and-forget, exception handling is internal)
            }
        }

        /// <summary>
        /// Stops the receive loop and disposes the UDP client.
        /// </summary>
        public override void Stop()
        {
            UdpClient client = null; // Local variable to hold the UdpClient reference for disposal outside the lock
            CancellationTokenSource cancellation = null; // Local variable to hold the CTS reference for disposal outside the lock
            lock (_sync) // Protect the snapshot of references and nullification of state
            {
                client = _udpClient; // Snapshot the current UdpClient reference
                cancellation = _cts; // Snapshot the current cancellation token source
                _udpClient = null; // Nullify so Start() or Output() know the socket is gone
                _cts = null; // Nullify so the receive loop knows it should exit
                _receiveLoopTask = null; // Nullify the task reference (task will complete asynchronously)
            }

            if (cancellation != null) // There is an active cancellation token source to signal
            {
                cancellation.Cancel(); // Signal cancellation to the receive loop so it exits its infinite loop
                cancellation.Dispose(); // Dispose the CTS to release its native wait handle resources
            }

            if (client != null) // There is an active UdpClient to clean up
            {
                client.Dispose(); // Dispose the UdpClient, which closes the socket and causes the pending ReceiveAsync to throw ObjectDisposedException
            }
        }

        /// <summary>
        /// Sends an encoded datagram to the specified remote endpoint via UDP.
        /// Lazy-starts the socket if not yet bound.
        /// </summary>
        /// <param name="datagram">The encoded packet bytes.</param>
        /// <param name="remote">The destination endpoint.</param>
        /// <param name="sender">The sending object (unused for direct UDP).</param>
        public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
        {
            if (datagram == null) // Validate the datagram buffer to avoid NullReferenceException in socket.Send
            {
                throw new ArgumentNullException(nameof(datagram)); // Fail fast with a clear error
            }

            if (remote == null) // Validate the remote endpoint to avoid NullReferenceException in socket.Send
            {
                throw new ArgumentNullException(nameof(remote)); // Fail fast with a clear error
            }

            UdpClient client; // Will hold the active UdpClient reference for sending
            lock (_sync) // Protect access to _udpClient and _disposed during send
            {
                if (_disposed) // Object has been disposed; cannot send
                {
                    throw new ObjectDisposedException(nameof(UcpDatagramNetwork)); // Fail fast; sending on a disposed network is a programming error
                }

                if (_udpClient == null) // Socket hasn't been started yet (lazy-start scenario)
                {
                    Start(0); // Lazy-start with OS-assigned port. (0 means the OS picks a free ephemeral port)
                }

                client = _udpClient; // Capture the current UdpClient reference for use outside the lock
            }

            client.Send(datagram, datagram.Length, remote); // Send the encoded datagram bytes to the remote endpoint via UDP (synchronous, non-blocking for UDP)
        }

        /// <summary>
        /// Disposes the network: stops the receive loop and releases resources.
        /// </summary>
        public override void Dispose()
        {
            lock (_sync) // Protect the _disposed flag from concurrent modification
            {
                if (_disposed) // Guard against double-dispose
                {
                    return; // Already disposed; nothing to do
                }

                _disposed = true; // Mark as disposed so subsequent operations throw ObjectDisposedException
            }

            base.Dispose(); // Call base.Dispose() which invokes Stop() to clean up the UDP socket and receive loop
        }

        /// <summary>
        /// Continuously receives UDP datagrams and injects them via Input()
        /// until cancelled or the socket is disposed.
        /// </summary>
        private async Task ReceiveLoopAsync()
        {
            while (true) // Infinite loop that runs until break conditions (cancellation or disposal)
            {
                UdpClient client; // Will hold the current UdpClient reference for this iteration
                CancellationTokenSource cancellation; // Will hold the current CancellationTokenSource for this iteration
                lock (_sync) // Snapshot the current client and cancellation state under lock
                {
                    client = _udpClient; // Capture the current socket (may become null during Stop/Dispose)
                    cancellation = _cts; // Capture the current cancellation token source
                }

                if (client == null || cancellation == null || cancellation.IsCancellationRequested) // Socket was stopped, CTS was nullified, or cancellation was requested
                {
                    break; // Exit the receive loop; network has been stopped or disposed
                }

                try
                {
                    UdpReceiveResult receiveResult = await client.ReceiveAsync().ConfigureAwait(false); // Await an incoming UDP datagram; blocks asynchronously until data arrives
                    Input(receiveResult.Buffer, receiveResult.RemoteEndPoint); // Inject the received bytes and remote endpoint into the base UcpNetwork's Input() for decoding and dispatch
                }
                catch (ObjectDisposedException) // Socket was disposed while waiting for a datagram (during Stop/Dispose)
                {
                    break; // Socket disposed; exit gracefully. Normal shutdown path.
                }
                catch (SocketException) // A socket-level error occurred (e.g., ICMP unreachable, network reset)
                {
                    if (cancellation.IsCancellationRequested) // Cancellation was requested while ReceiveAsync was in flight
                    {
                        break; // Cancelled; exit gracefully.
                    }
                    // Otherwise transient socket error, continue.
                    // The loop continues to retry receive; transient errors like ICMP messages don't require terminating the loop
                }
                catch
                {
                    // Swallow unexpected exceptions to keep the loop alive.
                    // The receive loop is critical infrastructure; unknown errors should not crash it.
                    // Individual packet errors are handled by Input() / packet codec.
                }
            }
        }
    }
}
