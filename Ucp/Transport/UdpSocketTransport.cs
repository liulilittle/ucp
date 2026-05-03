using System; // Provides ObjectDisposedException, IDisposable pattern types, and Action delegate
using System.Net; // Provides IPEndPoint for endpoint addressing and IPAddress for binding
using System.Net.Sockets; // Provides UdpClient, UdpReceiveResult, and SocketException for UDP I/O
using System.Threading; // Provides CancellationTokenSource and CancellationToken for cooperative cancellation
using System.Threading.Tasks; // Provides Task and Task.Run for async receive loop

namespace Ucp.Transport
{
    /// <summary>
    /// Default UDP socket transport implementation. Binds a UdpClient on demand,
    /// runs a background receive loop that raises OnDatagram, and sends encoded
    /// packets via the socket.
    /// </summary>
    internal sealed class UdpSocketTransport : IBindableTransport // Implements IBindableTransport to participate in the transport lifecycle managed by UcpPeer
    {
        /// <summary>Underlying UDP client; created on Start or first send.</summary>
        private UdpClient _udpClient; // The actual UDP socket wrapper; null until Start or first Send (lazy initialization)

        /// <summary>Cancellation token source to stop the receive loop.</summary>
        private CancellationTokenSource _cts; // Used to signal the receive loop to exit gracefully via cooperative cancellation

        /// <summary>Background task running the asynchronous receive loop.</summary>
        private Task _receiveLoopTask; // Holds the Task reference for the background receive loop; enables awaiting shutdown

        /// <summary>Whether the transport has been disposed.</summary>
        private bool _disposed; // Guard flag to prevent double-dispose and operations after disposal

        public event Action<byte[], IPEndPoint> OnDatagram; // Raised on each received datagram; the protocol stack subscribes to consume incoming data

        /// <summary>
        /// Gets the local endpoint of the bound UDP socket, or null if not yet started.
        /// </summary>
        public EndPoint LocalEndPoint
        {
            get { return _udpClient == null ? null : _udpClient.Client.LocalEndPoint; } // Return the bound endpoint if started, null otherwise; safe read for diagnostics
        }

        /// <summary>
        /// Binds the UDP socket to the specified port and starts the receive loop.
        /// </summary>
        /// <param name="port">The port to bind to (0 for OS-assigned).</param>
        public void Start(int port)
        {
            if (_udpClient != null) // Check if the transport is already started (idempotent guard)
            {
                return; // Already started; exit early to avoid double-binding or overwriting the socket
            }

            _udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, port)); // Create and bind a UdpClient to all interfaces on the requested port
            _cts = new CancellationTokenSource(); // Initialize the cancellation token source for cooperative shutdown signaling
            _receiveLoopTask = Task.Run(ReceiveLoopAsync); // Launch the async receive loop on a threadpool thread; capture the Task for potential await on shutdown
        }

        /// <summary>
        /// Sends encoded packet data to the specified remote endpoint via UDP.
        /// </summary>
        /// <param name="data">The encoded packet bytes.</param>
        /// <param name="remote">The destination endpoint.</param>
        public void Send(byte[] data, IPEndPoint remote)
        {
            // Ensure the client is active before sending (lazy start).
            EnsureClient(); // Verify transport is not disposed; start lazily with OS-assigned port if never bound
            if (data == null) // Validate that a non-null buffer was provided
            {
                throw new ArgumentNullException(nameof(data)); // Fail fast with a clear diagnostic
            }

            _udpClient.Send(data, data.Length, remote); // Transmit the encoded packet bytes to the remote endpoint via the UDP socket
        }

        /// <summary>
        /// Signals the receive loop to stop via cancellation.
        /// </summary>
        public void Stop()
        {
            if (_udpClient == null) // Check if the transport was never started; nothing to stop
            {
                return; // Exit early; no socket or loop to shut down
            }

            if (_cts != null) // Check if the cancellation token source exists (it should after Start)
            {
                _cts.Cancel(); // Signal the cancellation token to cause the receive loop to exit its while condition
            }
        }

        /// <summary>
        /// Disposes the transport: stops the receive loop, disposes the UDP client and CTS.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) // Guard against double-dispose
            {
                return; // Already disposed; exit early to avoid ObjectDisposedException on re-disposal
            }

            _disposed = true; // Mark as disposed immediately to prevent re-entry during disposal
            Stop(); // Signal the receive loop to stop via cancellation
            if (_udpClient != null) // Check if the socket was ever created
            {
                _udpClient.Dispose(); // Release the native UDP socket resources; this will also unblock any pending ReceiveAsync
            }

            if (_cts != null) // Check if the cancellation token source was ever created
            {
                _cts.Dispose(); // Release the CTS resources; safe to call even after cancellation
            }
        }

        /// <summary>
        /// Throws if disposed; lazily starts the transport if not yet bound.
        /// </summary>
        private void EnsureClient()
        {
            if (_disposed) // Check if Dispose() has already been called
            {
                throw new ObjectDisposedException(nameof(UdpSocketTransport)); // Throw to prevent using a disposed transport
            }

            if (_udpClient == null) // Check if the transport has not been started yet
            {
                Start(0); // Lazy-start with OS-assigned port so the first Send implicitly binds the socket
            }
        }

        /// <summary>
        /// Continuously receives UDP datagrams and dispatches them via OnDatagram
        /// until cancelled or disposed.
        /// </summary>
        private async Task ReceiveLoopAsync()
        {
            while (!_disposed && _cts != null && !_cts.IsCancellationRequested) // Continue looping while not disposed and not cancelled
            {
                try
                {
                    UdpReceiveResult receiveResult = await _udpClient.ReceiveAsync().ConfigureAwait(false); // Await the next incoming UDP datagram; ConfigureAwait(false) avoids thread-pinning
                    Action<byte[], IPEndPoint> handler = OnDatagram; // Capture the current event handler into a local to avoid null-deref from concurrent unsubscription
                    if (handler != null) // Check if there are any subscribers currently registered
                    {
                        handler(receiveResult.Buffer, receiveResult.RemoteEndPoint); // Raise the event with the received byte array and the sender's endpoint
                    }
                }
                catch (ObjectDisposedException) // Catch when the UdpClient is disposed during an active ReceiveAsync
                {
                    break; // Socket disposed; exit the receive loop gracefully
                }
                catch (SocketException) // Catch transient socket errors (e.g., ICMP port unreachable) or cancellation-induced errors
                {
                    if (_cts == null || _cts.IsCancellationRequested) // Check if this exception was caused by our own cancellation
                    {
                        break; // Cancelled; exit the receive loop gracefully
                    }
                    // Otherwise transient error, continue the loop.
                }
                catch // Catch-all for any unexpected exception
                {
                    // Swallow unexpected exceptions to keep the receive loop alive.
                }
            }
        }
    }
}
