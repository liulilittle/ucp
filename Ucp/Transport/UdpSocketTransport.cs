using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Ucp.Transport
{
    /// <summary>
    /// Default UDP socket transport implementation. Binds a UdpClient on demand,
    /// runs a background receive loop that raises OnDatagram, and sends encoded
    /// packets via the socket.
    /// </summary>
    internal sealed class UdpSocketTransport : IBindableTransport
    {
        /// <summary>Underlying UDP client; created on Start or first send.</summary>
        private UdpClient _udpClient;

        /// <summary>Cancellation token source to stop the receive loop.</summary>
        private CancellationTokenSource _cts;

        /// <summary>Background task running the asynchronous receive loop.</summary>
        private Task _receiveLoopTask;

        /// <summary>Whether the transport has been disposed.</summary>
        private bool _disposed;

        public event Action<byte[], IPEndPoint> OnDatagram;

        /// <summary>
        /// Gets the local endpoint of the bound UDP socket, or null if not yet started.
        /// </summary>
        public EndPoint LocalEndPoint
        {
            get { return _udpClient == null ? null : _udpClient.Client.LocalEndPoint; }
        }

        /// <summary>
        /// Binds the UDP socket to the specified port and starts the receive loop.
        /// </summary>
        /// <param name="port">The port to bind to (0 for OS-assigned).</param>
        public void Start(int port)
        {
            if (_udpClient != null)
            {
                return; // Already started.
            }

            _udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, port));
            _cts = new CancellationTokenSource();
            _receiveLoopTask = Task.Run(ReceiveLoopAsync);
        }

        /// <summary>
        /// Sends encoded packet data to the specified remote endpoint via UDP.
        /// </summary>
        /// <param name="data">The encoded packet bytes.</param>
        /// <param name="remote">The destination endpoint.</param>
        public void Send(byte[] data, IPEndPoint remote)
        {
            // Ensure the client is active before sending (lazy start).
            EnsureClient();
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            _udpClient.Send(data, data.Length, remote);
        }

        /// <summary>
        /// Signals the receive loop to stop via cancellation.
        /// </summary>
        public void Stop()
        {
            if (_udpClient == null)
            {
                return;
            }

            if (_cts != null)
            {
                _cts.Cancel();
            }
        }

        /// <summary>
        /// Disposes the transport: stops the receive loop, disposes the UDP client and CTS.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            Stop();
            if (_udpClient != null)
            {
                _udpClient.Dispose();
            }

            if (_cts != null)
            {
                _cts.Dispose();
            }
        }

        /// <summary>
        /// Throws if disposed; lazily starts the transport if not yet bound.
        /// </summary>
        private void EnsureClient()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(UdpSocketTransport));
            }

            if (_udpClient == null)
            {
                Start(0); // Lazy-start with OS-assigned port.
            }
        }

        /// <summary>
        /// Continuously receives UDP datagrams and dispatches them via OnDatagram
        /// until cancelled or disposed.
        /// </summary>
        private async Task ReceiveLoopAsync()
        {
            while (!_disposed && _cts != null && !_cts.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult receiveResult = await _udpClient.ReceiveAsync().ConfigureAwait(false);
                    Action<byte[], IPEndPoint> handler = OnDatagram;
                    if (handler != null)
                    {
                        handler(receiveResult.Buffer, receiveResult.RemoteEndPoint);
                    }
                }
                catch (ObjectDisposedException)
                {
                    break; // Socket disposed; exit gracefully.
                }
                catch (SocketException)
                {
                    if (_cts == null || _cts.IsCancellationRequested)
                    {
                        break; // Cancelled; exit gracefully.
                    }
                    // Otherwise transient error, continue the loop.
                }
                catch
                {
                    // Swallow unexpected exceptions to keep the receive loop alive.
                }
            }
        }
    }
}
