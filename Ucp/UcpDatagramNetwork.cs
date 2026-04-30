using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Ucp
{
    /// <summary>
    /// UDP socket-based network implementation for UCP. Runs a background
    /// receive loop that injects datagrams via <c>Input()</c>, sends encoded
    /// packets via <c>Output()</c>, and delegates protocol progress to the
    /// base <c>DoEvents()</c> event loop.
    /// </summary>
    public sealed class UcpDatagramNetwork : UcpNetwork
    {
        /// <summary>Synchronization lock for socket lifecycle operations.</summary>
        private readonly object _sync = new object();

        /// <summary>Underlying UDP client socket.</summary>
        private UdpClient _udpClient;

        /// <summary>Cancellation token to stop the receive loop.</summary>
        private CancellationTokenSource _cts;

        /// <summary>Background receive loop task.</summary>
        private Task _receiveLoopTask;

        /// <summary>Whether this instance has been disposed.</summary>
        private bool _disposed;

        /// <summary>
        /// Creates an unstarted UcpDatagramNetwork with default configuration.
        /// </summary>
        public UcpDatagramNetwork()
            : base(new UcpConfiguration())
        {
        }

        /// <summary>
        /// Creates and immediately starts a UcpDatagramNetwork on the given port.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
        public UcpDatagramNetwork(int port)
            : base(new UcpConfiguration())
        {
            Start(port);
        }

        /// <summary>
        /// Creates and immediately starts a UcpDatagramNetwork on the given
        /// address and port.
        /// </summary>
        /// <param name="localAddress">The local IP address to bind.</param>
        /// <param name="port">The local port to bind.</param>
        public UcpDatagramNetwork(IPAddress localAddress, int port)
            : base(new UcpConfiguration())
        {
            Start(localAddress, port);
        }

        /// <summary>
        /// Creates an unstarted UcpDatagramNetwork with the given configuration.
        /// </summary>
        /// <param name="configuration">Protocol configuration.</param>
        public UcpDatagramNetwork(UcpConfiguration configuration)
            : base(configuration)
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
            : base(configuration)
        {
            Start(localAddress, port);
        }

        /// <summary>
        /// Gets the local endpoint of the bound UDP socket.
        /// </summary>
        public override EndPoint LocalEndPoint
        {
            get
            {
                lock (_sync)
                {
                    return _udpClient == null ? null : _udpClient.Client.LocalEndPoint;
                }
            }
        }

        /// <summary>
        /// Starts the UDP socket on the given port, binding to all interfaces.
        /// </summary>
        /// <param name="port">The local port to bind.</param>
        public override void Start(int port)
        {
            Start(IPAddress.Any, port);
        }

        /// <summary>
        /// Starts the UDP socket on the given local address and port.
        /// </summary>
        /// <param name="localAddress">The local IP address.</param>
        /// <param name="port">The local port.</param>
        public void Start(IPAddress localAddress, int port)
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(UcpDatagramNetwork));
                }

                if (_udpClient != null)
                {
                    return; // Already started.
                }

                _udpClient = new UdpClient(new IPEndPoint(localAddress ?? IPAddress.Any, port));
                _cts = new CancellationTokenSource();
                _receiveLoopTask = Task.Run(ReceiveLoopAsync);
            }
        }

        /// <summary>
        /// Stops the receive loop and disposes the UDP client.
        /// </summary>
        public override void Stop()
        {
            UdpClient client = null;
            CancellationTokenSource cancellation = null;
            lock (_sync)
            {
                client = _udpClient;
                cancellation = _cts;
                _udpClient = null;
                _cts = null;
                _receiveLoopTask = null;
            }

            if (cancellation != null)
            {
                cancellation.Cancel();
                cancellation.Dispose();
            }

            if (client != null)
            {
                client.Dispose();
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
            if (datagram == null)
            {
                throw new ArgumentNullException(nameof(datagram));
            }

            if (remote == null)
            {
                throw new ArgumentNullException(nameof(remote));
            }

            UdpClient client;
            lock (_sync)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(UcpDatagramNetwork));
                }

                if (_udpClient == null)
                {
                    Start(0); // Lazy-start with OS-assigned port.
                }

                client = _udpClient;
            }

            client.Send(datagram, datagram.Length, remote);
        }

        /// <summary>
        /// Disposes the network: stops the receive loop and releases resources.
        /// </summary>
        public override void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
            }

            base.Dispose();
        }

        /// <summary>
        /// Continuously receives UDP datagrams and injects them via Input()
        /// until cancelled or the socket is disposed.
        /// </summary>
        private async Task ReceiveLoopAsync()
        {
            while (true)
            {
                UdpClient client;
                CancellationTokenSource cancellation;
                lock (_sync)
                {
                    client = _udpClient;
                    cancellation = _cts;
                }

                if (client == null || cancellation == null || cancellation.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    UdpReceiveResult receiveResult = await client.ReceiveAsync().ConfigureAwait(false);
                    Input(receiveResult.Buffer, receiveResult.RemoteEndPoint);
                }
                catch (ObjectDisposedException)
                {
                    break; // Socket disposed; exit gracefully.
                }
                catch (SocketException)
                {
                    if (cancellation.IsCancellationRequested)
                    {
                        break; // Cancelled; exit gracefully.
                    }
                    // Otherwise transient socket error, continue.
                }
                catch
                {
                    // Swallow unexpected exceptions to keep the loop alive.
                }
            }
        }
    }
}
