using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Ucp
{
    /// <summary>
    /// UDP socket based network implementation. The receive loop only injects datagrams
    /// into Input; protocol progress is still driven by DoEvents.
    /// </summary>
    public sealed class UcpDatagramNetwork : UcpNetwork
    {
        private readonly object _sync = new object();
        private UdpClient _udpClient;
        private CancellationTokenSource _cts;
        private Task _receiveLoopTask;
        private bool _disposed;

        public UcpDatagramNetwork()
            : base(new UcpConfiguration())
        {
        }

        public UcpDatagramNetwork(int port)
            : base(new UcpConfiguration())
        {
            Start(port);
        }

        public UcpDatagramNetwork(IPAddress localAddress, int port)
            : base(new UcpConfiguration())
        {
            Start(localAddress, port);
        }

        public UcpDatagramNetwork(UcpConfiguration configuration)
            : base(configuration)
        {
        }

        public UcpDatagramNetwork(IPAddress localAddress, int port, UcpConfiguration configuration)
            : base(configuration)
        {
            Start(localAddress, port);
        }

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

        public override void Start(int port)
        {
            Start(IPAddress.Any, port);
        }

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
                    return;
                }

                _udpClient = new UdpClient(new IPEndPoint(localAddress ?? IPAddress.Any, port));
                _cts = new CancellationTokenSource();
                _receiveLoopTask = Task.Run(ReceiveLoopAsync);
            }
        }

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
                    Start(0);
                }

                client = _udpClient;
            }

            client.Send(datagram, datagram.Length, remote);
        }

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
                    break;
                }
                catch (SocketException)
                {
                    if (cancellation.IsCancellationRequested)
                    {
                        break;
                    }
                }
                catch
                {
                }
            }
        }
    }
}
