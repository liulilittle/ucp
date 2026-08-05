using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Ucp
{

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
                    return null == _udpClient ? null : _udpClient.Client.LocalEndPoint;
                }
            }
        }

        public override void Start(int port)
        {
            Start(IPAddress.IPv6Any, port);
        }

        public void Start(IPAddress localAddress, int port)
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(UcpDatagramNetwork));
                }

                if (null != _udpClient)
                {
                    return;
                }

                _udpClient = CreateBoundUdpClient(localAddress ?? IPAddress.IPv6Any, port);
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

            if (null != cancellation)
            {
                cancellation.Cancel();
                cancellation.Dispose();
            }

            if (null != client)
            {
                client.Dispose();
            }
        }

        public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
        {
            if (null == datagram)
            {
                throw new ArgumentNullException(nameof(datagram));
            }

            if (null == remote)
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

                if (null == _udpClient)
                {
                    try
                    {
                        Start(0);
                    }
                    catch (SocketException)
                    {
                        throw new ObjectDisposedException(nameof(UcpDatagramNetwork), "Failed to bind UDP socket");
                    }
                }

                client = _udpClient;
            }

            ObserveSendCompletion(client.SendAsync(datagram, datagram.Length, remote));
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

                if (null == client || null == cancellation || cancellation.IsCancellationRequested)
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
                    // Windows UDP surfaces WSAECONNRESET as SocketException;
                    // throttle to avoid a hot re-arm loop.
                    try { await Task.Delay(1, cancellation.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    catch (ObjectDisposedException) { break; }
                }
                catch (Exception ex)
                {

                    System.Diagnostics.Trace.TraceError($"[UCP] Receive loop error: {ex}");
                }
            }
        }

        private static UdpClient CreateBoundUdpClient(IPAddress localAddress, int port)
        {
            IPAddress address = localAddress ?? IPAddress.IPv6Any;
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            {
                try
                {
                    UdpClient client = new UdpClient(AddressFamily.InterNetworkV6);
                    client.Client.DualMode = true;
                    client.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                    return client;
                }
                catch (SocketException)
                {
                    return new UdpClient(new IPEndPoint(IPAddress.Any, port));
                }
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                UdpClient client = new UdpClient(AddressFamily.InterNetworkV6);
                client.Client.DualMode = true;
                client.Client.Bind(new IPEndPoint(address, port));
                return client;
            }

            return new UdpClient(new IPEndPoint(address, port));
        }

        private static void ObserveSendCompletion(Task<int> sendTask)
        {
            if (sendTask.IsCompleted)
            {
                if (sendTask.IsFaulted)
                {
                    sendTask.Exception.Handle(delegate { return true; });
                }

                return;
            }

            sendTask.ContinueWith(delegate (Task<int> completed)
            {
                completed.Exception.Handle(delegate { return true; });
            }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }
}
