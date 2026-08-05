using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Ucp.Transport
{

    internal sealed class UdpSocketTransport : IBindableTransport
    {

        private UdpClient _udpClient;

        private CancellationTokenSource _cts;

        private Task _receiveLoopTask;

        private volatile bool _disposed;

        private int _started;

        public event Action<byte[], IPEndPoint> OnDatagram;

        public EndPoint LocalEndPoint
        {
            get { return null == _udpClient ? null : _udpClient.Client.LocalEndPoint; }
        }

        public void Start(int port)
        {
            if (Interlocked.CompareExchange(ref _started, 1, 0) != 0) return;
            if (_disposed) { _started = 0; return; }

            try
            {
                _udpClient = CreateBoundUdpClient(IPAddress.IPv6Any, port);
            }
            catch
            {
                Interlocked.Exchange(ref _started, 0);
                throw;
            }
            if (_disposed) { Interlocked.Exchange(ref _started, 0); try { _udpClient?.Dispose(); } catch { } _udpClient = null; return; }
            _cts = new CancellationTokenSource();
            _receiveLoopTask = Task.Run(ReceiveLoopAsync);
        }

        public void Send(byte[] data, IPEndPoint remote)
        {
            if (null == data)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (null == remote)
            {
                throw new ArgumentNullException(nameof(remote));
            }

            EnsureClient();
            var client = _udpClient;
            if (null == client)
            {
                return;
            }
            ObserveSendCompletion(client.SendAsync(data, data.Length, remote));
        }

        public void Stop()
        {
            CancellationTokenSource cts = _cts;
            if (null != cts)
            {
                try
                {
                    cts.Cancel();
                }
                catch (ObjectDisposedException)
                {

                }
            }

            // Close the socket so a pending ReceiveAsync in the receive loop
            // unblocks immediately (the loop observes a closed socket and
            // exits) instead of blocking until Dispose() runs. netstandard2.0
            // has no CancellationToken-aware UdpClient.ReceiveAsync overload,
            // so closing the underlying socket is the cancellation signal.
            UdpClient client = _udpClient;
            if (null != client)
            {
                try
                {
                    client.Close();
                }
                catch (ObjectDisposedException)
                {

                }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            if (null != _udpClient)
            {
                _udpClient.Dispose();
                _udpClient = null;
            }

            if (null != _cts)
            {
                _cts.Dispose();
                _cts = null;
            }

            _receiveLoopTask = null;
        }

        private void EnsureClient()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(UdpSocketTransport));
            }

            if (null == _udpClient)
            {
                Start(0);
            }
        }

        private async Task ReceiveLoopAsync()
        {
            while (!_disposed && null != _cts && !_cts.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult receiveResult = await _udpClient.ReceiveAsync().ConfigureAwait(false);
                    Action<byte[], IPEndPoint> handler = OnDatagram;
                    if (null != handler)
                    {
                        handler(receiveResult.Buffer, receiveResult.RemoteEndPoint);
                    }
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException)
                {
                    if (null == _cts || _cts.IsCancellationRequested)
                    {
                        break;
                    }
                    // Windows UDP sockets surface WSAECONNRESET (ICMP port
                    // unreachable) as SocketException; without throttling the
                    // loop would spin hot.  Yield briefly, then re-arm.
                    try { await Task.Delay(1, _cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    catch (ObjectDisposedException) { break; }
                }
                catch (Exception ex)
                {

                    Trace.WriteLine("[UDP Transport] Unexpected exception in receive loop: " + ex);
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
                    ConfigureSocketBuffers(client);
                    client.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                    return client;
                }
                catch (SocketException)
                {
                    UdpClient client = new UdpClient(AddressFamily.InterNetwork);
                    ConfigureSocketBuffers(client);
                    client.Client.Bind(new IPEndPoint(IPAddress.Any, port));
                    return client;
                }
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                UdpClient client = new UdpClient(AddressFamily.InterNetworkV6);
                client.Client.DualMode = true;
                ConfigureSocketBuffers(client);
                client.Client.Bind(new IPEndPoint(address, port));
                return client;
            }

            UdpClient ipv4Client = new UdpClient(AddressFamily.InterNetwork);
            ConfigureSocketBuffers(ipv4Client);
            ipv4Client.Client.Bind(new IPEndPoint(address, port));
            return ipv4Client;
        }

        private static void ConfigureSocketBuffers(UdpClient client)
        {
            client.Client.ReceiveBufferSize = UcpConstants.UDP_SOCKET_BUFFER_BYTES;
            client.Client.SendBufferSize = UcpConstants.UDP_SOCKET_BUFFER_BYTES;
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
