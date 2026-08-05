using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Ucp.Transport
{

    internal sealed class QuicTransport : IBindableTransport
    {
        private UdpClient _udpClient;
        private CancellationTokenSource _cts;
        private Task _receiveLoopTask;
        private volatile bool _disposed;
        private int _started;

        public event Action<byte[], IPEndPoint> OnDatagram;

        public EndPoint LocalEndPoint => _udpClient?.Client.LocalEndPoint;

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
            if (_disposed) { _started = 0; _udpClient?.Dispose(); _udpClient = null; return; }
            _cts = new CancellationTokenSource();
            _receiveLoopTask = Task.Run(ReceiveLoopAsync);
        }

        public void Stop()
        {
            var cts = _cts;
            cts?.Cancel();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _udpClient?.Dispose();
            _udpClient = null;
            _cts?.Dispose();
            _cts = null;
            _receiveLoopTask = null;
        }

        public void Send(byte[] data, IPEndPoint remote)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (remote == null) throw new ArgumentNullException(nameof(remote));
            EnsureClient();
            var client = _udpClient;
            if (null == client)
            {
                return;
            }
            // Placeholder: QUIC (RFC 9221) is not yet implemented -- datagrams
            // are sent in cleartext over plain UDP.
            ObserveSendCompletion(client.SendAsync(data, data.Length, remote));
        }

        private void EnsureClient()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(QuicTransport));
            if (_udpClient == null) Start(0);
        }

        private async Task ReceiveLoopAsync()
        {
            while (!_disposed && _cts != null && !_cts.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult receiveResult = await _udpClient.ReceiveAsync().ConfigureAwait(false);
                    var handler = OnDatagram;
                    if (handler != null)
                    {
                        handler(receiveResult.Buffer, receiveResult.RemoteEndPoint);
                    }
                }
                catch (ObjectDisposedException) { break; }
                catch (SocketException)
                {
                    if (_cts == null || _cts.IsCancellationRequested) break;
                    // Throttle to avoid a hot re-arm loop (Windows UDP surfaces
                    // WSAECONNRESET as SocketException).
                    try { await Task.Delay(1, _cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    catch (ObjectDisposedException) { break; }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("[QUIC Transport] Receive error: " + ex.Message);
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
                    var client = new UdpClient(AddressFamily.InterNetworkV6);
                    client.Client.DualMode = true;
                    ConfigureSocketBuffers(client);
                    client.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                    return client;
                }
                catch (SocketException)
                {
                    var client = new UdpClient(AddressFamily.InterNetwork);
                    ConfigureSocketBuffers(client);
                    client.Client.Bind(new IPEndPoint(IPAddress.Any, port));
                    return client;
                }
            }
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var client = new UdpClient(AddressFamily.InterNetworkV6);
                client.Client.DualMode = true;
                ConfigureSocketBuffers(client);
                client.Client.Bind(new IPEndPoint(address, port));
                return client;
            }
            var ipv4Client = new UdpClient(AddressFamily.InterNetwork);
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
                if (sendTask.IsFaulted) sendTask.Exception?.Handle(_ => true);
                return;
            }
            sendTask.ContinueWith(t => t.Exception?.Handle(_ => true),
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }
}
