using System;
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
        private bool _disposed;

        public event Action<byte[], IPEndPoint> OnDatagram;

        public EndPoint LocalEndPoint
        {
            get { return _udpClient == null ? null : _udpClient.Client.LocalEndPoint; }
        }

        public void Start(int port)
        {
            if (_udpClient != null)
            {
                return;
            }

            _udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, port));
            _cts = new CancellationTokenSource();
            _receiveLoopTask = Task.Run(ReceiveLoopAsync);
        }

        public void Send(byte[] data, IPEndPoint remote)
        {
            EnsureClient();
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            _udpClient.Send(data, data.Length, remote);
        }

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

        private void EnsureClient()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(UdpSocketTransport));
            }

            if (_udpClient == null)
            {
                Start(0);
            }
        }

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
                    break;
                }
                catch (SocketException)
                {
                    if (_cts == null || _cts.IsCancellationRequested)
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
