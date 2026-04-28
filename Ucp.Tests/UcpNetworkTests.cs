using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Ucp;
using Xunit;

namespace UcpTest
{
    public sealed class UcpNetworkTests
    {
        private sealed class LoopbackNetwork : UcpNetwork
        {
            private readonly Dictionary<int, LoopbackNetwork> peers;
            private readonly Queue<Datagram> inbox = new Queue<Datagram>();
            private readonly object sync = new object();
            private IPEndPoint? localEndPoint;

            public LoopbackNetwork(Dictionary<int, LoopbackNetwork> peers, UcpConfiguration configuration)
                : base(configuration)
            {
                this.peers = peers;
            }

            public override EndPoint? LocalEndPoint
            {
                get { return localEndPoint; }
            }

            public override void Start(int port)
            {
                if (localEndPoint != null)
                {
                    return;
                }

                if (port == 0)
                {
                    port = 50000 + peers.Count;
                }

                localEndPoint = new IPEndPoint(IPAddress.Loopback, port);
                peers[port] = this;
            }

            public override void Stop()
            {
                if (localEndPoint != null)
                {
                    peers.Remove(localEndPoint.Port);
                }
            }

            public override void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender)
            {
                if (localEndPoint == null)
                {
                    Start(0);
                }

                LoopbackNetwork? target;
                if (!peers.TryGetValue(remote.Port, out target))
                {
                    return;
                }

                byte[] copy = new byte[datagram.Length];
                Buffer.BlockCopy(datagram, 0, copy, 0, datagram.Length);
                IPEndPoint source = localEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0);
                target.Enqueue(copy, source);
            }

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

                    Input(datagram.Buffer, datagram.Remote);
                    processed++;
                }

                return processed + base.DoEvents();
            }

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

            private sealed class Datagram
            {
                public byte[] Buffer = Array.Empty<byte>();
                public IPEndPoint Remote = new IPEndPoint(IPAddress.Loopback, 0);
            }
        }

        [Fact]
        public async Task NetworkTimers_RunOnlyWhenDoEventsIsCalled()
        {
            Dictionary<int, LoopbackNetwork> peers = new Dictionary<int, LoopbackNetwork>();
            UcpConfiguration configuration = new UcpConfiguration();
            LoopbackNetwork network = new LoopbackNetwork(peers, configuration);
            int fired = 0;
            network.AddTimer(network.NowMicroseconds, delegate { fired++; });

            Assert.Equal(0, fired);
            await PumpAsync(network, null, 50);

            Assert.Equal(1, fired);
        }

        [Fact]
        public async Task NetworkApi_CanConnectAndTransferWithDoEvents()
        {
            Dictionary<int, LoopbackNetwork> peers = new Dictionary<int, LoopbackNetwork>();
            UcpConfiguration configuration = new UcpConfiguration();
            configuration.TimerIntervalMilliseconds = 1;
            configuration.FairQueueRoundMilliseconds = 1;
            LoopbackNetwork serverNetwork = new LoopbackNetwork(peers, configuration);
            LoopbackNetwork clientNetwork = new LoopbackNetwork(peers, configuration);

            UcpServer server = serverNetwork.CreateServer(41001);
            UcpConnection client = clientNetwork.CreateConnection();
            Task<UcpConnection> acceptTask = server.AcceptAsync();
            Task connectTask = client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 41001));

            await PumpUntilAsync(serverNetwork, clientNetwork, async delegate
            {
                await connectTask;
                await acceptTask;
            }, 5000);

            UcpConnection serverConnection = await acceptTask;
            byte[] payload = Encoding.ASCII.GetBytes(new string('N', 16 * 1024));
            byte[] received = new byte[payload.Length];
            Task<bool> readTask = serverConnection.ReadAsync(received, 0, received.Length);
            Task<int> writeTask = client.SendAsync(payload, 0, payload.Length);

            await PumpUntilAsync(serverNetwork, clientNetwork, async delegate
            {
                int written = await writeTask;
                bool readOk = await readTask;
                Assert.Equal(payload.Length, written);
                Assert.True(readOk);
            }, 5000);

            Assert.Equal(payload, received);
            await client.CloseAsync();
            server.Stop();
        }

        private static async Task PumpUntilAsync(UcpNetwork first, UcpNetwork? second, Func<Task> action, int timeoutMilliseconds)
        {
            Task task = action();
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
            while (!task.IsCompleted && DateTime.UtcNow < deadline)
            {
                first.DoEvents();
                if (second != null)
                {
                    second.DoEvents();
                }
                await Task.Delay(1);
            }

            if (!task.IsCompleted)
            {
                throw new TimeoutException("Network polling test timed out.");
            }

            await task;
        }

        private static async Task PumpAsync(UcpNetwork first, UcpNetwork? second, int durationMilliseconds)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(durationMilliseconds);
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
