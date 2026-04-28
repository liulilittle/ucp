using System;
using System.Net;

namespace Ucp.Transport
{
    /// <summary>
    /// Network IO abstraction used by the protocol stack to receive datagrams and send packets.
    /// </summary>
    public interface ITransport : IDisposable
    {
        event Action<byte[], IPEndPoint> OnDatagram;

        void Send(byte[] data, IPEndPoint remote);
    }

    /// <summary>
    /// Internal bindable transport implemented by the default UDP transport and test simulator.
    /// </summary>
    internal interface IBindableTransport : ITransport
    {
        EndPoint LocalEndPoint { get; }

        void Start(int port);

        void Stop();
    }
}
