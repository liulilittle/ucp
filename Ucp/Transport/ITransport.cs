using System;
using System.Net;

namespace Ucp.Transport
{

    public interface ITransport : IDisposable
    {

        event Action<byte[], IPEndPoint> OnDatagram;

        void Send(byte[] data, IPEndPoint remote);
    }
}
