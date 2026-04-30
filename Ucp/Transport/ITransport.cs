using System;
using System.Net;

namespace Ucp.Transport
{
    /// <summary>
    /// Network I/O abstraction used by the protocol stack to receive datagrams
    /// and send encoded packets. Implementations must raise OnDatagram when
    /// incoming UDP data is available and provide Send for outbound traffic.
    /// </summary>
    public interface ITransport : IDisposable
    {
        /// <summary>
        /// Raised when an incoming datagram is received from a remote endpoint.
        /// </summary>
        event Action<byte[], IPEndPoint> OnDatagram;

        /// <summary>
        /// Sends an encoded buffer to the specified remote endpoint.
        /// </summary>
        /// <param name="data">The encoded packet bytes to send.</param>
        /// <param name="remote">The destination endpoint.</param>
        void Send(byte[] data, IPEndPoint remote);
    }
}
