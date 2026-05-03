using System; // Provides IDisposable for the transport lifecycle contract
using System.Net; // Provides IPEndPoint for endpoint addressing

namespace Ucp.Transport // Placed in the Transport sub-namespace to isolate network I/O abstractions
{
    /// <summary>
    /// Network I/O abstraction used by the protocol stack to receive datagrams
    /// and send encoded packets. Implementations must raise OnDatagram when
    /// incoming UDP data is available and provide Send for outbound traffic.
    /// </summary>
    public interface ITransport : IDisposable // Extends IDisposable so transports can release native socket resources deterministically
    {
        /// <summary>
        /// Raised when an incoming datagram is received from a remote endpoint.
        /// </summary>
        event Action<byte[], IPEndPoint> OnDatagram; // Event that fires with the raw bytes and sender's endpoint; the protocol stack subscribes to consume incoming packets

        /// <summary>
        /// Sends an encoded buffer to the specified remote endpoint.
        /// </summary>
        /// <param name="data">The encoded packet bytes to send.</param>
        /// <param name="remote">The destination endpoint.</param>
        void Send(byte[] data, IPEndPoint remote); // Transmits the encoded packet via the underlying transport (UDP socket, simulator, etc.) to the remote peer
    }
}
