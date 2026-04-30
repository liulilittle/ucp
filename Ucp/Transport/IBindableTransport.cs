using System.Net;

namespace Ucp.Transport
{
    /// <summary>
    /// Internal bindable transport interface implemented by the default UDP transport
    /// and test simulator. Extends ITransport with Start/Stop lifecycle and a local
    /// endpoint property.
    /// </summary>
    internal interface IBindableTransport : ITransport
    {
        /// <summary>
        /// Gets the local endpoint this transport is bound to.
        /// </summary>
        EndPoint LocalEndPoint { get; }

        /// <summary>
        /// Binds the transport to a specific port and begins receiving.
        /// </summary>
        /// <param name="port">The local port to bind to (0 for OS-assigned).</param>
        void Start(int port);

        /// <summary>
        /// Stops receiving and optionally unbinds the underlying socket.
        /// </summary>
        void Stop();
    }
}
