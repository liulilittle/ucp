using System.Net; // Provides EndPoint for the local endpoint property

namespace Ucp.Transport // Transports live in the Transport sub-namespace alongside ITransport and concrete implementations
{
    /// <summary>
    /// Internal bindable transport interface implemented by the default UDP transport
    /// and test simulator. Extends ITransport with Start/Stop lifecycle and a local
    /// endpoint property.
    /// </summary>
    internal interface IBindableTransport : ITransport // Extends ITransport so implementations must provide Send + OnDatagram plus bind/lifecycle methods
    {
        /// <summary>
        /// Gets the local endpoint this transport is bound to.
        /// </summary>
        EndPoint LocalEndPoint { get; } // Returns the local IP address and port after binding; null if not yet started

        /// <summary>
        /// Binds the transport to a specific port and begins receiving.
        /// </summary>
        /// <param name="port">The local port to bind to (0 for OS-assigned).</param>
        void Start(int port); // Initializes the underlying socket, binds to the port, and starts the receive loop

        /// <summary>
        /// Stops receiving and optionally unbinds the underlying socket.
        /// </summary>
        void Stop(); // Signals the receive loop to exit and optionally closes the underlying socket binding
    }
}
