namespace Ucp // Root namespace for the UCP reliable-transport protocol library
{
    /// <summary>
    /// Defines the common metadata exposed by objects that can act as senders inside
    /// the UCP stack. Concrete network implementations receive this value in Output
    /// so they can make routing decisions without relying on untyped object values.
    /// This interface provides the minimum contract that any UCP-aware sender
    /// (server, client, or multiplexed socket) must satisfy for the transport layer
    /// to correctly multiplex or route packets.
    /// </summary>
    public interface IUcpObject // Contract every UCP-aware sender must implement for transport-layer routing
    {
        /// <summary>
        /// Gets the protocol connection identifier associated with this object.
        /// Servers and transport adapters that are not bound to a single connection
        /// return zero. This ID is embedded in every packet header so the receiving
        /// transport layer can demultiplex datagrams to the correct connection.
        /// </summary>
        uint ConnectionId { get; } // Protocol-level connection identifier for packet routing/demultiplexing

        /// <summary>
        /// Gets the network engine that owns this object when it is multiplexed over
        /// a shared UcpNetwork instance. Standalone socket-based objects may return
        /// null. The network reference enables coordinated scheduling and shared
        /// configuration across multiple multiplexed connections on a single port.
        /// </summary>
        UcpNetwork Network { get; } // Owning UcpNetwork instance for multiplexed scheduling, null for standalone
    }
}
