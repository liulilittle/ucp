namespace Ucp
{
    /// <summary>
    /// Defines the common metadata exposed by objects that can act as senders inside
    /// the UCP stack. Concrete network implementations receive this value in Output
    /// so they can make routing decisions without relying on untyped object values.
    /// </summary>
    public interface IUcpObject
    {
        /// <summary>
        /// Gets the protocol connection identifier associated with this object.
        /// Servers and transport adapters that are not bound to a single connection
        /// return zero.
        /// </summary>
        uint ConnectionId { get; }

        /// <summary>
        /// Gets the network engine that owns this object when it is multiplexed over
        /// a shared UcpNetwork instance. Standalone socket-based objects may return null.
        /// </summary>
        UcpNetwork Network { get; }
    }
}
