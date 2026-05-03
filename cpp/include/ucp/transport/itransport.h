#pragma once                                                              //< Prevent multiple inclusion of this header in a single translation unit.

/** @file itransport.h
 *  @brief Abstract transport interface for UCP — mirrors C# Ucp.Transport.ITransport.
 *
 *  Defines the base contract that all UCP transports must fulfill.  UCP is
 *  transport-agnostic:  the protocol engine sends and receives opaque datagrams
 *  through this interface, which can be backed by UDP, sockets, or a custom
 *  test harness.
 *
 *  The C# equivalent is <c>Ucp.Transport.ITransport</c> — a simple Send + callback
 *  contract that keeps the UCP stack decoupled from any particular socket layer.
 *
 *  Equivalence notes vs. C# Ucp.Transport.ITransport:
 *  - C# extends System.IDisposable; C++ uses a virtual destructor for the same purpose.
 *  - C# uses System.Net.IPEndPoint (typed address+port); C++ uses ucp::string for simplicity.
 *  - C# OnDatagram is a multicast event (Action<byte[], IPEndPoint>);
 *    C++ uses a single std::function callback.
 *  - C# Send(byte[] data, IPEndPoint remote) maps to Send(ucp::vector<uint8_t>, ucp::string).
 */

#include <cstdint>                                                            //< Fixed-width integer types (uint8_t).
#include <functional>                                                         //< std::function for the datagram callback.
#include "ucp/ucp_vector.h"                                                   //< ucp::vector<T> and ucp::string type aliases.

namespace ucp {                                                               //< Root namespace for the UCP reliable-transport protocol library.
namespace transport {                                                         //< Sub-namespace isolating all transport-layer abstractions.

/** @brief Minimal datagram transport contract used by the UCP protocol engine.
 *
 *  Implementations must provide Send() for outbound traffic and invoke
 *  on_datagram when an inbound datagram arrives.  The protocol stack never
 *  assumes a specific socket type — only this pure-virtual interface. */
class ITransport {
public:
    /** @brief Virtual destructor — equivalent to IDisposable.Dispose() in the C# interface.
     *
     *  Ensures derived transport implementations can release native socket
     *  resources through normal polymorphic deletion.  Marked =default because
     *  this interface owns no resources itself. */
    virtual ~ITransport() = default;

    /** @brief Send an opaque datagram to the given remote endpoint.
     *  @param data              Reference to the raw byte buffer to transmit.
     *  @param remote_endpoint   String representation of the remote peer (e.g. "127.0.0.1:9000").
     *
     *  Called by the protocol engine (UcpPcb::Output) whenever an encoded
     *  packet is ready for transmission.  The transport implementation
     *  delivers the bytes over whatever underlying socket or simulator it wraps.
     *
     *  C# equivalent: void ITransport.Send(byte[] data, IPEndPoint remote). */
    virtual void Send(const ucp::vector<uint8_t>& data,
                      const ucp::string& remote_endpoint) = 0;

    /** @brief Callback invoked when a datagram arrives from the network.
     *
     *  The transport implementation assigns this callback; the protocol stack
     *  subscribes to it.  Parameters are passed by value for thread safety —
     *  the caller may own a temporary buffer that must be captured.
     *
     *  @param  data      Raw bytes of the received datagram (moved/copied).
     *  @param  endpoint  Remote endpoint string that sent the datagram (moved/copied).
     *
     *  C# equivalent: event Action<byte[], IPEndPoint> ITransport.OnDatagram. */
    std::function<void(ucp::vector<uint8_t>, ucp::string)> on_datagram;
};

} // namespace transport
} // namespace ucp
