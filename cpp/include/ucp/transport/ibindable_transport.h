#pragma once                                                              //< Prevent multiple inclusion of this header in a single translation unit.

/** @file ibindable_transport.h
 *  @brief Bindable transport extension — mirrors C# Ucp.Transport.IBindableTransport.
 *
 *  Extends ITransport with the ability to bind to a local port and start/stop
 *  listening.  Used by UcpServer when the application wants UCP to own the
 *  underlying socket (not routed through UcpNetwork).
 *
 *  The C# equivalent lives in <c>Ucp.Transport.IBindableTransport</c>.
 *
 *  Equivalence notes vs. C# Ucp.Transport.IBindableTransport:
 *  - C# IBindableTransport is marked internal; C++ has no access modifier equivalent
 *    but the header is placed in the transport sub-namespace to signal its internal role.
 *  - C# EndPoint LocalEndPoint { get; } is a read-only property;
 *    C++ exposes it as a pure-virtual accessor method LocalEndPoint().
 *  - C# uses System.Net.EndPoint (base of IPEndPoint); C++ returns ucp::string.
 */

#include "itransport.h"                                                       //< Base interface ITransport (Send + on_datagram callback).
#include "ucp/ucp_vector.h"                                                   //< ucp::string type alias.

namespace ucp {                                                               //< Root namespace for the UCP reliable-transport protocol library.
namespace transport {                                                         //< Sub-namespace isolating all transport-layer abstractions.

/** @brief Transport that can bind to a local network port and accept inbound traffic.
 *
 *  Extends ITransport with bind/start/stop lifecycle methods.  Used internally
 *  by UcpServer to own a socket directly, rather than routing through UcpNetwork
 *  (which manages its own binding). */
class IBindableTransport : public ITransport {
public:
    /** @brief Bind the transport to the specified port and begin listening.
     *  @param port  Local UDP/TCP port number to bind to (0 for OS-assigned ephemeral port).
     *
     *  After calling Start, inbound datagrams will fire on_datagram as they arrive.
     *  Must be called before any Send operations on a server-owned transport.
     *
     *  C# equivalent: void IBindableTransport.Start(int port). */
    virtual void Start(int port) = 0;

    /** @brief Cease listening and release the bound socket.
     *
     *  After Stop returns, the transport must not invoke on_datagram or accept
     *  new inbound traffic.  The underlying socket binding is released.
     *
     *  C# equivalent: void IBindableTransport.Stop(). */
    virtual void Stop() = 0;

    /** @brief Return the local endpoint string after binding (e.g. "0.0.0.0:9000").
     *  @return The transport's bound address:port string, or empty if not yet started.
     *
     *  Useful for discovering the OS-assigned port when port 0 was passed to Start.
     *
     *  C# equivalent: EndPoint IBindableTransport.LocalEndPoint { get; } — C# uses
     *  a typed System.Net.EndPoint, while C++ returns a string for simplicity. */
    virtual ucp::string LocalEndPoint() = 0;
};

} // namespace transport
} // namespace ucp
