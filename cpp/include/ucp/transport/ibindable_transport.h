#pragma once

/** @file ibindable_transport.h
 *  @brief Bindable transport extension — mirrors C# Ucp.Transport.IBindableTransport.
 *
 *  Extends ITransport with the ability to bind to a local port and start/stop
 *  listening.  Used by UcpServer when the application wants UCP to own the
 *  underlying socket (not routed through UcpNetwork).
 *
 *  The C# equivalent lives in <c>Ucp.Transport.IBindableTransport</c>.
 */

#include "itransport.h"
#include <string>

namespace ucp {
namespace transport {

/** @brief Transport that can bind to a local network port and accept inbound traffic. */
class IBindableTransport : public ITransport {
public:
    /** @brief Bind the transport to the specified port and begin listening.
     *  @param port  Local UDP/TCP port number to bind to. */
    virtual void Start(int port) = 0;

    /** @brief Cease listening and release the bound socket. */
    virtual void Stop() = 0;

    /** @brief Return the local endpoint string after binding (e.g. "0.0.0.0:9000").
     *  @return The transport's bound address:port string. */
    virtual std::string LocalEndPoint() = 0;
};

} // namespace transport
} // namespace ucp
