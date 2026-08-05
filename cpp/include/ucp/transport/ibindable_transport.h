#pragma once

/**
 * MIT License
 *
 * Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file ibindable_transport.h
 *  @brief Bindable transport extension -- mirrors C# Ucp.Transport.IBindableTransport.
 *
 *  Extends ITransport with bind/start/stop lifecycle methods so the transport
 *  can be bound to a local port and explicitly started/stopped.  Used by
 *  UcpServer when the application wants UCP to own the underlying socket
 *  (not routed through UcpNetwork).
 *
 *  C# equivalent: Ucp.Transport.IBindableTransport (internal interface).
 */

#include "itransport.h"
#include "ucp/ucp_vector.h"

namespace ucp {
namespace transport {

/** @brief Transport that can bind to a local network port and accept inbound traffic.
 *
 *  Extends ITransport with bind/start/stop lifecycle methods.  Implementations
 *  create a UDP socket in Start() and release it in Stop().  LocalEndpoint()
 *  returns the address:port the transport is bound to (useful for discovering
 *  the OS-assigned port when 0 was passed to Start). */
class IBindableTransport : public ITransport {
  public:
    IBindableTransport() noexcept = default;
    IBindableTransport(const IBindableTransport&) = delete;
    IBindableTransport& operator=(const IBindableTransport&) = delete;
    IBindableTransport(IBindableTransport&&) = delete;
    IBindableTransport& operator=(IBindableTransport&&) = delete;

    /** @brief Bind the transport to the specified port and begin receiving.
     *  @param port  Local UDP port (0 = OS-assigned ephemeral port).
     *
     *  After Start returns, inbound datagrams fire on_datagram subscribers.
     *  Must be called before Send() on a server-owned transport. */
    virtual void Start(int port) noexcept = 0;

    /** @brief Stop receiving and release the bound socket.
     *
     *  After Stop returns, the transport must not invoke on_datagram callbacks.
     *  The underlying socket binding is released. */
    virtual void Stop() noexcept = 0;

    /** @brief Return the local endpoint after binding.
     *  @return The bound address:port as an Endpoint, or default Endpoint if not started. */
    virtual Endpoint LocalEndpoint() noexcept = 0;
};

} // namespace transport
} // namespace ucp
