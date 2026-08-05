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

/** @file udp_socket_transport.h
 *  @brief Boost.Asio UDP transport used by standalone UcpConnection and UcpServer.
 *
 *  Provides a concrete bindable UDP transport implementation backed by
 *  boost::asio.  Supports dual-stack IPv6/IPv4, configurable socket buffer
 *  sizes, and asynchronous receive via io_context::run() in a background thread.
 *  Used by standalone UcpConnection and UcpServer instances (not within
 *  a UcpNetwork managed context).
 *
 *  Mirrors the pattern from C# Ucp.Transport.UdpSocketTransport.
 */

#include "ucp/transport/ibindable_transport.h"
#include <atomic>
#include <boost/asio.hpp>
#include <mutex>
#include <thread>

namespace ucp {
namespace transport {

/** @brief Concrete bindable UDP transport using boost::asio with dual-stack IPv6/IPv4 support.
 *
 *  Creates and binds a UDP socket, then runs a background thread pumping
 *  boost::asio::io_context for asynchronous receive.  Outbound datagrams are
 *  sent synchronously via Send().  Inbound datagrams are dispatched to
 *  on_datagram subscribers via the RaiseOnDatagram() mechanism inherited
 *  from ITransport.
 *
 *  The socket is created with dual-stack (IPV6_V6ONLY=false) when binding to
 *  IPv6, with graceful fallback to IPv4-only if IPv6 is unavailable.
 *  Socket send/receive buffers are enlarged before binding to reduce drops
 *  under high throughput. */
class UdpSocketTransport : public IBindableTransport {
  public:
    /** @brief Constructs an unbound UDP transport in idle state.
     *  The socket is not opened; call Start() to bind and begin receiving. */
    UdpSocketTransport() noexcept;

    ~UdpSocketTransport() noexcept override;

    UdpSocketTransport(const UdpSocketTransport&) = delete;
    UdpSocketTransport& operator=(const UdpSocketTransport&) = delete;
    UdpSocketTransport(UdpSocketTransport&&) = delete;
    UdpSocketTransport& operator=(UdpSocketTransport&&) = delete;

    /** @brief Sends one datagram to the specified remote endpoint.
     *  @param data    Raw bytes of the encoded UCP packet to transmit.
     *  @param remote  Destination endpoint (address + port). */
    void Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept override;

    /** @brief Binds the socket to a local UDP port and starts the async receive loop.
     *  @param port  Local UDP port (0 = OS-assigned ephemeral port).
     *
     *  After Start returns, inbound datagrams will fire the on_datagram multicast
     *  to all subscribers.  Must be called before Send(). */
    void Start(int port) noexcept override;

    /** @brief Stops receive and closes the socket.
     *
     *  After Stop returns, no more on_datagram callbacks will fire.
     *  The underlying socket binding is released. */
    void Stop() noexcept override;

    /** @brief Returns the currently bound local endpoint.
     *  @return The local address:port, or a default-constructed Endpoint if not bound. */
    Endpoint LocalEndpoint() noexcept override;

  private:
    /** @brief Creates and binds a dual-stack UDP socket, falling back to IPv4 if IPv6 is unavailable.
     *  @param port  Local UDP port to bind (0 = OS-assigned ephemeral).
     *  @return True if the socket was successfully created and bound. */
    bool CreateSocket(int port) noexcept;

    /** @brief Enlarges OS UDP send and receive buffer sizes before binding to reduce drops under load.
     *
     *  Sets SO_RCVBUF and SO_SNDBUF to 8 MiB so that
     *  the kernel socket buffer can absorb bursts without dropping packets when
     *  the application thread is momentarily delayed. */
    void ConfigureSocketBuffers() noexcept;

    /** @brief Posts the first async_receive_from and runs io_context::run() in a background thread.
     *
     *  Allocates the receive buffer, posts the initial async_receive_from,
     *  then spawns a background thread to run io_context::run().  The completion
     *  handler (OnReceive) chains the next async_receive_from after processing
     *  each datagram, maintaining a continuous receive loop. */
    void StartReceiveLoop() noexcept;

    /** @brief Completion handler for async_receive_from: processes inbound datagram and chains next receive.
     *  @param error              Error code from the async operation (operation_aborted after socket close).
     *  @param bytesTransferred   Number of bytes received in the datagram. */
    void OnReceive(const boost::system::error_code& error, size_t bytesTransferred) noexcept;

    mutable std::mutex mutex_;
    boost::asio::io_context io_context_;
    boost::asio::ip::udp::socket socket_;
    std::thread receive_thread_;
    std::atomic<bool> receive_running_;
    std::atomic<bool> stopped_{false};
    Endpoint local_endpoint_;
    bool local_is_v6_ = false;
    ucp::vector<uint8_t> receive_buffer_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
};

} // namespace transport
} // namespace ucp
