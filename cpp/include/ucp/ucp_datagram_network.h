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

/** @file ucp_datagram_network.h
 *  @brief UDP-backed UcpNetwork transport implementation using boost::asio -- cross-platform IPv4/IPv6.
 *
 *  UcpDatagramNetwork extends UcpNetwork with a non-blocking UDP socket
 *  backed by boost::asio.  It implements Output() via synchronous send_to()
 *  and runs a dedicated io_context thread that reads datagrams asynchronously
 *  via async_receive_from and feeds them to Input().  Supports dual-stack
 *  IPv6 (IPv4 + IPv6 on the same socket) with automatic IPv4 fallback.
 */

#include "ucp/ucp_network.h"
#include <boost/asio.hpp>
#include <thread>
#include <mutex>
#include <atomic>

namespace ucp {

/** @brief Concrete UcpNetwork backed by a boost::asio UDP socket with dual-stack IPv4/IPv6 support.
 *
 *  Creates a UDP socket, binds it to the specified address/port, and
 *  starts a background thread running boost::asio::io_context.  Outbound
 *  datagrams from PCBs are transmitted via synchronous send_to().  Inbound
 *  datagrams are read by async_receive_from completion handlers and routed
 *  to Input() for PCB demultiplexing.  Supports dual-stack IPv6 sockets
 *  (IPV6_V6ONLY=false) with automatic fallback to IPv4 if IPv6 is unavailable.
 */
class UcpDatagramNetwork : public UcpNetwork {
  public:
    UcpDatagramNetwork(const UcpDatagramNetwork&) = delete;
    UcpDatagramNetwork& operator=(const UcpDatagramNetwork&) = delete;
    UcpDatagramNetwork(UcpDatagramNetwork&&) = delete;
    UcpDatagramNetwork& operator=(UcpDatagramNetwork&&) = delete;

    UcpDatagramNetwork() noexcept;

    /** @brief Construct and immediately start on the given port (binds to all interfaces).
     *  @param port  UDP port to bind to (0 = OS-assigned ephemeral port). */
    explicit UcpDatagramNetwork(int port) noexcept;

    /** @brief Construct with a configuration (not started).
     *  @param config  UcpConfiguration for the network (cloned internally). */
    explicit UcpDatagramNetwork(const UcpConfiguration& config) noexcept;

    /** @brief Construct, configure, and start on a specific address and port.
     *  @param localAddress  IPv4 or IPv6 address string (e.g. "0.0.0.0", "::", "127.0.0.1").
     *  @param port          UDP port to bind to. */
    UcpDatagramNetwork(const ucp::string& localAddress, int port) noexcept;

    /** @brief Construct with configuration, address, and port; start immediately.
     *  @param localAddress  IPv4 or IPv6 address string.
     *  @param port          UDP port.
     *  @param config        UcpConfiguration (cloned internally). */
    UcpDatagramNetwork(const ucp::string& localAddress, int port, const UcpConfiguration& config) noexcept;

    ~UcpDatagramNetwork() noexcept override;

    /** @brief Transmit raw bytes via UDP send_to() to the given endpoint.  Implements UcpNetwork::Output.
     *  @param data    Byte buffer to transmit.
     *  @param length  Number of bytes in the buffer.
     *  @param remote  Destination endpoint (IPv4 or IPv6 address string + port).
     *  @param sender  Source UcpObject (unused by raw UDP; included for interface conformance). */
    void Output(const uint8_t* data, size_t length, const Endpoint& remote, IUcpObject* sender) noexcept override;

    /** @brief Bind to the given port on all interfaces and start receive loop.
     *  @param port  UDP port to bind to. */
    void Start(int port) noexcept override;

    /** @brief Bind to a specific address and port, then start the receive loop.
     *  @param localAddress  IPv4 or IPv6 address string (e.g. "0.0.0.0", "::").
     *  @param port          UDP port to bind to. */
    void Start(const ucp::string& localAddress, int port) noexcept;

    void Stop() noexcept override;

    /** @brief Return the locally bound endpoint.
     *  @return The local Endpoint (address + port) as reported by socket_.local_endpoint() after bind. */
    Endpoint GetLocalEndpoint() const noexcept override;

    void Dispose() noexcept override;

    /** @brief Returns the total number of datagrams delivered by the receive loop. */
    int64_t GetReceivedDatagramCount() const noexcept;

    /** @brief Returns the number of outbound datagrams silently dropped because the OS send buffer was full. */
    int64_t GetSendWouldBlockCount() const noexcept;

    /** @brief Returns the number of outbound datagrams that failed with a non-would-block error. */
    int64_t GetSendErrorCount() const noexcept;

    /** @brief Returns the number of times the receive loop re-armed with an error code. */
    int64_t GetReceiveReArmErrorCount() const noexcept;

  private:
    void EnsureSocket() noexcept;

    void StartReceiveLoop() noexcept;

    void StopReceiveLoop() noexcept;

    /** @brief Create and bind a dual-stack UDP socket, falling back to IPv4 if IPv6 is unavailable.
     *  @param address  Address string to bind to ("0.0.0.0", "::", or specific IP).
     *  @param port     UDP port to bind to (0 = OS-assigned ephemeral port). */
    void CreateSocket(const ucp::string& address, int port) noexcept;

    /** @brief Sets the socket send/receive buffer sizes from the network configuration.
     *  Prevents silent packet drops when bursts exceed the OS default kernel buffer. */
    void SetSocketBufferSizes() noexcept;

    /** @brief Completion handler for async_receive_from: processes the datagram and chains the next receive.
     *  @param error              Error code from the async operation (operation_aborted after socket close).
     *  @param bytes_transferred  Number of bytes received in the datagram. */
    void OnReceive(const boost::system::error_code& error, size_t bytes_transferred) noexcept;

    mutable std::mutex mutex_;
    boost::asio::io_context io_context_;
    boost::asio::ip::udp::socket socket_{io_context_};
    std::thread recv_thread_;
    std::atomic<bool> recv_running_{false};
    Endpoint local_endpoint_;
    bool local_is_v6_ = false;
    ucp::vector<uint8_t> recv_buffer_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    std::atomic<int64_t> recv_datagram_count_{0};
    std::atomic<int64_t> send_would_block_count_{0};
    std::atomic<int64_t> send_error_count_{0};
    std::atomic<int64_t> recv_rearm_error_count_{0};
};

} // namespace ucp
