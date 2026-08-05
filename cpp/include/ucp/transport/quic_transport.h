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

/** @file quic_transport.h
 *  @brief QUIC datagram transport interface over UDP (placeholder).
 *
 *  Provides an IBindableTransport implementation intended to carry UCP
 *  datagrams over QUIC (RFC 9000) datagrams (RFC 9221).  NOTE: QUIC is not yet
 *  implemented -- InitQuicContext / DestroyQuicContext are currently no-ops
 *  and Send transmits plain UDP datagrams.  The class exists so the transport
 *  surface can be extended with real QUIC later without changing the
 *  ITransport contract.
 */

#include "ucp/transport/ibindable_transport.h"
#include <atomic>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <boost/asio.hpp>

namespace ucp {
namespace transport {

/** @brief QUIC datagram transport over UDP (placeholder, no QUIC yet).
 *
 *  Intended to use QUIC datagrams (RFC 9221) to carry UCP packets with QUIC's
 *  encryption, 0-RTT, and connection migration benefits.  Currently a
 *  plain-UDP placeholder: encryption hooks are stubbed out and datagrams are
 *  sent in cleartext. */
class QuicTransport : public IBindableTransport {
  public:
    QuicTransport() noexcept;
    ~QuicTransport() noexcept override;

    QuicTransport(const QuicTransport&) = delete;
    QuicTransport& operator=(const QuicTransport&) = delete;

    void Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept override;
    void Start(int port) noexcept override;
    void Stop() noexcept override;
    Endpoint LocalEndpoint() noexcept override;

    /** @brief Enable or disable QUIC encapsulation.
     *  @param enabled  True to wrap datagrams in QUIC.
     *
     *  When disabled, datagrams are sent as plain UDP. */
    void SetQuicEnabled(bool enabled) noexcept { _quicEnabled = enabled; }

    bool IsQuicEnabled() const noexcept { return _quicEnabled; }

  private:
    bool CreateSocket(int port) noexcept;
    void ConfigureSocketBuffers() noexcept;
    void StartReceiveLoop() noexcept;
    void OnReceive(const boost::system::error_code& error, size_t bytesTransferred) noexcept;

    void InitQuicContext();
    void DestroyQuicContext();

    mutable std::mutex mutex_;
    boost::asio::io_context io_context_;
    boost::asio::ip::udp::socket socket_;
    std::thread receive_thread_;
    std::atomic<bool> receive_running_;
    Endpoint local_endpoint_;
    ucp::vector<uint8_t> receive_buffer_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    std::atomic<bool> _quicEnabled{false};
};

} // namespace transport
} // namespace ucp
