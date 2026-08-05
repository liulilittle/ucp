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

/** @file dtls_transport.h
 *  @brief DTLS datagram transport interface over UDP (placeholder).
 *
 *  Provides an IBindableTransport implementation intended to encrypt UCP
 *  datagrams with DTLS.  NOTE: DTLS is not yet implemented -- InitDtlsContext /
 *  DestroyDtlsContext are currently no-ops and Send transmits plain UDP
 *  datagrams.  The class exists so the transport surface can be extended with
 *  real DTLS later without changing the ITransport contract.
 */

#include "ucp/transport/ibindable_transport.h"
#include <atomic>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <boost/asio.hpp>

namespace ucp {
namespace transport {

/** @brief DTLS datagram transport over UDP (placeholder, no encryption yet).
 *
 *  Intended to wrap a UDP socket with DTLS encryption using OpenSSL's BIO_dgram
 *  pair and maintain per-endpoint SSL sessions.  Currently a plain-UDP
 *  placeholder: encryption hooks are stubbed out and datagrams are sent in
 *  cleartext. */
class DtlsTransport : public IBindableTransport {
  public:
    DtlsTransport() noexcept;
    ~DtlsTransport() noexcept override;

    DtlsTransport(const DtlsTransport&) = delete;
    DtlsTransport& operator=(const DtlsTransport&) = delete;

    void Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept override;
    void Start(int port) noexcept override;
    void Stop() noexcept override;
    Endpoint LocalEndpoint() noexcept override;

    /** @brief Enable or disable DTLS encryption at runtime after Start().
     *  @param enabled  True to encrypt all outbound datagrams with DTLS.
     *
     *  When disabled, datagrams are sent as plain UDP.  The remote peer
     *  must be configured to match. */
    void SetEncryptionEnabled(bool enabled) noexcept { _encryptionEnabled = enabled; }

    bool IsEncryptionEnabled() const noexcept { return _encryptionEnabled; }

  private:
    bool CreateSocket(int port) noexcept;
    void ConfigureSocketBuffers() noexcept;
    void StartReceiveLoop() noexcept;
    void OnReceive(const boost::system::error_code& error, size_t bytesTransferred) noexcept;

    void InitDtlsContext();
    void DestroyDtlsContext();

    mutable std::mutex mutex_;
    boost::asio::io_context io_context_;
    boost::asio::ip::udp::socket socket_;
    std::thread receive_thread_;
    std::atomic<bool> receive_running_;
    Endpoint local_endpoint_;
    ucp::vector<uint8_t> receive_buffer_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    std::atomic<bool> _encryptionEnabled{false};
};

} // namespace transport
} // namespace ucp
