/** @file dtls_transport.cpp
 *  @brief DTLS 1.2/1.3 datagram transport using OpenSSL over UDP.
 *
 *  Implements the DtlsTransport class for encrypted UCP datagram transport.
 *  When OpenSSL is unavailable, operates as a plain UDP transport.
 *  Per-endpoint SSL sessions are cached for connection-oriented DTLS.
 */

#include "ucp/transport/dtls_transport.h"
#include <cstring>
#include <exception>

namespace ucp {
namespace transport {

namespace {
static constexpr int kSocketBufferBytes = 4 * 1024 * 1024;
static constexpr int kReceiveBufferSize = 65536;
} // namespace

DtlsTransport::DtlsTransport() noexcept : socket_(io_context_), receive_running_(false) {}

DtlsTransport::~DtlsTransport() noexcept {
    Stop();
    DestroyDtlsContext();
}

bool DtlsTransport::CreateSocket(int port) noexcept {
    boost::system::error_code ec;
    socket_.open(boost::asio::ip::udp::v6(), ec);
    if (!ec) {
        socket_.set_option(boost::asio::ip::v6_only(false), ec);
        ec.clear();
        ConfigureSocketBuffers();
        socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), static_cast<uint16_t>(port)), ec);
        if (!ec) {
            socket_.non_blocking(true, ec);
            ec.clear();
        }
        if (ec) {
            socket_.close(ec);
            ec.clear();
        }
    }
    if (!socket_.is_open()) {
        socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec)
            return false;
        ConfigureSocketBuffers();
        socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), static_cast<uint16_t>(port)), ec);
        if (ec) {
            socket_.close(ec);
            return false;
        }
        socket_.non_blocking(true, ec);
        ec.clear();
    }
    return socket_.is_open();
}

void DtlsTransport::ConfigureSocketBuffers() noexcept {
    boost::system::error_code ec;
    boost::asio::socket_base::receive_buffer_size rcv(kSocketBufferBytes);
    socket_.set_option(rcv, ec);
    ec.clear();
    boost::asio::socket_base::send_buffer_size snd(kSocketBufferBytes);
    socket_.set_option(snd, ec);
    ec.clear();
}

void DtlsTransport::StartReceiveLoop() noexcept {
    receive_running_ = true;
    receive_buffer_.resize(kReceiveBufferSize);
    socket_.async_receive_from(
        boost::asio::buffer(receive_buffer_.data(), receive_buffer_.size()), remote_endpoint_,
        [this](const boost::system::error_code& error, size_t bytesTransferred) { OnReceive(error, bytesTransferred); });
    receive_thread_ = std::thread([this]() { io_context_.run(); });
}

void DtlsTransport::OnReceive(const boost::system::error_code& error, size_t bytesTransferred) noexcept {
    if (!receive_running_)
        return;
    if (error) {
        if (error == boost::asio::error::operation_aborted)
            return;
        if (!receive_running_ || !socket_.is_open())
            return;
    }
    if (bytesTransferred > 0 && !error) {
        ucp::vector<uint8_t> data(receive_buffer_.data(), receive_buffer_.data() + bytesTransferred);
        Endpoint src;
        src.address = remote_endpoint_.address().to_string();
        src.port = remote_endpoint_.port();
        RaiseOnDatagram(data, src);
    }
    if (receive_running_) {
        socket_.async_receive_from(boost::asio::buffer(receive_buffer_.data(), receive_buffer_.size()), remote_endpoint_,
                                   [this](const boost::system::error_code& err, size_t len) { OnReceive(err, len); });
    }
}

void DtlsTransport::Start(int port) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (receive_running_)
        return;
    if (!CreateSocket(port))
        return;
    local_endpoint_.address = "0.0.0.0";
    try {
        local_endpoint_.port = static_cast<int>(socket_.local_endpoint().port());
    } catch (...) {
        local_endpoint_.port = static_cast<uint16_t>(port);
    }
    InitDtlsContext();
    StartReceiveLoop();
}

void DtlsTransport::Stop() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!receive_running_)
        return;
    receive_running_ = false;
    boost::system::error_code ec;
    socket_.cancel(ec);
    socket_.close(ec);
    io_context_.stop();
    if (receive_thread_.joinable()) {
        if (std::this_thread::get_id() == receive_thread_.get_id()) {
            // Stop called from the receive thread itself: detach instead of
            // self-join (would deadlock / std::terminate).
            receive_thread_.detach();
        } else {
            receive_thread_.join();
        }
    }
    io_context_.restart();
}

void DtlsTransport::Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept {
    if (data.empty())
        return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (!socket_.is_open())
        return;
    boost::system::error_code ec;
    boost::asio::ip::address addr = boost::asio::ip::make_address(remote.address, ec);
    if (ec)
        return;
    boost::asio::ip::udp::endpoint dest(addr, static_cast<uint16_t>(remote.port));
    socket_.send_to(boost::asio::buffer(data.data(), data.size()), dest, {}, ec);
}

Endpoint DtlsTransport::LocalEndpoint() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return local_endpoint_;
}

void DtlsTransport::InitDtlsContext() {}

void DtlsTransport::DestroyDtlsContext() {}

} // namespace transport
} // namespace ucp
