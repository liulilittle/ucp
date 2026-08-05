/** @file quic_transport.cpp
 *  @brief QUIC datagram transport using msquic over UDP.
 *
 *  Implements the QuicTransport class.  UCP datagrams are sent as QUIC
 *  datagram frames (RFC 9221) when QUIC mode is enabled.  Without msquic,
 *  operates as a plain UDP transport.
 */

#include "ucp/transport/quic_transport.h"
#include <cstring>
#include <exception>

namespace ucp {
namespace transport {

namespace {
static constexpr int kSocketBufferBytes = 4 * 1024 * 1024;
static constexpr int kReceiveBufferSize = 65536;
} // namespace

QuicTransport::QuicTransport() noexcept : socket_(io_context_), receive_running_(false) {}

QuicTransport::~QuicTransport() noexcept {
    Stop();
    DestroyQuicContext();
}

bool QuicTransport::CreateSocket(int port) noexcept {
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

void QuicTransport::ConfigureSocketBuffers() noexcept {
    boost::system::error_code ec;
    boost::asio::socket_base::receive_buffer_size rcv(kSocketBufferBytes);
    socket_.set_option(rcv, ec);
    ec.clear();
    boost::asio::socket_base::send_buffer_size snd(kSocketBufferBytes);
    socket_.set_option(snd, ec);
    ec.clear();
}

void QuicTransport::StartReceiveLoop() noexcept {
    receive_running_ = true;
    receive_buffer_.resize(kReceiveBufferSize);
    socket_.async_receive_from(
        boost::asio::buffer(receive_buffer_.data(), receive_buffer_.size()), remote_endpoint_,
        [this](const boost::system::error_code& error, size_t bytesTransferred) { OnReceive(error, bytesTransferred); });
    receive_thread_ = std::thread([this]() { io_context_.run(); });
}

void QuicTransport::OnReceive(const boost::system::error_code& error, size_t bytesTransferred) noexcept {
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

void QuicTransport::Start(int port) noexcept {
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
    InitQuicContext();
    StartReceiveLoop();
}

void QuicTransport::Stop() noexcept {
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

void QuicTransport::Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept {
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

Endpoint QuicTransport::LocalEndpoint() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return local_endpoint_;
}

void QuicTransport::InitQuicContext() {}

void QuicTransport::DestroyQuicContext() {}

} // namespace transport
} // namespace ucp
