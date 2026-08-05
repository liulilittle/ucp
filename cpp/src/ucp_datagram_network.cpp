/** @file ucp_datagram_network.cpp
 *  @brief boost::asio-based UDP transport -- dual-stack IPv6/IPv4 with async receive loop.
 *
 *  Implements UcpDatagramNetwork using boost::asio for cross-platform I/O.
 *  Attempts a dual-stack IPv6 socket (IPV6_V6ONLY=false) first, falling back
 *  to IPv4 if IPv6 is unavailable.  A single background thread runs
 *  io_context::run() which processes async_receive_from completions and
 *  chains subsequent receives.  The stop path closes the socket to unblock
 *  any pending asynchronous operations (mirroring CancellationToken + UdpClient.Close).
 */

#include "ucp/ucp_datagram_network.h"
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"
#include <cstring>
#include <boost/asio.hpp>

namespace ucp {

UcpDatagramNetwork::UcpDatagramNetwork() noexcept : UcpNetwork(UcpConfiguration()) {}

UcpDatagramNetwork::UcpDatagramNetwork(int port) noexcept : UcpNetwork(UcpConfiguration()) {
    Start(port);
}

UcpDatagramNetwork::UcpDatagramNetwork(const UcpConfiguration& config) noexcept : UcpNetwork(config) {}

UcpDatagramNetwork::UcpDatagramNetwork(const ucp::string& localAddress, int port) noexcept : UcpNetwork(UcpConfiguration()) {
    Start(localAddress, port);
}

UcpDatagramNetwork::UcpDatagramNetwork(const ucp::string& localAddress, int port, const UcpConfiguration& config) noexcept
    : UcpNetwork(config) {
    Start(localAddress, port);
}

UcpDatagramNetwork::~UcpDatagramNetwork() noexcept {
    Dispose();
}

void UcpDatagramNetwork::CreateSocket(const ucp::string& address, int port) noexcept {
    boost::system::error_code ec;

    socket_.open(boost::asio::ip::udp::v6(), ec);
    if (!ec) {

        socket_.set_option(boost::asio::socket_base::reuse_address(true), ec);
        ec.clear();
        socket_.set_option(boost::asio::ip::v6_only(false), ec);
        ec.clear();

        boost::asio::ip::address bindAddress;
        if (address.empty() || "0.0.0.0" == address || "::" == address) {
            bindAddress = boost::asio::ip::address_v6::any();
        } else {
            boost::system::error_code addrEc;
            bindAddress = boost::asio::ip::make_address(address, addrEc);
            if (addrEc) {
                bindAddress = boost::asio::ip::address_v6::any();
            }
        }

        SetSocketBufferSizes();

        boost::asio::ip::udp::endpoint bindEp(bindAddress, static_cast<uint16_t>(port));
        socket_.bind(bindEp, ec);
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
        if (ec) {
            return;
        }

        socket_.set_option(boost::asio::socket_base::reuse_address(true), ec);
        ec.clear();

        boost::asio::ip::address bindAddress;
        if (address.empty() || "0.0.0.0" == address || "::" == address) {
            bindAddress = boost::asio::ip::address_v4::any();
        } else {
            boost::system::error_code addrEc;
            bindAddress = boost::asio::ip::make_address(address, addrEc);
            if (addrEc) {
                bindAddress = boost::asio::ip::address_v4::any();
            }
        }

        SetSocketBufferSizes();

        boost::asio::ip::udp::endpoint bindEp(bindAddress, static_cast<uint16_t>(port));
        socket_.bind(bindEp, ec);
        if (!ec) {
            socket_.non_blocking(true, ec);
            ec.clear();
        }
        if (ec) {
            socket_.close(ec);
            return;
        }
    }

    boost::system::error_code ec2;
    auto localEp = socket_.local_endpoint(ec2);
    if (!ec2) {
        local_endpoint_.address = localEp.address().to_string();
        local_endpoint_.port = localEp.port();
        local_is_v6_ = (boost::asio::ip::udp::v6() == localEp.protocol());
    }
}

void UcpDatagramNetwork::EnsureSocket() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (disposed_) {
        return;
    }
    if (!socket_.is_open()) {
        CreateSocket("0.0.0.0", 0);
        if (socket_.is_open()) {
            StartReceiveLoop();
        }
    }
}

void UcpDatagramNetwork::Start(int port) noexcept {
    Start("0.0.0.0", port);
}

void UcpDatagramNetwork::Start(const ucp::string& localAddress, int port) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (disposed_) {
        return;
    }
    if (socket_.is_open()) {
        return;
    }

    CreateSocket(localAddress, port);
    if (socket_.is_open()) {
        StartReceiveLoop();
    }
}

void UcpDatagramNetwork::SetSocketBufferSizes() noexcept {
    boost::system::error_code ec;
    int sndBuf = config_.SendBufferSize();
    if (sndBuf <= 0) {
        sndBuf = 256 * 1024;
    }
    socket_.set_option(boost::asio::socket_base::send_buffer_size(sndBuf), ec);
    if (ec) {
        std::fprintf(stderr, "[UCP] WARNING: setsockopt SO_SNDBUF=%d failed: %s\n", sndBuf, ec.message().c_str());
    }
    ec.clear();
    int actualSnd = 0;
    boost::asio::socket_base::send_buffer_size sndOpt;
    socket_.get_option(sndOpt, ec);
    if (!ec) {
        actualSnd = sndOpt.value();
    }
    ec.clear();
    int rcvBuf = config_.ReceiveBufferSize();
    if (rcvBuf <= 0) {
        rcvBuf = 256 * 1024;
    }
    socket_.set_option(boost::asio::socket_base::receive_buffer_size(rcvBuf), ec);
    if (ec) {
        std::fprintf(stderr, "[UCP] WARNING: setsockopt SO_RCVBUF=%d failed: %s\n", rcvBuf, ec.message().c_str());
    }
    ec.clear();
    int actualRcv = 0;
    boost::asio::socket_base::receive_buffer_size rcvOpt;
    socket_.get_option(rcvOpt, ec);
    if (!ec) {
        actualRcv = rcvOpt.value();
    }
    ec.clear();
}

void UcpDatagramNetwork::StartReceiveLoop() noexcept {
    if (recv_running_.exchange(true)) {
        return;
    }

    recv_buffer_.resize(65536);

    socket_.async_receive_from(
        boost::asio::buffer(recv_buffer_.data(), recv_buffer_.size()), remote_endpoint_,
        [this](const boost::system::error_code& error, size_t bytes_transferred) noexcept { OnReceive(error, bytes_transferred); });

    recv_thread_ = std::thread([this]() noexcept { io_context_.run(); });
}

void UcpDatagramNetwork::OnReceive(const boost::system::error_code& error, size_t bytes_transferred) noexcept {
    if (!recv_running_) {
        return;
    }

    if (error) {
        if (boost::asio::error::operation_aborted == error) {
            return;
        }
        recv_rearm_error_count_.fetch_add(1, std::memory_order_relaxed);
        if (recv_running_ && socket_.is_open()) {
            // Throttle re-arm on persistent errors (e.g. Windows
            // WSAECONNRESET storms): re-arming immediately spins the
            // io_context thread in a hot loop.  A short sleep keeps the
            // socket alive while bounding the retry rate.
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (!recv_running_ || !socket_.is_open()) {
                return;
            }
            socket_.async_receive_from(boost::asio::buffer(recv_buffer_.data(), recv_buffer_.size()), remote_endpoint_,
                                       [this](const boost::system::error_code& err, size_t len) noexcept { OnReceive(err, len); });
        }
        return;
    }

    if (0 < bytes_transferred) {
        recv_datagram_count_.fetch_add(1, std::memory_order_relaxed);
        Endpoint remote;
        remote.address = remote_endpoint_.address().to_string();
        remote.port = remote_endpoint_.port();

        Input(recv_buffer_.data(), bytes_transferred, remote);
    }

    if (recv_running_ && socket_.is_open()) {
        socket_.async_receive_from(boost::asio::buffer(recv_buffer_.data(), recv_buffer_.size()), remote_endpoint_,
                                   [this](const boost::system::error_code& err, size_t len) noexcept { OnReceive(err, len); });
    }
}

int64_t UcpDatagramNetwork::GetReceivedDatagramCount() const noexcept {
    return recv_datagram_count_.load(std::memory_order_relaxed);
}

int64_t UcpDatagramNetwork::GetSendWouldBlockCount() const noexcept {
    return send_would_block_count_.load(std::memory_order_relaxed);
}

int64_t UcpDatagramNetwork::GetSendErrorCount() const noexcept {
    return send_error_count_.load(std::memory_order_relaxed);
}

int64_t UcpDatagramNetwork::GetReceiveReArmErrorCount() const noexcept {
    return recv_rearm_error_count_.load(std::memory_order_relaxed);
}

void UcpDatagramNetwork::StopReceiveLoop() noexcept {
    recv_running_ = false;
    boost::system::error_code ec;
    socket_.close(ec);
    io_context_.stop();
    if (recv_thread_.joinable()) {
        if (std::this_thread::get_id() != recv_thread_.get_id()) {
            recv_thread_.join();
        } else {
            recv_thread_.detach();
        }
    }
}

void UcpDatagramNetwork::Stop() noexcept {
    StopReceiveLoop();

    io_context_.restart();
}

void UcpDatagramNetwork::Output(const uint8_t* data, size_t length, const Endpoint& remote, IUcpObject*) noexcept {

    if (NULLPTR == data || 0 == length) {
        return;
    }

    EnsureSocket();

    std::lock_guard<std::mutex> lock(mutex_);
    if (disposed_ || !socket_.is_open()) {
        return;
    }

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(remote.address, ec);
    if (ec) {
        return;
    }

    boost::asio::ip::udp::endpoint dest(addr, remote.port);
    if (local_is_v6_ && addr.is_v4()) {
        boost::asio::ip::address_v4::bytes_type v4Bytes = addr.to_v4().to_bytes();
        boost::asio::ip::address_v6::bytes_type mappedBytes = {{0}};
        mappedBytes[10] = 0xff;
        mappedBytes[11] = 0xff;
        mappedBytes[12] = v4Bytes[0];
        mappedBytes[13] = v4Bytes[1];
        mappedBytes[14] = v4Bytes[2];
        mappedBytes[15] = v4Bytes[3];
        dest = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6(mappedBytes), remote.port);
    }

    socket_.send_to(boost::asio::const_buffer(data, length), dest, 0, ec);
    if (ec == boost::asio::error::would_block || ec == boost::asio::error::try_again) {
        send_would_block_count_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (ec) {
        send_error_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

Endpoint UcpDatagramNetwork::GetLocalEndpoint() const noexcept {
    return local_endpoint_;
}

void UcpDatagramNetwork::Dispose() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (disposed_.exchange(true)) {
            return;
        }
    }

    StopReceiveLoop();

    UcpNetwork::Dispose();
}

} // namespace ucp
