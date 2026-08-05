/** @file udp_socket_transport.cpp
 *  @brief Concrete bindable UDP transport using boost::asio with dual-stack IPv6/IPv4 support.
 *
 *  Implements the IBindableTransport interface for standalone UcpConnection and UcpServer
 *  instances.  Creates a UDP socket with configurable OS buffer sizes, launches a background
 *  thread running boost::asio::io_context::run() for asynchronous datagram receive, and
 *  dispatches inbound datagrams to ITransport on_datagram subscribers via RaiseOnDatagram().
 *
 *  Outbound datagrams are sent synchronously via Send().  The async receive loop chains
 *  boost::asio::async_receive_from completion handlers for continuous operation.  The Stop()
 *  path closes the socket to unblock pending async operations (mirroring CancellationToken
 *  + UdpClient.Close in C#).
 *
 *  Supports dual-stack IPv6 (IPV6_V6ONLY=false) with automatic IPv4 fallback when IPv6 is
 *  unavailable.  Socket send/receive buffers are enlarged (8 MB) before binding to absorb
 *  bursts from UCP pacing and reduce packet loss under high throughput.
 */

#include "ucp/transport/udp_socket_transport.h"

#include <exception>

namespace ucp {
namespace transport {

namespace {
static constexpr int kSocketBufferBytes = 8 * 1024 * 1024;
}

UdpSocketTransport::UdpSocketTransport() noexcept : socket_(io_context_), receive_running_(false) {}

UdpSocketTransport::~UdpSocketTransport() noexcept {
    Stop();
}

/** @brief Creates and binds a dual-stack UDP socket (IPv6 + IPv4 fallback).
 *  Configures OS socket buffers to 8 MB for paced burst absorption.
 *  @param port  Local port to bind (0 = OS-assigned ephemeral).
 *  @return True if the socket was successfully created and bound. */
bool UdpSocketTransport::CreateSocket(int port) noexcept {
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
        if (ec) {
            return false;
        }
        ConfigureSocketBuffers();
        socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), static_cast<uint16_t>(port)), ec);
        if (ec) {
            socket_.close(ec);
            return false;
        }
        socket_.non_blocking(true, ec);
        ec.clear();
    }

    auto localEndpoint = socket_.local_endpoint(ec);
    if (!ec) {
        local_endpoint_.address = localEndpoint.address().to_string();
        local_endpoint_.port = localEndpoint.port();
        local_is_v6_ = (boost::asio::ip::udp::v6() == localEndpoint.protocol());
    }
    return socket_.is_open();
}

/** @brief Configures OS-level send and receive socket buffer sizes to 8 MB.
 *  Larger buffers absorb bursts from UCP pacing and prevent UDP drops under load. */
void UdpSocketTransport::ConfigureSocketBuffers() noexcept {
    boost::system::error_code ec;
    socket_.set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), ec);
    ec.clear();
    socket_.set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), ec);
}

/** @brief Starts listening on the given port: creates socket and launches the async receive loop.
 *  Idempotent if called multiple times.
 *  @param port  UDP port to bind. */
void UdpSocketTransport::Start(int port) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    stopped_.store(false, std::memory_order_relaxed);
    if (socket_.is_open()) {
        return;
    }
    if (CreateSocket(port)) {
        StartReceiveLoop();
    }
}

/** @brief Launches the background async receive loop on an Asio io_context thread.
 *  Posts the first async_receive_from and spawns a thread to run the io_context event loop.
 *  Idempotent (atomic flag prevents duplicate threads). */
void UdpSocketTransport::StartReceiveLoop() noexcept {
    if (receive_running_.exchange(true)) {
        return;
    }

    receive_buffer_.resize(65536);
    socket_.async_receive_from(
        boost::asio::buffer(receive_buffer_.data(), receive_buffer_.size()), remote_endpoint_,
        [this](const boost::system::error_code& error, size_t bytesTransferred) noexcept { OnReceive(error, bytesTransferred); });

    receive_thread_ = std::thread([this]() noexcept {
        try {
            io_context_.run();
        } catch (const std::exception&) {
        }
    });
}

/** @brief Completion handler for async_receive_from: dispatches received data to subscribers
 *  and chains the next async receive.  On transient errors, re-arms the receive loop
 *  if the socket is still open.
 *  @param error              Asio error code (operation_aborted on socket close).
 *  @param bytesTransferred   Number of bytes received in the buffer. */
void UdpSocketTransport::OnReceive(const boost::system::error_code& error, size_t bytesTransferred) noexcept {
    if (!receive_running_) {
        return;
    }

    if (!error && 0 < bytesTransferred) {
        Endpoint remote;
        remote.address = remote_endpoint_.address().to_string();
        remote.port = remote_endpoint_.port();
        ucp::vector<uint8_t> datagram(receive_buffer_.begin(), receive_buffer_.begin() + bytesTransferred);
        RaiseOnDatagram(datagram, remote);
    }

    if (receive_running_ && socket_.is_open()) {
        if (error) {
            // Throttle re-arm on persistent errors (e.g. Windows
            // WSAECONNRESET storms): re-arming immediately spins the
            // io_context thread in a hot loop.
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (!receive_running_ || !socket_.is_open()) {
                return;
            }
        }
        socket_.async_receive_from(
            boost::asio::buffer(receive_buffer_.data(), receive_buffer_.size()), remote_endpoint_,
            [this](const boost::system::error_code& nextError, size_t nextBytes) noexcept { OnReceive(nextError, nextBytes); });
    }
}

/** @brief Synchronous UDP datagram send to the specified endpoint.
 *  Lazily creates a socket if one is not already bound.  Handles IPv4-mapped IPv6
 *  address translation for dual-stack sockets sending to IPv4 destinations.
 *  Silently drops fails (UDP semantics -- errors are undetectable at this layer).
 *  @param data    Raw bytes to send.
 *  @param remote  Destination endpoint (address + port). */
void UdpSocketTransport::Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept {
    if (data.empty() || remote.address.empty() || 0 == remote.port) {
        return;
    }
    // After Stop() the transport must not lazily recreate the socket + receive
    // thread (resource leak on concurrent Dispose + Send); mirrors C#'s
    // _disposed guard.  Start() clears the flag for legitimate restarts.
    if (stopped_.load(std::memory_order_relaxed)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!socket_.is_open()) {
            if (!CreateSocket(0)) {
                return;
            }
            StartReceiveLoop();
        }
    }

    boost::system::error_code ec;
    boost::asio::ip::address address = boost::asio::ip::make_address(remote.address, ec);
    if (ec) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!socket_.is_open()) {
            return;
        }
        boost::asio::ip::udp::endpoint destination(address, remote.port);
        // local_is_v6_ is cached at socket creation (no per-packet getsockname
        // syscall on the hot path); local_endpoint() is only queried when the
        // cache is stale (socket recreated).
        bool localV6 = local_is_v6_;
        if (!localV6 && socket_.is_open()) {
            boost::system::error_code localEc;
            boost::asio::ip::udp::endpoint localEndpoint = socket_.local_endpoint(localEc);
            if (!localEc && localEndpoint.protocol() == boost::asio::ip::udp::v6()) {
                localV6 = true;
            }
        }
        if (localV6 && address.is_v4()) {
            boost::asio::ip::address_v4::bytes_type v4Bytes = address.to_v4().to_bytes();
            boost::asio::ip::address_v6::bytes_type mappedBytes = {{0}};
            mappedBytes[10] = 0xff;
            mappedBytes[11] = 0xff;
            mappedBytes[12] = v4Bytes[0];
            mappedBytes[13] = v4Bytes[1];
            mappedBytes[14] = v4Bytes[2];
            mappedBytes[15] = v4Bytes[3];
            destination = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6(mappedBytes), remote.port);
        }
        socket_.send_to(boost::asio::buffer(data.data(), data.size()), destination, 0, ec);
        if (ec == boost::asio::error::would_block || ec == boost::asio::error::try_again) {
            return;
        }
    }
}

/** @brief Stops the receive loop, closes the socket, and joins the background thread.
 *  Idempotent.  Resets the io_context so the transport can be restarted. */
void UdpSocketTransport::Stop() noexcept {
    stopped_.store(true, std::memory_order_relaxed);
    receive_running_ = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        boost::system::error_code ec;
        socket_.close(ec);
    }
    if (receive_thread_.joinable()) {
        if (std::this_thread::get_id() == receive_thread_.get_id()) {
            receive_thread_.detach();
        } else {
            receive_thread_.join();
        }
    }
    io_context_.restart();
}

/** @brief Returns the locally bound endpoint (address and port) of the socket.
 *  @return Endpoint struct with the local address and port (may be empty if not bound). */
Endpoint UdpSocketTransport::LocalEndpoint() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return local_endpoint_;
}

} // namespace transport
} // namespace ucp
