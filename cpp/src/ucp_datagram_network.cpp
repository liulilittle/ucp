#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

/** @file ucp_datagram_network.cpp
 *  @brief UDP-backed UcpNetwork implementation — mirrors C# Ucp.Transport.UdpNetwork.
 *
 *  Creates a non-blocking UDP socket, binds it to the specified local
 *  address and port, and starts a background receive thread.  On Windows,
 *  automatically initializes Winsock (WSAStartup).  Outbound sends use
 *  sendto(); inbound datagrams are read in a loop and routed to Input().
 */

#include "ucp/ucp_datagram_network.h"
#include <cstring>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace ucp {

// === Winsock initialization (Windows only) ===

static bool s_wsa_initialized = false;  //< Guard for one-time WSAStartup.

static void EnsureWsaInit() {
#ifdef _WIN32
    if (!s_wsa_initialized) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        s_wsa_initialized = true;
    }
#endif
}

// ====================================================================================================
// Construction
// ====================================================================================================

UcpDatagramNetwork::UcpDatagramNetwork()
    : UcpNetwork(UcpConfiguration())
{
    EnsureWsaInit();
}

UcpDatagramNetwork::UcpDatagramNetwork(int port)
    : UcpNetwork(UcpConfiguration())
{
    EnsureWsaInit();
    Start(port);
}

UcpDatagramNetwork::UcpDatagramNetwork(const UcpConfiguration& config)
    : UcpNetwork(config)
{
    EnsureWsaInit();
}

UcpDatagramNetwork::UcpDatagramNetwork(const std::string& localAddress, int port)
    : UcpNetwork(UcpConfiguration())
{
    EnsureWsaInit();
    Start(localAddress, port);
}

UcpDatagramNetwork::UcpDatagramNetwork(const std::string& localAddress, int port,
                                        const UcpConfiguration& config)
    : UcpNetwork(config)
{
    EnsureWsaInit();
    Start(localAddress, port);
}

UcpDatagramNetwork::~UcpDatagramNetwork()
{
    Dispose();
}

// ====================================================================================================
// Socket creation
// ====================================================================================================

void UcpDatagramNetwork::CreateSocket(const std::string& address, int port)
{
    // === Create UDP socket ===
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == INVALID_SOCKET) return;

    // === Set non-blocking mode ===
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(socket_, FIONBIO, &mode);
#else
    fcntl(socket_, F_SETFL, O_NONBLOCK);
#endif

    // === Enable address reuse ===
    int reuse = 1;
    ::setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR,
#ifdef _WIN32
                 reinterpret_cast<const char*>(&reuse),
#else
                 &reuse,
#endif
                 sizeof(reuse));

    // === Bind to address and port ===
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (address.empty() || address == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;  //< Bind to all interfaces.
    } else {
        addr.sin_addr.s_addr = ::inet_addr(address.c_str());
    }

    if (::bind(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        return;
    }

    // === Retrieve the actual bound endpoint (port may be ephemeral) ===
    sockaddr_in localAddr{};
    socklen_t addrLen = sizeof(localAddr);
    ::getsockname(socket_, reinterpret_cast<sockaddr*>(&localAddr), &addrLen);
    local_endpoint_.address = ::inet_ntoa(localAddr.sin_addr);
    local_endpoint_.port = ntohs(localAddr.sin_port);
}

void UcpDatagramNetwork::EnsureSocket()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (disposed_) return;
    if (socket_ == INVALID_SOCKET) {
        CreateSocket("0.0.0.0", 0);  //< Ephemeral port on all interfaces.
        StartReceiveLoop();
    }
}

// ====================================================================================================
// Start / Stop
// ====================================================================================================

void UcpDatagramNetwork::Start(int port)
{
    Start("0.0.0.0", port);
}

void UcpDatagramNetwork::Start(const std::string& localAddress, int port)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (disposed_) return;
    if (socket_ != INVALID_SOCKET) return;  //< Already bound.

    CreateSocket(localAddress, port);
    if (socket_ != INVALID_SOCKET) {
        StartReceiveLoop();
    }
}

// ====================================================================================================
// Receive loop (background thread)
// ====================================================================================================

void UcpDatagramNetwork::StartReceiveLoop()
{
    if (recv_running_.exchange(true)) return;  //< Idempotent: only one receive loop.

    recv_thread_ = std::thread([this]() {
        static constexpr size_t BUF_SIZE = 65536;  //< Maximum UDP datagram size (64 KiB).
        auto buffer = std::make_unique<uint8_t[]>(BUF_SIZE);

        while (recv_running_) {
            sockaddr_in remoteAddr{};
            socklen_t addrLen = sizeof(remoteAddr);

            int recvLen = ::recvfrom(
                socket_,
#ifdef _WIN32
                reinterpret_cast<char*>(buffer.get()),
#else
                buffer.get(),
#endif
                static_cast<int>(BUF_SIZE),
                0,
                reinterpret_cast<sockaddr*>(&remoteAddr),
                &addrLen);

            if (recvLen > 0) {
                // === Extract remote endpoint from sockaddr_in ===
                Endpoint remote;
                remote.address = ::inet_ntoa(remoteAddr.sin_addr);
                remote.port = ntohs(remoteAddr.sin_port);

                // === Route to Input() for PCB demultiplexing ===
                Input(buffer.get(), static_cast<size_t>(recvLen), remote);
            } else if (recvLen == 0) {
                break;  //< Socket closed by OS.
            } else {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
#endif
                    // Non-blocking socket with no data — short sleep to avoid busy-wait
                    std::this_thread::sleep_for(std::chrono::microseconds(1000));
                    continue;
                }
                if (!recv_running_) break;
            }
        }
    });
}

void UcpDatagramNetwork::StopReceiveLoop()
{
    recv_running_ = false;
    if (recv_thread_.joinable()) {
        recv_thread_.join();
    }
}

void UcpDatagramNetwork::Stop()
{
    StopReceiveLoop();

    std::lock_guard<std::mutex> lock(mutex_);
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
}

// ====================================================================================================
// Output (send)
// ====================================================================================================

void UcpDatagramNetwork::Output(const uint8_t* data, size_t length,
                                 const Endpoint& remote, IUcpObject* /*sender*/)
{
    if (!data || length == 0) return;

    EnsureSocket();

    SOCKET s;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (disposed_ || socket_ == INVALID_SOCKET) return;
        s = socket_;
    }

    // === Build sockaddr_in for the remote endpoint ===
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(remote.port);
    addr.sin_addr.s_addr = ::inet_addr(remote.address.c_str());

    ::sendto(s,
#ifdef _WIN32
             reinterpret_cast<const char*>(data),
#else
             data,
#endif
             static_cast<int>(length),
             0,
             reinterpret_cast<sockaddr*>(&addr),
             sizeof(addr));
}

Endpoint UcpDatagramNetwork::GetLocalEndPoint() const
{
    return local_endpoint_;
}

// ====================================================================================================
// Dispose
// ====================================================================================================

void UcpDatagramNetwork::Dispose()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (disposed_.exchange(true)) return;
    }

    StopReceiveLoop();
    UcpNetwork::Dispose();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }
}

} // namespace ucp
