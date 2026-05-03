#ifdef _WIN32                                                  //< Windows platform conditional compilation block
#define _WINSOCK_DEPRECATED_NO_WARNINGS                         //< Suppress warnings about deprecated Winsock APIs
#endif                                                          //< End Windows-specific preprocessor block

/** @file ucp_datagram_network.cpp
 *  @brief UDP-backed UcpNetwork implementation — mirrors C# Ucp.Transport.UdpNetwork.
 *
 *  Creates a non-blocking UDP socket, binds it to the specified local
 *  address and port, and starts a background receive thread.  On Windows,
 *  automatically initializes Winsock (WSAStartup).  Outbound sends use
 *  sendto(); inbound datagrams are read in a loop and routed to Input().
 */

#include "ucp/ucp_datagram_network.h"    //< Header declaring UcpDatagramNetwork class and its SOCKET/platform macros
#include "ucp/ucp_vector.h"             //< ucp::vector<T> and ucp::string type alias definitions
#include "ucp/ucp_memory.h"             //< ucp::Malloc / ucp::Mfree allocation helpers
#include <cstring>                        //< C string functions (memset, memcpy, etc.)
#include <chrono>                         //< High-resolution clock and duration for timing

#ifdef _WIN32                                                  //< Windows platform: include Winsock headers
#include <winsock2.h>                                           //< Windows sockets API — all networking functions
#include <ws2tcpip.h>                                           //< Additional Winsock extensions (inet_ntoa, etc.)
#pragma comment(lib, "ws2_32.lib")                             //< Auto-link against the Winsock library
#else                                                           //< POSIX/Linux platform
#include <sys/socket.h>                                         //< Sockets API: socket(), bind(), sendto(), recvfrom()
#include <netinet/in.h>                                         //< Internet address structures: sockaddr_in, INADDR_ANY
#include <arpa/inet.h>                                          //< Address conversion: inet_addr(), inet_ntoa(), htons()
#include <unistd.h>                                             //< POSIX API: close() for sockets
#include <fcntl.h>                                              //< File control: O_NONBLOCK for non-blocking socket mode
#endif                                                          //< End of platform-specific includes

namespace ucp {

// === Winsock initialization (Windows only) ===

static bool s_wsa_initialized = false;                           //< Guard flag: true after one-time WSAStartup call

static void EnsureWsaInit() {                                    //< Ensure Winsock DLL is loaded (Windows) or no-op (POSIX)
#ifdef _WIN32                                                    //< Windows-only initialization block
    if (!s_wsa_initialized) {                                    //< Check if already initialized (idempotent guard)
        WSADATA wsaData;                                         //< Structure to receive Winsock implementation details
        WSAStartup(MAKEWORD(2, 2), &wsaData);                   //< Request Winsock version 2.2 — required before socket calls
        s_wsa_initialized = true;                                //< Mark as initialized so we don't call WSAStartup again
    }
#endif                                                           //< End Windows block
}

// ====================================================================================================
// Construction
// ====================================================================================================

UcpDatagramNetwork::UcpDatagramNetwork()                        //< Default constructor: empty configuration
    : UcpNetwork(UcpConfiguration())                             //< Delegate to base with default configuration
{
    EnsureWsaInit();                                             //< Initialize Winsock on Windows before any socket use
}

UcpDatagramNetwork::UcpDatagramNetwork(int port)                 //< Port-only constructor: bind and start immediately
    : UcpNetwork(UcpConfiguration())                             //< Default configuration for base class
{
    EnsureWsaInit();                                             //< Platform-safe Winsock initialization
    Start(port);                                                 //< Delegate to Start(port) — creates socket and begins receive loop
}

UcpDatagramNetwork::UcpDatagramNetwork(const UcpConfiguration& config)  //< Config-only constructor (not started)
    : UcpNetwork(config)                                          //< Pass configuration through to base class
{
    EnsureWsaInit();                                              //< Ensure networking is ready for later Start() calls
}

UcpDatagramNetwork::UcpDatagramNetwork(const ucp::string& localAddress, int port)  //< Address+port constructor
    : UcpNetwork(UcpConfiguration())                               //< Default configuration for base class
{
    EnsureWsaInit();                                               //< Initialize Winsock before binding
    Start(localAddress, port);                                     //< Bind to specified address and port immediately
}

UcpDatagramNetwork::UcpDatagramNetwork(const ucp::string& localAddress, int port,  //< Full constructor: address+port+config
                                        const UcpConfiguration& config)
    : UcpNetwork(config)                                            //< Forward configuration to base class
{
    EnsureWsaInit();                                                //< Platform-safe networking initialization
    Start(localAddress, port);                                      //< Create socket, bind, and start receive loop
}

UcpDatagramNetwork::~UcpDatagramNetwork()                          //< Destructor: release all socket resources
{
    Dispose();                                                      //< Stop receive loop, close socket, release base class resources
}

// ====================================================================================================
// Socket creation
// ====================================================================================================

void UcpDatagramNetwork::CreateSocket(const ucp::string& address, int port) {  //< Create, configure, and bind a non-blocking UDP socket
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);         //< Create IPv4 UDP datagram socket
    if (socket_ == INVALID_SOCKET) return;                         //< Socket creation failed — abort (caller checks socket_)

#ifdef _WIN32                                                     //< Windows: set non-blocking mode via ioctlsocket
    u_long mode = 1;                                               //< Non-zero value enables non-blocking mode
    ioctlsocket(socket_, FIONBIO, &mode);                          //< FIONBIO ioctl toggles the socket's blocking state
#else                                                              //< POSIX: set non-blocking via fcntl flags
    fcntl(socket_, F_SETFL, O_NONBLOCK);                           //< Set O_NONBLOCK flag on the socket file descriptor
#endif                                                             //< End platform-specific non-blocking setup

    int reuse = 1;                                                  //< Boolean flag to enable SO_REUSEADDR
    ::setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR,                 //< Allow port reuse — prevents "address in use" after restart
#ifdef _WIN32                                                      //< Windows requires char* cast for setsockopt
                 reinterpret_cast<const char*>(&reuse),             //< Cast int* to const char* for Winsock API compatibility
#else                                                               //< POSIX expects const void*
                 &reuse,                                            //< Direct pointer pass on Linux/macOS
#endif                                                              //< End platform-specific setsockopt cast
                 sizeof(reuse));                                    //< Size of the option value (int = 4 bytes)

    sockaddr_in addr{};                                             //< Zero-initialize IPv4 socket address structure
    addr.sin_family = AF_INET;                                      //< IPv4 address family (AF_INET)
    addr.sin_port = htons(static_cast<uint16_t>(port));             //< Convert port to network byte order (big-endian)

    if (address.empty() || address == "0.0.0.0") {                  //< Empty or "any" address means bind to all interfaces
        addr.sin_addr.s_addr = INADDR_ANY;                          //< 0.0.0.0 — accept packets on any network interface
    } else {                                                        //< Specific address requested
        addr.sin_addr.s_addr = ::inet_addr(address.c_str());        //< Convert dotted-decimal string to 32-bit network address
    }

    if (::bind(socket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {  //< Bind socket to address:port
        closesocket(socket_);                                       //< Bind failed — close the socket handle
        socket_ = INVALID_SOCKET;                                   //< Mark socket as invalid so subsequent calls bail out
        return;                                                     //< Construction failed; caller checks socket_ == INVALID_SOCKET
    }

    sockaddr_in localAddr{};                                        //< Structure to receive the actual bound address
    socklen_t addrLen = sizeof(localAddr);                           //< Size of the sockaddr_in structure for getsockname
    ::getsockname(socket_, reinterpret_cast<sockaddr*>(&localAddr), &addrLen);  //< Query the socket's locally bound address
    local_endpoint_.address = ::inet_ntoa(localAddr.sin_addr);      //< Convert binary address to dotted-decimal string
    local_endpoint_.port = ntohs(localAddr.sin_port);              //< Convert port from network byte order to host byte order
}

void UcpDatagramNetwork::EnsureSocket() {                            //< Lazily create socket if not already bound
    std::lock_guard<std::mutex> lock(mutex_);                       //< Acquire mutex for thread-safe socket creation
    if (disposed_) return;                                          //< Network has been disposed — don't create anything
    if (socket_ == INVALID_SOCKET) {                                //< Socket not yet created (or was closed)
        CreateSocket("0.0.0.0", 0);                                 //< Bind to all interfaces on an OS-assigned ephemeral port
        StartReceiveLoop();                                         //< Launch the background receive thread
    }
}

// ====================================================================================================
// Start / Stop
// ====================================================================================================

void UcpDatagramNetwork::Start(int port) {                           //< Start listening on a specific port (default any address)
    Start("0.0.0.0", port);                                        //< Delegate to address+port overload with wildcard address
}

void UcpDatagramNetwork::Start(const ucp::string& localAddress, int port) {  //< Start on specific address and port
    std::lock_guard<std::mutex> lock(mutex_);                       //< Protect socket creation from concurrent access
    if (disposed_) return;                                          //< Already disposed — refuse to start
    if (socket_ != INVALID_SOCKET) return;                           //< Socket already bound — idempotent guard

    CreateSocket(localAddress, port);                                //< Create non-blocking UDP socket and bind it
    if (socket_ != INVALID_SOCKET) {                                //< Socket was created and bound successfully
        StartReceiveLoop();                                         //< Launch background thread for inbound packet reading
    }
}

// ====================================================================================================
// Receive loop (background thread)
// ====================================================================================================

void UcpDatagramNetwork::StartReceiveLoop() {                        //< Launch a dedicated thread to read UDP datagrams
    if (recv_running_.exchange(true)) return;                       //< Atomic exchange: set to true; if already true, return (idempotent)

    recv_thread_ = std::thread([this]() {                            //< Create a new thread running this lambda as the receive loop
        static constexpr size_t BUF_SIZE = 65536;                    //< Maximum UDP datagram size including headers (64 KiB)
        ucp::vector<uint8_t> buffer(BUF_SIZE);         //< Allocate receive buffer once (shared across all iterations)

        while (recv_running_) {                                      //< Loop until StopReceiveLoop() sets recv_running_ to false
            sockaddr_in remoteAddr{};                                //< Zero-initialize structure to receive sender's address
            socklen_t addrLen = sizeof(remoteAddr);                  //< Size of the address structure for recvfrom

            int recvLen = ::recvfrom(                                //< Read one UDP datagram from the socket
                socket_,                                             //< The non-blocking UDP socket handle
#ifdef _WIN32                                                       //< Windows: buffer type must be char*
                reinterpret_cast<char*>(buffer.data()),              //< Cast raw uint8_t buffer to char* for Winsock
#else                                                                //< POSIX: accepts void* buffer
                buffer.data(),                                       //< Direct pointer pass on Linux/macOS
#endif                                                               //< End platform-specific buffer cast
                static_cast<int>(BUF_SIZE),                           //< Maximum bytes to read (limited to buffer size)
                0,                                                    //< No special flags for recvfrom
                reinterpret_cast<sockaddr*>(&remoteAddr),             //< Output: sender's address will be filled in
                &addrLen);                                            //< Input/output: size of address structure

            if (recvLen > 0) {                                       //< Successfully received a datagram (>0 bytes)
                Endpoint remote;                                      //< Build endpoint for the sender
                remote.address = ::inet_ntoa(remoteAddr.sin_addr);   //< Convert sender's binary address to dotted-decimal string
                remote.port = ntohs(remoteAddr.sin_port);            //< Convert sender's port from network to host byte order

                Input(buffer.data(), static_cast<size_t>(recvLen), remote);  //< Route datagram to base class for PCB demultiplexing
            } else if (recvLen == 0) {                               //< recvfrom returned 0 — socket was cleanly closed by the OS
                break;                                                //< Exit receive loop gracefully
            } else {                                                 //< recvfrom returned SOCKET_ERROR (negative value)
#ifdef _WIN32                                                       //< Windows error handling
                int err = WSAGetLastError();                          //< Get the last Winsock error code
                if (err == WSAEWOULDBLOCK) {                          //< WSAEWOULDBLOCK means no data available on non-blocking socket
#else                                                                //< POSIX error handling
                if (errno == EAGAIN || errno == EWOULDBLOCK) {        //< EAGAIN/EWOULDBLOCK = would block (no data available)
#endif                                                               //< End platform error check
                    std::this_thread::sleep_for(std::chrono::microseconds(1000));  //< Sleep 1ms to avoid busy-wait spin
                    continue;                                         //< Loop back to retry recvfrom
                }
                if (!recv_running_) break;                           //< Stop signal received between recvfrom and error check
            }
        }
    });
}

void UcpDatagramNetwork::StopReceiveLoop() {                         //< Signal receive thread to stop and wait for it
    recv_running_ = false;                                          //< Atomic flag: tells the receive loop to exit
    if (recv_thread_.joinable()) {                                  //< The thread was started and hasn't been joined yet
        recv_thread_.join();                                        //< Block until the receive thread finishes its current iteration
    }
}

void UcpDatagramNetwork::Stop() {                                   //< Stop network transport: stop receive loop + close socket
    StopReceiveLoop();                                              //< Signal and wait for the receive thread to finish

    std::lock_guard<std::mutex> lock(mutex_);                       //< Acquire mutex for thread-safe socket close
    if (socket_ != INVALID_SOCKET) {                                //< A valid socket exists
        closesocket(socket_);                                       //< Close the UDP socket (platform macro: closesocket/close)
        socket_ = INVALID_SOCKET;                                   //< Mark socket handle as invalid for subsequent use checks
    }
}

// ====================================================================================================
// Output (send)
// ====================================================================================================

void UcpDatagramNetwork::Output(const uint8_t* data, size_t length,  //< Send raw bytes via UDP to the given remote endpoint
                                 const Endpoint& remote, IUcpObject* sender) {  //< sender parameter used for interface conformance (unused here)
    (void)sender;                                                    //< Suppress unused parameter warning
    if (!data || length == 0) return;                                //< Guard: null data or zero-length — nothing to send

    EnsureSocket();                                                  //< Lazily create socket if not already bound

    SOCKET s;                                                        //< Local copy of socket handle for lock-free send
    {
        std::lock_guard<std::mutex> lock(mutex_);                   //< Acquire mutex to safely read socket_ and disposed_ state
        if (disposed_ || socket_ == INVALID_SOCKET) return;          //< Network disposed or no socket — abort send
        s = socket_;                                                 //< Copy socket handle for use outside the lock
    }

    sockaddr_in addr{};                                              //< Build destination IPv4 socket address
    addr.sin_family = AF_INET;                                       //< IPv4 address family
    addr.sin_port = htons(remote.port);                              //< Convert destination port to network byte order
    addr.sin_addr.s_addr = ::inet_addr(remote.address.c_str());      //< Convert destination dotted-decimal string to 32-bit address

    ::sendto(s,                                                      //< Transmit datagram via the UDP socket
#ifdef _WIN32                                                        //< Windows requires const char* buffer type
             reinterpret_cast<const char*>(data),                    //< Cast const uint8_t* to const char* for Winsock
#else                                                                 //< POSIX accepts const void*
             data,                                                    //< Direct pointer pass on Linux/macOS
#endif                                                                //< End platform buffer cast
             static_cast<int>(length),                                //< Number of bytes to send (cast to int for API)
             0,                                                       //< No special send flags
             reinterpret_cast<sockaddr*>(&addr),                      //< Destination address structure
             sizeof(addr));                                           //< Size of the address structure
}

Endpoint UcpDatagramNetwork::GetLocalEndPoint() const {               //< Return the locally bound endpoint (address+port)
    return local_endpoint_;                                          //< Return cached value set during CreateSocket::getsockname
}

// ====================================================================================================
// Dispose
// ====================================================================================================

void UcpDatagramNetwork::Dispose() {                                 //< Release all resources: socket, thread, base timers
    {
        std::lock_guard<std::mutex> lock(mutex_);                    //< Acquire mutex to atomically check and set disposed_ flag
        if (disposed_.exchange(true)) return;                         //< Already disposed — idempotent guard via atomic exchange
    }

    StopReceiveLoop();                                               //< Signal receive thread to stop and join it
    UcpNetwork::Dispose();                                           //< Let base class clean up timers and PCB registrations

    {
        std::lock_guard<std::mutex> lock(mutex_);                    //< Re-acquire mutex for safe socket cleanup
        if (socket_ != INVALID_SOCKET) {                             //< Socket was created and hasn't been closed
            closesocket(socket_);                                     //< Close the UDP socket handle
            socket_ = INVALID_SOCKET;                                 //< Mark as invalid to prevent double-close
        }
    }
}

} // namespace ucp