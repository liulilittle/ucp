#pragma once

/** @file ucp_datagram_network.h
 *  @brief UDP-backed UcpNetwork transport implementation — mirrors C# Ucp.UcpDatagramNetwork (Ucp.Transport.UdpNetwork).
 *
 *  UcpDatagramNetwork extends UcpNetwork with a non-blocking UDP socket.
 *  It implements Output() via sendto() and runs a dedicated receive loop
 *  thread that reads datagrams and feeds them to Input().  Supports
 *  binding to a specific local address and port, or to an ephemeral port.
 *
 *  This is the TRANSPORT LAYER — it uses raw BSD/Winsock socket APIs
 *  (sendto/recvfrom/bind) rather than ASIO/Boost.Asio.  The protocol
 *  stack base class UcpNetwork contains no socket code at all.
 */

#include "ucp/ucp_network.h" // Base event loop with timer heap, PCB registry, Input/Output interface (no socket code)
#include <cstdint>           // Fixed-width integers: uint8_t, uint16_t, size_t
#include <thread>            // std::thread for the background receive loop
#include <mutex>             // std::mutex for thread-safe socket lifecycle operations
#include <atomic>            // std::atomic<bool> for lock-free stop and disposed flags

#ifdef _WIN32
#include <winsock2.h>   // SOCKET, sockaddr_in, sendto, recvfrom, bind, closesocket for Windows UDP
#include <ws2tcpip.h>   // InetPton, inet_pton, getaddrinfo for address resolution on Windows
#pragma comment(lib, "ws2_32.lib") // Link against Winsock2 library on Windows
#else
#include <sys/socket.h>  // socket, sendto, recvfrom, bind, AF_INET, SOCK_DGRAM for POSIX UDP
#include <netinet/in.h>  // sockaddr_in, htons, INADDR_ANY for IPv4 addressing
#include <arpa/inet.h>   // inet_pton, inet_ntop for address string conversion
#include <unistd.h>      // close, fcntl for POSIX file descriptor operations
#include <fcntl.h>       // fcntl, O_NONBLOCK for setting socket to non-blocking mode
#define SOCKET int              // On POSIX, sockets are plain int file descriptors
#define INVALID_SOCKET (-1)     // Sentinel value for an invalid/uninitialized socket
#define SOCKET_ERROR (-1)       // Return value indicating a socket operation failed
#define closesocket close       // POSIX uses close() instead of closesocket()
#endif

namespace ucp {

/** @brief Concrete UcpNetwork backed by a non-blocking UDP socket.
 *
 *  Creates a UDP socket, binds it to the specified address/port, and
 *  starts a background receive thread.  Outbound datagrams from PCBs
 *  are transmitted via sendto().  Inbound datagrams are read by the
 *  receive thread and routed to Input() for PCB demultiplexing.
 *
 *  This class uses raw socket APIs — no ASIO/Boost.Asio dependency.
 */
class UcpDatagramNetwork : public UcpNetwork {
public:
    UcpDatagramNetwork(); // Default constructor: creates with default configuration, does NOT start the socket

    /** @brief Construct and immediately start on the given port (binds to 0.0.0.0).
     *  @param port  UDP port to bind to (0 = OS-assigned ephemeral port). */
    explicit UcpDatagramNetwork(int port); // Chains to string+port+config overload with default config, starts immediately

    /** @brief Construct with a configuration (not started).
     *  @param config  UcpConfiguration for the network (cloned internally). */
    explicit UcpDatagramNetwork(const UcpConfiguration& config); // Passes config to base class; socket is NOT created until Start()

    /** @brief Construct, configure, and start on a specific IPv4 address and port.
     *  @param localAddress  IPv4 address string (e.g. "0.0.0.0" for all interfaces, "127.0.0.1" for loopback).
     *  @param port          UDP port to bind to. */
    UcpDatagramNetwork(const ucp::string& localAddress, int port); // Uses default config, starts immediately on the given address:port

    /** @brief Construct with configuration, address, and port; start immediately.
     *  @param localAddress  IPv4 address string.
     *  @param port          UDP port.
     *  @param config        UcpConfiguration (cloned internally). */
    UcpDatagramNetwork(const ucp::string& localAddress, int port, const UcpConfiguration& config); // Full control: custom config + specific bind address

    ~UcpDatagramNetwork() override; // Stops the receive loop, closes the UDP socket, joins the receive thread

    /** @brief Transmit raw bytes via UDP sendto() to the given endpoint.  Implements UcpNetwork::Output.
     *  @param data    Byte buffer to transmit.
     *  @param length  Number of bytes in the buffer.
     *  @param remote  Destination endpoint (IPv4 address string + port).
     *  @param sender  Source UcpObject (unused by raw UDP; included for interface conformance). */
    void Output(const uint8_t* data, size_t length, const Endpoint& remote,
                IUcpObject* sender) override; // Calls sendto() on the non-blocking UDP socket; lazy-starts if not bound

    /** @brief Override: bind to the given port on 0.0.0.0 (all interfaces).
     *  @param port  UDP port to bind to. */
    void Start(int port) override; // Delegates to Start("0.0.0.0", port) for the actual socket creation

    /** @brief Bind to a specific IPv4 address and port, then start the receive loop.
     *  @param localAddress  IPv4 address string (e.g. "0.0.0.0", "127.0.0.1").
     *  @param port          UDP port to bind to. */
    void Start(const ucp::string& localAddress, int port); // Creates the non-blocking socket, binds it, launches the background receive thread

    /** @brief Stop the receive loop and close the UDP socket. */
    void Stop() override; // Signals the receive thread to exit via recv_running_ flag, joins the thread, closes the socket

    /** @brief Return the locally bound endpoint.
     *  @return The local Endpoint (address + port) as reported by getsockname after bind. */
    Endpoint GetLocalEndPoint() const override; // Returns cached local_endpoint_ populated during CreateSocket

    /** @brief Release all resources: stop receive loop, close socket, call base Dispose which clears timers. */
    void Dispose() override; // Sets disposed_ flag, then calls base::Dispose() which calls Stop() and clears timer heap

private:
    /** @brief Lazily create the UDP socket if not already bound (for ephemeral-port usage in Output). */
    void EnsureSocket(); // Called by Output() if socket_ == INVALID_SOCKET — creates and binds to port 0 (OS-assigned ephemeral)

    /** @brief Launch the background receive thread that runs the receive loop. */
    void StartReceiveLoop(); // Sets recv_running_ = true, spawns recv_thread_ with the receive-loop function

    /** @brief Signal the receive thread to stop and join it. */
    void StopReceiveLoop(); // Sets recv_running_ = false, joins recv_thread_ (blocks until thread exits)

    /** @brief Create and bind a non-blocking UDP socket.
     *  @param address  IPv4 address string to bind to ("0.0.0.0" for any interface).
     *  @param port     UDP port to bind to (0 = OS-assigned ephemeral port). */
    void CreateSocket(const ucp::string& address, int port); // Calls socket(), sets O_NONBLOCK / FIONBIO, calls bind(), stores local endpoint

    mutable std::mutex mutex_;                // Protects all socket lifecycle operations: create, send, close, and state flags
    SOCKET socket_ = INVALID_SOCKET;          // The non-blocking UDP socket handle (INVALID_SOCKET = not yet created or already closed)
    std::thread recv_thread_;                 // Background thread that runs the blocking recvfrom loop and injects datagrams via Input()
    std::atomic<bool> recv_running_{false};   // Atomic flag signaling the receive thread to exit its loop (set to false in StopReceiveLoop)
    std::atomic<bool> disposed_{false};       // Atomic flag indicating Dispose() has been called (prevents use-after-free)
    Endpoint local_endpoint_;                 // Cached local endpoint (address + port) populated by getsockname after bind
};

} // namespace ucp
