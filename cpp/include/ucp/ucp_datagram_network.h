#pragma once

/** @file ucp_datagram_network.h
 *  @brief UDP-backed UcpNetwork implementation — mirrors C# Ucp.Transport.UdpNetwork.
 *
 *  UcpDatagramNetwork extends UcpNetwork with a non-blocking UDP socket.
 *  It implements Output() via sendto() and runs a dedicated receive loop
 *  thread that reads datagrams and feeds them to Input().  Supports
 *  binding to a specific local address and port, or to an ephemeral port.
 */

#include "ucp/ucp_network.h"
#include <cstdint>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>

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
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close
#endif

namespace ucp {

/** @brief Concrete UcpNetwork backed by a non-blocking UDP socket.
 *
 *  Creates a UDP socket, binds it to the specified address/port, and
 *  starts a background receive thread.  Outbound datagrams from PCBs
 *  are transmitted via sendto().  Inbound datagrams are read by the
 *  receive thread and routed to Input() for PCB demultiplexing.
 */
class UcpDatagramNetwork : public UcpNetwork {
public:
    UcpDatagramNetwork();
    /** @brief Construct and immediately start on the given port.
     *  @param port  UDP port to bind to. */
    explicit UcpDatagramNetwork(int port);

    /** @brief Construct with a configuration (not started).
     *  @param config  UcpConfiguration for the network. */
    explicit UcpDatagramNetwork(const UcpConfiguration& config);

    /** @brief Construct, configure, and start on a specific address and port.
     *  @param localAddress  IPv4 address string (e.g. "0.0.0.0").
     *  @param port          UDP port to bind to. */
    UcpDatagramNetwork(const std::string& localAddress, int port);

    /** @brief Construct with configuration, address, and port; start immediately.
     *  @param localAddress  IPv4 address string.
     *  @param port          UDP port.
     *  @param config        UcpConfiguration. */
    UcpDatagramNetwork(const std::string& localAddress, int port, const UcpConfiguration& config);

    ~UcpDatagramNetwork() override;

    /** @brief Transmit raw bytes via UDP to the given endpoint.  Implements UcpNetwork::Output.
     *  @param data    Byte buffer to transmit.
     *  @param length  Number of bytes.
     *  @param remote  Destination endpoint (address + port).
     *  @param sender  Source UcpObject (unused by UDP; included for interface conformance). */
    void Output(const uint8_t* data, size_t length, const Endpoint& remote,
                IUcpObject* sender) override;

    /** @brief Override: bind to the given port (default address "0.0.0.0").
     *  @param port  UDP port. */
    void Start(int port) override;

    /** @brief Bind to a specific address and port.
     *  @param localAddress  IPv4 address string.
     *  @param port          UDP port. */
    void Start(const std::string& localAddress, int port);

    /** @brief Stop the receive loop and close the UDP socket. */
    void Stop() override;

    /** @brief Return the locally bound endpoint.
     *  @return The local Endpoint (address + port) as reported by getsockname. */
    Endpoint GetLocalEndPoint() const override;

    /** @brief Release all resources: stop receive loop, close socket, call base Dispose. */
    void Dispose() override;

private:
    /** @brief Lazily create the UDP socket if not already bound (for ephemeral-port usage). */
    void EnsureSocket();

    /** @brief Launch the background receive thread. */
    void StartReceiveLoop();

    /** @brief Signal the receive thread to stop and join it. */
    void StopReceiveLoop();

    /** @brief Create and bind a non-blocking UDP socket.
     *  @param address  IPv4 address to bind to ("0.0.0.0" for any).
     *  @param port     UDP port to bind to (0 = OS-assigned ephemeral port). */
    void CreateSocket(const std::string& address, int port);

    mutable std::mutex mutex_;       //< Protects socket operations (creation, close, send).
    SOCKET socket_ = INVALID_SOCKET; //< The non-blocking UDP socket handle.
    std::thread recv_thread_;        //< Background thread for the receive loop.
    std::atomic<bool> recv_running_{false};  //< Flag signaling the receive thread to stop.
    std::atomic<bool> disposed_{false};      //< Whether Dispose has been called.
    Endpoint local_endpoint_;                 //< Cached local endpoint after bind.
};

} // namespace ucp
