#pragma once

/** @file itransport.h
 *  @brief Abstract transport interface for UCP — mirrors C# Ucp.Transport.ITransport.
 *
 *  Defines the base contract that all UCP transports must fulfill.  UCP is
 *  transport-agnostic:  the protocol engine sends and receives opaque datagrams
 *  through this interface, which can be backed by UDP, sockets, or a custom
 *  test harness.
 *
 *  The C# equivalent is <c>Ucp.Transport.ITransport</c> — a simple Send + callback
 *  contract that keeps the UCP stack decoupled from any particular socket layer.
 */

#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace ucp {
namespace transport {

/** @brief Minimal datagram transport contract used by the UCP protocol engine. */
class ITransport {
public:
    virtual ~ITransport() = default;

    /** @brief Send an opaque datagram to the given remote endpoint.
     *  @param data       Raw byte buffer to transmit.
     *  @param remote_endpoint  String representation of the remote peer (e.g. "127.0.0.1:9000").
     */
    virtual void Send(const std::vector<uint8_t>& data, const std::string& remote_endpoint) = 0;

    /** @brief Callback invoked when a datagram arrives from the network.
     *  @param first  Raw bytes of the received datagram.
     *  @param second Remote endpoint string that sent the datagram.
     */
    std::function<void(std::vector<uint8_t>, std::string)> on_datagram;
};

} // namespace transport
} // namespace ucp
