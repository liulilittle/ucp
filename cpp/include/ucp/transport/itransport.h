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

/** @file itransport.h
 *  @brief Abstract datagram transport interface -- mirrors C# Ucp.Transport.ITransport.
 *
 *  Defines the base contract that all UCP transports must fulfill:
 *  Send() for outbound traffic and a multicast callback vector (on_datagram)
 *  for inbound datagrams.  The C# equivalent is Ucp.Transport.ITransport.
 *
 *  The on_datagram_ map supports multiple subscribers (multicast) which is
 *  required when a single transport is shared between a UcpServer and
 *  several UcpConnection instances inside a UcpNetwork.
 */

#include <cstdint>
#include <functional>
#include <mutex>
#include <atomic>
#include "ucp/ucp_vector.h"
#include "ucp/ucp_types.h"

namespace ucp {
namespace transport {

/** @brief Minimal datagram transport contract used by the UCP protocol engine.
 *
 *  Send() transmits outbound datagrams.  The on_datagram_ callback map is
 *  populated by protocol objects (UcpConnection, UcpServer) that need to
 *  receive inbound datagrams.  RaiseOnDatagram() iterates the map and invokes
 *  every subscriber -- this is the C++ equivalent of a C# multicast event. */
class ITransport {
  public:
    ITransport() noexcept = default;
    ITransport(const ITransport&) = delete;
    ITransport& operator=(const ITransport&) = delete;
    ITransport(ITransport&&) = delete;
    ITransport& operator=(ITransport&&) = delete;

    virtual ~ITransport() noexcept = default;

    using DatagramCallback = ucp::function<void(const ucp::vector<uint8_t>&, const Endpoint&)>;

    /** @brief Subscribe to inbound datagrams.
     *  @param  cb  Callback invoked for each received datagram.
     *  @return Opaque token used by RemoveOnDatagram to unsubscribe. */
    uint64_t AddOnDatagram(DatagramCallback cb) noexcept {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        uint64_t t = next_cb_token_++;
        cb_map_[t] = std::move(cb);
        return t;
    }

    /** @brief Unsubscribe from inbound datagrams.
     *  @param token  Token returned by a previous AddOnDatagram call. */
    void RemoveOnDatagram(uint64_t token) noexcept {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        cb_map_.erase(token);
    }

    /** @brief Send an encoded datagram to the given remote endpoint.
     *  @param data    Raw bytes to transmit.
     *  @param remote  Destination endpoint (address + port). */
    virtual void Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept = 0;

  protected:
    /** @brief Fire the on_datagram multicast to all subscribers.
     *  @param data    Raw bytes of the received datagram.
     *  @param remote  Source endpoint of the datagram.
     *
     *  Takes a snapshot of cb_map_ under lock and iterates outside the lock
     *  to prevent deadlocks when a subscriber mutates the map from within its
     *  callback. */
    void RaiseOnDatagram(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept {
        ucp::map<uint64_t, DatagramCallback> snapshot;
        {
            std::lock_guard<std::mutex> lock(cb_mutex_);
            snapshot = cb_map_;
        }
        for (auto& pair : snapshot) {
            if (pair.second) {
                try {
                    pair.second(data, remote);
                } catch (...) {
                }
            }
        }
    }

  private:
    ucp::map<uint64_t, DatagramCallback> cb_map_;
    mutable std::mutex cb_mutex_;
    std::atomic<uint64_t> next_cb_token_{1};
};

} // namespace transport
} // namespace ucp
