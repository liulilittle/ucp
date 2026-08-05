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

/** @file ucp_server.h
 *  @brief UCP server listener -- mirrors C# Ucp.UcpServer.
 *
 *  UcpServer listens for incoming UCP SYN packets and creates UcpConnection
 *  objects for each accepted connection.  It supports fair-queue bandwidth
 *  scheduling among active connections when running inside a UcpNetwork,
 *  distributing the server's total bandwidth budget in proportion to each
 *  connection's UCP pacing rate.
 *
 *  AcceptAsync() uses a callback-based pattern -- no thread is spawned per
 *  call and no promise/future is allocated.  The callback is invoked when a
 *  connection handshake completes, or immediately with UcpError::ShuttingDown
 *  if the server is already stopped.
 *
 *  The server subscribes to the transport's on_datagram multicast to receive
 *  incoming SYN packets.  In standalone mode, a periodic timer thread drives
 *  fair-queue rounds.  In network-managed mode, fair-queue rounds are
 *  scheduled via UcpNetwork::AddTimer. */

#include "ucp_types.h"
#include "ucp_configuration.h"
#include "ucp_constants.h"
#include "ucp_enums.h"
#include "ucp/transport/itransport.h"
#include "ucp/transport/ibindable_transport.h"
#include "ucp/ucp_network.h"
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>

namespace ucp {

class UcpConnection;
class UcpPcb;
class UcpPacket;

/** @brief Server that listens for incoming UCP connections and returns them via AcceptAsync.
 *
 *  The server can operate in standalone mode (owning its own transport and
 *  scheduling fair-queue via a background timer thread) or within a UcpNetwork
 *  (delegating transport and scheduling to the network's DoEvents loop).
 *
 *  AcceptAsync accepts a callback that is invoked when a new connection is
 *  ready.  If a connection is already queued the callback fires immediately
 *  (synchronously).  If no connection is ready the callback is queued and
 *  will be invoked later from the connection-handshake completion path.
 *  The callback is invoked with a UcpError::ShuttingDown and a NULLPTR
 *  connection if the server stops before a connection arrives. */
class UcpServer : public IUcpObject {
  public:
    /** @brief Maximum live connection entries (SYN-flood guard).
     *  Each entry owns a UcpPcb that spawns worker+notify+standalone-timer
     *  threads, so an unbounded flood of SYN packets with distinct CIDs could
     *  exhaust threads/memory. New SYNs are dropped once this cap is reached. */
    static constexpr size_t kMaxServerConnections = 1024;

    UcpServer() noexcept;

    /** @brief Construct with explicit configuration.
     *  @param config  UcpConfiguration to clone. */
    explicit UcpServer(const UcpConfiguration& config) noexcept;

    /** @brief Internal constructor: wrap transport with ownership and config.
     *  @param transport      Existing transport instance.
     *  @param ownsTransport   True to take ownership.
     *  @param config          Server configuration.
     *  @param network         Owning UcpNetwork (NULLPTR for standalone). */
    UcpServer(transport::ITransport* transport, bool ownsTransport, const UcpConfiguration& config, UcpNetwork* network = NULLPTR) noexcept;

    ~UcpServer() noexcept;

    UcpServer(const UcpServer&) = delete;
    UcpServer& operator=(const UcpServer&) = delete;
    UcpServer(UcpServer&&) = delete;
    UcpServer& operator=(UcpServer&&) = delete;

    /** @brief Start listening on the given port (standalone mode).
     *  @param port  UDP port to bind. */
    void Start(int port) noexcept;

    /** @brief Start listening within an existing UcpNetwork (multiplexed mode).
     *  @param network  Owning UcpNetwork.
     *  @param port     UDP port.
     *  @param config   Server configuration. */
    void Start(UcpNetwork* network, int port, const UcpConfiguration& config) noexcept;

    /** @brief Asynchronously accept the next incoming connection.
     *
     *  If a connection is already waiting in the accept queue, the callback is
     *  invoked immediately (synchronously) with the connection.  Otherwise the
     *  callback is queued and will be invoked when a connection handshake
     *  completes or the server stops.
     *
     *  If the server is already stopped or stops before the callback fires,
     *  the callback is invoked with UcpError::ShuttingDown and a NULLPTR
     *  connection.
     *
     *  The server retains ownership of the returned UcpConnection: the caller
     *  receives a non-owning pointer that remains valid until the connection
     *  is closed or the server is stopped.  The caller must NOT delete or wrap
     *  the pointer in a unique_ptr (the server owns it and releases it on
     *  close / server shutdown).
     *
     *  @param callback  Callback receiving error code and the accepted connection
     *                   (or NULLPTR on shutdown). */
    void AcceptAsync(AcceptAsyncCallback callback) noexcept;

    /** @brief Stop listening and close all active connections.
     *
     *  Drains the accept queue, invokes all pending AcceptAsync callbacks with
     *  UcpError::ShuttingDown, disposes all PCB instances, and releases all
     *  connection entries.  Idempotent -- safe to call multiple times. */
    void Stop() noexcept;

    void Dispose() noexcept;

    /** @brief Return connection ID (always 0 for server).
     *  @return 0. */
    uint32_t GetConnectionId() const noexcept override { return 0; }
    /** @brief Return the owning UcpNetwork.
     *  @return Network pointer, NULLPTR if standalone. */
    UcpNetwork* GetNetwork() const noexcept override { return network_; }

  public:
    /** @brief Per-connection server bookkeeping (created for each accepted SYN,
     *  removed on close).  Made public so the deferred-destruction helper in
     *  ucp_server.cpp can hold the shared_ptr while it reaps the connection on
     *  a background thread (never a PCB/connection worker thread). */
    struct ConnectionEntry {
        ucp::shared_ptr<UcpConnection> connection;
        ucp::shared_ptr<UcpConnection> acceptedConnection;
        UcpPcb* pcb = NULLPTR;
        bool accepted = false;
    };

  private:

    /** @brief Removes a closing PCB from the server maps and returns the entry
     *  for deferred destruction.  The entry (and its UcpConnection) is always
     *  handed to the deferred-cleanup thread so it is destroyed off any
     *  PCB/connection worker thread.
     *  @param  pcb  Closing PCB.
     *  @return Detached server-owned entry (possibly empty). */
    ucp::shared_ptr<ConnectionEntry> DetachClosedEntry(UcpPcb* pcb) noexcept;

    /** @brief Transport datagram callback: decode, find/create connection, dispatch.
     *  @param datagram  Received bytes.
     *  @param remote    Source endpoint. */
    void OnTransportDatagram(const ucp::vector<uint8_t>& datagram, const Endpoint& remote) noexcept;

    /** @brief Find existing or create new connection entry from a decoded packet.
     *  @param  remote  Source endpoint.
     *  @param  packet  Decoded packet.
     *  @return Connection entry pointer. */
    ucp::shared_ptr<ConnectionEntry> GetOrCreateConnection(const Endpoint& remote, const UcpPacket& packet) noexcept;

    /** @brief Called when a PCB handshake completes -- enqueue for accept.
     *  @param entry  Connection entry whose PCB is now established. */
    void OnPcbConnected(ConnectionEntry* entry) noexcept;

    /** @brief Called when a PCB closes -- remove from connections map.
     *  @param pcb  PCB that closed. */
    void OnPcbClosed(UcpPcb* pcb) noexcept;

    void ScheduleFairQueueRound() noexcept;

    void OnFairQueueRound() noexcept;

    void OnFairQueueRoundCore() noexcept;

    mutable std::mutex mutex_;
    bool started_ = false;
    UcpConfiguration config_;
    UcpNetwork* network_ = NULLPTR;
    bool owns_transport_ = true;
    int bandwidth_limit_bytes_per_sec_ = Constants::DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

    transport::ITransport* transport_ = NULLPTR;
    transport::IBindableTransport* bindable_transport_ = NULLPTR;
    ucp::shared_ptr<transport::ITransport> owned_transport_holder_;
    uint64_t transport_token_ = 0;

    ucp::map<uint32_t, ucp::shared_ptr<ConnectionEntry>> connections_;

    /** @name Accept synchronization
     *  AcceptAsync stores a callback in accept_callbacks_ if no connection
     *  is ready.  OnPcbConnected pops a pending callback or queues the
     *  connection in accept_queue_.  Stop() drains any remaining callbacks
     *  with UcpError::ShuttingDown.  This mirrors C# SemaphoreSlim semantics
     *  using callbacks instead of promises. */
    std::mutex accept_mutex_;
    ucp::queue<ucp::shared_ptr<UcpConnection>> accept_queue_;
    ucp::queue<AcceptAsyncCallback> accept_callbacks_;

    int fair_queue_start_index_ = 0;
    int64_t last_fair_queue_round_micros_ = 0;
    uint32_t fair_queue_timer_id_ = 0;

    std::thread fair_queue_timer_thread_;
    std::atomic<bool> fair_queue_timer_running_{false};
    std::mutex m_fairQueueTimerMutex;
    std::condition_variable m_fairQueueTimerCv;

    std::atomic<bool> stopped_{false};
};

} // namespace ucp
