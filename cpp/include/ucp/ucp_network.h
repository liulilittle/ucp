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

/** @file ucp_network.h
 *  @brief Central network event loop and PCB manager -- mirrors C# Ucp.UcpNetwork.
 *
 *  UcpNetwork serves as the central event loop for a set of UCP protocol
 *  control blocks (UcpPcb instances).  It manages:
 *  - A timer heap for scheduling callbacks with microsecond resolution.
 *  - A registry of active PCBs (by pointer and by connection ID).
 *  - A cached monotonic clock (updated on each DoEvents tick).
 *  - Input demultiplexing (routing incoming datagrams to the correct PCB).
 *  - Virtual Output method that subclasses (e.g. UcpDatagramNetwork) implement.
 *  - A NetworkTransportAdapter that bridges the network with the transport
 *    abstraction, enabling UcpServer/UcpConnection to share the same I/O path.
 *
 *  MeasuredThroughputBytesPerSecond is added to UcpTransferReport and
 *  UcpConnectionDiagnostics so that true measured throughput (not UCP
 *  BtlBw x pacingGain) is available for bandwidth display.
 */

#include "ucp_configuration.h"
#include "ucp_types.h"
#include "ucp/transport/ibindable_transport.h"
#include <cstdint>
#include <functional>
#include <mutex>
#include <chrono>

namespace ucp {

class UcpPcb;
class UcpServer;
class UcpConnection;

class IUcpObject {
  public:
    virtual ~IUcpObject() noexcept = default;

    /** @brief Return the connection ID associated with this object (0 if not applicable).
     *  @return Connection ID. */
    virtual uint32_t GetConnectionId() const noexcept = 0;

    /** @brief Return the UcpNetwork that manages this object (NULLPTR if standalone).
     *  @return Network pointer. */
    virtual class UcpNetwork* GetNetwork() const noexcept = 0;
};

/** @brief Central network event loop with timer management, PCB registry,
 *         and a NetworkTransportAdapter that bridges this network with the
 *         higher-level UcpServer and UcpConnection factories.
 *
 *  Call DoEvents() in a loop to advance all managed PCBs.  Input() injects
 *  received datagrams.  Output() is pure-virtual -- derived classes implement
 *  the actual socket send. */
class UcpNetwork {
  public:
    UcpNetwork(const UcpNetwork&) = delete;
    UcpNetwork& operator=(const UcpNetwork&) = delete;
    UcpNetwork(UcpNetwork&&) = delete;
    UcpNetwork& operator=(UcpNetwork&&) = delete;

    /** @brief Construct with explicit configuration.
     *  @param config  UcpConfiguration to clone. */
    explicit UcpNetwork(const UcpConfiguration& config) noexcept;

    UcpNetwork() noexcept;

    virtual ~UcpNetwork() noexcept;

    UcpConfiguration& GetConfiguration() noexcept { return config_; }

    const UcpConfiguration& GetConfiguration() const noexcept { return config_; }

    /** @brief Drive one event-loop iteration: fire expired timers, tick all PCBs.
     *  @return Number of work items processed (callbacks + PCB ticks). */
    virtual int DoEvents() noexcept;

    /** @brief Accept an inbound datagram, decode it, and route to the correct PCB.
     *         Falls back to the transport adapter for SYN packets.
     *  @param data    Raw bytes.
     *  @param length  Byte count.
     *  @param remote  Source endpoint. */
    void Input(const uint8_t* data, size_t length, const Endpoint& remote) noexcept;

    /** @brief Start the network on the given port.
     *  @param port  UDP port to bind. */
    virtual void Start(int port) noexcept;

    virtual void Stop() noexcept;

    /** @brief Send a datagram through the network transport (pure virtual).
     *  @param data    Raw bytes.
     *  @param length  Byte count.
     *  @param remote  Destination endpoint.
     *  @param sender  Source UcpObject (for tracing / access control). */
    virtual void Output(const uint8_t* data, size_t length, const Endpoint& remote, IUcpObject* sender) noexcept = 0;

    /** @brief Send overload without sender context.
     *  @param data    Raw bytes.
     *  @param length  Byte count.
     *  @param remote  Destination endpoint. */
    void Output(const uint8_t* data, size_t length, const Endpoint& remote) noexcept;

    /** @brief Add a timer that fires at the given microsecond timestamp.
     *  @param  expireUs  Expiration timestamp in microseconds.
     *  @param  callback  Callback to invoke on expiry.
     *  @return Timer ID for cancellation. */
    uint32_t AddTimer(int64_t expireUs, ucp::function<void()> callback) noexcept;

    /** @brief Cancel a previously added timer.
     *  @param  timerId  Timer ID from AddTimer.
     *  @return True if the timer was found and cancelled. */
    bool CancelTimer(uint32_t timerId) noexcept;

    /** @brief Factory: create a UcpServer bound to this network's transport adapter.
     *  @param  port  Port to bind.
     *  @return Shared pointer to a new UcpServer. */
    ucp::shared_ptr<UcpServer> CreateServer(int port) noexcept;

    /** @brief Factory: create a UcpConnection using this network's transport adapter.
     *  @return Shared pointer to a new UcpConnection. */
    ucp::shared_ptr<UcpConnection> CreateConnection() noexcept;
    /** @brief Factory: create a UcpConnection with explicit configuration.
     *  @param  config  Connection configuration.
     *  @return Shared pointer to a new UcpConnection. */
    ucp::shared_ptr<UcpConnection> CreateConnection(const UcpConfiguration& config) noexcept;

    /** @brief Returns the current cached time in microseconds.
     *  @return Cached microsecond timestamp. */
    int64_t GetNowMicroseconds() const noexcept;
    /** @brief Returns the current time in microseconds.
     *  @return Microsecond timestamp. */
    int64_t GetCurrentTimeUs() const noexcept;

    /** @brief Returns the local endpoint.
     *  @return Endpoint (default if not bound). */
    virtual Endpoint GetLocalEndpoint() const noexcept { return Endpoint(); }

    virtual void Dispose() noexcept;

    /** @brief Expose the shared transport adapter (IBindableTransport reference).
     *         UcpServer and UcpConnection factories pass this to their constructors.
     *  @return Transport adapter pointer. */
    transport::IBindableTransport* GetTransportAdapter() const noexcept { return transport_adapter_.get(); }

    UcpConfiguration& GetConfig() noexcept { return config_; }

  protected:
    void UpdateCachedClock() noexcept;

    /** @brief Read the raw stopwatch in microseconds.
     *  @return Microsecond timestamp. */
    int64_t ReadStopwatchMicros() const noexcept;

    void YieldWhenIdle() noexcept;

    std::atomic<int> idle_consecutive_{0};

    UcpConfiguration config_;

  private:
    struct TimerEntry {
        uint32_t id;
        int64_t expireUs;
        ucp::function<void()> callback;
        ucp::function<void()> wrappedCallback;
    };

    /** @brief Inner class that bridges UcpNetwork as an IBindableTransport for
     *         UcpServer and UcpConnection.
     *
     *  Implements IBindableTransport (Send -> network.Output, Start/Stop -> network.Start/Stop)
     *  and IUcpObject (ConnectionId=0, Network=this).  The Raise() method fires the
     *  inherited on_datagram multicast, which is how Input() relays SYN packets
     *  to server/connection subscribers. */
    struct NetworkTransportAdapter : public transport::IBindableTransport, public IUcpObject {
        UcpNetwork* network_;

        /** @brief Construct with owning network.
         *  @param net  Owning UcpNetwork. */
        explicit NetworkTransportAdapter(UcpNetwork* net) noexcept : network_(net) {}

        void Start(int port) noexcept override { network_->Start(port); }

        void Stop() noexcept override { network_->Stop(); }

        Endpoint LocalEndpoint() noexcept override { return network_->GetLocalEndpoint(); }

        void Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept override {
            network_->Output(data.data(), data.size(), remote, this);
        }

        uint32_t GetConnectionId() const noexcept override { return 0; }

        UcpNetwork* GetNetwork() const noexcept override { return network_; }

        /** @brief Raise the multicast on_datagram event (called by Input fallback).
         *  @param data    Datagram bytes.
         *  @param remote  Source endpoint. */
        void Raise(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept { RaiseOnDatagram(data, remote); }
    };

  public:
    /** @brief Register a PCB with the network.
     *  @param pcb  Shared pointer to PCB to register (keeps PCB alive during network dispatch). */
    void RegisterPcb(const ucp::shared_ptr<UcpPcb>& pcb) noexcept;
    /** @brief Unregister a PCB from the network.
     *  @param pcb  PCB to unregister. */
    void UnregisterPcb(UcpPcb* pcb) noexcept;
    /** @brief Update a PCB's connection ID mapping.
     *  @param pcb    PCB whose ID changed.
     *  @param oldId  Previous connection ID.
     *  @param newId  New connection ID. */
    void UpdatePcbConnectionId(UcpPcb* pcb, uint32_t oldId, uint32_t newId) noexcept;
    /** @brief Register a PCB by session key for reconnection detection.
     *  @param sessionKey  Session key.
     *  @param pcb         PCB to register. */
    void RegisterSessionKey(uint64_t sessionKey, UcpPcb* pcb) noexcept;
    /** @brief Atomically register a session key if not already taken by an active PCB.
     *  Combines LookupBySessionKey + RegisterSessionKey under a single lock to prevent
     *  TOCTOU races between separate calls.
     *  @param sessionKey  Session key.
     *  @param pcb         PCB to register.
     *  @return Existing active PCB if key was already taken, or nullptr on successful registration. */
    ucp::shared_ptr<UcpPcb> TryRegisterSessionKey(uint64_t sessionKey, UcpPcb* pcb) noexcept;
    /** @brief Unregister a session key from the registry.
     *  @param sessionKey  Session key to remove. */
    void UnregisterSessionKey(uint64_t sessionKey) noexcept;
    /** @brief Look up a PCB by session key.
     *  @param  sessionKey  Session key.
     *  @return PCB pointer or NULLPTR if not found. */
    ucp::shared_ptr<UcpPcb> LookupBySessionKey(uint64_t sessionKey) noexcept;
    /** @brief Look up a PCB by connection ID.
     *  @param  connectionId  Connection ID.
     *  @return PCB pointer or NULLPTR if not found. */
    ucp::shared_ptr<UcpPcb> LookupByConnectionId(uint32_t connectionId) noexcept;
    /** @brief Take a snapshot of all active PCBs.
     *  @return Vector of shared_ptrs (keeps PCBs alive during iteration). */
    ucp::vector<ucp::shared_ptr<UcpPcb>> SnapshotPcbs() noexcept;

  private:
    mutable std::mutex timer_mutex_;

    struct TimerHeapEntry {
        uint32_t id;
        ucp::function<void()> callback;
    };
    ucp::multimap<int64_t, TimerHeapEntry> timer_heap_;
    ucp::map<uint32_t, ucp::shared_ptr<TimerEntry>> active_timers_;
    std::atomic<uint32_t> next_timer_id_ = 1;

    mutable std::mutex pcb_mutex_;
    ucp::vector<ucp::shared_ptr<UcpPcb>> active_pcbs_;
    ucp::map<uint32_t, ucp::shared_ptr<UcpPcb>> pcbs_by_id_;
    ucp::map<uint64_t, ucp::shared_ptr<UcpPcb>> pcbs_by_session_key_;

    ucp::shared_ptr<NetworkTransportAdapter> transport_adapter_;

    std::chrono::steady_clock::time_point clock_start_;
    mutable std::atomic<int64_t> cached_time_us_{0};
    mutable std::atomic<int64_t> cached_time_ms_{0};
    std::atomic<bool> disposed_{false};

    friend class UcpPcb;
    friend class UcpDatagramNetwork;
};

} // namespace ucp
