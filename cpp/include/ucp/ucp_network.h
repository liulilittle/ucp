#pragma once

/** @file ucp_network.h
 *  @brief Central network event loop and PCB manager — mirrors C# Ucp.UcpNetwork.
 *
 *  UcpNetwork serves as the central event loop for a set of UCP protocol
 *  control blocks (UcpPcb instances).  It manages:
 *  - A timer heap for scheduling callbacks with microsecond resolution.
 *  - A registry of active PCBs (by pointer and by connection ID).
 *  - A cached monotonic clock (updated on each DoEvents tick).
 *  - Input demultiplexing (routing incoming datagrams to the correct PCB).
 *  - Virtual Output method that subclasses (e.g. UcpDatagramNetwork) implement.
 */

#include "ucp_configuration.h"
#include "ucp_types.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>
#include <map>
#include <list>
#include <chrono>

namespace ucp {

class UcpPcb;
class UcpServer;
class UcpConnection;

/** @brief Base interface for objects owned by the network (PCBs, connections, servers). */
class IUcpObject {
public:
    virtual ~IUcpObject() = default;
    /** @brief Return the connection ID associated with this object.
     *  @return 32-bit connection identifier (0 if not applicable). */
    virtual uint32_t GetConnectionId() const = 0;
    /** @brief Return the UcpNetwork instance that manages this object.
     *  @return Pointer to the owning UcpNetwork. */
    virtual class UcpNetwork* GetNetwork() const = 0;
};

/** @brief Central network event loop with timer management and PCB registry.
 *
 *  Each UcpNetwork manages a set of UcpPcb instances, each of which
 *  registers/unregisters itself.  The DoEvents method fires expired timers
 *  and ticks each PCB.  Subclasses must implement Output() to deliver
 *  outbound datagrams over the actual network transport.
 */
class UcpNetwork {
public:
    /** @brief Construct with a given configuration.
     *  @param config  Connection-level and server-level configuration. */
    explicit UcpNetwork(const UcpConfiguration& config);

    /** @brief Default-construct with a default UcpConfiguration. */
    UcpNetwork();

    virtual ~UcpNetwork();

    /** @brief Access the mutable configuration for this network.
     *  @return Reference to the UcpConfiguration used by all managed PCBs. */
    UcpConfiguration& GetConfiguration() { return config_; }

    /** @brief Read-only configuration access.
     *  @return Const reference to the UcpConfiguration. */
    const UcpConfiguration& GetConfiguration() const { return config_; }

    /** @brief Process one tick: fire expired timers, tick all registered PCBs.
     *  @return Number of callbacks and PCB ticks executed (0 = idle). */
    virtual int DoEvents();

    /** @brief Accept an inbound datagram and attempt to route it to the correct PCB.
     *  @param data    Raw byte buffer of the received datagram.
     *  @param length  Number of bytes in data.
     *  @param remote  Endpoint that sent the datagram. */
    void Input(const uint8_t* data, size_t length, const Endpoint& remote);

    /** @brief Start the network on the given port (subclass-dependent).
     *  @param port  UDP port to bind to (default implementation is no-op). */
    virtual void Start(int port);

    /** @brief Stop the network transport (subclass-dependent). */
    virtual void Stop();

    /** @brief Send a datagram through the network transport (pure virtual).
     *  @param data    Raw bytes to transmit.
     *  @param length  Number of bytes in data.
     *  @param remote  Destination endpoint.
     *  @param sender  The UCP object that originated the send (for firewalling). */
    virtual void Output(const uint8_t* data, size_t length,
                        const Endpoint& remote, IUcpObject* sender) = 0;

    /** @brief Convenience overload of Output that passes nullptr as sender.
     *  @param data    Raw bytes to transmit.
     *  @param length  Number of bytes in data.
     *  @param remote  Destination endpoint. */
    void Output(const uint8_t* data, size_t length, const Endpoint& remote);

    /** @brief Register a callback to fire at a specific microsecond timestamp.
     *  @param expireUs  Absolute timestamp (microseconds since network epoch) when the callback should fire.
     *  @param callback  Function to invoke (may be from a lambda capture).
     *  @return Timer ID (non-zero) that can be used to cancel the timer. */
    uint32_t AddTimer(int64_t expireUs, std::function<void()> callback);

    /** @brief Cancel a previously registered timer.
     *  @param timerId  ID returned by AddTimer.
     *  @return true if a timer was found and cancelled. */
    bool CancelTimer(uint32_t timerId);

    /** @brief Create a new UcpServer managed by this network.
     *  @param port  Port the server should bind to.
     *  @return A unique_ptr to the new UcpServer. */
    std::unique_ptr<UcpServer> CreateServer(int port);

    /** @brief Create a new UcpConnection managed by this network.
     *  @return A unique_ptr to the new UcpConnection. */
    std::unique_ptr<UcpConnection> CreateConnection();

    /** @brief Create a new UcpConnection with a specific configuration.
     *  @param config  Configuration for this connection.
     *  @return A unique_ptr to the new UcpConnection. */
    std::unique_ptr<UcpConnection> CreateConnection(const UcpConfiguration& config);

    /** @brief Current cached microsecond timestamp.
     *  @return Cached value updated by UpdateCachedClock (at most once per millisecond). */
    int64_t GetNowMicroseconds() const;

    /** @brief Alias for GetNowMicroseconds (legacy compatibility).
     *  @return Cached microsecond timestamp. */
    int64_t GetCurrentTimeUs() const;

    /** @brief Return the local endpoint of this network transport.
     *  @return An Endpoint; default is empty/zero. */
    virtual Endpoint GetLocalEndPoint() const { return {}; }

    /** @brief Release all resources: stop timers, disconnect PCBs, close sockets. */
    virtual void Dispose();

protected:
    /** @brief Update the cached clock (call at start of each DoEvents tick). */
    void UpdateCachedClock();

    /** @brief Read the raw stopwatch value (monotonic microseconds since epoch).
     *  @return Microseconds since clock_start_. */
    int64_t ReadStopwatchMicros() const;

    /** @brief Yield the calling thread when there is no work to do. */
    void YieldWhenIdle();

    UcpConfiguration config_;  //< Configuration shared by all objects managed by this network.

private:
    /** @brief Entry in the timer heap (expire-time -> callback mapping). */
    struct TimerEntry {
        uint32_t id;                              //< Unique timer ID.
        int64_t expireUs;                         //< Absolute expiration timestamp (microseconds).
        std::function<void()> callback;           //< User-provided callback to invoke.
        std::function<void()> wrappedCallback;    //< Wrapper that handles one-shot semantics.
    };

    /** @brief Register a UcpPcb in the active set (called by UcpPcb constructor).
     *  @param pcb  The PCB to register. */
    void RegisterPcb(UcpPcb* pcb);

    /** @brief Remove a UcpPcb from the active set (called by UcpPcb destructor / ReleaseNetworkRegistrations).
     *  @param pcb  The PCB to unregister. */
    void UnregisterPcb(UcpPcb* pcb);

    /** @brief Update the connection-ID -> PCB mapping (called when connection ID changes after SYN).
     *  @param pcb    The PCB being updated.
     *  @param oldId  Previous connection ID (0 if new PCB).
     *  @param newId  New connection ID. */
    void UpdatePcbConnectionId(UcpPcb* pcb, uint32_t oldId, uint32_t newId);

    /** @brief Take a snapshot of all active PCBs (under pcb_mutex_).
     *  @return Copy of the active PCB vector. */
    std::vector<UcpPcb*> SnapshotPcbs();

    mutable std::mutex timer_mutex_;                               //< Protects timer_heap_ and active_timers_.
    std::multimap<int64_t, std::function<void()>> timer_heap_;    //< Priority queue keyed by expiration timestamp.
    std::map<uint32_t, std::shared_ptr<TimerEntry>> active_timers_; //< Map from timer ID to entry (for cancellation).
    uint32_t next_timer_id_ = 1;                                   //< Monotonically increasing timer ID counter.

    mutable std::mutex pcb_mutex_;                //< Protects active_pcbs_ and pcbs_by_id_.
    std::vector<UcpPcb*> active_pcbs_;             //< All registered PCBs (for iteration/DoEvents).
    std::map<uint32_t, UcpPcb*> pcbs_by_id_;       //< Fast lookup by connection ID (for Input routing).

    std::chrono::steady_clock::time_point clock_start_;  //< Fixed epoch for all timing (set at construction).
    mutable int64_t cached_time_us_ = 0;                 //< Cached microsecond value (updated by UpdateCachedClock).
    mutable int64_t cached_time_ms_ = 0;                 //< Cached millisecond value (guards coarse-grained updates).
    bool disposed_ = false;                              //< Whether Dispose has been called.

    friend class UcpPcb;
    friend class UcpDatagramNetwork;
};

} // namespace ucp
