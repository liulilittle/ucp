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
 *
 *  The protocol stack does NOT directly use ASIO/Boost.Asio for UDP network I/O.
 *  Async network I/O lives in the transport layer (UcpDatagramNetwork), which
 *  uses raw BSD/Winsock sockets.  UcpNetwork itself is pure protocol logic.
 */

#include "ucp_configuration.h" // Per-connection protocol configuration (timeouts, window sizes, MSS, etc.)
#include "ucp_types.h"         // Endpoint, UcpTransferReport, UcpConnectionDiagnostics (includes ucp_vector.h and ucp_memory.h)
#include <cstdint>             // Fixed-width integer types: uint8_t, uint32_t, int64_t, size_t
#include <functional>          // std::function for timer callbacks and delegate-style registrations
#include <mutex>               // std::mutex for thread-safe timer heap and PCB registry access
#include <map>                 // std::map, std::multimap for timer heap and connection-ID-to-PCB routing
#include <list>                // std::list (reserved for future use / compatibility)
#include <chrono>              // std::chrono::steady_clock for monotonic time source

namespace ucp {

class UcpPcb;        // Forward declaration — protocol control block (defined in internal/ucp_pcb.h)
class UcpServer;     // Forward declaration — server listener (defined in ucp_server.h)
class UcpConnection; // Forward declaration — client connection (defined in ucp_connection.h)

/** @brief Base interface for objects owned by the network (PCBs, connections, servers). */
class IUcpObject {
public:
    virtual ~IUcpObject() = default; // Virtual destructor for safe polymorphic deletion through base pointer
    /** @brief Return the connection ID associated with this object.
     *  @return 32-bit connection identifier (0 if not applicable — e.g. server always returns 0). */
    virtual uint32_t GetConnectionId() const = 0; // Pure virtual — every managed object must report its ID
    /** @brief Return the UcpNetwork instance that manages this object.
     *  @return Pointer to the owning UcpNetwork (nullptr if standalone). */
    virtual class UcpNetwork* GetNetwork() const = 0; // Pure virtual — back-reference to the network event loop
};

/** @brief Central network event loop with timer management and PCB registry.
 *
 *  Each UcpNetwork manages a set of UcpPcb instances, each of which
 *  registers/unregisters itself.  The DoEvents method fires expired timers
 *  and ticks each PCB.  Subclasses must implement Output() to deliver
 *  outbound datagrams over the actual network transport.
 *
 *  This class contains NO socket or ASIO code — it is a pure protocol
 *  event loop.  Network I/O is the responsibility of derived classes
 *  such as UcpDatagramNetwork (which uses raw sendto/recvfrom).
 */
class UcpNetwork {
public:
    /** @brief Construct with a given configuration.
     *  @param config  Connection-level and server-level configuration (cloned internally). */
    explicit UcpNetwork(const UcpConfiguration& config); // Stores a copy of the configuration for all managed objects

    /** @brief Default-construct with a default UcpConfiguration. */
    UcpNetwork(); // Delegates to the parameterized constructor with a fresh default configuration

    virtual ~UcpNetwork(); // Virtual destructor — derived classes (UcpDatagramNetwork) add socket cleanup

    /** @brief Access the mutable configuration for this network.
     *  @return Reference to the UcpConfiguration used by all managed PCBs. */
    UcpConfiguration& GetConfiguration() { return config_; } // Non-const access for runtime tuning

    /** @brief Read-only configuration access.
     *  @return Const reference to the UcpConfiguration. */
    const UcpConfiguration& GetConfiguration() const { return config_; } // Const overload for read-only contexts

    /** @brief Process one tick: fire expired timers, tick all registered PCBs.
     *  @return Number of callbacks and PCB ticks executed (0 = idle, caller should sleep/yield). */
    virtual int DoEvents(); // The main event loop driver — call in a loop to advance protocol state

    /** @brief Accept an inbound datagram and attempt to route it to the correct PCB.
     *  @param data    Raw byte buffer of the received datagram.
     *  @param length  Number of bytes in data.
     *  @param remote  Endpoint that sent the datagram (address + port). */
    void Input(const uint8_t* data, size_t length, const Endpoint& remote); // Decodes packet header, routes to PCB or transport adapter

    /** @brief Start the network on the given port (subclass-dependent).
     *  @param port  UDP port to bind to (default implementation is no-op). */
    virtual void Start(int port); // Base implementation is empty — derived classes bind a socket here

    /** @brief Stop the network transport (subclass-dependent). */
    virtual void Stop(); // Base implementation is empty — derived classes close their socket here

    /** @brief Send a datagram through the network transport (pure virtual).
     *  @param data    Raw bytes to transmit.
     *  @param length  Number of bytes in data.
     *  @param remote  Destination endpoint (address + port).
     *  @param sender  The UCP object that originated the send (for firewalling / source tracking). */
    virtual void Output(const uint8_t* data, size_t length,
                        const Endpoint& remote, IUcpObject* sender) = 0; // Pure virtual — must be implemented by transport layer

    /** @brief Convenience overload of Output that passes nullptr as sender.
     *  @param data    Raw bytes to transmit.
     *  @param length  Number of bytes in data.
     *  @param remote  Destination endpoint. */
    void Output(const uint8_t* data, size_t length, const Endpoint& remote); // Calls Output(data, length, remote, nullptr)

    /** @brief Register a callback to fire at a specific microsecond timestamp.
     *  @param expireUs  Absolute timestamp (microseconds since network epoch) when the callback should fire.
     *  @param callback  Function to invoke (may capture local state via lambda).
     *  @return Timer ID (non-zero) that can be passed to CancelTimer. */
    uint32_t AddTimer(int64_t expireUs, std::function<void()> callback); // Wraps callback with cancellation guard, inserts into timer heap

    /** @brief Cancel a previously registered timer.
     *  @param timerId  ID returned by AddTimer.
     *  @return true if a timer was found and cancelled before it fired. */
    bool CancelTimer(uint32_t timerId); // Removes the timer registration; wrapper callback detects removal and skips execution

    /** @brief Create a new UcpServer managed by this network.
     *  @param port  Port the server should bind to.
     *  @return A unique_ptr to the new UcpServer (caller takes ownership). */
    ucp::unique_ptr<UcpServer> CreateServer(int port); // Factory method — creates server with network's transport adapter

    /** @brief Create a new UcpConnection managed by this network.
     *  @return A unique_ptr to the new UcpConnection (caller takes ownership). */
    ucp::unique_ptr<UcpConnection> CreateConnection(); // Factory method — delegates to overload with network's configuration

    /** @brief Create a new UcpConnection with a specific configuration.
     *  @param config  Configuration for this connection (cloned internally).
     *  @return A unique_ptr to the new UcpConnection (caller takes ownership). */
    ucp::unique_ptr<UcpConnection> CreateConnection(const UcpConfiguration& config); // Factory method — uses network's transport adapter

    /** @brief Current cached microsecond timestamp.
     *  @return Cached value updated by UpdateCachedClock (at most once per millisecond). */
    int64_t GetNowMicroseconds() const; // Returns the cached logical clock — avoids repeated system calls within a tick

    /** @brief Alias for GetNowMicroseconds (legacy compatibility).
     *  @return Cached microsecond timestamp. */
    int64_t GetCurrentTimeUs() const; // Same as GetNowMicroseconds — provided for naming consistency with C# UcpNetwork.CurrentTimeUs

    /** @brief Return the local endpoint of this network transport.
     *  @return An Endpoint; default is empty/zero (derived classes override). */
    virtual Endpoint GetLocalEndPoint() const { return {}; } // Returns default-constructed Endpoint; overridden by UcpDatagramNetwork

    /** @brief Release all resources: stop timers, disconnect PCBs, close sockets (virtual for derivation). */
    virtual void Dispose(); // Sets disposed flag, calls Stop(), clears timer heap and active timers

protected:
    /** @brief Update the cached clock (call at start of each DoEvents tick). */
    void UpdateCachedClock(); // Reads the monotonic stopwatch; updates cached_time_us_ only if >=1ms elapsed since last update

    /** @brief Read the raw stopwatch value (monotonic microseconds since epoch).
     *  @return Microseconds since clock_start_ (steady_clock, not wall time). */
    int64_t ReadStopwatchMicros() const; // Computes duration from clock_start_ to now in microseconds

    /** @brief Yield the calling thread when there is no work to do.
     *
     *  If the next timer is imminent (<= 1ms), calls std::this_thread::yield() for
     *  low latency; otherwise sleeps for 1ms to reduce CPU usage. */
    void YieldWhenIdle(); // Adaptive yield: checks next timer expiration to decide yield vs. sleep

    UcpConfiguration config_; // Configuration shared by all objects managed by this network (server + connections)

private:
    /** @brief Entry in the timer heap (expire-time -> callback mapping).
     *
     *  Each entry tracks a unique timer ID, its absolute expiration, the user callback,
     *  and a wrapped callback that performs cancellation checking before invocation. */
    struct TimerEntry {
        uint32_t id;                              // Unique timer ID (monotonically allocated from next_timer_id_)
        int64_t expireUs;                         // Absolute expiration timestamp in microseconds (monotonic epoch)
        std::function<void()> callback;           // User-provided callback to invoke when the timer fires
        std::function<void()> wrappedCallback;    // Wrapper that checks active_timers_ for this ID before invoking callback (one-shot semantic)
    };

    /** @brief Register a UcpPcb in the active set (called by UcpPcb constructor via friend).
     *  @param pcb  The PCB to register (must be non-null). */
    void RegisterPcb(UcpPcb* pcb); // Adds to active_pcbs_ list and pcbs_by_id_ map under pcb_mutex_

    /** @brief Remove a UcpPcb from the active set (called by UcpPcb destructor / ReleaseNetworkRegistrations).
     *  @param pcb  The PCB to unregister. */
    void UnregisterPcb(UcpPcb* pcb); // Removes from active_pcbs_ and pcbs_by_id_ under pcb_mutex_

    /** @brief Update the connection-ID -> PCB mapping (called when connection ID changes after SYN/SYN-ACK).
     *  @param pcb    The PCB being updated.
     *  @param oldId  Previous connection ID (0 if new PCB before handshake).
     *  @param newId  New connection ID assigned by the handshake. */
    void UpdatePcbConnectionId(UcpPcb* pcb, uint32_t oldId, uint32_t newId); // Removes old mapping, inserts new one under pcb_mutex_

    /** @brief Take a snapshot of all active PCBs (under pcb_mutex_).
     *  @return Copy of the active PCB vector for safe iteration outside the lock. */
    ucp::vector<UcpPcb*> SnapshotPcbs(); // Shallow-copy under lock; caller can iterate and call OnTick without holding lock

    mutable std::mutex timer_mutex_;                                 // Protects timer_heap_ and active_timers_ from concurrent access
    std::multimap<int64_t, std::function<void()>> timer_heap_;      // Min-heap keyed by expiration timestamp (earliest fires first); multiple callbacks per time
    std::map<uint32_t, ucp::shared_ptr<TimerEntry>> active_timers_; // Map from timer ID to TimerEntry shared_ptr (enables CancelTimer via removal)
    uint32_t next_timer_id_ = 1;                                     // Monotonically increasing timer ID counter (starts at 1; 0 reserved for invalid)

    mutable std::mutex pcb_mutex_;                     // Protects active_pcbs_ and pcbs_by_id_ from concurrent access
    ucp::vector<UcpPcb*> active_pcbs_;                  // All registered PCBs (iterated each DoEvents tick to call OnTick)
    std::map<uint32_t, UcpPcb*> pcbs_by_id_;            // Fast O(log n) lookup by connection ID for Input packet routing

    std::chrono::steady_clock::time_point clock_start_; // Fixed monotonic epoch for all timing (set at construction; never drifts with wall clock)
    mutable int64_t cached_time_us_ = 0;                // Cached microsecond value (updated by UpdateCachedClock at most once per millisecond)
    mutable int64_t cached_time_ms_ = 0;                // Cached millisecond value (guards coarse-grained UpdateCachedClock throttle)
    bool disposed_ = false;                             // Guard flag — set true in Dispose(); checked in Input/DoEvents to reject use-after-free

    friend class UcpPcb;            // UcpPcb calls RegisterPcb/UnregisterPcb/UpdatePcbConnectionId
    friend class UcpDatagramNetwork; // UcpDatagramNetwork accesses protected clock and config during socket operations
};

} // namespace ucp
