#pragma once

/** @file ucp_server.h
 *  @brief UCP server listener — mirrors C# Ucp.UcpServer.
 *
 *  UcpServer listens for incoming UCP SYN packets and creates UcpConnection
 *  objects for each accepted connection.  It supports fair-queue bandwidth
 *  scheduling among active connections when running inside a UcpNetwork,
 *  distributing the server's total bandwidth budget in proportion to each
 *  connection's BBR pacing rate.
 *
 *  This class contains NO socket or ASIO code — all network I/O is
 *  delegated to the UcpNetwork's transport adapter or a standalone
 *  transport layer.  The fair-queue timer is registered with UcpNetwork
 *  (in network-managed mode) or driven by a standalone timer.
 */

#include "ucp_types.h"         // Endpoint, UcpTransferReport, UcpConnectionDiagnostics (includes ucp_vector.h and ucp_memory.h)
#include "ucp_configuration.h" // Server and per-connection configuration (bandwidth limit, fair-queue interval)
#include "ucp_enums.h"         // UcpConnectionState, UcpPriority enumeration types
#include <cstdint>             // Fixed-width integers: uint8_t, uint32_t, int64_t, size_t
#include <functional>          // std::function for timer callbacks and delegate-style registrations
#include <future>              // std::future for AcceptAsync return type
#include <mutex>               // std::mutex for thread-safe connection registry and accept queue access
#include <queue>               // std::queue for the FIFO accept queue (connections ready for AcceptAsync)
#include <map>                 // std::map for the connection-ID-to-ConnectionEntry lookup table
#include <thread>              // std::thread (reserved for potential standalone timer thread)
#include <condition_variable>  // std::condition_variable to block AcceptAsync until a new connection is ready
#include <atomic>              // std::atomic<bool> for lock-free stopped_ flag

namespace ucp {

class UcpConnection; // Forward declaration — managed connection objects are created per accepted client
class UcpPcb;        // Forward declaration — protocol control block underlying each accepted connection
class UcpNetwork;    // Forward declaration — the owning network event loop (null for standalone servers)

/** @brief Server that listens for incoming UCP connections and returns them via AcceptAsync.
 *
 *  The server can operate in standalone mode (owning its own transport and
 *  scheduling fair-queue via an internal timer) or within a UcpNetwork
 *  (delegating transport and scheduling to the network's DoEvents loop).
 *
 *  All network I/O is abstracted behind the transport interfaces —
 *  no ASIO/Boost.Asio or raw socket code exists in this class.
 */
class UcpServer {
public:
    UcpServer(); // Default constructor: creates with default configuration, standalone transport

    /** @brief Construct with a specific configuration.
     *  @param config  Server configuration (bandwidth limit, fair-queue interval, etc.). */
    explicit UcpServer(const UcpConfiguration& config); // Stores a copy of the configuration for accepted connections

    ~UcpServer(); // Calls Stop() to release transport, dispose PCBs, and stop the fair-queue timer

    UcpServer(const UcpServer&) = delete; // Non-copyable — each server manages unique transport and connection state
    UcpServer& operator=(const UcpServer&) = delete; // Non-copyable — prevents shallow copies of transport/thread resources

    /** @brief Start listening on the given port (standalone mode).
     *
     *  Binds the transport to the specified port and subscribes to incoming
     *  datagram events.  Launches the fair-queue timer if in standalone mode.
     *  @param port  UDP port to bind to. */
    void Start(int port); // Binds transport, subscribes to datagrams, starts fair-queue timer (standalone) or schedules it (network)

    /** @brief Start listening within an existing UcpNetwork (multiplexed mode).
     *
     *  Swaps the transport to the network's adapter, then delegates to
     *  Start(port) for actual binding.  Fair-queue rounds are scheduled
     *  through the network's timer system.
     *  @param network  The network to route through.
     *  @param port     Port for the transport to bind to.
     *  @param config   Server configuration (cloned internally). */
    void Start(UcpNetwork* network, int port, const UcpConfiguration& config); // Sets up network-managed transport, then calls Start(port)

    /** @brief Asynchronously accept the next incoming connection.
     *
     *  Blocks until a new client completes the UCP handshake.  The returned
     *  connection is fully established and ready for data transfer.
     *  @return Future resolving to a unique_ptr<UcpConnection>; nullptr if the server is stopped. */
    std::future<ucp::unique_ptr<UcpConnection>> AcceptAsync(); // Waits on accept_cv_; dequeues the next established connection

    /** @brief Stop listening: unsubscribe from transport, stop fair-queue timer, dispose all PCBs.
     *
     *  Gracefully tears down all active connections and releases transport
     *  resources.  Idempotent — safe to call multiple times. */
    void Stop(); // Snapshot and clear connections under lock, dispose PCBs outside lock, stop transport

    /** @brief Release all server resources (calls Stop). */
    void Dispose(); // Delegates to Stop(); idempotent via started_ flag

    /** @brief Return the connection ID (server always returns 0).
     *  @return 0 — the server is not associated with any single connection ID. */
    uint32_t GetConnectionId() const { return 0; } // Mirrors C# IUcpObject.ConnectionId — server always returns 0

    /** @brief The UcpNetwork managing this server (null if standalone).
     *  @return Pointer to UcpNetwork or nullptr. */
    UcpNetwork* GetNetwork() const { return network_; } // Exposes the network context for diagnostics and timer access

private:
    /** @brief Per-connection bookkeeping entry tracking the connection object and its PCB.
     *
     *  Each ConnectionEntry represents an active client connection known to
     *  the server.  The entry holds the public UcpConnection wrapper and a
     *  raw pointer to the underlying UcpPcb (owned by the connection). */
    struct ConnectionEntry {
        ucp::unique_ptr<UcpConnection> connection; // Owning pointer to the public UcpConnection object exposed to the application
        UcpPcb* pcb = nullptr;                       // Raw pointer to the low-level protocol control block (owned by connection)
        bool accepted = false;                       // Guard flag — true after this entry has been enqueued for AcceptAsync
    };

    /** @brief Handle an inbound datagram from the transport layer.
     *  @param datagram  Raw datagram bytes received from the network.
     *  @param length    Number of bytes in datagram.
     *  @param remote    Source endpoint (address + port) that sent the datagram. */
    void OnTransportDatagram(const uint8_t* datagram, size_t length, const Endpoint& remote); // Decodes packet, finds/creates connection entry, dispatches

    /** @brief Find or create a ConnectionEntry for an incoming packet.
     *
     *  Looks up an existing entry by connection ID.  If the packet is a SYN
     *  and no entry exists, creates a new UcpPcb + UcpConnection pair and
     *  registers it.  Returns nullptr for non-SYN packets on unknown connections.
     *  @param remote  Source endpoint of the datagram.
     *  @param packet  Raw packet bytes (for parsing connection ID and type).
     *  @param length  Packet byte count.
     *  @return Pointer to the ConnectionEntry; nullptr if the packet should be dropped. */
    ConnectionEntry* GetOrCreateConnection(const Endpoint& remote, const uint8_t* packet, size_t length); // Keyed by connection ID (IP-agnostic); only SYN creates new entries

    /** @brief Called when a PCB transitions to the Established state.
     *
     *  Enqueues the connection for acceptance and signals the accept
     *  condition variable to wake any thread waiting in AcceptAsync.
     *  @param entry  The connection entry that completed its handshake. */
    void OnPcbConnected(ConnectionEntry* entry); // Sets accepted = true, enqueues connection, signals accept_cv_

    /** @brief Called when a PCB closes; removes the entry from the server's connection table.
     *  @param pcb  The PCB that closed (used to derive the connection key). */
    void OnPcbClosed(UcpPcb* pcb); // Removes the entry from connections_ by connection-ID-derived key

    /** @brief Schedule the next fair-queue round via the network timer.
     *
     *  Registers a one-shot timer in the network's event loop that fires after
     *  the configured round interval (FairQueueRoundMilliseconds). */
    void ScheduleFairQueueRound(); // Computes delay, calls network_->AddTimer() with OnFairQueueRound as callback

    /** @brief Timer callback for fair-queue scheduling.
     *
     *  Executes the core credit distribution round, then reschedules the
     *  next round if running under a UcpNetwork. */
    void OnFairQueueRound(); // Calls OnFairQueueRoundCore() then ScheduleFairQueueRound() if network-managed

    /** @brief Core fair-queue logic: distribute bandwidth credits to active connections.
     *
     *  1. Collects active connections that have pending send data.
     *  2. Calculates the credit pool for this round based on elapsed time and bandwidth limit.
     *  3. Distributes credit proportionally to each connection's BBR pacing rate (capped at fair share).
     *  4. Flushes each connection in rotated round-robin order. */
    void OnFairQueueRoundCore(); // Implements proportional-fair bandwidth scheduling across all connections

    mutable std::mutex mutex_;               // Protects all connection state: connections_, accept_queue_, fair-queue indices
    bool started_ = false;                    // Guard flag — true after Start() has been called, false after Stop()
    UcpConfiguration config_;                // Server configuration (bandwidth limit, fair-queue interval; cloned per-connection on accept)
    UcpNetwork* network_ = nullptr;          // Network context (null if standalone; non-null when multiplexed via UcpNetwork)
    bool owns_transport_ = true;             // True if the server created its transport internally (should dispose on Stop)
    int bandwidth_limit_bytes_per_sec_ = 12 * 1024 * 1024; // Total bandwidth cap for fair-queue scheduling (12 MB/s default)

    std::map<uint32_t, ucp::unique_ptr<ConnectionEntry>> connections_; // Active connections keyed by connection ID (IP-agnostic lookup)
    std::queue<UcpConnection*> accept_queue_;        // FIFO queue of established connections waiting for AcceptAsync pickup
    std::condition_variable accept_cv_;              // CV signaled when a new connection is enqueued for acceptance
    std::mutex accept_mutex_;                        // Protects accept_queue_ and accept_cv_ from concurrent access

    int fair_queue_start_index_ = 0;                 // Rotating start index for round-robin flush ordering across fair-queue rounds
    int64_t last_fair_queue_round_micros_ = 0;       // Timestamp (microseconds) of the most recent fair-queue round completion
    uint32_t fair_queue_timer_id_ = 0;               // Timer ID for the currently scheduled fair-queue round (0 = not scheduled)

    std::atomic<bool> stopped_{false};               // Atomic flag — set to true to signal all server operations should stop
};

} // namespace ucp
