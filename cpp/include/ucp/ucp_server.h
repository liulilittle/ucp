#pragma once

/** @file ucp_server.h
 *  @brief UCP server listener — mirrors C# Ucp.UcpServer.
 *
 *  UcpServer listens for incoming UCP SYN packets and creates UcpConnection
 *  objects for each accepted connection.  It supports fair-queue bandwidth
 *  scheduling among active connections when running inside a UcpNetwork,
 *  distributing the server's total bandwidth budget in proportion to each
 *  connection's BBR pacing rate.
 */

#include "ucp_types.h"
#include "ucp_configuration.h"
#include "ucp_enums.h"
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <map>
#include <vector>
#include <thread>
#include <condition_variable>
#include <atomic>

namespace ucp {

class UcpConnection;
class UcpPcb;
class UcpNetwork;

/** @brief Server that listens for incoming UCP connections and returns them via AcceptAsync.
 *
 *  The server can operate in standalone mode (owning its own transport and
 *  scheduling fair-queue via an internal timer) or within a UcpNetwork
 *  (delegating transport and scheduling to the network's DoEvents loop).
 */
class UcpServer {
public:
    UcpServer();
    /** @brief Construct with a specific configuration.
     *  @param config  Server configuration (bandwidth limit, fair-queue interval, etc.). */
    explicit UcpServer(const UcpConfiguration& config);
    ~UcpServer();

    UcpServer(const UcpServer&) = delete;
    UcpServer& operator=(const UcpServer&) = delete;

    /** @brief Start listening on the given port (standalone mode).
     *  @param port  UDP port to bind to. */
    void Start(int port);

    /** @brief Start listening within an existing UcpNetwork.
     *  @param network  The network to route through.
     *  @param port     Port for the transport.
     *  @param config   Server configuration. */
    void Start(UcpNetwork* network, int port, const UcpConfiguration& config);

    /** @brief Asynchronously accept the next incoming connection.
     *  @return Future resolving to a unique_ptr<UcpConnection>; nullptr if server is stopped. */
    std::future<std::unique_ptr<UcpConnection>> AcceptAsync();

    /** @brief Stop listening and close all connections. */
    void Stop();

    /** @brief Release all resources (calls Stop). */
    void Dispose();

    /** @brief Return the connection ID (server always returns 0).
     *  @return 0 (server is not a connection). */
    uint32_t GetConnectionId() const { return 0; }

    /** @brief The UcpNetwork managing this server.
     *  @return Pointer to UcpNetwork or nullptr. */
    UcpNetwork* GetNetwork() const { return network_; }

private:
    /** @brief Per-connection entry tracking the connection object and its PCB. */
    struct ConnectionEntry {
        std::unique_ptr<UcpConnection> connection;  //< Owning pointer to the public connection object.
        UcpPcb* pcb = nullptr;                       //< Raw pointer to the PCB (owned by the connection).
        bool accepted = false;                       //< Whether this entry has been passed to AcceptAsync.
    };

    /** @brief Handle an inbound datagram from the transport layer. */
    void OnTransportDatagram(const uint8_t* datagram, size_t length, const Endpoint& remote);

    /** @brief Find or create a ConnectionEntry for an incoming packet.
     *  @param remote  Source endpoint.
     *  @param packet  Raw packet bytes (for parsing connection ID and type).
     *  @param length  Packet byte count.
     *  @return Pointer to the ConnectionEntry; nullptr if the packet should be dropped. */
    ConnectionEntry* GetOrCreateConnection(const Endpoint& remote, const uint8_t* packet, size_t length);

    /** @brief Called when a PCB transitions to Established. */
    void OnPcbConnected(ConnectionEntry* entry);

    /** @brief Called when a PCB closes; removes the entry from connections_.
     *  @param pcb  The PCB that closed. */
    void OnPcbClosed(UcpPcb* pcb);

    /** @brief Schedule the next fair-queue round via the network timer. */
    void ScheduleFairQueueRound();

    /** @brief Timer callback for fair-queue scheduling. */
    void OnFairQueueRound();

    /** @brief Core fair-queue logic: distribute bandwidth credits to active connections. */
    void OnFairQueueRoundCore();

    mutable std::mutex mutex_;               //< Protects all connection state.
    bool started_ = false;                    //< Whether the server has been started.
    UcpConfiguration config_;                //< Server configuration.
    UcpNetwork* network_ = nullptr;          //< Network (null if standalone).
    bool owns_transport_ = true;             //< Whether the server owns its transport layer.
    int bandwidth_limit_bytes_per_sec_ = 12 * 1024 * 1024;  //< Total bandwidth cap for fair-queue (12 MB/s default).

    std::map<uint32_t, std::unique_ptr<ConnectionEntry>> connections_;  //< Active connections keyed by connId.
    std::queue<UcpConnection*> accept_queue_;       //< Queue of connections ready for AcceptAsync.
    std::condition_variable accept_cv_;             //< CV for signalling AcceptAsync waiters.
    std::mutex accept_mutex_;                       //< Protects accept_queue_ and accept_cv_.

    int fair_queue_start_index_ = 0;                //< Round-robin start index for fair-queue scheduling.
    int64_t last_fair_queue_round_micros_ = 0;      //< Timestamp of the last fair-queue round.
    uint32_t fair_queue_timer_id_ = 0;               //< Timer ID for the fair-queue round callback.

    std::atomic<bool> stopped_{false};              //< Signal to stop all server operations.
};

} // namespace ucp
