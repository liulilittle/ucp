/** @file ucp_server.cpp
 *  @brief UCP server listener implementation -- mirrors C# Ucp.UcpServer.
 *
 *  Listens for incoming SYN packets and creates UcpConnection instances
 *  for each accepted peer.  Supports fair-queue bandwidth scheduling
 *  (proportional to each connection's UCP pacing rate) when running
 *  inside a UcpNetwork with DoEvents-based timer dispatch.
 *
 *  AcceptAsync uses a callback-based pattern -- no thread is spawned per
 *  call and no promise/future is allocated.  The callback is invoked when
 *  a connection handshake completes or the server is shut down.  The server
 *  subscribes to the transport's on_datagram multicast to receive incoming
 *  packets.
 *
 *  Standalone mode uses a background timer thread for periodic fair-queue
 *  rounds.  Network-managed mode schedules rounds via UcpNetwork::AddTimer. */

#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include "ucp/internal/ucp_pcb.h"
#include "ucp/ucp_packet_codec.h"
#include "ucp/ucp_packets.h"
#include "ucp/transport/udp_socket_transport.h"
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"
#include "ucp/ucp_time.h"
#include "ucp/ucp_constants.h"
#include <algorithm>
#include <chrono>

namespace {

static constexpr int64_t kDefaultServerBandwidthLimit = ucp::Constants::DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

std::mutex s_serverPcbMapMutex;

/** @brief Stores UcpPcb shared-ownership pointers keyed by connection ID.
 *
 *  When the server creates a PCB via ucp::make_shared_object the resulting
 *  shared_ptr is stored here so that the PCB stays alive until the
 *  connection is closed.  Entries are erased in OnPcbClosed and the
 *  entire map is cleared in Stop().  This fixes the raw-pointer resource
 *  leak where PCBs were allocated with new but never deleted. */
ucp::map<uint32_t, ucp::shared_ptr<ucp::UcpPcb>> s_serverPcbMap;

// ---------------------------------------------------------------------------
// Deferred destruction of server-owned connections.
//
// A server-side connection can be destroyed from the PCB's own worker thread:
// TransitionToClosed -> m_closedCallback -> OnPcbClosed releases the entry's
// last shared_ptr while that very worker is still executing the transition.
// Destroying the connection/PCB there is unsafe (the worker loop, its queued
// std::function objects, and the peer connection's worker may still touch the
// freed memory).  So the entry is handed to a background cleanup thread which
// joins every non-self worker before releasing the shared_ptr.
// ---------------------------------------------------------------------------
std::mutex s_deferredMutex;
std::condition_variable s_deferredCv;
ucp::vector<ucp::shared_ptr<ucp::UcpServer::ConnectionEntry>> s_deferredEntries;
bool s_deferredShutdown = false;
std::thread s_cleanupThread;

void DeferredCleanupLoop() noexcept {
    for (;;) {
        ucp::vector<ucp::shared_ptr<ucp::UcpServer::ConnectionEntry>> batch;
        {
            std::unique_lock<std::mutex> lock(s_deferredMutex);
            s_deferredCv.wait(lock, []() noexcept { return !s_deferredEntries.empty() || s_deferredShutdown; });
            if (s_deferredShutdown && s_deferredEntries.empty()) {
                return;
            }
            batch.swap(s_deferredEntries);
        }
        // Drop the batch here (outside the lock): releasing these shared_ptrs
        // destroys the connections/PCBs from this thread, which is never any
        // of their worker threads, so every join below is safe.
        batch.clear();
    }
}

void EnsureCleanupThread() noexcept {
    // std::call_once guarantees the cleanup thread is created exactly once even
    // when multiple connections close concurrently on different threads.
    static std::once_flag s_once;
    std::call_once(s_once, []() noexcept {
        s_cleanupThread = std::thread(DeferredCleanupLoop);
        std::atexit([]() noexcept {
            {
                std::lock_guard<std::mutex> lock(s_deferredMutex);
                s_deferredShutdown = true;
            }
            s_deferredCv.notify_all();
            if (s_cleanupThread.joinable()) {
                s_cleanupThread.join();
            }
        });
    });
}

void DeferDestroyEntry(ucp::shared_ptr<ucp::UcpServer::ConnectionEntry> entry) noexcept {
    if (!entry) {
        return;
    }
    EnsureCleanupThread();
    {
        std::lock_guard<std::mutex> lock(s_deferredMutex);
        s_deferredEntries.push_back(std::move(entry));
    }
    s_deferredCv.notify_one();
}

} // namespace

namespace ucp {

/** @brief Internal constructor: wraps transport with ownership flag, configuration, and optional network.
 *  @param transport     Underlying transport pointer (may be NULLPTR).
 *  @param ownsTransport True if the server owns and will dispose the transport.
 *  @param config        Server configuration (cloned internally).
 *  @param network       Owning UcpNetwork (NULLPTR for standalone operation). */
UcpServer::UcpServer(transport::ITransport* transport, bool ownsTransport, const UcpConfiguration& config, UcpNetwork* network) noexcept
    : config_(config), network_(network), owns_transport_(ownsTransport), transport_(transport) {
    if (owns_transport_ && NULLPTR != transport_) {
        owned_transport_holder_.reset(transport_);
        transport_ = owned_transport_holder_.get();
    }
    bindable_transport_ = dynamic_cast<transport::IBindableTransport*>(transport_);
    bandwidth_limit_bytes_per_sec_ =
        0 < config_.ServerBandwidthBytesPerSecond ? config_.ServerBandwidthBytesPerSecond : kDefaultServerBandwidthLimit;
}

UcpServer::UcpServer() noexcept : UcpServer(NULLPTR, true, UcpConfiguration(), NULLPTR) {
    owned_transport_holder_ = ucp::make_shared_object<transport::UdpSocketTransport>();
    transport_ = owned_transport_holder_.get();
    bindable_transport_ = dynamic_cast<transport::IBindableTransport*>(transport_);
}

UcpServer::UcpServer(const UcpConfiguration& config) noexcept : UcpServer(NULLPTR, true, config, NULLPTR) {
    owned_transport_holder_ = ucp::make_shared_object<transport::UdpSocketTransport>();
    transport_ = owned_transport_holder_.get();
    bindable_transport_ = dynamic_cast<transport::IBindableTransport*>(transport_);
}

UcpServer::~UcpServer() noexcept {
    Dispose();
}

/** @brief Starts listening on the given port in standalone mode.
 *  @param port  UDP port to bind and listen on. */
void UcpServer::Start(int port) noexcept {
    bool scheduleNetworkFairQueue = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (started_) {
            return;
        }

        if (NULLPTR != transport_) {
            transport_token_ = transport_->AddOnDatagram(
                [this](const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept { OnTransportDatagram(data, remote); });
        }

        if (NULLPTR != bindable_transport_) {
            bindable_transport_->Start(port);
        }

        started_ = true;

        if (NULLPTR == network_) {
            fair_queue_timer_running_ = true;
            fair_queue_timer_thread_ = std::thread([this]() noexcept {
                while (true) {
                    {
                        std::unique_lock<std::mutex> lk(m_fairQueueTimerMutex);
                        m_fairQueueTimerCv.wait_for(lk, std::chrono::milliseconds(config_.FairQueueRoundMilliseconds),
                                                    [this]() { return !fair_queue_timer_running_; });
                    }
                    {
                        std::lock_guard<std::mutex> lk(m_fairQueueTimerMutex);
                        if (!fair_queue_timer_running_) {
                            break;
                        }
                    }
                    OnFairQueueRound();
                }
            });
        } else {
            scheduleNetworkFairQueue = true;
        }
    }
    if (scheduleNetworkFairQueue) {
        ScheduleFairQueueRound();
    }
}

/** @brief Starts listening on the given port within an existing UcpNetwork (multiplexed mode).
 *  @param network  The UcpNetwork that owns the transport and timer infrastructure.
 *  @param port     UDP port to bind and listen on.
 *  @param config   Server configuration. */
void UcpServer::Start(UcpNetwork* network, int port, const UcpConfiguration& config) noexcept {
    if (NULLPTR == network) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (started_) {
            return;
        }
        network_ = network;
        config_ = config;
        owns_transport_ = false;
        bandwidth_limit_bytes_per_sec_ =
            0 < config_.ServerBandwidthBytesPerSecond ? config_.ServerBandwidthBytesPerSecond : kDefaultServerBandwidthLimit;
        transport_ = network->GetTransportAdapter();
        bindable_transport_ = network->GetTransportAdapter();
    }
    Start(port);
}

/** @brief Asynchronously accepts the next incoming connection.
 *
 *  Uses a stored-callback pattern (no thread per call).  If a connection
 *  is already waiting in the accept queue it is returned immediately via
 *  the callback.  If the server is already stopped the callback fires
 *  with UcpError::ShuttingDown.  Otherwise the callback is queued and
 *  will be invoked when OnPcbConnected is called or the server stops.
 *
 *  @param callback  Callback receiving error code and accepted connection
 *                   (NULLPTR connection on shutdown).  The server retains
 *                   ownership of the UcpConnection pointer; the caller must
 *                   NOT delete it. */
void UcpServer::AcceptAsync(AcceptAsyncCallback callback) noexcept {
    ucp::shared_ptr<UcpConnection> conn;
    bool invokeStopped = false;

    {
        std::lock_guard<std::mutex> lock(accept_mutex_);
        if (!accept_queue_.empty()) {
            conn = accept_queue_.front();
            accept_queue_.pop();
        } else if (stopped_) {
            invokeStopped = true;
        } else {
            accept_callbacks_.push(std::move(callback));
            return;
        }
    }

    if (conn) {
        if (callback) {
            try {
                callback(UcpError::None, conn.get());
            } catch (...) {
            }
        }
    } else if (invokeStopped) {
        if (callback) {
            try {
                callback(UcpError::ShuttingDown, NULLPTR);
            } catch (...) {
            }
        }
    }
}

/** @brief Stops listening and closes all active connections.
 *
 *  Drains the accept queue, invokes all pending AcceptAsync callbacks
 *  with UcpError::ShuttingDown, disposes all PCB instances, and releases
 *  all connection entries.  PCB memory is properly freed via the shared_ptr
 *  map cleanup.  Idempotent. */
void UcpServer::Stop() noexcept {
    {
        ucp::vector<ucp::shared_ptr<ConnectionEntry>> entries;
        bool joinFairQueueTimer = false;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!started_) {
                return;
            }
            started_ = false;

            if (NULLPTR != transport_) {
                transport_->RemoveOnDatagram(transport_token_);
                transport_token_ = 0;
            }

            if (fair_queue_timer_running_) {
                fair_queue_timer_running_ = false;
                {
                    std::lock_guard<std::mutex> lk(m_fairQueueTimerMutex);
                    m_fairQueueTimerCv.notify_all();
                }
                joinFairQueueTimer = true;
            }

            if (NULLPTR != network_ && 0 != fair_queue_timer_id_) {
                network_->CancelTimer(fair_queue_timer_id_);
                fair_queue_timer_id_ = 0;
            }

            for (auto& pair : connections_) {
                entries.push_back(std::move(pair.second));
            }
            connections_.clear();
        }

        if (joinFairQueueTimer && fair_queue_timer_thread_.joinable() && std::this_thread::get_id() != fair_queue_timer_thread_.get_id()) {
            fair_queue_timer_thread_.join();
        } else if (fair_queue_timer_thread_.joinable()) {
            fair_queue_timer_thread_.detach();
        }

        for (auto& entry : entries) {
            if (NULLPTR != entry && NULLPTR != entry->pcb) {
                entry->pcb->Dispose();
            }
        }

        stopped_ = true;

        ucp::vector<AcceptAsyncCallback> pendingCallbacks;
        {
            std::lock_guard<std::mutex> lock(accept_mutex_);
            while (!accept_callbacks_.empty()) {
                pendingCallbacks.push_back(std::move(accept_callbacks_.front()));
                accept_callbacks_.pop();
            }
            while (!accept_queue_.empty()) {
                accept_queue_.pop();
            }
        }

        for (auto& cb : pendingCallbacks) {
            if (cb) {
                try {
                    cb(UcpError::ShuttingDown, NULLPTR);
                } catch (...) {
                }
            }
        }

        if (NULLPTR != bindable_transport_) {
            bindable_transport_->Stop();
        }
        if (owns_transport_ && owned_transport_holder_) {
            owned_transport_holder_.reset();
            transport_ = NULLPTR;
            bindable_transport_ = NULLPTR;
            owns_transport_ = false;
        }
    }
    /**< entries vector goes out of scope at the nested-block end, destroying all
     *   ConnectionEntry instances.  Each entry's UcpConnection is destroyed via
     *   shared_ptr, whose destructor calls Dispose().  The PCB is NOT deleted by the
     *   connection (server_managed_ is true).  After all connections are fully
     *   destroyed, it is safe to release the PCB shared_ptrs below. */

    {
        std::lock_guard<std::mutex> lock(s_serverPcbMapMutex);
        s_serverPcbMap.clear();
    }
}

void UcpServer::Dispose() noexcept {
    Stop();
}

/** @brief Handles an inbound transport datagram: decodes, finds/creates connection, dispatches.
 *  @param datagram  Raw byte buffer received from the transport.
 *  @param remote    Source endpoint of the datagram. */
void UcpServer::OnTransportDatagram(const ucp::vector<uint8_t>& datagram, const Endpoint& remote) noexcept {
    if (datagram.empty()) {
        return;
    }

    ucp::shared_ptr<UcpPacket> packet;
    if (!UcpPacketCodec::TryDecode(datagram.data(), 0, datagram.size(), packet)) {
        return;
    }

    ucp::shared_ptr<ConnectionEntry> entry = GetOrCreateConnection(remote, *packet);
    if (NULLPTR == entry) {
        return;
    }

    // The connection/acceptedConnection shared_ptr fields are written by the
    // PCB worker thread (OnPcbConnected / DetachClosedEntry) and read here on
    // the transport (network) thread.  Use the atomic free functions to make
    // these cross-thread accesses well-defined (no data race on the shared_ptr
    // control block / pointee).
    UcpConnection* connection = NULLPTR;
    ucp::shared_ptr<UcpConnection> conn = std::atomic_load(&entry->connection);
    if (conn) {
        connection = conn.get();
    } else {
        ucp::shared_ptr<UcpConnection> accepted = std::atomic_load(&entry->acceptedConnection);
        connection = accepted ? accepted.get() : NULLPTR;
    }
    if (NULLPTR != connection) {
        connection->DispatchPacket(packet, remote);
    }
}

/** @brief Finds an existing connection entry or creates a new one from an incoming SYN packet.
 *  @param remote   Source endpoint of the packet.
 *  @param decoded  The decoded UcpPacket (must be valid).
 *  @return Shared pointer to the ConnectionEntry, or empty on failure. The shared_ptr copy
 *          pins the entry so a concurrent DetachClosedEntry (OnPcbClosed) cannot destroy it
 *          while the caller is using it. */
ucp::shared_ptr<UcpServer::ConnectionEntry> UcpServer::GetOrCreateConnection(const Endpoint& remote, const UcpPacket& decoded) noexcept {

    uint32_t connId = decoded.header.connection_id;
    UcpPcb* stalePcb = NULLPTR;
    ucp::shared_ptr<UcpPcb> stalePcbHolder;
    ucp::shared_ptr<ConnectionEntry> staleEntryToDestroy;

    std::unique_lock<std::mutex> lock(mutex_);
    if (!started_) {
        // After Stop(), no new connections may be created; a datagram that
        // raced Stop must not spawn an orphan PCB (+worker/notify/timer
        // threads) that nothing will tear down.
        return ucp::shared_ptr<ConnectionEntry>();
    }

    auto it = connections_.find(connId);
    if (connections_.end() != it) {
        bool replaceCollision = false;
        if (UcpPacketType::Syn == decoded.header.type) {
            const UcpControlPacket* synPacket = dynamic_cast<const UcpControlPacket*>(&decoded);
            uint64_t existingSessionKey = it->second->pcb->GetSessionKey();
            replaceCollision = NULLPTR != synPacket && 0 != synPacket->session_key && 0 != existingSessionKey &&
                               existingSessionKey != synPacket->session_key;
        }
        if (!replaceCollision) {
            it->second->pcb->SetRemoteEndpoint(remote);
            return it->second;
        }

        stalePcb = it->second->pcb;
        if (NULLPTR == it->second->acceptedConnection) {
            staleEntryToDestroy = std::move(it->second);
        }
        connections_.erase(it);
        {
            std::lock_guard<std::mutex> mapLock(s_serverPcbMapMutex);
            auto mapIt = s_serverPcbMap.find(connId);
            if (s_serverPcbMap.end() != mapIt && mapIt->second.get() == stalePcb) {
                stalePcbHolder = mapIt->second;
                s_serverPcbMap.erase(mapIt);
            }
        }
    }

    if (UcpPacketType::Syn == decoded.header.type && NULLPTR != network_) {
        const UcpControlPacket* synPacket = dynamic_cast<const UcpControlPacket*>(&decoded);
        if (NULLPTR != synPacket && 0 != synPacket->session_key) {
            auto existingPcb = network_->LookupBySessionKey(synPacket->session_key);
            if (nullptr != existingPcb) {
                uint32_t existingKey = existingPcb->GetConnectionId();
                auto existingIt = connections_.find(existingKey);
                if (connections_.end() != existingIt) {
                    existingIt->second->pcb->SetRemoteEndpoint(remote);
                    return existingIt->second;
                }
            }
        }
    }

    if (UcpPacketType::Syn != decoded.header.type) {
        return NULLPTR;
    }

    // SYN-flood guard: cap the number of live connection entries so a flood of
    // SYN packets with distinct CIDs cannot exhaust threads/memory (each PCB
    // spawns worker+notify+standalone-timer threads). New SYNs are dropped
    // once the cap is reached; established connections are unaffected.
    if (connections_.size() >= kMaxServerConnections) {
        return NULLPTR;
    }

    /**< Allocate a new server-side PCB via make_shared_object.
     *   The shared_ptr is stored in s_serverPcbMap to ensure proper cleanup
     *   when the connection is closed or the server stops. */
    auto pcbShared = ucp::make_shared_object<UcpPcb>(
        transport_, true, true, [this](UcpPcb* p) noexcept { OnPcbClosed(p); }, connId, config_.Clone(), network_);

    if (NULLPTR == pcbShared) {
        return NULLPTR;
    }

    UcpPcb* pcb = pcbShared.get();
    pcb->SetRemoteEndpoint(remote);

    if (network_) {
        network_->RegisterPcb(pcbShared);
    }

    {
        std::lock_guard<std::mutex> mapLock(s_serverPcbMapMutex);
        s_serverPcbMap[connId] = pcbShared;
    }

    auto connection = ucp::make_shared_object<UcpConnection>(pcb, transport_, config_.Clone(), network_);
    if (NULLPTR == connection) {
        {
            std::lock_guard<std::mutex> mapLock(s_serverPcbMapMutex);
            s_serverPcbMap.erase(connId);
        }
        return NULLPTR;
    }

    // The connection keeps the PCB alive via SetServerPcbHolder from the very
    // start (not only once accepted): for standalone servers (network_ == NULL)
    // the connection worker ticks the PCB on its own thread, and if the PCB
    // were freed on handshake-timeout/close before the connection is destroyed,
    // that tick would dereference freed memory (UAF).  Holding the shared_ptr
    // guarantees the PCB outlives the connection.
    connection->SetServerPcbHolder(pcbShared);

    auto entry = ucp::make_shared_object<ConnectionEntry>();
    if (NULLPTR == entry) {
        {
            std::lock_guard<std::mutex> mapLock(s_serverPcbMapMutex);
            s_serverPcbMap.erase(connId);
        }
        return NULLPTR;
    }
    entry->pcb = pcb;
    std::atomic_store(&entry->connection, connection);

    // Weak ref breaks the cycle pcb->Connected->entry->connection->pcb_holder;
    // the entry itself is kept alive by connections_ while the handshake runs.
    ucp::weak_ptr<ConnectionEntry> entryWeak = entry;
    pcb->SetConnected([this, entryWeak]() noexcept {
        ucp::shared_ptr<ConnectionEntry> entryHolder = entryWeak.lock();
        if (entryHolder) {
            OnPcbConnected(entryHolder.get());
        }
    });

    connections_[connId] = std::move(entry);
    ucp::shared_ptr<ConnectionEntry> result = connections_[connId];
    if (NULLPTR != stalePcb) {
        lock.unlock();
        stalePcb->Abort(true);
    }
    return result;
}

/** @brief Called when a PCB handshake completes; enqueues the connection for accept.
 *
 *  If a pending AcceptAsync callback exists, the connection is delivered
 *  immediately via the callback.  Otherwise the connection is queued in
 *  accept_queue_ for a future AcceptAsync call.
 *
 *  @param entry  The ConnectionEntry whose handshake just completed. */
void UcpServer::OnPcbConnected(ConnectionEntry* entry) noexcept {
    if (NULLPTR == entry) {
        return;
    }

    ucp::shared_ptr<UcpConnection> conn;
    AcceptAsyncCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (entry->accepted) {
            return;
        }
        entry->accepted = true;
        conn = std::atomic_load(&entry->connection);
        std::atomic_store(&entry->connection, ucp::shared_ptr<UcpConnection>());
        std::atomic_store(&entry->acceptedConnection, conn);
        if (NULLPTR != conn && NULLPTR != entry->pcb) {
            std::lock_guard<std::mutex> mapLock(s_serverPcbMapMutex);
            auto mapIt = s_serverPcbMap.find(entry->pcb->GetConnectionId());
            if (s_serverPcbMap.end() != mapIt && mapIt->second.get() == entry->pcb) {
                conn->SetServerPcbHolder(mapIt->second);
            }
        }
    }

    if (NULLPTR == conn) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(accept_mutex_);
        if (!accept_callbacks_.empty()) {
            callback = std::move(accept_callbacks_.front());
            accept_callbacks_.pop();
        } else {
            accept_queue_.push(conn);
            conn.reset();
        }
    }

    if (callback) {
        try {
            callback(UcpError::None, conn.get());
        } catch (...) {
        }
    }
}

ucp::shared_ptr<UcpServer::ConnectionEntry> UcpServer::DetachClosedEntry(UcpPcb* pcb) noexcept {
    ucp::shared_ptr<ConnectionEntry> entryToDestroy;
    if (NULLPTR == pcb) {
        return entryToDestroy;
    }

    uint32_t connId = pcb->GetConnectionId();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(connId);
        if (connections_.end() != it && NULLPTR != it->second && it->second->pcb == pcb) {
            // Regardless of whether the application holds a (non-owning)
            // wrapper pointer, the entry is the sole shared owner of the
            // connection; hand it to deferred cleanup so it is destroyed on a
            // background thread rather than the PCB's own worker thread.
            entryToDestroy = it->second;
            connections_.erase(it);
        }
    }

    {
        std::lock_guard<std::mutex> lock(s_serverPcbMapMutex);
        auto it = s_serverPcbMap.find(connId);
        if (s_serverPcbMap.end() != it && it->second.get() == pcb) {
            s_serverPcbMap.erase(it);
        }
    }
    return entryToDestroy;
}

/** @brief Called when a PCB closes; removes the connection entry from the map
 *  and releases the PCB's shared_ptr so its memory is properly freed.
 *  The entry is destroyed on a background cleanup thread (never the PCB's own
 *  worker thread) to avoid destroying the connection/PCB from within the very
 *  worker that is executing the close transition. */
void UcpServer::OnPcbClosed(UcpPcb* pcb) noexcept {
    ucp::shared_ptr<ConnectionEntry> entryToDestroy = DetachClosedEntry(pcb);
    /**< entryToDestroy is handed to the deferred-cleanup thread, releasing the
     *   shared_ptr to the ConnectionEntry and its UcpConnection from a thread
     *   that is not any of their workers.  The UcpConnection destructor calls
     *   Dispose(), which stops the worker and cleans up transport.  The PCB is
     *   NOT deleted by the connection (server_managed_ is true). */
    DeferDestroyEntry(std::move(entryToDestroy));
}

void UcpServer::ScheduleFairQueueRound() noexcept {
    if (NULLPTR == network_) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!started_) {
        return;
    }

    int64_t delayUs = std::max<int64_t>(PcbConst::MIN_TIMER_WAIT_MILLISECONDS * Constants::MICROS_PER_MILLI,
                                        config_.FairQueueRoundMilliseconds * Constants::MICROS_PER_MILLI);

    fair_queue_timer_id_ = network_->AddTimer(network_->GetNowMicroseconds() + delayUs, [this]() noexcept { OnFairQueueRound(); });
}

void UcpServer::OnFairQueueRound() noexcept {
    OnFairQueueRoundCore();
    if (NULLPTR != network_) {
        ScheduleFairQueueRound();
    }
}

/** @brief Core fair-queue logic: collects active connections, computes credits
 *  proportional to each connection's UCP pacing rate, distributes credits,
 *  and flushes each connection in rotated round-robin order. */
void UcpServer::OnFairQueueRoundCore() noexcept {
    ucp::vector<ucp::shared_ptr<UcpConnection>> active;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : connections_) {
            auto& entry = pair.second;
            if (NULLPTR == entry || false == entry->accepted) {
                continue;
            }
            ucp::shared_ptr<UcpConnection> connection = std::atomic_load(&entry->connection);
            if (NULLPTR == connection) {
                connection = std::atomic_load(&entry->acceptedConnection);
            }
            if (NULLPTR == connection) {
                continue;
            }

            auto state = connection->GetState();
            if ((UcpConnectionState::Established == state || UcpConnectionState::ClosingFinSent == state ||
                 UcpConnectionState::ClosingFinReceived == state) &&
                connection->HasPendingSendData()) {
                active.push_back(std::move(connection));
            }
        }
    }

    int64_t nowUs = NULLPTR != network_ ? network_->GetCurrentTimeUs() : UcpTime::NowMicroseconds();

    if (active.empty()) {
        last_fair_queue_round_micros_ = nowUs;
        return;
    }

    if (active.size() <= 1) {
        active[0]->SetUncappedFairQueueCredit();
        active[0]->RequestFlush();
        last_fair_queue_round_micros_ = nowUs;
        return;
    }

    int64_t elapsedUs = (0 == last_fair_queue_round_micros_) ? config_.FairQueueRoundMilliseconds * Constants::MICROS_PER_MILLI
                                                             : nowUs - last_fair_queue_round_micros_;

    if (elapsedUs < Constants::MICROS_PER_MILLI) {
        elapsedUs = Constants::MICROS_PER_MILLI;
    }

    int64_t maxElapsed = config_.FairQueueRoundMilliseconds * Constants::MICROS_PER_MILLI * Constants::MaxBufferedFairQueueRounds;
    if (elapsedUs > maxElapsed) {
        elapsedUs = maxElapsed;
    }

    last_fair_queue_round_micros_ = nowUs;

    double roundBytes =
        static_cast<double>(bandwidth_limit_bytes_per_sec_) * (static_cast<double>(elapsedUs) / Constants::MICROS_PER_SECOND);
    double fairShareCap = static_cast<double>(bandwidth_limit_bytes_per_sec_) / active.size();

    double effectiveTotal = 0.0;
    ucp::vector<double> effectivePacing(active.size());

    for (size_t i = 0; i < active.size(); ++i) {
        double pacing = active[i]->GetCurrentPacingRateBytesPerSecond();
        if (0 >= pacing) {
            pacing = fairShareCap;
        }
        if (pacing > fairShareCap) {
            pacing = fairShareCap;
        }
        effectivePacing[i] = pacing;
        effectiveTotal += pacing;
    }

    if (0 >= effectiveTotal) {
        effectiveTotal = static_cast<double>(active.size());
    }

    for (size_t i = 0; i < active.size(); ++i) {
        double credit = (effectivePacing[i] / effectiveTotal) * roundBytes;
        active[i]->AddFairQueueCredit(credit);
    }

    int startIndex = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fair_queue_start_index_ >= static_cast<int>(active.size())) {
            fair_queue_start_index_ = 0;
        }
        startIndex = fair_queue_start_index_;
        fair_queue_start_index_++;
    }

    for (int i = 0; i < static_cast<int>(active.size()); ++i) {
        int index = (startIndex + i) % static_cast<int>(active.size());
        active[index]->RequestFlush();
    }
}

} // namespace ucp
