/** @file ucp_connection.cpp
 *  @brief High-level public UCP connection implementation -- mirrors C# Ucp.UcpConnection.
 *
 *  Wraps a UcpPcb behind a thread-safe async API with a serial worker queue.
 *  All public-facing operations (connect, send, receive, close) are enqueued
 *  onto a single worker thread that executes them in order, avoiding the need
 *  for the caller to manage thread safety internally.
 *
 *  Priority items (NAK packet dispatch) are enqueued at the front of the queue
 *  to ensure fast retransmission.  The worker thread processes items one at a
 *  time, invoking callbacks asynchronously without blocking.
 *
 *  OnTransportDatagram decodes inbound datagrams via UcpPacketCodec::TryDecode,
 *  validates the connection ID and remote endpoint, and dispatches to the PCB.
 */

#include "ucp/ucp_connection.h"
#include "ucp/internal/ucp_pcb.h"
#include "ucp/ucp_packet_codec.h"
#include "ucp/ucp_packets.h"
#include "ucp/transport/udp_socket_transport.h"
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"
#include "ucp/ucp_time.h"
#include <stdexcept>
#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstring>
#include <future>
#include <memory>

namespace {

std::mutex s_pcbSharedMapMutex;

/** @brief Stores UcpPcb shared-ownership pointers keyed by raw UcpConnection pointer.
 *
 *  When a non-server-managed UcpConnection creates a PCB via
 *  ucp::make_shared_object the resulting shared_ptr is stored here so that
 *  the PCB stays alive until the connection is disposed.  The entry is
 *  erased in Dispose(). */
ucp::map<const void*, ucp::shared_ptr<ucp::UcpPcb>> s_pcbSharedMap;

} // namespace

namespace ucp {

/** @brief Parses an "address:port" string into an Endpoint.
 *  @param str  The string to parse in "host:port" format.
 *  @return The parsed Endpoint; port defaults to 0 if no colon is present. */
Endpoint Endpoint::Parse(const ucp::string& str) noexcept {
    Endpoint ep;
    auto tryParsePort = [](const ucp::string& s) noexcept -> int {
        try {
            return std::stoi(s);
        } catch (const std::exception&) {
            return 0;
        }
    };
    if (!str.empty() && '[' == str[0]) {
        auto close = str.find(']');
        if (ucp::string::npos != close) {
            ep.address = str.substr(1, close - 1);
            if (close + 1 < str.size() && ':' == str[close + 1]) {
                ep.port = static_cast<uint16_t>(tryParsePort(str.substr(close + 2)));
            }
        } else {
            ep.address = str;
        }
    } else {
        auto colon = str.rfind(':');
        if (ucp::string::npos != colon && str.find(':') == colon) {
            ep.address = str.substr(0, colon);
            ep.port = static_cast<uint16_t>(tryParsePort(str.substr(colon + 1)));
        } else if (ucp::string::npos != colon) {
            int port = tryParsePort(str.substr(colon + 1));
            if (0 != port) {
                ep.address = str.substr(0, colon);
                ep.port = static_cast<uint16_t>(port);
            } else {
                ep.address = str;
                ep.port = 0;
            }
        } else {
            ep.address = str;
            ep.port = 0;
        }
    }
    return ep;
}

/** @brief Serialises this Endpoint to "address:port" string form.
 *  @return String representation in "host:port" format. */
ucp::string Endpoint::ToString() const noexcept {

    if (address.size() > 7 && 0 == address.compare(0, 7, "::ffff:")) {
        ucp::string plain4 = address.substr(7);
        return plain4 + ":" + std::to_string(port);
    }
    if (ucp::string::npos != address.find(':')) {
        return "[" + address + "]:" + std::to_string(port);
    }
    return address + ":" + std::to_string(port);
}

UcpConnection::UcpConnection(transport::ITransport* transport, bool ownsTransport, const UcpConfiguration& config,
                             UcpNetwork* network) noexcept
    : UcpConnection(transport, ownsTransport, false, config, network) {}

/** @brief Full internal constructor with an explicit server-managed flag.
 *  @param transport     Underlying transport pointer (may be NULLPTR).
 *  @param ownsTransport True if this connection owns and will dispose the transport.
 *  @param serverManaged True if this connection is managed by a UcpServer.
 *  @param config        Connection configuration (cloned internally).
 *  @param network       Owning UcpNetwork (NULLPTR for standalone connections). */
UcpConnection::UcpConnection(transport::ITransport* transport, bool ownsTransport, bool serverManaged, const UcpConfiguration& config,
                             UcpNetwork* network) noexcept
    : transport_(transport), owns_transport_(ownsTransport), server_managed_(serverManaged), config_(config), network_(network) {
    if (owns_transport_ && NULLPTR != transport_) {
        owned_transport_holder_.reset(transport_);
        transport_ = owned_transport_holder_.get();
    }
    bindable_transport_ = dynamic_cast<transport::IBindableTransport*>(transport_);
    if (!server_managed_) {
        SubscribeTransport();
    }
    EnsureWorkerStarted();
}

UcpConnection::UcpConnection() noexcept : UcpConnection(NULLPTR, true, UcpConfiguration(), NULLPTR) {
    owned_transport_holder_ = ucp::make_shared_object<transport::UdpSocketTransport>();
    transport_ = owned_transport_holder_.get();
    bindable_transport_ = dynamic_cast<transport::IBindableTransport*>(transport_);
    SubscribeTransport();
}

UcpConnection::UcpConnection(const UcpConfiguration& config) noexcept : UcpConnection(NULLPTR, true, config, NULLPTR) {
    owned_transport_holder_ = ucp::make_shared_object<transport::UdpSocketTransport>();
    transport_ = owned_transport_holder_.get();
    bindable_transport_ = dynamic_cast<transport::IBindableTransport*>(transport_);
    SubscribeTransport();
}

UcpConnection::UcpConnection(transport::ITransport* transport) noexcept : UcpConnection(transport, true, UcpConfiguration(), NULLPTR) {}

UcpConnection::UcpConnection(transport::ITransport* transport, bool ownsTransport) noexcept
    : UcpConnection(transport, ownsTransport, UcpConfiguration(), NULLPTR) {}

/** @brief Server-accept constructor: wraps an existing PCB created by a UcpServer.
 *  The connection does not own the transport or the PCB lifetime. */
UcpConnection::UcpConnection(UcpPcb* pcb, transport::ITransport* transport, const UcpConfiguration& config) noexcept
    : UcpConnection(pcb, transport, config, NULLPTR) {}

UcpConnection::UcpConnection(UcpPcb* pcb, transport::ITransport* transport, const UcpConfiguration& config, UcpNetwork* network) noexcept
    : UcpConnection(transport, false, true, config, network) {
    AttachPcb(pcb);
}

UcpConnection::~UcpConnection() noexcept {
    try {
        Dispose();
    } catch (...) {
    }
    // If we are the worker thread (the connection was destroyed from within a
    // callback executing on its own worker -- e.g. a server-side connection
    // whose entry is the sole owner), Dispose's StopWorker could not join us.
    // Detach so the std::thread object does not remain joinable when this
    // object is destroyed (that would std::terminate).  The worker loop
    // observes *alive == false and exits without touching members again.
    if (worker_thread_.joinable() && std::this_thread::get_id() == worker_thread_.get_id()) {
        worker_thread_.detach();
    }
}

/** @brief Starts the background serial worker thread if not already running.
 *  Restartable after StopWorker: resets worker_should_start_ to allow restart. */
void UcpConnection::StartWorker() noexcept {
    worker_should_start_.store(false);
    EnsureWorkerStarted();
}

/** @brief Signals the worker to stop and joins its thread.
 *  All pending work items are drained before the join completes. */
void UcpConnection::StopWorker() noexcept {
    bool onWorkerThread = (worker_thread_.joinable() && std::this_thread::get_id() == worker_thread_.get_id());
    if (!onWorkerThread && worker_thread_.joinable()) {
        // Set the joining flag BEFORE stopping: the worker loop checks
        // (stopped_ && !joining_) to decide whether to self-detach.  Ordering
        // joining_ before stopped_ guarantees that once the worker observes
        // stopped_=true (written by this external thread), joining_ is already
        // true, so it will never detach concurrently with our join() below
        // (detach+join on the same std::thread is UB / std::terminate).
        joining_.store(true, std::memory_order_release);
    }
    stopped_ = true;
    cv_.notify_all();
    if (onWorkerThread) {
        // The caller is the worker itself (user callback invoked Dispose).
        // We cannot join ourselves.  Detach now: WorkerLoop observes
        // *alive == false (set by Dispose) right after work() returns and
        // returns without touching any member, so detaching here is safe and
        // guarantees the std::thread object is not joinable when the object is
        // later destroyed (by the deferred-cleanup thread or the destructor).
        if (worker_thread_.joinable()) {
            worker_thread_.detach();
        }
        return;
    }
    if (worker_thread_.joinable()) {
        worker_thread_.join();
        joining_.store(false, std::memory_order_release);
    }
}

/** @brief Main worker thread loop: dequeues work items and ticks PCB periodically.
 *  Worker exits naturally when stopped_ is set; StopWorker handles join(). */
void UcpConnection::WorkerLoop() noexcept {
    worker_thread_id_ = std::this_thread::get_id();
    // Capture the alive flag OUTSIDE the loop: it is self-held (make_shared,
    // outlives this object), so after work() destroys the connection we can
    // still read it to decide whether to exit without touching any member.
    ucp::shared_ptr<std::atomic<bool>> alive = alive_flag_;
    while (!stopped_) {
        ucp::function<void()> work;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(50), [this]() noexcept { return !queue_.empty() || stopped_; });
            if (stopped_ && queue_.empty()) {
                break;
            }
            if (!queue_.empty()) {
                work = std::move(queue_.front());
                queue_.pop_front();
            }
        }
        if (work) {
            try {
                work();
            } catch (...) {
            }
        }

        // If the object was destroyed from within work() (e.g. a server-side
        // connection whose entry is the sole owner, destroyed in the worker
        // thread via TransitionToClosed -> OnPcbClosed), the destructor
        // detached us.  *alive is self-held (outlives the object), so check
        // the LOCAL copy FIRST and return without touching any other member.
        if (!alive || !alive->load(std::memory_order_acquire)) {
            return;
        }

        if (NULLPTR == network_) {
            // Snapshot the pcb as a shared_ptr so a PCB destroyed from within a
            // work item (e.g. an un-accepted server PCB whose last reference is
            // released in TransitionToClosed) cannot leave a dangling pcb_
            // dereference here.
            ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
            if (NULLPTR != pcb) {
                try {
                    pcb->OnTick(UcpTime::NowMicroseconds());
                } catch (...) {
                }
            }
        }
        if (stopped_ && worker_thread_.joinable() && std::this_thread::get_id() == worker_thread_.get_id()) {
            // Dispose was called from a user callback on this thread: StopWorker
            // could not join us, so detach here after the loop has stopped
            // touching members. The std::thread object must not remain
            // joinable when the owning object is destroyed (that would
            // std::terminate).
            // If an external thread is concurrently joining (joining_ set),
            // do NOT detach: detach+join on the same std::thread races; the
            // joiner will reap the thread as soon as we return.
            if (!joining_.load(std::memory_order_acquire)) {
                worker_thread_.detach();
            }
            return;
        }
    }
}

/** @brief Enqueues a work item at the back of the serial queue (normal priority).
 *  @param work  Callable to execute on the worker thread. */
void UcpConnection::Enqueue(ucp::function<void()> work) noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(std::move(work));
    }
    cv_.notify_one();
}

/** @brief Enqueues a work item at the front of the serial queue (priority / NAK dispatch).
 *  @param work  Callable to execute on the worker thread. */
void UcpConnection::EnqueuePriority(ucp::function<void()> work) noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_front(std::move(work));
    }
    cv_.notify_one();
}

/** @brief Ensures the worker thread has been started (idempotent).
 *  Uses compare_exchange to avoid TOCTOU between check and start (BUG 5 fix). */
void UcpConnection::EnsureWorkerStarted() noexcept {
    bool expected = false;
    if (worker_should_start_.compare_exchange_strong(expected, true)) {
        stopped_ = false;
        worker_thread_ = std::thread(&UcpConnection::WorkerLoop, this);
    }
}

void UcpConnection::SubscribeTransport() noexcept {
    if (transport_subscribed_) {
        return;
    }
    if (NULLPTR == transport_) {
        return;
    }
    transport_token_ = transport_->AddOnDatagram(
        [this, alive = alive_flag_](const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept {
            // The transport fires a snapshot of subscribers outside its lock;
            // this connection may have been destroyed after the snapshot was
            // taken but before this callback runs.  alive_flag_ is self-held
            // (outlives this object), so check the local copy first.
            if (!alive || !alive->load(std::memory_order_acquire)) {
                return;
            }
            OnTransportDatagram(data, remote);
        });
    transport_subscribed_ = true;
}

/** @brief Cleans up the transport subscription and, when the connection owns the transport,
 *  stops the bindable transport and releases ownership via the shared_ptr holder.
 *  If the transport is externally owned, only the datagram subscription is removed. */
void UcpConnection::CleanupTransport() noexcept {

    if (!server_managed_ && transport_subscribed_ && NULLPTR != transport_) {
        transport_->RemoveOnDatagram(transport_token_);
        transport_subscribed_ = false;
        transport_token_ = 0;
    }
    if (owns_transport_) {
        if (NULLPTR != bindable_transport_) {
            bindable_transport_->Stop();
        }
        if (owned_transport_holder_) {
            owned_transport_holder_.reset();
        }
        transport_ = NULLPTR;
        bindable_transport_ = NULLPTR;
        owns_transport_ = false;
    }
}

/** @brief Binds a UcpPcb to this connection and wires up registered event callbacks.
 *  @param pcb  The protocol control block to attach (may be NULLPTR).
 *  @note Holds mutex_ to prevent race with SetOnData/SetOnConnected/SetOnDisconnected (BUG 1 fix).
 *  The pcb callback install uses the PCB's thread-safe setters so the assignment is
 *  synchronized with the pcb worker's fire side; lock order is pcb-lock -> mutex_
 *  (never reversed). */
void UcpConnection::AttachPcb(UcpPcb* pcb) noexcept {
    pcb_ = pcb;
    if (NULLPTR != pcb_) {
        connection_id_ = pcb_->GetConnectionId();
        {
            Endpoint ep;
            if (pcb_->TryGetRemoteEndpoint(ep)) {
                std::lock_guard<std::mutex> lock(mutex_);
                remote_endpoint_ = ep;
            }
        }
        ucp::vector<DataCallback> dataSnapshot;
        ucp::vector<StateCallback> connectedSnapshot;
        ucp::vector<StateCallback> disconnectedSnapshot;
        bool anyData = false, anyConnected = false, anyDisconnected = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            anyData = !on_data_callbacks_.empty();
            anyConnected = !on_connected_callbacks_.empty();
            anyDisconnected = !on_disconnected_callbacks_.empty();
            dataSnapshot = on_data_callbacks_;
            connectedSnapshot = on_connected_callbacks_;
            disconnectedSnapshot = on_disconnected_callbacks_;
        }
        // Install callbacks outside mutex_ via the PCB's thread-safe setters.
        // Capture the self-held alive flag BY VALUE: the PCB (held by the
        // network's shared_ptr snapshot on the dispatch thread) may outlive the
        // connection, so the callback must not read this->alive_flag_ after the
        // connection is destroyed (that read itself would be a UAF).
        if (anyData) {
            pcb_->SetDataReceived([this, alive = alive_flag_, dataSnapshot = std::move(dataSnapshot)](const uint8_t* data, int offset, int length) {
                if (!alive || !alive->load(std::memory_order_acquire))
                    return;
                for (auto& cb : dataSnapshot) {
                    try {
                        cb(data, offset, length);
                    } catch (...) {
                    }
                }
            });
        }
        if (anyConnected) {
            pcb_->SetConnected([this, alive = alive_flag_, connectedSnapshot = std::move(connectedSnapshot)]() {
                if (!alive || !alive->load(std::memory_order_acquire))
                    return;
                for (auto& cb : connectedSnapshot) {
                    try {
                        cb();
                    } catch (...) {
                    }
                }
            });
        }
        if (anyDisconnected) {
            pcb_->SetDisconnected([this, alive = alive_flag_, disconnectedSnapshot = std::move(disconnectedSnapshot)]() {
                if (!alive || !alive->load(std::memory_order_acquire))
                    return;
                for (auto& cb : disconnectedSnapshot) {
                    try {
                        cb();
                    } catch (...) {
                    }
                }
            });
        }
    }
}

/** @brief Asynchronously connects to a remote endpoint using the standalone transport.
 *  Uses callback-based async to avoid blocking the worker thread (Proactor pattern).
 *  @param remoteEndpoint  "address:port" string of the remote peer.
 *  @param callback        Callback invoked when handshake completes (error=None on success). */
void UcpConnection::ConnectAsync(const ucp::string& remoteEndpoint, ConnectAsyncCallback callback) noexcept {
    EnsureWorkerStarted();

    Enqueue([this, callback, remoteEndpoint]() noexcept {
        try {
            Endpoint ep = Endpoint::Parse(remoteEndpoint);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                remote_endpoint_ = ep;
            }

            if (NULLPTR == pcb_) {
                if (NULLPTR == transport_) {
                    owned_transport_holder_ = ucp::make_shared_object<transport::UdpSocketTransport>();
                    transport_ = owned_transport_holder_.get();
                    bindable_transport_ = dynamic_cast<transport::IBindableTransport*>(transport_);
                    owns_transport_ = true;
                    SubscribeTransport();
                }
                if (NULLPTR != bindable_transport_) {
                    bindable_transport_->Start(0);
                }
                auto pcbShared = ucp::make_shared_object<UcpPcb>(transport_, false, false, NULLPTR, 0, config_.Clone(), network_);
                if (NULLPTR == pcbShared) {
                    if (callback) {
                        try {
                            callback(UcpError::InternalError, 0);
                        } catch (...) {
                        }
                    }
                    return;
                }
                pcb_ = pcbShared.get();
                if (network_) {
                    network_->RegisterPcb(pcbShared);
                }
                {
                    std::lock_guard<std::mutex> lock(s_pcbSharedMapMutex);
                    s_pcbSharedMap[this] = pcbShared;
                }
                AttachPcb(pcb_);
            }

            pcb_->ConnectAsync(ep, callback);
        } catch (const std::exception&) {
            if (callback) {
                try {
                    callback(UcpError::InternalError, 0);
                } catch (...) {
                }
            }
        }
    });
}

/** @brief Asynchronously connects to a remote endpoint via a specific UcpNetwork (multiplexed transport).
 *  Uses callback-based async to avoid blocking the worker thread (Proactor pattern).
 *  @param network         The UcpNetwork through which to route traffic.
 *  @param remoteEndpoint  "address:port" string of the remote peer.
 *  @param callback        Callback invoked when handshake completes (error=None on success). */
void UcpConnection::ConnectAsync(UcpNetwork* network, const ucp::string& remoteEndpoint, ConnectAsyncCallback callback) noexcept {
    if (NULLPTR == network) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, 0);
            } catch (...) {
            }
        }
        return;
    }

    EnsureWorkerStarted();

    Enqueue([this, callback, network, remoteEndpoint]() noexcept {
        try {

            if (transport_subscribed_ && NULLPTR != transport_) {
                transport_->RemoveOnDatagram(transport_token_);
                transport_subscribed_ = false;
                transport_token_ = 0;
            }
            if (owns_transport_ && NULLPTR != bindable_transport_) {
                bindable_transport_->Stop();
            }

            transport_ = network->GetTransportAdapter();
            bindable_transport_ = network->GetTransportAdapter();
            if (owns_transport_ && owned_transport_holder_) {
                owned_transport_holder_.reset();
            }
            owns_transport_ = false;
            server_managed_ = false;
            network_ = network;
            SubscribeTransport();

            Endpoint ep = Endpoint::Parse(remoteEndpoint);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                remote_endpoint_ = ep;
            }

            if (NULLPTR == pcb_) {
                auto pcbShared = ucp::make_shared_object<UcpPcb>(transport_, false, false, NULLPTR, 0, config_.Clone(), network_);
                if (NULLPTR == pcbShared) {
                    if (callback) {
                        try {
                            callback(UcpError::InternalError, 0);
                        } catch (...) {
                        }
                    }
                    return;
                }
                pcb_ = pcbShared.get();
                if (network_) {
                    network_->RegisterPcb(pcbShared);
                }
                {
                    std::lock_guard<std::mutex> lock(s_pcbSharedMapMutex);
                    s_pcbSharedMap[this] = pcbShared;
                }
                AttachPcb(pcb_);
            }

            pcb_->ConnectAsync(ep, callback);
        } catch (const std::exception&) {
            if (callback) {
                try {
                    callback(UcpError::InternalError, 0);
                } catch (...) {
                }
            }
        }
    });
}

/** @brief Synchronous send with Normal priority - may block caller thread.
 *  @param buf     Source buffer.
 *  @param offset  Byte offset in buffer.
 *  @param count   Number of bytes to send.
 *  @return Number of bytes accepted, or -1 on error. */
int UcpConnection::Send(const uint8_t* buf, size_t offset, size_t count) noexcept {
    return Send(buf, offset, count, UcpPriority::Normal);
}

/** @brief Synchronous send with explicit priority - may block caller thread.
 *  @param buf      Source buffer.
 *  @param offset   Byte offset in buffer.
 *  @param count    Number of bytes to send.
 *  @param priority QoS priority.
 *  @return Number of bytes accepted, or -1 on error. */
int UcpConnection::Send(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority) noexcept {
    if (NULLPTR == pcb_) {
        return -1;
    }
    if (offset > INT_MAX || count > INT_MAX) {
        return -1;
    }
    if (worker_thread_id_.load() == std::this_thread::get_id()) {
        ucp::shared_ptr<ucp::UcpPcb> pcbW = GetPcbSnapshot();
        if (NULLPTR == pcbW) {
            return -1;
        }
        return pcbW->Send(buf, static_cast<int>(offset), static_cast<int>(count), priority);
    }
    // Clamp to the protocol message ceiling before allocating a copy, so an
    // oversized count cannot trigger a multi-GB allocation (OOM -> terminate
    // in the noexcept path). MSS(1220) * 65535 fragments is the protocol
    // ceiling; the UcpPcb sender enforces the same bound.
    int cappedCount = static_cast<int>(count);
    int64_t maxAllowed = (int64_t)Constants::MSS * 65535;
    if (maxAllowed > INT_MAX) {
        maxAllowed = INT_MAX;
    }
    if (cappedCount > (int)maxAllowed) {
        cappedCount = (int)maxAllowed;
    }
    // Send directly on the PCB: UcpPcb::Send serializes internally via its own
    // worker queue and deep-copies the payload for its async lifetime, so the
    // previous conn-worker round-trip (copy into `data`, Enqueue, worker hops)
    // was a redundant full-buffer copy plus an extra thread hop.  Holding a
    // snapshot keeps the PCB alive across a concurrent Dispose().
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        return -1;
    }
    return pcb->Send(buf, static_cast<int>(offset), cappedCount, priority);
}

/** @brief Asynchronous send with Normal priority - non-blocking callback.
 *  @param buf      Source buffer.
 *  @param offset   Byte offset in buffer.
 *  @param count    Number of bytes to send.
 *  @param callback Callback invoked when send completes. */
void UcpConnection::SendAsync(const uint8_t* buf, size_t offset, size_t count, SendAsyncCallback callback) noexcept {
    SendAsync(buf, offset, count, UcpPriority::Normal, std::move(callback));
}

/** @brief Asynchronous send with explicit priority - non-blocking callback.
 *  @param buf      Source buffer.
 *  @param offset   Byte offset in buffer.
 *  @param count    Number of bytes to send.
 *  @param priority QoS priority.
 *  @param callback Callback invoked when send completes. */
void UcpConnection::SendAsync(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority, SendAsyncCallback callback) noexcept {
    if (offset > INT_MAX || count > INT_MAX) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, -1);
            } catch (...) {
            }
        }
        return;
    }
    // Snapshot the pcb under the shared-map lock so a concurrent Dispose()
    // cannot free it between our null-check and use (bare pcb_ would be a
    // use-after-free).
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        if (callback) {
            try {
                callback(UcpError::NotConnected, -1);
            } catch (...) {
            }
        }
        return;
    }
    pcb->SendAsync(buf, static_cast<int>(offset), static_cast<int>(count), priority, std::move(callback));
}

/** @brief Synchronous receive - may block caller thread.
 *  @param buf     Destination buffer.
 *  @param offset  Write offset in destination.
 *  @param count   Maximum bytes to receive.
 *  @return Number of bytes copied, 0 if closed, -1 on error.
 *  @note Uses async variant when on the worker thread to avoid deadlock (BUG 6 fix). */
int UcpConnection::Receive(uint8_t* buf, size_t offset, size_t count) noexcept {
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        return -1;
    }
    if (offset > INT_MAX || count > INT_MAX) {
        return -1;
    }

    if (worker_thread_id_.load() == std::this_thread::get_id()) {
        return pcb->Receive(buf, static_cast<int>(offset), static_cast<int>(count));
    }
    auto p = std::make_shared<std::promise<int>>();
    auto f = p->get_future();
    auto dst = ucp::make_shared_object<ucp::vector<uint8_t>>(count);
    if (NULLPTR == dst) {
        return -1;
    }
    auto len = static_cast<int>(count);
    Enqueue([p, dst, len, pcb]() mutable {
        p->set_value(pcb->Receive(dst->data(), 0, len));
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    int n = -1;
    while (n < 0) {
        if (f.wait_for(std::chrono::milliseconds(10)) == std::future_status::ready) {
            n = f.get();
            break;
        }
        if (std::chrono::steady_clock::now() > deadline)
            break;
    }
    if (n > 0)
        std::memcpy(buf + offset, dst->data(), static_cast<size_t>(n));
    return n;
}

/** @brief Snapshot the current pcb as a shared_ptr so async entry points can
 *  safely use it across a concurrent Dispose() (which frees the bare pcb_).
 *  Returns null if the connection is disposed/not attached. */
ucp::shared_ptr<ucp::UcpPcb> UcpConnection::GetPcbSnapshot() const noexcept {
    if (server_managed_) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (NULLPTR != pcb_holder_) {
            return pcb_holder_;
        }
        // Server-managed connection without a holder (bare-pcb constructor:
        // the caller owns the pcb and keeps it alive). Snapshot the raw
        // pointer; Dispose() nulls pcb_ under mutex_, so the aliasing
        // shared_ptr (no ownership) remains valid for the caller's lifetime.
        if (NULLPTR != pcb_) {
            return ucp::shared_ptr<ucp::UcpPcb>(ucp::shared_ptr<ucp::UcpPcb>(), pcb_);
        }
        return ucp::shared_ptr<ucp::UcpPcb>();
    }
    {
        std::lock_guard<std::mutex> lock(s_pcbSharedMapMutex);
        auto it = s_pcbSharedMap.find(this);
        if (it != s_pcbSharedMap.end()) {
            return it->second;
        }
    }
    // Non-server-managed connection without a map entry (bare-pcb
    // constructor): same aliasing fallback.
    std::lock_guard<std::mutex> lock(mutex_);
    if (NULLPTR == pcb_) {
        return ucp::shared_ptr<ucp::UcpPcb>();
    }
    return ucp::shared_ptr<ucp::UcpPcb>(ucp::shared_ptr<ucp::UcpPcb>(), pcb_);
}

/** @brief Asynchronous receive - non-blocking callback.
 *  @param buf      Destination buffer.
 *  @param offset   Write offset in destination.
 *  @param count    Maximum bytes to receive.
 *  @param callback Callback invoked when receive completes (0 bytes = closed). */
void UcpConnection::ReceiveAsync(uint8_t* buf, size_t offset, size_t count, ReceiveAsyncCallback callback) noexcept {
    if (offset > INT_MAX || count > INT_MAX) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, -1);
            } catch (...) {
            }
        }
        return;
    }
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        if (callback) {
            try {
                callback(UcpError::NotConnected, -1);
            } catch (...) {
            }
        }
        return;
    }
    pcb->ReceiveAsync(buf, static_cast<int>(offset), static_cast<int>(count), std::move(callback));
}

/** @brief Synchronous exact-byte-count read - may block caller thread.
 *  @param buf   Destination buffer.
 *  @param off   Write offset in destination.
 *  @param count Number of bytes to read.
 *  @return True if count bytes were received, false on error or premature close.
 *  @note Uses async variant when on the worker thread to avoid deadlock (BUG 6 fix). */
bool UcpConnection::Read(uint8_t* buf, size_t off, size_t count) noexcept {
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        return false;
    }
    if (off > INT_MAX || count > INT_MAX) {
        return false;
    }
    if (worker_thread_id_.load() == std::this_thread::get_id()) {
        return pcb->Read(buf, static_cast<int>(off), static_cast<int>(count));
    }
    auto p = std::make_shared<std::promise<bool>>();
    auto f = p->get_future();
    auto dst = ucp::make_shared_object<ucp::vector<uint8_t>>(count);
    if (!dst) {
        // Allocation failed on a noexcept path: return failure instead of
        // dereferencing null below (mirrors Receive's null check).
        return false;
    }
    auto len = static_cast<int>(count);
    Enqueue([p, dst, len, pcb]() mutable {
        p->set_value(pcb->Read(dst->data(), 0, len));
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool ok = false;
    while (!ok) {
        if (f.wait_for(std::chrono::milliseconds(10)) == std::future_status::ready) {
            ok = f.get();
            break;
        }
        if (std::chrono::steady_clock::now() > deadline)
            break;
    }
    if (ok)
        std::memcpy(buf + off, dst->data(), count);
    return ok;
}

/** @brief Asynchronous exact-byte-count read - non-blocking callback.
 *  Loops ReceiveAsync until count bytes are accumulated.
 *  @param buf      Destination buffer.
 *  @param off      Write offset in destination.
 *  @param count    Number of bytes to read.
 *  @param callback Callback invoked when read completes (success=false if closed before full read). */
void UcpConnection::ReadAsync(uint8_t* buf, size_t off, size_t count, ReadAsyncCallback callback) noexcept {
    if (off > INT_MAX || count > INT_MAX) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, false);
            } catch (...) {
            }
        }
        return;
    }
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        if (callback) {
            try {
                callback(UcpError::NotConnected, false);
            } catch (...) {
            }
        }
        return;
    }
    pcb->ReadAsync(buf, static_cast<int>(off), static_cast<int>(count), std::move(callback));
}

/** @brief Synchronous exact-byte-count write (Normal priority) - may block caller thread.
 *  @param buf   Source buffer.
 *  @param off   Byte offset in buffer.
 *  @param count Number of bytes to write.
 *  @return True if all bytes were accepted for sending. */
bool UcpConnection::Write(const uint8_t* buf, size_t off, size_t count) noexcept {
    return Write(buf, off, count, UcpPriority::Normal);
}

/** @brief Synchronous exact-byte-count write with explicit priority - may block caller thread.
 *  @param buf      Source buffer.
 *  @param off      Byte offset in buffer.
 *  @param count    Number of bytes to write.
 *  @param priority QoS priority.
 *  @return True if all bytes were accepted for sending. */
bool UcpConnection::Write(const uint8_t* buf, size_t off, size_t count, UcpPriority priority) noexcept {
    if (NULLPTR == pcb_) {
        return false;
    }
    if (off > INT_MAX || count > INT_MAX) {
        return false;
    }
    if (worker_thread_id_.load() == std::this_thread::get_id()) {
        ucp::shared_ptr<ucp::UcpPcb> pcbW = GetPcbSnapshot();
        if (NULLPTR == pcbW) {
            return false;
        }
        return pcbW->Write(buf, static_cast<int>(off), static_cast<int>(count), priority);
    }
    // Clamp count to the protocol's per-message maximum BEFORE copying, matching
    // Send (UcpPcb::SendAsync clamps to MSS*MAX_FRAGMENTS_PER_MESSAGE): an
    // unbounded count would read past the caller's buffer (OOB read) and attempt
    // a multi-GB allocation on a noexcept path (bad_alloc -> std::terminate).
    int64_t maxPayload = config_.MaxPayloadSize();
    if (maxPayload <= 0) {
        maxPayload = config_.Mss;
    }
    int64_t maxAllowed = maxPayload * 65535LL;
    if (maxAllowed > INT_MAX) {
        maxAllowed = INT_MAX;
    }
    if (count > (size_t)maxAllowed) {
        count = (size_t)maxAllowed;
    }
    // Write directly on the PCB: UcpPcb::Write serializes internally via its
    // own worker queue and deep-copies the payload for its async lifetime, so
    // the previous conn-worker round-trip (copy into `data`, Enqueue, worker
    // hop) was a redundant full-buffer copy plus an extra thread hop.  Holding
    // a snapshot keeps the PCB alive across a concurrent Dispose().
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        return false;
    }
    return pcb->Write(buf, static_cast<int>(off), static_cast<int>(count), priority);
}

/** @brief Asynchronous exact-byte-count write (Normal priority) - non-blocking callback.
 *  @param buf      Source buffer.
 *  @param off      Byte offset in buffer.
 *  @param count    Number of bytes to write.
 *  @param callback Callback invoked when write completes. */
void UcpConnection::WriteAsync(const uint8_t* buf, size_t off, size_t count, WriteAsyncCallback callback) noexcept {
    WriteAsync(buf, off, count, UcpPriority::Normal, std::move(callback));
}

/** @brief Asynchronous exact-byte-count write with explicit priority - non-blocking callback.
 *  @param buf      Source buffer.
 *  @param off      Byte offset in buffer.
 *  @param count    Number of bytes to write.
 *  @param priority QoS priority.
 *  @param callback Callback invoked when write completes. */
void UcpConnection::WriteAsync(const uint8_t* buf, size_t off, size_t count, UcpPriority priority, WriteAsyncCallback callback) noexcept {
    if (off > INT_MAX || count > INT_MAX) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, false);
            } catch (...) {
            }
        }
        return;
    }
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        if (callback) {
            try {
                callback(UcpError::NotConnected, false);
            } catch (...) {
            }
        }
        return;
    }
    pcb->WriteAsync(buf, static_cast<int>(off), static_cast<int>(count), priority, std::move(callback));
}

/** @brief Synchronous close - may block caller thread. Drains send buffer, sends FIN, awaits FIN-ACK, cleans transport.
 *  @note When called on the worker thread, performs synchronous close to avoid promise-based deadlock. */
void UcpConnection::Close() noexcept {
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        CleanupTransport();
        return;
    }
    if (worker_thread_id_.load() == std::this_thread::get_id()) {
        try {
            pcb->Close();
        } catch (const std::exception&) {
        }
        CleanupTransport();
        return;
    }
    auto p = std::make_shared<std::promise<void>>();
    auto f = p->get_future();
    Enqueue([p, pcb]() mutable {
        try {
            pcb->Close();
        } catch (const std::exception&) {
        }
        p->set_value();
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (f.wait_for(std::chrono::milliseconds(10)) != std::future_status::ready) {
        if (std::chrono::steady_clock::now() > deadline)
            break;
    }
    // The close may not have completed within the 5s deadline (the PCB's own
    // close waits up to DisconnectTimeoutMicros+2s = 6s). Abort the PCB now so
    // its worker stops touching the transport BEFORE we destroy it below;
    // otherwise the PCB could send an RST on a freed transport (UAF).  We hold
    // pcb (a snapshot) so a concurrent Dispose cannot free it underneath us.
    try {
        pcb->Abort(true);
    } catch (...) {
    }
    // The PCB's worker/standalone-timer threads keep running after Abort
    // (they are only stopped by Dispose).  Since we own the transport and
    // are about to release it below, stop the PCB now so no thread can
    // touch the freed transport afterwards.  Dispose is idempotent and
    // safe to call on an already-closed PCB.
    try {
        pcb->Dispose();
    } catch (...) {
    }
    CleanupTransport();
}

/** @brief Asynchronous close - non-blocking callback. Drains send buffer, sends FIN, awaits FIN-ACK, cleans transport.
 *  @param callback Callback invoked when connection is fully closed. */
void UcpConnection::CloseAsync(CloseAsyncCallback callback) noexcept {
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        CleanupTransport();
        if (callback) {
            try {
                callback(UcpError::None);
            } catch (...) {
            }
        }
        return;
    }
    auto alive = alive_flag_;
    pcb->CloseAsync([this, callback, alive](UcpError error) noexcept {
        if (!alive || !*alive)
            return;
        CleanupTransport();
        if (callback) {
            try {
                callback(error);
            } catch (...) {
            }
        }
    });
}

/** @brief Releases all connection resources.
 *  StopWorker -> pcb_ close -> CleanupTransport.
 *  This ordering ensures:
 *    1. The worker thread is joined and its queue drained before pcb_ is touched.
 *    2. pcb_ is closed before transport cleanup (no dangling transport refs).
 *    3. Transport unsubscribed/destroyed last (no callbacks after disposal).
 *  Thread-safe: only the first caller performs cleanup (BUG 2 fix). */
void UcpConnection::Dispose() noexcept {
    if (disposed_.exchange(true)) {
        return;
    }
    if (alive_flag_) {
        *alive_flag_ = false;
    }

    try {
        StopWorker();
    } catch (...) {
    }

    if (!server_managed_ && NULLPTR != pcb_) {

        try {
            pcb_->Abort(true);
        } catch (...) {
        }
        {
            // Clear the connection callbacks installed on the PCB (SetDataReceived /
            // SetConnected / SetDisconnected) so no in-flight dispatch can fire a
            // callback that reaches into this connection after we release the pcb.
            // The callbacks also capture the self-held alive flag by value (see
            // AttachPcb/SetOnData), but clearing them here shrinks the window
            // further (parity with the C# Dispose which unsubscribes).
            try {
                pcb_->SetDataReceived(ucp::function<void(const uint8_t*, int, int)>());
                pcb_->SetConnected(ucp::function<void()>());
                pcb_->SetDisconnected(ucp::function<void()>());
            } catch (...) {
            }
        }
        {
            // Synchronize the pcb_ pointer write with readers (GetState,
            // GetCurrentPacingRateBytesPerSecond) so they never dereference a
            // half-updated pointer.
            std::lock_guard<std::mutex> lock(mutex_);
            pcb_ = NULLPTR;
        }
        try {
            std::lock_guard<std::mutex> lock(s_pcbSharedMapMutex);
            s_pcbSharedMap.erase(this);
        } catch (...) {
        }
    } else if (server_managed_ && pcb_holder_) {
        {
            // Clear connection callbacks on the PCB before releasing the holder
            // (see comment in the non-server-managed branch above).
            try {
                pcb_holder_->SetDataReceived(ucp::function<void(const uint8_t*, int, int)>());
                pcb_holder_->SetConnected(ucp::function<void()>());
                pcb_holder_->SetDisconnected(ucp::function<void()>());
            } catch (...) {
            }
        }
        {
            // Synchronize with GetPcbSnapshot's read of pcb_holder_.
            std::lock_guard<std::mutex> lock(mutex_);
            pcb_holder_.reset();
            pcb_ = NULLPTR;
        }
    }

    CleanupTransport();
}

void UcpConnection::SetServerPcbHolder(const ucp::shared_ptr<UcpPcb>& holder) noexcept {
    if (server_managed_) {
        // Synchronize with GetPcbSnapshot (which reads pcb_holder_ under
        // mutex_); concurrent shared_ptr control-block access is UB.
        std::lock_guard<std::mutex> lock(mutex_);
        pcb_holder_ = holder;
    }
}

/** @brief Handles an inbound transport datagram: decodes, validates, and dispatches to the PCB.
 *  @param datagram  Raw byte buffer received from the transport.
 *  @param remote    Source endpoint of the datagram.
 *  @note Validation and dispatch are enqueued to the worker thread to avoid
 *        racing with WorkerLoop->pcb_->OnTick() (BUG 4 fix).  NAK packets
 *        are enqueued at priority (front of queue). */
void UcpConnection::OnTransportDatagram(const ucp::vector<uint8_t>& datagram, const Endpoint& remote) noexcept {
    if (datagram.empty()) {
        return;
    }

    ucp::shared_ptr<UcpPacket> packet;
    if (!UcpPacketCodec::TryDecode(datagram.data(), 0, datagram.size(), packet)) {
        return;
    }

    auto work = [this, packet, remote]() noexcept {
        if (NULLPTR == pcb_) {
            return;
        }

        uint32_t pcbConnId = pcb_->GetConnectionId();
        if (0 != pcbConnId && packet->header.connection_id != pcbConnId) {
            return;
        }

        if (!pcb_->ValidateRemoteEndpoint(remote)) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            remote_endpoint_ = remote;
        }
        pcb_->SetRemoteEndpoint(remote);
        pcb_->HandleInboundAsync(packet.get());
    };

    if (UcpPacketType::Nak == packet->header.type) {
        EnqueuePriority(std::move(work));
    } else {
        Enqueue(std::move(work));
    }
}

/** @brief Decodes a raw datagram and dispatches the resulting packet to the PCB via the serial queue.
 *  @param datagram  Raw byte buffer received from the transport.
 *  @param remote    Source endpoint of the datagram.
 *  @note Enqueued to the worker thread to avoid racing with WorkerLoop->pcb_->OnTick() (BUG 4 fix). */
void UcpConnection::DispatchPacket(const ucp::vector<uint8_t>& datagram, const Endpoint& remote) noexcept {
    if (datagram.empty()) {
        return;
    }

    ucp::shared_ptr<UcpPacket> decoded;
    if (!UcpPacketCodec::TryDecode(datagram.data(), 0, datagram.size(), decoded)) {
        return;
    }

    DispatchPacket(decoded, remote);
}

/** @brief Dispatches an already-decoded packet to the PCB via the serial queue.
 *  Used by UcpServer::OnTransportDatagram to avoid decoding the same datagram
 *  twice (the server decodes once to route, then hands the decoded packet in).
 *  @param decoded  The already-decoded packet.
 *  @param remote   Source endpoint of the datagram. */
void UcpConnection::DispatchPacket(const ucp::shared_ptr<UcpPacket>& decoded, const Endpoint& remote) noexcept {
    if (NULLPTR == decoded) {
        return;
    }

    Enqueue([this, decoded, remote]() noexcept {
        if (NULLPTR == pcb_) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            remote_endpoint_ = remote;
        }
        pcb_->SetRemoteEndpoint(remote);
        pcb_->HandleInboundAsync(decoded.get());
    });
}

/** @brief Adds fair-queue bandwidth credit to the PCB through the serial queue.
 *  @param bytes  Number of bytes of credit to add. */
void UcpConnection::AddFairQueueCredit(double bytes) noexcept {
    if (NULLPTR == pcb_) {
        return;
    }
    Enqueue([this, bytes]() noexcept {
        if (NULLPTR == pcb_) {
            return;
        }
        pcb_->AddFairQueueCredit(bytes);
    });
}

void UcpConnection::SetUncappedFairQueueCredit() noexcept {
    if (NULLPTR == pcb_) {
        return;
    }
    Enqueue([this]() noexcept {
        if (NULLPTR == pcb_) {
            return;
        }
        pcb_->SetUncappedFairQueueCredit();
    });
}

void UcpConnection::RequestFlush() noexcept {
    if (NULLPTR == pcb_) {
        return;
    }
    Enqueue([this]() noexcept {
        if (NULLPTR == pcb_) {
            return;
        }
        pcb_->RequestFlush();
    });
}

/** @brief Returns the current connection state.
 *  @return The UcpConnectionState enum value. */
UcpConnectionState UcpConnection::GetState() const noexcept {
    // Guard against Dispose() (application thread) concurrently setting
    // pcb_ = NULLPTR / releasing the pcb on another thread: reading the raw
    // pcb_ pointer without the mutex can dereference freed memory.
    std::lock_guard<std::mutex> lock(mutex_);
    return NULLPTR != pcb_ ? pcb_->GetState() : UcpConnectionState::Init;
}

/** @brief Returns the current UCP pacing rate in bytes per second.
 *  @return Pacing rate, or 0.0 if no PCB is attached. */
double UcpConnection::GetCurrentPacingRateBytesPerSecond() const noexcept {
    // Lock protects the raw pcb_ pointer against concurrent Dispose().
    std::lock_guard<std::mutex> lock(mutex_);
    return NULLPTR != pcb_ ? pcb_->GetCurrentPacingRateBytesPerSecond() : 0.0;
}

/** @brief Checks whether the connection has pending send data queued.
 *  @return True if the PCB exists and has buffered outgoing data. */
bool UcpConnection::HasPendingSendData() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return NULLPTR != pcb_ && pcb_->HasPendingSendData();
}

/** @brief Retrieves a diagnostics snapshot from the PCB.
 *  @return UcpConnectionDiagnostics with connection health metrics. */
UcpConnectionDiagnostics UcpConnection::GetDiagnostics() const noexcept {
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        return UcpConnectionDiagnostics();
    }
    return pcb->GetDiagnosticsSnapshot();
}

/** @brief Returns the measured bandwidth in bytes per second from PCB diagnostics.
 *  @return Bandwidth value, or 0.0 if no PCB is attached. */
double UcpConnection::GetMeasuredBandwidthBytesPerSecond() const noexcept {
    return GetDiagnostics().MeasuredBandwidthBytesPerSecond;
}

void UcpConnection::AbortForTest(bool sendReset) noexcept {
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR != pcb) {
        pcb->Abort(sendReset);
    }
}

/** @brief Builds a UcpTransferReport from the PCB's diagnostics snapshot.
 *  @return A populated UcpTransferReport. */
UcpTransferReport UcpConnection::GetReport() const noexcept {
    UcpConnectionDiagnostics diagnostics = GetDiagnostics();
    UcpTransferReport report;
    report.BytesSent = diagnostics.BytesSent;
    report.BytesReceived = diagnostics.BytesReceived;
    report.DataPacketsSent = diagnostics.SentDataPackets;
    report.RetransmittedPackets = diagnostics.RetransmittedPackets;
    report.AckPacketsSent = diagnostics.SentAckPackets;
    report.NakPacketsSent = diagnostics.SentNakPackets;
    report.FastRetransmissions = diagnostics.FastRetransmissions;
    report.TimeoutRetransmissions = diagnostics.TimeoutRetransmissions;
    report.LastRttMicros = diagnostics.LastRttMicros;
    report.RttSamplesMicros = diagnostics.RttSamplesMicros;
    report.CongestionWindowBytes = diagnostics.CongestionWindowBytes;
    report.PacingRateBytesPerSecond = diagnostics.PacingRateBytesPerSecond;
    report.EstimatedLossPercent = diagnostics.EstimatedLossPercent;
    report.RemoteWindowBytes = diagnostics.RemoteWindowBytes;
    report.MeasuredBandwidthBytesPerSecond = diagnostics.MeasuredBandwidthBytesPerSecond;
    return report;
}

/** @brief Returns the connection ID.
 *  @return The PCB's connection ID, or the cached ID if no PCB is attached. */
uint32_t UcpConnection::GetConnectionId() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return NULLPTR != pcb_ ? pcb_->GetConnectionId() : connection_id_;
}

/** @brief Returns the owning UcpNetwork, if any.
 *  @return Pointer to the UcpNetwork, or NULLPTR for standalone connections. */
UcpNetwork* UcpConnection::GetNetwork() const noexcept {
    return network_;
}

/** @brief Returns the remote endpoint as a string in "address:port" format.
 *  @return The remote endpoint string, or a descriptive fallback with
 *          connection ID if the endpoint is not yet known. */
ucp::string UcpConnection::GetRemoteEndpoint() const noexcept {
    // remote_endpoint_ is written from worker threads and from the
    // application thread (MigrateRemote); read it under mutex_ to avoid
    // concurrent std::string access (UB).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!remote_endpoint_.address.empty() && 0 != remote_endpoint_.port) {
            return remote_endpoint_.ToString();
        }
    }
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR != pcb) {
        Endpoint ep;
        if (pcb->TryGetRemoteEndpoint(ep)) {
            return ep.ToString();
        }
    }
    if (0 != connection_id_) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "<cid:%08X>", connection_id_);
        return ucp::string(buf);
    }
    return "unknown";
}

void UcpConnection::MigrateRemote(const Endpoint& newEndpoint) noexcept {
    ucp::shared_ptr<ucp::UcpPcb> pcb = GetPcbSnapshot();
    if (NULLPTR == pcb) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        remote_endpoint_ = newEndpoint;
    }
    pcb->SetRemoteEndpoint(newEndpoint);
    if (UcpConnectionState::Established == pcb->GetState()) {
        pcb->MarkPathChanged();
    }
}

/** @brief Registers a data-received callback.
 *  @param cb  Callback invoked when data arrives from the remote peer. */
void UcpConnection::SetOnData(DataCallback cb) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    on_data_callbacks_.push_back(std::move(cb));
    if (NULLPTR != pcb_) {
        // Install through the PCB's thread-safe setter (which takes the pcb
        // worker's callback lock). We are outside any pcb lock here (we only
        // hold mutex_, which guards on_data_callbacks_), so the lock order is
        // pcb-lock -> connection mutex_ on the fire side and never reversed.
        pcb_->SetDataReceived([this, alive = alive_flag_](const uint8_t* data, int offset, int length) {
            if (!alive || !alive->load(std::memory_order_acquire))
                return;
            ucp::vector<DataCallback> snapshot;
            {
                // Copy under mutex_: SetOnData may run concurrently on an app
                // thread while this (worker-thread) callback iterates.
                std::lock_guard<std::mutex> lock(mutex_);
                snapshot = on_data_callbacks_;
            }
            for (auto& cb : snapshot) {
                try {
                    cb(data, offset, length);
                } catch (...) {
                }
            }
        });
    }
}

void UcpConnection::SetOnConnected(StateCallback cb) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    on_connected_callbacks_.push_back(std::move(cb));
    if (NULLPTR != pcb_) {
        pcb_->SetConnected([this, alive = alive_flag_]() {
            if (!alive || !alive->load(std::memory_order_acquire))
                return;
            ucp::vector<StateCallback> snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                snapshot = on_connected_callbacks_;
            }
            for (auto& cb : snapshot) {
                try {
                    cb();
                } catch (...) {
                }
            }
        });
    }
}

void UcpConnection::SetOnDisconnected(StateCallback cb) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    on_disconnected_callbacks_.push_back(std::move(cb));
    if (NULLPTR != pcb_) {
        pcb_->SetDisconnected([this, alive = alive_flag_]() {
            if (!alive || !alive->load(std::memory_order_acquire))
                return;
            ucp::vector<StateCallback> snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                snapshot = on_disconnected_callbacks_;
            }
            for (auto& cb : snapshot) {
                try {
                    cb();
                } catch (...) {
                }
            }
        });
    }
}

} // namespace ucp
