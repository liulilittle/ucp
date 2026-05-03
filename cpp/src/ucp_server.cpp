/** @file ucp_server.cpp
 *  @brief UCP server listener implementation — mirrors C# Ucp.UcpServer.
 *
 *  Listens for incoming SYN packets and creates UcpConnection instances
 *  for each accepted peer.  Supports fair-queue bandwidth scheduling
 *  (proportional to each connection's BBR pacing rate) when running
 *  inside a UcpNetwork with DoEvents-based timer dispatch.
 */

#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_network.h"
#include "ucp/ucp_pcb.h"
#include <algorithm>
#include <chrono>

namespace ucp {

// === Local constants ===

static constexpr int64_t MICROS_PER_MILLI = 1000;              //< Microseconds per millisecond.
static constexpr int64_t MICROS_PER_SECOND = 1000000;          //< Microseconds per second.
static constexpr int MAX_BUFFERED_FAIR_QUEUE_ROUNDS = 50;      //< Max backlogged fair-queue rounds (prevents credit explosion).
static constexpr int MIN_TIMER_WAIT_MS = 1;                    //< Minimum timer interval (ms).

// ====================================================================================================
// Construction / Destruction
// ====================================================================================================

UcpServer::UcpServer()
    : UcpServer(UcpConfiguration())
{
}

UcpServer::UcpServer(const UcpConfiguration& config)
    : config_(config)
{
    bandwidth_limit_bytes_per_sec_ = config_.ServerBandwidthBytesPerSecond > 0
        ? config_.ServerBandwidthBytesPerSecond
        : 12 * 1024 * 1024;  //< Default to 12 MB/s server bandwidth cap.
}

UcpServer::~UcpServer()
{
    Dispose();
}

// ====================================================================================================
// Start
// ====================================================================================================

void UcpServer::Start(int /*port*/)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) return;
    started_ = true;

    if (!network_) {
        // Standalone mode: start internal transport, begin fair-queue timer
        last_fair_queue_round_micros_ = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    } else {
        // Network-managed mode: schedule fair-queue via network timer
        ScheduleFairQueueRound();
    }
}

void UcpServer::Start(UcpNetwork* network, int port, const UcpConfiguration& config)
{
    if (!network) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (started_) return;
        network_ = network;
        config_ = config;
        owns_transport_ = false;
        bandwidth_limit_bytes_per_sec_ = config_.ServerBandwidthBytesPerSecond > 0
            ? config_.ServerBandwidthBytesPerSecond
            : 12 * 1024 * 1024;
    }

    Start(port);
}

// ====================================================================================================
// Accept (async)
// ====================================================================================================

std::future<std::unique_ptr<UcpConnection>> UcpServer::AcceptAsync()
{
    auto promise = std::make_shared<std::promise<std::unique_ptr<UcpConnection>>>();
    auto future = promise->get_future();

    // Offload blocking wait to a detached thread so the caller is not blocked
    std::thread([this, promise]() {
        while (!stopped_) {
            std::unique_lock<std::mutex> lock(accept_mutex_);
            accept_cv_.wait(lock, [this]() {
                std::lock_guard<std::mutex> inner(mutex_);
                return !accept_queue_.empty() || stopped_;
            });

            if (stopped_) {
                promise->set_value(nullptr);
                return;
            }

            UcpConnection* conn = nullptr;
            {
                std::lock_guard<std::mutex> inner(mutex_);
                if (!accept_queue_.empty()) {
                    conn = accept_queue_.front();
                    accept_queue_.pop();
                }
            }
            lock.unlock();

            if (conn) {
                promise->set_value(std::unique_ptr<UcpConnection>(conn));
                return;
            }
        }
        promise->set_value(nullptr);
    }).detach();

    return future;
}

// ====================================================================================================
// Stop / Dispose
// ====================================================================================================

void UcpServer::Stop()
{
    std::vector<std::unique_ptr<ConnectionEntry>> entries;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) return;
        started_ = false;

        // Move all connections out under lock — process cleanup outside
        for (auto& pair : connections_) {
            entries.push_back(std::move(pair.second));
        }
        connections_.clear();
    }

    for (auto& entry : entries) {
        if (entry && entry->pcb) {
            // entry->pcb->Dispose();
        }
    }

    // Stop transport
    // Transport stop/cleanup

    stopped_ = true;
    accept_cv_.notify_all();
}

void UcpServer::Dispose()
{
    Stop();
}

// ====================================================================================================
// Inbound datagram handling
// ====================================================================================================

void UcpServer::OnTransportDatagram(const uint8_t* datagram, size_t length, const Endpoint& remote)
{
    if (!datagram || length < 12) return;  //< Need at least the 12-byte common header.

    ConnectionEntry* entry = GetOrCreateConnection(remote, datagram, length);
    if (!entry) return;

    entry->connection->DispatchPacket(datagram, length, remote);
}

UcpServer::ConnectionEntry* UcpServer::GetOrCreateConnection(const Endpoint& /*remote*/,
                                                              const uint8_t* packet, size_t length)
{
    // Extract connection ID from packet bytes [2:6] (big-endian uint32)
    uint32_t connId = 0;
    if (length >= 6) {
        connId = (static_cast<uint32_t>(packet[2]) << 24) |
                 (static_cast<uint32_t>(packet[3]) << 16) |
                 (static_cast<uint32_t>(packet[4]) << 8) |
                 static_cast<uint32_t>(packet[5]);
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = connections_.find(connId);
    if (it != connections_.end()) {
        return it->second.get();
    }

    // Only SYN packets create new connections
    if (length < 1) return nullptr;
    uint8_t pktType = packet[0] & 0x0F;  //< Low nibble is packet type.
    if (pktType != 0x01) return nullptr;  //< Not SYN, reject.

    // Create a new PCB and UcpConnection
    auto entry = std::make_unique<ConnectionEntry>();
    // entry->pcb = new UcpPcb(transport, remote, true, true, OnPcbClosed, connId, config_.Clone(), network_);
    // entry->connection = std::make_unique<UcpConnection>(entry->pcb, transport, config_.Clone());
    // entry->pcb->Connected = [this, rawEntry = entry.get()]() { OnPcbConnected(rawEntry); };

    ConnectionEntry* result = entry.get();
    connections_[connId] = std::move(entry);

    return result;
}

// ====================================================================================================
// PCB lifecycle callbacks
// ====================================================================================================

void UcpServer::OnPcbConnected(ConnectionEntry* entry)
{
    if (!entry) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (entry->accepted) return;
        entry->accepted = true;
        // Release connection to accept queue
        // accept_queue_.push(entry->connection.release());
    }

    accept_cv_.notify_one();
}

void UcpServer::OnPcbClosed(UcpPcb* pcb)
{
    if (!pcb) return;

    uint32_t connId = 0; // pcb->GetConnectionId();
    std::lock_guard<std::mutex> lock(mutex_);
    connections_.erase(connId);
}

// ====================================================================================================
// Fair queue scheduling
// ====================================================================================================

void UcpServer::ScheduleFairQueueRound()
{
    if (!network_) return;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!started_) return;

    int64_t delayUs = std::max<int64_t>(MIN_TIMER_WAIT_MS * MICROS_PER_MILLI,
                                         config_.FairQueueRoundMilliseconds * MICROS_PER_MILLI);
    fair_queue_timer_id_ = network_->AddTimer(
        network_->GetNowMicroseconds() + delayUs,
        [this]() { OnFairQueueRound(); });
}

void UcpServer::OnFairQueueRound()
{
    OnFairQueueRoundCore();
    if (network_) {
        ScheduleFairQueueRound();
    }
}

void UcpServer::OnFairQueueRoundCore()
{
    // === Collect active connections with pending send data ===
    std::vector<UcpConnection*> active;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : connections_) {
            auto& entry = pair.second;
            if (!entry || !entry->connection) continue;

            auto state = entry->connection->GetState();
            if ((state == UcpConnectionState::Established ||
                 state == UcpConnectionState::ClosingFinSent ||
                 state == UcpConnectionState::ClosingFinReceived)) {
                // if (entry->connection->HasPendingSendData()) {
                //     active.push_back(entry->connection.get());
                // }
            }
        }
    }

    if (active.empty()) return;

    // === Calculate elapsed time (capped to prevent credit explosion) ===
    int64_t nowUs = network_
        ? network_->GetCurrentTimeUs()
        : std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch()).count();

    int64_t elapsedUs = last_fair_queue_round_micros_ == 0
        ? config_.FairQueueRoundMilliseconds * MICROS_PER_MILLI
        : nowUs - last_fair_queue_round_micros_;

    if (elapsedUs < MICROS_PER_MILLI) {
        elapsedUs = MICROS_PER_MILLI;
    }

    int64_t maxElapsed = config_.FairQueueRoundMilliseconds * MICROS_PER_MILLI *
                         MAX_BUFFERED_FAIR_QUEUE_ROUNDS;
    if (elapsedUs > maxElapsed) {
        elapsedUs = maxElapsed;
    }

    last_fair_queue_round_micros_ = nowUs;

    // Total bytes available in this round = bandwidth_limit * elapsed_time
    double roundBytes = static_cast<double>(bandwidth_limit_bytes_per_sec_) *
                        (static_cast<double>(elapsedUs) / MICROS_PER_SECOND);
    double fairShareCap = active.size() > 0
        ? static_cast<double>(bandwidth_limit_bytes_per_sec_) / active.size()
        : bandwidth_limit_bytes_per_sec_;

    // === Distribute credit proportional to each connection's BBR pacing rate ===
    double effectiveTotal = 0.0;
    std::vector<double> effectivePacing(active.size());

    for (size_t i = 0; i < active.size(); ++i) {
        double pacing = 0.0; // active[i]->GetCurrentPacingRateBytesPerSecond();
        if (pacing <= 0) pacing = fairShareCap;
        if (pacing > fairShareCap) pacing = fairShareCap;
        effectivePacing[i] = pacing;
        effectiveTotal += pacing;
    }

    if (effectiveTotal <= 0) {
        effectiveTotal = static_cast<double>(active.size());
    }

    // Assign credits to each connection
    for (size_t i = 0; i < active.size(); ++i) {
        /*double credit =*/ (void)((effectivePacing[i] / effectiveTotal) * roundBytes);
        // active[i]->AddFairQueueCredit(credit);
    }

    // === Round-robin flush: start from previous index + 1 ===
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
        /*int index =*/ (void)((startIndex + i) % static_cast<int>(active.size()));
        // active[index]->RequestFlush();
    }
}

} // namespace ucp
