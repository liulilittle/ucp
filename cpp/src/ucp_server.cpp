/** @file ucp_server.cpp
 *  @brief UCP server listener implementation — mirrors C# Ucp.UcpServer.
 *
 *  Listens for incoming SYN packets and creates UcpConnection instances
 *  for each accepted peer.  Supports fair-queue bandwidth scheduling
 *  (proportional to each connection's BBR pacing rate) when running
 *  inside a UcpNetwork with DoEvents-based timer dispatch.
 */

#include "ucp/ucp_server.h"            //< Header declaring UcpServer class and its ConnectionEntry struct
#include "ucp/ucp_connection.h"        //< UcpConnection — created for each accepted client
#include "ucp/ucp_network.h"           //< UcpNetwork — optional network-managed timer integration
#include "ucp/internal/ucp_pcb.h"               //< UcpPcb — per-connection protocol engine (created on SYN)
#include "ucp/ucp_vector.h"            //< ucp::vector<T> and ucp::string type aliases
#include "ucp/ucp_memory.h"            //< ucp::Malloc / ucp::Mfree allocation helpers
#include <algorithm>                     //< std::max for numeric clamping
#include <chrono>                        //< std::chrono::steady_clock for standalone time measurement

namespace ucp {

// === Local constants ===

static constexpr int64_t MICROS_PER_MILLI = 1000;                      //< Microseconds per millisecond conversion factor
static constexpr int64_t MICROS_PER_SECOND = 1000000;                  //< Microseconds per second conversion factor
static constexpr int MAX_BUFFERED_FAIR_QUEUE_ROUNDS = 50;              //< Max backlogged fair-queue rounds (prevents credit explosion)
static constexpr int MIN_TIMER_WAIT_MS = 1;                            //< Minimum timer interval in milliseconds

// ====================================================================================================
// Construction / Destruction
// ====================================================================================================

UcpServer::UcpServer()                                                //< Default constructor: use default configuration
    : UcpServer(UcpConfiguration())                                   //< Delegate to parameterized constructor
{
}

UcpServer::UcpServer(const UcpConfiguration& config)                   //< Construct with specific configuration
    : config_(config)                                                  //< Store configuration for accepted connections
{
    bandwidth_limit_bytes_per_sec_ = config_.ServerBandwidthBytesPerSecond > 0  //< Use configured bandwidth if positive
        ? config_.ServerBandwidthBytesPerSecond                        //< Use the configured value
        : 12 * 1024 * 1024;                                            //< Default to 12 MB/s server bandwidth cap
}

UcpServer::~UcpServer()                                               //< Destructor: stop server and release resources
{
    Dispose();                                                         //< Delegate to Dispose() for cleanup
}

// ====================================================================================================
// Start
// ====================================================================================================

void UcpServer::Start(int /*port*/)                                   //< Start listening on a port (standalone mode)
{
    std::lock_guard<std::mutex> lock(mutex_);                          //< Acquire server mutex for safe state transition
    if (started_) return;                                              //< Already started — idempotent guard

    started_ = true;                                                   //< Mark server as active — prevents double-start

    if (!network_) {                                                   //< Standalone mode: no UcpNetwork available
        last_fair_queue_round_micros_ = std::chrono::duration_cast<std::chrono::microseconds>(  //< Record current time as baseline
            std::chrono::steady_clock::now().time_since_epoch()).count();  //< Monotonic microseconds since system boot
    } else {                                                           //< Network-managed mode: UcpNetwork drives timer
        ScheduleFairQueueRound();                                      //< Register the first fair-queue round via network timer
    }
}

void UcpServer::Start(UcpNetwork* network, int port, const UcpConfiguration& config) {  //< Start within a UcpNetwork context
    if (!network) return;                                              //< Guard against null network pointer

    {
        std::lock_guard<std::mutex> lock(mutex_);                      //< Protect state swap from concurrent access
        if (started_) return;                                          //< Already started — idempotent guard

        network_ = network;                                            //< Store network reference for timer scheduling
        config_ = config;                                              //< Store configuration (clone semantics by caller)
        owns_transport_ = false;                                       //< Network owns the transport — server must not dispose it
        bandwidth_limit_bytes_per_sec_ = config_.ServerBandwidthBytesPerSecond > 0   //< Recalculate bandwidth from new config
            ? config_.ServerBandwidthBytesPerSecond                    //< Use configured bandwidth limit
            : 12 * 1024 * 1024;                                        //< Default 12 MB/s if not configured
    }

    Start(port);                                                       //< Delegate binding and subscription to core Start
}

// ====================================================================================================
// Accept (async)
// ====================================================================================================

std::future<ucp::unique_ptr<UcpConnection>> UcpServer::AcceptAsync() {  //< Asynchronously accept next incoming connection
    auto promise = std::make_shared<std::promise<ucp::unique_ptr<UcpConnection>>>();  //< Allocate shared promise for async result
    auto future = promise->get_future();                               //< Get future for caller to await

    std::thread([this, promise]() {                                     //< Detached thread for blocking wait on accept queue
        while (!stopped_) {                                            //< Loop until server stops
            std::unique_lock<std::mutex> lock(accept_mutex_);          //< Acquire accept mutex for CV wait
            accept_cv_.wait(lock, [this]() {                            //< Wait until queue has a connection or server stops
                std::lock_guard<std::mutex> inner(mutex_);             //< Inner lock for thread-safe queue check
                return !accept_queue_.empty() || stopped_;              //< Wake when connection ready or server stopping
            });

            if (stopped_) {                                             //< Server was stopped while waiting
                promise->set_value(nullptr);                            //< Fulfill with nullptr — signals caller to stop
                return;                                                 //< Exit the wait thread
            }

            UcpConnection* conn = nullptr;                              //< Will hold the dequeued connection pointer
            {
                std::lock_guard<std::mutex> inner(mutex_);              //< Acquire mutex for thread-safe queue pop
                if (!accept_queue_.empty()) {                            //< A connection is waiting to be accepted
                    conn = accept_queue_.front();                        //< Take the front of the FIFO queue
                    accept_queue_.pop();                                 //< Remove it from the queue
                }
            }
            lock.unlock();                                               //< Release accept mutex before setting promise value

            if (conn) {                                                  //< Successfully dequeued a connection
                promise->set_value(ucp::unique_ptr<UcpConnection>(conn));  //< Wrap in unique_ptr and fulfill the promise
                return;                                                  //< Exit — caller now has the connection
            }
        }
        promise->set_value(nullptr);                                    //< Server stopped without any connections
    }).detach();                                                        //< Detach thread — fires and forgets, promise keeps it alive

    return future;                                                      //< Return future to the caller immediately
}

// ====================================================================================================
// Stop / Dispose
// ====================================================================================================

void UcpServer::Stop() {                                               //< Stop listening and close all active connections
    ucp::vector<ucp::unique_ptr<ConnectionEntry>> entries;             //< Collect connection entries for disposal outside lock

    {
        std::lock_guard<std::mutex> lock(mutex_);                      //< Acquire mutex for safe state snapshot
        if (!started_) return;                                         //< Server wasn't started or already stopped

        started_ = false;                                               //< Immediately mark as stopped so new operations fail

        for (auto& pair : connections_) {                               //< Iterate all active connections by connection ID
            entries.push_back(std::move(pair.second));                   //< Move unique_ptr out of the map into local vector
        }
        connections_.clear();                                           //< Clear the map — all entries now owned by entries vector
    }

    for (auto& entry : entries) {                                       //< Dispose all connection PCBs outside the lock
        if (entry && entry->pcb) {                                      //< Entry and its PCB are valid
            // entry->pcb->Dispose();                                   //< PLACEHOLDER: dispose the PCB to trigger graceful close
        }
    }

    stopped_ = true;                                                    //< Signal all waiting threads (accept, fair-queue) to exit
    accept_cv_.notify_all();                                            //< Wake any blocked AcceptAsync callers
}

void UcpServer::Dispose() {                                            //< Release all server resources
    Stop();                                                             //< Delegate to Stop() for cleanup — idempotent via started_ flag
}

// ====================================================================================================
// Inbound datagram handling
// ====================================================================================================

void UcpServer::OnTransportDatagram(const uint8_t* datagram, size_t length, const Endpoint& remote) {  //< Handle inbound UDP datagram
    if (!datagram || length < 12) return;                              //< Need at least the 12-byte common header to proceed

    ConnectionEntry* entry = GetOrCreateConnection(remote, datagram, length);  //< Look up or create a connection for this packet
    if (!entry) return;                                                //< Non-SYN packet for unknown connection — silently drop

    entry->connection->DispatchPacket(datagram, length, remote);       //< Forward decoded packet to the connection's serial queue
}

UcpServer::ConnectionEntry* UcpServer::GetOrCreateConnection(const Endpoint& /*remote*/,  //< Find existing or create new connection entry
                                                               const uint8_t* packet, size_t length) {
    uint32_t connId = 0;                                               //< Will hold the connection ID from the packet header
    if (length >= 6) {                                                  //< Packet has at least 6 bytes (ID at offset 2)
        connId = (static_cast<uint32_t>(packet[2]) << 24) |            //< Big-endian byte 0 (most significant)
                 (static_cast<uint32_t>(packet[3]) << 16) |             //< Big-endian byte 1
                 (static_cast<uint32_t>(packet[4]) << 8) |              //< Big-endian byte 2
                 static_cast<uint32_t>(packet[5]);                      //< Big-endian byte 3 (least significant)
    }

    std::lock_guard<std::mutex> lock(mutex_);                           //< Acquire server mutex for safe connection map access

    auto it = connections_.find(connId);                                //< Look up existing connection by ID
    if (it != connections_.end()) {                                     //< Connection already exists for this ID
        return it->second.get();                                         //< Return raw pointer to the existing ConnectionEntry
    }

    if (length < 1) return nullptr;                                     //< Packet too short to read type byte — reject
    uint8_t pktType = packet[0] & 0x0F;                                 //< Low nibble of first byte is the packet type
    if (pktType != 0x01) return nullptr;                                //< 0x01 = SYN packet; reject any other type from unknown connections

    auto entry = ucp::unique_ptr<ConnectionEntry>(new ConnectionEntry());  //< Allocate new connection bookkeeping entry
    // entry->pcb = new UcpPcb(transport, remote, true, true, OnPcbClosed, connId, config_.Clone(), network_);  //< PLACEHOLDER: create server-side PCB
    // entry->connection = std::make_unique<UcpConnection>(entry->pcb, transport, config_.Clone());  //< PLACEHOLDER: wrap PCB in UcpConnection
    // entry->pcb->Connected = [this, rawEntry = entry.get()]() { OnPcbConnected(rawEntry); };  //< PLACEHOLDER: wire Connected callback

    ConnectionEntry* result = entry.get();                               //< Save raw pointer before transferring ownership
    connections_[connId] = std::move(entry);                             //< Insert into map (moves unique_ptr ownership)

    return result;                                                       //< Return raw pointer (valid as long as connections_ holds the unique_ptr)
}

// ====================================================================================================
// PCB lifecycle callbacks
// ====================================================================================================

void UcpServer::OnPcbConnected(ConnectionEntry* entry) {               //< Called when a PCB handshake completes (Established)
    if (!entry) return;                                                //< Guard against null entry

    {
        std::lock_guard<std::mutex> lock(mutex_);                       //< Acquire mutex for thread-safe queue push
        if (entry->accepted) return;                                    //< Already enqueued — defensive idempotent guard
        entry->accepted = true;                                         //< Mark as accepted so we don't enqueue twice
        // accept_queue_.push(entry->connection.release());             //< PLACEHOLDER: transfer connection ownership to accept queue
    }

    accept_cv_.notify_one();                                            //< Wake one AcceptAsync waiter with the new connection
}

void UcpServer::OnPcbClosed(UcpPcb* pcb) {                              //< Called when a PCB transitions to Closed state
    if (!pcb) return;                                                  //< Guard against null PCB

    uint32_t connId = 0; // pcb->GetConnectionId();                     //< PLACEHOLDER: get the closing PCB's connection ID
    std::lock_guard<std::mutex> lock(mutex_);                           //< Acquire mutex for safe map removal
    connections_.erase(connId);                                         //< Remove this connection's entry from the server
}

// ====================================================================================================
// Fair queue scheduling
// ====================================================================================================

void UcpServer::ScheduleFairQueueRound() {                              //< Schedule next fair-queue credit round via network timer
    if (!network_) return;                                             //< Only meaningful when running under a UcpNetwork

    std::lock_guard<std::mutex> lock(mutex_);                           //< Protect started_ and fair_queue_timer_id_ from concurrent Stop
    if (!started_) return;                                             //< Server has been stopped — don't schedule

    int64_t delayUs = std::max<int64_t>(MIN_TIMER_WAIT_MS * MICROS_PER_MILLI,  //< Clamp delay to at least 1ms to avoid busy-waiting
                                         config_.FairQueueRoundMilliseconds * MICROS_PER_MILLI);  //< Configured round interval in microseconds
    fair_queue_timer_id_ = network_->AddTimer(                          //< Register one-shot timer in the network's event loop
        network_->GetNowMicroseconds() + delayUs,                       //< Absolute expiration time = now + delay
        [this]() { OnFairQueueRound(); });                               //< Callback: execute fair-queue round when timer fires
}

void UcpServer::OnFairQueueRound() {                                    //< Timer callback: distribute credits and re-schedule
    OnFairQueueRoundCore();                                             //< Execute the core credit distribution logic
    if (network_) {                                                     //< Running inside a UcpNetwork
        ScheduleFairQueueRound();                                        //< Re-arm the timer for the next round
    }
}

void UcpServer::OnFairQueueRoundCore() {                                //< Core fair-queue: distribute bandwidth credit proportionally
    ucp::vector<UcpConnection*> active;                                 //< List of connections eligible for credit this round

    {
        std::lock_guard<std::mutex> lock(mutex_);                       //< Protect connections_ dictionary during enumeration
        for (auto& pair : connections_) {                                //< Scan all tracked connections
            auto& entry = pair.second;                                   //< Get the ConnectionEntry for this connection ID
            if (!entry || !entry->connection) continue;                  //< Skip invalid entries

            auto state = entry->connection->GetState();                  //< Get current connection state
            if ((state == UcpConnectionState::Established ||             //< Connection can send data in these states
                 state == UcpConnectionState::ClosingFinSent ||
                 state == UcpConnectionState::ClosingFinReceived)) {
                // if (entry->connection->HasPendingSendData()) {         //< PLACEHOLDER: only include if buffer is not empty
                //     active.push_back(entry->connection.get());         //< PLACEHOLDER: add to active list
                // }
            }
        }
    }

    if (active.empty()) return;                                          //< No connections need bandwidth — nothing to distribute

    int64_t nowUs = network_                                            //< Get current time for elapsed calculation
        ? network_->GetCurrentTimeUs()                                  //< Use network's cached clock if multiplexed
        : std::chrono::duration_cast<std::chrono::microseconds>(        //< Otherwise read system monotonic clock
              std::chrono::steady_clock::now().time_since_epoch()).count();

    int64_t elapsedUs = last_fair_queue_round_micros_ == 0              //< Compute elapsed time since last round
        ? config_.FairQueueRoundMilliseconds * MICROS_PER_MILLI         //< First round: assume exactly one interval has passed
        : nowUs - last_fair_queue_round_micros_;                         //< Subsequent rounds: compute actual elapsed time

    if (elapsedUs < MICROS_PER_MILLI) {                                  //< Elapsed time less than 1ms (bursty timers)
        elapsedUs = MICROS_PER_MILLI;                                    //< Clamp to minimum 1ms to avoid zero/negative credit
    }

    int64_t maxElapsed = config_.FairQueueRoundMilliseconds * MICROS_PER_MILLI *  //< Maximum allowed elapsed time
                         MAX_BUFFERED_FAIR_QUEUE_ROUNDS;                 //< Cap at N buffered rounds to prevent credit explosion
    if (elapsedUs > maxElapsed) {                                        //< Elapsed time exceeds maximum (e.g., after long GC pause)
        elapsedUs = maxElapsed;                                          //< Clamp to prevent overwhelming credit burst
    }

    last_fair_queue_round_micros_ = nowUs;                               //< Record this round's time as baseline for the next

    double roundBytes = static_cast<double>(bandwidth_limit_bytes_per_sec_) *  //< Total bytes this round
                        (static_cast<double>(elapsedUs) / MICROS_PER_SECOND);    //< bandwidth_limit * elapsed_seconds
    double fairShareCap = active.size() > 0                              //< Each connection's maximum equal share
        ? static_cast<double>(bandwidth_limit_bytes_per_sec_) / active.size()  //< Bandwidth divided equally among active
        : bandwidth_limit_bytes_per_sec_;                                 //< Lone connection gets full bandwidth

    double effectiveTotal = 0.0;                                         //< Sum of all effective pacing rates (denominator)
    ucp::vector<double> effectivePacing(active.size());                  //< Per-connection effective pacing rate array

    for (size_t i = 0; i < active.size(); ++i) {                         //< Collect each connection's effective pacing rate
        double pacing = 0.0; // active[i]->GetCurrentPacingRateBytesPerSecond();  //< PLACEHOLDER: get BBR pacing rate
        if (pacing <= 0) pacing = fairShareCap;                          //< No computed pacing — default to equal fair share
        if (pacing > fairShareCap) pacing = fairShareCap;                //< Clamp pacing to fair share cap so no one starves
        effectivePacing[i] = pacing;                                      //< Store capped pacing for this connection
        effectiveTotal += pacing;                                         //< Accumulate into total for proportional distribution
    }

    if (effectiveTotal <= 0) {                                            //< All connections have zero pacing (edge case)
        effectiveTotal = static_cast<double>(active.size());              //< Fall back to equal weight distribution
    }

    for (size_t i = 0; i < active.size(); ++i) {                          //< Distribute credit proportional to pacing share
        /*double credit =*/ (void)((effectivePacing[i] / effectiveTotal) * roundBytes);  //< Credit = share * round_bytes
        // active[i]->AddFairQueueCredit(credit);                         //< PLACEHOLDER: add credit to connection's PCB
    }

    int startIndex = 0;                                                   //< Starting index for round-robin flush order
    {
        std::lock_guard<std::mutex> lock(mutex_);                         //< Protect fair_queue_start_index_ read-modify-write
        if (fair_queue_start_index_ >= static_cast<int>(active.size())) {  //< Start index past list bounds (connections removed)
            fair_queue_start_index_ = 0;                                   //< Reset to beginning of the list
        }
        startIndex = fair_queue_start_index_;                              //< Capture current start index for this round
        fair_queue_start_index_++;                                         //< Advance for next round (round-robin rotation)
    }

    for (int i = 0; i < static_cast<int>(active.size()); ++i) {            //< Flush each connection in rotated order
        /*int index =*/ (void)((startIndex + i) % static_cast<int>(active.size()));  //< Compute index with wrap-around
        // active[index]->RequestFlush();                                  //< PLACEHOLDER: trigger send buffer flush on the connection
    }
}

} // namespace ucp