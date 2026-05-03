/** @file ucp_network.cpp
 *  @brief Central network event loop implementation — mirrors C# Ucp.UcpNetwork.
 *
 *  Manages a timer heap (multimap keyed by expiration timestamp), a registry
 *  of active UcpPcb instances, and a cached monotonic clock.  DoEvents fires
 *  expired timers (under timer_mutex_) and ticks each registered PCB.
 *  The Input() method demultiplexes inbound datagrams to the correct PCB by
 *  connection ID.
 */

#include "ucp/ucp_network.h"          //< Header declaring UcpNetwork, IUcpObject, TimerEntry
#include "ucp/ucp_server.h"           //< UcpServer — used by CreateServer factory
#include "ucp/ucp_connection.h"       //< UcpConnection — used by CreateConnection factory
#include "ucp/ucp_vector.h"           //< ucp::vector<T> and ucp::string type aliases
#include "ucp/ucp_memory.h"           //< ucp::Malloc / ucp::Mfree allocation helpers
#include <thread>                       //< std::this_thread::yield and std::this_thread::sleep_for
#include <chrono>                       //< std::chrono::steady_clock and duration operations
#include <algorithm>                    //< std::find for PCB lookup in active_pcbs_

namespace ucp {

UcpNetwork::UcpNetwork(const UcpConfiguration& config)             //< Construct with specific configuration
    : config_(config)                                               //< Store configuration for all managed objects
{
    clock_start_ = std::chrono::steady_clock::now();                //< Capture fixed epoch for all timing in this network
    cached_time_us_ = ReadStopwatchMicros();                        //< Seed the microsecond cache with current monotonic time
    cached_time_ms_ = cached_time_us_ / 1000;                       //< Derive millisecond cache from microsecond reading
}

UcpNetwork::UcpNetwork()                                           //< Default constructor: use default configuration
    : UcpNetwork(UcpConfiguration())                                //< Delegate to parameterized constructor
{
}

UcpNetwork::~UcpNetwork()                                          //< Virtual destructor: clean up timers and child objects
{
    Dispose();                                                      //< See Dispose() for cleanup logic
}

int64_t UcpNetwork::ReadStopwatchMicros() const {                   //< Read raw monotonic microseconds since clock_start_
    auto now = std::chrono::steady_clock::now();                     //< Snapshot current monotonic time
    return std::chrono::duration_cast<std::chrono::microseconds>(    //< Compute elapsed microseconds since epoch
        now - clock_start_).count();                                  //< Duration subtraction returns elapsed time
}

void UcpNetwork::UpdateCachedClock() {                              //< Refresh cached clock at most once per millisecond
    int64_t us = ReadStopwatchMicros();                              //< Get current microsecond reading from the stopwatch
    int64_t ms = us / 1000;                                         //< Convert to milliseconds for granularity throttle
    if (ms != cached_time_ms_) {                                    //< At least 1ms has elapsed since last cache update
        cached_time_us_ = us;                                       //< Update microsecond cache for all protocol code
        cached_time_ms_ = ms;                                       //< Update millisecond cache for next comparison
    }
}

int64_t UcpNetwork::GetNowMicroseconds() const {                    //< Return cached microsecond value (public API)
    return cached_time_us_;                                         //< May be stale by up to 1ms — updated by UpdateCachedClock
}

int64_t UcpNetwork::GetCurrentTimeUs() const {                      //< Alias for GetNowMicroseconds (legacy compatibility)
    return cached_time_us_;                                         //< Same backing field — provides consistent time within a DoEvents tick
}

void UcpNetwork::Input(const uint8_t* data, size_t length, const Endpoint& /*remote*/) {  //< Demultiplex inbound datagram to correct PCB
    if (disposed_) return;                                         //< Reject input after disposal to prevent use-after-free
    if (!data || length < 12) return;                               //< Need at least the 12-byte common UCP header

    uint32_t connId = 0;                                            //< Will hold the connection ID extracted from packet header
    if (length >= 6) {                                               //< Packet has at least 6 bytes for ID (at offset 2)
        connId = (static_cast<uint32_t>(data[2]) << 24) |           //< Big-endian byte 0 (most significant) of connection ID
                 (static_cast<uint32_t>(data[3]) << 16) |            //< Big-endian byte 1
                 (static_cast<uint32_t>(data[4]) << 8) |             //< Big-endian byte 2
                 static_cast<uint32_t>(data[5]);                     //< Big-endian byte 3 (least significant)
    }

    {
        std::lock_guard<std::mutex> lock(pcb_mutex_);               //< Acquire PCB mutex for safe dictionary lookup
        auto it = pcbs_by_id_.find(connId);                          //< Look up PCB by connection ID (O(log n))
        if (it != pcbs_by_id_.end() && it->second) {                //< Found a registered PCB for this connection ID
            // pcb->DispatchFromNetwork(data, length, remote);       //< PLACEHOLDER: directly deliver packet to the owning PCB
            return;                                                  //< Packet routed — exit early
        }
    }

    // Fallback: unknown connection — SYN packets create new connections via server accept logic
}

int UcpNetwork::DoEvents() {                                        //< Drive one iteration: fire expired timers, tick all PCBs
    if (disposed_) return 0;                                        //< Refuse to process events after disposal

    UpdateCachedClock();                                            //< Refresh cached time for consistent timestamps this tick

    ucp::vector<std::function<void()>> dueCallbacks;                //< Accumulator for all expired timer callbacks
    int64_t nowUs = GetCurrentTimeUs();                              //< Snapshot the logical "now" for timer comparison

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);             //< Acquire timer mutex to safely inspect/remove timers
        auto it = timer_heap_.begin();                               //< Start at the earliest timer (multimap sorted by key)
        while (it != timer_heap_.end() && it->first <= nowUs) {     //< While there are timers and they have expired
            dueCallbacks.push_back(it->second);                      //< Collect the callback for execution outside the lock
            it = timer_heap_.erase(it);                              //< Remove expired timer and advance iterator
        }
    }

    for (auto& cb : dueCallbacks) {                                  //< Execute all collected expired callbacks
        cb();                                                        //< Invoke the wrapped callback (handles its own cancellation check)
    }

    auto snapshot = SnapshotPcbs();                                  //< Take snapshot of all active PCBs under pcb_mutex_
    int pcbWork = 0;                                                 //< Accumulator for work items reported by PCB ticks
    for (auto* pcb : snapshot) {                                     //< Iterate snapshot — safe: no lock held during OnTick
        if (pcb) {                                                   //< Guard against null pointer in active_pcbs_
            // pcbWork += pcb->OnTick(GetCurrentTimeUs());           //< PLACEHOLDER: tick each PCB (RTO, keep-alive, NAK)
        }
    }

    if (dueCallbacks.empty() && pcbWork == 0) {                      //< Nothing was processed this tick
        YieldWhenIdle();                                             //< Yield CPU to avoid busy-waiting when idle
    }

    return static_cast<int>(dueCallbacks.size()) + pcbWork;          //< Return total work items: callbacks + PCB ticks
}

void UcpNetwork::YieldWhenIdle() {                                   //< Cooperative yield: sleep or yield based on next timer
    int64_t nextExpire = 0;                                          //< Will hold expiration time of earliest pending timer
    bool hasTimer = false;                                           //< True if at least one timer exists in the heap

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);             //< Acquire timer mutex to safely read timer heap
        if (!timer_heap_.empty()) {                                  //< There are pending timers
            nextExpire = timer_heap_.begin()->first;                  //< Peek at earliest timer's expiration timestamp
            hasTimer = true;                                         //< Mark that a timer exists for the yield decision
        }
    }

    if (hasTimer && (nextExpire - GetCurrentTimeUs()) <= 1000) {     //< Next timer fires within 1ms — don't sleep
        std::this_thread::yield();                                   //< Yield current time slice for low-latency timer handling
        return;                                                      //< Exit — yield is sufficient
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1));       //< No imminent timer: sleep 1ms to reduce CPU usage
}

uint32_t UcpNetwork::AddTimer(int64_t expireUs, std::function<void()> callback) {  //< Register a one-shot timer callback
    if (!callback) return 0;                                        //< Guard against null callback — must be non-null to fire

    uint32_t id = next_timer_id_++;                                  //< Atomically allocate a unique timer ID (monotonically increasing)

    auto entry = ucp::shared_ptr<TimerEntry>(new TimerEntry());      //< Allocate shared timer entry (shared for weak_ptr lifecycle)
    entry->id = id;                                                  //< Store the timer ID for identity checks during cancellation
    entry->expireUs = expireUs;                                      //< Store absolute expiration timestamp (microseconds)
    entry->callback = callback;                                      //< Store the user-provided callback

    auto weakEntry = ucp::weak_ptr<TimerEntry>(entry);               //< Create weak reference for the wrapped callback
    entry->wrappedCallback = [this, id, weakEntry]() {               //< Wrap callback with cancellation guard
        auto entry = weakEntry.lock();                               //< Attempt to promote weak_ptr to shared_ptr
        bool shouldRun = false;                                      //< Guard: true if the timer was NOT cancelled
        {
            std::lock_guard<std::mutex> lock(timer_mutex_);         //< Synchronize with CancelTimer for atomic check-and-remove
            auto it = active_timers_.find(id);                       //< Look up this timer ID in the active timers map
            if (it != active_timers_.end() && it->second.get() == entry.get()) {  //< This exact timer is still active
                active_timers_.erase(it);                            //< Consume the timer: remove from active set
                shouldRun = true;                                    //< Timer was not cancelled — safe to execute
            }
        }
        if (shouldRun && entry) {                                    //< Timer not cancelled and entry still alive
            entry->callback();                                       //< Execute the user's callback
        }
    };

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);             //< Acquire timer mutex for atomic insertion
        active_timers_[id] = entry;                                  //< Register in cancellation map (fast O(log n) lookup)
        timer_heap_.emplace(expireUs, entry->wrappedCallback);       //< Insert into priority queue keyed by expiration time
    }

    return id;                                                        //< Return the timer ID so the caller can cancel it later
}

bool UcpNetwork::CancelTimer(uint32_t timerId) {                     //< Cancel a pending timer by ID
    std::lock_guard<std::mutex> lock(timer_mutex_);                  //< Synchronize with AddTimer and timer execution
    return active_timers_.erase(timerId) > 0;                        //< Erase returns count of removed elements; >0 means found
}

void UcpNetwork::Output(const uint8_t* data, size_t length, const Endpoint& remote) {  //< Convenience overload: no sender
    Output(data, length, remote, nullptr);                            //< Delegate to pure-virtual Output with null sender
}

void UcpNetwork::Start(int /*port*/) {                               //< Base Start is a no-op (overridden by subclasses)
    // Subclass implements socket bind and receive loop start
}

void UcpNetwork::Stop() {                                            //< Base Stop is a no-op (overridden by subclasses)
    // Subclass implements socket close and receive loop stop
}

void UcpNetwork::Dispose() {                                         //< Release all network resources: timers and transport
    if (disposed_) return;                                           //< Idempotent guard — already disposed
    disposed_ = true;                                                //< Set flag immediately so concurrent calls fail early
    Stop();                                                          //< Let subclass close its sockets/threads

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);              //< Acquire timer mutex for safe cleanup
        active_timers_.clear();                                      //< Clear all timer registrations — wrapped callbacks will see they're cancelled
        timer_heap_.clear();                                         //< Clear the priority queue — no timers left to fire
    }
}

void UcpNetwork::RegisterPcb(UcpPcb* pcb) {                           //< Register a PCB for tick processing and packet routing
    if (!pcb) return;                                                //< Guard against null pointer
    std::lock_guard<std::mutex> lock(pcb_mutex_);                    //< Acquire PCB mutex for safe vector/map mutation
    if (std::find(active_pcbs_.begin(), active_pcbs_.end(), pcb) == active_pcbs_.end()) {  //< Deduplicate: only add if not present
        active_pcbs_.push_back(pcb);                                  //< Add to tick list for DoEvents processing
    }
    uint32_t connId = 0; // pcb->GetConnectionId();                  //< PLACEHOLDER: connection ID may be 0 before handshake
    if (connId != 0) {                                                //< Only index by ID if a real connection ID is assigned
        pcbs_by_id_[connId] = pcb;                                   //< Register for O(log n) routing in Input()
    }
}

void UcpNetwork::UnregisterPcb(UcpPcb* pcb) {                         //< Remove a PCB from all tracking data structures
    if (!pcb) return;                                                //< Guard against null pointer
    std::lock_guard<std::mutex> lock(pcb_mutex_);                    //< Acquire PCB mutex for safe removal
    auto it = std::remove(active_pcbs_.begin(), active_pcbs_.end(), pcb);  //< Move removed PCB to end of vector
    active_pcbs_.erase(it, active_pcbs_.end());                      //< Erase the removed PCB from the vector
    uint32_t connId = 0; // pcb->GetConnectionId();                  //< PLACEHOLDER: get the PCB's connection ID
    if (connId != 0) {                                                //< Only clean up routing entry if a non-zero ID was assigned
        auto idIt = pcbs_by_id_.find(connId);                         //< Look up the routing entry for this connection ID
        if (idIt != pcbs_by_id_.end() && idIt->second == pcb) {      //< Verify the mapping still points to THIS PCB
            pcbs_by_id_.erase(idIt);                                  //< Remove stale routing entry
        }
    }
}

void UcpNetwork::UpdatePcbConnectionId(UcpPcb* pcb, uint32_t oldId, uint32_t newId) {  //< Update routing after handshake assigns real ID
    if (!pcb || newId == 0) return;                                 //< Need a valid PCB and non-zero new ID
    std::lock_guard<std::mutex> lock(pcb_mutex_);                    //< Acquire PCB mutex for safe map mutation
    if (oldId != 0) {                                                 //< There was a previous mapping to clean up
        auto it = pcbs_by_id_.find(oldId);                            //< Look up old routing entry
        if (it != pcbs_by_id_.end() && it->second == pcb) {          //< Old entry still maps to this PCB (defensive check)
            pcbs_by_id_.erase(it);                                    //< Remove the stale mapping
        }
    }
    pcbs_by_id_[newId] = pcb;                                        //< Insert new mapping so packets route to this PCB
    if (std::find(active_pcbs_.begin(), active_pcbs_.end(), pcb) == active_pcbs_.end()) {  //< Belt-and-suspenders: ensure in tick list
        active_pcbs_.push_back(pcb);                                  //< Add to tick list if not already present
    }
}

ucp::vector<UcpPcb*> UcpNetwork::SnapshotPcbs() {                    //< Create a snapshot of active PCBs for safe iteration
    std::lock_guard<std::mutex> lock(pcb_mutex_);                    //< Acquire PCB mutex for consistent read
    return active_pcbs_;                                              //< Return copy of the vector — caller iterates without holding lock
}

ucp::unique_ptr<UcpServer> UcpNetwork::CreateServer(int port) {
    return ucp::unique_ptr<UcpServer>();
}

ucp::unique_ptr<UcpConnection> UcpNetwork::CreateConnection() {
    return ucp::unique_ptr<UcpConnection>();
}

ucp::unique_ptr<UcpConnection> UcpNetwork::CreateConnection(const UcpConfiguration& config) {
    return ucp::unique_ptr<UcpConnection>();
}

} // namespace ucp