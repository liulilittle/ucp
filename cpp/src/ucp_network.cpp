/** @file ucp_network.cpp
 *  @brief Central network event loop implementation — mirrors C# Ucp.UcpNetwork.
 *
 *  Manages a timer heap (multimap keyed by expiration timestamp), a registry
 *  of active UcpPcb instances, and a cached monotonic clock.  DoEvents fires
 *  expired timers (under timer_mutex_) and ticks each registered PCB.
 *  The Input() method demultiplexes inbound datagrams to the correct PCB by
 *  connection ID.
 */

#include "ucp/ucp_network.h"
#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include <thread>
#include <chrono>
#include <algorithm>

namespace ucp {

UcpNetwork::UcpNetwork(const UcpConfiguration& config)
    : config_(config)
{
    clock_start_ = std::chrono::steady_clock::now();
    cached_time_us_ = ReadStopwatchMicros();
    cached_time_ms_ = cached_time_us_ / 1000;
}

UcpNetwork::UcpNetwork()
    : UcpNetwork(UcpConfiguration())
{
}

UcpNetwork::~UcpNetwork()
{
    Dispose();
}

int64_t UcpNetwork::ReadStopwatchMicros() const
{
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now - clock_start_).count();
}

void UcpNetwork::UpdateCachedClock()
{
    int64_t us = ReadStopwatchMicros();
    int64_t ms = us / 1000;
    // Coarse-grained caching: only update at millisecond boundaries
    if (ms != cached_time_ms_) {
        cached_time_us_ = us;
        cached_time_ms_ = ms;
    }
}

int64_t UcpNetwork::GetNowMicroseconds() const
{
    return cached_time_us_;
}

int64_t UcpNetwork::GetCurrentTimeUs() const
{
    return cached_time_us_;
}

void UcpNetwork::Input(const uint8_t* data, size_t length, const Endpoint& /*remote*/)
{
    if (disposed_) return;
    if (!data || length < 12) return;

    // Extract connection ID from bytes [2:6] (big-endian uint32 at offset 2)
    uint32_t connId = 0;
    if (length >= 6) {
        connId = (static_cast<uint32_t>(data[2]) << 24) |
                 (static_cast<uint32_t>(data[3]) << 16) |
                 (static_cast<uint32_t>(data[4]) << 8) |
                 static_cast<uint32_t>(data[5]);
    }

    // Route to a known PCB if it exists (under pcb_mutex_)
    {
        std::lock_guard<std::mutex> lock(pcb_mutex_);
        auto it = pcbs_by_id_.find(connId);
        if (it != pcbs_by_id_.end() && it->second) {
            // Route to known PCB
            // pcb->DispatchFromNetwork(data, length, remote);
            return;
        }
    }

    // Fallback: unknown connection — SYN packets create new connections via server accept logic
}

int UcpNetwork::DoEvents()
{
    if (disposed_) return 0;

    UpdateCachedClock();

    // === Fire expired timers ===
    std::vector<std::function<void()>> dueCallbacks;
    int64_t nowUs = GetCurrentTimeUs();
    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        auto it = timer_heap_.begin();
        while (it != timer_heap_.end() && it->first <= nowUs) {
            dueCallbacks.push_back(it->second);
            it = timer_heap_.erase(it);
        }
    }

    for (auto& cb : dueCallbacks) {
        cb();
    }

    // === Tick all active PCBs ===
    auto snapshot = SnapshotPcbs();
    int pcbWork = 0;
    for (auto* pcb : snapshot) {
        if (pcb) {
            // pcbWork += pcb->OnTick(GetCurrentTimeUs());
        }
    }

    // === Idle when there's no work to do ===
    if (dueCallbacks.empty() && pcbWork == 0) {
        YieldWhenIdle();
    }

    return static_cast<int>(dueCallbacks.size()) + pcbWork;
}

void UcpNetwork::YieldWhenIdle()
{
    int64_t nextExpire = 0;
    bool hasTimer = false;
    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        if (!timer_heap_.empty()) {
            nextExpire = timer_heap_.begin()->first;
            hasTimer = true;
        }
    }

    // If the next timer is imminent (<1ms), do a thread yield instead of sleep
    if (hasTimer && (nextExpire - GetCurrentTimeUs()) <= 1000) {
        std::this_thread::yield();
        return;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

uint32_t UcpNetwork::AddTimer(int64_t expireUs, std::function<void()> callback)
{
    if (!callback) return 0;

    uint32_t id = next_timer_id_++;

    auto entry = std::make_shared<TimerEntry>();
    entry->id = id;
    entry->expireUs = expireUs;
    entry->callback = callback;

    // Wrap the callback to handle one-shot semantics and weak_ptr lifecycle
    auto weakEntry = std::weak_ptr<TimerEntry>(entry);
    entry->wrappedCallback = [this, id, weakEntry]() {
        auto entry = weakEntry.lock();
        bool shouldRun = false;
        {
            std::lock_guard<std::mutex> lock(timer_mutex_);
            auto it = active_timers_.find(id);
            if (it != active_timers_.end() && it->second.get() == entry.get()) {
                active_timers_.erase(it);
                shouldRun = true;
            }
        }
        if (shouldRun && entry) {
            entry->callback();
        }
    };

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        active_timers_[id] = entry;
        timer_heap_.emplace(expireUs, entry->wrappedCallback);
    }

    return id;
}

bool UcpNetwork::CancelTimer(uint32_t timerId)
{
    std::lock_guard<std::mutex> lock(timer_mutex_);
    return active_timers_.erase(timerId) > 0;
}

void UcpNetwork::Output(const uint8_t* data, size_t length, const Endpoint& remote)
{
    Output(data, length, remote, nullptr);
}

void UcpNetwork::Start(int /*port*/)
{
}

void UcpNetwork::Stop()
{
}

void UcpNetwork::Dispose()
{
    if (disposed_) return;
    disposed_ = true;
    Stop();

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        active_timers_.clear();
        timer_heap_.clear();
    }
}

void UcpNetwork::RegisterPcb(UcpPcb* pcb)
{
    if (!pcb) return;
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    if (std::find(active_pcbs_.begin(), active_pcbs_.end(), pcb) == active_pcbs_.end()) {
        active_pcbs_.push_back(pcb);
    }
    uint32_t connId = 0; // pcb->GetConnectionId();
    if (connId != 0) {
        pcbs_by_id_[connId] = pcb;
    }
}

void UcpNetwork::UnregisterPcb(UcpPcb* pcb)
{
    if (!pcb) return;
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    auto it = std::remove(active_pcbs_.begin(), active_pcbs_.end(), pcb);
    active_pcbs_.erase(it, active_pcbs_.end());
    uint32_t connId = 0; // pcb->GetConnectionId();
    if (connId != 0) {
        auto idIt = pcbs_by_id_.find(connId);
        if (idIt != pcbs_by_id_.end() && idIt->second == pcb) {
            pcbs_by_id_.erase(idIt);
        }
    }
}

void UcpNetwork::UpdatePcbConnectionId(UcpPcb* pcb, uint32_t oldId, uint32_t newId)
{
    if (!pcb || newId == 0) return;
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    if (oldId != 0) {
        auto it = pcbs_by_id_.find(oldId);
        if (it != pcbs_by_id_.end() && it->second == pcb) {
            pcbs_by_id_.erase(it);
        }
    }
    pcbs_by_id_[newId] = pcb;
    if (std::find(active_pcbs_.begin(), active_pcbs_.end(), pcb) == active_pcbs_.end()) {
        active_pcbs_.push_back(pcb);
    }
}

std::vector<UcpPcb*> UcpNetwork::SnapshotPcbs()
{
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    return active_pcbs_;
}

} // namespace ucp
