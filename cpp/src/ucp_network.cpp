/** @file ucp_network.cpp
 *  @brief Central network event loop implementation -- mirrors C# Ucp.UcpNetwork.
 *
 *  Manages a timer heap (multimap keyed by expiration timestamp), a registry
 *  of active UcpPcb instances, and a cached monotonic clock.  DoEvents fires
 *  expired timers (under timer_mutex_) and ticks each registered PCB via
 *  pcb->OnTick().  The Input() method uses UcpPacketCodec::TryDecode to
 *  decode inbound datagrams, routes them to the correct PCB by connection ID,
 *  and falls back to the NetworkTransportAdapter for SYN packets.
 *
 *  CreateServer / CreateConnection factory methods instantiate server/client
 *  objects wired to the shared NetworkTransportAdapter, which bridges this
 *  network's Output() method as the ITransport::Send() implementation.
 */

#include "ucp/ucp_network.h"
#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include "ucp/internal/ucp_pcb.h"
#include "ucp/ucp_packet_codec.h"
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"
#include "ucp/ucp_time.h"
#include <thread>
#include <chrono>
#include <algorithm>

namespace ucp {

UcpNetwork::UcpNetwork(const UcpConfiguration& config) noexcept : config_(config) {
    clock_start_ = std::chrono::steady_clock::now();
    cached_time_us_ = ReadStopwatchMicros();
    cached_time_ms_ = cached_time_us_ / Constants::MICROS_PER_MILLI;
    transport_adapter_ = ucp::make_shared_object<NetworkTransportAdapter>(this);
}

UcpNetwork::UcpNetwork() noexcept : UcpNetwork(UcpConfiguration()) {}

UcpNetwork::~UcpNetwork() noexcept {
    Dispose();
}

int64_t UcpNetwork::ReadStopwatchMicros() const noexcept {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now - clock_start_).count();
}

void UcpNetwork::UpdateCachedClock() noexcept {
    int64_t us = ReadStopwatchMicros();
    cached_time_us_.store(us, std::memory_order_relaxed);
    int64_t ms = us / Constants::MICROS_PER_MILLI;
    if (ms != cached_time_ms_.load(std::memory_order_relaxed)) {
        cached_time_ms_.store(ms, std::memory_order_relaxed);
    }
}

int64_t UcpNetwork::GetNowMicroseconds() const noexcept {
    return cached_time_us_.load(std::memory_order_relaxed);
}

int64_t UcpNetwork::GetCurrentTimeUs() const noexcept {
    return cached_time_us_.load(std::memory_order_relaxed);
}

void UcpNetwork::Input(const uint8_t* data, size_t length, const Endpoint& remote) noexcept {

    if (disposed_) {
        return;
    }

    if (NULLPTR == data || length < static_cast<size_t>(Constants::CommonHeaderSize)) {
        return;
    }

    ucp::shared_ptr<UcpPacket> packet;

    if (UcpPacketCodec::TryDecode(data, 0, length, packet)) {
        uint32_t connId = packet->header.connection_id;

        ucp::shared_ptr<UcpPcb> pcb;
        {

            std::lock_guard<std::mutex> lock(pcb_mutex_);
            auto it = pcbs_by_id_.find(connId);
            if (it != pcbs_by_id_.end()) {
                pcb = it->second;
            }
        }

        if (NULLPTR != pcb) {

            pcb->DispatchFromNetwork(packet.get(), remote);
            return;
        }

        if (NULLPTR == pcb) {
            ucp::vector<ucp::shared_ptr<UcpPcb>> snapshot;
            {
                std::lock_guard<std::mutex> lock(pcb_mutex_);
                snapshot = active_pcbs_;
            }
            for (auto& candidate : snapshot) {
                if (NULLPTR != candidate && candidate->IsValidCid(connId)) {
                    pcb = candidate;
                    break;
                }
            }
        }

        if (NULLPTR != pcb) {
            pcb->DispatchFromNetwork(packet.get(), remote);
            return;
        }

        if (packet->header.type != UcpPacketType::Syn) {
            return;
        }
    }

    if (transport_adapter_) {
        ucp::vector<uint8_t> buf(data, data + length);
        transport_adapter_->Raise(buf, remote);
    }
}

int UcpNetwork::DoEvents() noexcept {
    if (disposed_) {
        return 0;
    }

    UpdateCachedClock();

    ucp::vector<ucp::function<void()>> dueCallbacks;
    int64_t nowUs = GetCurrentTimeUs();

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        auto it = timer_heap_.begin();
        while (it != timer_heap_.end() && it->first <= nowUs) {

            if (active_timers_.find(it->second.id) != active_timers_.end()) {
                dueCallbacks.push_back(it->second.callback);
            }
            it = timer_heap_.erase(it);
        }
    }

    for (auto& cb : dueCallbacks) {
        try {
            cb();
        } catch (...) {
        }
    }

    auto snapshot = SnapshotPcbs();
    int pcbWork = 0;
    for (auto& pcb : snapshot) {
        if (NULLPTR != pcb) {
            pcbWork += pcb->OnTick(GetCurrentTimeUs());
        }
    }

    if (dueCallbacks.empty() && 0 == pcbWork) {
        idle_consecutive_.fetch_add(1, std::memory_order_relaxed);
        YieldWhenIdle();
    } else {
        idle_consecutive_.store(0, std::memory_order_relaxed);
    }

    return static_cast<int>(dueCallbacks.size()) + pcbWork;
}

void UcpNetwork::YieldWhenIdle() noexcept {
    int idle = idle_consecutive_.load(std::memory_order_relaxed);
    if (idle < 3) {

        std::this_thread::yield();
    } else if (idle < 50) {

        std::this_thread::sleep_for(std::chrono::microseconds(1));
    } else if (idle < 500) {

        std::this_thread::sleep_for(std::chrono::microseconds(100));
    } else {

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

uint32_t UcpNetwork::AddTimer(int64_t expireUs, ucp::function<void()> callback) noexcept {
    if (!callback) {
        return 0;
    }

    uint32_t id = next_timer_id_++;

    auto entry = ucp::make_shared_object<TimerEntry>();
    entry->id = id;
    entry->expireUs = expireUs;
    entry->callback = callback;

    auto weakEntry = ucp::weak_ptr<TimerEntry>(entry);
    entry->wrappedCallback = [this, id, weakEntry]() noexcept {
        if (disposed_.load(std::memory_order_acquire)) {
            // Network is being/has been disposed: timer registry was cleared,
            // and the owning object may be destroyed concurrently with DoEvents.
            // Refuse to touch timer_mutex_ (could be freed memory) — drop the
            // callback entirely.
            return;
        }
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
            try {
                entry->callback();
            } catch (...) {
            }
        }
    };

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        active_timers_[id] = entry;
        timer_heap_.emplace(expireUs, TimerHeapEntry{id, entry->wrappedCallback});
    }

    return id;
}

bool UcpNetwork::CancelTimer(uint32_t timerId) noexcept {
    std::lock_guard<std::mutex> lock(timer_mutex_);
    return 0 < active_timers_.erase(timerId);
}

void UcpNetwork::Output(const uint8_t* data, size_t length, const Endpoint& remote) noexcept {
    Output(data, length, remote, NULLPTR);
}

void UcpNetwork::Start(int) noexcept {}

void UcpNetwork::Stop() noexcept {}

void UcpNetwork::Dispose() noexcept {
    if (disposed_.exchange(true)) {
        return;
    }
    Stop();

    {
        std::lock_guard<std::mutex> lock(timer_mutex_);
        active_timers_.clear();
        timer_heap_.clear();
    }

    ucp::vector<ucp::shared_ptr<UcpPcb>> detachedPcbs;
    {
        std::lock_guard<std::mutex> lock(pcb_mutex_);
        detachedPcbs = active_pcbs_;
        active_pcbs_.clear();
        pcbs_by_id_.clear();
        pcbs_by_session_key_.clear();
    }
    // Detach any registered PCBs so their timer registrations stop pointing at
    // this (now defunct) network (mirrors C# UcpNetwork.Dispose -> pcb.DetachNetwork).
    // Without this, surviving connections would dereference a destroyed UcpNetwork.
    for (auto& pcb : detachedPcbs) {
        if (NULLPTR != pcb) {
            pcb->DetachNetwork();
        }
    }
}

void UcpNetwork::RegisterPcb(const ucp::shared_ptr<UcpPcb>& pcb) noexcept {
    if (NULLPTR == pcb) {
        return;
    }
    if (disposed_.load(std::memory_order_acquire)) {
        // Network is being/has been disposed: its registries were cleared and
        // every registered PCB was DetachNetwork'd.  Registering now would
        // resurrect a stale entry pointing at a soon-destroyed network.
        return;
    }
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    // Double-check under pcb_mutex_: Dispose clears the registries while
    // holding pcb_mutex_, so a concurrent Dispose between the pre-check above
    // and here is excluded.
    if (disposed_.load(std::memory_order_acquire)) {
        return;
    }
    UcpPcb* raw = pcb.get();
    if (std::find_if(active_pcbs_.begin(), active_pcbs_.end(), [raw](const ucp::shared_ptr<UcpPcb>& p) { return p.get() == raw; }) ==
        active_pcbs_.end()) {
        active_pcbs_.push_back(pcb);
    }
    uint32_t connId = raw->GetConnectionId();
    if (0 != connId) {
        auto existing = pcbs_by_id_.find(connId);
        if (existing != pcbs_by_id_.end() && existing->second.get() != raw) {
            if (existing->second->GetState() == UcpConnectionState::Closed) {
                pcbs_by_id_.erase(existing);
            } else {
                return;
            }
        }
        pcbs_by_id_[connId] = pcb;
    }
    uint64_t sessionKey = raw->GetSessionKey();
    if (0 != sessionKey) {
        auto it = pcbs_by_session_key_.find(sessionKey);
        if (it != pcbs_by_session_key_.end() && it->second.get() != raw) {
            if (it->second->GetState() == UcpConnectionState::Closed) {
                pcbs_by_session_key_.erase(it);
            } else {
                return;
            }
        }
        pcbs_by_session_key_[sessionKey] = pcb;
    }
}

void UcpNetwork::UnregisterPcb(UcpPcb* pcb) noexcept {
    if (NULLPTR == pcb) {
        return;
    }
    auto match = [pcb](const ucp::shared_ptr<UcpPcb>& p) noexcept { return p.get() == pcb; };
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    auto it = std::remove_if(active_pcbs_.begin(), active_pcbs_.end(), match);
    active_pcbs_.erase(it, active_pcbs_.end());
    uint32_t connId = pcb->GetConnectionId();
    if (0 != connId) {
        auto idIt = pcbs_by_id_.find(connId);
        if (idIt != pcbs_by_id_.end() && idIt->second.get() == pcb) {
            pcbs_by_id_.erase(idIt);
        }
    }
    uint64_t sessionKey = pcb->GetSessionKey();
    if (0 != sessionKey) {
        auto skIt = pcbs_by_session_key_.find(sessionKey);
        if (skIt != pcbs_by_session_key_.end() && skIt->second.get() == pcb) {
            pcbs_by_session_key_.erase(skIt);
        }
    }
}

void UcpNetwork::UpdatePcbConnectionId(UcpPcb* pcb, uint32_t oldId, uint32_t newId) noexcept {
    if (NULLPTR == pcb || 0 == newId) {
        return;
    }
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    if (0 != oldId) {
        auto it = pcbs_by_id_.find(oldId);
        if (it != pcbs_by_id_.end() && it->second.get() == pcb) {
            pcbs_by_id_.erase(it);
        }
    }

    auto pcbShared = ucp::shared_ptr<UcpPcb>();
    for (auto& sp : active_pcbs_) {
        if (sp.get() == pcb) {
            pcbShared = sp;
            break;
        }
    }
    if (!pcbShared) {

        return;
    }
    pcbs_by_id_[newId] = pcbShared;
    if (std::find_if(active_pcbs_.begin(), active_pcbs_.end(), [pcb](const ucp::shared_ptr<UcpPcb>& p) { return p.get() == pcb; }) ==
        active_pcbs_.end()) {
        active_pcbs_.push_back(pcbShared);
    }
}

void UcpNetwork::RegisterSessionKey(uint64_t sessionKey, UcpPcb* pcb) noexcept {
    if (0 == sessionKey || NULLPTR == pcb) {
        return;
    }
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    ucp::shared_ptr<UcpPcb> pcbShared;
    for (auto& sp : active_pcbs_) {
        if (sp.get() == pcb) {
            pcbShared = sp;
            break;
        }
    }
    if (!pcbShared) {
        return;
    }
    auto it = pcbs_by_session_key_.find(sessionKey);
    if (it != pcbs_by_session_key_.end()) {
        if (it->second.get() == pcb) {
            return;
        }
        if (it->second->GetState() == UcpConnectionState::Closed) {
            pcbs_by_session_key_.erase(it);
        } else {
            return;
        }
    }
    pcbs_by_session_key_[sessionKey] = pcbShared;
}

ucp::shared_ptr<UcpPcb> UcpNetwork::TryRegisterSessionKey(uint64_t sessionKey, UcpPcb* pcb) noexcept {
    if (0 == sessionKey || NULLPTR == pcb) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    ucp::shared_ptr<UcpPcb> pcbShared;
    for (auto& sp : active_pcbs_) {
        if (sp.get() == pcb) {
            pcbShared = sp;
            break;
        }
    }
    if (!pcbShared) {
        return nullptr;
    }
    auto it = pcbs_by_session_key_.find(sessionKey);
    if (it != pcbs_by_session_key_.end()) {
        if (it->second.get() == pcb) {
            return it->second;
        }
        if (it->second->GetState() != UcpConnectionState::Closed) {
            return it->second;
        }
        pcbs_by_session_key_.erase(it);
    }
    pcbs_by_session_key_[sessionKey] = pcbShared;
    return nullptr;
}

void UcpNetwork::UnregisterSessionKey(uint64_t sessionKey) noexcept {
    if (0 == sessionKey) {
        return;
    }
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    pcbs_by_session_key_.erase(sessionKey);
}

ucp::shared_ptr<UcpPcb> UcpNetwork::LookupBySessionKey(uint64_t sessionKey) noexcept {
    if (0 == sessionKey) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    auto it = pcbs_by_session_key_.find(sessionKey);
    return (it != pcbs_by_session_key_.end()) ? it->second : nullptr;
}

ucp::shared_ptr<UcpPcb> UcpNetwork::LookupByConnectionId(uint32_t connectionId) noexcept {
    if (0 == connectionId) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    auto it = pcbs_by_id_.find(connectionId);
    return (it != pcbs_by_id_.end()) ? it->second : nullptr;
}

ucp::vector<ucp::shared_ptr<UcpPcb>> UcpNetwork::SnapshotPcbs() noexcept {
    std::lock_guard<std::mutex> lock(pcb_mutex_);
    return active_pcbs_;
}

ucp::shared_ptr<UcpServer> UcpNetwork::CreateServer(int port) noexcept {

    ucp::shared_ptr<UcpServer> server = ucp::make_shared_object<UcpServer>(transport_adapter_.get(), false, config_.Clone(), this);
    server->Start(port);
    return server;
}

ucp::shared_ptr<UcpConnection> UcpNetwork::CreateConnection() noexcept {
    return CreateConnection(config_);
}

ucp::shared_ptr<UcpConnection> UcpNetwork::CreateConnection(const UcpConfiguration& config) noexcept {
    UcpConfiguration cfg = config;

    ucp::shared_ptr<UcpConnection> conn = ucp::make_shared_object<UcpConnection>(transport_adapter_.get(), false, cfg, this);
    return conn;
}

} // namespace ucp
