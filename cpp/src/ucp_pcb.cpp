/** @file ucp_pcb.cpp
 *  @brief UCP Protocol Control Block implementation -- the core protocol engine.
 *
 *  Implements the complete UCP protocol state machine, including 3-way handshake,
 *  send/receive buffers, NAK/SACK-based loss detection, RTO recovery, UCP
 *  congestion control, pacing, fair-queue credit, and FEC encoding/decoding.
 *
 *  All async operations use callback-based Proactor pattern with a dedicated
 *  worker thread.  No std::async, std::future, or std::promise are used.
 *  Synchronous wrappers block the caller via condition_variable.
 */

#include "ucp/internal/ucp_pcb.h"
#include "ucp/ucp_packets.h"
#include "ucp/ucp_packet_codec.h"
#include "ucp/ucp_sack_generator.h"
#include "ucp/ucp_fec_codec.h"
#include "ucp/ucp_pacing.h"
#include "ucp/transport/itransport.h"
#include "ucp/ucp_memory.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <new>
#include <iostream>
#include <random>
#include <cmath>
#include <chrono>
#include <thread>

#ifdef UCP_TRACE
namespace {
std::atomic<bool> g_ucpTraceEnabled{false};
}
void ucp::UcpPcb::SetTraceEnabled(bool enabled) noexcept {
    g_ucpTraceEnabled = enabled;
}
bool ucp::UcpPcb::IsTraceEnabled() noexcept {
    return g_ucpTraceEnabled;
}
void ucp::UcpSetTraceEnabled(bool enabled) noexcept {
    g_ucpTraceEnabled = enabled;
}
#define UCP_LOG(pcb, event, ...)                                                                                                           \
    do {                                                                                                                                   \
        if (::g_ucpTraceEnabled) {                                                                                                         \
            std::fprintf(stderr, "[UCP_TRACE %08X] " event ": ", (pcb)->GetConnectionId());                                                \
            std::fprintf(stderr, __VA_ARGS__);                                                                                             \
            std::fprintf(stderr, "\n");                                                                                                    \
            std::fflush(stderr);                                                                                                           \
        }                                                                                                                                  \
    } while (0)
#else
void ucp::UcpSetTraceEnabled(bool) noexcept {}
void ucp::UcpPcb::SetTraceEnabled(bool) noexcept {}
bool ucp::UcpPcb::IsTraceEnabled() noexcept {
    return false;
}
#define UCP_LOG(pcb, event, ...) ((void)0)
#endif

namespace ucp {

static constexpr int64_t ACK_DELAY_RTT_THRESHOLD_MILLIS = 30LL;
static constexpr uint16_t MAX_FRAGMENTS_PER_MESSAGE = 65535;

/** @brief Generates a cryptographically random 32-bit unsigned integer.
 *  Uses std::random_device to seed entropy across two 16-bit halves.
 *  @return A random uint32_t value (may be zero). */
static uint32_t SecureRandomUint32() noexcept {
    try {
        std::random_device rd;
        uint32_t v = rd();
        v = (v << 16) | (uint32_t)(rd() & 0xFFFF);
        return v;
    } catch (...) {
        static std::atomic<bool> srandSeeded{false};
        if (!srandSeeded.exchange(true)) {
            std::srand(static_cast<unsigned>(std::chrono::system_clock::now().time_since_epoch().count()));
        }
        uint32_t v = static_cast<uint32_t>(std::rand());
        v = (v << 16) | (static_cast<uint32_t>(std::rand()) & 0xFFFF);
        return v;
    }
}
/** @brief Generates a cryptographically random 64-bit unsigned integer.
 *  Combines three std::random_device calls for full 64-bit entropy.
 *  @return A random uint64_t value (may be zero). */
static uint64_t SecureRandomUint64() noexcept {
    try {
        std::random_device rd;
        uint64_t v = (uint64_t)rd();
        v = (v << 32) | (uint64_t)rd();
        v = (v << 16) | (uint64_t)(rd() & 0xFFFF);
        return v;
    } catch (...) {

        uint64_t v = static_cast<uint64_t>(std::rand());
        v = (v << 32) | static_cast<uint64_t>(std::rand());
        v = (v << 16) | (static_cast<uint64_t>(std::rand()) & 0xFFFF);
        return v;
    }
}
/** @brief Generates the next connection ID (non-zero).
 *  @return A non-zero random uint32_t suitable as a connection identifier. */
uint32_t UcpPcb::NextConnectionId() noexcept {
    uint32_t id;
    do {
        id = SecureRandomUint32();
    } while (0 == id);
    return id;
}
/** @brief Generates the next session key (non-zero).
 *  @return A non-zero random uint64_t used for reconnection/persistent session identification. */
uint64_t UcpPcb::NextSessionKey() noexcept {
    uint64_t key;
    do {
        key = SecureRandomUint64();
    } while (0 == key);
    return key;
}
/** @brief Generates the next send sequence number.
 *  @return A random uint32_t starting sequence for the data stream. */
uint32_t UcpPcb::NextSequence() noexcept {
    return SecureRandomUint32();
}
/** @brief Generates a new connection ID for CID rotation.
 *  @return A non-zero random uint32_t used to migrate connection identity. */
uint32_t UcpPcb::GenerateNewCid() noexcept {
    return NextConnectionId();
}
/** @brief Returns the current microsecond timestamp from the network clock or system fallback.
 *  @return Microseconds since an unspecified epoch. */
int64_t UcpPcb::NowMicros() noexcept {
    if (m_ctsCanceled)
        return 0;
    auto* net = m_network.load(std::memory_order_acquire);
    return net ? net->GetCurrentTimeUs() : UcpTime::ReadStopwatchMicroseconds();
}
/** @brief Attempts to read the stored remote endpoint.
 *  @param[out] remoteEndpoint Filled with the remote endpoint on success.
 *  @return True if a remote endpoint has been set, false otherwise. */
bool UcpPcb::TryGetRemoteEndpoint(Endpoint& remoteEndpoint) const noexcept {
    std::lock_guard<std::mutex> lock(m_endpointMutex);
    if (!m_hasRemoteEndpoint) {
        return false;
    }
    remoteEndpoint = m_remoteEndpoint;
    return true;
}
/** @brief Records delivered bytes into the measured-bandwidth sliding time-slot accumulator.
 *  Advances the slot ring buffer forward when the current time crosses a slot boundary,
 *  zeroing any intermediate slots that have been skipped (no ACK activity during those periods).
 *  @param nowMicros     Current microsecond timestamp.
 *  @param deliveredBytes  Number of bytes newly acknowledged in this update. */
void UcpPcb::AdvanceMeasuredBwSlot(int64_t nowMicros, int64_t deliveredBytes) noexcept {
    if (0 >= deliveredBytes) {
        return;
    }
    int64_t slotDuration = PcbConst::MEASURED_BW_SLOT_MICROS;
    int64_t slotStart = nowMicros - (nowMicros % slotDuration);
    int idx = m_measuredBwSlotIndex.load(std::memory_order_relaxed);
    if (m_measuredBwSlotStart[idx].load(std::memory_order_relaxed) != slotStart) {
        int targetIndex = (int)((nowMicros / slotDuration) % PcbConst::MEASURED_BW_SLOT_COUNT);
        while (m_measuredBwSlotIndex.load(std::memory_order_relaxed) != targetIndex) {
            idx = (idx + 1) % PcbConst::MEASURED_BW_SLOT_COUNT;
            m_measuredBwSlotIndex.store(idx, std::memory_order_relaxed);
            m_measuredBwSlots[idx].store(0, std::memory_order_relaxed);
            m_measuredBwSlotStart[idx].store(-1, std::memory_order_relaxed);
        }
        m_measuredBwSlots[idx].store(0, std::memory_order_relaxed);
        m_measuredBwSlotStart[idx].store(slotStart, std::memory_order_relaxed);
    }
    m_measuredBwSlots[idx].fetch_add(deliveredBytes, std::memory_order_relaxed);
}
/** @brief Computes the measured bandwidth over the recent sliding window of time slots.
 *  Sums bytes from non-expired slots, determines the time span those slots cover, and
 *  divides byte count by elapsed wall-clock time to produce bytes per second.
 *  @param nowMicros  Current microsecond timestamp.
 *  @return Bandwidth in bytes per second, or 0.0 if insufficient data. */
double UcpPcb::ComputeMeasuredBandwidth(int64_t nowMicros) const noexcept {
    int64_t slotDuration = PcbConst::MEASURED_BW_SLOT_MICROS;
    int64_t minSlotStart = nowMicros - (PcbConst::MEASURED_BW_SLOT_COUNT * slotDuration);
    int64_t totalBytes = 0;
    for (int i = 0; i < PcbConst::MEASURED_BW_SLOT_COUNT; i++) {
        int64_t slotStart = m_measuredBwSlotStart[i].load(std::memory_order_relaxed);
        if (0 <= slotStart && slotStart >= minSlotStart && slotStart <= nowMicros) {
            totalBytes += m_measuredBwSlots[i].load(std::memory_order_relaxed);
        }
    }
    int64_t elapsed = PcbConst::MEASURED_BW_SLOT_COUNT * slotDuration;
    if (0 >= elapsed || 0 >= totalBytes) {
        return 0.0;
    }
    return (double)totalBytes * (double)Constants::MICROS_PER_SECOND / (double)elapsed;
}
/** @brief Creates a UCP common packet header with the current connection ID and timestamp.
 *  @param type              Packet type (Syn, Ack, Data, etc.).
 *  @param flags             OR-combination of UcpPacketFlags.
 *  @param timestampMicros   Monotonic timestamp for the packet header.
 *  @return A fully populated UcpCommonHeader struct. */
UcpCommonHeader UcpPcb::CreateHeader(UcpPacketType type, int flags, int64_t timestampMicros, uint32_t connectionId) noexcept {
    UcpCommonHeader header;
    header.type = type;
    header.flags = (UcpPacketFlags)flags;
    header.connection_id = connectionId;
    header.timestamp = timestampMicros;
    return header;
}

/** @brief Constructs the protocol control block -- the core state machine for one UCP connection.
 *  Initialises UCP congestion control, RTO estimator, SACK generator, pacing controller,
 *  optional FEC codec, and starts the background worker thread.  Registers with the network
 *  or starts a standalone timer thread depending on the operating mode.
 *  @param transport       The underlying ITransport for sending/receiving UDP datagrams.
 *  @param isServerSide    True if this PCB is server-side (determines session key ownership).
 *  @param useFairQueue    True to enable fair-queue bandwidth scheduling between connections.
 *  @param closedCallback  Callback invoked when the PCB transitions to Closed state.
 *  @param connectionId    Pre-assigned connection ID (0 = auto-generate).
 *  @param config          Protocol configuration (cloned internally).
 *  @param network         Owning UcpNetwork (NULLPTR for standalone connections). */
UcpPcb::UcpPcb(transport::ITransport* transport, bool isServerSide, bool useFairQueue, ClosedCallback closedCallback, uint32_t connectionId,
               const UcpConfiguration& config, UcpNetwork* network)
    : m_transport(transport), m_useFairQueue(useFairQueue), m_isServerSide(isServerSide), m_config(config),
      m_closedCallback(closedCallback), m_network(network), m_connectionId(0 != connectionId ? connectionId : NextConnectionId()),
      m_sessionKey(m_isServerSide.load(std::memory_order_relaxed) ? 0ULL : NextSessionKey()),
      m_aliveFlag(ucp::make_shared_object<std::atomic<bool>>(true)) {
    m_rtoEstimator = ucp::make_shared_object<UcpRtoEstimator>(m_config);
    if (!m_rtoEstimator) {
        // Component allocation failure: propagate so make_shared_object's catch
        // returns NULLPTR and the caller's null check handles it.  Leaving a
        // zombie object (non-null PCB with null components) would crash later
        // on m_rtoEstimator->... .
        throw std::bad_alloc();
    }
    m_rtoEstimatorAtomic.store(m_rtoEstimator.get(), std::memory_order_release);
    m_congestion = ucp::make_shared_object<UcpCongestionControl>(static_cast<int64_t>(m_config.InitialBandwidthBytesPerSecond),
                                                                 m_config.Mss, static_cast<int64_t>(m_config.MaxCongestionWindowBytes),
                                                                 static_cast<int64_t>(m_config.InitialCwndBytes()),
                                                                 static_cast<int64_t>(m_config.MaxPacingRateBytesPerSecond));
    if (!m_congestion) {
        throw std::bad_alloc();
    }
    m_congestionAtomic.store(m_congestion.get(), std::memory_order_release);
    m_sackGenerator = ucp::make_shared_object<UcpSackGenerator>();
    if (!m_sackGenerator) {
        throw std::bad_alloc();
    }
    m_sackGeneratorAtomic.store(m_sackGenerator.get(), std::memory_order_release);
    m_pacing = ucp::make_shared_object<PacingController>(m_config, static_cast<double>(m_config.InitialBandwidthBytesPerSecond));
    m_pacingAtomic.store(m_pacing.get(), std::memory_order_release);
    if (!m_pacing) {
        throw std::bad_alloc();
    }
    if (0.0 < m_config.FecRedundancy && 1 < m_config.FecGroupSize) {
        int fecRepairCount = (std::max)(1, (int)std::ceil(m_config.FecGroupSize * m_config.FecRedundancy));
        m_fecCodec = ucp::make_shared_object<UcpFecCodec>(m_config.FecGroupSize, fecRepairCount);
        m_fecCodecAtomic.store(m_fecCodec.get(), std::memory_order_release);
    }
    m_state = UcpConnectionState::Init;
    m_nextSendSequence.store(NextSequence(), std::memory_order_relaxed);
    m_lastPeerAliveMicros.store(NowMicros(), std::memory_order_relaxed);
    m_lastAckSentMicros = m_lastPeerAliveMicros.load(std::memory_order_relaxed);
    for (int i = 0; i < PcbConst::MEASURED_BW_SLOT_COUNT; i++) {
        m_measuredBwSlotStart[i] = -1;
    }

    uint32_t rwnd = m_config.ReceiveWindowBytes();
    m_remoteWindowBytes.store(0 < rwnd ? rwnd : PcbConst::DEFAULT_RECEIVE_WINDOW_BYTES, std::memory_order_relaxed);
    m_localReceiveWindowBytes = 0 < rwnd ? rwnd : PcbConst::DEFAULT_RECEIVE_WINDOW_BYTES;

    StartWorker();

    StartNotifyThread();

    if (nullptr != m_network.load(std::memory_order_relaxed)) {

        ScheduleTimer();
    } else {
        int timerDelayMs = (std::max)(PcbConst::MIN_TIMER_WAIT_MILLISECONDS, m_config.TimerIntervalMilliseconds);
        m_standaloneTimerRunning = true;
        m_standaloneTimerThread = std::thread([this, timerDelayMs]() noexcept {
            while (m_standaloneTimerRunning && !m_ctsCanceled) {
                int64_t delayMs = timerDelayMs;
                {
                    if (m_flushDelayed.load(std::memory_order_relaxed) && 0 < m_flushDelayedDeadline.load(std::memory_order_relaxed)) {
                        int64_t remainUs = m_flushDelayedDeadline.load(std::memory_order_relaxed) - NowMicros();
                        if (remainUs <= 0)
                            delayMs = 0;
                        else if (remainUs / 1000 < delayMs)
                            delayMs = std::max(static_cast<int64_t>(1), remainUs / 1000);
                    }
                }
                {
                    std::unique_lock<std::mutex> lk(m_standaloneTimerMutex);
                    m_standaloneTimerCv.wait_for(lk, std::chrono::milliseconds(delayMs),
                                                 [this]() noexcept { return !m_standaloneTimerRunning || m_ctsCanceled; });
                }
                if (!m_standaloneTimerRunning || m_ctsCanceled) {
                    break;
                }
                EnqueueWork([this]() noexcept { OnTimer(); });
            }
        });
    }
}

UcpPcb::~UcpPcb() noexcept {
    Dispose();
    // If the PCB was destroyed from within its own worker thread (server-side
    // path: TransitionToClosed -> m_closedCallback -> OnPcbClosed destroys the
    // entry, of which this PCB is part), Dispose's StopWorker could not join
    // us.  Detach so the std::thread object does not remain joinable when this
    // object is destroyed (that would std::terminate).  WorkerLoop observes
    // *m_aliveFlag == false and exits without touching members again.
    if (m_workerThread.joinable() && std::this_thread::get_id() == m_workerThread.get_id()) {
        m_workerThread.detach();
    }
}

/** @brief Releases all connection resources: stops worker, unregisters from network,
 *  fires pending callbacks with Closed/Disconnected, notifies conditions, and destroys
 *  all sub-components (RTO, UCP, SACK, FEC, pacing).  Idempotent. */
void UcpPcb::Dispose() noexcept {
    if (m_disposed) {
        return;
    }
    m_disposed = true;
    m_ctsCanceled = true;
    if (m_aliveFlag) {
        *m_aliveFlag = false;
    }
    m_standaloneTimerRunning = false;
    {
        std::lock_guard<std::mutex> lk(m_standaloneTimerMutex);
        m_standaloneTimerCv.notify_all();
    }
    if (m_standaloneTimerThread.joinable()) {
        if (std::this_thread::get_id() == m_standaloneTimerThread.get_id()) {
            m_standaloneTimerThread.detach();
        } else {
            try {
                m_standaloneTimerThread.join();
            } catch (...) {
            }
        }
    }

    StopNotifyThread();

    StopWorker();

    FlushPendingReceiveCallbacks();

    ReleaseNetworkRegistrations();

    FirePendingConnectCallback(UcpError::Disconnected);
    FirePendingCloseCallback(UcpError::None);

    ucp::vector<ReceiveAsyncCallback> pendingCbs;
    {
        std::lock_guard<std::mutex> lock(m_receiveMutex);
        while (!m_pendingReceives.empty()) {
            PendingReceiveOp op = m_pendingReceives.front();
            m_pendingReceives.pop_front();
            if (op.callback) {
                pendingCbs.push_back(op.callback);
            }
        }
    }
    for (size_t i = 0; i < pendingCbs.size(); i++) {
        if (pendingCbs[i]) {
            try {
                pendingCbs[i](UcpError::Closed, 0);
            } catch (...) {
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        m_receiveSignal.notify_all();
    }
    {
        std::lock_guard<std::mutex> lk(m_sendSpaceSignalMutex);
        m_sendSpaceSignal.notify_all();
    }

    {
        std::lock_guard<std::mutex> lock(m_sync);
        m_congestionAtomic.store(nullptr, std::memory_order_release);
        m_pacingAtomic.store(nullptr, std::memory_order_release);
        m_rtoEstimatorAtomic.store(nullptr, std::memory_order_release);
        m_sackGeneratorAtomic.store(nullptr, std::memory_order_release);
        m_fecCodecAtomic.store(nullptr, std::memory_order_release);
        // Component shared_ptrs (m_rtoEstimator/m_congestion/m_sackGenerator/m_fecCodec/m_pacing)
        // are intentionally NOT reset here: the network thread may still be dispatching an
        // in-flight packet through a shared_ptr-pinned UcpPcb (DispatchFromNetwork holds the
        // pcb alive).  Resetting here would let that thread dereference a null component
        // (segfault).  Components live until the pcb destructor runs, which is guaranteed to
        // happen after every dispatch reference is gone.  The atomic aliases above stop new
        // reads for public APIs (they return 0/empty after Dispose).
        m_network.store(NULLPTR, std::memory_order_release);
        m_transport.store(NULLPTR, std::memory_order_release);
    }
}

/** @brief Starts the background worker thread that serialises all async operations.
 *  The thread runs WorkerLoop() until StopWorker() signals termination. */
void UcpPcb::StartWorker() noexcept {
    m_workerStopped = false;
    m_workerThread = std::thread([this]() noexcept { WorkerLoop(); });
}

/** @brief Stops the background worker thread by setting the stop flag and notifying.
 *  Joins or detaches the thread depending on whether we are called from within it. */
void UcpPcb::StopWorker() noexcept {
    bool onWorkerThread = (m_workerThread.joinable() && std::this_thread::get_id() == m_workerThread.get_id());
    if (!onWorkerThread && m_workerThread.joinable()) {
        // Set the joining flag BEFORE stopping: the worker loop checks
        // (m_workerStopped && !m_workerJoining) to decide whether to
        // self-detach.  Ordering m_workerJoining before m_workerStopped
        // guarantees that once the worker observes m_workerStopped=true
        // (written by this external thread), m_workerJoining is already true,
        // so it never detaches concurrently with our join() below
        // (detach+join on the same std::thread is UB / std::terminate).
        m_workerJoining.store(true, std::memory_order_release);
    }
    m_workerStopped = true;
    {
        std::lock_guard<std::mutex> lock(m_workMutex);
        m_workSignal.notify_all();
    }
    if (onWorkerThread) {
        // The caller is the worker itself (user callback invoked Dispose).
        // We cannot join ourselves.  Detach now: WorkerLoop observes
        // *m_aliveFlag == false (set by Dispose) right after work() returns
        // and returns without touching any member, so detaching here is safe
        // and guarantees the std::thread object is not joinable when the pcb
        // is later destroyed.
        if (m_workerThread.joinable()) {
            m_workerThread.detach();
        }
        return;
    }
    if (m_workerThread.joinable()) {
        try {
            m_workerThread.join();
            m_workerJoining.store(false, std::memory_order_release);
        } catch (...) {
        }
    }
}

/** @brief Main loop of the background worker thread: dequeues work items one at a time
 *  and executes them.  Blocks on a condition variable when the queue is empty. */
void UcpPcb::WorkerLoop() noexcept {
    // Capture the alive flag OUTSIDE the loop: it is self-held (make_shared,
    // outlives this object), so after work() destroys the PCB we can still
    // read it to decide whether to exit without touching any other member.
    ucp::shared_ptr<std::atomic<bool>> alive = m_aliveFlag;
    while (!m_workerStopped) {
        ucp::function<void()> work;
        {
            std::unique_lock<std::mutex> lock(m_workMutex);
            m_workSignal.wait(lock, [this]() noexcept { return !m_workQueue.empty() || m_workerStopped; });
            if (m_workerStopped && m_workQueue.empty()) {
                break;
            }
            work = std::move(m_workQueue.front());
            m_workQueue.pop_front();
        }
        if (work) {
            try {
                work();
            } catch (...) {
            }
        }
        // If the PCB was destroyed from within work() (server-side path:
        // TransitionToClosed -> m_closedCallback -> OnPcbClosed releases the
        // last shared_ptr), the destructor detached us and the object memory
        // is gone.  *alive is self-held (outlives the object), so check the
        // LOCAL copy FIRST and return without touching any member.
        if (!alive || !alive->load(std::memory_order_acquire)) {
            return;
        }
        if (m_workerStopped && m_workerThread.joinable() && std::this_thread::get_id() == m_workerThread.get_id()) {
            // Dispose was called from a user callback on this thread (e.g. the
            // user's DataReceived handler disposed the connection): StopWorker
            // could not join us, so detach here after the loop has stopped
            // touching members. The std::thread object must not remain
            // joinable when the owning object is destroyed (that would
            // std::terminate), and we must not touch members afterwards.
            // If an external thread is concurrently joining (m_workerJoining
            // set), do NOT detach: detach+join on the same std::thread races;
            // the joiner will reap the thread as soon as we return.
            if (!m_workerJoining.load(std::memory_order_acquire)) {
                m_workerThread.detach();
            }
            return;
        }
    }
}

/** @brief Enqueues a work item onto the worker thread's serial queue.
 *  @param work  Callable to execute on the worker thread. */
void UcpPcb::EnqueueWork(ucp::function<void()> work) noexcept {
    if (!work) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(m_workMutex);
        m_workQueue.push_back(std::move(work));
    }
    m_workSignal.notify_one();
}

/** @brief Fires the pending connect callback (if any) with the given error code.
 *  Extracts and clears the callback under lock, invokes it outside the lock.
 *  Uses atomic exchange for m_hasPendingConnectCallback to avoid m_sync early-exit.
 *  @param error  Error code to deliver to the callback. */
void UcpPcb::FirePendingConnectCallback(UcpError error) noexcept {
    if (!m_hasPendingConnectCallback.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    ConnectAsyncCallback cb;
    {
        std::lock_guard<std::mutex> lock(m_pendingCallbackMutex);
        cb = m_pendingConnectCallback;
        m_pendingConnectCallback = ConnectAsyncCallback();
    }
    if (cb) {
        try {
            cb(error, m_connectionId);
        } catch (...) {
        }
    }
}

/** @brief Fires the pending close callback (if any) with the given error code.
 *  Extracts and clears the callback under lock, invokes it outside the lock.
 *  Uses atomic exchange for m_hasPendingCloseCallback to avoid m_sync early-exit.
 *  @param error  Error code to deliver to the callback. */
void UcpPcb::FirePendingCloseCallback(UcpError error) noexcept {
    if (!m_hasPendingCloseCallback.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    CloseAsyncCallback cb;
    {
        std::lock_guard<std::mutex> lock(m_pendingCallbackMutex);
        cb = m_pendingCloseCallback;
        m_pendingCloseCallback = CloseAsyncCallback();
    }
    if (cb) {
        try {
            cb(error);
        } catch (...) {
        }
    }
}

/** @brief Attempts to acquire the flush-send lock (atomic flag).
 *  Prevents concurrent FlushSendQueueAsync invocations.
 *  @return True if the lock was acquired, false if already held. */
bool UcpPcb::TryAcquireFlushLock() noexcept {
    bool expected = false;
    return m_flushLockAcquired.compare_exchange_strong(expected, true);
}

void UcpPcb::ReleaseFlushLock() noexcept {
    m_flushLockAcquired.store(false, std::memory_order_release);
}

/** @brief Starts the notification thread that fires deferred receive callbacks.
 *  This thread waits on m_notifyCV, fires queued callbacks via FlushPendingReceiveCallbacks,
 *  and loops until m_notifyStopped is set. */
void UcpPcb::StartNotifyThread() noexcept {
    m_notifyStopped = false;
    // Self-held alive flag (outlives this object): if a user receive callback
    // disposes the PCB, the destructor runs on THIS thread (StopNotifyThread
    // self-detaches) and the object memory is gone.  After FlushPendingReceiveCallbacks
    // we check the LOCAL copy before touching any member again.
    ucp::shared_ptr<std::atomic<bool>> alive = m_aliveFlag;
    m_notifyThread = std::thread([this, alive]() noexcept {
        while (true) {
            {
                std::unique_lock<std::mutex> lock(m_notifyMutex);
                m_notifyCV.wait(lock, [this]() noexcept {
                    return m_notifyStopped.load(std::memory_order_acquire) || m_callbackPending.load(std::memory_order_acquire);
                });
            }
            if (m_notifyStopped) {
                FlushPendingReceiveCallbacks();
                break;
            }
            while (m_callbackPending.exchange(false, std::memory_order_acq_rel)) {
                FlushPendingReceiveCallbacks();
                if (!alive || !alive->load(std::memory_order_acquire)) {
                    return;
                }
            }
        }
    });
}

/** @brief Stops the notification thread, flushes remaining callbacks, and joins the thread.
 *  Idempotent: safe to call multiple times. */
void UcpPcb::StopNotifyThread() noexcept {
    m_notifyStopped = true;
    {
        std::lock_guard<std::mutex> lock(m_notifyMutex);
        m_notifyCV.notify_one();
    }
    if (m_notifyThread.joinable()) {
        if (std::this_thread::get_id() == m_notifyThread.get_id()) {
            m_notifyThread.detach();
        } else {
            try {
                m_notifyThread.join();
            } catch (...) {
            }
        }
    }
}

/** @brief Returns the current connection state.
 *  @return UcpConnectionState enum (Init, HandshakeSynSent, Established, etc.). */
UcpConnectionState UcpPcb::GetState() noexcept {
    return m_state.load(std::memory_order_acquire);
}
/** @brief Returns the current UCP pacing rate in bytes per second.
 *  @return Pacing rate from UCP, or 0.0 if UCP is not initialised. */
double UcpPcb::GetCurrentPacingRateBytesPerSecond() noexcept {
    std::lock_guard<std::mutex> ccLock(m_sync);
    auto cc = m_congestionAtomic.load(std::memory_order_acquire);
    return cc ? cc->GetPacingRateBytesPerSecond() : 0.0;
}
/** @brief Checks whether the send buffer contains any pending (unacked) data.
 *  @return True if the send buffer is non-empty. */
bool UcpPcb::HasPendingSendData() noexcept {
    std::lock_guard<std::mutex> lock(m_sendBufMutex);
    return !m_sendBuffer.empty();
}
/** @brief Takes a snapshot of all connection diagnostics counters and estimates.
 *  Provides telemetry for external monitoring and debugging tools.
 *  @return A populated UcpConnectionDiagnostics struct with current metrics. */
UcpConnectionDiagnostics UcpPcb::GetDiagnosticsSnapshot() noexcept {
    if (m_disposed) {
        return UcpConnectionDiagnostics();
    }
    UcpConnectionDiagnostics diag;
    diag.State = (int)m_state.load(std::memory_order_relaxed);
    diag.FlightBytes = m_flightBytes.load(std::memory_order_relaxed);
    diag.RemoteWindowBytes = m_remoteWindowBytes.load(std::memory_order_relaxed);
    diag.BytesSent = m_bytesSent;
    diag.BytesReceived = m_bytesReceived;
    diag.SentDataPackets = m_sentDataPackets;
    diag.RetransmittedPackets = m_retransmittedPackets;
    diag.SentAckPackets = m_sentAckPackets;
    diag.SentNakPackets = m_sentNakPackets;
    diag.SentRstPackets = m_sentRstPackets;
    diag.FastRetransmissions = m_fastRetransmissions;
    diag.TimeoutRetransmissions = m_timeoutRetransmissions;
    {
        // CC mutations happen under m_sync (OnAck/OnPacketSent/...), so the
        // diagnostic snapshot must read under the same lock to avoid racing
        // the non-atomic CC fields.
        std::lock_guard<std::mutex> ccLock(m_sync);
        auto cc = m_congestionAtomic.load(std::memory_order_acquire);
        if (cc) {
            diag.CongestionWindowBytes = static_cast<int32_t>(cc->GetCongestionWindowBytes());
            diag.PacingRateBytesPerSecond = static_cast<double>(cc->GetPacingRateBytesPerSecond());
            diag.EstimatedLossPercent = cc->GetEstimatedLossPercent();
            diag.PacingGain = cc->GetPacingGain();
            diag.CwndGain = cc->GetCwndGain();
            diag.MinRttMicros = cc->GetMinRttMicros();
            diag.BtlBwBytesPerSecond = cc->GetBtlBwBytesPerSecond();
            diag.MaxBwBytesPerSecond = cc->GetMaxBwBytesPerSecond();
            diag.TotalDelivered = cc->GetTotalDelivered();
            diag.CurrentNetworkClass = static_cast<int32_t>(cc->GetMode());
            diag.GeodesicXEst = cc->GetGeodesicXEst();
            diag.GeodesicPEst = cc->GetGeodesicPEst();
            diag.GeodesicSampleCnt = cc->GetGeodesicSampleCnt();
            diag.GeodesicQDelayAvg = cc->GetGeodesicQDelayAvg();
            diag.GeodesicJitterEwma = cc->GetGeodesicJitterEwma();
        }
    }
    diag.LastRttMicros = m_lastRttMicros.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> rttLock(m_rttMutex);
        diag.RttSamplesMicros = m_rttSamplesMicros;
    }
    { diag.MeasuredBandwidthBytesPerSecond = ComputeMeasuredBandwidth(NowMicros()); }
    diag.ReceivedReset = m_rstReceived;
    diag.BufferedReceiveBytes = m_queuedReceiveBytes;
    diag.CurrentMtu = m_currentMtu;
    diag.ProbeMin = m_probeMin;
    diag.ProbeMax = m_probeMax;
    diag.IsMtuProbing = m_mtuProbePending;
    return diag;
}

/** @brief Abruptly aborts the connection.  Optionally sends a RST packet to the peer
 *  before transitioning to the Closed state.
 *  @param sendReset  If true, transmits a reset packet to the remote endpoint. */
void UcpPcb::Abort(bool sendReset) noexcept {
    if (sendReset && m_hasRemoteEndpoint.load(std::memory_order_acquire)) {
        SendControl(UcpPacketType::Rst, (int)UcpPacketFlags::None);
    }
    TransitionToClosed();
}
/** @brief Overrides the next send sequence number (test support only).
 *  @param nextSendSequence  New send sequence number to use. */
void UcpPcb::SetNextSendSequenceForTest(uint32_t nextSendSequence) noexcept {
    m_nextSendSequence.store(nextSendSequence, std::memory_order_relaxed);
}

/** @brief Overrides the advertised receive window size (test support only).
 *  @param windowBytes  New local receive window size in bytes. */
void UcpPcb::SetAdvertisedReceiveWindowForTest(uint32_t windowBytes) noexcept {
    m_localReceiveWindowBytes.store(windowBytes, std::memory_order_relaxed);
}

/** @brief Injects a measured-delivery sample into the bandwidth slot accumulator (test support only).
 *  @param nowMicros       Current timestamp for slot placement.
 *  @param deliveredBytes  Number of bytes to record in the current slot. */
void UcpPcb::AddMeasuredDeliveryForTest(int64_t nowMicros, int64_t deliveredBytes) noexcept {
    AdvanceMeasuredBwSlot(nowMicros, deliveredBytes);
}

/** @brief Validates buffer offset/count bounds for send/receive operations.
 *  @param buffer    The buffer pointer (must not be NULLPTR).
 *  @param offset    Starting byte offset into the buffer.
 *  @param count     Number of bytes to access.
 *  @param bufferLen Total allocated length of the buffer.
 *  @return True if the access range is valid, false on overflow or null pointer. */
bool UcpPcb::ValidateBuffer(const uint8_t* buffer, int offset, int count, int bufferLen) noexcept {
    if (NULLPTR == buffer) {
        return false;
    }
    if (offset < 0 || count < 0 || (size_t)offset > (size_t)bufferLen || (size_t)count > (size_t)bufferLen - (size_t)offset) {
        return false;
    }
    return true;
}

/** @brief Initiates an asynchronous connection to a remote endpoint (callback-based Proactor pattern).
 *  Transitions the state machine to HandshakeSynSent and transmits a SYN packet.
 *  If already connected, fires the callback immediately via the worker thread.
 *  @param remoteEndpoint  The remote endpoint to connect to.
 *  @param callback        Callback invoked when the handshake completes or fails. */
void UcpPcb::ConnectAsync(const Endpoint& remoteEndpoint, ConnectAsyncCallback callback) noexcept {
    SetRemoteEndpoint(remoteEndpoint);

    UcpConnectionState st = m_state.load(std::memory_order_acquire);
    if (UcpConnectionState::Established == st) {
        EnqueueWork([this, callback]() noexcept {
            if (callback) {
                try {
                    callback(UcpError::None, m_connectionId);
                } catch (...) {
                }
            }
        });
        return;
    }
    if (UcpConnectionState::Closed == st || UcpConnectionState::ClosingFinSent == st || UcpConnectionState::ClosingFinReceived == st) {
        if (callback) {
            EnqueueWork([callback]() noexcept {
                try {
                    callback(UcpError::NotConnected, 0);
                } catch (...) {
                }
            });
        }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_pendingCallbackMutex);
        st = m_state.load(std::memory_order_relaxed);
        if (UcpConnectionState::Established == st) {
            EnqueueWork([this, callback]() noexcept {
                if (callback) {
                    try {
                        callback(UcpError::None, m_connectionId);
                    } catch (...) {
                    }
                }
            });
            return;
        }
        if (UcpConnectionState::Closed == st || UcpConnectionState::ClosingFinSent == st || UcpConnectionState::ClosingFinReceived == st) {
            if (callback) {
                EnqueueWork([callback]() noexcept {
                    try {
                        callback(UcpError::NotConnected, 0);
                    } catch (...) {
                    }
                });
            }
            return;
        }
        if (m_hasPendingConnectCallback) {
            if (callback) {
                EnqueueWork([callback]() noexcept {
                    try {
                        callback(UcpError::InvalidState, 0);
                    } catch (...) {
                    }
                });
            }
            return;
        }
        m_pendingConnectCallback = callback;
        m_hasPendingConnectCallback = true;
        m_state.store(UcpConnectionState::HandshakeSynSent, std::memory_order_release);
        m_synSent.store(true, std::memory_order_relaxed);
        m_connectStartMicros.store(NowMicros(), std::memory_order_relaxed);
        m_lastSynSentMicros.store(m_connectStartMicros.load(std::memory_order_relaxed), std::memory_order_relaxed);
    }

    SendControl(UcpPacketType::Syn, (int)UcpPacketFlags::None);
}

/** @brief Synchronous connect: blocks the calling thread until the handshake completes.
 *  Wraps ConnectAsync with a condition variable.
 *  @param remoteEndpoint  The remote endpoint to connect to.
 *  @return True if the connection was established, false on failure. */
bool UcpPcb::Connect(const Endpoint& remoteEndpoint) noexcept {
    if (m_workerThread.get_id() == std::this_thread::get_id()) {
        ConnectAsync(remoteEndpoint, ConnectAsyncCallback());
        return false;
    }

    auto mtx = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<bool>(false);

    ConnectAsync(remoteEndpoint, [mtx, cv, done, result](UcpError error, uint32_t) noexcept {
        *result = (error == UcpError::None);
        done->store(true, std::memory_order_release);
        cv->notify_one();
    });

    {
        std::unique_lock<std::mutex> lk(*mtx);
        int64_t timeoutUs = m_config.DisconnectTimeoutMicros + 2000000LL;
        if (timeoutUs < 1000000LL) {
            timeoutUs = 5000000LL;
        }
        cv->wait_for(lk, std::chrono::microseconds(timeoutUs), [&done]() noexcept { return done->load(std::memory_order_acquire); });
    }

    return *result;
}

void UcpPcb::SendAsync(const uint8_t* buffer, int offset, int count, SendAsyncCallback callback) noexcept {
    SendAsync(buffer, offset, count, UcpPriority::Normal, std::move(callback));
}

void UcpPcb::SendAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority, SendAsyncCallback callback) noexcept {
    if (NULLPTR == buffer || offset < 0 || count < 0) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, -1);
            } catch (...) {
            }
        }
        return;
    }
    {
        int maxPayload = m_config.MaxPayloadSize();
        if (maxPayload <= 0) {
            maxPayload = m_config.Mss;
        }
        int64_t maxAllowed = (int64_t)maxPayload * MAX_FRAGMENTS_PER_MESSAGE;
        if (maxAllowed > INT_MAX) {
            maxAllowed = INT_MAX;
        }
        if (count > (int)maxAllowed) {
            count = (int)maxAllowed;
        }
    }
    if (count <= 0) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, -1);
            } catch (...) {
            }
        }
        return;
    }

    ucp::vector<uint8_t> data;
    try {
        data.resize((size_t)count);
        std::memcpy(data.data(), buffer + offset, (size_t)count);
    } catch (...) {
        // OOM on a noexcept path: report InternalError instead of std::terminate.
        if (callback) {
            try {
                callback(UcpError::InternalError, -1);
            } catch (...) {
            }
        }
        return;
    }

    EnqueueWork([this, data = std::move(data), count, priority, callback]() noexcept {
        int result = -1;
        try {
            int remaining = count;
            int currentOffset = 0;
            int acceptedBytes = 0;
            int maxPayload = m_config.MaxPayloadSize();
            bool invokeSendFail = false;
            {
                UcpConnectionState st = m_state.load(std::memory_order_acquire);
                if (UcpConnectionState::Established != st && UcpConnectionState::ClosingFinSent != st &&
                    UcpConnectionState::ClosingFinReceived != st) {
                    invokeSendFail = true;
                }
                int mtuBasedMax = m_currentMtu.load(std::memory_order_acquire) - PcbConst::DATA_HEADER_SIZE_WITH_ACK;
                if (mtuBasedMax < maxPayload && mtuBasedMax > 0) {
                    maxPayload = mtuBasedMax;
                }
            }
            if (invokeSendFail) {
                if (callback) {
                    try {
                        callback(UcpError::NotConnected, -1);
                    } catch (...) {
                    }
                }
                return;
            }
            if (maxPayload <= 0)
                maxPayload = m_config.Mss;
            int capped = count;
            int64_t maxAllowed = (int64_t)maxPayload * MAX_FRAGMENTS_PER_MESSAGE;
            if (maxAllowed > INT_MAX) {
                maxAllowed = INT_MAX;
            }
            if (capped > (int)maxAllowed) {
                capped = (int)maxAllowed;
                remaining = capped;
            }

            uint16_t fragmentTotal = (uint16_t)((capped + maxPayload - 1) / maxPayload);
            uint16_t fragmentIndex = 0;
            int maxBufferedSegments = (std::max)(1, m_config.SendBufferSize() / (std::max)(1, maxPayload));

            while (0 < remaining && !m_ctsCanceled) {
                int chunk = remaining > maxPayload ? maxPayload : remaining;

                ucp::vector<uint8_t> payload(data.data() + currentOffset, data.data() + currentOffset + chunk);

                {
                    std::lock_guard<std::mutex> lock(m_sendBufMutex);
                    if ((int)m_sendBuffer.size() >= maxBufferedSegments) {
                        break;
                    }
                    OutboundSegment segment;
                    segment.SequenceNumber = m_nextSendSequence.load(std::memory_order_relaxed);
                    segment.FragmentTotal = fragmentTotal;
                    segment.FragmentIndex = fragmentIndex;
                    segment.Payload = std::move(payload);
                    segment.Priority = priority;
                    m_sendBuffer[segment.SequenceNumber] = std::move(segment);
                    m_nextSendSequence.store(UcpSequenceComparer::Increment(m_nextSendSequence.load(std::memory_order_relaxed)),
                                             std::memory_order_relaxed);
                }

                currentOffset += chunk;
                remaining -= chunk;
                acceptedBytes += chunk;
                fragmentIndex++;
            }

            FlushSendQueueAsync();
            result = acceptedBytes;
        } catch (const std::exception&) {
            result = -1;
        }

        if (callback) {
            if (0 > result) {
                try {
                    callback(UcpError::InternalError, static_cast<int32_t>(result));
                } catch (...) {
                }
            } else if (0 == result) {
                try {
                    callback(UcpError::WouldBlock, 0);
                } catch (...) {
                }
            } else {
                // Mirrors C# SendAsync (UcpPcb.cs:818): a fresh app write means
                // the app is no longer application-limited, and an idle restart
                // resets the ACK-aggregation epoch so pacing resumes cleanly.
                // Serialize the CC mutation under m_sync (the same lock used by
                // OnAck/OnPacketSent on the network thread).
                {
                    std::lock_guard<std::mutex> ccLock(m_sync);
                    if (m_congestion) {
                        m_congestion->SetAppLimited(false);
                        m_congestion->OnIdleRestart();
                    }
                }
                try {
                    callback(UcpError::None, static_cast<int32_t>(result));
                } catch (...) {
                }
            }
        }
    });
}

/** @brief Synchronous send with explicit priority: blocks the calling thread until the data
 *  is queued in the send buffer or an error occurs.  Wraps SendAsync with a condition variable.
 *  @param buffer   Source buffer.
 *  @param offset   Byte offset in buffer.
 *  @param count    Number of bytes to send.
 *  @param priority QoS priority level.
 *  @return Number of bytes accepted, or -1 on error. */
int UcpPcb::Send(const uint8_t* buffer, int offset, int count, UcpPriority priority) noexcept {
    if (m_workerThread.get_id() == std::this_thread::get_id()) {
        SendAsync(buffer, offset, count, priority, SendAsyncCallback());
        return -1;
    }

    if (!ValidateBuffer(buffer, offset, count, count + offset)) {
        return -1;
    }

    auto mtx = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<int>(-1);

    SendAsync(buffer, offset, count, priority, [mtx, cv, done, result](UcpError, int32_t bytes) noexcept {
        {
            std::lock_guard<std::mutex> g(*mtx);
            *result = bytes;
        }
        done->store(true, std::memory_order_release);
        cv->notify_one();
    });

    {
        std::unique_lock<std::mutex> lk(*mtx);
        if (!cv->wait_for(lk, std::chrono::seconds(5), [&done]() noexcept { return done->load(std::memory_order_acquire); })) {
            std::lock_guard<std::mutex> g(*mtx);
            *result = -1;
        }
    }

    return *result;
}

/** @brief Attempts a non-blocking receive from the receive queue.
 *  Copies available data from queued ReceiveChunks up to count bytes.
 *  Returns 0 if the connection is closed with no data, -1 if no data is available yet.
 *  @param buffer  Destination buffer.
 *  @param offset  Write offset into destination.
 *  @param count   Maximum bytes to receive.
 *  @return Number of bytes copied, 0 if closed, -1 if no data pending. */
int UcpPcb::TryReceive(uint8_t* buffer, int offset, int count) noexcept {
    std::lock_guard<std::mutex> lock(m_receiveMutex);
    if (m_receiveQueue.empty()) {
        if (UcpConnectionState::Closed == m_state) {
            return 0;
        }
        return -1;
    }

    int copied = 0;
    while (!m_receiveQueue.empty() && copied < count) {
        ReceiveChunk& current = m_receiveQueue.front();
        int available = current.Count - current.Offset;
        int toCopy = (std::min)(available, count - copied);
        std::memcpy(buffer + offset + copied, current.Buffer.data() + current.Offset, (size_t)toCopy);
        current.Offset += toCopy;
        copied += toCopy;
        m_queuedReceiveBytes -= toCopy;
        if (current.Offset >= current.Count) {
            m_receiveQueue.pop();
        }
    }
    if (0 > m_queuedReceiveBytes) {
        m_queuedReceiveBytes = 0;
    }

    return copied;
}

/** @brief Attempts to satisfy pending ReceiveAsync operations with data that has arrived.
 *  Iterates pending receive operations and copies available data from the receive queue.
 *  Collects callbacks into m_pendingReceiveCallbacks for deferred firing via
 *  FlushPendingReceiveCallbacks (called from OnTick on the event-loop thread).
 *  Deferred firing prevents the UDP receive thread from being blocked by
 *  application-level callback chains, fixing the >256KB echo deadlock. */
void UcpPcb::TrySatisfyPendingReceives() noexcept {
    bool scheduleAck = false;
    bool hasCallbacks = false;
    {
        std::lock_guard<std::mutex> lock(m_receiveMutex);
        while (!m_pendingReceives.empty()) {
            PendingReceiveOp& op = m_pendingReceives.front();
            int copied = 0;
            if (!m_receiveQueue.empty()) {
                while (!m_receiveQueue.empty() && copied < op.count) {
                    ReceiveChunk& current = m_receiveQueue.front();
                    int available = current.Count - current.Offset;
                    int toCopy = (std::min)(available, op.count - copied);
                    std::memcpy(op.buffer + op.offset + copied, current.Buffer.data() + current.Offset, (size_t)toCopy);
                    current.Offset += toCopy;
                    copied += toCopy;
                    m_queuedReceiveBytes -= toCopy;
                    if (current.Offset >= current.Count) {
                        m_receiveQueue.pop();
                    }
                }
                if (0 > m_queuedReceiveBytes) {
                    m_queuedReceiveBytes = 0;
                }
            }

            if (0 < copied || UcpConnectionState::Closed == m_state) {
                m_pendingReceiveCallbacks.push_back(ucp::pair<ReceiveAsyncCallback, int32_t>(op.callback, static_cast<int32_t>(copied)));
                m_pendingReceives.pop_front();
                if (0 < copied)
                    scheduleAck = true;
                m_callbackPending.store(true, std::memory_order_release);
                hasCallbacks = true;
            } else {
                break;
            }
        }
    }

    if (hasCallbacks) {
        std::lock_guard<std::mutex> lock(m_notifyMutex);
        m_notifyCV.notify_one();
    }
    if (scheduleAck) {
        ScheduleAck();
    }
}

/** @brief Fires all callbacks queued in m_pendingReceiveCallbacks.
 *  Swaps the vector under m_receiveMutex, then fires callbacks outside the lock.
 *  Called from the notification thread. */
void UcpPcb::FlushPendingReceiveCallbacks() noexcept {
    ucp::vector<ucp::pair<ReceiveAsyncCallback, int32_t>> toFire;
    {
        std::lock_guard<std::mutex> lock(m_receiveMutex);
        toFire.swap(m_pendingReceiveCallbacks);
    }
    for (size_t i = 0; i < toFire.size(); i++) {
        if (toFire[i].first) {
            try {
                toFire[i].first(0 < toFire[i].second ? UcpError::None : UcpError::Closed, toFire[i].second);
            } catch (...) {
            }
        }
    }
}

/** @brief Asynchronous receive: tries non-blocking first; if no data is available,
 *  stores the operation as pending and will callback when data arrives.
 *  Callback fires with bytes copied (0 = closed, negative = error).
 *  @param buffer   Destination buffer.
 *  @param offset   Write offset into destination.
 *  @param count    Maximum bytes to receive.
 *  @param callback Callback invoked with error code and byte count. */
void UcpPcb::ReceiveAsync(uint8_t* buffer, int offset, int count, ReceiveAsyncCallback callback) noexcept {
    if (NULLPTR == buffer || offset < 0 || count < 0) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, -1);
            } catch (...) {
            }
        }
        return;
    }
    std::unique_lock<std::mutex> lock(m_receiveMutex);
    if (!m_receiveQueue.empty()) {
        int copied = 0;
        while (!m_receiveQueue.empty() && copied < count) {
            ReceiveChunk& current = m_receiveQueue.front();
            int toCopy = (std::min)(current.Count - current.Offset, count - copied);
            std::memcpy(buffer + offset + copied, current.Buffer.data() + current.Offset, (size_t)toCopy);
            current.Offset += toCopy;
            copied += toCopy;
            m_queuedReceiveBytes -= toCopy;
            if (current.Offset >= current.Count)
                m_receiveQueue.pop();
        }
        if (0 > m_queuedReceiveBytes)
            m_queuedReceiveBytes = 0;
        m_pendingReceiveCallbacks.push_back(ucp::pair<ReceiveAsyncCallback, int32_t>(callback, static_cast<int32_t>(copied)));
        m_callbackPending.store(true, std::memory_order_release);
        lock.unlock();
        {
            std::lock_guard<std::mutex> notifyLock(m_notifyMutex);
            m_notifyCV.notify_one();
        }
        if (0 < copied)
            ScheduleAck();
        return;
    }
    if (UcpConnectionState::Closed == m_state) {
        m_pendingReceiveCallbacks.push_back(ucp::pair<ReceiveAsyncCallback, int32_t>(callback, 0));
        m_callbackPending.store(true, std::memory_order_release);
        lock.unlock();
        {
            std::lock_guard<std::mutex> notifyLock(m_notifyMutex);
            m_notifyCV.notify_one();
        }
        return;
    }

    m_pendingReceives.push_back({buffer, offset, count, callback});
}

/** @brief Synchronous receive: blocks the calling thread until data arrives or the connection closes.
 *  Wraps ReceiveAsync with a condition variable.
 *  @param buffer  Destination buffer.
 *  @param offset  Write offset into destination.
 *  @param count   Maximum bytes to receive.
 *  @return Number of bytes copied, 0 if closed, -1 on error. */
int UcpPcb::Receive(uint8_t* buffer, int offset, int count) noexcept {
    if (m_workerThread.get_id() == std::this_thread::get_id()) {
        // On the worker thread we must NOT register the caller's raw buffer in a
        // pending op (the caller may return before data arrives ->
        // use-after-free) and MUST NOT block waiting for data (the worker
        // processes inbound data itself, so blocking here deadlocks the whole
        // connection).  Do a non-blocking TryReceive: copy whatever is queued,
        // or return -1 so the caller retries later.
        return TryReceive(buffer, offset, count);
    }

    if (!ValidateBuffer(buffer, offset, count, count + offset)) {
        return -1;
    }

    auto mtx = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<int>(-1);

    ReceiveAsync(buffer, offset, count, [mtx, cv, done, result](UcpError, int32_t bytes) noexcept {
        *result = bytes;
        done->store(true, std::memory_order_release);
        cv->notify_one();
    });

    {
        std::unique_lock<std::mutex> lk(*mtx);
        if (!cv->wait_for(lk, std::chrono::seconds(5), [&done]() noexcept { return done->load(std::memory_order_acquire); })) {
            *result = -1;
            // Timeout: pending op(s) still reference the caller's buffer.
            // The caller may free it after we return, so unregister ALL ops for
            // this buffer to prevent TrySatisfyPendingReceives from memcpy-ing
            // into freed memory.  (Also avoids racing the callback's write of
            // *result.)
            std::lock_guard<std::mutex> recvLock(m_receiveMutex);
            for (auto it = m_pendingReceives.begin(); it != m_pendingReceives.end();) {
                if (it->buffer == buffer) {
                    it = m_pendingReceives.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    return *result;
}

/** @brief Asynchronous exact-byte-count read: uses ReceiveAsync callback chaining
 *  to accumulate count bytes without blocking the worker thread.
 *  When partial data is received, issues another ReceiveAsync for remaining bytes.
 *  No std::this_thread::yield() and no busy-wait.
 *  @param buffer   Destination buffer.
 *  @param offset   Write offset into destination.
 *  @param count    Exact number of bytes to read.
 *  @param callback Callback invoked with success flag (false = connection closed or error). */
void UcpPcb::ReadAsync(uint8_t* buffer, int offset, int count, ReadAsyncCallback callback) noexcept {
    if (NULLPTR == buffer || offset < 0 || count < 0) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, false);
            } catch (...) {
            }
        }
        return;
    }
    struct ReadContext {
        uint8_t* buffer;
        int offset;
        int count;
        int completed;
        ReadAsyncCallback callback;
        ucp::shared_ptr<UcpPcb> pcb;
    };
    ucp::shared_ptr<UcpPcb> self = shared_from_this();
    auto ctx = ucp::make_shared_object<ReadContext>();
    ctx->buffer = buffer;
    ctx->offset = offset;
    ctx->count = count;
    ctx->completed = 0;
    ctx->callback = callback;
    ctx->pcb = self;

    auto recvCb = ucp::make_shared_object<ReceiveAsyncCallback>();
    *recvCb = [ctx, recvCb](UcpError err, int32_t copied) noexcept -> void {
        if (UcpError::None != err || 0 >= copied) {
            if (ctx->callback) {
                try {
                    ctx->callback(err, false);
                } catch (...) {
                }
            }
            return;
        }
        ctx->completed += static_cast<int>(copied);
        if (ctx->completed >= ctx->count) {
            if (ctx->callback) {
                try {
                    ctx->callback(UcpError::None, true);
                } catch (...) {
                }
            }
            return;
        }
        // Guard against int overflow in the cumulative offset: if offset or
        // count is huge, fail cleanly rather than wrapping negative.
        int64_t nextOffset64 = static_cast<int64_t>(ctx->offset) + ctx->completed;
        int64_t remaining64 = static_cast<int64_t>(ctx->count) - ctx->completed;
        if (nextOffset64 > INT_MAX || remaining64 <= 0) {
            try {
                ctx->callback(UcpError::InvalidArgument, false);
            } catch (...) {
            }
            return;
        }
        ctx->pcb->ReceiveAsync(ctx->buffer, static_cast<int>(nextOffset64), static_cast<int>(remaining64), *recvCb);
    };

    ReceiveAsync(buffer, offset, count, *recvCb);
}

bool UcpPcb::Read(uint8_t* buffer, int offset, int count) noexcept {
    if (m_workerThread.get_id() == std::this_thread::get_id()) {
        ReadAsync(buffer, offset, count, ReadAsyncCallback());
        return false;
    }

    if (!ValidateBuffer(buffer, offset, count, count + offset)) {
        return false;
    }

    auto mtx = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<bool>(false);

    ReadAsync(buffer, offset, count, [mtx, cv, done, result](UcpError, bool success) noexcept {
        *result = success;
        done->store(true, std::memory_order_release);
        cv->notify_one();
    });

    {
        std::unique_lock<std::mutex> lk(*mtx);
        if (!cv->wait_for(lk, std::chrono::seconds(5), [&done]() noexcept { return done->load(std::memory_order_acquire); })) {
            *result = false;
            // Timeout: pending op(s) still reference the caller's buffer.
            // The caller may free it after we return, so unregister ALL ops for
            // this buffer (ReadAsync chains re-register with incrementing
            // offsets, so a single (buffer,offset,count) match is insufficient)
            // to prevent TrySatisfyPendingReceives from memcpy-ing into freed
            // memory.  (Also avoids racing the callback's write of *result.)
            std::lock_guard<std::mutex> recvLock(m_receiveMutex);
            for (auto it = m_pendingReceives.begin(); it != m_pendingReceives.end();) {
                if (it->buffer == buffer) {
                    it = m_pendingReceives.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    return *result;
}

/** @brief Asynchronous write with Normal priority.  Delegates to the priority overload.
 *  @param buffer   Source buffer.
 *  @param offset   Byte offset in buffer.
 *  @param count    Number of bytes to write.
 *  @param callback Callback invoked when the write completes (success=false on partial/error). */
void UcpPcb::WriteAsync(const uint8_t* buffer, int offset, int count, WriteAsyncCallback callback) noexcept {
    WriteAsync(buffer, offset, count, UcpPriority::Normal, std::move(callback));
}

/** @brief Asynchronous write with explicit priority: copies the user data, fragments it into
 *  MTU-sized segments, enqueues them in the send buffer, and triggers a flush.  If the send
 *  buffer fills, remaining data is re-enqueued for later transmission.
 *  @param buffer   Source buffer.
 *  @param offset   Byte offset in buffer.
 *  @param count    Number of bytes to write.
 *  @param priority QoS priority level.
 *  @param callback Callback invoked with success flag (true = all bytes accepted). */
void UcpPcb::WriteAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority, WriteAsyncCallback callback) noexcept {
    if (NULLPTR == buffer || offset < 0 || count < 0) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, false);
            } catch (...) {
            }
        }
        return;
    }
    {
        int maxPayload = m_config.MaxPayloadSize();
        if (maxPayload <= 0) {
            maxPayload = m_config.Mss;
        }
        int64_t maxAllowed = (int64_t)maxPayload * MAX_FRAGMENTS_PER_MESSAGE;
        if (maxAllowed > INT_MAX) {
            maxAllowed = INT_MAX;
        }
        if (count > (int)maxAllowed) {
            count = (int)maxAllowed;
        }
    }
    if (count <= 0) {
        if (callback) {
            try {
                callback(UcpError::InvalidArgument, false);
            } catch (...) {
            }
        }
        return;
    }

    ucp::vector<uint8_t> data;
    try {
        data.resize((size_t)count);
        std::memcpy(data.data(), buffer + offset, (size_t)count);
    } catch (...) {
        // OOM on a noexcept path: report InternalError instead of std::terminate.
        if (callback) {
            try {
                callback(UcpError::InternalError, false);
            } catch (...) {
            }
        }
        return;
    }

    EnqueueWork([this, data = std::move(data), count, priority, callback]() noexcept {
        int totalWritten = 0;
        int remaining = count;
        int currentOffset = 0;
        bool success = false;
        int maxPayload = m_config.MaxPayloadSize();
        {
            int mtuBasedMax = m_currentMtu.load(std::memory_order_acquire) - PcbConst::DATA_HEADER_SIZE_WITH_ACK;
            if (mtuBasedMax < maxPayload && mtuBasedMax > 0) {
                maxPayload = mtuBasedMax;
            }
        }
        if (maxPayload <= 0)
            maxPayload = m_config.Mss;

        try {
            bool invokeWriteFail = false;
            {
                UcpConnectionState st = m_state.load(std::memory_order_acquire);
                if (UcpConnectionState::Established != st && UcpConnectionState::ClosingFinSent != st &&
                    UcpConnectionState::ClosingFinReceived != st) {
                    invokeWriteFail = true;
                }
            }

            int maxBufferedSegments = (std::max)(1, (m_config.SendBufferSize() + maxPayload - 1) / (std::max)(1, maxPayload));

            if (invokeWriteFail) {
                if (callback) {
                    try {
                        callback(UcpError::NotConnected, false);
                    } catch (...) {
                    }
                }
                return;
            }

            while (0 < remaining && !m_ctsCanceled) {
                int chunk = remaining > maxPayload ? maxPayload : remaining;

                ucp::vector<uint8_t> payload(data.data() + currentOffset, data.data() + currentOffset + chunk);

                {
                    std::lock_guard<std::mutex> lock(m_sendBufMutex);
                    if ((int)m_sendBuffer.size() >= maxBufferedSegments) {
                        break;
                    }
                    uint32_t seq = m_nextSendSequence.load(std::memory_order_relaxed);
                    OutboundSegment segment;
                    segment.SequenceNumber = seq;
                    segment.Payload = std::move(payload);
                    segment.Priority = priority;
                    uint16_t fragTotal = (uint16_t)((count + maxPayload - 1) / maxPayload);
                    segment.FragmentTotal = fragTotal;
                    segment.FragmentIndex = (uint16_t)(totalWritten / maxPayload);
                    m_sendBuffer[seq] = std::move(segment);
                    m_nextSendSequence.store(UcpSequenceComparer::Increment(seq), std::memory_order_relaxed);
                }

                currentOffset += chunk;
                remaining -= chunk;
                totalWritten += chunk;
            }

            FlushSendQueueAsync();

            success = (totalWritten >= count);
        } catch (const std::exception&) {
            success = false;
        }

        if (totalWritten < count && !m_ctsCanceled) {

            ucp::vector<uint8_t> remainingData(data.begin() + totalWritten, data.end());
            struct WriteMoreState {
                ucp::vector<uint8_t> Data;
                UcpPriority Priority;
                WriteAsyncCallback Callback;
                int MaxPayload = 0;
                int TotalOriginal = 0;
                int BytesConsumed = 0;
            };
            auto state = ucp::make_shared_object<WriteMoreState>();
            state->Data = std::move(remainingData);
            state->Priority = priority;
            state->Callback = callback;
            state->MaxPayload = maxPayload;
            state->TotalOriginal = count;
            state->BytesConsumed = totalWritten;
            auto writeMore = ucp::make_shared_object<ucp::function<void()>>();
            *writeMore = [this, state, writeMore]() noexcept {
                int o = 0;
                int total = (int)state->Data.size();
                int maxPayload = state->MaxPayload > 0 ? state->MaxPayload : m_config.MaxPayloadSize();
                if (maxPayload <= 0) {
                    maxPayload = m_config.Mss;
                }
                {
                    std::lock_guard<std::mutex> lock(m_sendBufMutex);
                    int maxSegments = (std::max)(1, (m_config.SendBufferSize() + maxPayload - 1) / (std::max)(1, maxPayload));
                    while (o < total && (int)m_sendBuffer.size() < maxSegments && !m_ctsCanceled) {
                        int chunk = (total - o) > maxPayload ? maxPayload : (total - o);
                        ucp::vector<uint8_t> payload(state->Data.data() + o, state->Data.data() + o + chunk);
                        OutboundSegment segment;
                        segment.SequenceNumber = m_nextSendSequence.load(std::memory_order_relaxed);
                        segment.FragmentTotal = (uint16_t)((state->TotalOriginal + maxPayload - 1) / maxPayload);
                        segment.FragmentIndex = (uint16_t)(state->BytesConsumed / maxPayload);
                        segment.Payload = std::move(payload);
                        segment.Priority = state->Priority;
                        m_sendBuffer[segment.SequenceNumber] = std::move(segment);
                        m_nextSendSequence.store(UcpSequenceComparer::Increment(m_nextSendSequence.load(std::memory_order_relaxed)),
                                                 std::memory_order_relaxed);
                        state->BytesConsumed += chunk;
                        o += chunk;
                    }
                }
                FlushSendQueueAsync();
                if (o < total && !m_ctsCanceled) {

                    state->Data = ucp::vector<uint8_t>(state->Data.begin() + o, state->Data.end());
                    EnqueueWork(*writeMore);
                } else {
                    if (state->Callback) {
                        try {
                            state->Callback((o >= total) ? UcpError::None : UcpError::WouldBlock, (o >= total));
                        } catch (...) {
                        }
                    }
                }
            };
            EnqueueWork(*writeMore);
        } else {
            if (callback) {
                try {
                    callback(success ? UcpError::None : UcpError::InternalError, success);
                } catch (...) {
                }
            }
        }
    });
}

/** @brief Synchronous write: blocks the calling thread until data is queued.
 *  Wraps WriteAsync with a condition variable.
 *  @param buffer   Source buffer.
 *  @param offset   Byte offset in buffer.
 *  @param count    Number of bytes to write.
 *  @param priority QoS priority level.
 *  @return True if all bytes were accepted for sending. */
bool UcpPcb::Write(const uint8_t* buffer, int offset, int count, UcpPriority priority) noexcept {
    if (m_workerThread.get_id() == std::this_thread::get_id()) {
        WriteAsync(buffer, offset, count, priority, WriteAsyncCallback());
        return false;
    }

    if (!ValidateBuffer(buffer, offset, count, count + offset)) {
        return false;
    }

    auto mtx = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<bool>(false);

    WriteAsync(buffer, offset, count, priority, [mtx, cv, done, result](UcpError, bool success) noexcept {
        {
            std::lock_guard<std::mutex> g(*mtx);
            *result = success;
        }
        done->store(true, std::memory_order_release);
        cv->notify_one();
    });

    {
        std::unique_lock<std::mutex> lk(*mtx);
        if (!cv->wait_for(lk, std::chrono::seconds(5), [&done]() noexcept { return done->load(std::memory_order_acquire); })) {
            std::lock_guard<std::mutex> g(*mtx);
            *result = false;
        }
    }

    return *result;
}

/** @brief Asynchronous graceful close: stores the callback, initiates the close state machine.
 *  The send buffer is drained, FIN is sent, and the callback fires when FIN-ACK is received
 *  or the close timeout expires.  If already closed, fires callback immediately.
 *  @param callback Callback invoked when the connection is fully closed. */
void UcpPcb::CloseAsync(CloseAsyncCallback callback) noexcept {

    if (UcpConnectionState::Closed == m_state.load(std::memory_order_acquire)) {
        if (callback) {
            try {
                callback(UcpError::None);
            } catch (...) {
            }
        }
        return;
    }
    if (m_hasPendingCloseCallback.load(std::memory_order_acquire)) {
        if (callback) {
            EnqueueWork([callback]() noexcept {
                try {
                    callback(UcpError::InvalidState);
                } catch (...) {
                }
            });
        }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_pendingCallbackMutex);
        if (UcpConnectionState::Closed == m_state.load(std::memory_order_relaxed)) {
            if (callback) {
                try {
                    callback(UcpError::None);
                } catch (...) {
                }
            }
            return;
        }
        if (m_hasPendingCloseCallback.load(std::memory_order_relaxed)) {
            if (callback) {
                EnqueueWork([callback]() noexcept {
                    try {
                        callback(UcpError::InvalidState);
                    } catch (...) {
                    }
                });
            }
            return;
        }
        m_pendingCloseCallback = callback;
        m_hasPendingCloseCallback = true;
        m_closeStartMicros.store(NowMicros(), std::memory_order_relaxed);
    }
}

/** @brief Synchronous close: blocks until the connection is fully closed
 *  or the disconnect timeout elapses.  Wraps CloseAsync with a condition
 *  variable and a timeout guard so the caller never hangs indefinitely. */
void UcpPcb::Close() noexcept {
    if (m_workerThread.get_id() == std::this_thread::get_id()) {

        if (!m_hasPendingCloseCallback.exchange(true)) {
            m_closeStartMicros = NowMicros();
        }
        return;
    }

    auto mtx = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto timedOut = std::make_shared<bool>(false);

    int64_t timeoutUs = m_config.DisconnectTimeoutMicros + 2000000LL;
    if (timeoutUs < 1000000LL) {
        timeoutUs = 5000000LL;
    }

    CloseAsync([cv, done](UcpError) noexcept {
        done->store(true, std::memory_order_release);
        cv->notify_one();
    });

    {
        std::unique_lock<std::mutex> lk(*mtx);
        if (!cv->wait_for(lk, std::chrono::microseconds(timeoutUs), [&done]() noexcept { return done->load(std::memory_order_acquire); })) {
            *timedOut = true;
        }
    }

    if (*timedOut) {
        if (UcpConnectionState::Closed != m_state.load(std::memory_order_acquire)) {
            Abort(true);
        }
    }
}

/** @brief Dispatches an inbound decoded packet to the correct handler based on its type.
 *  Updates the last-activity timestamp and applies PAWS timestamp validation to
 *  reject replayed or excessively old packets.  Handles Syn, SynAck, Ack, Nak, Data,
 *  FecRepair, Fin, and Rst packet types.
 *  @param packet  The decoded inbound UcpPacket (must not be NULLPTR). */
void UcpPcb::HandleInboundAsync(const UcpPacket* packet) {
    if (!packet || m_ctsCanceled || m_disposed) {
        return;
    }

    try {
        {
            // Any inbound packet is proof the remote peer is alive (PAWS below rejects stale or
            // replayed packets). This is the ONLY site that refreshes m_lastPeerAliveMicros;
            // outgoing sends must not count as peer activity or keepalives would self-refresh the
            // disconnect deadline forever (see the keepalive comment in OnTimerSync).
            m_lastPeerAliveMicros.store(NowMicros(), std::memory_order_relaxed);

            if (m_pawsEnabled.load(std::memory_order_relaxed) && 0 < m_largestTimestampSeen.load(std::memory_order_relaxed) &&
                m_largestTimestampSeen.load(std::memory_order_relaxed) - (int64_t)packet->header.timestamp >
                    PcbConst::PAWS_TIMEOUT_MICROS) {
                return;
            }

            if ((int64_t)packet->header.timestamp > m_largestTimestampSeen.load(std::memory_order_relaxed)) {
                m_largestTimestampSeen.store((int64_t)packet->header.timestamp, std::memory_order_relaxed);
            }
        }

        UcpPacketType type = packet->header.type;
        if (UcpPacketType::Syn == type) {
            HandleSyn(static_cast<const UcpControlPacket&>(*packet));
        } else if (UcpPacketType::SynAck == type) {
            HandleSynAck(static_cast<const UcpControlPacket&>(*packet));
        } else if (UcpPacketType::Ack == type) {
            HandleAckAsync(static_cast<const UcpAckPacket&>(*packet));
        } else if (UcpPacketType::Nak == type) {
            HandleNakAsync(static_cast<const UcpNakPacket&>(*packet));
        } else if (UcpPacketType::Data == type) {
            const auto& dataPkt = static_cast<const UcpDataPacket&>(*packet);
            if (dataPkt.sequence_number == PcbConst::CID_ROTATE_SEQUENCE_MARKER) {
                HandleCidRotation(dataPkt);
            } else {
                HandleData(dataPkt);
            }
        } else if (UcpPacketType::FecRepair == type) {
            HandleFecRepair(static_cast<const UcpFecRepairPacket&>(*packet));
        } else if (UcpPacketType::Fin == type) {
            HandleFin(static_cast<const UcpControlPacket&>(*packet));
        } else if (UcpPacketType::Rst == type) {
            m_rstReceived.store(true, std::memory_order_relaxed);
            TransitionToClosed();
        }
    } catch (...) {
        // Inbound dispatch runs inside noexcept lambdas (OnTransportDatagram /
        // DispatchPacket): an uncaught exception would std::terminate. All
        // packet handlers are best-effort; swallow any throw.
    }
}

/** @brief Network-facing dispatch entry: validates the remote endpoint for the packet,
 *  then delegates to HandleInboundAsync.  RST packets are filtered by IsRstFromKnownRemote
 *  to prevent off-path reset attacks.
 *  @param packet          The decoded inbound packet.
 *  @param remoteEndpoint  The source endpoint of the packet. */
void UcpPcb::DispatchFromNetwork(const UcpPacket* packet, const Endpoint& remoteEndpoint) noexcept {
    try {

        if (UcpPacketType::Rst != packet->header.type) {
            ValidateRemoteEndpoint(remoteEndpoint);
        }

        if (UcpPacketType::Rst == packet->header.type) {
            if (!IsRstFromKnownRemote(remoteEndpoint)) {
                return;
            }
        }

        bool hasPathChallengeFlag = (packet->header.flags & (int)UcpPacketFlags::PathChallenge) == (int)UcpPacketFlags::PathChallenge;
        if (hasPathChallengeFlag && UcpPacketType::Data == packet->header.type) {
            const auto& dataPkt = static_cast<const UcpDataPacket&>(*packet);
            if (dataPkt.payload.size() >= sizeof(uint64_t)) {
                uint64_t challengeVal;
                std::memcpy(&challengeVal, dataPkt.payload.data(), sizeof(uint64_t));

                bool isResponse = false;
                UcpDataPacket response;
                {
                    std::lock_guard<std::mutex> lock(m_endpointMutex);
                    if (m_pathChallengePending && challengeVal == m_pathChallenge &&
                        m_pendingMigrationEp.address == remoteEndpoint.address && m_pendingMigrationEp.port == remoteEndpoint.port) {
                        m_remoteEndpoint = m_pendingMigrationEp;
                        m_pathChallengePending = false;
                        m_pathChallengeAttempts = 0;
                        m_pathChanged = true;
                        isResponse = true;
                    } else {

                        response.header =
                            CreateHeader(UcpPacketType::Data, (int)UcpPacketFlags::PathChallenge, NowMicros(), m_connectionId);
                        response.sequence_number = PcbConst::CID_ROTATE_SEQUENCE_MARKER;
                        response.fragment_total = 1;
                        response.fragment_index = 0;
                        response.payload.resize(sizeof(uint64_t));
                        std::memcpy(response.payload.data(), &challengeVal, sizeof(uint64_t));
                        response.ack_number = 0 < m_nextExpectedSequence.load(std::memory_order_relaxed)
                                                  ? m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U
                                                  : 0;
                        response.window_size = m_localReceiveWindowBytes;
                        response.echo_timestamp = (uint64_t)m_lastEchoTimestamp.load(std::memory_order_relaxed);
                    }
                }
                if (isResponse) {

                    return;
                }
                ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(response);
                auto* trp = m_transport.load(std::memory_order_acquire);
                if (nullptr != trp) {
                    trp->Send(encoded, remoteEndpoint);
                }
                return;
            } else {
                return;
            }
        }

        bool shouldChallenge = false;
        Endpoint candidateEp;
        UcpDataPacket challenge;
        {
            std::lock_guard<std::mutex> lock(m_endpointMutex);
            if (m_hasRemoteEndpoint.load(std::memory_order_relaxed) && UcpConnectionState::Established == m_state &&
                (m_remoteEndpoint.address != remoteEndpoint.address || m_remoteEndpoint.port != remoteEndpoint.port)) {
                int64_t nowUs = NowMicros();
                if (!m_pathChallengePending &&
                    (0 == m_lastPathChallengeTime || nowUs - m_lastPathChallengeTime >= PcbConst::PATH_CHALLENGE_RATE_LIMIT_MICROS)) {

                    if (m_pathChallengeAttempts >= PcbConst::PATH_CHALLENGE_MAX_ATTEMPTS) {
                        m_remoteEndpoint = remoteEndpoint;
                        m_pathChanged = true;
                        m_pathChallengeAttempts = 0;
                        m_pathChallengePending = false;
                    } else {
                        m_pathChallenge = SecureRandomUint64();
                        m_pendingMigrationEp = remoteEndpoint;
                        m_pathChallengePending = true;
                        m_pathChallengeTime = nowUs;
                        m_lastPathChallengeTime = nowUs;
                        m_pathChallengeAttempts++;
                        shouldChallenge = true;
                        candidateEp = remoteEndpoint;
                        challenge.header =
                            CreateHeader(UcpPacketType::Data, (int)UcpPacketFlags::PathChallenge, NowMicros(), m_connectionId);
                        challenge.sequence_number = PcbConst::CID_ROTATE_SEQUENCE_MARKER;
                        challenge.fragment_total = 1;
                        challenge.fragment_index = 0;
                        challenge.payload.resize(sizeof(uint64_t));
                        std::memcpy(challenge.payload.data(), &m_pathChallenge, sizeof(uint64_t));
                        challenge.ack_number = 0 < m_nextExpectedSequence.load(std::memory_order_relaxed)
                                                   ? m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U
                                                   : 0;
                        challenge.window_size = m_localReceiveWindowBytes;
                        challenge.echo_timestamp = (uint64_t)m_lastEchoTimestamp.load(std::memory_order_relaxed);
                    }
                }
            }
        }

        if (shouldChallenge) {
            ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(challenge);
            auto* trp = m_transport.load(std::memory_order_acquire);
            if (nullptr != trp) {
                trp->Send(encoded, candidateEp);
            }
            return;
        }

        if (ValidateRemoteEndpoint(remoteEndpoint)) {
            HandleInboundAsync(packet);
        }
    } catch (const std::exception&) {
    } catch (...) {
    }
}

/** @brief Adds fair-queue bandwidth credit to this connection.
 *  Credits accumulate up to a maximum based on SendQuantumBytes and MaxBufferedFairQueueRounds.
 *  Only effective when m_useFairQueue is true.
 *  @param bytes  Number of bytes of credit to add. */
void UcpPcb::AddFairQueueCredit(double bytes) noexcept {
    if (!m_useFairQueue.load(std::memory_order_relaxed) || 0 >= bytes) {
        return;
    }
    double maxCredit = (std::max)(bytes, (std::max)((double)m_config.SendQuantumBytes, (double)m_config.Mss) *
                                             (double)Constants::MaxBufferedFairQueueRounds * 16);

    double expected = m_fairQueueCreditBytes.load(std::memory_order_relaxed);
    while (!m_fairQueueCreditBytes.compare_exchange_weak(expected, (std::min)(expected + bytes, maxCredit), std::memory_order_relaxed)) {
    }
}

void UcpPcb::SetUncappedFairQueueCredit() noexcept {
    if (!m_useFairQueue.load(std::memory_order_relaxed)) {
        return;
    }
    m_fairQueueCreditBytes.store(9.22e18, std::memory_order_relaxed);
}

void UcpPcb::RequestFlush() noexcept {
    EnqueueWork([this]() noexcept { FlushSendQueueAsync(); });
}

/** @brief Timer tick callback (called from the network event loop or standalone timer).
 *  Enqueues a work item that runs OnTimerAsync and triggers a flush if data is pending.
 *  @param nowMicros  Current microsecond timestamp.
 *  @return 1 if a work item was enqueued, 0 if disposed. */
int UcpPcb::OnTick(int64_t nowMicros) noexcept {
    UCP_LOG(this, "TICK", "time=%lld state=%d flight=%lld", (long long)nowMicros, (int)m_state.load(std::memory_order_relaxed),
            (long long)m_flightBytes.load(std::memory_order_relaxed));

    auto alive = m_aliveFlag;
    if (!alive || !*alive) {
        return 0;
    }
    // Gate tick frequency: the PCB is already driven by its own 1ms timer
    // (network ScheduleTimer / standalone timer thread).  DoEvents and the
    // connection worker also call OnTick on their own schedules; without a
    // gate those calls would enqueue OnTimerAsync far more often than the
    // configured interval, spin the event loop (DoEvents never yields) and
    // keep the worker busy.  Only enqueue once per timer interval.
    int64_t intervalMicros = (std::max)((int64_t)PcbConst::MIN_TIMER_WAIT_MILLISECONDS,
                                        (int64_t)m_config.TimerIntervalMilliseconds) *
                             Constants::MICROS_PER_MILLI;
    int64_t last = m_lastTickMicros.load(std::memory_order_relaxed);
    if (last != 0 && nowMicros - last < intervalMicros) {
        return 0;
    }
    m_lastTickMicros.store(nowMicros, std::memory_order_relaxed);
    EnqueueWork([this, nowMicros, alive]() noexcept {
        OnTimerAsync(nowMicros);
        if (HasPendingSendData()) {
            FlushSendQueueAsync();
        }
    });
    return 1;
}

/** @brief Processes a cumulative ACK piggybacked on an inbound packet.
 *  Marks acknowledged segments as acked, updates flight bytes, delivers ACK-based
 *  RTT samples to the RTO estimator, feeds UCP with delivery data, and advances
 *  the measured-bandwidth slot accumulator.
 *  @param ackNumber    Cumulative ACK sequence number from the remote peer.
 *  @param nowMicros    Current microsecond timestamp.
 *  @param echoMicros   Echo timestamp from the inbound packet (0 if unavailable). Used for accurate RTT computation.
 *  @return Number of bytes delivered by this ACK (0 if no new data was ACKed). */
int64_t UcpPcb::ProcessPiggybackedAck(uint32_t ackNumber, int64_t nowMicros, int64_t echoMicros) noexcept {
    ucp::vector<uint32_t> removeKeys;
    int64_t deliveredBytes = 0;
    int64_t flightBeforeAck = 0;

    bool needPcbCidUpdate = false;
    uint32_t pcbOldCid = 0;
    uint32_t pcbNewCid = 0;
    bool notifySendSpace = false;
    bool appLimitedWhenDrained = false;
    {
        std::lock_guard<std::mutex> sackLock(m_sackMutex);
        std::lock_guard<std::mutex> sendBufLock(m_sendBufMutex);
        if (0 == ackNumber) {
            return 0;
        }

        if (m_hasLargestCumulativeAckNumber && UcpSequenceComparer::IsBefore(ackNumber, m_largestCumulativeAckNumber)) {
            return 0;
        }

        if (!m_hasLargestCumulativeAckNumber || UcpSequenceComparer::IsAfter(ackNumber, m_largestCumulativeAckNumber)) {
            m_largestCumulativeAckNumber = ackNumber;
            m_hasLargestCumulativeAckNumber = true;
        }
        m_lastAckReceivedMicros = nowMicros;
        m_tailLossProbePending = false;
        int64_t bestRtt = 0;
        flightBeforeAck = m_flightBytes.load(std::memory_order_relaxed);
        for (auto& pair : m_sendBuffer) {
            OutboundSegment& segment = pair.second;
            if (segment.Acked) {
                continue;
            }
            if (UcpSequenceComparer::IsBeforeOrEqual(segment.SequenceNumber, ackNumber)) {
                segment.Acked = true;
                if (segment.InFlight) {
                    m_flightBytes.store(m_flightBytes.load(std::memory_order_relaxed) - static_cast<int64_t>(segment.Payload.size()),
                                        std::memory_order_relaxed);
                    if (0 > m_flightBytes.load(std::memory_order_relaxed)) {
                        m_flightBytes.store(0, std::memory_order_relaxed);
                    }
                }
                deliveredBytes += static_cast<int>(segment.Payload.size());
                if (1 == segment.SendCount && 0 < segment.LastSendMicros) {
                    int64_t segmentRtt = nowMicros - segment.LastSendMicros;
                    if (segmentRtt < 1) {
                        segmentRtt = 1;
                    }
                    if (m_rtoEstimator) {
                        int64_t rtoLimit = static_cast<int64_t>((double)m_rtoEstimator->CurrentRtoMicros() *
                                                                PcbConst::RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
                        if (segmentRtt <= rtoLimit) {
                            if (0 == bestRtt || segmentRtt < bestRtt) {
                                bestRtt = segmentRtt;
                            }
                        }
                    }
                }
                removeKeys.push_back(pair.first);
            } else if (UcpSequenceComparer::IsAfter(segment.SequenceNumber, ackNumber)) {
                break;
            }
        }
        if (0 < bestRtt) {
            m_lastRttMicros.store(bestRtt, std::memory_order_relaxed);
            AddRttSample(bestRtt);
            if (m_rtoEstimator) {
                m_rtoEstimator->Update(bestRtt);
            }
        }
        // Echo fallback (mirrors C# ProcessPiggybackedAck, UcpPcb.cs:1246-1250):
        // use the peer-echoed timestamp only when no fresh send-time sample was
        // available and the echo is within one RTO (guards against clock skew).
        if (0 == bestRtt && echoMicros > 0) {
            int64_t echoRtt = nowMicros - echoMicros;
            if (echoRtt < 1) {
                echoRtt = 1;
            }
            if (m_rtoEstimator && echoRtt <= m_rtoEstimator->CurrentRtoMicros()) {
                m_lastRttMicros.store(echoRtt, std::memory_order_relaxed);
                AddRttSample(echoRtt);
                m_rtoEstimator->Update(echoRtt);
            }
        }
        for (auto& key : removeKeys) {
            m_sackFastRetransmitNotified.erase(key);
            m_sackTracking.erase(key);
            m_sendBuffer.erase(key);
        }
        PurgeSackSendCounts();
        if (!removeKeys.empty()) {
            notifySendSpace = true;
        }

        if (m_mtuProbePending && 0 < deliveredBytes && m_hasLargestCumulativeAckNumber &&
            UcpSequenceComparer::IsAfter(m_largestCumulativeAckNumber, m_mtuProbeSequenceNumber)) {
            m_mtuProbePending = false;
            m_mtuProbeAcked = true;
        }

        if (m_cidRotatePending && m_hasLargestCumulativeAckNumber &&
            UcpSequenceComparer::IsAfterOrEqual(m_largestCumulativeAckNumber, m_cidRotateMarkerSequence)) {
            m_cidRotatePending = false;
            if (0 != m_pendingNewCid) {
                pcbOldCid = m_connectionId;
                m_connectionId.store(m_pendingNewCid.load(std::memory_order_relaxed), std::memory_order_relaxed);
                pcbNewCid = m_connectionId;
                m_pendingNewCid = 0;
                AddExtraCid(pcbOldCid);
                if (nullptr != m_network.load(std::memory_order_relaxed)) {
                    needPcbCidUpdate = true;
                }
            }
        }

        if (0 < deliveredBytes) {
            AdvanceMeasuredBwSlot(nowMicros, deliveredBytes);
        }
        if (0 < deliveredBytes) {
            UCP_LOG(this, "ACK", "ack_seq=%08X delivered=%lld rtt=%lld flight=%lld", ackNumber, (long long)deliveredBytes,
                    (long long)m_lastRttMicros.load(std::memory_order_relaxed), (long long)m_flightBytes.load(std::memory_order_relaxed));
            // Mirrors C# ProcessPiggybackedAck (UcpPcb.cs:1269-1271): when the
            // send buffer drains, the app is application-limited again.
            // Serialized under m_sync below (same lock as the CC mutation).
            if (m_sendBuffer.empty() && m_congestion) {
                appLimitedWhenDrained = true;
            }
        }
    }

    if (0 < deliveredBytes && m_congestion) {
        std::lock_guard<std::mutex> ccLock(m_sync);
        if (appLimitedWhenDrained && m_congestion) {
            m_congestion->SetAppLimited(true);
        }
        int64_t edtWstamp = nowMicros + (m_pacing ? m_pacing->GetWaitTimeMicros(m_config.Mss, nowMicros) : 0);
        m_congestion->SetEdtState(nowMicros, edtWstamp);
        m_congestion->OnAck(nowMicros, deliveredBytes, m_lastRttMicros.load(std::memory_order_acquire), flightBeforeAck);
        if (m_pacing) {
            m_pacing->SetRate(static_cast<double>(m_congestion->GetPacingRateBytesPerSecond()), nowMicros);
        }
    }

    if (notifySendSpace) {
        std::lock_guard<std::mutex> slk(m_sendSpaceSignalMutex);
        m_sendSpaceSignal.notify_all();
    }

    if (needPcbCidUpdate) {
        auto* net = m_network.load(std::memory_order_acquire);
        if (net) {
            net->UpdatePcbConnectionId(this, pcbOldCid, pcbNewCid);
        }
    }

    TrySatisfyPendingReceives();

    return deliveredBytes;
}

/** @brief Handles an inbound SYN packet (connection request).
 *  Server-side: records the session key, handles CID collision by aborting the stale PCB,
 *  advances to HandshakeSynReceived state, and replies with SynAck.
 *  Client-side: records the peer's sequence number.
 *  @param packet  The decoded SYN control packet. */
void UcpPcb::HandleSyn(const UcpControlPacket& packet) {
    m_lastEchoTimestamp.store((int64_t)packet.header.timestamp, std::memory_order_relaxed);
    bool shouldReply = false;
    bool shouldRegister = false;
    bool shouldCheckCollision = false;
    uint32_t synConnId = 0;
    UcpPcb* zombiePcb = NULLPTR;
    ucp::shared_ptr<UcpPcb> zombieHolder;
    ucp::shared_ptr<UcpPcb> existingBySessionPtr;

    m_sessionKey.store(packet.session_key, std::memory_order_relaxed);

    if (m_isServerSide.load(std::memory_order_relaxed) && 0 != m_sessionKey.load(std::memory_order_relaxed)) {
        auto* net = m_network.load(std::memory_order_acquire);
        if (net) {
            shouldRegister = true;
            synConnId = packet.header.connection_id;
            if (0 != synConnId) {
                shouldCheckCollision = true;
            }
        }
    }

    if (packet.has_sequence_number) {
        m_nextExpectedSequence.store(packet.sequence_number, std::memory_order_relaxed);
    }

    UcpConnectionState st = m_state.load(std::memory_order_acquire);
    if (UcpConnectionState::Init == st) {
        m_state.store(UcpConnectionState::HandshakeSynReceived, std::memory_order_release);
    }

    st = m_state.load(std::memory_order_acquire);
    if (UcpConnectionState::Closed != st) {
        m_synAckSent.store(true, std::memory_order_relaxed);
        m_synAckSentMicros.store(NowMicros(), std::memory_order_relaxed);
        shouldReply = true;
    }

    if (shouldRegister) {
        auto* net = m_network.load(std::memory_order_acquire);
        if (net) {
            existingBySessionPtr = net->TryRegisterSessionKey(m_sessionKey, this);
            if (nullptr != existingBySessionPtr && existingBySessionPtr.get() != this) {
                if (UcpConnectionState::Established == existingBySessionPtr->GetState()) {
                    // Mirrors C# HandleSyn session-reconnect path
                    // (UcpPcb.cs:1387 ResetLargestTimestampForReconnection): clear the
                    // old PAWS timestamp so packets from the reconnecting peer are not
                    // rejected as stale after a clock reset on the peer side.
                    existingBySessionPtr->m_largestTimestampSeen.store(0, std::memory_order_relaxed);
                    Endpoint ep;
                    {
                        std::lock_guard<std::mutex> lock(m_endpointMutex);
                        ep = m_remoteEndpoint;
                    }
                    existingBySessionPtr->SetRemoteEndpoint(ep);
                    existingBySessionPtr->DispatchFromNetwork(&packet, ep);
                    return;
                }
            }

            if (shouldCheckCollision) {
                ucp::shared_ptr<UcpPcb> collidingPcb = net->LookupByConnectionId(synConnId);
                if (nullptr != collidingPcb && collidingPcb.get() != this) {
                    zombiePcb = collidingPcb.get();
                    zombieHolder = collidingPcb;
                }
            }
        }

        if (NULLPTR != zombiePcb) {
            zombiePcb->Abort(true);
        }

        if (shouldReply) {
            SendControl(UcpPacketType::SynAck, (int)UcpPacketFlags::None);
        }
    }
}

/** @brief Handles an inbound SYN-ACK packet (handshake response from server).
 *  Records the server's sequence number, processes any piggybacked ACK,
 *  updates the connection ID to the server-assigned value if different,
 *  and transitions to Established state.
 *  @param packet  The decoded SYN-ACK control packet. */
void UcpPcb::HandleSynAck(const UcpControlPacket& packet) {
    bool shouldEstablish = false;
    uint32_t serverConnId = 0;
    uint32_t oldConnId = 0;
    bool needPcbUpdate = false;

    if (packet.has_sequence_number) {
        m_nextExpectedSequence.store(packet.sequence_number, std::memory_order_relaxed);
    }
    UcpConnectionState st = m_state.load(std::memory_order_acquire);
    if (m_synSent.load(std::memory_order_relaxed) && UcpConnectionState::Closed != st) {
        shouldEstablish = (UcpConnectionState::HandshakeSynSent == st);
    }
    if (shouldEstablish) {
        serverConnId = packet.header.connection_id;
        oldConnId = m_connectionId.load(std::memory_order_relaxed);
        if (nullptr != m_network.load(std::memory_order_relaxed) && 0 != serverConnId && serverConnId != oldConnId) {
            needPcbUpdate = true;
            m_connectionId.store(serverConnId, std::memory_order_relaxed);
        }
    }
    if ((packet.header.flags & (int)UcpPacketFlags::HasAckNumber) && 0 < packet.ack_number) {
        ProcessPiggybackedAck(packet.ack_number, NowMicros());
    }
    SendAckPacket((int)UcpPacketFlags::None, 0);
    if (shouldEstablish) {

        auto* netUpdate = m_network.load(std::memory_order_acquire);
        if (needPcbUpdate && netUpdate) {
            netUpdate->UpdatePcbConnectionId(this, oldConnId, serverConnId);
        }
        TransitionToEstablished();
    }
}

/** @brief Handles an inbound ACK packet with optional SACK blocks.
 *  Processes cumulative and selective acknowledgements, updates flight bytes,
 *  computes RTT samples, runs SACK-based fast retransmit detection, feeds UCP
 *  congestion control, and triggers a send queue flush if needed.
 *  Handles the transition from HandshakeSynReceived to Established on first data ACK.
 *  @param ackPacket  The decoded ACK packet (may contain SACK blocks). */
void UcpPcb::HandleAckAsync(const UcpAckPacket& ackPacket) noexcept {
    bool establishByHandshake = false;
    ucp::vector<uint32_t> removeKeys;
    int64_t deliveredBytes = 0;
    int64_t remainingFlight = 0;
    int64_t sampleRtt = 0;
    int64_t echoRtt = 0;
    int64_t flightBeforeAck = 0;
    int64_t nowMicros = NowMicros();
    bool fastRetransmitTriggered = false;

    bool needPcbCidUpdate = false;
    uint32_t pcbOldCid = 0;
    uint32_t pcbNewCid = 0;
    bool notifySendSpace = false;

    {
        std::lock_guard<std::mutex> sackLock(m_sackMutex);
        std::lock_guard<std::mutex> sendBufLock(m_sendBufMutex);
        if (!IsAckPlausible(ackPacket)) {
            remainingFlight = m_flightBytes.load(std::memory_order_relaxed);
            return;
        }
        m_remoteWindowBytes.store(ackPacket.window_size, std::memory_order_relaxed);
        if (m_congestion) {
            std::lock_guard<std::mutex> ccLock(m_sync);
            m_congestion->SetPeerWindow(ackPacket.window_size);
        }
        m_lastAckReceivedMicros = nowMicros;
        m_tailLossProbePending = false;
        if (UcpConnectionState::HandshakeSynReceived == m_state && m_synAckSent) {
            establishByHandshake = true;
        }
        if ((ackPacket.header.flags & (int)UcpPacketFlags::FinAck) == (int)UcpPacketFlags::FinAck) {
            m_finAcked = true;
        }
        if (0 < ackPacket.echo_timestamp) {
            echoRtt = nowMicros - (int64_t)ackPacket.echo_timestamp;
            if (echoRtt < 1) {
                echoRtt = 1;
            }
        }

        UpdateDuplicateAckState(ackPacket, nowMicros, fastRetransmitTriggered);

        const auto& sackBlocks = ackPacket.sack_blocks;
        ucp::vector<SackBlock> sortedSackBlocks;
        SortSackBlocks(sackBlocks, sortedSackBlocks);

        uint32_t highestSack = !sortedSackBlocks.empty() ? GetHighestSackEnd(sortedSackBlocks) : 0;
        uint32_t firstMissingSequence = UcpSequenceComparer::Increment(ackPacket.ack_number);

        int sackIndex = 0;
        bool hasSackBlocks = !sortedSackBlocks.empty();
        flightBeforeAck = m_flightBytes.load(std::memory_order_relaxed);

        {
            auto ackEnd = m_sendBuffer.upper_bound(ackPacket.ack_number);
            for (auto it = m_sendBuffer.begin(); it != ackEnd; ++it) {
                OutboundSegment& segment = it->second;
                if (segment.Acked) {
                    continue;
                }
                if (!m_hasLargestCumulativeAckNumber || UcpSequenceComparer::IsAfter(ackPacket.ack_number, m_largestCumulativeAckNumber)) {
                    m_largestCumulativeAckNumber = ackPacket.ack_number;
                    m_hasLargestCumulativeAckNumber = true;
                }
                segment.Acked = true;
                if (segment.InFlight) {
                    m_flightBytes.store(m_flightBytes.load(std::memory_order_relaxed) - static_cast<int64_t>(segment.Payload.size()),
                                        std::memory_order_relaxed);
                    if (0 > m_flightBytes.load(std::memory_order_relaxed)) {
                        m_flightBytes.store(0, std::memory_order_relaxed);
                    }
                }
                deliveredBytes += static_cast<int>(segment.Payload.size());
                if (1 == segment.SendCount && 0 < segment.LastSendMicros) {
                    int64_t segmentRtt = nowMicros - segment.LastSendMicros;
                    if (0 == sampleRtt || segmentRtt < sampleRtt) {
                        sampleRtt = segmentRtt;
                    }
                }
                removeKeys.push_back(it->first);
            }
        }

        if (hasSackBlocks) {
            auto sackStart = m_sendBuffer.upper_bound(ackPacket.ack_number);
            for (auto it = sackStart; it != m_sendBuffer.end(); ++it) {
                OutboundSegment& segment = it->second;
                if (segment.Acked) {
                    continue;
                }
                // Bound the scan: everything beyond the highest SACK end is
                // irrelevant (mirrors C# UcpPcb:1541-1544). Without this,
                // every SACK-carrying ACK scans the entire in-flight tail.
                if (UcpSequenceComparer::IsAfter(segment.SequenceNumber, highestSack)) {
                    break;
                }
                bool acked = false;
                while (sackIndex < (int)sortedSackBlocks.size() &&
                       UcpSequenceComparer::IsBefore(sortedSackBlocks[sackIndex].End, segment.SequenceNumber)) {
                    sackIndex++;
                }
                if (sackIndex < (int)sortedSackBlocks.size()) {
                    acked = UcpSequenceComparer::IsInForwardRange(segment.SequenceNumber, sortedSackBlocks[sackIndex].Start,
                                                                  sortedSackBlocks[sackIndex].End);
                }
                if (acked) {
                    segment.Acked = true;
                    if (segment.InFlight) {
                        m_flightBytes.store(m_flightBytes.load(std::memory_order_relaxed) - static_cast<int64_t>(segment.Payload.size()),
                                            std::memory_order_relaxed);
                        if (0 > m_flightBytes.load(std::memory_order_relaxed)) {
                            m_flightBytes.store(0, std::memory_order_relaxed);
                        }
                    }
                    deliveredBytes += static_cast<int>(segment.Payload.size());
                    if (1 == segment.SendCount && 0 < segment.LastSendMicros) {
                        int64_t segmentRtt = nowMicros - segment.LastSendMicros;
                        if (0 == sampleRtt || segmentRtt < sampleRtt) {
                            sampleRtt = segmentRtt;
                        }
                    }
                    removeKeys.push_back(it->first);
                    continue;
                }

                if (UcpSequenceComparer::IsBefore(segment.SequenceNumber, highestSack)) {
                    if (m_sackFastRetransmitNotified.find(segment.SequenceNumber) == m_sackFastRetransmitNotified.end()) {
                        SackTrackingState* sackState = GetOrCreateSackTracking(segment.SequenceNumber);
                        if (0 == sackState->MissingAckCount) {
                            sackState->FirstMissingAckMicros = nowMicros;
                        }
                        sackState->MissingAckCount++;
                    }

                    bool reportedSackHole = IsReportedSackHole(segment.SequenceNumber, ackPacket.ack_number, sortedSackBlocks);

                    if (1 == segment.SendCount && !segment.NeedsRetransmit &&
                        ShouldFastRetransmitSackHole(segment, firstMissingSequence, highestSack, reportedSackHole, nowMicros)) {
                        segment.NeedsRetransmit = true;
                        SackTrackingState* st = GetOrCreateSackTracking(segment.SequenceNumber);
                        st->UrgentRetransmit = true;
                        m_fastRetransmissions++;
                        m_sackFastRetransmitNotified.insert(segment.SequenceNumber);
                        bool isCongestion = IsCongestionLoss(segment.SequenceNumber, sampleRtt, nowMicros, 1);
                        (void)isCongestion;
                        if (m_congestion) {
                            // Report the lost segment's payload bytes so the CC
                            // can account for them (mirrors C# UcpPcb:1579,
                            // which passes segment.Payload.Length).
                            std::lock_guard<std::mutex> ccLock(m_sync);
                            m_congestion->OnFastRetransmit(nowMicros, isCongestion, static_cast<int64_t>(segment.Payload.size()));
                        }
                    }
                }
            }
        }
        for (auto& key : removeKeys) {
            m_sackFastRetransmitNotified.erase(key);
            m_sackTracking.erase(key);
            m_sendBuffer.erase(key);
        }
        PurgeSackSendCounts();
        if (!removeKeys.empty()) {
            notifySendSpace = true;
        }
        remainingFlight = m_flightBytes.load(std::memory_order_relaxed);

        if (m_mtuProbePending && 0 < deliveredBytes && m_hasLargestCumulativeAckNumber &&
            UcpSequenceComparer::IsAfter(m_largestCumulativeAckNumber, m_mtuProbeSequenceNumber)) {
            m_mtuProbePending = false;
            m_mtuProbeAcked = true;
        }

        if (m_cidRotatePending && m_hasLargestCumulativeAckNumber &&
            UcpSequenceComparer::IsAfterOrEqual(m_largestCumulativeAckNumber, m_cidRotateMarkerSequence)) {
            m_cidRotatePending = false;
            if (0 != m_pendingNewCid) {
                uint32_t oldCid = m_connectionId;
                m_connectionId.store(m_pendingNewCid.load(std::memory_order_relaxed), std::memory_order_relaxed);
                pcbOldCid = oldCid;
                pcbNewCid = m_connectionId;
                m_pendingNewCid = 0;
                AddExtraCid(oldCid);
                if (nullptr != m_network.load(std::memory_order_relaxed)) {
                    needPcbCidUpdate = true;
                }
            }
        }

        if (0 < deliveredBytes && 0 < echoRtt && echoRtt <= m_rtoEstimator->CurrentRtoMicros()) {
            sampleRtt = echoRtt;
        }

        bool acceptableRtt = 0 < sampleRtt && sampleRtt <= (int64_t)((double)m_rtoEstimator->CurrentRtoMicros() *
                                                                     PcbConst::RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
        if (0 < deliveredBytes && acceptableRtt) {
            m_lastRttMicros.store(sampleRtt, std::memory_order_relaxed);
            AddRttSample(sampleRtt);
            if (m_rtoEstimator) {
                m_rtoEstimator->Update(sampleRtt);
            }
        }

        if (0 < deliveredBytes) {
            AdvanceMeasuredBwSlot(nowMicros, deliveredBytes);
        }
    }

    if (notifySendSpace) {
        std::lock_guard<std::mutex> slk(m_sendSpaceSignalMutex);
        m_sendSpaceSignal.notify_all();
    }

    if (0 < deliveredBytes && m_congestion) {
        std::lock_guard<std::mutex> ccLock(m_sync);
        int64_t edtWstamp = nowMicros + (m_pacing ? m_pacing->GetWaitTimeMicros(m_config.Mss, nowMicros) : 0);
        m_congestion->SetEdtState(nowMicros, edtWstamp);
        m_congestion->OnAck(nowMicros, deliveredBytes, sampleRtt, flightBeforeAck);
        if (m_pacing) {
            m_pacing->SetRate(static_cast<double>(m_congestion->GetPacingRateBytesPerSecond()), nowMicros);
        }
    }

    auto* netCid = m_network.load(std::memory_order_acquire);
    if (needPcbCidUpdate && netCid) {
        netCid->UpdatePcbConnectionId(this, pcbOldCid, pcbNewCid);
    }

    if (establishByHandshake) {
        TransitionToEstablished();
    }
    if (m_finSent && m_finAcked && m_peerFinReceived) {
        TransitionToClosed();
    }
    if (fastRetransmitTriggered || 0 < deliveredBytes || 0 < remainingFlight) {
        EnqueueWork([this]() noexcept { FlushSendQueueAsync(); });
    }
}

/** @brief Handles an inbound NAK packet (negative acknowledgement).
 *  Processes any piggybacked ACK, marks the reported missing sequences for retransmission,
 *  and notifies UCP congestion control of packet loss for congestion state updates.
 *  @param nakPacket  The decoded NAK packet listing missing sequence numbers. */
void UcpPcb::HandleNakAsync(const UcpNakPacket& nakPacket) noexcept {
    bool notifiedLoss = false;
    int64_t lostBytes = 0;
    int64_t nowMicros = NowMicros();
    if (0 < nakPacket.ack_number) {
        ProcessPiggybackedAck(nakPacket.ack_number, nowMicros, 0);
    }

    {
        std::lock_guard<std::mutex> sackLock(m_sackMutex);
        std::lock_guard<std::mutex> sendBufLock(m_sendBufMutex);
        {
            if (IsTraceEnabled()) {
                ucp::string seqStr;
                for (size_t i = 0; i < std::min<size_t>(nakPacket.missing_sequences.size(), 10); i++) {
                    if (i > 0)
                        seqStr += ",";
                    char buf[16];
                    std::snprintf(buf, sizeof(buf), "%08X", nakPacket.missing_sequences[i]);
                    seqStr += buf;
                }
                if (nakPacket.missing_sequences.size() > 10)
                    seqStr += ",...";
                UCP_LOG(this, "NAK", "missing=%s count=%zu loss_bytes=%lld", seqStr.c_str(), nakPacket.missing_sequences.size(),
                        (long long)lostBytes);
            }
        }
        for (uint32_t sequence : nakPacket.missing_sequences) {
            auto it = m_sendBuffer.find(sequence);
            if (it != m_sendBuffer.end()) {
                OutboundSegment& segment = it->second;
                if (!segment.NeedsRetransmit && !segment.Acked && ShouldAcceptRetransmitRequest(segment, nowMicros)) {
                    segment.NeedsRetransmit = true;
                    SackTrackingState* st = GetOrCreateSackTracking(segment.SequenceNumber);
                    st->UrgentRetransmit = true;
                    m_tailLossProbePending = false;
                    notifiedLoss = true;
                    lostBytes += (int64_t)segment.Payload.size();
                }
            }
        }
        if (notifiedLoss) {
            bool isCongestion = ClassifyLosses(nakPacket.missing_sequences, nowMicros, 0);
            (void)isCongestion;
            if (m_congestion) {
                // Serialize CC mutation under the same lock as OnAck/OnPacketSent
                // (m_sync): a different lock set here would race the CC object.
                std::lock_guard<std::mutex> ccLock(m_sync);
                m_congestion->OnNakLoss(nowMicros, lostBytes);
            }
        }
    }
    EnqueueWork([this]() noexcept { FlushSendQueueAsync(); });
}

/** @brief Handles a CID rotation notification data packet.
 *  Extracts the new CID from the payload, adds it as an extra CID, retires the old one,
 *  and processes any piggybacked ACK/window update.
 *  @param dataPacket  The data packet with CID rotation payload. */
void UcpPcb::HandleCidRotation(const UcpDataPacket& dataPacket) noexcept {
    if (dataPacket.payload.size() < sizeof(uint32_t)) {
        return;
    }
    // CID rotation is authenticated by the established-handshake state:
    // accept rotation only while the connection is Established, so an
    // off-path packet (which cannot be routed to this PCB without the
    // correct ConnId) cannot flip CIDs mid-handshake.
    if (UcpConnectionState::Established != m_state) {
        return;
    }
    uint32_t newCid;
    std::memcpy(&newCid, dataPacket.payload.data(), sizeof(uint32_t));
    AddExtraCid(newCid);
    RemoveExtraCid(dataPacket.header.connection_id);

    if ((dataPacket.header.flags & (int)UcpPacketFlags::HasAckNumber) && 0 < dataPacket.ack_number) {
        ProcessPiggybackedAck(dataPacket.ack_number, NowMicros(), (int64_t)dataPacket.echo_timestamp);
        if (0 < dataPacket.window_size) {
            m_remoteWindowBytes.store(dataPacket.window_size, std::memory_order_relaxed);
            if (m_congestion) {
                std::lock_guard<std::mutex> ccLock(m_sync);
                m_congestion->SetPeerWindow(dataPacket.window_size);
            }
        }
    }
}

/** @brief Handles an inbound DATA packet with optional piggybacked ACK.
 *  Stores the data segment in the receive buffer, detects missing sequences for NAK generation,
 *  drains in-order ready payloads to the receive queue, triggers FEC recovery around
 *  the received sequence, and schedules or sends ACK/NAK responses.
 *  Triggers transition to Established on first data after handshake.
 *  @param dataPacket  The decoded DATA packet with payload and fragment metadata. */
void UcpPcb::HandleData(const UcpDataPacket& dataPacket) {
    ucp::vector<uint32_t> missing;
    ucp::vector<ucp::vector<uint8_t>> readyPayloads;
    bool shouldEstablish = false;
    bool shouldStore = false;
    bool sendImmediateAck = false;

    bool hasPiggybackedAck = 0 != (dataPacket.header.flags & (int)UcpPacketFlags::HasAckNumber);
    bool isMtuProbe = 0 != (dataPacket.header.flags & (int)UcpPacketFlags::MtuProbe);
    if (hasPiggybackedAck && 0 < dataPacket.ack_number) {
        ProcessPiggybackedAck(dataPacket.ack_number, NowMicros(), (int64_t)dataPacket.echo_timestamp);
    }

    {
        std::lock_guard<std::mutex> lock(m_sync);
        std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
        if (hasPiggybackedAck && 0 < dataPacket.window_size) {
            m_remoteWindowBytes.store(dataPacket.window_size, std::memory_order_relaxed);
            if (m_congestion) {
                m_congestion->SetPeerWindow(dataPacket.window_size);
            }
        }

        if (dataPacket.payload.empty() || (!isMtuProbe && (int)dataPacket.payload.size() > m_config.MaxPayloadSize()) ||
            (isMtuProbe && (int)dataPacket.payload.size() > PcbConst::MTU_PROBE_MAX - PcbConst::DATA_HEADER_SIZE_WITH_ACK) ||
            0 == dataPacket.fragment_total || dataPacket.fragment_index >= dataPacket.fragment_total) {
            return;
        }

        if (UcpConnectionState::HandshakeSynReceived == m_state && m_synAckSent) {
            shouldEstablish = true;
        }
        m_lastEchoTimestamp.store((int64_t)dataPacket.header.timestamp, std::memory_order_relaxed);

        if (!UcpSequenceComparer::IsBefore(dataPacket.sequence_number, m_nextExpectedSequence.load(std::memory_order_relaxed))) {
            uint32_t usedBytes = GetReceiveWindowUsedBytes();
            // Mirrors C# HandleData (UcpPcb.cs:2276-2278): MTU probes do not
            // consume receive-window bytes so a near-full window cannot block
            // MTU discovery.
            uint32_t payloadForWindow = isMtuProbe ? 0U : (uint32_t)dataPacket.payload.size();
            shouldStore = usedBytes + payloadForWindow <= m_localReceiveWindowBytes;

            if (shouldStore && m_recvBuffer.find(dataPacket.sequence_number) == m_recvBuffer.end()) {
                InboundSegment inbound;
                inbound.SequenceNumber = dataPacket.sequence_number;
                inbound.FragmentTotal = dataPacket.fragment_total;
                inbound.FragmentIndex = dataPacket.fragment_index;
                inbound.Payload = isMtuProbe ? ucp::vector<uint8_t>() : dataPacket.payload;
                int64_t payloadSize = (int64_t)inbound.Payload.size();
                m_recvBuffer[dataPacket.sequence_number] = std::move(inbound);
                m_recvBufferBytes.store(m_recvBufferBytes.load(std::memory_order_relaxed) + payloadSize, std::memory_order_relaxed);

                {
                    std::lock_guard<std::mutex> nakLock(m_nakMutex);
                    m_nakIssued.erase(dataPacket.sequence_number);
                    m_missingSequenceCounts.erase(dataPacket.sequence_number);
                    m_missingFirstSeenMicros.erase(dataPacket.sequence_number);
                    m_lastNakIssuedMicros.erase(dataPacket.sequence_number);
                }
                if (m_fecCodec) {
                    m_fecFragmentMetadata[dataPacket.sequence_number] =
                        FecFragmentMetadata{dataPacket.fragment_total, dataPacket.fragment_index};
                    m_fecCodec->FeedDataPacket(dataPacket.sequence_number, dataPacket.payload);
                    TryRecoverFecAround(dataPacket.sequence_number, readyPayloads);
                }
            }

            if (shouldStore &&
                UcpSequenceComparer::IsAfter(dataPacket.sequence_number, m_nextExpectedSequence.load(std::memory_order_relaxed))) {
                // Cache the clock once for the whole gap scan below: NowMicros()
                // is a syscall/timer read and the gap can be thousands of slots.
                int64_t nowMicrosCached = NowMicros();
                sendImmediateAck = ShouldSendImmediateReorderedAck(nowMicrosCached);
                uint32_t current = m_nextExpectedSequence.load(std::memory_order_relaxed);
                int remainingNakSlots = PcbConst::MAX_NAK_MISSING_SCAN;
                {
                    std::lock_guard<std::mutex> nakLock(m_nakMutex);
                    while (current != dataPacket.sequence_number && 0 < remainingNakSlots) {
                        if (m_recvBuffer.find(current) == m_recvBuffer.end()) {
                            int& missingCount = m_missingSequenceCounts[current];
                            missingCount++;
                            int64_t firstSeenMicros = GetMissingFirstSeenMicros(current);
                            bool missingAgeExpired = HasNakReorderGraceExpired(missingCount, firstSeenMicros, nowMicrosCached);
                            bool missingRepeatedEnough = missingCount >= PcbConst::NAK_MISSING_THRESHOLD;

                            if ((int)missing.size() < PcbConst::MAX_NAK_SEQUENCES_PER_PACKET && missingRepeatedEnough &&
                                missingAgeExpired && ShouldIssueNak(current)) {
                                MarkNakIssued(current);
                                missing.push_back(current);
                            }
                        }
                        current = UcpSequenceComparer::Increment(current);
                        remainingNakSlots--;
                    }
                }
            }

            DrainReadyPayloads(readyPayloads);
            if (!m_recvBuffer.empty() && m_recvBuffer.find(m_nextExpectedSequence.load(std::memory_order_relaxed)) == m_recvBuffer.end()) {
                int64_t nowMicrosCached2 = NowMicros();
                if ((int)m_recvBuffer.size() >= PcbConst::IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD &&
                    ShouldSendImmediateReorderedAck(nowMicrosCached2)) {
                    sendImmediateAck = true;
                }
                {
                    std::lock_guard<std::mutex> nakLock(m_nakMutex);
                    int& missingCount = m_missingSequenceCounts[m_nextExpectedSequence.load(std::memory_order_relaxed)];
                    int64_t firstSeenMicros = GetMissingFirstSeenMicros(m_nextExpectedSequence.load(std::memory_order_relaxed));
                    if ((int)missing.size() < PcbConst::MAX_NAK_SEQUENCES_PER_PACKET && missingCount >= PcbConst::NAK_MISSING_THRESHOLD &&
                        HasNakReorderGraceExpired(missingCount, firstSeenMicros, NowMicros()) &&
                        ShouldIssueNak(m_nextExpectedSequence.load(std::memory_order_relaxed))) {
                        MarkNakIssued(m_nextExpectedSequence.load(std::memory_order_relaxed));
                        missing.push_back(m_nextExpectedSequence.load(std::memory_order_relaxed));
                    }
                }
            }
        }
    }
    for (auto& payload : readyPayloads) {
        EnqueuePayload(std::move(payload));
    }
    if (shouldEstablish) {
        TransitionToEstablished();
    }
    if (!missing.empty()) {
        SendNak(missing);
    }
    if (sendImmediateAck) {
        SendAckPacket((int)UcpPacketFlags::None, 0);
    } else {
        ScheduleAck();
    }
    EnqueueWork([this]() noexcept { FlushSendQueueAsync(); });
}

/** @brief Handles an inbound FEC repair packet: attempts to recover missing data packets
 *  using the repair symbol and the stored data fragments in the same FEC group.
 *  Any successfully recovered segments are stored in the receive buffer and drained.
 *  @param packet  The decoded FEC repair packet with repair payload. */
void UcpPcb::HandleFecRepair(const UcpFecRepairPacket& packet) {
    UcpFecCodec* fec = m_fecCodecAtomic.load(std::memory_order_acquire);
    if (!fec || packet.payload.empty()) {
        return;
    }

    int64_t nowMicros = NowMicros();
    ucp::vector<ucp::vector<uint8_t>> fecReadyPayloads;
    ucp::vector<UcpFecCodec::RecoveredPacket> recoveredPackets;
    int recoveredCount = 0;
    int64_t recoveredBytes = 0;

    {
        std::lock_guard<std::mutex> lock(m_sync);
        recoveredPackets = fec->TryRecoverPacketsFromRepair(packet.payload, packet.group_id, packet.group_index);

        std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
        for (auto& rp : recoveredPackets) {
            recoveredBytes += (int64_t)rp.payload.size();
            if (StoreRecoveredFecSegment(rp.sequence_number, std::move(rp.payload))) {
                recoveredCount++;
            }
        }
        if (recoveredCount > 0 && m_congestion) {
            // Already inside the m_sync block (2703); no extra lock.
            m_congestion->OnFecRecovery(nowMicros, recoveredBytes);
        }
        DrainReadyPayloads(fecReadyPayloads);
    }
    if (0 == recoveredCount) {
        UCP_LOG(this, "FEC", "group=%08X idx=%d recovered=0", packet.group_id, packet.group_index);
        return;
    }

    UCP_LOG(this, "FEC", "group=%08X idx=%d recovered=%d bytes=%lld", packet.group_id, packet.group_index, recoveredCount,
            (long long)recoveredBytes);

    for (auto& payload : fecReadyPayloads) {
        EnqueuePayload(std::move(payload));
    }
    SendAckPacket((int)UcpPacketFlags::None, 0);
}

/** @brief Handles an inbound FIN packet (graceful close request from peer).
 *  Sets the peer FIN received flag, processes any piggybacked ACK,
 *  responds with FIN-ACK, and sends own FIN if not already sent.
 *  Transitions to Closed if both sides have FIN-ACKed.
 *  @param packet  The decoded FIN control packet. */
void UcpPcb::HandleFin(const UcpControlPacket& packet) {
    // A terminal Closed connection must not be resurrected by a late FIN.
    if (UcpConnectionState::Closed == m_state.load(std::memory_order_acquire)) {
        return;
    }
    bool needSendOwnFin = false;

    m_peerFinReceived.store(true, std::memory_order_relaxed);
    m_state.store(UcpConnectionState::ClosingFinReceived, std::memory_order_release);
    if (!m_finSent.load(std::memory_order_relaxed)) {
        m_finSent.store(true, std::memory_order_relaxed);
        needSendOwnFin = true;
    }
    if ((packet.header.flags & (int)UcpPacketFlags::HasAckNumber) && 0 < packet.ack_number) {
        ProcessPiggybackedAck(packet.ack_number, NowMicros());
    }
    SendAckPacket((int)UcpPacketFlags::FinAck, 0);
    if (needSendOwnFin) {
        SendControl(UcpPacketType::Fin, (int)UcpPacketFlags::None);
    }
    if (m_finAcked) {
        TransitionToClosed();
    }
}

/** @brief Sends a control packet (Syn, SynAck, Fin, Rst) with optional piggybacked ACK.
 *  Encodes the packet via UcpPacketCodec and transmits through the transport.
 *  Updates last-activity timestamp and increments sent counters.
 *  @param type   The control packet type to send.
 *  @param flags  Additional UcpPacketFlags to include. */
void UcpPcb::SendControl(UcpPacketType type, int flags) {
    UcpControlPacket packet;
    uint32_t cumAck = 0;
    bool hasAck = false;
    uint64_t sessionKey = 0;
    Endpoint remoteEndpoint;
    bool hasRemote = false;

    {
        if (UcpPacketType::Syn == type || UcpPacketType::SynAck == type) {
            packet.has_sequence_number = true;
            packet.sequence_number = m_nextSendSequence.load(std::memory_order_relaxed);
        }

        if (UcpPacketType::Syn == type) {
            sessionKey = m_sessionKey;
        } else if (UcpPacketType::SynAck == type) {
            sessionKey = m_sessionKey;
        }
        int packetFlags = flags;
        if (UcpPacketType::Syn != type && 0 < m_nextExpectedSequence.load(std::memory_order_relaxed)) {
            hasAck = true;
            cumAck = m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U;
            packetFlags |= (int)UcpPacketFlags::HasAckNumber;
            packet.ack_number = cumAck;
        }
        packet.header = CreateHeader(type, packetFlags, NowMicros(), m_connectionId);
        packet.session_key = sessionKey;
        hasRemote = m_hasRemoteEndpoint.load(std::memory_order_acquire);
        {
            std::lock_guard<std::mutex> epLock(m_endpointMutex);
            remoteEndpoint = m_remoteEndpoint;
        }
    }

    ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(packet);
    if (UcpPacketType::Rst == type) {
        m_sentRstPackets++;
    }
    auto* trp = m_transport.load(std::memory_order_acquire);
    if (nullptr != trp && hasRemote) {
        trp->Send(encoded, remoteEndpoint);
    }
}

/** @brief Sends a standalone ACK packet with cumulative ACK, SACK blocks, window advertisement,
 *  and echo timestamp.  Filters SACK blocks by send count to limit redundant transmissions.
 *  @param flags                  Additional UcpPacketFlags to include (e.g., FinAck).
 *  @param overrideEchoTimestamp  Non-zero to override the echo timestamp, -1 to suppress it. */
void UcpPcb::SendAckPacket(int flags, int64_t overrideEchoTimestamp) {
    UcpAckPacket packet;

    {
        std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
        int64_t nowMicros = NowMicros();

        packet.header = CreateHeader(UcpPacketType::Ack, flags, nowMicros, m_connectionId);
        packet.ack_number =
            0 < m_nextExpectedSequence.load(std::memory_order_relaxed) ? m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U : 0;

        ucp::vector<uint32_t> recvKeys;
        for (auto& pair : m_recvBuffer) {
            recvKeys.push_back(pair.first);
        }

        ucp::vector<SackBlock> rawBlocks =
            m_sackGenerator->Generate(m_nextExpectedSequence.load(std::memory_order_relaxed), recvKeys, m_config.MaxAckSackBlocks());

        ucp::vector<SackBlock> filteredBlocks;
        {
            std::lock_guard<std::mutex> sackLock(m_sackExtraMutex);
            for (auto& block : rawBlocks) {
                uint64_t key = PackSackBlockKey(block.Start, block.End);
                int sendCount = 0;
                auto scIt = m_sackBlockSendCounts.find(key);
                if (scIt != m_sackBlockSendCounts.end()) {
                    sendCount = scIt->second;
                }
                if (sendCount < PcbConst::MAX_SACK_SEND_COUNT) {
                    filteredBlocks.push_back(block);
                    m_sackBlockSendCounts[key] = sendCount + 1;
                }
            }
        }

        packet.sack_blocks = std::move(filteredBlocks);

        uint32_t usedBytes = GetReceiveWindowUsedBytes();
        packet.window_size = usedBytes >= m_localReceiveWindowBytes ? 0U : m_localReceiveWindowBytes - usedBytes;
        packet.echo_timestamp =
            0 > overrideEchoTimestamp
                ? 0
                : (0 < overrideEchoTimestamp ? overrideEchoTimestamp : m_lastEchoTimestamp.load(std::memory_order_relaxed));
        m_lastAckSentMicros = nowMicros;
    }
    ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(packet);
    m_sentAckPackets++;
    Endpoint remoteEndpoint;
    auto* trp = m_transport.load(std::memory_order_acquire);
    if (nullptr != trp && TryGetRemoteEndpoint(remoteEndpoint)) {
        trp->Send(encoded, remoteEndpoint);
    }
}

/** @brief Sends a NAK packet listing missing sequence numbers, rate-limited per RTT window.
 *  Tracks NAK send count within each RTT window to avoid flooding the peer with NAKs.
 *  @param missing  Vector of sequence numbers to report as missing. */
void UcpPcb::SendNak(const ucp::vector<uint32_t>& missing) {
    if (missing.empty()) {
        return;
    }

    Endpoint remoteEndpoint;
    bool hasRemote = false;
    UcpNakPacket packet;
    {
        int64_t nowMicros = NowMicros();
        int64_t smoothedRtt = 0;
        {
            // RTO estimator is written (Update/Backoff) under m_sync or
            // sack+sendBuf; serialize this read so it never races a write.
            std::lock_guard<std::mutex> ccLock(m_sync);
            if (m_rtoEstimator) {
                smoothedRtt = m_rtoEstimator->SmoothedRttMicros();
            }
        }
        int64_t rttWindowMicros = smoothedRtt > 0 ? smoothedRtt : m_config.DelayedAckTimeoutMicros();
        if (0 >= rttWindowMicros) {
            rttWindowMicros = PcbConst::UCP_MIN_ROUND_DURATION_MICROS;
        }

        if (0 == m_lastNakWindowMicros.load(std::memory_order_relaxed) ||
            nowMicros - m_lastNakWindowMicros.load(std::memory_order_relaxed) >= rttWindowMicros) {
            m_lastNakWindowMicros.store(nowMicros, std::memory_order_relaxed);
            m_naksSentThisRttWindow.store(0, std::memory_order_relaxed);
        }
        if (m_naksSentThisRttWindow.load(std::memory_order_relaxed) >= PcbConst::MAX_NAKS_PER_RTT) {
            return;
        }
        m_naksSentThisRttWindow.store(m_naksSentThisRttWindow.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);

        uint32_t cumAck =
            0 < m_nextExpectedSequence.load(std::memory_order_relaxed) ? m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U : 0;
        m_lastAckSentMicros.store(nowMicros, std::memory_order_relaxed);

        packet.header =
            CreateHeader(UcpPacketType::Nak, (int)UcpPacketFlags::None, nowMicros, m_connectionId.load(std::memory_order_relaxed));
        packet.ack_number = cumAck;
        packet.missing_sequences = missing;

        {
            std::lock_guard<std::mutex> epLock(m_endpointMutex);
            hasRemote = m_hasRemoteEndpoint.load(std::memory_order_relaxed);
            remoteEndpoint = m_remoteEndpoint;
        }
    }

    ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(packet);
    m_sentNakPackets++;
    auto* trpNak = m_transport.load(std::memory_order_acquire);
    if (nullptr != trpNak && hasRemote) {
        trpNak->Send(encoded, remoteEndpoint);
    }
}

/** @brief Schedules a delayed ACK to be sent after the configured timeout.
 *  Uses the network timer if available, otherwise sends immediately.
 *  Delayed ACK timeout is reduced when the RTT exceeds 30 ms (max 1 ms delay).
 *  Idempotent: subsequent calls are ignored while a delay is already pending. */
void UcpPcb::ScheduleAck() noexcept {
    int64_t delayedTimeout = m_config.DelayedAckTimeoutMicros();
    if (0 >= delayedTimeout) {
        SendAckPacket((int)UcpPacketFlags::None, 0);
        return;
    }

    int64_t ackDelayMicros = delayedTimeout;
    if (m_lastRttMicros.load(std::memory_order_acquire) > ACK_DELAY_RTT_THRESHOLD_MILLIS * Constants::MICROS_PER_MILLI) {
        ackDelayMicros = (std::min)(ackDelayMicros, Constants::MICROS_PER_MILLI);
    }

    {
        bool expected = false;
        if (!m_ackDelayed.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
            return;
        }
    }
    auto* netAck = m_network.load(std::memory_order_acquire);
    if (NULLPTR != netAck) {
        int64_t nowUs = netAck->GetCurrentTimeUs();
        auto alive = m_aliveFlag;
        m_ackTimerId = netAck->AddTimer(nowUs + ackDelayMicros, [this, alive]() noexcept {
            if (!alive || !*alive || m_ctsCanceled) {
                return;
            }
            EnqueueWork([this, alive]() noexcept {
                if (!alive || !*alive || m_ctsCanceled) {
                    return;
                }
                m_ackDelayed.store(false, std::memory_order_relaxed);
                SendAckPacket((int)UcpPacketFlags::None, 0);
            });
        });
    } else {
        m_ackDelayed.store(false, std::memory_order_relaxed);
        SendAckPacket((int)UcpPacketFlags::None, 0);
    }
}

/** @brief Sends a CID rotation notification data packet to inform the peer of a new
 *  connection ID.  The new CID is embedded in the payload for the peer to register.
 *  @param newCid  The new connection ID to announce to the peer. */
void UcpPcb::SendCidUpdate(uint32_t newCid) {
    if (0 == newCid) {
        return;
    }
    UcpDataPacket packet;
    {
        std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
        packet.header = CreateHeader(UcpPacketType::Data, (int)UcpPacketFlags::NeedAck | (int)UcpPacketFlags::HasAckNumber, NowMicros(),
                                     m_connectionId);
        packet.sequence_number = PcbConst::CID_ROTATE_SEQUENCE_MARKER;
        packet.fragment_total = 1;
        packet.fragment_index = 0;
        packet.payload.resize(sizeof(uint32_t));
        std::memcpy(packet.payload.data(), &newCid, sizeof(uint32_t));
        packet.ack_number =
            0 < m_nextExpectedSequence.load(std::memory_order_relaxed) ? m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U : 0;
        uint32_t usedBytes = GetReceiveWindowUsedBytes();
        packet.window_size = usedBytes >= m_localReceiveWindowBytes ? 0U : m_localReceiveWindowBytes - usedBytes;
        packet.echo_timestamp = m_lastEchoTimestamp.load(std::memory_order_relaxed);
    }
    ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(packet);
    m_sentDataPackets++;
    m_bytesSent += sizeof(uint32_t);
    Endpoint remoteEndpoint;
    auto* trp = m_transport.load(std::memory_order_acquire);
    if (nullptr != trp && TryGetRemoteEndpoint(remoteEndpoint)) {
        trp->Send(encoded, remoteEndpoint);
    }
}

/** @brief Flushes the send queue: selects segments for transmission based on pacing,
 *  congestion window, fair-queue credit, and priority.  Piggybacks ACK/SACK/window data
 *  on outbound data packets.  Encodes and transmits via the transport.
 *  Uses the flush-lock to prevent concurrent flushes.  Handles retransmission,
 *  FEC repair packet generation, and urgent recovery packets.
 *  Empties the send buffer of ACKed segments.
 *
 *  After draining, runs a bounded inline drain of pending inbound packets
 *  (ProcessPendingInbound) so inbound ACK processing can update flightBytes,
 *  preventing send-window stalls on loopback and real networks. */
void UcpPcb::FlushSendQueueAsync() noexcept {
    if (!TryAcquireFlushLock()) {
        m_flushNeeded = true;
        return;
    }

    bool sentAny = false;
    bool moreWork = false;
    bool windowLimited = false;
    try {

        m_segmentsToSend.clear();
        int64_t waitMicros = 0;
        uint32_t piggyCumAck = 0;
        int64_t sendTime = 0;
        uint32_t piggyWindow = 0;
        int64_t piggyEcho = 0;
        ucp::vector<SackBlock> piggySackBlocks;

        {
            std::lock_guard<std::mutex> sackLock(m_sackMutex);
            std::lock_guard<std::mutex> lock(m_sync);
            sendTime = NowMicros();
            int64_t nowMicros = sendTime;
            int windowBytes = GetSendWindowBytes();
            int piggybackedAckOverhead = PcbConst::DATA_HEADER_SIZE_WITH_ACK - PcbConst::DATA_HEADER_SIZE;
            int segmentsThisBurst = 0;

            auto flushIt = m_sendBuffer.lower_bound(m_sendCursorSeq);
            bool cursorWrapped = false;
            while (segmentsThisBurst < PcbConst::MAX_SEGMENTS_PER_FLUSH) {
                if (flushIt == m_sendBuffer.end()) {
                    if (cursorWrapped)
                        break;
                    flushIt = m_sendBuffer.begin();
                    cursorWrapped = true;
                    m_sendCursorSeq = 0;
                    if (flushIt == m_sendBuffer.end())
                        break;
                }
                {
                    auto& segment = flushIt->second;
                    if (segment.Acked) {
                        ++flushIt;
                        continue;
                    }
                    if (segment.InFlight && !segment.NeedsRetransmit) {
                        ++flushIt;
                        continue;
                    }

                    if (!segment.NeedsRetransmit && !segment.InFlight &&
                        m_flightBytes.load(std::memory_order_relaxed) + static_cast<int64_t>(segment.Payload.size()) > windowBytes) {
                        windowLimited = true;
                        if (m_segmentsToSend.empty()) {
                            waitMicros = Constants::DEFAULT_PACING_WAIT_MICROS;
                        }
                        ++flushIt;
                        break;
                    }

                    int packetSize = PcbConst::DATA_HEADER_SIZE + piggybackedAckOverhead + (int)segment.Payload.size();

                    SackTrackingState* flushSackState = NULLPTR;
                    auto stIt = m_sackTracking.find(segment.SequenceNumber);
                    if (stIt != m_sackTracking.end()) {
                        flushSackState = &stIt->second;
                    }
                    bool hasUrgentFlag = flushSackState && flushSackState->UrgentRetransmit;
                    bool urgentRecovery =
                        segment.NeedsRetransmit && 0 < segment.SendCount && hasUrgentFlag && CanUseUrgentRecovery(nowMicros);
                    if (m_useFairQueue.load(std::memory_order_relaxed) &&
                        m_fairQueueCreditBytes.load(std::memory_order_relaxed) < (double)packetSize && !urgentRecovery) {
                        if (m_segmentsToSend.empty()) {
                            waitMicros = std::max<int64_t>(PcbConst::MIN_TIMER_WAIT_MILLISECONDS * 1000LL, 1000LL);
                        }
                        ++flushIt;
                        break;
                    }
                    if (urgentRecovery) {
                        if (m_pacing) {
                            m_pacing->ForceConsume(packetSize, nowMicros);
                        }
                        m_urgentRecoveryPacketsInWindow++;
                    } else if (m_pacing && !m_pacing->TryConsume(packetSize, nowMicros)) {
                        waitMicros = m_pacing->GetWaitTimeMicros(packetSize, nowMicros);
                        ++flushIt;
                        break;
                    }
                    if (m_useFairQueue.load(std::memory_order_relaxed)) {
                        double fq = m_fairQueueCreditBytes.load(std::memory_order_relaxed) - (double)packetSize;
                        if (0 > fq) {
                            fq = 0;
                        }
                        m_fairQueueCreditBytes.store(fq, std::memory_order_relaxed);
                    }

                    segment.InFlight = true;
                    segment.NeedsRetransmit = false;
                    if (flushSackState) {
                        flushSackState->UrgentRetransmit = false;
                    }
                    if (0 == segment.SendCount) {
                        m_flightBytes.store(m_flightBytes.load(std::memory_order_relaxed) + static_cast<int64_t>(segment.Payload.size()),
                                            std::memory_order_relaxed);
                    }
                    segment.SendCount++;
                    segment.LastSendMicros = nowMicros;

                    if (m_congestion) {
                        // Already inside the sackMutex+m_sync block (3036-3037);
                        // no extra lock needed here.
                        m_congestion->OnPacketSent(nowMicros, segment.SendCount > 1);
                        int64_t edtWstamp =
                            nowMicros + (m_pacing ? m_pacing->GetWaitTimeMicros(static_cast<int>(segment.Payload.size()), nowMicros) : 0);
                        m_congestion->SetEdtState(nowMicros, edtWstamp);
                    }

                    m_segmentsToSend.emplace_back();
                    segmentsThisBurst++;
                    auto& copy = m_segmentsToSend.back();
                    copy.SequenceNumber = segment.SequenceNumber;
                    copy.FragmentTotal = segment.FragmentTotal;
                    copy.FragmentIndex = segment.FragmentIndex;
                    copy.Payload = segment.Payload;
                    copy.SendCount = segment.SendCount;
                    copy.Priority = segment.Priority;

                    if (1 < copy.SendCount) {
                        m_retransmittedPackets++;
                    } else {
                        m_sentDataPackets++;
                        m_bytesSent += (int64_t)segment.Payload.size();
                    }
                }
                ++flushIt;
            }

            if (flushIt != m_sendBuffer.end() && segmentsThisBurst >= PcbConst::MAX_SEGMENTS_PER_FLUSH) {
                m_sendCursorSeq = flushIt->first;
            } else if (flushIt == m_sendBuffer.end() && !m_sendBuffer.empty()) {

                m_sendCursorSeq = 0;
            }

            if (!m_segmentsToSend.empty() && m_ackDelayed.exchange(false, std::memory_order_relaxed)) {
                // A piggybacked ACK will be sent with this burst: cancel the
                // delayed-ACK timer so it does not fire a redundant ACK
                // (mirrors C# UcpPcb:3288-3292).
                uint32_t ackTimer = m_ackTimerId.exchange(0, std::memory_order_relaxed);
                if (0 != ackTimer) {
                    auto* netCancel = m_network.load(std::memory_order_acquire);
                    if (NULLPTR != netCancel) {
                        netCancel->CancelTimer(ackTimer);
                    }
                }
            }
            piggyCumAck = 0 < m_nextExpectedSequence.load(std::memory_order_relaxed)
                              ? m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U
                              : 0;
            piggyEcho = m_lastEchoTimestamp.load(std::memory_order_relaxed);
        }

        if (m_segmentsToSend.empty()) {
            if (0 < piggyCumAck && m_ackDelayed.exchange(false, std::memory_order_relaxed)) {
                SendAckPacket((int)UcpPacketFlags::None, piggyEcho);
            }

            moreWork = HasPendingSendData();
            if (0 < waitMicros) {
                ScheduleDelayedFlush(waitMicros);
            }
        } else {
            sentAny = true;

            uint32_t connIdForHeader = 0;
            {
                std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
                ucp::vector<uint32_t> recvKeys;
                for (auto& kv : m_recvBuffer) {
                    recvKeys.push_back(kv.first);
                }
                piggySackBlocks = m_sackGenerator->Generate(m_nextExpectedSequence.load(std::memory_order_relaxed), recvKeys,
                                                            m_config.MaxAckSackBlocks());
                piggyWindow = 0 < piggyCumAck ? (m_localReceiveWindowBytes > GetReceiveWindowUsedBytes()
                                                     ? m_localReceiveWindowBytes - GetReceiveWindowUsedBytes()
                                                     : 0U)
                                              : m_localReceiveWindowBytes;
                piggyEcho = m_lastEchoTimestamp.load(std::memory_order_relaxed);
                m_lastAckSentMicros = sendTime;
                connIdForHeader = m_connectionId;
            }

            if (m_segmentsToSend.size() > 1 && m_segmentsToSend[0].Priority != m_segmentsToSend.back().Priority) {
                std::sort(m_segmentsToSend.begin(), m_segmentsToSend.end(),
                          [](const FlushSegmentCopy& a, const FlushSegmentCopy& b) noexcept {
                              if (a.Priority != b.Priority) {
                                  return (int)a.Priority > (int)b.Priority;
                              }
                              return UcpSequenceComparer::IsBefore(a.SequenceNumber, b.SequenceNumber);
                          });
            }

            {
                Endpoint remoteEndpoint;
                bool hasRemote = TryGetRemoteEndpoint(remoteEndpoint);

                for (auto& segment : m_segmentsToSend) {
                    int pktFlags = 1 < segment.SendCount
                                       ? (int)UcpPacketFlags::NeedAck | (int)UcpPacketFlags::Retransmit | (int)UcpPacketFlags::HasAckNumber
                                       : (int)UcpPacketFlags::NeedAck | (int)UcpPacketFlags::HasAckNumber;

                    UcpDataPacket dataPacket;
                    dataPacket.header = CreateHeader(UcpPacketType::Data, pktFlags, sendTime, connIdForHeader);
                    dataPacket.sequence_number = segment.SequenceNumber;
                    dataPacket.fragment_total = segment.FragmentTotal;
                    dataPacket.fragment_index = segment.FragmentIndex;
                    dataPacket.payload = std::move(segment.Payload);

                    dataPacket.ack_number = piggyCumAck;
                    if (!piggySackBlocks.empty()) {
                        dataPacket.sack_blocks = piggySackBlocks;
                    }
                    dataPacket.window_size = piggyWindow;
                    dataPacket.echo_timestamp = piggyEcho;

                    ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(dataPacket);
                    auto* trp = m_transport.load(std::memory_order_acquire);
                    if (hasRemote && nullptr != trp) {
                        if (IsTraceEnabled()) {
                            // Serialize CC read for the trace only when tracing
                            // is actually enabled; otherwise this per-segment
                            // lock is pure overhead on the send hot path.
                            std::lock_guard<std::mutex> ccLock(m_sync);
                            UCP_LOG(this, "SEND", "seq=%08X size=%zu inflight=%lld cwnd=%lld pacing=%.0f",
                                    segment.SequenceNumber, segment.Payload.size(),
                                    (long long)m_flightBytes.load(std::memory_order_acquire),
                                    m_congestion ? (long long)m_congestion->GetCongestionWindowBytes() : 0LL,
                                    m_congestion ? m_congestion->GetPacingRateBytesPerSecond() : 0.0);
                        }
                        trp->Send(encoded, remoteEndpoint);
                    }

                    if (m_fecCodec && 1 >= segment.SendCount) {
                        uint32_t fecGroupBaseSeq = m_fecCodec->GetGroupBase(segment.SequenceNumber);
                        auto repairs = m_fecCodec->TryEncodeRepairs(segment.SequenceNumber, segment.Payload);
                        bool fecEligible = false;
                        if (repairs.has_value() && !repairs.value().empty() && m_congestion) {
                            std::lock_guard<std::mutex> ccLock(m_sync);
                            fecEligible =
                                m_congestion->GetEstimatedLossPercent() >= PcbConst::ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT;
                        }
                        if (fecEligible) {
                            for (int ri = 0; ri < (int)repairs.value().size(); ri++) {
                                UcpFecRepairPacket repairPkt;
                                repairPkt.header =
                                    CreateHeader(UcpPacketType::FecRepair, (int)UcpPacketFlags::None, sendTime, connIdForHeader);
                                repairPkt.group_id = fecGroupBaseSeq;
                                repairPkt.group_index = (uint8_t)ri;
                                repairPkt.payload = repairs.value()[ri];
                                ucp::vector<uint8_t> encodedRepair = UcpPacketCodec::Encode(repairPkt);
                                if (hasRemote && nullptr != trp) {
                                    trp->Send(encodedRepair, remoteEndpoint);
                                }
                            }
                            std::lock_guard<std::mutex> lock(m_fecRepairGroupsMutex);
                            m_fecRepairSentGroups.insert(fecGroupBaseSeq);
                        }
                    }
                }
            }

            moreWork = HasPendingSendData();
        }
    } catch (const std::exception&) {
    }
    ReleaseFlushLock();

    if (moreWork) {
        int iterations = 0;
        while (iterations < 8 && HasPendingSendData()) {
            ProcessPendingInbound();
            iterations++;
        }
    }

    bool flushRequested = m_flushNeeded.exchange(false);

    if (moreWork || flushRequested) {
        auto alive = m_aliveFlag;
        EnqueueWork([this, alive]() noexcept {
            if (!alive || !*alive)
                return;
            FlushSendQueueAsync();
        });
    }
}

/** @brief Processes up to 16 pending inbound work items from the work queue inline.
 *  This is called from FlushSendQueueAsync when the send window is full, to drain
 *  inbound ACKs and data that would otherwise be stuck behind the flush re-enqueue.
 *  Safe to call after m_flushLock is released: inbound handlers (HandleData,
 *  HandleAckAsync) acquire m_sackMutex/m_sync which are independent of the flush lock.
 *  Bounded to 16 items to limit inline processing time. */
void UcpPcb::ProcessPendingInbound() noexcept {
    static thread_local bool inlineDrainActive = false;
    if (inlineDrainActive) {
        return;
    }
    inlineDrainActive = true;
    for (int i = 0; i < 16; i++) {
        ucp::function<void()> task;
        {
            std::lock_guard<std::mutex> lock(m_workMutex);
            if (m_workQueue.empty()) {
                break;
            }
            task = std::move(m_workQueue.front());
            m_workQueue.pop_front();
        }
        if (task) {
            try {
                task();
            } catch (const std::exception&) {

            } catch (...) {
            }
        }
    }
    inlineDrainActive = false;
}

/** @brief Schedules a delayed flush when pacing prevents immediate transmission.
 *  Uses the network timer if available, otherwise sets a deadline for the next
 *  standalone timer tick to check.
 *  @param waitMicros  Minimum time to wait before the next flush attempt. */
void UcpPcb::ScheduleDelayedFlush(int64_t waitMicros) noexcept {
    if (waitMicros < 0) {
        waitMicros = 0;
    }

    auto* netFlush = m_network.load(std::memory_order_acquire);
    if (m_flushDelayed.load(std::memory_order_relaxed)) {
        if (netFlush && 0 != m_flushTimerId.load(std::memory_order_relaxed) &&
            waitMicros < (m_flushDelayedDeadline.load(std::memory_order_relaxed) - NowMicros())) {
            netFlush->CancelTimer(m_flushTimerId.load(std::memory_order_relaxed));
            m_flushTimerId.store(0, std::memory_order_relaxed);
            m_flushDelayedDeadline.store(0, std::memory_order_relaxed);
        } else {
            int64_t newDeadline = NowMicros() + waitMicros;
            if (newDeadline < m_flushDelayedDeadline.load(std::memory_order_relaxed)) {
                m_flushDelayedDeadline.store(newDeadline, std::memory_order_relaxed);
                if (nullptr == netFlush) {
                    m_standaloneTimerCv.notify_one();
                }
            }
            if (nullptr == netFlush) {
                m_workSignal.notify_one();
            }
            return;
        }
    }
    m_flushDelayed.store(true, std::memory_order_relaxed);

    if (nullptr != netFlush) {
        int64_t nowUs = netFlush->GetCurrentTimeUs();
        auto alive = m_aliveFlag;
        m_flushTimerId.store(netFlush->AddTimer(nowUs + waitMicros,
                                                [this, alive]() noexcept {
                                                    if (!alive || !*alive) {
                                                        return;
                                                    }

                                                    m_flushDelayed.store(false, std::memory_order_relaxed);
                                                    m_flushTimerId.store(0, std::memory_order_relaxed);
                                                    EnqueueWork([this, alive]() noexcept {
                                                        if (!alive || !*alive) {
                                                            return;
                                                        }
                                                        FlushSendQueueAsync();
                                                    });
                                                }),
                             std::memory_order_relaxed);
    } else {
        m_flushDelayedDeadline.store(NowMicros() + waitMicros, std::memory_order_relaxed);
        m_workSignal.notify_one();

        m_standaloneTimerCv.notify_one();
    }
}

/** @brief Enqueues a reassembled payload into the receive queue for the application.
 *  Fires the DataReceived callback and notifies any pending receive operations.
 *  @param payload  The complete payload bytes to deliver to the application. */
void UcpPcb::EnqueuePayload(ucp::vector<uint8_t> payload) noexcept {
    if (payload.empty()) {
        return;
    }
    int len = (int)payload.size();

    // Copy the payload for the DataReceived callback BEFORE moving it into the
    // queue (the callback must not reference the queued chunk: a concurrent
    // ReceiveAsync could pop it and free its buffer while the callback runs).
    // The callback fires AFTER the enqueue so that a user callback which
    // Disposes the connection cannot invalidate the enqueue that already ran.
    // Mirroring the C# side, which passes its own byte[] (UcpPcb.cs:3585).
    DataReceivedCallback cb;
    ucp::vector<uint8_t> callbackData;
    {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        cb = DataReceived;
        if (cb) {
            callbackData = payload;
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_receiveMutex);
        ReceiveChunk chunk;
        chunk.Buffer = std::move(payload);
        chunk.Count = len;
        chunk.Offset = 0;
        m_receiveQueue.push(std::move(chunk));
        m_queuedReceiveBytes += len;
        m_bytesReceived += len;
    }

    if (cb) {
        try {
            cb(callbackData.data(), 0, len);
        } catch (...) {
            // User callback must never escape a noexcept function: an uncaught
            // exception here would std::terminate the process. Swallow it.
        }
    }

    {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        m_receiveSignal.notify_all();
    }

    TrySatisfyPendingReceives();
}

void UcpPcb::OnTimerAsync() noexcept {
    OnTimerAsync(NowMicros());
}

/** @brief Main periodic timer handler: runs retransmission (RTO) detection, tail-loss probe (TLP),
 *  keep-alive, handshake retransmission, close state machine, NAK collection, and CID rotation.
 *  Executed on the worker thread.  This is the heart of the protocol's timer-driven state machine.
 *  @param nowMicros  Current microsecond timestamp for all timeout comparisons. */
void UcpPcb::OnTimerAsync(int64_t nowMicros) noexcept {
    bool timedOut = false;
    bool sendKeepAlive = false;
    bool retransmitSynAck = false;
    bool maxRetransmissionsExceeded = false;
    bool timedOutForCongestion = false;
    bool tailLossProbe = false;
    ucp::vector<uint32_t> missingForNak;

    bool retransmitSyn = false;
    bool connectTimedOut = false;
    bool closeDrained = false;
    bool closeTimedOut = false;

    bool shouldSendCidUpdate = false;
    uint32_t cidUpdatePayload = 0;

    bool shouldSendMtuProbe = false;

    bool disconnectTimedOut = false;

    if (m_pathChanged.exchange(false, std::memory_order_acq_rel) &&
        UcpConnectionState::Established == m_state.load(std::memory_order_acquire)) {
        m_probeMin.store(PcbConst::MTU_PROBE_BASE, std::memory_order_relaxed);
        m_probeMax.store(m_config.MtuProbeMax, std::memory_order_relaxed);
        m_mtuProbePending.store(false, std::memory_order_relaxed);
        m_mtuProbeAcked.store(false, std::memory_order_relaxed);
        m_lastMtuConvergeMicros.store(0, std::memory_order_relaxed);
        if (m_congestion) {
            std::lock_guard<std::mutex> ccLock(m_sync);
            m_congestion->OnPathChange(nowMicros);
        }
    }

    {
        std::lock_guard<std::mutex> sackLock(m_sackMutex);
        std::lock_guard<std::mutex> lock(m_sync);
        if (!m_rtoEstimator) {
            return;
        }

        int maxPayload = (std::max)(1, m_config.MaxPayloadSize());
        int inflightSegments =
            0 >= maxPayload ? 0 : (int)std::ceil((double)m_flightBytes.load(std::memory_order_relaxed) / (double)maxPayload);
        int rtoRetransmitBudget = PcbConst::RTO_RETRANSMIT_BUDGET_PER_TICK;
        int64_t rtoLostBytes = 0;
        for (auto& pair : m_sendBuffer) {
            OutboundSegment& segment = pair.second;
            if (!segment.InFlight || segment.Acked || segment.NeedsRetransmit) {
                continue;
            }

            int64_t rtoMicros = m_rtoEstimator->CurrentRtoMicros();
            int64_t segmentAge = nowMicros - segment.LastSendMicros;
            if (segmentAge >= rtoMicros) {
                if (0 >= rtoRetransmitBudget) {
                    break;
                }
                bool segTimedOutCongestion = IsCongestionLoss(segment.SequenceNumber, 0, nowMicros, 1);
                if (segment.SendCount >= m_config.MaxRetransmissions && segTimedOutCongestion) {
                    m_timeoutRetransmissions++;
                    maxRetransmissionsExceeded = true;
                    break;
                }
                segment.NeedsRetransmit = true;
                GetOrCreateSackTracking(segment.SequenceNumber)->UrgentRetransmit = true;
                timedOut = true;
                rtoRetransmitBudget--;
                rtoLostBytes += static_cast<int64_t>(segment.Payload.size());
                timedOutForCongestion = timedOutForCongestion || segTimedOutCongestion;
                m_timeoutRetransmissions++;
            }
        }

        if (!timedOut && !m_tailLossProbePending && 0 < inflightSegments && inflightSegments <= PcbConst::TLP_MAX_INFLIGHT_SEGMENTS) {
            int64_t tlpTimeoutMicros =
                m_rtoEstimator->SmoothedRttMicros() > 0
                    ? (int64_t)std::ceil((double)m_rtoEstimator->SmoothedRttMicros() * PcbConst::TLP_TIMEOUT_RTT_RATIO)
                    : m_rtoEstimator->CurrentRtoMicros();

            for (auto& pair : m_sendBuffer) {
                OutboundSegment& segment = pair.second;
                if (segment.Acked || !segment.InFlight || segment.NeedsRetransmit) {
                    continue;
                }
                int64_t segAge = nowMicros - segment.LastSendMicros;
                // Karn-style guard: never retransmit a freshly sent segment,
                // even when ACKs have stopped (mirrors C# UcpPcb.cs:3640).
                if (segAge < tlpTimeoutMicros) {
                    continue;
                }

                segment.NeedsRetransmit = true;
                GetOrCreateSackTracking(segment.SequenceNumber)->UrgentRetransmit = IsNearDisconnectTimeout(nowMicros);
                m_tailLossProbePending = true;
                tailLossProbe = true;
                break;
            }
        }

        if (!timedOut && !m_tailLossProbePending && inflightSegments > PcbConst::TLP_MAX_INFLIGHT_SEGMENTS &&
            m_rtoEstimator->SmoothedRttMicros() > 0) {
            bool ackStopped = (0 < m_lastAckReceivedMicros &&
                               nowMicros - m_lastAckReceivedMicros >= std::max<int64_t>(m_rtoEstimator->SmoothedRttMicros() * 3, 1000LL));
            if (!ackStopped) {
                for (auto& pair : m_sendBuffer) {
                    if (pair.second.Acked || !pair.second.InFlight || pair.second.NeedsRetransmit)
                        continue;
                    if (nowMicros - pair.second.LastSendMicros < m_rtoEstimator->CurrentRtoMicros()) {
                        continue;
                    }
                    ackStopped = true;
                    break;
                }
            }
            if (ackStopped) {
                uint32_t highestSeq = 0;
                OutboundSegment* newest = NULLPTR;
                for (auto& pair : m_sendBuffer) {
                    if (pair.second.Acked || !pair.second.InFlight || pair.second.NeedsRetransmit)
                        continue;
                    if (!newest || UcpSequenceComparer::IsAfter(pair.first, highestSeq)) {
                        highestSeq = pair.first;
                        newest = &pair.second;
                    }
                }
                if (newest) {
                    newest->NeedsRetransmit = true;
                    GetOrCreateSackTracking(newest->SequenceNumber)->UrgentRetransmit = true;
                    m_tailLossProbePending = true;
                    tailLossProbe = true;
                }
            }
        }
        if (timedOut) {
            UCP_LOG(this, "RTO", "rto=%lld us flight=%lld budget=%d", (long long)m_rtoEstimator->CurrentRtoMicros(),
                    (long long)m_flightBytes.load(std::memory_order_relaxed), PcbConst::RTO_RETRANSMIT_BUDGET_PER_TICK);
            if (m_congestion) {
                m_congestion->OnPacketLoss(nowMicros, GetRetransmissionRatio(), timedOutForCongestion, rtoLostBytes);
            }
            if (timedOutForCongestion) {
                m_rtoEstimator->Backoff();
            }
        }

        if (tailLossProbe) {
            UCP_LOG(this, "TLP", "flight=%lld rtt=%lld", (long long)m_flightBytes.load(std::memory_order_relaxed),
                    (long long)m_rtoEstimator->SmoothedRttMicros());
        }

        {
            std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
            CollectMissingForNak(missingForNak, nowMicros);
        }

        // Keepalive is driven purely by SEND idle time (m_lastAckSentMicros). It MUST NOT
        // depend on receive activity: if it did, a live peer that merely receives our
        // keepalives would have its own receive timestamps refreshed and would never emit its
        // own keepalives, so this side could never observe proof that the peer is alive. With
        // a send-idle-only trigger BOTH peers emit a keepalive every KeepAliveInterval on
        // their own schedule: each side continuously receives keepalives from a live peer and
        // refreshes m_lastPeerAliveMicros, while a dead peer stops sending and is torn down by
        // the disconnect check below.
        if (UcpConnectionState::Established == m_state && nowMicros - m_lastAckSentMicros >= m_config.KeepAliveIntervalMicros) {
            UCP_LOG(this, "KEEPALIVE", "peer-idle=%lld ms",
                    (long long)(nowMicros - m_lastPeerAliveMicros.load(std::memory_order_relaxed)) / 1000);
            sendKeepAlive = true;
        }

        if (UcpConnectionState::Established == m_state && m_remoteWindowBytes.load(std::memory_order_relaxed) == 0) {
            int64_t lastProbe = m_zeroWindowProbeTimeMicros.load(std::memory_order_relaxed);
            if (lastProbe == 0 || nowMicros - lastProbe >= PcbConst::ZERO_WINDOW_PROBE_INTERVAL_MICROS) {
                m_zeroWindowProbeTimeMicros.store(nowMicros, std::memory_order_relaxed);
                sendKeepAlive = true;
            }
        } else if (m_remoteWindowBytes.load(std::memory_order_relaxed) > 0) {

            m_zeroWindowProbeTimeMicros.store(0, std::memory_order_relaxed);
        }

        if (m_isServerSide.load(std::memory_order_relaxed) && UcpConnectionState::HandshakeSynReceived == m_state && m_synAckSent &&
            nowMicros - m_synAckSentMicros >= m_rtoEstimator->CurrentRtoMicros()) {
            UCP_LOG(this, "SYNACK_RETX", "rto=%lld us", (long long)m_rtoEstimator->CurrentRtoMicros());
            m_synAckSentMicros = nowMicros;
            retransmitSynAck = true;
        }

        if (m_hasPendingConnectCallback && UcpConnectionState::HandshakeSynSent == m_state) {

            int64_t deadlineMicros = m_connectStartMicros + (int64_t)m_config.ConnectTimeoutMilliseconds * Constants::MICROS_PER_MILLI;
            if (nowMicros >= deadlineMicros) {
                connectTimedOut = true;
            } else {

                int64_t rtoMicros = m_rtoEstimator->CurrentRtoMicros();
                int64_t handshakeWaitMicros = (std::max)(PcbConst::MIN_HANDSHAKE_WAIT_MILLISECONDS * Constants::MICROS_PER_MILLI,
                                                         rtoMicros / Constants::MICROS_PER_MILLI * Constants::MICROS_PER_MILLI);
                if (nowMicros - m_lastSynSentMicros >= handshakeWaitMicros) {
                    m_lastSynSentMicros = nowMicros;
                    retransmitSyn = true;
                }
            }
        }

        if (m_hasPendingCloseCallback && !m_finSent) {
            int64_t closeDeadlineMicros = m_closeStartMicros + m_config.DisconnectTimeoutMicros;
            if (nowMicros >= closeDeadlineMicros) {
                closeTimedOut = true;
            } else if (m_sendBuffer.empty() &&
                       (UcpConnectionState::ClosingFinSent == m_state || UcpConnectionState::ClosingFinReceived == m_state ||
                        UcpConnectionState::Established == m_state)) {
                m_finSent = true;
                m_finSentMicros = nowMicros;
                m_finRetransmitCount = 1;
                m_state = UcpConnectionState::ClosingFinSent;
                closeDrained = true;
            }
        }

        // Mirrors C# close path (UcpPcb.cs:3734-3747): a lost FIN must be
        // retransmitted on RTO, capped at MaxRetransmissions, so a dead peer
        // is detected via close timeout rather than waiting for the deadline.
        if (m_finSent && !m_finAcked && UcpConnectionState::Closed != m_state) {
            if (nowMicros - m_finSentMicros >= m_rtoEstimator->CurrentRtoMicros()) {
                if (m_finRetransmitCount >= m_config.MaxRetransmissions) {
                    closeTimedOut = true;
                } else {
                    m_finSentMicros = nowMicros;
                    m_finRetransmitCount++;
                    closeDrained = true;
                }
            }
        }

        if (UcpConnectionState::Established == m_state && 0 == m_lastCidRotateMicros) {
            m_lastCidRotateMicros = nowMicros;
        }

        if (UcpConnectionState::Established == m_state && !m_cidRotatePending && m_lastCidRotateMicros > 0 &&
            nowMicros - m_lastCidRotateMicros >= PcbConst::CID_ROTATE_INTERVAL_MICROS && m_hasRemoteEndpoint) {
            m_pendingNewCid = GenerateNewCid();
            {
                std::lock_guard<std::mutex> lk(m_endpointMutex);
                int cnt = m_extraCidCount.load(std::memory_order_relaxed);
                if (cnt < UcpPcb::MAX_EXTRA_CIDS) {
                    m_extraCidsArray[cnt] = m_pendingNewCid.load(std::memory_order_relaxed);
                    m_extraCidCount.store(cnt + 1, std::memory_order_release);
                }
            }
            m_cidRotatePending = true;
            m_cidRotateMarkerSequence = m_nextSendSequence.load(std::memory_order_relaxed) - 1U;
            m_lastCidRotateMicros = nowMicros;
            shouldSendCidUpdate = true;
            cidUpdatePayload = m_pendingNewCid;
        }

        if (m_lastCidRotateMicros > 0 && nowMicros - m_lastCidRotateMicros >= PcbConst::CID_RETIRE_AGE_MICROS) {
            {
                std::lock_guard<std::mutex> lk(m_endpointMutex);
                m_extraCidCount.store(0, std::memory_order_release);
            }
        }

        if (m_cidRotatePending && nowMicros - m_lastCidRotateMicros >= 5000000LL) {
            m_cidRotatePending = false;
        }

        if (m_pathChallengePending && nowMicros - m_pathChallengeTime >= PcbConst::PATH_CHALLENGE_TIMEOUT_MICROS) {
            m_pathChallengePending = false;
        }

        if (UcpConnectionState::Established == m_state && m_config.EnableMtuDiscovery) {
            if (m_mtuProbePending) {
                if (nowMicros - m_lastMtuProbeMicros >= m_config.MtuProbeTimeoutMicros) {
                    m_mtuProbePending = false;
                    m_probeMax.store(m_probeMtu.load(std::memory_order_relaxed), std::memory_order_relaxed);
                }
            } else if (m_mtuProbeAcked) {
                m_mtuProbeAcked = false;
                m_probeMin.store(m_probeMtu.load(std::memory_order_relaxed), std::memory_order_relaxed);
            }
            if (!m_mtuProbePending && m_probeMax - m_probeMin > 8) {
                m_probeMtu = (m_probeMin + m_probeMax) / 2;
                m_lastMtuProbeMicros = nowMicros;
                shouldSendMtuProbe = true;
            } else if (!m_mtuProbePending && m_probeMax - m_probeMin <= 8) {
                m_currentMtu.store(m_probeMin.load(std::memory_order_relaxed), std::memory_order_relaxed);
                if (0 == m_lastMtuConvergeMicros) {
                    m_lastMtuConvergeMicros = nowMicros;
                }
                if (nowMicros - m_lastMtuConvergeMicros >= m_config.MtuProbeIntervalMicros) {
                    m_probeMin = PcbConst::MTU_PROBE_BASE;
                    m_probeMax = m_config.MtuProbeMax;
                    m_lastMtuConvergeMicros = 0;
                    m_probeMtu = (m_probeMin + m_probeMax) / 2;
                    m_lastMtuProbeMicros = nowMicros;
                    shouldSendMtuProbe = true;
                }
            }
        }

        if ((UcpConnectionState::HandshakeSynSent == m_state || UcpConnectionState::HandshakeSynReceived == m_state ||
             UcpConnectionState::Established == m_state || UcpConnectionState::ClosingFinSent == m_state ||
             UcpConnectionState::ClosingFinReceived == m_state) &&
            nowMicros - m_lastPeerAliveMicros.load(std::memory_order_relaxed) >= m_config.DisconnectTimeoutMicros) {
            UCP_LOG(this, "DISCONNECT_TIMEOUT", "peer-idle=%lld ms timeout=%lld ms",
                    (long long)(nowMicros - m_lastPeerAliveMicros.load(std::memory_order_relaxed)) / 1000,
                    (long long)m_config.DisconnectTimeoutMicros / 1000);
            disconnectTimedOut = true;
        }
    }

    if (shouldSendCidUpdate && 0 != cidUpdatePayload) {
        SendCidUpdate(cidUpdatePayload);
    }

    if (shouldSendMtuProbe) {
        SendMtuProbe(m_probeMtu);
    }

    if (maxRetransmissionsExceeded) {
        TransitionToClosed();
        return;
    }
    if (timedOut || tailLossProbe) {
        FlushSendQueueAsync();
    }
    if (retransmitSynAck) {
        SendControl(UcpPacketType::SynAck, (int)UcpPacketFlags::None);
    }
    if (!missingForNak.empty()) {
        SendNak(missingForNak);
    }
    if (sendKeepAlive) {
        SendAckPacket((int)UcpPacketFlags::None, -1);
    }

    if (retransmitSyn) {
        SendControl(UcpPacketType::Syn, (int)UcpPacketFlags::None);
    }
    if (connectTimedOut) {
        FirePendingConnectCallback(UcpError::Timeout);
        TransitionToClosed();
    }

    if (closeDrained) {
        SendControl(UcpPacketType::Fin, (int)UcpPacketFlags::None);
    }
    if (closeTimedOut) {

        if (m_hasRemoteEndpoint.load(std::memory_order_acquire)) {
            SendControl(UcpPacketType::Rst, (int)UcpPacketFlags::None);
        }
        TransitionToClosed();
    }

    if (disconnectTimedOut) {
        TransitionToClosed();
        return;
    }

    bool shouldFlush = false;
    {
        if (m_flushDelayed.load(std::memory_order_relaxed) && 0 < m_flushDelayedDeadline.load(std::memory_order_relaxed) &&
            NowMicros() >= m_flushDelayedDeadline.load(std::memory_order_relaxed)) {
            m_flushDelayed.store(false, std::memory_order_relaxed);
            m_flushDelayedDeadline.store(0, std::memory_order_relaxed);
            shouldFlush = true;
        }
    }
    if (shouldFlush) {
        FlushSendQueueAsync();
    }
}

/** @brief Schedules the next periodic timer callback via the network timer infrastructure.
 *  Cancels any previously scheduled timer first to prevent orphaned heap entries.
 *  The timer fires after the configured TimerIntervalMilliseconds (with a minimum floor).
 *  Only used in network-managed mode; standalone mode uses a dedicated timer thread. */
void UcpPcb::ScheduleTimer() noexcept {
    if (nullptr == m_network.load(std::memory_order_relaxed) || m_disposed) {
        return;
    }
    auto* netTimer = m_network.load(std::memory_order_acquire);
    if (nullptr == netTimer || m_disposed) {
        // UcpNetwork::Dispose -> DetachNetwork may clear m_network between the
        // relaxed pre-check above and this acquire load; re-check before use.
        return;
    }
    if (0 != m_timerId) {
        netTimer->CancelTimer(m_timerId);
        m_timerId = 0;
    }
    int64_t intervalMicros = (std::max)((int64_t)PcbConst::MIN_TIMER_WAIT_MILLISECONDS, (int64_t)m_config.TimerIntervalMilliseconds) *
                             Constants::MICROS_PER_MILLI;
    auto alive = m_aliveFlag;
    // Capture a shared_ptr so the PCB cannot be destroyed between the alive
    // check and the work-item execution (a server PCB that never completes the
    // handshake may have its last external reference released from within
    // OnTimerAsync's transition-to-closed path).
    ucp::shared_ptr<UcpPcb> self;
    try {
        self = shared_from_this();
    } catch (...) {
        return;
    }
    m_timerId = netTimer->AddTimer(netTimer->GetCurrentTimeUs() + intervalMicros, [self, alive]() noexcept {
        if (!alive || !*alive) {
            return;
        }
        if (NULLPTR == self) {
            return;
        }
        self->EnqueueWork([self, alive]() noexcept {
            if (!alive || !*alive) {
                return;
            }
            self->OnTimer();
        });
    });
}

/** @brief Timer callback wrapper (standalone mode): runs the async timer logic, flushes
 *  pending send data, and reschedules the next timer if network-managed. */
void UcpPcb::OnTimer() noexcept {
    if (m_disposed) {
        return;
    }
    OnTimerAsync();
    if (HasPendingSendData()) {
        FlushSendQueueAsync();
    }
    if (nullptr != m_network.load(std::memory_order_relaxed)) {
        ScheduleTimer();
    }
}

/** @brief Transitions the connection to the Established state, firing the connected
 *  callback and any pending connect callback.  Idempotent. */
void UcpPcb::TransitionToEstablished() noexcept {

    UcpConnectionState st = m_state.load(std::memory_order_acquire);
    if (UcpConnectionState::Established == st || UcpConnectionState::Closed == st) {
        return;
    }

    ConnectedCallback connected;
    ConnectAsyncCallback connectCb;
    {
        std::lock_guard<std::mutex> lock(m_pendingCallbackMutex);
        st = m_state.load(std::memory_order_relaxed);
        if (UcpConnectionState::Established == st || UcpConnectionState::Closed == st) {
            return;
        }
        m_state.store(UcpConnectionState::Established, std::memory_order_release);
        if (!m_connectedRaised.load(std::memory_order_relaxed)) {
            m_connectedRaised.store(true, std::memory_order_relaxed);
            connected = Connected;
        }
        if (m_hasPendingConnectCallback.load(std::memory_order_relaxed)) {
            connectCb = m_pendingConnectCallback;
            m_pendingConnectCallback = ConnectAsyncCallback();
            m_hasPendingConnectCallback.store(false, std::memory_order_relaxed);
        }
    }
    {
        // CC read (log) serialized under m_sync like the mutation sites.
        std::lock_guard<std::mutex> ccLock(m_sync);
        UCP_LOG(this, "ESTABLISHED", "RTT=%lld us cwnd=%lld", (long long)m_lastRttMicros.load(std::memory_order_acquire),
                m_congestion ? (long long)m_congestion->GetCongestionWindowBytes() : 0LL);
    }
    if (connectCb) {
        try {
            connectCb(UcpError::None, m_connectionId);
        } catch (...) {
        }
    }
    if (connected) {
        try {
            connected();
        } catch (...) {
        }
    }
}

/** @brief Transitions the connection to the Closed state, firing disconnect/close callbacks,
 *  notifying receive and send-space conditions, releasing network registrations, and
 *  calling the closed callback.  Idempotent.
 *  Lock order: m_sync is released BEFORE m_receiveMutex to avoid nested locking. */
void UcpPcb::TransitionToClosed() noexcept {
    // Self-hold so the PCB cannot be destroyed from within one of the callbacks
    // fired below (Disconnected/CloseAsync/m_closedCallback can release the
    // last external shared_ptr, which would otherwise destroy *this while this
    // function is still running -> use-after-free on the remainder of the
    // transition and on the swapped-out buffers).  shared_from_this requires
    // the object to be owned by a shared_ptr; if it is not (some test paths
    // use raw new), the exception is swallowed and the transition proceeds
    // without the hold.
    ucp::shared_ptr<UcpPcb> selfHold;
    try {
        selfHold = shared_from_this();
    } catch (...) {
    }

    DisconnectedCallback disconnected;
    ConnectAsyncCallback connectCb;
    CloseAsyncCallback closeCb;
    bool releaseResources = false;

    SequenceMap oldSendBuf;
    RecvSequenceMap oldRecvBuf;
    decltype(m_sackTracking) oldSackTracking;
    decltype(m_sackFastRetransmitNotified) oldSackFastRetransmit;
    decltype(m_fecFragmentMetadata) oldFecMetadata;
    {
        // Lock order: m_sackMutex -> m_sendBufMutex -> m_sync -> m_recvBufMutex
        // (matches HandleAckAsync/HandleNakAsync's sack->sendBuf->sync prefix and
        // the existing sync->recvBuf edge; avoids the sendBuf<->sync cycle).
        std::lock_guard<std::mutex> sackLock(m_sackMutex);
        std::lock_guard<std::mutex> sendBufLock(m_sendBufMutex);
        std::lock_guard<std::mutex> lock(m_sync);
        std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
        if (UcpConnectionState::Closed == m_state) {
            if (m_closedResourcesReleased) {
                return;
            }
        }
        m_state = UcpConnectionState::Closed;
        if (!m_closedResourcesReleased) {
            m_closedResourcesReleased = true;
            releaseResources = true;
            UCP_LOG(this, "CLOSED", "reason=cleanup flight=%lld rtt=%lld", (long long)m_flightBytes.load(std::memory_order_relaxed),
                    (long long)m_lastRttMicros.load(std::memory_order_relaxed));

            m_sendBuffer.swap(oldSendBuf);
            m_recvBuffer.swap(oldRecvBuf);
            m_recvBufferBytes.store(0, std::memory_order_relaxed);
            m_sackTracking.swap(oldSackTracking);
            m_sackFastRetransmitNotified.swap(oldSackFastRetransmit);
            m_fecFragmentMetadata.swap(oldFecMetadata);
        }
        if (!m_disconnectedRaised) {
            m_disconnectedRaised = true;
            disconnected = Disconnected;
        }
        // m_pendingConnectCallback / m_pendingCloseCallback are guarded by
        // m_pendingCallbackMutex at every other access point (ConnectAsync,
        // FirePendingConnectCallback, FirePendingCloseCallback, CloseAsync,
        // TransitionToEstablished).  TransitionToClosed was the only place
        // reading/writing them without that lock -- a concurrent ConnectAsync /
        // CloseAsync (app thread) racing this close path is a data race on
        // std::function (UB).  Lock order m_sync -> m_pendingCallbackMutex is
        // safe: every other m_pendingCallbackMutex acquisition is standalone
        // (no nested m_sync), so no cycle exists.
        {
            std::lock_guard<std::mutex> cbLock(m_pendingCallbackMutex);
            if (m_hasPendingConnectCallback) {
                connectCb = m_pendingConnectCallback;
                m_pendingConnectCallback = ConnectAsyncCallback();
                m_hasPendingConnectCallback = false;
            }
            if (m_hasPendingCloseCallback) {
                closeCb = m_pendingCloseCallback;
                m_pendingCloseCallback = CloseAsyncCallback();
                m_hasPendingCloseCallback = false;
            }
        }
    }

    if (releaseResources) {
        StopNotifyThread();
    }

    {
        std::lock_guard<std::mutex> rlock(m_receiveMutex);
        decltype(m_receiveQueue) oldReceiveQueue;
        decltype(m_pendingReceives) oldPendingReceives;
        m_receiveQueue.swap(oldReceiveQueue);
        m_pendingReceives.swap(oldPendingReceives);
    }

    if (connectCb) {
        try {
            connectCb(UcpError::Disconnected, 0);
        } catch (...) {
        }
    }
    if (closeCb) {
        try {
            closeCb(UcpError::None);
        } catch (...) {
        }
    }
    {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        m_receiveSignal.notify_all();
    }
    {
        std::lock_guard<std::mutex> lk(m_sendSpaceSignalMutex);
        m_sendSpaceSignal.notify_all();
    }
    if (releaseResources) {
        ReleaseNetworkRegistrations();
    }
    if (disconnected) {
        try {
            disconnected();
        } catch (...) {
        }
    }
    if (m_closedCallback) {
        try {
            m_closedCallback(this);
        } catch (...) {
        }
    }
}

/** @brief Unregisters this PCB from the network and cancels all pending timers.
 *  Called during TransitionToClosed to clean up all network resources. */
void UcpPcb::ReleaseNetworkRegistrations() noexcept {
    auto* net = m_network.load(std::memory_order_acquire);
    if (nullptr == net) {
        return;
    }

    uint32_t timerId = m_timerId.exchange(0, std::memory_order_relaxed);
    uint32_t flushId = m_flushTimerId.exchange(0, std::memory_order_relaxed);
    uint32_t ackId = m_ackTimerId.exchange(0, std::memory_order_relaxed);
    m_flushDelayed.store(false, std::memory_order_relaxed);
    m_ackDelayed.store(false, std::memory_order_relaxed);

    net->UnregisterPcb(this);
    if (0 != timerId) {
        net->CancelTimer(timerId);
    }
    if (0 != flushId) {
        net->CancelTimer(flushId);
    }
    if (0 != ackId) {
        net->CancelTimer(ackId);
    }
}

/** @brief Detaches this PCB from the network: unregisters timers/registrations and
 *  clears m_network so subsequent ScheduleTimer/ScheduleAck/etc. become no-ops
 *  instead of dereferencing a destroyed UcpNetwork.  Mirrors C# UcpPcb.DetachNetwork. */
void UcpPcb::DetachNetwork() noexcept {
    {
        std::lock_guard<std::mutex> lock(m_sync);
        if (nullptr == m_network.load(std::memory_order_acquire)) {
            return;
        }
    }
    ReleaseNetworkRegistrations();
    m_network.store(NULLPTR, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(m_sync);
        m_timerId.store(0, std::memory_order_relaxed);
        m_flushTimerId.store(0, std::memory_order_relaxed);
        m_ackTimerId.store(0, std::memory_order_relaxed);
    }
}

/** @brief Validates an incoming ACK packet for plausibility: checks connection ID match,
 *  PAWS timestamp freshness, cumulative ACK progress, and SACK block ordering.
 *  @param ackPacket  The ACK packet to validate.
 *  @return True if the ACK is plausible and should be processed. */
bool UcpPcb::IsAckPlausible(const UcpAckPacket& ackPacket) noexcept {
    if (ackPacket.header.connection_id != m_connectionId) {

        bool found = false;
        int count = m_extraCidCount.load(std::memory_order_acquire);
        for (int _ei = 0; _ei < count; _ei++) {
            if (m_extraCidsArray[_ei] == ackPacket.header.connection_id) {
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }

    if (m_pawsEnabled && 0 < m_largestTimestampSeen &&
        m_largestTimestampSeen - (int64_t)ackPacket.header.timestamp > PcbConst::PAWS_TIMEOUT_MICROS) {
        return false;
    }

    if (m_hasLargestCumulativeAckNumber && UcpSequenceComparer::IsBefore(ackPacket.ack_number, m_largestCumulativeAckNumber)) {
        return false;
    }
    for (auto& block : ackPacket.sack_blocks) {
        if (UcpSequenceComparer::IsAfter(block.Start, block.End)) {
            return false;
        }
    }
    return true;
}

/** @brief Tracks duplicate ACK count and triggers fast retransmit when the threshold is reached.
 *  Resets the duplicate count and fast recovery flag on non-duplicate ACKs.
 *  @param ackPacket                 The incoming ACK packet.
 *  @param nowMicros                 Current microsecond timestamp.
 *  @param[out] fastRetransmitTriggered  Set to true if a fast retransmit was triggered. */
void UcpPcb::UpdateDuplicateAckState(const UcpAckPacket& ackPacket, int64_t nowMicros, bool& fastRetransmitTriggered) noexcept {
    fastRetransmitTriggered = false;
    bool duplicateAck = m_hasLastAckNumber && ackPacket.ack_number == m_lastAckNumber;
    if (duplicateAck) {
        m_duplicateAckCount++;
        if (m_duplicateAckCount >= PcbConst::DUPLICATE_ACK_THRESHOLD && !m_fastRecoveryActive) {
            uint32_t lostSeq = UcpSequenceComparer::Increment(ackPacket.ack_number);
            auto it = m_sendBuffer.find(lostSeq);
            if (it != m_sendBuffer.end() && !it->second.Acked && 1 == it->second.SendCount && !it->second.NeedsRetransmit) {
                int64_t rttForFastRetransmit = GetFastRetransmitAgeThreshold();
                if (ShouldTriggerEarlyRetransmit() || 0 >= rttForFastRetransmit ||
                    nowMicros - it->second.LastSendMicros >= rttForFastRetransmit) {
                    it->second.NeedsRetransmit = true;
                    SackTrackingState* st = GetOrCreateSackTracking(lostSeq);
                    st->UrgentRetransmit = true;
                    m_fastRecoveryActive = true;
                    m_fastRetransmissions++;
                    fastRetransmitTriggered = true;
                    bool isCongestion = IsCongestionLoss(lostSeq, 0, nowMicros, 1);
                    (void)isCongestion;
                    if (m_congestion) {
                        // Report the lost segment's payload bytes so the CC
                        // can account for them (mirrors C# UcpPcb:1994).
                        std::lock_guard<std::mutex> ccLock(m_sync);
                        m_congestion->OnFastRetransmit(nowMicros, isCongestion, static_cast<int64_t>(it->second.Payload.size()));
                    }
                }
            }
        }
    } else {
        m_duplicateAckCount = 0;
        m_fastRecoveryActive = false;
    }
    m_lastAckNumber = ackPacket.ack_number;
    m_hasLastAckNumber = true;
}

/** @brief Gets the SACK tracking state for a sequence number, creating a default entry if needed.
 *  @param sequenceNumber  The sequence number to track.
 *  @return Pointer to the SackTrackingState for this sequence. */
SackTrackingState* UcpPcb::GetOrCreateSackTracking(uint32_t sequenceNumber) noexcept {
    auto it = m_sackTracking.find(sequenceNumber);
    if (it == m_sackTracking.end()) {
        it = m_sackTracking.emplace(sequenceNumber, SackTrackingState{}).first;
    }
    return &it->second;
}

/** @brief Determines whether a SACK-reported hole should trigger a fast retransmission.
 *  Checks reorder grace period, FEC pending status, missing ACK count, and distance
 *  past the hole.  Only active when EnableAggressiveSackRecovery is configured.
 *  @param segment             The outbound segment potentially needing retransmit.
 *  @param firstMissingSequence  The first sequence number after the cumulative ACK not yet received.
 *  @param highestSack           The highest sequence covered by any SACK block.
 *  @param reportedSackHole      True if this segment is a SACK-reported hole (higher SACK exists).
 *  @param nowMicros             Current microsecond timestamp.
 *  @return True if fast retransmit should be triggered for this segment. */
bool UcpPcb::ShouldFastRetransmitSackHole(OutboundSegment& segment, uint32_t firstMissingSequence, uint32_t highestSack,
                                          bool reportedSackHole, int64_t nowMicros) noexcept {
    if (0 >= segment.LastSendMicros) {
        return false;
    }
    if (m_sackFastRetransmitNotified.find(segment.SequenceNumber) != m_sackFastRetransmitNotified.end()) {
        return false;
    }
    if (!m_config.EnableAggressiveSackRecovery) {
        return false;
    }

    int64_t reorderGraceMicros = GetSackFastRetransmitReorderGraceMicros();
    if (nowMicros - segment.LastSendMicros < reorderGraceMicros) {
        return false;
    }
    if (HasPendingFecRepair(segment, nowMicros)) {
        return false;
    }

    bool firstMissing = segment.SequenceNumber == firstMissingSequence;
    int requiredObservations = firstMissing ? PcbConst::SACK_FAST_RETRANSMIT_THRESHOLD : PcbConst::SACK_FAST_RETRANSMIT_THRESHOLD + 1;

    uint32_t distancePastHole =
        UcpSequenceComparer::IsBefore(segment.SequenceNumber, highestSack) ? (highestSack - segment.SequenceNumber) : 0;

    if (!firstMissing && reportedSackHole &&
        distancePastHole >= (uint32_t)(std::max)(PcbConst::SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD, m_config.FecGroupSize)) {
        requiredObservations = PcbConst::SACK_FAST_RETRANSMIT_THRESHOLD;
    }

    auto stIt = m_sackTracking.find(segment.SequenceNumber);
    int missingAckCount = stIt != m_sackTracking.end() ? stIt->second.MissingAckCount : 0;
    if (missingAckCount < requiredObservations) {
        return false;
    }
    if (firstMissing) {
        return true;
    }
    if (!reportedSackHole) {
        return false;
    }
    if (distancePastHole >= (uint32_t)PcbConst::SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD) {
        return true;
    }
    return false;
}

/** @brief Checks whether a FEC repair packet has been sent for the segment's group
 *  and the repair grace period has not yet expired (so fast retransmit is deferred).
 *  @param segment  The segment to check.
 *  @param nowMicros  Current microsecond timestamp.
 *  @return True if FEC recovery is still pending for this segment. */
bool UcpPcb::HasPendingFecRepair(OutboundSegment& segment, int64_t nowMicros) noexcept {
    if (!m_fecCodec) {
        return false;
    }
    auto stIt = m_sackTracking.find(segment.SequenceNumber);
    if (stIt == m_sackTracking.end() || 0 >= stIt->second.FirstMissingAckMicros) {
        return false;
    }

    uint32_t groupBase = m_fecCodec->GetGroupBase(segment.SequenceNumber);
    {
        std::lock_guard<std::mutex> fecLock(m_fecRepairGroupsMutex);
        if (m_fecRepairSentGroups.find(groupBase) == m_fecRepairSentGroups.end()) {
            return false;
        }
    }

    int64_t graceMicros = GetFecFastRetransmitGraceMicros();
    return nowMicros - stIt->second.FirstMissingAckMicros < graceMicros;
}

/** @brief Computes the grace period to wait for FEC repair before allowing SACK fast retransmit.
 *  Grace period is adaptively based on smoothed RTT, with configurable minimum and maximum bounds.
 *  @return Grace period in microseconds. */
int64_t UcpPcb::GetFecFastRetransmitGraceMicros() noexcept {
    int64_t rttMicros =
        m_rtoEstimator->SmoothedRttMicros() > 0 ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros.load(std::memory_order_acquire);
    if (0 >= rttMicros) {
        rttMicros = m_config.MinRtoMicros;
    }
    if (0 >= rttMicros) {
        return PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS;
    }

    int64_t adaptiveGrace = rttMicros / 16;
    int64_t maxGrace = PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS * 4;
    return (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, (std::min)(adaptiveGrace, maxGrace));
}

/** @brief Returns the minimum grace period before SACK-based fast retransmit triggers,
 *  computed as the larger of the minimum constant and the current RTT.
 *  Prevents spurious retransmissions due to packet reordering.
 *  @return Grace period in microseconds. */
int64_t UcpPcb::GetSackFastRetransmitReorderGraceMicros() noexcept {
    int64_t rttMicros =
        m_rtoEstimator->SmoothedRttMicros() > 0 ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros.load(std::memory_order_acquire);
    if (0 >= rttMicros) {
        int64_t fallback = 0 < m_config.MinRtoMicros ? m_config.MinRtoMicros : Constants::DEFAULT_RTO_MICROS;
        return (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, fallback * 2);
    }
    return (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros);
}

/** @brief Returns the minimum segment age required before a duplicate-ACK-based fast retransmit
 *  can be triggered.  Based on smoothed RTT with a safety floor.
 *  @return Age threshold in microseconds (0 means no threshold). */
int64_t UcpPcb::GetFastRetransmitAgeThreshold() noexcept {
    int64_t rttMicros =
        m_rtoEstimator->SmoothedRttMicros() > 0 ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros.load(std::memory_order_acquire);
    return 0 >= rttMicros ? 0 : (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros / 8);
}

/** @brief Checks whether early retransmit should trigger based on low inflight segment count.
 *  When few segments are in flight, fast recovery is triggered more aggressively.
 *  @return True if the inflight count is below the EarlyRetransmit max threshold. */
bool UcpPcb::ShouldTriggerEarlyRetransmit() noexcept {
    int maxPayload = (std::max)(1, m_config.MaxPayloadSize());
    if (0 >= maxPayload) {
        return false;
    }
    int inflightSegments = (int)std::ceil((double)m_flightBytes.load(std::memory_order_acquire) / (double)maxPayload);
    return 0 < inflightSegments && inflightSegments <= PcbConst::EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS;
}

/** @brief Determines whether a retransmit request (from NAK or SACK) should be honoured.
 *  For segments sent more than once, requires a minimum grace period based on smoothed RTT
 *  to prevent duplicate retransmission storms.
 *  @param segment    The segment requested for retransmission.
 *  @param nowMicros  Current microsecond timestamp.
 *  @return True if the retransmit request should be accepted. */
bool UcpPcb::ShouldAcceptRetransmitRequest(OutboundSegment& segment, int64_t nowMicros) noexcept {
    if (1 >= segment.SendCount || 0 >= segment.LastSendMicros) {
        return true;
    }
    int64_t graceMicros =
        m_rtoEstimator->SmoothedRttMicros() > 0 ? m_rtoEstimator->SmoothedRttMicros() : m_rtoEstimator->CurrentRtoMicros();
    if (0 >= graceMicros) {
        return true;
    }
    return nowMicros - segment.LastSendMicros >= graceMicros;
}

/** @brief Calculates the ratio of retransmitted packets to total sent packets.
 *  Used by UCP loss control to assess the path loss rate.
 *  @return Ratio in range [0.0, 1.0] (0.0 if no packets have been sent). */
double UcpPcb::GetRetransmissionRatio() noexcept {
    int total = m_sentDataPackets + m_retransmittedPackets;
    return 0 == total ? 0.0 : (double)m_retransmittedPackets / (double)total;
}

/** @brief Logs a debug message to stderr if debug logging is enabled in the configuration.
 *  @param message  The message string to log. */
void UcpPcb::TraceLog(const ucp::string& message) noexcept {
    if (m_config.EnableDebugLog) {
        std::cerr << "[UCP PCB] " << message << std::endl;
    }
}

/** @brief Convenience overload: checks if a single sequence loss event indicates congestion.
 *  Delegates to ClassifyLosses with a single-element sequence list.
 *  @param sequenceNumber      The lost sequence number.
 *  @param sampleRttMicros     RTT sample (may be 0 if unavailable).
 *  @param nowMicros           Current microsecond timestamp.
 *  @param contiguousLossCount Number of consecutive losses in this burst.
 *  @return True if the loss pattern suggests congestion rather than random loss. */
bool UcpPcb::IsCongestionLoss(uint32_t sequenceNumber, int64_t sampleRttMicros, int64_t nowMicros, int contiguousLossCount) noexcept {
    ucp::vector<uint32_t> sequences = {sequenceNumber};
    return ClassifyLosses(sequences, nowMicros, sampleRttMicros, contiguousLossCount);
}

/** @brief Classifies a set of lost sequences as congestion or random loss.
 *  Delegates to the full overload with automatic contiguous loss run computation.
 *  @param sequenceNumbers  Lost sequence numbers.
 *  @param nowMicros        Current microsecond timestamp.
 *  @param sampleRttMicros  RTT sample (may be 0 if unavailable).
 *  @return True if the loss pattern suggests congestion. */
bool UcpPcb::ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers, int64_t nowMicros, int64_t sampleRttMicros) noexcept {
    return ClassifyLosses(sequenceNumbers, nowMicros, sampleRttMicros, GetMaxContiguousLossRun(sequenceNumbers));
}

/** @brief Full loss classification: uses a time-windowed loss event history, median RTT,
 *  and contiguous burst analysis to distinguish congestion loss from random/cosmetic loss.
 *  Congestion is indicated when: loss events exceed random max thresholds, contiguous bursts
 *  exceed a threshold, and median RTT is significantly above the minimum observed RTT.
 *  @param sequenceNumbers     Sequence numbers involved in this loss event.
 *  @param nowMicros           Current microsecond timestamp.
 *  @param sampleRttMicros     RTT sample for this event (may be 0).
 *  @param contiguousLossCount  Number of consecutive lost sequences in this burst.
 *  @return True if the loss is classified as congestion. */
bool UcpPcb::ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers, int64_t nowMicros, int64_t sampleRttMicros,
                            int contiguousLossCount) noexcept {
    int64_t windowMicros = GetLossClassifierWindowMicros();

    int dedupedLossCount = 0;
    int maxContiguous = 0;
    int64_t medianRtt = 0;
    {
        std::lock_guard<std::mutex> lock(m_lossMutex);
        PruneLossEvents(nowMicros, windowMicros);

        int64_t rttMicros = 0 < sampleRttMicros ? sampleRttMicros : m_lastRttMicros.load(std::memory_order_acquire);
        bool addedLoss = false;
        for (uint32_t seq : sequenceNumbers) {
            if (m_recentLossSequences.insert(seq).second) {
                LossEvent ev;
                ev.SequenceNumber = seq;
                ev.TimestampMicros = nowMicros;
                ev.RttMicros = rttMicros;
                m_recentLossEvents.push(ev);
                addedLoss = true;
            }
        }
        if (addedLoss) {
            PruneLossEvents(nowMicros, windowMicros);
        }

        dedupedLossCount = (int)m_recentLossEvents.size();
        maxContiguous = GetMaxContiguousRecentLossRun();
        medianRtt = GetLossWindowMedianRttMicros();
    }
    if (0 == dedupedLossCount) {
        return false;
    }

    int maxContiguousLossCount = (std::max)(contiguousLossCount, maxContiguous);
    if (dedupedLossCount <= (int)PcbConst::UCP_RANDOM_LOSS_MAX_DEDUPED_EVENTS &&
        maxContiguousLossCount < PcbConst::UCP_CONGESTION_LOSS_BURST_THRESHOLD) {
        return false;
    }

    bool clusteredLoss = maxContiguousLossCount >= PcbConst::UCP_CONGESTION_LOSS_BURST_THRESHOLD ||
                         dedupedLossCount > PcbConst::UCP_CONGESTION_LOSS_WINDOW_THRESHOLD;
    if (!clusteredLoss) {
        return false;
    }

    int64_t minRtt = GetMinimumObservedRttMicros();
    if (0 >= medianRtt || 0 >= minRtt) {
        return false;
    }
    return medianRtt > (int64_t)((double)minRtt * PcbConst::UCP_CONGESTION_LOSS_RTT_MULTIPLIER);
}

/** @brief Returns the width of the sliding time window for loss event classification.
 *  Based on twice the minimum observed RTT, with a floor of 1 millisecond.
 *  @return Window duration in microseconds. */
int64_t UcpPcb::GetLossClassifierWindowMicros() noexcept {
    int64_t minRtt = GetMinimumObservedRttMicros();
    if (0 >= minRtt) {
        minRtt = m_rtoEstimator->SmoothedRttMicros() > 0 ? m_rtoEstimator->SmoothedRttMicros() : m_config.MinRtoMicros;
    }
    return (std::max)(Constants::MICROS_PER_MILLI, minRtt * 2);
}

/** @brief Removes loss events that are older than the classification window from the tracking queue.
 *  Keeps the loss event history bounded and prevents stale events from influencing classification.
 *  @param nowMicros    Current microsecond timestamp.
 *  @param windowMicros The maximum age of events to retain. */
void UcpPcb::PruneLossEvents(int64_t nowMicros, int64_t windowMicros) noexcept {
    while (!m_recentLossEvents.empty() && nowMicros - m_recentLossEvents.front().TimestampMicros > windowMicros) {
        m_recentLossSequences.erase(m_recentLossEvents.front().SequenceNumber);
        m_recentLossEvents.pop();
    }
}

/** @brief Computes the median RTT of all loss events currently in the recent-loss window.
 *  Used for congestion classification (elevated median RTT suggests queue buildup).
 *  @return Median RTT in microseconds, or 0 if no samples are available. */
int64_t UcpPcb::GetLossWindowMedianRttMicros() noexcept {
    ucp::vector<int64_t> samples;
    ucp::queue<LossEvent> copy = m_recentLossEvents;
    while (!copy.empty()) {
        auto& ev = copy.front();
        if (0 < ev.RttMicros) {
            samples.push_back(ev.RttMicros);
        }
        copy.pop();
    }
    if (samples.empty() && 0 < m_lastRttMicros.load(std::memory_order_acquire)) {
        samples.push_back(m_lastRttMicros.load(std::memory_order_acquire));
    }
    if (samples.empty()) {
        return 0;
    }

    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

/** @brief Returns the minimum RTT observed across all stored RTT samples.
 *  Used as the baseline propagation delay for congestion classification.
 *  @return Minimum RTT in microseconds, falling back to last RTT if no samples exist. */
int64_t UcpPcb::GetMinimumObservedRttMicros() noexcept {
    int64_t minRtt = 0;
    {
        std::lock_guard<std::mutex> lock(m_rttMutex);
        for (int64_t sample : m_rttSamplesMicros) {
            if (0 < sample && (0 == minRtt || sample < minRtt)) {
                minRtt = sample;
            }
        }
    }
    if (0 == minRtt && 0 < m_lastRttMicros.load(std::memory_order_acquire)) {
        minRtt = m_lastRttMicros.load(std::memory_order_acquire);
    }
    return minRtt;
}

/** @brief Finds the longest run of contiguous sequence numbers in the recent loss event queue.
 *  Used by congestion classification to distinguish burst losses from isolated drops.
 *  @return The length of the longest contiguous loss run (0 if no events). */
int UcpPcb::GetMaxContiguousRecentLossRun() noexcept {
    if (m_recentLossEvents.empty()) {
        return 0;
    }
    ucp::vector<uint32_t> seqs;
    ucp::queue<LossEvent> copy = m_recentLossEvents;
    while (!copy.empty()) {
        seqs.push_back(copy.front().SequenceNumber);
        copy.pop();
    }
    return GetMaxContiguousLossRun(seqs);
}

/** @brief Computes the longest run of consecutive sequence numbers in the given set.
 *  Sorts the input and counts runs where adjacent values differ by exactly 1.
 *  @param sequenceNumbers  The set of sequence numbers to analyse (may contain duplicates).
 *  @return The maximum contiguous run length (1 minimum if input is non-empty). */
int UcpPcb::GetMaxContiguousLossRun(const ucp::vector<uint32_t>& sequenceNumbers) noexcept {
    if (sequenceNumbers.empty()) {
        return 0;
    }
    ucp::vector<uint32_t> sorted = sequenceNumbers;
    std::sort(sorted.begin(), sorted.end());
    int maxRun = 1;
    int currentRun = 1;
    for (size_t i = 1; i < sorted.size(); i++) {
        if (sorted[i] == sorted[i - 1]) {
            continue;
        }
        if (sorted[i] - sorted[i - 1] == 1U) {
            currentRun++;
            if (currentRun > maxRun) {
                maxRun = currentRun;
            }
        } else {
            currentRun = 1;
        }
    }
    return maxRun;
}

/** @brief Computes the effective send window as the minimum of the remote receive window
 *  and the UCP congestion window.  This bounds the amount of data that can be in flight.
 *  @return Available send window in bytes (never negative). */
int UcpPcb::GetSendWindowBytes() noexcept {
    int receiveWindowBytes =
        static_cast<int>(std::min<uint32_t>(m_remoteWindowBytes.load(std::memory_order_acquire), static_cast<uint32_t>(INT_MAX)));
    int congestionWindowBytes = m_congestion
                                    ? static_cast<int>(std::min(m_congestion->GetCongestionWindowBytes(), static_cast<int64_t>(INT_MAX)))
                                    : m_config.InitialCongestionWindowBytes();
    int windowBytes;
    if (m_congestion && m_congestion->GetMode() == UcpMode::Startup && !m_congestion->IsFullBwReached()) {
        windowBytes = receiveWindowBytes;
    } else {
        windowBytes = congestionWindowBytes < receiveWindowBytes ? congestionWindowBytes : receiveWindowBytes;
    }
    if (0 > windowBytes) {
        windowBytes = 0;
    }
    return windowBytes;
}

/** @brief Checks whether urgent retransmit recovery is allowed this RTT window.
 *  Limits the number of urgent recovery packets per RTT to avoid congestion.
 *  @param nowMicros  Current microsecond timestamp.
 *  @return True if the urgent recovery budget is not yet exhausted this RTT. */
bool UcpPcb::CanUseUrgentRecovery(int64_t nowMicros) noexcept {
    int64_t windowMicros = m_rtoEstimator->SmoothedRttMicros() > 0 ? m_rtoEstimator->SmoothedRttMicros() : m_config.MinRtoMicros;
    if (0 >= windowMicros) {
        windowMicros = Constants::DEFAULT_RTO_MICROS;
    }

    if (0 == m_urgentRecoveryWindowMicros || nowMicros - m_urgentRecoveryWindowMicros >= windowMicros) {
        m_urgentRecoveryWindowMicros = nowMicros;
        m_urgentRecoveryPacketsInWindow = 0;
    }
    return m_urgentRecoveryPacketsInWindow < PcbConst::URGENT_RETRANSMIT_BUDGET_PER_RTT;
}

/** @brief Checks whether the connection is approaching the disconnect timeout.
 *  Used to prioritise retransmission urgency when the peer may be about to drop the connection.
 *  @param nowMicros  Current microsecond timestamp.
 *  @return True if idle time exceeds the disconnect threshold percentage. */
bool UcpPcb::IsNearDisconnectTimeout(int64_t nowMicros) noexcept {
    if (0 >= m_config.DisconnectTimeoutMicros) {
        return false;
    }
    int64_t idleMicros = nowMicros - m_lastPeerAliveMicros.load(std::memory_order_acquire);
    return idleMicros >= m_config.DisconnectTimeoutMicros * (int64_t)PcbConst::URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT / 100LL;
}

/** @brief Returns the total bytes currently occupied in the receive buffer (queued + stored).
 *  Used to compute the available receive window to advertise to the peer.
 *  @return Used receive buffer bytes, capped at UINT32_MAX.
 *  Precondition: caller must hold m_recvBufMutex. */
uint32_t UcpPcb::GetReceiveWindowUsedBytes() noexcept {
    int64_t usedBytes = (int64_t)m_queuedReceiveBytes.load(std::memory_order_relaxed) + m_recvBufferBytes.load(std::memory_order_relaxed);
    if (0 >= usedBytes) {
        return 0;
    }
    if (usedBytes >= (int64_t)UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)usedBytes;
}

/** @brief Records an RTT sample into the sliding window of samples, dropping the oldest
 *  sample when the window exceeds MAX_RTT_SAMPLES.
 *  @param sampleRttMicros  The RTT measurement in microseconds (must be positive). */
void UcpPcb::AddRttSample(int64_t sampleRttMicros) noexcept {
    if (0 >= sampleRttMicros) {
        return;
    }
    std::lock_guard<std::mutex> rttLock(m_rttMutex);
    m_rttSamplesMicros.push_back(sampleRttMicros);
    if ((int)m_rttSamplesMicros.size() > PcbConst::MAX_RTT_SAMPLES) {
        int excess = (int)m_rttSamplesMicros.size() - PcbConst::MAX_RTT_SAMPLES;
        m_rttSamplesMicros.erase(m_rttSamplesMicros.begin(), m_rttSamplesMicros.begin() + excess);
    }
}

/** @brief Clears the SACK block send count tracking when it exceeds a threshold (1024 entries).
 *  Prevents unbounded memory growth in the SACK send-count map. */
void UcpPcb::PurgeSackSendCounts() noexcept {
    std::lock_guard<std::mutex> sackLock(m_sackExtraMutex);
    if (m_sackBlockSendCounts.size() > 1024) {
        m_sackBlockSendCounts.clear();
    }
}

/** @brief Packs a SACK block start/end pair into a single 64-bit key for deduplication tracking.
 *  @param start  Start sequence number of the SACK block.
 *  @param end    End sequence number of the SACK block.
 *  @return Packed 64-bit key with start in the upper 32 bits and end in the lower 32 bits. */
uint64_t UcpPcb::PackSackBlockKey(uint32_t start, uint32_t end) noexcept {
    return ((uint64_t)start << 32) | end;
}

/** @brief Finds the highest end sequence number across a list of SACK blocks.
 *  Used to determine the farthest point of received data for hole detection.
 *  @param blocks  List of SACK blocks to scan.
 *  @return The maximum End value (0 if list is empty). */
uint32_t UcpPcb::GetHighestSackEnd(const ucp::vector<SackBlock>& blocks) noexcept {
    uint32_t highest = 0;
    bool hasValue = false;
    for (auto& block : blocks) {
        if (!hasValue || UcpSequenceComparer::IsAfter(block.End, highest)) {
            highest = block.End;
            hasValue = true;
        }
    }
    return highest;
}

/** @brief Sorts a list of SACK blocks by their Start sequence numbers in ascending order.
 *  Required for efficient SACK-based hole detection algorithms.
 *  @param blocks  Input SACK blocks (unsorted).
 *  @param[out] sorted  Output vector receiving the sorted blocks. */
void UcpPcb::SortSackBlocks(const ucp::vector<SackBlock>& blocks, ucp::vector<SackBlock>& sorted) noexcept {
    sorted = blocks;
    if (sorted.size() <= 1) {
        return;
    }
    // SACK blocks arrive in encoding order (usually already sorted); only sort
    // when they are actually out of order.
    bool alreadyOrdered = true;
    for (size_t i = 1; i < sorted.size(); ++i) {
        if (!UcpSequenceComparer::IsBefore(sorted[i - 1].Start, sorted[i].Start)) {
            alreadyOrdered = false;
            break;
        }
    }
    if (!alreadyOrdered) {
        std::sort(sorted.begin(), sorted.end(),
                  [](const SackBlock& a, const SackBlock& b) noexcept { return UcpSequenceComparer::IsBefore(a.Start, b.Start); });
    }
}

/** @brief Determines whether a given sequence number is a SACK-reported "hole" -- data that
 *  is between a lower cumulative ACK point and a higher SACK block, implying it was lost or
 *  reordered.  A sequence covered by a SACK block is not a hole.
 *  @param sequenceNumber      The sequence number to check.
 *  @param cumulativeAckNumber The cumulative ACK point from the packet.
 *  @param sackBlocks          The SACK blocks from the packet.
 *  @return True if the sequence is a reported hole (missing with higher SACK). */
bool UcpPcb::IsReportedSackHole(uint32_t sequenceNumber, uint32_t cumulativeAckNumber, const ucp::vector<SackBlock>& sackBlocks) noexcept {
    if (sackBlocks.empty()) {
        return false;
    }
    bool hasLowerAck = UcpSequenceComparer::IsBeforeOrEqual(cumulativeAckNumber, sequenceNumber);
    bool hasHigherSack = false;
    for (auto& block : sackBlocks) {
        if (UcpSequenceComparer::IsInForwardRange(sequenceNumber, block.Start, block.End)) {
            return false;
        }
        if (UcpSequenceComparer::IsBefore(block.End, sequenceNumber)) {
            hasLowerAck = true;
            continue;
        }
        if (UcpSequenceComparer::IsAfter(block.Start, sequenceNumber)) {
            hasHigherSack = true;
            break;
        }
    }
    return hasLowerAck && hasHigherSack;
}

/** @brief Checks whether the reorder grace period for a NAK has expired.
 *  Uses adaptive grace based on RTT, with shorter grace for high-confidence misses.
 *  Prevents spurious NAKs due to simple packet reordering.
 *  @param missingCount    How many times this sequence has been observed as missing.
 *  @param firstSeenMicros  First time the gap was detected.
 *  @param nowMicros        Current microsecond timestamp.
 *  @return True if the grace period has elapsed and a NAK should be issued. */
bool UcpPcb::HasNakReorderGraceExpired(int missingCount, int64_t firstSeenMicros, int64_t nowMicros) noexcept {
    int64_t baseGraceMicros = GetAdaptiveNakReorderGraceMicros();
    int64_t graceMicros = missingCount >= PcbConst::NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD
                              ? (std::max)(baseGraceMicros / 2, PcbConst::NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS)
                          : missingCount >= PcbConst::NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD
                              ? (std::max)(baseGraceMicros / 2, PcbConst::NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS)
                              : baseGraceMicros;
    return nowMicros - firstSeenMicros >= graceMicros;
}

/** @brief Computes an adaptive NAK reorder grace period based on RTT, capped by MinRto.
 *  Allows NAK generation to adapt to the path's actual reordering characteristics.
 *  @return Grace period in microseconds (never below NAK_REORDER_GRACE_MICROS minimum). */
int64_t UcpPcb::GetAdaptiveNakReorderGraceMicros() noexcept {
    int64_t rttMicros =
        m_rtoEstimator->SmoothedRttMicros() > 0 ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros.load(std::memory_order_acquire);
    if (0 >= rttMicros) {
        rttMicros = m_config.MinRtoMicros;
    }
    if (0 >= rttMicros) {
        return PcbConst::NAK_REORDER_GRACE_MICROS;
    }
    return (std::max)(PcbConst::NAK_REORDER_GRACE_MICROS, (std::min)(rttMicros / 2, m_config.MinRtoMicros));
}

/** @brief Records that a NAK has been issued for a specific sequence number.
 *  Prevents duplicate NAKs for the same gap within the same detection window.
 *  Caller must hold m_nakMutex.
 *  @param sequenceNumber  The sequence number for which a NAK was sent. */
void UcpPcb::MarkNakIssued(uint32_t sequenceNumber) noexcept {
    m_nakIssued.insert(sequenceNumber);
    m_lastNakIssuedMicros[sequenceNumber] = NowMicros();
}

/** @brief Gets or initialises the first-seen timestamp for a missing sequence number.
 *  Used to calculate how long a gap has been present for NAK reorder grace decisions.
 *  Caller must hold m_nakMutex.
 *  @param sequenceNumber  The sequence number that appears to be missing.
 *  @return The timestamp (micros) when this gap was first detected. */
int64_t UcpPcb::GetMissingFirstSeenMicros(uint32_t sequenceNumber) noexcept {
    auto it = m_missingFirstSeenMicros.find(sequenceNumber);
    if (it == m_missingFirstSeenMicros.end()) {
        int64_t now = NowMicros();
        m_missingFirstSeenMicros[sequenceNumber] = now;
        return now;
    }
    return it->second;
}

/** @brief Checks whether a NAK should be issued for the given sequence number.
 *  Returns false if a NAK was already issued for this gap.
 *  Caller must hold m_nakMutex.
 *  @param sequenceNumber  The sequence number to check.
 *  @return True if no NAK has been sent for this sequence yet. */
bool UcpPcb::ShouldIssueNak(uint32_t sequenceNumber) noexcept {
    return m_nakIssued.find(sequenceNumber) == m_nakIssued.end();
}

/** @brief Scans the receive buffer for missing sequences between nextExpected and highest received,
 *  appending eligible gaps to the missing vector for NAK generation.
 *  Rate-limited and grace-period protected to avoid NAK storms.
 *  @param[out] missing  Vector to receive sequence numbers that should be NAKed.
 *  @param nowMicros     Current microsecond timestamp. */
void UcpPcb::CollectMissingForNak(ucp::vector<uint32_t>& missing, int64_t nowMicros) noexcept {
    std::lock_guard<std::mutex> nakLock(m_nakMutex);
    if (m_recvBuffer.empty() || m_recvBuffer.find(m_nextExpectedSequence.load(std::memory_order_relaxed)) != m_recvBuffer.end()) {
        return;
    }

    uint32_t highestReceived = m_nextExpectedSequence.load(std::memory_order_relaxed);
    bool hasHighest = false;
    for (auto& pair : m_recvBuffer) {
        if (!hasHighest || UcpSequenceComparer::IsAfter(pair.first, highestReceived)) {
            highestReceived = pair.first;
            hasHighest = true;
        }
    }
    if (!hasHighest) {
        return;
    }

    uint32_t current = m_nextExpectedSequence.load(std::memory_order_relaxed);
    int remainingScan = PcbConst::MAX_NAK_MISSING_SCAN;
    while ((int)missing.size() < PcbConst::MAX_NAK_SEQUENCES_PER_PACKET && current != highestReceived && 0 < remainingScan) {
        if (m_recvBuffer.find(current) == m_recvBuffer.end()) {
            int64_t firstSeenMicros = GetMissingFirstSeenMicros(current);
            int& missingCount = m_missingSequenceCounts[current];
            missingCount++;

            if (missingCount >= PcbConst::NAK_MISSING_THRESHOLD && HasNakReorderGraceExpired(missingCount, firstSeenMicros, nowMicros) &&
                ShouldIssueNak(current)) {
                MarkNakIssued(current);
                missing.push_back(current);
            }
        }
        current = UcpSequenceComparer::Increment(current);
        remainingScan--;
    }
}

/** @brief Rate-limits immediate ACK transmission for reordered packets.
 *  Prevents ACK floods when the path reorders packets by enforcing a minimum interval.
 *  @param nowMicros  Current microsecond timestamp.
 *  @return True if an immediate ACK should be sent now. */
bool UcpPcb::ShouldSendImmediateReorderedAck(int64_t nowMicros) noexcept {
    if (0 == m_lastReorderedAckSentMicros || nowMicros - m_lastReorderedAckSentMicros >= PcbConst::REORDERED_ACK_MIN_INTERVAL_MICROS) {
        m_lastReorderedAckSentMicros = nowMicros;
        return true;
    }
    return false;
}

/** @brief Attempts FEC recovery of other packets in the same FEC group as the received packet.
 *  Iterates other group members and tries to recover them from stored repair symbols.
 *  @param receivedSequenceNumber  A sequence number whose FEC group should be checked for recovery.
 *  @param[out] readyPayloads  Vector to receive any successfully recovered payloads. */
void UcpPcb::TryRecoverFecAround(uint32_t receivedSequenceNumber, ucp::vector<ucp::vector<uint8_t>>& readyPayloads) noexcept {
    if (!m_fecCodec) {
        return;
    }

    int64_t nowMicros = NowMicros();
    int64_t recoveredBytes = 0;

    uint32_t groupBase = m_fecCodec->GetGroupBase(receivedSequenceNumber);
    int groupSize = (std::max)(2, m_config.FecGroupSize);
    for (int i = 0; i < groupSize; i++) {
        uint32_t candidateSeq = groupBase + (uint32_t)i;
        if (candidateSeq == receivedSequenceNumber ||
            UcpSequenceComparer::IsBefore(candidateSeq, m_nextExpectedSequence.load(std::memory_order_relaxed)) ||
            m_recvBuffer.find(candidateSeq) != m_recvBuffer.end()) {
            continue;
        }

        ucp::vector<UcpFecCodec::RecoveredPacket> recoveredPackets = m_fecCodec->TryRecoverPacketsFromStoredRepair(candidateSeq);
        if (recoveredPackets.empty()) {
            continue;
        }

        int stored = 0;
        for (auto& rp : recoveredPackets) {
            int64_t rpSize = static_cast<int64_t>(rp.payload.size());
            if (StoreRecoveredFecSegment(rp.sequence_number, std::move(rp.payload))) {
                stored++;
                recoveredBytes += rpSize;
            }
        }
        if (0 < stored) {
            DrainReadyPayloads(readyPayloads);
            if (m_congestion && recoveredBytes > 0) {
                // Caller (HandleData) already holds m_sync; taking it again here
                // would self-deadlock (non-recursive mutex).  No extra lock.
                m_congestion->OnFecRecovery(nowMicros, recoveredBytes);
            }
            return;
        }
    }
}

/** @brief Stores a batch of FEC-recovered packets into the receive buffer.
 *  @param recoveredPackets  Pointer to vector of (sequence, payload) pairs from FEC recovery.
 *  @param[out] readyPayloads  Vector to receive any newly in-order payloads after insertion.
 *  @return Number of packets successfully stored. */
int UcpPcb::StoreRecoveredFecPackets(const ucp::vector<ucp::pair<uint32_t, ucp::vector<uint8_t>>>* recoveredPackets,
                                     ucp::vector<ucp::vector<uint8_t>>& readyPayloads) noexcept {
    if (!recoveredPackets || recoveredPackets->empty()) {
        return 0;
    }

    int stored = 0;
    for (auto& rp : *recoveredPackets) {
        if (StoreRecoveredFecSegment(rp.first, rp.second)) {
            stored++;
        }
    }
    if (0 < stored) {
        DrainReadyPayloads(readyPayloads);
    }
    return stored;
}

/** @brief Stores a single FEC-recovered segment into the receive buffer.
 *  Skips segments that have already been received or are below the expected sequence.
 *  @param recoveredSeq  Sequence number of the recovered packet.
 *  @param recovered     Recovered payload bytes.
 *  @return True if the segment was stored, false if it was already present or stale. */
bool UcpPcb::StoreRecoveredFecSegment(uint32_t recoveredSeq, ucp::vector<uint8_t> recovered) noexcept {
    if (recovered.empty() || UcpSequenceComparer::IsBefore(recoveredSeq, m_nextExpectedSequence.load(std::memory_order_relaxed)) ||
        m_recvBuffer.find(recoveredSeq) != m_recvBuffer.end()) {
        return false;
    }

    FecFragmentMetadata metadata{1, 0};
    auto metaIt = m_fecFragmentMetadata.find(recoveredSeq);
    if (metaIt != m_fecFragmentMetadata.end()) {
        metadata = metaIt->second;
    }

    InboundSegment inbound;
    inbound.SequenceNumber = recoveredSeq;
    inbound.FragmentTotal = metadata.FragmentTotal;
    inbound.FragmentIndex = metadata.FragmentIndex;
    inbound.Payload = std::move(recovered);

    int64_t payloadSize = (int64_t)inbound.Payload.size();
    m_recvBuffer[recoveredSeq] = std::move(inbound);
    m_recvBufferBytes.store(m_recvBufferBytes.load(std::memory_order_relaxed) + payloadSize, std::memory_order_relaxed);
    ClearMissingReceiveState(recoveredSeq);
    return true;
}

/** @brief Drains in-order packets from the receive buffer into the ready-payloads vector.
 *  Starts from nextExpectedSequence and consumes consecutive entries, advancing
 *  the expected sequence for each drained packet.
 *  @param[out] readyPayloads  Vector receiving complete, in-order payloads. */
void UcpPcb::DrainReadyPayloads(ucp::vector<ucp::vector<uint8_t>>& readyPayloads) noexcept {
    while (!m_recvBuffer.empty()) {
        auto it = m_recvBuffer.find(m_nextExpectedSequence.load(std::memory_order_relaxed));
        if (it == m_recvBuffer.end()) {
            break;
        }

        ClearMissingReceiveState(m_nextExpectedSequence.load(std::memory_order_relaxed));
        m_recvBufferBytes.store(m_recvBufferBytes.load(std::memory_order_relaxed) - (int64_t)it->second.Payload.size(),
                                std::memory_order_relaxed);
        if (m_recvBufferBytes.load(std::memory_order_relaxed) < 0) {
            m_recvBufferBytes.store(0, std::memory_order_relaxed);
        }
        readyPayloads.push_back(std::move(it->second.Payload));
        m_recvBuffer.erase(it);
        m_nextExpectedSequence.store(UcpSequenceComparer::Increment(m_nextExpectedSequence.load(std::memory_order_relaxed)),
                                     std::memory_order_relaxed);
    }
}

/** @brief Clears all missing-sequence tracking state for a given sequence number.
 *  Removes NAK-issued flags, missing counts, first-seen timestamps, last-NAK timestamps,
 *  and FEC fragment metadata.  Called when a previously missing packet is received.
 *  @param sequenceNumber  The sequence number whose missing state should be cleared. */
void UcpPcb::ClearMissingReceiveState(uint32_t sequenceNumber) noexcept {
    {
        std::lock_guard<std::mutex> nakLock(m_nakMutex);
        m_nakIssued.erase(sequenceNumber);
        m_missingSequenceCounts.erase(sequenceNumber);
        m_missingFirstSeenMicros.erase(sequenceNumber);
        m_lastNakIssuedMicros.erase(sequenceNumber);
    }
    m_fecFragmentMetadata.erase(sequenceNumber);
}

/** @brief Sends a DPLPMTUD (Datagram Packetization Layer Path MTU Discovery) probe packet.
 *  Constructs a padded data packet to fill the candidate MTU, sets the MtuProbe flag,
 *  and transmits it through the transport.  The receiver's ACK confirms whether the
 *  probe size was successfully delivered, allowing the MTU estimation to converge.
 *  @param probeMtu  The candidate MTU size to probe, in bytes. */
void UcpPcb::SendMtuProbe(int probeMtu) {
    if (probeMtu <= PcbConst::MTU_PROBE_BASE || probeMtu > m_config.MtuProbeMax) {
        return;
    }
    UcpDataPacket packet;
    {
        std::lock_guard<std::mutex> rbufLock(m_recvBufMutex);
        m_mtuProbeSequenceNumber.store(m_nextSendSequence.load(std::memory_order_relaxed), std::memory_order_relaxed);
        m_nextSendSequence.store(UcpSequenceComparer::Increment(m_nextSendSequence.load(std::memory_order_relaxed)),
                                 std::memory_order_relaxed);
        packet.header = CreateHeader(UcpPacketType::Data,
                                     (int)(UcpPacketFlags::NeedAck) | (int)(UcpPacketFlags::HasAckNumber) | (int)(UcpPacketFlags::MtuProbe),
                                     NowMicros(), m_connectionId.load(std::memory_order_relaxed));
        packet.sequence_number = m_mtuProbeSequenceNumber.load(std::memory_order_relaxed);
        packet.fragment_total = 1;
        packet.fragment_index = 0;
        int payloadBytes = probeMtu - PcbConst::DATA_HEADER_SIZE_WITH_ACK;
        if (payloadBytes < 1) {
            return;
        }
        packet.payload.resize(payloadBytes, 0);
        packet.ack_number =
            0 < m_nextExpectedSequence.load(std::memory_order_relaxed) ? m_nextExpectedSequence.load(std::memory_order_relaxed) - 1U : 0;
        uint32_t usedBytes = GetReceiveWindowUsedBytes();
        packet.window_size = usedBytes >= m_localReceiveWindowBytes ? 0U : m_localReceiveWindowBytes - usedBytes;
        packet.echo_timestamp = m_lastEchoTimestamp.load(std::memory_order_relaxed);
        m_mtuProbePending.store(true, std::memory_order_relaxed);
        m_mtuProbeAcked.store(false, std::memory_order_relaxed);
        m_probeMtu.store(probeMtu, std::memory_order_relaxed);
    }
    ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(packet);
    m_sentDataPackets++;
    Endpoint remoteEndpoint;
    auto* trp = m_transport.load(std::memory_order_acquire);
    if (nullptr != trp && TryGetRemoteEndpoint(remoteEndpoint)) {
        trp->Send(encoded, remoteEndpoint);
    }
}

} // namespace ucp
