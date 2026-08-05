#pragma once

/**
 * MIT License
 *
 * Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file ucp_pcb.h
 *  @brief UCP Protocol Control Block -- the per-connection state machine. Mirrors C# Ucp.Internal.UcpPcb.
 *
 *  UcpPcb is the core of the UCP protocol engine.  Each PCB manages one
 *  connection's send buffer, receive reorder buffer, NAK gap tracking,
 *  SACK-based fast retransmit, RTO timer recovery, UCP congestion control,
 *  token-bucket pacing, fair-queue credit, and optional FEC encoding.
 *
 *  All async public methods use callback-based Proactor pattern.  A dedicated
 *  worker thread processes a serial work queue so that no std::async thread
 *  spawning or std::future blocking occurs.  Synchronous wrappers (Connect,
 *  Send, Receive, Read, Write, Close) enqueue work items and block the caller
 *  with a condition variable.
 */

#include "ucp/ucp_constants.h"
#include "ucp/ucp_enums.h"
#include "ucp/ucp_packets.h"
#include "ucp/ucp_sequence_comparer.h"
#include "ucp/ucp_time.h"
#include "ucp/ucp_rto_estimator.h"
#include "ucp/ucp_cc.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_network.h"
#include "ucp/ucp_types.h"
#include "ucp/transport/itransport.h"

#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"
#include <cstdint>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>

namespace ucp {

/**
 * @brief Protocol constant tunables used by the UCP PCB state machine.
 * @note These values control retransmission thresholds, NAK generation limits,
 *       UCP loss classification heuristics, FEC grace periods, and window sizes.
 */
namespace PcbConst {
constexpr int MAX_SACK_SEND_COUNT = 2;
constexpr int DUPLICATE_ACK_THRESHOLD = 3;
constexpr int NAK_MISSING_THRESHOLD = 2;
constexpr int MAX_NAK_MISSING_SCAN = 16384;
constexpr int MAX_NAK_SEQUENCES_PER_PACKET = Constants::MAX_NAK_SEQUENCES_PER_PACKET;
constexpr int MAX_NAKS_PER_RTT = 1024;
constexpr double UCP_RANDOM_LOSS_MAX_DEDUPED_EVENTS = 2.0;
constexpr int UCP_CONGESTION_LOSS_BURST_THRESHOLD = 3;
constexpr int UCP_CONGESTION_LOSS_WINDOW_THRESHOLD = 3;
constexpr double UCP_CONGESTION_LOSS_RTT_MULTIPLIER = 1.10;
constexpr int SACK_FAST_RETRANSMIT_THRESHOLD = 2;
constexpr int SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD = 48;
constexpr int64_t SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS = 5000;
constexpr int EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS = 4;
constexpr int TLP_MAX_INFLIGHT_SEGMENTS = 2;
constexpr double TLP_TIMEOUT_RTT_RATIO = 1.5;
constexpr int URGENT_RETRANSMIT_BUDGET_PER_RTT = 8192;
constexpr double URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT = 75.0;
constexpr int RTO_RETRANSMIT_BUDGET_PER_TICK = 4;
constexpr double RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER = 4.0;
constexpr int MIN_TIMER_WAIT_MILLISECONDS = 1;
constexpr int64_t MIN_HANDSHAKE_WAIT_MILLISECONDS = 100;
constexpr int64_t PAWS_TIMEOUT_MICROS = 60000000;
constexpr int CLOSE_WAIT_TIMEOUT_MILLISECONDS = 1000;
constexpr int64_t NAK_REORDER_GRACE_MICROS = 2000;
constexpr int NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD = 32;
constexpr int64_t NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS = 1000;
constexpr int NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD = 128;
constexpr int64_t NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS = 1000;
constexpr int64_t REORDERED_ACK_MIN_INTERVAL_MICROS = 250;
constexpr int IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD = 4;
constexpr double ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT = 2.0;
constexpr int64_t UCP_MIN_ROUND_DURATION_MICROS = 1000;
constexpr int DATA_HEADER_SIZE_WITH_ACK = 36;
constexpr int DATA_HEADER_SIZE = 20;
constexpr int MAX_RTT_SAMPLES = 1024;
constexpr int MEASURED_BW_SLOT_COUNT = 10;
constexpr int64_t MEASURED_BW_SLOT_MICROS = 200000;
constexpr int PATH_CHALLENGE_MAX_ATTEMPTS = 3;
constexpr int64_t PATH_CHALLENGE_RATE_LIMIT_MICROS = 5000000;
constexpr int64_t PATH_CHALLENGE_TIMEOUT_MICROS = 2000000;
constexpr uint32_t DEFAULT_RECEIVE_WINDOW_BYTES = 4096 * 1220;
constexpr int MAX_SEGMENTS_PER_FLUSH = 16;

constexpr int64_t ZERO_WINDOW_PROBE_INTERVAL_MICROS = 50000;

constexpr int64_t ZERO_WINDOW_PROBE_MIN_INTERVAL_MICROS = 5000;

constexpr int64_t CID_ROTATE_INTERVAL_MICROS = 60000000;

constexpr int64_t CID_RETIRE_AGE_MICROS = 120000000;

constexpr uint32_t CID_ROTATE_SEQUENCE_MARKER = 0xFFFFFFFF;

constexpr int MTU_PROBE_BASE = 1200;

constexpr int MTU_PROBE_MAX = 1500;

constexpr int64_t MTU_PROBE_INTERVAL_MICROS = 600000000;

constexpr int64_t MTU_PROBE_TIMEOUT_MICROS = 10000000;
} // namespace PcbConst

struct UcpCommonHeader;
class UcpPacket;
class UcpControlPacket;
class UcpDataPacket;
class UcpAckPacket;
class UcpNakPacket;
class UcpFecRepairPacket;
class UcpSackGenerator;
class UcpRtoEstimator;
class UcpFecCodec;
class PacingController;

/**
 * @brief Represents one outbound data segment queued in the send buffer.
 * @note Mirrors the C# `Ucp.Internal.OutboundSegment`. Each segment has a
 *       unique sequence number and tracks send state for ACK processing,
 *       retransmission decisions, and fair-queue credit accounting.
 */
class OutboundSegment {
  public:
    uint32_t SequenceNumber = 0;
    uint16_t FragmentTotal = 0;
    uint16_t FragmentIndex = 0;
    ucp::vector<uint8_t> Payload;
    bool InFlight = false;
    bool Acked = false;
    bool NeedsRetransmit = false;
    int SendCount = 0;
    int64_t LastSendMicros = 0;
    UcpPriority Priority = UcpPriority::Normal;
};

/**
 * @brief Per-sequence SACK hole tracking state for fast retransmit decisions.
 * @note Tracks how many SACK blocks have reported this sequence as missing,
 *       when the first observation occurred, and whether urgent action is needed.
 */
class SackTrackingState {
  public:
    int MissingAckCount = 0;
    int64_t FirstMissingAckMicros = 0;
    bool UrgentRetransmit = false;
};

/**
 * @brief Metadata associated with a single FEC-encoded data fragment.
 * @note Stored per-sequence-number so that recovered FEC segments can
 *       reconstruct the original fragment-total and fragment-index values.
 */
class FecFragmentMetadata {
  public:
    FecFragmentMetadata() noexcept : FragmentTotal(0), FragmentIndex(0) {}
    /** @brief Parameterized constructor.
     *  @param total  Total number of fragments.
     *  @param index  Zero-based fragment index. */
    FecFragmentMetadata(uint16_t total, uint16_t index) noexcept : FragmentTotal(total), FragmentIndex(index) {}
    uint16_t FragmentTotal = 0;
    uint16_t FragmentIndex = 0;
};

/**
 * @brief A single deduplicated loss event used by the UCP congestion / random-loss classifier.
 * @note Loss events are kept in a sliding window (m_recentLossEvents) and pruned by age.
 */
class LossEvent {
  public:
    uint32_t SequenceNumber = 0;
    int64_t TimestampMicros = 0;
    int64_t RttMicros = 0;
};

/**
 * @brief An inbound data segment stored in the reorder buffer waiting for delivery.
 * @note Inbound segments accumulate in m_recvBuffer until the next-expected sequence
 *       is received, at which point they are drained in order.
 */
class InboundSegment {
  public:
    uint32_t SequenceNumber = 0;
    uint16_t FragmentTotal = 0;
    uint16_t FragmentIndex = 0;
    ucp::vector<uint8_t> Payload;
};

/**
 * @brief A chunk of contiguous, in-order data delivered to the receive queue.
 * @note ReceiveChunk entries are consumed by the application via ReceiveAsync.
 *       Each chunk supports partial reads via the Offset/Count cursor.
 */
class ReceiveChunk {
  public:
    ucp::vector<uint8_t> Buffer;
    int Offset = 0;
    int Count = 0;
};

/**
 * @brief Custom less-than comparator for sequence numbers that handles wraparound.
 * @note Uses modulo-2^32 arithmetic: a sequence 'a' is before 'b' if (a - b) >= HALF_SEQUENCE_SPACE.
 *       This allows correct ordering of sequence numbers even when they wrap around 2^32.
 */
struct SeqCompare {
    /** @brief Compare two uint32_t sequence numbers with wraparound semantics.
     *  @param  a  Left sequence number.
     *  @param  b  Right sequence number.
     *  @return True if a is before b (older) in the 32-bit circular sequence space. */
    bool operator()(uint32_t a, uint32_t b) const noexcept {
        if (a == b) {
            return false;
        }
        uint32_t diff = a - b;
        return diff >= Constants::HALF_SEQUENCE_SPACE;
    }
};

using SequenceMap = ucp::map<uint32_t, OutboundSegment, SeqCompare>;

using RecvSequenceMap = ucp::map<uint32_t, InboundSegment, SeqCompare>;

/**
 * @brief Internal state tracking for a single pending ReceiveAsync operation.
 * @note Stored in m_pendingReceives when a ReceiveAsync work item finds no data.
 *       Satisfied by TrySatisfyPendingReceives when EnqueuePayload adds data.
 */
struct PendingReceiveOp {
    uint8_t* buffer;
    int offset;
    int count;
    ReceiveAsyncCallback callback;
};

/**
 * @brief UCP Protocol Control Block -- core per-connection protocol engine.
 * @note Manages the complete lifecycle of a UCP connection: handshake, data
 *       transfer with SACK/NAK loss detection, UCP congestion control, token-
 *       bucket pacing, fair-queue credit, FEC encoding/decoding, and graceful
 *       teardown.  All protocol work is serialized through a dedicated worker
 *       thread with a work queue.  Async public methods use callback-based
 *       Proactor pattern.
 */
class UcpPcb : public std::enable_shared_from_this<UcpPcb> {
  public:
    using ClosedCallback = ucp::function<void(UcpPcb*)>;

    using DataReceivedCallback = ucp::function<void(const uint8_t*, int, int)>;

    using ConnectedCallback = ucp::function<void()>;

    using DisconnectedCallback = ucp::function<void()>;

    /**
     * @brief Constructs a new UCP Protocol Control Block.
     * @param transport       The underlying network transport for sending raw packets.
     * @param isServerSide    True if this PCB was created in response to an incoming SYN (server role).
     * @param useFairQueue    True to enable fair-queue credit accounting for bandwidth distribution.
     * @param closedCallback  Callback invoked when the PCB is fully closed.
     * @param connectionId    Pre-assigned connection ID, or 0 for random generation.
     * @param config          Immutable UCP configuration reference.
     * @param network         Optional UcpNetwork for timer management; NULLPTR allows standalone operation.
     */
    UcpPcb(class transport::ITransport* transport, bool isServerSide, bool useFairQueue, ClosedCallback closedCallback,
           uint32_t connectionId, const UcpConfiguration& config, UcpNetwork* network = NULLPTR);

    ~UcpPcb() noexcept;

    UcpPcb(const UcpPcb&) = delete;
    UcpPcb& operator=(const UcpPcb&) = delete;
    UcpPcb(UcpPcb&&) = delete;
    UcpPcb& operator=(UcpPcb&&) = delete;

    /** @brief Returns the connection ID assigned during construction.
     *  @return Connection ID. */
    uint32_t GetConnectionId() const noexcept { return m_connectionId; }
    /** @brief Returns the session key for reconnection detection.
     *  @return Session key. */
    uint64_t GetSessionKey() const noexcept { return m_sessionKey; }
    /** @brief Returns the current connection state (thread-safe).
     *  @return Current UcpConnectionState. */
    UcpConnectionState GetState() noexcept;
    /** @brief Returns the current UCP pacing rate in bytes per second.
     *  @return Pacing rate in bytes/s. */
    double GetCurrentPacingRateBytesPerSecond() noexcept;
    /** @brief Returns true if one or more segments are still queued for transmission.
     *  @return True if pending send data exists. */
    bool HasPendingSendData() noexcept;
    /** @brief Captures a diagnostic snapshot of all connection metrics.
     *  @return UcpConnectionDiagnostics struct. */
    UcpConnectionDiagnostics GetDiagnosticsSnapshot() noexcept;

    /**
     * @brief Forces immediate teardown of the connection.
     * @param sendReset  If true, sends a RST packet to inform the peer.
     */
    void Abort(bool sendReset) noexcept;
    /** @brief (Test helper) Overrides the next send sequence number.
     *  @param nextSendSequence  Value to set for next send sequence. */
    void SetNextSendSequenceForTest(uint32_t nextSendSequence) noexcept;
    /** @brief (Test helper) Overrides the advertised receive window.
     *  @param windowBytes  Window size in bytes. */
    void SetAdvertisedReceiveWindowForTest(uint32_t windowBytes) noexcept;
    /** @brief (Test helper) Adds delivered bytes to measured-bandwidth accounting.
     *  @param nowMicros       Timestamp for the synthetic delivery sample.
     *  @param deliveredBytes  Delivered byte count to record. */
    void AddMeasuredDeliveryForTest(int64_t nowMicros, int64_t deliveredBytes) noexcept;
    /** @brief (Test helper) Computes measured bandwidth at a synthetic timestamp.
     *  @param nowMicros  Timestamp at which to read the rolling window.
     *  @return Measured bandwidth in bytes/second. */
    double ComputeMeasuredBandwidthForTest(int64_t nowMicros) noexcept { return ComputeMeasuredBandwidth(nowMicros); }
    /** @brief (Test helper) Returns the lower bound of the DPLPMTUD binary search.
     *  @return Probe min value. */
    int GetProbeMin() const noexcept { return m_probeMin; }
    /** @brief (Test helper) Returns the upper bound of the DPLPMTUD binary search.
     *  @return Probe max value. */
    int GetProbeMax() const noexcept { return m_probeMax; }
    /** @brief (Test helper) Returns the MTU value currently being probed.
     *  @return Current probe MTU. */
    int GetProbeMtu() const noexcept { return m_probeMtu; }
    /** @brief (Test helper) Returns true if a DPLPMTUD probe is in-flight.
     *  @return True if probe pending. */
    bool IsMtuProbePending() const noexcept { return m_mtuProbePending; }
    /** @brief (Test helper) Returns true if the in-flight DPLPMTUD probe was ACKed.
     *  @return True if probe ACKed. */
    bool IsMtuProbeAcked() const noexcept { return m_mtuProbeAcked; }
    /** @brief (Test helper) Returns the sequence number of the in-flight MTU probe.
     *  @return Probe sequence number. */
    uint32_t GetMtuProbeSequenceNumber() const noexcept { return m_mtuProbeSequenceNumber; }
    /** @brief (Test helper) Marks the in-flight MTU probe as ACKed for testing.
     *  Sets m_mtuProbePending=false and m_mtuProbeAcked=true. */
    void SetMtuProbeAckedForTest() noexcept {
        m_mtuProbePending = false;
        m_mtuProbeAcked = true;
    }
    /** @brief (Test helper) Sets the last MTU probe timestamp to a synthetic value.
     *  @param micros  Timestamp in microseconds. */
    void SetLastMtuProbeMicrosForTest(int64_t micros) noexcept { m_lastMtuProbeMicros = micros; }
    /** @brief (Test helper) Sets the last convergence timestamp for testing (skips interval gate).
     *  @param micros  Timestamp in microseconds. */
    void SetLastMtuConvergeMicrosForTest(int64_t micros) noexcept { m_lastMtuConvergeMicros = micros; }
    /** @brief (Test helper) Returns the reliable MTU after DPLPMTUD probing settled.
     *  @return Confirmed MTU. */
    int GetCurrentMtu() const noexcept { return m_currentMtu; }
    /** @brief (Test helper) Directly triggers the OnTimerAsync logic for testing.
     *  @param nowMicros  Synthetic current time in microseconds. */
    void RunTimerForTest(int64_t nowMicros) noexcept { OnTimerAsync(nowMicros); }
    /** @brief Registers or updates the peer's remote endpoint address.
     *  @param remoteEndpoint  Remote endpoint. */
    void SetRemoteEndpoint(const Endpoint& remoteEndpoint) noexcept {
        std::lock_guard<std::mutex> lock(m_endpointMutex);
        m_remoteEndpoint = remoteEndpoint;
        m_hasRemoteEndpoint = !remoteEndpoint.address.empty() && 0 != remoteEndpoint.port;
    }
    /**
     * @brief Validates and potentially updates the remote endpoint.
     * @param  remoteEndpoint  The peer endpoint claimed by the incoming packet.
     * @return True if the endpoint is accepted (first-time set or matching).
     * @note If the endpoint changes while Established, m_pathChanged is set to trigger UCP path-change logic.
     */
    bool ValidateRemoteEndpoint(const Endpoint& remoteEndpoint) noexcept {
        if (remoteEndpoint.address.empty() || 0 == remoteEndpoint.port) {
            return false;
        }
        bool shouldUpdate = false;
        {
            std::lock_guard<std::mutex> lock(m_endpointMutex);
            if (!m_hasRemoteEndpoint.load(std::memory_order_relaxed)) {
                shouldUpdate = true;
            } else if (m_remoteEndpoint.address == remoteEndpoint.address && m_remoteEndpoint.port == remoteEndpoint.port) {
                return true;
            } else {
                shouldUpdate = true;
                if (UcpConnectionState::Established == m_state) {
                    m_pathChanged = true;
                }
            }
            if (shouldUpdate) {
                m_remoteEndpoint = remoteEndpoint;
                m_hasRemoteEndpoint.store(true, std::memory_order_release);
            }
        }
        return true;
    }
    /**
     * @brief Checks whether a RST packet originates from a known remote endpoint.
     * @param  remoteEndpoint  The source endpoint of the RST packet.
     * @return True if the endpoint matches the stored remote or no remote is known yet.
     * @note RST from a completely unknown endpoint is rejected to mitigate off-path injection.
     */
    bool IsRstFromKnownRemote(const Endpoint& remoteEndpoint) const noexcept {
        if (!m_hasRemoteEndpoint.load(std::memory_order_acquire)) {
            return true;
        }
        std::lock_guard<std::mutex> lock(m_endpointMutex);
        return m_remoteEndpoint.address == remoteEndpoint.address && m_remoteEndpoint.port == remoteEndpoint.port;
    }
    /**
     * @brief Marks the path as changed so UCP resets its bandwidth estimation.
     */
    void MarkPathChanged() noexcept { m_pathChanged = true; }

    /**
     * @brief Register an additional connection ID that this PCB accepts.
     * @param cid  The extra connection ID to register.
     * @return True if the CID was added (false if already present or array full). */
    bool AddExtraCid(uint32_t cid) noexcept {
        if (0 == cid || cid == m_connectionId) {
            return false;
        }
        std::lock_guard<std::mutex> lock(m_endpointMutex);
        int count = m_extraCidCount.load(std::memory_order_relaxed);
        for (int i = 0; i < count; i++) {
            if (m_extraCidsArray[i] == cid) {
                return false;
            }
        }
        if (count >= MAX_EXTRA_CIDS) {
            return false;
        }
        m_extraCidsArray[count] = cid;
        m_extraCidCount.store(count + 1, std::memory_order_release);
        return true;
    }
    /**
     * @brief Unregister an extra connection ID from this PCB.
     * @param cid  The extra connection ID to remove.
     * @return True if the CID was removed (false if not found). */
    bool RemoveExtraCid(uint32_t cid) noexcept {
        if (0 == cid || cid == m_connectionId) {
            return false;
        }
        std::lock_guard<std::mutex> lock(m_endpointMutex);
        int count = m_extraCidCount.load(std::memory_order_relaxed);
        for (int i = 0; i < count; i++) {
            if (m_extraCidsArray[i] == cid) {
                m_extraCidsArray[i] = m_extraCidsArray[--count];
                m_extraCidCount.store(count, std::memory_order_release);
                return true;
            }
        }
        return false;
    }
    /**
     * @brief Check if the given connection ID belongs to this PCB (primary or extra).
     * @param cid  Connection ID to check.
     * @return True if this CID is valid for this PCB. */
    bool IsValidCid(uint32_t cid) const noexcept {
        if (cid == m_connectionId) {
            return true;
        }

        int count = m_extraCidCount.load(std::memory_order_acquire);
        for (int i = 0; i < count; i++) {
            if (m_extraCidsArray[i] == cid) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Initiates the 3-way handshake (active open) - callback-based Proactor pattern.
     * @param  remoteEndpoint  The peer to connect to.
     * @param  callback        Callback invoked with result when handshake completes.
     *                         The callback is invoked asynchronously, not blocking.
     */
    void ConnectAsync(const Endpoint& remoteEndpoint, ConnectAsyncCallback callback) noexcept;
    /**
     * @brief Synchronous connect (blocking) - blocks caller thread until handshake completes.
     * @param  remoteEndpoint  The peer to connect to.
     * @return True if handshake completes successfully.
     */
    bool Connect(const Endpoint& remoteEndpoint) noexcept;

    /**
     * @brief Queues data for transmission - callback-based Proactor pattern.
     * @param  buffer  Source buffer to copy payload from.
     * @param  offset  Byte offset into buffer.
     * @param  count   Number of bytes to send.
     * @param  callback Callback invoked with bytes accepted.
     */
    void SendAsync(const uint8_t* buffer, int offset, int count, SendAsyncCallback callback) noexcept;
    /**
     * @brief Queues data with a specific priority level - callback-based.
     * @param  buffer   Source buffer.
     * @param  offset   Byte offset.
     * @param  count    Number of bytes.
     * @param  priority Priority for scheduling (higher values send first).
     * @param  callback Callback invoked with bytes accepted.
     */
    void SendAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority, SendAsyncCallback callback) noexcept;
    /**
     * @brief Synchronous send - blocks caller thread until data is queued.
     * @param  buffer  Source buffer.
     * @param  offset  Byte offset.
     * @param  count   Number of bytes.
     * @param  priority Priority level.
     * @return Number of bytes accepted.
     */
    int Send(const uint8_t* buffer, int offset, int count, UcpPriority priority) noexcept;

    /**
     * @brief Non-blocking receive - callback-based Proactor pattern.
     * @param  buffer  Destination buffer.
     * @param  offset  Write offset in destination buffer.
     * @param  count   Maximum bytes to receive.
     * @param  callback Callback invoked with bytes received (0=closed, negative=error).
     * @note The caller MUST keep `buffer` valid until the callback fires; when no
     *       data is pending the raw pointer is stored and later written by
     *       TrySatisfyPendingReceives.  Passing a stack buffer that goes out of
     *       scope before the callback is use-after-free.
     */
    void ReceiveAsync(uint8_t* buffer, int offset, int count, ReceiveAsyncCallback callback) noexcept;
    /**
     * @brief Synchronous receive - blocks caller thread until data arrives.
     * @param  buffer  Destination buffer.
     * @param  offset  Write offset.
     * @param  count   Maximum bytes.
     * @return Bytes received, 0 on close, -1 on error.
     */
    int Receive(uint8_t* buffer, int offset, int count) noexcept;

    /**
     * @brief Non-blocking exact-byte read - callback-based Proactor pattern.
     * @param  buffer  Destination buffer.
     * @param  offset  Write offset.
     * @param  count   Number of bytes to read.
     * @param  callback Callback invoked with success flag.
     */
    void ReadAsync(uint8_t* buffer, int offset, int count, ReadAsyncCallback callback) noexcept;
    /**
     * @brief Synchronous exact-byte read - blocks caller thread.
     * @param  buffer  Destination buffer.
     * @param  offset  Write offset.
     * @param  count   Number of bytes.
     * @return True if all bytes received.
     */
    bool Read(uint8_t* buffer, int offset, int count) noexcept;

    /**
     * @brief Non-blocking exact-byte write - callback-based Proactor pattern.
     * @param  buffer  Source buffer.
     * @param  offset  Byte offset.
     * @param  count   Number of bytes.
     * @param  callback Callback invoked with success flag.
     */
    void WriteAsync(const uint8_t* buffer, int offset, int count, WriteAsyncCallback callback) noexcept;
    /**
     * @brief Non-blocking exact-byte write with priority - callback-based.
     * @param  buffer   Source buffer.
     * @param  offset   Byte offset.
     * @param  count    Number of bytes.
     * @param  priority QoS priority.
     * @param  callback Callback invoked with success flag.
     */
    void WriteAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority, WriteAsyncCallback callback) noexcept;
    /**
     * @brief Synchronous exact-byte write - blocks caller thread.
     * @param  buffer   Source buffer.
     * @param  offset   Byte offset.
     * @param  count    Number of bytes.
     * @param  priority QoS priority.
     * @return True if all bytes accepted.
     */
    bool Write(const uint8_t* buffer, int offset, int count, UcpPriority priority) noexcept;

    /**
     * @brief Initiates graceful connection teardown (FIN exchange) - callback-based Proactor pattern.
     * @note Drains send buffer, sends FIN, waits for peer FIN, then closes.
     * @param  callback Callback invoked when close completes.
     */
    void CloseAsync(CloseAsyncCallback callback) noexcept;
    /**
     * @brief Synchronous close - blocks caller thread until connection fully closed.
     */
    void Close() noexcept;

    /**
     * @brief Dispatches an incoming packet to the appropriate handler.
     * @param packet  The decoded packet (may be Syn, SynAck, Ack, Nak, Data, FecRepair, Fin, or Rst).
     * @note PAWS timestamp validation is performed before dispatch.
     */
    void HandleInboundAsync(const UcpPacket* packet);
    /**
     * @brief Adds fair-queue credit for this connection.
     * @param bytes  Amount of credit to add (clamped to a configurable maximum).
     * @note Fair-queue credit limits send bandwidth per connection when multiple PCB instances compete.
     */
    void AddFairQueueCredit(double bytes) noexcept;
    /**
     * @brief Sets fair-queue credit to an effectively unlimited value, bypassing the cap.
     * @note Used when only one connection is active — fair queue is unnecessary and
     *       the credit cap would otherwise cause starvation and retransmission storms.
     */
    void SetUncappedFairQueueCredit() noexcept;

    void RequestFlush() noexcept;
    /**
     * @brief Periodic processing callback invoked by the network timer or external loop.
     * @param  nowMicros  Current time in microseconds.
     * @return Number of work items performed (used for scheduling heuristics).
     */
    int OnTick(int64_t nowMicros) noexcept;
    /**
     * @brief Validates the remote endpoint and dispatches the packet if accepted.
     * @param packet           The incoming packet.
     * @param remoteEndpoint   The endpoint the packet arrived from.
     */
    void DispatchFromNetwork(const UcpPacket* packet, const Endpoint& remoteEndpoint) noexcept;

    void Dispose() noexcept;

    DataReceivedCallback DataReceived;

    ConnectedCallback Connected;

    DisconnectedCallback Disconnected;

    /** @brief Thread-safe setter for DataReceived (assigns under m_receiveSignalMutex,
     *  the same lock the pcb worker uses to copy the callback before firing).
     *  @param cb  Callback to install (replaces any existing one). */
    void SetDataReceived(DataReceivedCallback cb) noexcept {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        DataReceived = std::move(cb);
    }

    /** @brief Thread-safe setter for Connected (assigns under m_pendingCallbackMutex,
     *  the same lock HandleConnected uses to copy the callback before firing).
     *  @param cb  Callback to install (replaces any existing one). */
    void SetConnected(ConnectedCallback cb) noexcept {
        std::lock_guard<std::mutex> lk(m_pendingCallbackMutex);
        Connected = std::move(cb);
    }

    /** @brief Thread-safe setter for Disconnected (assigns under m_sync,
     *  the same lock HandleDisconnected (TransitionToClosed) uses to copy the
     *  callback before firing).
     *  @param cb  Callback to install (replaces any existing one). */
    void SetDisconnected(DisconnectedCallback cb) noexcept {
        std::lock_guard<std::mutex> lk(m_sync);
        Disconnected = std::move(cb);
    }

    /** @brief Copies the currently known remote endpoint if one has been set.
     *  @param[out] remoteEndpoint  Receives the remote endpoint when available.
     *  @return True if a remote endpoint is available. */
    bool TryGetRemoteEndpoint(Endpoint& remoteEndpoint) const noexcept;

  private:
    /** @brief Generates a random non-zero 32-bit connection ID.
     *  @return Random connection ID. */
    friend class UcpNetwork;
    static uint32_t NextConnectionId() noexcept;
    /** @brief Generates a cryptographically random non-zero 64-bit session key.
     *  @return Random session key for reconnection detection. */
    static uint64_t NextSessionKey() noexcept;
    /** @brief Generates a cryptographically random initial sequence number (ISN).
     *  @return Random ISN. */
    static uint32_t NextSequence() noexcept;
    /** @brief Generates a cryptographically random non-zero connection ID for rotation.
     *  @return Random connection ID for use in CID rotation. */
    static uint32_t GenerateNewCid() noexcept;
    /** @brief Returns the current wall-clock time in microseconds, using the network clock if available.
     *  @return Current time in microseconds. */
    int64_t NowMicros() noexcept;

    void AdvanceMeasuredBwSlot(int64_t nowMicros, int64_t deliveredBytes) noexcept;

    double ComputeMeasuredBandwidth(int64_t nowMicros) const noexcept;
    /** @brief Constructs a common header with the given type, flags, timestamp, and connection ID.
     *  @param  type              Packet type.
     *  @param  flags             Flag bitmask.
     *  @param  timestampMicros   Microsecond timestamp.
     *  @param  connectionId      Connection ID for the header.
     *  @return Populated UcpCommonHeader. */
    UcpCommonHeader CreateHeader(UcpPacketType type, int flags, int64_t timestampMicros, uint32_t connectionId) noexcept;

    /**
     * @name Packet Handlers
     * @brief Dispatch methods for each UCP packet type.
     * @{
     */
    /** @brief Processes an incoming SYN packet: transitions state and replies with SYN-ACK.
     *  @param packet  The decoded SYN control packet. */
    void HandleSyn(const UcpControlPacket& packet);
    /** @brief Processes an incoming SYN-ACK: updates expected sequence, processes piggybacked ACK, transitions to Established.
     *  @param packet  The decoded SYN-ACK control packet. */
    void HandleSynAck(const UcpControlPacket& packet);
    /** @brief Processes an incoming ACK: updates send buffer, collects RTT samples, applies UCP congestion feedback.
     *  @param  ackPacket  The decoded ACK packet. */
    void HandleAckAsync(const UcpAckPacket& ackPacket) noexcept;
    /** @brief Processes an incoming NAK: marks missing segments for retransmit, classifies congestion loss.
     *  @param  nakPacket  The decoded NAK packet. */
    void HandleNakAsync(const UcpNakPacket& nakPacket) noexcept;
    /** @brief Processes an incoming Data packet: inserts into reorder buffer, generates NAKs for gaps, triggers FEC recovery.
     *  @param dataPacket  The decoded data packet. */
    void HandleData(const UcpDataPacket& dataPacket);
    /** @brief Processes a CID-rotation DATA packet (sequence == CID_ROTATE_SEQUENCE_MARKER).
     *         Extracts the new CID from the payload and registers/unregisters extras.
     *  @param dataPacket  The decoded DATA packet carrying the CID rotation marker. */
    void HandleCidRotation(const UcpDataPacket& dataPacket) noexcept;
    /** @brief Processes an incoming FEC repair packet: attempts to recover missing data segments via erasure coding.
     *  @param packet  The decoded FEC repair packet. */
    void HandleFecRepair(const UcpFecRepairPacket& packet);
    /** @brief Processes an incoming FIN: transitions to Closing state, sends own FIN if not already sent.
     *  @param packet  The decoded FIN control packet. */
    void HandleFin(const UcpControlPacket& packet);

    /**
     * @brief Processes a piggybacked ACK embedded in a Data or NAK packet.
     * @param  ackNumber  The cumulative ACK number from the piggybacked ACK.
     * @param  nowMicros  Current monotonic time.
     * @param  echoMicros Echo timestamp from the packet for RTT calculation; 0 if unavailable.
     * @return Number of bytes newly acknowledged (used for measured bandwidth tracking).
     */
    int64_t ProcessPiggybackedAck(uint32_t ackNumber, int64_t nowMicros, int64_t echoMicros = 0) noexcept;
    /**
     * @brief Serializes and sends a control packet (Syn, SynAck, Fin, Rst).
     * @param type   The packet type to send.
     * @param flags  Bitmask of UcpPacketFlags to set on the packet.
     */
    void SendControl(UcpPacketType type, int flags);
    /**
     * @brief Builds and sends an ACK packet containing cumulative ACK, SACK blocks, and window advertisement.
     * @param flags                   Additional flags to include.
     * @param overrideEchoTimestamp   If > 0, sets echo_timestamp to this value; if 0, uses m_lastEchoTimestamp; if < 0, sets to 0
     * (keepalive).
     */
    void SendAckPacket(int flags, int64_t overrideEchoTimestamp);
    /**
     * @brief Builds and sends a NAK packet listing missing sequence numbers.
     * @param missing  Non-descending list of missing sequence numbers to report.
     * @note NAK rate is throttled per smoothed-RTT window (MAX_NAKS_PER_RTT).
     */
    void SendNak(const ucp::vector<uint32_t>& missing);

    void ScheduleAck() noexcept;
    /**
     * @brief Sends a CID rotation update as a DATA packet with reserved sequence number.
     * @param newCid  The new connection ID being rotated to. */
    void SendCidUpdate(uint32_t newCid);

    /**
     * @brief Sends a padded DATA packet to probe whether a larger MTU is supported.
     * @param probeMtu  The total UDP payload size to probe (IP + UDP headers not included).
     * @note The packet is padded to reach @p probeMtu bytes.  If the path supports
     *       this MTU, the peer will ACK the packet's sequence number.
     */
    void SendMtuProbe(int probeMtu);

    /**
     * @brief Drains the send buffer: builds data packets and hands them to the transport.
     * @note Runs inline on the calling thread.  Uses TryAcquireFlushLock to prevent
     *       concurrent flushes from different threads.
     */
    void FlushSendQueueAsync() noexcept;
    /**
     * @brief Schedules a deferred flush attempt after a pacing-induced delay.
     * @param waitMicros  How long to wait before retrying the flush.
     */
    void ScheduleDelayedFlush(int64_t waitMicros) noexcept;

    /**
     * @brief Appends in-order payload data to the receive queue and satisfies pending receives.
     * @param payload  The recovered/drained payload bytes.
     */
    void EnqueuePayload(ucp::vector<uint8_t> payload) noexcept;
    /**
     * @brief Attempts to copy data from the receive queue into a caller buffer.
     * @param  buffer  Destination buffer.
     * @param  offset  Write offset.
     * @param  count   Maximum bytes.
     * @return Number of bytes copied, 0 if closed, -1 if no data available yet.
     */
    int TryReceive(uint8_t* buffer, int offset, int count) noexcept;
    /**
     * @brief Satisfies any pending ReceiveAsync operations that now have data available.
     * @note Called from EnqueuePayload on the worker thread.
     */
    void TrySatisfyPendingReceives() noexcept;

    /**
     * @brief Periodic timer callback: checks for RTO timeouts, Tail Loss Probe, keepalive, NAK collection,
     *        SYN retransmission during handshake, and close phase advancement.
     * @note If an RTO timeout fires, marks segments for retransmit and optionally applies RTO backoff.
     */
    void OnTimerAsync() noexcept;

    void OnTimerAsync(int64_t nowMicros) noexcept;

    /**
     * @brief Transitions the connection to the Established state.
     * @note Fires the Connected callback and any pending connect callback on first transition.
     */
    void TransitionToEstablished() noexcept;
    /**
     * @brief Transitions the connection to the Closed state.
     * @note Fires Disconnected, pending callbacks, releases network registrations, and invokes the closed callback.
     */
    void TransitionToClosed() noexcept;

    void ReleaseNetworkRegistrations() noexcept;

    /** @brief Detaches this PCB from the network (mirrors C# UcpPcb.DetachNetwork):
     *  releases network registrations and clears the m_network pointer so no
     *  further timer/register calls reach a possibly-destroyed UcpNetwork.
     *  Safe to call after UcpNetwork::Dispose has cleared its registries. */
    void DetachNetwork() noexcept;

    /** @brief Returns true if the given buffer range is valid (non-null, non-negative, in-bounds).
     *  @param  buffer    Buffer pointer.
     *  @param  offset    Byte offset.
     *  @param  count     Number of bytes.
     *  @param  bufferLen Total buffer length.
     *  @return True if the range is valid. */
    static bool ValidateBuffer(const uint8_t* buffer, int offset, int count, int bufferLen) noexcept;
    /** @brief Packs a SACK block start/end pair into a 64-bit key for deduplication tracking.
     *  @param  start  SACK block start sequence.
     *  @param  end    SACK block end sequence.
     *  @return Packed 64-bit key. */
    static uint64_t PackSackBlockKey(uint32_t start, uint32_t end) noexcept;
    /** @brief Returns the highest End value from a collection of SACK blocks.
     *  @param  blocks  SACK block collection.
     *  @return Highest End sequence, or 0 if empty. */
    static uint32_t GetHighestSackEnd(const ucp::vector<SackBlock>& blocks) noexcept;
    /** @brief Sorts SACK blocks by ascending Start sequence number.
     *  @param blocks  Input SACK blocks.
     *  @param sorted  Output sorted SACK blocks. */
    static void SortSackBlocks(const ucp::vector<SackBlock>& blocks, ucp::vector<SackBlock>& sorted) noexcept;
    /**
     * @brief Determines whether a sequence number sits in a SACK-reported hole.
     * @param  sequenceNumber      The sequence to check.
     * @param  cumulativeAckNumber The cumulative ACK boundary.
     * @param  sackBlocks          The SACK blocks reported by the peer.
     * @return True if the sequence is below all SACK blocks (but above cumulative ACK) and SACK blocks exist above it.
     */
    static bool IsReportedSackHole(uint32_t sequenceNumber, uint32_t cumulativeAckNumber,
                                   const ucp::vector<SackBlock>& sackBlocks) noexcept;
    /** @brief Computes the maximum number of consecutive sequence numbers in a vector (after sorting and deduplication).
     *  @param  sequenceNumbers  Vector of sequence numbers.
     *  @return Maximum consecutive run length. */
    static int GetMaxContiguousLossRun(const ucp::vector<uint32_t>& sequenceNumbers) noexcept;

    /** @brief Retrieves or creates the SackTrackingState for a sequence number.
     *  @param  sequenceNumber  Sequence to look up.
     *  @return Pointer to SackTrackingState. */
    SackTrackingState* GetOrCreateSackTracking(uint32_t sequenceNumber) noexcept;
    /**
     * @brief Decides whether a SACK-reported hole should trigger a fast retransmit.
     * @param  segment                The potentially lost outbound segment.
     * @param  firstMissingSequence   The first unacknowledged sequence after cumulative ACK.
     * @param  highestSack            The highest sequence number acknowledged by any SACK block.
     * @param  reportedSackHole       Whether IsReportedSackHole() decided this is a hole.
     * @param  nowMicros              Current time.
     * @return True if the segment should be immediately retransmitted.
     */
    bool ShouldFastRetransmitSackHole(OutboundSegment& segment, uint32_t firstMissingSequence, uint32_t highestSack, bool reportedSackHole,
                                      int64_t nowMicros) noexcept;
    /**
     * @brief Checks if a pending FEC repair group might soon recover this segment, suppressing fast retransmit.
     * @param  segment    The segment to check.
     * @param  nowMicros  Current time.
     * @return True if we should wait for FEC repair rather than retransmit.
     */
    bool HasPendingFecRepair(OutboundSegment& segment, int64_t nowMicros) noexcept;

    /**
     * @name Adaptive Timing Helpers
     * @brief Compute reorder-grace and retransmit-timing windows based on current RTT estimates.
     * @{
     */
    /** @brief Grace period to wait for a FEC repair before allowing SACK fast retransmit.
     *  @return Grace period in microseconds. */
    int64_t GetFecFastRetransmitGraceMicros() noexcept;
    /** @brief Reordering grace for SACK fast retransmit.
     *  @return Grace period in microseconds. */
    int64_t GetSackFastRetransmitReorderGraceMicros() noexcept;
    /** @brief Minimum age a segment must have before fast retransmit is allowed.
     *  @return Age threshold in microseconds. */
    int64_t GetFastRetransmitAgeThreshold() noexcept;
    /** @brief Returns true if the number of inflight segments is low enough to justify early retransmit.
     *  @return True if early retransmit should be triggered. */
    bool ShouldTriggerEarlyRetransmit() noexcept;
    /** @brief Returns true if this segment is eligible for retransmission based on a NAK request.
     *  @param  segment    The outbound segment.
     *  @param  nowMicros  Current time.
     *  @return True if the segment should be retransmitted. */
    bool ShouldAcceptRetransmitRequest(OutboundSegment& segment, int64_t nowMicros) noexcept;
    /** @brief Returns the current retransmission ratio.
     *  @return Ratio of retransmitted packets to total sent packets. */
    double GetRetransmissionRatio() noexcept;

    /** @brief Logs a trace message to stderr if debug logging is enabled.
     *  @param message  Message to log. */
    void TraceLog(const ucp::string& message) noexcept;
    /** @brief Enables or disables UCP_TRACE output at runtime.
     *  @param enabled  True to enable trace output. */
    static void SetTraceEnabled(bool enabled) noexcept;
    /** @brief Returns whether UCP_TRACE output is currently enabled.
     *  @return True if trace output is enabled. */
    static bool IsTraceEnabled() noexcept;

    /**
     * @brief Validates that an incoming ACK packet is plausible (connection ID, PAWS, cumulative ACK progression, SACK block ordering).
     * @param  ackPacket  The received ACK packet.
     * @return True if the ACK passes all sanity checks.
     */
    bool IsAckPlausible(const UcpAckPacket& ackPacket) noexcept;
    /**
     * @brief Tracks duplicate ACK counts and triggers fast retransmit when the threshold is exceeded.
     * @param      ackPacket               The received ACK.
     * @param      nowMicros               Current time.
     * @param[out] fastRetransmitTriggered  Set to true if a new fast retransmit was just triggered.
     */
    void UpdateDuplicateAckState(const UcpAckPacket& ackPacket, int64_t nowMicros, bool& fastRetransmitTriggered) noexcept;

    /**
     * @name UCP Loss Classification
     * @brief Heuristics to distinguish congestion-caused loss from random/reordering loss.
     * @note Congestion signals reduce UCP's pacing rate and cwnd; random loss does not.
     * @{
     */
    /** @brief Convenience wrapper around ClassifyLosses for a single sequence number.
     *  @param  sequenceNumber       Sequence number of the lost packet.
     *  @param  sampleRttMicros      Current RTT sample.
     *  @param  nowMicros            Current time.
     *  @param  contiguousLossCount  Number of contiguous losses.
     *  @return True if the loss is classified as congestion. */
    bool IsCongestionLoss(uint32_t sequenceNumber, int64_t sampleRttMicros, int64_t nowMicros, int contiguousLossCount) noexcept;
    /** @brief Classifies a set of loss sequences using the contiguous run from the list.
     *  @param  sequenceNumbers  Lost sequence numbers.
     *  @param  nowMicros        Current time.
     *  @param  sampleRttMicros  Current RTT sample.
     *  @return True if classified as congestion. */
    bool ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers, int64_t nowMicros, int64_t sampleRttMicros) noexcept;
    /** @brief Core loss classifier: checks burst length, loss count, and RTT inflation against thresholds.
     *  @param  sequenceNumbers      Lost sequence numbers.
     *  @param  nowMicros            Current time.
     *  @param  sampleRttMicros      Current RTT sample.
     *  @param  contiguousLossCount  Number of contiguous losses.
     *  @return True if classified as congestion. */
    bool ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers, int64_t nowMicros, int64_t sampleRttMicros,
                        int contiguousLossCount) noexcept;

    /** @brief Returns the sliding window duration for the loss classifier.
     *  @return Window duration in microseconds. */
    int64_t GetLossClassifierWindowMicros() noexcept;
    /** @brief Removes loss events older than `windowMicros` from the front of m_recentLossEvents.
     *  @param nowMicros    Current time.
     *  @param windowMicros Window duration to retain. */
    void PruneLossEvents(int64_t nowMicros, int64_t windowMicros) noexcept;
    /** @brief Computes the median RTT from recent loss events (falls back to m_lastRttMicros).
     *  @return Median RTT in microseconds. */
    int64_t GetLossWindowMedianRttMicros() noexcept;
    /** @brief Returns the minimum RTT ever observed across all stored RTT samples.
     *  @return Minimum RTT in microseconds. */
    int64_t GetMinimumObservedRttMicros() noexcept;
    /** @brief Returns the longest run of consecutive sequence numbers among recent loss events.
     *  @return Maximum contiguous loss run. */
    int GetMaxContiguousRecentLossRun() noexcept;

    /**
     * @name FEC Recovery
     * @brief Erasure-code recovery of missing data segments using stored repair symbols.
     * @{
     */
    /** @brief Attempts to recover missing segments in the same FEC group as the given sequence number.
     *  @param receivedSequenceNumber  Sequence number in the FEC group to try recovery for.
     *  @param readyPayloads           Output vector of recovered payloads. */
    void TryRecoverFecAround(uint32_t receivedSequenceNumber, ucp::vector<ucp::vector<uint8_t>>& readyPayloads) noexcept;
    /** @brief Stores a batch of recovered FEC segments and drains any newly contiguous payloads.
     *  @param  recoveredPackets  Pairs of sequence number and recovered payload.
     *  @param  readyPayloads     Output vector of ready payloads.
     *  @return Number of segments successfully stored. */
    int StoreRecoveredFecPackets(const ucp::vector<ucp::pair<uint32_t, ucp::vector<uint8_t>>>* recoveredPackets,
                                 ucp::vector<ucp::vector<uint8_t>>& readyPayloads) noexcept;
    /** @brief Inserts a single FEC-recovered segment into the reorder buffer if it passes sanity checks.
     *  @param  recoveredSeq  Sequence number of the recovered segment.
     *  @param  recovered     Recovered payload bytes.
     *  @return True if the segment was stored. */
    bool StoreRecoveredFecSegment(uint32_t recoveredSeq, ucp::vector<uint8_t> recovered) noexcept;
    /** @brief Drains all in-order segments from m_recvBuffer into readyPayloads, advancing m_nextExpectedSequence.
     *  @param readyPayloads  Output vector of ready payloads. */
    void DrainReadyPayloads(ucp::vector<ucp::vector<uint8_t>>& readyPayloads) noexcept;
    /** @brief Removes all tracking state associated with a sequence number that has been delivered.
     *  @param sequenceNumber  Sequence to clear. */
    void ClearMissingReceiveState(uint32_t sequenceNumber) noexcept;

    /**
     * @name NAK Generation
     * @brief Logic for issuing negative acknowledgements when gaps are detected.
     * @{
     */
    /** @brief Returns true if a NAK has not yet been issued for this sequence.
     *  @param  sequenceNumber  Sequence to check.
     *  @return True if NAK should be issued. */
    bool ShouldIssueNak(uint32_t sequenceNumber) noexcept;
    /** @brief Returns true if an immediate reordered ACK should be sent (rate-limited).
     *  @param  nowMicros  Current time.
     *  @return True if reordered ACK should be sent. */
    bool ShouldSendImmediateReorderedAck(int64_t nowMicros) noexcept;
    /** @brief Checks whether the reorder grace period has elapsed for a missing sequence.
     *  @param  missingCount    Number of observations of this missing sequence.
     *  @param  firstSeenMicros Timestamp when first observed.
     *  @param  nowMicros       Current time.
     *  @return True if grace period has expired. */
    bool HasNakReorderGraceExpired(int missingCount, int64_t firstSeenMicros, int64_t nowMicros) noexcept;
    /** @brief Returns the adaptive NAK reorder grace period (clamped between NAK_REORDER_GRACE_MICROS and MinRtoMicros).
     *  @return Grace period in microseconds. */
    int64_t GetAdaptiveNakReorderGraceMicros() noexcept;
    /** @brief Marks a sequence as having a NAK issued, preventing duplicate NAK entries.
     *  @param sequenceNumber  Sequence to mark. */
    void MarkNakIssued(uint32_t sequenceNumber) noexcept;
    /** @brief Returns the timestamp when a missing sequence was first observed (creating the record if needed).
     *  @param  sequenceNumber  Sequence to look up.
     *  @return Timestamp in microseconds. */
    int64_t GetMissingFirstSeenMicros(uint32_t sequenceNumber) noexcept;
    /** @brief Scans the receive gap from m_nextExpectedSequence to the highest received, collecting NAK-worthy entries.
     *  @param missing    Output vector of missing sequences.
     *  @param nowMicros  Current time. */
    void CollectMissingForNak(ucp::vector<uint32_t>& missing, int64_t nowMicros) noexcept;

    /** @brief Returns the effective send window: min(congestion window, advertised receive window).
     *  @return Send window in bytes. */
    int GetSendWindowBytes() noexcept;
    /** @brief Returns true if we can allocate one more urgent retransmit within the per-RTT budget.
     *  @param  nowMicros  Current time.
     *  @return True if urgent recovery is available. */
    bool CanUseUrgentRecovery(int64_t nowMicros) noexcept;
    /** @brief Returns true if the connection has been idle long enough to be near the disconnect timeout.
     *  @param  nowMicros  Current time.
     *  @return True if near disconnect timeout. */
    bool IsNearDisconnectTimeout(int64_t nowMicros) noexcept;
    /** @brief Computes the total bytes consumed by data in the receive queue and reorder buffer.
     *  @return Used receive window bytes. */
    uint32_t GetReceiveWindowUsedBytes() noexcept;

    /** @brief Appends an RTT sample to the rolling buffer, trimming old samples if over MAX_RTT_SAMPLES.
     *  @param sampleRttMicros  RTT sample in microseconds. */
    void AddRttSample(int64_t sampleRttMicros) noexcept;

    void PurgeSackSendCounts() noexcept;

    /**
     * @name Worker thread
     * @brief Serial work queue and dedicated worker thread for all async protocol operations.
     * @{
     */
  public:
    /** @brief Enqueues a work item on the worker thread's serial queue.
     *  @param work  Callable to execute on the worker thread. */
    void EnqueueWork(ucp::function<void()> work) noexcept;

    void WorkerLoop() noexcept;

    void StartWorker() noexcept;

    void StopWorker() noexcept;
    /** @brief Fires the pending ConnectAsyncCallback (if any) and clears it.
     *  @param error  Result to pass to the callback. */
    void FirePendingConnectCallback(UcpError error) noexcept;
    /** @brief Fires the pending CloseAsyncCallback (if any) and clears it.
     *  @param error  Result to pass to the callback. */
    void FirePendingCloseCallback(UcpError error) noexcept;
    /** @brief Schedules the next periodic timer tick via m_network->AddTimer or standalone thread.
     *  Called from the constructor and from OnTimer after each tick. */
    void ScheduleTimer() noexcept;
    /** @brief Periodic timer callback driven by the network or standalone thread.
     *  Dispatches to OnTimerAsync on the worker thread. */
    void OnTimer() noexcept;
    /** @brief Attempts to acquire the flush lock (non-blocking).
     *  @return True if the lock was acquired. */
    bool TryAcquireFlushLock() noexcept;

    void ReleaseFlushLock() noexcept;
    /** @brief Processes pending inbound work items (ACKs, data) inline when the send window is full.
     *  Drains up to 16 items from the work queue to break the echo deadlock where the flush
     *  keeps re-enqueueing without ever processing the inbound ACKs that would drain the send window.
     *  Safe to call after releasing m_flushLock: inbound handlers acquire m_sync independently. */
    void ProcessPendingInbound() noexcept;

    void AdvanceCloseStateMachine() noexcept;

    void AdvanceConnectStateMachine() noexcept;

    /** @brief Primary mutex protecting connection state, timers, and cross-subsystem fields.
     *  All state is serialised through this mutex.  Sub-objects (m_rtoEstimator, m_sackGenerator)
     *  also have atomic raw-pointer aliases (m_rtoEstimatorAtomic, m_sackGeneratorAtomic) for
     *  lock-free reads in hot paths.
     *  For receive queue (m_receiveQueue) use m_receiveMutex instead.
     *  Lock order: m_sackMutex → m_sendBufMutex → m_sync → m_recvBufMutex
     *  (never reverse; m_endpointMutex/m_rttMutex/m_nakMutex/m_sackExtraMutex are leaf
     *  locks acquired only under the above prefix, never before it). */
    mutable std::mutex m_sync;
    mutable std::mutex m_sendBufMutex;
    mutable std::mutex m_endpointMutex;
    mutable std::mutex m_rttMutex;
    mutable std::mutex m_receiveMutex;
    mutable std::mutex m_lossMutex;
    mutable std::mutex m_nakMutex;
    mutable std::mutex m_recvBufMutex;
    mutable std::mutex m_pendingCallbackMutex;
    mutable std::mutex m_sackExtraMutex;
    mutable std::mutex m_sackMutex;
    mutable std::mutex m_fecRepairGroupsMutex;

    /** @name Worker thread members
     *  @{
     */
    ucp::deque<ucp::function<void()>> m_workQueue;
    std::mutex m_workMutex;
    std::condition_variable m_workSignal;
    std::thread m_workerThread;
    std::atomic<bool> m_workerStopped{false};
    /** @brief Set by StopWorker on a non-worker thread before it joins; the
     *  worker loop checks this before self-detaching so join() and detach()
     *  never race on the same std::thread object. */
    std::atomic<bool> m_workerJoining{false};

    /** @name Core infrastructure
     *  @brief Transport, configuration, callbacks, and network integration.
     *  @{
     */
    std::atomic<transport::ITransport*> m_transport{NULLPTR};
    std::atomic<bool> m_useFairQueue{false};
    std::atomic<bool> m_isServerSide{false};
    const UcpConfiguration m_config;
    ClosedCallback m_closedCallback;
    std::atomic<UcpNetwork*> m_network{NULLPTR};

    /** @name Send / Receive Buffers
     *  @{
     */
    SequenceMap m_sendBuffer;
    RecvSequenceMap m_recvBuffer;
    ucp::queue<ReceiveChunk> m_receiveQueue;

    /** @name NAK tracking maps
     *  @{
     */
    ucp::unordered_set<uint32_t> m_nakIssued;
    ucp::unordered_map<uint32_t, int> m_missingSequenceCounts;
    ucp::unordered_map<uint32_t, int64_t> m_missingFirstSeenMicros;
    ucp::unordered_map<uint32_t, int64_t> m_lastNakIssuedMicros;

    /** @name SACK tracking for fast retransmit
     *  @{
     */
    ucp::unordered_set<uint32_t> m_sackFastRetransmitNotified;
    ucp::unordered_map<uint64_t, int> m_sackBlockSendCounts;
    ucp::unordered_map<uint32_t, SackTrackingState> m_sackTracking;

    /** @name FEC state
     *  @{
     */
    ucp::unordered_set<uint32_t> m_fecRepairSentGroups;
    ucp::unordered_map<uint32_t, FecFragmentMetadata> m_fecFragmentMetadata;
    ucp::shared_ptr<UcpFecCodec> m_fecCodec;
    std::atomic<UcpFecCodec*> m_fecCodecAtomic{nullptr};

    /** @name Async coordination primitives
     *  @{
     */
    std::condition_variable m_receiveSignal;
    std::condition_variable m_sendSpaceSignal;
    std::mutex m_receiveSignalMutex;
    std::mutex m_sendSpaceSignalMutex;
    std::atomic<bool> m_flushLockAcquired{false};
    std::atomic<bool> m_flushNeeded{false};
    std::atomic<bool> m_ctsCanceled{false};

    /** @name Pending callback tracking
     *  @note These are used by the timer-driven handshake and close state machines.
     *  @{
     */
    ConnectAsyncCallback m_pendingConnectCallback;
    std::atomic<bool> m_hasPendingConnectCallback = false;
    CloseAsyncCallback m_pendingCloseCallback;
    std::atomic<bool> m_hasPendingCloseCallback = false;
    ucp::deque<PendingReceiveOp> m_pendingReceives;

    void StartNotifyThread() noexcept;

    void StopNotifyThread() noexcept;

    void FlushPendingReceiveCallbacks() noexcept;
    ucp::vector<ucp::pair<ReceiveAsyncCallback, int32_t>> m_pendingReceiveCallbacks;
    std::atomic<bool> m_callbackPending{false};
    std::thread m_notifyThread;
    std::mutex m_notifyMutex;
    std::condition_variable m_notifyCV;
    std::atomic<bool> m_notifyStopped{false};

    /** @name Connect / Close phase tracking
     *  @{
     */
    std::atomic<int64_t> m_connectStartMicros = 0;
    std::atomic<int64_t> m_lastSynSentMicros = 0;
    std::atomic<int64_t> m_closeStartMicros = 0;
    std::atomic<int64_t> m_flushDelayedDeadline = 0;
    std::atomic<int64_t> m_lastTickMicros = 0;

    /** @name Sub-objects (owned) — atomic raw pointer aliases for lock-free queries.
     *  Created once in constructor, destroyed in Dispose.  The atomic raw pointer
     *  is release-stored after creation and acquire-loaded in read-only paths.
     *  @{
     */
    ucp::shared_ptr<UcpSackGenerator> m_sackGenerator;
    ucp::shared_ptr<UcpRtoEstimator> m_rtoEstimator;
    ucp::shared_ptr<UcpCongestionControl> m_congestion;
    ucp::shared_ptr<PacingController> m_pacing;
    std::atomic<UcpCongestionControl*> m_congestionAtomic{nullptr};
    std::atomic<PacingController*> m_pacingAtomic{nullptr};
    std::atomic<UcpRtoEstimator*> m_rtoEstimatorAtomic{nullptr};
    std::atomic<UcpSackGenerator*> m_sackGeneratorAtomic{nullptr};

    /** @name Connection state and identifiers
     *  @{
     */
    std::atomic<UcpConnectionState> m_state{UcpConnectionState::Init};
    Endpoint m_remoteEndpoint;
    std::atomic<bool> m_hasRemoteEndpoint{false};
    std::atomic<uint32_t> m_connectionId{0};
    std::atomic<uint64_t> m_sessionKey{0};
    std::atomic<uint32_t> m_nextSendSequence{0};
    std::atomic<uint32_t> m_nextExpectedSequence{0};
    std::atomic<uint32_t> m_remoteWindowBytes{0};
    std::atomic<int64_t> m_flightBytes{0};
    std::atomic<double> m_fairQueueCreditBytes{0.0};
    std::atomic<int64_t> m_lastEchoTimestamp{0};
    std::atomic<int64_t> m_lastPeerAliveMicros{0};
    std::atomic<int64_t> m_lastAckSentMicros = 0;
    std::atomic<int64_t> m_lastRttMicros{0};

    /** @name CID rotation (Dynamic CID migration for anti-tracking / RST injection prevention)
     *  Extra CIDs stored in a fixed-size array (protected by m_endpointMutex).  @{ */
    static constexpr int MAX_EXTRA_CIDS = 8;
    uint32_t m_extraCidsArray[MAX_EXTRA_CIDS] = {};
    std::atomic<int> m_extraCidCount{0};
    std::atomic<uint32_t> m_pendingNewCid = 0;
    std::atomic<bool> m_cidRotatePending{false};
    std::atomic<uint32_t> m_cidRotateMarkerSequence = 0;
    std::atomic<int64_t> m_lastCidRotateMicros = 0;

    /** @name Path migration security (endpoint verification via challenge-response)
     *  @{
     */
    std::atomic<uint64_t> m_pathChallenge{0};
    Endpoint m_pendingMigrationEp;
    std::atomic<int64_t> m_pathChallengeTime{0};
    std::atomic<int64_t> m_lastPathChallengeTime{0};
    std::atomic<bool> m_pathChallengePending{false};
    std::atomic<int> m_pathChallengeAttempts{0};

    /** @name DPLPMTUD (Datagram PLPMTUD) path MTU discovery state
     *  @{
     */
    std::atomic<int> m_currentMtu = PcbConst::MTU_PROBE_BASE;
    std::atomic<int> m_probeMtu = 0;
    std::atomic<int> m_probeMin = PcbConst::MTU_PROBE_BASE;
    std::atomic<int> m_probeMax = PcbConst::MTU_PROBE_MAX;
    std::atomic<int64_t> m_lastMtuProbeMicros = 0;
    std::atomic<int64_t> m_lastMtuConvergeMicros = 0;
    std::atomic<uint32_t> m_mtuProbeSequenceNumber = 0;
    std::atomic<bool> m_mtuProbeAcked = false;
    std::atomic<bool> m_mtuProbePending = false;

    /** @name Handshake / teardown flags
     *  @{
     */
    std::atomic<bool> m_synSent = false;
    std::atomic<bool> m_synAckSent = false;
    std::atomic<int64_t> m_synAckSentMicros = 0;
    std::atomic<bool> m_finSent = false;
    std::atomic<bool> m_finAcked = false;
    std::atomic<bool> m_peerFinReceived = false;
    int64_t m_finSentMicros = 0;
    int m_finRetransmitCount = 0;
    std::atomic<bool> m_rstReceived = false;

    std::atomic<bool> m_disposed{false};

    std::atomic<int64_t> m_largestTimestampSeen = 0;
    std::atomic<bool> m_pawsEnabled = true;

    /** @name Timer / flush / ACK scheduling
     *  @{
     */
    std::atomic<uint32_t> m_sendCursorSeq{0};
    struct FlushSegmentCopy {
        uint32_t SequenceNumber;
        uint16_t FragmentTotal;
        uint16_t FragmentIndex;
        ucp::vector<uint8_t> Payload;
        int SendCount;
        ucp::vector<uint8_t> EncodedPacket;
        UcpPriority Priority;
    };
    ucp::vector<FlushSegmentCopy> m_segmentsToSend;
    std::atomic<bool> m_flushDelayed = false;
    std::atomic<bool> m_ackDelayed = false;
    std::atomic<uint32_t> m_timerId{0};
    std::atomic<uint32_t> m_flushTimerId{0};
    std::atomic<uint32_t> m_ackTimerId{0};
    ucp::shared_ptr<std::atomic<bool>> m_aliveFlag;
    std::thread m_standaloneTimerThread;
    std::atomic<bool> m_standaloneTimerRunning{false};
    std::mutex m_standaloneTimerMutex;
    std::condition_variable m_standaloneTimerCv;

    /** @name Callback dispatch guards
     *  @{
     */
    std::atomic<bool> m_connectedRaised = false;
    std::atomic<bool> m_disconnectedRaised = false;
    std::atomic<bool> m_closedResourcesReleased = false;
    std::atomic<bool> m_pathChanged = false;

    /** @name Duplicate ACK / fast recovery state
     *  @{
     */
    std::atomic<uint32_t> m_largestCumulativeAckNumber = 0;
    std::atomic<bool> m_hasLargestCumulativeAckNumber = false;
    std::atomic<uint32_t> m_lastAckNumber = 0;
    std::atomic<bool> m_hasLastAckNumber = false;
    std::atomic<int> m_duplicateAckCount = 0;
    std::atomic<bool> m_fastRecoveryActive = false;

    /** @name Receive window accounting
     *  @{
     */
    std::atomic<uint32_t> m_localReceiveWindowBytes = 0;
    std::atomic<int> m_queuedReceiveBytes{0};
    std::atomic<int64_t> m_recvBufferBytes{0};

    /** @name Diagnostics counters
     *  @{
     */
    std::atomic<int64_t> m_bytesSent = 0;
    std::atomic<int64_t> m_bytesReceived{0};
    /** @name Measured-bandwidth rolling slots (atomic, no mutex needed)
     *  @{
     */
    std::atomic<int64_t> m_measuredBwSlots[PcbConst::MEASURED_BW_SLOT_COUNT]{};
    std::atomic<int64_t> m_measuredBwSlotStart[PcbConst::MEASURED_BW_SLOT_COUNT]{};
    std::atomic<int> m_measuredBwSlotIndex = 0;
    std::atomic<int> m_sentDataPackets{0};
    std::atomic<int> m_retransmittedPackets{0};
    std::atomic<int> m_sentAckPackets{0};
    std::atomic<int> m_sentNakPackets{0};
    std::atomic<int> m_sentRstPackets{0};
    std::atomic<int> m_fastRetransmissions{0};
    std::atomic<int> m_timeoutRetransmissions{0};

    ucp::vector<int64_t> m_rttSamplesMicros;

    /** @name NAK send rate limiting
     *  @{
     */
    std::atomic<int64_t> m_lastNakWindowMicros = 0;
    std::atomic<int> m_naksSentThisRttWindow = 0;

    /** @name ACK scheduling / Tail Loss Probe state
     *  @{
     */
    std::atomic<int64_t> m_lastAckReceivedMicros = 0;
    std::atomic<int64_t> m_lastReorderedAckSentMicros = 0;
    std::atomic<bool> m_tailLossProbePending = false;

    /** @name Loss classifier state
     *  @{
     */
    ucp::queue<LossEvent> m_recentLossEvents;
    ucp::unordered_set<uint32_t> m_recentLossSequences;

    /** @name Urgent recovery rate limiting
     *  @{
     */
    std::atomic<int64_t> m_urgentRecoveryWindowMicros = 0;
    std::atomic<int> m_urgentRecoveryPacketsInWindow = 0;

    /** @name Zero-window probe state
     *  Zero-window probe periodically sends a minimal ACK when the peer's
     *  advertised window is zero, to elicit an updated window advertisement
     *  and prevent protocol deadlock (the echo deadlock scenario).
     *  @{
     */
    std::atomic<int64_t> m_zeroWindowProbeTimeMicros{0};
};

} // namespace ucp
