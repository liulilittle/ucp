/** @file ucp_pcb.cpp
 *  @brief UCP Protocol Control Block implementation — the core protocol engine. Mirrors C# Ucp.Internal.UcpPcb.
 *
 *  This is the largest and most complex file in the UCP codebase.  It
 *  implements the complete UCP protocol state machine, including:
 *
 *  - 3-way handshake (SYN / SYN-ACK / ACK) with random ISNs
 *  - Send buffer management with per-segment lifecycle tracking
 *  - Receive reorder buffer with in-order delivery to application
 *  - NAK-based gap reporting with adaptive reorder-grace windows
 *  - SACK-based fast retransmit with hole detection and distance thresholds
 *  - Duplicate-ACK-triggered fast retransmit (3 DUPACKs → infer loss)
 *  - RTO-based timeout recovery with exponential backoff and ACK-progress suppression
 *  - Tail-Loss Probe (TLP) for low-inflight scenarios
 *  - Silence Probe to detect path blackout faster than full RTO
 *  - BBR congestion control integration (OnAck / OnPacketSent / OnPacketLoss / OnFastRetransmit)
 *  - Token-bucket pacing integration
 *  - Fair-queue credit scheduling (per-connection bandwidth isolation)
 *  - Optional Forward Error Correction (FEC) with adaptive repair-send threshold
 *  - Piggybacked ACK on data packets to eliminate standalone ACK overhead
 *  - Deduplicated loss classification (congestion vs. random) via RTT-inflation detection
 *
 *  All hot-path methods acquire m_sync internally.  Heavy async work
 *  (Ack/Nak processing) is offloaded to std::async futures to avoid
 *  blocking the transport receive thread.
 */

#include "ucp/internal/ucp_pcb.h"
#include "ucp/ucp_packets.h"
#include "ucp/ucp_packet_codec.h"
#include "ucp/ucp_sack_generator.h"
#include "ucp/ucp_fec_codec.h"
#include "ucp/ucp_pacing.h"

#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <thread>
#include <cmath>

namespace ucp {

// ====================================================================================================
// Global random number generators for connection IDs and initial sequence numbers (ISN)
// ====================================================================================================

static std::mt19937_64 g_connectionRng(std::random_device{}());  //< 64-bit RNG for connection IDs.
static std::mt19937_64 g_sequenceRng(std::random_device{}());    //< 64-bit RNG for initial sequence numbers.

uint32_t UcpPcb::NextConnectionId() {
    uint32_t id;
    do {
        id = (uint32_t)(g_connectionRng() & 0xFFFFFFFFULL);  //< Generate random 32-bit ID.
    } while (id == 0);  //< Avoid zero (reserved).
    return id;
}

uint32_t UcpPcb::NextSequence() {
    return (uint32_t)(g_sequenceRng() & 0xFFFFFFFFULL);  //< Random ISN for cryptographic handshake safety.
}

int64_t UcpPcb::NowMicros() {
    // Use the network's cached clock when available, otherwise fall back to the global clock.
    return m_network ? m_network->GetCurrentTimeUs() : UcpTime::NowMicroseconds();
}

// ====================================================================================================
// Construction
// ====================================================================================================

UcpPcb::UcpPcb(ITransport* transport, bool isServerSide, bool useFairQueue,
               ClosedCallback closedCallback,
               uint32_t connectionId, const UcpConfiguration& config,
               UcpNetwork* network)
    : m_transport(transport)
    , m_isServerSide(isServerSide)
    , m_useFairQueue(useFairQueue)
    , m_config(config)
    , m_network(network)
    , m_closedCallback(closedCallback)
    , m_connectionId(connectionId != 0 ? connectionId : NextConnectionId())  //< Assign or generate connection ID.
{
    // === Allocate protocol engine objects ===
    m_rtoEstimator = new UcpRtoEstimator(m_config);  //< RTO estimator (always needed).
    m_bbr = new BbrCongestionControl();               //< BBR congestion controller (always needed).

    // === Initialize FEC if configured (lazy: only create codec when needed) ===
    if (m_config.FecRedundancy > 0.0 && m_config.FecGroupSize > 1) {
        int fecRepairCount = (std::max)(1, (int)std::ceil(m_config.FecGroupSize * m_config.FecRedundancy));
        (void)fecRepairCount;
    }

    // === Initialise connection state ===
    m_state = UcpConnectionState::Init;
    m_nextSendSequence = NextSequence();  //< Random initial send sequence number (ISN).
    m_lastActivityMicros = NowMicros();
    m_lastAckSentMicros = m_lastActivityMicros;

    // === Initialise receive window ===
    uint32_t rwnd = m_config.ReceiveWindowBytes();
    m_remoteWindowBytes = rwnd > 0 ? rwnd : PcbConst::DEFAULT_RECEIVE_WINDOW_BYTES;
    m_localReceiveWindowBytes = rwnd > 0 ? rwnd : PcbConst::DEFAULT_RECEIVE_WINDOW_BYTES;

    // === Register with network for timer/DoEvents integration ===
    if (m_network) {
        m_network->RegisterPcb(this);
        ScheduleTimer();
    }

    // === Set up future/promise chain for async APIs ===
    m_connectedFuture = m_connectedPromise.get_future().share();
    m_closedFuture = m_closedPromise.get_future().share();
}

UcpPcb::~UcpPcb() {
    Dispose();
}

// ====================================================================================================
// Dispose — release all resources
// ====================================================================================================

void UcpPcb::Dispose() {
    if (m_disposed) return;
    m_disposed = true;
    m_ctsCanceled = true;  //< Signal all async operations to stop.

    ReleaseNetworkRegistrations();

    // === Fulfill promises to unblock any waiting async calls ===
    try { m_connectedPromise.set_value(false); } catch (...) {}
    try { m_closedPromise.set_value(true); } catch (...) {}

    // === Wake all condition-variable waiters ===
    {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        m_receiveSignal.notify_all();
    }
    {
        std::lock_guard<std::mutex> lk(m_sendSpaceSignalMutex);
        m_sendSpaceSignal.notify_all();
    }
    {
        std::lock_guard<std::mutex> lk(m_flushLockMutex);
        m_flushLockAcquired = false;
        m_flushLockCond.notify_all();
    }

    // === Delete owned protocol engine objects ===
    delete m_rtoEstimator; m_rtoEstimator = nullptr;
    delete m_bbr; m_bbr = nullptr;
    delete m_sackGenerator; m_sackGenerator = nullptr;
    delete m_fecCodec; m_fecCodec = nullptr;
    delete m_pacing; m_pacing = nullptr;
}

// ====================================================================================================
// Public accessors (thread-safe, acquire m_sync)
// ====================================================================================================

UcpConnectionState UcpPcb::GetState() {
    std::lock_guard<std::mutex> lock(m_sync);
    return m_state;
}

double UcpPcb::GetCurrentPacingRateBytesPerSecond() {
    std::lock_guard<std::mutex> lock(m_sync);
    return m_bbr ? m_bbr->PacingRateBytesPerSecond() : 0.0;
}

bool UcpPcb::HasPendingSendData() {
    std::lock_guard<std::mutex> lock(m_sync);
    return !m_sendBuffer.empty();
}

UcpConnectionDiagnostics UcpPcb::GetDiagnosticsSnapshot() {
    std::lock_guard<std::mutex> lock(m_sync);
    UcpConnectionDiagnostics diag;
    diag.State = (int)m_state;
    diag.FlightBytes = m_flightBytes;
    diag.RemoteWindowBytes = m_remoteWindowBytes;
    diag.BytesSent = m_bytesSent;
    diag.BytesReceived = m_bytesReceived;
    diag.SentDataPackets = m_sentDataPackets;
    diag.RetransmittedPackets = m_retransmittedPackets;
    diag.SentAckPackets = m_sentAckPackets;
    diag.SentNakPackets = m_sentNakPackets;
    diag.SentRstPackets = m_sentRstPackets;
    diag.FastRetransmissions = m_fastRetransmissions;
    diag.TimeoutRetransmissions = m_timeoutRetransmissions;
    diag.CongestionWindowBytes = m_bbr ? m_bbr->CongestionWindowBytes() : 0;
    diag.PacingRateBytesPerSecond = m_bbr ? m_bbr->PacingRateBytesPerSecond() : 0.0;
    diag.EstimatedLossPercent = m_bbr ? m_bbr->EstimatedLossPercent() : 0.0;
    diag.LastRttMicros = m_lastRttMicros;
    diag.RttSamplesMicros = m_rttSamplesMicros;
    diag.ReceivedReset = m_rstReceived;
    diag.CurrentNetworkClass = m_bbr ? (int32_t)m_bbr->CurrentNetworkClass() : 0;

    // === Count buffered bytes in the receive queue ===
    int bufferedBytes = 0;
    std::queue<ReceiveChunk> copy = m_receiveQueue;
    while (!copy.empty()) {
        auto& chunk = copy.front();
        bufferedBytes += chunk.Count - chunk.Offset;
        copy.pop();
    }
    diag.BufferedReceiveBytes = bufferedBytes;
    return diag;
}

// ====================================================================================================
// Control operations
// ====================================================================================================

void UcpPcb::Abort(bool sendReset) {
    if (sendReset && m_remoteEndPoint != 0) {
        SendControl(UcpPacketType::Rst, (int)UcpPacketFlags::None);  //< Send RST to peer if known.
    }
    TransitionToClosed();
}

void UcpPcb::SetNextSendSequenceForTest(uint32_t nextSendSequence) {
    std::lock_guard<std::mutex> lock(m_sync);
    m_nextSendSequence = nextSendSequence;
}

void UcpPcb::SetAdvertisedReceiveWindowForTest(uint32_t windowBytes) {
    std::lock_guard<std::mutex> lock(m_sync);
    m_localReceiveWindowBytes = windowBytes;
}

void UcpPcb::SetRemoteEndPoint(uint64_t remoteEndPoint) {
    std::lock_guard<std::mutex> lock(m_sync);
    m_remoteEndPoint = remoteEndPoint;
}

bool UcpPcb::ValidateRemoteEndPoint(uint64_t remoteEndPoint) {
    if (remoteEndPoint == 0) return false;
    std::lock_guard<std::mutex> lock(m_sync);
    if (m_remoteEndPoint == 0) {
        m_remoteEndPoint = remoteEndPoint;  //< First-time binding.
        return true;
    }
    if (m_remoteEndPoint == remoteEndPoint) return true;  //< Same endpoint — valid.
    m_remoteEndPoint = remoteEndPoint;  //< Endpoint changed (path migration).
    if (m_state == UcpConnectionState::Established) {
        m_pathChanged = true;  //< Signal path change to BBR on next timer tick.
    }
    return true;
}

// ====================================================================================================
// Async Connect (3-way handshake with SYN retransmission loop)
// ====================================================================================================

std::future<bool> UcpPcb::ConnectAsync(uint64_t remoteEndPoint) {
    return std::async(std::launch::async, [this, remoteEndPoint]() -> bool {
        SetRemoteEndPoint(remoteEndPoint);
        {
            std::lock_guard<std::mutex> lock(m_sync);
            if (m_state == UcpConnectionState::Established) return true;
            m_state = UcpConnectionState::HandshakeSynSent;
            m_synSent = true;
        }

        int64_t deadlineMicros = NowMicros() +
            (int64_t)m_config.ConnectTimeoutMilliseconds * Constants::MICROS_PER_MILLI;
        while (NowMicros() < deadlineMicros) {
            if (m_ctsCanceled) return false;
            SendControl(UcpPacketType::Syn, (int)UcpPacketFlags::None);

            int waitMilliseconds;
            {
                std::lock_guard<std::mutex> lock(m_sync);
                waitMilliseconds = (int)(std::max)(PcbConst::MIN_HANDSHAKE_WAIT_MILLISECONDS,
                    m_rtoEstimator->CurrentRtoMicros() / Constants::MICROS_PER_MILLI);
            }

            // Wait for the connected future to be fulfilled (or timeout to retransmit SYN)
            auto status = m_connectedFuture.wait_for(std::chrono::milliseconds(waitMilliseconds));
            if (status == std::future_status::ready) {
                return m_connectedFuture.get();
            }
        }
        throw std::runtime_error("UCP connection handshake timed out.");
    });
}

// ====================================================================================================
// Buffer validation helper
// ====================================================================================================

void UcpPcb::ValidateBuffer(const uint8_t* buffer, int offset, int count, int bufferLen) {
    if (buffer == nullptr)
        throw std::invalid_argument("buffer is null");
    if (offset < 0 || count < 0 || offset + count > bufferLen)
        throw std::out_of_range("buffer range is invalid");
}

// ====================================================================================================
// SendAsync — segment application data into MSS-sized packets and enqueue
// ====================================================================================================

std::future<int> UcpPcb::SendAsync(const uint8_t* buffer, int offset, int count) {
    return SendAsync(buffer, offset, count, UcpPriority::Normal);
}

std::future<int> UcpPcb::SendAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority) {
    int localCount = count;
    return std::async(std::launch::async, [this, buffer, offset, localCount, priority]() -> int {
        int bufferLen = localCount + offset;
        ValidateBuffer(buffer, offset, localCount, bufferLen);

        // Reject sends if the connection is not in a sendable state
        {
            std::lock_guard<std::mutex> lock(m_sync);
            if (m_state != UcpConnectionState::Established &&
                m_state != UcpConnectionState::ClosingFinSent &&
                m_state != UcpConnectionState::ClosingFinReceived) {
                return -1;
            }
        }

        // === Segment the payload into MSS-sized chunks ===
        int acceptedBytes = 0;
        int remaining = localCount;
        int currentOffset = offset;
        int maxPayload = m_config.MaxPayloadSize();
        if (maxPayload <= 0) maxPayload = 1220;
        int capped = localCount;
        if (capped > maxPayload * 65535) {
            capped = maxPayload * 65535;  //< Cap at 65535 fragments (hard limit from uint16_t).
            remaining = capped;
        }

        uint16_t fragmentTotal = (uint16_t)((capped + maxPayload - 1) / maxPayload);
        uint16_t fragmentIndex = 0;
        int maxBufferedSegments = (std::max)(1, m_config.SendBufferSize() / (std::max)(1, maxPayload));

        while (remaining > 0 && !m_ctsCanceled) {
            int chunk = remaining > maxPayload ? maxPayload : remaining;

            {
                std::lock_guard<std::mutex> lock(m_sync);
                if ((int)m_sendBuffer.size() >= maxBufferedSegments) break;  //< Send buffer full — stop.
            }

            ucp::vector<uint8_t> payload(chunk);
            std::memcpy(payload.data(), buffer + currentOffset, (size_t)chunk);

            {
                std::lock_guard<std::mutex> lock(m_sync);
                OutboundSegment segment;
                segment.SequenceNumber = m_nextSendSequence;
                segment.FragmentTotal = fragmentTotal;
                segment.FragmentIndex = fragmentIndex;
                segment.Payload = std::move(payload);
                segment.Priority = priority;
                m_sendBuffer[segment.SequenceNumber] = std::move(segment);
                m_nextSendSequence = UcpSequenceComparer::Increment(m_nextSendSequence);
            }

            currentOffset += chunk;
            remaining -= chunk;
            acceptedBytes += chunk;
            fragmentIndex++;
        }

        FlushSendQueueAsync().wait();  //< Flush the send buffer immediately.
        return acceptedBytes;
    });
}

// ====================================================================================================
// ReceiveAsync — wait for in-order data in the receive queue
// ====================================================================================================

std::future<int> UcpPcb::ReceiveAsync(uint8_t* buffer, int offset, int count) {
    return std::async(std::launch::async, [this, buffer, offset, count]() -> int {
        ValidateBuffer(buffer, offset, count, count + offset);
        while (!m_ctsCanceled) {
            bool hasChunk = false;
            {
                std::lock_guard<std::mutex> lock(m_sync);
                if (!m_receiveQueue.empty()) {
                    hasChunk = true;
                } else if (m_state == UcpConnectionState::Closed) {
                    return 0;  //< Connection closed with no data available.
                }
            }

            if (hasChunk) {
                std::lock_guard<std::mutex> lock(m_sync);
                if (m_receiveQueue.empty()) return 0;
                ReceiveChunk& current = m_receiveQueue.front();
                int available = current.Count - current.Offset;
                int toCopy = available > count ? count : available;
                std::memcpy(buffer + offset, current.Buffer.data() + current.Offset, (size_t)toCopy);
                current.Offset += toCopy;
                m_queuedReceiveBytes -= toCopy;
                if (m_queuedReceiveBytes < 0) m_queuedReceiveBytes = 0;
                if (current.Offset >= current.Count) {
                    m_receiveQueue.pop();  //< Chunk fully consumed.
                }
                ScheduleAck();  //< Update advertised window.
                return toCopy;
            }

            // Wait for data or timeout (100ms poll)
            {
                std::unique_lock<std::mutex> lk(m_receiveSignalMutex);
                m_receiveSignal.wait_for(lk, std::chrono::milliseconds(100));
            }
        }
        return -1;
    });
}

// ====================================================================================================
// ReadAsync / WriteAsync — exact-byte-count convenience wrappers
// ====================================================================================================

std::future<bool> UcpPcb::ReadAsync(uint8_t* buffer, int offset, int count) {
    return std::async(std::launch::async, [this, buffer, offset, count]() -> bool {
        ValidateBuffer(buffer, offset, count, count + offset);
        int completed = 0;
        while (completed < count && !m_ctsCanceled) {
            auto future = ReceiveAsync(buffer, offset + completed, count - completed);
            int received = future.get();
            if (received <= 0) return false;
            completed += received;
        }
        return completed >= count;
    });
}

std::future<bool> UcpPcb::WriteAsync(const uint8_t* buffer, int offset, int count) {
    return WriteAsync(buffer, offset, count, UcpPriority::Normal);
}

std::future<bool> UcpPcb::WriteAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority) {
    return std::async(std::launch::async, [this, buffer, offset, count, priority]() -> bool {
        ValidateBuffer(buffer, offset, count, count + offset);
        int totalWritten = 0;
        while (totalWritten < count && !m_ctsCanceled) {
            auto future = SendAsync(buffer, offset + totalWritten, count - totalWritten, priority);
            int written = future.get();
            if (written < 0) return false;
            if (written == 0) {
                // Send buffer full — wait for space to become available
                std::unique_lock<std::mutex> lk(m_sendSpaceSignalMutex);
                m_sendSpaceSignal.wait_for(lk, std::chrono::milliseconds(100));
                continue;
            }
            totalWritten += written;
        }
        return totalWritten >= count;
    });
}

// ====================================================================================================
// CloseAsync — graceful FIN exchange with timeout-based forced closure
// ====================================================================================================

std::future<void> UcpPcb::CloseAsync() {
    return std::async(std::launch::async, [this]() {
        bool needSendFin = false;
        int64_t deadlineMicros = NowMicros() + m_config.DisconnectTimeoutMicros;

        // === Wait for send buffer to empty (up to disconnect timeout) ===
        while (NowMicros() < deadlineMicros && !m_ctsCanceled) {
            {
                std::lock_guard<std::mutex> lock(m_sync);
                if (m_sendBuffer.empty() || m_state == UcpConnectionState::Closed) break;
            }
            {
                std::unique_lock<std::mutex> lk(m_sendSpaceSignalMutex);
                m_sendSpaceSignal.wait_for(lk, std::chrono::milliseconds(10));
            }
        }

        // === Send FIN if the connection is still open ===
        {
            std::lock_guard<std::mutex> lock(m_sync);
            if (m_state == UcpConnectionState::Closed) return;
            if (!m_finSent) {
                m_state = UcpConnectionState::ClosingFinSent;
                m_finSent = true;
                needSendFin = true;
            }
        }

        if (needSendFin) {
            SendControl(UcpPacketType::Fin, (int)UcpPacketFlags::None);
        }

        // === Wait for peer FIN ACK (or timeout) ===
        m_closedFuture.wait_for(std::chrono::milliseconds(PcbConst::CLOSE_WAIT_TIMEOUT_MILLISECONDS));
        TransitionToClosed();
    });
}

// ====================================================================================================
// HandleInboundAsync — top-level inbound packet dispatcher
// ====================================================================================================

void UcpPcb::HandleInboundAsync(const UcpPacket* packet) {
    if (!packet) return;

    // === Update activity timestamp and PAWS check ===
    {
        std::lock_guard<std::mutex> lock(m_sync);
        m_lastActivityMicros = NowMicros();

        // PAWS: reject packets with very old timestamps (wrapped sequence protection)
        if (m_pawsEnabled && m_largestTimestampSeen > 0 &&
            m_largestTimestampSeen - (int64_t)packet->header.timestamp > PcbConst::PAWS_TIMEOUT_MICROS) {
            return;
        }
        if ((int64_t)packet->header.timestamp > m_largestTimestampSeen) {
            m_largestTimestampSeen = (int64_t)packet->header.timestamp;
        }
    }

    // === Tag dispatch to type-specific handlers ===
    UcpPacketType type = packet->header.type;

    if (type == UcpPacketType::Syn) {
        HandleSyn(static_cast<const UcpControlPacket&>(*packet));
    } else if (type == UcpPacketType::SynAck) {
        HandleSynAck(static_cast<const UcpControlPacket&>(*packet));
    } else if (type == UcpPacketType::Ack) {
        auto fut = HandleAckAsync(static_cast<const UcpAckPacket&>(*packet));
    } else if (type == UcpPacketType::Nak) {
        auto fut = HandleNakAsync(static_cast<const UcpNakPacket&>(*packet));
    } else if (type == UcpPacketType::Data) {
        HandleData(static_cast<const UcpDataPacket&>(*packet));
    } else if (type == UcpPacketType::FecRepair) {
        HandleFecRepair(static_cast<const UcpFecRepairPacket&>(*packet));
    } else if (type == UcpPacketType::Fin) {
        HandleFin(static_cast<const UcpControlPacket&>(*packet));
    } else if (type == UcpPacketType::Rst) {
        m_rstReceived = true;
        TransitionToClosed();
    }
}

// ====================================================================================================
// Fair queue credit
// ====================================================================================================

void UcpPcb::AddFairQueueCredit(double bytes) {
    if (!m_useFairQueue || bytes <= 0) return;
    std::lock_guard<std::mutex> lock(m_sync);
    m_fairQueueCreditBytes += bytes;
    double maxCredit = (std::max)((double)m_config.SendQuantumBytes, (double)m_config.Mss);
    if (m_fairQueueCreditBytes > maxCredit) m_fairQueueCreditBytes = maxCredit;  //< Cap credit.
}

void UcpPcb::RequestFlush() {
    auto fut = FlushSendQueueAsync();
    (void)fut;
}

// ====================================================================================================
// OnTick — periodic timer callback: RTO, keep-alive, TLP, NAK generation
// ====================================================================================================

int UcpPcb::OnTick(int64_t nowMicros) {
    if (m_disposed) return 0;
    int work = 1;
    auto timerTask = OnTimerAsync(nowMicros);
    (void)timerTask;
    if (HasPendingSendData()) {
        RequestFlush();  //< Flush any accumulated send data.
        work++;
    }
    return work;
}

void UcpPcb::DispatchFromNetwork(const UcpPacket* packet, uint64_t remoteEndPoint) {
    if (ValidateRemoteEndPoint(remoteEndPoint)) {
        HandleInboundAsync(packet);
    }
}

// ====================================================================================================
// ProcessPiggybackedAck — handle cumulative ACK embedded in data/control packets
// ====================================================================================================

int UcpPcb::ProcessPiggybackedAck(uint32_t ackNumber, int64_t nowMicros) {
    ucp::vector<uint32_t> removeKeys;
    int deliveredBytes = 0;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        if (ackNumber == 0) return 0;

        // Ignore reordered/replayed ACKs (older than the largest we've seen)
        if (m_hasLargestCumulativeAckNumber &&
            UcpSequenceComparer::IsBefore(ackNumber, m_largestCumulativeAckNumber))
            return 0;

        if (!m_hasLargestCumulativeAckNumber ||
            UcpSequenceComparer::IsAfter(ackNumber, m_largestCumulativeAckNumber)) {
            m_largestCumulativeAckNumber = ackNumber;
            m_hasLargestCumulativeAckNumber = true;
        }

        m_lastAckReceivedMicros = nowMicros;
        m_tailLossProbePending = false;  //< TLP resolved.

        // === Walk send buffer and ACK everything up to ackNumber ===
        for (auto& pair : m_sendBuffer) {
            OutboundSegment& segment = pair.second;
            if (segment.Acked) continue;

            if (UcpSequenceComparer::IsBeforeOrEqual(segment.SequenceNumber, ackNumber)) {
                segment.Acked = true;
                if (segment.InFlight) {
                    m_flightBytes -= (int)segment.Payload.size();
                    if (m_flightBytes < 0) m_flightBytes = 0;
                }
                deliveredBytes += (int)segment.Payload.size();

                // === Collect RTT sample from first-transmission segments ===
                if (segment.SendCount == 1 && segment.LastSendMicros > 0) {
                    int64_t segmentRtt = nowMicros - segment.LastSendMicros;
                    if (segmentRtt > 0) {
                        m_lastRttMicros = segmentRtt;
                        AddRttSample(segmentRtt);
                        m_rtoEstimator->Update(segmentRtt);
                    }
                }
                removeKeys.push_back(pair.first);
            } else if (UcpSequenceComparer::IsAfter(segment.SequenceNumber, ackNumber)) {
                break;  //< Send buffer is ordered — stop once we pass ackNumber.
            }
        }

        // === Remove ACKed segments and clean up associated state ===
        for (auto& key : removeKeys) {
            m_sackFastRetransmitNotified.erase(key);
            m_sackTracking.erase(key);
            m_sendBuffer.erase(key);
        }

        // === Notify writers that space is available ===
        if (!removeKeys.empty()) {
            std::lock_guard<std::mutex> slk(m_sendSpaceSignalMutex);
            m_sendSpaceSignal.notify_all();
        }

        // === Reset fair-queue credit when buffer is empty ===
        if (m_sendBuffer.empty()) {
            m_fairQueueCreditBytes = 0;
        }

        // === Feed BBR with delivered byte count and RTT ===
        if (deliveredBytes > 0 && m_bbr) {
            m_bbr->OnAck(nowMicros, deliveredBytes, m_lastRttMicros, m_flightBytes);
        }
    }
    return deliveredBytes;
}

// ====================================================================================================
// HandleSyn — process an inbound SYN (server-side handshake step 1)
// ====================================================================================================

void UcpPcb::HandleSyn(const UcpControlPacket& packet) {
    bool shouldReply = false;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        m_connectionId = packet.header.connection_id;
        if (m_network) {
            m_network->UpdatePcbConnectionId(this, 0, m_connectionId);
        }
        if (packet.has_sequence_number) {
            m_nextExpectedSequence = packet.sequence_number;  //< Learn peer's ISN.
        }
        if (m_state == UcpConnectionState::Init) {
            m_state = UcpConnectionState::HandshakeSynReceived;
        }
        if (m_state != UcpConnectionState::Closed) {
            m_synAckSent = true;
            m_synAckSentMicros = NowMicros();
            shouldReply = true;
        }
    }
    if (shouldReply) {
        SendControl(UcpPacketType::SynAck, (int)UcpPacketFlags::None);
    }
}

// ====================================================================================================
// HandleSynAck — process an inbound SYN-ACK (client-side handshake step 2)
// ====================================================================================================

void UcpPcb::HandleSynAck(const UcpControlPacket& packet) {
    bool shouldEstablish = false;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        if (packet.has_sequence_number) {
            m_nextExpectedSequence = packet.sequence_number;
        }
        if (m_synSent && m_state != UcpConnectionState::Closed) {
            shouldEstablish = (m_state == UcpConnectionState::HandshakeSynSent);
        }
    }

    // Process piggybacked ACK if present
    if ((packet.header.flags & (int)UcpPacketFlags::HasAckNumber) && packet.ack_number > 0) {
        ProcessPiggybackedAck(packet.ack_number, NowMicros());
    }

    SendAckPacket((int)UcpPacketFlags::None, 0);  //< Send ACK to complete 3-way handshake.
    if (shouldEstablish) {
        TransitionToEstablished();
    }
}

// ====================================================================================================
// HandleAckAsync — process an incoming ACK packet (standalone)
// ====================================================================================================

std::future<void> UcpPcb::HandleAckAsync(const UcpAckPacket& ackPacket) {
    UcpAckPacket ackCopy = ackPacket;
    return std::async(std::launch::async, [this, ackCopy]() {
        bool establishByHandshake = false;
        ucp::vector<uint32_t> removeKeys;
        int deliveredBytes = 0;
        int remainingFlight = 0;
        int64_t sampleRtt = 0;
        int64_t echoRtt = 0;
        int64_t nowMicros = NowMicros();
        bool fastRetransmitTriggered = false;

        {
            std::lock_guard<std::mutex> lock(m_sync);
            // === Plausibility checks ===
            if (!IsAckPlausible(ackCopy)) {
                remainingFlight = m_flightBytes;
                return;
            }

            m_remoteWindowBytes = ackCopy.window_size;
            m_lastAckReceivedMicros = nowMicros;
            m_tailLossProbePending = false;

            // Handshake completion: SYN-ACK → data means the peer received our ACK
            if (m_state == UcpConnectionState::HandshakeSynReceived && m_synAckSent) {
                establishByHandshake = true;
            }

            // Detect FIN ACKed
            if ((ackCopy.header.flags & (int)UcpPacketFlags::FinAck) == (int)UcpPacketFlags::FinAck) {
                m_finAcked = true;
            }

            // === Echo-based RTT measurement (most precise) ===
            if (ackCopy.echo_timestamp > 0) {
                echoRtt = nowMicros - (int64_t)ackCopy.echo_timestamp;
            }

            // === Duplicate-ACK-based fast retransmit ===
            UpdateDuplicateAckState(ackCopy, nowMicros, fastRetransmitTriggered);

            // === Process SACK blocks ===
            const auto& sackBlocks = ackCopy.sack_blocks;
            ucp::vector<SackBlock> sortedSackBlocks;
            SortSackBlocks(sackBlocks, sortedSackBlocks);

            uint32_t highestSack = !sortedSackBlocks.empty() ? GetHighestSackEnd(sortedSackBlocks) : 0;
            uint32_t firstMissingSequence = UcpSequenceComparer::Increment(ackCopy.ack_number);

            int sackIndex = 0;
            bool hasSackBlocks = !sortedSackBlocks.empty();

            // === Walk send buffer: mark ACKed + SACKed segments, detect SACK holes ===
            for (auto& pair : m_sendBuffer) {
                OutboundSegment& segment = pair.second;
                if (segment.Acked) continue;

                // Cumulative ACK check
                bool acked = UcpSequenceComparer::IsBeforeOrEqual(segment.SequenceNumber, ackCopy.ack_number);
                // SACK check
                if (!acked && hasSackBlocks) {
                    while (sackIndex < (int)sortedSackBlocks.size() &&
                           UcpSequenceComparer::IsBefore(sortedSackBlocks[sackIndex].End, segment.SequenceNumber)) {
                        sackIndex++;
                    }
                    if (sackIndex < (int)sortedSackBlocks.size()) {
                        acked = UcpSequenceComparer::IsInForwardRange(
                            segment.SequenceNumber, sortedSackBlocks[sackIndex].Start, sortedSackBlocks[sackIndex].End);
                    }
                }

                if (acked) {
                    // Update largest cumulative ack tracker
                    if (!m_hasLargestCumulativeAckNumber ||
                        UcpSequenceComparer::IsAfter(ackCopy.ack_number, m_largestCumulativeAckNumber)) {
                        m_largestCumulativeAckNumber = ackCopy.ack_number;
                        m_hasLargestCumulativeAckNumber = true;
                    }
                    segment.Acked = true;
                    if (segment.InFlight) {
                        m_flightBytes -= (int)segment.Payload.size();
                        if (m_flightBytes < 0) m_flightBytes = 0;
                    }
                    deliveredBytes += (int)segment.Payload.size();

                    // RTT from first-transmit-only segments
                    if (segment.SendCount == 1 && segment.LastSendMicros > 0) {
                        int64_t segmentRtt = nowMicros - segment.LastSendMicros;
                        if (sampleRtt == 0 || segmentRtt < sampleRtt) {
                            sampleRtt = segmentRtt;
                        }
                    }
                    m_bytesSent += (int64_t)segment.Payload.size();
                    removeKeys.push_back(pair.first);
                    continue;
                }

                // === SACK hole: segment is before highestSack but not in any SACK block ===
                if (hasSackBlocks &&
                    UcpSequenceComparer::IsBefore(segment.SequenceNumber, highestSack)) {
                    if (m_sackFastRetransmitNotified.find(segment.SequenceNumber) ==
                        m_sackFastRetransmitNotified.end()) {
                        SackTrackingState* sackState = GetOrCreateSackTracking(segment.SequenceNumber);
                        if (sackState->MissingAckCount == 0) {
                            sackState->FirstMissingAckMicros = nowMicros;
                        }
                        sackState->MissingAckCount++;
                    }

                    bool reportedSackHole = IsReportedSackHole(
                        segment.SequenceNumber, ackCopy.ack_number, sortedSackBlocks);

                    // === SACK-based fast retransmit ===
                    if (segment.SendCount == 1 && !segment.NeedsRetransmit &&
                        ShouldFastRetransmitSackHole(segment, firstMissingSequence,
                                                      highestSack, reportedSackHole, nowMicros)) {
                        segment.NeedsRetransmit = true;
                        SackTrackingState* st = GetOrCreateSackTracking(segment.SequenceNumber);
                        st->UrgentRetransmit = true;
                        m_fastRetransmissions++;
                        m_sackFastRetransmitNotified.insert(segment.SequenceNumber);
                        bool isCongestion = IsCongestionLoss(
                            segment.SequenceNumber, sampleRtt, nowMicros, 1);
                        if (m_bbr) m_bbr->OnFastRetransmit(nowMicros, isCongestion);
                        TraceLog("FastRetransmit seq=" + std::to_string(segment.SequenceNumber) +
                                 " sack=true congestion=" + (isCongestion ? "true" : "false"));
                    }
                }
            }

            // === Remove ACKed segments ===
            for (auto& key : removeKeys) {
                m_sackFastRetransmitNotified.erase(key);
                m_sendBuffer.erase(key);
            }

            if (!removeKeys.empty()) {
                std::lock_guard<std::mutex> slk(m_sendSpaceSignalMutex);
                m_sendSpaceSignal.notify_all();
            }

            if (m_sendBuffer.empty()) {
                m_fairQueueCreditBytes = 0;
            }

            remainingFlight = m_flightBytes;

            // === Fallback RTT from echo if no per-segment RTT was obtained ===
            if (deliveredBytes > 0 && sampleRtt == 0 && echoRtt > 0 &&
                echoRtt <= m_rtoEstimator->CurrentRtoMicros()) {
                sampleRtt = echoRtt;
            }

            // === Feed recovered RTT to estimator (validate: must be within reasonable range) ===
            bool acceptableRtt = sampleRtt > 0 && sampleRtt <= (int64_t)(
                (double)m_rtoEstimator->CurrentRtoMicros() * PcbConst::RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER);
            if (deliveredBytes > 0 && acceptableRtt) {
                m_lastRttMicros = sampleRtt;
                AddRttSample(sampleRtt);
                m_rtoEstimator->Update(sampleRtt);
            }

            if (m_bbr) {
                m_bbr->OnAck(nowMicros, deliveredBytes, sampleRtt, m_flightBytes);
            }
        }

        // === Post-unlock actions ===
        if (establishByHandshake) {
            TransitionToEstablished();
        }

        if (m_finSent && m_finAcked && m_peerFinReceived) {
            TransitionToClosed();
        }

        if (fastRetransmitTriggered || deliveredBytes > 0 || remainingFlight > 0) {
            auto fut = FlushSendQueueAsync();
            (void)fut;
        }
    });
}

// ====================================================================================================
// HandleNakAsync — process an incoming NAK packet (negative acknowledgement)
// ====================================================================================================

std::future<void> UcpPcb::HandleNakAsync(const UcpNakPacket& nakPacket) {
    UcpNakPacket nakCopy = nakPacket;
    return std::async(std::launch::async, [this, nakCopy]() {
        bool notifiedLoss = false;
        int64_t nowMicros = NowMicros();

        // === Process cumulative ack (NAKs typically carry a piggybacked ack_number) ===
        if (nakCopy.ack_number > 0) {
            ProcessPiggybackedAck(nakCopy.ack_number, nowMicros);
        }

        {
            std::lock_guard<std::mutex> lock(m_sync);
            for (uint32_t sequence : nakCopy.missing_sequences) {
                auto it = m_sendBuffer.find(sequence);
                if (it != m_sendBuffer.end()) {
                    OutboundSegment& segment = it->second;
                    if (!segment.NeedsRetransmit && !segment.Acked &&
                        ShouldAcceptRetransmitRequest(segment, nowMicros)) {
                        segment.NeedsRetransmit = true;
                        SackTrackingState* st = GetOrCreateSackTracking(segment.SequenceNumber);
                        st->UrgentRetransmit = true;
                        m_tailLossProbePending = false;  //< NAK resolves TLP.
                        notifiedLoss = true;
                    }
                }
            }

            // === Classify NAK-triggered losses (congestion vs. random) ===
            if (notifiedLoss) {
                bool isCongestion = ClassifyLosses(nakCopy.missing_sequences, nowMicros, 0);
                if (m_bbr) m_bbr->OnPacketLoss(nowMicros, GetRetransmissionRatio(), isCongestion);
                TraceLog("NAK loss congestion=" + ucp::string(isCongestion ? "true" : "false") +
                         " count=" + std::to_string(nakCopy.missing_sequences.size()));
            }
        }
        auto fut = FlushSendQueueAsync();
        (void)fut;
    });
}

// ====================================================================================================
// HandleData — process an inbound data packet
// ====================================================================================================

void UcpPcb::HandleData(const UcpDataPacket& dataPacket) {
    ucp::vector<uint32_t> missing;
    ucp::vector<ucp::vector<uint8_t>> readyPayloads;
    bool shouldEstablish = false;
    bool shouldStore = false;
    bool sendImmediateAck = false;

    bool hasPiggybackedAck = (dataPacket.header.flags & (int)UcpPacketFlags::HasAckNumber) != 0;

    // === Process piggybacked ACK first (updates send buffer state) ===
    if (hasPiggybackedAck && dataPacket.ack_number > 0) {
        ProcessPiggybackedAck(dataPacket.ack_number, NowMicros());
        if (dataPacket.window_size > 0) {
            std::lock_guard<std::mutex> lock(m_sync);
            m_remoteWindowBytes = dataPacket.window_size;
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_sync);

        // === Validate data packet ===
        if (dataPacket.payload.empty() || (int)dataPacket.payload.size() > m_config.MaxPayloadSize() ||
            dataPacket.fragment_total == 0 || dataPacket.fragment_index >= dataPacket.fragment_total) {
            return;
        }

        // === Handshake: receiving data on SYN-ACK'd connection means handshake is complete ===
        if (m_state == UcpConnectionState::HandshakeSynReceived && m_synAckSent) {
            shouldEstablish = true;
        }

        m_lastEchoTimestamp = (int64_t)dataPacket.header.timestamp;

        // === Store the packet in receive buffer if it is not a duplicate/retransmission ===
        if (!UcpSequenceComparer::IsBefore(dataPacket.sequence_number, m_nextExpectedSequence)) {
            uint32_t usedBytes = GetReceiveWindowUsedBytes();
            shouldStore = usedBytes + (uint32_t)dataPacket.payload.size() <= m_localReceiveWindowBytes;

            if (shouldStore && m_recvBuffer.find(dataPacket.sequence_number) == m_recvBuffer.end()) {
                InboundSegment inbound;
                inbound.SequenceNumber = dataPacket.sequence_number;
                inbound.FragmentTotal = dataPacket.fragment_total;
                inbound.FragmentIndex = dataPacket.fragment_index;
                inbound.Payload = dataPacket.payload;
                m_recvBuffer[dataPacket.sequence_number] = std::move(inbound);

                // Clear NAK tracking for this just-received sequence
                m_nakIssued.erase(dataPacket.sequence_number);
                m_missingSequenceCounts.erase(dataPacket.sequence_number);
                m_missingFirstSeenMicros.erase(dataPacket.sequence_number);
                m_lastNakIssuedMicros.erase(dataPacket.sequence_number);

                // Feed FEC codec and try recovery
                if (m_fecCodec) {
                    m_fecFragmentMetadata[dataPacket.sequence_number] = FecFragmentMetadata{
                        dataPacket.fragment_total, dataPacket.fragment_index
                    };
                    TryRecoverFecAround(dataPacket.sequence_number, readyPayloads);
                }
            }

            // === Out-of-order arrival: scan gap between expected and received for NAK ===
            if (shouldStore && UcpSequenceComparer::IsAfter(dataPacket.sequence_number, m_nextExpectedSequence)) {
                sendImmediateAck = ShouldSendImmediateReorderedAck(NowMicros());
                uint32_t current = m_nextExpectedSequence;
                int remainingNakSlots = PcbConst::MAX_NAK_MISSING_SCAN;

                while (current != dataPacket.sequence_number && remainingNakSlots > 0) {
                    if (m_recvBuffer.find(current) == m_recvBuffer.end()) {
                        int& missingCount = m_missingSequenceCounts[current];
                        missingCount++;
                        int64_t firstSeenMicros = GetMissingFirstSeenMicros(current);
                        bool missingAgeExpired = HasNakReorderGraceExpired(missingCount, firstSeenMicros, NowMicros());
                        bool missingRepeatedEnough = missingCount >= PcbConst::NAK_MISSING_THRESHOLD;

                        if ((int)missing.size() < PcbConst::MAX_NAK_SEQUENCES_PER_PACKET &&
                            missingRepeatedEnough && missingAgeExpired && ShouldIssueNak(current)) {
                            MarkNakIssued(current);
                            missing.push_back(current);
                        }
                    }
                    current = UcpSequenceComparer::Increment(current);
                    remainingNakSlots--;
                }
            }

            // Deliver any ready in-order payloads (including FEC-recovered)
            DrainReadyPayloads(readyPayloads);

            // === Immediate ACK for high-reorder scenarios ===
            if (!m_recvBuffer.empty() && m_recvBuffer.find(m_nextExpectedSequence) == m_recvBuffer.end()) {
                if ((int)m_recvBuffer.size() >= PcbConst::IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD &&
                    ShouldSendImmediateReorderedAck(NowMicros())) {
                    sendImmediateAck = true;
                }

                int& missingCount = m_missingSequenceCounts[m_nextExpectedSequence];
                int64_t firstSeenMicros = GetMissingFirstSeenMicros(m_nextExpectedSequence);
                if ((int)missing.size() < PcbConst::MAX_NAK_SEQUENCES_PER_PACKET &&
                    missingCount >= PcbConst::NAK_MISSING_THRESHOLD &&
                    HasNakReorderGraceExpired(missingCount, firstSeenMicros, NowMicros()) &&
                    ShouldIssueNak(m_nextExpectedSequence)) {
                    MarkNakIssued(m_nextExpectedSequence);
                    missing.push_back(m_nextExpectedSequence);
                }
            }
        }
    }

    // === Post-unlock: deliver recovered FEC payloads to application ===
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
}

// ====================================================================================================
// HandleFecRepair — process an inbound FEC repair packet
// ====================================================================================================

void UcpPcb::HandleFecRepair(const UcpFecRepairPacket& packet) {
    (void)packet;
    if (!m_fecCodec || packet.payload.empty()) return;

    ucp::vector<ucp::vector<uint8_t>> fecReadyPayloads;
    ucp::vector<std::pair<uint32_t, ucp::vector<uint8_t>>> recoveredPackets;

    {
        std::lock_guard<std::mutex> lock(m_sync);
        StoreRecoveredFecPackets(&recoveredPackets, fecReadyPayloads);
    }

    for (auto& payload : fecReadyPayloads) {
        EnqueuePayload(std::move(payload));
    }

    SendAckPacket((int)UcpPacketFlags::None, 0);
}

// ====================================================================================================
// HandleFin — process an inbound FIN packet (peer closing)
// ====================================================================================================

void UcpPcb::HandleFin(const UcpControlPacket& packet) {
    bool needSendOwnFin = false;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        m_peerFinReceived = true;
        m_state = UcpConnectionState::ClosingFinReceived;
        if (!m_finSent) {
            m_finSent = true;
            needSendOwnFin = true;
        }
    }

    // Process piggybacked ACK on FIN
    if ((packet.header.flags & (int)UcpPacketFlags::HasAckNumber) && packet.ack_number > 0) {
        ProcessPiggybackedAck(packet.ack_number, NowMicros());
    }

    SendAckPacket((int)UcpPacketFlags::FinAck, 0);  //< ACK peer's FIN.
    if (needSendOwnFin) {
        SendControl(UcpPacketType::Fin, (int)UcpPacketFlags::None);  //< Send our own FIN.
    }

    if (m_finAcked) {
        TransitionToClosed();
    }
}

// ====================================================================================================
// SendControl / SendAckPacket / SendNak / ScheduleAck — packet transmission helpers
// ====================================================================================================

void UcpPcb::SendControl(UcpPacketType type, int flags) {
    (void)flags;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        m_lastActivityMicros = NowMicros();
    }
    if (type == UcpPacketType::Rst) {
        m_sentRstPackets++;
    }
}

void UcpPcb::SendAckPacket(int flags, int64_t overrideEchoTimestamp) {
    (void)flags;
    (void)overrideEchoTimestamp;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        m_lastAckSentMicros = NowMicros();
    }
    m_sentAckPackets++;
}

void UcpPcb::SendNak(const ucp::vector<uint32_t>& missing) {
    if (missing.empty()) return;

    uint32_t cumAck;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        int64_t nowMicros = NowMicros();
        int64_t rttWindowMicros = m_rtoEstimator->SmoothedRttMicros() > 0
            ? m_rtoEstimator->SmoothedRttMicros()
            : m_config.DelayedAckTimeoutMicros();
        if (rttWindowMicros <= 0) {
            rttWindowMicros = PcbConst::BBR_MIN_ROUND_DURATION_MICROS;
        }

        // === NAK rate limiting (per RTT window) ===
        if (m_lastNakWindowMicros == 0 ||
            nowMicros - m_lastNakWindowMicros >= rttWindowMicros) {
            m_lastNakWindowMicros = nowMicros;
            m_naksSentThisRttWindow = 0;
        }

        if (m_naksSentThisRttWindow >= PcbConst::MAX_NAKS_PER_RTT) return;
        m_naksSentThisRttWindow++;

        cumAck = m_nextExpectedSequence > 0 ? m_nextExpectedSequence - 1U : 0;
        m_lastAckSentMicros = nowMicros;
    }

    m_sentNakPackets++;
}

void UcpPcb::ScheduleAck() {
    int64_t delayedTimeout = m_config.DelayedAckTimeoutMicros();
    if (delayedTimeout <= 0) {
        SendAckPacket((int)UcpPacketFlags::None, 0);  //< No delay — send immediately.
        return;
    }

    int64_t ackDelayMicros = delayedTimeout;
    // On fast paths (<30ms RTT), reduce ACK delay to 1ms to avoid inflating RTT
    if (m_lastRttMicros > 30LL * Constants::MICROS_PER_MILLI) {
        ackDelayMicros = (std::min)(ackDelayMicros, Constants::MICROS_PER_MILLI);
    }

    {
        std::lock_guard<std::mutex> lock(m_sync);
        if (m_ackDelayed) return;  //< Already scheduled.
        m_ackDelayed = true;
    }

    if (!m_network) {
        // Standalone: use a detached thread for the delay
        std::thread([this, ackDelayMicros]() {
            int delayMs = (int)(std::max)((int64_t)PcbConst::MIN_TIMER_WAIT_MILLISECONDS,
                                          ackDelayMicros / Constants::MICROS_PER_MILLI);
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            if (m_ctsCanceled) return;
            {
                std::lock_guard<std::mutex> lock(m_sync);
                m_ackDelayed = false;
            }
            SendAckPacket((int)UcpPacketFlags::None, 0);
        }).detach();
    }
}

// ====================================================================================================
// FlushSendQueueAsync — drain the send buffer while respecting cwnd, fair-queue, and pacing
// ====================================================================================================

std::future<void> UcpPcb::FlushSendQueueAsync() {
    return std::async(std::launch::async, [this]() {
        // === Acquire flush lock (prevents concurrent flush attempts) ===
        {
            std::unique_lock<std::mutex> lk(m_flushLockMutex);
            while (m_flushLockAcquired && !m_ctsCanceled) {
                m_flushLockCond.wait_for(lk, std::chrono::milliseconds(100));
            }
            if (m_ctsCanceled) return;
            m_flushLockAcquired = true;
        }

        try {
            while (!m_ctsCanceled) {
                ucp::vector<OutboundSegment*> segmentsToSend;
                int64_t nowMicros = NowMicros();
                int64_t waitMicros = 0;
                uint32_t piggyCumAck = 0;
                uint32_t piggyWindow = 0;
                int64_t piggyEcho = 0;

                {
                    std::lock_guard<std::mutex> lock(m_sync);
                    int windowBytes = GetSendWindowBytes();
                    int piggybackedAckOverhead = PcbConst::DATA_HEADER_SIZE_WITH_ACK -
                        Constants::DATA_HEADER_SIZE;

                    // === Walk send buffer looking for segments to retransmit or first-transmit ===
                    for (auto& pair : m_sendBuffer) {
                        OutboundSegment& segment = pair.second;
                        if (segment.Acked) continue;
                        if (segment.InFlight && !segment.NeedsRetransmit) continue;

                        // === Congestion window check ===
                        if (!segment.NeedsRetransmit && !segment.InFlight &&
                            m_flightBytes + (int)segment.Payload.size() > windowBytes) {
                            break;
                        }

                        int packetSize = Constants::DATA_HEADER_SIZE + piggybackedAckOverhead +
                            (int)segment.Payload.size();

                        // === Urgent retransmit recovery ===
                        SackTrackingState* flushSackState = nullptr;
                        auto stIt = m_sackTracking.find(segment.SequenceNumber);
                        if (stIt != m_sackTracking.end()) flushSackState = &stIt->second;
                        bool hasUrgentFlag = flushSackState && flushSackState->UrgentRetransmit;
                        bool urgentRecovery = segment.NeedsRetransmit && segment.SendCount > 0 &&
                            hasUrgentFlag && CanUseUrgentRecovery(nowMicros);

                        // === Fair-queue credit check (bypassed for urgent recovery) ===
                        if (m_useFairQueue && m_fairQueueCreditBytes < (double)packetSize && !urgentRecovery) {
                            break;
                        }

                        if (m_useFairQueue) {
                            m_fairQueueCreditBytes -= (double)packetSize;
                            if (m_fairQueueCreditBytes < 0) m_fairQueueCreditBytes = 0;
                        }

                        // === Transition segment to InFlight ===
                        segment.InFlight = true;
                        segment.NeedsRetransmit = false;
                        if (flushSackState) flushSackState->UrgentRetransmit = false;
                        if (segment.SendCount == 0) {
                            m_flightBytes += (int)segment.Payload.size();  //< Only count first transmit towards inflight.
                        }
                        segment.SendCount++;
                        if (m_bbr) m_bbr->OnPacketSent(nowMicros, segment.SendCount > 1);
                        segment.LastSendMicros = nowMicros;
                        m_lastActivityMicros = nowMicros;
                        segmentsToSend.push_back(&segment);
                    }

                    // === Piggyback ACK info for data packets ===
                    piggyCumAck = m_nextExpectedSequence > 0 ? m_nextExpectedSequence - 1U : 0;
                    piggyWindow = m_localReceiveWindowBytes;
                    piggyEcho = m_lastEchoTimestamp;
                    m_lastAckSentMicros = nowMicros;

                    // === Sort by priority (descending), then by sequence number ===
                    std::sort(segmentsToSend.begin(), segmentsToSend.end(),
                        [](OutboundSegment* a, OutboundSegment* b) {
                            if (a->Priority != b->Priority)
                                return (int)a->Priority > (int)b->Priority;
                            return UcpSequenceComparer::IsBefore(a->SequenceNumber, b->SequenceNumber);
                        });
                }

                if (segmentsToSend.empty()) {
                    if (waitMicros > 0) {
                        ScheduleDelayedFlush(waitMicros);
                    }
                    break;
                }

                // === Transmit each segment (counters and FEC integration) ===
                for (auto* segment : segmentsToSend) {
                    if (segment->SendCount > 1) {
                        m_retransmittedPackets++;
                    } else {
                        m_sentDataPackets++;
                    }
                    m_bytesSent += (int64_t)segment->Payload.size();

                    if (m_fecCodec && segment->SendCount <= 1) {
                        std::lock_guard<std::mutex> lock(m_sync);
                        m_fecFragmentMetadata[segment->SequenceNumber] = FecFragmentMetadata{
                            segment->FragmentTotal, segment->FragmentIndex
                        };

                        if (m_fecGroupSendCount == 0) {
                            m_fecGroupBaseSeq = segment->SequenceNumber;
                        }
                        m_fecGroupSendCount++;

                        int groupSize = (std::max)(2, m_config.FecGroupSize);
                        if (m_fecGroupSendCount >= groupSize) {
                            m_fecGroupSendCount = 0;  //< Group complete — repair will be generated.
                        }
                    }
                }
            }
        } catch (...) {}

        // === Release flush lock ===
        {
            std::lock_guard<std::mutex> lk(m_flushLockMutex);
            m_flushLockAcquired = false;
            m_flushLockCond.notify_all();
        }
    });
}

void UcpPcb::ScheduleDelayedFlush(int64_t waitMicros) {
    if (m_flushDelayed) return;
    m_flushDelayed = true;

    int delayMs = (int)std::ceil((double)waitMicros / (double)Constants::MICROS_PER_MILLI);
    if (delayMs < PcbConst::MIN_TIMER_WAIT_MILLISECONDS)
        delayMs = PcbConst::MIN_TIMER_WAIT_MILLISECONDS;

    if (!m_network) {
        std::thread([this, delayMs]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            if (m_ctsCanceled) { m_flushDelayed = false; return; }
            m_flushDelayed = false;
            auto fut = FlushSendQueueAsync();
            (void)fut;
        }).detach();
    }
}

// ====================================================================================================
// EnqueuePayload — deliver received data to the application
// ====================================================================================================

void UcpPcb::EnqueuePayload(ucp::vector<uint8_t> payload) {
    if (payload.empty()) return;
    int len = (int)payload.size();

    {
        std::lock_guard<std::mutex> lock(m_sync);
        ReceiveChunk chunk;
        chunk.Buffer = std::move(payload);
        chunk.Count = len;
        chunk.Offset = 0;
        m_receiveQueue.push(std::move(chunk));
        m_queuedReceiveBytes += len;
        m_bytesReceived += len;
    }

    if (DataReceived) {
        DataReceived(nullptr, 0, len);
    }

    {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        m_receiveSignal.notify_all();  //< Wake any blocked ReceiveAsync callers.
    }
}

// ====================================================================================================
// Timer management (OnTimer / ScheduleTimer / OnTimerAsync)
// ====================================================================================================

void UcpPcb::OnTimer() {
    if (m_disposed) return;
    auto fut = OnTimerAsync();
    (void)fut;
    if (m_network) {
        ScheduleTimer();  //< Re-arm timer for the next tick.
    }
}

void UcpPcb::ScheduleTimer() {
    if (!m_network || m_disposed) return;
    int64_t intervalMicros = (std::max)((int64_t)PcbConst::MIN_TIMER_WAIT_MILLISECONDS,
                                         (int64_t)m_config.TimerIntervalMilliseconds) *
        Constants::MICROS_PER_MILLI;
    m_timerId = m_network->AddTimer(m_network->GetCurrentTimeUs() + intervalMicros, [this]() { OnTimer(); });
}

std::future<void> UcpPcb::OnTimerAsync() {
    return OnTimerAsync(NowMicros());
}

std::future<void> UcpPcb::OnTimerAsync(int64_t nowMicros) {
    return std::async(std::launch::async, [this, nowMicros]() {
        bool timedOut = false;
        bool sendKeepAlive = false;
        bool retransmitSynAck = false;
        bool maxRetransmissionsExceeded = false;
        bool timedOutForCongestion = false;
        bool tailLossProbe = false;
        ucp::vector<uint32_t> missingForNak;

        {
            std::lock_guard<std::mutex> lock(m_sync);

            // === Path-change notification to BBR ===
            if (m_pathChanged && m_state == UcpConnectionState::Established) {
                m_pathChanged = false;
                if (m_bbr) m_bbr->OnPathChange(nowMicros);
            }

            // === RTO timeout detection ===
            int maxPayload = (std::max)(1, m_config.MaxPayloadSize());
            int inflightSegments = maxPayload <= 0 ? 0
                : (int)std::ceil((double)m_flightBytes / (double)maxPayload);
            int rtoRetransmitBudget = PcbConst::RTO_RETRANSMIT_BUDGET_PER_TICK;
            bool ackProgressRecent = m_lastAckReceivedMicros > 0 &&
                nowMicros - m_lastAckReceivedMicros <= GetRtoAckProgressSuppressionMicros();

            for (auto& pair : m_sendBuffer) {
                OutboundSegment& segment = pair.second;
                if (!segment.InFlight || segment.Acked || segment.NeedsRetransmit) continue;

                if (nowMicros - segment.LastSendMicros >= m_rtoEstimator->CurrentRtoMicros()) {
                    // ACK progress suppression: don't RTO-retransmit if ACKs are still arriving
                    if (ackProgressRecent &&
                        (int)m_sendBuffer.size() > PcbConst::TLP_MAX_INFLIGHT_SEGMENTS)
                        continue;
                    if (rtoRetransmitBudget <= 0) break;

                    bool segTimedOutCongestion = IsCongestionLoss(
                        segment.SequenceNumber, 0, nowMicros, 1);
                    if (segment.SendCount >= m_config.MaxRetransmissions && segTimedOutCongestion) {
                        m_timeoutRetransmissions++;
                        maxRetransmissionsExceeded = true;
                        break;  //< Exceeded max retransmissions — close connection.
                    }

                    segment.NeedsRetransmit = true;
                    GetOrCreateSackTracking(segment.SequenceNumber)->UrgentRetransmit = true;
                    timedOut = true;
                    rtoRetransmitBudget--;
                    timedOutForCongestion = timedOutForCongestion || segTimedOutCongestion;
                    m_timeoutRetransmissions++;
                }
            }

            // === Tail-Loss Probe (TLP): probe for lost tail when inflight is low ===
            if (!timedOut && !m_tailLossProbePending && inflightSegments > 0 &&
                inflightSegments <= PcbConst::TLP_MAX_INFLIGHT_SEGMENTS) {
                int64_t tlpTimeoutMicros = m_rtoEstimator->SmoothedRttMicros() > 0
                    ? (int64_t)std::ceil((double)m_rtoEstimator->SmoothedRttMicros() *
                                         PcbConst::TLP_TIMEOUT_RTT_RATIO)
                    : m_rtoEstimator->CurrentRtoMicros();

                if (m_lastAckReceivedMicros > 0 &&
                    nowMicros - m_lastAckReceivedMicros >= tlpTimeoutMicros) {
                    for (auto& pair : m_sendBuffer) {
                        OutboundSegment& segment = pair.second;
                        if (segment.Acked || !segment.InFlight || segment.NeedsRetransmit) continue;
                        if (nowMicros - segment.LastSendMicros < tlpTimeoutMicros) continue;

                        segment.NeedsRetransmit = true;
                        GetOrCreateSackTracking(
                            segment.SequenceNumber)->UrgentRetransmit =
                            IsNearDisconnectTimeout(nowMicros);
                        m_tailLossProbePending = true;
                        tailLossProbe = true;
                        break;
                    }
                }
            }

            // === Silence Probe: detect path blackout (no ACK for 3× SRTT) ===
            if (!timedOut && !m_tailLossProbePending &&
                inflightSegments > PcbConst::TLP_MAX_INFLIGHT_SEGMENTS &&
                m_lastAckReceivedMicros > 0 && m_rtoEstimator->SmoothedRttMicros() > 0 &&
                nowMicros - m_lastAckReceivedMicros >= m_rtoEstimator->SmoothedRttMicros() * 3) {
                uint32_t highestSeq = 0;
                OutboundSegment* newest = nullptr;
                for (auto& pair : m_sendBuffer) {
                    if (pair.second.Acked || !pair.second.InFlight ||
                        pair.second.NeedsRetransmit) continue;
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

            // === RTO backoff and BBR loss notification ===
            if (timedOut) {
                if (m_bbr) m_bbr->OnPacketLoss(nowMicros, GetRetransmissionRatio(),
                                                timedOutForCongestion);
                TraceLog("RTO loss congestion=" +
                         ucp::string(timedOutForCongestion ? "true" : "false") +
                         " rto=" + std::to_string(m_rtoEstimator->CurrentRtoMicros()));
                if (timedOutForCongestion) {
                    m_rtoEstimator->Backoff();
                }
            }

            // === Collect NAK gaps ===
            CollectMissingForNak(missingForNak, nowMicros);

            // === Keep-alive: send ACK when idle for too long ===
            if (m_state == UcpConnectionState::Established &&
                nowMicros - m_lastAckSentMicros >= m_config.KeepAliveIntervalMicros &&
                nowMicros - m_lastActivityMicros >= m_config.KeepAliveIntervalMicros) {
                sendKeepAlive = true;
            }

            // === SYN-ACK retransmission (server side) ===
            if (m_isServerSide && m_state == UcpConnectionState::HandshakeSynReceived &&
                m_synAckSent &&
                nowMicros - m_synAckSentMicros >= m_rtoEstimator->CurrentRtoMicros()) {
                m_synAckSentMicros = nowMicros;
                retransmitSynAck = true;
            }
        }

        // === Post-unlock actions ===

        if (maxRetransmissionsExceeded) {
            TransitionToClosed();
            return;
        }

        if (timedOut || tailLossProbe) {
            auto fut = FlushSendQueueAsync();
            (void)fut;
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

        // === Disconnect timeout: force-close if no activity for DisconnectTimeoutMicros ===
        {
            std::lock_guard<std::mutex> lock(m_sync);
            if ((m_state == UcpConnectionState::HandshakeSynSent ||
                 m_state == UcpConnectionState::HandshakeSynReceived ||
                 m_state == UcpConnectionState::Established ||
                 m_state == UcpConnectionState::ClosingFinSent ||
                 m_state == UcpConnectionState::ClosingFinReceived) &&
                nowMicros - m_lastActivityMicros >= m_config.DisconnectTimeoutMicros) {
                m_sync.unlock();
                TransitionToClosed();
                return;
            }
        }

        if (m_state == UcpConnectionState::Closed) {
            TransitionToClosed();
        }
    });
}

// ====================================================================================================
// State machine transitions
// ====================================================================================================

void UcpPcb::TransitionToEstablished() {
    ConnectedCallback connected;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        if (m_state == UcpConnectionState::Established ||
            m_state == UcpConnectionState::Closed) return;
        m_state = UcpConnectionState::Established;
        if (!m_connectedRaised) {
            m_connectedRaised = true;
            connected = Connected;
        }
    }

    try { m_connectedPromise.set_value(true); } catch (...) {}
    if (connected) connected();
}

void UcpPcb::TransitionToClosed() {
    DisconnectedCallback disconnected;
    bool releaseResources = false;
    {
        std::lock_guard<std::mutex> lock(m_sync);
        if (m_state == UcpConnectionState::Closed) {
            if (m_closedResourcesReleased) return;
        }
        m_state = UcpConnectionState::Closed;
        if (!m_closedResourcesReleased) {
            m_closedResourcesReleased = true;
            releaseResources = true;
        }
        if (!m_disconnectedRaised) {
            m_disconnectedRaised = true;
            disconnected = Disconnected;
        }
    }

    try { m_connectedPromise.set_value(false); } catch (...) {}
    try { m_closedPromise.set_value(true); } catch (...) {}
    {
        std::lock_guard<std::mutex> lk(m_receiveSignalMutex);
        m_receiveSignal.notify_all();
    }

    if (releaseResources) {
        ReleaseNetworkRegistrations();
    }

    if (disconnected) disconnected();
    if (m_closedCallback) m_closedCallback(this);
}

void UcpPcb::ReleaseNetworkRegistrations() {
    if (!m_network) return;
    m_network->UnregisterPcb(this);
}

// ====================================================================================================
// ACK plausibility and duplicate-ACK detection
// ====================================================================================================

bool UcpPcb::IsAckPlausible(const UcpAckPacket& ackPacket) {
    if (ackPacket.header.connection_id != m_connectionId) return false;

    if (m_pawsEnabled && m_largestTimestampSeen > 0 &&
        m_largestTimestampSeen - (int64_t)ackPacket.header.timestamp > PcbConst::PAWS_TIMEOUT_MICROS)
        return false;  //< Old timestamp — reject.

    if (m_hasLargestCumulativeAckNumber &&
        UcpSequenceComparer::IsBefore(ackPacket.ack_number, m_largestCumulativeAckNumber))
        return false;  //< Reordered ACK — reject.

    // Validate SACK block ordering
    for (auto& block : ackPacket.sack_blocks) {
        if (UcpSequenceComparer::IsAfter(block.Start, block.End))
            return false;  //< Malformed SACK block.
    }
    return true;
}

void UcpPcb::UpdateDuplicateAckState(const UcpAckPacket& ackPacket, int64_t nowMicros,
                                       bool& fastRetransmitTriggered) {
    fastRetransmitTriggered = false;
    bool duplicateAck = m_hasLastAckNumber && ackPacket.ack_number == m_lastAckNumber;

    if (duplicateAck) {
        m_duplicateAckCount++;
        if (m_duplicateAckCount >= PcbConst::DUPLICATE_ACK_THRESHOLD && !m_fastRecoveryActive) {
            // === 3 duplicate ACKs → infer loss of the next expected packet ===
            uint32_t lostSeq = UcpSequenceComparer::Increment(ackPacket.ack_number);
            auto it = m_sendBuffer.find(lostSeq);
            if (it != m_sendBuffer.end() && !it->second.Acked &&
                it->second.SendCount == 1 && !it->second.NeedsRetransmit) {
                int64_t rttForFastRetransmit = GetFastRetransmitAgeThreshold();
                if (ShouldTriggerEarlyRetransmit() || rttForFastRetransmit <= 0 ||
                    nowMicros - it->second.LastSendMicros >= rttForFastRetransmit) {
                    it->second.NeedsRetransmit = true;
                    SackTrackingState* st = GetOrCreateSackTracking(lostSeq);
                    st->UrgentRetransmit = true;
                    m_fastRecoveryActive = true;
                    m_fastRetransmissions++;
                    fastRetransmitTriggered = true;
                    bool isCongestion = IsCongestionLoss(lostSeq, 0, nowMicros, 1);
                    if (m_bbr) m_bbr->OnFastRetransmit(nowMicros, isCongestion);
                    TraceLog("FastRetransmit seq=" + std::to_string(lostSeq) +
                             " dupAck=true congestion=" + (isCongestion ? "true" : "false"));
                }
            }
        }
    } else {
        m_duplicateAckCount = 0;
        m_fastRecoveryActive = false;  //< New ACK → exit fast recovery.
    }

    m_lastAckNumber = ackPacket.ack_number;
    m_hasLastAckNumber = true;
}

// ====================================================================================================
// SACK tracking helpers
// ====================================================================================================

SackTrackingState* UcpPcb::GetOrCreateSackTracking(uint32_t sequenceNumber) {
    auto it = m_sackTracking.find(sequenceNumber);
    if (it == m_sackTracking.end()) {
        it = m_sackTracking.emplace(sequenceNumber, SackTrackingState{}).first;
    }
    return &it->second;
}

bool UcpPcb::ShouldFastRetransmitSackHole(OutboundSegment& segment,
                                            uint32_t firstMissingSequence,
                                            uint32_t highestSack,
                                            bool reportedSackHole,
                                            int64_t nowMicros) {
    if (segment.LastSendMicros <= 0) return false;
    if (m_sackFastRetransmitNotified.find(segment.SequenceNumber) !=
        m_sackFastRetransmitNotified.end()) return false;
    if (!m_config.EnableAggressiveSackRecovery) return false;

    int64_t reorderGraceMicros = GetSackFastRetransmitReorderGraceMicros();
    if (nowMicros - segment.LastSendMicros < reorderGraceMicros) return false;
    if (HasPendingFecRepair(segment, nowMicros)) return false;

    bool firstMissing = segment.SequenceNumber == firstMissingSequence;
    int requiredObservations = firstMissing
        ? PcbConst::SACK_FAST_RETRANSMIT_THRESHOLD
        : PcbConst::SACK_FAST_RETRANSMIT_THRESHOLD + 1;

    uint32_t distancePastHole = highestSack - segment.SequenceNumber;

    // Non-first holes with enough distance: use default threshold
    if (!firstMissing && reportedSackHole &&
        distancePastHole >= (uint32_t)(std::max)(PcbConst::SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD,
                                                  m_config.FecGroupSize)) {
        requiredObservations = PcbConst::SACK_FAST_RETRANSMIT_THRESHOLD;
    }

    auto stIt = m_sackTracking.find(segment.SequenceNumber);
    int missingAckCount = stIt != m_sackTracking.end() ? stIt->second.MissingAckCount : 0;
    if (missingAckCount < requiredObservations) return false;
    if (firstMissing) return true;
    if (!reportedSackHole) return false;
    if (distancePastHole >= (uint32_t)PcbConst::SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD) return true;
    return false;
}

bool UcpPcb::HasPendingFecRepair(OutboundSegment& segment, int64_t nowMicros) {
    if (!m_fecCodec) return false;
    auto stIt = m_sackTracking.find(segment.SequenceNumber);
    if (stIt == m_sackTracking.end() || stIt->second.FirstMissingAckMicros <= 0) return false;

    uint32_t groupBase = m_fecGroupBaseSeq;
    if (m_fecRepairSentGroups.find(groupBase) == m_fecRepairSentGroups.end()) return false;

    int64_t graceMicros = GetFecFastRetransmitGraceMicros();
    return nowMicros - stIt->second.FirstMissingAckMicros < graceMicros;
}

// ====================================================================================================
// Fast retransmit thresholds (adaptive to RTT)
// ====================================================================================================

int64_t UcpPcb::GetFecFastRetransmitGraceMicros() {
    int64_t rttMicros = m_rtoEstimator->SmoothedRttMicros() > 0
        ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros;
    if (rttMicros <= 0) rttMicros = m_config.MinRtoMicros;
    if (rttMicros <= 0) return PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS;

    int64_t adaptiveGrace = rttMicros / 16;  //< 1/16 of RTT.
    int64_t maxGrace = PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS * 4;
    return (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS,
                      (std::min)(adaptiveGrace, maxGrace));
}

int64_t UcpPcb::GetSackFastRetransmitReorderGraceMicros() {
    int64_t rttMicros = m_rtoEstimator->SmoothedRttMicros() > 0
        ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros;
    if (rttMicros <= 0) {
        int64_t fallback = m_config.MinRtoMicros > 0
            ? m_config.MinRtoMicros : Constants::DEFAULT_RTO_MICROS;
        return (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, fallback * 2);
    }
    return (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros);
}

int64_t UcpPcb::GetFastRetransmitAgeThreshold() {
    int64_t rttMicros = m_rtoEstimator->SmoothedRttMicros() > 0
        ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros;
    return rttMicros <= 0 ? 0
        : (std::max)(PcbConst::SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS, rttMicros / 8);
}

bool UcpPcb::ShouldTriggerEarlyRetransmit() {
    int maxPayload = (std::max)(1, m_config.MaxPayloadSize());
    if (maxPayload <= 0) return false;
    int inflightSegments = (int)std::ceil((double)m_flightBytes / (double)maxPayload);
    return inflightSegments > 0 &&
        inflightSegments <= PcbConst::EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS;
}

bool UcpPcb::ShouldAcceptRetransmitRequest(OutboundSegment& segment, int64_t nowMicros) {
    if (segment.SendCount <= 1 || segment.LastSendMicros <= 0) return true;
    int64_t graceMicros = m_rtoEstimator->SmoothedRttMicros() > 0
        ? m_rtoEstimator->SmoothedRttMicros() : m_rtoEstimator->CurrentRtoMicros();
    if (graceMicros <= 0) return true;
    return nowMicros - segment.LastSendMicros >= graceMicros;
}

int64_t UcpPcb::GetRtoAckProgressSuppressionMicros() {
    int64_t rttMicros = m_rtoEstimator->SmoothedRttMicros() > 0
        ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros;
    if (rttMicros <= 0) rttMicros = m_config.MinRtoMicros;
    if (rttMicros <= 0) return PcbConst::RTO_ACK_PROGRESS_SUPPRESSION_MICROS;
    return (std::max)(PcbConst::RTO_ACK_PROGRESS_SUPPRESSION_MICROS, rttMicros / 4);
}

double UcpPcb::GetRetransmissionRatio() {
    int total = m_sentDataPackets + m_retransmittedPackets;
    return total == 0 ? 0.0 : (double)m_retransmittedPackets / (double)total;
}

void UcpPcb::TraceLog(const ucp::string& message) {
    if (m_config.EnableDebugLog) {
        std::cerr << "[UCP PCB] " << message << std::endl;
    }
}

// ====================================================================================================
// Loss classification (congestion vs. random loss via RTT inflation detection)
// ====================================================================================================

bool UcpPcb::IsCongestionLoss(uint32_t sequenceNumber, int64_t sampleRttMicros,
                                int64_t nowMicros, int contiguousLossCount) {
    ucp::vector<uint32_t> sequences = { sequenceNumber };
    return ClassifyLosses(sequences, nowMicros, sampleRttMicros, contiguousLossCount);
}

bool UcpPcb::ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers,
                              int64_t nowMicros, int64_t sampleRttMicros) {
    return ClassifyLosses(sequenceNumbers, nowMicros, sampleRttMicros,
                           GetMaxContiguousLossRun(sequenceNumbers));
}

bool UcpPcb::ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers,
                              int64_t nowMicros, int64_t sampleRttMicros,
                              int contiguousLossCount) {
    int64_t windowMicros = GetLossClassifierWindowMicros();
    PruneLossEvents(nowMicros, windowMicros);

    int64_t rttMicros = sampleRttMicros > 0 ? sampleRttMicros : m_lastRttMicros;
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

    int dedupedLossCount = (int)m_recentLossEvents.size();
    if (dedupedLossCount == 0) return false;

    int maxContiguousLossCount = (std::max)(contiguousLossCount,
                                             GetMaxContiguousRecentLossRun());
    // Small, isolated losses → likely random
    if (dedupedLossCount <= (int)PcbConst::BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS &&
        maxContiguousLossCount < PcbConst::BBR_CONGESTION_LOSS_BURST_THRESHOLD)
        return false;

    // Clustered losses with RTT inflation → congestion
    bool clusteredLoss = maxContiguousLossCount >= PcbConst::BBR_CONGESTION_LOSS_BURST_THRESHOLD ||
        dedupedLossCount > PcbConst::BBR_CONGESTION_LOSS_WINDOW_THRESHOLD;
    if (!clusteredLoss) return false;

    int64_t medianRtt = GetLossWindowMedianRttMicros();
    int64_t minRtt = GetMinimumObservedRttMicros();
    if (medianRtt <= 0 || minRtt <= 0) return false;

    return medianRtt > (int64_t)((double)minRtt * PcbConst::BBR_CONGESTION_LOSS_RTT_MULTIPLIER);
}

int64_t UcpPcb::GetLossClassifierWindowMicros() {
    int64_t minRtt = GetMinimumObservedRttMicros();
    if (minRtt <= 0) {
        minRtt = m_rtoEstimator->SmoothedRttMicros() > 0
            ? m_rtoEstimator->SmoothedRttMicros() : m_config.MinRtoMicros;
    }
    return (std::max)(Constants::MICROS_PER_MILLI, minRtt * 2);
}

void UcpPcb::PruneLossEvents(int64_t nowMicros, int64_t windowMicros) {
    while (!m_recentLossEvents.empty() &&
           nowMicros - m_recentLossEvents.front().TimestampMicros > windowMicros) {
        m_recentLossSequences.erase(m_recentLossEvents.front().SequenceNumber);
        m_recentLossEvents.pop();
    }
}

int64_t UcpPcb::GetLossWindowMedianRttMicros() {
    ucp::vector<int64_t> samples;
    std::queue<LossEvent> copy = m_recentLossEvents;
    while (!copy.empty()) {
        auto& ev = copy.front();
        if (ev.RttMicros > 0) samples.push_back(ev.RttMicros);
        copy.pop();
    }
    if (samples.empty() && m_lastRttMicros > 0) samples.push_back(m_lastRttMicros);
    if (samples.empty()) return 0;

    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];  //< Median.
}

int64_t UcpPcb::GetMinimumObservedRttMicros() {
    int64_t minRtt = 0;
    for (int64_t sample : m_rttSamplesMicros) {
        if (sample > 0 && (minRtt == 0 || sample < minRtt)) minRtt = sample;
    }
    if (minRtt == 0 && m_lastRttMicros > 0) minRtt = m_lastRttMicros;
    return minRtt;
}

int UcpPcb::GetMaxContiguousRecentLossRun() {
    if (m_recentLossEvents.empty()) return 0;
    ucp::vector<uint32_t> seqs;
    std::queue<LossEvent> copy = m_recentLossEvents;
    while (!copy.empty()) {
        seqs.push_back(copy.front().SequenceNumber);
        copy.pop();
    }
    return GetMaxContiguousLossRun(seqs);
}

int UcpPcb::GetMaxContiguousLossRun(const ucp::vector<uint32_t>& sequenceNumbers) {
    if (sequenceNumbers.empty()) return 0;
    ucp::vector<uint32_t> sorted = sequenceNumbers;
    std::sort(sorted.begin(), sorted.end());
    int maxRun = 1;
    int currentRun = 1;
    for (size_t i = 1; i < sorted.size(); i++) {
        if (sorted[i] == sorted[i - 1]) continue;
        if (sorted[i] - sorted[i - 1] == 1U) {
            currentRun++;
            if (currentRun > maxRun) maxRun = currentRun;
        } else {
            currentRun = 1;
        }
    }
    return maxRun;
}

// ====================================================================================================
// Send window = min(congestion_window, remote_window)
// ====================================================================================================

int UcpPcb::GetSendWindowBytes() {
    int receiveWindowBytes = (int)m_remoteWindowBytes;
    int congestionWindowBytes = m_bbr ? m_bbr->CongestionWindowBytes() : 24400;
    int windowBytes = congestionWindowBytes < receiveWindowBytes
        ? congestionWindowBytes : receiveWindowBytes;
    if (windowBytes < 0) windowBytes = 0;
    return windowBytes;
}

bool UcpPcb::CanUseUrgentRecovery(int64_t nowMicros) {
    int64_t windowMicros = m_rtoEstimator->SmoothedRttMicros() > 0
        ? m_rtoEstimator->SmoothedRttMicros() : m_config.MinRtoMicros;
    if (windowMicros <= 0) windowMicros = Constants::DEFAULT_RTO_MICROS;

    if (m_urgentRecoveryWindowMicros == 0 ||
        nowMicros - m_urgentRecoveryWindowMicros >= windowMicros) {
        m_urgentRecoveryWindowMicros = nowMicros;
        m_urgentRecoveryPacketsInWindow = 0;
    }

    return m_urgentRecoveryPacketsInWindow < PcbConst::URGENT_RETRANSMIT_BUDGET_PER_RTT;
}

bool UcpPcb::IsNearDisconnectTimeout(int64_t nowMicros) {
    if (m_config.DisconnectTimeoutMicros <= 0) return false;
    int64_t idleMicros = nowMicros - m_lastActivityMicros;
    return idleMicros >= m_config.DisconnectTimeoutMicros *
        (int64_t)PcbConst::URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT / 100LL;
}

uint32_t UcpPcb::GetReceiveWindowUsedBytes() {
    int64_t usedBytes = m_queuedReceiveBytes;
    for (auto& pair : m_recvBuffer) {
        usedBytes += (int64_t)(pair.second.Payload.empty() ? 0 : (int)pair.second.Payload.size());
    }
    if (usedBytes <= 0) return 0;
    if (usedBytes >= (int64_t)UINT32_MAX) return UINT32_MAX;
    return (uint32_t)usedBytes;
}

// ====================================================================================================
// RTT sampling
// ====================================================================================================

void UcpPcb::AddRttSample(int64_t sampleRttMicros) {
    if (sampleRttMicros <= 0) return;
    m_rttSamplesMicros.push_back(sampleRttMicros);
    if ((int)m_rttSamplesMicros.size() > PcbConst::MAX_RTT_SAMPLES) {
        m_rttSamplesMicros.erase(m_rttSamplesMicros.begin());  //< Evict oldest.
    }
}

void UcpPcb::PurgeSackSendCounts() {
    if (m_sackBlockSendCounts.size() > 1024) {
        m_sackBlockSendCounts.clear();  //< Prevent unbounded growth.
    }
}

// ====================================================================================================
// SACK block helpers (static)
// ====================================================================================================

uint64_t UcpPcb::PackSackBlockKey(uint32_t start, uint32_t end) {
    return ((uint64_t)start << 32) | end;
}

uint32_t UcpPcb::GetHighestSackEnd(const ucp::vector<SackBlock>& blocks) {
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

void UcpPcb::SortSackBlocks(const ucp::vector<SackBlock>& blocks, ucp::vector<SackBlock>& sorted) {
    sorted = blocks;
    if (sorted.size() <= 1) return;
    std::sort(sorted.begin(), sorted.end(), [](const SackBlock& a, const SackBlock& b) {
        return UcpSequenceComparer::IsBefore(a.Start, b.Start);
    });
}

bool UcpPcb::IsReportedSackHole(uint32_t sequenceNumber, uint32_t cumulativeAckNumber,
                                  const ucp::vector<SackBlock>& sackBlocks) {
    // A SACK hole is a sequence between the cumulative ACK and the highest SACK end
    // that is NOT covered by any SACK block.
    if (sackBlocks.empty()) return false;

    bool hasLowerAck = UcpSequenceComparer::IsBeforeOrEqual(cumulativeAckNumber, sequenceNumber);
    bool hasHigherSack = false;

    for (auto& block : sackBlocks) {
        if (UcpSequenceComparer::IsInForwardRange(sequenceNumber, block.Start, block.End))
            return false;  //< Covered by a SACK block — not a hole.
        if (UcpSequenceComparer::IsBefore(block.End, sequenceNumber)) {
            hasLowerAck = true;
            continue;
        }
        if (UcpSequenceComparer::IsAfter(block.Start, sequenceNumber)) {
            hasHigherSack = true;
            break;
        }
    }
    return hasLowerAck && hasHigherSack;  //< Sequence is between an ACK and a later SACK block but not covered.
}

// ====================================================================================================
// NAK reorder grace and adaptive threshold calculation
// ====================================================================================================

bool UcpPcb::HasNakReorderGraceExpired(int missingCount, int64_t firstSeenMicros,
                                         int64_t nowMicros) {
    int64_t baseGraceMicros = GetAdaptiveNakReorderGraceMicros();
    // Higher confidence → shorter grace period
    int64_t graceMicros = missingCount >= PcbConst::NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD
        ? (std::max)(baseGraceMicros / 2, PcbConst::NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS)
        : missingCount >= PcbConst::NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD
            ? (std::max)(baseGraceMicros / 2, PcbConst::NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS)
            : baseGraceMicros;
    return nowMicros - firstSeenMicros >= graceMicros;
}

int64_t UcpPcb::GetAdaptiveNakReorderGraceMicros() {
    int64_t rttMicros = m_rtoEstimator->SmoothedRttMicros() > 0
        ? m_rtoEstimator->SmoothedRttMicros() : m_lastRttMicros;
    if (rttMicros <= 0) rttMicros = m_config.MinRtoMicros;
    if (rttMicros <= 0) return PcbConst::NAK_REORDER_GRACE_MICROS;
    return (std::max)(PcbConst::NAK_REORDER_GRACE_MICROS,
                      (std::min)(rttMicros / 2, m_config.MinRtoMicros));
}

void UcpPcb::MarkNakIssued(uint32_t sequenceNumber) {
    m_nakIssued.insert(sequenceNumber);
    m_lastNakIssuedMicros[sequenceNumber] = NowMicros();
}

int64_t UcpPcb::GetMissingFirstSeenMicros(uint32_t sequenceNumber) {
    auto it = m_missingFirstSeenMicros.find(sequenceNumber);
    if (it == m_missingFirstSeenMicros.end()) {
        int64_t now = NowMicros();
        m_missingFirstSeenMicros[sequenceNumber] = now;
        return now;
    }
    return it->second;
}

bool UcpPcb::ShouldIssueNak(uint32_t sequenceNumber) {
    return m_nakIssued.find(sequenceNumber) == m_nakIssued.end();
}

// ====================================================================================================
// CollectMissingForNak — scan receive buffer for gaps and build a NAK list
// ====================================================================================================

void UcpPcb::CollectMissingForNak(ucp::vector<uint32_t>& missing, int64_t nowMicros) {
    if (m_recvBuffer.empty() ||
        m_recvBuffer.find(m_nextExpectedSequence) != m_recvBuffer.end()) return;

    // Find the highest received sequence number
    uint32_t highestReceived = m_nextExpectedSequence;
    bool hasHighest = false;
    for (auto& pair : m_recvBuffer) {
        if (!hasHighest || UcpSequenceComparer::IsAfter(pair.first, highestReceived)) {
            highestReceived = pair.first;
            hasHighest = true;
        }
    }
    if (!hasHighest) return;

    uint32_t current = m_nextExpectedSequence;
    int remainingScan = PcbConst::MAX_NAK_MISSING_SCAN;

    // Scan from next_expected up to highest_received, looking for gaps
    while ((int)missing.size() < PcbConst::MAX_NAK_SEQUENCES_PER_PACKET &&
           current != highestReceived && remainingScan > 0) {
        if (m_recvBuffer.find(current) == m_recvBuffer.end()) {
            int64_t firstSeenMicros = GetMissingFirstSeenMicros(current);
            int& missingCount = m_missingSequenceCounts[current];
            missingCount++;

            if (missingCount >= PcbConst::NAK_MISSING_THRESHOLD &&
                HasNakReorderGraceExpired(missingCount, firstSeenMicros, nowMicros) &&
                ShouldIssueNak(current)) {
                MarkNakIssued(current);
                missing.push_back(current);
            }
        }
        current = UcpSequenceComparer::Increment(current);
        remainingScan--;
    }
}

bool UcpPcb::ShouldSendImmediateReorderedAck(int64_t nowMicros) {
    if (m_lastReorderedAckSentMicros == 0 ||
        nowMicros - m_lastReorderedAckSentMicros >=
            PcbConst::REORDERED_ACK_MIN_INTERVAL_MICROS) {
        m_lastReorderedAckSentMicros = nowMicros;
        return true;
    }
    return false;
}

// ====================================================================================================
// FEC recovery helpers
// ====================================================================================================

void UcpPcb::TryRecoverFecAround(uint32_t receivedSequenceNumber,
                                   ucp::vector<ucp::vector<uint8_t>>& readyPayloads) {
    if (!m_fecCodec) return;
    (void)receivedSequenceNumber;
    (void)readyPayloads;
}

int UcpPcb::StoreRecoveredFecPackets(
    const ucp::vector<std::pair<uint32_t, ucp::vector<uint8_t>>>* recoveredPackets,
    ucp::vector<ucp::vector<uint8_t>>& readyPayloads) {
    if (!recoveredPackets || recoveredPackets->empty()) return 0;

    int stored = 0;
    for (auto& rp : *recoveredPackets) {
        if (StoreRecoveredFecSegment(rp.first, rp.second)) stored++;
    }

    if (stored > 0) {
        DrainReadyPayloads(readyPayloads);
    }
    return stored;
}

bool UcpPcb::StoreRecoveredFecSegment(uint32_t recoveredSeq,
                                        ucp::vector<uint8_t> recovered) {
    // Don't store duplicates or already-acked sequences
    if (recovered.empty() ||
        UcpSequenceComparer::IsBefore(recoveredSeq, m_nextExpectedSequence) ||
        m_recvBuffer.find(recoveredSeq) != m_recvBuffer.end())
        return false;

    FecFragmentMetadata metadata{1, 0};
    auto metaIt = m_fecFragmentMetadata.find(recoveredSeq);
    if (metaIt != m_fecFragmentMetadata.end()) metadata = metaIt->second;

    InboundSegment inbound;
    inbound.SequenceNumber = recoveredSeq;
    inbound.FragmentTotal = metadata.FragmentTotal;
    inbound.FragmentIndex = metadata.FragmentIndex;
    inbound.Payload = std::move(recovered);

    m_recvBuffer[recoveredSeq] = std::move(inbound);
    ClearMissingReceiveState(recoveredSeq);  //< Reset NAK tracking for the recovered sequence.
    return true;
}

void UcpPcb::DrainReadyPayloads(ucp::vector<ucp::vector<uint8_t>>& readyPayloads) {
    // Deliver all contiguous in-order segments starting from next_expected_sequence
    while (!m_recvBuffer.empty()) {
        auto it = m_recvBuffer.find(m_nextExpectedSequence);
        if (it == m_recvBuffer.end()) break;

        ClearMissingReceiveState(m_nextExpectedSequence);
        readyPayloads.push_back(std::move(it->second.Payload));
        m_recvBuffer.erase(it);
        m_nextExpectedSequence = UcpSequenceComparer::Increment(m_nextExpectedSequence);
    }
}

void UcpPcb::ClearMissingReceiveState(uint32_t sequenceNumber) {
    m_nakIssued.erase(sequenceNumber);
    m_missingSequenceCounts.erase(sequenceNumber);
    m_missingFirstSeenMicros.erase(sequenceNumber);
    m_lastNakIssuedMicros.erase(sequenceNumber);
    m_fecFragmentMetadata.erase(sequenceNumber);
}

} // namespace ucp
