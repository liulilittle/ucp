#pragma once

/** @file ucp_pcb.h
 *  @brief UCP Protocol Control Block — the per-connection state machine. Mirrors C# Ucp.Internal.UcpPcb.
 *
 *  UcpPcb is the core of the UCP protocol engine.  Each PCB manages one
 *  connection's send buffer, receive reorder buffer, NAK gap tracking,
 *  SACK-based fast retransmit, RTO timer recovery, BBR congestion control,
 *  token-bucket pacing, fair-queue credit, and optional FEC encoding.
 *
 *  The C# equivalent is the internal sealed class UcpPcb.  This header
 *  defines the complete class interface along with all helper classes
 *  (OutboundSegment, InboundSegment, SackTrackingState, LossEvent, etc.)
 *  that model sub-states of the protocol machine.
 *
 *  All protocol state mutation happens under <c>m_sync</c> lock — methods
 *  that are called without external synchronisation acquire it internally.
 *  Inbound packet dispatch runs on the transport receive thread but the
 *  heavy work (Ack/Nak processing) is offloaded to std::async futures.
 */

#include "ucp/ucp_constants.h"
#include "ucp/ucp_enums.h"
#include "ucp/ucp_sequence_comparer.h"
#include "ucp/ucp_time.h"
#include "ucp/ucp_rto_estimator.h"
#include "ucp/ucp_bbr.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_network.h"
#include "ucp/ucp_types.h"

#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <condition_variable>

namespace ucp {

// ====================================================================================================
// PCB-local compile-time constants — mirror C# inner PcbConst class.
// ====================================================================================================

/** @brief Constants specific to the UcpPcb implementation (not exposed in public Constants). */
namespace PcbConst {
    constexpr int MAX_SACK_SEND_COUNT = 2;                //< Maximum times a single SACK block is reported before suppression.
    constexpr int DUPLICATE_ACK_THRESHOLD = 3;             //< Number of duplicate ACKs required to trigger fast retransmit.
    constexpr int NAK_MISSING_THRESHOLD = 3;               //< Number of times a gap must be observed before a NAK is sent.
    constexpr int MAX_NAK_MISSING_SCAN = 64;               //< Maximum sequence numbers to scan for gaps when generating a NAK.
    constexpr int MAX_NAK_SEQUENCES_PER_PACKET = 32;       //< Maximum missing sequences reported per NAK packet.
    constexpr int MAX_NAKS_PER_RTT = 4;                    //< Maximum NAK packets sent per RTT window.
    constexpr double BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS = 2.0;  //< Deduped loss events below this threshold are treated as random loss.
    constexpr int BBR_CONGESTION_LOSS_BURST_THRESHOLD = 3;      //< Contiguous loss run >= this value suggests congestion.
    constexpr int BBR_CONGESTION_LOSS_WINDOW_THRESHOLD = 6;     //< Deduped loss events >= this value suggest congestion.
    constexpr double BBR_CONGESTION_LOSS_RTT_MULTIPLIER = 1.5;  //< RTT inflation ratio for classifying loss as congestion.
    constexpr int SACK_FAST_RETRANSMIT_THRESHOLD = 2;           //< SACK hole observations needed to trigger fast retransmit.
    constexpr int SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD = 100;//< Distance past a SACK hole beyond which fast retransmit is aggressive.
    constexpr int64_t SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS = 1000; //< Minimum reorder grace window for SACK fast retransmit.
    constexpr int EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS = 4;   //< Max inflight segments to allow early retransmit (low-inflight scenario).
    constexpr int TLP_MAX_INFLIGHT_SEGMENTS = 3;                //< Max inflight segments for Tail-Loss Probe (TLP).
    constexpr double TLP_TIMEOUT_RTT_RATIO = 1.5;               //< TLP fires at 1.5× SRTT after last ACK if inflight is low.
    constexpr int URGENT_RETRANSMIT_BUDGET_PER_RTT = 4;         //< Max urgent retransmits allowed per RTT window.
    constexpr double URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT = 75.0; //< Idle % of disconnect timeout before urgent retransmit kicks in.
    constexpr int RTO_RETRANSMIT_BUDGET_PER_TICK = 8;           //< Max RTO-triggered retransmits per timer tick.
    constexpr int64_t RTO_ACK_PROGRESS_SUPPRESSION_MICROS = 1000; //< Skip RTO if recent ACK progress was observed.
    constexpr double RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER = 3.0; //< Max acceptable RTT sample as a multiple of current RTO.
    constexpr int MIN_TIMER_WAIT_MILLISECONDS = 1;              //< Minimum timer/sleep granularity (1 ms).
    constexpr int64_t MIN_HANDSHAKE_WAIT_MILLISECONDS = 10;     //< Minimum wait between SYN retransmissions (10 ms).
    constexpr int64_t PAWS_TIMEOUT_MICROS = 60000000;           //< Protect Against Wrapped Sequences timeout (60 s).
    constexpr int CLOSE_WAIT_TIMEOUT_MILLISECONDS = 5000;       //< Wait before forcing close after FIN exchange (5 s).
    constexpr int64_t NAK_REORDER_GRACE_MICROS = 1000;          //< Base reorder grace period before sending a NAK (1 ms).
    constexpr int NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD = 4;  //< Missing count threshold for medium-confidence NAK.
    constexpr int64_t NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS = 800; //< Grace period for medium-confidence NAK.
    constexpr int NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD = 7;    //< Missing count threshold for high-confidence NAK.
    constexpr int64_t NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS = 500;  //< Grace period for high-confidence NAK.
    constexpr int64_t REORDERED_ACK_MIN_INTERVAL_MICROS = 1000; //< Minimum interval between reordered-ACK sends.
    constexpr int IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD = 3; //< Reordered-packet count that triggers an immediate ACK.
    constexpr double ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT = 1.0; //< Loss % threshold for enabling adaptive FEC.
    constexpr int64_t BBR_MIN_ROUND_DURATION_MICROS = 5000;     //< Minimum BBR round duration (5 ms).
    constexpr int DATA_HEADER_SIZE_WITH_ACK = 28;               //< Data packet header size including piggybacked ACK fields.
    constexpr int MAX_RTT_SAMPLES = 256;                        //< Maximum number of stored RTT samples for percentile queries.
    constexpr uint32_t DEFAULT_RECEIVE_WINDOW_BYTES = 1024 * 1024; //< Default receive window (1 MiB).
}

// === Forward declarations for cross-references ===

struct UcpCommonHeader;
class UcpPacket;
class UcpControlPacket;
class UcpDataPacket;
class UcpAckPacket;
class UcpNakPacket;
class UcpFecRepairPacket;
class UcpSackGenerator;
class UcpFecCodec;
class PacingController;

// ====================================================================================================
// Inner data structures — each models one aspect of the protocol state machine.
// Mirrors the private inner classes in C# Ucp.Internal.UcpPcb.
// ====================================================================================================

/** @brief Tracks a single outbound data segment in the send buffer (sorted by sequence number).
 *
 *  Each segment transitions through these states:
 *    1. Created (InFlight=false, Acked=false) — stored in send buffer, not yet transmitted.
 *    2. InFlight (InFlight=true) — sent to network, consuming flightBytes budget.
 *    3. NeedsRetransmit — detected as lost via SACK/NAK/DUPACK/RTO, awaiting retransmission.
 *    4. Acked — confirmed received by peer, eligible for garbage collection.
 */
class OutboundSegment {
public:
    uint32_t SequenceNumber = 0;     //< Sequence number assigned to this segment.
    uint16_t FragmentTotal = 0;      //< Total fragments in the logical message (1 = single-fragment).
    uint16_t FragmentIndex = 0;      //< Zero-based index of this fragment within the message.
    ucp::vector<uint8_t> Payload;    //< Application payload bytes.
    bool InFlight = false;           //< Whether this segment is currently in flight (sent but not acked).
    bool Acked = false;              //< Whether this segment has been acknowledged by the peer.
    bool NeedsRetransmit = false;    //< Whether this segment is marked for retransmission.
    int SendCount = 0;               //< Number of times transmitted (0 = never sent).
    int64_t LastSendMicros = 0;      //< Microsecond timestamp of the most recent send.
    UcpPriority Priority = UcpPriority::Normal;  //< QoS priority level.
};

/** @brief Per-sequence tracking for SACK-based fast retransmit decisions.
 *
 *  Each sequence observed as missing in SACK blocks gets a SackTrackingState
 *  entry.  This tracks how many consecutive ACKs have reported this sequence
 *  as missing and when the first miss was observed.
 */
class SackTrackingState {
public:
    int MissingAckCount = 0;         //< Number of consecutive ACKs that identified this sequence as missing.
    int64_t FirstMissingAckMicros = 0; //< Timestamp when the first missing observation occurred.
    bool UrgentRetransmit = false;    //< Whether this sequence needs urgent (out-of-order) retransmission.
};

/** @brief Metadata extracted from the FEC fragment header of a data packet. */
class FecFragmentMetadata {
public:
    FecFragmentMetadata() : FragmentTotal(0), FragmentIndex(0) {}
    FecFragmentMetadata(uint16_t total, uint16_t index) : FragmentTotal(total), FragmentIndex(index) {}

    uint16_t FragmentTotal = 0;   //< Total fragments in the FEC-encoded message.
    uint16_t FragmentIndex = 0;   //< Zero-based fragment index within the FEC group.
};

/** @brief Record of a single loss event for deduplication and loss-classification windows. */
class LossEvent {
public:
    uint32_t SequenceNumber = 0;   //< Sequence number of the lost segment.
    int64_t TimestampMicros = 0;   //< When the loss was detected (microseconds).
    int64_t RttMicros = 0;         //< RTT measured at the time of loss detection.
};

/** @brief A received data segment buffered in the receive reorder buffer. */
class InboundSegment {
public:
    uint32_t SequenceNumber = 0;      //< Sequence number of the received data.
    uint16_t FragmentTotal = 0;       //< Total fragments in the message.
    uint16_t FragmentIndex = 0;       //< Zero-based fragment index.
    ucp::vector<uint8_t> Payload;     //< Received application payload bytes.
};

/** @brief A consecutive chunk of in-order received data queued for application delivery. */
class ReceiveChunk {
public:
    ucp::vector<uint8_t> Buffer;   //< Contiguous byte buffer of received data.
    int Offset = 0;                //< Read offset within the buffer (for partial consumption).
    int Count = 0;                 //< Number of valid bytes in the buffer.
};

/** @brief Comparator for std::map using half-space sequence ordering.
 *
 *  Ensures that SequenceMap and RecvSequenceMap iterate in circular
 *  sequence-number order.  Returns true if @p a follows @p b under the
 *  half-space rule, placing smaller (earlier) sequences first.
 */
struct SeqCompare {
    bool operator()(uint32_t a, uint32_t b) const {
        if (a == b) return false;
        uint32_t diff = a - b;
        return diff >= Constants::HALF_SEQUENCE_SPACE;
    }
};

/** @brief Ordered map of outbound segments keyed by sequence number. */
using SequenceMap = std::map<uint32_t, OutboundSegment, SeqCompare>;

/** @brief Ordered map of inbound received segments keyed by sequence number. */
using RecvSequenceMap = std::map<uint32_t, InboundSegment, SeqCompare>;

// ====================================================================================================
// UcpPcb — per-connection protocol state machine.
// ====================================================================================================

/** @brief UCP Protocol Control Block — the per-connection state machine.
 *
 *  Manages the send buffer (sorted by sequence number), receive reorder
 *  buffer, NAK gap tracking, SACK-based fast retransmit, RTO timer recovery,
 *  BBR congestion control, token-bucket pacing, fair-queue credit, and FEC
 *  encoding.  All protocol state mutation happens under m_sync lock.
 *
 *  Data delivery to the application fires the DataReceived callback when
 *  consecutive in-order segments become available (no batching delay).
 */
class UcpPcb {
public:
    /** @brief Callback invoked when the PCB is fully closed (for server/network cleanup). */
    using ClosedCallback = std::function<void(UcpPcb*)>;
    /** @brief Callback invoked when in-order data is queued for application delivery. */
    using DataReceivedCallback = std::function<void(const uint8_t*, int, int)>;
    /** @brief Callback invoked when the connection transitions to Established. */
    using ConnectedCallback = std::function<void()>;
    /** @brief Callback invoked when the connection transitions to Closed. */
    using DisconnectedCallback = std::function<void()>;

    /** @brief Construct a new PCB.
     *  @param transport      The ITransport interface for sending datagrams.
     *  @param isServerSide   Whether this PCB is server-side (waits for SYN).
     *  @param useFairQueue   Whether to obey fair-queue credit limits.
     *  @param closedCallback Callback invoked when the PCB is fully closed.
     *  @param connectionId   Pre-assigned connection ID (0 = generate random).
     *  @param config         Configuration for this connection.
     *  @param network        Optional UcpNetwork for timer/DoEvents integration. */
    UcpPcb(class ITransport* transport, bool isServerSide, bool useFairQueue,
           ClosedCallback closedCallback,
           uint32_t connectionId, const UcpConfiguration& config,
           UcpNetwork* network = nullptr);
    ~UcpPcb();

    UcpPcb(const UcpPcb&) = delete;
    UcpPcb& operator=(const UcpPcb&) = delete;

    // === Public accessors ===

    uint32_t GetConnectionId() const { return m_connectionId; }
    UcpConnectionState GetState();
    double GetCurrentPacingRateBytesPerSecond();
    bool HasPendingSendData();
    UcpConnectionDiagnostics GetDiagnosticsSnapshot();

    // === Test and control hooks ===

    void Abort(bool sendReset);
    void SetNextSendSequenceForTest(uint32_t nextSendSequence);
    void SetAdvertisedReceiveWindowForTest(uint32_t windowBytes);
    void SetRemoteEndPoint(uint64_t remoteEndPoint);
    bool ValidateRemoteEndPoint(uint64_t remoteEndPoint);

    // === Async API (matched to UcpConnection) ===

    std::future<bool> ConnectAsync(uint64_t remoteEndPoint);
    std::future<int> SendAsync(const uint8_t* buffer, int offset, int count);
    std::future<int> SendAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority);
    std::future<int> ReceiveAsync(uint8_t* buffer, int offset, int count);
    std::future<bool> ReadAsync(uint8_t* buffer, int offset, int count);
    std::future<bool> WriteAsync(const uint8_t* buffer, int offset, int count);
    std::future<bool> WriteAsync(const uint8_t* buffer, int offset, int count, UcpPriority priority);
    std::future<void> CloseAsync();

    // === Network/Timer interface ===

    /** @brief Handle an inbound decoded packet (called from network receive path).
     *  @param packet  The decoded packet (non-owning pointer; PCB may copy). */
    void HandleInboundAsync(const UcpPacket* packet);

    /** @brief Add fair-queue bandwidth credit to this PCB.
     *  @param bytes  Number of bytes of credit (from fair-queue scheduling round). */
    void AddFairQueueCredit(double bytes);

    /** @brief Request that the send queue be flushed (enqueue FlushSendQueueAsync). */
    void RequestFlush();

    /** @brief Periodic timer tick: handle RTO, keep-alive, NAK generation, etc.
     *  @param nowMicros  Current timestamp in microseconds.
     *  @return Number of work items executed (1+). */
    int OnTick(int64_t nowMicros);

    /** @brief Dispatch a packet received from the network (validates remote endpoint first).
     *  @param packet          Decoded packet from the network.
     *  @param remoteEndPoint  Packed endpoint (IP + port) for validation. */
    void DispatchFromNetwork(const UcpPacket* packet, uint64_t remoteEndPoint);

    /** @brief Release all PCB resources (timers, memory, network registrations). */
    void Dispose();

    // === Public callback delegates ===

    DataReceivedCallback DataReceived;           //< Fired when in-order data is ready for application.
    ConnectedCallback Connected;                 //< Fired on Established transition.
    DisconnectedCallback Disconnected;           //< Fired on Closed transition.

private:
    // === Static helpers ===

    static uint32_t NextConnectionId();   //< Generate a random non-zero connection ID.
    static uint32_t NextSequence();       //< Generate a random initial sequence number (ISN).
    int64_t NowMicros();                  //< Get the current timestamp (network or system clock).

    // === Packet handler methods ===

    void HandleSyn(const UcpControlPacket& packet);
    void HandleSynAck(const UcpControlPacket& packet);
    std::future<void> HandleAckAsync(const UcpAckPacket& ackPacket);
    std::future<void> HandleNakAsync(const UcpNakPacket& nakPacket);
    void HandleData(const UcpDataPacket& dataPacket);
    void HandleFecRepair(const UcpFecRepairPacket& packet);
    void HandleFin(const UcpControlPacket& packet);

    // === ACK/NAK/Control sending ===

    int ProcessPiggybackedAck(uint32_t ackNumber, int64_t nowMicros);
    void SendControl(UcpPacketType type, int flags);
    void SendAckPacket(int flags, int64_t overrideEchoTimestamp);
    void SendNak(const ucp::vector<uint32_t>& missing);
    void ScheduleAck();

    // === Send queue management ===

    std::future<void> FlushSendQueueAsync();
    void ScheduleDelayedFlush(int64_t waitMicros);

    // === Receive queue management ===

    void EnqueuePayload(ucp::vector<uint8_t> payload);

    // === Timer management ===

    void OnTimer();
    void ScheduleTimer();
    std::future<void> OnTimerAsync();
    std::future<void> OnTimerAsync(int64_t nowMicros);

    // === State machine transitions ===

    void TransitionToEstablished();
    void TransitionToClosed();
    void ReleaseNetworkRegistrations();

    // === Static validation ===

    static void ValidateBuffer(const uint8_t* buffer, int offset, int count, int bufferLen);
    static uint64_t PackSackBlockKey(uint32_t start, uint32_t end);
    static uint32_t GetHighestSackEnd(const ucp::vector<SackBlock>& blocks);
    static void SortSackBlocks(const ucp::vector<SackBlock>& blocks, ucp::vector<SackBlock>& sorted);
    static bool IsReportedSackHole(uint32_t sequenceNumber, uint32_t cumulativeAckNumber,
                                    const ucp::vector<SackBlock>& sackBlocks);
    static int GetMaxContiguousLossRun(const ucp::vector<uint32_t>& sequenceNumbers);

    // === SACK-based fast retransmit ===

    SackTrackingState* GetOrCreateSackTracking(uint32_t sequenceNumber);
    bool ShouldFastRetransmitSackHole(OutboundSegment& segment, uint32_t firstMissingSequence,
                                        uint32_t highestSack, bool reportedSackHole, int64_t nowMicros);
    bool HasPendingFecRepair(OutboundSegment& segment, int64_t nowMicros);

    // === Fast-retransmit thresholds ===

    int64_t GetFecFastRetransmitGraceMicros();
    int64_t GetSackFastRetransmitReorderGraceMicros();
    int64_t GetFastRetransmitAgeThreshold();
    bool ShouldTriggerEarlyRetransmit();
    bool ShouldAcceptRetransmitRequest(OutboundSegment& segment, int64_t nowMicros);
    int64_t GetRtoAckProgressSuppressionMicros();
    double GetRetransmissionRatio();

    // === Debug logging ===

    void TraceLog(const ucp::string& message);

    // === ACK validation ===

    bool IsAckPlausible(const UcpAckPacket& ackPacket);
    void UpdateDuplicateAckState(const UcpAckPacket& ackPacket, int64_t nowMicros, bool& fastRetransmitTriggered);

    // === Loss classification ===

    bool IsCongestionLoss(uint32_t sequenceNumber, int64_t sampleRttMicros, int64_t nowMicros, int contiguousLossCount);
    bool ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers, int64_t nowMicros, int64_t sampleRttMicros);
    bool ClassifyLosses(const ucp::vector<uint32_t>& sequenceNumbers, int64_t nowMicros, int64_t sampleRttMicros, int contiguousLossCount);

    int64_t GetLossClassifierWindowMicros();
    void PruneLossEvents(int64_t nowMicros, int64_t windowMicros);
    int64_t GetLossWindowMedianRttMicros();
    int64_t GetMinimumObservedRttMicros();
    int GetMaxContiguousRecentLossRun();

    // === FEC recovery ===

    void TryRecoverFecAround(uint32_t receivedSequenceNumber, ucp::vector<ucp::vector<uint8_t>>& readyPayloads);
    int StoreRecoveredFecPackets(const ucp::vector<std::pair<uint32_t, ucp::vector<uint8_t>>>* recoveredPackets,
                                   ucp::vector<ucp::vector<uint8_t>>& readyPayloads);
    bool StoreRecoveredFecSegment(uint32_t recoveredSeq, ucp::vector<uint8_t> recovered);
    void DrainReadyPayloads(ucp::vector<ucp::vector<uint8_t>>& readyPayloads);
    void ClearMissingReceiveState(uint32_t sequenceNumber);

    // === NAK generation ===

    bool ShouldIssueNak(uint32_t sequenceNumber);
    bool ShouldSendImmediateReorderedAck(int64_t nowMicros);
    bool HasNakReorderGraceExpired(int missingCount, int64_t firstSeenMicros, int64_t nowMicros);
    int64_t GetAdaptiveNakReorderGraceMicros();
    void MarkNakIssued(uint32_t sequenceNumber);
    int64_t GetMissingFirstSeenMicros(uint32_t sequenceNumber);
    void CollectMissingForNak(ucp::vector<uint32_t>& missing, int64_t nowMicros);

    // === Send window helpers ===

    int GetSendWindowBytes();
    bool CanUseUrgentRecovery(int64_t nowMicros);
    bool IsNearDisconnectTimeout(int64_t nowMicros);
    uint32_t GetReceiveWindowUsedBytes();

    // === RTT sampling ===

    void AddRttSample(int64_t sampleRttMicros);
    void PurgeSackSendCounts();

    // ================================================================================================
    // Member variables — protected by m_sync unless otherwise noted.
    // ================================================================================================

    mutable std::mutex m_sync;  //< Primary synchronization mutex — guards all mutable state below.

    // === Transport and infrastructure ===

    ITransport* m_transport = nullptr;       //< Transport layer for sending datagrams (non-owning).
    bool m_useFairQueue = false;             //< Whether to respect fair-queue credit limits.
    bool m_isServerSide = false;             //< Whether this PCB is in server (passive-open) mode.
    const UcpConfiguration& m_config;        //< Read-only reference to the connection configuration.
    ClosedCallback m_closedCallback;          //< Callback for notifying owner (server) of closure.
    UcpNetwork* m_network = nullptr;         //< Optional network for timer/event-loop integration.

    // === Send/receive buffers ===

    SequenceMap m_sendBuffer;                 //< Outbound segments sorted by sequence number (SeqCompare order).
    RecvSequenceMap m_recvBuffer;            //< Received out-of-order segments sorted by sequence number.
    std::queue<ReceiveChunk> m_receiveQueue; //< In-order chunks ready for application consumption.

    // === NAK gap tracking ===

    std::unordered_set<uint32_t> m_nakIssued;                      //< Sequences for which a NAK has been sent.
    std::unordered_map<uint32_t, int> m_missingSequenceCounts;     //< How many times each gap has been observed.
    std::unordered_map<uint32_t, int64_t> m_missingFirstSeenMicros; //< When each gap was first noticed.
    std::unordered_map<uint32_t, int64_t> m_lastNakIssuedMicros;  //< When the last NAK for each sequence was sent.

    // === SACK fast-retransmit tracking ===

    std::unordered_set<uint32_t> m_sackFastRetransmitNotified;     //< Sequences already fast-retransmitted via SACK.
    std::unordered_map<uint64_t, int> m_sackBlockSendCounts;       //< How many times each SACK block has been sent.
    std::unordered_map<uint32_t, SackTrackingState> m_sackTracking; //< Per-sequence SACK hole tracking state.

    // === FEC state ===

    std::unordered_set<uint32_t> m_fecRepairSentGroups;              //< FEC group bases for which repairs have been sent.
    std::unordered_map<uint32_t, FecFragmentMetadata> m_fecFragmentMetadata; //< Per-sequence FEC fragment metadata.

    UcpFecCodec* m_fecCodec = nullptr;        //< FEC codec instance (null if FEC is disabled).
    uint32_t m_fecGroupBaseSeq = 0;           //< Base sequence of the current FEC send group.
    int m_fecGroupSendCount = 0;              //< Number of packets sent in the current FEC group.

    // === Async signalling ===

    std::condition_variable m_receiveSignal;          //< Signals ReceiveAsync waiters when data is available.
    std::condition_variable m_sendSpaceSignal;        //< Signals WriteAsync waiters when send buffer space frees up.
    std::mutex m_receiveSignalMutex;                   //< Protects m_receiveSignal.
    std::mutex m_sendSpaceSignalMutex;                 //< Protects m_sendSpaceSignal.

    std::mutex m_flushLockMutex;                       //< Guards the flush lock mechanism.
    bool m_flushLockAcquired = false;                  //< Whether the flush lock is currently held.
    std::condition_variable m_flushLockCond;           //< CV for waiting on flush lock release.

    std::atomic<bool> m_ctsCanceled{false};            //< Cooperative cancellation token (set on Dispose).

    // === Promises/futures for external async APIs ===

    std::promise<bool> m_connectedPromise;             //< Fulfilled with true/false when connection completes/fails.
    std::promise<bool> m_closedPromise;                //< Fulfilled with true when the connection closes.
    std::shared_future<bool> m_connectedFuture;        //< Shared future for multiple waiters on connection.
    std::shared_future<bool> m_closedFuture;           //< Shared future for multiple waiters on close.

    // === Protocol engines (owned, allocated via new) ===

    UcpSackGenerator* m_sackGenerator = nullptr;     //< SACK block generator (lazily allocated).
    UcpRtoEstimator* m_rtoEstimator = nullptr;       //< RTO estimator (always allocated at construct).
    BbrCongestionControl* m_bbr = nullptr;           //< BBR congestion controller (always allocated at construct).
    PacingController* m_pacing = nullptr;             //< Token-bucket pacing controller (lazily allocated).

    // === Connection state ===

    UcpConnectionState m_state = UcpConnectionState::Init; //< Current connection state machine state.
    uint64_t m_remoteEndPoint = 0;                        //< Packed remote endpoint (IP + port).
    uint32_t m_connectionId = 0;                           //< Unique connection identifier.
    uint32_t m_nextSendSequence = 0;                       //< Next sequence number to assign for a new outbound segment.
    uint32_t m_nextExpectedSequence = 0;                  //< Next in-order sequence number we expect to receive.
    uint32_t m_remoteWindowBytes = 0;                     //< Peer's advertised receive window (bytes).
    int m_flightBytes = 0;                                //< Total payload bytes currently in flight.
    double m_fairQueueCreditBytes = 0.0;                  //< Fair-queue credit remaining (bytes).
    int64_t m_lastEchoTimestamp = 0;                      //< Most recent echo timestamp from the peer (for piggybacked ACK).
    int64_t m_lastActivityMicros = 0;                     //< Timestamp of the last send or receive activity.
    int64_t m_lastAckSentMicros = 0;                      //< Timestamp of the last ACK packet transmission.
    int64_t m_lastRttMicros = 0;                          //< Most recent valid RTT sample (microseconds).

    // === Handshake flags ===

    bool m_synSent = false;               //< Whether we have sent a SYN packet.
    bool m_synAckSent = false;            //< Whether the server has sent a SYN-ACK.
    int64_t m_synAckSentMicros = 0;       //< Timestamp when SYN-ACK was last sent (for retransmission).
    bool m_finSent = false;               //< Whether we have sent a FIN packet.
    bool m_finAcked = false;              //< Whether our FIN has been acknowledged by the peer.
    bool m_peerFinReceived = false;       //< Whether we have received a FIN from the peer.
    bool m_rstReceived = false;           //< Whether we have received an RST from the peer.

    bool m_disposed = false;              //< Whether Dispose has been called.

    // === PAWS / timestamp tracking ===

    int64_t m_largestTimestampSeen = 0;   //< Largest timestamp seen from the peer (for PAWS protection).
    bool m_pawsEnabled = true;            //< Whether PAWS (Protect Against Wrapped Sequences) is active.

    // === Timer and flush state ===

    bool m_flushDelayed = false;          //< Whether a delayed flush has been scheduled.
    bool m_ackDelayed = false;            //< Whether a delayed ACK has been scheduled.
    uint32_t m_timerId = 0;               //< Network timer ID for the OnTimer callback.
    uint32_t m_flushTimerId = 0;          //< Network timer ID for the delayed flush callback.
    bool m_connectedRaised = false;       //< Whether the Connected callback has been fired.
    bool m_disconnectedRaised = false;    //< Whether the Disconnected callback has been fired.
    bool m_closedResourcesReleased = false; //< Whether network registrations have been released.
    bool m_pathChanged = false;           //< Whether a path change has been detected.

    // === Duplicate ACK tracking ===

    uint32_t m_largestCumulativeAckNumber = 0;       //< Largest cumulative ACK seen so far.
    bool m_hasLargestCumulativeAckNumber = false;     //< Whether we have a valid cumulative ack.
    uint32_t m_lastAckNumber = 0;                     //< Last ACK number received (for duplicate detection).
    bool m_hasLastAckNumber = false;                   //< Whether we have a valid last ACK.
    int m_duplicateAckCount = 0;                       //< Consecutive duplicate ACK count.
    bool m_fastRecoveryActive = false;                  //< Whether we are in fast recovery mode.

    // === Receive window ===

    uint32_t m_localReceiveWindowBytes = 0;          //< Our advertised receive window (bytes).
    int m_queuedReceiveBytes = 0;                     //< Total bytes in m_receiveQueue awaiting consumption.

    // === Counters (for diagnostics / transfer report) ===

    int64_t m_bytesSent = 0;              //< Total payload bytes ever transmitted.
    int64_t m_bytesReceived = 0;          //< Total payload bytes ever received.
    int m_sentDataPackets = 0;            //< Total unique data packets sent (excludes retransmits).
    int m_retransmittedPackets = 0;       //< Total retransmitted data packets.
    int m_sentAckPackets = 0;             //< Total ACK packets sent.
    int m_sentNakPackets = 0;             //< Total NAK packets sent.
    int m_sentRstPackets = 0;             //< Total RST packets sent.
    int m_fastRetransmissions = 0;        //< Packets retransmitted via fast retransmit.
    int m_timeoutRetransmissions = 0;     //< Packets retransmitted after RTO expiry.

    ucp::vector<int64_t> m_rttSamplesMicros;   //< Ring buffer of recent RTT samples (max MAX_RTT_SAMPLES).

    // === NAK rate limiting ===

    int64_t m_lastNakWindowMicros = 0;       //< Start of the current NAK rate-limit window.
    int m_naksSentThisRttWindow = 0;          //< Number of NAKs sent in this window.

    // === ACK and TLP state ===

    int64_t m_lastAckReceivedMicros = 0;        //< Timestamp of the most recent ACK received.
    int64_t m_lastReorderedAckSentMicros = 0;   //< Timestamp of the last reordered-ACK sent.
    bool m_tailLossProbePending = false;         //< Whether a Tail-Loss Probe has been scheduled or is in-flight.

    // === Loss classification window ===

    std::queue<LossEvent> m_recentLossEvents;            //< FIFO queue of recent loss events (pruned by time window).
    std::unordered_set<uint32_t> m_recentLossSequences;  //< Set of sequences in m_recentLossEvents (for dedup).

    // === Urgent recovery rate limiting ===

    int64_t m_urgentRecoveryWindowMicros = 0;    //< Start of the current urgent-recovery rate-limit window.
    int m_urgentRecoveryPacketsInWindow = 0;      //< Urgent retransmits sent in this window.
};

} // namespace ucp
