#pragma once

/** @file ucp_bbr.h
 *  @brief BBRv1 congestion control engine — mirrors C# Ucp.Internal.BbrCongestionControl.
 *
 *  Implements the BBR (Bottleneck Bandwidth and Round-trip propagation time)
 *  congestion control algorithm as described in the IETF BBR drafts.  The
 *  algorithm continuously estimates the path's bottleneck bandwidth and minimum
 *  RTT, adjusts the pacing rate and congestion window accordingly, and cycles
 *  through four modes:  Startup → Drain → ProbeBw → ProbeRtt.
 *
 *  Mirrors C# Ucp.Internal.BbrCongestionControl with additional features:
 *  network path classification, inflight bounds management, loss-EWMA tracking,
 *  and adaptive pacing gain based on loss class (random vs. congestion).
 */

#include <cstdint>  // Include fixed-width integer types (int64_t, int32_t, etc.) used throughout the BBR engine.
#include "ucp/ucp_vector.h"
#include "ucp/ucp_memory.h"
#include "ucp_enums.h" // Include the UCP enumeration definitions (BbrMode, NetworkClass, NetworkCondition) shared between C++ and C#.

namespace ucp {

/** @brief Configuration subset specific to the BBR congestion controller.
 *
 *  Pulled from UcpConfiguration when constructing BbrCongestionControl.
 *  Mirrors C# Ucp.Internal.BbrConfig.
 */
struct BbrConfig {
    int Mss = 1220;                                  // Maximum segment size in bytes (excludes IP/TCP headers); mirrors C# UcpConfiguration.Mss.
    double StartupPacingGain = 2.89;                 // Pacing gain during Startup mode (≈ 2/ln(2) ≈ 2.885, standard BBR Startup gain for exponential probing).
    double StartupCwndGain = 2.0;                    // Congestion-window gain during Startup mode (2.0× BDP for aggressive initial ramp-up).
    double DrainPacingGain = 1.0;                    // Pacing gain during Drain mode; may be reduced on lossy paths (e.g. 0.75–0.90) to actively drain the standing queue.
    double ProbeBwHighGain = 1.35;                   // Pacing gain during the single high-gain phase of the 8-phase ProbeBw cycle (probes for more bandwidth).
    double ProbeBwLowGain = 0.85;                    // Pacing gain during the low-gain (drain) phases of the 8-phase ProbeBw cycle; c.75× to drain any accumulated queue.
    double ProbeBwCwndGain = 2.0;                    // Congestion-window gain during ProbeBw steady-state mode (2.0× BDP provides retransmission headroom without bufferbloat).
    double MaxBandwidthWastePercent = 0.25;          // Maximum fraction of bandwidth that may be treated as waste when clamping the CWND gain ceiling.
    double MaxBandwidthLossPercent = 0.25;           // Loss-percentage threshold (0.0–1.0) above which the loss-control feature triggers aggressive back-off.
    double EffectiveMaxBandwidthLossPercent = 0.25;  // Clamped/effective loss threshold derived from MaxBandwidthLossPercent by configuration logic.
    bool LossControlEnable = true;                   // Whether to treat loss as a congestion signal and apply multiplicative CWND reduction and pacing back-off.
    bool EnableDebugLog = false;                     // Whether to emit verbose BBR state-transition debug messages to stderr; mirrors C# UcpConfiguration.EnableDebugLog.
    int64_t InitialBandwidthBytesPerSecond = 12500000; // Initial bottleneck-bandwidth estimate in bytes/s (≈ 100 Mbps); used as the starting BtlBw before any measurements.
    int64_t MaxPacingRateBytesPerSecond = 0;          // Hard ceiling on the pacing rate in bytes/s; 0 means unlimited (no user-configured rate cap).
    int MaxCongestionWindowBytes = 0;                  // Hard ceiling on the congestion window in bytes; 0 means unlimited.
    int InitialCongestionWindowBytes = 24400;          // Initial congestion window in bytes (≈ 20 × MSS of 1220); the CWND floor during Startup.
    int BbrWindowRtRounds = 10;                        // Number of RTTs of history kept in the bandwidth max-filter window (sliding time window width).
    int64_t ProbeRttIntervalMicros = 30000000;         // Interval between automatic ProbeRtt entries (30 seconds); after this time, MinRtt is considered stale.
    int64_t ProbeRttDurationMicros = 100000;           // Minimum duration of the ProbeRtt deep-drain phase (100 ms); the connection stays in ProbeRtt at least this long.
};

/** @brief Aggregated statistics for one classifier observation window.
 *
 *  The path classifier slides a window of kNetworkClassifierWindowCount
 *  observations, each summarizing avg RTT, loss rate, jitter, and throughput
 *  ratio over a fixed duration (kNetworkClassifierWindowDurationMicros).
 *  Mirrors C# BbrCongestionControl.ClassifierWindow.
 */
struct ClassifierWindow {
    double AvgRttMicros = 0.0;     // Arithmetic mean RTT during the observation window in microseconds; computed as sum / count of all RTT samples.
    double LossRate = 0.0;         // Loss ratio snapshot for this window (0.0 = no loss, 1.0 = 100% loss); recorded at window finalization.
    double JitterMicros = 0.0;     // RTT jitter (max_rtt − min_rtt) during the window in microseconds; high jitter suggests link-layer variance (radio, WiFi).
    double ThroughputRatio = 0.0;  // Ratio of actual throughput to estimated bottleneck bandwidth (0.0–1.0); represents path utilisation during the window.
};

/** @brief BBRv1 congestion controller with adaptive gain, inflight bounds, and path classification.
 *
 *  Each UcpPcb instance owns one BbrCongestionControl.  The congestion
 *  controller receives callbacks (OnAck, OnPacketSent, OnPacketLoss,
 *  OnFastRetransmit, OnPathChange) from the protocol engine and continuously
 *  updates its internal model:  bottleneck bandwidth, min RTT, pacing rate,
 *  cwnd, and estimated loss percentage.
 *
 *  The controller is not internally synchronised — the caller (UcpPcb) is
 *  responsible for serialising access under its own m_sync lock.
 *  Mirrors C# Ucp.Internal.BbrCongestionControl.
 */
class BbrCongestionControl {
public:
    /** @brief Default constructor (uses default BbrConfig). */
    BbrCongestionControl(); // Delegates to the parameterised constructor with BbrConfig{} defaults; mirrors C# parameterless constructor.

    /** @brief Construct with an explicit BbrConfig.
     *  @param config  BBR configuration values. */
    explicit BbrCongestionControl(const BbrConfig& config); // Initialises all rate/window/loss state from the provided config, enters Startup, runs initial model.

    /** @brief Called by UcpPcb when a cumulative or SACK ack arrives.
     *  @param nowMicros         Current timestamp (microseconds).
     *  @param deliveredBytes     Number of bytes newly acknowledged.
     *  @param sampleRttMicros    The RTT sample from this ack (or 0 if unavailable).
     *  @param flightBytes        Current in-flight bytes after processing the ack. */
    void OnAck(int64_t nowMicros, int deliveredBytes, int64_t sampleRttMicros, int flightBytes);

    /** @brief Called by UcpPcb when a packet is sent or retransmitted.
     *  @param nowMicros     Current timestamp.
     *  @param isRetransmit  Whether this packet is a retransmission. */
    void OnPacketSent(int64_t nowMicros, bool isRetransmit);

    /** @brief Called by UcpPcb when a fast retransmit is triggered.
     *  @param nowMicros    Current timestamp.
     *  @param isCongestion Whether the loss was classified as congestion. */
    void OnFastRetransmit(int64_t nowMicros, bool isCongestion);

    /** @brief Called by UcpPcb when packets are classified as lost.
     *  @param nowMicros    Current timestamp.
     *  @param lossRate     Recent retransmission ratio (0..1).
     *  @param isCongestion Whether this loss event represents congestion. */
    void OnPacketLoss(int64_t nowMicros, double lossRate, bool isCongestion);

    /** @brief Called by UcpPcb when the network path may have changed (endpoint migration).
     *  @param nowMicros  Current timestamp.
     *
     *  Resets the min RTT, RTT history, and path classifier state so that
     *  BBR re-learns the path from scratch. */
    void OnPathChange(int64_t nowMicros);

    // === Public accessors ===

    NetworkClass CurrentNetworkClass() const { return _currentNetworkClass; }  // Returns the most recent network-path classification (LAN, Mobile, LossyFat, etc.).
    BbrMode Mode() const { return _mode; }                                    // Returns the current BBR operating mode (Startup, Drain, ProbeBw, or ProbeRtt).
    double BtlBwBytesPerSecond() const { return _btlBwBytesPerSecond; }        // Returns the estimated bottleneck bandwidth in bytes per second.
    int64_t MinRttMicros() const { return _minRttMicros; }                    // Returns the minimum observed RTT in microseconds (sticky floor with up to 25% reduction per sample).
    double PacingGain() const { return _pacingGain; }                         // Returns the current effective pacing gain multiplier applied to BtlBw.
    double CwndGain() const { return _cwndGain; }                             // Returns the current effective congestion-window gain multiplier.
    double PacingRateBytesPerSecond() const { return _pacingRateBytesPerSecond; } // Returns the current effective pacing rate (BtlBw × PacingGain) in bytes/s.
    int CongestionWindowBytes() const { return _congestionWindowBytes; }       // Returns the current congestion window in bytes.
    double EstimatedLossPercent() const { return _estimatedLossPercent; }      // Returns the EWMA-smoothed loss percentage estimate (0.0–100.0).

private:
    // === Internal constants ===

    static constexpr int kRecentRateSampleCount = 10;        // Number of recent delivery-rate samples stored in the max-filter ring buffer; mirrors C# BBR_RECENT_RATE_SAMPLE_COUNT.
    static constexpr int kDeliveryRateHistoryCount = 16;     // Number of delivery-rate samples for oldest-vs-newest trend detection; mirrors C# BBR_DELIVERY_RATE_HISTORY_COUNT.
    static constexpr int kRttHistoryCount = 32;              // Number of RTT samples retained for percentile estimation (P10, P25, P30); mirrors C# BBR_RTT_HISTORY_COUNT.
    static constexpr int kLossBucketCount = 10;              // Number of fixed-duration time-buckets for sliding-window loss-ratio tracking; mirrors C# BBR_LOSS_BUCKET_COUNT.
    static constexpr int kClassifierWindowCount = 8;         // Number of classifier observation windows stored for network-path classification; mirrors C# NETWORK_CLASSIFIER_WINDOW_COUNT.

    // === Internal update methods ===

    void AddRateSample(double deliveryRate, int64_t nowMicros);       // Inserts a delivery-rate sample into the max-filter ring buffer and updates the BtlBw estimate.
    void AddDeliveryRateSample(double deliveryRate);                  // Inserts a delivery-rate sample into the delivery-rate history buffer for trend-based congestion detection.
    void AddRttSample(int64_t sampleRttMicros);                       // Inserts a validated RTT sample (≤ 500ms cap) into the RTT-history ring buffer for percentile queries.
    int GetTargetCwndBytes();                                         // Computes the target congestion window (BDP × CwndGain) with all guardrails, floors, and ceilings applied.
    void RecalculateModel(int64_t nowMicros);                         // The central model recomputation: derives pacing rate and CWND from BtlBw, pacing gain, and CWND gain.
    void EnterDrain(int64_t nowMicros);                               // Transitions from Startup to Drain: sets drain pacing gain and records entry timestamp.
    void EnterProbeBw(int64_t nowMicros);                             // Transitions into the steady-state ProbeBw mode: resets the 8-phase cycle to index 0.
    void EnterProbeRtt(int64_t nowMicros);                            // Enters the periodic ProbeRtt deep-drain mode to refresh the minimum RTT estimate.
    void ExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros);    // Exits ProbeRtt: conditionally adopts a new MinRtt and transitions back to ProbeBw.
    bool ShouldExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros); // Checks whether ProbeRtt should exit (fresh near-minimum RTT sample observed or safety timeout expired).
    double CalculatePacingGain(int64_t nowMicros);                   // Computes the adaptive pacing gain from network condition, path class, loss ratio, and RTT trend.
    double CalculateLossPercent(int64_t nowMicros);                  // Computes the composite loss percentage from retransmission ratio and delivery-rate shortfall.
    NetworkCondition ClassifyNetworkCondition(int64_t nowMicros);     // Runs the three-tier congestion classifier: rate drop + RTT rise + loss → Congested, RandomLoss, LightLoad, or Idle.
    bool ShouldTreatLossAsCongestion(int64_t nowMicros, bool isCongestionSignal); // Final gate: determines whether a loss event warrants multiplicative CWND reduction vs fast recovery only.
    int64_t GetCwndModelRttMicros();                                  // Returns the model RTT for CWND computation: max(MinRtt, P10 RTT), capped at 500ms.
    double GetAverageRttIncreaseRatio();                              // Computes (averageRtt − MinRtt) / MinRtt; returns 0.0 if no RTT history available.
    int64_t GetP10RttMicros();                                        // Returns the 10th-percentile RTT from the history buffer (robust propagation-delay estimate).
    int64_t GetP25RttMicros();                                        // Returns the 25th-percentile RTT from the history buffer (used for LossyLongFat paths).
    int64_t GetP30RttMicros();                                        // Returns the 30th-percentile RTT from the history buffer (used for MobileUnstable paths).
    int64_t GetPercentileRtt(double percentile);                      // Generic percentile-RTT function: sorts a copy of the RTT history and picks the value at percentile × count.
    void UpdateInflightBounds();                                       // Recomputes the upper and lower inflight guardrails (CWND ceiling/floor) from current BDP and path class.
    double GetRecentLossRatio(int64_t nowMicros);                     // Returns the recent loss ratio (total retransmits / total sent) across all active loss buckets.
    void AdvanceLossBuckets(int64_t nowMicros);                       // Ages out expired loss-bucket time slots and advances the ring pointer to the current aligned time.
    double GetEffectiveCwndGain();                                    // Returns the CWND gain capped by the bandwidth-waste budget (prevents excessive inflight during high-gain phases).
    double GetDrainPacingGain(int64_t nowMicros);                     // Determines the drain pacing gain: 1.0 on clean paths, config value on lossy paths.
    void AdvanceClassifierWindow(int64_t nowMicros, int sentOrAckedBytes, int64_t sampleRttMicros, double lossRateSnapshot); // Accumulates data into a classifier observation window; finalises and rotates when the window duration elapses.
    NetworkClass ClassifyNetworkPath();                               // Classifies the end-to-end network path into one of six types from averaged classifier-window statistics.
    void UpdateEstimatedLossPercent(int64_t nowMicros);               // One-parameter overload: calls the two-parameter version with a freshly computed loss percentage.
    void UpdateEstimatedLossPercent(int64_t nowMicros, double candidateLossPercent); // Updates the EWMA-smoothed loss percentage (75% retained + 25% new sample, with idle decay).
    void UpdateStartup();                                              // Checks bandwidth growth at each round boundary; transitions to Drain when growth stalls for the required number of rounds.
    double ClampBandwidthGrowth(double candidateRate, int64_t nowMicros); // Limits per-round BtlBw growth to prevent unrealistic jumps from a single bursty measurement.
    void TraceLog(const char* message);                                // Conditionally emits a debug trace message to stderr if EnableDebugLog is set.

    // === Configuration ===

    BbrConfig _config;  // The BBR configuration subset (gains, limits, thresholds) pulled from the protocol configuration; mirrors C# _config.

    // === Bandwidth estimation ===

    ucp::array<double, kRecentRateSampleCount> _recentRates{};              // Circular buffer of recent delivery-rate samples for the max-filter bandwidth estimation; mirrors C# _recentRates.
    ucp::array<int64_t, kRecentRateSampleCount> _recentRateTimestamps{};    // Timestamps corresponding to each entry in _recentRates for age-based sample expiry; mirrors C# _recentRateTimestamps.
    int _recentRateCount = 0;       // Number of valid entries currently in _recentRates (increments until the buffer fills, then stays at kRecentRateSampleCount).
    int _recentRateIndex = 0;       // Current write position in the _recentRates circular buffer (advances and wraps with each sample).

    ucp::array<double, kDeliveryRateHistoryCount> _deliveryRateHistory{};   // Circular buffer of recent delivery rates for oldest-vs-newest trend-based congestion detection; mirrors C# _deliveryRateHistory.
    int _deliveryRateHistoryCount = 0;  // Number of valid entries in _deliveryRateHistory (increments until the buffer fills).
    int _deliveryRateHistoryIndex = 0;  // Current write position in the _deliveryRateHistory circular buffer.

    // === RTT tracking ===

    ucp::array<int64_t, kRttHistoryCount> _rttHistoryMicros{};  // Circular buffer of recent RTT samples (≤ 500ms cap) for percentile queries and average-RTT computation; mirrors C# _rttHistoryMicros.
    int _rttHistoryCount = 0;         // Number of valid entries in _rttHistoryMicros.
    int _rttHistoryIndex = 0;         // Current write position in the _rttHistoryMicros circular buffer.

    // === BBR mode and round tracking ===

    double _fullBandwidthEstimate = 0.0;   // The best BtlBw seen during the current Startup phase; used to detect bandwidth growth stalls for Startup exit; mirrors C# _fullBandwidthEstimate.
    int _fullBandwidthRounds = 0;           // Number of consecutive rounds in which bandwidth has not grown by ≥ 25% (Startup stall counter); mirrors C# _fullBandwidthRounds.
    int _probeBwCycleIndex = 0;             // Current index into the 8-phase ProbeBw gain cycle (0..7); advances once per round; mirrors C# _probeBwCycleIndex.

    int64_t _modeEnteredMicros = 0;   // Timestamp in microseconds when the current BBR mode was entered; used for mode-duration exit checks; mirrors C# _modeEnteredMicros.
    int64_t _lastAckMicros = 0;       // Timestamp in microseconds of the most recent OnAck call; used to compute the wall-clock interval between ACKs; mirrors C# _lastAckMicros.

    int64_t _minRttTimestampMicros = 0;   // Timestamp of the most recent minimum-RTT update; used to detect MinRtt staleness and trigger ProbeRtt; mirrors C# _minRttTimestampMicros.
    int64_t _probeRttEnteredMicros = 0;   // Timestamp when the current ProbeRtt cycle was entered; used for ProbeRtt exit-condition evaluation; mirrors C# _probeRttEnteredMicros.

    int64_t _totalDeliveredBytes = 0;           // Cumulative sum of bytes delivered (newly acknowledged) since the connection started; used for round-boundary detection; mirrors C# _totalDeliveredBytes.
    int64_t _nextRoundDeliveredBytes = 0;       // The delivered-byte threshold at which the next BBR round begins (approximately one BDP's worth of data ahead); mirrors C# _nextRoundDeliveredBytes.
    int64_t _currentRttMicros = 0;              // The most recent valid RTT sample in microseconds; stored for diagnostic/round-tracking purposes; mirrors C# _currentRttMicros.

    // === Loss tracking (time-bucketed) ===

    int64_t _lossBucketStartMicros = 0;                     // Start timestamp of the current loss-bucket window in microseconds; used to align and advance the bucket ring; mirrors C# _lossBucketStartMicros.
    int _lossBucketIndex = 0;                                // Current write position in the loss-bucket circular buffers (_sentBuckets and _retransmitBuckets); mirrors C# _lossBucketIndex.
    ucp::array<int, kLossBucketCount> _sentBuckets{};        // Per-bucket sent-packet counters; each bucket represents a fixed-duration time slot (100 ms); mirrors C# _sentBuckets.
    ucp::array<int, kLossBucketCount> _retransmitBuckets{};  // Per-bucket retransmit-packet counters; mirrors C# _retransmitBuckets.

    // === Derived state ===

    double _lossCwndGain = 1.0;                        // Multiplicative CWND reduction factor from congestion loss events (1.0 = no reduction, 0.70 after one event); mirrors C# _lossCwndGain.
    double _deliveryRateBytesPerSecond = 0.0;           // The most recent instantaneous delivery-rate estimate in bytes/s; mirrors C# _deliveryRateBytesPerSecond.
    double _inflightHighBytes = 0.0;                    // Upper bound on in-flight bytes (CWND ceiling derived from BDP × high-gain multiplier); mirrors C# _inflightHighBytes.
    double _inflightLowBytes = 0.0;                     // Lower bound on in-flight bytes (CWND floor derived from BDP × low-gain multiplier); mirrors C# _inflightLowBytes.
    double _maxBandwidthLossPercent = 0.0;              // Effective loss-percentage threshold loaded from config; used by loss-control feature to decide when loss has exceeded the budget; mirrors C# _maxBandwidthLossPercent.

    int64_t _fastRecoveryEnteredMicros = 0;             // Timestamp when fast recovery was entered (non-congestion loss); 0 means not currently in fast recovery; mirrors C# _fastRecoveryEnteredMicros.

    // === Bandwidth growth stall detection ===

    int64_t _bandwidthGrowthWindowMicros = 0;           // Start timestamp of the current bandwidth-growth-stall detection window (resets each RTT); mirrors C# _bandwidthGrowthWindowMicros.
    double _bandwidthGrowthWindowStartRate = 0.0;       // BtlBw value at the start of the current bandwidth-growth-stall window; used as the baseline for the per-round growth clamp; mirrors C# _bandwidthGrowthWindowStartRate.
    double _maxBtlBwInNonCongestedWindow = 0.0;         // Maximum BtlBw observed outside of congestion; serves as a soft floor (90% recovery) to prevent transient dips from permanently depressing the estimate; mirrors C# _maxBtlBwInNonCongestedWindow.

    NetworkCondition _networkCondition = NetworkCondition::Idle;  // Current network condition classification (Idle, LightLoad, Congested, or RandomLoss); mirrors C# _networkCondition.

    // === Path classifier ===

    ucp::array<ClassifierWindow, kClassifierWindowCount> _classifierWindows{};  // Circular buffer of finalized classifier observation windows (each ~200ms); used by ClassifyNetworkPath; mirrors C# _classifierWindows.
    int _classifierWindowIndex = 0;          // Current write position in the classifier-window circular buffer; mirrors C# _classifierWindowIndex.
    int _classifierWindowCount = 0;          // Number of finalized classifier windows in the buffer; mirrors C# _classifierWindowCount.
    int64_t _classifierWindowStartMicros = 0;   // Start timestamp of the currently accumulating (not-yet-finalized) classifier window; mirrors C# _classifierWindowStartMicros.
    int64_t _classifierWindowSentBytes = 0;     // Total bytes sent+acked in the current classifier window; used for throughput ratio computation; mirrors C# _classifierWindowSentBytes.
    int64_t _classifierWindowMinRttMicros = 0;  // Minimum RTT observed during the current classifier window; mirrors C# _classifierWindowMinRttMicros.
    int64_t _classifierWindowMaxRttMicros = 0;  // Maximum RTT observed during the current classifier window; mirrors C# _classifierWindowMaxRttMicros.
    int64_t _classifierWindowRttSumMicros = 0;  // Running sum of all RTT samples collected in the current classifier window; mirrors C# _classifierWindowRttSumMicros.
    int _classifierWindowRttCount = 0;          // Number of RTT samples collected in the current classifier window; mirrors C# _classifierWindowRttCount.

    // === Public-facing derived values ===

    NetworkClass _currentNetworkClass = NetworkClass::Default; // The most recent network-path classification (updated each OnAck via ClassifyNetworkPath); mirrors C# CurrentNetworkClass.
    BbrMode _mode = BbrMode::Startup;                          // Current BBR operating mode (Startup, Drain, ProbeBw, or ProbeRtt); mirrors C# Mode.
    double _btlBwBytesPerSecond = 0.0;                         // Estimated bottleneck bandwidth in bytes/s (the max-filter output from AddRateSample); mirrors C# BtlBwBytesPerSecond.
    int64_t _minRttMicros = 0;                                 // Minimum observed RTT in microseconds (sticky floor with up to 25% reduction per update); mirrors C# MinRttMicros.
    double _pacingGain = 0.0;                                  // Current effective pacing gain multiplier applied to BtlBw; mirrors C# PacingGain.
    double _cwndGain = 0.0;                                    // Current effective congestion-window gain multiplier; mirrors C# CwndGain.
    double _pacingRateBytesPerSecond = 0.0;                    // Current effective pacing rate (BtlBw × PacingGain) in bytes/s; mirrors C# PacingRateBytesPerSecond.
    int _congestionWindowBytes = 0;                            // Current congestion window in bytes (the output of GetTargetCwndBytes); mirrors C# CongestionWindowBytes.
    double _estimatedLossPercent = 0.0;                        // EWMA-smoothed loss percentage estimate (0.0–100.0); mirrors C# EstimatedLossPercent.
};

} // namespace ucp
