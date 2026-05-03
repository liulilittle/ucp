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

#include <cstdint>
#include <array>
#include "ucp_enums.h"

namespace ucp {

/** @brief Configuration subset specific to the BBR congestion controller.
 *
 *  Pulled from UcpConfiguration when constructing BbrCongestionControl.
 *  Mirrors C# Ucp.Internal.BbrConfig.
 */
struct BbrConfig {
    int Mss = 1220;                                  //< Maximum segment size (bytes).
    double StartupPacingGain = 2.89;                 //< Pacing gain during Startup (≈ 2.89 = 2/ln(2)).
    double StartupCwndGain = 2.0;                    //< Cwnd gain during Startup.
    double DrainPacingGain = 1.0;                    //< Pacing gain during Drain (may be reduced with loss).
    double ProbeBwHighGain = 1.35;                   //< Pacing gain during the high-gain ProbeBw cycle (1 of 8).
    double ProbeBwLowGain = 0.85;                    //< Pacing gain during the low-gain ProbeBw cycles (7 of 8).
    double ProbeBwCwndGain = 2.0;                    //< Cwnd gain during ProbeBw.
    double MaxBandwidthWastePercent = 0.25;          //< Max fraction of bandwidth treated as waste (cwnd clamping).
    double MaxBandwidthLossPercent = 0.25;           //< Loss threshold for triggering aggressive response.
    double EffectiveMaxBandwidthLossPercent = 0.25;  //< Clamped loss threshold from config.
    bool LossControlEnable = true;                   //< Whether to treat loss as a congestion signal.
    bool EnableDebugLog = false;                     //< Enable verbose debug logging to stderr.
    int64_t InitialBandwidthBytesPerSecond = 12500000; //< Initial bandwidth estimate (bytes/s).
    int64_t MaxPacingRateBytesPerSecond = 0;          //< Hard ceiling on pacing rate (0 = unlimited).
    int MaxCongestionWindowBytes = 0;                  //< Hard ceiling on cwnd (0 = unlimited).
    int InitialCongestionWindowBytes = 24400;          //< Initial cwnd in bytes (≈ 20 × MSS).
    int BbrWindowRtRounds = 10;                        //< Number of RTTs for max-bandwidth windowing.
    int64_t ProbeRttIntervalMicros = 30000000;         //< Interval between ProbeRtt entries (30 s).
    int64_t ProbeRttDurationMicros = 100000;           //< Minimum ProbeRtt duration (100 ms).
};

/** @brief Aggregated statistics for one classifier observation window.
 *
 *  The path classifier slides a window of kNetworkClassifierWindowCount
 *  observations, each summarizing avg RTT, loss rate, jitter, and throughput
 *  ratio over a fixed duration (kNetworkClassifierWindowDurationMicros).
 */
struct ClassifierWindow {
    double AvgRttMicros = 0.0;     //< Arithmetic mean RTT during the window (microseconds).
    double LossRate = 0.0;         //< Loss ratio snapshot (0.0 .. 1.0).
    double JitterMicros = 0.0;     //< max_rtt - min_rtt during the window (microseconds).
    double ThroughputRatio = 0.0;  //< Actual throughput / estimated bottleneck bandwidth (0.0 .. 1.0).
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
 */
class BbrCongestionControl {
public:
    /** @brief Default constructor (uses default BbrConfig). */
    BbrCongestionControl();
    /** @brief Construct with an explicit BbrConfig.
     *  @param config  BBR configuration values. */
    explicit BbrCongestionControl(const BbrConfig& config);

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

    NetworkClass CurrentNetworkClass() const { return _currentNetworkClass; }  //< Path classification determined by the classifier.
    BbrMode Mode() const { return _mode; }                                    //< Current BBR operating mode.
    double BtlBwBytesPerSecond() const { return _btlBwBytesPerSecond; }        //< Estimated bottleneck bandwidth (bytes/s).
    int64_t MinRttMicros() const { return _minRttMicros; }                    //< Minimum observed RTT (microseconds).
    double PacingGain() const { return _pacingGain; }                         //< Current effective pacing gain multiplier.
    double CwndGain() const { return _cwndGain; }                             //< Current effective cwnd gain multiplier.
    double PacingRateBytesPerSecond() const { return _pacingRateBytesPerSecond; } //< Current effective pacing rate (bytes/s).
    int CongestionWindowBytes() const { return _congestionWindowBytes; }       //< Current congestion window (bytes).
    double EstimatedLossPercent() const { return _estimatedLossPercent; }      //< EWMA-smoothed loss percentage (0..100).

private:
    // === Internal constants ===

    static constexpr int kRecentRateSampleCount = 10;        //< Number of recent delivery-rate samples for max-rate window.
    static constexpr int kDeliveryRateHistoryCount = 16;     //< Delivery-rate history for trend detection.
    static constexpr int kRttHistoryCount = 32;              //< RTT history for percentile calculation.
    static constexpr int kLossBucketCount = 10;              //< Number of time-buckets for loss ratio tracking.
    static constexpr int kClassifierWindowCount = 8;         //< Number of classifier observation windows.

    // === Internal update methods ===

    void AddRateSample(double deliveryRate, int64_t nowMicros);
    void AddDeliveryRateSample(double deliveryRate);
    void AddRttSample(int64_t sampleRttMicros);
    int GetTargetCwndBytes();
    void RecalculateModel(int64_t nowMicros);
    void EnterDrain(int64_t nowMicros);
    void EnterProbeBw(int64_t nowMicros);
    void EnterProbeRtt(int64_t nowMicros);
    void ExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros);
    bool ShouldExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros);
    double CalculatePacingGain(int64_t nowMicros);
    double CalculateLossPercent(int64_t nowMicros);
    NetworkCondition ClassifyNetworkCondition(int64_t nowMicros);
    bool ShouldTreatLossAsCongestion(int64_t nowMicros, bool isCongestionSignal);
    int64_t GetCwndModelRttMicros();
    double GetAverageRttIncreaseRatio();
    int64_t GetP10RttMicros();
    int64_t GetP25RttMicros();
    int64_t GetP30RttMicros();
    int64_t GetPercentileRtt(double percentile);
    void UpdateInflightBounds();
    double GetRecentLossRatio(int64_t nowMicros);
    void AdvanceLossBuckets(int64_t nowMicros);
    double GetEffectiveCwndGain();
    double GetDrainPacingGain(int64_t nowMicros);
    void AdvanceClassifierWindow(int64_t nowMicros, int sentOrAckedBytes, int64_t sampleRttMicros, double lossRateSnapshot);
    NetworkClass ClassifyNetworkPath();
    void UpdateEstimatedLossPercent(int64_t nowMicros);
    void UpdateEstimatedLossPercent(int64_t nowMicros, double candidateLossPercent);
    void UpdateStartup();
    double ClampBandwidthGrowth(double candidateRate, int64_t nowMicros);
    void TraceLog(const char* message);

    // === Configuration ===

    BbrConfig _config;  //< BBR configuration subset.

    // === Bandwidth estimation ===

    std::array<double, kRecentRateSampleCount> _recentRates{};              //< Ring buffer of recent delivery-rate samples.
    std::array<int64_t, kRecentRateSampleCount> _recentRateTimestamps{};    //< Timestamps corresponding to _recentRates.
    int _recentRateCount = 0;       //< Number of valid entries in _recentRates.
    int _recentRateIndex = 0;       //< Current insertion index.

    std::array<double, kDeliveryRateHistoryCount> _deliveryRateHistory{};   //< Ring buffer for delivery-rate trend detection.
    int _deliveryRateHistoryCount = 0;  //< Valid count.
    int _deliveryRateHistoryIndex = 0;  //< Insertion index.

    // === RTT tracking ===

    std::array<int64_t, kRttHistoryCount> _rttHistoryMicros{};  //< Ring buffer of RTT samples for percentile queries.
    int _rttHistoryCount = 0;         //< Valid count.
    int _rttHistoryIndex = 0;         //< Insertion index.

    // === BBR mode and round tracking ===

    double _fullBandwidthEstimate = 0.0;   //< Bandwidth estimate from the last full-bandwidth round.
    int _fullBandwidthRounds = 0;           //< Number of consecutive rounds without doubling bandwidth.
    int _probeBwCycleIndex = 0;             //< Index into the 8-phase ProbeBw gain cycle (0..7).

    int64_t _modeEnteredMicros = 0;   //< Timestamp when current mode was entered.
    int64_t _lastAckMicros = 0;       //< Timestamp of the most recent OnAck call.

    int64_t _minRttTimestampMicros = 0;   //< Timestamp of the most recent min RTT update.
    int64_t _probeRttEnteredMicros = 0;   //< Timestamp when ProbeRtt mode was entered.

    int64_t _totalDeliveredBytes = 0;           //< Cumulative delivered bytes (lifetime).
    int64_t _nextRoundDeliveredBytes = 0;       //< Delivered-byte threshold for the next round boundary.
    int64_t _currentRttMicros = 0;              //< Most recent RTT sample (microseconds).

    // === Loss tracking (time-bucketed) ===

    int64_t _lossBucketStartMicros = 0;                     //< Timestamp of the start of the current loss bucket.
    int _lossBucketIndex = 0;                                //< Index of the current bucket in _sentBuckets / _retransmitBuckets.
    std::array<int, kLossBucketCount> _sentBuckets{};        //< Per-bucket sent-packet counts.
    std::array<int, kLossBucketCount> _retransmitBuckets{};  //< Per-bucket retransmit counts.

    // === Derived state ===

    double _lossCwndGain = 1.0;                        //< Multiplicative cwnd reduction from loss events (1.0 = no reduction).
    double _deliveryRateBytesPerSecond = 0.0;           //< Current delivery rate estimate (bytes/s).
    double _inflightHighBytes = 0.0;                    //< Upper bound on in-flight bytes (ceil from BDP × gain).
    double _inflightLowBytes = 0.0;                     //< Lower bound on in-flight bytes (floor from BDP × gain).
    double _maxBandwidthLossPercent = 0.0;              //< Effective loss percent threshold.

    int64_t _fastRecoveryEnteredMicros = 0;             //< Timestamp when fast recovery was entered (0 = not in recovery).

    // === Bandwidth growth stall detection ===

    int64_t _bandwidthGrowthWindowMicros = 0;           //< Start of the current growth-stall detection window.
    double _bandwidthGrowthWindowStartRate = 0.0;       //< Bandwidth at the start of the growth-stall window.
    double _maxBtlBwInNonCongestedWindow = 0.0;         //< Max bottleneck bandwidth seen outside of congestion.

    NetworkCondition _networkCondition = NetworkCondition::Idle;  //< Current network condition classification.

    // === Path classifier ===

    std::array<ClassifierWindow, kClassifierWindowCount> _classifierWindows{};  //< Ring buffer of classifier observation windows.
    int _classifierWindowIndex = 0;          //< Insertion index.
    int _classifierWindowCount = 0;          //< Valid count.
    int64_t _classifierWindowStartMicros = 0;   //< Start timestamp of the current observation window.
    int64_t _classifierWindowSentBytes = 0;     //< Total bytes sent+acked in the current window.
    int64_t _classifierWindowMinRttMicros = 0;  //< Min RTT seen in the current window.
    int64_t _classifierWindowMaxRttMicros = 0;  //< Max RTT seen in the current window.
    int64_t _classifierWindowRttSumMicros = 0;  //< Sum of RTT samples in the current window.
    int _classifierWindowRttCount = 0;          //< Number of RTT samples in the current window.

    // === Public-facing derived values ===

    NetworkClass _currentNetworkClass = NetworkClass::Default; //< Most recent path classification.
    BbrMode _mode = BbrMode::Startup;                          //< Current BBR mode.
    double _btlBwBytesPerSecond = 0.0;                         //< Bottleneck bandwidth estimate (bytes/s).
    int64_t _minRttMicros = 0;                                 //< Minimum observed RTT (microseconds).
    double _pacingGain = 0.0;                                  //< Effective pacing gain multiplier.
    double _cwndGain = 0.0;                                    //< Effective cwnd gain multiplier.
    double _pacingRateBytesPerSecond = 0.0;                    //< Effective pacing rate (bytes/s).
    int _congestionWindowBytes = 0;                            //< Current cwnd (bytes).
    double _estimatedLossPercent = 0.0;                        //< EWMA-smoothed loss percentage.
};

} // namespace ucp
