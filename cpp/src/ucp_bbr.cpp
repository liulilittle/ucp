/** @file ucp_bbr.cpp
 *  @brief BBRv1 congestion control implementation — mirrors C# Ucp.Internal.BbrCongestionControl.
 *
 *  Implements the BBR (Bottleneck Bandwidth and Round-trip time) algorithm.
 *  BBR estimates the path's bottleneck bandwidth and minimum RTT, then
 *  adjusts pacing rate and congestion window to operate near the optimal
 *  point (BDP) without filling the bottleneck queue.  The operational cycle
 *  is:  Startup (exponential probe) → Drain (queue drain) → ProbeBw (cyclic
 *  gain probes) → ProbeRtt (periodic min-RTT refresh every 30 s).
 *
 *  Includes network path classification (LowLatencyLAN, MobileUnstable,
 *  LossyLongFat, CongestedBottleneck, SymmetricVPN) to adapt gain and
 *  inflight bounds to the observed path characteristics.
 */

#include "ucp/ucp_bbr.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <chrono>

namespace ucp {

// ====================================================================================================
// Local constants
// ====================================================================================================

static int64_t NowMicroseconds() {
    static const auto start = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now - start).count());
}

static constexpr int64_t kMicrosPerSecond = 1000000;           //< Microseconds per second.
static constexpr int64_t kMicrosPerMilli = 1000;               //< Microseconds per millisecond.

// === BBR timing constants ===

static constexpr int64_t kProbeRttIntervalMicros = 30000000;   //< ProbeRtt entry interval (30 s).
static constexpr int64_t kProbeRttDurationMicros = 100000;     //< Minimum ProbeRtt duration (100 ms).
static constexpr double kProbeRttPacingGain = 0.85;            //< Pacing gain during ProbeRtt (drain).
static constexpr double kProbeRttExitRttMultiplier = 1.05;     //< Up to 5% above min RTT qualifies as fresh min sample.
static constexpr int64_t kProbeRttMaxDurationMultiplier = 2;   //< Hard safety timeout at 2x ProbeRttDurationMicros.
static constexpr int kProbeBwGainCount = 8;                    //< Number of gain phases in ProbeBw cycle.
static constexpr double kStartupGrowthTarget = 1.25;            //< Bandwidth increase threshold for Startup growth detection.
static constexpr int kMinStartupFullBandwidthRounds = 3;       //< Minimum stalled rounds before exiting Startup.
static constexpr int kRtoMaxBackoffMinRtoMultiplier = 2;       //< Minimum RTT multiplication factor for RTO backoff.
static constexpr int kWindowRtRounds = 10;                      //< Default window width for BBR bandwidth estimation.
static constexpr double kStartupAckAggregationRateCapGain = 4.0;   //< Max ACK aggregation gain in Startup.
static constexpr double kSteadyAckAggregationRateCapGain = 1.50;   //< Max ACK aggregation gain in steady state.
static constexpr double kStartupBandwidthGrowthPerRound = 2.0;     //< Max bandwidth growth per RTT in Startup.
static constexpr double kSteadyBandwidthGrowthPerRound = 1.25;     //< Max bandwidth growth per RTT in steady state.
static constexpr int64_t kDefaultRateWindowMicros = kMicrosPerSecond; //< Default rate window (1 s).
static constexpr int64_t kBandwidthGrowthFallbackIntervalMicros = 10000; //< Fallback interval for growth clamping (10 ms).

// === Loss recovery constants ===

static constexpr double kLossCwndRecoveryStep = 0.08;           //< Cwnd recovery step per ACK after loss (8%).
static constexpr double kLossCwndRecoveryStepFast = 0.15;       //< Faster recovery step for Mobile/random-loss.
static constexpr double kCongestionLossReduction = 0.98;        //< Cwnd multiplier on congestion loss (98%).
static constexpr double kMinLossCwndGain = 0.95;                //< Minimum loss cwnd multiplier (95%).
static constexpr double kLossBudgetRecoveryRatio = 0.80;        //< Recovery trigger threshold (80% of max loss budget).

// === Loss EWMA constants ===

static constexpr double kLossEwmaIdleDecay = 0.90;              //< Decay factor when no loss is observed.
static constexpr double kLossEwmaRetainedWeight = 0.75;         //< Weight of previous EWMA estimate.
static constexpr double kLossEwmaSampleWeight = 0.25;           //< Weight of new sample.

// === Congestion classification thresholds ===

static constexpr double kCongestionRateDropRatio = -0.15;       //< Delivery rate drop ratio for congestion signal.
static constexpr double kCongestionRttIncreaseRatio = 0.50;     //< RTT increase ratio for congestion signal.
static constexpr double kCongestionLossRatio = 0.10;            //< Loss ratio for congestion signal.
static constexpr int kCongestionRateDropScore = 1;              //< Score for rate drop.
static constexpr int kCongestionRttGrowthScore = 1;             //< Score for RTT growth.
static constexpr int kCongestionLossScore = 1;                  //< Score for loss.
static constexpr int kCongestionClassifierScoreThreshold = 2;   //< Cumulative score threshold for congestion.

// === Random loss thresholds ===

static constexpr double kRandomLossMaxRttIncreaseRatio = 0.20;  //< Max RTT increase for a loss to be considered random.
static constexpr double kRateLossHintMaxRatio = 0.05;           //< Max additional loss from rate hints.

// === Pacing gain by network class ===

static constexpr double kFastRecoveryPacingGain = 1.25;          //< Pacing gain during fast recovery.
static constexpr double kHighLossPacingGain = 1.00;              //< Pacing gain under high loss.
static constexpr double kLowLossRatio = 0.01;                     //< Loss ratio threshold for "low loss".
static constexpr double kModerateLossRatio = 0.03;                //< Loss ratio threshold for "moderate loss".
static constexpr double kLightLossRatio = 0.08;                   //< Loss ratio threshold for "light loss".
static constexpr double kMediumLossRatio = 0.15;                  //< Loss ratio threshold for "medium loss".
static constexpr double kLowRttIncreaseRatio = 0.10;              //< RTT increase ratio for "low".
static constexpr double kModerateRttIncreaseRatio = 0.20;         //< RTT increase ratio for "moderate".
static constexpr double kModerateProbeGain = 1.50;                //< Moderate probe gain.
static constexpr double kLightLossPacingGain = 1.10;              //< Pacing gain under light loss.
static constexpr double kMediumLossPacingGain = 1.05;             //< Pacing gain under medium loss.

// === Inflight bounds ===

static constexpr double kInflightLowGain = 1.25;                 //< Lower inflight bound = BDP * 1.25.
static constexpr double kInflightHighGain = 2.00;                //< Upper inflight bound = BDP * 2.00.
static constexpr double kInflightMobileHighGain = 2.00;          //< Upper inflight bound for mobile paths.

static constexpr int64_t kMinRoundDurationMicros = kMicrosPerMilli; //< Minimum BBR round (1 ms).
static constexpr int64_t kLossBucketMicros = 100000;               //< Loss bucket duration (100 ms).
static constexpr int kLossBucketCount = 10;                         //< Number of loss buckets.

// === Network classifier thresholds ===

static constexpr double kNetworkClassifierLongFatRttMs = 80.0;    //< RTT threshold for LossyLongFat (80 ms).
static constexpr double kNetworkClassifierMobileLossRate = 0.03;   //< Loss threshold for MobileUnstable (3%).
static constexpr double kNetworkClassifierMobileJitterMs = 20.0;   //< Jitter threshold for MobileUnstable (20 ms).
static constexpr double kNetworkClassifierLanRttMs = 5.0;          //< RTT threshold for LowLatencyLAN (5 ms).
static constexpr double kNetworkClassifierLanJitterMs = 3.0;       //< Jitter threshold for LowLatencyLAN (3 ms).
static constexpr int64_t kNetworkClassifierWindowDurationMicros = 200000; //< Classifier observation window (200 ms).
static constexpr int kNetworkClassifierWindowCount = 8;            //< Number of classifier windows.

// ====================================================================================================
// Construction
// ====================================================================================================

BbrCongestionControl::BbrCongestionControl()
    : BbrCongestionControl(BbrConfig{}) {
}

BbrCongestionControl::BbrCongestionControl(const BbrConfig& config)
    : _config(config) {
    _mode = BbrMode::Startup;
    _pacingGain = _config.StartupPacingGain;
    _cwndGain = _config.StartupCwndGain;
    _maxBandwidthLossPercent = _config.EffectiveMaxBandwidthLossPercent;
    _btlBwBytesPerSecond = static_cast<double>(_config.InitialBandwidthBytesPerSecond);
    if (_config.MaxPacingRateBytesPerSecond > 0 && _btlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) {
        _btlBwBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond);
    }
    _minRttMicros = 0;
    RecalculateModel(NowMicroseconds());
}

// ====================================================================================================
// BBR lifecycle: Ack -> model update -> mode transitions
// ====================================================================================================

void BbrCongestionControl::OnAck(int64_t nowMicros, int deliveredBytes, int64_t sampleRttMicros, int flightBytes) {
    // === Update min RTT ===
    bool minRttExpired = _minRttMicros > 0 && nowMicros - _minRttTimestampMicros >= _config.ProbeRttIntervalMicros;
    if (sampleRttMicros > 0) {
        _currentRttMicros = sampleRttMicros;
        if (_minRttMicros == 0 || sampleRttMicros < _minRttMicros) {
            if (_minRttMicros > 0) {
                // Smoothly reduce min RTT (up to 25% improvement per sample)
                _minRttMicros = std::max(sampleRttMicros, static_cast<int64_t>(_minRttMicros * 0.75));
            } else {
                _minRttMicros = sampleRttMicros;
            }
            _minRttTimestampMicros = nowMicros;
            minRttExpired = false;
        }
    }

    // === Compute delivery rate ===
    int64_t intervalMicros;
    if (_lastAckMicros == 0) {
        intervalMicros = sampleRttMicros > 0 ? sampleRttMicros : 1;
    } else {
        intervalMicros = std::max(static_cast<int64_t>(1), nowMicros - _lastAckMicros);
    }
    _lastAckMicros = nowMicros;

    if (deliveredBytes > 0) {
        _totalDeliveredBytes += deliveredBytes;
        double deliveryRate = deliveredBytes * static_cast<double>(kMicrosPerSecond) / static_cast<double>(intervalMicros);
        // Cap by aggregation: delivery rate can't exceed pacing_rate + aggregation gain
        if (_pacingRateBytesPerSecond > 0) {
            double aggregationCapGain = _mode == BbrMode::Startup
                ? kStartupAckAggregationRateCapGain
                : kSteadyAckAggregationRateCapGain;
            deliveryRate = std::min(deliveryRate, _pacingRateBytesPerSecond * aggregationCapGain);
        }
        _deliveryRateBytesPerSecond = deliveryRate;
        AddRateSample(deliveryRate, nowMicros);
        AddDeliveryRateSample(deliveryRate);

        // === Recover loss cwnd gain ===
        if (_lossCwndGain < 1.0 && _mode != BbrMode::ProbeRtt) {
            double recoveryStep = (_currentNetworkClass == NetworkClass::MobileUnstable
                                    || _networkCondition == NetworkCondition::RandomLoss)
                ? kLossCwndRecoveryStepFast
                : kLossCwndRecoveryStep;
            _lossCwndGain = std::min(1.0, _lossCwndGain + recoveryStep);
            if (_currentNetworkClass == NetworkClass::MobileUnstable && _lossCwndGain < 0.98) {
                _lossCwndGain = std::min(1.0, _lossCwndGain + recoveryStep * 2.0);
            }
        }
    }

    // === Track RTT history for percentile estimation ===
    if (sampleRttMicros > 0) {
        AddRttSample(sampleRttMicros);
    }

    // === Path classification ===
    AdvanceClassifierWindow(nowMicros, deliveredBytes + flightBytes, sampleRttMicros, GetRecentLossRatio(nowMicros));
    _currentNetworkClass = ClassifyNetworkPath();

    _networkCondition = ClassifyNetworkCondition(nowMicros);
    if (_networkCondition == NetworkCondition::Congested) {
        _maxBtlBwInNonCongestedWindow = 0;
    }

    UpdateEstimatedLossPercent(nowMicros);
    UpdateInflightBounds();

    // === ProbeRtt transitions ===
    if (minRttExpired && _mode != BbrMode::ProbeRtt) {
        bool bandwidthGrowthStalled = _fullBandwidthRounds >= kRtoMaxBackoffMinRtoMultiplier;
        bool isLossyFat = _currentNetworkClass == NetworkClass::LossyLongFat;
        bool isMobile = _currentNetworkClass == NetworkClass::MobileUnstable;

        if (isMobile) {
            _minRttTimestampMicros = nowMicros;  // Postpone ProbeRtt on mobile paths
        } else if (bandwidthGrowthStalled || !isLossyFat) {
            EnterProbeRtt(nowMicros);
        } else {
            char buf[256];
            snprintf(buf, sizeof(buf), "SkipProbeRtt btlBw=%.0f fullBwRounds=%d preservedOnLossyFat",
                     _btlBwBytesPerSecond, _fullBandwidthRounds);
            TraceLog(buf);
        }
    }

    // === Round detection ===
    bool roundStart = false;
    if (_nextRoundDeliveredBytes == 0) {
        _nextRoundDeliveredBytes = _totalDeliveredBytes + std::max(static_cast<int64_t>(deliveredBytes), static_cast<int64_t>(flightBytes));
    } else if (_totalDeliveredBytes >= _nextRoundDeliveredBytes) {
        _nextRoundDeliveredBytes = _totalDeliveredBytes + std::max(static_cast<int64_t>(deliveredBytes), static_cast<int64_t>(flightBytes));
        roundStart = deliveredBytes > 0;
    }

    // === Mode-specific updates ===
    if (_mode == BbrMode::Startup) {
        if (roundStart) {
            UpdateStartup();
        }
    } else if (_mode == BbrMode::Drain) {
        if (flightBytes <= GetTargetCwndBytes() || nowMicros - _modeEnteredMicros >= std::max(_minRttMicros, kMinRoundDurationMicros)) {
            EnterProbeBw(nowMicros);
        }
    } else if (_mode == BbrMode::ProbeBw) {
        // Cycle through 8 gain phases every min_rtt
        if (nowMicros - _modeEnteredMicros >= std::max(_minRttMicros, kMinRoundDurationMicros)) {
            _probeBwCycleIndex = (_probeBwCycleIndex + 1) % kProbeBwGainCount;
            _modeEnteredMicros = nowMicros;
        }
        // Mobile/Lossy paths: use low gain for 7 of 8 cycles, moderate for 1
        if ((_currentNetworkClass == NetworkClass::MobileUnstable
             || _currentNetworkClass == NetworkClass::LossyLongFat)
            && _networkCondition != NetworkCondition::Congested) {
            if (_probeBwCycleIndex < kProbeBwGainCount - 1) {
                _pacingGain = CalculatePacingGain(nowMicros);
            } else {
                _pacingGain = std::min(1.0, _config.ProbeBwLowGain);
            }
        } else {
            _pacingGain = CalculatePacingGain(nowMicros);
        }
    } else if (_mode == BbrMode::ProbeRtt) {
        _pacingGain = kProbeRttPacingGain;
        if (ShouldExitProbeRtt(nowMicros, sampleRttMicros)) {
            ExitProbeRtt(nowMicros, sampleRttMicros);
        }
    }

    // === Exit fast recovery after min_rtt expires ===
    if (_fastRecoveryEnteredMicros > 0 && _minRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros >= _minRttMicros) {
        _fastRecoveryEnteredMicros = 0;
    }

    RecalculateModel(nowMicros);
}

void BbrCongestionControl::OnPacketSent(int64_t nowMicros, bool isRetransmit) {
    // Advance loss bucket
    AdvanceLossBuckets(nowMicros);
    _sentBuckets[_lossBucketIndex]++;
    if (isRetransmit) {
        _retransmitBuckets[_lossBucketIndex]++;
    }
}

void BbrCongestionControl::OnFastRetransmit(int64_t nowMicros, bool isCongestion) {
    if (_config.EnableDebugLog) {
        TraceLog("FastRetransmit");
    }
    if (!isCongestion) {
        _fastRecoveryEnteredMicros = nowMicros;
        _pacingGain = kFastRecoveryPacingGain;
        RecalculateModel(nowMicros);
    }
    OnPacketLoss(nowMicros, GetRecentLossRatio(nowMicros), isCongestion);
}

void BbrCongestionControl::OnPacketLoss(int64_t nowMicros, double lossRate, bool isCongestion) {
    if (nowMicros <= 0) {
        nowMicros = NowMicroseconds();
    }
    double recentLossRate = GetRecentLossRatio(nowMicros);
    lossRate = std::max(lossRate, recentLossRate);

    _networkCondition = ClassifyNetworkCondition(nowMicros);
    UpdateEstimatedLossPercent(nowMicros, lossRate * 100.0);

    bool treatAsCongestion = ShouldTreatLossAsCongestion(nowMicros, isCongestion);

    if (treatAsCongestion) {
        // Reduce cwnd multiplicatively
        _lossCwndGain = std::max(kMinLossCwndGain, _lossCwndGain * kCongestionLossReduction);
        if (_mode != BbrMode::ProbeRtt && _mode != BbrMode::Startup) {
            EnterProbeRtt(nowMicros);
        }
    } else {
        // Random loss: enter fast recovery with increased pacing gain
        _fastRecoveryEnteredMicros = nowMicros;
        if (_mode == BbrMode::ProbeBw) {
            _pacingGain = std::max(_pacingGain, CalculatePacingGain(nowMicros));
        }
    }

    RecalculateModel(nowMicros);
}

void BbrCongestionControl::OnPathChange(int64_t nowMicros) {
    // Reset all path-dependent state to relearn the new path from scratch
    _minRttTimestampMicros = 0;
    _minRttMicros = 0;
    _rttHistoryMicros.fill(0);
    _rttHistoryCount = 0;
    _rttHistoryIndex = 0;
    _bandwidthGrowthWindowMicros = 0;
    _bandwidthGrowthWindowStartRate = 0;
    _classifierWindowCount = 0;
    _classifierWindowIndex = 0;
    _classifierWindowStartMicros = 0;
    _fullBandwidthRounds = 0;
    _fullBandwidthEstimate = 0;
    _nextRoundDeliveredBytes = 0;
    RecalculateModel(nowMicros);
    char buf[128];
    snprintf(buf, sizeof(buf), "PathChange btlBw=%.0f cwnd=%d", _btlBwBytesPerSecond, _congestionWindowBytes);
    TraceLog(buf);
}

// ====================================================================================================
// Startup detection
// ====================================================================================================

void BbrCongestionControl::UpdateStartup() {
    double current = _btlBwBytesPerSecond;
    if (_fullBandwidthEstimate <= 0) {
        _fullBandwidthEstimate = current;
        return;
    }

    // If bandwidth is still growing (>= 1.25×), reset the stall counter
    if (current >= _fullBandwidthEstimate * kStartupGrowthTarget) {
        _fullBandwidthEstimate = current;
        _fullBandwidthRounds = 0;
    } else {
        _fullBandwidthRounds++;
    }

    int requiredStallRounds = kMinStartupFullBandwidthRounds;
    if (_config.MaxPacingRateBytesPerSecond > 0
        && _btlBwBytesPerSecond >= _config.MaxPacingRateBytesPerSecond * 0.90) {
        requiredStallRounds = 1;  // Near max rate: exit startup quickly
    }

    if (_fullBandwidthRounds >= requiredStallRounds) {
        EnterDrain(_lastAckMicros);
    }
}

// ====================================================================================================
// Rate sampling and bandwidth estimation
// ====================================================================================================

void BbrCongestionControl::AddRateSample(double deliveryRate, int64_t nowMicros) {
    // Store sample in ring buffer
    _recentRates[_recentRateIndex] = deliveryRate;
    _recentRateTimestamps[_recentRateIndex] = nowMicros;
    _recentRateIndex = (_recentRateIndex + 1) % kRecentRateSampleCount;
    if (_recentRateCount < kRecentRateSampleCount) {
        _recentRateCount++;
    }

    // Find max rate within the BBR window
    double maxRate = 0;
    int64_t rttWindowMicros = _minRttMicros > 0
        ? _minRttMicros * std::max(static_cast<int64_t>(1), static_cast<int64_t>(_config.BbrWindowRtRounds))
        : kDefaultRateWindowMicros;

    for (int i = 0; i < _recentRateCount; i++) {
        if (nowMicros - _recentRateTimestamps[i] > std::max(rttWindowMicros, static_cast<int64_t>(1))) {
            continue;
        }
        if (_recentRates[i] > maxRate) {
            maxRate = _recentRates[i];
        }
    }

    if (maxRate > 0) {
        maxRate = ClampBandwidthGrowth(maxRate, nowMicros);
        if (_config.MaxPacingRateBytesPerSecond > 0 && maxRate > _config.MaxPacingRateBytesPerSecond) {
            maxRate = static_cast<double>(_config.MaxPacingRateBytesPerSecond);
        }

        // Track max bandwidth in non-congested state for recovery
        if (_networkCondition != NetworkCondition::Congested) {
            if (maxRate > _maxBtlBwInNonCongestedWindow) {
                _maxBtlBwInNonCongestedWindow = maxRate;
            }
        }

        _btlBwBytesPerSecond = maxRate;

        // Floor at initial bandwidth (never drop below zero)
        if (_btlBwBytesPerSecond < _config.InitialBandwidthBytesPerSecond) {
            _btlBwBytesPerSecond = static_cast<double>(_config.InitialBandwidthBytesPerSecond);
            if (_config.MaxPacingRateBytesPerSecond > 0 && _btlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) {
                _btlBwBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond);
            }
        }

        // Recover from congestion: restore towards non-congested max if loss is low
        if (_networkCondition != NetworkCondition::Congested
            && _maxBtlBwInNonCongestedWindow > 0
            && GetRecentLossRatio(nowMicros) < 0.05
            && _btlBwBytesPerSecond < _maxBtlBwInNonCongestedWindow * 0.90) {
            _btlBwBytesPerSecond = _maxBtlBwInNonCongestedWindow * 0.90;
        }
    }
}

double BbrCongestionControl::ClampBandwidthGrowth(double candidateRate, int64_t nowMicros) {
    if (candidateRate <= _btlBwBytesPerSecond || _btlBwBytesPerSecond <= 0) {
        return candidateRate;
    }

    int64_t growthIntervalMicros = _minRttMicros > 0 ? _minRttMicros : kBandwidthGrowthFallbackIntervalMicros;
    if (_bandwidthGrowthWindowMicros == 0 || nowMicros - _bandwidthGrowthWindowMicros >= growthIntervalMicros) {
        _bandwidthGrowthWindowMicros = nowMicros;
        _bandwidthGrowthWindowStartRate = _btlBwBytesPerSecond;
    }

    double growthGain = _mode == BbrMode::Startup
        ? kStartupBandwidthGrowthPerRound
        : kSteadyBandwidthGrowthPerRound;
    double growthCap = std::max(_btlBwBytesPerSecond, _bandwidthGrowthWindowStartRate * growthGain);
    return std::min(candidateRate, growthCap);
}

void BbrCongestionControl::AddDeliveryRateSample(double deliveryRate) {
    _deliveryRateHistory[_deliveryRateHistoryIndex] = deliveryRate;
    _deliveryRateHistoryIndex = (_deliveryRateHistoryIndex + 1) % kDeliveryRateHistoryCount;
    if (_deliveryRateHistoryCount < kDeliveryRateHistoryCount) {
        _deliveryRateHistoryCount++;
    }
}

void BbrCongestionControl::AddRttSample(int64_t sampleRttMicros) {
    if (sampleRttMicros <= 0) return;
    if (sampleRttMicros > 500000) return;  // Ignore outliers >500ms

    _rttHistoryMicros[_rttHistoryIndex] = sampleRttMicros;
    _rttHistoryIndex = (_rttHistoryIndex + 1) % kRttHistoryCount;
    if (_rttHistoryCount < kRttHistoryCount) {
        _rttHistoryCount++;
    }
}

// ====================================================================================================
// Cwnd and model calculation
// ====================================================================================================

int BbrCongestionControl::GetTargetCwndBytes() {
    if (_btlBwBytesPerSecond <= 0 || _minRttMicros <= 0) {
        return _config.InitialCongestionWindowBytes;
    }

    int64_t modelRttMicros = GetCwndModelRttMicros();

    if (modelRttMicros > 500000 || modelRttMicros <= 0) {
        modelRttMicros = 500000;  // Cap at 500ms
    }

    // BDP = bandwidth * propagation_delay
    double bdp = _btlBwBytesPerSecond * (modelRttMicros / static_cast<double>(kMicrosPerSecond));
    double effectiveCwndGain = GetEffectiveCwndGain();
    int cwnd = static_cast<int>(std::ceil(bdp * effectiveCwndGain));
    if (cwnd < _config.InitialCongestionWindowBytes && _mode == BbrMode::Startup) {
        cwnd = _config.InitialCongestionWindowBytes;
    }

    // Clamp to configured max
    if (_config.MaxCongestionWindowBytes > 0 && cwnd > _config.MaxCongestionWindowBytes) {
        cwnd = _config.MaxCongestionWindowBytes;
    }

    // Apply loss cwnd gain (multiplicative reduction)
    if (_lossCwndGain < 1.0) {
        cwnd = static_cast<int>(std::ceil(cwnd * _lossCwndGain));
        if (cwnd < _config.InitialCongestionWindowBytes) {
            cwnd = _config.InitialCongestionWindowBytes;
        }
    }

    // Clamp to inflight bounds
    if (_inflightHighBytes > 0) {
        cwnd = std::min(cwnd, static_cast<int>(std::ceil(_inflightHighBytes)));
    }

    if (_inflightLowBytes > 0) {
        cwnd = std::max(cwnd, static_cast<int>(std::ceil(_inflightLowBytes)));
    }

    return cwnd;
}

void BbrCongestionControl::RecalculateModel(int64_t nowMicros) {
    if (_btlBwBytesPerSecond <= 0) {
        _btlBwBytesPerSecond = static_cast<double>(_config.InitialBandwidthBytesPerSecond);
    }

    if (_config.MaxPacingRateBytesPerSecond > 0 && _btlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) {
        _btlBwBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond);
    }

    if (_mode == BbrMode::ProbeRtt) {
        _pacingGain = kProbeRttPacingGain;
    }

    // Loss control: slowly increase pacing gain when loss is within budget
    if (_config.LossControlEnable) {
        if (_estimatedLossPercent <= _maxBandwidthLossPercent * kLossBudgetRecoveryRatio) {
            _pacingGain = std::min(_config.ProbeBwHighGain, _pacingGain + kLossCwndRecoveryStep);
        }
    }

    _pacingRateBytesPerSecond = _btlBwBytesPerSecond * _pacingGain;
    if (_config.MaxPacingRateBytesPerSecond > 0
        && _pacingRateBytesPerSecond > _config.MaxPacingRateBytesPerSecond
        && _estimatedLossPercent < 3.0) {
        _pacingRateBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond);
    }

    // Allow extra burst headroom for stable-path non-mobile classes
    if (_config.MaxPacingRateBytesPerSecond > 0
        && _currentNetworkClass != NetworkClass::MobileUnstable
        && _currentNetworkClass != NetworkClass::LossyLongFat) {
        double maxPacing = _config.MaxPacingRateBytesPerSecond * 1.50;
        if (_pacingRateBytesPerSecond > maxPacing) {
            _pacingRateBytesPerSecond = maxPacing;
        }
    }

    _congestionWindowBytes = GetTargetCwndBytes();
    // Time ceiling: limiter from estimated bandwidth (avoid huge cwnd)
    if (_btlBwBytesPerSecond > 0) {
        int timeCeiling = static_cast<int>(_btlBwBytesPerSecond * 0.200);
        if (_congestionWindowBytes > timeCeiling) {
            _congestionWindowBytes = timeCeiling;
        }
    }

    if (_congestionWindowBytes < _config.Mss * 2) {
        _congestionWindowBytes = _config.Mss * 2;
    }

    _modeEnteredMicros = _modeEnteredMicros == 0 ? nowMicros : _modeEnteredMicros;
}

// ====================================================================================================
// Mode transitions
// ====================================================================================================

void BbrCongestionControl::EnterDrain(int64_t nowMicros) {
    _mode = BbrMode::Drain;
    _pacingGain = GetDrainPacingGain(nowMicros);
    _modeEnteredMicros = nowMicros;
}

void BbrCongestionControl::EnterProbeBw(int64_t nowMicros) {
    _mode = BbrMode::ProbeBw;
    _probeBwCycleIndex = 0;
    _cwndGain = _config.ProbeBwCwndGain;
    _pacingGain = CalculatePacingGain(nowMicros);
    _modeEnteredMicros = nowMicros;
}

double BbrCongestionControl::GetDrainPacingGain(int64_t nowMicros) {
    double recentLossRatio = GetRecentLossRatio(nowMicros);
    if (recentLossRatio <= 0 && _estimatedLossPercent <= 0) {
        return 1.0;
    }
    return _config.DrainPacingGain;
}

void BbrCongestionControl::EnterProbeRtt(int64_t nowMicros) {
    _mode = BbrMode::ProbeRtt;
    _pacingGain = kProbeRttPacingGain;
    _probeRttEnteredMicros = nowMicros;
    _modeEnteredMicros = nowMicros;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "EnterProbeRtt cwnd=%d btlBw=%.0f minRtt=%lld fullBwRounds=%d lossPct=%.1f netClass=%d",
             _congestionWindowBytes, _btlBwBytesPerSecond,
             static_cast<long long>(_minRttMicros), _fullBandwidthRounds,
             _estimatedLossPercent, static_cast<int>(_currentNetworkClass));
    TraceLog(buf);
}

void BbrCongestionControl::ExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros) {
    if (sampleRttMicros > 0
        && (_minRttMicros == 0 || sampleRttMicros <= static_cast<int64_t>(_minRttMicros * kProbeRttExitRttMultiplier))) {
        _minRttMicros = sampleRttMicros;
    }
    _minRttTimestampMicros = nowMicros;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "ExitProbeRtt cwnd=%d btlBw=%.0f minRtt=%lld sampleRtt=%lld elapsedUs=%lld",
             _congestionWindowBytes, _btlBwBytesPerSecond,
             static_cast<long long>(_minRttMicros), static_cast<long long>(sampleRttMicros),
             static_cast<long long>(nowMicros - _probeRttEnteredMicros));
    TraceLog(buf);
    EnterProbeBw(nowMicros);
}

bool BbrCongestionControl::ShouldExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros) {
    int64_t elapsedMicros = nowMicros - _probeRttEnteredMicros;
    int64_t minDuration = _config.ProbeRttDurationMicros;

    // Shorten minimum duration when not congested
    if (_networkCondition != NetworkCondition::Congested) {
        minDuration = std::max(minDuration / 2, static_cast<int64_t>(30000));
    }

    if (elapsedMicros < minDuration) {
        return false;
    }

    bool hasFreshMinRttSample = sampleRttMicros > 0
        && _minRttMicros > 0
        && sampleRttMicros <= static_cast<int64_t>(_minRttMicros * kProbeRttExitRttMultiplier);

    bool exceededSafetyDuration = elapsedMicros >= _config.ProbeRttDurationMicros * kProbeRttMaxDurationMultiplier;
    return hasFreshMinRttSample || exceededSafetyDuration;
}

// ====================================================================================================
// Pacing gain calculation
// ====================================================================================================

double BbrCongestionControl::CalculatePacingGain(int64_t nowMicros) {
    double lossRatio = GetRecentLossRatio(nowMicros);
    double rttIncrease = GetAverageRttIncreaseRatio();

    // Congested with high loss: minimal pacing gain
    if (_config.LossControlEnable
        && _networkCondition == NetworkCondition::Congested
        && _estimatedLossPercent > _maxBandwidthLossPercent) {
        return kHighLossPacingGain;
    }

    // Fast recovery: elevated pacing gain
    if (_fastRecoveryEnteredMicros > 0
        && _minRttMicros > 0
        && nowMicros - _fastRecoveryEnteredMicros < _minRttMicros) {
        return kFastRecoveryPacingGain;
    }

    if (_networkCondition == NetworkCondition::Congested) {
        if (_estimatedLossPercent <= _maxBandwidthLossPercent) {
            return 1.0;
        }
        return kProbeRttPacingGain;
    }

    // Mobile: use high gain when RTT is stable, moderate when rising
    if (_currentNetworkClass == NetworkClass::MobileUnstable) {
        if (rttIncrease < kLowRttIncreaseRatio) {
            return _config.ProbeBwHighGain;
        }
        if (rttIncrease < kModerateRttIncreaseRatio) {
            return kLightLossPacingGain;
        }
        return 1.0;
    }

    // Lossy long fat: moderate probe gain when RTT is low
    if (_currentNetworkClass == NetworkClass::LossyLongFat) {
        if (rttIncrease < kModerateRttIncreaseRatio) {
            return kModerateProbeGain;
        }
        return 1.0;
    }

    // Random loss: probe with bounded gains
    if (_networkCondition == NetworkCondition::RandomLoss) {
        if (rttIncrease < kLowRttIncreaseRatio) {
            return std::max(1.0, _config.ProbeBwHighGain);
        }
        if (rttIncrease < kModerateRttIncreaseRatio) {
            return std::max(1.0, kModerateProbeGain);
        }
        return 1.0;
    }

    // Low-latency LAN: aggressive probe
    if (_currentNetworkClass == NetworkClass::LowLatencyLAN) {
        return _config.ProbeBwHighGain;
    }

    // Default path: gain ladder based on loss and RTT increase
    if (lossRatio < kLowLossRatio && rttIncrease < kLowRttIncreaseRatio) {
        return std::max(1.0, _config.ProbeBwHighGain);
    }

    if (lossRatio < kModerateLossRatio && rttIncrease < kModerateRttIncreaseRatio) {
        return std::max(1.0, kModerateProbeGain);
    }

    if (lossRatio < kLightLossRatio) {
        return std::max(1.0, kLightLossPacingGain);
    }

    if (lossRatio < kMediumLossRatio) {
        return std::max(1.0, kMediumLossPacingGain);
    }

    return std::max(1.0, kHighLossPacingGain);
}

// ====================================================================================================
// Loss estimation (EWMA)
// ====================================================================================================

void BbrCongestionControl::UpdateEstimatedLossPercent(int64_t nowMicros) {
    UpdateEstimatedLossPercent(nowMicros, CalculateLossPercent(nowMicros));
}

void BbrCongestionControl::UpdateEstimatedLossPercent(int64_t nowMicros, double candidateLossPercent) {
    double boundedCandidate = std::max(0.0, std::min(100.0, candidateLossPercent));
    if (boundedCandidate <= 0.0 && GetRecentLossRatio(nowMicros) <= 0.0) {
        _estimatedLossPercent *= kLossEwmaIdleDecay;
        return;
    }

    if (_estimatedLossPercent <= 0.0) {
        _estimatedLossPercent = boundedCandidate;
        return;
    }

    _estimatedLossPercent = (_estimatedLossPercent * kLossEwmaRetainedWeight) + (boundedCandidate * kLossEwmaSampleWeight);
}

double BbrCongestionControl::CalculateLossPercent(int64_t nowMicros) {
    double targetRate = _btlBwBytesPerSecond > 0 ? _btlBwBytesPerSecond : static_cast<double>(_config.InitialBandwidthBytesPerSecond);
    if (targetRate <= 0) {
        return 0.0;
    }

    double retransmissionLoss = GetRecentLossRatio(nowMicros);

    // In non-congested or startup: pure retransmission-based loss
    if (_networkCondition != NetworkCondition::Congested
        || _deliveryRateBytesPerSecond <= 0
        || _mode == BbrMode::Startup) {
        return retransmissionLoss * 100.0;
    }

    // In congested steady state: combine rate deficiency + retransmission loss
    double actualRate = _deliveryRateBytesPerSecond;
    double lossFromRate = std::max(0.0, 1.0 - (actualRate / targetRate));
    double rateLossHint = std::min(lossFromRate, retransmissionLoss + kRateLossHintMaxRatio);
    return std::max(rateLossHint, retransmissionLoss) * 100.0;
}

// ====================================================================================================
// Network condition classification
// ====================================================================================================

NetworkCondition BbrCongestionControl::ClassifyNetworkCondition(int64_t nowMicros) {
    if (_deliveryRateHistoryCount < 2) {
        return NetworkCondition::Idle;
    }

    // Compute delivery-rate trend over history window
    int newestIndex = (_deliveryRateHistoryIndex + kDeliveryRateHistoryCount - 1) % kDeliveryRateHistoryCount;
    int oldestIndex = (_deliveryRateHistoryIndex + kDeliveryRateHistoryCount - _deliveryRateHistoryCount) % kDeliveryRateHistoryCount;
    double oldestRate = _deliveryRateHistory[oldestIndex];
    double newestRate = _deliveryRateHistory[newestIndex];
    double deliveryRateChange = oldestRate <= 0 ? 0.0 : (newestRate - oldestRate) / oldestRate;
    double lossRatio = GetRecentLossRatio(nowMicros);
    double rttIncrease = GetAverageRttIncreaseRatio();
    int congestionScore = 0;

    // Congestion = rate dropping AND RTT rising
    if (deliveryRateChange <= kCongestionRateDropRatio && rttIncrease >= kCongestionRttIncreaseRatio) {
        congestionScore += kCongestionRateDropScore;
    }

    if (rttIncrease >= kCongestionRttIncreaseRatio) {
        congestionScore += kCongestionRttGrowthScore;
    }

    if (lossRatio >= kCongestionLossRatio && rttIncrease >= kCongestionRttIncreaseRatio) {
        congestionScore += kCongestionLossScore;
    }

    if (congestionScore >= kCongestionClassifierScoreThreshold) {
        return NetworkCondition::Congested;
    }

    // Loss without RTT increase = random loss (non-congestion)
    if (lossRatio > 0 && rttIncrease <= kRandomLossMaxRttIncreaseRatio) {
        return NetworkCondition::RandomLoss;
    }

    if (lossRatio < kLowLossRatio) {
        return NetworkCondition::LightLoad;
    }

    return NetworkCondition::Idle;
}

bool BbrCongestionControl::ShouldTreatLossAsCongestion(int64_t nowMicros, bool isCongestionSignal) {
    if (!isCongestionSignal) {
        return false;
    }

    if (_networkCondition == NetworkCondition::Congested) {
        return true;
    }

    double rttIncrease = GetAverageRttIncreaseRatio();
    double lossRatio = GetRecentLossRatio(nowMicros);
    return rttIncrease >= kCongestionRttIncreaseRatio && lossRatio >= kCongestionLossRatio;
}

// ====================================================================================================
// RTT percentile and statistics
// ====================================================================================================

int64_t BbrCongestionControl::GetCwndModelRttMicros() {
    int64_t p10Rtt = GetP10RttMicros();
    int64_t modelRttMicros = p10Rtt > 0 ? std::max(_minRttMicros, p10Rtt) : _minRttMicros;
    if (modelRttMicros <= 0) {
        return 0;
    }
    return modelRttMicros;
}

double BbrCongestionControl::GetAverageRttIncreaseRatio() {
    if (_rttHistoryCount == 0 || _minRttMicros <= 0) {
        return 0.0;
    }

    int64_t total = 0;
    for (int i = 0; i < _rttHistoryCount; i++) {
        total += _rttHistoryMicros[i];
    }

    double averageRtt = static_cast<double>(total) / _rttHistoryCount;
    return std::max(0.0, (averageRtt - _minRttMicros) / _minRttMicros);
}

int64_t BbrCongestionControl::GetP10RttMicros() {
    return GetPercentileRtt(0.10);
}

int64_t BbrCongestionControl::GetP25RttMicros() {
    return GetPercentileRtt(0.25);
}

int64_t BbrCongestionControl::GetP30RttMicros() {
    return GetPercentileRtt(0.30);
}

int64_t BbrCongestionControl::GetPercentileRtt(double percentile) {
    if (_rttHistoryCount < 4) {
        return _minRttMicros;
    }

    int64_t sorted[64];
    for (int i = 0; i < _rttHistoryCount && i < 64; i++) {
        sorted[i] = _rttHistoryMicros[i];
    }
    int count = _rttHistoryCount;
    std::sort(sorted, sorted + count);

    int index = std::max(0, std::min(count - 1, static_cast<int>(count * percentile)));
    return sorted[index];
}

// ====================================================================================================
// Inflight bounds
// ====================================================================================================

void BbrCongestionControl::UpdateInflightBounds() {
    if (_btlBwBytesPerSecond <= 0 || _minRttMicros <= 0) {
        _inflightHighBytes = 0;
        _inflightLowBytes = 0;
        return;
    }

    double bdpBytes = _btlBwBytesPerSecond * (_minRttMicros / static_cast<double>(kMicrosPerSecond));

    _inflightLowBytes = std::max(static_cast<double>(_config.InitialCongestionWindowBytes), bdpBytes * kInflightLowGain);

    double highGain = (_networkCondition != NetworkCondition::Congested
                        && (_currentNetworkClass == NetworkClass::MobileUnstable
                            || _currentNetworkClass == NetworkClass::LossyLongFat))
        ? kInflightMobileHighGain
        : kInflightHighGain;
    _inflightHighBytes = std::max(_inflightLowBytes, bdpBytes * highGain);
}

// ====================================================================================================
// Loss ratio from time-bucketed packet counters
// ====================================================================================================

double BbrCongestionControl::GetRecentLossRatio(int64_t nowMicros) {
    AdvanceLossBuckets(nowMicros);

    int64_t sent = 0;
    int64_t retransmits = 0;
    for (int i = 0; i < kLossBucketCount; i++) {
        sent += _sentBuckets[i];
        retransmits += _retransmitBuckets[i];
    }

    return sent == 0 ? 0.0 : static_cast<double>(retransmits) / sent;
}

void BbrCongestionControl::AdvanceLossBuckets(int64_t nowMicros) {
    if (nowMicros <= 0) {
        nowMicros = NowMicroseconds();
    }

    int64_t alignedNow = nowMicros - (nowMicros % kLossBucketMicros);
    if (_lossBucketStartMicros == 0 || nowMicros < _lossBucketStartMicros) {
        _sentBuckets.fill(0);
        _retransmitBuckets.fill(0);
        _lossBucketIndex = 0;
        _lossBucketStartMicros = alignedNow;
        return;
    }

    int64_t steps = (nowMicros - _lossBucketStartMicros) / kLossBucketMicros;
    if (steps <= 0) {
        return;
    }

    if (steps >= kLossBucketCount) {
        _sentBuckets.fill(0);
        _retransmitBuckets.fill(0);
        _lossBucketIndex = 0;
        _lossBucketStartMicros = alignedNow;
        return;
    }

    for (int64_t i = 0; i < steps; i++) {
        _lossBucketIndex = (_lossBucketIndex + 1) % kLossBucketCount;
        _sentBuckets[_lossBucketIndex] = 0;
        _retransmitBuckets[_lossBucketIndex] = 0;
    }

    _lossBucketStartMicros += steps * kLossBucketMicros;
}

// ====================================================================================================
// Effective cwnd gain
// ====================================================================================================

double BbrCongestionControl::GetEffectiveCwndGain() {
    if (_currentNetworkClass == NetworkClass::MobileUnstable
        || _currentNetworkClass == NetworkClass::LossyLongFat) {
        return _cwndGain;
    }

    if (_mode == BbrMode::Startup) {
        return _cwndGain;
    }

    // Clamp cwnd gain to respect bandwidth waste budget
    double wasteBudget = std::max(0.50, _config.MaxBandwidthWastePercent);
    double maxWasteGain = 1.0 + wasteBudget;
    double limit = maxWasteGain * _config.ProbeBwCwndGain;
    if (_pacingGain <= 0 || _pacingGain * _cwndGain <= limit) {
        return _cwndGain;
    }

    return std::max(1.0, limit / _pacingGain);
}

// ====================================================================================================
// Debug logging
// ====================================================================================================

void BbrCongestionControl::TraceLog(const char* message) {
    if (_config.EnableDebugLog) {
        fprintf(stderr, "[UCP BBR] %s\n", message);
    }
}

// ====================================================================================================
// Network path classification (long-term)
// ====================================================================================================

void BbrCongestionControl::AdvanceClassifierWindow(int64_t nowMicros, int sentOrAckedBytes,
                                                      int64_t sampleRttMicros, double lossRateSnapshot) {
    if (_classifierWindowStartMicros == 0) {
        _classifierWindowStartMicros = nowMicros;
    }

    _classifierWindowSentBytes += std::max(0, sentOrAckedBytes);
    if (sampleRttMicros > 0) {
        _classifierWindowRttSumMicros += sampleRttMicros;
        _classifierWindowRttCount++;
        if (_classifierWindowMinRttMicros == 0 || sampleRttMicros < _classifierWindowMinRttMicros) {
            _classifierWindowMinRttMicros = sampleRttMicros;
        }
        if (sampleRttMicros > _classifierWindowMaxRttMicros) {
            _classifierWindowMaxRttMicros = sampleRttMicros;
        }
    }

    // Window closed: record and slide
    if (nowMicros - _classifierWindowStartMicros >= kNetworkClassifierWindowDurationMicros) {
        ClassifierWindow& window = _classifierWindows[_classifierWindowIndex];
        window.AvgRttMicros = _classifierWindowRttCount > 0
            ? static_cast<double>(_classifierWindowRttSumMicros) / _classifierWindowRttCount
            : 0.0;
        window.JitterMicros = (_classifierWindowMinRttMicros > 0 && _classifierWindowMaxRttMicros > 0)
            ? static_cast<double>(_classifierWindowMaxRttMicros - _classifierWindowMinRttMicros)
            : 0.0;
        window.LossRate = lossRateSnapshot;
        double elapsedWindow = static_cast<double>(std::max(static_cast<int64_t>(1), nowMicros - _classifierWindowStartMicros));
        double windowBytesPerSecond = _classifierWindowSentBytes * kMicrosPerSecond / elapsedWindow;
        window.ThroughputRatio = _btlBwBytesPerSecond > 0
            ? std::min(1.0, windowBytesPerSecond / _btlBwBytesPerSecond)
            : 0.0;

        _classifierWindowIndex = (_classifierWindowIndex + 1) % kNetworkClassifierWindowCount;
        if (_classifierWindowCount < kNetworkClassifierWindowCount) {
            _classifierWindowCount++;
        }

        // Reset for next window
        _classifierWindowStartMicros = nowMicros;
        _classifierWindowSentBytes = 0;
        _classifierWindowMinRttMicros = 0;
        _classifierWindowMaxRttMicros = 0;
        _classifierWindowRttSumMicros = 0;
        _classifierWindowRttCount = 0;
    }
}

NetworkClass BbrCongestionControl::ClassifyNetworkPath() {
    if (_classifierWindowCount < 2) {
        return NetworkClass::Default;
    }

    double avgRtt = 0.0;
    double avgLoss = 0.0;
    double avgJitter = 0.0;
    double minThroughput = 1.0;
    for (int i = 0; i < _classifierWindowCount; i++) {
        avgRtt += _classifierWindows[i].AvgRttMicros;
        avgLoss += _classifierWindows[i].LossRate;
        avgJitter += _classifierWindows[i].JitterMicros;
        if (_classifierWindows[i].ThroughputRatio > 0 && _classifierWindows[i].ThroughputRatio < minThroughput) {
            minThroughput = _classifierWindows[i].ThroughputRatio;
        }
    }

    avgRtt /= _classifierWindowCount;
    avgLoss /= _classifierWindowCount;
    avgJitter /= _classifierWindowCount;

    double avgRttMs = avgRtt / static_cast<double>(kMicrosPerMilli);
    double avgJitterMs = avgJitter / static_cast<double>(kMicrosPerMilli);

    // Low-latency LAN: <5ms RTT, <0.1% loss, <3ms jitter
    if (avgRttMs < kNetworkClassifierLanRttMs && avgLoss < 0.001 && avgJitterMs < kNetworkClassifierLanJitterMs) {
        return NetworkClass::LowLatencyLAN;
    }

    // Mobile: >3% loss, >20ms jitter
    if (avgLoss > kNetworkClassifierMobileLossRate && avgJitterMs > kNetworkClassifierMobileJitterMs) {
        return NetworkClass::MobileUnstable;
    }

    // Lossy long fat: >80ms RTT, >1% loss
    if (avgRttMs > kNetworkClassifierLongFatRttMs && avgLoss > 0.01) {
        return NetworkClass::LossyLongFat;
    }

    // Congested bottleneck: sustained throughput drop, growing RTT
    if (minThroughput < 0.7
        && _classifierWindowCount > 0
        && avgRttMs > (_classifierWindows[0].AvgRttMicros / static_cast<double>(kMicrosPerMilli)) * 1.1) {
        return NetworkClass::CongestedBottleneck;
    }

    // Symmetric VPN: moderate-high RTT through corporate tunnels
    if (avgRttMs > 60.0) {
        return NetworkClass::SymmetricVPN;
    }

    return NetworkClass::Default;
}

} // namespace ucp
