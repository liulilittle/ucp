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
 *
 *  === C# EQUIVALENCE VERIFICATION ===
 *  All public and private methods, constants, and state variables directly
 *  mirror C# Ucp.Internal.BbrCongestionControl.  Constant values match
 *  UcpConstants.cs; logic is step-identical.
 */

#include "ucp/ucp_bbr.h"      // Include the header for the BbrCongestionControl class declaration and BbrConfig/ClassifierWindow types.
#include <algorithm>           // Include std::min, std::max, std::sort, std::ceil, std::fill for numerical operations.
#include <cmath>               // Include std::ceil (also from cmath), std::fmax etc. — not directly used but present for portability.
#include <cstdio>              // Include snprintf and fprintf for TraceLog debug output.
#include <cstring>             // Include memcpy/memset — not directly used but present for safety.
#include <chrono>              // Include std::chrono::steady_clock for NowMicroseconds() monotonic timestamp generation.

namespace ucp {

// ====================================================================================================
// Local helper: monotonic microsecond clock
// ====================================================================================================

static int64_t NowMicroseconds() {
    static const auto start = std::chrono::steady_clock::now(); // Snapshot the steady clock at first call as the zero-reference; never drifts.
    auto now = std::chrono::steady_clock::now(); // Get the current steady clock reading.
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now - start).count()); // Return elapsed microseconds from the reference point as a monotonic counter; mirrors C# UcpTime.NowMicroseconds().
}

// ====================================================================================================
// Local constants
// ====================================================================================================

static constexpr int64_t kMicrosPerSecond = 1000000;           // Number of microseconds in one second; used for rate and time-base conversions throughout.
static constexpr int64_t kMicrosPerMilli = 1000;               // Number of microseconds in one millisecond; used for human-readable threshold comparisons.

// === BBR timing constants ===

static constexpr double kProbeRttPacingGain = 0.85;            // Pacing gain during ProbeRtt: 0.85× BtlBw to drain the pipe; mirrors C# BBR_PROBE_RTT_PACING_GAIN.
static constexpr double kProbeRttExitRttMultiplier = 1.05;     // Up to 5% above current MinRtt qualifies as a fresh near-minimum RTT sample for ProbeRtt exit; mirrors C# BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER.
static constexpr int64_t kProbeRttMaxDurationMultiplier = 2;   // Hard safety timeout at 2× the configured ProbeRtt duration; mirrors C# BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER.
static constexpr int kProbeBwGainCount = 8;                    // Number of gain phases in the 8-phase ProbeBw cycle (1 high-gain + 7 low-gain slots); mirrors C# BBR_PROBE_BW_GAIN_COUNT.
static constexpr double kStartupGrowthTarget = 1.25;            // Bandwidth increase threshold per round for Startup growth detection: BtlBw must grow by ≥ 25% to reset the stall counter; mirrors C# BbrStartupGrowthTarget.
static constexpr int kMinStartupFullBandwidthRounds = 3;       // Minimum number of consecutive stalled rounds before exiting Startup and entering Drain; mirrors C# MinBbrStartupFullBandwidthRounds.
static constexpr int kRtoMaxBackoffMinRtoMultiplier = 2;       // Minimum RTT multiplication factor for bandwidth-growth-stall detection (used in ProbeRtt entry logic); mirrors C# RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER.
static constexpr double kStartupAckAggregationRateCapGain = 4.0;   // Maximum ACK aggregation gain in Startup (delivery rate capped at 4.0× pacing rate); mirrors C# BBR_STARTUP_ACK_AGGREGATION_RATE_CAP_GAIN.
static constexpr double kSteadyAckAggregationRateCapGain = 1.50;   // Maximum ACK aggregation gain in steady-state modes (delivery rate capped at 1.50× pacing rate); mirrors C# BBR_STEADY_ACK_AGGREGATION_RATE_CAP_GAIN.
static constexpr double kStartupBandwidthGrowthPerRound = 2.0;     // Maximum bandwidth growth per RTT round during Startup (2.0× = double each round); mirrors C# BBR_STARTUP_BANDWIDTH_GROWTH_PER_ROUND.
static constexpr double kSteadyBandwidthGrowthPerRound = 1.25;     // Maximum bandwidth growth per RTT round during steady-state modes (1.25× per round); mirrors C# BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND.
static constexpr int64_t kDefaultRateWindowMicros = kMicrosPerSecond; // Default rate-sampling window when MinRtt is not yet available (1 second); mirrors C# BBR_DEFAULT_RATE_WINDOW_MICROS.
static constexpr int64_t kBandwidthGrowthFallbackIntervalMicros = 10000; // Fallback interval for bandwidth growth clamping when MinRtt is unavailable (10 ms); mirrors C# BBR_BANDWIDTH_GROWTH_FALLBACK_INTERVAL_MICROS.

// === Loss recovery constants ===

static constexpr double kLossCwndRecoveryStep = 0.08;           // Standard CWND-gain recovery increment per ACK after loss (8% per ACK, ~12 ACKs to full); mirrors C# BBR_LOSS_CWND_RECOVERY_STEP.
static constexpr double kLossCwndRecoveryStepFast = 0.15;       // Fast CWND-gain recovery increment for Mobile/random-loss paths (15% per ACK, ~7 ACKs to full); mirrors C# BBR_LOSS_CWND_RECOVERY_STEP_FAST.
static constexpr double kCongestionLossReduction = 0.98;        // Multiplicative CWND-gain reduction on confirmed congestion loss: gain × 0.98 per event; mirrors C# BBR_CONGESTION_LOSS_REDUCTION.
static constexpr double kMinLossCwndGain = 0.95;                // Absolute floor for the loss CWND gain (95%); prevents CWND from collapsing below 95% of BDP; mirrors C# BBR_MIN_LOSS_CWND_GAIN.
static constexpr double kLossBudgetRecoveryRatio = 0.80;        // Loss-budget recovery threshold: pacing gain resumes increasing when loss ≤ 80% of MaxBandwidthLossPercent; mirrors C# BBR_LOSS_BUDGET_RECOVERY_RATIO.

// === Loss EWMA constants ===

static constexpr double kLossEwmaIdleDecay = 0.90;              // Decay multiplier for the loss EWMA when no loss is observed (estimate drifts toward zero); mirrors C# BBR_LOSS_EWMA_IDLE_DECAY.
static constexpr double kLossEwmaRetainedWeight = 0.75;         // Weight of the previous EWMA estimate in the blending formula (75% retained); mirrors C# BBR_LOSS_EWMA_RETAINED_WEIGHT.
static constexpr double kLossEwmaSampleWeight = 0.25;           // Weight of the new loss sample in the blending formula (25% new data); mirrors C# BBR_LOSS_EWMA_SAMPLE_WEIGHT.

// === Congestion classification thresholds ===

static constexpr double kCongestionRateDropRatio = -0.15;       // Delivery-rate drop ratio threshold for the congestion signal: a 15% decline flags the bottleneck as saturated; mirrors C# BBR_CONGESTION_RATE_DROP_RATIO.
static constexpr double kCongestionRttIncreaseRatio = 0.50;     // RTT increase ratio threshold for congestion: average RTT must be ≥ 50% above MinRtt; mirrors C# BBR_CONGESTION_RTT_INCREASE_RATIO.
static constexpr double kCongestionLossRatio = 0.10;            // Loss ratio threshold for congestion classification (10% loss + rising RTT); mirrors C# BBR_CONGESTION_LOSS_RATIO.
static constexpr int kCongestionRateDropScore = 1;              // Score contribution from the rate-drop classifier rule; mirrors C# BBR_CONGESTION_RATE_DROP_SCORE.
static constexpr int kCongestionRttGrowthScore = 1;             // Score contribution from the RTT-growth classifier rule; mirrors C# BBR_CONGESTION_RTT_GROWTH_SCORE.
static constexpr int kCongestionLossScore = 1;                  // Score contribution from the loss-ratio classifier rule; mirrors C# BBR_CONGESTION_LOSS_SCORE.
static constexpr int kCongestionClassifierScoreThreshold = 2;   // Cumulative score threshold: if total score ≥ 2, the path is classified as Congested; mirrors C# BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD.

// === Random loss thresholds ===

static constexpr double kRandomLossMaxRttIncreaseRatio = 0.20;  // Maximum RTT increase for a loss event to be considered random (RTT increase ≤ 20% → RandomLoss); mirrors C# BBR_RANDOM_LOSS_MAX_RTT_INCREASE_RATIO.
static constexpr double kRateLossHintMaxRatio = 0.05;           // Maximum additional loss contribution from the delivery-rate shortfall hint (5% cap); mirrors C# BBR_RATE_LOSS_HINT_MAX_RATIO.

// === Pacing gain by network class ===

static constexpr double kFastRecoveryPacingGain = 1.25;          // Pacing gain during fast recovery after a non-congestion loss event (25% above BtlBw); mirrors C# BBR_FAST_RECOVERY_PACING_GAIN.
static constexpr double kHighLossPacingGain = 1.00;              // Pacing gain under high loss conditions (1.00× = no probing, maintain at bottleneck rate); mirrors C# BBR_HIGH_LOSS_PACING_GAIN.
static constexpr double kLowLossRatio = 0.01;                     // Loss-ratio threshold for "low loss" tier in the default pacing-gain ladder (1%); mirrors C# BBR_LOW_LOSS_RATIO.
static constexpr double kModerateLossRatio = 0.03;                // Loss-ratio threshold for "moderate loss" tier in the default pacing-gain ladder (3%); mirrors C# BBR_MODERATE_LOSS_RATIO.
static constexpr double kLightLossRatio = 0.08;                   // Loss-ratio threshold for "light loss" tier in the default pacing-gain ladder (8%); mirrors C# BBR_LIGHT_LOSS_RATIO.
static constexpr double kMediumLossRatio = 0.15;                  // Loss-ratio threshold for "medium loss" tier in the default pacing-gain ladder (15%); mirrors C# BBR_MEDIUM_LOSS_RATIO.
static constexpr double kLowRttIncreaseRatio = 0.10;              // RTT-increase-ratio threshold for "low" tier: average RTT ≤ 10% above MinRtt; mirrors C# BBR_LOW_RTT_INCREASE_RATIO.
static constexpr double kModerateRttIncreaseRatio = 0.20;         // RTT-increase-ratio threshold for "moderate" tier: average RTT ≤ 20% above MinRtt; mirrors C# BBR_MODERATE_RTT_INCREASE_RATIO.
static constexpr double kModerateProbeGain = 1.50;                // Moderate probe gain used for LossyLongFat and moderate-loss conditions (1.50×); mirrors C# BBR_MODERATE_PROBE_GAIN.
static constexpr double kLightLossPacingGain = 1.10;              // Pacing gain under light-loss conditions (1.10×, slight upward bias); mirrors C# BBR_LIGHT_LOSS_PACING_GAIN.
static constexpr double kMediumLossPacingGain = 1.05;             // Pacing gain under medium-loss conditions (1.05×, very slight upward bias); mirrors C# BBR_MEDIUM_LOSS_PACING_GAIN.

// === Inflight bounds ===

static constexpr double kInflightLowGain = 1.25;                 // Lower inflight bound multiplier: CWND floor = max(InitialCwnd, BDP × 1.25); mirrors C# BBR_INFLIGHT_LOW_GAIN.
static constexpr double kInflightHighGain = 2.00;                // Upper inflight bound multiplier: CWND ceiling = max(LowBound, BDP × 2.00); mirrors C# BBR_INFLIGHT_HIGH_GAIN.
static constexpr double kInflightMobileHighGain = 2.00;          // Upper inflight bound multiplier for mobile/lossy paths (2.00× BDP, higher headroom for non-congestion retransmissions); mirrors C# BBR_INFLIGHT_MOBILE_HIGH_GAIN.

static constexpr int64_t kMinRoundDurationMicros = kMicrosPerMilli; // Minimum BBR round duration (1 ms); prevents pathological zero-length rounds; mirrors C# BBR_MIN_ROUND_DURATION_MICROS.
static constexpr int64_t kLossBucketMicros = 100000;               // Duration of each loss-accounting time bucket (100 ms); mirrors C# BBR_LOSS_BUCKET_MICROS.

// === Network classifier thresholds ===

static constexpr double kNetworkClassifierLongFatRttMs = 80.0;    // RTT threshold for classifying a path as LossyLongFat (80 ms); mirrors C# NETWORK_CLASSIFIER_LONG_FAT_RTT_MS.
static constexpr double kNetworkClassifierMobileLossRate = 0.03;   // Loss-rate threshold for classifying a path as MobileUnstable (3%); mirrors C# NETWORK_CLASSIFIER_MOBILE_LOSS_RATE.
static constexpr double kNetworkClassifierMobileJitterMs = 20.0;   // Jitter threshold for classifying a path as MobileUnstable (20 ms); mirrors C# NETWORK_CLASSIFIER_MOBILE_JITTER_MS.
static constexpr double kNetworkClassifierLanRttMs = 5.0;          // RTT threshold for classifying a path as LowLatencyLAN (5 ms); mirrors C# NETWORK_CLASSIFIER_LAN_RTT_MS.
static constexpr double kNetworkClassifierLanJitterMs = 3.0;       // Jitter threshold for classifying a path as LowLatencyLAN (3 ms); mirrors C# NETWORK_CLASSIFIER_LAN_JITTER_MS.
static constexpr int64_t kNetworkClassifierWindowDurationMicros = 200000; // Duration of each classifier observation window (200 ms); mirrors C# NETWORK_CLASSIFIER_WINDOW_DURATION_MICROS.
static constexpr int kNetworkClassifierWindowCount = 8;            // Number of classifier observation windows retained (8 × 200ms = 1.6 seconds of history); mirrors C# NETWORK_CLASSIFIER_WINDOW_COUNT.

// ====================================================================================================
// Construction
// ====================================================================================================

BbrCongestionControl::BbrCongestionControl()
    : BbrCongestionControl(BbrConfig{}) { // Delegate to the parameterised constructor with default BbrConfig; mirrors C# parameterless constructor delegating to `this(new UcpConfiguration())`.
}

BbrCongestionControl::BbrCongestionControl(const BbrConfig& config)
    : _config(config) { // Store the BBR configuration reference; mirrors C# `_config = config ?? new UcpConfiguration()`.
    _mode = BbrMode::Startup; // Start in Startup mode to rapidly discover the bottleneck bandwidth via exponential probing; mirrors C# `Mode = BbrMode.Startup`.
    _pacingGain = _config.StartupPacingGain; // Set the initial pacing gain (typically 2.89×, derived from 2/ln(2)) for exponential Startup ramp-up; mirrors C# `PacingGain = _config.StartupPacingGain`.
    _cwndGain = _config.StartupCwndGain; // Set the initial CWND gain (typically 2.0×) to match the pacing gain for aggressive probing; mirrors C# `CwndGain = _config.StartupCwndGain`.
    _maxBandwidthLossPercent = _config.EffectiveMaxBandwidthLossPercent; // Load the effective maximum tolerable loss percentage from config (e.g. 25%) for loss-control decisions; mirrors C# `_maxBandwidthLossPercent = _config.EffectiveMaxBandwidthLossPercent`.
    _btlBwBytesPerSecond = static_cast<double>(_config.InitialBandwidthBytesPerSecond); // Initialise BtlBw to the configured target bottleneck rate as the starting estimate; mirrors C# `BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond`.
    if (_config.MaxPacingRateBytesPerSecond > 0 && _btlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) { // A hard user-configured rate cap exists AND the initial BtlBw exceeds it.
        _btlBwBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond); // Clamp BtlBw to the configured maximum pacing rate; mirrors C# clamp to MaxPacingRate.
    }
    _minRttMicros = 0; // No RTT samples collected yet; MinRtt starts at zero until the first ACK arrives; mirrors C# `MinRttMicros = 0`.
    RecalculateModel(NowMicroseconds()); // Compute the initial pacing rate and CWND from the starting BtlBw and MinRtt estimates; mirrors C# `RecalculateModel(UcpTime.NowMicroseconds())`.
}

// ====================================================================================================
// BBR lifecycle: Ack -> model update -> mode transitions
// ====================================================================================================

void BbrCongestionControl::OnAck(int64_t nowMicros, int deliveredBytes, int64_t sampleRttMicros, int flightBytes) {
    // === Step 1: Update MinRtt estimate ===
    // MinRtt is the sticky floor of all RTT samples: it can only decrease by at most 25% per sample
    // to prevent a single lucky fast measurement from collapsing the CWND model.
    bool minRttExpired = _minRttMicros > 0 && nowMicros - _minRttTimestampMicros >= _config.ProbeRttIntervalMicros; // Determine if MinRtt has gone stale (exceeded the configured ProbeRTT refresh interval); mirrors C# `minRttExpired`.
    if (sampleRttMicros > 0) { // Only process valid (non-zero) RTT samples — some ACKs carry no RTT measurement; mirrors C# `if (sampleRttMicros > 0)`.
        _currentRttMicros = sampleRttMicros; // Record the most recent RTT sample for round-tracking and diagnostic purposes; mirrors C# `_currentRttMicros = sampleRttMicros`.
        if (_minRttMicros == 0 || sampleRttMicros < _minRttMicros) { // First-ever RTT sample OR a new candidate minimum that beats the current sticky floor; mirrors C# `if (MinRttMicros == 0 || sampleRttMicros < MinRttMicros)`.
            if (_minRttMicros > 0) { // Not the first sample — use the sticky floor to prevent excessive reduction; mirrors C# `if (MinRttMicros > 0)`.
                _minRttMicros = std::max(sampleRttMicros, static_cast<int64_t>(_minRttMicros * 0.75)); // Allow at most 25% reduction per sample to prevent CWND collapse from one lucky fast measurement; mirrors C# sticky floor.
            } else {
                _minRttMicros = sampleRttMicros; // First-ever RTT sample: use it directly as the initial MinRtt baseline; mirrors C# first-sample assignment.
            }
            _minRttTimestampMicros = nowMicros; // Record the time of this MinRtt update to track freshness for the ProbeRTT interval timer; mirrors C# timestamp update.
            minRttExpired = false; // A fresh MinRtt update resets the expiry clock; mirrors C# `minRttExpired = false`.
        }
    }

    // === Step 2: Compute delivery rate for this ACK ===
    // Delivery rate = newly ACKed bytes / wall-clock interval since last ACK.
    int64_t intervalMicros; // Declare the interval variable for the delivery-rate denominator; mirrors C# `long intervalMicros`.
    if (_lastAckMicros == 0) { // First ACK ever received — no previous timestamp exists to compute a real interval; mirrors C# `if (_lastAckMicros == 0)`.
        intervalMicros = sampleRttMicros > 0 ? sampleRttMicros : 1; // Use the RTT sample itself as a fallback interval, or 1µs to avoid division by zero; mirrors C# fallback.
    } else {
        intervalMicros = std::max(static_cast<int64_t>(1), nowMicros - _lastAckMicros); // Compute wall-clock interval since the last ACK, with a 1µs minimum to avoid divide-by-zero; mirrors C# `Math.Max(1, nowMicros - _lastAckMicros)`.
    }
    _lastAckMicros = nowMicros; // Update the last-ACK timestamp for the next interval computation on the next ACK; mirrors C# `_lastAckMicros = nowMicros`.

    // === Step 3: Feed delivery-rate samples into the max-filter ===
    if (deliveredBytes > 0) { // Only process ACKs that actually acknowledge new data — pure window updates may carry zero bytes; mirrors C# `if (deliveredBytes > 0)`.
        _totalDeliveredBytes += deliveredBytes; // Accumulate total delivered bytes (since connection start) for round boundary detection; mirrors C# accumulation.
        double deliveryRate = deliveredBytes * static_cast<double>(kMicrosPerSecond) / static_cast<double>(intervalMicros); // Compute instantaneous delivery rate in bytes/s: bytes ÷ seconds; mirrors C# rate calc.
        if (_pacingRateBytesPerSecond > 0) { // Only apply the ACK aggregation cap when we have a valid pacing rate baseline to compare against; mirrors C# `if (PacingRateBytesPerSecond > 0)`.
            double aggregationCapGain = _mode == BbrMode::Startup
                ? kStartupAckAggregationRateCapGain // Startup: looser cap (4.0×) to allow rapid ramp-up without under-clamping.
                : kSteadyAckAggregationRateCapGain; // Steady state: tighter cap (1.50×) to prevent ACK aggregation from inflating estimates; mirrors C# aggregation cap.
            deliveryRate = std::min(deliveryRate, _pacingRateBytesPerSecond * aggregationCapGain); // Clamp the delivery rate to at most pacing_rate × aggregation_cap_gain; mirrors C# clamp.
        }
        _deliveryRateBytesPerSecond = deliveryRate; // Store the most recent delivery rate for diagnostics and loss-percentage calculations; mirrors C# assignment.
        AddRateSample(deliveryRate, nowMicros);       // Max-filter for BtlBw estimation (the core bandwidth discovery mechanism); mirrors C# `AddRateSample(deliveryRate, nowMicros)`.
        AddDeliveryRateSample(deliveryRate);           // Trend history for oldest-vs-newest congestion detection; mirrors C# `AddDeliveryRateSample(deliveryRate)`.

        // === Recover loss CWND gain ===
        // After a congestion loss reduces _lossCwndGain below 1.0, gradually recover it on each ACK.
        if (_lossCwndGain < 1.0 && _mode != BbrMode::ProbeRtt) { // CWND loss reduction is active AND we're not in the ProbeRtt drain phase; mirrors C# recovery guard.
            double recoveryStep = (_currentNetworkClass == NetworkClass::MobileUnstable
                                    || _networkCondition == NetworkCondition::RandomLoss)
                ? kLossCwndRecoveryStepFast // Fast recovery step for mobile/random-loss paths where loss is typically noise, not congestion.
                : kLossCwndRecoveryStep; // Standard (slower) recovery step for all other path types; mirrors C# recoveryStep selection.
            _lossCwndGain = std::min(1.0, _lossCwndGain + recoveryStep); // Increment CWND gain by one recovery step toward 1.0 (full recovery), never exceeding 1.0; mirrors C# increment.
            if (_currentNetworkClass == NetworkClass::MobileUnstable && _lossCwndGain < 0.98) { // On mobile paths, CWND gain is still significantly below full — apply accelerated recovery; mirrors C# mobile double-step.
                _lossCwndGain = std::min(1.0, _lossCwndGain + recoveryStep * 2.0); // Apply a double recovery step to rapidly restore throughput on mobile links; mirrors C# double-step.
            }
        }
    }

    // === Track RTT history for percentile estimation ===
    if (sampleRttMicros > 0) { // A valid RTT sample was included with this ACK — store it for jitter and percentile analysis; mirrors C# `if (sampleRttMicros > 0)`.
        AddRttSample(sampleRttMicros); // Feed the RTT sample into the history buffer (capped at 500ms to filter RTO stalls); mirrors C# `AddRttSample(sampleRttMicros)`.
    }

    // === Step 4: Classify network condition and path type ===
    AdvanceClassifierWindow(nowMicros, deliveredBytes + flightBytes, sampleRttMicros, GetRecentLossRatio(nowMicros)); // Accumulate bytes, RTT, and loss data into the current classifier observation window; mirrors C# `AdvanceClassifierWindow(...)`.
    _currentNetworkClass = ClassifyNetworkPath(); // Classify the end-to-end network path (LAN, Mobile, LossyFat, VPN, etc.) from multi-second aggregated statistics; mirrors C# `CurrentNetworkClass = ClassifyNetworkPath()`.

    _networkCondition = ClassifyNetworkCondition(nowMicros); // Classify the instantaneous local network condition (Idle, LightLoad, Congested, or RandomLoss) from recent trends; mirrors C# `_networkCondition = ClassifyNetworkCondition(nowMicros)`.
    if (_networkCondition == NetworkCondition::Congested) { // The network is congested — the path's capacity may have changed; mirrors C# `if (_networkCondition == NetworkCondition.Congested)`.
        _maxBtlBwInNonCongestedWindow = 0; // Invalidate the non-congested BtlBw soft floor since congestion indicates the path cannot sustain its previous rate; mirrors C# reset.
    }

    UpdateEstimatedLossPercent(nowMicros); // Update the EWMA-smoothed loss percentage estimate from the current loss data; mirrors C# `UpdateEstimatedLossPercent(nowMicros)`.
    UpdateInflightBounds(); // Recompute the upper and lower inflight guardrails (CWND ceilings/floors) based on current BDP and path class; mirrors C# `UpdateInflightBounds()`.

    // === Step 5: ProbeRTT entry logic ===
    if (minRttExpired && _mode != BbrMode::ProbeRtt) { // MinRtt has gone stale AND we're not currently in the middle of a ProbeRTT cycle; mirrors C# `if (minRttExpired && Mode != BbrMode.ProbeRtt)`.
        bool bandwidthGrowthStalled = _fullBandwidthRounds >= kRtoMaxBackoffMinRtoMultiplier; // Check if bandwidth discovery has stalled for a sufficient number of rounds; mirrors C# stall check.
        bool isLossyFat = _currentNetworkClass == NetworkClass::LossyLongFat; // Determine if the current path is classified as lossy long-fat (satellite/long-haul); mirrors C# `isLossyFat`.
        bool isMobile = _currentNetworkClass == NetworkClass::MobileUnstable; // Determine if the current path is classified as mobile/unstable (LTE/5G/WiFi); mirrors C# `isMobile`.

        if (isMobile) { // Mobile path detected — skip ProbeRTT entirely to avoid a throughput penalty on a path dominated by non-queuing jitter; mirrors C# mobile skip.
            _minRttTimestampMicros = nowMicros;  // Reset the MinRtt timestamp so the ProbeRTT interval timer restarts without actually entering the probe; mirrors C# timestamp refresh.
        } else if (bandwidthGrowthStalled || !isLossyFat) { // Bandwidth growth has stalled OR path is not lossy-long-fat; mirrors C# `else if (bandwidthGrowthStalled || !isLossyFat)`.
            EnterProbeRtt(nowMicros); // Enter the ProbeRTT deep-drain phase to collect a fresh minimum RTT measurement; mirrors C# `EnterProbeRtt(nowMicros)`.
        } else { // Lossy long-fat path with active bandwidth growth — skip ProbeRTT to preserve the discovery; mirrors C# else branch.
            char buf[256]; // Stack-allocated buffer for the trace log message; mirrors C# string concatenation in TraceLog.
            snprintf(buf, sizeof(buf), "SkipProbeRtt btlBw=%.0f fullBwRounds=%d preservedOnLossyFat",
                     _btlBwBytesPerSecond, _fullBandwidthRounds); // Format the skip-ProbeRTT diagnostic message with BtlBw and stall rounds; mirrors C# TraceLog.
            TraceLog(buf); // Emit the skip-ProbeRTT diagnostic trace if debug logging is enabled; mirrors C# `TraceLog(...)`.
        }
    }

    // === Step 6: Round detection ===
    // A BBR "round" is completed when cumulative delivered bytes reach the threshold (_nextRoundDeliveredBytes).
    bool roundStart = false; // Default: no round boundary detected unless proven otherwise below; mirrors C# `bool roundStart = false`.
    if (_nextRoundDeliveredBytes == 0) { // First ACK — the round-delivered threshold has not been initialised yet; mirrors C# `if (_nextRoundDeliveredBytes == 0)`.
        _nextRoundDeliveredBytes = _totalDeliveredBytes + std::max(static_cast<int64_t>(deliveredBytes), static_cast<int64_t>(flightBytes)); // Initialize the next round boundary at approximately one BDP's worth of data ahead; mirrors C# initialization.
    } else if (_totalDeliveredBytes >= _nextRoundDeliveredBytes) { // Cumulative delivered bytes have crossed the round boundary — a new round begins; mirrors C# `else if (_totalDeliveredBytes >= _nextRoundDeliveredBytes)`.
        _nextRoundDeliveredBytes = _totalDeliveredBytes + std::max(static_cast<int64_t>(deliveredBytes), static_cast<int64_t>(flightBytes)); // Advance the round boundary by another BDP's worth of data for the next round; mirrors C# advance.
        roundStart = deliveredBytes > 0; // Mark the round start (only meaningful if actual data bytes were delivered this ACK); mirrors C# `roundStart = deliveredBytes > 0`.
    }

    // === Step 7: State-machine dispatch ===
    if (_mode == BbrMode::Startup) { // We are in Startup mode — evaluate bandwidth growth at each round boundary; mirrors C# `if (Mode == BbrMode.Startup)`.
        if (roundStart) { // A round boundary has been reached during Startup; mirrors C# `if (roundStart)`.
            UpdateStartup(); // Run the Startup bandwidth-growth check and potentially transition to Drain if growth has stalled; mirrors C# `UpdateStartup()`.
        }
    } else if (_mode == BbrMode::Drain) { // We are in Drain mode — waiting for the standing queue to be flushed; mirrors C# `else if (Mode == BbrMode.Drain)`.
        if (flightBytes <= GetTargetCwndBytes() || nowMicros - _modeEnteredMicros >= std::max(_minRttMicros, kMinRoundDurationMicros)) { // In-flight has drained to the CWND target OR the minimum drain duration has elapsed; mirrors C# drain-exit condition.
            EnterProbeBw(nowMicros); // Transition to ProbeBW steady-state cycling — the pipe is now clean; mirrors C# `EnterProbeBw(nowMicros)`.
        }
    } else if (_mode == BbrMode::ProbeBw) { // We are in ProbeBW mode — advance the gain cycle and adjust for path class; mirrors C# `else if (Mode == BbrMode.ProbeBw)`.
        if (nowMicros - _modeEnteredMicros >= std::max(_minRttMicros, kMinRoundDurationMicros)) { // A full round has elapsed since the current gain-phase began — time to cycle; mirrors C# cycle-advance condition.
            _probeBwCycleIndex = (_probeBwCycleIndex + 1) % kProbeBwGainCount; // Advance to the next phase in the 8-phase gain cycle (wrapping from 7 back to 0); mirrors C# cycle increment.
            _modeEnteredMicros = nowMicros; // Record the timestamp when this new gain-phase began for the next round-duration check; mirrors C# timestamp update.
        }
        if ((_currentNetworkClass == NetworkClass::MobileUnstable
             || _currentNetworkClass == NetworkClass::LossyLongFat)
            && _networkCondition != NetworkCondition::Congested) { // Path is mobile or lossy-fat AND not currently congested — use extended high-gain policy; mirrors C# mobile/lossy branch.
            if (_probeBwCycleIndex < kProbeBwGainCount - 1) { // Not in the final (drain) phase of the cycle — use the normal adaptive pacing gain; mirrors C# `if (_probeBwCycleIndex < ...)`.
                _pacingGain = CalculatePacingGain(nowMicros); // Compute the adaptive pacing gain for the current cycle phase and path conditions; mirrors C# `PacingGain = CalculatePacingGain(nowMicros)`.
            } else { // In the drain phase — use the configured low gain, capped at 1.0×; mirrors C# else branch.
                _pacingGain = std::min(1.0, _config.ProbeBwLowGain); // In the drain phase: use the configured low gain (0.85×), capped at 1.0× so we never exceed the bottleneck rate; mirrors C# low-gain clamp.
            }
        } else { // Standard path or congested — use the normal adaptive pacing gain for the current cycle index; mirrors C# else branch.
            _pacingGain = CalculatePacingGain(nowMicros); // Compute the adaptive pacing gain without the mobile/lossy special case; mirrors C# `PacingGain = CalculatePacingGain(nowMicros)`.
        }
    } else if (_mode == BbrMode::ProbeRtt) { // We are in ProbeRTT mode — maintain the low pacing gain and check for exit conditions; mirrors C# `else if (Mode == BbrMode.ProbeRtt)`.
        _pacingGain = kProbeRttPacingGain; // Enforce the ProbeRTT low pacing gain (0.85×) to drain the pipe and measure the true base RTT; mirrors C# `PacingGain = BBR_PROBE_RTT_PACING_GAIN`.
        if (ShouldExitProbeRtt(nowMicros, sampleRttMicros)) { // Check exit conditions: fresh near-minimum RTT sample observed OR safety timeout expired; mirrors C# `if (ShouldExitProbeRtt(...))`.
            ExitProbeRtt(nowMicros, sampleRttMicros); // Exit ProbeRTT: adopt the new MinRtt if valid, then transition back to ProbeBW; mirrors C# `ExitProbeRtt(...)`.
        }
    }

    // === Step 8: Fast recovery timeout ===
    // Fast recovery (elevated pacing for non-congestion loss) lasts at most one RTT.
    if (_fastRecoveryEnteredMicros > 0 && _minRttMicros > 0 && nowMicros - _fastRecoveryEnteredMicros >= _minRttMicros) { // Fast recovery is active and one full RTT has elapsed since it was entered; mirrors C# recovery timeout.
        _fastRecoveryEnteredMicros = 0; // Exit fast recovery after one RTT — normal pacing resumes on the next OnAck; mirrors C# `_fastRecoveryEnteredMicros = 0`.
    }

    // === Step 9: Recompute pacing rate and CWND ===
    RecalculateModel(nowMicros); // Run the final model recomputation: derive pacing rate (BtlBw × PacingGain) and CWND (BDP × CwndGain) from all updated estimates; mirrors C# `RecalculateModel(nowMicros)`.
}

void BbrCongestionControl::OnPacketSent(int64_t nowMicros, bool isRetransmit) {
    AdvanceLossBuckets(nowMicros); // Age out expired loss buckets and advance the ring pointer to the current time slot; mirrors C# `AdvanceLossBuckets(nowMicros)`.
    _sentBuckets[_lossBucketIndex]++; // Increment the sent-packet counter for the current bucket — every packet (original or retransmit) counts toward the total; mirrors C# sent increment.
    if (isRetransmit) { // This packet is a retransmission (RTO, fast retransmit, or SACK-triggered retransmit); mirrors C# `if (isRetransmit)`.
        _retransmitBuckets[_lossBucketIndex]++; // Increment the retransmit counter — this directly feeds the loss ratio (retransmits / total sent); mirrors C# retransmit increment.
    }
}

void BbrCongestionControl::OnFastRetransmit(int64_t nowMicros, bool isCongestion) {
    if (_config.EnableDebugLog) { // Debug logging is enabled in the configuration — emit a diagnostic trace to aid troubleshooting; mirrors C# `if (_config.EnableDebugLog)`.
        TraceLog("FastRetransmit"); // Log the fast retransmit event for diagnostics; mirrors C# `Trace.WriteLine(...)`.
    }
    if (!isCongestion) { // The loss was NOT classified as congestion by the caller — treat as random/burst loss; mirrors C# `if (!isCongestion)`.
        _fastRecoveryEnteredMicros = nowMicros; // Mark the start of the fast recovery period (lasts at most one RTT); mirrors C# `_fastRecoveryEnteredMicros = nowMicros`.
        _pacingGain = kFastRecoveryPacingGain; // Elevate pacing gain to 1.25× to rapidly refill the loss hole without creating new loss; mirrors C# `PacingGain = BBR_FAST_RECOVERY_PACING_GAIN`.
        RecalculateModel(nowMicros); // Recompute pacing rate and CWND with the elevated fast-recovery pacing gain; mirrors C# `RecalculateModel(nowMicros)`.
    }
    OnPacketLoss(nowMicros, GetRecentLossRatio(nowMicros), isCongestion); // Always forward to the general loss handler for EWMA loss-tracking and condition re-classification; mirrors C# `OnPacketLoss(...)`.
}

void BbrCongestionControl::OnPacketLoss(int64_t nowMicros, double lossRate, bool isCongestion) {
    if (nowMicros <= 0) { // Timestamp was not provided (zero/negative) — use the current real time as a fallback; mirrors C# `if (nowMicros <= 0)`.
        nowMicros = NowMicroseconds(); // Get the current high-resolution timestamp to ensure valid timing for all subsequent decisions; mirrors C# `nowMicros = UcpTime.NowMicroseconds()`.
    }
    double recentLossRate = GetRecentLossRatio(nowMicros); // Get the internally-tracked loss ratio from the sliding per-bucket sent/retransmit counters; mirrors C# `recentLossRate = GetRecentLossRatio(nowMicros)`.
    lossRate = std::max(lossRate, recentLossRate); // Be conservative: use the higher of the externally-provided and internally-computed loss rates; mirrors C# `lossRate = Math.Max(lossRate, recentLossRate)`.

    _networkCondition = ClassifyNetworkCondition(nowMicros); // Re-run the three-tier congestion classifier with the most recent delivery-rate and RTT data; mirrors C# classification.
    UpdateEstimatedLossPercent(nowMicros, lossRate * 100.0); // Update the EWMA-smoothed loss percentage estimate with the new loss data (converted from ratio to percent); mirrors C# `UpdateEstimatedLossPercent(nowMicros, lossRate * 100d)`.

    bool treatAsCongestion = ShouldTreatLossAsCongestion(nowMicros, isCongestion); // Determine whether this loss event warrants multiplicative CWND reduction vs fast recovery only; mirrors C# `treatAsCongestion = ShouldTreatLossAsCongestion(...)`.

    if (treatAsCongestion) { // This loss is confirmed as congestion — apply aggressive multiplicative reduction; mirrors C# `if (treatAsCongestion)`.
        _lossCwndGain = std::max(kMinLossCwndGain, _lossCwndGain * kCongestionLossReduction); // Multiply current CWND gain by 0.98 for multiplicative reduction, with a hard floor at 0.95 to prevent total starvation; mirrors C# reduction.
        if (_mode != BbrMode::ProbeRtt && _mode != BbrMode::Startup) { // Only enter ProbeRTT if we're not already probing and not in the initial ramp-up; mirrors C# `if (Mode != BbrMode.ProbeRtt && Mode != BbrMode.Startup)`.
            EnterProbeRtt(nowMicros); // Enter ProbeRTT deep-drain to refresh the MinRtt estimate after the congestion queue has subsided; mirrors C# `EnterProbeRtt(nowMicros)`.
        }
    } else { // Random/non-congestion loss: fast recovery with elevated pacing — never reduce CWND for random loss; mirrors C# else branch.
        _fastRecoveryEnteredMicros = nowMicros; // Start the fast recovery timer for non-congestion loss (one RTT of elevated pacing); mirrors C# `_fastRecoveryEnteredMicros = nowMicros`.
        if (_mode == BbrMode::ProbeBw) { // We are in steady-state ProbeBW — ensure the pacing gain stays at or above the normal calculated level; mirrors C# `if (Mode == BbrMode.ProbeBw)`.
            _pacingGain = std::max(_pacingGain, CalculatePacingGain(nowMicros)); // Take the higher of current and calculated pacing gains — never let random loss reduce pacing; mirrors C# `PacingGain = Math.Max(PacingGain, CalculatePacingGain(nowMicros))`.
        }
    }

    RecalculateModel(nowMicros); // Recompute pacing rate and CWND with the updated loss parameters, reflecting any gain changes; mirrors C# `RecalculateModel(nowMicros)`.
}

void BbrCongestionControl::OnPathChange(int64_t nowMicros) {
    // Reset all path-dependent state to relearn the new path from scratch
    _minRttTimestampMicros = 0; // Reset min-RTT timestamp so the next RTT sample becomes the new baseline for the new path; mirrors C# `_minRttTimestampMicros = 0`.
    _minRttMicros = 0; // Reset minimum RTT — the new path has a different propagation delay that must be re-measured; mirrors C# `MinRttMicros = 0`.
    _rttHistoryMicros.fill(0); // Clear all stale RTT samples collected from the old path to prevent them from corrupting new estimates; mirrors C# `Array.Clear(_rttHistoryMicros, ...)`.
    _rttHistoryCount = 0; // Reset RTT history sample count so the new path starts with a fresh buffer; mirrors C# `_rttHistoryCount = 0`.
    _rttHistoryIndex = 0; // Reset RTT history write position to the start of the circular buffer; mirrors C# `_rttHistoryIndex = 0`.
    _bandwidthGrowthWindowMicros = 0; // Reset bandwidth growth window — the new path has different bottleneck characteristics; mirrors C# `_bandwidthGrowthWindowMicros = 0`.
    _bandwidthGrowthWindowStartRate = 0; // Reset growth window starting rate so the first sample on the new path establishes a fresh baseline; mirrors C# `_bandwidthGrowthWindowStartRate = 0`.
    _classifierWindowCount = 0; // Reset classifier window count — old path statistics are stale and must not influence path classification; mirrors C# `_classifierWindowCount = 0`.
    _classifierWindowIndex = 0; // Reset classifier write position to the start of the circular buffer; mirrors C# `_classifierWindowIndex = 0`.
    _classifierWindowStartMicros = 0; // Reset classifier window start timestamp so a new window begins on the next ACK; mirrors C# `_classifierWindowStartMicros = 0`.
    _fullBandwidthRounds = 0; // Reset startup full-bandwidth round counter — the new path needs fresh bandwidth discovery; mirrors C# `_fullBandwidthRounds = 0`.
    _fullBandwidthEstimate = 0; // Reset full-bandwidth estimate so bandwidth growth is re-evaluated from scratch on the new path; mirrors C# `_fullBandwidthEstimate = 0`.
    _nextRoundDeliveredBytes = 0; // Reset round boundary tracking so the next ACK initialises a new round on the new path; mirrors C# `_nextRoundDeliveredBytes = 0`.
    RecalculateModel(nowMicros); // Recompute cwnd and pacing rate with the reset parameter state as the starting point for the new path; mirrors C# `RecalculateModel(nowMicros)`.
    char buf[128]; // Stack-allocated buffer for the path-change trace log message; mirrors C# TraceLog string.
    snprintf(buf, sizeof(buf), "PathChange btlBw=%.0f cwnd=%d", _btlBwBytesPerSecond, _congestionWindowBytes); // Format the path-change diagnostic message with current BtlBw and CWND; mirrors C# TraceLog.
    TraceLog(buf); // Emit the path-change diagnostic trace if debug logging is enabled; mirrors C# `TraceLog(...)`.
}

// ====================================================================================================
// Startup detection
// ====================================================================================================

void BbrCongestionControl::UpdateStartup() {
    double current = _btlBwBytesPerSecond; // Snapshot the current BtlBw estimate for comparison against the tracked full-bandwidth best; mirrors C# `double current = BtlBwBytesPerSecond`.
    if (_fullBandwidthEstimate <= 0) { // First round of Startup — no previous best exists to compare against; mirrors C# `if (_fullBandwidthEstimate <= 0)`.
        _fullBandwidthEstimate = current; // Initialize the full-bandwidth estimate to the current BtlBw as the baseline; mirrors C# `_fullBandwidthEstimate = current`.
        return; // Nothing more to do on the first round — exit early; mirrors C# early return.
    }

    // Growth ≥ 1.25× → still ramping up; reset stall counter.
    if (current >= _fullBandwidthEstimate * kStartupGrowthTarget) { // BtlBw grew by at least the growth target (1.25×) since the tracked best; mirrors C# growth check.
        _fullBandwidthEstimate = current; // Update the tracked best BtlBw to the new higher value; mirrors C# `_fullBandwidthEstimate = current`.
        _fullBandwidthRounds = 0; // Growth achieved; reset the stall counter; mirrors C# `_fullBandwidthRounds = 0`.
    } else { // No significant growth this round — increment the stall counter; mirrors C# else branch.
        _fullBandwidthRounds++; // Increment the stall counter: one more round without sufficient bandwidth growth; mirrors C# `_fullBandwidthRounds++`.
    }

    int requiredStallRounds = kMinStartupFullBandwidthRounds; // Default number of consecutive stall rounds required to exit Startup (typically 3); mirrors C# `requiredStallRounds = MinBbrStartupFullBandwidthRounds`.
    if (_config.MaxPacingRateBytesPerSecond > 0
        && _btlBwBytesPerSecond >= _config.MaxPacingRateBytesPerSecond * 0.90) { // A user-configured rate cap exists AND we've reached 90% of it — fast exit is appropriate; mirrors C# fast-exit condition.
        requiredStallRounds = 1;  // Fast exit: already at the configured target — start draining after just one stall round; mirrors C# `requiredStallRounds = 1`.
    }

    if (_fullBandwidthRounds >= requiredStallRounds) { // Bandwidth has stalled for the required number of rounds — the pipe is full and Startup should end; mirrors C# `if (_fullBandwidthRounds >= requiredStallRounds)`.
        EnterDrain(_lastAckMicros); // Transition to Drain mode to flush the standing queue accumulated during Startup's aggressive probing; mirrors C# `EnterDrain(_lastAckMicros)`.
    }
}

// ====================================================================================================
// Rate sampling and bandwidth estimation
// ====================================================================================================

void BbrCongestionControl::AddRateSample(double deliveryRate, int64_t nowMicros) {
    // Push new sample into the circular buffer.
    _recentRates[_recentRateIndex] = deliveryRate; // Store the delivery rate value at the current circular buffer write position; mirrors C# `_recentRates[_recentRateIndex] = deliveryRate`.
    _recentRateTimestamps[_recentRateIndex] = nowMicros; // Store the corresponding timestamp for age-based sample expiry during the max-filter scan; mirrors C# timestamp storage.
    _recentRateIndex = (_recentRateIndex + 1) % kRecentRateSampleCount; // Advance the write position by one (wrapping around when reaching the end of the buffer); mirrors C# index advance.
    if (_recentRateCount < kRecentRateSampleCount) { // The buffer has not yet filled up (first pass through) — increment the valid sample count; mirrors C# count increment guard.
        _recentRateCount++; // Increase the count of valid entries available for the max-filter scan; mirrors C# `_recentRateCount++`.
    }

    // Max-filter: scan all recent samples within the time window and pick the maximum.
    double maxRate = 0; // Initialize the maximum rate accumulator to zero before the scan; mirrors C# `double maxRate = 0`.
    int64_t rttWindowMicros = _minRttMicros > 0
        ? _minRttMicros * std::max(static_cast<int64_t>(1), static_cast<int64_t>(_config.BbrWindowRtRounds)) // Compute the sliding window: MinRtt × configured BBR window rounds.
        : kDefaultRateWindowMicros; // No MinRtt yet — use the default 1-second window; mirrors C# window computation.

    for (int i = 0; i < _recentRateCount; i++) { // Iterate through all valid entries in the circular rate buffer; mirrors C# `for (int i = 0; i < _recentRateCount; i++)`.
        if (nowMicros - _recentRateTimestamps[i] > std::max(rttWindowMicros, static_cast<int64_t>(1))) { // The sample's age exceeds the sliding window — it is stale and must be ignored; mirrors C# age check.
            continue; // Sample is outside the window — skip to the next entry; mirrors C# `continue`.
        }
        if (_recentRates[i] > maxRate) { // This sample's rate is higher than the current running maximum; mirrors C# `if (_recentRates[i] > maxRate)`.
            maxRate = _recentRates[i]; // Update the running maximum with this higher value; mirrors C# `maxRate = _recentRates[i]`.
        }
    }

    if (maxRate > 0) { // At least one valid (in-window) sample was found — a new BtlBw candidate exists; mirrors C# `if (maxRate > 0)`.
        // Clamp growth: limit how fast BtlBw can increase per round.
        maxRate = ClampBandwidthGrowth(maxRate, nowMicros); // Apply the per-round growth clamp to prevent unrealistic bandwidth jumps from a single ACK burst; mirrors C# `ClampBandwidthGrowth(maxRate, nowMicros)`.
        if (_config.MaxPacingRateBytesPerSecond > 0 && maxRate > _config.MaxPacingRateBytesPerSecond) { // A hard user-configured rate cap exists and the candidate rate exceeds it; mirrors C# rate-cap check.
            maxRate = static_cast<double>(_config.MaxPacingRateBytesPerSecond); // Clamp to the configured maximum — never exceed the user-specified rate limit; mirrors C# clamp.
        }

        // Track max bandwidth in non-congested state for recovery (soft floor).
        if (_networkCondition != NetworkCondition::Congested) { // The path is not congested — this delivery rate is a valid indicator of true path capacity; mirrors C# non-congested check.
            if (maxRate > _maxBtlBwInNonCongestedWindow) { // The new candidate exceeds the previously tracked non-congested maximum BtlBw; mirrors C# `if (maxRate > _maxBtlBwInNonCongestedWindow)`.
                _maxBtlBwInNonCongestedWindow = maxRate; // Update the non-congested maximum — this strengthens the soft floor for future rate depressions; mirrors C# update.
            }
        }

        _btlBwBytesPerSecond = maxRate; // Set the official bottleneck bandwidth estimate to the max-filter scan result; mirrors C# `BtlBwBytesPerSecond = maxRate`.

        // Hard floor: BtlBw never drops below the configured initial bandwidth.
        if (_btlBwBytesPerSecond < _config.InitialBandwidthBytesPerSecond) { // BtlBw fell below the configured initial bandwidth floor; mirrors C# hard-floor check.
            _btlBwBytesPerSecond = static_cast<double>(_config.InitialBandwidthBytesPerSecond); // Restore BtlBw to the hard floor — the path is expected to support at least this rate; mirrors C# `BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond`.
            if (_config.MaxPacingRateBytesPerSecond > 0 && _btlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) { // The hard floor itself exceeds the configured rate cap — re-apply the cap; mirrors C# re-cap check.
                _btlBwBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond); // Clamp to the rate cap on top of the hard floor; mirrors C# re-clamp.
            }
        }

        // Soft floor: recover towards non-congested max if loss is low.
        if (_networkCondition != NetworkCondition::Congested
            && _maxBtlBwInNonCongestedWindow > 0
            && GetRecentLossRatio(nowMicros) < 0.05
            && _btlBwBytesPerSecond < _maxBtlBwInNonCongestedWindow * 0.90) { // Not congested, soft floor exists, loss is under 5%, and BtlBw fell below 90% of the non-congested peak; mirrors C# soft-floor condition.
            _btlBwBytesPerSecond = _maxBtlBwInNonCongestedWindow * 0.90; // Restore BtlBw to 90% of the best non-congested rate — prevent a transient gap from permanently depressing the estimate; mirrors C# recovery.
        }
    }
}

double BbrCongestionControl::ClampBandwidthGrowth(double candidateRate, int64_t nowMicros) {
    if (candidateRate <= _btlBwBytesPerSecond || _btlBwBytesPerSecond <= 0) { // The candidate rate does not exceed the current estimate, or no current estimate exists — no clamping is needed; mirrors C# `if (candidateRate <= BtlBwBytesPerSecond || BtlBwBytesPerSecond <= 0)`.
        return candidateRate; // No increase → return the candidate unchanged; mirrors C# early return.
    }

    int64_t growthIntervalMicros = _minRttMicros > 0 ? _minRttMicros : kBandwidthGrowthFallbackIntervalMicros; // Determine the growth window duration: use measured MinRtt, or a fixed 10ms fallback if not yet available; mirrors C# interval selection.
    if (_bandwidthGrowthWindowMicros == 0 || nowMicros - _bandwidthGrowthWindowMicros >= growthIntervalMicros) { // No growth window is active yet, or the current window has expired — start a new window; mirrors C# window-reset condition.
        _bandwidthGrowthWindowMicros = nowMicros; // Record the start time of this new bandwidth growth window; mirrors C# `_bandwidthGrowthWindowMicros = nowMicros`.
        _bandwidthGrowthWindowStartRate = _btlBwBytesPerSecond; // Snapshot the current BtlBw as the baseline rate for this window's growth cap; mirrors C# `_bandwidthGrowthWindowStartRate = BtlBwBytesPerSecond`.
    }

    double growthGain = _mode == BbrMode::Startup
        ? kStartupBandwidthGrowthPerRound // Startup allows more aggressive growth (2.0× per round) since BtlBw is expected to double each round during ramp-up.
        : kSteadyBandwidthGrowthPerRound; // Steady state caps at 1.25× per round to prevent overshoot from a single bursty measurement; mirrors C# growth-gain selection.
    double growthCap = std::max(_btlBwBytesPerSecond, _bandwidthGrowthWindowStartRate * growthGain); // Compute the maximum allowed rate: starting rate × growth gain, floored at current BtlBw; mirrors C# `Math.Max(BtlBw, startRate * growthGain)`.
    return std::min(candidateRate, growthCap); // Clamp the candidate rate to at most the computed growth cap; mirrors C# `Math.Min(candidateRate, growthCap)`.
}

void BbrCongestionControl::AddDeliveryRateSample(double deliveryRate) {
    _deliveryRateHistory[_deliveryRateHistoryIndex] = deliveryRate; // Store the delivery rate at the current write position in the trend-history circular buffer; mirrors C# `_deliveryRateHistory[_deliveryRateHistoryIndex] = deliveryRate`.
    _deliveryRateHistoryIndex = (_deliveryRateHistoryIndex + 1) % kDeliveryRateHistoryCount; // Advance the write position by one (wrapping around at the end of the buffer); mirrors C# index advance.
    if (_deliveryRateHistoryCount < kDeliveryRateHistoryCount) { // The buffer has not yet wrapped — increase the valid entry count; mirrors C# count guard.
        _deliveryRateHistoryCount++; // Increment the count of valid samples available for oldest-vs-newest trend comparison; mirrors C# `_deliveryRateHistoryCount++`.
    }
}

void BbrCongestionControl::AddRttSample(int64_t sampleRttMicros) {
    if (sampleRttMicros <= 0) return; // Invalid RTT sample (zero or negative) — nothing to store; mirrors C# `if (sampleRttMicros <= 0) return`.
    if (sampleRttMicros > 500000) return;  // RTT exceeds 500ms (indicative of an RTO stall rather than normal queuing delay) — discard the sample; mirrors C# 500ms cap.

    _rttHistoryMicros[_rttHistoryIndex] = sampleRttMicros; // Store the valid RTT sample at the current write position in the history buffer; mirrors C# `_rttHistoryMicros[_rttHistoryIndex] = sampleRttMicros`.
    _rttHistoryIndex = (_rttHistoryIndex + 1) % kRttHistoryCount; // Advance the write position by one (wrapping around at the buffer end); mirrors C# index advance.
    if (_rttHistoryCount < kRttHistoryCount) { // The buffer has not yet wrapped — increase the valid sample count; mirrors C# count guard.
        _rttHistoryCount++; // Increment the count of valid RTT samples for percentile and average calculations; mirrors C# `_rttHistoryCount++`.
    }
}

// ====================================================================================================
// Cwnd and model calculation
// ====================================================================================================

int BbrCongestionControl::GetTargetCwndBytes() {
    if (_btlBwBytesPerSecond <= 0 || _minRttMicros <= 0) { // Either BtlBw or MinRtt is unavailable — cannot compute a meaningful BDP; mirrors C# `if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)`.
        return _config.InitialCongestionWindowBytes; // Return the configured initial CWND as a safe starting point (typically 20 × MSS); mirrors C# `return _config.InitialCongestionWindowBytes`.
    }

    int64_t modelRttMicros = GetCwndModelRttMicros(); // Get the model RTT (P10-based propagation-delay estimate with MinRtt as floor); mirrors C# `modelRttMicros = GetCwndModelRttMicros()`.

    if (modelRttMicros > 500000 || modelRttMicros <= 0) { // Model RTT is above 500ms or invalid — cap it to prevent CWND explosion; mirrors C# `if (modelRttMicros > 500000L || modelRttMicros <= 0)`.
        modelRttMicros = 500000;  // Cap model RTT at 500ms — any stall longer than this is not representative of normal path conditions; mirrors C# `modelRttMicros = 500000L`.
    }

    // BDP = bandwidth × propagation delay.
    double bdp = _btlBwBytesPerSecond * (modelRttMicros / static_cast<double>(kMicrosPerSecond)); // Compute BDP in bytes: bandwidth (bytes/s) × propagation delay (seconds); mirrors C# BDP calculation.
    double effectiveCwndGain = GetEffectiveCwndGain(); // Get the effective CWND gain (adjusted for waste budget and path-class multipliers); mirrors C# `effectiveCwndGain = GetEffectiveCwndGain()`.
    int cwnd = static_cast<int>(std::ceil(bdp * effectiveCwndGain)); // Compute the target CWND: BDP × effective gain, rounded up to the nearest integer byte; mirrors C# `(int)Math.Ceiling(bdp * effectiveCwndGain)`.
    if (cwnd < _config.InitialCongestionWindowBytes && _mode == BbrMode::Startup) { // CWND fell below the initial floor during Startup — keep at least the initial value to allow ramp-up; mirrors C# initial-CWND floor.
        cwnd = _config.InitialCongestionWindowBytes; // Restore CWND to the configured initial floor to ensure reliable startup probing; mirrors C# `cwnd = _config.InitialCongestionWindowBytes`.
    }

    // Clamp to configured max.
    if (_config.MaxCongestionWindowBytes > 0 && cwnd > _config.MaxCongestionWindowBytes) { // A hard maximum CWND is configured and the computed CWND exceeds it; mirrors C# max-CWND check.
        cwnd = _config.MaxCongestionWindowBytes; // Clamp CWND to the configured upper bound to prevent unbounded growth on high-BDP paths; mirrors C# `cwnd = _config.MaxCongestionWindowBytes`.
    }

    // Apply loss-driven CWND reduction.
    if (_lossCwndGain < 1.0) { // Loss reduction is active — the CWND needs to be scaled down multiplicatively; mirrors C# `if (_lossCwndGain < 1d)`.
        cwnd = static_cast<int>(std::ceil(cwnd * _lossCwndGain)); // Apply the loss-driven multiplicative reduction: cwnd = cwnd × _lossCwndGain; mirrors C# `cwnd = (int)Math.Ceiling(cwnd * _lossCwndGain)`.
        if (cwnd < _config.InitialCongestionWindowBytes) { // The reduced CWND has fallen below the absolute minimum floor; mirrors C# floor check.
            cwnd = _config.InitialCongestionWindowBytes; // Restore CWND to the initial floor to prevent complete starvation during loss events; mirrors C# `cwnd = _config.InitialCongestionWindowBytes`.
        }
    }

    // Apply inflight guardrails.
    if (_inflightHighBytes > 0) { // An upper inflight guardrail has been computed — apply the ceiling; mirrors C# `if (_inflightHighBytes > 0)`.
        cwnd = std::min(cwnd, static_cast<int>(std::ceil(_inflightHighBytes))); // Clamp CWND to at most the upper inflight guardrail (typically ~2× BDP); mirrors C# ceiling clamp.
    }

    if (_inflightLowBytes > 0) { // A lower inflight guardrail has been computed — apply the floor; mirrors C# `if (_inflightLowBytes > 0)`.
        cwnd = std::max(cwnd, static_cast<int>(std::ceil(_inflightLowBytes))); // Clamp CWND to at least the lower inflight guardrail to prevent under-utilization; mirrors C# floor clamp.
    }

    return cwnd; // Return the fully clamped target congestion window in bytes; mirrors C# `return cwnd`.
}

void BbrCongestionControl::RecalculateModel(int64_t nowMicros) {
    if (_btlBwBytesPerSecond <= 0) { // BtlBw is invalid (zero or negative) — restore it to a safe default; mirrors C# `if (BtlBwBytesPerSecond <= 0)`.
        _btlBwBytesPerSecond = static_cast<double>(_config.InitialBandwidthBytesPerSecond); // Set BtlBw to the configured initial bandwidth as a safe fallback; mirrors C# `BtlBwBytesPerSecond = _config.InitialBandwidthBytesPerSecond`.
    }

    if (_config.MaxPacingRateBytesPerSecond > 0 && _btlBwBytesPerSecond > _config.MaxPacingRateBytesPerSecond) { // A user-configured rate cap exists and the current BtlBw exceeds it; mirrors C# rate-cap check.
        _btlBwBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond); // Clamp BtlBw to the configured maximum — never let the estimate exceed the user's limit; mirrors C# clamp.
    }

    if (_mode == BbrMode::ProbeRtt) { // We are in the ProbeRTT deep-drain phase — enforce the low pacing gain unconditionally; mirrors C# `if (Mode == BbrMode.ProbeRtt)`.
        _pacingGain = kProbeRttPacingGain; // Override pacing gain to the ProbeRTT low value (0.85×) to drain the standing queue; mirrors C# `PacingGain = BBR_PROBE_RTT_PACING_GAIN`.
    }

    // Loss-control: when loss is well within budget, gradually increase pacing gain back toward the high gain.
    if (_config.LossControlEnable) { // The loss-control feature is enabled in the configuration; mirrors C# `if (_config.LossControlEnable)`.
        if (_estimatedLossPercent <= _maxBandwidthLossPercent * kLossBudgetRecoveryRatio) { // Current loss is well within the bandwidth loss budget (≤ 80% of max) — safe to increase pacing gain; mirrors C# budget check.
            _pacingGain = std::min(_config.ProbeBwHighGain, _pacingGain + kLossCwndRecoveryStep); // Slowly increment pacing gain by one recovery step toward the high probe gain, capped at the config limit; mirrors C# increment.
        }
    }

    _pacingRateBytesPerSecond = _btlBwBytesPerSecond * _pacingGain; // Compute the pacing rate as BtlBw multiplied by the current pacing gain; mirrors C# `PacingRateBytesPerSecond = BtlBwBytesPerSecond * PacingGain`.
    if (_config.MaxPacingRateBytesPerSecond > 0
        && _pacingRateBytesPerSecond > _config.MaxPacingRateBytesPerSecond
        && _estimatedLossPercent < 3.0) { // Pacing rate exceeds the configured cap BUT loss is under 3% — clamp rather than penalising; mirrors C# rate-cap+loss check.
        _pacingRateBytesPerSecond = static_cast<double>(_config.MaxPacingRateBytesPerSecond); // Clamp the pacing rate to the user-configured maximum; mirrors C# clamp.
    }

    // Unconditional cap for non-mobile non-lossy-fat paths: pacing rate never exceeds 1.50× the configured target.
    if (_config.MaxPacingRateBytesPerSecond > 0
        && _currentNetworkClass != NetworkClass::MobileUnstable
        && _currentNetworkClass != NetworkClass::LossyLongFat) { // A rate cap is configured and the path is a standard (non-mobile, non-lossy) type; mirrors C# `if (...) CurrentNetworkClass != MobileUnstable && ...`.
        double maxPacing = _config.MaxPacingRateBytesPerSecond * 1.50; // Compute the 1.50× safety cap relative to the configured maximum pacing rate; mirrors C# `double maxPacing = _config.MaxPacingRateBytesPerSecond * 1.50d`.
        if (_pacingRateBytesPerSecond > maxPacing) { // The current pacing rate exceeds the 1.50× safety cap; mirrors C# `if (PacingRateBytesPerSecond > maxPacing)`.
            _pacingRateBytesPerSecond = maxPacing; // Clamp the pacing rate to 1.50× of the configured max — prevent excessive queuing on clean paths; mirrors C# `PacingRateBytesPerSecond = maxPacing`.
        }
    }

    _congestionWindowBytes = GetTargetCwndBytes(); // Compute the target CWND from the BDP model (BtlBw × modelRtt × CwndGain) with all guardrails applied; mirrors C# `CongestionWindowBytes = GetTargetCwndBytes()`.
    // Time ceiling: 200ms worth of BtlBw flat cap prevents pathological CWND growth.
    if (_btlBwBytesPerSecond > 0) { // BtlBw is valid — apply the time-based absolute ceiling; mirrors C# `if (BtlBwBytesPerSecond > 0)`.
        int timeCeiling = static_cast<int>(_btlBwBytesPerSecond * 0.200); // Compute 200ms worth of data at the current BtlBw rate as the absolute CWND ceiling; mirrors C# `(int)(BtlBwBytesPerSecond * 0.200d)`.
        if (_congestionWindowBytes > timeCeiling) { // The BDP-model CWND exceeds the 200ms time-based ceiling; mirrors C# `if (CongestionWindowBytes > timeCeiling)`.
            _congestionWindowBytes = timeCeiling; // Clamp CWND to the 200ms ceiling — prevents pathological CWND growth during Startup or high-gain phases; mirrors C# `CongestionWindowBytes = timeCeiling`.
        }
    }

    if (_congestionWindowBytes < _config.Mss * 2) { // CWND has fallen below 2× MSS — the connection is at risk of stalling; mirrors C# `if (CongestionWindowBytes < _config.Mss * 2)`.
        _congestionWindowBytes = _config.Mss * 2; // Enforce the absolute minimum CWND of 2× MSS to ensure the connection can always send at least two segments; mirrors C# `CongestionWindowBytes = _config.Mss * 2`.
    }

    _modeEnteredMicros = _modeEnteredMicros == 0 ? nowMicros : _modeEnteredMicros; // Initialize the mode-entered timestamp on the first invocation if not already set by a mode-transition call; mirrors C# `_modeEnteredMicros = _modeEnteredMicros == 0 ? nowMicros : _modeEnteredMicros`.
}

// ====================================================================================================
// Mode transitions
// ====================================================================================================

void BbrCongestionControl::EnterDrain(int64_t nowMicros) {
    _mode = BbrMode::Drain; // Transition the state machine to Drain mode to flush the standing queue; mirrors C# `Mode = BbrMode.Drain`.
    _pacingGain = GetDrainPacingGain(nowMicros); // Compute the adaptive drain pacing gain (1.00× on clean paths, config value on lossy paths); mirrors C# `PacingGain = GetDrainPacingGain(nowMicros)`.
    _modeEnteredMicros = nowMicros; // Record the entry timestamp for drain-duration exit checks; mirrors C# `_modeEnteredMicros = nowMicros`.
}

void BbrCongestionControl::EnterProbeBw(int64_t nowMicros) {
    _mode = BbrMode::ProbeBw; // Transition the state machine to the steady-state ProbeBW cycling mode; mirrors C# `Mode = BbrMode.ProbeBw`.
    _probeBwCycleIndex = 0; // Reset the 8-phase gain cycle to the first phase (index 0); mirrors C# `_probeBwCycleIndex = 0`.
    _cwndGain = _config.ProbeBwCwndGain; // Set CWND gain to the configured ProbeBW value (2.0× BDP) for retransmission headroom without bufferbloat; mirrors C# `CwndGain = _config.ProbeBwCwndGain`.
    _pacingGain = CalculatePacingGain(nowMicros); // Compute the initial ProbeBW pacing gain based on current network condition and path class; mirrors C# `PacingGain = CalculatePacingGain(nowMicros)`.
    _modeEnteredMicros = nowMicros; // Record the entry timestamp for tracking the duration of each gain-cycle phase; mirrors C# `_modeEnteredMicros = nowMicros`.
}

double BbrCongestionControl::GetDrainPacingGain(int64_t nowMicros) {
    double recentLossRatio = GetRecentLossRatio(nowMicros); // Get the recent loss ratio from the sliding bucket windows; mirrors C# `double recentLossRatio = GetRecentLossRatio(nowMicros)`.
    if (recentLossRatio <= 0 && _estimatedLossPercent <= 0) { // Both recent and smoothed loss are zero — the path is completely clean; mirrors C# `if (recentLossRatio <= 0 && EstimatedLossPercent <= 0)`.
        return 1.0; // Clean drain: return 1.00× pacing gain — no active draining needed, the queue drains naturally; mirrors C# `return 1d`.
    }
    return _config.DrainPacingGain; // Loss is present — return the configured drain pacing gain for active queue draining (typically 0.75–0.90×); mirrors C# `return _config.DrainPacingGain`.
}

void BbrCongestionControl::EnterProbeRtt(int64_t nowMicros) {
    _mode = BbrMode::ProbeRtt; // Transition to the ProbeRTT deep-drain mode to measure the true base RTT; mirrors C# `Mode = BbrMode.ProbeRtt`.
    _pacingGain = kProbeRttPacingGain; // Set pacing gain to the ProbeRTT low value (0.85×) to drain the pipe; mirrors C# `PacingGain = BBR_PROBE_RTT_PACING_GAIN`.
    _probeRttEnteredMicros = nowMicros; // Record the entry timestamp for ProbeRTT exit-condition evaluation (duration checks); mirrors C# `_probeRttEnteredMicros = nowMicros`.
    _modeEnteredMicros = nowMicros; // Standard mode-entry timestamp (used by other methods for duration tracking); mirrors C# `_modeEnteredMicros = nowMicros`.
    char buf[256]; // Stack-allocated buffer for the ProbeRTT entry trace log; mirrors C# TraceLog string concatenation.
    snprintf(buf, sizeof(buf),
             "EnterProbeRtt cwnd=%d btlBw=%.0f minRtt=%lld fullBwRounds=%d lossPct=%.1f netClass=%d",
             _congestionWindowBytes, _btlBwBytesPerSecond,
             static_cast<long long>(_minRttMicros), _fullBandwidthRounds,
             _estimatedLossPercent, static_cast<int>(_currentNetworkClass)); // Format the ProbeRTT entry diagnostic message with full context; mirrors C# `TraceLog(...)`.
    TraceLog(buf); // Emit the ProbeRTT entry diagnostic trace if debug logging is enabled; mirrors C# `TraceLog(...)`.
}

void BbrCongestionControl::ExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros) {
    // Adopt the sample as new MinRtt if it's within 1.05× of the current MinRtt.
    if (sampleRttMicros > 0
        && (_minRttMicros == 0 || sampleRttMicros <= static_cast<int64_t>(_minRttMicros * kProbeRttExitRttMultiplier))) { // A valid RTT sample exists AND it is within 1.05× of the current MinRtt — the probe succeeded; mirrors C# exit condition.
        _minRttMicros = sampleRttMicros; // Update MinRtt to the new value measured during the probe — the pipe was truly empty; mirrors C# `MinRttMicros = sampleRttMicros`.
    }
    _minRttTimestampMicros = nowMicros; // Reset the MinRtt timestamp to restart the ProbeRTT interval timer — delays the next probe cycle; mirrors C# `_minRttTimestampMicros = nowMicros`.
    char buf[256]; // Stack-allocated buffer for the ProbeRTT exit trace log; mirrors C# TraceLog string.
    snprintf(buf, sizeof(buf),
             "ExitProbeRtt cwnd=%d btlBw=%.0f minRtt=%lld sampleRtt=%lld elapsedUs=%lld",
             _congestionWindowBytes, _btlBwBytesPerSecond,
             static_cast<long long>(_minRttMicros), static_cast<long long>(sampleRttMicros),
             static_cast<long long>(nowMicros - _probeRttEnteredMicros)); // Format the ProbeRTT exit diagnostic with elapsed time; mirrors C# `TraceLog(...)`.
    TraceLog(buf); // Emit the ProbeRTT exit diagnostic trace if debug logging is enabled; mirrors C# `TraceLog(...)`.
    EnterProbeBw(nowMicros); // Transition back to ProbeBW steady-state cycling with the refreshed MinRtt estimate; mirrors C# `EnterProbeBw(nowMicros)`.
}

bool BbrCongestionControl::ShouldExitProbeRtt(int64_t nowMicros, int64_t sampleRttMicros) {
    int64_t elapsedMicros = nowMicros - _probeRttEnteredMicros; // Compute how long we have been in ProbeRTT (microseconds since entry); mirrors C# `elapsedMicros = nowMicros - _probeRttEnteredMicros`.
    int64_t minDuration = _config.ProbeRttDurationMicros; // Get the configured minimum ProbeRTT duration (~100ms by default); mirrors C# `minDuration = _config.ProbeRttDurationMicros`.

    // On non-congested paths, allow earlier exit: halve the minimum duration, floor at 30ms.
    if (_networkCondition != NetworkCondition::Congested) { // The path is not congested — RTT is likely already near the true propagation minimum; mirrors C# `if (_networkCondition != NetworkCondition.Congested)`.
        minDuration = std::max(minDuration / 2, static_cast<int64_t>(30000)); // Halve the minimum ProbeRTT duration, but never below 30ms as an absolute safety floor; mirrors C# `Math.Max(minDuration / 2, 30000L)`.
    }

    if (elapsedMicros < minDuration) { // The minimum required ProbeRTT duration has not yet elapsed — must wait longer; mirrors C# `if (elapsedMicros < minDuration)`.
        return false; // Minimum duration not yet met — stay in ProbeRTT; mirrors C# `return false`.
    }

    // Exit condition 1: fresh sample close to current MinRtt (≤ 1.05×).
    bool hasFreshMinRttSample = sampleRttMicros > 0
        && _minRttMicros > 0
        && sampleRttMicros <= static_cast<int64_t>(_minRttMicros * kProbeRttExitRttMultiplier); // A valid RTT sample was observed that is within 1.05× of the current MinRtt — the probe achieved its goal; mirrors C# `hasFreshMinRttSample`.

    // Exit condition 2: safety timeout (2× the normal duration) — prevents indefinite starvation.
    bool exceededSafetyDuration = elapsedMicros >= _config.ProbeRttDurationMicros * kProbeRttMaxDurationMultiplier; // ProbeRTT has been running for 2× the normal duration — safety timeout has fired; mirrors C# `exceededSafetyDuration`.
    return hasFreshMinRttSample || exceededSafetyDuration; // Exit ProbeRTT if either the probe succeeded (good RTT sample observed) or the safety timeout expired; mirrors C# `return hasFreshMinRttSample || exceededSafetyDuration`.
}

// ====================================================================================================
// Pacing gain calculation
// ====================================================================================================

double BbrCongestionControl::CalculatePacingGain(int64_t nowMicros) {
    double lossRatio = GetRecentLossRatio(nowMicros); // Get the recent loss ratio (retransmits / sent) from the sliding bucket windows; mirrors C# `lossRatio = GetRecentLossRatio(nowMicros)`.
    double rttIncrease = GetAverageRttIncreaseRatio(); // Get how much the average RTT exceeds MinRtt: (avg − min) / min; mirrors C# `rttIncrease = GetAverageRttIncreaseRatio()`.

    // === Loss-control override: congested with high loss → minimal pacing gain ===
    if (_config.LossControlEnable
        && _networkCondition == NetworkCondition::Congested
        && _estimatedLossPercent > _maxBandwidthLossPercent) { // Loss-control is active, path is congested, and loss has blown past the bandwidth loss budget; mirrors C# loss-control check.
        return kHighLossPacingGain; // Return the aggressive back-off pacing gain (1.00×) to relieve the congested bottleneck; mirrors C# `return BBR_HIGH_LOSS_PACING_GAIN`.
    }

    // === Fast recovery: elevated pacing gain ===
    if (_fastRecoveryEnteredMicros > 0
        && _minRttMicros > 0
        && nowMicros - _fastRecoveryEnteredMicros < _minRttMicros) { // Fast recovery is active and has not yet exceeded one RTT since entry; mirrors C# fast-recovery check.
        return kFastRecoveryPacingGain; // Return the elevated fast-recovery pacing gain (1.25×) to refill the loss hole; mirrors C# `return BBR_FAST_RECOVERY_PACING_GAIN`.
    }

    // === Congested path ===
    if (_networkCondition == NetworkCondition::Congested) { // The network condition classifier confirms the path is currently congested; mirrors C# `if (_networkCondition == NetworkCondition.Congested)`.
        if (_estimatedLossPercent <= _maxBandwidthLossPercent) { // Loss is still within the tolerable bandwidth loss budget — no need for aggressive back-off; mirrors C# budget check.
            return 1.0; // Pace at exactly the bottleneck rate — maintain current throughput without probing higher; mirrors C# `return 1d`.
        }
        return kProbeRttPacingGain; // Loss exceeds the budget — return the ProbeRTT low gain (0.85×) to aggressively drain the bottleneck queue; mirrors C# `return BBR_PROBE_RTT_PACING_GAIN`.
    }

    // === Mobile/Unstable paths ===
    if (_currentNetworkClass == NetworkClass::MobileUnstable) { // The path is classified as mobile/unstable (high jitter, burst loss, LTE/5G/WiFi); mirrors C# `if (CurrentNetworkClass == NetworkClass.MobileUnstable)`.
        if (rttIncrease < kLowRttIncreaseRatio) { // RTT is stable (≤ 10% above MinRtt) — the jitter is link-layer noise, not queuing; mirrors C# `if (rttIncrease < LOW_RTT_INCREASE_RATIO)`.
            return _config.ProbeBwHighGain; // Return the full high probe gain (1.35×) — aggressive probing is safe when RTT is stable; mirrors C# `return _config.ProbeBwHighGain`.
        }
        if (rttIncrease < kModerateRttIncreaseRatio) { // RTT is moderately elevated (≤ 20% above MinRtt) — possible early congestion signal; mirrors C# moderate check.
            return kLightLossPacingGain; // Return the light-loss pacing gain (1.10×) — still probe, but less aggressively; mirrors C# `return BBR_LIGHT_LOSS_PACING_GAIN`.
        }
        return 1.0; // RTT is significantly elevated — genuine congestion; pace conservatively at 1.00×; mirrors C# `return 1d`.
    }

    // === Lossy Long-Fat paths ===
    if (_currentNetworkClass == NetworkClass::LossyLongFat) { // The path is classified as lossy long-fat (satellite, long-haul undersea cable with steady background loss); mirrors C# `if (CurrentNetworkClass == NetworkClass.LossyLongFat)`.
        if (rttIncrease < kModerateRttIncreaseRatio) { // RTT is relatively stable (≤ 20% above MinRtt) — the background loss is from physical noise, not queuing; mirrors C# moderate check.
            return kModerateProbeGain; // Return the moderate probe gain (1.50×) to compensate for steady background throughput loss; mirrors C# `return BBR_MODERATE_PROBE_GAIN`.
        }
        return 1.0; // RTT is rising significantly — this is genuine congestion; pace at 1.00×; mirrors C# `return 1d`.
    }

    // === Random loss (non-congestion, stable RTT) ===
    if (_networkCondition == NetworkCondition::RandomLoss) { // Loss is present but the condition classifier says it's random (RTT was stable when loss appeared); mirrors C# `if (_networkCondition == NetworkCondition.RandomLoss)`.
        if (rttIncrease < kLowRttIncreaseRatio) { // RTT is completely stable (≤ 10% above MinRtt) — the path can handle the current rate; mirrors C# low-RTT check.
            return std::max(1.0, _config.ProbeBwHighGain); // Return at minimum 1.00×, ideally the full high probe gain (1.35×) since loss is not from congestion; mirrors C# `return Math.Max(1d, _config.ProbeBwHighGain)`.
        }
        if (rttIncrease < kModerateRttIncreaseRatio) { // RTT is moderately rising (≤ 20% above MinRtt) — possible onset of congestion on top of random loss; mirrors C# moderate check.
            return std::max(1.0, kModerateProbeGain); // Return at minimum 1.00×, with a moderate probe gain (1.50×) for cautious recovery; mirrors C# `return Math.Max(1d, BBR_MODERATE_PROBE_GAIN)`.
        }
        return 1.0; // RTT is rising significantly — treat as genuine congestion; pace conservatively at 1.00×; mirrors C# `return 1d`.
    }

    // === Low-latency LAN: always aggressive ===
    if (_currentNetworkClass == NetworkClass::LowLatencyLAN) { // The path is a low-latency LAN (sub-5ms RTT, minimal jitter, negligible loss); mirrors C# `if (CurrentNetworkClass == NetworkClass.LowLatencyLAN)`.
        return _config.ProbeBwHighGain; // Always use the aggressive high probe gain (1.35×) — zero queuing risk on a LAN; mirrors C# `return _config.ProbeBwHighGain`.
    }

    // === Default path: tiered by loss ratio and RTT increase ===
    if (lossRatio < kLowLossRatio && rttIncrease < kLowRttIncreaseRatio) { // Both loss (≤ 1%) and RTT increase (≤ 10%) are low — the path is healthy; mirrors C# lowest tier check.
        return std::max(1.0, _config.ProbeBwHighGain); // Return at minimum 1.00×, ideally the full high probe gain (1.35×) for aggressive bandwidth discovery; mirrors C# `return Math.Max(1d, _config.ProbeBwHighGain)`.
    }

    if (lossRatio < kModerateLossRatio && rttIncrease < kModerateRttIncreaseRatio) { // Both loss (≤ 3%) and RTT (≤ 20%) are moderate — cautious probing is appropriate; mirrors C# moderate tier.
        return std::max(1.0, kModerateProbeGain); // Return at minimum 1.00×, with a moderate probe gain (1.50×) for balanced bandwidth probing; mirrors C# `return Math.Max(1d, BBR_MODERATE_PROBE_GAIN)`.
    }

    if (lossRatio < kLightLossRatio) { // Loss is light (≤ 8%) — a slight upward bias is still safe; mirrors C# light-loss tier.
        return std::max(1.0, kLightLossPacingGain); // Return at minimum 1.00×, with a light-loss pacing gain (1.10×) for cautious probing; mirrors C# `return Math.Max(1d, BBR_LIGHT_LOSS_PACING_GAIN)`.
    }

    if (lossRatio < kMediumLossRatio) { // Loss is at medium level (≤ 15%) — modest back-off; mirrors C# medium-loss tier.
        return std::max(1.0, kMediumLossPacingGain); // Return at minimum 1.00×, with a medium-loss pacing gain (1.05×) for very cautious probing; mirrors C# `return Math.Max(1d, BBR_MEDIUM_LOSS_PACING_GAIN)`.
    }

    return std::max(1.0, kHighLossPacingGain); // Loss is high — use the strong back-off pacing gain (1.00× at minimum) to relieve the path; mirrors C# `return Math.Max(1d, BBR_HIGH_LOSS_PACING_GAIN)`.
}

// ====================================================================================================
// Loss estimation (EWMA)
// ====================================================================================================

void BbrCongestionControl::UpdateEstimatedLossPercent(int64_t nowMicros) {
    UpdateEstimatedLossPercent(nowMicros, CalculateLossPercent(nowMicros)); // Delegate to the two-parameter EWMA update with a freshly computed loss percentage; mirrors C# `UpdateEstimatedLossPercent(nowMicros, CalculateLossPercent(nowMicros))`.
}

void BbrCongestionControl::UpdateEstimatedLossPercent(int64_t nowMicros, double candidateLossPercent) {
    double boundedCandidate = std::max(0.0, std::min(100.0, candidateLossPercent)); // Clamp the candidate loss percentage to the valid range [0, 100] to prevent nonsensical values; mirrors C# `boundedCandidate = Math.Max(0d, Math.Min(100d, candidateLossPercent))`.
    if (boundedCandidate <= 0.0 && GetRecentLossRatio(nowMicros) <= 0.0) { // No current loss candidate and no recent loss in the sliding window — the loss event has fully passed; mirrors C# idle-decay condition.
        _estimatedLossPercent *= kLossEwmaIdleDecay; // Idle decay: multiply the estimate by 0.90 to let it drift toward zero over time; mirrors C# `EstimatedLossPercent *= BBR_LOSS_EWMA_IDLE_DECAY`.
        return; // Exit early — there is no new loss signal to incorporate into the EWMA; mirrors C# early return.
    }

    if (_estimatedLossPercent <= 0.0) { // This is the first time we are setting the EWMA loss estimate (or it has fully decayed to zero); mirrors C# `if (EstimatedLossPercent <= 0d)`.
        _estimatedLossPercent = boundedCandidate; // First estimate: set directly without blending — no previous value exists for EWMA; mirrors C# `EstimatedLossPercent = boundedCandidate`.
        return; // Exit early — no previous value exists for EWMA blending; mirrors C# early return.
    }

    // EWMA: 75% retained + 25% new sample.
    _estimatedLossPercent = (_estimatedLossPercent * kLossEwmaRetainedWeight) + (boundedCandidate * kLossEwmaSampleWeight); // Blend the new sample (25% weight) with the previous estimate (75% weight) for a smooth, responsive estimate; mirrors C# EWMA formula.
}

double BbrCongestionControl::CalculateLossPercent(int64_t nowMicros) {
    double targetRate = _btlBwBytesPerSecond > 0 ? _btlBwBytesPerSecond : static_cast<double>(_config.InitialBandwidthBytesPerSecond); // Determine the target delivery rate: current BtlBw if valid, otherwise the configured initial bandwidth; mirrors C# target-rate selection.
    if (targetRate <= 0) { // No valid target rate is available — cannot compute a meaningful loss percentage; mirrors C# `if (targetRate <= 0)`.
        return 0.0; // Return zero — there is no basis for computing a loss percentage; mirrors C# `return 0d`.
    }

    double retransmissionLoss = GetRecentLossRatio(nowMicros); // Get the recent retransmission-based loss ratio from the sliding bucket windows; mirrors C# `retransmissionLoss = GetRecentLossRatio(nowMicros)`.

    // In non-congested state or Startup: pure retransmission-based loss.
    if (_networkCondition != NetworkCondition::Congested
        || _deliveryRateBytesPerSecond <= 0
        || _mode == BbrMode::Startup) { // Path is not congested, no recent delivery rate, or still in Startup — rate shortfall is not a congestion signal; mirrors C# shortfall guard.
        return retransmissionLoss * 100.0; // Return the straightforward retransmission-based loss percentage (ratio × 100); mirrors C# `return retransmissionLoss * 100d`.
    }

    // In congested steady state: combine rate deficiency + retransmission loss.
    double actualRate = _deliveryRateBytesPerSecond; // Snapshot the most recent delivery rate for the shortfall calculation; mirrors C# `actualRate = _deliveryRateBytesPerSecond`.
    double lossFromRate = std::max(0.0, 1.0 - (actualRate / targetRate)); // Compute the rate shortfall fraction: how far below target the actual delivery is (1.0 − utilization); mirrors C# `lossFromRate = Math.Max(0d, 1d - (actualRate / targetRate))`.
    double rateLossHint = std::min(lossFromRate, retransmissionLoss + kRateLossHintMaxRatio); // Cap the rate-based loss hint: it can be at most the retransmission ratio plus a 5% margin, to prevent over-stating loss from application-limited gaps; mirrors C# `rateLossHint = Math.Min(lossFromRate, retransmissionLoss + RATE_LOSS_HINT_MAX_RATIO)`.
    return std::max(rateLossHint, retransmissionLoss) * 100.0; // Return the higher of the two loss signals (rate shortfall or retransmission), converted to a percentage; mirrors C# `return Math.Max(rateLossHint, retransmissionLoss) * 100d`.
}

// ====================================================================================================
// Network condition classification
// ====================================================================================================

NetworkCondition BbrCongestionControl::ClassifyNetworkCondition(int64_t nowMicros) {
    if (_deliveryRateHistoryCount < 2) { // Less than 2 delivery-rate samples in the trend buffer — cannot compute a meaningful rate change; mirrors C# `if (_deliveryRateHistoryCount < 2)`.
        return NetworkCondition::Idle; // Not enough data to classify — return Idle as the safe default; mirrors C# `return NetworkCondition.Idle`.
    }

    // Compute delivery-rate trend: oldest vs newest sample.
    int newestIndex = (_deliveryRateHistoryIndex + kDeliveryRateHistoryCount - 1) % kDeliveryRateHistoryCount; // Compute the circular buffer index of the newest (most recently written) sample; mirrors C# newestIndex calculation.
    int oldestIndex = (_deliveryRateHistoryIndex + kDeliveryRateHistoryCount - _deliveryRateHistoryCount) % kDeliveryRateHistoryCount; // Compute the circular buffer index of the oldest (first valid) sample; mirrors C# oldestIndex calculation.
    double oldestRate = _deliveryRateHistory[oldestIndex]; // Retrieve the oldest delivery rate sample for the trend baseline; mirrors C# `oldestRate = _deliveryRateHistory[oldestIndex]`.
    double newestRate = _deliveryRateHistory[newestIndex]; // Retrieve the newest delivery rate sample for the trend endpoint; mirrors C# `newestRate = _deliveryRateHistory[newestIndex]`.
    double deliveryRateChange = oldestRate <= 0 ? 0.0 : (newestRate - oldestRate) / oldestRate; // Compute the relative delivery-rate change: positive = increasing throughput, negative = declining (congestion signal); mirrors C# `deliveryRateChange = oldestRate <= 0 ? 0d : (newestRate - oldestRate) / oldestRate`.
    double lossRatio = GetRecentLossRatio(nowMicros); // Get the recent packet loss ratio for the scoring rules; mirrors C# `lossRatio = GetRecentLossRatio(nowMicros)`.
    double rttIncrease = GetAverageRttIncreaseRatio(); // Get the RTT increase ratio (avg − min) / min for the scoring rules; mirrors C# `rttIncrease = GetAverageRttIncreaseRatio()`.
    int congestionScore = 0; // Initialize the cumulative congestion score — starts at zero, each rule adds points; mirrors C# `int congestionScore = 0`.

    // Tier 1: delivery rate dropping AND RTT rising → strongest congestion signal.
    if (deliveryRateChange <= kCongestionRateDropRatio && rttIncrease >= kCongestionRttIncreaseRatio) { // Delivery rate is declining (≤ −15%) AND RTT is rising (≥ 50% above min); mirrors C# tier-1 condition.
        congestionScore += kCongestionRateDropScore; // Add the rate-drop+RTT-rise score (typically +1) for the strongest combined congestion signal; mirrors C# `congestionScore += BBR_CONGESTION_RATE_DROP_SCORE`.
    }

    // Tier 2: RTT growth alone → early-warning signal.
    if (rttIncrease >= kCongestionRttIncreaseRatio) { // RTT has risen above the congestion threshold (≥ 50%) — queues are building at the bottleneck; mirrors C# tier-2 condition.
        congestionScore += kCongestionRttGrowthScore; // Add the RTT-growth score (typically +1) for early-warning queue buildup detection; mirrors C# `congestionScore += BBR_CONGESTION_RTT_GROWTH_SCORE`.
    }

    // Tier 3: loss ratio above threshold AND RTT rising → loss confirms congestion.
    if (lossRatio >= kCongestionLossRatio && rttIncrease >= kCongestionRttIncreaseRatio) { // Loss ratio exceeds threshold (≥ 10%) AND RTT is rising — loss corroborates the congestion signal; mirrors C# tier-3 condition.
        congestionScore += kCongestionLossScore; // Add the loss-confirmed score (typically +1) — loss is corroborating evidence for congestion; mirrors C# `congestionScore += BBR_CONGESTION_LOSS_SCORE`.
    }

    if (congestionScore >= kCongestionClassifierScoreThreshold) { // The cumulative congestion score meets or exceeds the classifier threshold (≥ 2); mirrors C# `if (congestionScore >= BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD)`.
        return NetworkCondition::Congested; // Congestion confirmed — apply multiplicative CWND reduction and conservative pacing; mirrors C# `return NetworkCondition.Congested`.
    }

    // Loss present but RTT is flat → random/corruption loss, not queuing.
    if (lossRatio > 0 && rttIncrease <= kRandomLossMaxRttIncreaseRatio) { // Loss exists but RTT is flat (RTT increase ≤ 20%) — this is random/corruption loss, not queuing; mirrors C# random-loss condition.
        return NetworkCondition::RandomLoss; // Classify as random loss — use fast recovery (elevated pacing) without CWND reduction; mirrors C# `return NetworkCondition.RandomLoss`.
    }

    if (lossRatio < kLowLossRatio) { // Loss ratio is below the low-loss threshold (≤ 1%) — the path is essentially clean; mirrors C# `if (lossRatio < BBR_LOW_LOSS_RATIO)`.
        return NetworkCondition::LightLoad; // Classify as light load — aggressive probing is safe on a lightly loaded path; mirrors C# `return NetworkCondition.LightLoad`.
    }

    return NetworkCondition::Idle; // Insufficient data or ambiguous signals — return Idle as the safe default (no action taken); mirrors C# `return NetworkCondition.Idle`.
}

bool BbrCongestionControl::ShouldTreatLossAsCongestion(int64_t nowMicros, bool isCongestionSignal) {
    if (!isCongestionSignal) { // External source explicitly flags this as non-congestion — trust the signal and skip all further classification; mirrors C# `if (!isCongestionSignal)`.
        return false; // Treat as non-congestion loss (random) — fast recovery only, no CWND reduction; mirrors C# `return false`.
    }

    if (_networkCondition == NetworkCondition::Congested) { // The internal three-tier classifier independently confirms the path is congested — both signals align; mirrors C# `if (_networkCondition == NetworkCondition.Congested)`.
        return true; // Treat as congestion — both external (RTO/NAK) and internal (classifier) signals agree on congestion; mirrors C# `return true`.
    }

    double rttIncrease = GetAverageRttIncreaseRatio(); // Get the average RTT increase ratio for cross-verification with the external signal; mirrors C# `rttIncrease = GetAverageRttIncreaseRatio()`.
    double lossRatio = GetRecentLossRatio(nowMicros); // Get the recent loss ratio for cross-verification with the external signal; mirrors C# `lossRatio = GetRecentLossRatio(nowMicros)`.
    return rttIncrease >= kCongestionRttIncreaseRatio && lossRatio >= kCongestionLossRatio; // Both RTT (≥ 50%) AND loss (≥ 10%) must be elevated to confirm congestion; either alone is insufficient; mirrors C# `return rttIncrease >= ... && lossRatio >= ...`.
}

// ====================================================================================================
// RTT percentile and statistics
// ====================================================================================================

int64_t BbrCongestionControl::GetCwndModelRttMicros() {
    int64_t p10Rtt = GetP10RttMicros(); // Compute the 10th-percentile RTT from the history buffer (robust to occasional fast samples); mirrors C# `p10Rtt = GetP10RttMicros()`.
    int64_t modelRttMicros = p10Rtt > 0 ? std::max(_minRttMicros, p10Rtt) : _minRttMicros; // Use max(MinRtt, P10-RTT) as the model RTT; fall back to raw MinRtt if P10 is not yet available (< 4 samples); mirrors C# `modelRttMicros = p10Rtt > 0 ? Math.Max(MinRttMicros, p10Rtt) : MinRttMicros`.
    if (modelRttMicros <= 0) { // No valid model RTT could be determined — no RTT samples have been collected yet; mirrors C# `if (modelRttMicros <= 0)`.
        return 0; // Return zero to signal that CWND computation cannot proceed — use initial CWND instead; mirrors C# `return 0`.
    }
    return modelRttMicros; // Return the model RTT (robust, percentile-based) for BDP calculation in GetTargetCwndBytes; mirrors C# `return modelRttMicros`.
}

double BbrCongestionControl::GetAverageRttIncreaseRatio() {
    if (_rttHistoryCount == 0 || _minRttMicros <= 0) { // No RTT history samples OR MinRtt has never been set — cannot compute the ratio; mirrors C# `if (_rttHistoryCount == 0 || MinRttMicros <= 0)`.
        return 0.0; // Return zero — no RTT increase data is available; mirrors C# `return 0d`.
    }

    int64_t total = 0; // Initialize the running sum accumulator for the arithmetic mean; mirrors C# `long total = 0`.
    for (int i = 0; i < _rttHistoryCount; i++) { // Iterate through all valid RTT samples in the history buffer; mirrors C# `for (int i = 0; i < _rttHistoryCount; i++)`.
        total += _rttHistoryMicros[i]; // Accumulate each RTT sample into the running sum; mirrors C# `total += _rttHistoryMicros[i]`.
    }

    double averageRtt = static_cast<double>(total) / _rttHistoryCount; // Compute the simple arithmetic mean of all RTT samples: sum / count; mirrors C# `averageRtt = total / (double)_rttHistoryCount`.
    return std::max(0.0, (averageRtt - _minRttMicros) / _minRttMicros); // Return the relative increase ratio: (avg − min) / min, clamped to prevent negative values; mirrors C# `return Math.Max(0d, (averageRtt - MinRttMicros) / MinRttMicros)`.
}

int64_t BbrCongestionControl::GetP10RttMicros() {
    return GetPercentileRtt(0.10); // Delegate to the generic percentile function with the 10th percentile (P10); mirrors C# `return GetPercentileRtt(0.10d)`.
}

int64_t BbrCongestionControl::GetP25RttMicros() {
    return GetPercentileRtt(0.25); // Delegate to the generic percentile function with the 25th percentile (P25); mirrors C# `return GetPercentileRtt(0.25d)`.
}

int64_t BbrCongestionControl::GetP30RttMicros() {
    return GetPercentileRtt(0.30); // Delegate to the generic percentile function with the 30th percentile (P30); mirrors C# `return GetPercentileRtt(0.30d)`.
}

int64_t BbrCongestionControl::GetPercentileRtt(double percentile) {
    if (_rttHistoryCount < 4) { // Fewer than 4 RTT samples — percentile computation is unreliable with too few data points; mirrors C# `if (_rttHistoryCount < 4)`.
        return _minRttMicros; // Not enough samples — fall back to the raw minimum RTT as the best available estimate; mirrors C# `return MinRttMicros`.
    }

    int64_t sorted[64]; // Stack-allocated temporary array for sorting up to 64 RTT samples (buffer size: kRttHistoryCount = 32, plus safety); mirrors C# `new long[_rttHistoryCount]`.
    for (int i = 0; i < _rttHistoryCount && i < 64; i++) { // Copy valid samples from the circular buffer into the contiguous temporary array; mirrors C# `Array.Copy(_rttHistoryMicros, sorted, _rttHistoryCount)`.
        sorted[i] = _rttHistoryMicros[i]; // Copy each sample from the circular buffer to the temporary array; mirrors C# copy operation.
    }
    int count = _rttHistoryCount; // Record the number of valid entries for the sort and index calculation; mirrors C# implicit count.
    std::sort(sorted, sorted + count); // Sort the temporary array in ascending order — the lowest values come first, highest last; mirrors C# `Array.Sort(sorted)`.

    int index = std::max(0, std::min(count - 1, static_cast<int>(count * percentile))); // Compute the index: count × percentile fraction, clamped to the valid range [0, count−1]; mirrors C# `index = Math.Max(0, Math.Min(count - 1, (int)(count * percentile)))`.
    return sorted[index]; // Return the RTT value at the computed percentile position in the sorted array; mirrors C# `return sorted[index]`.
}

// ====================================================================================================
// Inflight bounds
// ====================================================================================================

void BbrCongestionControl::UpdateInflightBounds() {
    if (_btlBwBytesPerSecond <= 0 || _minRttMicros <= 0) { // Missing critical estimates — BDP cannot be computed for guardrail derivation; mirrors C# `if (BtlBwBytesPerSecond <= 0 || MinRttMicros <= 0)`.
        _inflightHighBytes = 0; // Reset the upper guardrail to zero (meaning no ceiling is applied during clamping); mirrors C# `_inflightHighBytes = 0`.
        _inflightLowBytes = 0; // Reset the lower guardrail to zero (meaning no floor is applied during clamping); mirrors C# `_inflightLowBytes = 0`.
        return; // Exit early — guardrails cannot be established without valid BtlBw and MinRtt; mirrors C# early return.
    }

    double bdpBytes = _btlBwBytesPerSecond * (_minRttMicros / static_cast<double>(kMicrosPerSecond)); // Compute the bandwidth-delay product in bytes using raw MinRtt for guardrail simplicity; mirrors C# `bdpBytes = BtlBwBytesPerSecond * (MinRttMicros / (double)MICROS_PER_SECOND)`.

    // Lower guardrail: at minimum the initial CWND, otherwise a fraction of BDP.
    _inflightLowBytes = std::max(static_cast<double>(_config.InitialCongestionWindowBytes), bdpBytes * kInflightLowGain); // Set the lower bound: the higher of the configured initial CWND or 1.25× BDP; mirrors C# `_inflightLowBytes = Math.Max(_config.InitialCongestionWindowBytes, bdpBytes * BBR_INFLIGHT_LOW_GAIN)`.

    // Upper guardrail: mobile/lossy paths get higher headroom for non-congestion retransmissions.
    double highGain = (_networkCondition != NetworkCondition::Congested
                        && (_currentNetworkClass == NetworkClass::MobileUnstable
                            || _currentNetworkClass == NetworkClass::LossyLongFat))
        ? kInflightMobileHighGain // Non-congested mobile/lossy path — allow more inflight headroom (2.00× BDP) for non-congestion retransmissions.
        : kInflightHighGain; // All other path types — use the standard (conservative) inflight high gain (2.00× BDP); mirrors C# highGain selection.
    _inflightHighBytes = std::max(_inflightLowBytes, bdpBytes * highGain); // Set the upper bound: the higher of the lower guardrail or BDP × path-class-appropriate high gain; mirrors C# `_inflightHighBytes = Math.Max(_inflightLowBytes, bdpBytes * highGain)`.
}

// ====================================================================================================
// Loss ratio from time-bucketed packet counters
// ====================================================================================================

double BbrCongestionControl::GetRecentLossRatio(int64_t nowMicros) {
    AdvanceLossBuckets(nowMicros); // Age out expired loss buckets before computing the ratio to ensure data freshness; mirrors C# `AdvanceLossBuckets(nowMicros)`.

    int64_t sent = 0; // Initialize the total-sent accumulator to zero; mirrors C# `long sent = 0`.
    int64_t retransmits = 0; // Initialize the total-retransmit accumulator to zero; mirrors C# `long retransmits = 0`.
    for (int i = 0; i < kLossBucketCount; i++) { // Iterate through all buckets in the sliding window; mirrors C# `for (int i = 0; i < BBR_LOSS_BUCKET_COUNT; i++)`.
        sent += _sentBuckets[i]; // Accumulate the sent-packet count from this bucket into the running total; mirrors C# `sent += _sentBuckets[i]`.
        retransmits += _retransmitBuckets[i]; // Accumulate the retransmit count from this bucket into the running total; mirrors C# `retransmits += _retransmitBuckets[i]`.
    }

    return sent == 0 ? 0.0 : static_cast<double>(retransmits) / sent; // Compute the loss ratio: retransmits / total-sent; return zero if no packets were sent to avoid divide-by-zero; mirrors C# `return sent == 0 ? 0d : retransmits / (double)sent`.
}

void BbrCongestionControl::AdvanceLossBuckets(int64_t nowMicros) {
    if (nowMicros <= 0) { // Timestamp is invalid (zero or negative) — use the current real time as a fallback; mirrors C# `if (nowMicros <= 0)`.
        nowMicros = NowMicroseconds(); // Get the current high-resolution timestamp to ensure correct bucket slot alignment; mirrors C# `nowMicros = UcpTime.NowMicroseconds()`.
    }

    int64_t alignedNow = nowMicros - (nowMicros % kLossBucketMicros); // Round down the timestamp to the nearest bucket boundary for deterministic time-slot allocation; mirrors C# `alignedNow = nowMicros - (nowMicros % BBR_LOSS_BUCKET_MICROS)`.
    if (_lossBucketStartMicros == 0 || nowMicros < _lossBucketStartMicros) { // First call ever (no window started) OR clock went backwards (system time adjustment); mirrors C# `if (_lossBucketStartMicros == 0 || nowMicros < _lossBucketStartMicros)`.
        _sentBuckets.fill(0); // Zero out all sent-packet bucket counters to start fresh; mirrors C# `Array.Clear(_sentBuckets, ...)`.
        _retransmitBuckets.fill(0); // Zero out all retransmit bucket counters to start fresh; mirrors C# `Array.Clear(_retransmitBuckets, ...)`.
        _lossBucketIndex = 0; // Reset the ring buffer write position to the first bucket; mirrors C# `_lossBucketIndex = 0`.
        _lossBucketStartMicros = alignedNow; // Set the window start time to the current aligned timestamp; mirrors C# `_lossBucketStartMicros = alignedNow`.
        return; // Done — all buckets are cleared and a new window begins now; mirrors C# early return.
    }

    int64_t steps = (nowMicros - _lossBucketStartMicros) / kLossBucketMicros; // Calculate how many full bucket durations have elapsed since the window start; mirrors C# `steps = (nowMicros - _lossBucketStartMicros) / BBR_LOSS_BUCKET_MICROS`.
    if (steps <= 0) { // No full bucket boundaries have been crossed — nothing to advance; mirrors C# `if (steps <= 0)`.
        return; // No advancement needed — exit early; mirrors C# early return.
    }

    if (steps >= kLossBucketCount) { // The elapsed time exceeds the total window span — all buckets are stale; mirrors C# `if (steps >= BBR_LOSS_BUCKET_COUNT)`.
        _sentBuckets.fill(0); // Clear all sent counters since the entire window is now expired; mirrors C# `Array.Clear(_sentBuckets, ...)`.
        _retransmitBuckets.fill(0); // Clear all retransmit counters since the entire window is now expired; mirrors C# `Array.Clear(_retransmitBuckets, ...)`.
        _lossBucketIndex = 0; // Reset the ring buffer write position to the first bucket; mirrors C# `_lossBucketIndex = 0`.
        _lossBucketStartMicros = alignedNow; // Reset the window start to the current aligned timestamp; mirrors C# `_lossBucketStartMicros = alignedNow`.
        return; // Done — all stale data is discarded, new window starts now; mirrors C# early return.
    }

    for (int64_t i = 0; i < steps; i++) { // Iterate through each elapsed bucket step to clear the now-expired time slots; mirrors C# `for (long i = 0; i < steps; i++)`.
        _lossBucketIndex = (_lossBucketIndex + 1) % kLossBucketCount; // Advance the ring buffer index to the next slot (wrapping around at the buffer end); mirrors C# `_lossBucketIndex = (_lossBucketIndex + 1) % BBR_LOSS_BUCKET_COUNT`.
        _sentBuckets[_lossBucketIndex] = 0; // Clear the sent counter at the new (now-active) slot — old data must not carry over; mirrors C# `_sentBuckets[_lossBucketIndex] = 0`.
        _retransmitBuckets[_lossBucketIndex] = 0; // Clear the retransmit counter at the new (now-active) slot — old data must not carry over; mirrors C# `_retransmitBuckets[_lossBucketIndex] = 0`.
    }

    _lossBucketStartMicros += steps * kLossBucketMicros; // Advance the window start time by exactly the number of buckets that were cleared; mirrors C# `_lossBucketStartMicros += steps * BBR_LOSS_BUCKET_MICROS`.
}

// ====================================================================================================
// Effective cwnd gain
// ====================================================================================================

double BbrCongestionControl::GetEffectiveCwndGain() {
    // Mobile/lossy paths skip the waste-budget cap — they need extra CWND for retransmission headroom.
    if (_currentNetworkClass == NetworkClass::MobileUnstable
        || _currentNetworkClass == NetworkClass::LossyLongFat) { // Path is mobile or lossy-fat — these need extra CWND for non-congestion retransmission headroom; mirrors C# `if (CurrentNetworkClass == NetworkClass.MobileUnstable || ...)`.
        return _cwndGain; // Return the CWND gain unchanged (no waste-budget cap) to maintain retransmission headroom; mirrors C# `return CwndGain`.
    }

    // Startup also skips the cap to allow rapid ramp-up.
    if (_mode == BbrMode::Startup) { // We are in Startup mode — the waste budget would artificially limit bandwidth discovery; mirrors C# `if (Mode == BbrMode.Startup)`.
        return _cwndGain; // Return the CWND gain unchanged (no waste-budget cap) to allow exponential Startup ramp-up; mirrors C# `return CwndGain`.
    }

    // Waste budget: limits total inflight to (1 + waste_budget) × base CWND gain.
    double wasteBudget = std::max(0.50, _config.MaxBandwidthWastePercent); // Determine the waste budget: use configured value, but never below 0.50 (50%) to maintain some headroom; mirrors C# `wasteBudget = Math.Max(0.50d, _config.MaxBandwidthWastePercent)`.
    double maxWasteGain = 1.0 + wasteBudget; // Compute the total permissible inflight multiplier: 1.0 (base BDP) + waste budget; mirrors C# `maxWasteGain = 1d + wasteBudget`.
    double limit = maxWasteGain * _config.ProbeBwCwndGain; // Compute the absolute gain ceiling: waste-budget cap multiplied by the base ProbeBW CWND gain; mirrors C# `limit = maxWasteGain * _config.ProbeBwCwndGain`.
    if (_pacingGain <= 0 || _pacingGain * _cwndGain <= limit) { // Pacing gain is invalid OR the total inflight is already within the waste budget; mirrors C# `if (PacingGain <= 0 || PacingGain * CwndGain <= limit)`.
        return _cwndGain; // No cap needed — the total inflight (CwndGain × PacingGain) is within the waste budget; mirrors C# `return CwndGain`.
    }

    // Cap CwndGain so that total inflight multiplier ≤ wasteBudget + 1.
    return std::max(1.0, limit / _pacingGain); // Derive a capped CWND gain: limit / pacing gain, floored at 1.0 so CWND never drops below BDP; mirrors C# `return Math.Max(1d, limit / PacingGain)`.
}

// ====================================================================================================
// Debug logging
// ====================================================================================================

void BbrCongestionControl::TraceLog(const char* message) {
    if (_config.EnableDebugLog) { // Debug logging is enabled in the configuration — the message passes the gate; mirrors C# `if (_config.EnableDebugLog)`.
        fprintf(stderr, "[UCP BBR] %s\n", message); // Emit the message to stderr with the "[UCP BBR]" prefix for filtering; mirrors C# `Trace.WriteLine("[UCP BBR] " + message)`.
    }
}

// ====================================================================================================
// Network path classification (long-term)
// ====================================================================================================

void BbrCongestionControl::AdvanceClassifierWindow(int64_t nowMicros, int sentOrAckedBytes,
                                                      int64_t sampleRttMicros, double lossRateSnapshot) {
    if (_classifierWindowStartMicros == 0) { // This is the first classifier window — initialize the start timestamp; mirrors C# `if (_classifierWindowStartMicros == 0)`.
        _classifierWindowStartMicros = nowMicros; // Set the window start to the current timestamp for duration tracking; mirrors C# `_classifierWindowStartMicros = nowMicros`.
    }

    _classifierWindowSentBytes += std::max(0, sentOrAckedBytes); // Accumulate sent/acked bytes into the current window (clamp negative values to zero for safety); mirrors C# `_classifierWindowSentBytes += Math.Max(0, sentOrAckedBytes)`.
    if (sampleRttMicros > 0) { // A valid RTT sample was provided with this call — update the RTT statistics; mirrors C# `if (sampleRttMicros > 0)`.
        _classifierWindowRttSumMicros += sampleRttMicros; // Add this RTT sample to the running sum for average computation; mirrors C# `_classifierWindowRttSumMicros += sampleRttMicros`.
        _classifierWindowRttCount++; // Increment the sample count for the denominator of the average; mirrors C# `_classifierWindowRttCount++`.
        if (_classifierWindowMinRttMicros == 0 || sampleRttMicros < _classifierWindowMinRttMicros) { // First RTT sample in this window OR a new minimum was observed; mirrors C# min-check.
            _classifierWindowMinRttMicros = sampleRttMicros; // Update the window's minimum RTT with this lower value; mirrors C# `_classifierWindowMinRttMicros = sampleRttMicros`.
        }
        if (sampleRttMicros > _classifierWindowMaxRttMicros) { // This RTT sample exceeds the current window maximum; mirrors C# max-check.
            _classifierWindowMaxRttMicros = sampleRttMicros; // Update the window's maximum RTT with this higher value; mirrors C# `_classifierWindowMaxRttMicros = sampleRttMicros`.
        }
    }

    // Window closed: finalize and slide.
    if (nowMicros - _classifierWindowStartMicros >= kNetworkClassifierWindowDurationMicros) { // The classifier window duration (200ms) has elapsed — finalize and store this window; mirrors C# `if (nowMicros - _classifierWindowStartMicros >= NETWORK_CLASSIFIER_WINDOW_DURATION_MICROS)`.
        ClassifierWindow& window = _classifierWindows[_classifierWindowIndex]; // Get a reference to the current slot in the classifier window circular buffer; mirrors C# `ref ClassifierWindow window = ref _classifierWindows[_classifierWindowIndex]`.
        window.AvgRttMicros = _classifierWindowRttCount > 0
            ? static_cast<double>(_classifierWindowRttSumMicros) / _classifierWindowRttCount // Compute the average RTT: sum / count, or zero if no samples were collected.
            : 0.0; // No RTT samples in this window — set average to zero; mirrors C# avgRtt computation.
        window.JitterMicros = (_classifierWindowMinRttMicros > 0 && _classifierWindowMaxRttMicros > 0)
            ? static_cast<double>(_classifierWindowMaxRttMicros - _classifierWindowMinRttMicros) // Compute the RTT jitter: max − min.
            : 0.0; // Either min or max RTT is missing — set jitter to zero; mirrors C# jitter computation.
        window.LossRate = lossRateSnapshot; // Store the current loss rate snapshot in this classifier window; mirrors C# `window.LossRate = lossRateSnapshot`.
        double elapsedWindow = static_cast<double>(std::max(static_cast<int64_t>(1), nowMicros - _classifierWindowStartMicros)); // Compute the elapsed window duration in microseconds (minimum 1 µs to avoid div-by-zero); mirrors C# elapsed computation.
        double windowBytesPerSecond = _classifierWindowSentBytes * kMicrosPerSecond / elapsedWindow; // Compute the throughput in bytes/s over the classifier window duration; mirrors C# `windowBytesPerSecond = ...`.
        window.ThroughputRatio = _btlBwBytesPerSecond > 0
            ? std::min(1.0, windowBytesPerSecond / _btlBwBytesPerSecond) // Compute the throughput ratio: actual / BtlBw, capped at 1.0 so utilisation can never exceed 100%.
            : 0.0; // BtlBw is zero — cannot compute a meaningful throughput ratio; mirrors C# throughputRatio computation.

        _classifierWindowIndex = (_classifierWindowIndex + 1) % kNetworkClassifierWindowCount; // Advance the circular buffer write position by one (wrapping around at the end); mirrors C# `_classifierWindowIndex = (_classifierWindowIndex + 1) % NETWORK_CLASSIFIER_WINDOW_COUNT`.
        if (_classifierWindowCount < kNetworkClassifierWindowCount) { // The buffer has not yet filled up — increase the valid window count; mirrors C# count guard.
            _classifierWindowCount++; // Increment the count of finalized classifier windows available for path classification; mirrors C# `_classifierWindowCount++`.
        }

        // Reset accumulators for the next window.
        _classifierWindowStartMicros = nowMicros; // Start a new classifier window at the current timestamp; mirrors C# `_classifierWindowStartMicros = nowMicros`.
        _classifierWindowSentBytes = 0; // Reset sent bytes counter for the new window; mirrors C# `_classifierWindowSentBytes = 0`.
        _classifierWindowMinRttMicros = 0; // Reset min RTT tracker for the new window; mirrors C# `_classifierWindowMinRttMicros = 0`.
        _classifierWindowMaxRttMicros = 0; // Reset max RTT tracker for the new window; mirrors C# `_classifierWindowMaxRttMicros = 0`.
        _classifierWindowRttSumMicros = 0; // Reset RTT sum accumulator for the new window; mirrors C# `_classifierWindowRttSumMicros = 0`.
        _classifierWindowRttCount = 0; // Reset RTT sample counter for the new window; mirrors C# `_classifierWindowRttCount = 0`.
    }
}

NetworkClass BbrCongestionControl::ClassifyNetworkPath() {
    if (_classifierWindowCount < 2) { // Fewer than 2 finalized classifier windows — not enough data (~400ms minimum) for reliable classification; mirrors C# `if (_classifierWindowCount < 2)`.
        return NetworkClass::Default; // Not enough data yet — return the generic default classification; mirrors C# `return NetworkClass.Default`.
    }

    // Average all windows.
    double avgRtt = 0.0; // Initialize the running average RTT accumulator; mirrors C# `double avgRtt = 0d`.
    double avgLoss = 0.0; // Initialize the running average loss accumulator; mirrors C# `double avgLoss = 0d`.
    double avgJitter = 0.0; // Initialize the running average jitter accumulator; mirrors C# `double avgJitter = 0d`.
    double minThroughput = 1.0; // Initialize the minimum throughput tracker (start high at 1.0, reduce when lower values are found); mirrors C# `double minThroughput = 1d`.
    for (int i = 0; i < _classifierWindowCount; i++) { // Iterate through all finalized classifier windows; mirrors C# `for (int i = 0; i < _classifierWindowCount; i++)`.
        avgRtt += _classifierWindows[i].AvgRttMicros; // Accumulate this window's average RTT into the running sum; mirrors C# `avgRtt += _classifierWindows[i].AvgRttMicros`.
        avgLoss += _classifierWindows[i].LossRate; // Accumulate this window's loss rate into the running sum; mirrors C# `avgLoss += _classifierWindows[i].LossRate`.
        avgJitter += _classifierWindows[i].JitterMicros; // Accumulate this window's jitter into the running sum; mirrors C# `avgJitter += _classifierWindows[i].JitterMicros`.
        if (_classifierWindows[i].ThroughputRatio > 0 && _classifierWindows[i].ThroughputRatio < minThroughput) { // This window has a valid throughput ratio that is lower than the current minimum; mirrors C# min-check.
            minThroughput = _classifierWindows[i].ThroughputRatio; // Update the minimum throughput tracker to this lower value; mirrors C# `minThroughput = _classifierWindows[i].ThroughputRatio`.
        }
    }

    avgRtt /= _classifierWindowCount; // Compute the arithmetic mean RTT across all windows; mirrors C# `avgRtt /= _classifierWindowCount`.
    avgLoss /= _classifierWindowCount; // Compute the arithmetic mean loss rate across all windows; mirrors C# `avgLoss /= _classifierWindowCount`.
    avgJitter /= _classifierWindowCount; // Compute the arithmetic mean jitter across all windows; mirrors C# `avgJitter /= _classifierWindowCount`.

    double avgRttMs = avgRtt / static_cast<double>(kMicrosPerMilli); // Convert the average RTT from microseconds to milliseconds for readable threshold comparison; mirrors C# `avgRttMs = avgRtt / MICROS_PER_MILLI`.
    double avgJitterMs = avgJitter / static_cast<double>(kMicrosPerMilli); // Convert the average jitter from microseconds to milliseconds for readable threshold comparison; mirrors C# `avgJitterMs = avgJitter / MICROS_PER_MILLI`.

    // Rule 1: Low-latency LAN — < 5ms RTT, < 0.1% loss, < 3ms jitter.
    if (avgRttMs < kNetworkClassifierLanRttMs && avgLoss < 0.001 && avgJitterMs < kNetworkClassifierLanJitterMs) { // RTT < 5ms, loss < 0.1%, jitter < 3ms — this is a classic LAN; mirrors C# LAN rule.
        return NetworkClass::LowLatencyLAN; // Classify as low-latency LAN — use aggressive pacing (1.35×) on this clean high-speed path; mirrors C# `return NetworkClass.LowLatencyLAN`.
    }

    // Rule 2: Mobile/Unstable — > 3% loss and > 20ms jitter.
    if (avgLoss > kNetworkClassifierMobileLossRate && avgJitterMs > kNetworkClassifierMobileJitterMs) { // Loss rate > 3% AND jitter > 20ms — this is a wireless/mobile path; mirrors C# mobile rule.
        return NetworkClass::MobileUnstable; // Classify as mobile/unstable — use extended high-gain cycles and fast recovery for non-congestion radio loss; mirrors C# `return NetworkClass.MobileUnstable`.
    }

    // Rule 3: Lossy Long-Fat — > 80ms RTT and > 1% loss.
    if (avgRttMs > kNetworkClassifierLongFatRttMs && avgLoss > 0.01) { // RTT exceeds 80ms AND loss is above 1% — this is a satellite/long-haul path; mirrors C# lossy-fat rule.
        return NetworkClass::LossyLongFat; // Classify as lossy long-fat — use RTT-trend-based gain decisions and higher inflight guardrails; mirrors C# `return NetworkClass.LossyLongFat`.
    }

    // Rule 4: Congested Bottleneck — throughput < 70% AND RTT growing.
    if (minThroughput < 0.7
        && _classifierWindowCount > 0
        && avgRttMs > (_classifierWindows[0].AvgRttMicros / static_cast<double>(kMicrosPerMilli)) * 1.1) { // Throughput < 70% of BtlBw AND latest window's RTT > 110% of average (RTT is rising); mirrors C# congested rule.
        return NetworkClass::CongestedBottleneck; // Classify as congested bottleneck — use conservative pacing gains and tight CWND limits; mirrors C# `return NetworkClass.CongestedBottleneck`.
    }

    // Rule 5: Symmetric VPN — > 60ms RTT, stable pattern.
    if (avgRttMs > 60.0) { // Average RTT exceeds 60ms — this is likely a VPN tunnel or long-distance routed path; mirrors C# VPN rule.
        return NetworkClass::SymmetricVPN; // Classify as symmetric VPN — cap CWND conservatively to avoid tunnel bufferbloat; mirrors C# `return NetworkClass.SymmetricVPN`.
    }

    return NetworkClass::Default; // No specific pattern matched — return the generic default classification with standard pacing policies; mirrors C# `return NetworkClass.Default`.
}

} // namespace ucp
