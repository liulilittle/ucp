/** @file ucp_pacing.cpp
 *  @brief Token-bucket pacing controller implementation — mirrors C# Ucp.Internal.PacingController.
 *
 *  Implements a token-bucket algorithm for smooth outbound send pacing.
 *  Tokens accumulate at PacingRateBytesPerSecond and are consumed by each
 *  packet send.  When tokens are insufficient, the caller can either
 *  wait (TryConsume returns false) or force-consume (ForceConsume drains
 *  any positive token balance to zero).
 */

#include "ucp/ucp_pacing.h"
#include <algorithm>
#include <cmath>

namespace ucp {
using namespace Constants;

PacingController::PacingController(double initialRateBytesPerSecond)
    : PacingController(UcpConfiguration(), initialRateBytesPerSecond) { // Delegate to the config-based constructor with a default UcpConfiguration.
}

PacingController::PacingController(const UcpConfiguration& config, double initialRateBytesPerSecond)
    : PacingRateBytesPerSecond(0.0) // Initialize rate to zero; will be set by SetRate below.
    , _sendQuantumBytes(config.SendQuantumBytes > 0 ? config.SendQuantumBytes : config.Mss) // Use configured quantum or fall back to MSS as a sensible one-packet batch size.
    , _minimumPacketCapacityBytes(DATA_HEADER_SIZE_WITH_ACK + std::max(1, config.MaxPayloadSize())) // Calculate minimum bytes for one full packet: header + max payload, clamped to at least 1.
    , _maxPacingRateBytesPerSecond(config.MaxPacingRateBytesPerSecond) // Cache the absolute maximum rate ceiling for fast clamping in SetRate.
    , _minPacingIntervalMicros(config.MinPacingIntervalMicros()) // Cache the minimum inter-send gap to avoid timer granularity issues.
    , _bucketDurationMicros(config.PacingBucketDurationMicros() <= 0 ? DEFAULT_PACING_BUCKET_DURATION_MICROS : config.PacingBucketDurationMicros()) // Use configured bucket window or protocol default if zero/negative.
    , _tokens(0.0) // Initialize token balance to zero; will be filled to capacity by SetRate below.
    , _capacity(0.0) // Initialize capacity to zero; will be recalculated by SetRate below.
    , _lastRefillMicros(0) // Mark as never refilled so the first Refill call only stamps the timestamp.
{
    SetRate(initialRateBytesPerSecond, 0); // Apply the initial rate and pre-fill the bucket at time zero.
    _tokens = _capacity; // Start with a full bucket so the first send is immediately eligible without waiting.
}

void PacingController::SetRate(double rateBytesPerSecond, int64_t nowMicros) {
    if (rateBytesPerSecond <= 0) { // Guard against zero or negative rate that would break refill and wait-time math.
        rateBytesPerSecond = static_cast<double>(_sendQuantumBytes); // Floor rate to one quantum per second so the bucket still refills slowly.
    }

    if (_maxPacingRateBytesPerSecond > 0 && rateBytesPerSecond > static_cast<double>(_maxPacingRateBytesPerSecond)) { // Check if the requested rate exceeds the configured ceiling.
        rateBytesPerSecond = static_cast<double>(_maxPacingRateBytesPerSecond); // Clamp to the maximum allowed rate to prevent excessive send bursts.
    }

    Refill(nowMicros); // Refill tokens based on elapsed time at the current (old) rate before switching to the new rate.
    PacingRateBytesPerSecond = rateBytesPerSecond; // Commit the new pacing rate for subsequent refills and wait-time calculations.

    // Recalculate bucket capacity from new rate, floored at the larger of send quantum and minimum packet capacity.
    _capacity = std::max({static_cast<double>(_sendQuantumBytes), // Ensure the bucket can hold at least one send quantum.
                          static_cast<double>(_minimumPacketCapacityBytes), // Ensure the bucket can hold at least one full packet.
                          rateBytesPerSecond * static_cast<double>(_bucketDurationMicros) / static_cast<double>(MICROS_PER_SECOND)}); // Capacity = rate × bucket duration / 1 second.
    if (_tokens > _capacity) { // If the old bucket had more tokens than the new smaller capacity allows.
        _tokens = _capacity; // Cap tokens at the new capacity; prevents surplus from being carried forward.
    }

    _lastRefillMicros = nowMicros; // Reset the refill timestamp so future refills are measured from this rate change point.
}

void PacingController::Refill(int64_t nowMicros) {
    if (_lastRefillMicros == 0) { // First-ever refill call; no elapsed time to compute yet.
        _lastRefillMicros = nowMicros; // Initialize the timestamp so the next refill computes actual elapsed time.
        return; // Exit early; no tokens to add on the very first call.
    }

    int64_t elapsedMicros = nowMicros - _lastRefillMicros; // Compute how many microseconds have passed since the last refill.
    if (elapsedMicros <= 0) { // Guard against non-monotonic clock or same-timestamp duplicate calls.
        return; // No time has elapsed; skip refill to avoid zero or negative token additions.
    }

    // Add tokens proportional to elapsed time: tokens += elapsed_seconds × rate_bytes_per_second.
    _tokens += (static_cast<double>(elapsedMicros) / static_cast<double>(MICROS_PER_SECOND)) * PacingRateBytesPerSecond;
    if (_tokens > _capacity) { // Check if the token balance exceeds the bucket capacity ceiling.
        _tokens = _capacity; // Cap at bucket capacity to prevent unlimited token accumulation during idle periods.
    }

    _lastRefillMicros = nowMicros; // Update the last refill timestamp for the next refill calculation.
}

bool PacingController::TryConsume(int bytes, int64_t nowMicros) {
    Refill(nowMicros); // Add tokens proportional to elapsed time before checking balance.
    if (_tokens >= static_cast<double>(bytes)) { // Check if the bucket has enough tokens to cover the requested byte count.
        _tokens -= static_cast<double>(bytes); // Deduct the consumed bytes from the token balance.
        return true; // Signal that the send is eligible and tokens were consumed.
    }
    return false; // Insufficient tokens; the caller should defer this send or use ForceConsume.
}

void PacingController::ForceConsume(int /*bytes*/, int64_t nowMicros) {
    Refill(nowMicros); // Add tokens proportional to elapsed time before draining.
    if (_tokens > 0) { // If there are any positive tokens available in the bucket.
        _tokens = 0; // Drain tokens to zero so the next regular send is blocked until refill; creates temporary backpressure after a forced urgent send.
    }
}

int64_t PacingController::GetWaitTimeMicros(int bytes, int64_t nowMicros) {
    Refill(nowMicros); // Add tokens proportional to elapsed time before checking balance.
    if (_tokens >= static_cast<double>(bytes)) { // If the bucket already has enough tokens to cover the requested bytes.
        return 0; // No wait needed; the send can proceed immediately.
    }

    if (PacingRateBytesPerSecond <= 0) { // Guard against zero pacing rate which would cause division by zero.
        return DEFAULT_PACING_WAIT_MICROS; // Fallback wait time when the rate is undefined or stopped.
    }

    double deficit = static_cast<double>(bytes) - _tokens; // Calculate how many tokens we are short of the required amount.
    // Convert byte deficit to seconds of refill time, then to microseconds, rounding up.
    int64_t waitMicros = static_cast<int64_t>(std::ceil((deficit / PacingRateBytesPerSecond) * static_cast<double>(MICROS_PER_SECOND)));
    if (_minPacingIntervalMicros > 0 && waitMicros < _minPacingIntervalMicros) { // If the computed wait is shorter than the minimum pacing interval.
        return _minPacingIntervalMicros; // Respect minimum pacing interval to avoid excessive CPU churn from tiny waits.
    }

    return waitMicros; // Return the estimated wait time in microseconds.
}

} // namespace ucp
