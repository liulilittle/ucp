/** @file ucp_pacing.cpp
 *  @brief Token-bucket pacing controller implementation — mirrors C# Ucp.Internal.PacingController.
 *
 *  Implements a token-bucket algorithm for smooth outbound send pacing.
 *  Tokens accumulate at PacingRateBytesPerSecond and are consumed by each
 *  packet send.  When tokens are insufficient, the caller can either
 *  wait (TryConsume returns false) or force-consume with a bounded
 *  deficit (ForceConsume allows up to 50% of capacity as a shortfall).
 */

#include "ucp/ucp_pacing.h"
#include <algorithm>
#include <cmath>

namespace ucp {
using namespace Constants;

PacingController::PacingController(double initialRateBytesPerSecond)
    : PacingController(UcpConfiguration(), initialRateBytesPerSecond) {
}

PacingController::PacingController(const UcpConfiguration& config, double initialRateBytesPerSecond)
    : _sendQuantumBytes(config.SendQuantumBytes > 0 ? config.SendQuantumBytes : config.Mss)
    , _minimumPacketCapacityBytes(DATA_HEADER_SIZE_WITH_ACK + std::max(1, config.MaxPayloadSize()))
    , _maxPacingRateBytesPerSecond(config.MaxPacingRateBytesPerSecond)
    , _minPacingIntervalMicros(config.MinPacingIntervalMicros())
    , _bucketDurationMicros(config.PacingBucketDurationMicros() <= 0 ? DEFAULT_PACING_BUCKET_DURATION_MICROS : config.PacingBucketDurationMicros())
    , _tokens(0.0)
    , _capacity(0.0)
    , _lastRefillMicros(0)
    , PacingRateBytesPerSecond(0.0)
{
    SetRate(initialRateBytesPerSecond, 0);
    _tokens = _capacity;  // Start with a full bucket to allow an immediate burst
}

void PacingController::SetRate(double rateBytesPerSecond, int64_t nowMicros) {
    // Clamp the rate: zero defaults to SendQuantumBytes (minimum 1 byte/s)
    if (rateBytesPerSecond <= 0) {
        rateBytesPerSecond = static_cast<double>(_sendQuantumBytes);
    }

    // Cap at configured maximum pacing rate
    if (_maxPacingRateBytesPerSecond > 0 && rateBytesPerSecond > static_cast<double>(_maxPacingRateBytesPerSecond)) {
        rateBytesPerSecond = static_cast<double>(_maxPacingRateBytesPerSecond);
    }

    Refill(nowMicros);
    PacingRateBytesPerSecond = rateBytesPerSecond;

    // Bucket capacity = max(send_quantum, min_packet_size, rate * bucket_duration)
    _capacity = std::max({static_cast<double>(_sendQuantumBytes),
                          static_cast<double>(_minimumPacketCapacityBytes),
                          rateBytesPerSecond * static_cast<double>(_bucketDurationMicros) / static_cast<double>(MICROS_PER_SECOND)});
    if (_tokens > _capacity) {
        _tokens = _capacity;
    }

    _lastRefillMicros = nowMicros;
}

void PacingController::Refill(int64_t nowMicros) {
    // On first call, just record the timestamp — no elapsed time to refill from
    if (_lastRefillMicros == 0) {
        _lastRefillMicros = nowMicros;
        return;
    }

    int64_t elapsedMicros = nowMicros - _lastRefillMicros;
    if (elapsedMicros <= 0) {
        return;
    }

    // tokens += (elapsed_seconds) * rate_bytes_per_second
    _tokens += (static_cast<double>(elapsedMicros) / static_cast<double>(MICROS_PER_SECOND)) * PacingRateBytesPerSecond;
    if (_tokens > _capacity) {
        _tokens = _capacity;
    }

    _lastRefillMicros = nowMicros;
}

bool PacingController::TryConsume(int bytes, int64_t nowMicros) {
    Refill(nowMicros);
    if (_tokens >= static_cast<double>(bytes)) {
        _tokens -= static_cast<double>(bytes);
        return true;
    }
    return false;
}

void PacingController::ForceConsume(int bytes, int64_t nowMicros) {
    Refill(nowMicros);
    _tokens -= static_cast<double>(bytes);

    // Allow a deficit of up to 50% of bucket capacity (soft ceiling)
    double floorVal = -0.5 * _capacity;
    if (_tokens < floorVal) {
        _tokens = floorVal;
    }
}

int64_t PacingController::GetWaitTimeMicros(int bytes, int64_t nowMicros) {
    Refill(nowMicros);
    if (_tokens >= static_cast<double>(bytes)) {
        return 0;
    }

    // No rate set — return default wait
    if (PacingRateBytesPerSecond <= 0) {
        return DEFAULT_PACING_WAIT_MICROS;
    }

    // wait_time = deficit / rate (in seconds), converted to microseconds
    double deficit = static_cast<double>(bytes) - _tokens;
    int64_t waitMicros = static_cast<int64_t>(std::ceil((deficit / PacingRateBytesPerSecond) * static_cast<double>(MICROS_PER_SECOND)));

    // Enforce minimum pacing interval
    if (_minPacingIntervalMicros > 0 && waitMicros < _minPacingIntervalMicros) {
        return _minPacingIntervalMicros;
    }

    return waitMicros;
}

} // namespace ucp
