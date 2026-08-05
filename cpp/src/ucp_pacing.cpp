/** @file ucp_pacing.cpp
 *  @brief Token-bucket pacing controller implementation -- mirrors C# Ucp.Internal.PacingController.
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

PacingController::PacingController(double initialRateBytesPerSecond) noexcept
    : PacingController(UcpConfiguration(), initialRateBytesPerSecond) {}

PacingController::PacingController(const UcpConfiguration& config, double initialRateBytesPerSecond) noexcept
    : PacingRateBytesPerSecond(0.0), _sendQuantumBytes(0 < config.SendQuantumBytes ? config.SendQuantumBytes : config.Mss),
      _minimumPacketCapacityBytes(DATA_HEADER_SIZE_WITH_ACK + std::max(1, config.MaxPayloadSize())),
      _maxPacingRateBytesPerSecond(config.MaxPacingRateBytesPerSecond), _minPacingIntervalMicros(config.MinPacingIntervalMicros()),
      _bucketDurationMicros(config.PacingBucketDurationMicros() <= 0 ? DEFAULT_PACING_BUCKET_DURATION_MICROS
                                                                     : config.PacingBucketDurationMicros()),
      _tokens(0.0), _capacity(0.0), _lastRefillMicros(0) {
    SetRate(initialRateBytesPerSecond, 0);
    _tokens = std::max(std::min(_capacity, static_cast<double>(_sendQuantumBytes)), static_cast<double>(_minimumPacketCapacityBytes));
}

void PacingController::SetRate(double rateBytesPerSecond, int64_t nowMicros) noexcept {
    if (0 >= rateBytesPerSecond) {
        rateBytesPerSecond = static_cast<double>(_sendQuantumBytes);
    }

    if (0 < _maxPacingRateBytesPerSecond && rateBytesPerSecond > static_cast<double>(_maxPacingRateBytesPerSecond)) {
        rateBytesPerSecond = static_cast<double>(_maxPacingRateBytesPerSecond);
    }

    Refill(nowMicros);
    PacingRateBytesPerSecond = rateBytesPerSecond;

    _capacity = std::max({static_cast<double>(_sendQuantumBytes), static_cast<double>(_minimumPacketCapacityBytes),
                          rateBytesPerSecond * static_cast<double>(_bucketDurationMicros) / static_cast<double>(MICROS_PER_SECOND)});
    if (_tokens > _capacity) {
        _tokens = _capacity;
    }

    _lastRefillMicros = nowMicros;
}

void PacingController::Refill(int64_t nowMicros) noexcept {
    if (0 == _lastRefillMicros) {
        _lastRefillMicros = nowMicros;
        return;
    }

    int64_t elapsedMicros = nowMicros - _lastRefillMicros;
    if (0 >= elapsedMicros) {
        return;
    }

    _tokens += (static_cast<double>(elapsedMicros) / static_cast<double>(MICROS_PER_SECOND)) * PacingRateBytesPerSecond;
    if (_tokens > _capacity) {
        _tokens = _capacity;
    }

    _lastRefillMicros = nowMicros;
}

bool PacingController::TryConsume(int bytes, int64_t nowMicros) noexcept {
    Refill(nowMicros);
    if (_tokens >= static_cast<double>(bytes)) {
        _tokens -= static_cast<double>(bytes);
        return true;
    }
    return false;
}

void PacingController::ForceConsume(int, int64_t nowMicros) noexcept {
    Refill(nowMicros);
    if (0 < _tokens) {
        _tokens = 0;
    }
}

int64_t PacingController::GetWaitTimeMicros(int bytes, int64_t nowMicros) noexcept {
    Refill(nowMicros);
    if (_tokens >= static_cast<double>(bytes)) {
        if (0 < _minPacingIntervalMicros) {
            return _minPacingIntervalMicros;
        }
        return 0;
    }

    if (0 >= PacingRateBytesPerSecond) {
        return DEFAULT_PACING_WAIT_MICROS;
    }

    double deficit = static_cast<double>(bytes) - _tokens;

    int64_t waitMicros = static_cast<int64_t>(std::ceil((deficit / PacingRateBytesPerSecond) * static_cast<double>(MICROS_PER_SECOND)));
    if (0 < _minPacingIntervalMicros && waitMicros < _minPacingIntervalMicros) {
        return _minPacingIntervalMicros;
    }

    static constexpr int64_t kMinPacingWaitMicros = 100;
    if (waitMicros < kMinPacingWaitMicros) {
        return kMinPacingWaitMicros;
    }

    return waitMicros;
}

} // namespace ucp
