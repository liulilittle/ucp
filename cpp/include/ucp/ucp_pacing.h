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

/** @file ucp_pacing.h
 *  @brief Token-bucket pacing controller -- mirrors C# Ucp.Internal.PacingController.
 *
 *  The pacing controller smooths outbound packet transmission by accumulating
 *  tokens at a configured bytes-per-second rate.  Each send consumes tokens
 *  from the bucket; if insufficient tokens are available, the caller should
 *  wait or force-consume (draining tokens to zero).  This prevents bursts
 *  that would overwhelm bottleneck buffers.
 *
 *  The controller is driven by the UCP bandwidth estimate but imposes its own
 *  minimum pacing interval and maximum rate bounds via UcpConfiguration.
 */

#include "ucp_constants.h"
#include "ucp_configuration.h"
#include <cstdint>

namespace ucp {

class PacingController {
  public:
    double PacingRateBytesPerSecond;

    /** @brief Minimum bytes that can be sent per quantum (aligns with packet size granularity).
     *  @return The SendQuantumBytes value. */
    int SendQuantumBytes() const noexcept { return _sendQuantumBytes; }

    /** @brief Construct with an initial rate and default configuration.
     *  @param initialRateBytesPerSecond  Starting pacing rate (bytes/s). */
    explicit PacingController(double initialRateBytesPerSecond) noexcept;

    /** @brief Construct with explicit configuration and initial rate.
     *  @param config                     UcpConfiguration providing bucket duration, min interval, max rate.
     *  @param initialRateBytesPerSecond  Starting pacing rate (bytes/s). */
    PacingController(const UcpConfiguration& config, double initialRateBytesPerSecond) noexcept;

    PacingController(const PacingController&) = delete;

    PacingController& operator=(const PacingController&) = delete;
    PacingController(PacingController&&) = delete;
    PacingController& operator=(PacingController&&) = delete;

    /** @brief Change the target pacing rate, refilling the token bucket.
     *  @param rateBytesPerSecond  New pacing rate (clamped by max rate).
     *  @param nowMicros           Current timestamp for refill calculation. */
    void SetRate(double rateBytesPerSecond, int64_t nowMicros) noexcept;

    /** @brief Attempt to consume tokens for a send of the given size.
     *  @param  bytes      Number of bytes to send.
     *  @param  nowMicros  Current timestamp.
     *  @return True if enough tokens are available; false if the caller should wait. */
    bool TryConsume(int bytes, int64_t nowMicros) noexcept;

    /** @brief Force-consume tokens even when insufficient, draining any positive balance to zero.
     *  @param bytes      Number of bytes being sent (unused in deduction; only drains balance).
     *  @param nowMicros  Current timestamp. */
    void ForceConsume(int bytes, int64_t nowMicros) noexcept;

    /** @brief Estimate how many microseconds to wait before enough tokens accumulate.
     *  @param  bytes      Bytes the caller wants to send.
     *  @param  nowMicros  Current timestamp.
     *  @return 0 if sufficient tokens exist; otherwise wait time in microseconds. */
    int64_t GetWaitTimeMicros(int bytes, int64_t nowMicros) noexcept;

  private:
    /** @brief Refill tokens based on elapsed time since last refill.
     *  @param nowMicros  Current timestamp. */
    void Refill(int64_t nowMicros) noexcept;

    int _sendQuantumBytes;
    int _minimumPacketCapacityBytes;
    int64_t _maxPacingRateBytesPerSecond;
    int64_t _minPacingIntervalMicros;
    int64_t _bucketDurationMicros;
    double _tokens;
    double _capacity;
    int64_t _lastRefillMicros;
};

} // namespace ucp
