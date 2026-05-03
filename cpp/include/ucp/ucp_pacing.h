#pragma once

/** @file ucp_pacing.h
 *  @brief Token-bucket pacing controller — mirrors C# Ucp.Internal.PacingController.
 *
 *  The pacing controller smooths outbound packet transmission by accumulating
 *  tokens at a configured bytes-per-second rate.  Each send consumes tokens
 *  from the bucket; if insufficient tokens are available, the caller should
 *  wait or force-consume (allowing a bounded deficit).  This prevents bursts
 *  that would overwhelm bottleneck buffers.
 *
 *  The controller is driven by the BBR bandwidth estimate but imposes its own
 *  minimum pacing interval and maximum rate bounds via UcpConfiguration.
 */

#include "ucp_constants.h"
#include "ucp_configuration.h"

#include <cstdint>

namespace ucp {

/** @brief Token-bucket pacing controller that regulates outbound packet transmission rate. */
class PacingController {
public:
    double PacingRateBytesPerSecond;  //< Current target pacing rate (set dynamically by BBR).

    /** @brief Minimum bytes that can be sent per quantum (aligns with packet size granularity).
     *  @return The SendQuantumBytes value. */
    int SendQuantumBytes() const { return _sendQuantumBytes; }

    /** @brief Construct with an initial rate and default configuration.
     *  @param initialRateBytesPerSecond  Starting pacing rate (bytes/s). */
    PacingController(double initialRateBytesPerSecond);

    /** @brief Construct with explicit configuration and initial rate.
     *  @param config                     UcpConfiguration providing bucket duration, min interval, max rate.
     *  @param initialRateBytesPerSecond  Starting pacing rate (bytes/s). */
    PacingController(const UcpConfiguration& config, double initialRateBytesPerSecond);

    /** @brief Change the target pacing rate, refilling the token bucket.
     *  @param rateBytesPerSecond  New pacing rate (clamped by max rate).
     *  @param nowMicros           Current timestamp for refill calculation. */
    void SetRate(double rateBytesPerSecond, int64_t nowMicros);

    /** @brief Attempt to consume tokens for a send of the given size.
     *  @param bytes      Number of bytes to send.
     *  @param nowMicros  Current timestamp.
     *  @return true if enough tokens are available; false if the caller should wait. */
    bool TryConsume(int bytes, int64_t nowMicros);

    /** @brief Force-consume tokens even when insufficient (allowing a bounded deficit up to 50% of capacity).
     *  @param bytes      Number of bytes being sent.
     *  @param nowMicros  Current timestamp. */
    void ForceConsume(int bytes, int64_t nowMicros);

    /** @brief Estimate how many microseconds to wait before enough tokens accumulate.
     *  @param bytes      Bytes the caller wants to send.
     *  @param nowMicros  Current timestamp.
     *  @return 0 if sufficient tokens exist; otherwise wait time in microseconds. */
    int64_t GetWaitTimeMicros(int bytes, int64_t nowMicros);

private:
    /** @brief Refill tokens based on elapsed time since last refill.
     *  @param nowMicros  Current timestamp. */
    void Refill(int64_t nowMicros);

    int _sendQuantumBytes;              //< Minimum send unit (typically = MSS).
    int _minimumPacketCapacityBytes;    //< Minimum bucket capacity = sizeof(worst-case packet header + payload).
    int64_t _maxPacingRateBytesPerSecond; //< Absolute ceiling on pacing rate (0 = no limit).
    int64_t _minPacingIntervalMicros;    //< Floor on pacing interval (0 = no floor).
    int64_t _bucketDurationMicros;       //< Duration of the token bucket refill window.
    double _tokens;                      //< Current token count (bytes).
    double _capacity;                    //< Maximum token count (bucket depth in bytes).
    int64_t _lastRefillMicros;           //< Timestamp of the most recent Refill call.
};

} // namespace ucp
