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

/** @file ucp_rto_estimator.h
 *  @brief TCP-style RTO (Retransmission Time-Out) estimator -- mirrors C# Ucp.Internal.RtoEstimator.
 *
 *  Maintains Smoothed RTT (SRTT) and RTT Variance (RTTVAR) using the standard
 *  Jacobson/Karels algorithm from RFC 6298.  Exposes backoff mechanics for
 *  RTO growth on loss events (scaled by the configured backoff factor).
 *
 *  All bounds (min/max RTO, backoff factor) are pulled from UcpConfiguration
 *  so different connections can operate with different RTO profiles.
 */

#include "ucp_configuration.h"
#include <cstdint>

namespace ucp {

/** @brief Jacobson/Karels RTO estimator with exponential backoff.
 *
 *  Tracks SRTT, RTTVAR, and the current RTO value.  On each new RTT sample
 *  the SRTT and RTTVAR are updated via EWMA, and RTO = SRTT + 4 * RTTVAR.
 *  When backoff is triggered (e.g. timeout retransmission), the RTO is
 *  multiplied by the backoff factor up to a configured maximum.
 */
class UcpRtoEstimator {
  public:
    UcpRtoEstimator() noexcept;

    /** @brief Construct with a specific configuration (min/max RTO, backoff factor).
     *  @param config  UcpConfiguration providing RTO bounds. */
    explicit UcpRtoEstimator(const UcpConfiguration& config) noexcept;

    UcpRtoEstimator(const UcpRtoEstimator&) = delete;

    UcpRtoEstimator& operator=(const UcpRtoEstimator&) = delete;
    UcpRtoEstimator(UcpRtoEstimator&&) = delete;
    UcpRtoEstimator& operator=(UcpRtoEstimator&&) = delete;

    /** @brief Feed a new RTT measurement into the estimator.
     *  @param sample_micros  RTT sample in microseconds (> 0). */
    void Update(int64_t sample_micros) noexcept;

    void Backoff() noexcept;

    /** @brief Current smoothed RTT estimate in microseconds.
     *  @return SRTT value. */
    int64_t SmoothedRttMicros() const noexcept { return m_srtt_micros; }

    /** @brief Current RTT variance estimate in microseconds.
     *  @return RTTVAR value. */
    int64_t RttVarianceMicros() const noexcept { return m_rttvar_micros; }

    /** @brief Current effective RTO in microseconds (SRTT + 4*RTTVAR, clamped).
     *  @return Clamped RTO value. */
    int64_t CurrentRtoMicros() const noexcept { return m_current_rto_micros; }

  private:
    int64_t m_min_rto_micros;
    int64_t m_max_rto_micros;
    double m_backoff_factor;
    int64_t m_srtt_micros = 0;
    int64_t m_rttvar_micros = 0;
    int64_t m_current_rto_micros = 0;
};

} // namespace ucp
