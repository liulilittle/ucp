#pragma once

/** @file ucp_rto_estimator.h
 *  @brief TCP-style RTO (Retransmission Time-Out) estimator — mirrors C# Ucp.Internal.RtoEstimator.
 *
 *  Maintains Smoothed RTT (SRTT) and RTT Variance (RTTVAR) using the standard
 *  Jacobson/Karels algorithm from RFC 6298.  Exposes backoff mechanics for
 *  exponential RTO doubling during loss events.
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
    /** @brief Default constructor — uses a default UcpConfiguration. */
    UcpRtoEstimator();

    /** @brief Construct with a specific configuration (min/max RTO, backoff factor).
     *  @param config  UcpConfiguration providing RTO bounds and backoff settings. */
    explicit UcpRtoEstimator(const UcpConfiguration& config);

    /** @brief Feed a new RTT measurement into the estimator.
     *  @param sample_micros  Measured round-trip time in microseconds (> 0). */
    void Update(int64_t sample_micros);

    /** @brief Apply exponential backoff to the current RTO (used on timeout retransmission). */
    void Backoff();

    /** @brief Current smoothed RTT estimate.
     *  @return Smoothed RTT in microseconds. */
    int64_t SmoothedRttMicros()   const { return m_srtt_micros; }

    /** @brief Current RTT variance estimate.
     *  @return RTTVAR in microseconds. */
    int64_t RttVarianceMicros()   const { return m_rttvar_micros; }

    /** @brief Current effective RTO value.
     *  @return RTO in microseconds (clamped to [min, max] bounds). */
    int64_t CurrentRtoMicros()    const { return m_current_rto_micros; }

private:
    int64_t m_min_rto_micros;    //< Lower clamp for RTO (microseconds).
    int64_t m_max_rto_micros;    //< Upper clamp for RTO (microseconds).
    double  m_backoff_factor;    //< Multiplier applied on each Backoff() call (typ. 1.2).

    int64_t m_srtt_micros          = 0;  //< Smoothed round-trip time (EWMA).
    int64_t m_rttvar_micros        = 0;  //< RTT variance (mean deviation approximation).
    int64_t m_current_rto_micros   = 0;  //< Current effective RTO = SRTT + 4*RTTVAR, clamped.
};

} // namespace ucp
