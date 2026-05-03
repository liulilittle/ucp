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

#include "ucp_configuration.h"                                 // Provides UcpConfiguration for min/max RTO and backoff factor
#include <cstdint>                                              // Provides int64_t for microsecond timestamps

namespace ucp {                                                 // UCP protocol library namespace

/** @brief Jacobson/Karels RTO estimator with exponential backoff.
 *
 *  Tracks SRTT, RTTVAR, and the current RTO value.  On each new RTT sample
 *  the SRTT and RTTVAR are updated via EWMA, and RTO = SRTT + 4 * RTTVAR.
 *  When backoff is triggered (e.g. timeout retransmission), the RTO is
 *  multiplied by the backoff factor up to a configured maximum.
 */
class UcpRtoEstimator {
public:
    UcpRtoEstimator();                                          // Default constructor — delegates to config-based constructor with a default UcpConfiguration

    explicit UcpRtoEstimator(const UcpConfiguration& config);   // Construct with a specific configuration (min/max RTO, backoff factor)

    void Update(int64_t sample_micros);                         // Feed a new RTT measurement into the estimator (> 0 microseconds)

    void Backoff();                                              // Apply exponential backoff to the current RTO (used on timeout retransmission)

    int64_t SmoothedRttMicros()   const { return m_srtt_micros; }         // Current smoothed RTT estimate in microseconds (EWMA of recent samples)

    int64_t RttVarianceMicros()   const { return m_rttvar_micros; }       // Current RTT variance estimate in microseconds (mean deviation)

    int64_t CurrentRtoMicros()    const { return m_current_rto_micros; }  // Current effective RTO in microseconds (SRTT + 4*RTTVAR, clamped)

private:
    int64_t m_min_rto_micros;    //< Lower clamp for RTO from configuration; RTO never drops below this floor

    int64_t m_max_rto_micros;    //< Upper clamp for RTO from configuration; RTO never exceeds this ceiling

    double  m_backoff_factor;    //< Exponential backoff multiplier applied on each Backoff() call (typically 2.0)

    int64_t m_srtt_micros          = 0;  //< Smoothed round-trip time in microseconds (EWMA with α=1/8 per RFC 6298)

    int64_t m_rttvar_micros        = 0;  //< RTT variance in microseconds (mean deviation EWMA with β=1/4 per RFC 6298)

    int64_t m_current_rto_micros   = 0;  //< Current effective retransmission timeout in microseconds (SRTT + 4*RTTVAR, clamped)

}; // class UcpRtoEstimator

} // namespace ucp
