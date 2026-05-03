/** @file ucp_rto_estimator.cpp
 *  @brief Jacobson/Karels RTO estimator implementation — mirrors C# Ucp.Internal.RtoEstimator.
 *
 *  Tracks SRTT and RTTVAR via EWMA and computes RTO = SRTT + 4*RTTVAR
 *  (RFC 6298).  Backoff() doubles the RTO on timeout events, capped by
 *  configured min/max bounds and a maximum backoff multiplier.
 */

#include "ucp/ucp_rto_estimator.h"                               // Self header — declares UcpRtoEstimator class

#include "ucp/ucp_constants.h"                                    // Provides RTO/RTT constants: INITIAL_RTO_MICROS, RTO_GAIN_MULTIPLIER, etc.

#include <algorithm>                                              // Provides std::max for clamping and backoff cap computation

#include <cstdlib>                                                // Provides std::llabs for computing absolute delta between SRTT and sample

namespace ucp {                                                   // UCP protocol library namespace

UcpRtoEstimator::UcpRtoEstimator()                                // Default constructor — delegates to config-based constructor
    : UcpRtoEstimator(UcpConfiguration{})                         // Forward to the parameterized constructor with a default UcpConfiguration
{
}

UcpRtoEstimator::UcpRtoEstimator(const UcpConfiguration& config)  // Construct with a specific configuration (min/max RTO, backoff factor)
    : m_min_rto_micros(config.EffectiveMinRtoMicros())            // Cache the clamped minimum RTO from configuration
    , m_max_rto_micros(config.EffectiveMaxRtoMicros())            // Cache the clamped maximum RTO from configuration
    , m_backoff_factor(config.EffectiveRetransmitBackoffFactor()) // Cache the exponential backoff factor from configuration
{
    m_current_rto_micros = std::max(m_min_rto_micros, Constants::INITIAL_RTO_MICROS); // Set initial RTO = max(minRto, 100 ms) before any RTT sample
}

void UcpRtoEstimator::Update(int64_t sample_micros) {             // Feed a new RTT measurement into the estimator
    if (sample_micros <= 0) {                                     // Reject non-positive samples to prevent estimator corruption
        return;                                                   // Silently ignore invalid input (mirrors C# behavior)
    }

    if (m_srtt_micros == 0) {                                     // No previous sample exists — this is the first valid RTT measurement
        m_srtt_micros   = sample_micros;                          // Bootstrap SRTT to the first measured sample value
        m_rttvar_micros = sample_micros / Constants::RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER; // Initialize RTTVAR = sample / 2 (per RFC 6298 section 2.2)
    } else {                                                      // Subsequent sample — apply the RFC 6298 EWMA smoothing formulas
        int64_t delta = std::llabs(m_srtt_micros - sample_micros); // Absolute prediction error for the RTT variance update

        m_rttvar_micros = ((m_rttvar_micros * Constants::RTT_VAR_PREVIOUS_WEIGHT) + delta) / Constants::RTT_VAR_DENOM; // RTTVAR = (3*RTTVAR + |delta|) / 4 (β=1/4 EWMA)

        m_srtt_micros   = ((m_srtt_micros * Constants::RTT_SMOOTHING_PREVIOUS_WEIGHT) + sample_micros) / Constants::RTT_SMOOTHING_DENOM; // SRTT = (7*SRTT + sample) / 8 (α=1/8 EWMA)
    }

    int64_t candidate = m_srtt_micros + (Constants::RTO_GAIN_MULTIPLIER * m_rttvar_micros); // Compute RTO = SRTT + 4*RTTVAR per RFC 6298

    if (candidate < m_min_rto_micros) {                           // Enforce the minimum RTO floor from configuration
        candidate = m_min_rto_micros;                             // Floor clamping — RTO must not drop below minRto
    }

    if (candidate > m_max_rto_micros) {                           // Enforce the maximum RTO ceiling from configuration
        candidate = m_max_rto_micros;                             // Ceiling clamping — RTO must not exceed maxRto
    }

    m_current_rto_micros = candidate;                             // Commit the computed and clamped RTO value for use by the retransmission timer
}

void UcpRtoEstimator::Backoff() {                                 // Apply exponential backoff on consecutive timeout events
    double backed_off = static_cast<double>(m_current_rto_micros) * m_backoff_factor; // Multiply current RTO by the exponential backoff factor (typically 2.0)

    double max_backoff = std::max(static_cast<double>(m_current_rto_micros),    // Lower-bound: at least the current RTO
                                  static_cast<double>(m_min_rto_micros * Constants::RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER)); // Or minRto*2, whichever is larger

    if (backed_off > max_backoff) {                               // Cap the backed-off value at the computed lower-bound maximum
        backed_off = max_backoff;                                 // Apply the max-backoff cap to prevent unbounded growth
    }

    if (backed_off > static_cast<double>(m_max_rto_micros)) {     // Enforce the absolute maximum RTO ceiling from configuration
        backed_off = static_cast<double>(m_max_rto_micros);       // Hard ceiling — prevents the RTO from blocking the connection indefinitely
    }

    m_current_rto_micros = static_cast<int64_t>(backed_off);      // Cast back to integral microseconds and commit the backed-off RTO value
}

} // namespace ucp
