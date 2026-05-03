/** @file ucp_rto_estimator.cpp
 *  @brief Jacobson/Karels RTO estimator implementation — mirrors C# Ucp.Internal.RtoEstimator.
 *
 *  Tracks SRTT and RTTVAR via EWMA and computes RTO = SRTT + 4*RTTVAR
 *  (RFC 6298).  Backoff() doubles the RTO on timeout events, capped by
 *  configured min/max bounds and a maximum backoff multiplier.
 */

#include "ucp/ucp_rto_estimator.h"
#include "ucp/ucp_constants.h"

#include <algorithm>
#include <cstdlib>

namespace ucp {

UcpRtoEstimator::UcpRtoEstimator()
    : UcpRtoEstimator(UcpConfiguration{})
{
}

UcpRtoEstimator::UcpRtoEstimator(const UcpConfiguration& config)
    : m_min_rto_micros(config.EffectiveMinRtoMicros())
    , m_max_rto_micros(config.EffectiveMaxRtoMicros())
    , m_backoff_factor(config.EffectiveRetransmitBackoffFactor())
{
    // Seed the initial RTO to max(MinRto, INITIAL_RTO_MICROS)
    m_current_rto_micros = std::max(m_min_rto_micros, Constants::INITIAL_RTO_MICROS);
}

void UcpRtoEstimator::Update(int64_t sample_micros) {
    if (sample_micros <= 0) {
        return;
    }

    if (m_srtt_micros == 0) {
        // First sample: initialise SRTT = sample, RTTVAR = sample / 2
        m_srtt_micros   = sample_micros;
        m_rttvar_micros = sample_micros / Constants::RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER;
    } else {
        // RFC 6298 EWMA:  SRTT = (7/8)*SRTT + (1/8)*sample
        //                 RTTVAR = (3/4)*RTTVAR + (1/4)*|SRTT - sample|
        int64_t delta = std::llabs(m_srtt_micros - sample_micros);
        m_rttvar_micros = ((m_rttvar_micros * Constants::RTT_VAR_PREVIOUS_WEIGHT) + delta) / Constants::RTT_VAR_DENOM;
        m_srtt_micros   = ((m_srtt_micros * Constants::RTT_SMOOTHING_PREVIOUS_WEIGHT) + sample_micros) / Constants::RTT_SMOOTHING_DENOM;
    }

    // RTO = SRTT + max(G, K * RTTVAR) where K = RTO_GAIN_MULTIPLIER (4)
    int64_t candidate = m_srtt_micros + (Constants::RTO_GAIN_MULTIPLIER * m_rttvar_micros);
    if (candidate < m_min_rto_micros) {
        candidate = m_min_rto_micros;
    }
    if (candidate > m_max_rto_micros) {
        candidate = m_max_rto_micros;
    }
    m_current_rto_micros = candidate;
}

void UcpRtoEstimator::Backoff() {
    // Exponential backoff: RTO = min(RTO * backoff_factor, max(previous, min_rto * 2))
    double backed_off = static_cast<double>(m_current_rto_micros) * m_backoff_factor;
    double max_backoff = std::max(static_cast<double>(m_current_rto_micros),
                                  static_cast<double>(m_min_rto_micros * Constants::RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER));
    if (backed_off > max_backoff) {
        backed_off = max_backoff;
    }
    if (backed_off > static_cast<double>(m_max_rto_micros)) {
        backed_off = static_cast<double>(m_max_rto_micros);
    }
    m_current_rto_micros = static_cast<int64_t>(backed_off);
}

} // namespace ucp
