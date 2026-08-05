/** @file ucp_rto_estimator.cpp
 *  @brief Jacobson/Karels RTO estimator implementation -- mirrors C# Ucp.Internal.RtoEstimator.
 *
 *  Tracks SRTT and RTTVAR via EWMA and computes RTO = SRTT + 4*RTTVAR
 *  (RFC 6298).  Backoff() multiplies the RTO by the configured backoff
 *  factor (default 1.2) on timeout events, floored by configured min/max
 *  bounds and a maximum backoff multiplier.
 */

#include "ucp/ucp_rto_estimator.h"

#include "ucp/ucp_constants.h"

#include <algorithm>

#include <cstdlib>

namespace ucp {

UcpRtoEstimator::UcpRtoEstimator() noexcept : UcpRtoEstimator(UcpConfiguration{}) {}

UcpRtoEstimator::UcpRtoEstimator(const UcpConfiguration& config) noexcept
    : m_min_rto_micros(config.EffectiveMinRtoMicros()), m_max_rto_micros(config.EffectiveMaxRtoMicros()),
      m_backoff_factor(config.EffectiveRetransmitBackoffFactor()) {
    m_current_rto_micros = std::max(m_min_rto_micros, Constants::INITIAL_RTO_MICROS);
}

void UcpRtoEstimator::Update(int64_t sample_micros) noexcept {
    if (0 >= sample_micros) {
        return;
    }

    if (0 == m_srtt_micros) {
        m_srtt_micros = sample_micros;
        m_rttvar_micros = sample_micros / Constants::INITIAL_RTTVAR_DIVISOR;
    } else {
        int64_t delta = std::llabs(m_srtt_micros - sample_micros);

        m_rttvar_micros = ((m_rttvar_micros * Constants::RTT_VAR_PREVIOUS_WEIGHT) + delta) / Constants::RTT_VAR_DENOM;

        m_srtt_micros = ((m_srtt_micros * Constants::RTT_SMOOTHING_PREVIOUS_WEIGHT) + sample_micros) / Constants::RTT_SMOOTHING_DENOM;
    }

    int64_t candidate = m_srtt_micros + (Constants::RTO_GAIN_MULTIPLIER * m_rttvar_micros);

    if (candidate < m_min_rto_micros) {
        candidate = m_min_rto_micros;
    }

    if (candidate > m_max_rto_micros) {
        candidate = m_max_rto_micros;
    }

    m_current_rto_micros = candidate;
}

void UcpRtoEstimator::Backoff() noexcept {
    double backed_off = static_cast<double>(m_current_rto_micros) * m_backoff_factor;

    double min_backoff = std::max(static_cast<double>(m_current_rto_micros),
                                  static_cast<double>(m_min_rto_micros * Constants::RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER));

    if (backed_off < min_backoff) {
        backed_off = min_backoff;
    }

    if (backed_off > static_cast<double>(m_max_rto_micros)) {
        backed_off = static_cast<double>(m_max_rto_micros);
    }

    m_current_rto_micros = static_cast<int64_t>(backed_off);
}

} // namespace ucp
