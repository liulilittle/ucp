// ============================================================================
// UcpCongestionControl — KCC 2.0 (Geodesic Congestion Control) C++ port.
//
// This is a faithful, byte-level port of the authoritative reference
// implementation linux/tcp_kcc.c (MODULE_VERSION "2.0") into the UCP
// userspace protocol stack. Every constant, state variable, and formula
// below mirrors the C source of truth (linux/tcp_kcc.c, authoritative).
//
// Design overview (KCC 2.0):
//   - 3-mode finite state machine: STARTUP -> DRAIN -> PROBE_BW.
//     There is NO PROBE_RTT mode: min_rtt tracking is handled
//     continuously by the geodesic estimator (G1/G3) and the
//     traditional min_rtt window with sticky fast-fall semantics.
//   - Geodesic estimator (G1/G2/G3/G4): separates the RTT sample z into
//     propagation delay (T_prop), queuing delay (T_queue) and noise
//     (T_noise) using minimal-path rules:
//         G1: innovation <= 0  -> x_est = min(x_est, z)        (instant drop)
//         G2: innovation >  0  -> x_est = min(x_est + 12.2% growth, z)
//         G3: dual-threshold path-increase detection (fast 6x @ 1.10x,
//             slow 7x @ 1.05x of min_rtt) with a one-shot <5ms lock.
//         G4: BDP model RTT = min(x_est >> 10, min_rtt_us) safety floor.
//   - Bandwidth: sliding-window max (10-RTT minmax), LT-BW policer
//     detection, and the cross-connection Kalman filter (KF) floor.
//   - Pacing: bw * gain >> 8 * 990000 >> 24 (1% haircut; bw is byte-granular,
//     so no mss factor — see SetPacingRate NOTE), with
//     per-mode pacing gain cycling {1.25, 0.75, 1.0 x6}.
//   - cwnd: BDP target = ceil(bw * model_rtt * gain >> 8 >> 24) plus
//     TSO headroom, even rounding, and probe bonus; slow-start growth
//     until full_bw_reached, then min(cwnd + acked, target).
//   - The UCP protocol layer supplies higher-fidelity signals than the
//     kernel TCP stack (byte-granular delivery samples, precise loss
//     events from NAK/SACK, EDT pacing feedback, peer window reports),
//     improving estimate precision and throughput (per user requirement).
//
// Thread-safety: all public entry points must be called from the
// connection's worker thread (the SerialQueue strand). No internal
// locking is required — this mirrors the kernel softirq-only access
// model of tcp_kcc.c.
// ============================================================================

#include "ucp/ucp_cc.h"
#include <algorithm>
#include <atomic>
#include <random>

namespace ucp {

// ----------------------------------------------------------------------------
// Cross-connection KF (Kalman filter) shared state.
// Mirrors the global atomics in tcp_kcc.c (kcc_kf_x, kcc_kf_P,
// kcc_kf_active) guarded by a mutex-equivalent in the userspace port.
// ----------------------------------------------------------------------------
static std::atomic<int64_t> s_kfX{0};
static std::atomic<int64_t> s_kfP{0};
static std::atomic<bool> s_kfActive{false};
static std::mutex s_kfMutex;

// ----------------------------------------------------------------------------
// Deterministic PRNG for PROBE_BW phase randomization (flow de-sync).
// Mirrors kcc_random_below() from tcp_kcc.c.
// ----------------------------------------------------------------------------
static int64_t ucp_random_below(int64_t bound) {
    static std::mt19937_64 s_rng(std::random_device{}());
    if (bound <= 1)
        return 0;
    return static_cast<int64_t>(s_rng() % static_cast<uint64_t>(bound));
}

// ----------------------------------------------------------------------------
// Scale helpers (byte-oriented userspace equivalents of the kernel
// segment-oriented arithmetic; identical fixed-point math).
// ----------------------------------------------------------------------------
static int64_t bw_to_bytes_per_second(int64_t bw) {
    if (bw <= 0)
        return 0;
    return static_cast<int64_t>((static_cast<uint64_t>(bw) * static_cast<uint64_t>(Constants::MICROS_PER_SECOND)) >> Constants::BW_SCALE);
}

// ----------------------------------------------------------------------------
// Constructor. Seeds all KCC 2.0 per-connection state.
// ----------------------------------------------------------------------------
UcpCongestionControl::UcpCongestionControl(int64_t initialBandwidthBps, int mss, int64_t maxCwndBytes, int64_t initialCwndBytes,
                                           int64_t maxPacingRate, bool kfEnabled)
    : _bwSampleCount(0), _bwSampleCur(0), _kccMaxBw(0), _initialBandwidthBps(initialBandwidthBps), _mss(mss > 0 ? mss : 1),
      _maxCwndBytes(maxCwndBytes),
      _initialCwndBytes(initialCwndBytes > 0 ? initialCwndBytes : static_cast<int64_t>(Constants::CWND_MIN_TARGET) * _mss),
      _maxPacingRate(maxPacingRate), _kccMode(static_cast<uint32_t>(Constants::KCC_MODE_STARTUP)), _kccMinRttUs(Constants::MIN_RTT_UNINIT),
      _kccMinRttStampUs(0), _kccRttCnt(0), _kccNextRttDelivered(0), _kccCycleMstampUs(0), _kccRoundStart(0), _kccIdleRestart(0),
      _kccPacketConservation(0), _kccLtIsSampling(0), _kccLtRttCnt(0), _kccMinRttFastFallCnt(0), _kccCycleIdx(0), _kccFullBwReached(0),
      _kccFullBwCnt(0), _kccHasSeenRtt(0), _kccLtUseBw(0), _kccPacingGain(static_cast<uint32_t>(Constants::KCC_HIGH_GAIN)),
      _kccCwndGain(static_cast<uint32_t>(Constants::KCC_HIGH_GAIN)), _kccLocked(0), _kccConfirmCnt(0), _kccConfirmSlowCnt(0),
      _kccCaState(Constants::CA_OPEN), _kccPrevCaState(Constants::CA_OPEN), _kccPriorCwnd(0),
      _kccFullBw(0), _kccLtBw(0), _kccLtLastDelivered(0), _kccLtLastStampUs(0), _kccLtLastLost(0), _kccXEst(0),
      _kccPEst(Constants::KCC_P_EST_INIT), _kccQdelayAvg(0), _kccSampleCnt(0), _kccJitterEwma(0), _kccMrUpdateRttCnt(0), _kccSrttUs(0),
      _kccEcnEwma(0), _kccEcnCeMarks(0), _kccLastDeliveredCe(0), _kccAckEpochMstampUs(0), _kccAckEpochAcked(0), _kccExtraAckedWinRtts(0),
      _kccExtraAckedWinIdx(0), _kccRoundRttMin(0xFFFFFFFFU), _kccPrevRoundRttMin(0xFFFFFFFFU), _kccDrainEnterStampUs(0), _lastAckUs(0),
      _prevAckUs(0), _prevDelivered(0), _totalDelivered(0), _totalLost(0), _flightBytes(0), _currSampleLosses(false), _ackLosses(0),
      _isAppLimited(false), _kfEnabled(kfEnabled), _congestionWindowBytes(_initialCwndBytes), _estimatedLossPercent(0.0),
      _pacingRateBytesPerSecond((initialBandwidthBps * Constants::KCC_HIGH_GAIN) / Constants::BBR_UNIT), _pacingWstampUs(0),
      _pacingNowUsEdt(0), _peerWindowBytes(0) {
    _kccExtraAcked[0] = 0;
    _kccExtraAcked[1] = 0;

    // Clamp the initial pacing rate to the configured ceiling.
    if (_maxPacingRate > 0 && _pacingRateBytesPerSecond > _maxPacingRate) {
        _pacingRateBytesPerSecond = _maxPacingRate;
    }

    // Precompute the 256-slot gain table (8-phase cycle repeated).
    for (int i = 0; i < Constants::GAIN_SLOTS; i++) {
        int phase = i % Constants::KCC_PROBE_BW_CYCLE_LEN;
        int num, den;
        if (phase == 0) {
            num = Constants::GAIN_PROBE_PHASE_NUM;
            den = Constants::GAIN_PROBE_PHASE_DEN;
        } else if (phase == 1) {
            num = Constants::GAIN_DRAIN_PHASE_NUM;
            den = Constants::GAIN_DRAIN_PHASE_DEN;
        } else {
            num = Constants::GAIN_CRUISE_PHASE_NUM;
            den = Constants::GAIN_CRUISE_PHASE_DEN;
        }
        uint64_t val = (static_cast<uint64_t>(Constants::BBR_UNIT) * num) / den;
        _cycleGainTable[i] = static_cast<uint32_t>(val > Constants::KCC_GAIN_MAX ? Constants::KCC_GAIN_MAX : val);
    }

    // Seed initial bandwidth: use the configured estimate as the
    // sliding-window max until the first ACK-delivered sample arrives.
    int64_t initBw = _initialBandwidthBps > 0
                         ? (static_cast<int64_t>(_initialBandwidthBps) << Constants::BW_SCALE) / Constants::MICROS_PER_SECOND
                         : Constants::BW_UNIT;
    if (initBw <= 0)
        initBw = Constants::BW_UNIT;
    BwUpdate(initBw, 0);
    _kccMaxBw = BwMax();

    // KF fast-start: if the cross-connection filter has history, seed
    // the initial cwnd from the discounted fair-share bandwidth
    // (mirrors kcc_init / kcc_kf_get_init_bw; peer window acts as the
    // flow-control send cap per the UCP requirement — the fixed 10-packet
    // initial cwnd is NOT an upper bound on the first send).
    if (_kfEnabled) {
        int64_t kfInitBw = KfGetInitBw(static_cast<int64_t>(_congestionWindowBytes / _mss),
                                       static_cast<int64_t>(_kccSrttUs >> Constants::KCC_SRTT_SHIFT), _mss);
        if (kfInitBw > 0) {
            if (kfInitBw > INT32_MAX)
                kfInitBw = INT32_MAX;
            BwUpdate(kfInitBw, _kccRttCnt);
            _kccMaxBw = BwMax();
            _pacingRateBytesPerSecond = (kfInitBw * Constants::MICROS_PER_SECOND) >> Constants::BW_SCALE;
            // The KF-initialised pacing must still respect the configured ceiling.
            if (_maxPacingRate > 0 && _pacingRateBytesPerSecond > _maxPacingRate) {
                _pacingRateBytesPerSecond = _maxPacingRate;
            }
            int64_t lo = std::max<int64_t>(_congestionWindowBytes / _mss, 1);
            int64_t initCwndSegs = Bdp(kfInitBw, Constants::BBR_UNIT) / _mss;
            int64_t peerCapSegs = Constants::KCC_KF_CWND_SEGS_MAX;
            if (_peerWindowBytes > 0) {
                peerCapSegs = std::min<int64_t>(peerCapSegs, std::max<int64_t>(1, _peerWindowBytes / _mss));
            }
            initCwndSegs = std::min(std::max(initCwndSegs, lo), peerCapSegs);
            _congestionWindowBytes = initCwndSegs * _mss;
            _kccHasSeenRtt = 1;
        }
    }
}

// ----------------------------------------------------------------------------
// SetPeerWindow — flow-control window from the peer.
//
// Per the user requirement ("sendable upper limit = peer-declared window",
// standard TCP/QUIC flow control), the peer's advertised receive window is
// the flow-control cap: the effective send window is min(cwnd, peerWindow).
// During STARTUP (before full bandwidth is reached) the cwnd is raised
// toward the peer window so the first send is not artificially limited to
// the fixed initial cwnd (10 packets); after full bandwidth, cwnd is
// BDP-driven and the peer window only ever caps it downward.
// ----------------------------------------------------------------------------
void UcpCongestionControl::SetPeerWindow(int64_t windowBytes) {
    if (windowBytes <= 0)
        return;
    int64_t mss = _mss > 0 ? _mss : 1;
    int64_t bounded = std::min(windowBytes, static_cast<int64_t>(Constants::KCC_KF_CWND_SEGS_MAX) * mss);
    if (bounded < mss)
        bounded = mss;
    _peerWindowBytes = bounded;
    if (_congestionWindowBytes > bounded) {
        _congestionWindowBytes = bounded;
    } else if (_kccMode == static_cast<uint32_t>(Constants::KCC_MODE_STARTUP) && !_kccFullBwReached) {
        _congestionWindowBytes = bounded;
    }
}

// ----------------------------------------------------------------------------
// OnAck — per-ACK pipeline entry (mirrors kcc_main).
//   1. Update the model (bw, ECN, ACK aggregation, cycle, full-bw, drain,
//      min_rtt, gains).
//   2. Apply cwnd constraints (ECN backoff).
//   3. Set pacing rate and cwnd.
// ----------------------------------------------------------------------------
void UcpCongestionControl::OnAck(int64_t nowMicros, int64_t deliveredBytes, int64_t sampleRttMicros, int64_t flightBytes) {
    _flightBytes = flightBytes;
    if (deliveredBytes < 0)
        deliveredBytes = 0;
    int64_t acked = deliveredBytes;
    int64_t rttUs = sampleRttMicros;
    _prevDelivered = _totalDelivered;
    _totalDelivered += acked;
    _prevAckUs = _lastAckUs;
    _lastAckUs = nowMicros;

    // SRTT EWMA (7/8), matching kernel tcp semantics (srtt stored shifted).
    if (rttUs > 0) {
        if (_kccSrttUs == 0) {
            _kccSrttUs = static_cast<uint32_t>(rttUs) << Constants::KCC_SRTT_SHIFT;
            if (_kccMinRttUs == Constants::MIN_RTT_UNINIT) {
                _kccMinRttUs = static_cast<uint32_t>(rttUs);
                _kccMinRttStampUs = nowMicros;
            }
        } else {
            // _kccSrttUs is stored shifted by KCC_SRTT_SHIFT (kernel tcp
            // convention, tcp_kcc.c:4661). The EWMA must blend the shifted
            // history with the shifted new sample — mixing unshifted rttUs
            // would corrupt the scale and bias all downstream reads.
            _kccSrttUs = (_kccSrttUs * 7 + (static_cast<uint32_t>(rttUs) << Constants::KCC_SRTT_SHIFT)) / 8;
        }
    }

    int64_t ackLosses = _ackLosses;
    _ackLosses = 0;
    UpdateModel(nowMicros, deliveredBytes, rttUs, acked, flightBytes);

    // Feed the cross-connection KF at PROBE_BW round starts while cruising at
    // unity pacing gain (mirrors C# OnAck, UcpCongestionControl.cs:503-508).
    // The filter only learns from clean, steady-state probing rounds; the
    // fast-start / STARTUP floor then uses the discounted fair-share estimate.
    if (_kfEnabled && _kccRoundStart && _kccMode == static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW) &&
        _kccPacingGain == static_cast<uint32_t>(Constants::BBR_UNIT) && acked > 0 && _prevAckUs > 0) {
        KfFeedSample(acked, std::max<int64_t>(1, nowMicros - _prevAckUs));
    }

    ApplyCwndConstraints();
    int64_t pacingBw = _kccMaxBw;
    if (_kccLtUseBw && _kccLtBw > 0)
        pacingBw = static_cast<int64_t>(_kccLtBw);
    SetPacingRate(pacingBw, static_cast<int>(_kccPacingGain));
    SetCwnd(pacingBw, static_cast<int>(_kccCwndGain), acked, flightBytes, ackLosses);
}

// ----------------------------------------------------------------------------
// UpdateModel — the estimation pipeline (mirrors kcc_update_model).
// Ordering is load-bearing: bandwidth before drain, cycle advance before
// gains, min_rtt before gain assignment.
// ----------------------------------------------------------------------------
void UcpCongestionControl::UpdateModel(int64_t nowMicros, int64_t delivered, int64_t rttUs, int64_t acked, int64_t flightBytes) {
    (void)acked;
    (void)flightBytes;

    // Bandwidth sample: delivered bytes per microsecond, BW_UNIT-scaled.
    int64_t intervalUs = (nowMicros - _prevAckUs);
    if (intervalUs < 0)
        intervalUs = 0;
    int64_t bw = 0;
    if (delivered > 0 && intervalUs > 0) {
        if (static_cast<uint64_t>(delivered) < (UINT64_MAX >> Constants::BW_SCALE)) {
            bw = (delivered << Constants::BW_SCALE) / intervalUs;
        }
    }
    UpdateBw(nowMicros, bw, delivered, intervalUs, _prevDelivered);

    // Fallback: keep the configured initial bandwidth until a real sample.
    if (_kccMaxBw <= 0) {
        int64_t initBw = _initialBandwidthBps > 0
                             ? (static_cast<int64_t>(_initialBandwidthBps) << Constants::BW_SCALE) / Constants::MICROS_PER_SECOND
                             : Constants::BW_UNIT;
        if (initBw <= 0)
            initBw = Constants::BW_UNIT;
        BwUpdate(initBw, _kccRttCnt);
        _kccMaxBw = BwMax();
    }

    UpdateEcnEwma(delivered, 0);
    UpdateAckAggregation(nowMicros, delivered, acked, intervalUs);
    UpdateCyclePhase();
    CheckFullBwReached();
    CheckDrain(nowMicros);
    if (rttUs > 0) {
        UpdateMinRtt(rttUs, nowMicros, delivered);
    }

    // Per-round min RTT filter.
    if (rttUs >= 0 && _kccRoundStart) {
        uint32_t r = static_cast<uint32_t>(rttUs);
        if (r < _kccRoundRttMin)
            _kccRoundRttMin = r;
    }

    // Assign gains per mode (mirrors kcc_update_gains).
    switch (_kccMode) {
    case Constants::KCC_MODE_STARTUP:
        _kccPacingGain = static_cast<uint32_t>(Constants::KCC_HIGH_GAIN);
        _kccCwndGain = static_cast<uint32_t>(Constants::KCC_HIGH_GAIN);
        break;
    case Constants::KCC_MODE_DRAIN:
        _kccPacingGain = static_cast<uint32_t>(Constants::KCC_DRAIN_GAIN);
        _kccCwndGain = static_cast<uint32_t>(Constants::KCC_HIGH_GAIN);
        break;
    case Constants::KCC_MODE_PROBE_BW:
        _kccPacingGain = _kccLtUseBw ? static_cast<uint32_t>(Constants::BBR_UNIT) : static_cast<uint32_t>(GetCyclePacingGain());
        _kccCwndGain = static_cast<uint32_t>(Constants::KCC_CWND_GAIN);
        break;
    default:
        break;
    }
}

// ----------------------------------------------------------------------------
// UpdateBw — round boundary tracking + sliding-window max bandwidth.
// Mirrors kcc_update_bw.
// ----------------------------------------------------------------------------
void UcpCongestionControl::UpdateBw(int64_t nowMicros, int64_t bw, int64_t delivered, int64_t intervalUs, int64_t priorDelivered) {
    (void)nowMicros;
    _kccRoundStart = 0;
    if (delivered < 0 || intervalUs <= 0) {
        return;
    }

    // Round boundary: prior_delivered >= next_rtt_delivered triggers a new
    // round. The per-round loss flag is cleared so a fresh round starts
    // loss-free (mirrors C# UpdateBw, UcpCongestionControl.cs:612); this gates
    // LT-BW sampling-start and the PROBE_BW cycle advance.
    if (!(priorDelivered < _kccNextRttDelivered)) {
        _kccNextRttDelivered = _totalDelivered;
        _kccRttCnt++;
        _kccRoundStart = 1;
        _kccPacketConservation = 0;
        _currSampleLosses = false;
        _kccPrevRoundRttMin = _kccRoundRttMin;
        _kccRoundRttMin = 0xFFFFFFFFU;
    }

    UpdateLtBw(nowMicros, 0);

    // Sliding-window max: only update when not app-limited or when the
    // sample is at least the current max (mirrors minmax_running_max).
    int64_t prevMax = BwMax();
    if (!_isAppLimited || bw >= prevMax) {
        BwUpdate(bw, _kccRttCnt);
        _kccMaxBw = BwMax();
    }
}

// ----------------------------------------------------------------------------
// BwUpdate / BwMax — 10-slot ring buffer sliding-window max.
// ----------------------------------------------------------------------------
void UcpCongestionControl::BwUpdate(int64_t bw, uint32_t rttCnt) {
    if (bw <= 0)
        return;
    if (_bwSampleCount == 0) {
        _bwSampleCount = 1;
        _bwSampleCur = 0;
        _bwSamples[0].val = bw;
        _bwSamples[0].rttCnt = rttCnt;
        return;
    }
    int next = (_bwSampleCur + 1) % kWinMinmaxSamples;
    _bwSamples[next].val = bw;
    _bwSamples[next].rttCnt = rttCnt;
    _bwSampleCur = next;
    if (_bwSampleCount < kWinMinmaxSamples)
        _bwSampleCount++;
}

int64_t UcpCongestionControl::BwMax() const {
    if (_bwSampleCount == 0)
        return 0;
    int64_t result = 0;
    uint32_t curRtt = _kccRttCnt;
    for (int i = 0; i < _bwSampleCount; i++) {
        if (curRtt - _bwSamples[i].rttCnt >= static_cast<uint32_t>(Constants::KCC_BW_RT_CYCLE_LEN)) {
            continue;
        }
        if (_bwSamples[i].val > result)
            result = _bwSamples[i].val;
    }
    if (result == 0 && _bwSampleCount > 0) {
        for (int i = 0; i < _bwSampleCount; i++) {
            if (_bwSamples[i].val > result)
                result = _bwSamples[i].val;
        }
    }
    return result;
}

// ----------------------------------------------------------------------------
// GeodesicUpdate — the G1/G2 estimator (mirrors kcc_update).
// See linux/tcp_kcc.c for the exact arithmetic.
// ----------------------------------------------------------------------------
void UcpCongestionControl::GeodesicUpdate(int64_t rttUs) {
    uint32_t rtt = static_cast<uint32_t>(std::max<int64_t>(rttUs, Constants::KCC_RTT_MIN_FLOOR_US));
    uint64_t z = static_cast<uint64_t>(rtt) << Constants::KCC_SCALE_SHIFT;

    if (_kccSampleCnt == 0) {
        _kccXEst = z;
        _kccPEst = static_cast<uint32_t>(Constants::KCC_P_EST_INIT);
        _kccQdelayAvg = 0;
        _kccJitterEwma = std::max<uint32_t>(rtt >> Constants::KCC_JITTER_SEED_SHIFT, 1);
        _kccSampleCnt = 1;
        return;
    }

    // Cold-start ceiling: clamp x_est to min_rtt on the second sample.
    if (_kccSampleCnt == 1 && _kccMinRttUs != Constants::MIN_RTT_UNINIT && _kccMinRttUs > 0) {
        uint64_t ceiling = static_cast<uint64_t>(_kccMinRttUs) << Constants::KCC_SCALE_SHIFT;
        if (_kccXEst > ceiling)
            _kccXEst = ceiling;
    }

    int64_t innovation = static_cast<int64_t>(z) - static_cast<int64_t>(_kccXEst);
    uint64_t absInnov = (innovation >= 0) ? static_cast<uint64_t>(innovation) : static_cast<uint64_t>(-(innovation + 1)) + 1;

    // G1: instant downward absorption (censored min).
    if (innovation <= 0) {
        _kccXEst = std::min<uint64_t>(_kccXEst, z);
    }
    // G2: bounded geometric growth capped at the observation.
    else {
        uint64_t growth = _kccXEst * Constants::KCC_G2_GROWTH_NUM / Constants::KCC_G2_GROWTH_DEN;
        uint64_t newX = _kccXEst + growth;
        if (newX < _kccXEst)
            newX = UINT64_MAX;
        _kccXEst = std::min<uint64_t>(newX, z);
    }

    // Staleness pull-back: after 128 rounds without a min_rtt update and
    // x_est within 1.10x of min_rtt, pull back to 95% and restart the window.
    if (_kccMinRttUs != Constants::MIN_RTT_UNINIT &&
        _kccRttCnt - _kccMrUpdateRttCnt >= static_cast<uint32_t>(Constants::KCC_STALENESS_RNDS)) {
        uint64_t mrScaled = static_cast<uint64_t>(_kccMinRttUs) << Constants::KCC_SCALE_SHIFT;
        if (_kccXEst <= mrScaled * Constants::KCC_G3_FAST_TH_NUM / Constants::KCC_G3_FAST_TH_DEN) {
            _kccXEst = mrScaled * Constants::KCC_PD_NOISE_GATE_NUM / Constants::KCC_PD_NOISE_GATE_DEN;
            _kccMrUpdateRttCnt = _kccRttCnt;
        }
    }

    // Jitter EWMA (7/8), capped at max(min_rtt, 500000).
    {
        uint32_t rawJitter = static_cast<uint32_t>(std::min<uint64_t>(absInnov >> Constants::KCC_SCALE_SHIFT, UINT32_MAX));
        _kccJitterEwma = (_kccSampleCnt > 1)
                             ? ((_kccJitterEwma * Constants::KCC_EWMA_JITTER_NUM + rawJitter) / Constants::KCC_EWMA_JITTER_DEN)
                             : rawJitter;
        uint32_t jitterCap = (_kccMinRttUs != Constants::MIN_RTT_UNINIT)
                                 ? std::max(_kccMinRttUs, static_cast<uint32_t>(Constants::KCC_RTT_SAMPLE_MAX_US))
                                 : static_cast<uint32_t>(Constants::KCC_RTT_SAMPLE_MAX_US);
        if (_kccJitterEwma > jitterCap)
            _kccJitterEwma = jitterCap;
    }

    // Queuing-delay EWMA (7/8): max(0, z - x_est) >> 10.
    {
        uint32_t qdelayInstant = (z > _kccXEst) ? static_cast<uint32_t>((z - _kccXEst) >> Constants::KCC_SCALE_SHIFT) : 0;
        if (_kccSampleCnt == 1) {
            _kccQdelayAvg = qdelayInstant;
        } else {
            _kccQdelayAvg = static_cast<uint32_t>((static_cast<uint64_t>(_kccQdelayAvg) * Constants::KCC_EWMA_QDELAY_NUM + qdelayInstant) /
                                                  Constants::KCC_EWMA_QDELAY_DEN);
        }
    }

    if (_kccSampleCnt < UINT32_MAX)
        _kccSampleCnt++;

    // Convergence proxy p_est: decay toward floor when x_est is at/below
    // 1.05x min_rtt; growth toward init when above 1.10x min_rtt.
    if (_kccSampleCnt >= static_cast<uint32_t>(Constants::KCC_MIN_SAMPLES)) {
        uint32_t pFloor = static_cast<uint32_t>(Constants::KCC_P_EST_FLOOR);
        uint64_t xEstUs = _kccXEst >> Constants::KCC_SCALE_SHIFT;
        if (xEstUs <= static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_G3_SLOW_TH_NUM / Constants::KCC_G3_SLOW_TH_DEN &&
            !_kccConfirmCnt && !_kccConfirmSlowCnt) {
            uint32_t delta = _kccPEst > pFloor ? (_kccPEst - pFloor) >> Constants::KCC_P_EST_DECAY_SHIFT : 0;
            if (_kccPEst > pFloor + delta)
                _kccPEst -= (std::max)(delta, 1U);
        } else if (xEstUs > static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_G3_FAST_TH_NUM / Constants::KCC_G3_FAST_TH_DEN) {
            uint32_t delta = _kccPEst < static_cast<uint32_t>(Constants::KCC_P_EST_INIT)
                                 ? (static_cast<uint32_t>(Constants::KCC_P_EST_INIT) - _kccPEst) >> Constants::KCC_P_EST_GROWTH_SHIFT
                                 : 0;
            if (_kccPEst + delta < static_cast<uint32_t>(Constants::KCC_P_EST_MAX))
                _kccPEst += (std::max)(delta, 1U);
        }
    }
}

// ----------------------------------------------------------------------------
// UpdateMinRtt — min_rtt maintenance with G3 detection, lock, sticky
// fast-fall, SRTT guard and geodesic takeover (mirrors kcc_update_min_rtt).
// ----------------------------------------------------------------------------
void UcpCongestionControl::UpdateMinRtt(int64_t rttUs, int64_t nowMicros, int64_t delivered) {
    if (rttUs <= 0)
        return;
    bool minFallCntIncrThisAck = false;
    uint32_t rtt = static_cast<uint32_t>(rttUs);
    uint32_t mrSnapshot = _kccMinRttUs;

    GeodesicUpdate(rttUs);

    // One-shot lock: any sample below 5ms proves a fiber path where G3
    // step detection is physically impossible; lock forever.
    if (rtt < static_cast<uint32_t>(Constants::KCC_LOCK_THRESH_US)) {
        _kccLocked = 1;
    }

    // G3 dual-threshold consecutive-event detection.
    if (!_kccLocked && _kccMinRttUs >= static_cast<uint32_t>(Constants::KCC_FAST_ONLY_THRESH_US)) {
        if (_kccXEst >=
            static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_SCALE * Constants::KCC_G3_FAST_TH_NUM / Constants::KCC_G3_FAST_TH_DEN) {
            if (_kccConfirmCnt < Constants::KCC_BITFIELD_3BIT_MAX)
                _kccConfirmCnt++;
        } else {
            _kccConfirmCnt = 0;
        }
        if (_kccXEst >=
            static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_SCALE * Constants::KCC_G3_SLOW_TH_NUM / Constants::KCC_G3_SLOW_TH_DEN) {
            if (_kccConfirmSlowCnt < Constants::KCC_BITFIELD_3BIT_MAX)
                _kccConfirmSlowCnt++;
        } else {
            _kccConfirmSlowCnt = 0;
        }
    } else if (!_kccLocked && _kccMinRttUs >= static_cast<uint32_t>(Constants::KCC_LOCK_THRESH_US)) {
        // Gray zone (5ms..7.5ms): fast-only.
        if (_kccXEst >=
            static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_SCALE * Constants::KCC_G3_FAST_TH_NUM / Constants::KCC_G3_FAST_TH_DEN) {
            if (_kccConfirmCnt < Constants::KCC_BITFIELD_3BIT_MAX)
                _kccConfirmCnt++;
        } else {
            _kccConfirmCnt = 0;
        }
        _kccConfirmSlowCnt = 0;
    } else {
        _kccConfirmCnt = 0;
        _kccConfirmSlowCnt = 0;
    }

    // Baseline return: x_est at/below min_rtt resets both counters.
    if (_kccXEst <= static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_SCALE) {
        _kccConfirmCnt = 0;
        _kccConfirmSlowCnt = 0;
    }

    // Fast path confirmed (6 consecutive).
    if (_kccConfirmCnt >= static_cast<uint32_t>(Constants::KCC_G3_FAST_CNT)) {
        _kccMinRttUs = static_cast<uint32_t>(_kccXEst >> Constants::KCC_SCALE_SHIFT);
        _kccMinRttStampUs = nowMicros;
        _kccConfirmCnt = 0;
        _kccConfirmSlowCnt = 0;
        _kccPEst = static_cast<uint32_t>(Constants::KCC_P_EST_INIT);
        _kccMrUpdateRttCnt = _kccRttCnt;
    }
    // Slow path confirmed (7 consecutive).
    else if (_kccConfirmSlowCnt >= static_cast<uint32_t>(Constants::KCC_G3_SLOW_CNT)) {
        _kccMinRttUs = static_cast<uint32_t>(_kccXEst >> Constants::KCC_SCALE_SHIFT);
        _kccMinRttStampUs = nowMicros;
        _kccConfirmCnt = 0;
        _kccConfirmSlowCnt = 0;
        _kccPEst = static_cast<uint32_t>(Constants::KCC_P_EST_INIT);
        _kccMrUpdateRttCnt = _kccRttCnt;
    }

    // While any G3 counter is non-zero, freeze the traditional min_rtt
    // manipulation to protect the threshold baseline.
    if (_kccConfirmCnt > 0 || _kccConfirmSlowCnt > 0) {
        return;
    }

    // Traditional min_rtt: fast fall (/4), sticky fall (75%), direct.
    if (rtt <= _kccMinRttUs) {
        rtt = std::max(rtt, static_cast<uint32_t>(Constants::KCC_RTT_MIN_FLOOR_US));
        if (rtt < static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_MINRTT_STICKY_NUM / Constants::KCC_MINRTT_STICKY_DEN) {
            if (rtt < _kccMinRttUs / static_cast<uint32_t>(Constants::KCC_MINRTT_FAST_FALL_DIV)) {
                _kccMinRttUs = rtt;
                _kccMinRttFastFallCnt = 0;
            } else {
                _kccMinRttFastFallCnt = std::min<uint32_t>(_kccMinRttFastFallCnt + 1, Constants::KCC_BITFIELD_3BIT_MAX);
                minFallCntIncrThisAck = true;
                if (_kccMinRttFastFallCnt >= static_cast<uint32_t>(Constants::KCC_MINRTT_FAST_FALL_CNT)) {
                    _kccMinRttUs = rtt;
                    _kccMinRttFastFallCnt = 0;
                } else if (_kccRoundStart) {
                    _kccMinRttUs = std::max<uint32_t>(Constants::KCC_RTT_MIN_FLOOR_US, static_cast<uint64_t>(_kccMinRttUs) *
                                                                                           Constants::KCC_MINRTT_STICKY_NUM /
                                                                                           Constants::KCC_MINRTT_STICKY_DEN);
                }
            }
        } else {
            _kccMinRttUs = rtt;
            _kccMinRttFastFallCnt = 0;
        }
        _kccMinRttStampUs = nowMicros;
    } else if (rtt >= _kccMinRttUs) {
        _kccMinRttFastFallCnt = 0;
    }

    // SRTT guard: if SRTT < min_rtt * 90/100, override min_rtt.
    if (_kccSrttUs && _kccMinRttUs) {
        uint32_t srttShifted = std::max<uint32_t>(_kccSrttUs >> Constants::KCC_SRTT_SHIFT, 1);
        if (srttShifted <
            static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_MINRTT_SRTT_GUARD_NUM / Constants::KCC_MINRTT_SRTT_GUARD_DEN) {
            _kccMinRttUs = srttShifted;
            _kccMinRttStampUs = nowMicros;
        }
    }

    if (delivered > 0) {
        _kccIdleRestart = 0;
    }

    // Geodesic takeover: x_est reliably below min_rtt (95% gate) pulls
    // min_rtt down using the same fast-fall accumulator.
    if (_kccXEst && _kccSampleCnt >= static_cast<uint32_t>(Constants::KCC_MIN_SAMPLES)) {
        uint32_t krtt = static_cast<uint32_t>(_kccXEst >> Constants::KCC_SCALE_SHIFT);
        if (krtt < _kccMinRttUs && krtt < _kccMinRttUs * Constants::KCC_PD_NOISE_GATE_NUM / Constants::KCC_PD_NOISE_GATE_DEN) {
            if (!minFallCntIncrThisAck) {
                _kccMinRttFastFallCnt = std::min<uint32_t>(_kccMinRttFastFallCnt + 1, Constants::KCC_BITFIELD_3BIT_MAX);
                if (_kccMinRttFastFallCnt >= static_cast<uint32_t>(Constants::KCC_MINRTT_FAST_FALL_CNT)) {
                    _kccMinRttUs = krtt;
                    _kccMinRttFastFallCnt = 0;
                    _kccMinRttStampUs = nowMicros;
                    _kccMrUpdateRttCnt = _kccRttCnt;
                }
            }
        } else {
            _kccMinRttFastFallCnt = 0;
        }
    }

    if (_kccMinRttUs != mrSnapshot) {
        _kccMrUpdateRttCnt = _kccRttCnt;
    }
}

// ----------------------------------------------------------------------------
// SetPacingRate — pacing rate = bw * gain >> 8 * 990000 >> 24,
// with a 1% conservative haircut folded into a single multiply (matches
// kcc_rate_bytes_per_sec exactly; bw is byte-granular, no mss factor).
// Monotonic in STARTUP, always after.
// ----------------------------------------------------------------------------
void UcpCongestionControl::SetPacingRate(int64_t bw, int gain) {
    if (bw <= 0)
        bw = Constants::BW_UNIT;
    // NOTE: In the kernel reference, bw is segment-granular (delivered counts
    // packets) so kcc_rate_bytes_per_sec multiplies by mss to obtain bytes.
    // In this userspace port, bw is already byte-granular (deliveredBytes),
    // so the mss multiplication must NOT be applied here. The single-step
    // *990000>>24 folds the 1% conservative haircut (tcp_kcc.c:3564-3565).
    int64_t rate = static_cast<int64_t>((static_cast<uint64_t>(bw) * static_cast<uint64_t>(gain)) >> Constants::BBR_SCALE);
    rate = static_cast<int64_t>((static_cast<uint64_t>(rate) * 990000ULL) >> Constants::BW_SCALE);
    if (_maxPacingRate > 0 && rate > _maxPacingRate)
        rate = _maxPacingRate;

    // Boot-rate lift on first RTT: high_gain * cwnd / RTT.
    // bdpBw here is segment-granular (cwndSegs), so mss converts to bytes/sec.
    if (!_kccHasSeenRtt && _kccSrttUs > 0) {
        _kccHasSeenRtt = 1;
        int64_t rttUs = std::max<int64_t>(static_cast<int64_t>(_kccSrttUs >> Constants::KCC_SRTT_SHIFT), 1);
        int64_t cwndSegs = _congestionWindowBytes / _mss;
        int64_t bdpBw = (cwndSegs * static_cast<int64_t>(Constants::BW_UNIT)) / rttUs;
        int64_t bootRate = static_cast<int64_t>((static_cast<uint64_t>(bdpBw) * static_cast<uint64_t>(_mss)) >> 0);
        bootRate = static_cast<int64_t>((static_cast<uint64_t>(bootRate) * static_cast<uint64_t>(Constants::STARTUP_HIGH_GAIN)) >>
                                        Constants::BBR_SCALE);
        bootRate = static_cast<int64_t>((static_cast<uint64_t>(bootRate) * 990000ULL) >> Constants::BW_SCALE);
        // The lifted boot rate must still respect the configured pacing ceiling.
        if (_maxPacingRate > 0 && bootRate > _maxPacingRate)
            bootRate = _maxPacingRate;
        if (bootRate > rate)
            rate = bootRate;
    }

    // KF floor in STARTUP: never pace below 50% of the KF fair-share.
    // kfBw is byte-granular (from the cross-connection KF), so no mss factor.
    if (_kfEnabled && !_kccFullBwReached && _kccMode == static_cast<uint32_t>(Constants::KCC_MODE_STARTUP)) {
        int64_t kfBw = s_kfX.load(std::memory_order_acquire);
        if (kfBw > 0) {
            int64_t initBw = kfBw * Constants::KF_DISCOUNT_NUM / Constants::KF_DISCOUNT_DEN;
            initBw = (initBw << Constants::BBR_SCALE) / Constants::KCC_HIGH_GAIN;
            int64_t kfRate = static_cast<int64_t>((static_cast<uint64_t>(initBw) * 990000ULL) >> Constants::BW_SCALE);
            if (kfRate > rate)
                rate = kfRate;
        }
    }

    if (_kccFullBwReached) {
        _pacingRateBytesPerSecond = rate;
    } else if (rate > _pacingRateBytesPerSecond) {
        _pacingRateBytesPerSecond = rate;
    }
}

// ----------------------------------------------------------------------------
// SetCwnd — cwnd update per kcc_set_cwnd: loss deduction, recovery
// conservation, BDP target, slow-start growth, floor at 4 segments.
// ----------------------------------------------------------------------------
void UcpCongestionControl::SetCwnd(int64_t bw, int gain, int64_t acked, int64_t flightBytes, int64_t losses) {
    int64_t cwnd = _congestionWindowBytes;
    int caState = static_cast<int>(_kccCaState);
    if (acked <= 0) {
        goto done_cwnd;
    }

    // Loss deduction (mirrors kcc_set_cwnd_to_recover_or_restore).
    if (losses > 0) {
        if (cwnd > losses) {
            cwnd -= losses;
        } else {
            cwnd = Constants::KCC_CWND_ABSOLUTE_MIN * _mss;
        }
    }

    {
        if (caState == Constants::CA_RECOVERY && _kccPrevCaState != Constants::CA_RECOVERY) {
            _kccPacketConservation = 1;
            cwnd = flightBytes + acked;
            _kccNextRttDelivered = _totalDelivered;
            _kccPrevCaState = static_cast<uint32_t>(caState);
        } else if (_kccPrevCaState >= static_cast<uint32_t>(Constants::CA_RECOVERY) && caState < Constants::CA_RECOVERY) {
            cwnd = std::max(cwnd, static_cast<int64_t>(_kccPriorCwnd));
            _kccPacketConservation = 0;
            _kccPrevCaState = static_cast<uint32_t>(caState);
        }
    }

    if (_kccPacketConservation) {
        cwnd = std::max(cwnd, flightBytes + acked);
        // Exit recovery once the conservation constraint is met: a forward
        // ACK that acknowledges everything that was in flight
        // (flightBytes + acked <= cwnd) proves the recovery window has
        // drained. The kernel reference exits TCP_CA_Recovery via the TCP
        // state machine; UCP's PCB does not drive CA state, so the CC must
        // self-exit here or cwnd stays pinned at flight size forever
        // (throughput collapse under sustained loss).
        if (acked > 0 && flightBytes + acked <= cwnd) {
            _kccPacketConservation = 0;
            _kccPrevCaState = static_cast<uint32_t>(Constants::CA_OPEN);
            _kccCaState = static_cast<uint32_t>(Constants::CA_OPEN);
            cwnd = std::max(cwnd, static_cast<int64_t>(_kccPriorCwnd));
        } else {
            goto done_cwnd;
        }
    }

    if (bw > 0) {
        int64_t target = Bdp(bw, gain);
        // ACK aggregation compensation, only when min_rtt >= 7.5ms
        // (BBRv3 single compensation; the KCC 1.0 confidence FSM layer
        // was a structural error and is removed in KCC 2.0).
        if (_kccMinRttUs >= static_cast<uint32_t>(Constants::KCC_FAST_ONLY_THRESH_US)) {
            int64_t aggBase = AckAggCwndBonus(bw);
            if (aggBase > 0) {
                target += aggBase;
            }
        }
        // TSO/GSO headroom + even rounding + probe bonus.
        target += static_cast<int64_t>(Constants::KCC_TSO_HEADROOM_MULT) * TsoSegsGoal() * _mss;
        target = (target + 1) & ~1LL;
        if (_kccMode == static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW) && _kccCycleIdx == 0) {
            target += static_cast<int64_t>(Constants::KCC_PROBE_CWND_BONUS) * _mss;
        }

        if (_kccFullBwReached) {
            cwnd = std::min(cwnd + acked, target);
        } else {
            // Slow start: grow by acked while below the BDP target, or while
            // fewer than TCP_INIT_CWND (10) packets have been delivered in
            // total (mirrors tcp_kcc.c:4050 "cwnd < target ||
            // tp->delivered < TCP_INIT_CWND"). The peer-declared window
            // (flow control) remains the send cap via SetPeerWindow and the
            // PCB send gate; this latch only guarantees initial growth.
            if (cwnd < target || (_totalDelivered / _mss) < Constants::INITIAL_CWND_PACKETS) {
                cwnd += acked;
            }
        }
    }

done_cwnd:
    if (_maxCwndBytes > 0 && cwnd > _maxCwndBytes) {
        cwnd = _maxCwndBytes;
    }
    if (!_kccPacketConservation)
        cwnd = std::max(cwnd, static_cast<int64_t>(Constants::KCC_CWND_MIN_TARGET) * _mss);
    _congestionWindowBytes = cwnd;
}

// ----------------------------------------------------------------------------
// Bdp — ceil(bw * model_rtt * gain >> 8 >> 24) with G4 geodesic model RTT.
// ----------------------------------------------------------------------------
int64_t UcpCongestionControl::Bdp(int64_t bw, int gain) {
    if (bw <= 0) {
        return _initialCwndBytes > 0 ? _initialCwndBytes : static_cast<int64_t>(Constants::KCC_CWND_MIN_TARGET) * _mss;
    }
    int64_t modelRtt = static_cast<int64_t>(GetModelRtt());
    if (modelRtt <= 0)
        return _initialCwndBytes > 0 ? _initialCwndBytes : static_cast<int64_t>(Constants::KCC_CWND_MIN_TARGET) * _mss;
    // Pre-convergence floor.
    if (modelRtt < static_cast<int64_t>(Constants::KCC_BDP_MIN_RTT_US) &&
        !(_kccSampleCnt >= static_cast<uint32_t>(Constants::KCC_MIN_SAMPLES) && _kccXEst > 0)) {
        modelRtt = static_cast<int64_t>(Constants::KCC_BDP_MIN_RTT_US);
    }
    if (modelRtt <= 0)
        modelRtt = 1;
    uint64_t w;
    if (static_cast<uint64_t>(bw) > UINT64_MAX / static_cast<uint64_t>(modelRtt)) {
        w = UINT64_MAX;
    } else {
        w = static_cast<uint64_t>(bw) * static_cast<uint64_t>(modelRtt);
    }
    if (w > UINT64_MAX / static_cast<uint64_t>(gain)) {
        w = UINT64_MAX;
    } else {
        w = w * static_cast<uint64_t>(gain);
    }
    w = w >> Constants::BBR_SCALE;
    return static_cast<int64_t>((w + static_cast<uint64_t>(Constants::BW_UNIT) - 1) >> Constants::BW_SCALE);
}

// ----------------------------------------------------------------------------
// GetModelRtt — G4 safety floor: min(x_est >> 10, min_rtt), with cold-start
// fallback to min_rtt.
// ----------------------------------------------------------------------------
uint32_t UcpCongestionControl::GetModelRtt() const {
    if (!_kccXEst || _kccSampleCnt < static_cast<uint32_t>(Constants::KCC_MIN_SAMPLES)) {
        return _kccMinRttUs == Constants::MIN_RTT_UNINIT ? static_cast<uint32_t>(Constants::KCC_DEFAULT_RTT_US) : _kccMinRttUs;
    }
    uint32_t xUs = static_cast<uint32_t>(_kccXEst >> Constants::KCC_SCALE_SHIFT);
    return std::min(xUs, _kccMinRttUs);
}

// ----------------------------------------------------------------------------
// Inflight — BDP + quantization budget (TSO headroom, even rounding,
// probe bonus in cycle phase 0).
// ----------------------------------------------------------------------------
int64_t UcpCongestionControl::Inflight(int64_t bw, int gain) {
    if (_kccMinRttUs == Constants::MIN_RTT_UNINIT)
        return 0;
    int64_t inflight = Bdp(bw, gain);
    inflight += static_cast<int64_t>(Constants::KCC_TSO_HEADROOM_MULT) * TsoSegsGoal() * _mss;
    inflight = (inflight + 1) & ~1LL;
    if (_kccMode == static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW) && _kccCycleIdx == 0) {
        inflight += static_cast<int64_t>(Constants::KCC_PROBE_CWND_BONUS) * _mss;
    }
    return inflight;
}

// ----------------------------------------------------------------------------
// PacketsInNetAtEdt — inflight projected at the EDT (earliest departure
// time), used by the cycle-phase and drain decisions.
// ----------------------------------------------------------------------------
int64_t UcpCongestionControl::PacketsInNetAtEdt(int64_t bw) const {
    int64_t nowUs = _pacingNowUsEdt > 0 ? _pacingNowUsEdt : _lastAckUs;
    int64_t wstampUs = _pacingWstampUs > 0 ? _pacingWstampUs : nowUs;
    int64_t inflightAtEdt = _flightBytes;
    if (_kccPacingGain > static_cast<uint32_t>(Constants::BBR_UNIT)) {
        inflightAtEdt += static_cast<int64_t>(TsoSegsGoal()) * _mss;
    }
    int64_t deltaUs = wstampUs - nowUs;
    if (deltaUs <= 0) {
        return inflightAtEdt;
    }
    int64_t deltaNs = deltaUs * Constants::NANOS_PER_MICRO;
    if (deltaNs <= static_cast<int64_t>(Constants::EDT_NEAR_NOW_NS)) {
        return inflightAtEdt;
    }
    int64_t intervalDelivered = 0;
    if (bw > 0) {
        intervalDelivered = (bw * deltaUs) >> Constants::BW_SCALE;
    }
    if (intervalDelivered >= inflightAtEdt) {
        return 0;
    }
    return inflightAtEdt - intervalDelivered;
}

// ----------------------------------------------------------------------------
// Cycle-phase machinery (PROBE_BW pacing gain cycling).
// ----------------------------------------------------------------------------
int UcpCongestionControl::GetCyclePacingGain() {
    return static_cast<int>(_cycleGainTable[_kccCycleIdx & (Constants::KCC_PROBE_BW_CYCLE_LEN - 1)]);
}

void UcpCongestionControl::AdvanceCyclePhase() {
    _kccCycleIdx = (_kccCycleIdx + 1) & (Constants::KCC_PROBE_BW_CYCLE_LEN - 1);
    _kccCycleMstampUs = _lastAckUs;
}

void UcpCongestionControl::UpdateCyclePhase() {
    if (_kccMode != static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW))
        return;

    bool isFullLength = (_lastAckUs - _kccCycleMstampUs) > static_cast<int64_t>(_kccMinRttUs);
    bool advance = false;
    if (_kccPacingGain == static_cast<uint32_t>(Constants::BBR_UNIT)) {
        advance = isFullLength;
    } else if (_kccPacingGain > static_cast<uint32_t>(Constants::BBR_UNIT)) {
        int64_t inflight = PacketsInNetAtEdt(_kccMaxBw);
        advance = isFullLength && (_currSampleLosses || inflight >= Inflight(_kccMaxBw, static_cast<int>(_kccPacingGain)));
    } else {
        int64_t inflight = PacketsInNetAtEdt(_kccMaxBw);
        advance = (isFullLength && inflight <= Inflight(_kccMaxBw, static_cast<int>(Constants::BBR_UNIT))) ||
                  (_lastAckUs - _kccCycleMstampUs) > static_cast<int64_t>(_kccMinRttUs) * 4;
    }
    if (advance) {
        AdvanceCyclePhase();
    }
}

// ----------------------------------------------------------------------------
// CheckFullBwReached — STARTUP exit: 3 rounds without 1.25x bw growth.
// ----------------------------------------------------------------------------
void UcpCongestionControl::CheckFullBwReached() {
    // Mirror kcc_check_full_bw_reached (tcp_kcc.c:4892-4908): while the KF
    // fair-share filter is active and we are still within the first FULL_BW_CNT
    // rounds of STARTUP, a measured bandwidth at/above the KF fair-share floor
    // must NOT advance the full-bw counter (otherwise a shared link's per-flow
    // share during ramp-up is misread as pipe-full, exiting STARTUP early).
    if (_kfEnabled && _kccRoundStart && _kccRttCnt <= static_cast<uint32_t>(Constants::KCC_FULL_BW_CNT) &&
        _kccMode == static_cast<uint32_t>(Constants::KCC_MODE_STARTUP) && s_kfActive.load(std::memory_order_acquire)) {
        int64_t kfBw = s_kfX.load(std::memory_order_acquire);
        if (kfBw > 0) {
            int64_t initFloor = kfBw * Constants::KF_DISCOUNT_NUM / Constants::KF_DISCOUNT_DEN;
            initFloor = (initFloor << Constants::BBR_SCALE) / Constants::KCC_HIGH_GAIN;
            if (BwMax() >= initFloor) {
                _kccFullBw = BwMax();
                _kccFullBwCnt = 0;
                return;
            }
        }
    }

    if (_kccFullBwReached || !_kccRoundStart || _isAppLimited) {
        return;
    }
    int64_t bwThresh = (_kccFullBw * Constants::KCC_FULL_BW_THRESH) >> Constants::BBR_SCALE;
    int64_t maxBw = BwMax();
    if (maxBw >= bwThresh) {
        _kccFullBw = maxBw;
        _kccFullBwCnt = 0;
        return;
    }
    _kccFullBwCnt++;
    _kccFullBwReached = _kccFullBwCnt >= static_cast<uint32_t>(Constants::KCC_FULL_BW_CNT);
}

// ----------------------------------------------------------------------------
// CheckDrain — enter DRAIN from STARTUP, exit to PROBE_BW when drained
// (AND gate by default: drained AND 1 RTT, or 4x min_rtt timeout).
// ----------------------------------------------------------------------------
void UcpCongestionControl::CheckDrain(int64_t nowMicros) {
    if (_kccMode == static_cast<uint32_t>(Constants::KCC_MODE_STARTUP) && _kccFullBwReached) {
        _kccMode = static_cast<uint32_t>(Constants::KCC_MODE_DRAIN);
        _kccDrainEnterStampUs = nowMicros;
    }

    if (_kccMode == static_cast<uint32_t>(Constants::KCC_MODE_DRAIN)) {
        int64_t inflight = PacketsInNetAtEdt(_kccMaxBw);
        int64_t bdp = Inflight(_kccMaxBw, static_cast<int>(Constants::BBR_UNIT));
        int64_t drainElapsed = nowMicros - _kccDrainEnterStampUs;
        int64_t minRtt = (_kccMinRttUs == Constants::MIN_RTT_UNINIT) ? static_cast<int64_t>(Constants::KCC_DEFAULT_RTT_US)
                                                                     : static_cast<int64_t>(_kccMinRttUs);
        bool drained = inflight <= bdp;
        bool timeout = drainElapsed > minRtt * 4;
        bool oneRtt = drainElapsed > minRtt;
        bool exit = false;
        if constexpr (Constants::DRAIN_AND_OR_MODE != 0) {
            exit = (drained && oneRtt) || timeout;
        } else {
            exit = drained || timeout;
        }
        if (exit) {
            _kccMode = static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW);
            _kccCwndGain = static_cast<uint32_t>(Constants::KCC_CWND_GAIN);
            _kccCycleIdx = (Constants::KCC_PROBE_BW_CYCLE_LEN - 1 - ucp_random_below(Constants::KCC_PROBE_BW_CYCLE_RAND)) &
                           (Constants::KCC_PROBE_BW_CYCLE_LEN - 1);
            _kccCycleMstampUs = _lastAckUs;
            AdvanceCyclePhase();
            _kccPacingGain = static_cast<uint32_t>(GetCyclePacingGain());
        }
    }
}

// ----------------------------------------------------------------------------
// ACK aggregation measurement (dual-window sliding max, 5-RTT rotation).
// Mirrors kcc_update_ack_aggregation.
// ----------------------------------------------------------------------------
void UcpCongestionControl::UpdateAckAggregation(int64_t nowMicros, int64_t delivered, int64_t acked, int64_t intervalUs) {
    if (acked <= 0 || delivered < 0 || intervalUs <= 0)
        return;
    if (_kccRoundStart) {
        _kccExtraAckedWinRtts = std::min<uint32_t>(_kccExtraAckedWinRtts + 1, Constants::KCC_EXTRA_ACKED_WIN_RTTS_MAX);
        if (_kccExtraAckedWinRtts >= static_cast<uint32_t>(Constants::KCC_AGG_WINDOW_ROTATION_RTTS)) {
            _kccExtraAckedWinRtts = 0;
            _kccExtraAckedWinIdx = _kccExtraAckedWinIdx ? 0 : 1;
            _kccExtraAcked[_kccExtraAckedWinIdx] = 0;
        }
    }
    int64_t epochUs = (_kccAckEpochMstampUs > 0) ? nowMicros - static_cast<int64_t>(_kccAckEpochMstampUs) : 0;
    int64_t activeBw = (_kccLtUseBw && _kccLtBw > 0) ? static_cast<int64_t>(_kccLtBw) : _kccMaxBw;
    int64_t expectedAckedBytes = 0;
    if (activeBw > 0 && epochUs > 0) {
        expectedAckedBytes =
            static_cast<int64_t>((static_cast<uint64_t>(activeBw) * static_cast<uint64_t>(epochUs)) >> Constants::BW_SCALE);
    }
    if (_kccAckEpochMstampUs == 0 || _kccAckEpochAcked <= static_cast<uint32_t>(expectedAckedBytes) ||
        static_cast<uint64_t>(_kccAckEpochAcked) + static_cast<uint64_t>(acked) >= static_cast<uint64_t>(Constants::ACK_EPOCH_MAX)) {
        _kccAckEpochAcked = 0;
        _kccAckEpochMstampUs = static_cast<uint64_t>(nowMicros);
    }
    _kccAckEpochAcked =
        std::min<uint32_t>(_kccAckEpochAcked + static_cast<uint32_t>(acked), static_cast<uint32_t>(Constants::ACK_EPOCH_MAX));
    epochUs = nowMicros - static_cast<int64_t>(_kccAckEpochMstampUs);
    expectedAckedBytes = 0;
    if (activeBw > 0 && epochUs > 0) {
        expectedAckedBytes =
            static_cast<int64_t>((static_cast<uint64_t>(activeBw) * static_cast<uint64_t>(epochUs)) >> Constants::BW_SCALE);
    }
    int64_t extraAcked =
        (_kccAckEpochAcked > static_cast<uint32_t>(expectedAckedBytes)) ? static_cast<int64_t>(_kccAckEpochAcked) - expectedAckedBytes : 0;
    extraAcked = std::min<int64_t>(extraAcked, _congestionWindowBytes / _mss);
    if (extraAcked > static_cast<int64_t>(_kccExtraAcked[_kccExtraAckedWinIdx])) {
        _kccExtraAcked[_kccExtraAckedWinIdx] = static_cast<uint32_t>(extraAcked);
    }
}

// ----------------------------------------------------------------------------
// AckAggCwndBonus — gain x max(extra_acked), capped at bw x 100ms.
// Mirrors kcc_ack_aggregation_cwnd. Only applied when full_bw_reached.
// ----------------------------------------------------------------------------
int64_t UcpCongestionControl::AckAggCwndBonus(int64_t bw) const {
    if (!_kccFullBwReached)
        return 0;
    int64_t maxExtra = std::max(static_cast<int64_t>(_kccExtraAcked[0]), static_cast<int64_t>(_kccExtraAcked[1]));
    int64_t extraAckedGain = (static_cast<int64_t>(Constants::EXTRA_ACKED_GAIN_NUM) * Constants::BBR_UNIT) /
                             static_cast<int64_t>(Constants::EXTRA_ACKED_GAIN_DEN);
    int64_t bonus = (maxExtra * extraAckedGain) / Constants::BBR_UNIT;
    int64_t cap = (bw * Constants::EXTRA_ACKED_MAX_MS_RATIO * Constants::MICROS_PER_MILLI) >> Constants::BW_SCALE;
    if (bonus > cap)
        bonus = cap;
    return bonus;
}

// ----------------------------------------------------------------------------
// ECN EWMA (disabled by default, mirrors kcc_update_ecn_ewma).
// ----------------------------------------------------------------------------
void UcpCongestionControl::UpdateEcnEwma(int64_t delivered, int64_t losses) {
    (void)delivered;
    (void)losses;
#if KCC_ECN_ENABLED != 0
    if (delivered <= 0 || losses < 0)
        return;
    int64_t ceDelta = _kccEcnCeMarks - _kccLastDeliveredCe;
    _kccLastDeliveredCe = _kccEcnCeMarks;
    int64_t total = delivered + losses;
    if (ceDelta > 0) {
        uint32_t instant = static_cast<uint32_t>((static_cast<uint64_t>(ceDelta) << Constants::BBR_SCALE) / total);
        if (_kccEcnEwma == 0) {
            _kccEcnEwma = instant;
        } else {
            _kccEcnEwma = (_kccEcnEwma * Constants::KCC_ECN_EWMA_RETAINED + instant) / Constants::KCC_ECN_EWMA_TOTAL;
        }
    } else {
        if (_kccEcnEwma > 0) {
            if (_kccRoundStart) {
                _kccEcnEwma = _kccEcnEwma * Constants::KCC_ECN_EWMA_RETAINED / Constants::KCC_ECN_EWMA_TOTAL;
            } else {
                if (_kccEcnEwma < static_cast<uint32_t>(Constants::KCC_ECN_EWMA_FLOOR)) {
                    _kccEcnEwma = 0;
                } else {
                    _kccEcnEwma = static_cast<uint32_t>((static_cast<uint64_t>(_kccEcnEwma) * Constants::KCC_ECN_IDLE_DECAY_NUM) /
                                                        Constants::KCC_ECN_IDLE_DECAY_DEN);
                }
            }
        }
    }
#endif // KCC_ECN_ENABLED != 0
}

// ----------------------------------------------------------------------------
// ApplyCwndConstraints — ECN backoff (mirrors kcc_apply_cwnd_constraints).
// ----------------------------------------------------------------------------
void UcpCongestionControl::ApplyCwndConstraints() {
#if KCC_ECN_ENABLED != 0
    if (_kccSampleCnt < static_cast<uint32_t>(Constants::KCC_MIN_SAMPLES))
        return;
    if (_kccEcnEwma == 0)
        return;
    uint32_t ecnBackoff = (static_cast<uint32_t>(Constants::ECN_BACKOFF_NUM) << Constants::BBR_SCALE) / Constants::ECN_BACKOFF_DEN;
    if (!ecnBackoff)
        return;
    if (_kccPacingGain > static_cast<uint32_t>(Constants::BBR_UNIT)) {
        uint32_t ecnScale = (1U << (Constants::BBR_SCALE + Constants::BBR_SCALE)) / _kccPacingGain;
        ecnBackoff = static_cast<uint32_t>((static_cast<uint64_t>(ecnBackoff) * ecnScale) >> Constants::BBR_SCALE);
    }
    uint32_t factor = Constants::BBR_UNIT - std::min(ecnBackoff, static_cast<uint32_t>(Constants::BBR_UNIT));
    if (_kccQdelayAvg > CongThresh()) {
        _kccCwndGain = std::min<uint32_t>(_kccCwndGain,
                                          std::max<uint32_t>(Constants::KCC_GAIN_FLOOR, (_kccCwndGain * factor) >> Constants::BBR_SCALE));
    }
#endif // KCC_ECN_ENABLED != 0
}

// ----------------------------------------------------------------------------
// LT-BW (long-term bandwidth / policer detection). Mirrors
// kcc_lt_bw_sampling + kcc_lt_bw_interval_done.
// ----------------------------------------------------------------------------
void UcpCongestionControl::ResetLtBw() {
    _kccLtBw = 0;
    _kccLtUseBw = 0;
    _kccLtIsSampling = 0;
    _kccLtRttCnt = 0;
    _kccLtLastDelivered = _totalDelivered;
    _kccLtLastLost = _totalLost;
    _kccLtLastStampUs = _lastAckUs;
}

void UcpCongestionControl::UpdateLtBw(int64_t nowMicros, int64_t lossVal) {
    (void)lossVal;
    if (_kccLtUseBw) {
        if (_kccMode == static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW) && _kccRoundStart) {
            uint32_t cnt = _kccLtRttCnt + 1;
            if (cnt >= Constants::KCC_LT_RTT_CNT_MAX)
                cnt = Constants::KCC_LT_RTT_CNT_MAX;
            _kccLtRttCnt = cnt;
            if (cnt >= static_cast<uint32_t>(Constants::KCC_LT_BW_MAX_RTTS)) {
                ResetLtBw();
                _kccMode = static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW);
                _kccCycleIdx = (Constants::KCC_PROBE_BW_CYCLE_LEN - 1 - ucp_random_below(Constants::KCC_PROBE_BW_CYCLE_RAND)) &
                               (Constants::KCC_PROBE_BW_CYCLE_LEN - 1);
                _kccCycleMstampUs = _lastAckUs;
                _kccCwndGain = static_cast<uint32_t>(Constants::KCC_CWND_GAIN);
                AdvanceCyclePhase();
            }
        }
        return;
    }

    if (_kccSampleCnt < static_cast<uint32_t>(Constants::KCC_MIN_SAMPLES)) {
        return;
    }

    if (!_kccLtIsSampling) {
        if (_isAppLimited) {
            ResetLtBw();
            return;
        }
        if (!_currSampleLosses)
            return;
        _kccLtIsSampling = 1;
        _kccLtLastDelivered = _totalDelivered;
        _kccLtLastStampUs = nowMicros;
        _kccLtLastLost = _totalLost;
        _kccLtRttCnt = 0;
        return;
    }

    if (_isAppLimited) {
        ResetLtBw();
        return;
    }

    if (_kccRoundStart) {
        uint32_t cnt = _kccLtRttCnt + 1;
        if (cnt >= Constants::KCC_LT_RTT_CNT_MAX)
            cnt = Constants::KCC_LT_RTT_CNT_MAX;
        _kccLtRttCnt = cnt;
    }
    if (_kccLtRttCnt < static_cast<uint32_t>(Constants::KCC_LT_INTVL_MIN_RTTS))
        return;
    uint32_t ltTimeout = Constants::KCC_LT_INTVL_MAX_MULT * Constants::KCC_LT_INTVL_MIN_RTTS;
    if (_kccLtRttCnt > ltTimeout) {
        ResetLtBw();
        return;
    }

    int64_t delivered = _totalDelivered - _kccLtLastDelivered;
    int64_t elapsedUs = nowMicros - _kccLtLastStampUs;
    if (elapsedUs < static_cast<int64_t>(Constants::MICROS_PER_MILLI) || delivered <= 0)
        return;
    int64_t lostSince = _totalLost - _kccLtLastLost;
    if ((static_cast<uint64_t>(std::max<int64_t>(lostSince, 0)) << Constants::BBR_SCALE) <
        static_cast<uint64_t>(Constants::KCC_LT_LOSS_THRESH) * static_cast<uint64_t>(delivered)) {
        return;
    }
    int64_t intervalBw = static_cast<int64_t>((static_cast<uint64_t>(delivered) << Constants::BW_SCALE) / static_cast<uint64_t>(elapsedUs));

    if (_kccLtBw != 0) {
        int64_t diff = (intervalBw > static_cast<int64_t>(_kccLtBw)) ? intervalBw - static_cast<int64_t>(_kccLtBw)
                                                                     : static_cast<int64_t>(_kccLtBw) - intervalBw;
        int64_t ratioThresh = static_cast<int64_t>(_kccLtBw) * Constants::KCC_LT_BW_RATIO_NUM / Constants::KCC_LT_BW_RATIO_DEN;
        uint64_t rateProduct = static_cast<uint64_t>(diff);
        uint64_t rate = (rateProduct > UINT64_MAX / static_cast<uint64_t>(Constants::MICROS_PER_SECOND)
                             ? UINT64_MAX
                             : (rateProduct * static_cast<uint64_t>(Constants::MICROS_PER_SECOND))) >>
                        Constants::BW_SCALE;
        int64_t bwDiffBps = static_cast<int64_t>(rate);
        if (diff <= ratioThresh || bwDiffBps <= static_cast<int64_t>(Constants::KCC_LT_BW_DIFF)) {
            // Stability check passed (mirrors tcp_kcc.c:4120-4121): only now
            // apply the qdelay/srtt safety checks (tcp_kcc.c:4136-4144).
            if (_kccQdelayAvg > CongThresh()) {
                ResetLtBw();
                return;
            }
            if (_kccSrttUs > 0 && _kccMinRttUs != Constants::MIN_RTT_UNINIT &&
                (_kccSrttUs >> Constants::KCC_SRTT_SHIFT) > _kccMinRttUs + static_cast<uint32_t>(Constants::KCC_LT_BW_ITHRESH)) {
                ResetLtBw();
                return;
            }
            _kccLtBw =
                static_cast<uint32_t>((intervalBw * Constants::KCC_LT_BW_EMA_NUM +
                                       static_cast<int64_t>(_kccLtBw) * (Constants::KCC_LT_BW_EMA_DEN - Constants::KCC_LT_BW_EMA_NUM)) /
                                      Constants::KCC_LT_BW_EMA_DEN);
            _kccLtBw = std::max(_kccLtBw, 1U);
            _kccLtUseBw = 1;
            _kccLtRttCnt = 0;
            _kccPacingGain = static_cast<uint32_t>(Constants::BBR_UNIT);
            _kccLtLastLost = _totalLost;
            return;
        } else {
            _kccLtBw = static_cast<uint32_t>(intervalBw);
            _kccLtLastDelivered = _totalDelivered;
            _kccLtLastStampUs = nowMicros;
            _kccLtRttCnt = 0;
            _kccLtLastLost = _totalLost;
            return;
        }
    } else {
        _kccLtBw = static_cast<uint32_t>(intervalBw);
        _kccLtRttCnt = 0;
    }
    _kccLtLastDelivered = _totalDelivered;
    _kccLtLastStampUs = nowMicros;
    _kccLtLastLost = _totalLost;
    if (_kccLtRttCnt >= static_cast<uint32_t>(Constants::KCC_LT_BW_MAX_RTTS)) {
        ResetLtBw();
    }
}

// ----------------------------------------------------------------------------
// TSO helpers.
// ----------------------------------------------------------------------------
int UcpCongestionControl::MinTsoSegs() const {
    int divisor = Constants::KCC_MIN_TSO_RATE_DIV;
    if (_kccJitterEwma > static_cast<uint32_t>(Constants::KCC_TSO_HIGH_JITTER_THRESH_US)) {
        divisor = std::min(Constants::KCC_TSO_DIV_CEIL, divisor << Constants::KCC_TSO_DIV_DOUBLE_SHIFT);
    }
    int64_t tsoRateThresh = std::max<int64_t>(1, Constants::KCC_MIN_TSO_RATE / divisor);
    return (_pacingRateBytesPerSecond > 0 && _pacingRateBytesPerSecond < tsoRateThresh) ? Constants::KCC_TSO_SEGS_LOW
                                                                                        : Constants::KCC_TSO_SEGS_DEFAULT;
}

int UcpCongestionControl::TsoSegsGoal() const {
    int minSegs = MinTsoSegs();
    int64_t segs = (_mss > 0) ? ((_pacingRateBytesPerSecond >> 10) / _mss) : Constants::KCC_TSO_SEGS_DEFAULT;
    return std::min(Constants::KCC_TSO_MAX_SEGS, std::max(minSegs, static_cast<int>(segs > INT32_MAX ? INT32_MAX : segs)));
}

// ----------------------------------------------------------------------------
// Thresholds.
// ----------------------------------------------------------------------------
uint32_t UcpCongestionControl::CleanThresh() const {
    return std::max<uint32_t>(static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_QDELAY_CLEAN_BP / Constants::KCC_QDELAY_BP_BASE,
                              static_cast<uint32_t>(Constants::KCC_QDELAY_FLOOR_US));
}

uint32_t UcpCongestionControl::CongThresh() const {
    return std::max<uint32_t>(static_cast<uint64_t>(_kccMinRttUs) * Constants::KCC_QDELAY_CONG_BP / Constants::KCC_QDELAY_BP_BASE,
                              static_cast<uint32_t>(Constants::KCC_QDELAY_FLOOR_US));
}

// ----------------------------------------------------------------------------
// GetBtlBwBytesPerSecond / GetMaxBwBytesPerSecond — diagnostics.
// ----------------------------------------------------------------------------
int64_t UcpCongestionControl::GetBtlBwBytesPerSecond() const {
    return bw_to_bytes_per_second(_kccMaxBw);
}

int64_t UcpCongestionControl::GetMaxBwBytesPerSecond() const {
    return bw_to_bytes_per_second(_kccMaxBw);
}

// ----------------------------------------------------------------------------
// Loss / recovery / control event handlers.
// ----------------------------------------------------------------------------
void UcpCongestionControl::OnFecRecovery(int64_t, int64_t recoveredBytes) {
    if (recoveredBytes <= 0)
        return;
    if (_isAppLimited)
        _isAppLimited = false;
}

void UcpCongestionControl::OnNakLoss(int64_t nowMicros, int64_t lostBytes) {
    if (lostBytes <= 0)
        return;
    _totalLost += lostBytes;
    _ackLosses += lostBytes;
    _currSampleLosses = true;
    {
        int64_t roundDelivered = std::max<int64_t>(0, _totalDelivered - _prevDelivered);
        int64_t totalInRound = roundDelivered + lostBytes;
        if (totalInRound > 0) {
            double instantPct =
                static_cast<double>(Constants::PCT_BASE) * static_cast<double>(lostBytes) / static_cast<double>(totalInRound);
            _estimatedLossPercent = _estimatedLossPercent * 0.95 + instantPct * 0.05;
        } else {
            _estimatedLossPercent = _estimatedLossPercent * 0.95 + 5.0;
        }
    }
    if (_kccCaState < static_cast<uint32_t>(Constants::CA_RECOVERY)) {
        _kccPriorCwnd = static_cast<uint64_t>(_congestionWindowBytes);
    } else {
        _kccPriorCwnd = std::max(_kccPriorCwnd, static_cast<uint64_t>(_congestionWindowBytes));
    }
    SetCaState(Constants::CA_RECOVERY);
    UpdateLtBw(nowMicros, 0);
}

void UcpCongestionControl::OnPacketSent(int64_t nowMicros, bool isRetransmit) {
    (void)isRetransmit;
    _pacingNowUsEdt = nowMicros;
    _pacingWstampUs = nowMicros;
    _isAppLimited = false;
}

void UcpCongestionControl::OnFastRetransmit(int64_t nowMicros, bool isCongestionLoss, int64_t lostBytes) {
    _currSampleLosses = true;
    if (isCongestionLoss) {
        if (_kccCaState < static_cast<uint32_t>(Constants::CA_RECOVERY)) {
            _kccPriorCwnd = static_cast<uint64_t>(_congestionWindowBytes);
        }
        SetCaState(Constants::CA_RECOVERY);
    }
    // Derive the loss fraction from the lost payload relative to the bytes
    // delivered since the previous round, mirroring the C# OnFastRetransmit
    // (UcpCongestionControl.cs): deliveredSince = max(0, totalDelivered -
    // prevDelivered), lossRate = lostBytes / (deliveredSince + lostBytes).
    // Feeding the real fraction (instead of a fixed 0.0) keeps the loss-rate
    // EWMA in lockstep between C++ and C#: a fast retransmit with lostBytes > 0
    // now RAISES EstimatedLossPercent on both sides, where the old hardcoded
    // 0.0 decayed the C++ estimate toward zero.  Forward the lost-payload byte
    // count so it also reaches _totalLost and _ackLosses (mirrors C#, which
    // passes segment payload length through to OnPacketLoss).
    double lossRate = 0.0;
    if (lostBytes > 0) {
        int64_t deliveredSince = std::max<int64_t>(0, _totalDelivered - _prevDelivered);
        int64_t totalInRound = deliveredSince + lostBytes;
        if (totalInRound > 0) {
            lossRate = static_cast<double>(lostBytes) / static_cast<double>(totalInRound);
        }
    }
    OnPacketLoss(nowMicros, lossRate, isCongestionLoss, lostBytes);
    UpdateLtBw(nowMicros, 0);
}

void UcpCongestionControl::OnPacketLoss(int64_t nowMicros, double lossRate, bool isCongestionLoss, int64_t lostBytes) {
    if (nowMicros <= 0)
        return;
    if (lostBytes > 0) {
        _totalLost += lostBytes;
        _ackLosses += lostBytes;
        _currSampleLosses = true;
    }
    if (isCongestionLoss) {
        if (_kccCaState < static_cast<uint32_t>(Constants::CA_RECOVERY)) {
            _kccPriorCwnd = static_cast<uint64_t>(_congestionWindowBytes);
        }
        SetCaState(Constants::CA_RECOVERY);
    }
    {
        double fraction = lossRate;
        if (fraction <= 0.0)
            fraction = 0.0;
        if (fraction > 0.99)
            fraction = 0.99;
        _estimatedLossPercent = _estimatedLossPercent * 0.75 + fraction * 100.0 * 0.25;
    }
    UpdateLtBw(nowMicros, 0);
}

void UcpCongestionControl::OnCeMark(int64_t ceMarks) {
    if (ceMarks > 0) {
        _kccEcnCeMarks += ceMarks;
    }
}

void UcpCongestionControl::OnRto() {
    _kccCaState = static_cast<uint32_t>(Constants::CA_OPEN);
    _kccFullBw = 0;
    _kccFullBwCnt = 0;
    _kccRoundStart = 1;
    _kccPacingGain = static_cast<uint32_t>(Constants::KCC_HIGH_GAIN);
    _kccCwndGain = static_cast<uint32_t>(Constants::KCC_HIGH_GAIN);
    _congestionWindowBytes = _initialCwndBytes;
    UpdateLtBw(_lastAckUs, 0);
}

void UcpCongestionControl::OnPathChange(int64_t nowMicros) {
    (void)nowMicros;
    _kccMode = static_cast<uint32_t>(Constants::KCC_MODE_STARTUP);
    _kccMinRttUs = Constants::MIN_RTT_UNINIT;
    _kccMinRttStampUs = 0;
    _kccRttCnt = 0;
    _kccNextRttDelivered = 0;
    _kccCycleMstampUs = 0;
    _kccRoundStart = 0;
    _kccIdleRestart = 0;
    _kccPacketConservation = 0;
    _kccLtIsSampling = 0;
    _kccLtRttCnt = 0;
    _kccMinRttFastFallCnt = 0;
    _kccCycleIdx = 0;
    _kccFullBwReached = 0;
    _kccFullBwCnt = 0;
    _kccLocked = 0;
    _kccConfirmCnt = 0;
    _kccConfirmSlowCnt = 0;
    _kccHasSeenRtt = 0;
    _kccLtUseBw = 0;
    _kccPacingGain = static_cast<uint32_t>(Constants::KCC_HIGH_GAIN);
    _kccCwndGain = static_cast<uint32_t>(Constants::KCC_HIGH_GAIN);
    _kccPriorCwnd = 0;
    _kccFullBw = 0;
    _kccLtBw = 0;
    _kccLtLastDelivered = 0;
    _kccLtLastStampUs = 0;
    _kccLtLastLost = 0;
    _kccXEst = 0;
    _kccPEst = static_cast<uint32_t>(Constants::KCC_P_EST_INIT);
    _kccQdelayAvg = 0;
    _kccSampleCnt = 0;
    _kccJitterEwma = 0;
    _kccMrUpdateRttCnt = 0;
    _kccSrttUs = 0;
    _kccEcnEwma = 0;
    _kccAckEpochMstampUs = 0;
    _kccAckEpochAcked = 0;
    _kccExtraAckedWinRtts = 0;
    _kccExtraAckedWinIdx = 0;
    _kccExtraAcked[0] = 0;
    _kccExtraAcked[1] = 0;
    _kccRoundRttMin = 0xFFFFFFFFU;
    _kccPrevRoundRttMin = 0xFFFFFFFFU;
    _kccDrainEnterStampUs = 0;
    // Align with C# OnPathChange (UcpCongestionControl.cs:1943-1982): the
    // loss counters, EDT stamps, ECN marks and loss percent must be reset so
    // stale values from the old path never leak into the new path.
    _totalLost = 0;
    _currSampleLosses = false;
    _ackLosses = 0;
    _kccCaState = static_cast<uint32_t>(Constants::CA_OPEN);
    _kccPrevCaState = static_cast<uint32_t>(Constants::CA_OPEN);
    _kccEcnCeMarks = 0;
    _kccLastDeliveredCe = 0;
    _pacingWstampUs = 0;
    _pacingNowUsEdt = 0;
    _bwSampleCount = 0;
    _bwSampleCur = 0;
    int64_t initBw = _initialBandwidthBps > 0
                         ? (static_cast<int64_t>(_initialBandwidthBps) << Constants::BW_SCALE) / Constants::MICROS_PER_SECOND
                         : Constants::BW_UNIT;
    if (initBw <= 0)
        initBw = Constants::BW_UNIT;
    BwUpdate(initBw, 0);
    _kccMaxBw = BwMax();
    _congestionWindowBytes = _initialCwndBytes;
    _pacingRateBytesPerSecond =
        (_initialBandwidthBps > 0 ? _initialBandwidthBps : Constants::MICROS_PER_SECOND) * Constants::KCC_HIGH_GAIN / Constants::BBR_UNIT;
    if (_maxPacingRate > 0 && _pacingRateBytesPerSecond > _maxPacingRate) {
        _pacingRateBytesPerSecond = _maxPacingRate;
    }
    _estimatedLossPercent = 0.0;
}

void UcpCongestionControl::OnIdleRestart() {
    _kccIdleRestart = 1;
    _kccAckEpochMstampUs = 0;
    _kccAckEpochAcked = 0;
    if (_kccMode == static_cast<uint32_t>(Constants::KCC_MODE_PROBE_BW)) {
        _kccPacingGain = static_cast<uint32_t>(Constants::BBR_UNIT);
    }
}

void UcpCongestionControl::SetCaState(int state) {
    uint32_t newState = static_cast<uint32_t>(state);
    uint32_t prevState = _kccCaState;
    if (newState == prevState)
        return;
    _kccPrevCaState = prevState;
    _kccCaState = newState;
    if (newState == static_cast<uint32_t>(Constants::CA_LOSS)) {
        _kccFullBw = 0;
        _kccFullBwCnt = 0;
        _kccRoundStart = 1;
        _kccNextRttDelivered = _totalDelivered;
    }
    if (newState == static_cast<uint32_t>(Constants::CA_RECOVERY) && !_kccPacketConservation) {
        if (_kccPrevCaState < static_cast<uint32_t>(Constants::CA_RECOVERY))
            _kccPriorCwnd = static_cast<uint64_t>(_congestionWindowBytes);
        else
            _kccPriorCwnd = std::max(_kccPriorCwnd, static_cast<uint64_t>(_congestionWindowBytes));
    }
}

// ----------------------------------------------------------------------------
// KF (cross-connection Kalman filter) — mirrors kcc_kf_compute_R,
// kcc_kf_update, kcc_kf_get_init_bw.
// ----------------------------------------------------------------------------
int64_t UcpCongestionControl::KfComputeR(int64_t z, int pct) {
    int64_t r = z * pct / Constants::KCC_PCT_BASE;
    // Cap r at INT32_MAX (mirrors C# GlobalKfEstimator.KfUpdate) so that
    // r*r always fits in int64 (INT32_MAX^2 = 4.61e18 < INT64_MAX = 9.22e18).
    // A UINT32_MAX cap would let r*r overflow signed int64 for r > ~3.04e9
    // (signed-overflow UB); the kernel is safe only because it uses u64.
    if (r > static_cast<int64_t>(INT32_MAX))
        r = static_cast<int64_t>(INT32_MAX);
    // Square in uint64 to avoid any signed-overflow UB; the result still fits
    // in int64 (return type unchanged, matches callers in KfUpdate).
    return static_cast<int64_t>(static_cast<uint64_t>(r) * static_cast<uint64_t>(r));
}

int64_t UcpCongestionControl::KfUpdate(int64_t z, int rPct, bool check) {
    if (z == 0) {
        return s_kfX.load(std::memory_order_acquire);
    }
    int64_t R = KfComputeR(z, rPct);
    int64_t P, x;
    {
        std::lock_guard<std::mutex> lock(s_kfMutex);
        P = s_kfP.load(std::memory_order_relaxed);
        x = s_kfX.load(std::memory_order_relaxed);
    }
    P += (INT64_C(1) << Constants::KCC_KF_Q_SHIFT);
    if (!s_kfActive.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(s_kfMutex);
        if (!s_kfActive.load(std::memory_order_relaxed)) {
            s_kfX.store(z, std::memory_order_relaxed);
            s_kfP.store(std::max(R, INT64_C(1)), std::memory_order_relaxed);
            s_kfActive.store(true, std::memory_order_release);
            return z;
        }
        P = s_kfP.load(std::memory_order_relaxed);
        x = s_kfX.load(std::memory_order_relaxed);
        P += (INT64_C(1) << Constants::KCC_KF_Q_SHIFT);
    }

    if (check) {
        int64_t delta = z - x;
        uint64_t nu2 = (delta < 0) ? static_cast<uint64_t>(-delta) : static_cast<uint64_t>(delta);
        uint64_t S = static_cast<uint64_t>(P) + static_cast<uint64_t>(R);
        if (nu2 > Constants::KCC_INNOV_SQ_CAP)
            nu2 = Constants::KCC_INNOV_SQ_CAP;
        nu2 = (nu2 >> Constants::KCC_KF_INNOV_SHIFT) * (nu2 >> Constants::KCC_KF_INNOV_SHIFT);
        S >>= Constants::KCC_KF_VAR_SHIFT;
        if (S > 0 && nu2 * Constants::KCC_KF_CHI2_DEN > Constants::KCC_KF_CHI2_NUM * S) {
            return x;
        }
    }

    uint64_t Pcopy = static_cast<uint64_t>(P);
    uint64_t Rcopy = static_cast<uint64_t>(R);
    uint64_t xcopy = static_cast<uint64_t>(x);
    uint64_t zcopy = static_cast<uint64_t>(z);
    uint32_t shift = 0;
    {
        uint64_t maxV = Pcopy + Rcopy;
        while (maxV >= Constants::KCC_KF_OVERFLOW_GUARD) {
            Pcopy >>= 1;
            Rcopy >>= 1;
            maxV >>= 1;
            shift++;
        }
        xcopy >>= shift;
        zcopy >>= shift;
    }
    uint64_t denom = Pcopy + Rcopy;
    x = static_cast<int64_t>((xcopy * Rcopy + zcopy * Pcopy) / denom);
    P = static_cast<int64_t>(Pcopy * Rcopy / denom);
    if (shift > 0) {
        x <<= shift;
        P <<= shift;
    }
    {
        uint64_t q = UINT64_C(1) << Constants::KCC_KF_Q_SHIFT;
        if (static_cast<uint64_t>(P) < q)
            P = static_cast<int64_t>(q);
    }
    if (x > 0) {
        std::lock_guard<std::mutex> lock(s_kfMutex);
        s_kfX.store(x, std::memory_order_relaxed);
        s_kfP.store(P, std::memory_order_relaxed);
    }
    return x;
}

int64_t UcpCongestionControl::KfGetInitBw(int64_t currentCwndSegs, int64_t srttUs, int mss) {
    (void)mss;
    if (!s_kfActive.load(std::memory_order_acquire))
        return 0;
    int64_t fair = s_kfX.load(std::memory_order_acquire);
    if (fair == 0)
        return 0;
    int64_t initBw = fair * Constants::KF_DISCOUNT_NUM / Constants::KF_DISCOUNT_DEN;
    initBw = (initBw << Constants::BBR_SCALE) / Constants::KCC_PACING_INIT_GAIN;
    int64_t rttUs = std::max<int64_t>(srttUs, Constants::KCC_RTT_MIN_FLOOR_US);
    int64_t cwndFloor = (currentCwndSegs * static_cast<int64_t>(Constants::BW_UNIT)) / rttUs;
    if (initBw < cwndFloor)
        return 0;
    return std::min<int64_t>(initBw, UINT32_MAX);
}

void UcpCongestionControl::KfFeedSample(int64_t delivered, int64_t intervalUs) {
    if (delivered <= 0 || intervalUs <= 0)
        return;
    int64_t kbw = static_cast<int64_t>((static_cast<uint64_t>(delivered) << Constants::BW_SCALE) / static_cast<uint64_t>(intervalUs));
    if (!s_kfActive.load(std::memory_order_acquire)) {
        KfUpdate(kbw, Constants::KCC_KF_STARTUP_R_PCT, false);
    } else {
        KfUpdate(kbw, Constants::KCC_KF_STEADY_R_PCT, true);
    }
}

// ----------------------------------------------------------------------------
// Static member definitions.
// ----------------------------------------------------------------------------
std::atomic<int64_t> UcpCongestionControl::s_kfX{0};
std::atomic<int64_t> UcpCongestionControl::s_kfP{0};
std::atomic<bool> UcpCongestionControl::s_kfActive{false};

} // namespace ucp
