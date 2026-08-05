#pragma once

#include <atomic>
#include <cstdint>
#include <climits>
#include <mutex>
#include "ucp/ucp_constants.h"
#include "ucp/ucp_enums.h"

namespace ucp {

class UcpCongestionControl {
  public:
    UcpCongestionControl(int64_t initialBandwidthBps, int mss, int64_t maxCwndBytes, int64_t initialCwndBytes, int64_t maxPacingRate,
                         bool kfEnabled = false);
    ~UcpCongestionControl() = default;

    UcpCongestionControl(const UcpCongestionControl&) = delete;
    UcpCongestionControl& operator=(const UcpCongestionControl&) = delete;

    void OnAck(int64_t nowMicros, int64_t deliveredBytes, int64_t sampleRttMicros, int64_t flightBytes);
    void OnFecRecovery(int64_t nowMicros, int64_t recoveredBytes);
    void OnNakLoss(int64_t nowMicros, int64_t lostBytes);
    void OnPacketSent(int64_t nowMicros, bool isRetransmit);
    void OnFastRetransmit(int64_t nowMicros, bool isCongestionLoss, int64_t lostBytes = 0);
    void OnPacketLoss(int64_t nowMicros, double lossRate, bool isCongestionLoss, int64_t lostBytes = 0);
    void OnCeMark(int64_t ceMarks = 1);
    void OnRto();
    void OnPathChange(int64_t nowMicros);
    void OnIdleRestart();
    void SetCaState(int state);
    // Thread-safety: all setters below MUST be called from the connection's
    // worker thread only (single-threaded ACK processing context).
    void SetAppLimited(bool v) {
        if (_isAppLimited && !v) {
            _kccIdleRestart = 1;
            _kccAckEpochMstampUs = 0;
            _kccAckEpochAcked = 0;
        }
        _isAppLimited = v;
    }
    void SetEdtState(int64_t nowUs, int64_t wstampUs) {
        _pacingNowUsEdt = nowUs;
        _pacingWstampUs = wstampUs;
    }
    bool IsKfEnabled() const { return _kfEnabled; }
    void SetKfEnabled(bool enabled) { _kfEnabled = enabled; }
    void SetPeerWindow(int64_t windowBytes);

    UcpMode GetMode() const {
        // The internal _kccMode uses the kernel FSM numbering from tcp_kcc.c
        // (STARTUP=0, PROBE_BW=1, DRAIN=2); UcpMode uses the C#-mirror ordering
        // (Startup=0, Drain=1, ProbeBw=2). Translate so callers observe the
        // correct public mode enum.
        switch (_kccMode) {
        case Constants::KCC_MODE_PROBE_BW:
            return UcpMode::ProbeBw;
        case Constants::KCC_MODE_DRAIN:
            return UcpMode::Drain;
        default:
            return UcpMode::Startup;
        }
    }
    int64_t GetBtlBwBytesPerSecond() const;
    int64_t GetMinRttMicros() const {
        // Mirror the C# contract (UcpCongestionControl.MinRttMicros returns 0
        // before the first RTT sample): report 0 instead of leaking the
        // MIN_RTT_UNINIT sentinel (0xFFFFFFFF) into diagnostics before any
        // sample has been taken.
        return (_kccMinRttUs == Constants::MIN_RTT_UNINIT) ? 0 : static_cast<int64_t>(_kccMinRttUs);
    }
    int GetPacingGain() const { return _kccPacingGain; }
    int GetCwndGain() const { return _kccCwndGain; }
    int64_t GetPacingRateBytesPerSecond() const { return _pacingRateBytesPerSecond; }
    int64_t GetCongestionWindowBytes() const { return _congestionWindowBytes; }
    double GetEstimatedLossPercent() const { return _estimatedLossPercent; }
    int64_t GetMaxBwBytesPerSecond() const;
    bool IsFullBwReached() const { return _kccFullBwReached != 0; }

    // Test-only accessors for unit test verification.
    // KCC 2.0 renamed the RTT estimator from "Kalman" to "Geodesic"; these
    // expose the geodesic estimator state.
    int64_t GetGeodesicXEst() const { return static_cast<int64_t>(_kccXEst); }
    int64_t GetGeodesicPEst() const { return static_cast<int64_t>(_kccPEst); }
    uint32_t GetGeodesicSampleCnt() const { return _kccSampleCnt; }
    int64_t GetGeodesicQDelayAvg() const { return static_cast<int64_t>(_kccQdelayAvg); }
    int64_t GetGeodesicJitterEwma() const { return static_cast<int64_t>(_kccJitterEwma); }
    uint32_t GetEcnEwmaValue() const { return _kccEcnEwma; }
    bool IsLtUseBw() const { return _kccLtUseBw != 0; }
    int64_t GetLtBwValue() const { return static_cast<int64_t>(_kccLtBw); }
    int64_t GetTotalDelivered() const { return _totalDelivered; }
    uint32_t GetProbeBwCycleIdx() const { return _kccCycleIdx; }

    void KfFeedSample(int64_t delivered, int64_t intervalUs);

  private:
    // Global KF cross-connection bandwidth filter (shared across connections)
    static std::atomic<int64_t> s_kfX;
    static std::atomic<int64_t> s_kfP;
    static std::atomic<bool> s_kfActive;

    static int64_t KfComputeR(int64_t z, int pct);
    static int64_t KfUpdate(int64_t z, int rPct, bool check);
    static int64_t KfGetInitBw(int64_t currentCwndSegs, int64_t srttUs, int mss);

    static constexpr int kWinMinmaxSamples = Constants::KCC_BW_RT_CYCLE_LEN;

    struct UcpMinMaxSample {
        int64_t val;
        uint32_t rttCnt;
    };

    UcpMinMaxSample _bwSamples[kWinMinmaxSamples]{};
    int _bwSampleCount;
    int _bwSampleCur;
    int64_t _kccMaxBw;

    int64_t _initialBandwidthBps;
    int _mss;
    int64_t _maxCwndBytes;
    int64_t _initialCwndBytes;
    int64_t _maxPacingRate;

    uint32_t _kccMode;
    uint32_t _kccMinRttUs;
    int64_t _kccMinRttStampUs;

    uint32_t _kccRttCnt;
    int64_t _kccNextRttDelivered;
    int64_t _kccCycleMstampUs;

    uint32_t _kccRoundStart : 1;
    uint32_t _kccIdleRestart : 1;
    uint32_t _kccPacketConservation : 1;
    uint32_t _kccLtIsSampling : 1;
    uint32_t _kccLtRttCnt : 12;
    uint32_t _kccMinRttFastFallCnt : 3;
    uint32_t _kccCycleIdx : 8;

    uint32_t _kccFullBwReached : 1;
    uint32_t _kccFullBwCnt : 2;
    uint32_t _kccHasSeenRtt : 1;
    uint32_t _kccLtUseBw : 1;
    uint32_t _kccPacingGain : 10;
    uint32_t _kccCwndGain : 10;
    uint32_t _kccLocked : 1;
    uint32_t _kccConfirmCnt : 3;
    uint32_t _kccConfirmSlowCnt : 3;
    uint32_t _kccCaState;

    uint32_t _kccPrevCaState;
    uint64_t _kccPriorCwnd;
    int64_t _kccFullBw;
    uint32_t _kccLtBw;
    int64_t _kccLtLastDelivered;
    int64_t _kccLtLastStampUs;
    int64_t _kccLtLastLost;

    uint64_t _kccXEst;
    uint32_t _kccPEst;
    uint32_t _kccQdelayAvg;
    uint32_t _kccSampleCnt;
    uint32_t _kccJitterEwma;
    uint32_t _kccMrUpdateRttCnt;
    uint32_t _kccSrttUs = 0;

    uint32_t _kccEcnEwma;
    int64_t _kccEcnCeMarks;
    int64_t _kccLastDeliveredCe;

    uint64_t _kccAckEpochMstampUs;
    uint32_t _kccExtraAcked[2];
    uint32_t _kccAckEpochAcked;
    uint32_t _kccExtraAckedWinRtts;
    uint32_t _kccExtraAckedWinIdx;

    uint32_t _kccRoundRttMin;
    uint32_t _kccPrevRoundRttMin;
    int64_t _kccDrainEnterStampUs;

    int64_t _lastAckUs;
    int64_t _prevAckUs;
    int64_t _prevDelivered;
    int64_t _totalDelivered;
    int64_t _totalLost;
    int64_t _flightBytes;
    bool _currSampleLosses;
    int64_t _ackLosses;

    bool _isAppLimited;
    bool _kfEnabled = false;
    int64_t _congestionWindowBytes;
    double _estimatedLossPercent;
    int64_t _pacingRateBytesPerSecond;
    int64_t _pacingWstampUs;
    int64_t _pacingNowUsEdt;

    int64_t _peerWindowBytes = 0;

    uint32_t _cycleGainTable[Constants::GAIN_SLOTS]{};

    void BwUpdate(int64_t bw, uint32_t rttCnt);
    int64_t BwMax() const;
    int64_t PacketsInNetAtEdt(int64_t bw) const;

    void GeodesicUpdate(int64_t rttUs);
    void UpdateMinRtt(int64_t rttUs, int64_t nowMicros, int64_t delivered);
    void UpdateBw(int64_t nowMicros, int64_t bw, int64_t delivered, int64_t intervalUs, int64_t priorDelivered);
    void UpdateModel(int64_t nowMicros, int64_t delivered, int64_t rttUs, int64_t acked, int64_t flightBytes);
    void SetPacingRate(int64_t bw, int gain);
    void SetCwnd(int64_t bw, int gain, int64_t acked, int64_t flightBytes, int64_t losses);
    int64_t Bdp(int64_t bw, int gain);
    int GetCyclePacingGain();
    void CheckFullBwReached();
    void CheckDrain(int64_t nowMicros);
    void UpdateCyclePhase();
    void AdvanceCyclePhase();
    void UpdateLtBw(int64_t nowMicros, int64_t lossVal);
    void ResetLtBw();
    int64_t AckAggCwndBonus(int64_t bw) const;
    int64_t Inflight(int64_t bw, int gain);
    void UpdateEcnEwma(int64_t delivered, int64_t losses);
    void ApplyCwndConstraints();
    void UpdateAckAggregation(int64_t nowMicros, int64_t delivered, int64_t acked, int64_t intervalUs);
    uint32_t GetModelRtt() const;
    int MinTsoSegs() const;
    int TsoSegsGoal() const;
    uint32_t CleanThresh() const;
    uint32_t CongThresh() const;
};

} // namespace ucp
