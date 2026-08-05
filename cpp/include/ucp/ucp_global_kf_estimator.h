#pragma once

#include <cstdint>
#include <atomic>

namespace ucp {

class GlobalKfEstimator {
  public:
    static GlobalKfEstimator& Instance();

    GlobalKfEstimator(const GlobalKfEstimator&) = delete;
    GlobalKfEstimator& operator=(const GlobalKfEstimator&) = delete;

    void UpdateBw(int64_t bw);

    void KfUpdate(int64_t z, int rPct, bool check);
    void KfFeedProbeBw(int64_t bw, bool firstRtt);
    bool KfIsActive() const { return active_.load(std::memory_order_acquire) != 0; }
    int64_t GetKfXValue() const { return kfX_.load(std::memory_order_acquire); }

    int64_t GetKfInitBw(int64_t discountNum, int64_t discountDen, int64_t cwndSegs, int64_t srttUs, int64_t rttMinFloorUs,
                        int64_t pacingInitGain, int bbrScale, int bwScale) const;

    void Reset();

  private:
    static constexpr int64_t KCC_KF_OVERFLOW_GUARD = INT64_C(1) << 31;
    static constexpr int KCC_KF_INNOV_SHIFT = 10;
    static constexpr int KCC_KF_VAR_SHIFT = 2 * KCC_KF_INNOV_SHIFT;
    static constexpr int64_t KCC_KF_CHI2_NUM = 384;
    static constexpr int64_t KCC_KF_CHI2_DEN = 100;
    static constexpr int KCC_KF_Q_SHIFT = 20;
    static constexpr int KCC_KF_STEADY_R_PCT = 5;
    static constexpr int KCC_KF_STARTUP_R_PCT = 15;
    static constexpr int64_t KCC_INNOV_SQ_CAP = 3000000000LL;
    static constexpr int KCC_PCT_BASE = 100;

    GlobalKfEstimator() = default;

    mutable std::atomic<int64_t> globalBw_{0};
    mutable std::atomic<int64_t> globalBwPeak_{0};
    mutable std::atomic<int> active_{0};
    mutable std::atomic<int64_t> kfX_{0};
    mutable std::atomic<int64_t> kfP_{0};
    mutable std::atomic<int64_t> kfXSteady_{0};
};

} // namespace ucp
