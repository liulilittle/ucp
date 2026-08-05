#include "ucp/ucp_global_kf_estimator.h"

#include <algorithm>
#include <mutex>

namespace ucp {

static std::mutex gKfLock;

GlobalKfEstimator& GlobalKfEstimator::Instance() {
    static GlobalKfEstimator instance;
    return instance;
}

void GlobalKfEstimator::UpdateBw(int64_t bw) {
    if (bw <= 0)
        return;

    globalBw_.store(bw, std::memory_order_release);
    active_.store(1, std::memory_order_release);

    int64_t peak = globalBwPeak_.load(std::memory_order_acquire);
    while (bw > peak) {
        if (globalBwPeak_.compare_exchange_weak(peak, bw, std::memory_order_release, std::memory_order_acquire)) {
            break;
        }
    }
}

void GlobalKfEstimator::KfUpdate(int64_t z, int rPct, bool check) {
    if (z == 0)
        return;

    int64_t r = z * static_cast<int64_t>(rPct) / KCC_PCT_BASE;
    if (r > INT32_MAX)
        r = INT32_MAX;
    int64_t R = r * r;

    int64_t P, x;
    {
        std::lock_guard<std::mutex> lock(gKfLock);
        P = kfP_.load(std::memory_order_acquire);
        x = kfX_.load(std::memory_order_acquire);
    }

    P += (INT64_C(1) << KCC_KF_Q_SHIFT);

    if (active_.load(std::memory_order_acquire) == 0) {
        std::lock_guard<std::mutex> lock(gKfLock);
        if (active_.load(std::memory_order_acquire) == 0) {
            kfX_.store(z, std::memory_order_release);
            kfP_.store(std::max(R, INT64_C(1)), std::memory_order_release);
            active_.store(1, std::memory_order_release);
            return;
        }
        P = kfP_.load(std::memory_order_acquire);
        x = kfX_.load(std::memory_order_acquire);
        P += (INT64_C(1) << KCC_KF_Q_SHIFT);
    }

    if (check) {
        int64_t delta = z - x;
        int64_t nu2 = delta < 0 ? -delta : delta;
        int64_t S = P + R;
        if (nu2 > KCC_INNOV_SQ_CAP)
            nu2 = KCC_INNOV_SQ_CAP;

        nu2 = (nu2 >> KCC_KF_INNOV_SHIFT) * (nu2 >> KCC_KF_INNOV_SHIFT);
        S >>= KCC_KF_VAR_SHIFT;
        if (S > 0 && nu2 * KCC_KF_CHI2_DEN > KCC_KF_CHI2_NUM * S) {
            return;
        }
    }

    int64_t Pcopy = P;
    int64_t Rcopy = R;
    int64_t xcopy = x;
    int64_t zcopy = z;
    int shift = 0;

    int64_t maxV = Pcopy + Rcopy;
    while (maxV >= KCC_KF_OVERFLOW_GUARD) {
        Pcopy >>= 1;
        Rcopy >>= 1;
        maxV >>= 1;
        shift++;
    }
    xcopy >>= shift;
    zcopy >>= shift;

    int64_t denom = Pcopy + Rcopy;
    if (denom == 0)
        denom = 1;
    x = (xcopy * Rcopy + zcopy * Pcopy) / denom;
    P = Pcopy * Rcopy / denom;
    if (shift > 0) {
        x <<= shift;
        P <<= shift;
    }

    int64_t q = INT64_C(1) << KCC_KF_Q_SHIFT;
    if (P < q)
        P = q;

    if (x > 0) {
        std::lock_guard<std::mutex> lock(gKfLock);
        kfX_.store(x, std::memory_order_release);
        kfP_.store(P, std::memory_order_release);

        int64_t oldSteady = kfXSteady_.load(std::memory_order_acquire);
        while (x > oldSteady) {
            if (kfXSteady_.compare_exchange_weak(oldSteady, x, std::memory_order_release, std::memory_order_acquire)) {
                break;
            }
        }
    }
}

void GlobalKfEstimator::KfFeedProbeBw(int64_t bw, bool firstRtt) {
    if (firstRtt) {
        KfUpdate(bw, KCC_KF_STARTUP_R_PCT, false);
    } else {
        KfUpdate(bw, KCC_KF_STEADY_R_PCT, true);
    }
}

int64_t GlobalKfEstimator::GetKfInitBw(int64_t discountNum, int64_t discountDen, int64_t cwndSegs, int64_t srttUs, int64_t rttMinFloorUs,
                                       int64_t pacingInitGain, int bbrScale, int bwScale) const {
    if (!active_.load(std::memory_order_acquire))
        return 0;

    int64_t fair = kfX_.load(std::memory_order_acquire);
    if (fair == 0)
        return 0;

    // Use only the current KF estimate, not the steady peak. The kernel only
    // applies the steady peak when kcc_kf_mode != 0 (tcp_kcc.c:5179-5184) and
    // kf_mode defaults to off; both the C# GlobalKfEstimator and the production
    // KfGetInitBw (ucp_cc.cpp:1585) use only s_kfX. kfXSteady_ is still
    // maintained by KfUpdate and Reset, but is not consulted here, matching D4.

    int64_t initBw = fair * std::max<int64_t>(discountNum, 0) / std::max<int64_t>(discountDen, 1);
    initBw = (initBw << bbrScale) / std::max<int64_t>(pacingInitGain, 1);

    int64_t srtt = std::max(srttUs, rttMinFloorUs);
    if (srtt <= 0)
        srtt = 1;
    int64_t localFloor = (cwndSegs << bwScale) / srtt;
    if (initBw < localFloor)
        return 0;

    return std::min(initBw, static_cast<int64_t>(INT32_MAX));
}

void GlobalKfEstimator::Reset() {
    globalBw_.store(0, std::memory_order_release);
    globalBwPeak_.store(0, std::memory_order_release);
    kfX_.store(0, std::memory_order_release);
    kfP_.store(0, std::memory_order_release);
    kfXSteady_.store(0, std::memory_order_release);
    active_.store(0, std::memory_order_release);
}

} // namespace ucp
