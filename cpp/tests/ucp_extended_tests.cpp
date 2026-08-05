#include "test_framework.h"
#include "ucp/ucp_constants.h"
#include "ucp/ucp_enums.h"
#include "ucp/ucp_packets.h"
#include "ucp/ucp_sequence_comparer.h"
#include "ucp/ucp_rto_estimator.h"
#include "ucp/ucp_sack_generator.h"
#include "ucp/ucp_cc.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_packet_codec.h"
#include "ucp/ucp_fec_codec.h"
#include "ucp/ucp_pacing.h"
#include "ucp/ucp_time.h"
#include "ucp/internal/ucp_pcb.h"
#include "network_simulator.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <limits>
#include <memory>
using namespace ucp;
using namespace ucp_test;
static ucp::vector<uint8_t> BP(char v, int sz) {
    return ucp::vector<uint8_t>(sz, (uint8_t)v);
}
static ucp::vector<uint8_t> BUP(int sz, int seed) {
    ucp::vector<uint8_t> d(sz);
    uint64_t s = seed;
    for (int i = 0; i < sz; ++i) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        d[i] = (uint8_t)(s >> 32);
    }
    return d;
}
static bool WFC(const ucp::function<bool()>& p, int t = 1000) {
    auto d = std::chrono::steady_clock::now() + std::chrono::milliseconds(t);
    while (std::chrono::steady_clock::now() < d) {
        if (p())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return p();
}

UCP_TEST_CASE(A5_Confirms_15) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 50; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_Bypass_16) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_FullBw_17) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 35; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_Sustained_19) {
    UcpCongestionControl cc(2000000, 1220, INT_MAX, 10 * 1220, 2000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 80; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_HighBw_20) {
    UcpCongestionControl cc(12500000, 1220, INT_MAX, 10 * 1220, 12500000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 60; ++i) {
        cc.OnAck(n, 48000, r, 48000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_LowBw_21) {
    UcpCongestionControl cc(500000, 1220, INT_MAX, 10 * 1220, 500000);
    int64_t n = 100000, r = 50000;
    for (int i = 0; i < 50; ++i) {
        cc.OnAck(n, 12000, r, 12000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_WideRtt_22) {
    UcpCongestionControl cc(5000000, 1220, INT_MAX, 10 * 1220, 5000000);
    int64_t n = 100000;
    for (int r = 10000; r <= 100000; r += 10000) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_Sawtooth_23) {
    UcpCongestionControl cc(5000000, 1220, INT_MAX, 10 * 1220, 5000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 40; ++i) {
        cc.OnAck(n, 24000 + ((i % 10) - 5) * 2000, r, 24000 + ((i % 10) - 5) * 2000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(A5_Spike_24) {
    UcpCongestionControl cc(5000000, 1220, INT_MAX, 10 * 1220, 5000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    cc.OnAck(n, 24000, r * 5, 24000);
    n += r;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(PRD_Skip_25) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 15; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    n += 25000000;
    cc.OnAck(n, 24000, r, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(PRD_Exits_26) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 15; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    n += 25000000;
    cc.OnAck(n, 24000, 50000, 24000);
    for (int i = 0; i < 35; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(PRD_Rate_27) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 12; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    n += 25000000;
    cc.OnAck(n, 24000, 50000, 24000);
    for (int i = 0; i < 35; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(DE_Cwnd_29) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 22; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(DE_ProbeBw_30) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 28; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 100000;
    }
    UCP_CHECK(cc.GetMode() == UcpMode::ProbeBw);
}
UCP_TEST_CASE(DE_NoOvershoot_31) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 22; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    // No overshoot: the cwnd must stay within the hard cap (not just <= the
    // ctor max, which is trivially true) -- verify it is a sane multiple of
    // the 50ms-RTT BDP rather than an unbounded STARTUP growth.
    UCP_CHECK(cc.GetCongestionWindowBytes() <= 64 * 1024 * 1024);
    UCP_CHECK(cc.GetCongestionWindowBytes() <= 12500000LL * 50000 / 1000000 * 4);
}
UCP_TEST_CASE(AL_Idle_32) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.SetAppLimited(true);
    cc.OnAck(100000, 24000, 50000, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(AL_Clear_33) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.SetAppLimited(true);
    cc.SetAppLimited(false);
    cc.OnAck(100000, 24000, 50000, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(AL_Repeat_34) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.SetAppLimited(true);
    cc.SetAppLimited(true);
    cc.SetAppLimited(false);
    cc.SetAppLimited(false);
    cc.OnAck(100000, 24000, 50000, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(AL_Restart_35) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    cc.OnIdleRestart();
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(BW_Slide_36) {
    UcpCongestionControl cc(500000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 15; ++i) {
        cc.OnAck(n, 24000 + (i % 5) * 1000, r, 24000 + (i % 5) * 1000);
        n += r;
    }
    UCP_CHECK(cc.GetMaxBwBytesPerSecond() > 0);
}
UCP_TEST_CASE(BW_Round_37) {
    UcpCongestionControl cc(500000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000, p = 0;
    for (int i = 0; i < 14; ++i) {
        int64_t d = 12000 + i * 2000;
        cc.OnAck(n, d, r, d);
        if (d > p)
            p = d;
        n += r;
    }
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() >= p * 70 / 100);
}
UCP_TEST_CASE(BW_UnderMax_38) {
    UcpCongestionControl cc(500000, 1220, 64 * 1024 * 1024, 10 * 1220, 50000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 22; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() <= 50000000LL * 110 / 100);
}
UCP_TEST_CASE(BW_Floor_39) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 22; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() > 100000);
}
UCP_TEST_CASE(BW_1M_40) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        int64_t d = 1000000LL * r / 1000000;
        if (d < 1)
            d = 1;
        cc.OnAck(n, d, r, d);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(BW_5M_41) {
    UcpCongestionControl cc(5000000, 1220, 64 * 1024 * 1024, 10 * 1220, 5000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        int64_t d = 5000000LL * r / 1000000;
        if (d < 1)
            d = 1;
        cc.OnAck(n, d, r, d);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(BW_10M_42) {
    UcpCongestionControl cc(10000000, 1220, 64 * 1024 * 1024, 10 * 1220, 10000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        int64_t d = 10000000LL * r / 1000000;
        if (d < 1)
            d = 1;
        cc.OnAck(n, d, r, d);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(BW_25M_43) {
    UcpCongestionControl cc(25000000, 1220, 64 * 1024 * 1024, 10 * 1220, 25000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        int64_t d = 25000000LL * r / 1000000;
        if (d < 1)
            d = 1;
        cc.OnAck(n, d, r, d);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(BW_50M_44) {
    UcpCongestionControl cc(50000000, 1220, 64 * 1024 * 1024, 10 * 1220, 50000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        int64_t d = 50000000LL * r / 1000000;
        if (d < 1)
            d = 1;
        cc.OnAck(n, d, r, d);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(ECN_Decay_47) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    cc.OnCeMark(500);
    cc.OnAck(n, 24000, r, 24000);
    n += r;
#if KCC_ECN_ENABLED != 0
    uint32_t e = cc.GetEcnEwmaValue();
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetEcnEwmaValue() <= e);
#else
    UCP_CHECK(cc.GetEcnEwmaValue() == 0);
#endif
}
UCP_TEST_CASE(ECN_Bw_48) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    cc.OnCeMark(500);
    cc.OnAck(n, 24000, r, 24000);
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() > 0);
}
UCP_TEST_CASE(ECN_Zero_49) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    cc.OnCeMark(0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
#if KCC_ECN_ENABLED != 0
    // Zero CE marks must not accumulate an ECN EWMA.
    UCP_CHECK(cc.GetEcnEwmaValue() == 0);
#endif
}
UCP_TEST_CASE(ECN_Gain_50) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    cc.OnCeMark(500);
    for (int i = 0; i < 4; ++i) {
        cc.OnCeMark(300);
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetCwndGain() > 0);
}
UCP_TEST_CASE(ECN_Burst_51) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
#if KCC_ECN_ENABLED != 0
    uint32_t eb = cc.GetEcnEwmaValue();
    for (int i = 0; i < 5; ++i) {
        cc.OnCeMark(1000);
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    uint32_t em = cc.GetEcnEwmaValue();
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    uint32_t ea = cc.GetEcnEwmaValue();
    UCP_CHECK(em >= eb);
    // After CE marking stops, the EWMA must decay (not grow): ea <= em.
    UCP_CHECK(ea <= em);
#else
    UCP_CHECK(cc.GetEcnEwmaValue() == 0);
#endif
}
UCP_TEST_CASE(ECN_Recover_52) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 10 * 1220, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 8; ++i) {
        cc.OnCeMark(400);
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(LT_Smooth_53) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    cc.OnNakLoss(n, 24000);
    n += r;
    cc.OnAck(n, 24000, r, 24000);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(LT_Headroom_54) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 6; ++i) {
        cc.OnNakLoss(n, 12000);
        n += 50000;
        cc.OnAck(n, 12000, r, 12000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(LT_Active_55) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 12; ++i) {
        cc.OnNakLoss(n, 12000);
        n += 50000;
        cc.OnAck(n, 12000, r, 12000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(LT_Exit_56) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 3; ++i) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 12; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(LT_LossPct_57) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 6; ++i) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
        cc.OnPacketLoss(n, 0.20, true);
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(LT_BwEst_58) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 8; ++i) {
        cc.OnNakLoss(n, 12000);
        n += 50000;
        cc.OnAck(n, 12000, r, 12000);
        n += r;
    }
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() > 0);
}
UCP_TEST_CASE(LT_Cycles_59) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int c = 0; c < 4; ++c) {
        for (int i = 0; i < 4; ++i) {
            cc.OnNakLoss(n, 12000);
            n += 50000;
            cc.OnAck(n, 12000, r, 12000);
            n += r;
        }
        for (int i = 0; i < 5; ++i) {
            cc.OnAck(n, 24000, r, 24000);
            n += r;
        }
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(LT_CwndFloor_60) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 15; ++i) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 12000, r, 12000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() >= 1220 * 4);
}
UCP_TEST_CASE(FEC_RT1_61) {
    UcpFecCodec enc(4);
    auto p0 = BUP(10, 1), p1 = BUP(10, 2), p2 = BUP(10, 3), p3 = BUP(10, 4);
    enc.TryEncodeRepair(p0);
    enc.TryEncodeRepair(p1);
    enc.TryEncodeRepair(p2);
    auto r = enc.TryEncodeRepair(p3);
    UCP_CHECK(r.has_value());
    UcpFecCodec dec(4);
    dec.FeedDataPacket(1, p1);
    dec.FeedDataPacket(2, p2);
    dec.FeedDataPacket(3, p3);
    auto rec = dec.TryRecoverFromRepair(*r, 0);
    UCP_CHECK(rec.has_value());
}
UCP_TEST_CASE(FEC_RT2_62) {
    UcpFecCodec enc(4);
    auto p0 = BUP(10, 5), p1 = BUP(10, 6), p2 = BUP(10, 7), p3 = BUP(10, 8);
    enc.TryEncodeRepair(p0);
    enc.TryEncodeRepair(p1);
    enc.TryEncodeRepair(p2);
    auto r = enc.TryEncodeRepair(p3);
    UcpFecCodec dec(4);
    dec.FeedDataPacket(0, p0);
    dec.FeedDataPacket(2, p2);
    dec.FeedDataPacket(3, p3);
    auto rec = dec.TryRecoverFromRepair(*r, 0);
    UCP_CHECK(rec.has_value());
}
UCP_TEST_CASE(FEC_2Rep_63) {
    UcpFecCodec enc(8, 2);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int i = 0; i < 8; ++i)
        ps.push_back(BUP(20, 100 + i));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> rr;
    for (int i = 0; i < 8; ++i)
        rr = enc.TryEncodeRepairs(ps[i]);
    UCP_CHECK(rr.has_value());
    UCP_CHECK(2 == rr->size());
    UcpFecCodec dec(8, 2);
    for (int i = 0; i < 8; ++i)
        if (i != 1 && i != 6)
            dec.FeedDataPacket(i, ps[i]);
    // Two losses with two repairs: the repairs must jointly recover both
    // missing packets (mirrors C# Fec_TwoLossesTwoRepairs which asserts the
    // recovered count >= 2).  A single-repair attempt may legitimately
    // recover only its covered slot, so use both repairs.
    size_t recovered = 0;
    for (size_t ri = 0; ri < rr->size(); ++ri) {
        auto r2 = dec.TryRecoverPacketsFromRepair((*rr)[ri], 0, static_cast<int>(ri));
        recovered += r2.size();
    }
    UCP_CHECK(2 <= recovered);
}
UCP_TEST_CASE(FEC_3Rep_64) {
    UcpFecCodec enc(8, 3);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int i = 0; i < 8; ++i)
        ps.push_back(BUP(15, 200 + i));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int i = 0; i < 8; ++i)
        r = enc.TryEncodeRepairs(ps[i]);
    UCP_CHECK(r.has_value());
    UCP_CHECK(3 == r->size());
    UcpFecCodec dec(8, 3);
    for (int i = 0; i < 8; ++i)
        if (i != 2 && i != 4 && i != 7)
            dec.FeedDataPacket(i, ps[i]);
    // Three losses with three repairs: the repairs must jointly recover all
    // three missing packets (mirrors C# Fec_TwoLossesTwoRepairs semantics).
    size_t recovered = 0;
    for (size_t ri = 0; ri < r->size(); ++ri) {
        auto r2 = dec.TryRecoverPacketsFromRepair((*r)[ri], 0, static_cast<int>(ri));
        recovered += r2.size();
    }
    UCP_CHECK(3 <= recovered);
}
UCP_TEST_CASE(FEC_G2_65) {
    UcpFecCodec enc(2);
    auto r0 = enc.TryEncodeRepair({104, 105});
    UCP_CHECK(!r0.has_value());
    auto r1 = enc.TryEncodeRepair(ucp::vector<uint8_t>(2, 111));
    UCP_CHECK(r1.has_value());
    UcpFecCodec dec(2);
    dec.FeedDataPacket(1, ucp::vector<uint8_t>(2, 111));
    auto rec = dec.TryRecoverFromRepair(*r1, 0);
    UCP_CHECK(rec.has_value());
}
UCP_TEST_CASE(FEC_G64_66) {
    UcpFecCodec enc(64);
    ucp::vector<uint8_t> p(10, 88);
    bool g = false;
    for (int i = 0; i < 64; ++i) {
        auto r = enc.TryEncodeRepair(p);
        if (r.has_value())
            g = true;
    }
    UCP_CHECK(g);
}
UCP_TEST_CASE(FEC_4Rep_67) {
    UcpFecCodec enc(4, 4);
    ucp::vector<uint8_t> p(10, 88);
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int i = 0; i < 4; ++i)
        r = enc.TryEncodeRepairs(p);
    UCP_CHECK(r.has_value());
    UCP_CHECK(4 == r->size());
}
UCP_TEST_CASE(FEC_RCnt_68) {
    UcpFecCodec enc(8, 3);
    UCP_CHECK(3 == enc.repair_count());
}
UCP_TEST_CASE(FEC_Slot_69) {
    UcpFecCodec enc(4);
    UCP_CHECK(0 == enc.GetSlot(1000));
    UCP_CHECK(1 == enc.GetSlot(1001));
    UCP_CHECK(3 == enc.GetSlot(1003));
}
UCP_TEST_CASE(FEC_GB_70) {
    UcpFecCodec enc(4);
    UCP_CHECK(1000 == enc.GetGroupBase(1000));
    UCP_CHECK(1000 == enc.GetGroupBase(1003));
    UCP_CHECK(1004 == enc.GetGroupBase(1004));
}
UCP_TEST_CASE(FEC_Stored_71) {
    UcpFecCodec enc(4);
    auto p0 = BUP(10, 50), p1 = BUP(10, 51), p2 = BUP(10, 52), p3 = BUP(10, 53);
    enc.TryEncodeRepair(p0);
    enc.TryEncodeRepair(p1);
    enc.TryEncodeRepair(p2);
    auto r = enc.TryEncodeRepair(p3);
    UcpFecCodec dec(4);
    dec.FeedDataPacket(0, p0);
    dec.FeedDataPacket(2, p2);
    dec.FeedDataPacket(3, p3);
    int ms = -1;
    auto rec = dec.TryRecoverFromRepair(*r, 0, 0, ms);
    UCP_CHECK(rec.has_value());
}
UCP_TEST_CASE(FEC_FeedAfter_72) {
    UcpFecCodec enc(4);
    auto p0 = BUP(8, 1), p1 = BUP(8, 2), p2 = BUP(8, 3), p3 = BUP(8, 4);
    enc.TryEncodeRepair(p0);
    enc.TryEncodeRepair(p1);
    enc.TryEncodeRepair(p2);
    auto r = enc.TryEncodeRepair(p3);
    UcpFecCodec dec(4);
    dec.FeedDataPacket(0, p0);
    dec.FeedDataPacket(2, p2);
    dec.FeedDataPacket(3, p3);
    int ms = -1;
    auto rec = dec.TryRecoverFromRepair(*r, 0, 0, ms);
    UCP_CHECK(rec.has_value());
    dec.FeedDataPacket(1, p1);
}
UCP_TEST_CASE(FEC_Singular_73) {
    UcpFecCodec dec(4);
    auto r = dec.TryRecoverFromRepair({105, 110, 118}, 0);
    UCP_CHECK(!r.has_value());
}
UCP_TEST_CASE(FEC_SeqNearMax_74) {
    UcpFecCodec enc(4);
    ucp::vector<uint8_t> p(8, 87);
    uint32_t nm = ~0U - 2;
    enc.TryEncodeRepair(nm, p);
    enc.TryEncodeRepair(nm + 1, p);
    auto r2 = enc.TryEncodeRepair(nm + 2, p);
    UCP_CHECK(!r2.has_value());
}
UCP_TEST_CASE(FEC_Zero_75) {
    UcpFecCodec enc(4);
    ucp::vector<uint8_t> e;
    auto r = enc.TryEncodeRepair(e);
    UCP_CHECK(!r.has_value());
}
UCP_TEST_CASE(NAK_Pct_76) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    cc.OnNakLoss(n, 24000);
    n += r;
    cc.OnAck(n, 12000, r, 12000);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(NAK_Multi_77) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 6; ++i) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(NAK_Cwnd_78) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 3; ++i) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 12000, r, 12000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(NAK_Rate_79) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 4; ++i) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(NAK_TotalDel_80) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 18; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetTotalDelivered() > 0);
}
UCP_TEST_CASE(NAK_OnLoss_81) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    cc.OnPacketLoss(n, 0.10, true, 24000);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(NAK_Zero_82) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    cc.OnNakLoss(n, 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(NAK_Alt_83) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 12; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
        if (i % 3 == 0) {
            cc.OnNakLoss(n, 12000);
            n += 50000;
        }
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(NAK_BwBurst_84) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 8; ++i) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
    }
    for (int i = 0; i < 12; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() > 0);
}
UCP_TEST_CASE(RTO_Bf_85) {
    UcpConfiguration c;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 60000000;
    UcpRtoEstimator e(c);
    e.Update(50000);
    int64_t r = e.CurrentRtoMicros();
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() >= r);
}
UCP_TEST_CASE(RTO_Clamp_86) {
    UcpConfiguration c;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 50000;
    UcpRtoEstimator e(c);
    e.Update(100000);
    for (int i = 0; i < 5; ++i)
        e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() >= 50000);
}
UCP_TEST_CASE(RTO_MultiBf_87) {
    UcpConfiguration c;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    e.Update(50000);
    for (int i = 0; i < 12; ++i) {
        e.Backoff();
        UCP_CHECK(e.CurrentRtoMicros() <= 1000000 * 2);
    }
}
UCP_TEST_CASE(RTO_Srtt_88) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    e.Update(100000);
    e.Update(120000);
    UCP_CHECK(e.SmoothedRttMicros() > 0);
}
UCP_TEST_CASE(RTO_Var_89) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    e.Update(100000);
    int64_t v = e.RttVarianceMicros();
    e.Update(500000);
    UCP_CHECK(e.RttVarianceMicros() >= v);
}
UCP_TEST_CASE(RTO_Smooth_90) {
    UcpConfiguration c;
    c.MinRtoMicros = 20000;
    UcpRtoEstimator e(c);
    e.Update(100000);
    e.Update(120000);
    e.Update(110000);
    e.Update(105000);
    UCP_CHECK(e.CurrentRtoMicros() >= c.MinRtoMicros);
}
UCP_TEST_CASE(RTO_Neg_91) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    int64_t b = e.CurrentRtoMicros();
    e.Update(-5000);
    UCP_CHECK(e.CurrentRtoMicros() == b);
}
UCP_TEST_CASE(RTO_ZeroSamp_92) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    int64_t b = e.CurrentRtoMicros();
    e.Update(0);
    UCP_CHECK(e.CurrentRtoMicros() == b);
}
UCP_TEST_CASE(RTO_LargeBf_93) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 3.0;
    c.MinRtoMicros = 50000;
    UcpRtoEstimator e(c);
    e.Update(50000);
    int64_t r = e.CurrentRtoMicros();
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() >= r);
}
UCP_TEST_CASE(RTO_SmallBf_94) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.01;
    c.MinRtoMicros = 50000;
    UcpRtoEstimator e(c);
    e.Update(50000);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() >= 50000);
}
UCP_TEST_CASE(RTO_Many_95) {
    UcpConfiguration c;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 60000000;
    UcpRtoEstimator e(c);
    e.Update(100000);
    for (int i = 0; i < 25; ++i)
        e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
    UCP_CHECK(e.CurrentRtoMicros() <= 120000000);
}
UCP_TEST_CASE(RTO_Alt_96) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    for (int i = 0; i < 6; ++i) {
        e.Update(100000 + i * 10000);
        e.Backoff();
    }
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_SrttNZ_97) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    e.Update(50000);
    UCP_CHECK(e.SmoothedRttMicros() > 0);
}
UCP_TEST_CASE(RTO_VarNZ_98) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    e.Update(50000);
    e.Update(150000);
    UCP_CHECK(e.RttVarianceMicros() > 0);
}
UCP_TEST_CASE(RTO_VarZero_99) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    e.Update(100000);
    e.Update(100000);
    e.Update(100000);
    UCP_CHECK(e.RttVarianceMicros() >= 0);
}
UCP_TEST_CASE(RTO_Def_100) {
    UcpConfiguration c;
    UcpRtoEstimator e(c);
    UCP_CHECK(e.CurrentRtoMicros() >= 50000);
}
UCP_TEST_CASE(PACE_Consume_101) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 100000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    UCP_CHECK(p.TryConsume(1000, n));
    UCP_CHECK(p.TryConsume(1000, n));
    n += 100000;
    UCP_CHECK(p.TryConsume(1000, n));
}
UCP_TEST_CASE(PACE_Wait_102) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 1000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    (void)p.TryConsume(1000, n);
    int64_t w = p.GetWaitTimeMicros(500, n);
    n += 500000;
    UCP_CHECK(p.GetWaitTimeMicros(500, n) <= w + 1000);
}
UCP_TEST_CASE(PACE_Zero_103) {
    UcpConfiguration c;
    PacingController p(c, 1000);
    UCP_CHECK(p.TryConsume(0, 0));
}
UCP_TEST_CASE(PACE_Wait0_104) {
    UcpConfiguration c;
    PacingController p(c, 1000);
    UCP_CHECK(p.GetWaitTimeMicros(0, 0) >= 0);
}
UCP_TEST_CASE(PACE_HiRate_105) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    c.MaxPacingRateBytesPerSecond = 0;
    PacingController p(c, 100000000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    UCP_CHECK(p.TryConsume(1000, n));
}
UCP_TEST_CASE(PACE_Force_106) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 1000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    (void)p.TryConsume(1000, n);
    p.ForceConsume(2000, n);
    UCP_CHECK(p.GetWaitTimeMicros(1, n) >= 0);
}
UCP_TEST_CASE(PACE_Tiny_107) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1);
    c.SendQuantumBytes = 1220 + 1460;
    c.MaxPacingRateBytesPerSecond = 0;
    PacingController p(c, 1000000);
    UCP_CHECK(p.TryConsume(1220 + c.MaxPayloadSize(), 0));
}
UCP_TEST_CASE(PACE_Refill_108) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(100000);
    PacingController p(c, 100000);
    (void)p.TryConsume(0, 1);
    int64_t n = 100000;
    UCP_CHECK(p.TryConsume(2000, n));
    n += 50000;
    UCP_CHECK(p.TryConsume(1, n));
}
UCP_TEST_CASE(PACE_ZeroRate_109) {
    UcpConfiguration c;
    PacingController p(c, 0);
    p.SetRate(0, 0);
    int cap = c.Mss + c.MaxPayloadSize() + 20;
    int s = 0;
    while (p.TryConsume(cap, 0) && s++ < 10000) {
    }
    UCP_CHECK(p.GetWaitTimeMicros(cap, 0) > 0);
}
UCP_TEST_CASE(PACE_AfterForce_110) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(100000);
    PacingController p(c, 1000);
    (void)p.TryConsume(0, 1);
    int64_t n = 100000;
    (void)p.TryConsume(1000, n);
    p.ForceConsume(500, n);
    UCP_CHECK(p.GetWaitTimeMicros(1, n) >= 0);
}
UCP_TEST_CASE(CC_Rto_111) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.OnRto();
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(CC_Sent_112) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.OnPacketSent(100000, false);
    cc.OnPacketSent(100000, true);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(CC_Ca_113) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.SetCaState(0);
    cc.SetCaState(2);
    cc.SetCaState(3);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= 0);
}
UCP_TEST_CASE(CC_RateSc_114) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 22; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= cc.GetBtlBwBytesPerSecond() * 25 / 100);
}
UCP_TEST_CASE(CC_Gain_115) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 22; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    UCP_CHECK(cc.GetCwndGain() >= 0);
}
UCP_TEST_CASE(CC_Noise0_116) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.OnAck(100000, 24000, 50000, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Noise1_117) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.OnAck(100000, 24000, 50000, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_ZeroDel_118) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.OnAck(100000, 0, 50000, 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= 0);
}
UCP_TEST_CASE(CC_NegRtt_119) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.OnAck(100000, 24000, -1000, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_MultiCyc_120) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int c = 0; c < 6; ++c)
        for (int i = 0; i < 16; ++i) {
            cc.OnAck(n, 24000, r, 24000);
            n += r * 2;
        }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Fast_121) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 6; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    int64_t cw = cc.GetCongestionWindowBytes();
    cc.OnFastRetransmit(n, true);
    UCP_CHECK(cc.GetCongestionWindowBytes() <= cw);
}
UCP_TEST_CASE(CC_FecRec_122) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    cc.OnFecRecovery(n, 24000);
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Full_123) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 35; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    // "Full" = full bandwidth reached: sustained delivery must trip the
    // full-bw detection (3 rounds without 1.25x growth).
    UCP_CHECK(cc.IsFullBwReached());
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_LossNC_124) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    cc.OnPacketLoss(n, 0.0, false);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(CC_PathCh_125) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    for (int i = 0; i < 3; ++i)
        cc.OnPathChange(n);
    UCP_CHECK(cc.GetMode() == UcpMode::Startup);
}
UCP_TEST_CASE(CC_NakNoA_126) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    cc.OnNakLoss(100000, 24000);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(CC_Init0_127) {
    UcpCongestionControl cc(0, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= 0);
}
UCP_TEST_CASE(CC_InitCw_128) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(CC_CwMax_129) {
    UcpCongestionControl cc(12500000, 1220, 256 * 1024, 10 * 1220, 50000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 55; ++i) {
        cc.OnAck(n, 64000, r, 64000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() <= 256 * 1024);
}
UCP_TEST_CASE(CC_Btl_130) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 15; ++i) {
        cc.OnAck(n, 48000, r, 48000);
        n += r;
    }
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() > 0);
}
UCP_TEST_CASE(SEQ_Adj_131) {
    UCP_CHECK(UcpSequenceComparer::IsAfter(1, 0));
    UCP_CHECK(UcpSequenceComparer::IsBefore(0, 1));
}
UCP_TEST_CASE(SEQ_Eq_132) {
    UCP_CHECK_FALSE(UcpSequenceComparer::IsAfter(100, 100));
    UCP_CHECK_FALSE(UcpSequenceComparer::IsBefore(100, 100));
}
UCP_TEST_CASE(SEQ_Wrap_133) {
    uint32_t m = ~0U;
    UCP_CHECK(UcpSequenceComparer::IsAfter(0, m));
    UCP_CHECK(UcpSequenceComparer::IsBefore(m, 0));
}
UCP_TEST_CASE(SEQ_Half_134) {
    uint32_t m = ~0U, h = 2147483648U;
    UCP_CHECK(UcpSequenceComparer::IsAfter(m, h));
    UCP_CHECK(UcpSequenceComparer::IsBefore(h, m));
}
UCP_TEST_CASE(SEQ_OrEq_135) {
    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(5, 5));
    UCP_CHECK(UcpSequenceComparer::IsBeforeOrEqual(5, 5));
    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(10, 5));
}
UCP_TEST_CASE(SEQ_Cmp_136) {
    UCP_CHECK_EQUAL(0, UcpSequenceComparer::Compare(0, 0));
    UCP_CHECK_EQUAL(1, UcpSequenceComparer::Compare(1, 0));
    UCP_CHECK_EQUAL(-1, UcpSequenceComparer::Compare(0, 1));
}
UCP_TEST_CASE(SEQ_CmpW_137) {
    uint32_t m = ~0U;
    UCP_CHECK_EQUAL(1, UcpSequenceComparer::Compare(0, m));
    UCP_CHECK_EQUAL(-1, UcpSequenceComparer::Compare(m, 0));
}
UCP_TEST_CASE(SEQ_LGap_138) {
    UCP_CHECK(UcpSequenceComparer::IsAfter(2000000, 1000000));
}
UCP_TEST_CASE(SEQ_HSpace_139) {
    uint32_t h = 2147483648U;
    UCP_CHECK(UcpSequenceComparer::Compare(h, 0) != 0);
}
UCP_TEST_CASE(SACK_Empty_140) {
    UcpSackGenerator g;
    auto b = g.Generate(0, {}, 8);
    UCP_CHECK(b.empty());
}
UCP_TEST_CASE(SACK_Single_141) {
    UcpSackGenerator g;
    ucp::vector<uint32_t> r = {5};
    auto b = g.Generate(0, r, 8);
    UCP_CHECK(1 == b.size());
}
UCP_TEST_CASE(SACK_Gap_142) {
    UcpSackGenerator g;
    ucp::vector<uint32_t> r = {1, 3, 5};
    auto b = g.Generate(0, r, 8);
    UCP_CHECK(3 == b.size());
}
UCP_TEST_CASE(SACK_Gaps_143) {
    UcpSackGenerator g;
    ucp::vector<uint32_t> r = {1, 3, 5, 7, 9};
    auto b = g.Generate(0, r, 15);
    // Values are 2 apart: none coalesce, so each gap is its own block.
    UCP_CHECK(5 == b.size());
}
UCP_TEST_CASE(SACK_Cont_144) {
    UcpSackGenerator g;
    ucp::vector<uint32_t> r;
    for (uint32_t i = 100; i <= 200; ++i)
        r.push_back(i);
    auto b = g.Generate(99, r, 8);
    UCP_CHECK(b.size() <= 2);
}
UCP_TEST_CASE(SACK_Front_145) {
    UcpSackGenerator g;
    ucp::vector<uint32_t> r = {5, 6, 7, 8};
    auto b = g.Generate(0, r, 8);
    UCP_CHECK(b.size() <= 4);
}
UCP_TEST_CASE(SACK_Back_146) {
    UcpSackGenerator g;
    ucp::vector<uint32_t> r = {0, 1, 2, 3, 10};
    auto b = g.Generate(0, r, 8);
    // {0,1,2,3} coalesce into one block and {10} stands alone: exactly 2.
    UCP_CHECK(2 == b.size());
}
UCP_TEST_CASE(SACK_All_147) {
    UcpSackGenerator g;
    ucp::vector<uint32_t> r = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    auto b = g.Generate(0, r, 8);
    UCP_CHECK(b.size() <= 10);
}
UCP_TEST_CASE(COD_Ack_148) {
    UcpAckPacket a;
    a.header.type = UcpPacketType::Ack;
    a.header.connection_id = 33;
    a.ack_number = 200;
    a.window_size = 64000;
    auto e = UcpPacketCodec::Encode(a);
    ucp::shared_ptr<UcpPacket> d;
    UCP_CHECK(UcpPacketCodec::TryDecode(e.data(), 0, e.size(), d));
    auto* da = dynamic_cast<UcpAckPacket*>(d.get());
    UCP_CHECK(NULLPTR != da);
    UCP_CHECK(da->ack_number == 200);
}
UCP_TEST_CASE(COD_Data_149) {
    UcpDataPacket d;
    d.header.type = UcpPacketType::Data;
    d.header.flags = UcpPacketFlags::HasAckNumber;
    d.header.connection_id = 44;
    d.ack_number = 300;
    d.sequence_number = 500;
    d.payload = {1, 2, 3};
    auto e = UcpPacketCodec::Encode(d);
    ucp::shared_ptr<UcpPacket> p;
    UCP_CHECK(UcpPacketCodec::TryDecode(e.data(), 0, e.size(), p));
    auto* dd = dynamic_cast<UcpDataPacket*>(p.get());
    UCP_CHECK(NULLPTR != dd);
    UCP_CHECK(dd->ack_number == 300);
}
UCP_TEST_CASE(COD_Nak_150) {
    UcpNakPacket n;
    n.header.type = UcpPacketType::Nak;
    n.header.connection_id = 55;
    n.ack_number = 100;
    n.missing_sequences = {101, 105, 110};
    auto e = UcpPacketCodec::Encode(n);
    ucp::shared_ptr<UcpPacket> d;
    UCP_CHECK(UcpPacketCodec::TryDecode(e.data(), 0, e.size(), d));
    auto* dn = dynamic_cast<UcpNakPacket*>(d.get());
    UCP_CHECK(NULLPTR != dn);
    UCP_CHECK(3 == dn->missing_sequences.size());
}
UCP_TEST_CASE(COD_Empty_151) {
    ucp::shared_ptr<UcpPacket> p;
    UCP_CHECK_FALSE(UcpPacketCodec::TryDecode(NULLPTR, 0, 0, p));
}
UCP_TEST_CASE(COD_Trunc_152) {
    ucp::vector<uint8_t> b(5, 0);
    ucp::shared_ptr<UcpPacket> p;
    UCP_CHECK_FALSE(UcpPacketCodec::TryDecode(b.data(), 0, 5, p));
}
UCP_TEST_CASE(COD_Sack_153) {
    UcpAckPacket a;
    a.header.type = UcpPacketType::Ack;
    a.header.connection_id = 10;
    a.ack_number = 500;
    a.sack_blocks.push_back({600, 605});
    a.sack_blocks.push_back({610, 615});
    a.window_size = 32768;
    a.echo_timestamp = 123456;
    auto e = UcpPacketCodec::Encode(a);
    ucp::shared_ptr<UcpPacket> d;
    UCP_CHECK(UcpPacketCodec::TryDecode(e.data(), 0, e.size(), d));
    auto* da = dynamic_cast<UcpAckPacket*>(d.get());
    UCP_CHECK(NULLPTR != da);
    UCP_CHECK(2 == da->sack_blocks.size());
}
UCP_TEST_CASE(COD_Large_154) {
    UcpDataPacket d;
    d.header.type = UcpPacketType::Data;
    d.header.connection_id = 1;
    d.sequence_number = 999;
    d.payload = BUP(1000, 12345);
    auto e = UcpPacketCodec::Encode(d);
    UCP_CHECK(e.size() > 1000);
    ucp::shared_ptr<UcpPacket> p;
    UCP_CHECK(UcpPacketCodec::TryDecode(e.data(), 0, e.size(), p));
    auto* dd = dynamic_cast<UcpDataPacket*>(p.get());
    UCP_CHECK(NULLPTR != dd);
}
UCP_TEST_CASE(COD_Rtx_155) {
    UcpDataPacket d;
    d.header.type = UcpPacketType::Data;
    d.header.flags = UcpPacketFlags::Retransmit;
    d.header.connection_id = 7;
    d.sequence_number = 42;
    d.payload = {82, 84, 88};
    auto e = UcpPacketCodec::Encode(d);
    ucp::shared_ptr<UcpPacket> p;
    UCP_CHECK(UcpPacketCodec::TryDecode(e.data(), 0, e.size(), p));
    auto* dd = dynamic_cast<UcpDataPacket*>(p.get());
    UCP_CHECK(NULLPTR != dd);
    UCP_CHECK(0 != (dd->header.flags & UcpPacketFlags::Retransmit));
}
UCP_TEST_CASE(BDP_Cwnd_156) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 20000;
    for (int i = 0; i < 25; ++i) {
        cc.OnAck(n, 48000, r, 48000);
        n += r;
    }
    UCP_CHECK(cc.GetMinRttMicros() > 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(BDP_RttBw_157) {
    UcpCongestionControl cc1(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    UcpCongestionControl cc2(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 20; ++i) {
        cc1.OnAck(n, 24000, 10000, 24000);
        n += 10000;
    }
    n = 100000;
    for (int i = 0; i < 20; ++i) {
        cc2.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    UCP_CHECK(cc1.GetPacingRateBytesPerSecond() > 0);
    UCP_CHECK(cc2.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(BDP_MaxCw_158) {
    UcpCongestionControl cc(12500000, 1220, 100000, 10 * 1220, 12500000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 40; ++i) {
        cc.OnAck(n, 48000, r, 48000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() <= 100000);
}
UCP_TEST_CASE(CW_Small_159) {
    UcpCongestionControl cc(1000000, 1220, 1220 * 10, 10 * 1220, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() <= 1220 * 10);
}
UCP_TEST_CASE(CW_MaxImm_160) {
    UcpCongestionControl cc(12500000, 1220, 1220 * 50, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 64000, r, 64000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() <= 1220 * 50);
}
UCP_TEST_CASE(CW_InitS_161) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 1220 * 2, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() >= 1220 * 2);
}
UCP_TEST_CASE(CW_InitL_162) {
    UcpCongestionControl cc(1000000, 1220, INT_MAX, 1220 * 1000, 1000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(OPC_Reset_163) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.OnAck(1000, 100000, 50000, 100000);
    cc.OnPathChange(250000);
    UCP_CHECK(UcpMode::Startup == cc.GetMode());
}
UCP_TEST_CASE(OPC_Multi_164) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(n, 24000, 50000, 24000);
        n += 50000;
    }
    for (int i = 0; i < 3; ++i)
        cc.OnPathChange(n);
    UCP_CHECK(cc.GetMode() == UcpMode::Startup);
}
UCP_TEST_CASE(PRT_IV_165) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 15; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    n += 30000000;
    cc.OnAck(n, 24000, 50000, 24000);
    for (int i = 0; i < 30; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(PRT_Long_166) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 15; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    n += 25000000;
    cc.OnAck(n, 24000, 50000, 24000);
    for (int i = 0; i < 50; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(PRT_Rapid_167) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 12; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int i = 0; i < 30; ++i) {
        cc.OnAck(n, 24000, r, 24000);
        n += r * 2;
    }
    n += 25000000;
    cc.OnAck(n, 24000, 50000, 24000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(PRT_Multi_168) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int cy = 0; cy < 3; ++cy) {
        for (int i = 0; i < 15; ++i) {
            cc.OnAck(n, 24000, r, 24000);
            n += r;
        }
        n += 30000000;
        cc.OnAck(n, 24000, 50000 + cy * 10000, 24000);
        for (int i = 0; i < 30; ++i) {
            cc.OnAck(n, 24000, r, 24000);
            n += r;
        }
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(PCB_Cid_169) {
    UcpConfiguration c;
    auto p = ucp::make_shared_object<UcpPcb>((ucp::transport::ITransport*)NULLPTR, false, false, UcpPcb::ClosedCallback(NULLPTR), 0xABCDU,
                                             c, (ucp::UcpNetwork*)NULLPTR);
    UCP_CHECK(0xABCDU == p->GetConnectionId());
    UCP_CHECK(p->AddExtraCid(0xDEADU));
    UCP_CHECK(p->IsValidCid(0xDEADU));
    UCP_CHECK(p->RemoveExtraCid(0xDEADU));
    UCP_CHECK_FALSE(p->IsValidCid(0xDEADU));
}
UCP_TEST_CASE(PCB_Inv_170) {
    UcpConfiguration c;
    auto p = ucp::make_shared_object<UcpPcb>((ucp::transport::ITransport*)NULLPTR, false, false, UcpPcb::ClosedCallback(NULLPTR), 0x6000U,
                                             c, (ucp::UcpNetwork*)NULLPTR);
    UCP_CHECK_FALSE(p->IsValidCid(0xDEADU));
}
UCP_TEST_CASE(PCB_Rm_171) {
    UcpConfiguration c;
    auto p = ucp::make_shared_object<UcpPcb>((ucp::transport::ITransport*)NULLPTR, false, false, UcpPcb::ClosedCallback(NULLPTR), 0x6000U,
                                             c, (ucp::UcpNetwork*)NULLPTR);
    UCP_CHECK_FALSE(p->RemoveExtraCid(0x9999U));
}
UCP_TEST_CASE(PCB_Abt_172) {
    UcpConfiguration c;
    c.Mss = 512;
    std::atomic<bool> d{false};
    {
        UcpPcb p((ucp::transport::ITransport*)NULLPTR, false, false, UcpPcb::ClosedCallback(NULLPTR), 0xE0U, c, (ucp::UcpNetwork*)NULLPTR);
        p.Disconnected = [&d]() { d = true; };
        p.Abort(false);
    }
    UCP_CHECK(d.load());
}
UCP_TEST_CASE(PCB_Multi_173) {
    UcpConfiguration c;
    auto p = ucp::make_shared_object<UcpPcb>((ucp::transport::ITransport*)NULLPTR, false, false, UcpPcb::ClosedCallback(NULLPTR), 0xABCU, c,
                                             (ucp::UcpNetwork*)NULLPTR);
    for (uint32_t i = 0x1000U; i < 0x1008U; ++i)
        UCP_CHECK(p->AddExtraCid(i));
    for (uint32_t i = 0x1000U; i < 0x1008U; ++i) {
        UCP_CHECK(p->IsValidCid(i));
        UCP_CHECK(p->RemoveExtraCid(i));
        UCP_CHECK_FALSE(p->IsValidCid(i));
    }
}
UCP_TEST_CASE(PCB_Dup_174) {
    UcpConfiguration c;
    auto p = ucp::make_shared_object<UcpPcb>((ucp::transport::ITransport*)NULLPTR, false, false, UcpPcb::ClosedCallback(NULLPTR), 0xD0U, c,
                                             (ucp::UcpNetwork*)NULLPTR);
    UCP_CHECK(p->AddExtraCid(0xD1U));
    UCP_CHECK_FALSE(p->AddExtraCid(0xD1U));
}
UCP_TEST_CASE(MISC_PBIdx_175) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 30000;
    for (int i = 0; i < 200; ++i) {
        cc.OnAck(n, 12200, r, 500000);
        n += r;
    }
    // In ProbeBw the cycle index must advance (a live cycle, not frozen):
    // the effective phase moves forward over sustained in-flight delivery.
    if (cc.GetMode() == UcpMode::ProbeBw) {
        uint32_t start = cc.GetProbeBwCycleIdx() & 7;
        bool advanced = false;
        for (int i = 0; i < 128; ++i) {
            cc.OnAck(n, 12200, r, 500000);
            n += r;
            if ((cc.GetProbeBwCycleIdx() & 7) != start) {
                advanced = true;
                break;
            }
        }
        UCP_CHECK(advanced);
    }
}
UCP_TEST_CASE(MISC_Edt_176) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    cc.SetEdtState(1000000, 500000);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_0_Min50000_V0_181) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.0;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_0_Min50000_V1_182) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.0;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_0_Min100000_V0_183) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.0;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_0_Min100000_V1_184) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.0;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_2_Min50000_V0_185) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.2;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_2_Min50000_V1_186) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.2;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_2_Min100000_V0_187) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.2;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_2_Min100000_V1_188) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.2;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_5_Min50000_V0_189) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.5;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_5_Min50000_V1_190) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.5;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_5_Min100000_V0_191) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.5;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf1_5_Min100000_V1_192) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 1.5;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf2_0_Min50000_V0_193) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 2.0;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf2_0_Min50000_V1_194) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 2.0;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf2_0_Min100000_V0_195) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 2.0;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf2_0_Min100000_V1_196) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 2.0;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf3_0_Min50000_V0_197) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 3.0;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf3_0_Min50000_V1_198) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 3.0;
    c.MinRtoMicros = 50000;
    c.MaxRtoMicros = 1000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf3_0_Min100000_V0_199) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 3.0;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(RTO_Sweep_Bf3_0_Min100000_V1_200) {
    UcpConfiguration c;
    c.RetransmitBackoffFactor = 3.0;
    c.MinRtoMicros = 100000;
    c.MaxRtoMicros = 2000000;
    UcpRtoEstimator e(c);
    const int64_t sweepVals[] = {50000, 60000, 55000};
    for (auto sv : sweepVals)
        e.Update(sv);
    e.Backoff();
    UCP_CHECK(e.CurrentRtoMicros() > 0);
}
UCP_TEST_CASE(PACE_Comb_R1000_C500_200_201) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 1000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(500, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R1000_C2000_201_202) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 1000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(2000, n);
    UCP_CHECK(!ok);
}
UCP_TEST_CASE(PACE_Comb_R10000_C500_202_203) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 10000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(500, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R10000_C2000_203_204) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 10000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(2000, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R10000_C10000_204_205) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 10000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(10000, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R100000_C500_205_206) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 100000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(500, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R100000_C2000_206_207) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 100000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(2000, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R100000_C10000_207_208) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 100000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(10000, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R1000000_C500_208_209) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 1000000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(500, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R1000000_C2000_209_210) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 1000000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(2000, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(PACE_Comb_R1000000_C10000_210_211) {
    UcpConfiguration c;
    c.SetPacingBucketDurationMicros(1000000);
    PacingController p(c, 1000000);
    (void)p.TryConsume(0, 1);
    int64_t n = 1000000;
    bool ok = p.TryConsume(10000, n);
    UCP_CHECK(ok);
}
UCP_TEST_CASE(CC_Sweep_B500000_R5000_212_213) {
    UcpCongestionControl cc(500000, 1220, 64 * 1024 * 1024, 10 * 1220, 500000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 500000 * r / 1000000, r, 500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B500000_R10000_214_215) {
    UcpCongestionControl cc(500000, 1220, 64 * 1024 * 1024, 10 * 1220, 500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 500000 * r / 1000000, r, 500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B500000_R50000_216_217) {
    UcpCongestionControl cc(500000, 1220, 64 * 1024 * 1024, 10 * 1220, 500000);
    int64_t n = 100000, r = 50000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 500000 * r / 1000000, r, 500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B2000000_R5000_218_219) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B2000000_R10000_220_221) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B2000000_R50000_222_223) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 50000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B5000000_R5000_224_225) {
    UcpCongestionControl cc(5000000, 1220, 64 * 1024 * 1024, 10 * 1220, 5000000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 5000000 * r / 1000000, r, 5000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B5000000_R10000_226_227) {
    UcpCongestionControl cc(5000000, 1220, 64 * 1024 * 1024, 10 * 1220, 5000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 5000000 * r / 1000000, r, 5000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B5000000_R50000_228_229) {
    UcpCongestionControl cc(5000000, 1220, 64 * 1024 * 1024, 10 * 1220, 5000000);
    int64_t n = 100000, r = 50000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 5000000 * r / 1000000, r, 5000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B12500000_R5000_230_231) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 12500000 * r / 1000000, r, 12500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B12500000_R10000_232_233) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 12500000 * r / 1000000, r, 12500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B12500000_R50000_234_235) {
    UcpCongestionControl cc(12500000, 1220, 64 * 1024 * 1024, 10 * 1220, 12500000);
    int64_t n = 100000, r = 50000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 12500000 * r / 1000000, r, 12500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B25000000_R5000_236_237) {
    UcpCongestionControl cc(25000000, 1220, 64 * 1024 * 1024, 10 * 1220, 25000000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 25000000 * r / 1000000, r, 25000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B25000000_R10000_238_239) {
    UcpCongestionControl cc(25000000, 1220, 64 * 1024 * 1024, 10 * 1220, 25000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 25000000 * r / 1000000, r, 25000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B25000000_R50000_240_241) {
    UcpCongestionControl cc(25000000, 1220, 64 * 1024 * 1024, 10 * 1220, 25000000);
    int64_t n = 100000, r = 50000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 25000000 * r / 1000000, r, 25000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B50000000_R5000_242_243) {
    UcpCongestionControl cc(50000000, 1220, 64 * 1024 * 1024, 10 * 1220, 50000000);
    int64_t n = 100000, r = 5000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 50000000 * r / 1000000, r, 50000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B50000000_R10000_244_245) {
    UcpCongestionControl cc(50000000, 1220, 64 * 1024 * 1024, 10 * 1220, 50000000);
    int64_t n = 100000, r = 10000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 50000000 * r / 1000000, r, 50000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Sweep_B50000000_R50000_246_247) {
    UcpCongestionControl cc(50000000, 1220, 64 * 1024 * 1024, 10 * 1220, 50000000);
    int64_t n = 100000, r = 50000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(n, 50000000 * r / 1000000, r, 50000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B0_R0_247_248) {
    UcpCongestionControl cc(100000, 1220, 64 * 1024 * 1024, 10 * 1220, 100000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 100000 * r / 1000000, r, 100000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B0_R1_248_249) {
    UcpCongestionControl cc(100000, 1220, 64 * 1024 * 1024, 10 * 1220, 100000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 100000 * r / 1000000, r, 100000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B0_R2_249_250) {
    UcpCongestionControl cc(100000, 1220, 64 * 1024 * 1024, 10 * 1220, 100000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 100000 * r / 1000000, r, 100000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B0_R3_250_251) {
    UcpCongestionControl cc(100000, 1220, 64 * 1024 * 1024, 10 * 1220, 100000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 100000 * r / 1000000, r, 100000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B0_R4_251_252) {
    UcpCongestionControl cc(100000, 1220, 64 * 1024 * 1024, 10 * 1220, 100000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 100000 * r / 1000000, r, 100000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B1_R0_252_253) {
    UcpCongestionControl cc(200000, 1220, 64 * 1024 * 1024, 10 * 1220, 200000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 200000 * r / 1000000, r, 200000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B1_R1_253_254) {
    UcpCongestionControl cc(200000, 1220, 64 * 1024 * 1024, 10 * 1220, 200000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 200000 * r / 1000000, r, 200000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B1_R2_254_255) {
    UcpCongestionControl cc(200000, 1220, 64 * 1024 * 1024, 10 * 1220, 200000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 200000 * r / 1000000, r, 200000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B1_R3_255_256) {
    UcpCongestionControl cc(200000, 1220, 64 * 1024 * 1024, 10 * 1220, 200000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 200000 * r / 1000000, r, 200000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B1_R4_256_257) {
    UcpCongestionControl cc(200000, 1220, 64 * 1024 * 1024, 10 * 1220, 200000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 200000 * r / 1000000, r, 200000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B2_R0_257_258) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 1000000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 1000000 * r / 1000000, r, 1000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B2_R1_258_259) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 1000000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 1000000 * r / 1000000, r, 1000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B2_R2_259_260) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 1000000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 1000000 * r / 1000000, r, 1000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B2_R3_260_261) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 1000000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 1000000 * r / 1000000, r, 1000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B2_R4_261_262) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 1000000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 1000000 * r / 1000000, r, 1000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B3_R0_262_263) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B3_R1_263_264) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B3_R2_264_265) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B3_R3_265_266) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B3_R4_266_267) {
    UcpCongestionControl cc(2000000, 1220, 64 * 1024 * 1024, 10 * 1220, 2000000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 2000000 * r / 1000000, r, 2000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B4_R0_267_268) {
    UcpCongestionControl cc(4000000, 1220, 64 * 1024 * 1024, 10 * 1220, 4000000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 4000000 * r / 1000000, r, 4000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B4_R1_268_269) {
    UcpCongestionControl cc(4000000, 1220, 64 * 1024 * 1024, 10 * 1220, 4000000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 4000000 * r / 1000000, r, 4000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B4_R2_269_270) {
    UcpCongestionControl cc(4000000, 1220, 64 * 1024 * 1024, 10 * 1220, 4000000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 4000000 * r / 1000000, r, 4000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B4_R3_270_271) {
    UcpCongestionControl cc(4000000, 1220, 64 * 1024 * 1024, 10 * 1220, 4000000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 4000000 * r / 1000000, r, 4000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B4_R4_271_272) {
    UcpCongestionControl cc(4000000, 1220, 64 * 1024 * 1024, 10 * 1220, 4000000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 4000000 * r / 1000000, r, 4000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B5_R0_272_273) {
    UcpCongestionControl cc(8000000, 1220, 64 * 1024 * 1024, 10 * 1220, 8000000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 8000000 * r / 1000000, r, 8000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B5_R1_273_274) {
    UcpCongestionControl cc(8000000, 1220, 64 * 1024 * 1024, 10 * 1220, 8000000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 8000000 * r / 1000000, r, 8000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B5_R2_274_275) {
    UcpCongestionControl cc(8000000, 1220, 64 * 1024 * 1024, 10 * 1220, 8000000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 8000000 * r / 1000000, r, 8000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B5_R3_275_276) {
    UcpCongestionControl cc(8000000, 1220, 64 * 1024 * 1024, 10 * 1220, 8000000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 8000000 * r / 1000000, r, 8000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B5_R4_276_277) {
    UcpCongestionControl cc(8000000, 1220, 64 * 1024 * 1024, 10 * 1220, 8000000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 8000000 * r / 1000000, r, 8000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B6_R0_277_278) {
    UcpCongestionControl cc(16000000, 1220, 64 * 1024 * 1024, 10 * 1220, 16000000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 16000000 * r / 1000000, r, 16000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B6_R1_278_279) {
    UcpCongestionControl cc(16000000, 1220, 64 * 1024 * 1024, 10 * 1220, 16000000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 16000000 * r / 1000000, r, 16000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B6_R2_279_280) {
    UcpCongestionControl cc(16000000, 1220, 64 * 1024 * 1024, 10 * 1220, 16000000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 16000000 * r / 1000000, r, 16000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B6_R3_280_281) {
    UcpCongestionControl cc(16000000, 1220, 64 * 1024 * 1024, 10 * 1220, 16000000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 16000000 * r / 1000000, r, 16000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B6_R4_281_282) {
    UcpCongestionControl cc(16000000, 1220, 64 * 1024 * 1024, 10 * 1220, 16000000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 16000000 * r / 1000000, r, 16000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B7_R0_282_283) {
    UcpCongestionControl cc(32000000, 1220, 64 * 1024 * 1024, 10 * 1220, 32000000);
    int64_t n = 100000, r = 2000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 32000000 * r / 1000000, r, 32000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B7_R1_283_284) {
    UcpCongestionControl cc(32000000, 1220, 64 * 1024 * 1024, 10 * 1220, 32000000);
    int64_t n = 100000, r = 4000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 32000000 * r / 1000000, r, 32000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B7_R2_284_285) {
    UcpCongestionControl cc(32000000, 1220, 64 * 1024 * 1024, 10 * 1220, 32000000);
    int64_t n = 100000, r = 8000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 32000000 * r / 1000000, r, 32000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B7_R3_285_286) {
    UcpCongestionControl cc(32000000, 1220, 64 * 1024 * 1024, 10 * 1220, 32000000);
    int64_t n = 100000, r = 16000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 32000000 * r / 1000000, r, 32000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Comb2_B7_R4_286_287) {
    UcpCongestionControl cc(32000000, 1220, 64 * 1024 * 1024, 10 * 1220, 32000000);
    int64_t n = 100000, r = 32000;
    for (int k = 0; k < 15; ++k) {
        cc.OnAck(n, 32000000 * r / 1000000, r, 32000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(FEC_Comb_G4_R1_287_288) {
    UcpFecCodec enc(4, 1);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 4; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 4; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G4_R2_288_289) {
    UcpFecCodec enc(4, 2);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 4; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 4; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G4_R4_289_290) {
    UcpFecCodec enc(4, 4);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 4; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 4; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G8_R1_290_291) {
    UcpFecCodec enc(8, 1);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 8; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 8; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G8_R2_291_292) {
    UcpFecCodec enc(8, 2);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 8; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 8; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G8_R4_292_293) {
    UcpFecCodec enc(8, 4);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 8; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 8; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G16_R1_293_294) {
    UcpFecCodec enc(16, 1);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 16; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 16; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G16_R2_294_295) {
    UcpFecCodec enc(16, 2);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 16; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 16; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G16_R4_295_296) {
    UcpFecCodec enc(16, 4);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 16; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 16; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G32_R1_296_297) {
    UcpFecCodec enc(32, 1);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 32; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 32; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G32_R2_297_298) {
    UcpFecCodec enc(32, 2);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 32; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 32; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(FEC_Comb_G32_R4_298_299) {
    UcpFecCodec enc(32, 4);
    ucp::vector<ucp::vector<uint8_t>> ps;
    for (int k = 0; k < 32; ++k)
        ps.push_back(BUP(10, 1000 + k));
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> r;
    for (int k = 0; k < 32; ++k)
        r = enc.TryEncodeRepairs(ps[k]);
    UCP_CHECK(r.has_value());
}
UCP_TEST_CASE(NAK_Comb_N2_362_363) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int k = 0; k < 5; ++k) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int k = 0; k < 2; ++k) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(NAK_Comb_N4_363_364) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int k = 0; k < 5; ++k) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int k = 0; k < 4; ++k) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(NAK_Comb_N6_364_365) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int k = 0; k < 5; ++k) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int k = 0; k < 6; ++k) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(NAK_Comb_N8_365_366) {
    UcpCongestionControl cc(1000000, 1220, 64 * 1024 * 1024, 10 * 1220, 0);
    int64_t n = 100000, r = 10000;
    for (int k = 0; k < 5; ++k) {
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    for (int k = 0; k < 8; ++k) {
        cc.OnNakLoss(n, 24000);
        n += 50000;
        cc.OnAck(n, 24000, r, 24000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
}
UCP_TEST_CASE(CC_Mass_B250000_R3000_L0_378_379) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R3000_L1_379_380) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R3000_L5_380_381) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R6000_L0_381_382) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R6000_L1_382_383) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R6000_L5_383_384) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R12000_L0_384_385) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R12000_L1_385_386) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R12000_L5_386_387) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R24000_L0_387_388) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R24000_L1_388_389) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R24000_L5_389_390) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R48000_L0_390_391) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R48000_L1_391_392) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B250000_R48000_L5_392_393) {
    UcpCongestionControl cc(250000, 1220, 64 * 1024 * 1024, 10 * 1220, 250000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 250000 * r / 1000000, r, 250000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R3000_L0_393_394) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R3000_L1_394_395) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R3000_L5_395_396) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R6000_L0_396_397) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R6000_L1_397_398) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R6000_L5_398_399) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R12000_L0_399_400) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R12000_L1_400_401) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R12000_L5_401_402) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R24000_L0_402_403) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R24000_L1_403_404) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R24000_L5_404_405) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R48000_L0_405_406) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R48000_L1_406_407) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B750000_R48000_L5_407_408) {
    UcpCongestionControl cc(750000, 1220, 64 * 1024 * 1024, 10 * 1220, 750000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 750000 * r / 1000000, r, 750000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R3000_L0_408_409) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R3000_L1_409_410) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R3000_L5_410_411) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R6000_L0_411_412) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R6000_L1_412_413) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R6000_L5_413_414) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R12000_L0_414_415) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R12000_L1_415_416) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R12000_L5_416_417) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R24000_L0_417_418) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R24000_L1_418_419) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R24000_L5_419_420) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R48000_L0_420_421) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R48000_L1_421_422) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B1500000_R48000_L5_422_423) {
    UcpCongestionControl cc(1500000, 1220, 64 * 1024 * 1024, 10 * 1220, 1500000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 1500000 * r / 1000000, r, 1500000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R3000_L0_423_424) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R3000_L1_424_425) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R3000_L5_425_426) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R6000_L0_426_427) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R6000_L1_427_428) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R6000_L5_428_429) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R12000_L0_429_430) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R12000_L1_430_431) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R12000_L5_431_432) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R24000_L0_432_433) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R24000_L1_433_434) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R24000_L5_434_435) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R48000_L0_435_436) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R48000_L1_436_437) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B3000000_R48000_L5_437_438) {
    UcpCongestionControl cc(3000000, 1220, 64 * 1024 * 1024, 10 * 1220, 3000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 3000000 * r / 1000000, r, 3000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R3000_L0_438_439) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R3000_L1_439_440) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R3000_L5_440_441) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R6000_L0_441_442) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R6000_L1_442_443) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R6000_L5_443_444) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R12000_L0_444_445) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R12000_L1_445_446) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R12000_L5_446_447) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R24000_L0_447_448) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R24000_L1_448_449) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R24000_L5_449_450) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R48000_L0_450_451) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R48000_L1_451_452) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B6000000_R48000_L5_452_453) {
    UcpCongestionControl cc(6000000, 1220, 64 * 1024 * 1024, 10 * 1220, 6000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 6000000 * r / 1000000, r, 6000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R3000_L0_453_454) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R3000_L1_454_455) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R3000_L5_455_456) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R6000_L0_456_457) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R6000_L1_457_458) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R6000_L5_458_459) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R12000_L0_459_460) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R12000_L1_460_461) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R12000_L5_461_462) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R24000_L0_462_463) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R24000_L1_463_464) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R24000_L5_464_465) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R48000_L0_465_466) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R48000_L1_466_467) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B12000000_R48000_L5_467_468) {
    UcpCongestionControl cc(12000000, 1220, 64 * 1024 * 1024, 10 * 1220, 12000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 12000000 * r / 1000000, r, 12000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R3000_L0_468_469) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R3000_L1_469_470) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R3000_L5_470_471) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R6000_L0_471_472) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R6000_L1_472_473) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R6000_L5_473_474) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R12000_L0_474_475) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R12000_L1_475_476) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R12000_L5_476_477) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R24000_L0_477_478) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R24000_L1_478_479) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R24000_L5_479_480) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R48000_L0_480_481) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R48000_L1_481_482) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B24000000_R48000_L5_482_483) {
    UcpCongestionControl cc(24000000, 1220, 64 * 1024 * 1024, 10 * 1220, 24000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 24000000 * r / 1000000, r, 24000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R3000_L0_483_484) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R3000_L1_484_485) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R3000_L5_485_486) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 3000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R6000_L0_486_487) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R6000_L1_487_488) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R6000_L5_488_489) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 6000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R12000_L0_489_490) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R12000_L1_490_491) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R12000_L5_491_492) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 12000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R24000_L0_492_493) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R24000_L1_493_494) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R24000_L5_494_495) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 24000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R48000_L0_495_496) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    UCP_CHECK(cc.GetEstimatedLossPercent() <= 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R48000_L1_496_497) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.01, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(CC_Mass_B40000000_R48000_L5_497_498) {
    UcpCongestionControl cc(40000000, 1220, 64 * 1024 * 1024, 10 * 1220, 40000000);
    int64_t n = 100000, r = 48000;
    for (int k = 0; k < 18; ++k) {
        cc.OnAck(n, 40000000 * r / 1000000, r, 40000000 * r / 1000000);
        n += r;
    }
    cc.OnPacketLoss(n, 0.05, true, 1220);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}
UCP_TEST_CASE(FEC_Mass_G3_R1_498_499) {
    UcpFecCodec enc(3, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 3; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G3_R2_499_500) {
    UcpFecCodec enc(3, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 3; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G3_R3_500_501) {
    UcpFecCodec enc(3, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 3; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G5_R1_501_502) {
    UcpFecCodec enc(5, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 5; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G5_R2_502_503) {
    UcpFecCodec enc(5, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 5; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G5_R3_503_504) {
    UcpFecCodec enc(5, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 5; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G7_R1_504_505) {
    UcpFecCodec enc(7, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 7; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G7_R2_505_506) {
    UcpFecCodec enc(7, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 7; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G7_R3_506_507) {
    UcpFecCodec enc(7, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 7; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G9_R1_507_508) {
    UcpFecCodec enc(9, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 9; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G9_R2_508_509) {
    UcpFecCodec enc(9, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 9; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G9_R3_509_510) {
    UcpFecCodec enc(9, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 9; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G10_R1_510_511) {
    UcpFecCodec enc(10, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 10; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G10_R2_511_512) {
    UcpFecCodec enc(10, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 10; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G10_R3_512_513) {
    UcpFecCodec enc(10, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 10; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G12_R1_513_514) {
    UcpFecCodec enc(12, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 12; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G12_R2_514_515) {
    UcpFecCodec enc(12, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 12; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G12_R3_515_516) {
    UcpFecCodec enc(12, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 12; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G15_R1_516_517) {
    UcpFecCodec enc(15, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 15; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G15_R2_517_518) {
    UcpFecCodec enc(15, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 15; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G15_R3_518_519) {
    UcpFecCodec enc(15, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 15; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G20_R1_519_520) {
    UcpFecCodec enc(20, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 20; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G20_R2_520_521) {
    UcpFecCodec enc(20, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 20; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G20_R3_521_522) {
    UcpFecCodec enc(20, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 20; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G24_R1_522_523) {
    UcpFecCodec enc(24, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 24; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G24_R2_523_524) {
    UcpFecCodec enc(24, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 24; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G24_R3_524_525) {
    UcpFecCodec enc(24, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 24; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G30_R1_525_526) {
    UcpFecCodec enc(30, 1);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 30; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G30_R2_526_527) {
    UcpFecCodec enc(30, 2);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 30; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}
UCP_TEST_CASE(FEC_Mass_G30_R3_527_528) {
    UcpFecCodec enc(30, 3);
    ucp::vector<uint8_t> p(8, 65);
    int repCount = 0;
    for (int k = 0; k < 30; ++k) {
        if (enc.TryEncodeRepair(p).has_value())
            repCount++;
    }
    UCP_CHECK(repCount > 0);
    ;
}




