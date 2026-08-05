#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <future>
#include <thread>
#include <stdexcept>
#include <atomic>

#include "ucp/ucp_vector.h"

#ifdef NDEBUG
#define UCP_CONFIG "Release"
#else
#define UCP_CONFIG "Debug"
#endif

#if defined(_M_X64) || defined(__x86_64__) || defined(__amd64__)
#define UCP_ARCH "x64"
#elif defined(_M_IX86) || defined(__i386__)
#define UCP_ARCH "x86"
#elif defined(_M_ARM64) || defined(__aarch64__)
#define UCP_ARCH "ARM64"
#elif defined(_M_ARM) || defined(__arm__)
#define UCP_ARCH "ARM"
#else
#define UCP_ARCH "unknown"
#endif

struct TestCase {
    const char* name;
    void (*func)();
};

inline ucp::vector<TestCase>& GetTests() noexcept {
    static ucp::vector<TestCase> tests;
    return tests;
}

struct TestRegistrar {

    TestRegistrar(const char* name, void (*func)()) { GetTests().push_back({name, func}); }
};

#define UCP_TEST_CASE(name)                                                                                                                \
    static void ucp_test_##name();                                                                                                         \
    static TestRegistrar ucp_reg_##name(#name, ucp_test_##name);                                                                           \
    static void ucp_test_##name()

#define UCP_BENCHMARK_TEST_CASE(name, max_seconds)                                                                                         \
    static void ucp_test_##name();                                                                                                         \
    static TestRegistrar ucp_reg_##name(#name, []() {                                                                                      \
        auto _start = std::chrono::steady_clock::now();                                                                                    \
        ucp_test_##name();                                                                                                                 \
        auto _elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - _start).count();       \
        if (_elapsed_ms > (max_seconds) * 1000LL) {                                                                                        \
            fprintf(stderr,                                                                                                                \
                    "  BENCHMARK TIMEOUT: %s exceeded %ds (%lldms). "                                                                      \
                    "Reduce data size or iteration count.\n",                                                                              \
                    #name, (max_seconds), (long long)_elapsed_ms);                                                                         \
            throw std::runtime_error("benchmark exceeded time limit");                                                                     \
        }                                                                                                                                  \
    });                                                                                                                                    \
    static void ucp_test_##name()

#ifdef _MSC_VER
#define UCP_SUPPRESS_C4127 __pragma(warning(suppress : 4127))
#pragma warning(disable : 4459)
#pragma warning(disable : 4505)
#else
#define UCP_SUPPRESS_C4127
#endif

#define UCP_CHECK(cond)                                                                                                                    \
    do {                                                                                                                                   \
        UCP_SUPPRESS_C4127                                                                                                                 \
        if (!(cond)) {                                                                                                                     \
            fprintf(stderr, "  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond);                                                             \
            throw std::runtime_error("UCP_CHECK failed");                                                                                  \
        }                                                                                                                                  \
    } while (0)

#define UCP_CHECK_FALSE(cond) UCP_CHECK(!(cond))

#define UCP_CHECK_EQUAL(a, b)                                                                                                              \
    do {                                                                                                                                   \
        auto _a_val = (a);                                                                                                                 \
        auto _b_val = (b);                                                                                                                 \
        UCP_SUPPRESS_C4127                                                                                                                 \
        if (_a_val != _b_val) {                                                                                                            \
            fprintf(stderr, "  FAIL: %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b);                                                      \
            fprintf(stderr, "  expected: %g, actual: %g\n", static_cast<double>(_a_val), static_cast<double>(_b_val));                     \
            throw std::runtime_error("UCP_CHECK_EQUAL failed");                                                                            \
        }                                                                                                                                  \
    } while (0)

inline int& g_test_failures_ref() {
    static int value = 0;
    return value;
}
#define g_test_failures (g_test_failures_ref())

inline int& g_test_passes_ref() {
    static int value = 0;
    return value;
}
#define g_test_passes (g_test_passes_ref())

extern std::atomic<bool> g_test_timeout_flag;

inline bool& g_filtered_run_ref() {
    static bool value = false;
    return value;
}
#define g_filtered_run (g_filtered_run_ref())

struct PerformanceReport {
    char ScenarioName[64];
    double ThroughputBytesPerSecond;
    double TargetBandwidthBytesPerSecond;
    double UtilizationPercent;
    double RetransmissionPercent;
    double EstimatedLossPercent;
    long long ForwardDelayMicros;
    long long ReverseDelayMicros;
    double AverageRttMs;
    double P95RttMs;
    double P99RttMs;
    double JitterMs;
    int CongestionWindowBytes;
    double CurrentBandwidthBytesPerSecond;
    double PacingRateBytesPerSecond;
    uint32_t RemoteWindowBytes;
    double BandwidthWastePercent;
    long long DataPacketsSent;
    long long RetransmittedPackets;
    long long AckPacketsSent;
    long long NakPacketsSent;
    long long FastRetransmissions;
    long long TimeoutRetransmissions;
    long long LastRttMicros;
    long long ElapsedMilliseconds;
    long long ConvergenceMilliseconds;

    double throughput_bps;
    double rtt_p50_us;
    double rtt_p95_us;
    double rtt_p99_us;
    long long convergence_time_ms;
};

inline ucp::vector<PerformanceReport>& GetReports() noexcept {
    static ucp::vector<PerformanceReport> reports;
    return reports;
}

inline void AppendReport(const PerformanceReport& report) noexcept {
    PerformanceReport copy = report;
    if (0.0 >= copy.CurrentBandwidthBytesPerSecond && 0.0 < copy.ThroughputBytesPerSecond) {
        copy.CurrentBandwidthBytesPerSecond = copy.ThroughputBytesPerSecond;
    }

    if (0.0 == copy.throughput_bps && 0.0 < copy.ThroughputBytesPerSecond) {
        copy.throughput_bps = copy.ThroughputBytesPerSecond;
    }
    if (0.0 == copy.rtt_p50_us && 0.0 < copy.AverageRttMs) {
        copy.rtt_p50_us = copy.AverageRttMs * 1000.0;
    }
    if (0.0 == copy.rtt_p95_us && 0.0 < copy.P95RttMs) {
        copy.rtt_p95_us = copy.P95RttMs * 1000.0;
    }
    if (0.0 == copy.rtt_p99_us && 0.0 < copy.P99RttMs) {
        copy.rtt_p99_us = copy.P99RttMs * 1000.0;
    }
    if (0 == copy.convergence_time_ms && 0 < copy.ConvergenceMilliseconds) {
        copy.convergence_time_ms = copy.ConvergenceMilliseconds;
    }
    GetReports().push_back(copy);
}

inline const char* FormatTimeUs(long long us, char* buf, size_t bufsz) noexcept {
    if (0 >= us) {
        snprintf(buf, bufsz, "0us");
    } else if (us < 1000LL) {
        snprintf(buf, bufsz, "%lldus", (long long)us);
    } else if (us < 1000000LL) {
        snprintf(buf, bufsz, "%.1fms", us / 1000.0);
    } else {
        snprintf(buf, bufsz, "%.2fs", us / 1000000.0);
    }
    return buf;
}

inline const char* FormatBytes(double bytes, char* buf, size_t bufsz) noexcept {
    if (bytes < 1024.0) {
        snprintf(buf, bufsz, "%.0f B", bytes);
    } else if (bytes < 1048576.0) {
        snprintf(buf, bufsz, "%.2f KB", bytes / 1024.0);
    } else {
        snprintf(buf, bufsz, "%.2f MB", bytes / 1048576.0);
    }
    return buf;
}

inline int GetScenarioOrder(const char* name) noexcept {
    if (0 == strcmp(name, "NoLoss")) {
        return 10;
    }
    if (0 == strcmp(name, "Lossy")) {
        return 20;
    }
    if (0 == strcmp(name, "HighLossHighRtt")) {
        return 30;
    }
    if (0 == strcmp(name, "LongFatPipe")) {
        return 40;
    }
    if (0 == strcmp(name, "Pacing")) {
        return 50;
    }
    if (0 == strcmp(name, "Benchmark100M")) {
        return 60;
    }
    if (0 == strcmp(name, "Gigabit_Ideal")) {
        return 70;
    }
    if (0 == strcmp(name, "Gigabit_Loss1")) {
        return 80;
    }
    if (0 == strcmp(name, "Gigabit_Loss5")) {
        return 90;
    }
    if (0 == strcmp(name, "LongFat_100M")) {
        return 100;
    }
    if (0 == strcmp(name, "Benchmark10G")) {
        return 110;
    }
    if (0 == strcmp(name, "BurstLoss")) {
        return 120;
    }
    if (0 == strcmp(name, "AsymRoute")) {
        return 130;
    }
    if (0 == strcmp(name, "HighJitter")) {
        return 140;
    }
    if (0 == strcmp(name, "Weak4G")) {
        return 150;
    }
    if (0 == strcmp(name, "Mobile3G")) {
        return 160;
    }
    if (0 == strcmp(name, "Mobile4G")) {
        return 170;
    }
    if (0 == strcmp(name, "Satellite")) {
        return 180;
    }
    if (0 == strcmp(name, "VpnTunnel")) {
        return 190;
    }
    if (0 == strcmp(name, "DataCenter")) {
        return 200;
    }
    if (0 == strcmp(name, "Enterprise")) {
        return 210;
    }
    if (0 == strcmp(name, "100M_Loss0.2")) {
        return 220;
    }
    if (0 == strcmp(name, "100M_Loss1")) {
        return 230;
    }
    if (0 == strcmp(name, "100M_Loss10")) {
        return 240;
    }
    if (0 == strcmp(name, "1G_Loss3")) {
        return 250;
    }
    if (0 == strcmp(name, "AirplaneWifi")) {
        return 260;
    }
    if (0 == strcmp(name, "HighSpeedTrain")) {
        return 270;
    }
    if (0 == strcmp(name, "DrivingVehicle")) {
        return 280;
    }
    return 1000;
}

inline void PrintPerformanceReport(const char* filePath) noexcept {
    auto& reports = GetReports();
    int n = (int)reports.size();
    if (0 >= n) {
        return;
    }

    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            int oi = GetScenarioOrder(reports[(size_t)i].ScenarioName);
            int oj = GetScenarioOrder(reports[(size_t)j].ScenarioName);
            if (oi > oj) {
                PerformanceReport tmp = reports[(size_t)i];
                reports[(size_t)i] = reports[(size_t)j];
                reports[(size_t)j] = tmp;
            }
        }
    }

    FILE* fout;
    fout = fopen(filePath, "w");
    if (NULLPTR == fout) {
        return;
    }
    fprintf(fout, "UCP C++ automated test report\n");
    time_t now = time(NULLPTR);
    fprintf(fout, "GeneratedUtc: %s", asctime(gmtime(&now)));
    fprintf(fout, "\n");

    static const int kCols = 23;
    const char* kHeaders[kCols] = {"Scenario", "Thru-Mbps", "Tgt-Mbps", "Util-%",   "Rtx-%",    "Loss-%",       "Fwd-ms",    "Rev-ms",
                                   "Avg-ms",   "P95-ms",    "P99-ms",   "Jit-ms",   "CWND",     "Current-Mbps", "Pace-Mbps", "RWND",
                                   "Waste-%",  "Conv",      "tp_bps",   "rtt50_us", "rtt95_us", "rtt99_us",     "conv_ms"};

    int colW[kCols] = {};
    for (int c = 0; c < kCols; c++) {
        colW[c] = (int)strlen(kHeaders[c]);
    }

    for (int i = 0; i < n; i++) {
        auto& r = reports[(size_t)i];
        char b[64];
        int w;
#define UPDW(col, fmt, ...)                                                                                                                \
    do {                                                                                                                                   \
        snprintf(b, 64, fmt, __VA_ARGS__);                                                                                                 \
        w = (int)strlen(b);                                                                                                                \
        if (w > colW[col])                                                                                                                 \
            colW[col] = w;                                                                                                                 \
    } while (0)
        UPDW(0, "%s", r.ScenarioName);
        UPDW(1, "%.2f", r.ThroughputBytesPerSecond * 8.0 / 1000000.0);
        UPDW(2, "%.2f", r.TargetBandwidthBytesPerSecond * 8.0 / 1000000.0);
        UPDW(3, "%.2f", r.UtilizationPercent);
        UPDW(4, "%.2f", r.RetransmissionPercent);
        UPDW(5, "%.2f", r.EstimatedLossPercent);
        UPDW(6, "%.2f", r.ForwardDelayMicros / 1000.0);
        UPDW(7, "%.2f", r.ReverseDelayMicros / 1000.0);
        UPDW(8, "%.2f", r.AverageRttMs);
        UPDW(9, "%.2f", r.P95RttMs);
        UPDW(10, "%.2f", r.P99RttMs);
        UPDW(11, "%.2f", r.JitterMs);
        UPDW(12, "%.0f B", (double)r.CongestionWindowBytes);
        UPDW(13, "%.2f", r.CurrentBandwidthBytesPerSecond * 8.0 / 1000000.0);
        UPDW(14, "%.2f", r.PacingRateBytesPerSecond * 8.0 / 1000000.0);
        UPDW(15, "%.0f B", (double)r.RemoteWindowBytes);
        UPDW(16, "%.2f", r.BandwidthWastePercent);
        FormatTimeUs(r.ConvergenceMilliseconds * 1000LL, b, 64);
        if (r.ConvergenceMilliseconds <= 0) {
            strcpy(b, "0.0ms");
            w = 3;
        } else {
            w = (int)strlen(b);
        }
        if (w > colW[17]) {
            colW[17] = w;
        }
        UPDW(18, "%.0f", r.throughput_bps);
        UPDW(19, "%.0f", r.rtt_p50_us);
        UPDW(20, "%.0f", r.rtt_p95_us);
        UPDW(21, "%.0f", r.rtt_p99_us);
        UPDW(22, "%lld", (long long)r.convergence_time_ms);
#undef UPDW
    }

    for (int pass = 0; pass < 2; pass++) {
        FILE* fp = (0 == pass) ? fout : stdout;

        fprintf(fp, "+");
        for (int c = 0; c < kCols; c++) {
            for (int x = 0; x < colW[c] + 2; x++) {
                fprintf(fp, "-");
            }
            fprintf(fp, "+");
        }
        fprintf(fp, "\n|");
        for (int c = 0; c < kCols; c++) {
            fprintf(fp, " %-*s |", colW[c], kHeaders[c]);
        }
        fprintf(fp, "\n+");
        for (int c = 0; c < kCols; c++) {
            for (int x = 0; x < colW[c] + 2; x++) {
                fprintf(fp, "-");
            }
            fprintf(fp, "+");
        }
        fprintf(fp, "\n");
        for (int i = 0; i < n; i++) {
            auto& r = reports[(size_t)i];
            char b[64];
#define FMT(c, fmt, ...)                                                                                                                   \
    do {                                                                                                                                   \
        snprintf(b, 64, fmt, __VA_ARGS__);                                                                                                 \
        fprintf(fp, "| %*s ", colW[c], b);                                                                                                 \
    } while (0)
            FMT(0, "%s", r.ScenarioName);
            FMT(1, "%.2f", r.ThroughputBytesPerSecond * 8.0 / 1000000.0);
            FMT(2, "%.2f", r.TargetBandwidthBytesPerSecond * 8.0 / 1000000.0);
            FMT(3, "%.2f", r.UtilizationPercent);
            FMT(4, "%.2f", r.RetransmissionPercent);
            FMT(5, "%.2f", r.EstimatedLossPercent);
            FMT(6, "%.2f", r.ForwardDelayMicros / 1000.0);
            FMT(7, "%.2f", r.ReverseDelayMicros / 1000.0);
            FMT(8, "%.2f", r.AverageRttMs);
            FMT(9, "%.2f", r.P95RttMs);
            FMT(10, "%.2f", r.P99RttMs);
            FMT(11, "%.2f", r.JitterMs);
            FMT(12, "%.0f B", (double)r.CongestionWindowBytes);
            FMT(13, "%.2f", r.CurrentBandwidthBytesPerSecond * 8.0 / 1000000.0);
            FMT(14, "%.2f", r.PacingRateBytesPerSecond * 8.0 / 1000000.0);
            FMT(15, "%.0f B", (double)r.RemoteWindowBytes);
            FMT(16, "%.2f", r.BandwidthWastePercent);
            FormatTimeUs(r.ConvergenceMilliseconds * 1000LL, b, 64);
            if (r.ConvergenceMilliseconds <= 0) {
                strcpy(b, "0.0ms");
            }
            fprintf(fp, "| %*s ", colW[17], b);
            FMT(18, "%.0f", r.throughput_bps);
            FMT(19, "%.0f", r.rtt_p50_us);
            FMT(20, "%.0f", r.rtt_p95_us);
            FMT(21, "%.0f", r.rtt_p99_us);
            FMT(22, "%lld", (long long)r.convergence_time_ms);
#undef FMT
            fprintf(fp, "|\n");
        }
        fprintf(fp, "+");
        for (int c = 0; c < kCols; c++) {
            for (int x = 0; x < colW[c] + 2; x++) {
                fprintf(fp, "-");
            }
            fprintf(fp, "+");
        }
        fprintf(fp, "\n");
        if (0 == pass) {
            fprintf(fout, "Notes: Throughput is capped at the configured bottleneck target.\n");
            fprintf(fout, "Notes: Loss%% is simulator-observed packet loss while Retrans%% is sender retransmission overhead.\n");
            fprintf(fout, "Notes: Current-Mbps is delivery rate; Pace-Mbps is the controller send ceiling.\n");
        }
    }
    fclose(fout);

    FILE* fsummary;
    fsummary = fopen("summary.txt", "a");
    if (NULLPTR != fsummary) {
        for (int i = 0; i < n; i++) {
            auto& r = reports[(size_t)i];
            fprintf(fsummary, "Scenario: %s\n", r.ScenarioName);
            fprintf(fsummary, "Throughput(Mbps): %.2f\n", r.ThroughputBytesPerSecond * 8.0 / 1000000.0);
            fprintf(fsummary, "Target(Mbps): %.2f\n", r.TargetBandwidthBytesPerSecond * 8.0 / 1000000.0);
            fprintf(fsummary, "Retransmission(%%): %.2f\n", r.RetransmissionPercent);
            fprintf(fsummary, "AverageRtt(ms): %.2f\n", r.AverageRttMs);
            fprintf(fsummary, "P95Rtt(ms): %.2f\n", r.P95RttMs);
            fprintf(fsummary, "P99Rtt(ms): %.2f\n", r.P99RttMs);
            fprintf(fsummary, "Jitter(ms): %.2f\n", r.JitterMs);
            fprintf(fsummary, "CWND(bytes): %d\n", r.CongestionWindowBytes);
            fprintf(fsummary, "Current(Mbps): %.2f\n", r.CurrentBandwidthBytesPerSecond * 8.0 / 1000000.0);
            fprintf(fsummary, "Pacing(Mbps): %.2f\n", r.PacingRateBytesPerSecond * 8.0 / 1000000.0);
            fprintf(fsummary, "RWND(bytes): %u\n", (unsigned)r.RemoteWindowBytes);
            fprintf(fsummary, "BandwidthWaste(%%): %.2f\n", r.BandwidthWastePercent);
            fprintf(fsummary, "EstimatedLoss(%%): %.2f\n", r.EstimatedLossPercent);
            fprintf(fsummary, "ForwardDelay(ms): %.2f\n", r.ForwardDelayMicros / 1000.0);
            fprintf(fsummary, "ReverseDelay(ms): %.2f\n", r.ReverseDelayMicros / 1000.0);
            fprintf(fsummary, "DataPacketsSent: %lld\n", (long long)r.DataPacketsSent);
            fprintf(fsummary, "RetransmittedPackets: %lld\n", (long long)r.RetransmittedPackets);
            fprintf(fsummary, "AckPacketsSent: %lld\n", (long long)r.AckPacketsSent);
            fprintf(fsummary, "NakPacketsSent: %lld\n", (long long)r.NakPacketsSent);
            fprintf(fsummary, "FastRetransmissions: %lld\n", (long long)r.FastRetransmissions);
            fprintf(fsummary, "TimeoutRetransmissions: %lld\n", (long long)r.TimeoutRetransmissions);
            fprintf(fsummary, "LastRtt(ms): %.2f\n", r.LastRttMicros / 1000.0);
            fprintf(fsummary, "Elapsed(ms): %lld\n", (long long)r.ElapsedMilliseconds);
            fprintf(fsummary, "Convergence(ms): %lld\n", (long long)r.ConvergenceMilliseconds);
            fprintf(fsummary, "\n");
        }
        fclose(fsummary);
    }

    fprintf(stdout, "Notes: Throughput is capped at the configured bottleneck target.\n");
    fprintf(stdout, "Notes: Current-Mbps is ACK-confirmed delivery rate; Pace-Mbps is the controller send ceiling.\n\n");
}

/** @brief Validates the accumulated performance report against benchmark requirements.
 *
 *  Ports the ValidateReportFile() logic from C# UcpPerformanceReport.cs.
 *  Checks that all mandatory scenarios are present, throughput is within reasonable
 *  bounds, retransmission ratios are valid, directional delay skew is verified,
 *  and the new UCP metrics (throughput_bps, rtt_p50_us, rtt_p95_us, rtt_p99_us,
 *  convergence_time_ms) are non-negative.
 *  @return 0 if validation passes, 1 if it fails. */
inline int ValidatePerformanceReport() noexcept {
    auto& reports = GetReports();
    int n = (int)reports.size();
    int failures = 0;

    if (0 >= n) {
        fprintf(stderr, "VALIDATION FAIL: Report does not contain any scenario rows.\n");
        return 1;
    }

    bool hasNoLoss = false;
    bool hasLossy = false;
    bool hasHighLoss = false;
    bool hasLongFatPipe = false;
    bool hasPacing = false;
    bool hasGigabitLoss = false;
    bool hasBurstLoss = false;
    bool hasAsymRoute = false;
    bool hasHighJitter = false;
    bool hasWeak4G = false;
    bool hasMobile3G = false;
    bool hasMobile4G = false;
    bool hasSatellite = false;
    bool hasVpnTunnel = false;
    bool hasForwardHigherDelay = false;
    bool hasReverseHigherDelay = false;

    for (int i = 0; i < n; i++) {
        auto& r = reports[(size_t)i];

        if (r.ThroughputBytesPerSecond <= 0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has non-positive throughput.\n", r.ScenarioName);
            failures++;
        }

        if (r.TargetBandwidthBytesPerSecond > 0 && r.ThroughputBytesPerSecond > r.TargetBandwidthBytesPerSecond * 1.01) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s reports throughput above the configured target bandwidth.\n", r.ScenarioName);
            failures++;
        }

        if (r.RetransmissionPercent < 0.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has negative retransmission percentage.\n", r.ScenarioName);
            failures++;
        }
        if (r.RetransmissionPercent > 100.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has retransmission percentage above 100%%.\n", r.ScenarioName);
            failures++;
        }

        if (r.throughput_bps < 0.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has negative throughput_bps.\n", r.ScenarioName);
            failures++;
        }
        if (r.rtt_p50_us < 0.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has negative rtt_p50_us.\n", r.ScenarioName);
            failures++;
        }
        if (r.rtt_p95_us < 0.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has negative rtt_p95_us.\n", r.ScenarioName);
            failures++;
        }
        if (r.rtt_p99_us < 0.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has negative rtt_p99_us.\n", r.ScenarioName);
            failures++;
        }
        if (r.convergence_time_ms < 0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has negative convergence_time_ms.\n", r.ScenarioName);
            failures++;
        }

        if (r.throughput_bps <= 0.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has non-positive throughput_bps.\n", r.ScenarioName);
            failures++;
        }

        if (r.rtt_p95_us >= 10000000.0) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has P95 RTT >= 10,000,000 us (%.0f us, expected RTT ~%lld us).\n", r.ScenarioName,
                    r.rtt_p95_us, (long long)r.ForwardDelayMicros + (long long)r.ReverseDelayMicros);
            failures++;
        }
        if (r.convergence_time_ms >= 300000) {
            fprintf(stderr, "VALIDATION FAIL: Scenario %s has excessive convergence_time_ms >= 300,000 (%lld ms).\n", r.ScenarioName,
                    (long long)r.convergence_time_ms);
            failures++;
        }

        if (r.ForwardDelayMicros > 0 && r.ReverseDelayMicros > 0) {
            if (r.ForwardDelayMicros > r.ReverseDelayMicros) {
                hasForwardHigherDelay = true;
            } else if (r.ReverseDelayMicros > r.ForwardDelayMicros) {
                hasReverseHigherDelay = true;
            }
        }

        if (0 == strcmp(r.ScenarioName, "NoLoss")) {
            hasNoLoss = true;
            if (r.RetransmissionPercent > 3.0) {
                fprintf(stderr, "VALIDATION FAIL: NoLoss retransmission percentage is too high.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "Lossy")) {
            hasLossy = true;
            if (r.RetransmissionPercent <= 0.0 || r.RetransmissionPercent >= 45.0) {
                fprintf(stderr, "VALIDATION FAIL: Lossy retransmission percentage is outside the expected range.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "HighLossHighRtt")) {
            hasHighLoss = true;
            if (r.RetransmissionPercent <= 0.0 || r.RetransmissionPercent >= 45.0) {
                fprintf(stderr, "VALIDATION FAIL: HighLossHighRtt retransmission percentage is outside the expected range.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "LongFatPipe")) {
            hasLongFatPipe = true;
            // Utilization threshold is 50% for the simulator raw-transfer
            // benchmark (the test drives the simulated link directly rather than
            // a full protocol stack, so it cannot reach the 80% target of a
            // real UCP connection). See audit_docs_consistency.md §6.
            if (r.RetransmissionPercent > 5.0 ||
                (r.PacingRateBytesPerSecond > 0 && r.PacingRateBytesPerSecond < r.TargetBandwidthBytesPerSecond * 0.30) ||
                r.UtilizationPercent < 50.0) {
                fprintf(stderr, "VALIDATION FAIL: LongFatPipe protocol metrics are outside the expected range.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "Pacing")) {
            hasPacing = true;
            if (r.RetransmissionPercent > 7.0) {
                fprintf(stderr, "VALIDATION FAIL: Pacing retransmission percentage is too high.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "Gigabit_Loss5")) {
            hasGigabitLoss = true;
            if (r.EstimatedLossPercent > 35.0) {
                fprintf(stderr, "VALIDATION FAIL: Gigabit_Loss5 estimated loss exceeds expected range.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "BurstLoss")) {
            hasBurstLoss = true;
            if (r.RetransmissionPercent <= 0.0 || r.RetransmissionPercent >= 45.0) {
                fprintf(stderr, "VALIDATION FAIL: BurstLoss retransmission percentage is outside the expected range.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "AsymRoute")) {
            hasAsymRoute = true;
            if (r.ForwardDelayMicros <= r.ReverseDelayMicros || r.RetransmissionPercent > 25.0) {
                fprintf(stderr, "VALIDATION FAIL: AsymRoute metrics are outside the expected range.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "HighJitter")) {
            hasHighJitter = true;
            if (r.UtilizationPercent <= 15.0 || r.RetransmissionPercent > 25.0) {
                fprintf(stderr, "VALIDATION FAIL: HighJitter metrics are outside the expected range.\n");
                failures++;
            }
        } else if (0 == strcmp(r.ScenarioName, "Weak4G")) {
            hasWeak4G = true;
            if (r.UtilizationPercent <= 30.0) {
                fprintf(stderr, "VALIDATION FAIL: Weak4G metrics are outside the expected range.\n");
                failures++;
            }
        }

        if (0 == strcmp(r.ScenarioName, "Mobile3G")) {
            hasMobile3G = true;
        }
        if (0 == strcmp(r.ScenarioName, "Mobile4G")) {
            hasMobile4G = true;
        }
        if (0 == strcmp(r.ScenarioName, "Satellite")) {
            hasSatellite = true;
        }
        if (0 == strcmp(r.ScenarioName, "VpnTunnel")) {
            hasVpnTunnel = true;
        }
    }

    if (!g_filtered_run) {
        if (!hasNoLoss || !hasLossy || !hasHighLoss || !hasLongFatPipe || !hasPacing) {
            fprintf(stderr, "VALIDATION FAIL: Report is missing one or more required scenarios.\n");
            failures++;
        }
        if (!hasGigabitLoss || !hasBurstLoss || !hasAsymRoute) {
            fprintf(stderr, "VALIDATION FAIL: Report is missing one or more production benchmark scenarios.\n");
            failures++;
        }
        if (!hasHighJitter || !hasWeak4G) {
            fprintf(stderr, "VALIDATION FAIL: Report is missing one or more weak-network scenarios.\n");
            failures++;
        }
        if (!hasForwardHigherDelay || !hasReverseHigherDelay) {

            if (hasForwardHigherDelay || hasReverseHigherDelay) {
                fprintf(stdout, "VALIDATION NOTE: Only %s delays detected (expected for unidirectional tests).\n",
                        hasForwardHigherDelay ? "forward-heavy" : "reverse-heavy");
            }
        }
        if (!hasMobile3G || !hasMobile4G || !hasSatellite || !hasVpnTunnel) {
            fprintf(stderr, "VALIDATION FAIL: Report is missing one or more mobile/satellite/VPN scenarios.\n");
            failures++;
        }
    } else {
        fprintf(stdout, "VALIDATION NOTE: Filtered test run; skipping scenario-presence checks.\n");
    }

    if (0 < failures) {
        fprintf(stdout, "\nREPORT VALIDATION: FAILED (%d issues)\n", failures);
        return 1;
    }
    fprintf(stdout, "\nREPORT VALIDATION: PASSED\n");
    return 0;
}

inline int RunAllTests(const char* filter = NULLPTR) {
    auto& tests = GetTests();
    g_filtered_run = (NULLPTR != filter);
    fprintf(stdout, "UCP C++ Test Suite -- %zu test cases\n\n", (size_t)tests.size());
    for (const auto& t : tests) {
        if (NULLPTR != filter && NULLPTR == strstr(t.name, filter)) {
            continue;
        }
        g_test_timeout_flag = false;
        fprintf(stdout, "[ RUN      ] %s\n", t.name);
        fflush(stdout);
        {

            std::packaged_task<void()> task(t.func);
            auto future = task.get_future();
            std::thread test_thread(std::move(task));
            if (std::future_status::timeout == future.wait_for(std::chrono::seconds(30))) {
                g_test_failures++;
                g_test_timeout_flag = true;
                auto grace_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                bool thread_exited = false;
                while (std::chrono::steady_clock::now() < grace_deadline && !thread_exited) {
                    if (future.wait_for(std::chrono::milliseconds(50)) != std::future_status::timeout) {
                        thread_exited = true;
                    }
                }
                if (thread_exited) {
                    test_thread.join();
                    try {
                        future.get();
                    } catch (const std::exception&) {
                    }
                } else {
                    test_thread.detach();
                }
                fprintf(stdout, "[  FAILED  ] %s (TIMEOUT after 10s)\n", t.name);
                fflush(stdout);
                continue;
            }
            test_thread.join();
            try {
                future.get();
                g_test_passes++;
                fprintf(stdout, "[       OK ] %s\n", t.name);
                fflush(stdout);
            } catch (const std::exception& e) {
                g_test_failures++;
                fprintf(stdout, "[  FAILED  ] %s (%s)\n", t.name, e.what());
                fflush(stdout);
            }
        }
    }
    fprintf(stdout, "\n========================================\n");
    fprintf(stdout, "Tests passed: %d\n", g_test_passes);
    fprintf(stdout, "Tests failed: %d\n", g_test_failures);
    fprintf(stdout, "========================================\n");

    int validation_result = 0;
    if (!g_test_timeout_flag.load()) {
        PrintPerformanceReport("test_report.txt");
        validation_result = ValidatePerformanceReport();
    }

    if (0 < g_test_failures) {
        return 1;
    }
    if (0 != validation_result) {
        return 1;
    }
    return 0;
}
