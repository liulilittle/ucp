#include <chrono>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <thread>
#include <string>
#include <mutex>
#include <vector>
#include <algorithm>
#include <future>
#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_types.h"
#include "ucp/ucp_datagram_network.h"

namespace {
constexpr int kDefaultPort = 9000;
constexpr int kDefaultBandwidthMbps = 100;
constexpr int kRecvBufSize = 65536;
std::atomic<std::sig_atomic_t> g_stop_requested{0};
void OnShutdownSignal(int) noexcept {
    g_stop_requested = 1;
}
int64_t MbpsToBytesPerSec(int64_t mbps) noexcept {
    return mbps * 125000;
}
int TryParseInt(const char* s, int fb = 0) noexcept {
    try {
        return std::stoi(s);
    } catch (...) {
        return fb;
    }
}

struct EchoSession {
    ucp::UcpConnection* conn = nullptr;
    uint32_t connId = 0;
    int64_t totalBytes = 0;
    std::chrono::steady_clock::time_point start;
    std::chrono::steady_clock::time_point tick5s;
    bool greeting = false;
    std::atomic<bool> closing{false};
    ucp::vector<uint8_t> buf;
    explicit EchoSession() : buf(kRecvBufSize) {}
};

std::mutex g_mutex;
std::vector<ucp::shared_ptr<EchoSession>> g_sessions;
std::atomic<int> g_completed{0};
int g_autoexitN = 0;

void TSN(char* b, size_t sz) {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::snprintf(b, sz, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void PrintStats(ucp::shared_ptr<EchoSession> s) {
    s->tick5s = std::chrono::steady_clock::now();
    if (!s || !s->conn)
        return;
    auto rpt = s->conn->GetReport();
    double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - s->start).count();
    double th = el > 0 ? s->totalBytes * 8.0 / el / 1e6 : 0;
    char ts[16];
    TSN(ts, sizeof(ts));
    std::printf("[%s] C%08X: %.2f MB %.2f Mbps RTT %.2f ms CWND %dB Retx %.1f%%\n", ts, s->connId, s->totalBytes / 1e6, th,
                rpt.LastRttMicros / 1e3, (int)rpt.CongestionWindowBytes, rpt.RetransmissionRatio() * 100);
}

void RemoveSession(ucp::shared_ptr<EchoSession> s) {
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        auto it = std::find(g_sessions.begin(), g_sessions.end(), s);
        if (it != g_sessions.end())
            g_sessions.erase(it);
    }
    g_completed.fetch_add(1);
}

void BeginReceive(ucp::shared_ptr<EchoSession> s);
void BeginEchoWrite(ucp::shared_ptr<EchoSession> s, int32_t n);

void OnRecv(ucp::shared_ptr<EchoSession> s, int32_t n) {
    if (!s || !s->conn)
        return;
    if (n <= 0) {
        RemoveSession(s);
        return;
    }
    if (!s->greeting) {
        s->greeting = true;
        char ts[16];
        TSN(ts, sizeof(ts));
        std::printf("[%s] First data from %08X\n", ts, s->connId);
    }
    s->totalBytes += n;

    BeginEchoWrite(s, n);
    BeginReceive(s);
}

void OnEchoSent(ucp::shared_ptr<EchoSession> s, ucp::UcpError e, bool ok) {
    if (e != ucp::UcpError::None || !ok) {
        RemoveSession(s);
        return;
    }
    auto now = std::chrono::steady_clock::now();
    if (now - s->tick5s > std::chrono::seconds(5))
        PrintStats(s);
}

void BeginEchoWrite(ucp::shared_ptr<EchoSession> s, int32_t n) {
    if (!s->conn || g_stop_requested)
        return;
    s->conn->WriteAsync(s->buf.data(), 0, n, [s](ucp::UcpError e, bool ok) { OnEchoSent(s, e, ok); });
}

void BeginReceive(ucp::shared_ptr<EchoSession> s) {
    if (!s->conn || g_stop_requested) {
        if (s->conn)
            RemoveSession(s);
        return;
    }
    s->conn->ReceiveAsync(s->buf.data(), 0, kRecvBufSize, [s](ucp::UcpError e, int32_t n) {
        if (e != ucp::UcpError::None) {
            if (e != ucp::UcpError::Closed && e != ucp::UcpError::ShuttingDown)
                RemoveSession(s);
            return;
        }
        OnRecv(s, n);
    });
}

} // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    std::signal(SIGINT, OnShutdownSignal);
    int port = kDefaultPort, bwMbps = kDefaultBandwidthMbps;
    for (int i = 1; i < argc; ++i) {
        ucp::string a(argv[i]);
        if ("--port" == a && i + 1 < argc)
            port = TryParseInt(argv[++i], kDefaultPort);
        else if ("--bandwidth" == a && i + 1 < argc)
            bwMbps = TryParseInt(argv[++i], kDefaultBandwidthMbps);
        else if ("--autoexit" == a)
            g_autoexitN = (i + 1 < argc && argv[i + 1][0] != '-') ? TryParseInt(argv[++i], 1) : 1;
        else if ("--trace" == a)
            ucp::UcpSetTraceEnabled(true);
        else if ("--help" == a) {
            std::printf("Usage: %s [--port PORT] [--bandwidth MBPS] [--autoexit N] [--trace] [--help]\n", argv[0]);
            return 0;
        }
    }
    int64_t bw = MbpsToBytesPerSec(bwMbps);
    auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
    cfg.ServerBandwidthBytesPerSecond = (int)bw;
    cfg.InitialBandwidthBytesPerSecond = bw;
    cfg.MaxPacingRateBytesPerSecond = bw;
    cfg.SetSendBufferSize(64 * 1024 * 1024);
    cfg.SetReceiveBufferSize(64 * 1024 * 1024);
    ucp::UcpDatagramNetwork net(cfg);
    auto srv = net.CreateServer(port);
    if (!srv) {
        std::fprintf(stderr, "FAIL: create server\n");
        return 1;
    }
    std::printf("UCP Echo Server port %d (%d Mbps)\n", port, bwMbps);
    std::atomic<bool> stopped{false};
    ucp::function<void(ucp::UcpError, ucp::UcpConnection*)> onAccept;
    onAccept = [&](ucp::UcpError e, ucp::UcpConnection* c) {
        if (e != ucp::UcpError::None || !c) {
            stopped = true;
            return;
        }
        auto s = ucp::make_shared_object<EchoSession>();
        s->conn = c;
        s->connId = c->GetConnectionId();
        s->start = std::chrono::steady_clock::now();
        s->tick5s = s->start;
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            g_sessions.push_back(s);
        }
        char ts[16];
        TSN(ts, sizeof(ts));
        std::printf("[%s] Accept %08X\n", ts, s->connId);
        BeginReceive(s);
        if (!g_stop_requested)
            srv->AcceptAsync(onAccept);
    };
    srv->AcceptAsync(onAccept);
    auto lastTick = std::chrono::steady_clock::now();
    int idle = 0;
    while (!stopped && !g_stop_requested) {
        int ev = net.DoEvents();
        idle = (ev == 0) ? idle + 1 : 0;
        if (idle > 30000) {
            std::printf("Stalled.\n");
            stopped = true;
        }
        if (g_autoexitN > 0 && g_completed >= g_autoexitN) {
            std::printf("Autoexit.\n");
            stopped = true;
        }
        auto now = std::chrono::steady_clock::now();
        if (now - lastTick > std::chrono::seconds(5)) {
            lastTick = now;
            char ts[16];
            TSN(ts, sizeof(ts));
            size_t n = 0;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                n = g_sessions.size();
            }
            std::printf("[%s] %zu active\n", ts, n);
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for (auto& s : g_sessions) {
            if (s && s->conn) {
                s->conn->CloseAsync([](ucp::UcpError) {});
                s->conn = nullptr;
            }
        }
        g_sessions.clear();
    }
    srv->Stop();
    net.Dispose();
    return 0;
}
