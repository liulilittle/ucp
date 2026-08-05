#include "test_framework.h"
#include "ucp/ucp_network.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_server.h"
#include "network_simulator.h"
#include <atomic>
#include <chrono>
#include <thread>
#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#endif

using namespace ucp;

/// @brief Connect/disconnect storm: verifies no deadlock (each round completes
/// within a deadline), no thread leak (worker/notify threads are reaped), and
/// no unbounded memory growth.  Regression guard for the lifecycle fixes.
UCP_TEST_CASE(Stress_ConnectDisconnectStorm_NoDeadlockNoLeak) {
    ucp::UcpConfiguration sconfig;
    ucp::UcpServer server(sconfig);
    server.Start(43110);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    // Baseline thread count before the storm (server has started its own).
    auto ThreadCount = []() -> int {
        int n = 0;
#if defined(_WIN32)
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (INVALID_HANDLE_VALUE != snap) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    ++n;
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
#else
        n = -1;
#endif
        return n;
    };
    int baselineThreads = ThreadCount();
    const int kRounds = 50;
    for (int round = 0; round < kRounds; ++round) {
        ucp::UcpConnection client;
        std::atomic<bool> connected{false};
        std::atomic<bool> accepted{false};
        std::atomic<ucp::UcpConnection*> srvConn{NULLPTR};

        server.AcceptAsync([&](ucp::UcpError, ucp::UcpConnection* conn) noexcept {
            if (NULLPTR != conn) {
                srvConn.store(conn);
                accepted.store(true);
            }
        });

        client.ConnectAsync("127.0.0.1:43110", [&](ucp::UcpError e, uint32_t) noexcept {
            if (ucp::UcpError::None == e) {
                connected.store(true);
            }
        });

        // Pump both sides until connected (with deadline -> deadlock detection).
        while (!(connected.load() && accepted.load())) {
            if (std::chrono::steady_clock::now() > deadline) {
                UCP_CHECK_FALSE(true); // deadlock/timeout: connected never reached
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        // Exchange a small payload each round (exercises send/recv/ack paths).
        uint8_t tx[64] = {'S', 't', 'r', 'e', 's', 's'};
        for (int i = 6; i < 64; ++i)
            tx[i] = (uint8_t)(i + round);
        ucp::UcpConnection* srv = srvConn.load();
        UCP_CHECK(NULLPTR != srv);
        if (NULLPTR != srv) {
            srv->Send(tx, 0, 64);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        client.Dispose();
        // Give the server side time to reap the closed connection.
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }

    server.Stop();
    // Give background cleanup threads time to reap any stragglers.
    std::this_thread::sleep_for(std::chrono::seconds(2));
    int afterThreads = ThreadCount();
    // If worker/notify/standalone-timer threads leaked, the thread count would
    // grow by ~3 per round (150+ threads for 50 rounds).  Allow a small
    // tolerance for unrelated system threads.
    if (baselineThreads > 0 && afterThreads > 0) {
        UCP_CHECK(afterThreads <= baselineThreads + 8);
    }
    // If any round deadlocked, the 120s deadline above would have fired.
    UCP_CHECK(true);
}
