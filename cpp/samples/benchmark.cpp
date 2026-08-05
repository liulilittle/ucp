#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <future>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>

#include "ucp/ucp_datagram_network.h"
#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_types.h"

static const int kFragmentBytes = 32 * 1024;
static const int kFragmentCount = 1;
static const int64_t kPayloadBytes = static_cast<int64_t>(kFragmentBytes) * kFragmentCount;
static const int64_t kBandwidthBps = 12500000;
static const int kServerPort = 9990;
static const int kTimeoutMs = 10000;

int main() {
    try {
        std::setvbuf(stdout, NULL, _IONBF, 0);
        std::printf("UCP Performance Benchmark (Smoke Test)\n");
        std::printf("====================================\n");

        auto config = ucp::UcpConfiguration::GetOptimizedConfig();
        config.InitialBandwidthBytesPerSecond = kBandwidthBps;
        config.MaxPacingRateBytesPerSecond = kBandwidthBps;
        config.ServerBandwidthBytesPerSecond = static_cast<int>(kBandwidthBps);

        ucp::UcpDatagramNetwork serverNetwork(config);
        ucp::UcpDatagramNetwork clientNetwork(config);

        ucp::shared_ptr<ucp::UcpServer> server = serverNetwork.CreateServer(kServerPort);
        if (!server) {
            std::printf("FAIL: server creation\n");
            return 1;
        }

        ucp::shared_ptr<ucp::UcpConnection> client = clientNetwork.CreateConnection(config);
        if (!client) {
            std::printf("FAIL: client creation\n");
            return 1;
        }

        std::printf("  Config: 0%% loss, 100 Mbps, %lld KB (%d x %d KB)\n", static_cast<long long>(kPayloadBytes / 1024), kFragmentCount,
                    kFragmentBytes / 1024);

        ucp::UcpConnection* serverConn = NULLPTR;
        auto accept_promise = std::make_shared<std::promise<bool>>();
        auto accept_future = accept_promise->get_future();
        auto accept_fired = std::make_shared<std::atomic<bool>>(false);
        server->AcceptAsync([accept_promise, accept_fired, &serverConn](ucp::UcpError err, ucp::UcpConnection* conn) {
            try {
                bool expected = false;
                if (accept_fired->compare_exchange_strong(expected, true)) {
                    if (err == ucp::UcpError::None && conn) {
                        serverConn = conn;
                    }
                    accept_promise->set_value(err == ucp::UcpError::None);
                }
            } catch (...) {
                accept_promise->set_value(false);
            }
        });

        auto connect_promise = std::make_shared<std::promise<bool>>();
        auto connect_future = connect_promise->get_future();
        auto connect_fired = std::make_shared<std::atomic<bool>>(false);
        client->ConnectAsync("127.0.0.1:9990", [connect_promise, connect_fired](ucp::UcpError err, uint32_t) {
            try {
                bool expected = false;
                if (connect_fired->compare_exchange_strong(expected, true)) {
                    connect_promise->set_value(err == ucp::UcpError::None);
                }
            } catch (...) {
                connect_promise->set_value(false);
            }
        });

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kTimeoutMs);
        bool connected = false;
        bool accepted = false;

        while (!connected || !accepted) {
            serverNetwork.DoEvents();
            clientNetwork.DoEvents();

            if (!connected && connect_future.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready)
                connected = connect_future.get();
            if (!accepted && accept_future.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready)
                accepted = accept_future.get();

            if (std::chrono::steady_clock::now() > deadline)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        if (!connected || !accepted || NULLPTR == serverConn) {
            std::printf("FAIL: handshake timeout\n");
            server->Stop();
            serverNetwork.Dispose();
            clientNetwork.Dispose();
            return 1;
        }

        std::vector<uint8_t> payload(static_cast<size_t>(kPayloadBytes));
        for (size_t i = 0; i < payload.size(); ++i)
            payload[i] = static_cast<uint8_t>(i & 0xFF);

        auto transfer_start = std::chrono::steady_clock::now();

        int written_fragments = 0;
        auto fragment_done = std::make_shared<std::atomic<bool>>(false);

        auto PumpUntil = [&](const std::function<bool()>& done, int timeoutMs) -> bool {
            auto xferDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
            while (!done()) {
                serverNetwork.DoEvents();
                clientNetwork.DoEvents();
                if (std::chrono::steady_clock::now() > xferDeadline)
                    return false;
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return true;
        };

        std::function<std::shared_future<bool>()> sendNextFragment = [&]() -> std::shared_future<bool> {
            if (written_fragments >= kFragmentCount) {
                auto empty_promise = std::make_shared<std::promise<bool>>();
                empty_promise->set_value(false);
                return empty_promise->get_future().share();
            }
            int offset = written_fragments * kFragmentBytes;
            int count = kFragmentBytes;
            written_fragments++;
            auto frag_promise = std::make_shared<std::promise<bool>>();
            auto frag_future = frag_promise->get_future();
            auto frag_fired = std::make_shared<std::atomic<bool>>(false);
            client->WriteAsync(payload.data() + offset, 0, count, [frag_promise, frag_fired](ucp::UcpError, bool ok) {
                try {
                    bool expected = false;
                    if (frag_fired->compare_exchange_strong(expected, true)) {
                        frag_promise->set_value(ok);
                    }
                } catch (...) {
                    frag_promise->set_value(false);
                }
            });
            return frag_future.share();
        };

        auto currentFrag = sendNextFragment();
        int completedFrags = 0;
        auto xferDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kTimeoutMs * kFragmentCount);

        while (completedFrags < kFragmentCount) {
            serverNetwork.DoEvents();
            clientNetwork.DoEvents();

            if (currentFrag.valid() && currentFrag.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready) {
                bool ok = currentFrag.get();
                if (!ok) {
                    std::printf("FAIL: fragment %d write failed\n", completedFrags);
                    server->Stop();
                    serverNetwork.Dispose();
                    clientNetwork.Dispose();
                    return 1;
                }
                completedFrags++;
                if (completedFrags < kFragmentCount) {
                    currentFrag = sendNextFragment();
                }
            }

            if (std::chrono::steady_clock::now() > xferDeadline) {
                std::printf("FAIL: fragment transfer timeout\n");
                server->Stop();
                serverNetwork.Dispose();
                clientNetwork.Dispose();
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        if (!PumpUntil(
                [&]() {
                    if (!serverConn)
                        return true;
                    auto r = serverConn->GetReport();
                    return r.BytesReceived >= kPayloadBytes;
                },
                5000)) {
            std::printf("FAIL: delivery timeout\n");
            server->Stop();
            serverNetwork.Dispose();
            clientNetwork.Dispose();
            return 1;
        }

        if (serverConn) {
            auto serverReport = serverConn->GetReport();
            if (serverReport.BytesReceived != kPayloadBytes) {
                std::printf("FAIL: only %lld of %lld bytes delivered\n", static_cast<long long>(serverReport.BytesReceived),
                            static_cast<long long>(kPayloadBytes));
                server->Stop();
                serverNetwork.Dispose();
                clientNetwork.Dispose();
                return 1;
            }

            double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - transfer_start).count();
            double throughput = (elapsed > 0.0) ? serverReport.BytesReceived * 8.0 / elapsed / 1000000.0 : 0.0;
            std::printf("  PASS: %lld bytes, %.2f Mbps\n", static_cast<long long>(serverReport.BytesReceived), throughput);
        } else {
            std::printf("FAIL: server connection lost\n");
            server->Stop();
            serverNetwork.Dispose();
            clientNetwork.Dispose();
            return 1;
        }

        serverConn = NULLPTR;

        {
            auto close_promise = std::make_shared<std::promise<void>>();
            auto close_future = close_promise->get_future();
            client->CloseAsync([close_promise](ucp::UcpError) {
                try {
                    close_promise->set_value();
                } catch (const std::future_error&) {
                }
            });
            auto close_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (close_future.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready &&
                   std::chrono::steady_clock::now() < close_deadline) {
                serverNetwork.DoEvents();
                clientNetwork.DoEvents();
            }
            if (close_future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
                std::printf("Warning: close timeout\n");
            }
        }
        client.reset();

        server->Stop();
        serverNetwork.Dispose();
        clientNetwork.Dispose();

        std::printf("Benchmark smoke test PASSED\n");
        return 0;
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "FATAL: %s\n", ex.what());
        return 1;
    }
}
