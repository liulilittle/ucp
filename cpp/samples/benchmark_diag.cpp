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

static const int kPayloadBytes = 32 * 1024;
static const int64_t kBandwidthBps = 12500000;
static const int kServerPort = 9991;
static const int kTimeoutMs = 10000;

int main() {
    try {
        std::setvbuf(stdout, NULL, _IONBF, 0);
        std::printf("UCP Diagnostic Benchmark\n");
        std::printf("================================================================================\n");

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

        std::printf("  Payload: %d KB, Bandwidth: %.1f Mbps\n", kPayloadBytes / 1024, static_cast<double>(kBandwidthBps) / 125000.0);

        ucp::UcpConnection* serverConn = NULLPTR;
        auto accept_promise = std::make_shared<std::promise<ucp::UcpConnection*>>();
        auto accept_future = accept_promise->get_future();
        auto accept_fired = std::make_shared<std::atomic<bool>>(false);
        server->AcceptAsync([accept_promise, accept_fired](ucp::UcpError err, ucp::UcpConnection* conn) {
            try {
                bool expected = false;
                if (accept_fired->compare_exchange_strong(expected, true)) {
                    accept_promise->set_value(err == ucp::UcpError::None ? conn : NULLPTR);
                }
            } catch (...) {
                accept_promise->set_value(NULLPTR);
            }
        });

        auto connect_promise = std::make_shared<std::promise<bool>>();
        auto connect_future = connect_promise->get_future();
        auto connect_fired = std::make_shared<std::atomic<bool>>(false);
        client->ConnectAsync("127.0.0.1:9991", [connect_promise, connect_fired](ucp::UcpError err, uint32_t) {
            try {
                bool expected = false;
                if (connect_fired->compare_exchange_strong(expected, true)) {
                    connect_promise->set_value(err == ucp::UcpError::None);
                }
            } catch (...) {
                connect_promise->set_value(false);
            }
        });

        bool connected = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kTimeoutMs);

        while (!connected || NULLPTR == serverConn) {
            serverNetwork.DoEvents();
            clientNetwork.DoEvents();

            if (!connected && connect_future.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready)
                connected = connect_future.get();
            if (NULLPTR == serverConn && accept_future.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready)
                serverConn = accept_future.get();

            if (std::chrono::steady_clock::now() > deadline)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        if (!connected || NULLPTR == serverConn) {
            std::printf("FAIL: handshake timeout\n");
            server->Stop();
            serverNetwork.Dispose();
            clientNetwork.Dispose();
            return 1;
        }

        std::printf("  Handshake: OK\n");

        std::vector<uint8_t> payload(kPayloadBytes);
        for (int i = 0; i < kPayloadBytes; ++i)
            payload[i] = static_cast<uint8_t>(i & 0xFF);

        auto write_promise = std::make_shared<std::promise<bool>>();
        auto write_future = write_promise->get_future();
        auto write_fired = std::make_shared<std::atomic<bool>>(false);
        client->WriteAsync(payload.data(), 0, payload.size(), [write_promise, write_fired](ucp::UcpError, bool ok) {
            try {
                bool expected = false;
                if (write_fired->compare_exchange_strong(expected, true)) {
                    write_promise->set_value(ok);
                }
            } catch (...) {
                write_promise->set_value(false);
            }
        });

        bool writeOk = false;
        auto xferDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kTimeoutMs);

        while (!writeOk) {
            serverNetwork.DoEvents();
            clientNetwork.DoEvents();

            if (write_future.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready)
                writeOk = write_future.get();

            if (std::chrono::steady_clock::now() > xferDeadline)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        if (!writeOk) {
            std::printf("FAIL: transfer timeout\n");
            server->Stop();
            serverNetwork.Dispose();
            clientNetwork.Dispose();
            return 1;
        }

        auto pumpDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
        int64_t delivered = 0;
        while (delivered < kPayloadBytes) {
            serverNetwork.DoEvents();
            clientNetwork.DoEvents();

            if (serverConn) {
                auto sr = serverConn->GetReport();
                delivered = sr.BytesReceived;
            }
            if (std::chrono::steady_clock::now() > pumpDeadline)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        auto clientReport = client->GetReport();

        if (delivered != kPayloadBytes) {
            std::printf("FAIL: only %lld of %d bytes delivered to receiver\n", static_cast<long long>(delivered), kPayloadBytes);
            server->Stop();
            serverNetwork.Dispose();
            clientNetwork.Dispose();
            return 1;
        }

        auto serverDiag = serverConn->GetDiagnostics();
        auto clientDiag = client->GetDiagnostics();

        std::printf("  Transfer: %lld bytes, OK\n", static_cast<long long>(clientReport.BytesSent));
        std::printf("\n");
        std::printf("--- Connection Diagnostics (Server) ---\n");
        std::printf("  State: %d, Flight: %lld B, CWND: %d B\n", serverDiag.State, static_cast<long long>(serverDiag.FlightBytes),
                    serverDiag.CongestionWindowBytes);
        std::printf("  Pacing: %.0f B/s, Measured BW: %.0f B/s (%.1f Mbps)\n", serverDiag.PacingRateBytesPerSecond,
                    serverDiag.MeasuredBandwidthBytesPerSecond, serverDiag.MeasuredBandwidthBytesPerSecond * 8.0 / 1000000.0);
        std::printf("  RTT last: %lld us, min: %lld us, loss: %.1f%%\n", static_cast<long long>(serverDiag.LastRttMicros),
                    static_cast<long long>(serverDiag.MinRttMicros), serverDiag.EstimatedLossPercent);

        std::printf("\n--- Connection Diagnostics (Client) ---\n");
        std::printf("  State: %d, Flight: %lld B, CWND: %d B\n", clientDiag.State, static_cast<long long>(clientDiag.FlightBytes),
                    clientDiag.CongestionWindowBytes);
        std::printf("  Pacing: %.0f B/s, Measured BW: %.0f B/s (%.1f Mbps)\n", clientDiag.PacingRateBytesPerSecond,
                    clientDiag.MeasuredBandwidthBytesPerSecond, clientDiag.MeasuredBandwidthBytesPerSecond * 8.0 / 1000000.0);
        std::printf("  RTT last: %lld us, min: %lld us, loss: %.1f%%\n", static_cast<long long>(clientDiag.LastRttMicros),
                    static_cast<long long>(clientDiag.MinRttMicros), clientDiag.EstimatedLossPercent);

        std::printf("\n--- UCP (Congestion Control) State ---\n");
        std::printf("  PacingGain:          %d (x 1/256)\n", clientDiag.PacingGain);
        std::printf("  CwndGain:            %d (x 1/256)\n", clientDiag.CwndGain);
        std::printf("  BtlBw:               %.0f B/s (%.1f Mbps)\n", static_cast<double>(clientDiag.BtlBwBytesPerSecond),
                    clientDiag.BtlBwBytesPerSecond * 8.0 / 1000000.0);
        std::printf("  MaxBw:               %.0f B/s (%.1f Mbps)\n", static_cast<double>(clientDiag.MaxBwBytesPerSecond),
                    clientDiag.MaxBwBytesPerSecond * 8.0 / 1000000.0);
        std::printf("  TotalDelivered:      %lld B\n", static_cast<long long>(clientDiag.TotalDelivered));

        std::printf("\nDiagnostic benchmark PASSED\n");

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
        return 0;
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "FATAL: %s\n", ex.what());
        return 1;
    }
}
