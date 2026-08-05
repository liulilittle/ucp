#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <future>
#include <random>
#include <thread>
#include <string>
#include <atomic>
#include <memory>
#include "ucp/ucp_datagram_network.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_types.h"
#include "ucp/ucp_vector.h"
namespace {
constexpr int kDefaultPort = 9000, kDefaultDataBytes = 256 * 1024, kDefaultDataMb = 1, kMaxDataMb = 100, kDefaultBandwidthMbps = 100;
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
} // namespace
int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    try {
        std::string host = "127.0.0.1";
        int port = kDefaultPort, data_mb = 0, bw_mbps = kDefaultBandwidthMbps;
        for (int i = 1; i < argc; ++i) {
            std::string a(argv[i]);
            if ("--host" == a && i + 1 < argc)
                host = argv[++i];
            else if ("--port" == a && i + 1 < argc)
                port = TryParseInt(argv[++i], kDefaultPort);
            else if ("--size" == a && i + 1 < argc)
                data_mb = TryParseInt(argv[++i], kDefaultDataMb);
            else if ("--bandwidth" == a && i + 1 < argc)
                bw_mbps = TryParseInt(argv[++i], kDefaultBandwidthMbps);
            else if ("--help" == a || "-h" == a) {
                std::printf("Usage: ucp_echo_client [--host <host>] [--port <port>] [--size <MB>] [--bandwidth <Mbps>] [--help]\n");
                return 0;
            }
        }
        if (data_mb > kMaxDataMb)
            data_mb = kMaxDataMb;
        int64_t total = (0 == data_mb) ? kDefaultDataBytes : static_cast<int64_t>(data_mb) * 1024 * 1024;
        int64_t bw = MbpsToBytesPerSec(bw_mbps);
        auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
        cfg.InitialBandwidthBytesPerSecond = bw;
        cfg.MaxPacingRateBytesPerSecond = bw;
        cfg.ServerBandwidthBytesPerSecond = static_cast<int>(bw);
        cfg.SetSendBufferSize(8 * 1024 * 1024);
        cfg.SetReceiveBufferSize(8 * 1024 * 1024);
        ucp::UcpDatagramNetwork net(cfg);
        auto cl = net.CreateConnection(cfg);
        if (!cl) {
            std::fprintf(stderr, "FAIL: connect\n");
            return 1;
        }
        auto sw = std::chrono::high_resolution_clock::now();
        bool connected = false;
        for (int a = 0; a < 5 && !connected; ++a) {
            auto p = std::make_shared<std::promise<bool>>();
            auto f = p->get_future();
            cl->ConnectAsync(&net, ucp::Endpoint(host, (uint16_t)port).ToString(), [p](ucp::UcpError e, uint32_t) {
                try {
                    p->set_value(ucp::UcpError::None == e);
                } catch (...) {
                }
            });
            auto dl = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
            while (!connected && std::chrono::steady_clock::now() < dl) {
                net.DoEvents();
                if (f.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready) {
                    connected = f.get();
                    break;
                }
            }
        }
        if (!connected) {
            std::printf("ERROR: timeout\n");
            return 1;
        }
        std::printf("Connected (ConnId=%08X), sending %.2f MB...\n", cl->GetConnectionId(), total / 1024.0 / 1024.0);

        ucp::vector<uint8_t> tx(static_cast<size_t>(total)), rx(static_cast<size_t>(total));
        {
            std::mt19937 rng(42);
            std::uniform_int_distribution<int> d(0, 255);
            for (size_t i = 0; i < tx.size(); ++i)
                tx[i] = (uint8_t)d(rng);
        }

        auto done = std::make_shared<std::promise<bool>>();
        auto done_future = done->get_future();
        std::atomic<int64_t> rxd{0};
        std::function<void()> pump;
        pump = [&]() {
            size_t off = (size_t)rxd.load();
            if (off >= (size_t)total) {
                try {
                    done->set_value(true);
                } catch (...) {
                }
                return;
            }
            cl->ReceiveAsync(rx.data() + off, 0, (size_t)total - off, [&](ucp::UcpError e, int32_t n) {
                if (ucp::UcpError::None != e || n <= 0) {
                    try {
                        done->set_value(false);
                    } catch (...) {
                    }
                    return;
                }
                rxd.fetch_add(n);
                pump();
            });
        };
        pump();

        auto writeDone = std::make_shared<std::promise<bool>>();
        auto writeFuture = writeDone->get_future();

        std::thread writeThread([&]() {
            cl->WriteAsync(tx.data(), 0, (int)total, [writeDone](ucp::UcpError e, bool ok) {
                try {
                    writeDone->set_value(ok && e == ucp::UcpError::None);
                } catch (...) {
                }
            });
            auto lastPrint = std::chrono::steady_clock::now();
            while (writeFuture.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
                net.DoEvents();
                auto now = std::chrono::steady_clock::now();
                if (now - lastPrint > std::chrono::seconds(3)) {
                    lastPrint = now;
                    std::printf("  Sending: waiting for write, recv %lld / %lld bytes (%.1f%%)\n", (long long)rxd.load(), (long long)total,
                                total > 0 ? 100.0 * rxd.load() / total : 0.0);
                }
            }
        });

        std::thread recvThread([&]() {
            auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(600);
            auto lastPrint = std::chrono::steady_clock::now();
            while (done_future.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready &&
                   std::chrono::steady_clock::now() < dl) {
                net.DoEvents();
                auto now = std::chrono::steady_clock::now();
                if (now - lastPrint > std::chrono::seconds(3)) {
                    lastPrint = now;
                    std::printf("  Receiving: %lld / %lld bytes (%.1f%%)\n", (long long)rxd.load(), (long long)total,
                                total > 0 ? 100.0 * rxd.load() / total : 0.0);
                }
            }
        });

        writeThread.join();
        recvThread.join();

        bool writeOk = writeFuture.get();
        if (!writeOk) {
            std::printf("ERROR: write failed\n");
            return 1;
        }
        std::printf("Write complete: %lld bytes sent\n", (long long)total);

        if (rxd.load() != total) {
            std::printf("ERROR: received %lld/%lld\n", (long long)rxd.load(), (long long)total);
            return 1;
        }
        bool ok = (0 == std::memcmp(tx.data(), rx.data(), (size_t)total));
        std::printf("Data verification: %s\n", ok ? "PASS" : "FAIL");
        auto elapsed = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - sw).count();
        std::printf("  Throughput: %.2f Mbps\n", (elapsed > 0 ? total * 8.0 / elapsed / 1e6 : 0));
        cl->CloseAsync([](ucp::UcpError) {});
        cl.reset();
        net.Dispose();
        return ok ? 0 : 1;
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "FATAL: %s\n", ex.what());
        return 1;
    }
}
