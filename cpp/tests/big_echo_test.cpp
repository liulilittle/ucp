#include "ucp/ucp_datagram_network.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_configuration.h"
#include <cstdio>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
    cfg.InitialBandwidthBytesPerSecond = 12500000;
    cfg.MaxPacingRateBytesPerSecond = 12500000;
    cfg.SetSendBufferSize(16 * 1024 * 1024);
    cfg.SetReceiveBufferSize(16 * 1024 * 1024);
    ucp::UcpDatagramNetwork net(cfg);
    auto cli = net.CreateConnection(cfg);
    auto p = std::make_shared<std::promise<bool>>();
    auto f = p->get_future();
    cli->ConnectAsync(&net, "127.0.0.1:19001", [p](ucp::UcpError e, uint32_t) { p->set_value(e == ucp::UcpError::None); });
    auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (f.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
        net.DoEvents();
        if (std::chrono::steady_clock::now() > dl) {
            printf("FAIL connect\n");
            return 1;
        }
    }
    if (!f.get()) {
        printf("FAIL connect2\n");
        return 1;
    }
    printf("OK connected\n");
    const int kDataSize = 2 * 1024 * 1024;
    ucp::vector<uint8_t> tx(kDataSize), rx(kDataSize);
    for (int i = 0; i < kDataSize; i++)
        tx[i] = (uint8_t)(i & 0xFF);

    auto done = std::make_shared<std::promise<bool>>();
    auto doneFut = done->get_future();
    std::atomic<int64_t> rxd{0};
    std::function<void()> pump;
    pump = [&]() {
        size_t off = (size_t)rxd.load();
        if (off >= (size_t)kDataSize) {
            try {
                done->set_value(true);
            } catch (...) {
            }
            return;
        }
        cli->ReceiveAsync(rx.data() + off, 0, (size_t)kDataSize - off, [&](ucp::UcpError e, int32_t n) {
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
    auto wp = std::make_shared<std::promise<bool>>();
    auto wf = wp->get_future();
    std::thread writeThread([&]() {
        cli->WriteAsync(tx.data(), 0, kDataSize, [wp](ucp::UcpError, bool ok) { wp->set_value(ok); });
        auto dl2 = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        while (wf.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
            net.DoEvents();
            if (std::chrono::steady_clock::now() > dl2) {
                printf("FAIL write timeout\n");
                return;
            }
        }
    });
    std::thread recvThread([&]() {
        pump();
        auto dl2 = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (doneFut.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
            net.DoEvents();
            if (std::chrono::steady_clock::now() > dl2) {
                auto d = cli->GetDiagnostics();
                printf("FAIL recv timeout (rxd=%lld) diag: state=%d flight=%lld rwnd=%u cwnd=%d sent=%lld recv=%lld ackPkts=%d "
                       "retx=%d/fast=%d/to=%d rtt=%lld btlBw=%lld pace=%.0f bufferedRx=%d netTx: recvPkts=%lld sendWB=%lld sendErr=%lld\n",
                       (long long)rxd.load(), (int)d.State, (long long)d.FlightBytes, d.RemoteWindowBytes, d.CongestionWindowBytes,
                       (long long)d.BytesSent, (long long)d.BytesReceived, d.SentAckPackets, d.RetransmittedPackets, d.FastRetransmissions,
                       d.TimeoutRetransmissions, (long long)d.LastRttMicros, (long long)d.BtlBwBytesPerSecond, d.PacingRateBytesPerSecond,
                       d.BufferedReceiveBytes, (long long)net.GetReceivedDatagramCount(), (long long)net.GetSendWouldBlockCount(),
                       (long long)net.GetSendErrorCount());
                printf("STALLED; failing immediately (120s debugger sleep removed)\n");
                return;
            }
        }
    });
    writeThread.join();
    recvThread.join();
    if (wf.wait_for(std::chrono::seconds(0)) != std::future_status::ready || !wf.get()) {
        printf("FAIL write\n");
        return 1;
    }
    printf("OK write %d bytes\n", kDataSize);
    if (doneFut.wait_for(std::chrono::seconds(0)) != std::future_status::ready || !doneFut.get()) {
        printf("FAIL recv incomplete\n");
        return 1;
    }
    printf("OK recv %lld / %d bytes\n", (long long)rxd.load(), kDataSize);
    if (rxd.load() != kDataSize) {
        printf("FAIL recv incomplete\n");
        return 1;
    }
    bool match = (0 == std::memcmp(tx.data(), rx.data(), kDataSize));
    printf(match ? "PASS\n" : "FAIL data mismatch\n");
    return match ? 0 : 1;
}
