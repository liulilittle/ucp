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
    auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
    cfg.InitialBandwidthBytesPerSecond = 12500000;
    cfg.MaxPacingRateBytesPerSecond = 12500000;
    cfg.SetSendBufferSize(8 * 1024 * 1024);
    cfg.SetReceiveBufferSize(8 * 1024 * 1024);
    ucp::UcpDatagramNetwork net(cfg);
    auto cli = net.CreateConnection(cfg);
    if (!cli) {
        printf("FAIL create\n");
        return 1;
    }
    auto p = std::make_shared<std::promise<bool>>();
    auto f = p->get_future();
    cli->ConnectAsync(&net, "127.0.0.1:19001", [p, cli](ucp::UcpError e, uint32_t) { p->set_value(e == ucp::UcpError::None); });
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
    printf("OK connected %08X\n", cli->GetConnectionId());

    const int kDataSize = 300 * 1024;
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
    pump();
    auto wp = std::make_shared<std::promise<bool>>();
    auto wf = wp->get_future();
    cli->WriteAsync(tx.data(), 0, kDataSize, [wp](ucp::UcpError, bool ok) { wp->set_value(ok); });
    dl = std::chrono::steady_clock::now() + std::chrono::seconds(30);

    while (wf.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
        net.DoEvents();
        if (std::chrono::steady_clock::now() > dl) {
            printf("FAIL write timeout\n");
            return 1;
        }
    }
    if (!wf.get()) {
        printf("FAIL write\n");
        return 1;
    }
    printf("OK write %d bytes\n", kDataSize);

    dl = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (doneFut.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
        net.DoEvents();
        if (std::chrono::steady_clock::now() > dl) {
            printf("FAIL recv timeout (rxd=%lld)\n", (long long)rxd.load());
            return 1;
        }
    }
    bool ok = doneFut.get();
    printf("OK recv %lld / %d bytes\n", (long long)rxd.load(), kDataSize);
    if (!ok || rxd.load() != kDataSize) {
        printf("FAIL recv incomplete\n");
        return 1;
    }
    bool match = (0 == std::memcmp(tx.data(), rx.data(), kDataSize));
    printf(match ? "PASS\n" : "FAIL data mismatch\n");
    return match ? 0 : 1;
}
