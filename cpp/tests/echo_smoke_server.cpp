#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_datagram_network.h"
#include <cstdio>
#include <thread>
#include <memory>
#include <atomic>
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
    cfg.InitialBandwidthBytesPerSecond = 12500000;
    cfg.SetSendBufferSize(64 * 1024 * 1024);
    cfg.SetReceiveBufferSize(64 * 1024 * 1024);
    ucp::UcpDatagramNetwork net(cfg);
    auto srv = net.CreateServer(19001);
    if (!srv) {
        printf("FAIL srv\n");
        return 1;
    }
    printf("OK srv\n");
    std::atomic<bool> done{false};
    std::shared_ptr<ucp::UcpConnection> gConn;
    ucp::function<void(ucp::UcpError, ucp::UcpConnection*)> onAccept;
    onAccept = [&](ucp::UcpError e, ucp::UcpConnection* c) {
        if (e != ucp::UcpError::None || !c) {
            done = true;
            return;
        }
        printf("OK accept %08X\n", c->GetConnectionId());
        auto conn = c;
        gConn = std::shared_ptr<ucp::UcpConnection>(conn, [](ucp::UcpConnection*) {});
        auto buf = std::make_shared<ucp::vector<uint8_t>>(65536);
        auto total = std::make_shared<int64_t>(0);
        ucp::function<void()> doRecv;
        auto pDoRecv = std::make_shared<ucp::function<void()>>();
        *pDoRecv = [conn, buf, total, pDoRecv, &done]() {
            conn->ReceiveAsync(buf->data(), 0, 65536, [conn, buf, total, pDoRecv, &done](ucp::UcpError e, int32_t n) {
                if (e != ucp::UcpError::None || n <= 0) {
                    done = true;
                    return;
                }
                *total += n;
                printf("OK recv %d (total %lld)\n", n, (long long)*total);
                conn->WriteAsync(buf->data(), 0, n, [conn, pDoRecv, total, &done](ucp::UcpError e, bool ok) {
                    if (e != ucp::UcpError::None || !ok) {
                        done = true;
                        return;
                    }
                    printf("OK echo %lld\n", (long long)*total);
                    (*pDoRecv)();
                });
            });
        };
        (*pDoRecv)();
        if (!done)
            srv->AcceptAsync(onAccept);
    };
    srv->AcceptAsync(onAccept);
    auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (!done && std::chrono::steady_clock::now() < dl) {
        net.DoEvents();
    }
    if (!done) {
        auto d = gConn ? gConn->GetDiagnostics() : ucp::UcpConnectionDiagnostics();
        printf("TIMEOUT diag: state=%d flight=%lld rwnd=%u cwnd=%d sent=%lld recv=%lld ackPkts=%d retx=%d/fast=%d/to=%d rtt=%lld "
               "btlBw=%lld pace=%.0f netTx: recvPkts=%lld sendWB=%lld sendErr=%lld\n",
               (int)d.State, (long long)d.FlightBytes, d.RemoteWindowBytes, d.CongestionWindowBytes, (long long)d.BytesSent,
               (long long)d.BytesReceived, d.SentAckPackets, d.RetransmittedPackets, d.FastRetransmissions, d.TimeoutRetransmissions,
               (long long)d.LastRttMicros, (long long)d.BtlBwBytesPerSecond, d.PacingRateBytesPerSecond,
               (long long)net.GetReceivedDatagramCount(), (long long)net.GetSendWouldBlockCount(), (long long)net.GetSendErrorCount());
    }
    printf("DONE\n");
    return 0;
}
