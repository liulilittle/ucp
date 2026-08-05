#include "ucp/ucp_datagram_network.h"
#include "ucp/ucp_server.h"
#include "ucp/ucp_connection.h"
#include "ucp/ucp_enums.h"

#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <thread>
#include "ucp/ucp_vector.h"

static std::atomic<bool> g_done{false};

int main(int argc, char* argv[]) {
    if (2 > argc) {
        std::fprintf(stderr, "Usage: interop_server <port>\n");
        return 1;
    }
    int port = std::atoi(argv[1]);

    ucp::UcpConfiguration config;
    ucp::UcpDatagramNetwork network(config);
    auto server = network.CreateServer(port);

    std::printf("READY\n");
    std::fflush(stdout);

    server->AcceptAsync([](ucp::UcpError error, ucp::UcpConnection* conn) noexcept {
        if (ucp::UcpError::None == error && NULLPTR != conn) {
            std::printf("ACCEPTED\n");
            std::fflush(stdout);
            auto recvBuf = ucp::make_shared_object<ucp::vector<uint8_t>>(65536);
            auto buf = recvBuf;
            conn->ReceiveAsync(buf->data(), 0, (int)buf->size(), [conn, buf](ucp::UcpError err, int32_t bytesReceived) noexcept {
                std::printf("RECEIVED %d bytes\n", (int)bytesReceived);
                std::fflush(stdout);
                if (ucp::UcpError::None == err && 0 < bytesReceived) {
                    std::printf("ECHOING\n");
                    std::fflush(stdout);
                    conn->SendAsync(buf->data(), 0, bytesReceived, ucp::UcpPriority::Normal, [](ucp::UcpError, int) noexcept {
                        std::printf("DONE\n");
                        std::fflush(stdout);
                        g_done = true;
                    });
                } else {
                    std::printf("DONE\n");
                    std::fflush(stdout);
                    g_done = true;
                }
            });
        } else {
            std::printf("ACCEPT FAILED\n");
            std::fflush(stdout);
            g_done = true;
        }
    });

    while (!g_done.load()) {
        network.DoEvents();
    }

    auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < drain_deadline) {
        network.DoEvents();
    }

    server->Stop();
    network.Dispose();
    return 0;
}
