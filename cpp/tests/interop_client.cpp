#include "ucp/ucp_connection.h"
#include "ucp/ucp_datagram_network.h"
#include "ucp/ucp_enums.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Cross-language interop CLIENT: connects to a (C# or C++) UCP server,
// sends a fixed payload, expects the server to echo it back, then exits.
// Used by UcpTest.InteropTests (reverse direction of interop_server.cpp).
int main(int argc, char* argv[]) {
    if (3 > argc) {
        std::fprintf(stderr, "Usage: interop_client <address> <port> [payload]\n");
        return 1;
    }
    const char* address = argv[1];
    int port = std::atoi(argv[2]);
    const char* payloadText = (4 <= argc) ? argv[3] : "Hello from C++!";
    size_t payloadLen = std::strlen(payloadText);

    ucp::UcpConfiguration config;
    ucp::UcpConnection conn;
    std::atomic<bool> connected{false};
    std::atomic<bool> echoed{false};
    std::atomic<int> echoLen{0};
    ucp::vector<uint8_t> recvBuf(65536);

    char endpoint[128];
    std::snprintf(endpoint, sizeof(endpoint), "%s:%d", address, port);
    conn.ConnectAsync(endpoint, [&](ucp::UcpError e, uint32_t) noexcept {
        if (ucp::UcpError::None != e) {
            std::printf("CONNECT FAILED\n");
            std::fflush(stdout);
            return;
        }
        connected.store(true);
        conn.SendAsync(reinterpret_cast<const uint8_t*>(payloadText), 0, (int)payloadLen,
                       ucp::UcpPriority::Normal, [&](ucp::UcpError err, int sent) noexcept {
                           if (ucp::UcpError::None != err || sent != (int)payloadLen) {
                               std::printf("SEND FAILED\n");
                               std::fflush(stdout);
                               return;
                           }
                           conn.ReceiveAsync(recvBuf.data(), 0, (int)recvBuf.size(),
                                             [&](ucp::UcpError rerr, int32_t received) noexcept {
                                                 if (ucp::UcpError::None == rerr && received > 0) {
                                                     echoLen.store(received);
                                                     echoed.store(true);
                                                 } else {
                                                     std::printf("RECEIVE FAILED\n");
                                                     std::fflush(stdout);
                                                 }
                                             });
                       });
    });

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!echoed.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    if (!echoed.load()) {
        std::printf("ECHO TIMEOUT\n");
        std::fflush(stdout);
        conn.Dispose();
        return 2;
    }
    int len = echoLen.load();
    bool match = (len == (int)payloadLen) && (0 == std::memcmp(recvBuf.data(), payloadText, payloadLen));
    std::printf("ECHO %s (%d bytes)\n", match ? "OK" : "MISMATCH", len);
    std::fflush(stdout);
    conn.Dispose();
    return match ? 0 : 3;
}
