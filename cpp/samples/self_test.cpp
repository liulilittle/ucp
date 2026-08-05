#include <cstdio>
#include <memory>
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_datagram_network.h"
#include "ucp/ucp_server.h"

int main() {
    std::printf("=== UCP SelfTest (C++) ===\n");
    int pass = 0, fail = 0;

    // 1: Library config
    try {
        auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
        pass++;
        std::printf("[PASS] Config create\n");
    } catch (...) {
        fail++;
        std::printf("[FAIL] Config create\n");
    }

    // 2: Network create/destroy
    try {
        auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
        { ucp::UcpDatagramNetwork net(cfg); }
        pass++;
        std::printf("[PASS] Network create/destroy\n");
    } catch (...) {
        fail++;
        std::printf("[FAIL] Network create/destroy\n");
    }

    // 3: Server create via network
    try {
        auto cfg = ucp::UcpConfiguration::GetOptimizedConfig();
        ucp::UcpDatagramNetwork net(cfg);
        auto srv = net.CreateServer(48001);
        if (srv) {
            srv->Stop();
            pass++;
            std::printf("[PASS] Server create/stop\n");
        } else {
            fail++;
            std::printf("[FAIL] Server create/stop\n");
        }
    } catch (...) {
        fail++;
        std::printf("[FAIL] Server create/stop\n");
    }

    std::printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
