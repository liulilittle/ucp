#include "network_simulator.h"
#include <atomic>
#include <cstdio>

using namespace ucp_test;

int main() {
    constexpr int kBw = 1000000000 / 8;
    NetworkSimulator sim(0, 1, 0, kBw, 1234, nullptr, 0, 0, -1, -1);
    auto* srv = sim.CreateTransport("srv");
    srv->Start(40299);
    auto* cli = sim.CreateTransport("cli");
    cli->Start(0);

    ucp::vector<uint8_t> payload(1024, 'A');
    cli->Send(payload.data(), (int)payload.size(), srv->local_port);

    bool ok = sim.WaitForDeliveryCount(1, 5000);
    std::printf("Delivery: %s, packets=%lld, bytes=%lld\n", ok ? "OK" : "FAIL", (long long)sim.DeliveredPackets(),
                (long long)sim.DeliveredBytes());
    return ok ? 0 : 1;
}
