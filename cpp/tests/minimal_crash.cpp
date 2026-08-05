#include "ucp/ucp_connection.h"
#include "ucp/ucp_configuration.h"
#include <cstdio>
#include <cstdlib>

int main() {
    _set_abort_behavior(0, _WRITE_ABORT_MSG);
    fprintf(stderr, "1-create\n");
    auto config = ucp::UcpConfiguration::GetOptimizedConfig();
    ucp::UcpConnection client(config);
    fprintf(stderr, "2-dispose\n");
    client.Dispose();
    fprintf(stderr, "3-done\n");
    return 0;
}
