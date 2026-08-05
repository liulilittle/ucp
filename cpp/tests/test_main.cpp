#include "test_framework.h"

#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <cstdlib>
#include <errhandlingapi.h>
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    _set_abort_behavior(0, _WRITE_ABORT_MSG);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    const char* filter = 1 < argc ? argv[1] : NULLPTR;
    int result = RunAllTests(filter);

#ifdef _WIN32
    WSACleanup();
#endif

    return result;
}
