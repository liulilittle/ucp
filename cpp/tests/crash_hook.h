#pragma once
#include <cstdio>
#include <cstdlib>
#include <windows.h>

namespace {
static void CrashLog(const char* why) noexcept {
    FILE* f = fopen("ucp_crash.log", "a");
    if (f) {
        fprintf(f, "[CRASH] %s\n", why);
        fflush(f);
        fclose(f);
    }
    fprintf(stderr, "\n[UCP CRASH] %s\n", why);
}

static LONG WINAPI SehFilter(_EXCEPTION_POINTERS* p) noexcept {
    DWORD code = p->ExceptionRecord->ExceptionCode;
    void* addr = p->ExceptionRecord->ExceptionAddress;
    CrashLog("SEH exception");
    FILE* f = fopen("ucp_crash.log", "a");
    if (f) {
        fprintf(f, "  SEH code=0x%08X addr=%p\n", code, addr);
        fclose(f);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static void TerminateHandler() noexcept {
    CrashLog("std::terminate called");
    abort();
}

static void PurecallHandler() noexcept {
    CrashLog("pure virtual function call");
    abort();
}

static int AbortReport(int rptType, char* msg, int* retVal) noexcept {
    CrashLog(msg ? msg : "CrtDbgReport (no msg)");
    return 0;
}

__declspec(allocate(".CRT$XIU")) static void(WINAPI* volatile _ucp_seh_init)(void*) = [](void*) noexcept {
    SetUnhandledExceptionFilter(SehFilter);
};
} // namespace
