// Minimal test framework for UCP C++ tests — mirrors C# xUnit test runner pattern.
// Tests are defined with UCP_TEST_CASE macros that auto-register via global constructors.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <string>

extern int g_test_failures;
extern int g_test_passes;
extern const char* g_current_test;

struct TestCase {
    const char* name;
    void (*func)();
};

static inline std::vector<TestCase>& GetTests() {
    static std::vector<TestCase> tests;
    return tests;
}

struct TestRegistrar {
    TestRegistrar(const char* name, void (*func)()) {
        GetTests().push_back({name, func});
    }
};

#define UCP_TEST_CASE(name) \
    static void ucp_test_##name(); \
    static TestRegistrar ucp_reg_##name(#name, ucp_test_##name); \
    static void ucp_test_##name()

#define UCP_CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        throw std::runtime_error("check failed"); \
    } \
} while(0)

#define UCP_CHECK_EQUAL(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "  FAIL: %s:%d: %s == %s\n  expected: %lld, actual: %lld\n", \
            __FILE__, __LINE__, #a, #b, (long long)(b), (long long)(a)); \
        throw std::runtime_error("check failed"); \
    } \
} while(0)

int RunAllTests();
