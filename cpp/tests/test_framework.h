#pragma once
// Minimal test framework for UCP C++ tests — mirrors C# xUnit test runner pattern.
// Test cases auto-register via global constructors. No external library dependency.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>

struct TestCase {
    const char* name;
    void (*func)();
};

inline std::vector<TestCase>& GetTests() {
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
        throw std::runtime_error("UCP_CHECK failed"); \
    } \
} while(0)

#define UCP_CHECK_FALSE(cond) UCP_CHECK(!(cond))

#define UCP_CHECK_EQUAL(a, b) do { \
    auto _a_val = (a); \
    auto _b_val = (b); \
    if (_a_val != _b_val) { \
        fprintf(stderr, "  FAIL: %s:%d: %s != %s\n  expected: %lld, actual: %lld\n", \
            __FILE__, __LINE__, #a, #b, (long long)(_b_val), (long long)(_a_val)); \
        throw std::runtime_error("UCP_CHECK_EQUAL failed"); \
    } \
} while(0)

static int g_test_failures = 0;
static int g_test_passes = 0;

inline int RunAllTests() {
    auto& tests = GetTests();
    fprintf(stdout, "UCP C++ Test Suite -- %zu test cases\n\n", (size_t)tests.size());
    for (const auto& t : tests) {
        fprintf(stdout, "[ RUN      ] %s\n", t.name);
        try {
            t.func();
            g_test_passes++;
            fprintf(stdout, "[       OK ] %s\n", t.name);
        } catch (const std::exception& e) {
            g_test_failures++;
            fprintf(stdout, "[  FAILED  ] %s (%s)\n", t.name, e.what());
        } catch (...) {
            g_test_failures++;
            fprintf(stdout, "[  FAILED  ] %s (unknown exception)\n", t.name);
        }
    }
    fprintf(stdout, "\n========================================\n");
    fprintf(stdout, "Tests passed: %d\n", g_test_passes);
    fprintf(stdout, "Tests failed: %d\n", g_test_failures);
    fprintf(stdout, "========================================\n");
    return g_test_failures > 0 ? 1 : 0;
}
