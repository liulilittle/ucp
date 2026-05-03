// Entry point for the C++ UCP test executable.
// Delegates to RunAllTests() which auto-discovers all test cases
// registered via UCP_TEST_CASE macros in linked translation units.
#include "test_framework.h"
int main() { return RunAllTests(); }
