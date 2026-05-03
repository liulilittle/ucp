using Xunit; // Import the xUnit testing framework for assembly-level attributes

// Disable parallel test execution across the assembly because UCP integration tests
// bind ephemeral ports and share simulator state; concurrent tests would conflict.
[assembly: CollectionBehavior(DisableTestParallelization = true)] // Prevent parallel test runs to avoid port/simulator conflicts
