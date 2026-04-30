using Xunit;

// Disable parallel test execution across the assembly because UCP integration tests
// bind ephemeral ports and share simulator state; concurrent tests would conflict.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
