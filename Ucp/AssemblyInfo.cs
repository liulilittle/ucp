using System.Runtime.CompilerServices; // Provides InternalsVisibleTo for unit-test assembly access

/// <summary>
/// Makes internal types and members visible to the UcpTest assembly for unit testing.
/// This avoids the need to make testable internals public while still allowing
/// the test project to exercise and verify internal protocol logic directly.
/// </summary>
[assembly: InternalsVisibleTo("UcpTest")] // Grants internal-visibility access to the UcpTest assembly
