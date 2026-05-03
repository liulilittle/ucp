using System; // Import core .NET types (Console, etc.)

namespace UcpTest // Define the test namespace for the UCP project
{
    /// <summary>
    /// Standalone console entry point that validates and prints a UCP performance report file.
    /// Used by CI/CD pipelines to verify benchmark results after test execution.
    /// </summary>
    internal static class ReportPrinter // Static class housing the console entry point for CI/CD report validation
    {
        /// <summary>
        /// Validates the report file at the given path (or the default test report path)
        /// and prints a formatted table to stdout. Returns 0 on success, 1 on validation failure.
        /// </summary>
        /// <param name="args">Optional file path argument; defaults to <see cref="UcpTestHelpers.TestReportPath"/>.</param>
        /// <returns>Exit code: 0 for valid report, 1 for missing/empty/invalid report.</returns>
        public static int Main(string[] args) // Application entry point for report validation
        {
            // Determine the report path from the first argument or fall back to the default test report location.
            string reportPath = args != null && args.Length > 0 ? args[0] : UcpTestHelpers.TestReportPath; // Use CLI arg[0] if provided, otherwise default test report path
            Console.WriteLine("[report] " + reportPath); // Print the report file path being processed to stdout
            string errorMessage; // Declare output variable for validation error message

            // Validate the report file against all required scenario checks.
            if (!UcpPerformanceReport.ValidateReportFile(reportPath, out errorMessage)) // Check if the report passes all validation rules, capturing error message
            {
                Console.WriteLine("[report-error] " + errorMessage); // Print the validation error to stdout for CI log inspection
                return 1; // Return non-zero exit code to signal failure to the CI pipeline
            }

            // Print the formatted console table of all parsed scenario rows.
            Console.WriteLine(UcpPerformanceReport.FormatReportFileForConsole(reportPath)); // Parse and format the validated report for human-readable console display
            return 0; // Return zero exit code to signal success to the CI pipeline
        }
    }
}
