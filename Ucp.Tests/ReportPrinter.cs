using System;

namespace UcpTest
{
    /// <summary>
    /// Standalone console entry point that validates and prints a UCP performance report file.
    /// Used by CI/CD pipelines to verify benchmark results after test execution.
    /// </summary>
    internal static class ReportPrinter
    {
        /// <summary>
        /// Validates the report file at the given path (or the default test report path)
        /// and prints a formatted table to stdout. Returns 0 on success, 1 on validation failure.
        /// </summary>
        /// <param name="args">Optional file path argument; defaults to <see cref="UcpTestHelpers.TestReportPath"/>.</param>
        /// <returns>Exit code: 0 for valid report, 1 for missing/empty/invalid report.</returns>
        public static int Main(string[] args)
        {
            // Determine the report path from the first argument or fall back to the default test report location.
            string reportPath = args != null && args.Length > 0 ? args[0] : UcpTestHelpers.TestReportPath;
            Console.WriteLine("[report] " + reportPath);
            string errorMessage;

            // Validate the report file against all required scenario checks.
            if (!UcpPerformanceReport.ValidateReportFile(reportPath, out errorMessage))
            {
                Console.WriteLine("[report-error] " + errorMessage);
                return 1;
            }

            // Print the formatted console table of all parsed scenario rows.
            Console.WriteLine(UcpPerformanceReport.FormatReportFileForConsole(reportPath));
            return 0;
        }
    }
}
