using System; // Import core .NET types (AppContext, TimeoutException, etc.)
using System.IO; // Import file I/O types (Path, File, Directory)
using System.Threading.Tasks; // Import async task types (Task, Task<T>)

namespace UcpTest // Define the test namespace for the UCP project
{
    /// <summary>
    /// Shared test utilities used across the UCP test suite, including report file paths
    /// and async timeout helpers.
    /// </summary>
    internal static class UcpTestHelpers // Static utility class providing shared test infrastructure
    {
        /// <summary>
        /// Path to the summary performance report file, persisted across test runs.
        /// </summary>
        public static readonly string ReportPath = Path.Combine(AppContext.BaseDirectory, "reports", "summary.txt"); // Build the absolute path to the cumulative performance summary report file

        /// <summary>
        /// Path to the test-specific report file used by <see cref="ReportPrinter"/> for CI validation.
        /// </summary>
        public static readonly string TestReportPath = Path.Combine(AppContext.BaseDirectory, "reports", "test_report.txt"); // Build the absolute path to the CI-validated test report file

        /// <summary>
        /// Static initializer: ensures the reports directory and seed files exist
        /// so the first report append does not fail.
        /// </summary>
        static UcpTestHelpers() // Static constructor that runs once before any members are accessed
        {
            // Create the reports directory if it does not already exist.
            string directory = Path.GetDirectoryName(ReportPath) ?? AppContext.BaseDirectory; // Extract the directory from the report path, falling back to base directory if null
            Directory.CreateDirectory(directory); // Ensure the reports directory exists so file writes don't fail

            // Seed the summary report file with a header line if it is new.
            if (!File.Exists(ReportPath)) // Check if the summary report file already exists to avoid overwriting
            {
                File.WriteAllText(ReportPath, "UCP automated performance report" + Environment.NewLine); // Create the file with a header line so the first append has a valid starting point
            }

            // Seed the test report file with a header line if it is new.
            if (!File.Exists(TestReportPath)) // Check if the test report file already exists to avoid overwriting
            {
                File.WriteAllText(TestReportPath, "UCP automated test report" + Environment.NewLine); // Create the file with a header line so CI validation has a valid starting point
            }
        }

        /// <summary>
        /// Awaits the given task with a timeout. If the task does not complete within
        /// <paramref name="timeoutMilliseconds"/>, a <see cref="TimeoutException"/> is thrown.
        /// </summary>
        /// <typeparam name="T">The task result type.</typeparam>
        /// <param name="task">The task to await.</param>
        /// <param name="timeoutMilliseconds">Maximum wait time in milliseconds.</param>
        /// <returns>The result of the completed task.</returns>
        /// <exception cref="TimeoutException">Thrown when the task exceeds the timeout.</exception>
        public static async Task<T> WithTimeout<T>(Task<T> task, int timeoutMilliseconds) // Generic async helper that awaits a task with a configurable timeout
        {
            // Race the task against a delay; if the delay finishes first, the task timed out.
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMilliseconds)); // Start both the original task and a delay; the first to complete is returned
            if (completed != task) // If the delay won the race, the original task did not complete in time
            {
                throw new TimeoutException("Test timed out."); // Signal timeout failure to the calling test
            }

            // Await the already-completed task to unwrap its result (or propagate its exception).
            return await task; // Unwrap the Task<T> result or propagate any stored exception
        }
    }
}
