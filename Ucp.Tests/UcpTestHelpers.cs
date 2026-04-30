using System;
using System.IO;
using System.Threading.Tasks;

namespace UcpTest
{
    /// <summary>
    /// Shared test utilities used across the UCP test suite, including report file paths
    /// and async timeout helpers.
    /// </summary>
    internal static class UcpTestHelpers
    {
        /// <summary>
        /// Path to the summary performance report file, persisted across test runs.
        /// </summary>
        public static readonly string ReportPath = Path.Combine(AppContext.BaseDirectory, "reports", "summary.txt");

        /// <summary>
        /// Path to the test-specific report file used by <see cref="ReportPrinter"/> for CI validation.
        /// </summary>
        public static readonly string TestReportPath = Path.Combine(AppContext.BaseDirectory, "reports", "test_report.txt");

        /// <summary>
        /// Static initializer: ensures the reports directory and seed files exist
        /// so the first report append does not fail.
        /// </summary>
        static UcpTestHelpers()
        {
            // Create the reports directory if it does not already exist.
            string directory = Path.GetDirectoryName(ReportPath) ?? AppContext.BaseDirectory;
            Directory.CreateDirectory(directory);

            // Seed the summary report file with a header line if it is new.
            if (!File.Exists(ReportPath))
            {
                File.WriteAllText(ReportPath, "UCP automated performance report" + Environment.NewLine);
            }

            // Seed the test report file with a header line if it is new.
            if (!File.Exists(TestReportPath))
            {
                File.WriteAllText(TestReportPath, "UCP automated test report" + Environment.NewLine);
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
        public static async Task<T> WithTimeout<T>(Task<T> task, int timeoutMilliseconds)
        {
            // Race the task against a delay; if the delay finishes first, the task timed out.
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMilliseconds));
            if (completed != task)
            {
                throw new TimeoutException("Test timed out.");
            }

            // Await the already-completed task to unwrap its result (or propagate its exception).
            return await task;
        }
    }
}
