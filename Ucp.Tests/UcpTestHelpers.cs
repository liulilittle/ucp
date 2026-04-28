using System;
using System.IO;
using System.Threading.Tasks;

namespace UcpTest
{
    internal static class UcpTestHelpers
    {
        public static readonly string ReportPath = Path.Combine(AppContext.BaseDirectory, "reports", "summary.txt");
        public static readonly string TestReportPath = Path.Combine(AppContext.BaseDirectory, "reports", "test_report.txt");

        static UcpTestHelpers()
        {
            string directory = Path.GetDirectoryName(ReportPath) ?? AppContext.BaseDirectory;
            Directory.CreateDirectory(directory);
            if (!File.Exists(ReportPath))
            {
                File.WriteAllText(ReportPath, "UCP automated performance report" + Environment.NewLine);
            }

            if (!File.Exists(TestReportPath))
            {
                File.WriteAllText(TestReportPath, "UCP automated test report" + Environment.NewLine);
            }
        }

        public static async Task<T> WithTimeout<T>(Task<T> task, int timeoutMilliseconds)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMilliseconds));
            if (completed != task)
            {
                throw new TimeoutException("Test timed out.");
            }

            return await task;
        }
    }
}
