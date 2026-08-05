using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Ucp;

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

        public static async Task<T> WithTimeout<T>(Task<T> task, int timeoutMilliseconds = 10000)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMilliseconds));
            if (completed != task)
            {
                throw new TimeoutException("Test timed out.");
            }
            return await task;
        }

        public static async Task WithTimeout(Task task, int timeoutMilliseconds = 10000)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMilliseconds));
            if (completed != task)
            {
                throw new TimeoutException("Test timed out.");
            }
            await task;
        }

        public static async Task<bool> ReadWithTimeout(UcpConnection connection, byte[] buffer, int timeoutMs)
        {
            return await ReadWithTimeout(connection, buffer, buffer.Length, timeoutMs);
        }

        public static async Task<bool> ReadWithTimeout(UcpConnection connection, byte[] buffer, int count, int timeoutMs)
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            Task<bool> readTask;
            try
            {
                readTask = connection.ReadAsync(buffer, 0, count);
            }
            catch (InvalidOperationException)
            {
                return false;
            }
            try
            {
                Task completed = await Task.WhenAny(readTask, Task.Delay(timeoutMs, cts.Token));
                if (completed != readTask)
                    return false;
                cts.Cancel();
                return await readTask;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }

        public static async Task<bool> ReadWithTimeoutTask(Task<bool> task, int timeoutMs)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(timeoutMs));
            if (completed != task) return false;
            return await task;
        }

        public static async Task<bool> WaitForRttSamplesAsync(UcpConnection conn, int minSamples = 1, int timeoutMs = 5000)
        {
            long deadline = Environment.TickCount64 + timeoutMs;
            while (Environment.TickCount64 < deadline)
            {
                if (conn.GetReport().RttSamplesMicros.Count >= minSamples)
                    return true;
                await Task.Delay(20);
            }
            return conn.GetReport().RttSamplesMicros.Count >= minSamples;
        }

        public static async Task CloseWithTimeout(UcpConnection conn, int timeoutMs = 3000)
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            try
            {
                Task closeTask = conn.CloseAsync();
                if (await Task.WhenAny(closeTask, Task.Delay(timeoutMs, cts.Token)) == closeTask)
                {
                    cts.Cancel();
                    await closeTask;
                }
            }
            catch (OperationCanceledException) { }
        }
    }
}
