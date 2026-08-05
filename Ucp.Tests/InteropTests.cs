using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ucp;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{

    public sealed class InteropTests
    {
        private readonly ITestOutputHelper _output;

        public InteropTests(ITestOutputHelper output) => _output = output;

        private static string? FindInteropServer()
        {
            string baseDir = AppContext.BaseDirectory;
            string? envPath = Environment.GetEnvironmentVariable("UCP_INTEROP_SERVER");
            var candidates = new List<string>();
            if (!string.IsNullOrEmpty(envPath)) candidates.Add(envPath);
            candidates.Add(Path.Combine(baseDir, "interop_server.exe"));
            candidates.Add(Path.Combine(baseDir, "..", "..", "..", "..", "cpp", "build_release_x64", "tests", "interop_server.exe"));
            candidates.Add(Path.Combine(baseDir, "..", "..", "..", "..", "cpp", "build_verify", "tests", "interop_server.exe"));
            candidates.Add(Path.Combine(baseDir, "..", "..", "..", "..", "cpp", "build", "tests", "Release", "interop_server.exe"));
            foreach (string c in candidates)
            {
                string full = Path.GetFullPath(c);
                if (File.Exists(full)) return full;
            }
            return null;
        }

        [Fact]
        public async Task Interop_CppServer_CsClient_EchoesData()
        {
            int port = 0;
            string? portEnv = Environment.GetEnvironmentVariable("UCP_INTEROP_PORT");
            bool useExisting = !string.IsNullOrEmpty(portEnv) && int.TryParse(portEnv, out port) && port > 0;

            string? serverPath = FindInteropServer();
            Process? serverProc = null;
            if (!useExisting)
            {
                if (string.IsNullOrEmpty(serverPath))
                {
                    Assert.Fail("interop_server.exe not found; cannot run cross-language interop test. Build cpp/tests first.");
                }
                port = 19003;
                serverProc = new Process();
                serverProc.StartInfo.FileName = serverPath;
                serverProc.StartInfo.Arguments = port.ToString();
                serverProc.StartInfo.UseShellExecute = false;
                serverProc.StartInfo.RedirectStandardOutput = true;
                serverProc.StartInfo.RedirectStandardError = true;
                serverProc.EnableRaisingEvents = true;
                if (!serverProc.Start())
                {
                    Assert.Fail("Failed to start interop_server.exe");
                }
                // Wait for READY on stdout (the server signals readiness before accepting).
                var readyTask = serverProc.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
                string? ready = await readyTask;
                if (ready != "READY")
                {
                    string err = await serverProc.StandardError.ReadToEndAsync();
                    Assert.Fail($"interop_server did not signal READY (got '{ready}'): {err}");
                }
            }

            try
            {
                _output.WriteLine($"Connecting to interop server on port {port}...");
                var client = new UcpConnection();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
                _output.WriteLine("Connected, sending payload...");

                byte[] sendBuf = Encoding.ASCII.GetBytes("Hello from C#!");
                int sent = await client.SendAsync(sendBuf, 0, sendBuf.Length);
                Assert.Equal(sendBuf.Length, sent);
                _output.WriteLine($"Sent {sent} bytes, waiting for echo...");

                byte[] recvBuf = new byte[65536];
                int received = 0;

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                while (received == 0 && !cts.IsCancellationRequested)
                {
                    try
                    {
                        received = await client.ReceiveAsync(recvBuf, 0, recvBuf.Length).WaitAsync(cts.Token);
                    }
                    catch (Exception ex)
                    {
                        _output.WriteLine($"ReceiveAsync retry: {ex.GetType().Name}: {ex.Message}");
                        await Task.Delay(100, cts.Token);
                    }
                }
                _output.WriteLine($"Received {received} bytes");

                Assert.True(received == sendBuf.Length,
                    $"Echo must return the full payload: got {received}, expected {sendBuf.Length}");
                string echo = Encoding.ASCII.GetString(recvBuf, 0, received);
                Assert.Equal("Hello from C#!", echo);
                _output.WriteLine($"Echo verified: '{echo}'");
                await client.CloseAsync();
            }
            finally
            {
                if (serverProc != null && !serverProc.HasExited)
                {
                    try { serverProc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                    serverProc.Dispose();
                }
            }
        }

        [Fact]
        public async Task Interop_CppClient_CsServer_EchoesData()
        {
            // Reverse direction of the above: a C++ client (interop_client.exe)
            // connects to an in-process C# UcpServer and echoes a payload.
            string? clientPath = FindInteropClient();
            if (string.IsNullOrEmpty(clientPath))
            {
                Assert.Fail("interop_client.exe not found; cannot run C++-client/C#-server interop test. Build cpp/tests first.");
            }

            var server = new UcpServer();
            // Random high port to avoid collisions with other tests that bind
            // real sockets; the C++ client receives it via command line.
            // Retry on a fresh port if the OS has it in use (TIME_WAIT etc.).
            var rng = new Random();
            int port = 0;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                port = rng.Next(22000, 40000);
                try
                {
                    server.Start(port);
                    break;
                }
                catch
                {
                    if (attempt == 4) throw;
                }
            }

            string payload = "Hello from C++!";
            string arguments = $"{IPAddress.Loopback} {port} \"{payload}\"";

            using var proc = new Process();
            proc.StartInfo.FileName = clientPath;
            proc.StartInfo.Arguments = arguments;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.StartInfo.RedirectStandardError = true;

            Task<UcpConnection> acceptTask = server.AcceptAsync();
            bool started = proc.Start();
            Assert.True(started, "Failed to start interop_client.exe");
            try
            {
                UcpConnection srvConn = await acceptTask.WaitAsync(TimeSpan.FromSeconds(10));
                byte[] recvBuf = new byte[65536];
                byte[] sendBuf = Encoding.ASCII.GetBytes(payload);

                int received = 0;
                var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                try
                {
                    received = await srvConn.ReceiveAsync(recvBuf, 0, recvBuf.Length).WaitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    Assert.Fail("C# server timed out waiting for C++ client payload");
                }

                Assert.Equal(sendBuf.Length, received);
                Assert.Equal(payload, Encoding.ASCII.GetString(recvBuf, 0, received));

                int echoed = await srvConn.SendAsync(recvBuf, 0, received).WaitAsync(cts.Token);
                Assert.Equal(received, echoed);

                string stdout = await proc.StandardOutput.ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(15));
                int exit = proc.HasExited ? proc.ExitCode : 1;
                Assert.True(0 == exit, $"interop_client exit={exit} stdout={stdout}");
                Assert.Contains("ECHO OK", stdout);
            }
            finally
            {
                server.Dispose();
            }
        }

        private static string? FindInteropClient()
        {
            string baseDir = AppContext.BaseDirectory;
            string? envPath = Environment.GetEnvironmentVariable("UCP_INTEROP_CLIENT");
            var candidates = new List<string>();
            if (!string.IsNullOrEmpty(envPath)) candidates.Add(envPath);
            candidates.Add(Path.Combine(baseDir, "interop_client.exe"));
            candidates.Add(Path.Combine(baseDir, "..", "..", "..", "..", "cpp", "build_release_x64", "tests", "interop_client.exe"));
            candidates.Add(Path.Combine(baseDir, "..", "..", "..", "..", "cpp", "build_verify", "tests", "interop_client.exe"));
            foreach (string c in candidates)
            {
                string full = Path.GetFullPath(c);
                if (File.Exists(full)) return full;
            }
            return null;
        }
    }
}
