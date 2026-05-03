// ucp_echo_server.cpp — UCP Echo Server
// Mirrors C# samples/cs/Server/Program.cs line-for-line behaviorally.
// Listens for UCP connections and echoes all received data back to the client.
//
// Equivalence verified against C# version:
//   - Same default port (9000) and bandwidth (100 Mbps).
//   - Same --port, --bandwidth, --help argument parsing.
//   - Same bandwidth conversion: Mbps * 1_000_000 / 8 → bytes/sec.
//   - Same UcpConfiguration.GetOptimizedConfig() tuning.
//   - Same buffer sizes: 64 MiB send + receive via SetSendBufferSize/SetReceiveBufferSize.
//   - AcceptAsync polling loop with Ctrl+C cancellation (C# uses CancellationToken,
//     C++ uses std::atomic flag + signal handler).
//   - Per-connection handler thread echoes data, prints periodic stats every 5 s,
//     identical metrics (MB transferred, Mbps, RTT ms, CWND, retrans ratio).
//   - Connection close via CloseAsync in finally-equivalent block.
//   - Error handling via catch (log + close).

#include <chrono>      // std::chrono::steady_clock, std::chrono::duration, std::chrono::seconds
#include <csignal>     // std::signal, SIGINT
#include <cstdint>     // int64_t, int32_t, uint8_t
#include <ctime>       // std::time_t, std::tm, localtime_s / localtime_r
#include <cstdio>      // std::printf
#include <future>      // std::future, std::future_status

#include <string>      // std::to_string
#include <thread>      // std::thread

#include "ucp/ucp_server.h"        // ucp::UcpServer
#include "ucp/ucp_connection.h"    // ucp::UcpConnection
#include "ucp/ucp_configuration.h" // ucp::UcpConfiguration
#include "ucp/ucp_types.h"         // ucp::Endpoint, ucp::UcpTransferReport
#include "ucp/ucp_vector.h"        // ucp::vector, ucp::string

// ============================================================================
// Constants — mirror C# Server/Program.cs lines 5-6
// ============================================================================
namespace {

constexpr int kDefaultPort          = 9000;  // Default listen port.
constexpr int kDefaultBandwidthMbps = 100;   // Default bandwidth cap (Mbps).

// Global stop flag set by the SIGINT signal handler.
// Mirrors C# CancellationTokenSource pattern.
volatile std::sig_atomic_t g_stop_requested = 0;

// ============================================================================
// Signal handler for graceful shutdown on Ctrl+C.
// Equivalent to C# Console.CancelKeyPress handler (line 45-50).
// ============================================================================
void OnShutdownSignal(int /*signum*/) {
    g_stop_requested = 1;
}

// ============================================================================
// Convert Mbps to bytes per second.
// Mirrors C# line 30: int bandwidthBytesPerSec = bandwidthMbps * 1000000 / 8;
// ============================================================================
int MbpsToBytesPerSec(int mbps) {
    return mbps * 1000000 / 8;
}

// ============================================================================
// Format current wall-clock time as "HH:MM:SS" string.
// Mirrors C# DateTime.Now.ToString("HH:mm:ss") usage throughout the file.
// ============================================================================
ucp::string TimestampNow() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
                  tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    return ucp::string(buf);
}

// ============================================================================
// HandleConnection — worker for a single accepted client connection.
// Mirrors C# HandleConnectionAsync (line 74-123).
//
// Receives data, echoes it back, and prints throughput statistics
// every 5 seconds.  Runs in a detached std::thread.
// ============================================================================
void HandleConnection(ucp::unique_ptr<ucp::UcpConnection> conn) {
    uint32_t conn_id = conn->GetConnectionId();  // Snapshot ID for logging.

    // ---------- try block (C# line 76) ----------
    try {
        int64_t total_bytes = 0;
        // 64 KiB temporary buffer — mirrors C# new byte[65536] (line 79).
        ucp::vector<uint8_t> buf(65536);

        // High-resolution stopwatch — mirrors C# Stopwatch.StartNew() (line 80).
        auto start   = std::chrono::steady_clock::now();
        auto tick_5s = start;  // Last time we printed a 5-second update.

        // Main echo loop — mirrors C# while(true) at line 83.
        while (true) {
            // ----- Receive data (C# line 85: await conn.ReceiveAsync) -----
            // Use ReceiveAsync to read up to buf.size() bytes.
            auto recv_fut = conn->ReceiveAsync(buf.data(), 0, buf.size());
            // Block until the future is ready.
            int n = recv_fut.get();
            if (n <= 0)
                break;  // Connection closed by peer, or error — mirrors C# line 86-87.

            total_bytes += n;  // Accumulate total echo'ed bytes (C# line 89).

            // ----- Echo data back (C# line 91: await conn.WriteAsync) -----
            auto send_fut = conn->WriteAsync(buf.data(), 0, static_cast<size_t>(n));
            bool sent = send_fut.get();
            if (!sent)
                break;  // Write failed — connection is dead (C# line 92-93).

            // ----- Periodic statistics every 5 seconds (C# line 95-104) -----
            auto now = std::chrono::steady_clock::now();
            if (now - tick_5s > std::chrono::seconds(5)) {
                tick_5s = now;

                // Fetch a snapshot of transfer statistics — C# conn.GetReport().
                auto report = conn->GetReport();
                double elapsed_sec =
                    std::chrono::duration<double>(now - start).count();
                double throughput_mbps =
                    static_cast<double>(total_bytes) * 8.0 / elapsed_sec / 1000000.0;

                std::printf(
                    "[%s] Conn %08X: %.2f MB transferred, %.2f Mbps, "
                    "RTT %.2f ms, CWND %d B, Retrans %.1f%%\n",
                    TimestampNow().c_str(),
                    conn_id,
                    total_bytes / 1024.0 / 1024.0,
                    throughput_mbps,
                    report.LastRttMicros / 1000.0,
                    static_cast<int>(report.CongestionWindowBytes),
                    report.RetransmissionRatio() * 100.0);
            }
        }  // end while(true)

        // ---------- Final statistics (C# line 107-113) ----------
        auto end = std::chrono::steady_clock::now();
        double elapsed_total =
            std::chrono::duration<double>(end - start).count();
        auto final_report = conn->GetReport();
        double avg_throughput =
            elapsed_total > 0
                ? static_cast<double>(total_bytes) * 8.0 / elapsed_total / 1000000.0
                : 0.0;

        std::printf(
            "[%s] Conn %08X closed: %.2f MB in %.2fs, %.2f Mbps, "
            "avgRTT %.2f ms, Retrans %.1f%%\n",
            TimestampNow().c_str(),
            conn_id,
            total_bytes / 1024.0 / 1024.0,
            elapsed_total,
            avg_throughput,
            final_report.LastRttMicros / 1000.0,
            final_report.RetransmissionRatio() * 100.0);

    // ---------- catch block (C# line 115-118) ----------
    } catch (const std::exception& ex) {
        std::printf("[%s] Conn %08X error: %s\n",
                    TimestampNow().c_str(), conn_id, ex.what());
    } catch (...) {
        std::printf("[%s] Conn %08X error: unknown\n",
                    TimestampNow().c_str(), conn_id);
    }

    // ---------- finally block (C# line 119-122) ----------
    // Close the connection gracefully; ignore failures during cleanup.
    try {
        conn->CloseAsync().get();
    } catch (...) {
        // Swallow exceptions during close — mirrors C# empty catch.
    }
}

}  // anonymous namespace

// ============================================================================
// main — entry point for ucp_echo_server.
// Mirrors C# top-level statements in Server/Program.cs.
// ============================================================================
int main(int argc, char* argv[]) {
    // ---------- Register Ctrl+C handler (C# line 44-50) ----------
    std::signal(SIGINT, OnShutdownSignal);

    // ---------- Parse command-line arguments (C# lines 8-28) ----------
    int port          = kDefaultPort;
    int bandwidth_mbps = kDefaultBandwidthMbps;

    for (int i = 1; i < argc; ++i) {
        ucp::string arg(argv[i]);
        if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--bandwidth" && i + 1 < argc) {
            bandwidth_mbps = std::stoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            std::printf(
                "Usage: ucp_echo_server [--port <port>] "
                "[--bandwidth <Mbps>] [--help]\n");
            std::printf("  --port       Listen port (default: %d)\n",
                        kDefaultPort);
            std::printf("  --bandwidth  Server bandwidth limit in Mbps "
                        "(default: %d)\n",
                        kDefaultBandwidthMbps);
            return 0;
        }
    }

    int bandwidth_bps = MbpsToBytesPerSec(bandwidth_mbps);  // C# line 30.

    // ---------- Build optimized configuration (C# lines 32-37) ----------
    auto config = ucp::UcpConfiguration::GetOptimizedConfig();
    config.ServerBandwidthBytesPerSecond = bandwidth_bps;
    config.InitialBandwidthBytesPerSecond = bandwidth_bps;
    config.MaxPacingRateBytesPerSecond    = bandwidth_bps;
    config.SetSendBufferSize(64 * 1024 * 1024);
    config.SetReceiveBufferSize(64 * 1024 * 1024);

    // ---------- Create and start server (C# lines 39-42) ----------
    ucp::UcpServer server(config);
    server.Start(port);
    std::printf("UCP Echo Server listening on port %d (%d Mbps)\n",
                port, bandwidth_mbps);
    std::printf("Press Ctrl+C to stop.\n");

    // ---------- Accept loop (C# lines 52-70) ----------
    // Mirrors the CancellationToken-driven accept loop:
    //   server.AcceptAsync() is polled; on success the accepted connection
    //   is dispatched to a background thread.  Ctrl+C sets g_stop_requested.
    try {
        while (!g_stop_requested) {
            // Initiate async accept — C# line 57.
            auto accept_future = server.AcceptAsync();

            // Busy-poll with 250-ms timeout so we can check the stop flag.
            // Equivalent to C# Task.WhenAny(acceptTask, Task.Delay(∞, token)).
            while (accept_future.wait_for(std::chrono::milliseconds(250))
                       != std::future_status::ready) {
                if (g_stop_requested) {
                    server.Stop();  // Trigger AcceptAsync to resolve as nullptr.
                    goto accept_done;
                }
            }

            // Accept completed; retrieve the connection — C# line 62.
            auto conn = accept_future.get();
            if (conn) {
                std::printf("[%s] Accepted connection %08X from %s\n",
                            TimestampNow().c_str(),
                            conn->GetConnectionId(),
                            conn->GetRemoteEndPoint().c_str());

                // Fire-and-forget into background thread — C# line 64: _ = HandleConnectionAsync(conn);
                std::thread(HandleConnection, std::move(conn)).detach();
            }
        }
    } catch (const std::exception& ex) {
        std::printf("Accept loop error: %s\n", ex.what());
    }

accept_done:
    // ---------- Clean shutdown (C# line 72) ----------
    server.Dispose();
    std::printf("Server stopped.\n");
    return 0;
}
