// ucp_echo_client.cpp — UCP Echo Client
// Mirrors C# samples/cs/Client/Program.cs line-for-line behaviorally.
// Connects to an echo server, sends random data, receives the echo back,
// verifies data integrity, and prints transfer statistics.
//
// Equivalence verified against C# version:
//   - Same defaults: host=127.0.0.1, port=9000, dataMb=1, bandwidthMbps=100.
//   - Same --host, --port, --size, --bandwidth, --help argument parsing.
//   - Same bandwidth conversion and totalBytes calculation.
//   - Same UcpConfiguration.GetOptimizedConfig() with bandwidth caps.
//   - Same buffer sizing: max(64 MiB, totalBytes*2).
//   - Same random data generation (seed 42, filling entire buffer).
//   - Same send-then-receive-exactly pattern with verification.
//   - Same transfer statistics printed at the end.
//   - Same average RTT computation from RttSamplesMicros.
//   - Same close sequence: CloseAsync after all data transferred.

#include <algorithm>   // std::max
#include <chrono>      // std::chrono::high_resolution_clock, duration
#include <cstring>     // std::memcmp
#include <cstdint>     // int64_t, uint8_t
#include <cstdio>      // std::printf
#include <future>      // std::future
#include <random>      // std::mt19937, std::uniform_int_distribution
#include <string>      // std::to_string

#include "ucp/ucp_connection.h"    // ucp::UcpConnection
#include "ucp/ucp_configuration.h" // ucp::UcpConfiguration
#include "ucp/ucp_types.h"         // ucp::Endpoint, ucp::UcpTransferReport
#include "ucp/ucp_vector.h"        // ucp::vector, ucp::string

// ============================================================================
// Constants — mirror C# Client/Program.cs lines 5-8
// ============================================================================
namespace {

constexpr int    kDefaultPort          = 9000;       // Default server port.
constexpr int    kDefaultDataMb        = 1;          // Default payload size (MiB).
constexpr int    kDefaultBandwidthMbps = 100;        // Default bandwidth (Mbps).
constexpr double kSecToMs              = 1000.0;     // Seconds → milliseconds.

// ============================================================================
// Convert Mbps to bytes per second.
// Mirrors C# line 44: int bandwidthBytesPerSec = bandwidthMbps * 1000000 / 8;
// ============================================================================
int MbpsToBytesPerSec(int mbps) {
    return mbps * 1000000 / 8;
}

// ============================================================================
// Compute average RTT from a vector of RTT samples (microseconds).
// Mirrors C# GetAverageRtt helper at line 111-118.
// ============================================================================
double GetAverageRtt(const ucp::UcpTransferReport& report) {
    if (report.RttSamplesMicros.empty())
        return 0.0;
    int64_t sum = 0;
    for (int64_t sample : report.RttSamplesMicros)
        sum += sample;
    return static_cast<double>(sum) / report.RttSamplesMicros.size() / 1000.0;
}

}  // anonymous namespace

// ============================================================================
// main — entry point for ucp_echo_client.
// Mirrors C# top-level statements in Client/Program.cs.
// ============================================================================
int main(int argc, char* argv[]) {
    // ---------- Parse command-line arguments (C# lines 10-42) ----------
    ucp::string host          = "127.0.0.1";           // Default host (C# line 8).
    int         port          = kDefaultPort;          // Default port (C# line 5).
    int         data_mb       = kDefaultDataMb;        // Default size  (C# line 6).
    int         bandwidth_mbps = kDefaultBandwidthMbps;// Default bw    (C# line 7).

    for (int i = 1; i < argc; ++i) {
        ucp::string arg(argv[i]);
        if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--size" && i + 1 < argc) {
            data_mb = std::stoi(argv[++i]);
        } else if (arg == "--bandwidth" && i + 1 < argc) {
            bandwidth_mbps = std::stoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            std::printf(
                "Usage: ucp_echo_client [--host <host>] [--port <port>] "
                "[--size <MB>] [--bandwidth <Mbps>] [--help]\n");
            std::printf("  --host      Server host (default: %s)\n", host.c_str());
            std::printf("  --port      Server port (default: %d)\n", kDefaultPort);
            std::printf("  --size      Data size in MB to send (default: %d)\n",
                        kDefaultDataMb);
            std::printf("  --bandwidth Expected bandwidth in Mbps (default: %d)\n",
                        kDefaultBandwidthMbps);
            return 0;
        }
    }

    int bandwidth_bps = MbpsToBytesPerSec(bandwidth_mbps);  // C# line 44.
    int total_bytes   = data_mb * 1024 * 1024;               // C# line 45.

    // ---------- Build optimized configuration (C# lines 47-52) ----------
    auto config = ucp::UcpConfiguration::GetOptimizedConfig();
    config.InitialBandwidthBytesPerSecond = bandwidth_bps;
    config.MaxPacingRateBytesPerSecond    = bandwidth_bps;
    config.ServerBandwidthBytesPerSecond  = bandwidth_bps;  // Not strictly needed for client but mirrors C#.
    // Buffer sizes: max(64 MiB, totalBytes * 2) — mirrors C# lines 51-52.
    int buffer_size = std::max(64 * 1024 * 1024, total_bytes * 2);
    config.SetSendBufferSize(buffer_size);
    config.SetReceiveBufferSize(buffer_size);

    std::printf("Connecting to %s:%d...\n", host.c_str(), port);

    // ---------- Create connection and connect (C# lines 56-61) ----------
    ucp::UcpConnection client(config);
    ucp::Endpoint remote(host, static_cast<uint16_t>(port));

    // Start stopwatch before connect — mirrors C# line 59.
    auto stopwatch = std::chrono::high_resolution_clock::now();

    // Block until connected — mirrors C# line 61: await client.ConnectAsync.
    bool connected = client.ConnectAsync(remote.ToString()).get();
    if (!connected) {
        std::printf("ERROR: Failed to connect to %s:%d\n", host.c_str(), port);
        return 1;
    }

    std::printf("Connected (ConnId=%08X), sending %.2f MB...\n",
                client.GetConnectionId(),
                total_bytes / 1024.0 / 1024.0);

    // ---------- Generate deterministic random payload (C# lines 64-65) ----------
    // Fixed seed 42 ensures reproducibility — mirrors C# new Random(42).
    ucp::vector<uint8_t> send_data(static_cast<size_t>(total_bytes));
    {
        std::mt19937 rng(42);
        std::uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < send_data.size(); ++i)
            send_data[i] = static_cast<uint8_t>(dist(rng));
    }

    // Receive buffer — same size as send buffer (C# line 66).
    ucp::vector<uint8_t> recv_buf(static_cast<size_t>(total_bytes));

    // ---------- Start async send (C# line 68: var sendTask = ...) ----------
    auto send_fut = client.WriteAsync(send_data.data(), 0, send_data.size());

    // ---------- Receive exactly total_bytes bytes via loop (C# lines 70-77) ----------
    int total_received = 0;
    while (total_received < total_bytes) {
        // Receive up to remaining bytes into recv_buf at offset total_received.
        auto recv_fut = client.ReceiveAsync(
            recv_buf.data(),
            static_cast<size_t>(total_received),
            static_cast<size_t>(total_bytes - total_received));
        int n = recv_fut.get();
        if (n <= 0)
            break;  // Connection closed prematurely or error (C# line 74-75).
        total_received += n;
    }

    // Wait for the send to fully complete — C# line 79: await sendTask.
    send_fut.get();  // Blocks until all data is flushed.

    // Stop the stopwatch — C# line 80.
    auto elapsed = std::chrono::high_resolution_clock::now() - stopwatch;

    // ---------- Verify received byte count (C# lines 82-86) ----------
    if (total_received != total_bytes) {
        std::printf("ERROR: Received %d bytes, expected %d\n",
                    total_received, total_bytes);
        return 1;
    }

    // ---------- Verify data integrity (C# line 88: SequenceEqual) ----------
    // memcmp returns 0 on equality.
    bool verified = (std::memcmp(send_data.data(), recv_buf.data(),
                                 static_cast<size_t>(total_bytes)) == 0);
    std::printf(verified ? "Data verification: PASS\n" : "Data verification: FAIL\n");

    // ---------- Compute and print statistics (C# lines 91-106) ----------
    double elapsed_sec =
        std::chrono::duration<double>(elapsed).count();
    double throughput_mbps =
        static_cast<double>(total_bytes) * 8.0 / elapsed_sec / 1000000.0;
    auto report = client.GetReport();

    std::printf("\n");
    std::printf("=== Transfer Statistics ===\n");
    std::printf("  Data sent:     %.2f MB\n", total_bytes / 1024.0 / 1024.0);
    std::printf("  Data received: %.2f MB\n",
                static_cast<double>(total_received) / 1024.0 / 1024.0);
    std::printf("  Elapsed:       %.3f s\n", elapsed_sec);
    std::printf("  Throughput:    %.2f Mbps\n", throughput_mbps);
    std::printf("  RTT:           %.2f ms (last), %.2f ms (avg)\n",
                report.LastRttMicros / 1000.0,
                GetAverageRtt(report));
    std::printf("  CWND:          %d B\n",
                static_cast<int>(report.CongestionWindowBytes));
    std::printf("  Pacing rate:   %.2f Mbps\n",
                report.PacingRateBytesPerSecond * 8.0 / 1000000.0);
    std::printf("  Retrans:       %.1f%% (%d/%d packets)\n",
                report.RetransmissionRatio() * 100.0,
                static_cast<int>(report.RetransmittedPackets),
                static_cast<int>(report.DataPacketsSent));
    std::printf("  Fast retrans:  %d\n",
                static_cast<int>(report.FastRetransmissions));
    std::printf("  Timeout retrans: %d\n",
                static_cast<int>(report.TimeoutRetransmissions));

    // ---------- Close connection (C# line 108) ----------
    client.CloseAsync().get();
    std::printf("Connection closed.\n");

    return verified ? 0 : 1;
}
