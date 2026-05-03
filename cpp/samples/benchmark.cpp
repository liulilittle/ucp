// ucp_benchmark.cpp — UCP Performance Benchmark
// Mirrors C# samples/cs/Benchmark/Program.cs line-for-line behaviorally.
// Runs a suite of network-impairment scenarios through a simulated network
// (SimPeer), transfers payload data, verifies integrity, and prints a
// results table comparing actual throughput to README targets.
//
// Equivalence verified against C# version:
//   - Same 5 scenarios with identical Loss, Delay, Jitter, Bw, Payload, targets.
//   - Same readmeTargets dictionary mapping scenario names to min/max Mbps.
//   - SimPeer class: virtual-network peer simulating delay, jitter, packet loss,
//     and bandwidth limits.  Mirrors C# SimPeer inner class exactly.
//   - Output() method: loss check, delay calculation (propagation + jitter +
//     bandwidth serialisation), async delivery via timer queue (C# uses
//     Task.Delay; C++ uses a priority queue polled in DoEvents).
//   - EventPumpLoop drives both peers' DoEvents every 1 ms when idle.
//   - RunScenario creates two SimPeers, runs a pump thread, establishes a
//     connection, sends/receives payload, verifies data, and returns a
//     ScenarioReport.
//   - Summary table printed at end matching C# format.

#include <algorithm>   // std::max, std::min
#include <atomic>      // std::atomic<bool>
#include <chrono>      // std::chrono::high_resolution_clock, duration
#include <cmath>       // std::ceil
#include <cstdint>     // int64_t, uint8_t
#include <cstdio>      // std::printf
#include <cstring>     // std::memcmp
#include <future>      // std::future, std::future_status
#include <map>         // std::map

#include <mutex>       // std::mutex, std::lock_guard
#include <queue>       // std::queue
#include <random>      // std::mt19937, uniform_int_distribution, uniform_real_distribution
#include <string>      // std::to_string, std::stoi
#include <thread>      // std::thread, std::this_thread::sleep_for
#include <vector>      // std::vector (for non-ucp containers like peer lists)

#include "ucp/ucp_network.h"         // ucp::UcpNetwork, ucp::IUcpObject
#include "ucp/ucp_server.h"          // ucp::UcpServer
#include "ucp/ucp_connection.h"      // ucp::UcpConnection
#include "ucp/ucp_configuration.h"   // ucp::UcpConfiguration
#include "ucp/ucp_types.h"           // ucp::Endpoint, ucp::UcpTransferReport
#include "ucp/ucp_vector.h"          // ucp::vector, ucp::string

// ============================================================================
// Internal helpers; defined in anonymous namespace.
// ============================================================================
namespace {
namespace chr = std::chrono;

// --------------------------------------------------------------------------
// ScenarioReport — mirrors C# ScenarioReport class (lines 190-198).
// --------------------------------------------------------------------------
struct ScenarioReport {
    double   throughput_bps      = 0.0;
    int64_t  avg_rtt_us          = 0;
    double   retransmission_ratio = 0.0;
    int64_t  elapsed_ms          = 0;
    int      cwnd_bytes          = 0;
    double   observed_loss_pct   = 0.0;
};

// ============================================================================
// SimPeer — virtual-network peer that simulates network impairments.
// Mirrors C# SimPeer class (lines 200-315) exactly.
//
// Each SimPeer derives from UcpNetwork.  It overrides Output() to intercept
// outgoing datagrams and apply artificial delay, jitter, loss, and bandwidth
// shaping before delivering them to the destination peer.
// ============================================================================
class SimPeer : public ucp::UcpNetwork {
public:
    // ---- Public fields for stats collection (C# lines 212-213) ----
    int64_t packets_sent    = 0;
    int64_t packets_dropped = 0;

    // ---- Constructor (C# lines 215-225) ----
    // peers:      shared map of port → SimPeer* used for cross-peer delivery.
    // peers_lock: shared mutex protecting the peers map.
    // delay_ms:   one-way propagation delay in milliseconds.
    // jitter_ms:  ±jitter range in milliseconds.
    // loss_rate:  packet loss probability in [0..1].
    // bw_bps:     bottleneck bandwidth in bytes/second (0 = unlimited).
    // seed:       RNG seed for reproducible loss/jitter.
    SimPeer(std::map<int, SimPeer*>* peers,
            std::mutex*             peers_lock,
            const ucp::UcpConfiguration& config,
            int delay_ms, int jitter_ms, double loss_rate,
            int bw_bps, int seed)
        : ucp::UcpNetwork(config)
        , peers_(peers)
        , peers_lock_(peers_lock)
        , delay_ms_(delay_ms)
        , jitter_ms_(jitter_ms)
        , loss_rate_(loss_rate)
        , bandwidth_bps_(bw_bps)
        , rng_(static_cast<unsigned int>(seed))
        , loss_dist_(0.0, 1.0)
        , jitter_dist_(-jitter_ms, jitter_ms) {}

    // ---- LocalEndPoint (C# line 227) ----
    ucp::Endpoint local_endpoint() const { return local_endpoint_; }

    // ---- Start: bind to port (C# lines 229-235) ----
    void Start(int port) override {
        if (local_endpoint_.port != 0) return;
        if (port == 0)
            port = 50000 + static_cast<int>(peers_->size());
        local_endpoint_ = ucp::Endpoint("127.0.0.1",
                                        static_cast<uint16_t>(port));
        {
            std::lock_guard<std::mutex> lock(*peers_lock_);
            (*peers_)[port] = this;
        }
    }

    // ---- Stop: remove from peers map (C# lines 237-243) ----
    void Stop() override {
        if (local_endpoint_.port != 0) {
            std::lock_guard<std::mutex> lock(*peers_lock_);
            peers_->erase(local_endpoint_.port);
        }
    }

    // ---- Output: intercept and impair outbound datagrams (C# lines 245-272) ----
    void Output(const uint8_t* data, size_t length,
                const ucp::Endpoint& remote,
                ucp::IUcpObject* /*sender*/) override {
        // Lazy-bind if not yet started — C# line 247.
        if (local_endpoint_.port == 0)
            Start(0);

        // Copy the datagram so we own its lifetime — C# lines 249-250.
        ucp::vector<uint8_t> copy(data, data + length);

        // ---- Packet loss check (C# lines 252-260) ----
        {
            std::lock_guard<std::mutex> lock(sync_);
            packets_sent++;
            if (loss_dist_(rng_) < loss_rate_) {
                packets_dropped++;
                return;  // Drop the packet silently.
            }
        }

        // ---- Compute artificial delay (C# lines 262-269) ----
        // Jitter: random integer in [-jitter_ms, +jitter_ms].
        int var_jitter = (jitter_ms_ > 0) ? jitter_dist_(rng_) : 0;
        int64_t delay_us =
            static_cast<int64_t>(std::max(0, delay_ms_ + var_jitter)) * 1000LL;

        // Bandwidth serialisation delay: time to clock out the bits.
        if (bandwidth_bps_ > 0) {
            int64_t bw_serial_us = static_cast<int64_t>(
                std::ceil(copy.size() * 1000000.0 / bandwidth_bps_));
            delay_us += bw_serial_us;
        }

        // ---- Enqueue for delayed delivery (C# line 271) ----
        // C# uses _ = DeliverAfterAsync(copy, remote, delayUs);
        // C++ uses a priority queue polled by DoEvents to avoid per-packet threads.
        int64_t deliver_at =
            std::chrono::duration_cast<std::chrono::microseconds>(
                chr::high_resolution_clock::now().time_since_epoch())
                .count()
            + delay_us;

        {
            std::lock_guard<std::mutex> lock(delivery_mutex_);
            PendingDelivery pd;
            pd.deliver_at_us = deliver_at;
            pd.data          = std::move(copy);
            pd.source        = local_endpoint_;
            pd.target_port   = static_cast<int>(remote.port);
            pending_deliveries_.emplace(deliver_at, std::move(pd));
        }
    }

    // ---- DoEvents: drain inbox + fire expired delayed deliveries (C# lines 301-315) ----
    int DoEvents() override {
        // Drain the inbox of instant deliveries from other peers.
        // Mirrors C# while-loop dequeuing from _inbox.
        while (true) {
            InboxItem item;
            {
                std::lock_guard<std::mutex> lock(inbox_mutex_);
                if (inbox_.empty()) break;
                item = std::move(inbox_.front());
                inbox_.pop();
            }
            // Route the datagram into the UCP protocol engine — C# Input(...).
            UcpNetwork::Input(item.data.data(), item.data.size(), item.source);
        }

        // Deliver expired time-delayed packets.
        // Mirrors the completion of C# DeliverAfterAsync tasks.
        int64_t now_us =
            std::chrono::duration_cast<std::chrono::microseconds>(
                chr::high_resolution_clock::now().time_since_epoch())
                .count();

        // Collect expired deliveries under lock.
        ucp::vector<PendingDelivery> ready;
        {
            std::lock_guard<std::mutex> lock(delivery_mutex_);
            auto it = pending_deliveries_.begin();
            while (it != pending_deliveries_.end() &&
                   it->first <= now_us) {
                ready.push_back(std::move(it->second));
                it = pending_deliveries_.erase(it);
            }
        }

        // Deliver each expired item to the target peer's inbox.
        for (auto& pd : ready) {
            SimPeer* target = nullptr;
            {
                std::lock_guard<std::mutex> lock(*peers_lock_);
                auto fit = peers_->find(pd.target_port);
                if (fit != peers_->end())
                    target = fit->second;
            }
            if (target)
                target->Enqueue(std::move(pd.data), pd.source);
        }

        // Let the base UcpNetwork tick timers and PCBs — C# line 314.
        return UcpNetwork::DoEvents();
    }

    // ---- Enqueue: push a datagram into the receiving peer's inbox (C# lines 293-299) ----
    void Enqueue(ucp::vector<uint8_t> data, const ucp::Endpoint& source) {
        std::lock_guard<std::mutex> lock(inbox_mutex_);
        inbox_.emplace(std::move(data), source);
    }

    // ---- GetLocalEndPoint override (C# line 227) ----
    ucp::Endpoint GetLocalEndPoint() const override {
        return local_endpoint_;
    }

private:
    // ---- Inbox item: (data, source) pair (C# line 210) ----
    struct InboxItem {
        ucp::vector<uint8_t> data;
        ucp::Endpoint        source;
        InboxItem() = default;
        InboxItem(ucp::vector<uint8_t> d, ucp::Endpoint s)
            : data(std::move(d)), source(std::move(s)) {}
    };

    // ---- Pending delayed delivery entry (C++ equivalent of DeliverAfterAsync params) ----
    struct PendingDelivery {
        int64_t              deliver_at_us;  // Absolute microsecond deadline.
        ucp::vector<uint8_t> data;           // Copy of the datagram.
        ucp::Endpoint        source;         // Originating peer endpoint.
        int                  target_port;    // Destination peer's port for lookup.
    };

    // ---- Shared peers registry (C# lines 202-205) ----
    std::map<int, SimPeer*>* peers_ = nullptr;
    std::mutex*              peers_lock_ = nullptr;

    // ---- Network impairment parameters (C# lines 203-207) ----
    int    delay_ms_      = 0;
    int    jitter_ms_     = 0;
    double loss_rate_     = 0.0;
    int    bandwidth_bps_ = 0;

    // ---- Local state (C# lines 208-210) ----
    ucp::Endpoint local_endpoint_;

    // ---- Thread synchronisation ----
    std::mutex sync_;                   // Protects packet_sent / packets_dropped (C# _sync).
    std::mutex inbox_mutex_;            // Protects inbox_ (C# lock(_inbox)).
    std::mutex delivery_mutex_;         // Protects pending_deliveries_ (C++ addition).
    std::queue<InboxItem> inbox_;       // Inbox for immediate cross-peer delivery (C# _inbox).
    // Priority queue for delayed deliveries; keyed by absolute delivery time.
    std::multimap<int64_t, PendingDelivery> pending_deliveries_;

    // ---- RNG for loss and jitter (C# lines 207, 224) ----
    std::mt19937                         rng_;
    std::uniform_real_distribution<double> loss_dist_;
    std::uniform_int_distribution<int>    jitter_dist_;
};

// ============================================================================
// EventPumpLoop — continuously drain events from all peers.
// Mirrors C# EventPumpLoop static method (lines 163-173).
// ============================================================================
void EventPumpLoop(const ucp::vector<SimPeer*>& peers,
                   std::atomic<bool>&           stop) {
    while (!stop.load(std::memory_order_relaxed)) {
        int work = 0;
        for (auto* peer : peers)
            work += peer->DoEvents();
        if (work == 0)
            std::this_thread::sleep_for(chr::milliseconds(1));
    }
}

// ============================================================================
// RunScenario — execute a single benchmark scenario.
// Mirrors C# RunScenarioAsync (lines 79-161).
//
// Creates two SimPeers connected back-to-back, transfers the payload from
// client to server, verifies data integrity, and returns a ScenarioReport.
// Returns nullptr-equivalent (report with zero throughput_bps) on failure.
// ============================================================================
ScenarioReport RunScenario(
    const ucp::string& name,
    int                bandwidth_bps,
    int                payload_bytes,
    int                delay_ms,
    int                jitter_ms,
    double             loss_rate,
    int                seed) {

    ScenarioReport result;

    try {
        // ---- Build configuration (C# lines 84-95) ----
        auto config = ucp::UcpConfiguration::GetOptimizedConfig();
        config.InitialBandwidthBytesPerSecond = static_cast<int64_t>(bandwidth_bps);
        config.MaxPacingRateBytesPerSecond    = static_cast<int64_t>(bandwidth_bps);
        config.ServerBandwidthBytesPerSecond  = static_cast<int64_t>(bandwidth_bps);
        int bufsz = std::max(64 * 1024 * 1024, payload_bytes * 2);
        config.SetSendBufferSize(bufsz);
        config.SetReceiveBufferSize(bufsz);

        // Enable FEC for lossy scenarios — C# lines 91-95.
        if (loss_rate > 0.0) {
            config.FecRedundancy = (loss_rate >= 0.05) ? 0.50 : 0.25;
            config.FecGroupSize  = 8;
        }

        // ---- Create the two SimPeers (C# lines 99-101) ----
        std::map<int, SimPeer*> peers;
        std::mutex              peers_lock;

        auto server_peer = ucp::unique_ptr<SimPeer>(new SimPeer(
            &peers, &peers_lock, config.Clone(),
            delay_ms, jitter_ms, loss_rate, bandwidth_bps, seed + 1));
        auto client_peer = ucp::unique_ptr<SimPeer>(new SimPeer(
            &peers, &peers_lock, config.Clone(),
            delay_ms, jitter_ms, loss_rate, bandwidth_bps, seed + 2));

        server_peer->Start(9000);   // Bind to port 9000 — C# line 103.
        client_peer->Start(0);      // Bind to ephemeral port  — C# line 104.

        // ---- Start the event pump thread (C# line 106) ----
        std::atomic<bool> pump_stop{false};
        ucp::vector<SimPeer*> peer_ptrs = { server_peer.get(), client_peer.get() };
        std::thread pump_thread(EventPumpLoop, std::cref(peer_ptrs),
                                std::ref(pump_stop));

        // ---- Create server and client objects (C# lines 108-109) ----
        auto server = server_peer->CreateServer(9000);
        auto client = client_peer->CreateConnection(config);

        // ---- Accept + Connect handshake (C# lines 111-112) ----
        auto accept_fut = server->AcceptAsync();
        bool connected = client->ConnectAsync(
            ucp::Endpoint("127.0.0.1", 9000).ToString()).get();
        if (!connected) {
            pump_stop.store(true);
            pump_thread.join();
            return result;  // Return zero-initialized report (failure).
        }
        auto server_conn = accept_fut.get();

        // ---- Generate deterministically random payload (C# lines 115-117) ----
        ucp::vector<uint8_t> payload(static_cast<size_t>(payload_bytes));
        {
            // Seed 42 matches C# new Random(42) — line 116.
            std::mt19937 rng(42);
            std::uniform_int_distribution<int> dist(0, 255);
            for (size_t i = 0; i < payload.size(); ++i)
                payload[i] = static_cast<uint8_t>(dist(rng));
        }

        ucp::vector<uint8_t> received(payload.size());

        // ---- Timed transfer (C# lines 119-123) ----
        auto sw_start = chr::high_resolution_clock::now();

        // Start server read asynchronously (hot future) — C# line 120.
        // ReadAsync returns immediately; the actual read completes when data
        // arrives through the simulated network via the event pump thread.
        auto read_fut = server_conn->ReadAsync(received.data(), 0,
                                               received.size());

        // Client side: send entire payload and block until fully flushed — C# line 121.
        bool write_ok = client->WriteAsync(payload.data(), 0,
                                           payload.size()).get();

        // Now wait for the server to receive the data, with a 180 s timeout — C# line 122.
        auto read_status = read_fut.wait_for(chr::milliseconds(180000));
        bool read_ok = (read_status == std::future_status::ready) && read_fut.get();

        auto sw_end = chr::high_resolution_clock::now();

        // ---- Stop the pump thread (C# lines 125-126) ----
        pump_stop.store(true);
        pump_thread.join();

        // ---- Validate transfer (C# lines 128-133) ----
        if (!write_ok || !read_ok)
            return result;  // Failure.

        bool verified = (std::memcmp(payload.data(), received.data(),
                                     payload.size()) == 0);
        if (!verified)
            return result;  // Data corruption.

        // Brief settle period for final stats — C# line 135.
        std::this_thread::sleep_for(chr::milliseconds(200));

        // ---- Gather statistics (C# lines 137-154) ----
        auto transfer_report = client->GetReport();
        double elapsed_sec =
            chr::duration<double>(sw_end - sw_start).count();
        double throughput_bps =
            static_cast<double>(payload_bytes) /
            std::max(0.001, elapsed_sec);
        // Cap at the configured bandwidth — C# lines 139-140.
        if (bandwidth_bps > 0)
            throughput_bps = std::min(throughput_bps,
                                      static_cast<double>(bandwidth_bps));

        int64_t obs_drop = server_peer->packets_dropped +
                           client_peer->packets_dropped;
        int64_t obs_sent = server_peer->packets_sent +
                           client_peer->packets_sent;
        double obs_loss = (obs_sent > 0)
            ? static_cast<double>(obs_drop) * 100.0 / obs_sent
            : 0.0;

        result.throughput_bps       = throughput_bps;
        result.avg_rtt_us           = transfer_report.LastRttMicros;
        result.retransmission_ratio  = transfer_report.RetransmissionRatio();
        result.elapsed_ms =
            chr::duration_cast<chr::milliseconds>(sw_end - sw_start).count();
        result.cwnd_bytes           = static_cast<int>(transfer_report.CongestionWindowBytes);
        result.observed_loss_pct    = obs_loss;

    } catch (const std::exception& ex) {
        std::printf("  Error: %s\n", ex.what());
        // Return zero-initialized report to indicate failure.
    }

    return result;
}

// ============================================================================
// Scenario descriptor — mirrors C# anonymous-type array (lines 4-11).
// ============================================================================
struct ScenarioDef {
    const char* name;
    double      loss;           // Packet loss probability [0..1].
    int         delay_ms;       // One-way propagation delay (ms).
    int         jitter_ms;      // Jitter range ± (ms).
    int         bw_bps;         // Bandwidth limit (bytes/sec).
    int         payload_mb;     // Payload size in MiB.
    double      target_util_min;   // Minimum acceptable utilisation %.
    double      target_retrans_max;// Maximum acceptable retransmission %.
};

// ============================================================================
// README throughput targets — mirrors C# readmeTargets dictionary (lines 13-20).
// ============================================================================
struct ReadmeTarget {
    double min_mbps;
    double max_mbps;
};

}  // anonymous namespace

// ============================================================================
// main — entry point for ucp_benchmark.
// Mirrors C# top-level statements in Benchmark/Program.cs.
// ============================================================================
int main() {
    // ---------- Scenario definitions (C# lines 4-11) ----------
    const ScenarioDef kScenarios[] = {
        { "NoLoss",      0.00, 5,  0,  12500000, 4, 90.0, 0.5 },
        { "Lossy_1%",    0.01, 10, 2,  12500000, 4, 85.0, 2.0 },
        { "Lossy_5%",    0.05, 10, 2,  12500000, 8, 70.0, 7.0 },
        { "LongFatPipe", 0.00, 50, 2,  12500000, 4, 80.0, 0.5 },
        { "HighJitter",  0.005,50, 25, 12500000, 4, 65.0, 2.0 },
    };

    // ---------- README targets (C# lines 13-20) ----------
    // Maps scenario name → (min Mbps, max Mbps).
    std::map<ucp::string, ReadmeTarget> readme_targets;
    readme_targets["NoLoss"]      = { 95.0, 100.0 };
    readme_targets["Lossy_1%"]    = { 90.0,  99.0 };
    readme_targets["Lossy_5%"]    = { 75.0,  95.0 };
    readme_targets["LongFatPipe"] = { 85.0,  99.0 };
    readme_targets["HighJitter"]  = { 70.0,  99.0 };

    std::printf("UCP Performance Benchmark\n");
    std::printf(
        "=====================================================================================\n");

    // ---------- Run each scenario and collect results (C# lines 25-66) ----------
    struct ResultRow {
        ucp::string name;
        double      actual_mbps;
        double      util_pct;
        ucp::string status;  // "PASS", "FAIL", or "N/A"
    };
    ucp::vector<ResultRow> all_results;

    for (size_t si = 0; si < sizeof(kScenarios) / sizeof(kScenarios[0]); ++si) {
        const auto& sc = kScenarios[si];

        std::printf("\n--- %s ---\n", sc.name);
        std::printf("  Config: %.1f%% loss, %dms delay, %dms jitter, "
                    "%.1f Mbps, %d MB\n",
                    sc.loss * 100.0, sc.delay_ms, sc.jitter_ms,
                    sc.bw_bps / 125000.0,
                    sc.payload_mb);

        // Run the scenario — C# line 32.
        ScenarioReport report = RunScenario(
            sc.name, sc.bw_bps, sc.payload_mb * 1024 * 1024,
            sc.delay_ms, sc.jitter_ms, sc.loss,
            12345 + static_cast<int>(si)  // Seed offset — C# line 33.
        );

        // Check if the scenario failed (zero throughput = failure) — C# lines 35-39.
        if (report.throughput_bps <= 0.0) {
            std::printf("  FAILED\n");
            all_results.push_back({ sc.name, 0.0, 0.0, "FAIL" });
            continue;
        }

        double throughput_mbps = report.throughput_bps * 8.0 / 1000000.0;
        double target_mbps     = sc.bw_bps * 8.0 / 1000000.0;
        double util_pct = (target_mbps > 0.0)
            ? throughput_mbps * 100.0 / target_mbps : 0.0;

        std::printf("  Throughput:     %.2f Mbps (%.1f%% util)\n",
                    throughput_mbps, util_pct);
        std::printf("  Avg RTT:        %.2f ms\n",
                    report.avg_rtt_us / 1000.0);
        std::printf("  Retransmission: %.2f%%\n",
                    report.retransmission_ratio * 100.0);
        std::printf("  Observed loss:  %.2f%%\n",
                    report.observed_loss_pct);
        std::printf("  CWND:           %d B\n", report.cwnd_bytes);
        std::printf("  Elapsed:        %lld ms\n",
                    static_cast<long long>(report.elapsed_ms));

        // Pass/fail checks — C# lines 52-54.
        bool util_ok    = (util_pct >= sc.target_util_min);
        bool retrans_ok = (report.retransmission_ratio * 100.0 <=
                           sc.target_retrans_max);
        std::printf("  Utilization:    %s (>= %.0f%%)\n",
                    util_ok ? "PASS" : "FAIL", sc.target_util_min);
        std::printf("  Retransmission: %s (<= %.0f%%)\n",
                    retrans_ok ? "PASS" : "FAIL", sc.target_retrans_max);

        // Check against README targets — C# lines 57-63.
        ucp::string readme_status = "N/A";
        auto rt = readme_targets.find(sc.name);
        if (rt != readme_targets.end()) {
            bool within = (throughput_mbps >= rt->second.min_mbps);
            readme_status = within ? "PASS" : "FAIL";
            std::printf("  vs README (%.0f-%.0f Mbps): %s (>= %.0f)\n",
                        rt->second.min_mbps, rt->second.max_mbps,
                        readme_status.c_str(), rt->second.min_mbps);
        }

        all_results.push_back({ sc.name, throughput_mbps, util_pct,
                                readme_status });
    }

    // ---------- Summary table (C# lines 68-77) ----------
    std::printf("\n");
    std::printf(
        "=====================================================================================\n");
    std::printf("%-16s %-18s %-16s %-8s %s\n",
                "Scenario", "Target (Mbps)", "Actual (Mbps)",
                "Util%", "vs README");
    std::printf(
        "--------------------------------------------------------------------------------\n");

    for (const auto& row : all_results) {
        ucp::string target_str = "N/A";
        auto rt = readme_targets.find(row.name);
        if (rt != readme_targets.end()) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.0f-%.0f",
                          rt->second.min_mbps, rt->second.max_mbps);
            target_str = buf;
        }
        std::printf("%-16s %-18s %-16.2f %-8.1f %s\n",
                    row.name.c_str(), target_str.c_str(),
                    row.actual_mbps, row.util_pct,
                    row.status.c_str());
    }

    return 0;
}
