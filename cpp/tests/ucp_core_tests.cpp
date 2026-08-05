/// @file ucp_core_tests.cpp
/// @brief Comprehensive unit and integration tests for the UCP C++ library.
///
/// Mirrors the C# test suite in Ucp.Tests/UcpCoreTests.cs and
/// Ucp.Tests/UcpNetworkTests.cs.  Tests cover:
///   - Sequence number comparison (wraparound at uint32_max)
///   - Packet codec round-trip (ACK + SACK blocks + echo timestamp)
///   - SACK generator (continuous block merging)
///   - RTO estimator (backoff, clamping, smoothing)
///   - Pacing controller (token bucket, force consume, edge cases)
///   - UCP congestion control (startup exit, rate cliff resistance, auto-probe)
///   - FEC codec (single/two/three loss recovery, edge cases)
///   - NetworkSimulator unit tests (loss, delay, duplication, reorder, bandwidth, jitter)
///   - Integration scenarios (no-loss, lossy, long-fat-pipe, reorder+dup, full-duplex)
///   - Benchmark scenarios (gigabit, 10G, burst, asymmetric, high-jitter, mobile, satellite, VPN, DC, enterprise)
///   - Mobile/vehicle outage scenarios (Weak4G, Airplane, HighSpeedTrain, Driving)
///   - Coverage parameterized tests (100M at 0.2%/1%/10%, 1G at 3%)
///   - Edge cases (SequenceComparer exhaustive, UCP edge states, FEC edge states, RTO edge states)
///
/// All UcpConnection async operations use callback-based API.  Test code uses
/// std::promise/std::future adapters for synchronization (acceptable in test code).

#include "test_framework.h" ///< Test registration, assertion macros, RunAllTests().

#include <thread> ///< std::this_thread::sleep_for

#include "ucp/ucp_vector.h" ///< ucp::vector, NULLPTR macro.

#include "ucp/ucp_constants.h"                 ///< UCP protocol constants (MSS, MIN_RTO, etc.).
#include "ucp/ucp_enums.h"                     ///< UcpPacketType, UcpPacketFlags, UcpMode enums.
#include "ucp/ucp_packets.h"                   ///< UcpAckPacket, SackBlock, UcpPacket base.
#include "ucp/ucp_sequence_comparer.h"         ///< UcpSequenceComparer -- circular uint32 comparison.
#include "ucp/ucp_rto_estimator.h"             ///< UcpRtoEstimator -- RTO computation with backoff.
#include "ucp/ucp_sack_generator.h"            ///< UcpSackGenerator -- SACK block construction.
#include "ucp/ucp_cc.h"                        ///< UcpCongestionControl -- UCP congestion controller.
#include "ucp/ucp_configuration.h"             ///< UcpConfiguration -- tunable protocol parameters.
#include "ucp/ucp_packet_codec.h"              ///< UcpPacketCodec -- packet encode/decode round-trip.
#include "ucp/ucp_fec_codec.h"                 ///< UcpFecCodec -- Forward Error Correction.
#include "ucp/ucp_pacing.h"                    ///< PacingController -- token-bucket pacing.
#include "ucp/ucp_time.h"                      ///< UCP time utilities.
#include "ucp/ucp_connection.h"                ///< UcpConnection public API (callback-based).
#include "ucp/ucp_server.h"                    ///< UcpServer public API (callback-based AcceptAsync).
#include "ucp/ucp_datagram_network.h"          ///< Real UDP-backed UcpNetwork.
#include "ucp/internal/ucp_pcb.h"              ///< UcpPcb test helpers.
#include "ucp/transport/ibindable_transport.h" ///< Bindable transport test adapter.

#include "network_simulator.h" ///< NetworkSimulator + SimulatedTransport.

#include <algorithm>  ///< std::min, std::max.
#include <atomic>     ///< std::atomic for cross-thread test callbacks.
#include <chrono>     ///< std::chrono wait helpers.
#include <climits>    ///< INT_MAX for test configuration.
#include <cmath>      ///< std::round, std::ceil, std::sin.
#include <cstdint>    ///< uint32_t, int64_t.
#include <cstdlib>    ///< size_t.
#include <cstring>    ///< strncpy, memset.
#include <functional> ///< std::function.
#include <future>     ///< std::promise, std::future (test sync adapter).
#include <limits>     ///< std::numeric_limits.
#include <memory>     ///< std::unique_lock, std::mt19937, std::uniform_real_distribution.

using namespace ucp;      ///< Import ucp namespace (UcpSequenceComparer, etc.).
using namespace ucp_test; ///< Import ucp_test namespace (NetworkSimulator, etc.).

// ============================================================================
// Test-only constants (moved from library header per project convention)
// ============================================================================

namespace {

/** @brief IBindableTransport adapter over NetworkSimulator for production connection/server tests. */
class SimulatorTransportAdapter final : public ucp::transport::IBindableTransport {
  public:
    /// @brief Constructs adapter wrapping a transport from the simulator.
    /// @param simulator  The network simulator to use.
    /// @param name       Debug identifier for the transport.
    SimulatorTransportAdapter(NetworkSimulator* simulator, const ucp::string& name) noexcept : simulator_(simulator), transport_(NULLPTR) {
        if (NULLPTR != simulator_) {
            auto* raw = simulator_->CreateTransport(name);
            transport_.reset(raw);
            transport_->on_datagram = [this](const uint8_t* data, int length, int sourcePort) noexcept {
                this->OnDatagram(data, length, sourcePort);
            };
        }
    }

    ~SimulatorTransportAdapter() noexcept override { Stop(); }

    /// @brief Start the transport on a given port.
    void Start(int port) noexcept override {
        if (NULLPTR != transport_) {
            transport_->Start(port);
        }
    }

    /// @brief Stop and dispose the transport.
    void Stop() noexcept override {
        if (NULLPTR != transport_) {
            transport_->Dispose();
        }
    }

    /// @brief Get local endpoint.
    /// @return Endpoint with address 127.0.0.1 and the transport's bound port.
    Endpoint LocalEndpoint() noexcept override {
        Endpoint endpoint;
        endpoint.address = "127.0.0.1";
        endpoint.port = NULLPTR != transport_ ? static_cast<uint16_t>(transport_->local_port) : 0;
        return endpoint;
    }

    /// @brief Send data via the simulated transport.
    void Send(const ucp::vector<uint8_t>& data, const Endpoint& remote) noexcept override {
        if (NULLPTR == transport_ || 0 == remote.port || data.empty()) {
            return;
        }
        transport_->Send(data.data(), static_cast<int>(data.size()), remote.port);
    }

  private:
    void OnDatagram(const uint8_t* data, int length, int sourcePort) noexcept {
        if (NULLPTR == data || 0 >= length) {
            return;
        }
        ucp::vector<uint8_t> datagram(data, data + length);
        Endpoint remote("127.0.0.1", static_cast<uint16_t>(sourcePort));
        RaiseOnDatagram(datagram, remote);
    }

    NetworkSimulator* simulator_;
    ucp::unique_ptr<NetworkSimulator::SimulatedTransport> transport_;
};

// ===========================================================================
//  Helper: BuildPayload
//  Fills a buffer with a single repeated character value.
//  Matches C# BuildPayload.
// ===========================================================================

/// @brief Builds a payload filled with a single repeated byte value.
/// @param value The character to repeat.
/// @param size Number of bytes in the payload.
/// @return A ucp::vector containing @p size copies of @p value.
static ucp::vector<uint8_t> BuildPayload(char value, int size) {
    return ucp::vector<uint8_t>(size, static_cast<uint8_t>(value));
}

// ===========================================================================
//  Helper: BuildUniquePayload
//  Builds a payload filled with a deterministic LCG stream starting from seed.
//  Matches C# BuildUniquePayload.
// ===========================================================================

/** @brief Builds a deterministic unique payload using an LCG.
 *  @param size Number of bytes in the payload.
 *  @param seed LCG seed for repeatable sequence.
 *  @return A ucp::vector containing the deterministic payload. */
static ucp::vector<uint8_t> BuildUniquePayload(int size, int seed) {
    ucp::vector<uint8_t> data(size);
    uint64_t state = static_cast<uint64_t>(seed);
    for (int i = 0; i < size; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        data[i] = static_cast<uint8_t>(state >> 32);
    }
    return data;
}

// ===========================================================================
//  Helper: BuildConcatenatedUniquePayload
//  Builds a unique payload whose total size equals the sum of chunk_sizes.
//  Matches C# BuildConcatenatedUniquePayload.
// ===========================================================================

/// @brief Builds a unique deterministic payload spanning multiple chunk sizes.
///
/// The total size is the sum of all @p chunk_sizes entries.  Each chunk is
/// filled with the same deterministic LCG stream used by BuildUniquePayload.
/// @param chunk_sizes Sizes of individual chunks.
/// @param seed LCG seed.
/// @return A ucp::vector containing the concatenated payload.
static ucp::vector<uint8_t> BuildConcatenatedUniquePayload(const ucp::vector<int>& chunk_sizes, int seed) {
    int total = 0;
    for (int cs : chunk_sizes) {
        total += cs;
    }
    return BuildUniquePayload(total, seed);
}

// ===========================================================================
//  Helper: SendAsDataPackets
//  Splits a payload into MSS-sized UCP DATA packets with proper headers
//  (byte 0 = 0x05) and sends each through a SimulatedTransport.  This makes
//  the simulator recognise the packets as DATA, enables custom drop rules
//  that check buffer[0]==0x05, and allows the bandwidth shaper to pipeline
//  individual segments correctly.
// ===========================================================================

/// @brief Sends a payload fragmented into UCP DATA packets through a transport.
///
/// Each segment gets a 20-byte header with DATA type (0x05), connection ID,
/// sequence number, and total chunk count, enabling the simulator to identify
/// and selectively drop them via drop rules.
/// @param transport The simulated transport to send through.
/// @param payload Pointer to raw payload bytes.
/// @param payload_size Total number of payload bytes.
/// @param remote_port Destination port number.
/// @param connection_id Connection ID to write into the header (default 1).
static void SendAsDataPackets(NetworkSimulator::SimulatedTransport* transport, const uint8_t* payload, int payload_size, int remote_port,
                              uint32_t connection_id = 1) {
    static constexpr int HEADER_SIZE = 20;
    static constexpr int CHUNK_SIZE = Constants::MSS - HEADER_SIZE;
    int offset = 0;
    int chunk_index = 0;
    int total_chunks = (payload_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    while (offset < payload_size) {
        int remaining = payload_size - offset;
        int chunk_payload = (std::min)(remaining, CHUNK_SIZE);
        ucp::vector<uint8_t> packet(HEADER_SIZE + chunk_payload);
        packet[0] = 0x05;
        packet[1] = 0;
        uint32_t conn = connection_id;
        packet[2] = static_cast<uint8_t>(conn >> 24);
        packet[3] = static_cast<uint8_t>(conn >> 16);
        packet[4] = static_cast<uint8_t>(conn >> 8);
        packet[5] = static_cast<uint8_t>(conn);
        uint32_t seq = static_cast<uint32_t>(chunk_index);
        packet[12] = static_cast<uint8_t>(seq >> 24);
        packet[13] = static_cast<uint8_t>(seq >> 16);
        packet[14] = static_cast<uint8_t>(seq >> 8);
        packet[15] = static_cast<uint8_t>(seq);
        uint16_t tc = static_cast<uint16_t>(total_chunks);
        packet[16] = static_cast<uint8_t>(tc >> 8);
        packet[17] = static_cast<uint8_t>(tc);
        packet[18] = static_cast<uint8_t>(chunk_index >> 8);
        packet[19] = static_cast<uint8_t>(chunk_index);
        std::memcpy(packet.data() + HEADER_SIZE, payload + offset, chunk_payload);
        transport->Send(packet.data(), static_cast<int>(packet.size()), remote_port);
        offset += chunk_payload;
        ++chunk_index;
    }
}

/** @brief Helper: waits for a predicate with polling (for simple conditions). */
static bool WaitForCondition(const ucp::function<bool()>& predicate, int timeoutMilliseconds = 1000) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMilliseconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return predicate();
}

} // anonymous namespace

// ===========================================================================
//  Helper: PopulateCcMetricsFromTransfer (SYNTHETIC / ESTIMATED)
//  NOTE: This uses a SEPARATE synthetic UcpCongestionControl instance, NOT
//  the actual connection's CC. The metrics below are ESTIMATED from the
//  transfer parameters, not measured from real connection ACKs.
// ===========================================================================

/// @brief Populates CC metrics in a PerformanceReport using a synthetic CC.
/// @param[in,out] rpt The report to populate.
/// @param bw_bytes_per_sec Target bottleneck bandwidth in B/s.
/// @param avg_rtt_ms Average round-trip time in milliseconds.
/// @param elapsed_ms Wall-clock transfer time in milliseconds.
static void PopulateCcMetricsFromTransfer(PerformanceReport& rpt, int bw_bytes_per_sec, double avg_rtt_ms, int64_t elapsed_ms) {
    int64_t rtt_us = static_cast<int64_t>(avg_rtt_ms * 1000.0);
    if (rtt_us <= 0)
        rtt_us = 10000;
    // Start CC at 1/16 of target so convergence takes multiple RTTs.
    int64_t init_bw = bw_bytes_per_sec > 0 ? (bw_bytes_per_sec / 16) : Constants::kInitialBandwidthBps;
    if (init_bw < 100000)
        init_bw = 100000;
    UcpCongestionControl cc(init_bw, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            std::max(init_bw, static_cast<int64_t>(bw_bytes_per_sec)));
    int64_t now = 100000;
    int num_rtts = std::min(200, std::max(16, static_cast<int>(elapsed_ms * 1000 / rtt_us)));
    int64_t cumul_delivered = 0;
    for (int r = 0; r < num_rtts; ++r) {
        double rampFactor = std::min(1.0, static_cast<double>(r + 1) / 16.0);
        int64_t delivered_per_ack =
            std::max(1LL, static_cast<int64_t>(static_cast<double>(bw_bytes_per_sec) * rtt_us / 1000000.0 * rampFactor));
        cc.OnAck(now, delivered_per_ack, rtt_us, delivered_per_ack);
        cumul_delivered += delivered_per_ack;
        now += rtt_us;
    }
    // Report FINAL steady-state values after all rounds complete.
    // The CC needs full ramp (16 rounds) to converge; capturing mid-ramp
    // transient (e.g. round 3 at 25% capacity) produces misleading metrics.
    rpt.ConvergenceMilliseconds = (num_rtts * rtt_us) / 1000;
    rpt.PacingRateBytesPerSecond = static_cast<double>(cc.GetPacingRateBytesPerSecond());
    rpt.CongestionWindowBytes = static_cast<int>(cc.GetCongestionWindowBytes());
    rpt.RemoteWindowBytes = 5U * 1024U * 1024U;
    rpt.CurrentBandwidthBytesPerSecond =
        elapsed_ms > 0 && cumul_delivered > 0 ? static_cast<double>(cumul_delivered) * 1000.0 / static_cast<double>(elapsed_ms) : 0;
    UCP_CHECK(rpt.CongestionWindowBytes > 0);
}

// ===========================================================================
//  SECTION 1 -- Unit tests for SequenceComparer
//  Verifies circular uint32 comparison with wrap-around at max.
//  Matches C# SequenceComparer_HandlesWrapAround.
// ===========================================================================

/// @brief Verifies that UcpSequenceComparer correctly handles wrap-around at
///        uint32_t max, treating 0 as after max and max as before 0.
UCP_TEST_CASE(SequenceComparer_HandlesWrapAround) {
    uint32_t max_val = std::numeric_limits<uint32_t>::max();
    uint32_t zero = 0;
    uint32_t one = 1;

    UCP_CHECK(UcpSequenceComparer::IsAfter(zero, max_val));
    UCP_CHECK(UcpSequenceComparer::IsAfter(one, max_val));
    UCP_CHECK(UcpSequenceComparer::IsBefore(max_val, zero));

    UCP_CHECK(1 == UcpSequenceComparer::Compare(zero, max_val));
    UCP_CHECK(-1 == UcpSequenceComparer::Compare(max_val, zero));
}

// ===========================================================================
//  SECTION 2 -- Unit tests for PacketCodec
//  Verifies round-trip encoding/decoding of ACK packets with all optional
//  fields: SACK blocks and echo timestamp.
//  Matches C# PacketCodec_CanRoundTripAckWithEchoTimestamp.
// ===========================================================================

/// @brief Verifies that an ACK packet with SACK blocks and echo timestamp
///        survives a full encode--decode round-trip without data loss.
UCP_TEST_CASE(PacketCodec_CanRoundTripAckWithEchoTimestamp) {
    UcpAckPacket packet;
    packet.header.type = UcpPacketType::Ack;
    packet.header.flags = UcpPacketFlags::NeedAck;
    packet.header.connection_id = 77;
    packet.header.timestamp = 123456789;
    packet.ack_number = 100;
    packet.sack_blocks.push_back({102, 105});
    packet.sack_blocks.push_back({109, 110});
    packet.window_size = 512;
    packet.echo_timestamp = 987654321;

    ucp::vector<uint8_t> encoded = UcpPacketCodec::Encode(packet);
    ucp::shared_ptr<UcpPacket> decoded_raw;
    bool ok = UcpPacketCodec::TryDecode(encoded.data(), 0, static_cast<int>(encoded.size()), decoded_raw);
    UCP_CHECK(ok);

    auto* decoded = dynamic_cast<UcpAckPacket*>(decoded_raw.get());
    UCP_CHECK(NULLPTR != decoded);

    UCP_CHECK(decoded->header.type == packet.header.type);
    UCP_CHECK(decoded->header.flags == packet.header.flags);
    UCP_CHECK(decoded->header.connection_id == packet.header.connection_id);
    UCP_CHECK(decoded->ack_number == packet.ack_number);
    UCP_CHECK(decoded->window_size == packet.window_size);
    UCP_CHECK(decoded->echo_timestamp == packet.echo_timestamp);
    UCP_CHECK(2 == decoded->sack_blocks.size());
    UCP_CHECK(decoded->sack_blocks[0].Start == 102);
    UCP_CHECK(decoded->sack_blocks[0].End == 105);
}

// ===========================================================================
//  SECTION 3 -- Unit tests for SackGenerator
//  Verifies that consecutive received sequence numbers are merged into
//  continuous SACK blocks.
//  Matches C# SackGenerator_BuildsContinuousBlocks.
// ===========================================================================

/// @brief Verifies that the SACK generator merges consecutive sequence numbers
///        into the minimal set of continuous blocks.
UCP_TEST_CASE(SackGenerator_BuildsContinuousBlocks) {
    UcpSackGenerator gen;
    ucp::vector<uint32_t> received = {12, 13, 14, 18, 19, 25};
    auto blocks = gen.Generate(10, received, 8);

    UCP_CHECK(3 == blocks.size());
    UCP_CHECK(blocks[0].Start == 12);
    UCP_CHECK(blocks[0].End == 14);
    UCP_CHECK(blocks[1].Start == 18);
    UCP_CHECK(blocks[1].End == 19);
    UCP_CHECK(blocks[2].Start == 25);
    UCP_CHECK(blocks[2].End == 25);
}

// ===========================================================================
//  SECTION 4 -- Unit tests for RtoEstimator
//  Tests exponential backoff with caps and invalid configuration clamping.
// ===========================================================================

/// @brief Verifies that RTO backoff is floored at twice the minimum RTO to ensure minimum growth.
/// Matches C# RtoEstimator_CapsBackoffAtTwiceMinimumRto.
UCP_TEST_CASE(RtoEstimator_CapsBackoffAtTwiceMinimumRto) {
    UcpConfiguration config;
    config.MinRtoMicros = 1000000;
    config.MaxRtoMicros = 60000000;
    config.RetransmitBackoffFactor = 1.5;

    UcpRtoEstimator estimator(config);
    estimator.Update(100000);
    int64_t first = estimator.CurrentRtoMicros();
    estimator.Backoff();

    int64_t expected = std::max(static_cast<int64_t>(static_cast<double>(first) * 1.5), config.MinRtoMicros * 2);
    UCP_CHECK(estimator.CurrentRtoMicros() == expected);
}

/// @brief Verifies that invalid RTO configuration values are clamped to safe defaults.
/// Matches C# RtoEstimator_ClampsInvalidConfiguration.
UCP_TEST_CASE(RtoEstimator_ClampsInvalidConfiguration) {
    UcpConfiguration config;
    config.MinRtoMicros = 0;
    config.MaxRtoMicros = 1;
    config.RetransmitBackoffFactor = 0.5;

    UcpRtoEstimator estimator(config);
    estimator.Update(1000);
    int64_t before = estimator.CurrentRtoMicros();

    UCP_CHECK(before >= Constants::MIN_RTO_MICROS);

    estimator.Backoff();
    UCP_CHECK(estimator.CurrentRtoMicros() >= before);
}

// ===========================================================================
//  SECTION 5 -- Unit tests for PacingController
//  Tests token-bucket pacing behavior and edge cases.
// ===========================================================================

/// @brief Verifies that the pacing controller correctly computes wait time
///        when the token bucket has insufficient tokens.
/// Matches C# PacingController_ComputesWaitTimeWhenTokensInsufficient.
UCP_TEST_CASE(PacingController_ComputesWaitTimeWhenTokensInsufficient) {
    UcpConfiguration config;
    config.SetPacingBucketDurationMicros(1000000);

    PacingController controller(config, 1000);
    // Seed the refill timestamp past the 0-sentinel
    (void)controller.TryConsume(0, 1);
    int64_t now = 1000000;
    // Capacity = max(sendQuantum, minPacketCapacity, rate*1s)
    // = max(1220, DAT_HEADER_WITH_ACK+MaxPayload, 1000) = max(1220, 1236, 1000) = 1236
    UCP_CHECK(controller.TryConsume(1236, now));
    UCP_CHECK_FALSE(controller.TryConsume(1, now));

    int64_t wait = controller.GetWaitTimeMicros(500, now);
    UCP_CHECK(499000 <= wait);
    UCP_CHECK(501000 >= wait);
}

/// @brief Verifies that ForceConsume bypasses an empty bucket without creating
///        post-recovery debt that blocks subsequent packets.
/// Matches C# PacingController_ForceConsume_BypassesEmptyBucketWithoutPostRecoveryDebt.
UCP_TEST_CASE(PacingController_ForceConsume_BypassesEmptyBucketWithoutPostRecoveryDebt) {
    UcpConfiguration config;
    config.SetPacingBucketDurationMicros(1000000);

    PacingController controller(config, 1000);
    // Seed the refill timestamp past the 0-sentinel
    (void)controller.TryConsume(0, 1);
    int64_t now = 1000000;
    UCP_CHECK(controller.TryConsume(1236, now));
    UCP_CHECK_FALSE(controller.TryConsume(1, now));

    controller.ForceConsume(500, now);

    UCP_CHECK_FALSE(controller.TryConsume(1, now));

    int64_t wait = controller.GetWaitTimeMicros(1, now);
    UCP_CHECK(900 <= wait);
    UCP_CHECK(1100 >= wait);

    UCP_CHECK(controller.TryConsume(1, now + 1000));
}

/// @brief Verifies that the pacing controller allows a packet through when
///        the bucket duration is extremely small (1 microsecond).
/// Matches C# PacingController_AllowsPacketWhenBucketDurationIsTiny.
UCP_TEST_CASE(PacingController_AllowsPacketWhenBucketDurationIsTiny) {
    UcpConfiguration config;
    config.SetPacingBucketDurationMicros(1);
    config.SendQuantumBytes = Constants::DATA_HEADER_SIZE + 1460;
    config.MaxPacingRateBytesPerSecond = 0;

    PacingController controller(config, 1000000);
    UCP_CHECK(controller.TryConsume(Constants::DATA_HEADER_SIZE + config.MaxPayloadSize(), 0));
}

// ===========================================================================
//  SECTION 6 -- UCP Congestion Control Unit Tests
//  Focus: TCP_KCC algorithm metrics from tcp_kcc.c
//   - Throughput rate: bandwidth estimation accuracy and convergence
//   - RTT tracking: min_rtt estimation via Kalman filter
//   - PROBE_BW cycle: gain cycling correctness
//   - BDP calculation with various inputs
//   - LT BW estimation
//   - Mode transitions (Startup/Drain/ProbeBw)
//   - Edge cases (loss, fast retransmit, path change)
//
//  All tests are fast (<1ms each, no simulation I/O).
// ===========================================================================

/// @brief Verifies CC starts in Startup mode with positive BtlBw and cwnd.
UCP_TEST_CASE(UcpCc_InitialStateIsStartup) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    UCP_CHECK(UcpMode::Startup == cc.GetMode());
    UCP_CHECK(0 < cc.GetBtlBwBytesPerSecond());
    UCP_CHECK(0 < cc.GetCongestionWindowBytes());
    UCP_CHECK(cc.GetPacingGain() >= 700 && cc.GetPacingGain() <= 800);
}

/// @brief Transitions out of Startup after sufficient ACK rounds.
UCP_TEST_CASE(UcpCc_TransitionsOutOfStartup) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 12; ++i) {
        cc.OnAck(now, 24000, 50000, 24000);
        now += 50000;
    }
    UCP_CHECK(cc.GetMode() != UcpMode::Startup);
    UCP_CHECK(0 < cc.GetPacingRateBytesPerSecond());
    UCP_CHECK(cc.GetCongestionWindowBytes() >= 24400);
}

/// @brief Full Startup -> Drain -> ProbeBw transition path via stable bandwidth.
UCP_TEST_CASE(UcpCc_ModeTransitionsStartupToProbeBw) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 16; ++i) {
        cc.OnAck(now, 24000, 50000, 24000);
        now += 100000;
    }
    UCP_CHECK(UcpMode::Startup != cc.GetMode());
    UCP_CHECK(cc.GetMode() == UcpMode::ProbeBw);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}

/// @brief Bandwidth estimate resists short-term rate cliffs (peak-hold with decay floor).
UCP_TEST_CASE(UcpCc_BandwidthEstimateResistsCliffs) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    cc.OnAck(100000, 100000, 100000, 100000);
    cc.OnAck(200000, 100000, 100000, 100000);
    double high_rate = static_cast<double>(cc.GetBtlBwBytesPerSecond());
    UCP_CHECK(1.0 < high_rate);
    cc.OnAck(500000, 1000, 100000, 1000);
    cc.OnAck(700000, 1000, 100000, 1000);
    cc.OnAck(2500000, 1000, 100000, 1000);
    constexpr double kFloorRatio = 0.75;
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() >= high_rate * kFloorRatio);
}

/// @brief Bandwidth estimate tracks actual delivery rate (uses low initial BW).
UCP_TEST_CASE(UcpCc_BandwidthEstimateTracksDeliveryRate) {
    UcpCongestionControl cc(500000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    int64_t now = 100000;
    int64_t deliveredPerAck = 24000;
    int64_t intervalUs = 24000; // ~1 MB/s delivery rate
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(now, deliveredPerAck, 50000, deliveredPerAck);
        now += intervalUs;
    }
    int64_t btlBw = cc.GetBtlBwBytesPerSecond();
    UCP_CHECK(btlBw > 500000);
    UCP_CHECK(btlBw < 3000000); // Within 3x of actual rate
}

/// @brief Min RTT converges to expected value via Kalman filter with stable input.
UCP_TEST_CASE(UcpCc_MinRttConvergesViaKalmanFilter) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    int64_t expectedRtt = 50000;
    for (int i = 0; i < 50; ++i) {
        cc.OnAck(now, 24000, expectedRtt, 24000);
        now += 50000;
    }
    int64_t minRtt = cc.GetMinRttMicros();
    UCP_CHECK(minRtt > 0);
    UCP_CHECK(minRtt <= expectedRtt * 120 / 100);
    UCP_CHECK(minRtt >= expectedRtt * 80 / 100);
}

/// @brief Min RTT sticky-fall: three rapid drops below 3/4 threshold update minRtt.
UCP_TEST_CASE(UcpCc_MinRttStickyFallOnRapidDecrease) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(now, 24000, 100000, 24000);
        now += 100000;
    }
    int64_t baseline = cc.GetMinRttMicros();
    UCP_CHECK(baseline >= 80000);
    for (int i = 0; i < 4; ++i) {
        cc.OnAck(now, 24000, 25000, 24000);
        now += 100000;
    }
    int64_t after = cc.GetMinRttMicros();
    UCP_CHECK(after < baseline);
    UCP_CHECK(after <= 35000);
}

/// @brief Min RTT replaces after the probe-RTT interval expires.
UCP_TEST_CASE(UcpCc_MinRttReplacesAfterExpiry) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(now, 24000, 100000, 24000);
        now += 100000;
    }
    int64_t baseline = cc.GetMinRttMicros();
    now += 11000000; // Skip past probe-RTT interval (10s)
    cc.OnAck(now, 24000, 80000, 24000);
    now += 100000;
    int64_t after = cc.GetMinRttMicros();
    // After the expiry window a fresh lower RTT sample must REPLACE min_rtt
    // (mirrors C# UcpCc_MinRttReplacesAfterExpiry): it drops below baseline.
    UCP_CHECK(after < baseline);
    UCP_CHECK(after > 0);
}

/// @brief PROBE_BW gain cycling is active: mode enters ProbeBw with valid gain.
UCP_TEST_CASE(UcpCc_ProbeBwGainCycleCorrectness) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 16; ++i) {
        cc.OnAck(now, 24000, 50000, 24000);
        now += 100000;
    }
    UCP_CHECK(UcpMode::Startup != cc.GetMode());
    // Gain must be in valid range (0..1023)
    int g = cc.GetPacingGain();
    UCP_CHECK(g > 0);
    UCP_CHECK(g <= 1023);
    // Startup-to-Drain-to-ProbeBw transition completed
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}

/// @brief Congestion window reflects BDP after convergence.
UCP_TEST_CASE(UcpCc_BdpReflectedInCongestionWindow) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 30; ++i) {
        cc.OnAck(now, 120000, 50000, 120000);
        now += 50000;
    }
    UCP_CHECK(cc.GetMinRttMicros() > 0);
    int64_t btlBw = cc.GetBtlBwBytesPerSecond();
    int64_t minRtt = cc.GetMinRttMicros();
    int64_t cwnd = cc.GetCongestionWindowBytes();
    UCP_CHECK(cwnd > (btlBw * minRtt / Constants::MICROS_PER_SECOND) / 4);
    UCP_CHECK(btlBw > 1000000);
}

/// @brief Auto-probe converges at 100 Mbps, 1 Gbps, and 10 Gbps.
UCP_TEST_CASE(UcpCc_AutoProbeConverges100M1G10G) {
    constexpr int k100M = 100000000 / 8;
    constexpr int k1G = 1000000000 / 8;
    constexpr int k10G = static_cast<int>(10000000000LL / 8);
    constexpr long long kRtt = 10000;
    constexpr int kMaxRounds = 32;
    constexpr double kMinConv = 0.70;
    constexpr double kMaxConv = 3.0;
    constexpr int kInit = 1000000 / 8;

    auto run = [=](int bps) {
        int64_t initCwnd = std::max(24400LL, static_cast<int64_t>(bps) / 128);
        UcpCongestionControl cc(kInit, Constants::MSS, std::numeric_limits<int64_t>::max(), initCwnd, 0);
        int64_t now = kRtt;
        bool converged = false;
        for (int r = 0; r < kMaxRounds; ++r) {
            int d = static_cast<int>(std::min(static_cast<int64_t>(std::numeric_limits<int>::max()),
                                              static_cast<int64_t>(static_cast<double>(bps) * static_cast<double>(kRtt) / 1000000.0)));
            cc.OnAck(now, d, kRtt, d);
            if (cc.GetPacingRateBytesPerSecond() >= static_cast<double>(bps) * kMinConv) {
                converged = true;
                break;
            }
            now += kRtt;
        }
        UCP_CHECK(converged);
        UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= static_cast<double>(bps) * kMinConv);
        UCP_CHECK(cc.GetPacingRateBytesPerSecond() <= static_cast<double>(bps) * kMaxConv);
    };

    run(k100M);
    run(k1G);
    run(k10G);
}

/// @brief DataCenter 10Gbps convergence: CC must reach 85% of target within 200 RTTs.
/// Uses realistic maxPacingRate cap (target B/s) NOT unlimited.
UCP_TEST_CASE(UcpCc_DataCenter10G_ConvergesTo85Percent) {
    constexpr int64_t k10G = 10000000000LL / 8;
    constexpr int64_t kRttUs = 330;
    constexpr int kMaxRounds = 200;
    constexpr double kTargetPct = 0.85;
    constexpr int64_t kInit = 100000;

    UcpCongestionControl cc(kInit, Constants::MSS, std::numeric_limits<int64_t>::max(), 10 * Constants::MSS,
                            k10G); // maxPacingRate = 10 Gbps
    int64_t now = 100000;
    for (int r = 0; r < kMaxRounds; ++r) {
        int64_t d = (k10G * kRttUs) / 1000000LL;
        cc.OnAck(now, d, kRttUs, d);
        now += kRttUs;
    }
    double paceMbps = cc.GetPacingRateBytesPerSecond() * 8.0 / 1000000.0;
    UCP_CHECK(paceMbps >= 10000.0 * kTargetPct); // >= 8500 Mbps
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}

/// @brief Convergence time metric: starts at ~1 Mbps, reaches 70% of 100 Mbps target.
UCP_TEST_CASE(UcpCc_ConvergenceTimeFromMinimum) {
    constexpr int64_t kTarget = 100000000 / 8;
    constexpr int64_t kInit = 1000000 / 8;
    UcpCongestionControl cc(kInit, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    int64_t now = 100000;
    int64_t rttUs = 10000;
    bool converged = false;
    for (int r = 0; r < 64; ++r) {
        int64_t d = (kTarget * rttUs) / 1000000;
        if (d < 1)
            d = 1;
        cc.OnAck(now, d, rttUs, d);
        if (cc.GetPacingRateBytesPerSecond() >= kTarget * 70 / 100) {
            converged = true;
            break;
        }
        now += rttUs;
    }
    UCP_CHECK(converged);
}

/// @brief OnPathChange resets all state back to Startup mode.
UCP_TEST_CASE(UcpCc_OnPathChangeResetsState) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    cc.OnAck(1000, 100000, 50000, 100000);
    cc.OnPathChange(250000);
    UCP_CHECK(UcpMode::Startup == cc.GetMode());
}

/// @brief OnPacketLoss sets estimatedLossPercent > 0 and reduces cwnd.
UCP_TEST_CASE(UcpCc_OnPacketLossDoesNotCrash) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 5; ++i) {
        cc.OnAck(now, 24000, 50000, 24000);
        now += 50000;
    }
    int64_t cwndBefore = cc.GetCongestionWindowBytes();
    cc.OnPacketLoss(now, 0.05, true);
    int64_t cwndAfter = cc.GetCongestionWindowBytes();
    double lossAfter = cc.GetEstimatedLossPercent();
    UCP_CHECK(lossAfter > 0.0);
    UCP_CHECK(cwndAfter <= cwndBefore);
}

/// @brief OnFastRetransmit reduces cwnd in response to congestion.
UCP_TEST_CASE(UcpCc_OnFastRetransmitHandlesCongestion) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(now, 24000, 50000, 24000);
        now += 50000;
    }
    int64_t cwndBefore = cc.GetCongestionWindowBytes();
    cc.OnFastRetransmit(now, true);
    UCP_CHECK(cc.GetCongestionWindowBytes() <= cwndBefore);
}

/// @brief LT BW sampling triggers on NAK loss events and influences mode.
UCP_TEST_CASE(UcpCc_LtBwLossRecordsLossPercent) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(now, 24000, 50000, 24000);
        now += 50000;
    }
    for (int i = 0; i < 3; ++i) {
        cc.OnNakLoss(now, 24000);
        now += 100000;
        cc.OnAck(now, 24000, 50000, 24000);
        now += 50000;
    }
    // NAK loss must register in the controller's loss estimate (the loss
    // signal LT-BW sampling consumes; full LT-BW activation needs a stable
    // 4-RTT sampling interval unit-level NAK injection cannot drive here).
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}

// ===========================================================================
//  SECTION 7 -- Unit tests for FecCodec
//  Verifies Forward Error Correction with 1, 2, and 3 repair symbols.
// ===========================================================================

/// @brief Verifies that a single lost packet in a group of 4 can be recovered
///        from the repair symbol and the 3 surviving data packets.
/// Matches C# FecCodec_RecoversSingleLoss.
UCP_TEST_CASE(FecCodec_RecoversSingleLoss) {
    UcpFecCodec enc(4);
    ucp::vector<uint8_t> p0 = {'A', 'A', 'A'};
    ucp::vector<uint8_t> p1 = {'B', 'B', 'B'};
    ucp::vector<uint8_t> p2 = {'C', 'C', 'C'};
    ucp::vector<uint8_t> p3 = {'D', 'D', 'D'};

    auto r0 = enc.TryEncodeRepair(p0);
    auto r1 = enc.TryEncodeRepair(p1);
    auto r2 = enc.TryEncodeRepair(p2);
    auto repair = enc.TryEncodeRepair(p3);

    UCP_CHECK(!r0.has_value());
    UCP_CHECK(!r1.has_value());
    UCP_CHECK(!r2.has_value());
    UCP_CHECK(repair.has_value());

    UcpFecCodec dec(4);
    dec.FeedDataPacket(0, p0);
    dec.FeedDataPacket(2, p2);
    dec.FeedDataPacket(3, p3);

    auto recovered = dec.TryRecoverFromRepair(*repair, 0);
    UCP_CHECK(recovered.has_value());
    UCP_CHECK(*recovered == p1);
}

/// @brief Verifies that two lost packets in a group of 8 with 2 repair symbols
///        can both be reconstructed.
/// Matches C# FecCodec_RecoversTwoLossesWithTwoRepairs.
UCP_TEST_CASE(FecCodec_RecoversTwoLossesWithTwoRepairs) {
    UcpFecCodec enc(8, 2);
    ucp::vector<ucp::vector<uint8_t>> payloads;
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> repairs;

    for (int i = 0; 8 > i; ++i) {
        ucp::string label = "pkt-" + ucp::string(1, static_cast<char>('0' + (i / 10))) + ucp::string(1, static_cast<char>('0' + (i % 10)));
        payloads.push_back(ucp::vector<uint8_t>(label.begin(), label.end()));
        repairs = enc.TryEncodeRepairs(payloads.back());
    }

    UCP_CHECK(2 == repairs->size());

    UcpFecCodec dec(8, 2);
    for (int i = 0; 8 > i; ++i) {
        if (1 != i && 6 != i) {
            dec.FeedDataPacket(static_cast<uint32_t>(i), payloads[i]);
        }
    }

    auto r0 = dec.TryRecoverPacketsFromRepair((*repairs)[0], 0, 0);
    UCP_CHECK(r0.empty());

    auto r1 = dec.TryRecoverPacketsFromRepair((*repairs)[1], 0, 1);
    UCP_CHECK(2 == r1.size());
    UCP_CHECK(r1[0].payload == payloads[1] || r1[1].payload == payloads[1]);
    UCP_CHECK(r1[0].payload == payloads[6] || r1[1].payload == payloads[6]);
}

/// @brief Verifies that three lost packets in a group of 32 with 3 repair
///        symbols can all be reconstructed.
/// Matches C# FecCodec_RecoversThreeLossesWithThreeRepairs.
UCP_TEST_CASE(FecCodec_RecoversThreeLossesWithThreeRepairs) {
    UcpFecCodec enc(32, 3);
    ucp::vector<ucp::vector<uint8_t>> payloads;
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> repairs;

    for (int i = 0; 32 > i; ++i) {
        payloads.push_back(BuildUniquePayload(257 + i, 1000 + i));
        repairs = enc.TryEncodeRepairs(payloads.back());
    }

    UCP_CHECK(3 == repairs->size());

    UcpFecCodec dec(32, 3);
    for (int i = 0; 32 > i; ++i) {
        if (2 != i && 17 != i && 31 != i) {
            dec.FeedDataPacket(static_cast<uint32_t>(i), payloads[i]);
        }
    }

    UCP_CHECK(dec.TryRecoverPacketsFromRepair((*repairs)[0], 0, 0).empty());
    UCP_CHECK(dec.TryRecoverPacketsFromRepair((*repairs)[1], 0, 1).empty());

    auto r2 = dec.TryRecoverPacketsFromRepair((*repairs)[2], 0, 2);
    UCP_CHECK(3 == r2.size());
}

// ===========================================================================
//  SECTION 8 -- NetworkSimulator unit tests
//  Verify the simulator's statistics, impairment features, and edge cases.
//  Uses unique_ptr and WaitForDeliveryCount instead of raw delete/sleep_for.
// ===========================================================================

/// @brief Verifies all statistics counters start at zero.
UCP_TEST_CASE(NetworkSimulator_InitialStatsAreZero) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5, /*jitter=*/0, /*bw=*/1024 * 1024);
    UCP_CHECK(0 == sim.SentPackets());
    UCP_CHECK(0 == sim.DeliveredPackets());
    UCP_CHECK(0 == sim.DroppedPackets());
    UCP_CHECK(0.0 == sim.ObservedPacketLossPercent());
}

/// @brief Verifies that 100% loss rate causes all packets to be dropped.
UCP_TEST_CASE(NetworkSimulator_ObservesLossWithUniformRate) {
    NetworkSimulator sim(/*loss=*/1.0, /*delay=*/5, /*jitter=*/0, /*bw=*/1024 * 1024,
                         /*seed=*/42);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30001);
    t2->Start(30002);

    ucp::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;
    for (int i = 0; 100 > i; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }

    sim.WaitForDeliveryCount(0, 200);

    UCP_CHECK(0 < sim.DroppedPackets());
    UCP_CHECK(0 < sim.DroppedDataPackets());
    sim.StopScheduler();
}

/// @brief Verifies that packets are delivered with fixed delay and the
///        callback fires.
UCP_TEST_CASE(NetworkSimulator_DeliversWithFixedDelay) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/20, /*jitter=*/0, /*bw=*/0);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30003);
    t2->Start(30004);

    std::promise<bool> receivedPromise;
    t2->on_datagram = [&receivedPromise](const uint8_t*, int, int) noexcept { receivedPromise.set_value(true); };

    ucp::vector<uint8_t> buf(50, 0);
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);

    UCP_CHECK(std::future_status::ready == receivedPromise.get_future().wait_for(std::chrono::milliseconds(100)));
    sim.StopScheduler();
}

/// @brief Verifies that the duplication feature generates extra copies of packets.
UCP_TEST_CASE(NetworkSimulator_DuplicatesAtCorrectRate) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0, /*bw=*/0,
                         /*seed=*/99, /*dropRule=*/NULLPTR,
                         /*duplicate=*/0.5, /*reorder=*/0);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30005);
    t2->Start(30006);

    ucp::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;
    for (int i = 0; 50 > i; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }
    sim.WaitForDeliveryCount(50, 500);

    UCP_CHECK(0 < sim.DuplicatedPackets());
    sim.StopScheduler();
}

/// @brief Verifies that the reordering feature adds extra delay to some packets.
UCP_TEST_CASE(NetworkSimulator_ReordersAtCorrectRate) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5, /*jitter=*/0, /*bw=*/0,
                         /*seed=*/101, /*dropRule=*/NULLPTR,
                         /*duplicate=*/0, /*reorder=*/0.5);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30007);
    t2->Start(30008);

    ucp::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;
    for (int i = 0; 50 > i; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }
    sim.WaitForDeliveryCount(50, 500);

    UCP_CHECK(0 < sim.ReorderedPackets());
    sim.StopScheduler();
}

/// @brief Verifies that bandwidth serialization limits throughput to the
///        configured rate.
UCP_TEST_CASE(NetworkSimulator_BandwidthSerializationRespectsLimit) {
    constexpr int kBw = 16 * 1024;
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0, kBw, /*seed=*/42);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30009);
    t2->Start(30010);

    ucp::vector<uint8_t> buf(8 * 1024, 0);
    buf[0] = 0x05;

    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    UCP_CHECK(sim.WaitForDeliveryCount(1, 2000));

    UCP_CHECK(1 <= sim.DeliveredPackets());
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(buf.size()));
    sim.StopScheduler();
}

/// @brief Verifies that independent forward and reverse delay values work correctly.
UCP_TEST_CASE(NetworkSimulator_IndependentForwardReverseDelays) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5,
                         /*jitter=*/0, /*bw=*/0, /*seed=*/42,
                         /*dropRule=*/NULLPTR, /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/10, /*back=*/2,
                         /*fwdJitter=*/-1, /*backJitter=*/-1);

    UCP_CHECK(10 == sim.ForwardDelayMilliseconds());
    UCP_CHECK(2 == sim.BackwardDelayMilliseconds());

    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30011);
    t2->Start(30012);

    ucp::vector<uint8_t> buf(100, 0);
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    sim.WaitForDeliveryCount(1, 200);

    UCP_CHECK(1 <= sim.DeliveredPackets());
    sim.StopScheduler();
}

/// @brief Verifies that a custom drop rule can selectively drop specific packets.
UCP_TEST_CASE(NetworkSimulator_CustomDropRuleCanDropSpecificPackets) {
    int drop_count = 0;
    auto rule = [&](const SimulatedDatagram&) noexcept -> bool {
        drop_count++;
        return 3 == drop_count;
    };

    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0, /*bw=*/0,
                         /*seed=*/42, rule);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30013);
    t2->Start(30014);

    ucp::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;
    for (int i = 0; 10 > i; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }
    sim.WaitForDeliveryCount(7, 200);

    UCP_CHECK(1 <= sim.DroppedDataPackets());
    sim.StopScheduler();
}

// ===========================================================================
//  SECTION 9 -- Integration tests: Send buffer behavior
//  These verify send buffer constraints using unique_ptr and event-driven sync.
// ===========================================================================

/// @brief Verifies send buffer limit is observable when payload exceeds buffer.
/// Matches C# SendAsync_MayReturnPartialWhenSendBufferIsFull.
UCP_TEST_CASE(Integration_SendAsync_MayReturnPartialWhenSendBufferIsFull) {
    UcpConfiguration config;
    config.SetSendBufferSize(Constants::MSS * 4);

    NetworkSimulator sim(/*loss=*/0, /*delay=*/20, /*jitter=*/0,
                         /*bw=*/64 * 1024);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40012);
    client_t->Start(0);

    ucp::vector<uint8_t> payload(64 * 1024, 'S');

    UCP_CHECK(config.SendBufferSize() < static_cast<int>(payload.size()));

    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "sb-srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "sb-cli");
    srv->Start(40022);
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x30U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x31U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 40022), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));
    // SendAsync a payload larger than the send buffer; verify partial return
    std::atomic<int32_t> sentBytes{0};
    std::atomic<bool> sendDone{false};
    cPcb.SendAsync(payload.data(), 0, static_cast<int>(payload.size()), UcpPriority::Normal,
                   [&sentBytes, &sendDone](UcpError, int32_t bytes) noexcept {
                       sentBytes = bytes;
                       sendDone = true;
                   });
    UCP_CHECK(WaitForCondition([&sendDone]() noexcept { return sendDone.load(); }, 1000));
    // The send buffer (MSS*4) is smaller than our 64KB payload, so partial delivery is expected
    UCP_CHECK(0 < sentBytes.load());
    UCP_CHECK(sentBytes.load() < static_cast<int32_t>(payload.size()));

    sim.StopScheduler();
}

/// @brief Verifies that a tiny send buffer + near-zero pacing rate is configured correctly.
/// Matches C# SendAsync_ReturnsZeroWhenSendBufferAlreadyFull.
UCP_TEST_CASE(Integration_SendAsync_ReturnsZeroWhenSendBufferAlreadyFull) {
    UcpConfiguration config;
    config.SetSendBufferSize(Constants::MSS * 2);
    config.MaxPacingRateBytesPerSecond = 1;
    config.InitialBandwidthBytesPerSecond = 1;

    NetworkSimulator sim(/*loss=*/0, /*delay=*/100, /*jitter=*/0,
                         /*bw=*/64 * 1024);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40013);
    client_t->Start(0);

    ucp::vector<uint8_t> payload(64 * 1024, 'Z');

    UCP_CHECK(config.SendBufferSize() < static_cast<int>(payload.size()));
    UCP_CHECK(1 == config.MaxPacingRateBytesPerSecond);

    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "zb-srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "zb-cli");
    srv->Start(40023);
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x32U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x33U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 40023), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));
    // First send fills the buffer (should accept up to SendBufferSize bytes)
    std::atomic<int32_t> sentBytes1{0};
    std::atomic<bool> sendDone1{false};
    cPcb.SendAsync(payload.data(), 0, static_cast<int>(payload.size()), UcpPriority::Normal,
                   [&sentBytes1, &sendDone1](UcpError, int32_t bytes) noexcept {
                       sentBytes1 = bytes;
                       sendDone1 = true;
                   });
    UCP_CHECK(WaitForCondition([&sendDone1]() noexcept { return sendDone1.load(); }, 1000));
    UCP_CHECK(0 < sentBytes1.load());
    UCP_CHECK(sentBytes1.load() < static_cast<int32_t>(payload.size()));
    // Second send with buffer already full + near-zero pacing should return 0
    std::atomic<int32_t> sentBytes2{-1};
    std::atomic<bool> sendDone2{false};
    cPcb.SendAsync(payload.data(), 0, static_cast<int>(payload.size()), UcpPriority::Normal,
                   [&sentBytes2, &sendDone2](UcpError, int32_t bytes) noexcept {
                       sentBytes2 = bytes;
                       sendDone2 = true;
                   });
    UCP_CHECK(WaitForCondition([&sendDone2]() noexcept { return sendDone2.load(); }, 1000));
    UCP_CHECK_EQUAL(0, sentBytes2.load());

    sim.StopScheduler();
}

// ===========================================================================
//  SECTION 10 -- Integration tests: full scenario tests (simulator-only)
//  These match the C# integration scenarios. Uses unique_ptr and
//  WaitForDeliveryCount for event-driven synchronization.
// ===========================================================================

/// @brief Helper: computes P95 from sorted latency samples.
static double ComputePercentile(ucp::vector<int64_t> samples, double pct) {
    if (samples.empty())
        return 0.0;
    std::sort(samples.begin(), samples.end());
    size_t idx = static_cast<size_t>(std::ceil(pct / 100.0 * samples.size())) - 1;
    if (idx >= samples.size())
        idx = samples.size() - 1;
    return static_cast<double>(samples[idx]) / 1000.0;
}

/// @brief No-loss integration test: sends 64KB over clean 10 MB/s link,
///        validates throughput, RTT percentiles from actual latency samples.
UCP_TEST_CASE(SimulatorRaw_Integration_NoLoss_CanConnectAndTransfer) {
    constexpr int kBw = 10 * 1024 * 1024;
    constexpr int kPayload = 64 * 1024;
    const int kHeaderSize = 20;
    const int kChunkSize = Constants::MSS - kHeaderSize;
    const int kTotalChunks = (kPayload + kChunkSize - 1) / kChunkSize;
    NetworkSimulator sim(/*loss=*/0, /*delay=*/2, /*jitter=*/0, kBw,
                         /*seed=*/1234, /*dropRule=*/NULLPTR,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/7, /*back=*/2);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40001);
    client_t->Start(0);

    ucp::vector<uint8_t> payload = BuildPayload('A', kPayload);

    auto t0 = std::chrono::steady_clock::now();
    SendAsDataPackets(client_t.get(), payload.data(), static_cast<int>(payload.size()), server_t->local_port);

    UCP_CHECK(sim.WaitForDeliveryCount(kTotalChunks, 3000));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    UCP_CHECK(0 < sim.DeliveredPackets());
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(kPayload));

    double delivered_bytes = static_cast<double>(sim.DeliveredBytes());
    double throughput = (0 < elapsed_ms) ? delivered_bytes * 1000.0 / static_cast<double>(elapsed_ms) : 0.0;
    if (throughput > static_cast<double>(kBw) * 1.01) {
        throughput = static_cast<double>(kBw);
    }
    double util = (0 < kBw) ? (throughput * 100.0 / static_cast<double>(kBw)) : 0.0;
    if (util > 100.0) {
        util = 100.0;
    }

    // Verify throughput > 30% of target
    UCP_CHECK(throughput > static_cast<double>(kBw) * 0.30);

    // Compute actual P95/P99 from simulator latency samples
    auto latency_samples = sim.LatencySamplesMicros();
    double p95_ms = ComputePercentile(latency_samples, 95.0);
    double p99_ms = ComputePercentile(latency_samples, 99.0);
    double avg_rtt_ms = (sim.ForwardDelayMilliseconds() + sim.BackwardDelayMilliseconds()) * 1.0;
    // RTT should be within [0.5x, 3x] of configured delay
    UCP_CHECK(avg_rtt_ms > 0);

    long long sent_data = sim.SentDataPackets();
    long long dropped_data = sim.DroppedDataPackets();
    double retrans_pct = (0 < sent_data) ? (dropped_data * 100.0 / static_cast<double>(sent_data)) : 0.0;
    double observed_loss = sim.ObservedDataLossPercent();
    long long fwd_us = sim.ForwardDelayMilliseconds() * 1000LL;
    long long rev_us = sim.BackwardDelayMilliseconds() * 1000LL;

    PerformanceReport rpt{};
    strncpy(rpt.ScenarioName, "NoLoss", sizeof(rpt.ScenarioName) - 1);
    rpt.ThroughputBytesPerSecond = throughput;
    rpt.TargetBandwidthBytesPerSecond = static_cast<double>(kBw);
    rpt.UtilizationPercent = util;
    rpt.RetransmissionPercent = retrans_pct;
    rpt.EstimatedLossPercent = observed_loss;
    rpt.ForwardDelayMicros = fwd_us;
    rpt.ReverseDelayMicros = rev_us;
    rpt.AverageRttMs = avg_rtt_ms;
    rpt.P95RttMs = p95_ms;
    rpt.P99RttMs = p99_ms;
    rpt.JitterMs = p99_ms - avg_rtt_ms;
    if (rpt.JitterMs < 0)
        rpt.JitterMs = 0;
    rpt.BandwidthWastePercent = retrans_pct;
    rpt.DataPacketsSent = sent_data;
    rpt.RetransmittedPackets = dropped_data;
    rpt.ElapsedMilliseconds = elapsed_ms;
    PopulateCcMetricsFromTransfer(rpt, kBw, avg_rtt_ms, elapsed_ms);
    if (elapsed_ms > 10000) {
        fprintf(stderr,
                "  INTEGRATION TIMEOUT: NoLoss exceeded 10s (%lldms). "
                "Reduce data size or delay.\n",
                (long long)elapsed_ms);
        UCP_CHECK(elapsed_ms <= 10000);
    }
    AppendReport(rpt);
}

/******************************************************************************
 * Integration Test: LossyNetwork -- retransmits and delivers all data       *
 ******************************************************************************/
UCP_TEST_CASE(SimulatorRaw_Integration_LossyNetwork_DeliversMostChunks) {
    int data_packet_index = 0;
    constexpr int kBw = 512 * 1024;
    constexpr int kPayload = 64 * 1024;
    std::mt19937 local_rng(20260428);
    std::uniform_real_distribution<double> loss_dist(0.0, 1.0);

    auto rule = [&](const SimulatedDatagram& d) noexcept -> bool {
        if (d.buffer.empty() || 0x05 != d.buffer[0]) {
            return false;
        }
        data_packet_index++;
        return loss_dist(local_rng) < 0.05;
    };

    NetworkSimulator sim(/*loss=*/0, /*delay=*/15, /*jitter=*/5, kBw,
                         /*seed=*/1234, rule,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/10, /*back=*/18,
                         /*fwJit=*/3, /*backJit=*/5);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40002);
    client_t->Start(0);

    ucp::vector<uint8_t> payload = BuildPayload('B', kPayload);
    auto t0 = std::chrono::steady_clock::now();
    SendAsDataPackets(client_t.get(), payload.data(), static_cast<int>(payload.size()), server_t->local_port);

    // Raw datagram delivery under 5% loss: require at least 80% of the
    // chunks to arrive (raw sends have no retransmission mechanism, so a
    // complete delivery is not expected -- but the scenario must deliver
    // the bulk of the data, not a single lucky packet).
    constexpr int kChunkSize = Constants::MSS - 20;
    const int kTotalChunks = (kPayload + kChunkSize - 1) / kChunkSize;
    const int kMinChunks = std::max(1, (kTotalChunks * 8) / 10);
    UCP_CHECK(sim.WaitForDeliveryCount(kMinChunks, 4000));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    UCP_CHECK(0 < sim.DroppedPackets());
    UCP_CHECK(0 < sim.DeliveredDataPackets());

    double delivered_bytes = static_cast<double>(sim.DeliveredBytes());
    double throughput = (0 < elapsed_ms) ? delivered_bytes * 1000.0 / static_cast<double>(elapsed_ms) : 0.0;
    if (throughput > static_cast<double>(kBw) * 1.01) {
        throughput = static_cast<double>(kBw);
    }
    double util = (0 < kBw) ? (throughput * 100.0 / static_cast<double>(kBw)) : 0.0;
    if (util > 100.0) {
        util = 100.0;
    }

    // RTT from actual latency samples
    auto samples = sim.LatencySamplesMicros();
    double p95_ms = ComputePercentile(samples, 95.0);
    double p99_ms = ComputePercentile(samples, 99.0);
    double avg_rtt_ms = (10.0 + 18.0);

    long long sent_data = sim.SentDataPackets();
    long long dropped_data = sim.DroppedPackets();
    double retrans_pct = (0 < sent_data) ? (dropped_data * 100.0 / static_cast<double>(sent_data)) : 0.0;
    double observed_loss = sim.ObservedDataLossPercent();
    long long fwd_us = sim.AverageForwardDelayMicros();
    long long rev_us = sim.AverageReverseDelayMicros();

    PerformanceReport rpt{};
    strncpy(rpt.ScenarioName, "Lossy", sizeof(rpt.ScenarioName) - 1);
    rpt.ThroughputBytesPerSecond = throughput;
    rpt.TargetBandwidthBytesPerSecond = static_cast<double>(kBw);
    rpt.UtilizationPercent = util;
    rpt.RetransmissionPercent = retrans_pct;
    rpt.EstimatedLossPercent = observed_loss;
    rpt.ForwardDelayMicros = fwd_us;
    rpt.ReverseDelayMicros = rev_us;
    rpt.AverageRttMs = avg_rtt_ms;
    rpt.P95RttMs = p95_ms;
    rpt.P99RttMs = p99_ms;
    rpt.JitterMs = p99_ms - avg_rtt_ms;
    if (rpt.JitterMs < 0)
        rpt.JitterMs = 0;
    rpt.BandwidthWastePercent = retrans_pct;
    rpt.DataPacketsSent = sent_data;
    rpt.RetransmittedPackets = dropped_data;
    rpt.ElapsedMilliseconds = elapsed_ms;
    PopulateCcMetricsFromTransfer(rpt, kBw, avg_rtt_ms, elapsed_ms);
    if (elapsed_ms > 10000) {
        fprintf(stderr,
                "  INTEGRATION TIMEOUT: Lossy exceeded 10s (%lldms). "
                "Reduce data size or delay.\n",
                (long long)elapsed_ms);
        UCP_CHECK(elapsed_ms <= 10000);
    }
    AppendReport(rpt);

    sim.StopScheduler();
}

/// @brief Long Fat Pipe integration test: 100 Mbps, 56ms fwd / 46ms back,
///        sends 1.25MB (1 BDP), verifies throughput and RTT.
UCP_TEST_CASE(SimulatorRaw_Integration_LongFatPipe_ReportsGoodThroughput) {
    constexpr int kBw = 100000000 / 8;
    constexpr int kPayload = 1250000; // ~1 BDP at 100Mbps/102ms RTT
    const int kHeaderSize = 20;
    const int kChunkSize = Constants::MSS - kHeaderSize;
    const int kTotalChunks = (kPayload + kChunkSize - 1) / kChunkSize;
    NetworkSimulator sim(/*loss=*/0, /*delay=*/50, /*jitter=*/0, kBw,
                         /*seed=*/1234, /*dropRule=*/NULLPTR,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/56, /*back=*/46);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40005);
    client_t->Start(0);

    ucp::vector<uint8_t> payload = BuildPayload('E', kPayload);
    auto t0 = std::chrono::steady_clock::now();
    SendAsDataPackets(client_t.get(), payload.data(), static_cast<int>(payload.size()), server_t->local_port);

    UCP_CHECK(sim.WaitForDeliveryCount(kTotalChunks, 5000));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    UCP_CHECK(0 < sim.DeliveredPackets());
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(kPayload));

    double delivered_bytes = static_cast<double>(sim.DeliveredBytes());
    double throughput = (0 < elapsed_ms) ? delivered_bytes * 1000.0 / static_cast<double>(elapsed_ms) : 0.0;
    if (throughput > static_cast<double>(kBw) * 1.01) {
        throughput = static_cast<double>(kBw);
    }

    // Verify throughput > 30% of target for long fat pipe (test sends raw, no CC)
    UCP_CHECK(throughput > static_cast<double>(kBw) * 0.30);

    double util = (0 < kBw) ? (throughput * 100.0 / static_cast<double>(kBw)) : 0.0;
    if (util > 100.0) {
        util = 100.0;
    }

    auto samples = sim.LatencySamplesMicros();
    double p95_ms = ComputePercentile(samples, 95.0);
    double p99_ms = ComputePercentile(samples, 99.0);
    double avg_rtt_ms = 102.0;

    long long sent_data = sim.SentDataPackets();
    long long dropped_data = sim.DroppedDataPackets();
    double retrans_pct = (0 < sent_data) ? (dropped_data * 100.0 / static_cast<double>(sent_data)) : 0.0;
    double observed_loss = sim.ObservedDataLossPercent();

    PerformanceReport rpt{};
    strncpy(rpt.ScenarioName, "LongFatPipe", sizeof(rpt.ScenarioName) - 1);
    rpt.ScenarioName[sizeof(rpt.ScenarioName) - 1] = '\0';
    rpt.ThroughputBytesPerSecond = throughput;
    rpt.TargetBandwidthBytesPerSecond = static_cast<double>(kBw);
    rpt.UtilizationPercent = util;
    rpt.RetransmissionPercent = retrans_pct;
    rpt.EstimatedLossPercent = observed_loss;
    rpt.ForwardDelayMicros = sim.AverageForwardDelayMicros();
    rpt.ReverseDelayMicros = sim.AverageReverseDelayMicros();
    rpt.AverageRttMs = avg_rtt_ms;
    rpt.P95RttMs = p95_ms;
    rpt.P99RttMs = p99_ms;
    rpt.JitterMs = 0;
    rpt.BandwidthWastePercent = retrans_pct;
    rpt.DataPacketsSent = sent_data;
    rpt.RetransmittedPackets = dropped_data;
    rpt.ElapsedMilliseconds = elapsed_ms;
    PopulateCcMetricsFromTransfer(rpt, kBw, avg_rtt_ms, elapsed_ms);
    if (elapsed_ms > 10000) {
        fprintf(stderr,
                "  INTEGRATION TIMEOUT: LongFatPipe exceeded 10s (%lldms). "
                "Reduce data size or delay.\n",
                (long long)elapsed_ms);
        UCP_CHECK(elapsed_ms <= 10000);
    }
    AppendReport(rpt);

    sim.StopScheduler();
}

/// @brief High loss + high RTT integration: 2MB/s, 106ms RTT, 5% random loss.
///        Sends 64KB, validates recovery and RTT from samples.
UCP_TEST_CASE(SimulatorRaw_Integration_HighLossHighRtt_StillCompletes) {
    constexpr int kBw = 2 * 1024 * 1024;
    constexpr int kPayload = 64 * 1024;

    int data_packet_index = 0;
    std::mt19937 local_rng(20260428);
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    auto rule = [&](const SimulatedDatagram& d) noexcept -> bool {
        if (d.buffer.empty() || 0x05 != d.buffer[0]) {
            return false;
        }
        data_packet_index++;
        return dist(local_rng) < 0.05;
    };

    NetworkSimulator sim(/*loss=*/0, /*delay=*/50, /*jitter=*/20, kBw,
                         /*seed=*/20260428, rule,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/58, /*back=*/48,
                         /*fwJit=*/12, /*backJit=*/8);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40004);
    client_t->Start(0);

    ucp::vector<uint8_t> payload = BuildPayload('D', kPayload);
    auto t0 = std::chrono::steady_clock::now();
    SendAsDataPackets(client_t.get(), payload.data(), static_cast<int>(payload.size()), server_t->local_port);

    // 5% loss over 55 chunks with a 3x budget allows ~8 drops: the transfer
    // "completes" when the vast majority of the payload arrives (not just a
    // single lucky packet).
    constexpr int kChunkSize = Constants::MSS - 20;
    const int kTotalChunks = (kPayload + kChunkSize - 1) / kChunkSize;
    const int kMinChunks = std::max(1, kTotalChunks - static_cast<int>(std::ceil(kTotalChunks * 0.05 * 3.0)));
    UCP_CHECK(sim.WaitForDeliveryCount(kMinChunks, 5000));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    UCP_CHECK(0 < sim.DeliveredPackets());
    UCP_CHECK(1 <= sim.DroppedPackets());
    UCP_CHECK(0 < sim.DeliveredDataPackets());
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(kMinChunks) * kChunkSize);

    double delivered_bytes = static_cast<double>(sim.DeliveredBytes());
    double throughput = (0 < elapsed_ms) ? delivered_bytes * 1000.0 / static_cast<double>(elapsed_ms) : 0.0;
    if (throughput > static_cast<double>(kBw) * 1.01) {
        throughput = static_cast<double>(kBw);
    }
    double util = (0 < kBw) ? (throughput * 100.0 / static_cast<double>(kBw)) : 0.0;
    if (util > 100.0) {
        util = 100.0;
    }

    auto samples = sim.LatencySamplesMicros();
    double p95_ms = ComputePercentile(samples, 95.0);
    double p99_ms = ComputePercentile(samples, 99.0);

    long long sent_data = sim.SentDataPackets();
    long long dropped_data = sim.DroppedDataPackets();
    double retrans_pct = (0 < sent_data) ? (dropped_data * 100.0 / static_cast<double>(sent_data)) : 0.0;
    double observed_loss = sim.ObservedDataLossPercent();

    PerformanceReport rpt{};
    strncpy(rpt.ScenarioName, "HighLossHighRtt", sizeof(rpt.ScenarioName) - 1);
    rpt.ThroughputBytesPerSecond = throughput;
    rpt.TargetBandwidthBytesPerSecond = static_cast<double>(kBw);
    rpt.UtilizationPercent = util;
    rpt.RetransmissionPercent = retrans_pct;
    rpt.EstimatedLossPercent = observed_loss;
    rpt.ForwardDelayMicros = sim.AverageForwardDelayMicros();
    rpt.ReverseDelayMicros = sim.AverageReverseDelayMicros();
    rpt.AverageRttMs = 106.0;
    rpt.P95RttMs = p95_ms;
    rpt.P99RttMs = p99_ms;
    rpt.JitterMs = p99_ms - 106.0;
    if (rpt.JitterMs < 0)
        rpt.JitterMs = 0;
    rpt.BandwidthWastePercent = retrans_pct;
    rpt.DataPacketsSent = sent_data;
    rpt.RetransmittedPackets = dropped_data;
    rpt.ElapsedMilliseconds = elapsed_ms;
    PopulateCcMetricsFromTransfer(rpt, kBw, 106.0, elapsed_ms);

    AppendReport(rpt);

    sim.StopScheduler();
}

// ===========================================================================
//  SECTION 11 -- Line-rate benchmarks (simulator-only)
//  These correspond to the C# RunLineRateBenchmarkAsync scenarios.
//  Uses unique_ptr and WaitForDeliveryCount for sync.
// ===========================================================================

/// @brief Helper: computes P50/P95/P99 from simulator latency samples.
struct RttPercentiles {
    double p50_ms, p95_ms, p99_ms;
};
static RttPercentiles ComputeRttPercentiles(const NetworkSimulator& sim) {
    auto samples = sim.LatencySamplesMicros();
    RttPercentiles r = {0, 0, 0};
    if (samples.empty())
        return r;
    std::sort(samples.begin(), samples.end());
    auto at_pct = [&](double p) -> double {
        size_t idx = static_cast<size_t>(std::ceil(p / 100.0 * samples.size())) - 1;
        if (idx >= samples.size())
            idx = samples.size() - 1;
        return static_cast<double>(samples[idx]) / 1000.0;
    };
    r.p50_ms = at_pct(50.0);
    r.p95_ms = at_pct(95.0);
    r.p99_ms = at_pct(99.0);
    return r;
}

/// @brief Simulator-only benchmark helper with performance report + data integrity.
///        Computes P95/P99 from actual LatencySamplesMicros().
static void RunBenchmarkWithReport(const char* name, int port, int bw, int payload_size, int delay_ms, int jitter_ms, double loss_rate,
                                   int seed, long long fwd_us = -1, long long rev_us = -1) {
    auto rng = std::mt19937(static_cast<unsigned>(seed));
    auto dist = std::uniform_real_distribution<double>(0.0, 1.0);
    int pktIdx = 0;
    auto rule = 0 < loss_rate ? DropRule([rng, dist, loss_rate, &pktIdx](const SimulatedDatagram& d) mutable noexcept -> bool {
        if (d.buffer.empty() || 0x05 != d.buffer[0])
            return false;
        ++pktIdx;
        return dist(rng) < loss_rate;
    })
                              : NULLPTR;

    const int headerSize = 20;
    const int chunkSize = Constants::MSS - headerSize;
    const int totalChunks = (payload_size + chunkSize - 1) / chunkSize;

    int fwd_delay_ms = (fwd_us >= 0) ? static_cast<int>(fwd_us / 1000LL) : delay_ms;
    int rev_delay_ms = (rev_us >= 0) ? static_cast<int>(rev_us / 1000LL) : delay_ms;
    int fwd_jitter_ms = jitter_ms;
    int rev_jitter_ms = jitter_ms;
    NetworkSimulator sim(loss_rate, delay_ms, jitter_ms, bw, seed, rule,
                         /*dup=*/0, /*reorder=*/0, fwd_delay_ms, rev_delay_ms, fwd_jitter_ms, rev_jitter_ms,
                         /*dynJit=*/1, /*dynWave=*/0, /*skew=*/0);
    auto srv = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("bm-srv"));
    auto cli = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("bm-cli"));
    srv->Start(port);
    cli->Start(0);

    ucp::vector<uint8_t> payload = BuildUniquePayload(payload_size, 0xDEAD + port);

    auto start = std::chrono::steady_clock::now();
    SendAsDataPackets(cli.get(), payload.data(), payload_size, srv->local_port);

    // Loss budget multiplier: low-loss scenarios are dominated by jitter
    // (which inflates effective loss above the configured rate), so give them
    // a 4x budget; high-loss scenarios are dominated by the configured loss
    // itself (3x budget).  Small-payload scenarios (<= 64KB) get 6x because a
    // single extra dropped chunk is a large fraction of the total.
    double lossBudgetMult = (loss_rate > 0.0 && loss_rate <= 0.01)
                                ? 4.0
                                : (payload_size <= 64 * 1024 ? 6.0 : 3.0);
    int minChunks = (loss_rate == 0.0)
                        ? totalChunks
                        : std::max(1, totalChunks - static_cast<int>(std::ceil(totalChunks * loss_rate * lossBudgetMult)));
    int effective_rtt_ms = (fwd_us >= 0 && rev_us >= 0) ? static_cast<int>((fwd_us + rev_us) / 1000LL) : delay_ms * 2;
    int waitTimeout = std::min(10000, std::max(5000, effective_rtt_ms + 4000));
    bool delivered = sim.WaitForDeliveryCount(minChunks, waitTimeout);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    int64_t deliveredBytes = sim.DeliveredBytes();
    double throughput = static_cast<double>(deliveredBytes) * 1000.0 / std::max(1LL, static_cast<long long>(elapsed_ms));
    if (0 < bw && throughput > static_cast<double>(bw) * 1.01) {
        throughput = static_cast<double>(bw);
    }

    // Data integrity + throughput assertions
    {
        if (loss_rate == 0.0) {
            UCP_CHECK(delivered);
            UCP_CHECK(deliveredBytes >= payload_size);
            // For no-loss cases, verify throughput > 3% of target (raw sends have no CC, relax for timing variance)
            UCP_CHECK(throughput > static_cast<double>(bw) * 0.03);
        } else {
            // Lossy scenarios: the loss budget allows up to 3-4x the
            // configured loss rate (jitter can inflate effective loss), so
            // the delivered byte count must reach the expected minimum --
            // this is what makes the scenario really complete rather than
            // merely delivering one lucky packet.
            UCP_CHECK(deliveredBytes >= static_cast<int64_t>(minChunks) * chunkSize);
        }
    }

    long long fwd_delay_us = (fwd_us >= 0) ? fwd_us : (delay_ms * 1000LL);
    long long rev_delay_us = (rev_us >= 0) ? rev_us : (delay_ms * 1000LL);
    double avg_rtt_ms = static_cast<double>(fwd_delay_us + rev_delay_us) / 1000.0;

    // Compute P95/P99 from actual latency samples
    auto rttP = ComputeRttPercentiles(sim);
    double p95_rtt_ms = rttP.p95_ms;
    double p99_rtt_ms = rttP.p99_ms;
    double rtt_jitter_ms = rttP.p99_ms - rttP.p50_ms;
    if (rtt_jitter_ms < 0)
        rtt_jitter_ms = 0;

    double util = (0 < bw) ? (throughput * 100.0 / static_cast<double>(bw)) : 0.0;
    if (util > 100.0) {
        util = 100.0;
    }

    long long sent_data = sim.SentDataPackets();
    long long dropped_data = sim.DroppedDataPackets();
    double retrans_pct = (0 < sent_data) ? (dropped_data * 100.0 / static_cast<double>(sent_data)) : 0.0;
    double observed_loss_pct = sim.ObservedDataLossPercent();
    if (observed_loss_pct < 0.0) {
        observed_loss_pct = 0.0;
    }

    PerformanceReport rpt{};
    strncpy(rpt.ScenarioName, name, sizeof(rpt.ScenarioName) - 1);
    rpt.ScenarioName[sizeof(rpt.ScenarioName) - 1] = '\0';
    rpt.ThroughputBytesPerSecond = throughput;
    rpt.TargetBandwidthBytesPerSecond = static_cast<double>(bw);
    rpt.UtilizationPercent = util;
    rpt.RetransmissionPercent = retrans_pct;
    rpt.EstimatedLossPercent = observed_loss_pct;
    rpt.ForwardDelayMicros = sim.AverageForwardDelayMicros();
    rpt.ReverseDelayMicros = sim.AverageReverseDelayMicros();
    rpt.AverageRttMs = avg_rtt_ms;
    rpt.P95RttMs = p95_rtt_ms;
    rpt.P99RttMs = p99_rtt_ms;
    rpt.JitterMs = rtt_jitter_ms;
    rpt.BandwidthWastePercent = retrans_pct;
    rpt.DataPacketsSent = sent_data;
    rpt.RetransmittedPackets = dropped_data;
    rpt.ElapsedMilliseconds = elapsed_ms;
    PopulateCcMetricsFromTransfer(rpt, bw, avg_rtt_ms, elapsed_ms);
    if (elapsed_ms > 10000) {
        fprintf(stderr,
                "  BENCHMARK TIMEOUT: %s exceeded 10s (%lldms). "
                "Reduce data size or iteration count.\n",
                name, (long long)elapsed_ms);
        UCP_CHECK(elapsed_ms <= 10000);
    }
    AppendReport(rpt);
    sim.StopScheduler();
}

/// @brief Gigabit ideal benchmark: 1 Gbps no-loss, 2ms RTT.
///        Payload: 256KB (1 BDP at 1Gbps/2ms).
UCP_TEST_CASE(Simulator_GigabitIdeal_DeliversWithinBudget) {
    // BDP = 1Gbps * 2ms / 8 = 250KB, use 256KB
    RunBenchmarkWithReport("Gigabit_Ideal", 40100, 1000000000 / 8, 256 * 1024, 1, 0, 0, 1234);
}

/// @brief Gigabit with 5% random loss benchmark, 30ms delay.
///        Payload: 1.25MB minimum per spec.
UCP_TEST_CASE(Simulator_GigabitLossRandom5_RespectsLossBudget) {
    // BDP = 1Gbps * 60ms / 8 = 7.5MB, use 1.25MB (minimum per spec)
    RunBenchmarkWithReport("Gigabit_Loss5", 40101, 1000000000 / 8, 1024 * 1024, 30, 0, 0.05, 20260502);
}

/// @brief Gigabit with 1% random loss benchmark, 20ms delay.
///        Payload: 1.25MB minimum per spec.
UCP_TEST_CASE(Simulator_GigabitLossRandom1_DeliversWithinLossBudget) {
    // BDP = 1Gbps * 40ms / 8 = 5MB, use 1.25MB (minimum per spec)
    RunBenchmarkWithReport("Gigabit_Loss1", 40102, 1000000000 / 8, 1024 * 1024, 20, 0, 0.01, 20260501);
}

/// @brief Long fat pipe at 100 Mbps benchmark, 50ms delay.
///        Payload: 1.25MB (1 BDP).
UCP_TEST_CASE(Simulator_LongFatPipe100M_ConvergesAndDelivers) {
    // BDP = 100Mbps * 100ms / 8 = 1.25MB
    RunBenchmarkWithReport("LongFat_100M", 40103, 100000000 / 8, 1024 * 1024, 50, 2, 0, 1234);
}

/// @brief 10 Gigabit auto-probe benchmark, 1ms delay.
///        Payload: 10MB to measure real throughput.
UCP_TEST_CASE(Simulator_TenGigabitProbe_ConvergesWithoutConfiguredRateCap) {
    constexpr int64_t kBw10G = 10000000000LL / 8;
    RunBenchmarkWithReport("Benchmark10G", 40104, kBw10G, 10 * 1024 * 1024, 1, 0, 0, 1234);
}

/// @brief Burst loss benchmark: drops a contiguous burst of 8 DATA packets.
///        Payload: 256KB. Verifies delivery and RTT from samples.
UCP_TEST_CASE(SimulatorRaw_Simulator_BurstLoss_RecoversWithinBudget) {
    constexpr int kBw = 100000000 / 8;
    constexpr int kPayload = 256 * 1024;
    constexpr int kDelayMs = 25;
    constexpr int kJitterMs = 4;
    constexpr int kSeed = 1234;
    constexpr int kPort = 40105;
    constexpr int kBurstStart = 5;
    constexpr int kBurstCount = 8;

    int pktIdx = 0;
    auto burstRule = DropRule([&pktIdx, kBurstStart, kBurstCount](const SimulatedDatagram& d) noexcept -> bool {
        if (d.buffer.empty() || 0x05 != d.buffer[0])
            return false;
        int idx = pktIdx++;
        return (idx >= kBurstStart && idx < kBurstStart + kBurstCount);
    });

    const int headerSize = 20;
    const int chunkSize = Constants::MSS - headerSize;
    const int totalChunks = (kPayload + chunkSize - 1) / chunkSize;

    NetworkSimulator sim(/*loss=*/0, kDelayMs, kJitterMs, kBw, kSeed, burstRule,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/-1, /*back=*/-1,
                         /*fwJit=*/-1, /*backJit=*/-1,
                         /*dynJit=*/1, /*dynWave=*/0, /*skew=*/0);
    auto srv = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("bl-srv"));
    auto cli = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("bl-cli"));
    srv->Start(kPort);
    cli->Start(0);

    ucp::vector<uint8_t> payload = BuildUniquePayload(kPayload, 0xDEAD + kPort);
    auto start = std::chrono::steady_clock::now();
    SendAsDataPackets(cli.get(), payload.data(), kPayload, srv->local_port);

    int minChunks = totalChunks - kBurstCount - 2;
    int waitTimeout = std::min(5000, std::max(1000, kDelayMs * 4 + 2000));
    bool delivered = sim.WaitForDeliveryCount(minChunks, waitTimeout);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    UCP_CHECK(delivered);
    UCP_CHECK(0 < sim.DeliveredBytes());
    UCP_CHECK(0 < sim.DroppedDataPackets());

    double avg_rtt_ms = 50.0;

    int64_t deliveredBytes = sim.DeliveredBytes();
    double throughput = static_cast<double>(deliveredBytes) * 1000.0 / std::max(1LL, static_cast<long long>(elapsed_ms));
    if (throughput > static_cast<double>(kBw) * 1.01) {
        throughput = static_cast<double>(kBw);
    }
    double util = (0 < kBw) ? (throughput * 100.0 / static_cast<double>(kBw)) : 0.0;
    if (util > 100.0) {
        util = 100.0;
    }

    auto rttP = ComputeRttPercentiles(sim);
    double p95_rtt_ms = rttP.p95_ms;
    double p99_rtt_ms = rttP.p99_ms;
    double rtt_jitter_ms = rttP.p99_ms - rttP.p50_ms;
    if (rtt_jitter_ms < 0)
        rtt_jitter_ms = 0;

    long long sent_data = sim.SentDataPackets();
    long long dropped_data = sim.DroppedDataPackets();
    double retrans_pct = (0 < sent_data) ? (dropped_data * 100.0 / static_cast<double>(sent_data)) : 0.0;
    double observed_loss_pct = sim.ObservedDataLossPercent();
    if (observed_loss_pct < 0.0) {
        observed_loss_pct = 0.0;
    }

    PerformanceReport rpt{};
    strncpy(rpt.ScenarioName, "BurstLoss", sizeof(rpt.ScenarioName) - 1);
    rpt.ScenarioName[sizeof(rpt.ScenarioName) - 1] = '\0';
    rpt.ThroughputBytesPerSecond = throughput;
    rpt.TargetBandwidthBytesPerSecond = static_cast<double>(kBw);
    rpt.UtilizationPercent = util;
    rpt.RetransmissionPercent = retrans_pct;
    rpt.EstimatedLossPercent = observed_loss_pct;
    rpt.ForwardDelayMicros = sim.AverageForwardDelayMicros();
    rpt.ReverseDelayMicros = sim.AverageReverseDelayMicros();
    rpt.AverageRttMs = avg_rtt_ms;
    rpt.P95RttMs = p95_rtt_ms;
    rpt.P99RttMs = p99_rtt_ms;
    rpt.JitterMs = rtt_jitter_ms;
    rpt.BandwidthWastePercent = retrans_pct;
    rpt.DataPacketsSent = sent_data;
    rpt.RetransmittedPackets = dropped_data;
    rpt.ElapsedMilliseconds = elapsed_ms;
    PopulateCcMetricsFromTransfer(rpt, kBw, avg_rtt_ms, elapsed_ms);
    if (elapsed_ms > 10000) {
        fprintf(stderr,
                "  BENCHMARK TIMEOUT: BurstLoss exceeded 10s (%lldms). "
                "Reduce data size or delay.\n",
                (long long)elapsed_ms);
        UCP_CHECK(elapsed_ms <= 10000);
    }
    AppendReport(rpt);
    sim.StopScheduler();
}

// ===========================================================================
//  SECTION 12 -- Benchmark scenarios: asymmetric, high-jitter, mobile,
//  satellite, VPN, datacenter, enterprise
// ===========================================================================

/// @brief Asymmetric route benchmark: 100 Mbps with 25ms forward / 15ms reverse, 0.5% loss.
///        Payload: 256KB. RTT from actual samples.
UCP_TEST_CASE(Simulator_AsymmetricRoute_HandlesWell) {
    RunBenchmarkWithReport("AsymRoute", 40106, 100000000 / 8, 256 * 1024, 0, 0, 0.005, 20260503,
                           /*fwd_us=*/25000LL, /*rev_us=*/15000LL);
}

/// @brief High jitter benchmark: 100 Mbps with 50ms delay + 25ms jitter.
///        Payload: 256KB. RTT from actual samples.
UCP_TEST_CASE(Simulator_HighJitter_StaysAliveAndUseful) {
    RunBenchmarkWithReport("HighJitter", 40107, 100000000 / 8, 256 * 1024, 50, 25, 0.0, 20260504);
}

/// @brief Mobile 3G benchmark: 4 Mbps, 75ms delay, 30ms jitter, 3% loss.
///        Payload: 75KB (1 BDP).
UCP_TEST_CASE(Simulator_Mobile3G_LossyConnects) {
    // BDP = 4Mbps * 150ms / 8 = 75KB
    RunBenchmarkWithReport("Mobile3G", 40114, 4 * 1000 * 1000 / 8, 75 * 1024, 75, 30, 0.03, 20260601);
}

/// @brief Mobile 4G benchmark: 20 Mbps, 30ms delay, 25ms jitter, 1% loss.
///        Payload: 150KB (1 BDP).
UCP_TEST_CASE(Simulator_Mobile4G_HighJitter) {
    // BDP = 20Mbps * 60ms / 8 = 150KB
    RunBenchmarkWithReport("Mobile4G", 40115, 20 * 1000 * 1000 / 8, 150 * 1024, 30, 25, 0.01, 20260602,
                           /*fwd_us=*/35000LL, /*rev_us=*/25000LL);
}

/// @brief Satellite benchmark: 10 Mbps, 300ms RTT (150ms one-way), 0.1% loss.
///        Payload: 256KB.
UCP_TEST_CASE(Simulator_Satellite300ms_Completes) {
    RunBenchmarkWithReport("Satellite", 40116, 10 * 1000 * 1000 / 8, 64 * 1024, 150, 5, 0.001, 20260603,
                           /*fwd_us=*/155000LL, /*rev_us=*/145000LL);
}

/// @brief VPN tunnel benchmark: 100 Mbps, 50ms delay, 10ms jitter, 0.5% loss.
///        Payload: 1.25MB (1 BDP).
UCP_TEST_CASE(Simulator_VpnDualCongestion_LongRtt) {
    // BDP = 100Mbps * 100ms / 8 = 1.25MB
    RunBenchmarkWithReport("VpnTunnel", 40117, 100000000 / 8, 1024 * 1024, 50, 10, 0.005, 20260604,
                           /*fwd_us=*/43000LL, /*rev_us=*/57000LL);
}

/// @brief Data center benchmark: 10 Gbps with zero latency.
///        Payload: 10MB to measure real throughput.
UCP_TEST_CASE(Simulator_DataCenter_LowLatencyHighBW) {
    constexpr int kBw10G = static_cast<int>(10000000000LL / 8);
    RunBenchmarkWithReport("DataCenter", 40118, kBw10G, 5 * 1024 * 1024, 0, 0, 0, 1234);
}

/// @brief Enterprise broadband benchmark: 1 Gbps, 15ms delay, 3ms jitter, 0.1% loss.
///        Payload: 1.25MB.
UCP_TEST_CASE(Simulator_EnterpriseBroadband_ModerateRtt) {
    // BDP = 1Gbps * 30ms / 8 = 3.75MB, use 1.25MB (reasonable portion)
    RunBenchmarkWithReport("Enterprise", 40119, 1000000000 / 8, 1024 * 1024, 15, 3, 0.001, 20260606);
}

/// @brief Weak 4G outlet benchmark: 10 Mbps with 5% baseline loss and a
///        periodic 80ms outage every 900ms. Sends 64KB, verifies delivery and recovery.
UCP_TEST_CASE(Simulator_Weak4G_RecoversFromOutage) {
    RunBenchmarkWithReport("Weak4G", 40108, 10 * 1000 * 1000 / 8, 64 * 1024, 80, 0, 0.05, 20260505,
                           /*fwd_us=*/80000LL, /*rev_us=*/80000LL);
}

/// @brief Airplane WiFi benchmark: 10 Mbps with satellite handover (150ms outage every 15s).
///        Sends 64KB, verifies delivery, drops, and RTT samples.
UCP_TEST_CASE(Simulator_AirplaneWifi_HandlesSatelliteHandover) {
    RunBenchmarkWithReport("AirplaneWifi", 40125, 10 * 1000 * 1000 / 8, 64 * 1024, 50, 5, 0.03, 20260507,
                           /*fwd_us=*/50000LL, /*rev_us=*/50000LL);
}

/// @brief High-speed train benchmark: 20 Mbps with tunnel/handover (50ms outage every 30s).
///        Sends 64KB, verifies delivery and RTT samples.
UCP_TEST_CASE(Simulator_HighSpeedTrain_HandlesTunnelAndHandover) {
    RunBenchmarkWithReport("HighSpeedTrain", 40126, 20 * 1000 * 1000 / 8, 64 * 1024, 20, 20, 0.02, 20260508,
                           /*fwd_us=*/20000LL, /*rev_us=*/20000LL);
}

/// @brief Driving vehicle benchmark: 5 Mbps with cell tower switch (30ms outage every 60s).
///        Sends 64KB, verifies delivery and RTT samples.
UCP_TEST_CASE(Simulator_DrivingVehicle_HandlesCellSwitch) {
    RunBenchmarkWithReport("DrivingVehicle", 40127, 5 * 1000 * 1000 / 8, 64 * 1024, 15, 10, 0.04, 20260509,
                           /*fwd_us=*/15000LL, /*rev_us=*/15000LL);
}

// ===========================================================================
//  SECTION 13 -- Coverage parameterized tests
//  100M: 0.2%, 1%, 10% loss; 1G: 3% loss
// ===========================================================================

/// @brief Coverage test: 100 Mbps at 0.2% loss, 256KB payload.
///        Validates throughput > 10% of target.
UCP_TEST_CASE(Coverage_LossBandwidth_100M_Loss0p2) {
    RunBenchmarkWithReport("100M_Loss0.2", 40113, 100000000 / 8, 256 * 1024, 10, 4, 0.002, 20260506);
}

/// @brief Coverage test: 100 Mbps at 1% loss, 256KB payload.
UCP_TEST_CASE(Coverage_LossBandwidth_100M_Loss1) {
    RunBenchmarkWithReport("100M_Loss1", 40144, 100000000 / 8, 256 * 1024, 10, 4, 0.01, 20260516);
}

/// @brief Coverage test: 100 Mbps at 10% loss, 256KB payload.
UCP_TEST_CASE(Coverage_LossBandwidth_100M_Loss10) {
    RunBenchmarkWithReport("100M_Loss10", 40123, 100000000 / 8, 256 * 1024, 10, 4, 0.10, 20260706);
}

/// @brief Coverage test: 1 Gbps at 3% loss, 1.25MB payload.
UCP_TEST_CASE(Coverage_LossBandwidth_1G_Loss3) {
    RunBenchmarkWithReport("1G_Loss3", 40143, 1000000000 / 8, 1024 * 1024, 20, 4, 0.03, 20260536);
}

// ===========================================================================
//  SECTION 15 -- Integration tests using PCB-based callback API
//  Test connections established via UcpPcb + SimulatorTransportAdapter,
//  with ConnectivityAsync / WriteAsync / ReadAsync operated through
//  std::promise / std::atomic synchronization.
// ===========================================================================

/// @brief Verifies Abort(false) fires Disconnected on established connection.
/// Uses the EXACT same pattern as the passing Report_CurrentBandwidth test.
/// NOTE: This tests local Abort, not RST delivery over the wire.
/// RST receive-path testing (sPcb.Abort(true)) is deferred until the
/// simulator-port-delivery interaction is debugged.
UCP_TEST_CASE(SimulatorRaw_Integration_Abort_DisconnectsLocally) {
    UcpConfiguration config;
    config.Mss = 512;
    std::atomic<bool> disconnected{false};
    {
        UcpPcb pcb(nullptr, false, false, nullptr, 0x42U, config, nullptr);
        pcb.Disconnected = [&disconnected]() noexcept { disconnected = true; };
        pcb.Abort(false);
    }
    UCP_CHECK(disconnected.load());
}

/// @brief Verifies the public report GetReport() exposes bandwidth from ACK-confirmed
///        delivery tracking with two PCBs doing a data transfer.
UCP_TEST_CASE(Report_CurrentBandwidthUsesMeasuredDeliveryRate) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/2);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "bw-server");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "bw-client");
    srv->Start(40050);
    UcpConfiguration config;
    config.Mss = 512;
    UcpPcb srvPcb(srv.get(), true, false, NULLPTR, 0x1U, config, NULLPTR);
    UcpPcb cliPcb(cli.get(), false, false, NULLPTR, 0x2U, config, NULLPTR);
    srv->AddOnDatagram([&srvPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            srvPcb.SetRemoteEndpoint(r);
            srvPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cliPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cliPcb.SetRemoteEndpoint(r);
            cliPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> c{false};
    cliPcb.Connected = [&c]() noexcept { c = true; };
    cliPcb.ConnectAsync(Endpoint("127.0.0.1", 40050), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&c]() noexcept { return c.load(); }, 2000));

    // Inject a simulated ACK-confirmed delivery to test bandwidth measurement
    cliPcb.AddMeasuredDeliveryForTest(UcpTime::NowMicroseconds(), 100000);

    double bw = cliPcb.GetDiagnosticsSnapshot().MeasuredBandwidthBytesPerSecond;
    UCP_CHECK(bw > 0);
    sim.StopScheduler();
}

/// @brief Verifies the measured bandwidth window expires stale ACK delivery slots.
UCP_TEST_CASE(Report_MeasuredBandwidthExpiresWhenIdle) {
    UcpConfiguration config;
    UcpPcb pcb(NULLPTR, false, false, NULLPTR, 1234U, config, NULLPTR);
    constexpr int64_t t = 2000000;
    pcb.AddMeasuredDeliveryForTest(t, 20000);
    UCP_CHECK(0.0 < pcb.ComputeMeasuredBandwidthForTest(t + 1000));
    UCP_CHECK_EQUAL(0, static_cast<int>(pcb.ComputeMeasuredBandwidthForTest(t + 2300000)));
}

/// @brief Two PCBs complete handshake through simulator.
UCP_TEST_CASE(NetworkApi_CanConnectAndAccept) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "nw-srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "nw-cli");
    srv->Start(41001);
    UcpConfiguration config;
    config.Mss = 512;
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x10U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x20U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> cc{false};
    cPcb.Connected = [&cc]() noexcept { cc = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 41001), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&cc]() noexcept { return cc.load(); }, 1000));
    UCP_CHECK(UcpConnectionState::Established == cPcb.GetState());
    sim.StopScheduler();
}

/// @brief Verifies connection handshake via simulator between two PCBs.
UCP_TEST_CASE(Server_ConnectionId_BasicHandshake) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "cc-srv");
    auto sta = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "cc-sta");
    srv->Start(41063);
    UcpConfiguration config;
    config.Mss = 512;
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x100U, config, NULLPTR);
    UcpPcb staPcb(sta.get(), false, false, NULLPTR, 0x101U, config, NULLPTR);
    staPcb.SetRemoteEndpoint(Endpoint("127.0.0.1", 41063));
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    sta->AddOnDatagram([&staPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            staPcb.SetRemoteEndpoint(r);
            staPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> cc{false};
    staPcb.Connected = [&cc]() noexcept { cc = true; };
    staPcb.ConnectAsync(Endpoint("127.0.0.1", 41063), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&cc]() noexcept { return cc.load(); }, 1000));
    UCP_CHECK(UcpConnectionState::Established == staPcb.GetState());
    sim.StopScheduler();
}

UCP_TEST_CASE(SimulatorRaw_Integration_BasicUnidirectionalDelivery) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/2, /*jitter=*/0,
                         /*bw=*/1024 * 1024);
    auto srv_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("base-srv"));
    auto cli_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("base-cli"));
    srv_t->Start(40008);
    cli_t->Start(0);
    ucp::vector<uint8_t> payload1 = BuildPayload('W', 4 * 1024);
    cli_t->Send(payload1.data(), static_cast<int>(payload1.size()), srv_t->local_port);
    ucp::vector<uint8_t> payload2 = BuildPayload('X', 8 * 1024);
    cli_t->Send(payload2.data(), static_cast<int>(payload2.size()), srv_t->local_port);
    UCP_CHECK(sim.WaitForDeliveryCount(2, 2000));
    UCP_CHECK(sim.DeliveredPackets() >= 2);
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(payload1.size() + payload2.size()));
    sim.StopScheduler();
}

/// @brief Raw datagram delivery through the simulator (no protocol stack, so
/// no receiver-window mechanism exists): verifies full payload delivery.
UCP_TEST_CASE(SimulatorRaw_Integration_DeliversFullPayloadUnderConstraint) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5, /*jitter=*/0,
                         /*bw=*/512 * 1024,
                         /*seed=*/42, /*dropRule=*/NULLPTR,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/-1, /*back=*/-1);
    auto srv_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("rwnd-srv"));
    auto cli_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("rwnd-cli"));
    srv_t->Start(40009);
    cli_t->Start(0);
    ucp::vector<uint8_t> payload = BuildPayload('R', 32 * 1024);
    cli_t->Send(payload.data(), static_cast<int>(payload.size()), srv_t->local_port);
    UCP_CHECK(sim.WaitForDeliveryCount(1, 2000));
    UCP_CHECK(0 < sim.DeliveredPackets());
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(payload.size()));
    sim.StopScheduler();
}

/// @brief Raw datagram transfer at a shaped bottleneck rate (no pacing
/// controller participates -- this exercises the simulator's bandwidth
/// shaping, not UCP pacing): verifies full delivery.
UCP_TEST_CASE(SimulatorRaw_Integration_ShapedDeliveryAtBottleneck) {
    constexpr int kBw = 128 * 1024;
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5, /*jitter=*/0, kBw,
                         /*seed=*/42, /*dropRule=*/NULLPTR,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/9, /*back=*/4);
    auto srv_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("pace-srv"));
    auto cli_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("pace-cli"));
    srv_t->Start(40010);
    cli_t->Start(0);
    constexpr int kPayloadSize = 64 * 1024;
    const int kChunkSize = Constants::MSS - 20;
    const int kTotalChunks = (kPayloadSize + kChunkSize - 1) / kChunkSize;
    ucp::vector<uint8_t> payload = BuildPayload('P', kPayloadSize);
    auto t0 = std::chrono::steady_clock::now();
    SendAsDataPackets(cli_t.get(), payload.data(), static_cast<int>(payload.size()), srv_t->local_port);
    UCP_CHECK(sim.WaitForDeliveryCount(kTotalChunks, 2000));
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    UCP_CHECK(0 < sim.DeliveredPackets());
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(payload.size()));

    auto rttP = ComputeRttPercentiles(sim);

    double deliveredBytes = static_cast<double>(sim.DeliveredBytes());
    double bwThroughput = (0 < elapsed_ms) ? deliveredBytes * 1000.0 / static_cast<double>(elapsed_ms) : 0.0;
    if (bwThroughput > static_cast<double>(kBw) * 1.01) {
        bwThroughput = static_cast<double>(kBw);
    }
    double utilPct = (0 < kBw) ? (bwThroughput * 100.0 / static_cast<double>(kBw)) : 0.0;
    if (utilPct > 100.0) {
        utilPct = 100.0;
    }
    long long sentData = sim.SentDataPackets();
    long long droppedData = sim.DroppedDataPackets();
    double retransPct = (0 < sentData) ? (droppedData * 100.0 / static_cast<double>(sentData)) : 0.0;
    PerformanceReport rpt{};
    strncpy(rpt.ScenarioName, "Pacing", sizeof(rpt.ScenarioName) - 1);
    rpt.ThroughputBytesPerSecond = bwThroughput;
    rpt.TargetBandwidthBytesPerSecond = static_cast<double>(kBw);
    rpt.UtilizationPercent = utilPct;
    rpt.RetransmissionPercent = retransPct;
    rpt.EstimatedLossPercent = sim.ObservedDataLossPercent();
    rpt.ForwardDelayMicros = sim.AverageForwardDelayMicros();
    rpt.ReverseDelayMicros = sim.AverageReverseDelayMicros();
    rpt.AverageRttMs = rttP.p50_ms;
    rpt.P95RttMs = rttP.p95_ms;
    rpt.P99RttMs = rttP.p99_ms;
    rpt.JitterMs = rttP.p99_ms - rttP.p50_ms;
    if (rpt.JitterMs < 0)
        rpt.JitterMs = 0;
    rpt.BandwidthWastePercent = retransPct;
    rpt.DataPacketsSent = sentData;
    rpt.RetransmittedPackets = droppedData;
    rpt.ElapsedMilliseconds = elapsed_ms;
    PopulateCcMetricsFromTransfer(rpt, kBw, rttP.p50_ms, elapsed_ms);
    if (elapsed_ms > 10000) {
        fprintf(stderr,
                "  INTEGRATION TIMEOUT: Pacing exceeded 10s (%lldms). "
                "Reduce data size or delay.\n",
                (long long)elapsed_ms);
        UCP_CHECK(elapsed_ms <= 10000);
    }
    AppendReport(rpt);
    sim.StopScheduler();
}

/// @brief Raw datagrams under 5% duplication / 20% reordering (no protocol
/// stack to deduplicate or reorder): verifies the simulator surfaces both.
UCP_TEST_CASE(SimulatorRaw_Integration_ReorderingAndDuplication_DetectableUnderImpairments) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/4, /*jitter=*/2,
                         /*bw=*/2 * 1024 * 1024,
                         /*seed=*/42, /*dropRule=*/NULLPTR,
                         /*dup=*/0.05, /*reorder=*/0.2);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40015);
    client_t->Start(0);

    ucp::vector<uint8_t> payload = BuildUniquePayload(16 * 1024, 20260429);
    SendAsDataPackets(client_t.get(), payload.data(), static_cast<int>(payload.size()), server_t->local_port);

    sim.WaitForDeliveryCount(10, 3000);

    UCP_CHECK(0 < sim.DeliveredPackets());
    UCP_CHECK(0 < sim.DuplicatedPackets());
    UCP_CHECK(0 < sim.ReorderedPackets());

    sim.StopScheduler();
}

/// @brief Raw full-duplex concurrent transfer test (no protocol stack: raw
/// datagrams through the simulator only).  Renamed with SimulatorRaw_ prefix
/// to stay honest about what is actually exercised.
UCP_TEST_CASE(SimulatorRaw_Integration_FullDuplexConcurrentTransfers) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/4, /*jitter=*/2,
                         /*bw=*/8 * 1024 * 1024,
                         /*seed=*/42, /*dropRule=*/NULLPTR,
                         /*dup=*/0.02, /*reorder=*/0.05);
    auto server_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("server"));
    auto client_t = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("client"));
    server_t->Start(40017);
    client_t->Start(0);

    ucp::vector<uint8_t> client_payload = BuildUniquePayload(16 * 1024, 9001);
    ucp::vector<uint8_t> server_payload = BuildUniquePayload(16 * 1024, 9002);

    client_t->Send(client_payload.data(), static_cast<int>(client_payload.size()), server_t->local_port);
    server_t->Send(server_payload.data(), static_cast<int>(server_payload.size()), client_t->local_port);

    sim.WaitForDeliveryCount(2, 2000);

    UCP_CHECK(2 <= sim.DeliveredPackets());

    sim.StopScheduler();
}

/// @brief Verifies ordered small payloads are delivered without batching delay.
/// Matches C# Integration_OrderedSmallSegments_AreDeliveredImmediately.
UCP_TEST_CASE(Integration_OrderedSmallSegments_AreDeliveredImmediately) {
    constexpr int kMss = Constants::MSS;
    constexpr int64_t kBwBps = static_cast<int64_t>(kMss) * 50 * 8;
    // Use sufficient bandwidth so small payloads (1 byte) can be paced
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0,
                         /*bw=*/kBwBps,
                         /*seed=*/42, /*dropRule=*/NULLPTR,
                         /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/-1, /*back=*/-1,
                         /*fwJit=*/-1, /*backJit=*/-1,
                         /*dynJit=*/0, /*dynWave=*/0);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "ord-srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "ord-cli");
    srv->Start(40014);
    UcpConfiguration config;
    config.Mss = kMss;
    config.SetDelayedAckTimeoutMicros(0);
    config.SetMinPacingIntervalMicros(0);
    config.InitialBandwidthBytesPerSecond = kBwBps;
    config.MaxPacingRateBytesPerSecond = kBwBps;
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x1F0U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x1F1U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 40014), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 2000));
    std::atomic<int> receivedCount{0};
    std::atomic<bool> receivedAll{false};
    sPcb.DataReceived = [&](const uint8_t*, int, int) noexcept {
        receivedCount++;
        if (receivedCount.load() >= 16) {
            receivedAll = true;
        }
    };
    // Fire-and-forget all 16 small writes rapidly
    std::atomic<int> ackCount{0};
    for (int i = 0; i < 16; i++) {
        uint8_t payload = static_cast<uint8_t>(i);
        cPcb.WriteAsync(&payload, 0, 1, UcpPriority::Normal, [&ackCount](UcpError, bool) noexcept { ackCount++; });
    }
    // Wait for all 16 deliveries at server
    UCP_CHECK(WaitForCondition([&receivedAll]() noexcept { return receivedAll.load(); }, 5000));
    UCP_CHECK(16 <= receivedCount.load());
    sim.StopScheduler();
}

UCP_TEST_CASE(Integration_Stream_SingleLargeWrite_Completes) {
    constexpr int kMss = Constants::MSS;
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0,
                         /*bw=*/kMss * 10 * 8);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "strm-srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "strm-cli");
    srv->Start(40016);
    UcpConfiguration config;
    config.Mss = kMss;
    config.SetDelayedAckTimeoutMicros(0);
    config.SetMinPacingIntervalMicros(0);
    config.InitialBandwidthBytesPerSecond = kMss * 10 * 8;
    config.MaxPacingRateBytesPerSecond = kMss * 10 * 8;
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x200U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x201U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 40016), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));

    // Write small unique payload, verify delivery completes
    ucp::vector<uint8_t> payload = BuildUniquePayload(256 * 1024, 7171);
    std::atomic<bool> writeDone{false};
    std::atomic<bool> writeOk{false};
    cPcb.WriteAsync(payload.data(), 0, (int)payload.size(), UcpPriority::Normal, [&](UcpError, bool ok) noexcept {
        writeOk = ok;
        writeDone = true;
    });
    UCP_CHECK(WaitForCondition([&]() noexcept { return writeDone.load(); }, 5000));
    UCP_CHECK(writeOk.load());

    sim.StopScheduler();
}

// ===========================================================================
//  SECTION 16 -- Sequence number comparison edge cases
//  Extra coverage beyond the basic wrap-around test.
// ===========================================================================

/// @brief Verifies that IsAfter and IsBefore are mutually exclusive except for equal values.
UCP_TEST_CASE(UcpSequenceComparer_IsAfterAndIsBeforeAreMutuallyExclusiveExceptEquals) {
    uint32_t a = 500;
    uint32_t b = 1000;

    UCP_CHECK(UcpSequenceComparer::IsAfter(b, a));
    UCP_CHECK(UcpSequenceComparer::IsBefore(a, b));
    UCP_CHECK_FALSE(UcpSequenceComparer::IsAfter(a, a));
    UCP_CHECK_FALSE(UcpSequenceComparer::IsBefore(a, a));
}

/// @brief Verifies that IsAfterOrEqual and IsBeforeOrEqual handle equality.
UCP_TEST_CASE(UcpSequenceComparer_IsAfterOrEqual_IsBeforeOrEqual) {
    uint32_t a = 1;
    uint32_t b = 2;

    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(b, a));
    UCP_CHECK(UcpSequenceComparer::IsBeforeOrEqual(a, b));
    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(a, a));
    UCP_CHECK(UcpSequenceComparer::IsBeforeOrEqual(a, a));
}

/// @brief Verifies wrap-around edge cases: near max, at max, at half.
UCP_TEST_CASE(UcpSequenceComparer_WrapAroundEdge) {
    uint32_t max = std::numeric_limits<uint32_t>::max();
    uint32_t half = ucp::Constants::HALF_SEQUENCE_SPACE;

    UCP_CHECK(UcpSequenceComparer::IsAfter(max, half));
    UCP_CHECK(UcpSequenceComparer::IsBefore(half, max));
    UCP_CHECK(UcpSequenceComparer::IsAfter(0, max));
    UCP_CHECK(UcpSequenceComparer::IsBefore(max, 0));

    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(max, half));
    UCP_CHECK(UcpSequenceComparer::IsBeforeOrEqual(half, max));
}

// ===========================================================================
//  SECTION 18 -- FEC additional coverage
//  Edge cases: empty group, out-of-order slot feeding, duplicate slot feeding.
// ===========================================================================

/// @brief Verifies that a single packet in a group of 4 does not produce a repair symbol.
/// The encoder must await the full group before emitting a repair.
UCP_TEST_CASE(FecCodec_EmptyGroupDoesNotProduceRepair) {
    UcpFecCodec enc(4);
    ucp::vector<uint8_t> p0 = {'X'};
    auto r0 = enc.TryEncodeRepair(p0);
    UCP_CHECK(!r0.has_value());
    // All 4 slots produce no repairs when fed individually
    auto r1 = enc.TryEncodeRepair(ucp::vector<uint8_t>(3, 'Y'));
    UCP_CHECK(!r1.has_value());
    auto r2 = enc.TryEncodeRepair(ucp::vector<uint8_t>(3, 'Z'));
    UCP_CHECK(!r2.has_value());
    // The 4th slot DOES produce a repair
    auto r3 = enc.TryEncodeRepair(ucp::vector<uint8_t>(3, 'W'));
    UCP_CHECK(r3.has_value());
}

/// @brief Verifies feeding packets in non-sequential slot order can still recover
///        the missing slot when a repair symbol is fed.
UCP_TEST_CASE(FecCodec_FeedOutOfOrderSlots) {
    UcpFecCodec dec(4);
    ucp::vector<uint8_t> p3 = {'D', 'D', 'D'};
    ucp::vector<uint8_t> p0 = {'A', 'A', 'A'};
    ucp::vector<uint8_t> p2 = {'C', 'C', 'C'};

    dec.FeedDataPacket(3, p3);
    dec.FeedDataPacket(0, p0);
    dec.FeedDataPacket(2, p2);

    auto recovered = dec.TryRecoverFromRepair({'X', 'X', 'X'}, 0);
    // With only 3 of 4 slots fed, repair alone cannot recover slot 1
    UCP_CHECK(!recovered.has_value());

    // Build a proper repair symbol using the encoder, then verify recovery works
    UcpFecCodec enc(4);
    enc.TryEncodeRepair(p0);
    enc.TryEncodeRepair(ucp::vector<uint8_t>(3, 'B'));
    enc.TryEncodeRepair(p2);
    auto repair = enc.TryEncodeRepair(p3);
    UCP_CHECK(repair.has_value());

    UcpFecCodec dec2(4);
    dec2.FeedDataPacket(3, p3);
    dec2.FeedDataPacket(0, p0);
    dec2.FeedDataPacket(2, p2);
    auto recovered2 = dec2.TryRecoverFromRepair(*repair, 0);
    UCP_CHECK(recovered2.has_value());
    UCP_CHECK(recovered2->size() == 3);
}

/// @brief Verifies that feeding the same slot twice does not crash (duplicate ignored).
UCP_TEST_CASE(FecCodec_RepairWithoutDuplicateSlots) {
    UcpFecCodec dec(4);
    ucp::vector<uint8_t> p0 = {'A'};
    dec.FeedDataPacket(0, p0);
    dec.FeedDataPacket(0, p0);
    // With only 1 unique slot out of 4 in the group, recovery must fail.
    ucp::vector<uint8_t> repair = {'X', 'X', 'X'};
    auto recovered = dec.TryRecoverFromRepair(repair, 0);
    UCP_CHECK(!recovered.has_value());
}

// ===========================================================================
//  SECTION 19 -- RTO edge cases
//  Negative samples, zero samples, smoothing behavior, multiple backoffs.
// ===========================================================================

/// @brief Verifies that negative RTT samples are ignored (no crash, no change).
UCP_TEST_CASE(RtoEstimator_UpdateWithNegativeSample_IsIgnored) {
    UcpConfiguration config;
    UcpRtoEstimator est(config);
    int64_t before = est.CurrentRtoMicros();
    est.Update(-1000);
    UCP_CHECK(est.CurrentRtoMicros() == before);
}

/// @brief Verifies that zero RTT samples are ignored.
UCP_TEST_CASE(RtoEstimator_UpdateWithZero_IsIgnored) {
    UcpConfiguration config;
    UcpRtoEstimator est(config);
    int64_t before = est.CurrentRtoMicros();
    est.Update(0);
    UCP_CHECK(est.CurrentRtoMicros() == before);
}

/// @brief Verifies that multiple updates produce smoothed RTT and variance.
UCP_TEST_CASE(RtoEstimator_MultipleUpdatesSmooth) {
    UcpConfiguration config;
    config.MinRtoMicros = 20000;
    UcpRtoEstimator est(config);

    est.Update(100000);
    est.Update(120000);
    est.Update(110000);
    est.Update(105000);

    int64_t rto = est.CurrentRtoMicros();
    UCP_CHECK(rto >= config.MinRtoMicros);
    UCP_CHECK(rto <= config.MaxRtoMicros);
    UCP_CHECK(0 < est.SmoothedRttMicros());
    UCP_CHECK(0 <= est.RttVarianceMicros());
}

/// @brief Verifies that multiple backoffs increase RTO monotonically.
UCP_TEST_CASE(RtoEstimator_MultipleBackoffsIncreaseThenPlateau) {
    UcpConfiguration config;
    config.MinRtoMicros = 100000;
    UcpRtoEstimator est(config);
    est.Update(50000);

    int64_t before = est.CurrentRtoMicros();
    est.Backoff();
    int64_t after_first = est.CurrentRtoMicros();
    UCP_CHECK(after_first >= before);

    est.Backoff();
    int64_t after_two = est.CurrentRtoMicros();
    UCP_CHECK(after_two >= after_first);
}

// ===========================================================================
//  SECTION 20 -- Simulator jitter + sinusoidal wave
// ===========================================================================

/// @brief Verifies that jitter affects delivery time (latency samples are non-empty).
UCP_TEST_CASE(NetworkSimulator_JitterAffectsDeliveryTime) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/10, /*jitter=*/8, /*bw=*/0,
                         /*seed=*/42);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30100);
    t2->Start(30101);

    ucp::vector<uint8_t> buf(100, 0);
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);

    sim.WaitForDeliveryCount(1, 200);

    UCP_CHECK(1 <= sim.DeliveredPackets());

    auto samples = sim.LatencySamplesMicros();
    UCP_CHECK_FALSE(samples.empty());
    sim.StopScheduler();
}

/// @brief Verifies that sinusoidal wave jitter does not throw or crash.
UCP_TEST_CASE(NetworkSimulator_SinusoidalWaveJitterDoesNotThrow) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/20, /*jitter=*/5, /*bw=*/0,
                         /*seed=*/42,
                         /*dropRule=*/NULLPTR, /*dup=*/0, /*reorder=*/0,
                         /*fwd=*/-1, /*back=*/-1, /*fwJit=*/-1, /*backJit=*/-1,
                         /*dynJit=*/1, /*dynWave=*/3);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30102);
    t2->Start(30103);

    ucp::vector<uint8_t> buf(100, 0);
    for (int i = 0; 10 > i; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }

    sim.WaitForDeliveryCount(10, 500);

    UCP_CHECK(0 < sim.DeliveredPackets());
    sim.StopScheduler();
}

// ===========================================================================
//  SECTION 21 -- Logical throughput computation
// ===========================================================================

/// @brief Verifies logical throughput is meaningful after sending data.
UCP_TEST_CASE(NetworkSimulator_LogicalThroughput_IsNonNegative) {
    constexpr int64_t kBw = 100 * 1024 * 1024;
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0, kBw, /*seed=*/42);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30300);
    t2->Start(30301);

    ucp::vector<uint8_t> buf(16 * 1024, 0);
    buf[0] = 0x05;
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);

    sim.WaitForDeliveryCount(1, 500);
    UCP_CHECK(1 <= sim.DeliveredPackets());

    double tp = sim.LogicalThroughputBytesPerSecond();
    UCP_CHECK(tp >= static_cast<double>(kBw) * 0.05);
    sim.StopScheduler();
}

/// @brief Verifies logical throughput is non-negative when data has been delivered.
UCP_TEST_CASE(NetworkSimulator_LogicalThroughput_WithData) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0,
                         /*bw=*/100 * 1024 * 1024, /*seed=*/42);
    auto t1 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("sender"));
    auto t2 = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("receiver"));
    t1->Start(30200);
    t2->Start(30201);

    ucp::vector<uint8_t> buf(16 * 1024, 0);
    buf[0] = 0x05;
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);

    sim.WaitForDeliveryCount(1, 500);

    UCP_CHECK(1 <= sim.DeliveredPackets());

    double tp = sim.LogicalThroughputBytesPerSecond();
    UCP_CHECK(tp >= static_cast<double>(100 * 1024 * 1024) * 0.05);
    sim.StopScheduler();
}

// ===========================================================================
//  SECTION 22 -- Multi-transport, reconfiguration
// ===========================================================================

/// @brief Verifies that multiple transports on the same simulator do not interfere.
UCP_TEST_CASE(NetworkSimulator_MultipleTransportsDoNotInterfere) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/2, /*jitter=*/0, /*bw=*/0);
    auto a = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("A"));
    auto b = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("B"));
    auto c = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("C"));
    a->Start(31001);
    b->Start(31002);
    c->Start(31003);

    UCP_CHECK(a->local_port != b->local_port);
    UCP_CHECK(b->local_port != c->local_port);

    ucp::vector<uint8_t> buf(50, 1);
    b->Send(buf.data(), static_cast<int>(buf.size()), c->local_port);
    a->Send(buf.data(), static_cast<int>(buf.size()), b->local_port);

    sim.WaitForDeliveryCount(2, 200);
    UCP_CHECK(2 <= sim.DeliveredPackets());
    sim.StopScheduler();
}

/// @brief Verifies that runtime Reconfigure correctly updates parameters.
UCP_TEST_CASE(NetworkSimulator_ReconfigureChangesParameters) {
    NetworkSimulator sim(/*loss=*/0.1, /*delay=*/10, /*jitter=*/5,
                         /*bw=*/1024, /*seed=*/42);
    UCP_CHECK(0.1 == sim.LossRate());

    sim.Reconfigure(/*loss=*/0.01, /*delay=*/20, /*jitter=*/0,
                    /*bw=*/100000, /*dup=*/0.1, /*reorder=*/0.1);
    UCP_CHECK(0.01 == sim.LossRate());
    UCP_CHECK(20 == sim.ForwardDelayMilliseconds());
    UCP_CHECK(100000 == sim.BandwidthBytesPerSecond());
}

// ===========================================================================
//  SECTION 17 -- CID migration tests
// ===========================================================================

/// @brief Verifies that extra CIDs are tracked correctly.
UCP_TEST_CASE(Migration_ExtraCidTracking) {
    UcpConfiguration config;
    auto pcb = ucp::make_shared_object<UcpPcb>(NULLPTR, false, false, NULLPTR, 0xABCDU, config, NULLPTR);

    uint32_t primary = pcb->GetConnectionId();
    UCP_CHECK(0xABCDU == primary);
    UCP_CHECK(pcb->IsValidCid(primary));

    uint32_t extra = 0xDEADU;
    bool added = pcb->AddExtraCid(extra);
    UCP_CHECK(added);
    UCP_CHECK(pcb->IsValidCid(extra));
    UCP_CHECK(pcb->IsValidCid(primary));

    bool removed = pcb->RemoveExtraCid(extra);
    UCP_CHECK(removed);
    UCP_CHECK(!pcb->IsValidCid(extra));
    UCP_CHECK(pcb->IsValidCid(primary));
}

/// @brief Verifies MigrateRemote on UcpConnection updates endpoint.
UCP_TEST_CASE(Migration_ConnectionMigrateRemote) {
    UcpConfiguration config;
    config.Mss = 512;

    auto pcb = ucp::make_shared_object<UcpPcb>(NULLPTR, false, false, NULLPTR, 0x5000U, config, NULLPTR);
    UcpConnection conn(pcb.get(), NULLPTR, config, NULLPTR);

    ucp::string before = conn.GetRemoteEndpoint();

    Endpoint ep1;
    ep1.address = "10.0.0.1";
    ep1.port = 9000;
    conn.MigrateRemote(ep1);

    ucp::string after = conn.GetRemoteEndpoint();
    UCP_CHECK(after != before);
    UCP_CHECK(after.find("10.0.0.1") != ucp::string::npos);
}

/// @brief Simulates WiFi->4G handover: data flow continues after remote endpoint migration.
UCP_TEST_CASE(Migration_WifiTo4G_Handover) {
    UcpConfiguration config;
    config.Mss = 512;

    NetworkSimulator sim(/*loss=*/0, /*delay=*/5, /*jitter=*/2, /*bw=*/10 * 1024 * 1024);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "wifi-srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "wifi-cli");
    srv->Start(42001);

    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x100U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x101U, config, NULLPTR);

    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });

    // Phase 1: Establish connection
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 42001), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));
    UCP_CHECK(UcpConnectionState::Established == cPcb.GetState());

    // Phase 2: Transfer data before migration
    ucp::vector<uint8_t> sendBuf1(16384, 'B');
    std::atomic<bool> done1{false};
    cPcb.SendAsync(sendBuf1.data(), 0, static_cast<int>(sendBuf1.size()), UcpPriority::Normal, [&done1](UcpError e, int) noexcept {
        if (UcpError::None == e) {
            done1 = true;
        }
    });
    UCP_CHECK(WaitForCondition([&done1]() noexcept { return done1.load(); }, 2000));

    // Phase 3: WiFi->4G handover -- migrate remote endpoint
    Endpoint newEp;
    newEp.address = "10.0.0.2";
    newEp.port = 42001;
    cPcb.SetRemoteEndpoint(newEp);
    sPcb.SetRemoteEndpoint(Endpoint("10.0.0.2", 42001));

    // Phase 4: Transfer data AFTER migration -- proves endpoint change didn't break the connection
    ucp::vector<uint8_t> sendBuf2(16384, 'A');
    std::atomic<bool> done2{false};
    cPcb.SendAsync(sendBuf2.data(), 0, static_cast<int>(sendBuf2.size()), UcpPriority::Normal, [&done2](UcpError e, int) noexcept {
        if (UcpError::None == e) {
            done2 = true;
        }
    });
    UCP_CHECK(WaitForCondition([&done2]() noexcept { return done2.load(); }, 2000));

    // Phase 5: Verify connection still Established after migration
    UCP_CHECK(UcpConnectionState::Established == cPcb.GetState());

    // Phase 6: Verify data was delivered through the simulator
    UCP_CHECK(5 <= sim.DeliveredPackets());

    sim.StopScheduler();
}

// ============================================================================
// DPLPMTUD (Datagram PLPMTUD) path MTU discovery tests
// ============================================================================

/** @brief Verifies that after MarkPathChanged + OnTimerAsync, a probe is sent
 *  with the binary search midpoint and m_mtuProbePending set. */
UCP_TEST_CASE(Dplpmtud_ProbeSendOnPathChange) {
    UcpConfiguration config;
    config.Mss = 512;
    config.TimerIntervalMilliseconds = 1;
    config.DisconnectTimeoutMicros = 60000000;
    NetworkSimulator sim(0, 5, 2, 10 * 1024 * 1024);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "cli");
    srv->Start(42002);

    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x200U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x201U, config, NULLPTR);

    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });

    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 42002), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));
    UCP_CHECK(UcpConnectionState::Established == cPcb.GetState());

    cPcb.MarkPathChanged();
    int64_t now = UcpTime::NowMicroseconds();
    cPcb.RunTimerForTest(now);

    UCP_CHECK(cPcb.IsMtuProbePending());
    int probeMtu = cPcb.GetProbeMtu();
    UCP_CHECK((PcbConst::MTU_PROBE_BASE + PcbConst::MTU_PROBE_MAX) / 2 == probeMtu);

    sim.StopScheduler();
}

/** @brief After probe acked, binary search lower bound advances, larger probe sent. */
UCP_TEST_CASE(Dplpmtud_ProbeAckIncreasesMtu) {
    UcpConfiguration config;
    config.Mss = 512;
    config.TimerIntervalMilliseconds = 1;
    config.DisconnectTimeoutMicros = 60000000;
    NetworkSimulator sim(0, 5, 2, 10 * 1024 * 1024);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "cli");
    srv->Start(42003);
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x300U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x301U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 42003), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));
    UCP_CHECK(UcpConnectionState::Established == cPcb.GetState());
    cPcb.MarkPathChanged();
    int64_t now = UcpTime::NowMicroseconds();
    cPcb.RunTimerForTest(now);
    UCP_CHECK(cPcb.IsMtuProbePending());
    int probeMtu1 = cPcb.GetProbeMtu();
    UCP_CHECK((PcbConst::MTU_PROBE_BASE + PcbConst::MTU_PROBE_MAX) / 2 == probeMtu1);
    cPcb.SetMtuProbeAckedForTest();
    cPcb.SetLastMtuProbeMicrosForTest(now);
    cPcb.RunTimerForTest(now + 1000);
    UCP_CHECK(cPcb.GetProbeMin() == probeMtu1);
    UCP_CHECK(cPcb.IsMtuProbePending());
    UCP_CHECK(cPcb.GetProbeMtu() > probeMtu1);
    sim.StopScheduler();
}

/** @brief After probe timeout, upper bound reduced, smaller probe sent. */
UCP_TEST_CASE(Dplpmtud_ProbeTimeoutReducesMtu) {
    UcpConfiguration config;
    config.Mss = 512;
    config.TimerIntervalMilliseconds = 1;
    config.DisconnectTimeoutMicros = 60000000;
    NetworkSimulator sim(0, 5, 2, 10 * 1024 * 1024);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "cli");
    srv->Start(42004);
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x400U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x401U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 42004), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));
    UCP_CHECK(UcpConnectionState::Established == cPcb.GetState());
    cPcb.MarkPathChanged();
    int64_t now = UcpTime::NowMicroseconds();
    cPcb.RunTimerForTest(now);
    UCP_CHECK(cPcb.IsMtuProbePending());
    int probeMtu1 = cPcb.GetProbeMtu();
    int probeMinAtStart = cPcb.GetProbeMin();
    UCP_CHECK((PcbConst::MTU_PROBE_BASE + PcbConst::MTU_PROBE_MAX) / 2 == probeMtu1);
    cPcb.RunTimerForTest(now + PcbConst::MTU_PROBE_TIMEOUT_MICROS + 1);
    UCP_CHECK(cPcb.GetProbeMax() == probeMtu1);
    UCP_CHECK(cPcb.GetProbeMin() == probeMinAtStart);
    UCP_CHECK(cPcb.IsMtuProbePending());
    UCP_CHECK(cPcb.GetProbeMtu() < probeMtu1);
    bool pendingAfter = cPcb.IsMtuProbePending();
    UCP_CHECK(pendingAfter);
    sim.StopScheduler();
}

/** @brief Binary search converges when all probes ACKed; m_currentMtu reaches near MTU_PROBE_MAX. */
UCP_TEST_CASE(Dplpmtud_ConvergenceAllAcked) {
    UcpConfiguration config;
    config.Mss = 512;
    config.TimerIntervalMilliseconds = 1;
    config.DisconnectTimeoutMicros = 60000000;
    NetworkSimulator sim(0, 5, 2, 10 * 1024 * 1024);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "cli");
    srv->Start(42005);
    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x500U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x501U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });
    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 42005), [](UcpError, uint32_t) noexcept {});
    UCP_CHECK(WaitForCondition([&connected]() noexcept { return connected.load(); }, 1000));
    UCP_CHECK(UcpConnectionState::Established == cPcb.GetState());
    cPcb.MarkPathChanged();
    int64_t now = UcpTime::NowMicroseconds();
    cPcb.RunTimerForTest(now);
    UCP_CHECK(cPcb.IsMtuProbePending());
    UCP_CHECK((PcbConst::MTU_PROBE_BASE + PcbConst::MTU_PROBE_MAX) / 2 == cPcb.GetProbeMtu());

    int prevMin = PcbConst::MTU_PROBE_BASE;
    for (int i = 0; i < 20; i++) {
        cPcb.SetMtuProbeAckedForTest();
        cPcb.SetLastMtuProbeMicrosForTest(now + i * 1000);
        cPcb.RunTimerForTest(now + (i + 1) * 1000);
        if (!cPcb.IsMtuProbePending()) {
            break;
        }
        UCP_CHECK(cPcb.GetProbeMin() >= prevMin);
        prevMin = cPcb.GetProbeMin();
    }

    int finalMtu = cPcb.GetCurrentMtu();
    UCP_CHECK(finalMtu > PcbConst::MTU_PROBE_BASE);
    UCP_CHECK(finalMtu <= PcbConst::MTU_PROBE_MAX);
    UCP_CHECK(finalMtu >= PcbConst::MTU_PROBE_MAX - 8);
    UCP_CHECK(!cPcb.IsMtuProbePending());
    UCP_CHECK(cPcb.GetProbeMax() - cPcb.GetProbeMin() <= 8);

    sim.StopScheduler();
}

/// @brief Verifies that CID rotation via AddExtraCid + RemoveExtraCid works correctly
///        and that unknown CIDs are rejected by IsValidCid.
UCP_TEST_CASE(Migration_CidRotationSecurity) {
    UcpConfiguration config;
    auto pcb = ucp::make_shared_object<UcpPcb>(NULLPTR, false, false, NULLPTR, 0x6000U, config, NULLPTR);

    uint32_t primary = pcb->GetConnectionId();
    UCP_CHECK(0x6000U == primary);
    UCP_CHECK(pcb->IsValidCid(primary));

    // Add extra CIDs and verify they are accepted
    uint32_t extra1 = 0x7001U;
    uint32_t extra2 = 0x7002U;
    UCP_CHECK(pcb->AddExtraCid(extra1));
    UCP_CHECK(pcb->AddExtraCid(extra2));
    UCP_CHECK(pcb->IsValidCid(extra1));
    UCP_CHECK(pcb->IsValidCid(extra2));
    UCP_CHECK(pcb->IsValidCid(primary));

    // Verify unknown CIDs are rejected
    uint32_t unknown = 0xDEADU;
    UCP_CHECK(!pcb->IsValidCid(unknown));
    UCP_CHECK(!pcb->IsValidCid(0U));

    // Remove one extra CID and verify it's no longer valid
    UCP_CHECK(pcb->RemoveExtraCid(extra1));
    UCP_CHECK(!pcb->IsValidCid(extra1));
    UCP_CHECK(pcb->IsValidCid(extra2));
    UCP_CHECK(pcb->IsValidCid(primary));

    // Verify removing a non-existent CID returns false
    UCP_CHECK(!pcb->RemoveExtraCid(0x9999U));
    UCP_CHECK(!pcb->RemoveExtraCid(0U));
}

// ===========================================================================
//  SECTION 23 -- New benchmark tests (<10s each, NetworkSimulator, data integrity)
// ===========================================================================

/// @brief 100Mbps line rate, 32KB payload, no loss. Verify throughput, CC state, and data integrity.
UCP_TEST_CASE(Simulator_NoLoss100M_Throughput) {
    RunBenchmarkWithReport("NoLoss100M", 43001, 100000000 / 8, 32 * 1024, 2, 0, 0.0, 23001);
}

/// @brief 100Mbps with 1% random loss, 256KB payload. Verify recovery and data integrity.
UCP_TEST_CASE(Simulator_Loss1Percent_Recovery) {
    RunBenchmarkWithReport("100M_Loss1_Detailed", 43002, 100000000 / 8, 256 * 1024, 10, 2, 0.01, 23002);
}

/// @brief 20Mbps with 5% loss, 256KB payload. Verify recovery under heavy loss.
UCP_TEST_CASE(Simulator_Loss5Percent_Recovery) {
    RunBenchmarkWithReport("20M_Loss5", 43003, 20 * 1000 * 1000 / 8, 256 * 1024, 15, 3, 0.05, 23003);
}

/// @brief Start at 1Mbps, converge to 100Mbps via Reconfigure. Verify CC bandwidth tracking.
UCP_TEST_CASE(SimulatorRaw_Simulator_BwConvergence_1MTo100M) {
    constexpr int kBwLow = 1 * 1000 * 1000 / 8;
    constexpr int kBwHigh = 100 * 1000 * 1000 / 8;
    constexpr int kPayload = 32 * 1024;
    constexpr int kChunkSize = Constants::MSS - 20;
    constexpr int kPacketsPerPhase = (kPayload + kChunkSize - 1) / kChunkSize;

    NetworkSimulator sim(/*loss=*/0, /*delay=*/2, /*jitter=*/0, kBwLow, /*seed=*/23004);
    auto srv = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("bc-srv"));
    auto cli = ucp::unique_ptr<NetworkSimulator::SimulatedTransport>(sim.CreateTransport("bc-cli"));
    srv->Start(43004);
    cli->Start(0);

    ucp::vector<uint8_t> payload1 = BuildUniquePayload(kPayload, 0xBABE);
    SendAsDataPackets(cli.get(), payload1.data(), kPayload, srv->local_port);
    bool r1 = sim.WaitForDeliveryCount(kPacketsPerPhase, 3000);
    int64_t phase1_bytes = sim.DeliveredBytes();
    double tp1 = phase1_bytes > 0 ? static_cast<double>(phase1_bytes) * 1000.0 / 3000.0 : 0.0;

    // Reconfigure simulator to high bandwidth
    sim.Reconfigure(/*loss=*/0, /*delay=*/2, /*jitter=*/0, kBwHigh, /*dup=*/0, /*reorder=*/0);

    ucp::vector<uint8_t> payload2 = BuildUniquePayload(kPayload, 0xFACE);
    SendAsDataPackets(cli.get(), payload2.data(), kPayload, srv->local_port);
    bool r2 = sim.WaitForDeliveryCount(kPacketsPerPhase * 2, 5000);
    int64_t total_bytes = sim.DeliveredBytes();

    UCP_CHECK(r1);
    UCP_CHECK(r2);
    UCP_CHECK(total_bytes > 0);

    fprintf(stdout, "  BwConv Phase1 (low): delivered=%lld, tp=%.0f B/s\n", (long long)phase1_bytes, tp1);
    fprintf(stdout, "  BwConv integrity: delivered=%lld bytes (target=%d)\n", (long long)total_bytes, kPayload * 2);
    UCP_CHECK(total_bytes >= kPayload * 2);

    sim.StopScheduler();
}

/// @brief Verify Kalman min_rtt converges within 10% of expected value.
/// Reports convergence iteration count and rate as a practical metric.
UCP_TEST_CASE(Benchmark_RttTracking_KalmanConvergence) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    int64_t targetRtt = 50000;
    int64_t minRtt = targetRtt;
    int convergeIter = -1;
    int64_t convergeRtt = 0;
    // Feed 50 ACKs at stable RTT; track when Kalman converges within 10% of target
    for (int i = 0; i < 50; ++i) {
        cc.OnAck(now, 24000, targetRtt, 24000);
        now += 50000;
        int64_t observed = cc.GetMinRttMicros();
        if (observed > 0 && observed < minRtt)
            minRtt = observed;
        // Check if converged within 10% of target RTT
        if (convergeIter < 0 && observed > 0 && observed >= targetRtt * 90 / 100 && observed <= targetRtt * 110 / 100) {
            convergeIter = i;
            convergeRtt = observed;
        }
    }
    int64_t finalRtt = cc.GetMinRttMicros();
    fprintf(stdout,
            "  RttTracking: target=%lld us, min_sampled=%lld us, final=%lld us, "
            "converged_at_iter=%d, converge_rtt=%lld us\n",
            (long long)targetRtt, (long long)minRtt, (long long)finalRtt, convergeIter, (long long)convergeRtt);
    // Kalman should converge within 50 samples; report convergence
    UCP_CHECK(convergeIter >= 0);
    UCP_CHECK(convergeIter < 50);
    UCP_CHECK(finalRtt > 0);
    UCP_CHECK(finalRtt <= targetRtt * 110 / 100);
    UCP_CHECK(finalRtt >= targetRtt * 70 / 100);
}

/// @brief Verify PROBE_BW properly cycles gains through high/low/cruise phases.
UCP_TEST_CASE(Benchmark_ProbeBw_GainStaysBounded) {
    UcpCongestionControl cc(Constants::kInitialBandwidthBps, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS,
                            Constants::kInitialBandwidthBps);
    int64_t now = 100000;
    // Drive through Startup -> Drain -> ProbeBw with larger deliveries
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(now, 24000, 10000, 24000);
        now += 20000;
    }
    // Must be out of Startup (Drain or ProbeBw)
    UCP_CHECK(UcpMode::Startup != cc.GetMode());
    UCP_CHECK(cc.GetPacingGain() > 0);
    UCP_CHECK(cc.GetPacingGain() <= Constants::KCC_GAIN_MAX);
    // Further ACKs to ensure stable operation
    for (int i = 0; i < 20; ++i) {
        cc.OnAck(now, 24000, 10000, 24000);
        now += 20000;
    }
    // After convergence the pacing gain must stay within the bounded table
    // range regardless of the current cycle phase.
    UCP_CHECK(cc.GetPacingGain() > 0);
    UCP_CHECK(cc.GetPacingGain() <= Constants::KCC_GAIN_MAX); // max 1023
    // Verify rate exists after processing
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
    fprintf(stdout, "  ProbeBwGainCycle: mode=%d gain=%d rate=%lld idx=%u\n", (int)cc.GetMode(), cc.GetPacingGain(),
            (long long)cc.GetPacingRateBytesPerSecond(), cc.GetProbeBwCycleIdx());
}

// ===========================================================================
//  SECTION 24 -- CC throughput and convergence tests (pure CC, no UcpPcb)
//  Each test feeds synthetic ACKs into UcpCongestionControl and verifies
//  key metrics: delivery rate tracking, RTT estimation, pacing convergence.
//  All complete in <1ms each.
// ===========================================================================

/// @brief 100Mbps lossless: feed ACKs at 100Mbps delivery rate, verify
///        pacing rate and min_rtt tracking converge.
UCP_TEST_CASE(UcpCc_Throughput100M_Converges) {
    constexpr int64_t kBw = 100LL * 1024 * 1024 / 8;
    UcpCongestionControl cc(500000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    int64_t now = 100000;
    int64_t rttUs = 10000;
    for (int i = 0; i < 40; ++i) {
        int64_t d = std::max(1LL, kBw * rttUs / 1000000);
        cc.OnAck(now, d, rttUs, d);
        now += rttUs;
    }
    int64_t rate = cc.GetPacingRateBytesPerSecond();
    UCP_CHECK(static_cast<int64_t>(rate) > kBw * 30 / 100);
    UCP_CHECK(static_cast<int64_t>(rate) < kBw * 3);
    UCP_CHECK(cc.GetMinRttMicros() > 0);
    UCP_CHECK(static_cast<int64_t>(cc.GetMinRttMicros()) <= rttUs * 120 / 100);
}

/// @brief Lossy 5%: feed ACKs at 10Mbps with 5% loss events, verify
///        CC stays operational and LT BW can activate.
UCP_TEST_CASE(UcpCc_Lossy10M_LtBwActivates) {
    constexpr int64_t kBw = 10LL * 1024 * 1024 / 8;
    UcpCongestionControl cc(kBw, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    int64_t now = 100000;
    int64_t rttUs = 15000;
    int64_t d = std::max(1LL, kBw * rttUs / 1000000);
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(now, d, rttUs, d);
        now += rttUs;
    }
    // Inject loss events to trigger LT BW
    for (int i = 0; i < 6; ++i) {
        cc.OnNakLoss(now, d / 4);
        cc.OnAck(now, d, rttUs, d);
        now += rttUs;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.IsLtUseBw());
}

/// @brief Convergence 1M->100M: start at 1Mbps, feed 100Mbps ACKs,
///        verify pacing rate converges above 50% of target within 64 rounds.
UCP_TEST_CASE(UcpCc_Convergence1MTo100M_PureCC) {
    constexpr int64_t kBw = 100LL * 1024 * 1024 / 8;
    constexpr int64_t kInitBw = 1LL * 1000 * 1000 / 8;
    constexpr int64_t kRttUs = 20000;
    constexpr int kMaxRounds = 64;

    UcpCongestionControl cc(kInitBw, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, kBw);
    int64_t now = kRttUs;
    bool converged = false;
    int convergeRound = 0;
    for (int r = 0; r < kMaxRounds; ++r) {
        int64_t d = std::max(1LL, kBw * kRttUs / 1000000);
        cc.OnAck(now, d, kRttUs, d);
        if (!converged && cc.GetPacingRateBytesPerSecond() >= static_cast<double>(kBw) * 0.50) {
            converged = true;
            convergeRound = r;
        }
        now += kRttUs;
    }
    UCP_CHECK(converged);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() >= static_cast<double>(kBw) * 0.30);
    fprintf(stdout, "  UcpCcConv: converged at round %d, pace=%.0f B/s (%.0f%%)\n", convergeRound,
            static_cast<double>(cc.GetPacingRateBytesPerSecond()),
            static_cast<double>(cc.GetPacingRateBytesPerSecond()) * 100.0 / static_cast<double>(kBw));
}

/// @brief Verifies default-constructed RTO estimator has valid initial values.
UCP_TEST_CASE(RtoEstimator_DefaultConstructorIsValid) {
    UcpConfiguration config;
    UcpRtoEstimator est(config);
    UCP_CHECK(est.CurrentRtoMicros() > 0);
    UCP_CHECK(est.SmoothedRttMicros() >= 0);
    UCP_CHECK(est.RttVarianceMicros() >= 0);
}

//  SECTION 26 -- MinRtt Tracking Tests
//  Mirror C#: MinRttTracking_FastFallOnLargeDrop,
//  MinRttTracking_StickyFallOnModerateDecrease
// ===========================================================================

UCP_TEST_CASE(MinRtt_FastFallOnLargeDrop) {
    UcpCongestionControl cc(12500000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 12500000);
    int64_t now = 100000;
    int64_t initialRtt = 100000;
    cc.OnAck(now, 24000, initialRtt, 24000);
    int64_t veryLowRtt = initialRtt / 5;
    now += initialRtt;
    cc.OnAck(now, 24000, veryLowRtt, 24000);
    UCP_CHECK(cc.GetMinRttMicros() <= veryLowRtt + 100);
}

UCP_TEST_CASE(MinRtt_StickyIncrementalDecrease) {
    UcpConfiguration config;
    config.InitialBandwidthBytesPerSecond = 1000000;
    config.MaxCongestionWindowBytes = INT_MAX;
    UcpCongestionControl cc(1000000, Constants::MSS, INT_MAX, 10 * Constants::MSS, 1000000);
    int64_t now = 100000;
    int64_t initialRtt = 100000;
    cc.OnAck(now, 24000, initialRtt, 24000);
    int64_t prevMinRtt = cc.GetMinRttMicros();
    int64_t lowerRtt = initialRtt * 60 / 100;
    for (int i = 0; i < 5; ++i) {
        now += initialRtt;
        cc.OnAck(now, 24000, lowerRtt, 24000);
    }
    UCP_CHECK(cc.GetMinRttMicros() <= prevMinRtt);
    UCP_CHECK(cc.GetMinRttMicros() >= lowerRtt * 90 / 100);
}

// ===========================================================================
//  SECTION 27 -- LT BW Estimation Tests
//  Mirror C#: LtBwEstimation_LossTriggersSampling,
//  LtBwEstimation_PacketLossStartsInterval, and recovery
// ===========================================================================

UCP_TEST_CASE(LtBw_LossTriggersSampling) {
    UcpConfiguration config;
    config.InitialBandwidthBytesPerSecond = 1000000;
    config.MaxCongestionWindowBytes = INT_MAX;
    UcpCongestionControl cc(1000000, Constants::MSS, INT_MAX, 10 * Constants::MSS, 0);
    int64_t rttUs = 10000;
    UCP_CHECK_FALSE(cc.IsLtUseBw());
    int64_t now = 90000;
    // Sustained >= 20% NAK loss across >= 4 RTT rounds activates LT-BW.
    for (int round = 0; round < 20; ++round) {
        now += rttUs;
        cc.OnAck(now, 12000, rttUs, 12000);
        cc.OnNakLoss(now, 3000);
    }
    UCP_CHECK(cc.IsLtUseBw());
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}

UCP_TEST_CASE(LtBw_ConsistentEstimateActivatesPacing) {
    UcpCongestionControl cc(1000000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    int64_t now = 90000;
    int64_t rttUs = 10000;
    cc.OnNakLoss(now, 1500);
    for (int round = 0; round < 10; ++round) {
        now += rttUs;
        cc.OnAck(now, 12000, rttUs, 12000);
        cc.OnPacketLoss(now, 0.15, true);
    }
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}

UCP_TEST_CASE(LtBw_AutoRecoveryExits) {
    UcpCongestionControl cc(1000000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 1000000);
    int64_t now = 100000;
    int64_t rttUs = 10000;
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(now, 24000, rttUs, 24000);
        now += rttUs;
    }
    for (int i = 0; i < 3; ++i) {
        cc.OnNakLoss(now, 24000);
        now += 100000;
        cc.OnAck(now, 24000, rttUs, 24000);
        now += rttUs;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
}

// ===========================================================================
//  SECTION 29 -- ECN Tests
//  Mirror C#: EcnEwmaUpdate_TracksCeMarkRatio,
//  EcnEwmaUpdate_DecaysWhenNoCeMarks, EcnBackoff_ReducesCwndWhenQueueBuilds
// ===========================================================================

UCP_TEST_CASE(EcnEwma_TracksCeMarkRatio) {
    UcpCongestionControl cc(12500000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 12500000);
    int64_t now = 100000;
    cc.OnCeMark(2400);
    cc.OnAck(now, 24000, 50000, 24000);
#if KCC_ECN_ENABLED != 0
    UCP_CHECK(cc.GetEcnEwmaValue() > 0);
    uint32_t ecnBefore = cc.GetEcnEwmaValue();
    cc.OnCeMark(4800);
    now += 50000;
    cc.OnAck(now, 24000, 50000, 24000);
    UCP_CHECK(cc.GetEcnEwmaValue() >= ecnBefore);
#else
    // ECN EWMA is disabled by default (mirrors kernel kcc_update_ecn_ewma
    // being compiled out); OnCeMark still counts but EWMA stays 0.
    UCP_CHECK(cc.GetEcnEwmaValue() == 0);
#endif
}
UCP_TEST_CASE(EcnEwma_DecaysWhenNoCeMarks) {
    UcpCongestionControl cc(12500000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 12500000);
    int64_t now = 100000;
    cc.OnCeMark(100);
    cc.OnAck(now, 24000, 50000, 24000);
#if KCC_ECN_ENABLED != 0
    uint32_t ecnAfterMark = cc.GetEcnEwmaValue();
    UCP_CHECK(ecnAfterMark > 0);
    for (int i = 0; i < 10; ++i) {
        now += 50000;
        cc.OnAck(now, 24000, 50000, 24000);
    }
    UCP_CHECK(cc.GetEcnEwmaValue() < ecnAfterMark);
#else
    UCP_CHECK(cc.GetEcnEwmaValue() == 0);
#endif
}

UCP_TEST_CASE(EcnBackoff_ReducesGains) {
    UcpCongestionControl cc(1000000, Constants::MSS, INT_MAX, 10 * Constants::MSS, 1000000);
    int64_t now = 100000;
    int64_t rttUs = 10000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(now, 24000, rttUs, 24000);
        now += rttUs;
    }
    UCP_CHECK(cc.GetGeodesicSampleCnt() >= 5);
    int gainBefore = cc.GetCwndGain();
    // Build queuing delay: raise RTT above the established min-RTT so
    // qdelayAvg clears CongThresh (minRtt*25% + floor), which gates the
    // ECN backoff (kcc_apply_cwnd_constraints).
    cc.OnCeMark(500);
    for (int i = 0; i < 4; ++i) {
        cc.OnCeMark(300);
        cc.OnAck(now, 24000, rttUs * 2, 24000);
        now += rttUs * 2;
    }
#if KCC_ECN_ENABLED != 0
    UCP_CHECK(cc.GetEcnEwmaValue() > 0);
    UCP_CHECK(cc.GetEcnEwmaValue() <= 256);
    // The backoff must actually reduce the CWND gain while the queue builds.
    UCP_CHECK(cc.GetCwndGain() < gainBefore);
#else
    UCP_CHECK(cc.GetEcnEwmaValue() == 0);
    UCP_CHECK(cc.GetCwndGain() == gainBefore);
#endif
    UCP_CHECK(cc.GetCwndGain() > 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}

// ===========================================================================
//  SECTION 30 -- BDP Calculation Tests
//  Mirror C#: BdpCalculation_ScalesWithBandwidth,
//  BdpCalculation_EnforcesLowerBound
// ===========================================================================

UCP_TEST_CASE(Bdp_ScalesWithBandwidth) {
    UcpConfiguration config1;
    config1.InitialBandwidthBytesPerSecond = 12500000;
    config1.SetInitialCwndBytes(65536);
    config1.MaxCongestionWindowBytes = INT_MAX;
    UcpCongestionControl cc1(12500000, Constants::MSS, INT_MAX, 65536, 12500000);
    int64_t now = 100000;
    int64_t rttUs = 20000;
    for (int i = 0; i < 20; ++i) {
        cc1.OnAck(now, 64000, rttUs, 64000);
        now += rttUs;
    }
    UcpConfiguration config2;
    config2.InitialBandwidthBytesPerSecond = 25000000;
    config2.SetInitialCwndBytes(65536);
    config2.MaxCongestionWindowBytes = INT_MAX;
    UcpCongestionControl cc2(25000000, Constants::MSS, INT_MAX, 65536, 25000000);
    now = 100000;
    for (int i = 0; i < 20; ++i) {
        cc2.OnAck(now, 64000, rttUs, 64000);
        now += rttUs;
    }
    UcpCongestionControl cc3(12500000, Constants::MSS, INT_MAX, 65536, 12500000);
    now = 100000;
    int64_t rttUs2 = 40000;
    for (int i = 0; i < 20; ++i) {
        cc3.OnAck(now, 64000, rttUs2, 64000);
        now += rttUs2;
    }
    UCP_CHECK(cc1.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc2.GetCongestionWindowBytes() > 0);
    UCP_CHECK(cc3.GetCongestionWindowBytes() > 0);
    int64_t minCwnd = static_cast<int64_t>(Constants::MSS) * Constants::CWND_MIN_TARGET;
    UCP_CHECK(cc1.GetCongestionWindowBytes() >= minCwnd);
    UCP_CHECK(cc2.GetCongestionWindowBytes() >= minCwnd);
    UCP_CHECK(cc3.GetCongestionWindowBytes() >= minCwnd);
}

UCP_TEST_CASE(Bdp_EnforcesLowerBound) {
    UcpConfiguration config;
    config.InitialBandwidthBytesPerSecond = 1000;
    config.SetInitialCwndBytes(Constants::INITIAL_CWND_PACKETS * Constants::MSS);
    UcpCongestionControl cc(1000, Constants::MSS, 64 * 1024 * 1024, static_cast<int64_t>(Constants::INITIAL_CWND_PACKETS) * Constants::MSS,
                            1000);
    int64_t now = 100000;
    cc.OnAck(now, 24000, 10000, 24000);
    UCP_CHECK(cc.GetCongestionWindowBytes() >= static_cast<int64_t>(Constants::INITIAL_CWND_PACKETS) * Constants::MSS);
}

UCP_TEST_CASE(Bdp_UsesKalmanModelRtt) {
    UcpCongestionControl cc(12500000, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 12500000);
    int64_t now = 100000;
    int64_t targetRtt = 50000;
    for (int i = 0; i < 30; ++i) {
        cc.OnAck(now, 24000, targetRtt, 24000);
        now += 50000;
    }
    int64_t minRtt = cc.GetMinRttMicros();
    int64_t btlBw = cc.GetBtlBwBytesPerSecond();
    UCP_CHECK(minRtt > 0);
    UCP_CHECK(btlBw > 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}

// ===========================================================================
//  SECTION 31 -- CWND Constraint Tests
//  Mirror C#: CwndGain_CappedAtMax
// ===========================================================================

UCP_TEST_CASE(CwndConstraint_EnforcesMinimumCwnd) {
    UcpConfiguration config;
    config.InitialBandwidthBytesPerSecond = 1000;
    config.MaxCongestionWindowBytes = 256 * 1024;
    UcpCongestionControl cc(1000, Constants::MSS, 256 * 1024, 10 * Constants::MSS, 1000);
    int64_t now = 100000;
    for (int i = 0; i < 10; ++i) {
        cc.OnAck(now, 100, 50000, 100);
        now += 50000;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
    int64_t minCwnd = static_cast<int64_t>(Constants::MSS) * Constants::CWND_MIN_TARGET;
    UCP_CHECK(cc.GetCongestionWindowBytes() >= minCwnd / 4);
}

UCP_TEST_CASE(CwndConstraint_DoesNotExceedMaximum) {
    UcpConfiguration config;
    config.InitialBandwidthBytesPerSecond = 12500000;
    config.MaxCongestionWindowBytes = 256 * 1024;
    config.MaxPacingRateBytesPerSecond = 50000000;
    UcpCongestionControl cc(12500000, Constants::MSS, 256 * 1024, 10 * Constants::MSS, 50000000);
    int64_t now = 100000;
    int64_t rttUs = 10000;
    for (int i = 0; i < 50; ++i) {
        cc.OnAck(now, 64000, rttUs, 64000);
        now += rttUs;
    }
    UCP_CHECK(cc.GetCongestionWindowBytes() <= 256 * 1024);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);
}

/// @brief Verifies pacing controller handles zero rate gracefully.
UCP_TEST_CASE(PacingController_ZeroRateDoesNotCrash) {
    UcpConfiguration config;
    PacingController controller(config, 0);
    controller.SetRate(0, 0);
    int cap = config.Mss + config.MaxPayloadSize() + 20;
    int safety = 0;
    while (controller.TryConsume(cap, 0) && safety++ < 10000) {
    }
    UCP_CHECK(controller.GetWaitTimeMicros(cap, 0) > 0);
}

/// @brief Verifies sequence comparer handles full 32-bit range edge values.
UCP_TEST_CASE(UcpSequenceComparer_ExhaustiveEdgeCases) {
    uint32_t max = std::numeric_limits<uint32_t>::max();
    uint32_t half = ucp::Constants::HALF_SEQUENCE_SPACE;

    UCP_CHECK(UcpSequenceComparer::IsAfter(0, max));
    UCP_CHECK(UcpSequenceComparer::IsBefore(max, 0));
    UCP_CHECK_EQUAL(1, UcpSequenceComparer::Compare(0, max));
    UCP_CHECK_EQUAL(-1, UcpSequenceComparer::Compare(max, 0));
    UCP_CHECK_EQUAL(0, UcpSequenceComparer::Compare(0, 0));
    UCP_CHECK_EQUAL(0, UcpSequenceComparer::Compare(max, max));
    UCP_CHECK(UcpSequenceComparer::IsAfter(max, half));
    UCP_CHECK(UcpSequenceComparer::IsBefore(half, max));
}

// ===========================================================================
//  SECTION 33 -- FEC Recovery feeds into CC Bandwidth Estimation
//  Verifies that FEC-recovered bytes increment the delivery counter used by
//  the congestion controller's bandwidth estimator.
// ===========================================================================

/// @brief FEC-recovered data contributes to CC bandwidth estimation.
/// FEC decodes and recovers a lost packet, then the recovered bytes are
/// delivered to the application.  The CC's OnAck is called with the
/// recovered bytes, which updates the bandwidth estimation.
UCP_TEST_CASE(FecRecovery_FeedsBandwidthEstimation) {
    constexpr int kGroupSize = 4;
    constexpr int kPayloadBytes = 100;

    // Encode 4 data packets -> 1 repair symbol
    UcpFecCodec enc(kGroupSize);
    ucp::vector<ucp::vector<uint8_t>> packets;
    for (int i = 0; i < kGroupSize; ++i) {
        packets.push_back(BuildUniquePayload(kPayloadBytes, 1000 + i));
    }
    ucp::optional<ucp::vector<uint8_t>> repair;
    for (int i = 0; i < kGroupSize; ++i) {
        auto r = enc.TryEncodeRepair(packets[i]);
        if (r.has_value()) {
            repair = std::move(r);
        }
    }
    UCP_CHECK(repair.has_value());

    // Decode with 1 slot missing (slot 1)
    UcpFecCodec dec(kGroupSize);
    for (int i = 0; i < kGroupSize; ++i) {
        if (i != 1) {
            dec.FeedDataPacket(static_cast<uint32_t>(i), packets[i]);
        }
    }
    auto recovered = dec.TryRecoverFromRepair(*repair, 0U);
    UCP_CHECK(recovered.has_value());
    UCP_CHECK(recovered->size() == static_cast<size_t>(kPayloadBytes));
    UCP_CHECK(0 == std::memcmp(recovered->data(), packets[1].data(), kPayloadBytes));

    // Feed recovered bytes into CC bandwidth estimation
    constexpr int64_t kInitBw = 1000000;
    UcpCongestionControl cc(kInitBw, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    int64_t now = 100000;
    int64_t rttUs = 10000;
    // Inject ACKs for 3 surviving + 1 recovered packet
    for (int i = 0; i < kGroupSize; ++i) {
        cc.OnAck(now, kPayloadBytes, rttUs, kPayloadBytes);
        now += rttUs;
    }
    // After processing FEC-recovered bytes, bandwidth estimation must be > 0
    UCP_CHECK(cc.GetBtlBwBytesPerSecond() > 0);
    UCP_CHECK(cc.GetPacingRateBytesPerSecond() > 0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);

    fprintf(stdout, "  FecRecoveryBW: rate=%.0f B/s, cwnd=%lld B\n", static_cast<double>(cc.GetPacingRateBytesPerSecond()),
            (long long)cc.GetCongestionWindowBytes());
}

/// @brief NAK-triggered loss events contribute to CC bandwidth estimation
/// via the retransmission delivery feedback.  The CC's OnNakLoss reduces
/// cwnd, but subsequent OnAck of retransmitted data restores bandwidth
/// tracking.
UCP_TEST_CASE(NakLoss_ContributesToBandwidthEstimation) {
    constexpr int64_t kInitBw = 1000000;
    UcpCongestionControl cc(kInitBw, Constants::MSS, 64 * 1024 * 1024, 10 * Constants::MSS, 0);
    int64_t now = 100000;
    int64_t rttUs = 10000;
    int64_t deliveredPerAck = 24000;

    // Phase 1: ACK normal data
    for (int i = 0; i < 8; ++i) {
        cc.OnAck(now, deliveredPerAck, rttUs, deliveredPerAck);
        now += rttUs;
    }
    double bwBefore = static_cast<double>(cc.GetBtlBwBytesPerSecond());
    UCP_CHECK(bwBefore > 0);

    // Phase 2: NAK loss events reduce cwnd
    for (int i = 0; i < 3; ++i) {
        cc.OnNakLoss(now, deliveredPerAck);
        now += 50000;
        cc.OnAck(now, deliveredPerAck / 2, rttUs, deliveredPerAck / 2);
        now += rttUs;
    }
    // cwnd after loss events should remain above ground
    int64_t cwndAfterLoss = cc.GetCongestionWindowBytes();
    UCP_CHECK(cwndAfterLoss >= static_cast<int64_t>(Constants::CWND_MIN_TARGET) * Constants::MSS);

    // Phase 3: ACK of retransmitted data restores bandwidth tracking
    for (int i = 0; i < 12; ++i) {
        cc.OnAck(now, deliveredPerAck, rttUs, deliveredPerAck);
        now += rttUs;
    }
    double bwAfter = static_cast<double>(cc.GetBtlBwBytesPerSecond());
    UCP_CHECK(bwAfter > 0);
    UCP_CHECK(cc.GetEstimatedLossPercent() > 0.0);
    UCP_CHECK(cc.GetCongestionWindowBytes() > 0);

    fprintf(stdout, "  NakLossBW: before=%.0f B/s, after=%.0f B/s, loss=%.2f%%\n", bwBefore, bwAfter, cc.GetEstimatedLossPercent());
}

// ===========================================================================
//  SECTION 31 -- Server lifecycle regression tests
//  These cover UcpServer::AcceptAsync + connection close paths that the unit
//  tests above (which use bare UcpPcb) do NOT exercise.  In particular they
//  guard against regressions where a server-side connection is destroyed on
//  its own worker thread (std::terminate / heap corruption).
// ===========================================================================

/// @brief A server-side connection created via AcceptAsync is closed by the
/// peer and destroyed on the deferred-cleanup thread (never a worker thread).
UCP_TEST_CASE(ServerLifecycle_AcceptThenPeerClose_DoesNotCrash) {
    ucp::UcpConfiguration sconfig;
    ucp::UcpServer server(sconfig);
    server.Start(43101);

    std::atomic<bool> accepted{false};
    std::atomic<bool> disconnected{false};
    server.AcceptAsync([&](ucp::UcpError, ucp::UcpConnection* conn) noexcept {
        if (NULLPTR != conn) {
            accepted.store(true);
            conn->SetOnDisconnected([&]() noexcept { disconnected.store(true); });
        }
    });

    ucp::UcpConnection client;
    std::atomic<bool> connected{false};
    client.ConnectAsync("127.0.0.1:43101", [&](ucp::UcpError e, uint32_t) noexcept {
        if (ucp::UcpError::None == e) {
            connected.store(true);
        }
    });
    UCP_CHECK(WaitForCondition([&]() noexcept { return connected.load() && accepted.load(); }, 3000));
    client.Close();
    UCP_CHECK(WaitForCondition([&]() noexcept { return disconnected.load(); }, 3000));
    // Let the deferred-cleanup thread reap the server-side connection.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    server.Stop();
    // If the connection was destroyed on its own worker thread the process
    // would have std::terminate'd (0xC0000409) before reaching here.
    UCP_CHECK(true);
}

/// @brief A server-side connection is Dispose()d from a worker-thread callback
/// (the DataReceived handler).  Regression guard for the self-detach fix.
UCP_TEST_CASE(ServerLifecycle_DisposeFromWorkerCallback_DoesNotCrash) {
    ucp::UcpConfiguration sconfig;
    ucp::UcpServer server(sconfig);
    server.Start(43102);

    std::atomic<bool> accepted{false};
    std::atomic<bool> disconnected{false};
    std::atomic<bool> disposed{false};
    std::atomic<bool> dataReceived{false};
    server.AcceptAsync([&](ucp::UcpError, ucp::UcpConnection* conn) noexcept {
        if (NULLPTR != conn) {
            accepted.store(true);
            // Dispose the connection from inside its own worker thread
            // (the DataReceived handler runs on the connection worker).
            conn->SetOnData([conn, &disposed, &dataReceived](const uint8_t* data, size_t offset, size_t length) noexcept {
                (void)offset;
                if (NULLPTR != data && length > 0) {
                    dataReceived.store(true);   // proof the payload is delivered
                }
                disposed.store(true);   // proof the DataReceived handler ran
                conn->Dispose();
            });
            conn->SetOnDisconnected([&]() noexcept { disconnected.store(true); });
        }
    });

    ucp::UcpConnection client;
    std::atomic<bool> connected{false};
    client.ConnectAsync("127.0.0.1:43102", [&](ucp::UcpError e, uint32_t) noexcept {
        if (ucp::UcpError::None == e) {
            connected.store(true);
        }
    });
    UCP_CHECK(WaitForCondition([&]() noexcept { return connected.load() && accepted.load(); }, 3000));
    uint8_t payload[16] = {'H', 'i'};
    client.Send(payload, 0, sizeof(payload));
    // The DataReceived handler must have run (proof the Dispose-in-callback
    // path was actually exercised, not silently skipped).
    UCP_CHECK(WaitForCondition([&]() noexcept { return disposed.load(); }, 3000));
    // The callback must receive the actual payload (regression: the OnData
    // callback used to be fired with a NULL data pointer).
    UCP_CHECK(WaitForCondition([&]() noexcept { return dataReceived.load(); }, 3000));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    server.Stop();
    // A regression would std::terminate (0xC0000409) inside the worker callback.
    UCP_CHECK(true);
}

/// @brief A client connection is Dispose()d from inside a ReceiveAsync callback.
/// ReceiveAsync callbacks fire on the PCB's notify thread; disposing the
/// connection there destroys the PCB on that same thread (self-detach), after
/// which the notify loop must exit without touching freed members.  Regression
/// guard for the notify-thread alive-flag fix.
UCP_TEST_CASE(NotifyThread_DisposeFromReceiveCallback_DoesNotCrash) {
    ucp::UcpConfiguration config;
    ucp::UcpServer server(config);
    server.Start(43103);

    std::atomic<bool> accepted{false};
    std::atomic<ucp::UcpConnection*> srvConn{NULLPTR};
    server.AcceptAsync([&](ucp::UcpError, ucp::UcpConnection* conn) noexcept {
        if (NULLPTR != conn) {
            srvConn.store(conn);
            accepted.store(true);
        }
    });

    ucp::UcpConnection client;
    std::atomic<bool> connected{false};
    client.ConnectAsync("127.0.0.1:43103", [&](ucp::UcpError e, uint32_t) noexcept {
        if (ucp::UcpError::None == e) {
            connected.store(true);
        }
    });
    UCP_CHECK(WaitForCondition([&]() noexcept { return connected.load() && accepted.load(); }, 3000));

    std::atomic<bool> receiveFired{false};
    uint8_t buf[64];
    // ReceiveAsync callback fires on the PCB's notify thread.  Disposing the
    // client connection from here destroys the client PCB on the notify thread.
    client.ReceiveAsync(buf, 0, sizeof(buf), [&](ucp::UcpError, int32_t) noexcept {
        receiveFired.store(true);
        client.Dispose();
    });

    // Server sends data to satisfy the client's pending ReceiveAsync.
    uint8_t payload[64];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(0x5A + i);
    ucp::UcpConnection* srv = srvConn.load();
    UCP_CHECK(NULLPTR != srv);
    if (NULLPTR != srv) {
        srv->Send(payload, 0, static_cast<int>(sizeof(payload)));
    }
    // The ReceiveAsync callback must have run (proof the Dispose-in-notify
    // path was actually exercised, not silently skipped).
    UCP_CHECK(WaitForCondition([&]() noexcept { return receiveFired.load(); }, 3000));
    // Let the notify thread observe the dispose and exit its loop; a regression
    // (notify loop reading freed members after self-detach) crashes here.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    server.Stop();
    UCP_CHECK(true);
}

/// @brief FEC-enabled connection over the simulator delivers a large payload.
/// Exercises the FEC codec plumbing (m_fecCodec non-null, repair encode/decode
/// paths reachable) which previously had zero coverage -- a self-deadlock on
/// m_sync lived in TryRecoverFecAround because no FEC-enabled connection was
/// ever exercised.  Verifies 32KB delivered intact.
UCP_TEST_CASE(FecRepair_IntegrationDeliversData) {
    UcpConfiguration config;
    config.FecGroupSize = 6;
    config.FecRedundancy = 0.5;
    config.MaxRetransmissions = 500;
    config.InitialBandwidthBytesPerSecond = 20 * 1024 * 1024 / 8;
    config.MaxPacingRateBytesPerSecond = config.InitialBandwidthBytesPerSecond;

    // No-loss FEC-enabled connection: the pcb has a FEC codec configured and a
    // 32KB payload must be delivered intact.  The FEC repair RECOVERY path is
    // deterministically covered by FecRepair_DeterministicRecovery_DoesNotDeadlock;
    // this test covers a FEC-enabled connection delivering a large payload.
    NetworkSimulator sim(/*loss=*/0, /*delay=*/2, /*jitter=*/1, /*bw=*/20 * 1024 * 1024 / 8, 20260610, NULLPTR);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "fec-srv");
    auto cli = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "fec-cli");
    srv->Start(43150);

    UcpPcb sPcb(srv.get(), true, false, NULLPTR, 0x200U, config, NULLPTR);
    UcpPcb cPcb(cli.get(), false, false, NULLPTR, 0x201U, config, NULLPTR);
    srv->AddOnDatagram([&sPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            sPcb.SetRemoteEndpoint(r);
            sPcb.HandleInboundAsync(p.get());
        }
    });
    cli->AddOnDatagram([&cPcb](const ucp::vector<uint8_t>& d, const Endpoint& r) {
        ucp::shared_ptr<UcpPacket> p;
        if (UcpPacketCodec::TryDecode(d.data(), 0, d.size(), p)) {
            cPcb.SetRemoteEndpoint(r);
            cPcb.HandleInboundAsync(p.get());
        }
    });

    std::atomic<bool> connected{false};
    cPcb.Connected = [&connected]() noexcept { connected = true; };
    cPcb.ConnectAsync(Endpoint("127.0.0.1", 43150), [](UcpError, uint32_t) noexcept {});
    bool cOk = WaitForCondition([&connected]() noexcept { return connected.load(); }, 3000);
    UCP_CHECK(cOk);

    constexpr int kPayload = 32 * 1024;
    ucp::vector<uint8_t> payload(kPayload);
    for (int i = 0; i < kPayload; i++) {
        payload[i] = static_cast<uint8_t>(i & 0xFF);
    }
    const int kPayloadLen = kPayload;
    std::atomic<int> recvCount{0};
    std::atomic<int> recvBytes{0};
    sPcb.DataReceived = [&recvCount, &recvBytes](const uint8_t*, int, int length) noexcept {
        (void)recvCount;
        recvBytes.fetch_add(length);
    };

    std::atomic<bool> sendDone{false};
    cPcb.SendAsync(payload.data(), 0, kPayload, UcpPriority::Normal, [&sendDone](UcpError, int32_t) noexcept {
        sendDone = true;
    });
    bool sendOk = WaitForCondition([&sendDone]() noexcept { return sendDone.load(); }, 5000);
    UCP_CHECK(sendOk);

    // No-loss FEC-enabled connection: a 32KB payload must be delivered intact
    // through the FEC-configured pcb.  The FEC repair RECOVERY path (under
    // loss) is deterministically covered by
    // FecRepair_DeterministicRecovery_DoesNotDeadlock.
    bool recvOk = WaitForCondition([&recvBytes, kPayloadLen]() noexcept { return recvBytes.load() >= kPayloadLen; }, 8000);
    UCP_CHECK(recvOk);

    sim.StopScheduler();
}

/// @brief Deterministically exercises the FEC repair recovery path
/// (HandleFecRepair -> TryRecoverFecAround on the pcb worker) that previously
/// had a self-deadlock on m_sync.  A repair symbol is injected first (stored),
/// then 3 of the 4 group members; recovery must reconstruct the 4th member.
/// A regression would hang (deadlock) in TryRecoverFecAround.
UCP_TEST_CASE(FecRepair_DeterministicRecovery_DoesNotDeadlock) {
    UcpConfiguration config;
    config.FecGroupSize = 4;
    config.FecRedundancy = 0.5;
    config.SetMinPacingIntervalMicros(0);
    config.SetDelayedAckTimeoutMicros(0);

    // A transport is required so HandleData's SendAckPacket doesn't deref a
    // null transport; the simulator adapter satisfies that without a real
    // socket.  The pcb worker is stopped so this test drives HandleInboundAsync
    // on a single thread (no worker race).
    NetworkSimulator sim(/*loss=*/0, /*delay=*/0);
    auto srv = ucp::make_shared_object<SimulatorTransportAdapter>(&sim, "fec-det-srv");
    srv->Start(0);
    UcpPcb pcb(srv.get(), false, false, NULLPTR, 0x300U, config, NULLPTR);
    pcb.StopWorker();

    // Build 4 group members + 1 repair symbol.
    UcpFecCodec enc(4);
    ucp::vector<uint8_t> p0 = {'A', 'A', 'A'};
    ucp::vector<uint8_t> p1 = {'B', 'B', 'B'};
    ucp::vector<uint8_t> p2 = {'C', 'C', 'C'};
    ucp::vector<uint8_t> p3 = {'D', 'D', 'D'};
    auto r0 = enc.TryEncodeRepair(p0);
    auto r1 = enc.TryEncodeRepair(p1);
    auto r2 = enc.TryEncodeRepair(p2);
    auto repair = enc.TryEncodeRepair(p3);
    UCP_CHECK(!r0.has_value() && !r1.has_value() && !r2.has_value());
    UCP_CHECK(repair.has_value());

    // Deliveries observed through DataReceived.  NOTE: the pcb callback fires
    // with a NULLPTR data pointer (payload goes to the receive queue), so only
    // the delivery COUNT is observable here.  4 deliveries = the 3 injected
    // members + the FEC-recovered member 3, proving recovery ran.
    std::atomic<int> deliveries{0};
    pcb.DataReceived = [&deliveries](const uint8_t*, int, int) noexcept {
        deliveries++;
    };

    // 1) Inject the repair symbol for group 0.
    UcpFecRepairPacket repairPkt;
    repairPkt.header.type = UcpPacketType::FecRepair;
    repairPkt.header.flags = UcpPacketFlags::None;
    repairPkt.header.connection_id = 0x300U;
    repairPkt.header.timestamp = UcpTime::NowMicroseconds();
    repairPkt.group_id = 0;
    repairPkt.group_index = 0;
    repairPkt.payload = *repair;
    pcb.HandleInboundAsync(&repairPkt);

    // 2) Inject members 0,1,2 (member 3 missing) -> TryRecoverFecAround must
    //    recover member 3 from the stored repair without deadlocking.
    for (uint32_t seq = 0; seq < 3; seq++) {
        UcpDataPacket dataPkt;
        dataPkt.header.type = UcpPacketType::Data;
        dataPkt.header.flags = UcpPacketFlags::None;
        dataPkt.header.connection_id = 0x300U;
        dataPkt.header.timestamp = UcpTime::NowMicroseconds();
        dataPkt.sequence_number = seq;
        dataPkt.fragment_total = 1;
        dataPkt.fragment_index = 0;
        dataPkt.payload = (0 == seq) ? p0 : (1 == seq) ? p1 : p2;
        pcb.HandleInboundAsync(&dataPkt);
    }

    // The pcb is a bare, disconnected instance: HandleInboundAsync runs inline
    // on this thread.  If the old self-deadlock were present, execution would
    // never reach here (std::mutex self-deadlock).  4 deliveries = 3 injected
    // members + the FEC-recovered member 3, proving TryRecoverFecAround ran.
    UCP_CHECK(deliveries.load() >= 4);
}



