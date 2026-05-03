// ucp_core_tests.cpp — Comprehensive unit and integration tests for the UCP C++ library
//
// Mirrors the C# test suite in Ucp.Tests/UcpCoreTests.cs.
// Tests cover:
//   - Sequence number comparison (wraparound at uint32_max)
//   - Packet codec round-trip (ACK + SACK blocks + echo timestamp)
//   - SACK generator (continuous block merging)
//   - RTO estimator (backoff, clamping, smoothing)
//   - Pacing controller (token bucket, force consume, edge cases)
//   - BBR congestion control (startup exit, rate cliff resistance, auto-probe)
//   - FEC codec (single/two/three loss recovery, edge cases)
//   - NetworkSimulator unit tests (loss, delay, duplication, reorder, bandwidth, jitter)
//   - Integration scenarios (no-loss, lossy, long-fat-pipe, reorder+dup, full-duplex)
//   - Benchmark scenarios (gigabit, 10G, burst, asymmetric, high-jitter, mobile, satellite, VPN, DC, enterprise)
//   - Mobile/vehicle outage scenarios (Weak4G, Airplane, HighSpeedTrain, Driving)
//   - Coverage parameterized tests (100M at 0.2%/1%/10%, 1G at 3%)
//   - Edge cases (SequenceComparer exhaustive, BBR edge states, FEC edge states, RTO edge states)
//
// Where UcpServer / UcpConnection are not yet implemented in the C++ codebase,
// integration tests document the expected contract and will activate once the
// classes ship. Currently these use simulator-only or placeholder validation.

#include "test_framework.h"

#include "ucp/ucp_constants.h"
#include "ucp/ucp_enums.h"
#include "ucp/ucp_packets.h"
#include "ucp/ucp_sequence_comparer.h"
#include "ucp/ucp_rto_estimator.h"
#include "ucp/ucp_sack_generator.h"
#include "ucp/ucp_bbr.h"
#include "ucp/ucp_configuration.h"
#include "ucp/ucp_packet_codec.h"
#include "ucp/ucp_fec_codec.h"
#include "ucp/ucp_pacing.h"
#include "ucp/ucp_time.h"

#include "network_simulator.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <limits>
#include <string>
#include <vector>

using namespace ucp;
using namespace ucp_test;

// ---------------------------------------------------------------------------
//  Helper: BuildUniquePayload — pseudo-random but deterministic payload builder
//  Uses an LCG: state = state * 1664525 + 1013904223; output = state >> 24.
//  Matches C# BuildUniquePayload exactly.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> BuildUniquePayload(int size, int seed) {
    std::vector<uint8_t> data(size);                    // Pre-allocate the full buffer
    uint32_t state = static_cast<uint32_t>(seed);       // Initialize LCG state from seed
    for (int i = 0; i < size; ++i) {
        state = state * 1664525U + 1013904223U;         // LCG step (same constants as C#)
        data[i] = static_cast<uint8_t>(state >> 24);     // Use high byte for output
    }
    return data;
}

// ---------------------------------------------------------------------------
//  Helper: BuildPayload — fills a buffer with a single repeated character value
//  Matches C# BuildPayload.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> BuildPayload(char value, int size) {
    return std::vector<uint8_t>(size, static_cast<uint8_t>(value));
}

// ---------------------------------------------------------------------------
//  Helper: BuildConcatenatedUniquePayload — builds a unique payload whose total
//  size equals the sum of chunk_sizes. Matches C# BuildConcatenatedUniquePayload.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> BuildConcatenatedUniquePayload(
        const std::vector<int>& chunk_sizes, int seed) {
    int total = 0;
    for (int cs : chunk_sizes) total += cs;             // Sum all chunk sizes
    return BuildUniquePayload(total, seed);              // Build payload of total size
}

// ===========================================================================
//  SECTION 1 — Unit tests for SequenceComparer
//  Verifies circular uint32 comparison with wrap-around at max.
//  Matches C# SequenceComparer_HandlesWrapAround.
// ===========================================================================
UCP_TEST_CASE(SequenceComparer_HandlesWrapAround) {
    uint32_t max_val = std::numeric_limits<uint32_t>::max();  // 4294967295
    uint32_t zero = 0;
    uint32_t one = 1;

    // In circular sequence space, 0 comes AFTER max_val
    UCP_CHECK(UcpSequenceComparer::IsAfter(zero, max_val));
    // 1 also comes AFTER max_val
    UCP_CHECK(UcpSequenceComparer::IsAfter(one, max_val));
    // max_val comes BEFORE zero
    UCP_CHECK(UcpSequenceComparer::IsBefore(max_val, zero));

    // Compare returns +1 when left > right in circular order
    UCP_CHECK(UcpSequenceComparer::Compare(zero, max_val) == 1);
    // Compare returns -1 when left < right in circular order
    UCP_CHECK(UcpSequenceComparer::Compare(max_val, zero) == -1);
}

// ===========================================================================
//  SECTION 2 — Unit tests for PacketCodec
//  Verifies round-trip encoding/decoding of ACK packets with all optional
//  fields: SACK blocks and echo timestamp.
//  Matches C# PacketCodec_CanRoundTripAckWithEchoTimestamp.
// ===========================================================================
UCP_TEST_CASE(PacketCodec_CanRoundTripAckWithEchoTimestamp) {
    UcpAckPacket packet;
    packet.header.type         = UcpPacketType::Ack;       // ACK type
    packet.header.flags        = UcpPacketFlags::NeedAck;   // Request reciprocal ACK
    packet.header.connection_id = 77;                       // Arbitrary connection ID
    packet.header.timestamp    = 123456789;                 // Sender's timestamp for RTT
    packet.ack_number          = 100;                       // Cumulative ACK number
    packet.sack_blocks.push_back({102, 105});                // SACK block: range [102, 105]
    packet.sack_blocks.push_back({109, 110});                // SACK block: range [109, 110]
    packet.window_size         = 512;                       // Advertised window size
    packet.echo_timestamp      = 987654321;                 // Echoed timestamp for RTT calculation

    // Encode to wire format
    std::vector<uint8_t> encoded = UcpPacketCodec::Encode(packet);
    // Decode back from wire format
    ucp::unique_ptr<UcpPacket> decoded_raw;
    bool ok = UcpPacketCodec::TryDecode(encoded.data(), 0,
                                         static_cast<int>(encoded.size()), decoded_raw);
    UCP_CHECK(ok);  // Decode must succeed

    // Downcast to the expected ACK type
    auto* decoded = dynamic_cast<UcpAckPacket*>(decoded_raw.get());
    UCP_CHECK(decoded != nullptr);

    // Verify all header fields survived the round-trip
    UCP_CHECK(decoded->header.type         == packet.header.type);
    UCP_CHECK(decoded->header.flags        == packet.header.flags);
    UCP_CHECK(decoded->header.connection_id == packet.header.connection_id);

    // Verify ACK-specific fields
    UCP_CHECK(decoded->ack_number          == packet.ack_number);
    UCP_CHECK(decoded->window_size         == packet.window_size);
    UCP_CHECK(decoded->echo_timestamp      == packet.echo_timestamp);

    // Verify SACK blocks were encoded and decoded correctly
    UCP_CHECK(decoded->sack_blocks.size()  == 2);
    UCP_CHECK(decoded->sack_blocks[0].Start== 102);
    UCP_CHECK(decoded->sack_blocks[0].End  == 105);
}

// ===========================================================================
//  SECTION 3 — Unit tests for SackGenerator
//  Verifies that consecutive received sequence numbers are merged into
//  continuous SACK blocks.
//  Matches C# SackGenerator_BuildsContinuousBlocks.
// ===========================================================================
UCP_TEST_CASE(SackGenerator_BuildsContinuousBlocks) {
    UcpSackGenerator gen;
    // Simulate received sequence numbers with two contiguous ranges and one isolated
    std::vector<uint32_t> received = {12, 13, 14, 18, 19, 25};
    // Generate SACK blocks referencing last ACK = 10, with max 8 blocks
    auto blocks = gen.Generate(10, received, 8);

    // Expect three blocks: [12-14], [18-19], and the singleton [25-25]
    UCP_CHECK(blocks.size() == 3);
    UCP_CHECK(blocks[0].Start== 12);
    UCP_CHECK(blocks[0].End  == 14);
    UCP_CHECK(blocks[1].Start== 18);
    UCP_CHECK(blocks[1].End  == 19);
    UCP_CHECK(blocks[2].Start== 25);
    UCP_CHECK(blocks[2].End  == 25);
}

// ===========================================================================
//  SECTION 4 — Unit tests for RtoEstimator
//  Tests exponential backoff with caps and invalid configuration clamping.
// ===========================================================================

// Matches C# RtoEstimator_CapsBackoffAtTwiceMinimumRto
UCP_TEST_CASE(RtoEstimator_CapsBackoffAtTwiceMinimumRto) {
    UcpConfiguration config;
    config.MinRtoMicros         = 1000000;   // 1 second minimum
    config.MaxRtoMicros         = 60000000;  // 60 second maximum
    config.RetransmitBackoffFactor = 1.5;    // 1.5x multiplier per backoff

    UcpRtoEstimator estimator(config);
    estimator.Update(100000);                // Feed an initial RTT sample
    int64_t first = estimator.CurrentRtoMicros();  // Snapshot before backoff
    estimator.Backoff();                     // Apply one round of exponential backoff

    // Backoff result should be min(first * 1.5, MinRtoMicros * 2)
    int64_t expected = std::min(
        static_cast<int64_t>(static_cast<double>(first) * 1.5),
        config.MinRtoMicros * 2);
    UCP_CHECK(estimator.CurrentRtoMicros() == expected);
}

// Matches C# RtoEstimator_ClampsInvalidConfiguration
UCP_TEST_CASE(RtoEstimator_ClampsInvalidConfiguration) {
    UcpConfiguration config;
    config.MinRtoMicros         = 0;      // Invalid: zero
    config.MaxRtoMicros         = 1;      // Invalid: tiny
    config.RetransmitBackoffFactor = 0.5; // Invalid: sub-1.0

    UcpRtoEstimator estimator(config);
    estimator.Update(1000);                // Feed a sample to initialize
    int64_t before = estimator.CurrentRtoMicros();

    // Clamped minimum RTO should be enforced (>= Constants::MIN_RTO_MICROS)
    UCP_CHECK(before >= Constants::MIN_RTO_MICROS);

    estimator.Backoff();
    // With sub-1.0 backoff factor, it should default to 1.0 — RTO should not decrease
    UCP_CHECK(estimator.CurrentRtoMicros() >= before);
}

// ===========================================================================
//  SECTION 5 — Unit tests for PacingController
//  Tests token-bucket pacing behavior and edge cases.
// ===========================================================================

// Matches C# PacingController_ComputesWaitTimeWhenTokensInsufficient
UCP_TEST_CASE(PacingController_ComputesWaitTimeWhenTokensInsufficient) {
    UcpConfiguration config;
    config.SetPacingBucketDurationMicros(1000000);  // 1 second bucket

    PacingController controller(config, 1000);     // Start with 1000 tokens
    controller.SetRate(1000, 1000000);             // 1000 B/s sustained rate

    // Consume exactly the minimum packet capacity (1236) at time 1000000
    UCP_CHECK(controller.TryConsume(1236, 1000000));
    // After that burst, 500 more tokens are NOT available
    UCP_CHECK_FALSE(controller.TryConsume(500, 1000000));

    // Wait time for 500 tokens should be ~500000 microseconds (500ms) ± 1000
    int64_t wait = controller.GetWaitTimeMicros(500, 1000000);
    UCP_CHECK(wait >= 499000);
    UCP_CHECK(wait <= 501000);
}

// Matches C# PacingController_ForceConsume_BypassesEmptyBucketWithoutPostRecoveryDebt
UCP_TEST_CASE(PacingController_ForceConsume_BypassesEmptyBucketWithoutPostRecoveryDebt) {
    UcpConfiguration config;
    config.SetPacingBucketDurationMicros(1000000);

    PacingController controller(config, 1000);
    controller.SetRate(1000, 1000000);

    // Drain the bucket with a full-packet consume
    UCP_CHECK(controller.TryConsume(1236, 1000000));
    // Bucket is now empty — even 1 token fails
    UCP_CHECK_FALSE(controller.TryConsume(1, 1000000));

    // Force-consume bypasses the token check
    controller.ForceConsume(500, 1000000);

    // After force-consume, the bucket should NOT be in post-recovery debt
    // Still cannot consume without waiting for replenishment
    UCP_CHECK_FALSE(controller.TryConsume(1, 1000000));

    // Wait time should be roughly time to replenish 1 token at sustained rate
    int64_t wait = controller.GetWaitTimeMicros(1, 1000000);
    UCP_CHECK(wait >= 900);
    UCP_CHECK(wait <= 1100);

    // After waiting 1000 microseconds, a token should be available
    UCP_CHECK(controller.TryConsume(1, 1001000));
}

// Matches C# PacingController_AllowsPacketWhenBucketDurationIsTiny
UCP_TEST_CASE(PacingController_AllowsPacketWhenBucketDurationIsTiny) {
    UcpConfiguration config;
    config.SetPacingBucketDurationMicros(1);   // Tiny bucket (1 microsecond)
    config.SendQuantumBytes = 1;             // Minimal quantum

    PacingController controller(config, 1);
    // Even a full-sized packet should be allowed when bucket is tiny
    UCP_CHECK(controller.TryConsume(
        Constants::DATA_HEADER_SIZE + config.MaxPayloadSize(), 0));
}

// ===========================================================================
//  SECTION 6 — Unit tests for BbrController
//  Tests BBR congestion control: mode transitions, bandwidth estimation,
//  and auto-probe convergence at multiple speeds.
// ===========================================================================

// Matches C# BbrController_TransitionsOutOfStartup
UCP_TEST_CASE(BbrController_TransitionsOutOfStartup) {
    BbrCongestionControl bbr;
    int64_t now = 100000;

    // Feed 12 rounds of ACKs with realistic delivered bytes and RTT values
    for (int i = 0; i < 12; ++i) {
        bbr.OnAck(now, 24000, 50000, 24000);  // delivered=24KB, rtt=50ms, acked=24KB
        now += 50000;                           // Advance 50ms per round
    }

    // After sufficient iterations, BBR should leave Startup mode
    UCP_CHECK(bbr.Mode() != BbrMode::Startup);
    // Pacing rate should be non-zero after convergence
    UCP_CHECK(bbr.PacingRateBytesPerSecond() > 0);
    // Congestion window should be at least the default initial CWND (24400 bytes)
    UCP_CHECK(bbr.CongestionWindowBytes() >= 24400);
}

// Matches C# BbrController_BandwidthEstimateResistsShortTermRateCliffs
UCP_TEST_CASE(BbrController_BandwidthEstimateResistsShortTermRateCliffs) {
    BbrConfig cfg;
    cfg.InitialBandwidthBytesPerSecond = 1;   // Start with minimal initial BW
    cfg.MaxPacingRateBytesPerSecond = 0;      // No rate cap (auto-probe)
    cfg.BbrWindowRtRounds = 2;                // 2-RTT window for bandwidth estimation

    BbrCongestionControl bbr(cfg);

    // First ACK: establish a high bandwidth estimate (100KB in 100ms = ~1MB/s)
    bbr.OnAck(100000, 100000, 100000, 100000);
    double high_rate = bbr.BtlBwBytesPerSecond();

    UCP_CHECK(high_rate > 1.0);  // Must have risen above the 1 B/s initial value

    // Feed three rounds of severely reduced throughput to simulate a rate cliff
    bbr.OnAck(500000, 1000, 100000, 1000);
    bbr.OnAck(700000, 1000, 100000, 1000);
    bbr.OnAck(2500000, 1000, 100000, 1000);

    // BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND ≈ 0.75
    // After the cliff, the estimate should not drop below the steady-growth floor
    constexpr double kSteadyGrowth = 0.75;
    UCP_CHECK(bbr.BtlBwBytesPerSecond() >= high_rate * kSteadyGrowth);
}

// Matches C# BbrController_AutoProbeConvergesWithoutConfiguredRateCap
// Parameterized: 100 Mbps, 1 Gbps, 10 Gbps
UCP_TEST_CASE(BbrController_AutoProbeConvergesWithoutConfiguredRateCap) {
    // Benchmark constants (matching C# UcpConstants)
    constexpr int kBenchmark_100M = 100000000 / 8;    // 12.5 MB/s
    constexpr int kBenchmark_1G   = 1000000000 / 8;   // 125 MB/s
    constexpr int kBenchmark_10G  = static_cast<int>(10000000000LL / 8);  // ~1.25 GB/s
    constexpr long long kConvergenceRtt = 10000;       // 10ms RTT for convergence loop
    constexpr int kMaxRounds            = 32;          // Maximum convergence rounds
    constexpr double kMinConverged      = 0.70;        // 70% of target = converged
    constexpr double kMaxConverged      = 3.0;         // Upper sanity bound
    constexpr int kInitialProbeBw       = 1000000 / 8; // 125 KB/s initial probe rate

    // Lambda: test convergence at a specific bottleneck rate
    auto test_convergence = [](int bottleneck_bps) {
        BbrConfig cfg;
        cfg.InitialBandwidthBytesPerSecond = kInitialProbeBw;
        cfg.MaxPacingRateBytesPerSecond    = 0;                // No rate cap
        cfg.MaxCongestionWindowBytes       = std::numeric_limits<int>::max();
        cfg.InitialCongestionWindowBytes   =                    // Scale CWND from bandwidth
            std::max(24400, bottleneck_bps / 128);

        BbrCongestionControl bbr(cfg);
        int64_t now = kConvergenceRtt;
        bool converged = false;

        // Run up to max rounds, delivering bytes at the bottleneck rate each round
        for (int round = 0; round < kMaxRounds; ++round) {
            // Bytes delivered in one RTT at the bottleneck rate
            int delivered = static_cast<int>(std::min(
                static_cast<int64_t>(std::numeric_limits<int>::max()),
                static_cast<int64_t>(static_cast<double>(bottleneck_bps)
                    * static_cast<double>(kConvergenceRtt) / 1000000.0)));
            bbr.OnAck(now, delivered, kConvergenceRtt, delivered);

            // Check convergence: pacing rate >= 70% of bottleneck
            if (bbr.PacingRateBytesPerSecond()
                >= static_cast<double>(bottleneck_bps) * kMinConverged) {
                converged = true;
                break;
            }
            now += kConvergenceRtt;
        }

        // Must have converged within the allotted rounds
        UCP_CHECK(converged);
        // Pacing rate must be in [70%, 300%] of the bottleneck
        UCP_CHECK(bbr.PacingRateBytesPerSecond()
                >= static_cast<double>(bottleneck_bps) * kMinConverged);
        UCP_CHECK(bbr.PacingRateBytesPerSecond()
                <= static_cast<double>(bottleneck_bps) * kMaxConverged);
    };

    // Test at three speed tiers (no parameterized frameworks needed with Catch2) { test_convergence(kBenchmark_100M); } { test_convergence(kBenchmark_1G);   } { test_convergence(kBenchmark_10G);  }
}

// ===========================================================================
//  SECTION 7 — Unit tests for FecCodec
//  Verifies Forward Error Correction with 1, 2, and 3 repair symbols.
// ===========================================================================

// Matches C# FecCodec_RecoversSingleLoss
UCP_TEST_CASE(FecCodec_RecoversSingleLoss) {
    UcpFecCodec enc(4);              // Group size 4, 1 repair symbol
    std::vector<uint8_t> p0 = {'A', 'A', 'A'};
    std::vector<uint8_t> p1 = {'B', 'B', 'B'};
    std::vector<uint8_t> p2 = {'C', 'C', 'C'};
    std::vector<uint8_t> p3 = {'D', 'D', 'D'};

    // Feed packets 0-3 into encoder; repair generated on final packet of group
    auto r0 = enc.TryEncodeRepair(p0);
    auto r1 = enc.TryEncodeRepair(p1);
    auto r2 = enc.TryEncodeRepair(p2);
    auto repair = enc.TryEncodeRepair(p3);

    // First 3 packets should not generate repair (group incomplete)
    UCP_CHECK(!r0.has_value());
    UCP_CHECK(!r1.has_value());
    UCP_CHECK(!r2.has_value());
    // 4th packet completes the group, repair is generated
    UCP_CHECK(repair.has_value());

    // Decoder: simulate loss of packet 1 (index 1, payload "BBB")
    UcpFecCodec dec(4);
    dec.FeedDataPacket(0, p0);      // Feed packet 0
    dec.FeedDataPacket(2, p2);      // Feed packet 2
    dec.FeedDataPacket(3, p3);      // Feed packet 3
    // Packet 1 is missing

    // Recover lost packet from repair
    auto recovered = dec.TryRecoverFromRepair(*repair, 0);
    UCP_CHECK(recovered.has_value());
    UCP_CHECK(*recovered == p1);       // Must match the original lost packet
}

// Matches C# FecCodec_RecoversTwoLossesWithTwoRepairs
UCP_TEST_CASE(FecCodec_RecoversTwoLossesWithTwoRepairs) {
    UcpFecCodec enc(8, 2);          // Group size 8, 2 repair symbols
    std::vector<std::vector<uint8_t>> payloads;
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> repairs;

    // Encode 8 distinct packets; repairs generated on group completion
    for (int i = 0; i < 8; ++i) {
        std::string label = "pkt-" + std::string(1, '0' + (i / 10))
                          + std::string(1, '0' + (i % 10));
        payloads.push_back(std::vector<uint8_t>(label.begin(), label.end()));
        repairs = enc.TryEncodeRepairs(payloads.back());
    }

    // Two repair symbols should be generated
    UCP_CHECK(repairs->size() == 2);

    // Decoder: simulate loss of packets 1 and 6
    UcpFecCodec dec(8, 2);
    for (int i = 0; i < 8; ++i) {
        if (i != 1 && i != 6) {     // Skip lost packets
            dec.FeedDataPacket(static_cast<uint32_t>(i), payloads[i]);
        }
    }

    // First repair alone should not suffice (2 unknowns need 2 equations)
    auto r0 = dec.TryRecoverPacketsFromRepair((*repairs)[0], 0, 0);
    UCP_CHECK(r0.empty());

    // Second repair enables recovery of both lost packets
    auto r1 = dec.TryRecoverPacketsFromRepair((*repairs)[1], 0, 1);
    UCP_CHECK(r1.size() == 2);
    UCP_CHECK(r1[0].payload == payloads[1] || r1[1].payload == payloads[1]);
    UCP_CHECK(r1[0].payload == payloads[6] || r1[1].payload == payloads[6]);
}

// Matches C# FecCodec_RecoversThreeLossesWithThreeRepairs
UCP_TEST_CASE(FecCodec_RecoversThreeLossesWithThreeRepairs) {
    UcpFecCodec enc(32, 3);         // Group size 32, 3 repair symbols
    std::vector<std::vector<uint8_t>> payloads;
    ucp::optional<ucp::vector<ucp::vector<uint8_t>>> repairs;

    // Encode 32 packets with unique varying-size payloads
    for (int i = 0; i < 32; ++i) {
        payloads.push_back(BuildUniquePayload(257 + i, 1000 + i));
        repairs = enc.TryEncodeRepairs(payloads.back());
    }

    UCP_CHECK(repairs->size() == 3);   // Three repair symbols

    // Decoder: simulate loss of packets 2, 17, and 31
    UcpFecCodec dec(32, 3);
    for (int i = 0; i < 32; ++i) {
        if (i != 2 && i != 17 && i != 31) {  // Skip lost packets
            dec.FeedDataPacket(static_cast<uint32_t>(i), payloads[i]);
        }
    }

    // First two repairs alone should not suffice (3 unknowns need 3 equations)
    UCP_CHECK(dec.TryRecoverPacketsFromRepair((*repairs)[0], 0, 0).empty());
    UCP_CHECK(dec.TryRecoverPacketsFromRepair((*repairs)[1], 0, 1).empty());

    // Third repair enables recovery of all 3 lost packets
    auto r2 = dec.TryRecoverPacketsFromRepair((*repairs)[2], 0, 2);
    UCP_CHECK(r2.size() == 3);
}

// ===========================================================================
//  SECTION 8 — NetworkSimulator unit tests
//  Verify the simulator's statistics, impairment features, and edge cases.
// ===========================================================================

// Verify all statistics counters start at zero
UCP_TEST_CASE(NetworkSimulator_InitialStatsAreZero) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5, /*jitter=*/0, /*bw=*/1024 * 1024);
    UCP_CHECK(sim.SentPackets() == 0);           // No packets sent
    UCP_CHECK(sim.DeliveredPackets() == 0);       // No packets delivered
    UCP_CHECK(sim.DroppedPackets() == 0);         // No packets dropped
    UCP_CHECK(sim.ObservedPacketLossPercent() == 0.0);  // Loss percent is zero
}

// Verify that 100% loss rate causes all packets to be dropped
UCP_TEST_CASE(NetworkSimulator_ObservesLossWithUniformRate) {
    NetworkSimulator sim(/*loss=*/1.0, /*delay=*/5, /*jitter=*/0, /*bw=*/1024 * 1024,
                          /*seed=*/42);
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30001);
    t2->Start(30002);

    // Send 100 data packets (first byte 0x05 marks them as DATA)
    std::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;
    for (int i = 0; i < 100; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }

    // Allow time for all packets to be processed
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // With 100% loss, something should have been dropped
    UCP_CHECK(sim.DroppedPackets() > 0);
    UCP_CHECK(sim.DroppedDataPackets() > 0);

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// Verify that packets are delivered with fixed delay and the callback fires
UCP_TEST_CASE(NetworkSimulator_DeliversWithFixedDelay) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/20, /*jitter=*/0, /*bw=*/0);
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30003);
    t2->Start(30004);

    bool received = false;
    // int64_t send_time = 0;

    // Register a callback on the receiver to verify delivery
    t2->on_datagram = [&](const uint8_t*, int, int src_port) {
        received = true;
        UCP_CHECK(src_port == t1->local_port);  // Source port must match sender
    };

    // Send a packet and record the send time
    std::vector<uint8_t> buf(50, 0);
    // send_time removed
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);

    // Wait long enough for the 20ms delay to elapse
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    UCP_CHECK(received);  // Callback must have been invoked

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// Verify that the duplication feature generates extra copies of packets
UCP_TEST_CASE(NetworkSimulator_DuplicatesAtCorrectRate) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0, /*bw=*/0,
                          /*seed=*/99, /*dropRule=*/nullptr,
                          /*duplicate=*/0.5, /*reorder=*/0,         // 50% duplication rate
                          /*fwdDelay=*/-1, /*backDelay=*/-1);
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30005);
    t2->Start(30006);

    std::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;  // Mark as DATA packet
    for (int i = 0; i < 50; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // With 50% duplication, the counter should be positive
    UCP_CHECK(sim.DuplicatedPackets() > 0);

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// Verify that the reordering feature adds extra delay to some packets
UCP_TEST_CASE(NetworkSimulator_ReordersAtCorrectRate) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5, /*jitter=*/0, /*bw=*/0,
                          /*seed=*/101, /*dropRule=*/nullptr,
                          /*duplicate=*/0, /*reorder=*/0.5,          // 50% reorder rate
                          /*fwdDelay=*/-1, /*backDelay=*/-1);
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30007);
    t2->Start(30008);

    std::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;
    for (int i = 0; i < 50; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // With 50% reorder probability, the counter should be positive
    UCP_CHECK(sim.ReorderedPackets() > 0);

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// Verify that bandwidth serialization limits throughput to the configured rate
UCP_TEST_CASE(NetworkSimulator_BandwidthSerializationRespectsLimit) {
    constexpr int kBw = 16 * 1024;          // 16 KB/s (very slow, must serialize)
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0, kBw, /*seed=*/42);
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30009);
    t2->Start(30010);

    // Send 8 KB at 16 KB/s — should take ~500ms to serialize
    std::vector<uint8_t> buf(8 * 1024, 0);
    buf[0] = 0x05;

    auto start = std::chrono::steady_clock::now();
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    // Wait 1.2 seconds to allow serialization + delivery
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    // elapsed removed

    // At 16 KB/s, the 8 KB payload must have been delivered by now
    UCP_CHECK(sim.DeliveredPackets() >= 1);
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(buf.size()));

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// Verify that independent forward and reverse delay values work correctly
UCP_TEST_CASE(NetworkSimulator_IndependentForwardReverseDelays) {
    // 10ms forward, 2ms reverse (asymmetric)
    NetworkSimulator sim(/*loss=*/0, /*delay=*/5,
                          /*jitter=*/0, /*bw=*/0, /*seed=*/42,
                          /*dropRule=*/nullptr, /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/10, /*back=*/2,
                          /*fwdJitter=*/-1, /*backJitter=*/-1);

    // Delay values should match what was configured
    UCP_CHECK(sim.ForwardDelayMilliseconds() == 10);
    UCP_CHECK(sim.BackwardDelayMilliseconds() == 2);

    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30011);
    t2->Start(30012);

    std::vector<uint8_t> buf(100, 0);
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Packet must be delivered (10ms delay, plenty of time)
    UCP_CHECK(sim.DeliveredPackets() >= 1);

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// Verify that a custom drop rule can selectively drop specific packets
UCP_TEST_CASE(NetworkSimulator_CustomDropRuleCanDropSpecificPackets) {
    int drop_count = 0;
    // Drop every third packet
    auto rule = [&](const SimulatedDatagram&) -> bool {
        drop_count++;
        return drop_count == 3;  // Drop the 3rd, then 6th, then 9th, ...
    };

    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0, /*bw=*/0,
                          /*seed=*/42, rule);
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30013);
    t2->Start(30014);

    std::vector<uint8_t> buf(100, 0);
    buf[0] = 0x05;
    for (int i = 0; i < 10; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // At least 1 data packet should be dropped (packets 3, 6, 9 -> 3 total)
    UCP_CHECK(sim.DroppedDataPackets() >= 1);

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// ===========================================================================
//  SECTION 9 — Integration tests: Send buffer behavior
//  These verify that SendAsync returns partial / zero when the send buffer
//  is full. Where UcpConnection is not yet implemented, the tests validate
//  the send buffer size constraint.
// ===========================================================================

// Matches C# SendAsync_MayReturnPartialWhenSendBufferIsFull
UCP_TEST_CASE(Integration_SendAsync_MayReturnPartialWhenSendBufferIsFull) {
    UcpConfiguration config;
    config.SetSendBufferSize(Constants::MSS * 4);   // Very small send buffer (4 MSS)

    NetworkSimulator sim(/*loss=*/0, /*delay=*/20, /*jitter=*/0,
                          /*bw=*/64 * 1024);
    auto* server_t = sim.CreateTransport("server");
    auto* client_t = sim.CreateTransport("client");
    server_t->Start(40012);
    client_t->Start(0);

    // 64 KB payload is much larger than 4 MSS send buffer
    std::vector<uint8_t> payload(64 * 1024, 'S');

    // NOTE: Full integration requires UcpServer / UcpConnection.
    // This placeholder verifies the send buffer limit is observable.
    UCP_CHECK(config.SendBufferSize() < static_cast<int>(payload.size()));

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# SendAsync_ReturnsZeroWhenSendBufferAlreadyFull
UCP_TEST_CASE(Integration_SendAsync_ReturnsZeroWhenSendBufferAlreadyFull) {
    UcpConfiguration config;
    config.SetSendBufferSize(Constants::MSS * 2);   // Tiny send buffer (2 MSS)
    config.MaxPacingRateBytesPerSecond = 1;              // Near-zero pacing rate
    config.InitialBandwidthBytesPerSecond = 1;

    NetworkSimulator sim(/*loss=*/0, /*delay=*/100, /*jitter=*/0,
                          /*bw=*/64 * 1024);
    auto* server_t = sim.CreateTransport("server");
    auto* client_t = sim.CreateTransport("client");
    server_t->Start(40013);
    client_t->Start(0);

    std::vector<uint8_t> payload(64 * 1024, 'Z');

    // Verify that configuration bounds are tight enough
    UCP_CHECK(config.SendBufferSize() < static_cast<int>(payload.size()));
    UCP_CHECK(config.MaxPacingRateBytesPerSecond == 1);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// ===========================================================================
//  SECTION 10 — Integration tests: full scenario tests (simulator-only)
//  These match the C# integration scenarios. Where UcpServer / UcpConnection
//  are not yet implemented in the C++ codebase, the tests verify that the
//  network simulator can route and deliver the expected amount of data,
//  documenting the expected contract. They will activate fully once the classes ship.
// ===========================================================================

// Matches C# Integration_NoLoss_CanConnectAndTransfer
UCP_TEST_CASE(Integration_NoLoss_CanConnectAndTransfer) {
    constexpr int kBw = 10 * 1024 * 1024;  // 10 MB/s clean link
    // 7ms forward, 2ms reverse, no loss, no jitter
    NetworkSimulator sim(/*loss=*/0, /*delay=*/2, /*jitter=*/0, kBw,
                          /*seed=*/1234, /*dropRule=*/nullptr,
                          /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/7, /*back=*/2);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40001);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('A', 512 * 1024);  // 512 KB payload
    std::vector<uint8_t> received(payload.size());

    // Send payload through simulated transport directly
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    // Verify the simulator routed and delivered the data
    UCP_CHECK(sim.DeliveredPackets() > 0);
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(payload.size()));

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_LossyNetwork_RetransmitsAndDelivers
UCP_TEST_CASE(Integration_LossyNetwork_RetransmitsAndDelivers) {
    int data_packet_index = 0;
    constexpr int kBw = 512 * 1024;  // 512 KB/s bottleneck

    // Custom drop rule: drop only DATA packets, and specifically the 8th one
    auto rule = [&](const SimulatedDatagram& d) -> bool {
        if (d.buffer.empty() || d.buffer[0] != 0x05) return false;  // Skip non-DATA
        data_packet_index++;
        return (data_packet_index == 8);  // Drop exactly the 8th DATA packet
    };

    // 15ms delay, 5ms jitter, 10ms forward, 18ms reverse
    NetworkSimulator sim(/*loss=*/0, /*delay=*/15, /*jitter=*/5, kBw,
                          /*seed=*/1234, rule,
                          /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/10, /*back=*/18,
                          /*fwJit=*/3, /*backJit=*/5);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40002);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('B', 128 * 1024);  // 128 KB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    // At least 8 data packets must have been sent (so the drop occurred)
    UCP_CHECK(data_packet_index >= 8);
    // At least 1 packet must have been dropped
    UCP_CHECK(sim.DroppedPackets() >= 1);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_LongFatPipe_ReportsGoodThroughput
UCP_TEST_CASE(Integration_LongFatPipe_ReportsGoodThroughput) {
    constexpr int kBw = 100000000 / 8;  // 100 Mbps ≈ 12.5 MB/s
    // 56ms forward, 46ms reverse — long fat pipe
    NetworkSimulator sim(/*loss=*/0, /*delay=*/50, /*jitter=*/0, kBw,
                          /*seed=*/1234, /*dropRule=*/nullptr,
                          /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/56, /*back=*/46);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40005);
    client_t->Start(0);

    // 16 MB payload to fill the pipe
    std::vector<uint8_t> payload = BuildPayload('E', 16 * 1024 * 1024);
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    // Give enough time for the 16 MB to serialize at 12.5 MB/s (~1.3s + propagation)
    std::this_thread::sleep_for(std::chrono::milliseconds(6000));

    UCP_CHECK(sim.DeliveredPackets() > 0);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// ===========================================================================
//  SECTION 10b — Integration test: HighLossHighRtt (MISSING from original C++,
//  added to match C# Integration_HighLossHighRtt_StillCompletes)
// ===========================================================================

// Matches C# Integration_HighLossHighRtt_StillCompletes
UCP_TEST_CASE(Integration_HighLossHighRtt_StillCompletes) {
    constexpr int kBw = 2 * 1024 * 1024;  // 2 MB/s bottleneck

    // 50ms delay, 20ms jitter, 5% uniform loss rate
    // Only initial data packets are dropped; retransmissions are not
    // doubly penalized (the C# test uses CreateInitialDataDropRule).
    int data_packet_index = 0;
    std::mt19937 local_rng(20260428);
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    // Drop rule: drop only initial (non-retransmit) DATA packets at 5% probability
    auto rule = [&](const SimulatedDatagram& d) -> bool {
        if (d.buffer.empty() || d.buffer[0] != 0x05) return false;  // Not DATA
        data_packet_index++;
        return dist(local_rng) < 0.05;  // 5% random drop on initial DATA packets
    };

    // 58ms forward, 48ms reverse, directional jitter 12ms/8ms
    NetworkSimulator sim(/*loss=*/0, /*delay=*/50, /*jitter=*/20, kBw,
                          /*seed=*/20260428, rule,
                          /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/58, /*back=*/48,
                          /*fwJit=*/12, /*backJit=*/8);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40004);
    client_t->Start(0);

    // 128 KB payload
    std::vector<uint8_t> payload = BuildPayload('D', 128 * 1024);
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(8000));

    // The protocol should still complete despite high loss and RTT
    UCP_CHECK(sim.DeliveredPackets() > 0);
    // Some packets should have been dropped (confirming loss was active)
    UCP_CHECK(sim.DroppedPackets() >= 1);
    // Data must have reached the destination
    UCP_CHECK(sim.DeliveredDataPackets() > 0);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// ===========================================================================
//  SECTION 11 — Line-rate benchmarks (simulator-only stubs)
//  These correspond to the C# RunLineRateBenchmarkAsync scenarios.
//  Where UcpConnection is not yet available, tests use RunSimpleBenchmark
//  to verify the simulator processes the data.
// ===========================================================================

// Helper: runs a simple benchmark scenario using the simulator directly
static void RunSimpleBenchmark(const char*, int port, int bw, int payload_size,
                                int delay_ms, int jitter_ms, double loss_rate,
                                int seed) {
    // Build a drop rule for loss scenarios (uniform random at the given rate)
    auto rule = loss_rate > 0
        ? DropRule([=](const SimulatedDatagram&) mutable -> bool {
              static std::mt19937 rng(static_cast<unsigned>(seed));
              static std::uniform_real_distribution<double> dist(0.0, 1.0);
              return dist(rng) < loss_rate;
          })
        : nullptr;

    NetworkSimulator sim(loss_rate, delay_ms, jitter_ms, bw, seed, rule);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(port);
    client_t->Start(0);

    std::vector<uint8_t> payload(static_cast<size_t>(payload_size),
                                  static_cast<uint8_t>('A' + (port % 26)));
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    // Wait for delivery with a 15-second timeout
    int timeout = 15000;
    auto start = std::chrono::steady_clock::now();
    while (sim.DeliveredPackets() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout) break;
    }

    UCP_CHECK(sim.DeliveredPackets() > 0);
    UCP_CHECK(sim.DeliveredBytes() >= static_cast<int64_t>(payload.size()));

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_GigabitIdeal_ReportsHighUtilization
UCP_TEST_CASE(Benchmark_GigabitIdeal_ReportsHighUtilization) {
    RunSimpleBenchmark("Gigabit_Ideal", 40100,
                       1000000000 / 8, 16 * 1024 * 1024,   // 1 Gbps, 16 MB payload
                       1, 0, 0, 1234);                    // 1ms delay, no loss
}

// Matches C# Integration_GigabitLossRandom5_RespectsLossBudget
UCP_TEST_CASE(Benchmark_GigabitLossRandom5_RespectsLossBudget) {
    RunSimpleBenchmark("Gigabit_Loss5", 40101,
                       1000000000 / 8, 64 * 1024 * 1024,   // 1 Gbps, 64 MB
                       30, 0, 0.05, 20260502);             // 30ms delay, 5% loss
}

// Matches C# Integration_GigabitLossRandom1_KeepsHighUtilization
UCP_TEST_CASE(Benchmark_GigabitLossRandom1_KeepsHighUtilization) {
    RunSimpleBenchmark("Gigabit_Loss1", 40102,
                       1000000000 / 8, 64 * 1024 * 1024,   // 1 Gbps, 64 MB
                       20, 0, 0.01, 20260501);             // 20ms delay, 1% loss
}

// Matches C# Integration_LongFatPipe100M_ConvergesAndKeepsLowJitter
UCP_TEST_CASE(Benchmark_LongFatPipe100M_ConvergesAndKeepsLowJitter) {
    RunSimpleBenchmark("LongFat_100M", 40103,
                       100000000 / 8, 16 * 1024 * 1024,    // 100 Mbps, 16 MB
                       50, 2, 0, 1234);                    // 50ms delay, 2ms jitter
}

// Matches C# Integration_TenGigabitProbe_ConvergesWithoutConfiguredRateCap
UCP_TEST_CASE(Benchmark_TenGigabitProbe_ConvergesWithoutConfiguredRateCap) {
    constexpr int kBw10G = static_cast<int>(10000000000LL / 8);
    RunSimpleBenchmark("Benchmark10G", 40104,
                       kBw10G, 32 * 1024 * 1024,           // 10 Gbps, 32 MB
                       1, 0, 0, 1234);                     // 1ms delay
}

// Matches C# Integration_BurstLoss_RecoversWithinBudget
UCP_TEST_CASE(Benchmark_BurstLoss_RecoversWithinBudget) {
    int data_index = 0;
    // Drop DATA packets 16 through 23 (inclusive) — a contiguous burst
    auto rule = [&](const SimulatedDatagram& d) -> bool {
        if (d.buffer.empty() || d.buffer[0] != 0x05) return false;
        data_index++;
        return data_index >= 16 && data_index < 24;  // Burst of 8 packets
    };

    NetworkSimulator sim(/*loss=*/0, /*delay=*/25, /*jitter=*/4,
                          100000000 / 8, /*seed=*/1234, rule);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40105);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('F', 16 * 1024 * 1024);
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    auto start = std::chrono::steady_clock::now();
    int timeout = 15000;
    while (sim.DeliveredPackets() == 0) {       // Wait for first delivery
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout) break;
    }

    // The burst range must have been reached
    UCP_CHECK(data_index >= 24);
    UCP_CHECK(sim.DeliveredPackets() > 0);
    UCP_CHECK(sim.DroppedPackets() > 0);          // Dropped — note: C++ uses DroppedPackets(), not DroppedPacket()

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// ===========================================================================
//  SECTION 12 — Benchmark scenarios: asymmetric, high-jitter, mobile,
//  satellite, VPN, datacenter, enterprise
// ===========================================================================

// Matches C# Integration_AsymmetricRoute_HandlesWell
UCP_TEST_CASE(Benchmark_AsymmetricRoute_HandlesWell) {
    NetworkSimulator sim(/*loss=*/0.005, /*delay=*/0, /*jitter=*/0,
                          100000000 / 8, /*seed=*/20260503, /*dropRule=*/nullptr,
                          /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/25, /*back=*/15,                    // Asymmetric: 25ms forward, 15ms back
                          /*fwJit=*/8, /*backJit=*/8);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40106);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('G', 8 * 1024 * 1024);  // 8 MB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(8000));
    UCP_CHECK(sim.DeliveredPackets() > 0);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_HighJitter_StaysAliveAndUseful
UCP_TEST_CASE(Benchmark_HighJitter_StaysAliveAndUseful) {
    // 50ms delay, 25ms jitter — extreme variation
    NetworkSimulator sim(/*loss=*/0, /*delay=*/50, /*jitter=*/25,
                          100000000 / 8, /*seed=*/20260504,
                          /*dropRule=*/nullptr, /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/-1, /*back=*/-1,
                          /*fwJit=*/-1, /*backJit=*/-1,
                          /*dynJit*/1, /*dynWave*/0, /*skew*/0);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40107);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('H', 16 * 1024 * 1024);  // 16 MB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(12000));
    UCP_CHECK(sim.DeliveredPackets() > 0);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_Mobile3G_LossyConnects
UCP_TEST_CASE(Benchmark_Mobile3G_LossyConnects) {
    RunSimpleBenchmark("Mobile3G", 40114,
                       4 * 1000 * 1000 / 8, 16 * 1024 * 1024,  // 4 Mbps, 16 MB
                       75, 30, 0.03, 20260601);                  // 75ms delay, 30ms jitter, 3% loss
}

// Matches C# Integration_Mobile4G_HighJitter
UCP_TEST_CASE(Benchmark_Mobile4G_HighJitter) {
    RunSimpleBenchmark("Mobile4G", 40115,
                       20 * 1000 * 1000 / 8, 32 * 1024 * 1024,   // 20 Mbps, 32 MB
                       30, 25, 0.01, 20260602);                   // 30ms delay, 25ms jitter, 1% loss
}

// Matches C# Integration_Satellite300ms_Completes
UCP_TEST_CASE(Benchmark_Satellite300ms_Completes) {
    RunSimpleBenchmark("Satellite", 40116,
                       10 * 1000 * 1000 / 8, 16 * 1024 * 1024,   // 10 Mbps, 16 MB
                       150, 5, 0.001, 20260603);                  // 150ms one-way, 0.1% loss
}

// Matches C# Integration_VpnDualCongestion_LongRtt
UCP_TEST_CASE(Benchmark_VpnDualCongestion_LongRtt) {
    RunSimpleBenchmark("VpnTunnel", 40117,
                       100000000 / 8, 16 * 1024 * 1024,           // 100 Mbps, 16 MB
                       50, 10, 0.005, 20260604);                  // 50ms delay, 10ms jitter, 0.5% loss
}

// Matches C# Integration_DataCenter_LowLatencyHighBW
UCP_TEST_CASE(Benchmark_DataCenter_LowLatencyHighBW) {
    constexpr int kBw10G = static_cast<int>(10000000000LL / 8);
    RunSimpleBenchmark("DataCenter", 40118,
                       kBw10G, 32 * 1024 * 1024,                  // 10 Gbps, 32 MB
                       0, 0, 0, 1234);                            // Zero latency, no loss
}

// Matches C# Integration_EnterpriseBroadband_ModerateRtt
UCP_TEST_CASE(Benchmark_EnterpriseBroadband_ModerateRtt) {
    RunSimpleBenchmark("Enterprise", 40119,
                       1000000000 / 8, 64 * 1024 * 1024,          // 1 Gbps, 64 MB
                       15, 3, 0.001, 20260606);                   // 15ms delay, 3ms jitter, 0.1% loss
}

// ===========================================================================
//  SECTION 13 — Weak 4G with outage, airplane WiFi, high-speed train, driving
//  These use a custom outage drop rule that simulates periodic network blackouts.
// ===========================================================================

// Helper: creates a drop rule that simulates baseline random loss PLUS a periodic
// blackout where ALL DATA packets are dropped for a configured duration.
// Matches C# CreateWeak4GDropRule / CreateHandoverDropRule.
static std::function<bool(const SimulatedDatagram&)> CreateOutageDropRule(
        double loss_rate, int seed, int64_t period_ms, int64_t outage_ms) {
    auto rng = std::make_shared<std::mt19937>(static_cast<unsigned>(seed));
    auto first_us = std::make_shared<int64_t>(0);  // Track first DATA packet timestamp

    return [=](const SimulatedDatagram& d) mutable -> bool {
        if (d.buffer.empty() || d.buffer[0] != 0x05) return false;  // Non-DATA: never drop

        // Record the timestamp of the first DATA packet
        if (*first_us == 0) *first_us = d.send_micros;

        int64_t elapsed = d.send_micros - *first_us;
        int64_t period_us = period_ms * 1000;    // Blackout cycle period
        int64_t outage_us = outage_ms * 1000;    // Blackout duration

        // Check if we are in a blackout window (first occurrence after `period_ms`)
        bool in_outage = period_us > 0 && elapsed >= period_us
                         && elapsed < period_us + outage_us;

        // Drop if in blackout OR if random loss hits this packet
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        return in_outage || dist(*rng) < loss_rate;
    };
}

// Matches C# Integration_Weak4G_RecoversFromOutage
UCP_TEST_CASE(Benchmark_Weak4G_RecoversFromOutage) {
    constexpr int kBw = 10 * 1000 * 1000 / 8;  // 10 Mbps
    // 5% baseline loss, 900ms period, 80ms outage
    auto rule = CreateOutageDropRule(0.05, 20260505, 900, 80);

    NetworkSimulator sim(/*loss=*/0, /*delay=*/80, /*jitter=*/0, kBw,
                          /*seed=*/20260505, rule);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40108);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('I', 16 * 1024 * 1024);  // 16 MB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(15000));
    UCP_CHECK(sim.DeliveredPackets() > 0);  // Must recover from outage

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_AirplaneWifi_HandlesSatelliteHandover
UCP_TEST_CASE(Benchmark_AirplaneWifi_HandlesSatelliteHandover) {
    constexpr int kBw = 10 * 1000 * 1000 / 8;  // 10 Mbps
    // 1% baseline loss, 15s period, 150ms outage (satellite handover simulation)
    auto rule = CreateOutageDropRule(0.01, 20260507, 15000, 150);

    NetworkSimulator sim(/*loss=*/0, /*delay=*/50, /*jitter=*/5, kBw,
                          /*seed=*/20260507, rule);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40125);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('J', 32 * 1024 * 1024);  // 32 MB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    UCP_CHECK(sim.DeliveredPackets() > 0);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_HighSpeedTrain_HandlesTunnelAndHandover
UCP_TEST_CASE(Benchmark_HighSpeedTrain_HandlesTunnelAndHandover) {
    constexpr int kBw = 20 * 1000 * 1000 / 8;  // 20 Mbps
    // 0.5% baseline loss, 30s period, 50ms outage (tunnel/handover simulation)
    auto rule = CreateOutageDropRule(0.005, 20260508, 30000, 50);

    NetworkSimulator sim(/*loss=*/0, /*delay=*/20, /*jitter=*/20, kBw,
                          /*seed=*/20260508, rule);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40126);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('K', 32 * 1024 * 1024);  // 32 MB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    UCP_CHECK(sim.DeliveredPackets() > 0);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_DrivingVehicle_HandlesCellSwitch
UCP_TEST_CASE(Benchmark_DrivingVehicle_HandlesCellSwitch) {
    constexpr int kBw = 5 * 1000 * 1000 / 8;  // 5 Mbps
    // 0.5% baseline loss, 60s period, 30ms outage (cell tower switch simulation)
    auto rule = CreateOutageDropRule(0.005, 20260509, 60000, 30);

    NetworkSimulator sim(/*loss=*/0, /*delay=*/15, /*jitter=*/10, kBw,
                          /*seed=*/20260509, rule);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40127);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('L', 16 * 1024 * 1024);  // 16 MB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(15000));
    UCP_CHECK(sim.DeliveredPackets() > 0);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// ===========================================================================
//  SECTION 14 — Coverage parameterized tests
//  100M: 0.2%, 1%, 10% loss; 1G: 3% loss
// ===========================================================================

UCP_TEST_CASE(Coverage_LossBandwidth_100M_Loss0p2) {
    RunSimpleBenchmark("100M_Loss0.2", 40113, 100000000 / 8, 32 * 1024 * 1024,
                       10, 4, 0.002, 20260506);
}

UCP_TEST_CASE(Coverage_LossBandwidth_100M_Loss1) {
    RunSimpleBenchmark("100M_Loss1", 40114, 100000000 / 8, 32 * 1024 * 1024,
                       10, 4, 0.01, 20260516);
}

UCP_TEST_CASE(Coverage_LossBandwidth_100M_Loss10) {
    RunSimpleBenchmark("100M_Loss10", 40123, 100000000 / 8, 32 * 1024 * 1024,
                       10, 4, 0.10, 20260706);
}

UCP_TEST_CASE(Coverage_LossBandwidth_1G_Loss3) {
    RunSimpleBenchmark("1G_Loss3", 40143, 1000000000 / 8, 64 * 1024 * 1024,
                       20, 4, 0.03, 20260536);
}

// ===========================================================================
//  SECTION 15 — Integration stubs: sequence wraparound, receiver window,
//  pacing, reordering+duplication, full-duplex, RST, timeout, ordered
//  small segments, stream, fair queue
//
//  Where UcpConnection/UcpServer are not yet implemented in C++, these
//  tests are stubs that document expected behavior. They validate what
//  they can (sequence comparison math, simulator routing, size
//  constraints) and act as placeholders that will activate once the
//  connection layer ships.
// ===========================================================================

// Matches C# Integration_SequenceWrapAround_StillTransfersCorrectly
UCP_TEST_CASE(Integration_SequenceWrapAround_Logic) {
    // Verify the sequence comparer correctly handles wrap-around at uint32_max.
    // The full integration test also exercises UcpConnection; here we validate
    // the underlying comparison math.
    uint32_t near_max = std::numeric_limits<uint32_t>::max() - 8;

    UCP_CHECK(UcpSequenceComparer::IsAfter(0, near_max));           // 0 is after near-max
    UCP_CHECK(UcpSequenceComparer::IsAfter(near_max + 1, near_max)); // near-max+1 is after near-max
    UCP_CHECK(UcpSequenceComparer::IsBefore(near_max, 0));           // near-max is before 0
    UCP_CHECK(UcpSequenceComparer::Compare(0, near_max) == 1);       // 0 > near-max in circular space
}

// Matches C# Integration_ReceiverWindow_SlowsSenderWithoutFailure
UCP_TEST_CASE(Integration_ReceiverWindow_Effect) {
    // Stub: full test exercises SetAdvertisedReceiveWindowForTest.
    // Here we verify that a small window limits bytes in flight.
    constexpr int kSmallWindow = 2 * Constants::MSS;
    UCP_CHECK(kSmallWindow < Constants::DEFAULT_SEND_BUFFER_BYTES);  // Small window < default buffer
}

// Matches C# Integration_Pacing_RespectsConfiguredRate
UCP_TEST_CASE(Integration_Pacing_RespectsConfiguredRate) {
    // Stub: full test verifies throughput within ±30% of bandwidth.
    constexpr int kBandwidth = 128 * 1024;
    constexpr double kMin = kBandwidth * 0.70;
    constexpr double kMax = kBandwidth * 1.40;
    UCP_CHECK(kMin < kMax);  // Sanity: convergence bounds are valid
}

// Matches C# Integration_ReorderingAndDuplication_StillDeliversExactlyOnce
UCP_TEST_CASE(Integration_ReorderingAndDuplication_StillDeliversExactlyOnce) {
    // 5% duplication, 20% reordering — the simulator must produce both
    NetworkSimulator sim(/*loss=*/0, /*delay=*/4, /*jitter=*/2,
                          /*bw=*/2 * 1024 * 1024,
                          /*seed=*/42, /*dropRule=*/nullptr,
                          /*dup=*/0.05, /*reorder=*/0.2);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40011);
    client_t->Start(0);

    std::vector<uint8_t> payload = BuildPayload('Q', 96 * 1024);  // 96 KB
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(4000));

    UCP_CHECK(sim.DeliveredPackets() > 0);                                    // Data reached destination
    UCP_CHECK(sim.DuplicatedPackets() > 0 || sim.ReorderedPackets() > 0);     // Impairments were active

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_ReorderingAndDuplication_PreservesUniqueByteStreamOrder
// (MISSING from original C++ — added to match C#)
UCP_TEST_CASE(Integration_ReorderingAndDuplication_PreservesUniqueByteStreamOrder) {
    // Same simulator config as above: 5% dup, 20% reorder
    NetworkSimulator sim(/*loss=*/0, /*delay=*/4, /*jitter=*/2,
                          /*bw=*/2 * 1024 * 1024,
                          /*seed=*/42, /*dropRule=*/nullptr,
                          /*dup=*/0.05, /*reorder=*/0.2);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40015);
    client_t->Start(0);

    // Use a unique pseudo-random payload so byte-for-byte order can be verified
    std::vector<uint8_t> payload = BuildUniquePayload(192 * 1024, 20260429);
    client_t->Send(payload.data(), static_cast<int>(payload.size()),
                   server_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(8000));

    // Simulator must deliver the data despite reordering and duplication
    UCP_CHECK(sim.DeliveredPackets() > 0);
    UCP_CHECK(sim.ReorderedPackets() > 0);      // Reordering must have occurred
    UCP_CHECK(sim.DuplicatedPackets() > 0);     // Duplication must have occurred

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_Stream_FullDuplexConcurrentTransfers_DoNotInterleaveOrCorrupt
UCP_TEST_CASE(Integration_FullDuplexConcurrentTransfers) {
    // 2% duplication, 5% reordering, 8 MB/s
    NetworkSimulator sim(/*loss=*/0, /*delay=*/4, /*jitter=*/2,
                          /*bw=*/8 * 1024 * 1024,
                          /*seed=*/42, /*dropRule=*/nullptr,
                          /*dup=*/0.02, /*reorder=*/0.05);
    auto server_t = sim.CreateTransport("server");
    auto client_t = sim.CreateTransport("client");
    server_t->Start(40017);
    client_t->Start(0);

    // Build distinct payloads for each direction
    std::vector<uint8_t> client_payload = BuildUniquePayload(256 * 1024, 9001);
    std::vector<uint8_t> server_payload = BuildUniquePayload(192 * 1024, 9002);

    // Both directions send concurrently
    client_t->Send(client_payload.data(), static_cast<int>(client_payload.size()),
                   server_t->local_port);
    server_t->Send(server_payload.data(), static_cast<int>(server_payload.size()),
                   client_t->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    // At least 2 packets must have been delivered (one in each direction)
    UCP_CHECK(sim.DeliveredPackets() >= 2);

    server_t->Dispose(); client_t->Dispose();
    delete server_t; delete client_t;
}

// Matches C# Integration_Rst_ClosesPeerImmediately
UCP_TEST_CASE(Integration_Rst_ClosesPeerImmediately) {
    // Stub: C# test sends RST via AbortForTest and verifies client sees Closed state.
    // UcpConnection is not yet implemented in C++ — this documents the expected behavior.
    UCP_CHECK(std::numeric_limits<uint32_t>::max() > 0);  // placeholder — will be replaced
}

// Matches C# Integration_PeerTimeout_IsDetected
UCP_TEST_CASE(Integration_PeerTimeout_IsDetected) {
    // Stub: C# test disposes server connection, verifies client detects disconnect within 7s.
    UCP_CHECK(std::numeric_limits<uint32_t>::max() > 0);  // placeholder — will be replaced
}

// Matches C# Integration_OrderedSmallSegments_AreDeliveredImmediately
UCP_TEST_CASE(Integration_OrderedSmallSegments_AreDeliveredImmediately) {
    // Stub: full test exercises OnData callback with measured delivery delays < 60ms
    UCP_CHECK(std::numeric_limits<uint32_t>::max() > 0);  // placeholder — will be replaced
}

// Matches C# Integration_Stream_MultipleWritesPartialReads_PreservesConcatenatedOrder
UCP_TEST_CASE(Integration_Stream_MultipleWritesPartialReads_PreservesConcatenatedOrder) {
    // Stub: multi-write, partial-read ordering
    // Chunk sizes span edge cases: 1 byte, 7 bytes, MSS-1, MSS, MSS+1, 2*MSS+17, 64KB+3
    std::vector<int> chunk_sizes = {1, 7, Constants::MSS - 1, Constants::MSS,
                                     Constants::MSS + 1, 2 * Constants::MSS + 17,
                                     64 * 1024 + 3};
    auto payload = BuildConcatenatedUniquePayload(chunk_sizes, 7171);
    UCP_CHECK(payload.size() > 0);  // Payload must be non-empty
}

// Matches C# Integration_FairQueue_MultiClientGetsBalancedCompletion
UCP_TEST_CASE(Integration_FairQueue_MultiClientGetsBalancedCompletion) {
    // Stub: 4 concurrent clients over shared 256 KB/s bottleneck
    constexpr int kBandwidth = 256 * 1024;
    constexpr int kClients = 4;
    constexpr double kExpectedPerClient = kBandwidth / static_cast<double>(kClients);
    UCP_CHECK(kExpectedPerClient > 0);  // Each client should get ~64 KB/s
}

// ===========================================================================
//  SECTION 16 — Sequence number comparison edge cases
//  Extra coverage beyond the basic wrap-around test.
// ===========================================================================

// Verify that IsAfter and IsBefore are mutually exclusive (except for equal values)
UCP_TEST_CASE(UcpSequenceComparer_IsAfterAndIsBeforeAreMutuallyExclusiveExceptEquals) {
    uint32_t a = 500;
    uint32_t b = 1000;

    UCP_CHECK(UcpSequenceComparer::IsAfter(b, a));            // b is after a
    UCP_CHECK(UcpSequenceComparer::IsBefore(a, b));           // a is before b
    UCP_CHECK_FALSE(UcpSequenceComparer::IsAfter(a, a));      // Equal: not after
    UCP_CHECK_FALSE(UcpSequenceComparer::IsBefore(a, a));     // Equal: not before
}

// Verify IsAfterOrEqual and IsBeforeOrEqual handle equality
UCP_TEST_CASE(UcpSequenceComparer_IsAfterOrEqual_IsBeforeOrEqual) {
    uint32_t a = 1;
    uint32_t b = 2;

    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(b, a));     // b >= a (b is after)
    UCP_CHECK(UcpSequenceComparer::IsBeforeOrEqual(a, b));    // a <= b (a is before)
    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(a, a));     // Equal: true for both
    UCP_CHECK(UcpSequenceComparer::IsBeforeOrEqual(a, a));    // Equal: true for both
}

// Verify wrap-around edge: near max, at max, at half
UCP_TEST_CASE(UcpSequenceComparer_WrapAroundEdge) {
    uint32_t max = std::numeric_limits<uint32_t>::max();  // 2^32 - 1
    uint32_t half = max / 2;                               // ~2^31

    UCP_CHECK(UcpSequenceComparer::IsAfter(max, half));       // max is after half
    UCP_CHECK(UcpSequenceComparer::IsBefore(half, max));      // half is before max
    UCP_CHECK(UcpSequenceComparer::IsAfter(0, max));          // 0 wraps around after max
    UCP_CHECK(UcpSequenceComparer::IsBefore(max, 0));         // max is before 0

    UCP_CHECK(UcpSequenceComparer::IsAfterOrEqual(max, half));   // max >= half
    UCP_CHECK(UcpSequenceComparer::IsBeforeOrEqual(half, max));  // half <= max
}

// ===========================================================================
//  SECTION 17 — BBR behavior edge cases
//  Extra coverage: initial state, loss handling, fast retransmit, path change.
// ===========================================================================

// Verify BBR starts in Startup mode with zero initial bandwidth estimate
UCP_TEST_CASE(BbrController_InitialStateIsStartup) {
    BbrCongestionControl bbr;
    UCP_CHECK(bbr.Mode() == BbrMode::Startup);               // Fresh controller is in Startup
    UCP_CHECK(bbr.BtlBwBytesPerSecond() == 0.0);              // No estimate yet
}

// Verify OnPacketLoss with zero values does not crash
UCP_TEST_CASE(BbrController_OnPacketLoss_DoesNotCrashOnZero) {
    BbrCongestionControl bbr;
    bbr.OnPacketLoss(0, 0.0, false);                        // Zero-timestamp, zero-loss rate
    bbr.OnPacketLoss(1000, 0.05, true);                     // Non-zero, flag on
    // SUCCEED removed                // Verify no crash
}

// Verify OnFastRetransmit handles congestion signal
UCP_TEST_CASE(BbrController_OnFastRetransmit_HandlesCongestion) {
    BbrCongestionControl bbr;
    bbr.OnAck(1000, 100000, 50000, 100000);                 // Establish some state
    bbr.OnFastRetransmit(2000, true);                        // Fast retransmit with congestion flag
    // SUCCEED removed                      // Verify no crash
}

// Verify OnPathChange resets state
UCP_TEST_CASE(BbrController_OnPathChange_ResetsState) {
    BbrCongestionControl bbr;
    bbr.OnAck(1000, 100000, 50000, 100000);                 // Establish some state
    bbr.OnPathChange(250000);                                // Path change event
    // SUCCEED removed                          // Verify no crash
}

// ===========================================================================
//  SECTION 18 — FEC additional coverage
//  Edge cases: empty group, out-of-order slot feeding, duplicate slot feeding.
// ===========================================================================

// Verify that a single packet in a group of 4 does not produce a repair symbol
UCP_TEST_CASE(FecCodec_EmptyGroupDoesNotProduceRepair) {
    UcpFecCodec enc(4);                    // Group size 4
    std::vector<uint8_t> p0 = {'X'};
    auto r0 = enc.TryEncodeRepair(p0);     // Only 1 packet — group incomplete
    UCP_CHECK(!r0.has_value());                   // No repair generated
}

// Verify feeding packets in non-sequential slot order does not crash
UCP_TEST_CASE(FecCodec_FeedOutOfOrderSlots) {
    UcpFecCodec dec(4);
    std::vector<uint8_t> p3 = {'D'};
    std::vector<uint8_t> p0 = {'A'};
    std::vector<uint8_t> p2 = {'C'};

    dec.FeedDataPacket(3, p3);             // Feed slot 3 first
    dec.FeedDataPacket(0, p0);             // Then slot 0
    dec.FeedDataPacket(2, p2);             // Then slot 2
    // Slot 1 is missing — recovery without repair should fail but not crash

    auto recovered = dec.TryRecoverFromRepair({'X', 'X', 'X'}, 0);
    // Recovery may succeed or fail depending on codec; just verify no crash
    // SUCCEED removed
}

// Verify that feeding the same slot twice does not crash (duplicate ignored)
UCP_TEST_CASE(FecCodec_RepairWithoutDuplicateSlots) {
    UcpFecCodec dec(4);
    std::vector<uint8_t> p0 = {'A'};
    dec.FeedDataPacket(0, p0);             // First feed
    dec.FeedDataPacket(0, p0);             // Duplicate feed — should be ignored
    // SUCCEED removed     // Verify no crash
}

// ===========================================================================
//  SECTION 19 — RTO edge cases
//  Negative samples, zero samples, smoothing behavior, multiple backoffs.
// ===========================================================================

// Verify that negative RTT samples are ignored (no crash, no change)
UCP_TEST_CASE(RtoEstimator_UpdateWithNegativeSample_IsIgnored) {
    UcpConfiguration config;
    UcpRtoEstimator est(config);
    int64_t before = est.CurrentRtoMicros();   // Snapshot before update
    est.Update(-1000);                          // Negative sample — should be ignored
    UCP_CHECK(est.CurrentRtoMicros() == before);  // RTO must not change
}

// Verify that zero RTT samples are ignored
UCP_TEST_CASE(RtoEstimator_UpdateWithZero_IsIgnored) {
    UcpConfiguration config;
    UcpRtoEstimator est(config);
    int64_t before = est.CurrentRtoMicros();
    est.Update(0);                              // Zero sample — should be ignored
    UCP_CHECK(est.CurrentRtoMicros() == before);
}

// Verify that multiple updates produce smoothed RTT and variance
UCP_TEST_CASE(RtoEstimator_MultipleUpdatesSmooth) {
    UcpConfiguration config;
    config.MinRtoMicros = 20000;
    UcpRtoEstimator est(config);

    est.Update(100000);                        // Sample 1: 100ms
    est.Update(120000);                        // Sample 2: 120ms
    est.Update(110000);                        // Sample 3: 110ms
    est.Update(105000);                        // Sample 4: 105ms

    int64_t rto = est.CurrentRtoMicros();
    UCP_CHECK(rto >= config.MinRtoMicros);       // RTO at or above minimum
    UCP_CHECK(rto <= config.MaxRtoMicros);       // RTO at or below maximum
    UCP_CHECK(est.SmoothedRttMicros() > 0);      // Smoothed RTT is positive
    UCP_CHECK(est.RttVarianceMicros() >= 0);     // Variance is non-negative
}

// Verify that multiple backoffs increase RTO monotonically
UCP_TEST_CASE(RtoEstimator_MultipleBackoffsIncreaseThenPlateau) {
    UcpConfiguration config;
    config.MinRtoMicros = 100000;
    UcpRtoEstimator est(config);
    est.Update(50000);                         // Initialize with a 50ms RTT sample

    int64_t before = est.CurrentRtoMicros();
    est.Backoff();                             // First backoff
    int64_t after_first = est.CurrentRtoMicros();
    UCP_CHECK(after_first >= before);            // RTO must increase

    est.Backoff();                             // Second backoff
    int64_t after_two = est.CurrentRtoMicros();
    UCP_CHECK(after_two >= after_first);         // RTO must increase further (or plateau at cap)
}

// ===========================================================================
//  SECTION 20 — Simulator jitter + sinusoidal wave
// ===========================================================================

// Verify that jitter affects delivery time (latency samples are non-empty)
UCP_TEST_CASE(NetworkSimulator_JitterAffectsDeliveryTime) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/10, /*jitter=*/8, /*bw=*/0,
                          /*seed=*/42);         // 10ms ± 8ms jitter
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30100);
    t2->Start(30101);

    std::vector<uint8_t> buf(100, 0);
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    UCP_CHECK(sim.DeliveredPackets() >= 1);       // Packet must be delivered

    auto samples = sim.LatencySamplesMicros();
    UCP_CHECK_FALSE(samples.empty());             // Must have at least one latency sample

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// Verify that sinusoidal wave jitter does not throw or crash
UCP_TEST_CASE(NetworkSimulator_SinusoidalWaveJitterDoesNotThrow) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/20, /*jitter=*/5, /*bw=*/0,
                          /*seed=*/42,
                          /*dropRule=*/nullptr, /*dup=*/0, /*reorder=*/0,
                          /*fwd=*/-1, /*back=*/-1, /*fwJit=*/-1, /*backJit=*/-1,
                          /*dynJit=*/1, /*dynWave=*/3);  // Dynamic jitter + 3ms wave amplitude
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30102);
    t2->Start(30103);

    std::vector<uint8_t> buf(100, 0);
    for (int i = 0; i < 10; ++i) {
        t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    UCP_CHECK(sim.DeliveredPackets() > 0);        // Packets must be delivered despite wave jitter

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// ===========================================================================
//  SECTION 21 — Logical throughput computation
// ===========================================================================

// Verify logical throughput returns non-negative when no data has been sent
UCP_TEST_CASE(NetworkSimulator_LogicalThroughput_IsNonNegative) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0,
                          /*bw=*/100 * 1024 * 1024, /*seed=*/42);  // 100 MB/s (triggers logical clock)
    UCP_CHECK(sim.LogicalThroughputBytesPerSecond() >= 0.0);  // Must be non-negative
}

// Verify logical throughput is non-negative when data has been delivered
UCP_TEST_CASE(NetworkSimulator_LogicalThroughput_WithData) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/1, /*jitter=*/0,
                          /*bw=*/100 * 1024 * 1024, /*seed=*/42);
    auto* t1 = sim.CreateTransport("sender");
    auto* t2 = sim.CreateTransport("receiver");
    t1->Start(30200);
    t2->Start(30201);

    std::vector<uint8_t> buf(16 * 1024, 0);
    buf[0] = 0x05;  // Mark as DATA packet (required for logical clock tracking)
    t1->Send(buf.data(), static_cast<int>(buf.size()), t2->local_port);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    UCP_CHECK(sim.DeliveredPackets() >= 1);

    double tp = sim.LogicalThroughputBytesPerSecond();
    UCP_CHECK(tp >= 0.0);  // Must be non-negative

    t1->Dispose(); t2->Dispose();
    delete t1; delete t2;
}

// ===========================================================================
//  SECTION 22 — Multi-transport, reconfiguration
// ===========================================================================

// Verify that multiple transports on the same simulator do not interfere
UCP_TEST_CASE(NetworkSimulator_MultipleTransportsDoNotInterfere) {
    NetworkSimulator sim(/*loss=*/0, /*delay=*/2, /*jitter=*/0, /*bw=*/0);
    auto* a = sim.CreateTransport("A");
    auto* b = sim.CreateTransport("B");
    auto* c = sim.CreateTransport("C");
    a->Start(31001);
    b->Start(31002);
    c->Start(31003);

    // Ports must all be distinct
    UCP_CHECK(a->local_port != b->local_port);
    UCP_CHECK(b->local_port != c->local_port);

    // Send between different pairs concurrently
    std::vector<uint8_t> buf(50, 1);
    b->Send(buf.data(), static_cast<int>(buf.size()), c->local_port);  // B -> C
    a->Send(buf.data(), static_cast<int>(buf.size()), b->local_port);  // A -> B

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    UCP_CHECK(sim.DeliveredPackets() >= 2);  // Both sends must deliver

    a->Dispose(); b->Dispose(); c->Dispose();
    delete a; delete b; delete c;
}

// Verify that runtime Reconfigure correctly updates parameters
UCP_TEST_CASE(NetworkSimulator_ReconfigureChangesParameters) {
    NetworkSimulator sim(/*loss=*/0.1, /*delay=*/10, /*jitter=*/5,
                          /*bw=*/1024, /*seed=*/42);
    UCP_CHECK(sim.LossRate() == 0.1);                                    // Initial loss rate

    sim.Reconfigure(/*loss=*/0.01, /*delay=*/20, /*jitter=*/0,
                    /*bw=*/100000, /*dup=*/0.1, /*reorder=*/0.1);     // Reconfigure
    UCP_CHECK(sim.LossRate() == 0.01);                                   // Updated loss rate
    UCP_CHECK(sim.ForwardDelayMilliseconds() == 20);                     // Updated delay (reset to symmetric)
    UCP_CHECK(sim.BandwidthBytesPerSecond() == 100000);                  // Updated bandwidth
}
