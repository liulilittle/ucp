// ============================================================================
//  PPP PRIVATE NETWORK™ X — Universal Communication Protocol (ppp+ucp)
//  UcpBenchmarkConstants.cs — Benchmark test constants (moved from UcpConstants)
//
//  These constants define the pre-configured test scenarios covering UCP's
//  entire target operating range (100Mbps → 10Gbps, 1ms → 300ms delay,
//  0% → 10% loss).  They are test-infrastructure concerns and do not belong
//  in the core protocol library.
// ============================================================================

using System; // Import core .NET types (Math, etc.)

namespace Ucp // Use the Ucp namespace to access UcpConstants directly
{
    /// <summary>
    /// Benchmark scenario constants used exclusively by the test suite.
    /// Moved from UcpConstants to keep the core library free of test-specific
    /// configuration.  Each constant documents the scenario it serves and the
    /// rationale for the chosen value.
    /// </summary>
    internal static class UcpBenchmarkConstants // Static class containing all benchmark configuration constants
    {
        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 1 — BANDWIDTH BENCHMARKS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Benchmark bandwidth for 100 Mbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_100_MBPS_BYTES_PER_SECOND = 100000000 / 8; // 100 Mbps / 8 bits per byte = 12,500,000 bytes/s

        /// <summary>Benchmark bandwidth for 1 Gbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_1_GBPS_BYTES_PER_SECOND = 1000000000 / 8; // 1 Gbps / 8 = 125,000,000 bytes/s

        /// <summary>Benchmark bandwidth for 10 Gbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_10_GBPS_BYTES_PER_SECOND = 10000000000L / 8 > int.MaxValue ? int.MaxValue : (int)(10000000000L / 8); // 10 Gbps / 8, capped at int.MaxValue to prevent overflow

        /// <summary>Initial probe bandwidth used by unconstrained benchmark tests, in bytes per second.</summary>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND = 1000000 / 8; // 1 Mbps / 8 = 125,000 bytes/s — a safe starting probe rate

        /// <summary>Relative divisor used to choose a practical initial bandwidth probe for large links.</summary>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_DIVISOR = 128; // Divisor to scale initial CWND relative to bottleneck bandwidth

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 2 — BENCHMARK META-PARAMETERS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Path multiplier used to estimate RTT from one-way simulator delay.</summary>
        public const int BENCHMARK_RTT_PATH_MULTIPLIER = 2; // RTT ≈ 2 × one-way delay

        /// <summary>Initial congestion-window gain relative to estimated BDP for line-rate benchmarks.</summary>
        public const double BENCHMARK_INITIAL_CWND_BDP_GAIN = 1.25d; // Start CWND at 1.25× BDP for no-loss line-rate tests

        /// <summary>Bandwidth divisor used as the no-loss benchmark initial congestion-window floor.</summary>
        public const int BENCHMARK_NO_LOSS_INITIAL_CWND_BANDWIDTH_DIVISOR = 16; // CWND floor = bandwidth / 16 for no-loss scenarios

        /// <summary>Initial congestion-window gain relative to estimated BDP for lossy benchmarks.</summary>
        public const double BENCHMARK_LOSS_INITIAL_CWND_BDP_GAIN = 4.0d; // Start CWND at 4× BDP to accelerate loss recovery

        /// <summary>Initial congestion-window gain for weak/high-latency network benchmarks.</summary>
        public const double BENCHMARK_WEAK_NETWORK_INITIAL_CWND_BDP_GAIN = 8.0d; // Start CWND at 8× BDP for very weak high-latency paths

        /// <summary>ProbeRTT interval for weak/high-latency network benchmarks (120s).</summary>
        public const long BENCHMARK_WEAK_NETWORK_PROBE_RTT_INTERVAL_MICROS = 120000000L; // 120 seconds in microseconds for weak network RTT probing

        /// <summary>Serial-time threshold (seconds) above which a benchmark is considered long-running.</summary>
        public const double BENCHMARK_LONG_RUNNING_SERIAL_SECONDS = 10d; // Benchmarks over 10 seconds are flagged as long-running

        /// <summary>Maximum initial congestion window used by random-loss benchmarks, in bytes.</summary>
        public const int BENCHMARK_MAX_LOSS_INITIAL_CWND_BYTES = 128 * 1024 * 1024; // Cap loss-scenario CWND at 128 MB to avoid excessive memory

        /// <summary>Minimum RTO used by long-fat-pipe benchmarks to avoid simulator serialization false positives.</summary>
        public const long BENCHMARK_LONG_FAT_MIN_RTO_MICROS = UcpConstants.MICROS_PER_SECOND; // 1 second minimum RTO for LFN scenarios

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 3 — LOSS RATES AND SEEDS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Light random data loss rate used by benchmark scenarios.</summary>
        public const double BENCHMARK_LIGHT_RANDOM_LOSS_RATE = 0.01d; // 1% random packet loss for light-loss benchmarks

        /// <summary>Heavy random data loss rate used by benchmark scenarios.</summary>
        public const double BENCHMARK_HEAVY_RANDOM_LOSS_RATE = 0.05d; // 5% random packet loss for heavy-loss benchmarks

        /// <summary>Very heavy random data loss rate (>=10%) used by benchmark scenarios.</summary>
        public const double BENCHMARK_VERY_HEAVY_RANDOM_LOSS_RATE = 0.10d; // 10% random packet loss for very heavy loss benchmarks

        /// <summary>FEC redundancy ratio for very heavy loss (>=10%) benchmark scenarios.</summary>
        public const double BENCHMARK_VERY_HEAVY_LOSS_FEC_REDUNDANCY = 0.50d; // 50% FEC redundancy for very heavy loss paths

        /// <summary>Medium random loss rate (>=3%) threshold for increased FEC redundancy.</summary>
        public const double BENCHMARK_MEDIUM_RANDOM_LOSS_RATE = 0.03d; // 3% threshold that triggers medium FEC redundancy level

        /// <summary>FEC redundancy ratio for medium loss (3-10%) benchmark scenarios.</summary>
        public const double BENCHMARK_MEDIUM_LOSS_FEC_REDUNDANCY = 0.50d; // 50% FEC redundancy for medium-loss scenarios

        /// <summary>Deterministic random seed used by light-loss benchmark data drops.</summary>
        public const int BENCHMARK_LIGHT_RANDOM_LOSS_SEED = 20260501; // Fixed seed for reproducible light-loss drop patterns

        /// <summary>Deterministic random seed used by heavy-loss benchmark data drops.</summary>
        public const int BENCHMARK_HEAVY_RANDOM_LOSS_SEED = 20260502; // Fixed seed for reproducible heavy-loss drop patterns

        /// <summary>Deterministic random seed used by asymmetric route benchmark data drops.</summary>
        public const int BENCHMARK_ASYM_RANDOM_LOSS_SEED = 20260503; // Fixed seed for reproducible asymmetric route drop patterns

        /// <summary>Deterministic random seed used by high-jitter benchmark data drops.</summary>
        public const int BENCHMARK_HIGH_JITTER_LOSS_SEED = 20260504; // Fixed seed for reproducible high-jitter drop patterns

        /// <summary>Deterministic random seed used by weak 4G benchmark data drops.</summary>
        public const int BENCHMARK_WEAK_4G_LOSS_SEED = 20260505; // Fixed seed for reproducible weak-4G drop patterns

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 4 — BBR AND PACING BENCHMARK TUNING
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>RTT used by controller-only auto-probe convergence benchmarks, in microseconds.</summary>
        public const long BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS = 10000L; // 10ms simulated RTT for unit-level BBR convergence tests

        /// <summary>Maximum BBR rounds allowed for controller-only auto-probe convergence benchmarks.</summary>
        public const int BENCHMARK_CONTROLLER_MAX_CONVERGENCE_ROUNDS = 32; // Up to 32 ACK rounds for BBR auto-probe convergence

        /// <summary>Minimum line-rate utilization target for no-loss benchmark scenarios.</summary>
        public const double BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT = 70d; // 70% minimum utilization for no-loss line-rate tests

        /// <summary>Minimum line-rate utilization target for controlled-loss benchmark scenarios.</summary>
        public const double BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT = 45d; // 45% minimum utilization for lossy line-rate tests

        /// <summary>Minimum throughput target for the 5% random-loss 1 Gbps benchmark, in Mbps.</summary>
        public const double BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS = 145d; // 145 Mbps minimum throughput for gigabit + 5% loss

        /// <summary>Maximum acceptable RTT jitter multiplier relative to the configured one-way delay.</summary>
        public const double BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER = 4d; // Jitter must not exceed 4× the configured delay

        /// <summary>Minimum pacing ratio accepted after auto-probing converges.</summary>
        public const double BENCHMARK_MIN_CONVERGED_PACING_RATIO = 0.70d; // Pacing rate must reach at least 70% of target for convergence

        /// <summary>Maximum pacing ratio accepted after auto-probing converges.</summary>
        public const double BENCHMARK_MAX_CONVERGED_PACING_RATIO = 3.0d; // Pacing rate may overshoot up to 3× target during probe phases

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 5 — PAYLOAD SIZES
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_100M_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for 100 Mbps benchmarks
        public const int BENCHMARK_ASYM_PAYLOAD_BYTES = 8 * 1024 * 1024; // 8 MB payload for asymmetric route benchmarks
        public const int BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for high-jitter benchmarks
        public const int BENCHMARK_WEAK_4G_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for weak 4G benchmarks
        public const int BENCHMARK_100M_LOSS_PAYLOAD_BYTES = 32 * 1024 * 1024; // 32 MB payload for 100 Mbps loss benchmarks
        public const int BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for high-loss/high-RTT benchmarks
        public const int BENCHMARK_MOBILE_3G_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for mobile 3G benchmarks
        public const int BENCHMARK_MOBILE_4G_PAYLOAD_BYTES = 32 * 1024 * 1024; // 32 MB payload for mobile 4G benchmarks
        public const int BENCHMARK_SATELLITE_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for satellite benchmarks
        public const int BENCHMARK_VPN_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for VPN benchmarks
        public const int BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for long-fat 100M benchmarks
        public const int BENCHMARK_1G_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB payload for 1 Gbps ideal benchmarks
        public const int BENCHMARK_1G_LOSS_PAYLOAD_BYTES = 64 * 1024 * 1024; // 64 MB payload for 1 Gbps loss benchmarks
        public const int BENCHMARK_HIGH_BANDWIDTH_MSS = 9000; // 9000-byte MSS for high-bandwidth (jumbo-frame) scenarios
        public const int BENCHMARK_10G_PAYLOAD_BYTES = 32 * 1024 * 1024; // 32 MB payload for 10 Gbps benchmarks
        public const int BENCHMARK_BURST_LOSS_PAYLOAD_BYTES = 2 * 1024 * 1024; // 2 MB payload for burst-loss benchmarks

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 6 — BENCHMARK PORTS
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_BASE_PORT = 40100; // Base port number for benchmark scenarios
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_IDEAL = 0; // Port offset for gigabit ideal scenario: 40100
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS5 = 1; // Port offset for gigabit 5% loss scenario: 40101
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS1 = 2; // Port offset for gigabit 1% loss scenario: 40102
        public const int BENCHMARK_PORT_OFFSET_LONG_FAT_100M = 3; // Port offset for long-fat 100M scenario: 40103
        public const int BENCHMARK_PORT_OFFSET_10G = 4; // Port offset for 10G scenario: 40104
        public const int BENCHMARK_PORT_OFFSET_BURST_LOSS = 5; // Port offset for burst-loss scenario: 40105
        public const int BENCHMARK_PORT_OFFSET_ASYM_ROUTE = 6; // Port offset for asymmetric route scenario: 40106
        public const int BENCHMARK_PORT_OFFSET_HIGH_JITTER = 7; // Port offset for high-jitter scenario: 40107
        public const int BENCHMARK_PORT_OFFSET_WEAK_4G = 8; // Port offset for weak 4G scenario: 40108
        public const int BENCHMARK_PORT_OFFSET_MOBILE_3G = 14; // Port offset for mobile 3G scenario: 40114
        public const int BENCHMARK_PORT_OFFSET_MOBILE_4G = 15; // Port offset for mobile 4G scenario: 40115
        public const int BENCHMARK_PORT_OFFSET_SATELLITE = 16; // Port offset for satellite scenario: 40116
        public const int BENCHMARK_PORT_OFFSET_VPN = 17; // Port offset for VPN scenario: 40117
        public const int BENCHMARK_PORT_OFFSET_DATACENTER = 18; // Port offset for datacenter scenario: 40118
        public const int BENCHMARK_PORT_OFFSET_ENTERPRISE = 19; // Port offset for enterprise scenario: 40119

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 7 — BENCHMARK DELAYS
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_100M_DELAY_MILLISECONDS = 5; // 5ms one-way delay for 100 Mbps benchmarks
        public const int BENCHMARK_1G_IDEAL_DELAY_MILLISECONDS = 1; // 1ms one-way delay for ideal gigabit benchmarks
        public const int BENCHMARK_1G_LIGHT_LOSS_DELAY_MILLISECONDS = 20; // 20ms one-way delay for 1% loss gigabit benchmarks
        public const int BENCHMARK_1G_LIGHT_LOSS_JITTER_MILLISECONDS = 3; // ±3ms jitter for 1% loss gigabit benchmarks
        public const int BENCHMARK_1G_HEAVY_LOSS_DELAY_MILLISECONDS = 30; // 30ms one-way delay for 5% loss gigabit benchmarks
        public const int BENCHMARK_1G_HEAVY_LOSS_JITTER_MILLISECONDS = 5; // ±5ms jitter for 5% loss gigabit benchmarks
        public const int BENCHMARK_LONG_FAT_DELAY_MILLISECONDS = 50; // 50ms one-way delay for long-fat-pipe benchmarks
        public const int BENCHMARK_LONG_FAT_JITTER_MILLISECONDS = 2; // ±2ms jitter for long-fat-pipe benchmarks
        public const int BENCHMARK_10G_DELAY_MILLISECONDS = 1; // 1ms one-way delay for 10G benchmarks
        public const int BENCHMARK_BURST_LOSS_DELAY_MILLISECONDS = 25; // 25ms one-way delay for burst-loss benchmarks
        public const int BENCHMARK_BURST_LOSS_JITTER_MILLISECONDS = 4; // ±4ms jitter for burst-loss benchmarks
        public const int BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS = 25; // 25ms forward delay for asymmetric route benchmarks
        public const int BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS = 15; // 15ms reverse delay for asymmetric route benchmarks
        public const int BENCHMARK_ASYM_JITTER_MILLISECONDS = 8; // ±8ms jitter for asymmetric route benchmarks
        public const double BENCHMARK_ASYM_RANDOM_LOSS_RATE = 0.005d; // 0.5% random loss for asymmetric route benchmarks
        public const double BENCHMARK_HIGH_JITTER_LOSS_RATE = 0.005d; // 0.5% random loss for high-jitter benchmarks
        public const double BENCHMARK_WEAK_4G_LOSS_RATE = 0.05d; // 5% random loss for weak 4G benchmarks
        public const int BENCHMARK_HIGH_JITTER_DELAY_MILLISECONDS = 50; // 50ms one-way delay for high-jitter benchmarks
        public const int BENCHMARK_HIGH_JITTER_JITTER_MILLISECONDS = 25; // ±25ms jitter for high-jitter benchmarks
        public const int BENCHMARK_WEAK_4G_DELAY_MILLISECONDS = 80; // 80ms one-way delay for weak 4G benchmarks
        public const int BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS = 900; // 900ms period between network blackouts for weak 4G
        public const int BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS = 80; // 80ms duration of each weak 4G network blackout

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 8 — MISCELLANEOUS BENCHMARK CONSTANTS
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_READ_TIMEOUT_MILLISECONDS = 180000; // 3-minute maximum read timeout for benchmark transfers
        public const int BENCHMARK_ACK_SETTLEMENT_TIMEOUT_MILLISECONDS = 1000; // 1-second ACK settlement timeout for metric capture
        public const long BENCHMARK_HIGH_RTT_FEC_THRESHOLD_MICROS = 80000L; // 80ms RTT threshold above which FEC is activated
        public const int BENCHMARK_HIGH_JITTER_FEC_THRESHOLD_MS = 15; // 15ms jitter threshold above which FEC is activated
        public const int BENCHMARK_BURST_LOSS_FIRST_PACKET = 16; // Sequence index of the first packet dropped in burst-loss tests
        public const int BENCHMARK_BURST_LOSS_PACKET_COUNT = 8; // Number of consecutive packets dropped in burst-loss tests
        public const int SIMULATOR_BASE_PORT = 30000; // Base port number for simulator transports
    }
}
