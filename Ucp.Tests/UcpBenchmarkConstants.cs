// ============================================================================
//  PPP PRIVATE NETWORK™ X — Universal Communication Protocol (ppp+ucp)
//  UcpBenchmarkConstants.cs — Benchmark test constants (moved from UcpConstants)
//
//  These constants define the pre-configured test scenarios covering UCP's
//  entire target operating range (100Mbps → 10Gbps, 1ms → 300ms delay,
//  0% → 10% loss).  They are test-infrastructure concerns and do not belong
//  in the core protocol library.
// ============================================================================

using System;

namespace Ucp
{
    /// <summary>
    /// Benchmark scenario constants used exclusively by the test suite.
    /// Moved from UcpConstants to keep the core library free of test-specific
    /// configuration.  Each constant documents the scenario it serves and the
    /// rationale for the chosen value.
    /// </summary>
    internal static class UcpBenchmarkConstants
    {
        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 1 — BANDWIDTH BENCHMARKS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Benchmark bandwidth for 100 Mbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_100_MBPS_BYTES_PER_SECOND = 100000000 / 8;

        /// <summary>Benchmark bandwidth for 1 Gbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_1_GBPS_BYTES_PER_SECOND = 1000000000 / 8;

        /// <summary>Benchmark bandwidth for 10 Gbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_10_GBPS_BYTES_PER_SECOND = 10000000000L / 8 > int.MaxValue ? int.MaxValue : (int)(10000000000L / 8);

        /// <summary>Initial probe bandwidth used by unconstrained benchmark tests, in bytes per second.</summary>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND = 1000000 / 8;

        /// <summary>Relative divisor used to choose a practical initial bandwidth probe for large links.</summary>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_DIVISOR = 128;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 2 — BENCHMARK META-PARAMETERS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Path multiplier used to estimate RTT from one-way simulator delay.</summary>
        public const int BENCHMARK_RTT_PATH_MULTIPLIER = 2;

        /// <summary>Initial congestion-window gain relative to estimated BDP for line-rate benchmarks.</summary>
        public const double BENCHMARK_INITIAL_CWND_BDP_GAIN = 1.25d;

        /// <summary>Bandwidth divisor used as the no-loss benchmark initial congestion-window floor.</summary>
        public const int BENCHMARK_NO_LOSS_INITIAL_CWND_BANDWIDTH_DIVISOR = 16;

        /// <summary>Initial congestion-window gain relative to estimated BDP for lossy benchmarks.</summary>
        public const double BENCHMARK_LOSS_INITIAL_CWND_BDP_GAIN = 4.0d;

        /// <summary>Initial congestion-window gain for weak/high-latency network benchmarks.</summary>
        public const double BENCHMARK_WEAK_NETWORK_INITIAL_CWND_BDP_GAIN = 8.0d;

        /// <summary>ProbeRTT interval for weak/high-latency network benchmarks (120s).</summary>
        public const long BENCHMARK_WEAK_NETWORK_PROBE_RTT_INTERVAL_MICROS = 120000000L;

        /// <summary>Serial-time threshold (seconds) above which a benchmark is considered long-running.</summary>
        public const double BENCHMARK_LONG_RUNNING_SERIAL_SECONDS = 10d;

        /// <summary>Maximum initial congestion window used by random-loss benchmarks, in bytes.</summary>
        public const int BENCHMARK_MAX_LOSS_INITIAL_CWND_BYTES = 128 * 1024 * 1024;

        /// <summary>Minimum RTO used by long-fat-pipe benchmarks to avoid simulator serialization false positives.</summary>
        public const long BENCHMARK_LONG_FAT_MIN_RTO_MICROS = UcpConstants.MICROS_PER_SECOND;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 3 — LOSS RATES AND SEEDS
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>Light random data loss rate used by benchmark scenarios.</summary>
        public const double BENCHMARK_LIGHT_RANDOM_LOSS_RATE = 0.01d;

        /// <summary>Heavy random data loss rate used by benchmark scenarios.</summary>
        public const double BENCHMARK_HEAVY_RANDOM_LOSS_RATE = 0.05d;

        /// <summary>Very heavy random data loss rate (>=10%) used by benchmark scenarios.</summary>
        public const double BENCHMARK_VERY_HEAVY_RANDOM_LOSS_RATE = 0.10d;

        /// <summary>FEC redundancy ratio for very heavy loss (>=10%) benchmark scenarios.</summary>
        public const double BENCHMARK_VERY_HEAVY_LOSS_FEC_REDUNDANCY = 0.50d;

        /// <summary>Medium random loss rate (>=3%) threshold for increased FEC redundancy.</summary>
        public const double BENCHMARK_MEDIUM_RANDOM_LOSS_RATE = 0.03d;

        /// <summary>FEC redundancy ratio for medium loss (3-10%) benchmark scenarios.</summary>
        public const double BENCHMARK_MEDIUM_LOSS_FEC_REDUNDANCY = 0.50d;

        /// <summary>Deterministic random seed used by light-loss benchmark data drops.</summary>
        public const int BENCHMARK_LIGHT_RANDOM_LOSS_SEED = 20260501;

        /// <summary>Deterministic random seed used by heavy-loss benchmark data drops.</summary>
        public const int BENCHMARK_HEAVY_RANDOM_LOSS_SEED = 20260502;

        /// <summary>Deterministic random seed used by asymmetric route benchmark data drops.</summary>
        public const int BENCHMARK_ASYM_RANDOM_LOSS_SEED = 20260503;

        /// <summary>Deterministic random seed used by high-jitter benchmark data drops.</summary>
        public const int BENCHMARK_HIGH_JITTER_LOSS_SEED = 20260504;

        /// <summary>Deterministic random seed used by weak 4G benchmark data drops.</summary>
        public const int BENCHMARK_WEAK_4G_LOSS_SEED = 20260505;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 4 — BBR AND PACING BENCHMARK TUNING
        // ═══════════════════════════════════════════════════════════════════

        /// <summary>RTT used by controller-only auto-probe convergence benchmarks, in microseconds.</summary>
        public const long BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS = 10000L;

        /// <summary>Maximum BBR rounds allowed for controller-only auto-probe convergence benchmarks.</summary>
        public const int BENCHMARK_CONTROLLER_MAX_CONVERGENCE_ROUNDS = 32;

        /// <summary>Minimum line-rate utilization target for no-loss benchmark scenarios.</summary>
        public const double BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT = 70d;

        /// <summary>Minimum line-rate utilization target for controlled-loss benchmark scenarios.</summary>
        public const double BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT = 45d;

        /// <summary>Minimum throughput target for the 5% random-loss 1 Gbps benchmark, in Mbps.</summary>
        public const double BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS = 145d;

        /// <summary>Maximum acceptable RTT jitter multiplier relative to the configured one-way delay.</summary>
        public const double BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER = 4d;

        /// <summary>Minimum pacing ratio accepted after auto-probing converges.</summary>
        public const double BENCHMARK_MIN_CONVERGED_PACING_RATIO = 0.70d;

        /// <summary>Maximum pacing ratio accepted after auto-probing converges.</summary>
        public const double BENCHMARK_MAX_CONVERGED_PACING_RATIO = 3.0d;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 5 — PAYLOAD SIZES
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_100M_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_ASYM_PAYLOAD_BYTES = 8 * 1024 * 1024;
        public const int BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_WEAK_4G_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_100M_LOSS_PAYLOAD_BYTES = 32 * 1024 * 1024;
        public const int BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_MOBILE_3G_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_MOBILE_4G_PAYLOAD_BYTES = 32 * 1024 * 1024;
        public const int BENCHMARK_SATELLITE_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_VPN_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_1G_PAYLOAD_BYTES = 16 * 1024 * 1024;
        public const int BENCHMARK_1G_LOSS_PAYLOAD_BYTES = 64 * 1024 * 1024;
        public const int BENCHMARK_HIGH_BANDWIDTH_MSS = 9000;
        public const int BENCHMARK_10G_PAYLOAD_BYTES = 32 * 1024 * 1024;
        public const int BENCHMARK_BURST_LOSS_PAYLOAD_BYTES = 2 * 1024 * 1024;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 6 — BENCHMARK PORTS
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_BASE_PORT = 40100;
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_IDEAL = 0;
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS5 = 1;
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS1 = 2;
        public const int BENCHMARK_PORT_OFFSET_LONG_FAT_100M = 3;
        public const int BENCHMARK_PORT_OFFSET_10G = 4;
        public const int BENCHMARK_PORT_OFFSET_BURST_LOSS = 5;
        public const int BENCHMARK_PORT_OFFSET_ASYM_ROUTE = 6;
        public const int BENCHMARK_PORT_OFFSET_HIGH_JITTER = 7;
        public const int BENCHMARK_PORT_OFFSET_WEAK_4G = 8;
        public const int BENCHMARK_PORT_OFFSET_MOBILE_3G = 14;
        public const int BENCHMARK_PORT_OFFSET_MOBILE_4G = 15;
        public const int BENCHMARK_PORT_OFFSET_SATELLITE = 16;
        public const int BENCHMARK_PORT_OFFSET_VPN = 17;
        public const int BENCHMARK_PORT_OFFSET_DATACENTER = 18;
        public const int BENCHMARK_PORT_OFFSET_ENTERPRISE = 19;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 7 — BENCHMARK DELAYS
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_100M_DELAY_MILLISECONDS = 5;
        public const int BENCHMARK_1G_IDEAL_DELAY_MILLISECONDS = 1;
        public const int BENCHMARK_1G_LIGHT_LOSS_DELAY_MILLISECONDS = 20;
        public const int BENCHMARK_1G_LIGHT_LOSS_JITTER_MILLISECONDS = 3;
        public const int BENCHMARK_1G_HEAVY_LOSS_DELAY_MILLISECONDS = 30;
        public const int BENCHMARK_1G_HEAVY_LOSS_JITTER_MILLISECONDS = 5;
        public const int BENCHMARK_LONG_FAT_DELAY_MILLISECONDS = 50;
        public const int BENCHMARK_LONG_FAT_JITTER_MILLISECONDS = 2;
        public const int BENCHMARK_10G_DELAY_MILLISECONDS = 1;
        public const int BENCHMARK_BURST_LOSS_DELAY_MILLISECONDS = 25;
        public const int BENCHMARK_BURST_LOSS_JITTER_MILLISECONDS = 4;
        public const int BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS = 25;
        public const int BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS = 15;
        public const int BENCHMARK_ASYM_JITTER_MILLISECONDS = 8;
        public const double BENCHMARK_ASYM_RANDOM_LOSS_RATE = 0.005d;
        public const double BENCHMARK_HIGH_JITTER_LOSS_RATE = 0.005d;
        public const double BENCHMARK_WEAK_4G_LOSS_RATE = 0.05d;
        public const int BENCHMARK_HIGH_JITTER_DELAY_MILLISECONDS = 50;
        public const int BENCHMARK_HIGH_JITTER_JITTER_MILLISECONDS = 25;
        public const int BENCHMARK_WEAK_4G_DELAY_MILLISECONDS = 80;
        public const int BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS = 900;
        public const int BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS = 80;

        // ═══════════════════════════════════════════════════════════════════
        //  SECTION 8 — MISCELLANEOUS BENCHMARK CONSTANTS
        // ═══════════════════════════════════════════════════════════════════

        public const int BENCHMARK_READ_TIMEOUT_MILLISECONDS = 180000;
        public const int BENCHMARK_ACK_SETTLEMENT_TIMEOUT_MILLISECONDS = 1000;
        public const long BENCHMARK_HIGH_RTT_FEC_THRESHOLD_MICROS = 80000L;
        public const int BENCHMARK_HIGH_JITTER_FEC_THRESHOLD_MS = 15;
        public const int BENCHMARK_BURST_LOSS_FIRST_PACKET = 16;
        public const int BENCHMARK_BURST_LOSS_PACKET_COUNT = 8;
        public const int SIMULATOR_BASE_PORT = 30000;
    }
}
