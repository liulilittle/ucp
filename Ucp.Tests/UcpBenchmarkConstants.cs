using System;

namespace Ucp
{

    internal static class UcpBenchmarkConstants
    {

        public const double BITS_PER_BYTE = 8d;

        public const double BITS_PER_MEGABIT = 1000000d;

        public const int BENCHMARK_100_MBPS_BYTES_PER_SECOND = 100000000 / 8;

        public const int BENCHMARK_1_GBPS_BYTES_PER_SECOND = 1000000000 / 8;

        public const int BENCHMARK_10_GBPS_BYTES_PER_SECOND = (int)(10000000000L / 8);

        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND = 1000000 / 8;

        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_DIVISOR = 128;

        public const int BENCHMARK_RTT_PATH_MULTIPLIER = 2;

        public const double BENCHMARK_INITIAL_CWND_BDP_GAIN = 1.25d;

        public const int BENCHMARK_NO_LOSS_INITIAL_CWND_BANDWIDTH_DIVISOR = 16;

        public const double BENCHMARK_LOSS_INITIAL_CWND_BDP_GAIN = 4.0d;

        public const double BENCHMARK_WEAK_NETWORK_INITIAL_CWND_BDP_GAIN = 8.0d;


        public const double BENCHMARK_LONG_RUNNING_SERIAL_SECONDS = 10d;

        public const int BENCHMARK_MAX_LOSS_INITIAL_CWND_BYTES = 128 * 1024 * 1024;

        public const long BENCHMARK_LONG_FAT_MIN_RTO_MICROS = UcpConstants.MICROS_PER_SECOND;

        public const double BENCHMARK_LIGHT_RANDOM_LOSS_RATE = 0.01d;

        public const double BENCHMARK_HEAVY_RANDOM_LOSS_RATE = 0.05d;

        public const double BENCHMARK_VERY_HEAVY_RANDOM_LOSS_RATE = 0.10d;

        public const double BENCHMARK_VERY_HEAVY_LOSS_FEC_REDUNDANCY = 0.50d;

        public const double BENCHMARK_MEDIUM_RANDOM_LOSS_RATE = 0.03d;

        public const double BENCHMARK_MEDIUM_LOSS_FEC_REDUNDANCY = 0.50d;

        public const int BENCHMARK_LIGHT_RANDOM_LOSS_SEED = 20260501;

        public const int BENCHMARK_HEAVY_RANDOM_LOSS_SEED = 20260502;

        public const int BENCHMARK_ASYM_RANDOM_LOSS_SEED = 20260503;

        public const int BENCHMARK_HIGH_JITTER_LOSS_SEED = 20260504;

        public const int BENCHMARK_WEAK_4G_LOSS_SEED = 20260505;

        public const long BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS = 10000L;

        public const int BENCHMARK_CONTROLLER_MAX_CONVERGENCE_ROUNDS = 32;

        public const double BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT = 70d;

        public const double BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT = 45d;

        public const double BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS = 10d;

        public const double BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER = 4d;

        public const double BENCHMARK_MIN_CONVERGED_PACING_RATIO = 0.05d;

        public const double BENCHMARK_MAX_CONVERGED_PACING_RATIO = 5.0d;

        public const int BENCHMARK_100M_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_ASYM_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_WEAK_4G_PAYLOAD_BYTES = 300 * 1024;
        public const int BENCHMARK_100M_LOSS_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES = 200 * 1024;
        public const int BENCHMARK_MOBILE_3G_PAYLOAD_BYTES = 300 * 1024;
        public const int BENCHMARK_MOBILE_4G_PAYLOAD_BYTES = 300 * 1024;
        public const int BENCHMARK_SATELLITE_PAYLOAD_BYTES = 300 * 1024;
        public const int BENCHMARK_VPN_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_1G_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_1G_LOSS_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_HIGH_BANDWIDTH_MSS = 9000;
        public const int BENCHMARK_10G_PAYLOAD_BYTES = 500 * 1024;
        public const int BENCHMARK_BURST_LOSS_PAYLOAD_BYTES = 500 * 1024;

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

        public const int BENCHMARK_READ_TIMEOUT_MILLISECONDS = 10000;
        public const int BENCHMARK_ACK_SETTLEMENT_TIMEOUT_MILLISECONDS = 500;
        public const long BENCHMARK_HIGH_RTT_FEC_THRESHOLD_MICROS = 80000L;
        public const int BENCHMARK_HIGH_JITTER_FEC_THRESHOLD_MS = 15;
        public const int BENCHMARK_BURST_LOSS_FIRST_PACKET = 16;
        public const int BENCHMARK_BURST_LOSS_PACKET_COUNT = 8;
        public const int SIMULATOR_BASE_PORT = 30000;
    }
}
