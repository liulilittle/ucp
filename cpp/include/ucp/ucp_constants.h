#pragma once

#include <cstdint>

namespace ucp {
namespace Constants {

// Fixed-point scales (KCC2.0, tcp_kcc.c compatible)
constexpr int BW_SCALE = 24;
constexpr int64_t BW_UNIT = INT64_C(1) << BW_SCALE;
constexpr int BBR_SCALE = 8;
constexpr int BBR_UNIT = 1 << BBR_SCALE;
constexpr int KCC_SCALE_SHIFT = 10;
constexpr int64_t KCC_SCALE = INT64_C(1) << KCC_SCALE_SHIFT;
constexpr int64_t MICROS_PER_SECOND = 1000000LL;
constexpr int64_t MICROS_PER_MILLI = 1000LL;
constexpr int64_t NANOS_PER_MICRO = 1000;

// Geodesic estimator (KCC2.0)
constexpr int KCC_G2_GROWTH_NUM = 122;
constexpr int KCC_G2_GROWTH_DEN = 1000;
constexpr int KCC_G3_FAST_TH_NUM = 11;
constexpr int KCC_G3_FAST_TH_DEN = 10;
constexpr int KCC_G3_SLOW_TH_NUM = 21;
constexpr int KCC_G3_SLOW_TH_DEN = 20;
constexpr uint32_t KCC_PD_NOISE_GATE_NUM = 95;
constexpr uint32_t KCC_PD_NOISE_GATE_DEN = 100;
constexpr uint64_t KCC_INNOV_SQ_CAP = 3000000000ULL;
constexpr int KCC_PCT_BASE = 100;
constexpr int PCT_BASE = KCC_PCT_BASE;
constexpr int KCC_QDELAY_BP_BASE = 10000;
constexpr int KCC_BITFIELD_3BIT_MAX = 7;
constexpr int KCC_GAIN_MAX = 1023;
constexpr uint32_t KCC_LT_RTT_CNT_MAX = 4095;
constexpr int KCC_KF_CWND_SEGS_MAX = 20000;
constexpr uint64_t KCC_KF_OVERFLOW_GUARD = UINT64_C(1) << 31;
constexpr int KCC_KF_INNOV_SHIFT = 10;
constexpr int KCC_KF_VAR_SHIFT = 20;
constexpr int KCC_SRTT_SHIFT = 3;
constexpr int KCC_RTT_MIN_FLOOR_US = 1;
constexpr int KCC_GAIN_FLOOR = 1;
constexpr int KCC_TSO_DIV_CEIL = (1 << 5);
constexpr int KCC_TSO_DIV_DOUBLE_SHIFT = 1;
constexpr int KCC_CWND_ABSOLUTE_MIN = 1;
constexpr int KCC_G3_FAST_CNT = 6;
constexpr int KCC_G3_SLOW_CNT = 7;
constexpr int KCC_LOCK_THRESH_US = 5000;
constexpr int KCC_FAST_ONLY_THRESH_US = 7500;

// FSM modes
constexpr int KCC_MODE_STARTUP = 0;
constexpr int KCC_MODE_PROBE_BW = 1;
constexpr int KCC_MODE_DRAIN = 2;

// Probe BW cycle
constexpr int KCC_PROBE_BW_CYCLE_LEN = 8;
constexpr int KCC_PROBE_BW_CYCLE_RAND = 7;
constexpr int KCC_HIGH_GAIN = (BBR_UNIT * 2885 / 1000 + 1);
constexpr int STARTUP_HIGH_GAIN = KCC_HIGH_GAIN;
constexpr int KCC_DRAIN_GAIN = (BBR_UNIT * 1000 / 2885);
constexpr int DRAIN_GAIN = KCC_DRAIN_GAIN;
constexpr int KCC_CWND_GAIN = (BBR_UNIT * 2);
constexpr int CWND_GAIN = KCC_CWND_GAIN;
constexpr int KCC_FULL_BW_THRESH = 320;
constexpr int FULL_BW_THRESH = KCC_FULL_BW_THRESH;
constexpr int KCC_FULL_BW_CNT = 3;
constexpr int FULL_BW_CNT = KCC_FULL_BW_CNT;
constexpr int KCC_STALENESS_RNDS = 128;
constexpr int KCC_QDELAY_CLEAN_BP = 1000;
constexpr int KCC_QDELAY_CONG_BP = 2500;
constexpr int KCC_RTT_SAMPLE_MAX_US = 500000;
constexpr int KCC_CWND_MIN_TARGET = 4;
constexpr int CWND_MIN_TARGET = KCC_CWND_MIN_TARGET;
constexpr int KCC_P_EST_INIT = 1000;
constexpr int KCC_P_EST_FLOOR = 10;
constexpr int KCC_P_EST_DECAY_SHIFT = 4;
constexpr int KCC_P_EST_GROWTH_SHIFT = 3;
constexpr int KCC_P_EST_MAX = 1000000;
constexpr int KCC_EWMA_JITTER_NUM = 7;
constexpr int KCC_EWMA_JITTER_DEN = 8;
constexpr int KCC_EWMA_QDELAY_NUM = 7;
constexpr int KCC_EWMA_QDELAY_DEN = 8;
constexpr int KCC_EWMA_NEW_WEIGHT = 1;
constexpr int KCC_MIN_SAMPLES = 5;
constexpr int KCC_ACK_EPOCH_MAX = 0x100000;
constexpr int64_t ACK_EPOCH_MAX = KCC_ACK_EPOCH_MAX;
constexpr int KCC_AGG_WINDOW_ROTATION_RTTS = 5;
constexpr int64_t KCC_BDP_MIN_RTT_US = 1;
constexpr int64_t BDP_MIN_RTT_US = KCC_BDP_MIN_RTT_US;
constexpr int KCC_BW_RT_CYCLE_LEN = 10;
constexpr int KCC_ECN_EWMA_FLOOR = 4;
constexpr int KCC_ECN_EWMA_RETAINED = 3;
constexpr int KCC_ECN_EWMA_TOTAL = 4;
constexpr int KCC_ECN_IDLE_DECAY_NUM = 31;
constexpr int KCC_ECN_IDLE_DECAY_DEN = 32;
constexpr int KCC_EXTRA_ACKED_MAX_MS_RATIO = 100;
constexpr int64_t EXTRA_ACKED_MAX_MS_RATIO = KCC_EXTRA_ACKED_MAX_MS_RATIO;
constexpr int KCC_EXTRA_ACKED_WIN_RTTS_MAX = 31;
constexpr int KCC_JITTER_SEED_SHIFT = 2;
constexpr int KCC_KF_CHI2_NUM = 384;
constexpr int KCC_KF_CHI2_DEN = 100;
constexpr int KCC_KF_Q_SHIFT = 20;
constexpr int KCC_KF_STEADY_R_PCT = 5;
constexpr int KCC_KF_STARTUP_R_PCT = 15;
constexpr int KCC_LT_INTVL_MIN_RTTS = 4;
constexpr int KCC_LT_LOSS_THRESH = 50;
constexpr int KCC_LT_BW_RATIO_NUM = 1;
constexpr int KCC_LT_BW_RATIO_DEN = 8;
constexpr int KCC_LT_BW_RATIO = (BBR_UNIT * KCC_LT_BW_RATIO_NUM) / KCC_LT_BW_RATIO_DEN;
constexpr int KCC_LT_BW_DIFF = 500;
constexpr int KCC_LT_BW_MAX_RTTS = 48;
constexpr int KCC_LT_BW_EMA_NUM = 1;
constexpr int KCC_LT_BW_EMA_DEN = 2;
constexpr int KCC_LT_BW_ITHRESH = 5000;
constexpr int KCC_LT_INTVL_MAX_MULT = 4;
constexpr int KCC_MIN_TSO_RATE = 1200000;
constexpr int64_t UCP_MIN_TSO_RATE_BPS = KCC_MIN_TSO_RATE;
constexpr int KCC_MIN_TSO_RATE_DIV = 8;
constexpr int KCC_MINRTT_FAST_FALL_CNT = 5;
constexpr int KCC_MINRTT_FAST_FALL_DIV = 4;
constexpr int KCC_MINRTT_SRTT_GUARD_NUM = 90;
constexpr int KCC_MINRTT_SRTT_GUARD_DEN = 100;
constexpr int KCC_MINRTT_STICKY_NUM = 75;
constexpr int KCC_MINRTT_STICKY_DEN = 100;
constexpr int KCC_PROBE_CWND_BONUS = 2;
constexpr int KCC_QDELAY_FLOOR_US = 500;
constexpr int KCC_DEFAULT_RTT_US = 1000;
constexpr int KCC_PACING_INIT_GAIN = 739;
constexpr int KCC_TSO_HEADROOM_MULT = 3;
constexpr int KCC_TSO_HIGH_JITTER_THRESH_US = 4000;
constexpr int KCC_TSO_MAX_SEGS = 127;
constexpr int TSO_MAX_SEGS = KCC_TSO_MAX_SEGS;
constexpr int KCC_TSO_SEGS_DEFAULT = 2;
constexpr int TSO_SEGS_DEFAULT = KCC_TSO_SEGS_DEFAULT;
constexpr int KCC_TSO_SEGS_LOW = 1;

// ECN (default disabled, KCC2.0)
#define KCC_ECN_ENABLED 0
constexpr int ECN_ENABLE = KCC_ECN_ENABLED;
constexpr int ECN_BACKOFF_NUM = 20;
constexpr int ECN_BACKOFF_DEN = 100;
constexpr int KF_DISCOUNT_NUM = 50;
constexpr int KF_DISCOUNT_DEN = 100;
constexpr int DRAIN_AND_OR_MODE = 1;
constexpr int EXTRA_ACKED_GAIN_NUM = 1;
constexpr int EXTRA_ACKED_GAIN_DEN = 1;
constexpr int GAIN_SLOTS = 256;
constexpr int KCC_GAIN_MAX_DISPLAY = KCC_GAIN_MAX;

// CA states
constexpr int CA_OPEN = 0;
constexpr int CA_RECOVERY = 2;
constexpr int CA_LOSS = 3;
constexpr uint32_t MIN_RTT_UNINIT = ~0U;

// Gain cycle phases
constexpr int GAIN_PROBE_PHASE_NUM = 5;
constexpr int GAIN_PROBE_PHASE_DEN = 4;
constexpr int GAIN_DRAIN_PHASE_NUM = 3;
constexpr int GAIN_DRAIN_PHASE_DEN = 4;
constexpr int GAIN_CRUISE_PHASE_NUM = 1;
constexpr int GAIN_CRUISE_PHASE_DEN = 1;
constexpr int64_t EDT_NEAR_NOW_NS = 1000;

// Protocol constants (UCP protocol layer)
constexpr int MSS = 1220;
constexpr int DATA_HEADER_SIZE = 20;
constexpr int64_t kInitialBandwidthBps = 12500000;
constexpr uint32_t HALF_SEQUENCE_SPACE = 2147483648U;
constexpr int MaxBufferedFairQueueRounds = 4;
constexpr int64_t DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND = 12500000;
constexpr int64_t MIN_RTO_MICROS = 50000;
constexpr int64_t DEFAULT_RTO_MICROS = 50000;
constexpr int CommonHeaderSize = 12;
constexpr int MaxAckSackBlocks = 149;
constexpr int64_t DEFAULT_MAX_RTO_MICROS = 15000000;
constexpr double RTO_BACKOFF_FACTOR = 1.2;
constexpr int INITIAL_CWND_PACKETS = 10;
constexpr int DEFAULT_ACK_SACK_BLOCK_LIMIT = 2;
constexpr double DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT = 25.0;
constexpr double MIN_MAX_BANDWIDTH_LOSS_PERCENT = 15.0;
constexpr double MAX_MAX_BANDWIDTH_LOSS_PERCENT = 35.0;
constexpr int ACK_FIXED_SIZE = 28;
constexpr int SACK_BLOCK_SIZE = 8;
constexpr int64_t INITIAL_RTO_MICROS = 50000;
constexpr int RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER = 2;
constexpr int RTT_SMOOTHING_PREVIOUS_WEIGHT = 7;
constexpr int RTT_SMOOTHING_DENOM = 8;
constexpr int RTT_VAR_PREVIOUS_WEIGHT = 3;
constexpr int RTT_VAR_DENOM = 4;
constexpr int RTO_GAIN_MULTIPLIER = 4;
constexpr int64_t NANOS_PER_MILLI = 1000000;
constexpr int64_t TIMER_INTERVAL_MILLIS_DEFAULT = 1;
constexpr int64_t MAX_RTO_MICROS = 60000000;
constexpr int DATA_HEADER_SIZE_WITH_ACK = 36;
constexpr int64_t DEFAULT_PACING_BUCKET_DURATION_MICROS = 10000;
constexpr int64_t DEFAULT_PACING_WAIT_MICROS = 1000;
constexpr int BYTE_BITS = 8;
constexpr int UINT16_BITS = 16;
constexpr int UINT24_BITS = 24;
constexpr int UINT32_BITS = 32;
constexpr int UINT40_BITS = 40;
constexpr uint64_t UINT48_MASK = 0xFFFFFFFFFFFFULL;
constexpr int UINT48_BITS = 48;
constexpr int UINT56_BITS = 56;
constexpr int COMMON_HEADER_SIZE = 12;
constexpr int PACKET_TYPE_FIELD_SIZE = 1;
constexpr int PACKET_FLAGS_FIELD_SIZE = 1;
constexpr int CONNECTION_ID_SIZE = 4;
constexpr int ACK_NUMBER_SIZE = 4;
constexpr int SEQUENCE_NUMBER_SIZE = 4;
constexpr int ACK_TIMESTAMP_FIELD_SIZE = 6;
constexpr int MAX_ACK_SACK_BLOCKS = (MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE;
constexpr int NAK_FIXED_SIZE = 18;
constexpr int MAX_NAK_SEQUENCES_PER_PACKET = 256;
constexpr int INITIAL_RTTVAR_DIVISOR = 2;
constexpr int FEC_MAX_SEND_GROUPS = 16;
constexpr int FEC_MAX_RECV_GROUPS = 16;
constexpr int FEC_MAX_REPAIR_GROUPS = 16;

} // namespace Constants
} // namespace ucp
