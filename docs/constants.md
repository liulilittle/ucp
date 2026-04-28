# UCP Constants

The implementation keeps protocol-level constants in `UcpConstants`. Names use `UPPER_SNAKE_CASE` for C++ portability and to make unit boundaries explicit.

## Time Units

- `MICROS_PER_MILLI`: microseconds in one millisecond.
- `MICROS_PER_SECOND`: microseconds in one second.
- `NANOS_PER_MICRO`: nanoseconds in one microsecond.

## Packet Layout

- `MSS`: protocol maximum segment size in bytes.
- `COMMON_HEADER_SIZE`, `DATA_HEADER_SIZE`, `ACK_FIXED_SIZE`, `NAK_FIXED_SIZE`: encoded packet sizes in bytes.
- `SACK_BLOCK_SIZE`, `SEQUENCE_NUMBER_SIZE`, `CONNECTION_ID_SIZE`: encoded field sizes in bytes.
- `UCP_*_TYPE_VALUE` and `UCP_FLAG_*_VALUE`: wire values for packet types and flags.

## RTO And Loss Recovery

- `DEFAULT_RTO_MICROS`: optimized minimum RTO used by default configuration.
- `INITIAL_RTO_MICROS`: initial RTO before RTT samples are available.
- `DEFAULT_MAX_RTO_MICROS`: optimized maximum RTO.
- `RTO_BACKOFF_FACTOR`: retransmission timeout backoff multiplier.
- `RTT_SMOOTHING_DENOM`, `RTT_VAR_DENOM`, `RTO_GAIN_MULTIPLIER`: RTT/RTO filter coefficients.
- `DUPLICATE_ACK_THRESHOLD`: duplicate ACK/SACK threshold for fast retransmit.
- `NAK_MISSING_THRESHOLD`: receiver missing-observation threshold before emitting NAK.
- `MAX_NAK_MISSING_SCAN`: maximum forward sequence slots scanned when updating missing state.

## BBR

- `BBR_STARTUP_PACING_GAIN`, `BBR_STARTUP_CWND_GAIN`, `BBR_DRAIN_PACING_GAIN`: startup and drain gains.
- `BBR_PROBE_BW_HIGH_GAIN`, `BBR_PROBE_BW_LOW_GAIN`, `BBR_PROBE_BW_CWND_GAIN`: ProbeBW gains.
- `BBR_PROBE_RTT_PACING_GAIN`: ProbeRTT pacing gain.
- `BBR_PROBE_RTT_INTERVAL_MICROS`, `BBR_PROBE_RTT_DURATION_MICROS`: minimum RTT refresh timing.
- `BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER`: acceptable RTT sample multiplier for ProbeRTT exit.
- `BBR_*_LOSS_RATIO`: recent loss ratio thresholds used for dynamic pacing gain.

## Reporting

- Internal bandwidth remains bytes per second.
- User-facing reports convert throughput, target bandwidth, and pacing rate to Mbps.
- Probability-like values are displayed as percentages.
