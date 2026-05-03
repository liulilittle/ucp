#pragma once

/** @file ucp_time.h
 *  @brief High-resolution clock utilities — mirrors C# Ucp.Internal.Stopwatch / NowMicros.
 *
 *  UCP timestamps all packets with microsecond-precision wall-clock values
 *  (48-bit echo timestamps).  This class provides a global steady-clock
 *  reference shared by the entire protocol stack so that all RTT, RTO, and
 *  pacing calculations agree on a common time base.
 */

#include <cstdint>

namespace ucp {

/** @brief Monotonic microsecond clock facade used throughout the UCP stack.
 *
 *  All time values in UCP are expressed in microseconds relative to an
 *  arbitrary fixed epoch (steady_clock::now() captured at static init).
 *  This guarantees monotonicity even across NTP adjustments or suspend/resume.
 */
class UcpTime {
public:
    UcpTime() = delete;

    /** @brief High-frequency raw microsecond counter — bypasses the millisecond cache.
     *  @return Microseconds since the fixed epoch, recomputed every call. */
    static int64_t ReadStopwatchMicroseconds();

    /** @brief Cached microsecond clock — updated at most once per millisecond.
     *  @return Cached microsecond value suitable for bulk timestamp generation. */
    static int64_t NowMicroseconds();
};

} // namespace ucp
