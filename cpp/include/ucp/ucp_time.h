#pragma once

/**
 * MIT License
 *
 * Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file ucp_time.h
 *  @brief High-resolution clock utilities -- mirrors C# Ucp.Internal.Stopwatch / NowMicros.
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

    /** @brief High-frequency raw microsecond counter -- bypasses the millisecond cache.
     *  @return Microseconds since the fixed epoch, recomputed every call. */
    static int64_t ReadStopwatchMicroseconds() noexcept;

    /** @brief Cached microsecond clock -- updated at most once per millisecond.
     *  @return Cached microsecond value suitable for bulk timestamp generation. */
    static int64_t NowMicroseconds() noexcept;
};

} // namespace ucp
