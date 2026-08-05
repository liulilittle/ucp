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

/** @file ucp_transfer_report.h
 *  @brief UcpTransferReport type re-export and bandwidth calculation utilities.
 *
 *  The canonical definition of UcpTransferReport lives in ucp_types.h.
 *  This header exists for backward compatibility -- code that previously
 *  included ucp_transfer_report.h will still find the type through
 *  ucp_types.h.  Additionally, this header provides bandwidth calculation
 *  helper functions commonly used with transfer report data.
 */

#include "ucp_types.h"

namespace ucp {

static constexpr double kMicrosPerSecond = 1000000.0;
static constexpr double kBitsPerByte = 8.0;

/** @brief Calculate bandwidth in bytes per second from transferred byte count and elapsed time.
 *  @param bytes          Number of bytes transferred.
 *  @param elapsedMicros  Time elapsed during the transfer in microseconds.
 *  @return Bandwidth in bytes per second, or 0.0 if elapsedMicros is zero to avoid division by zero. */
inline double CalculateBandwidthBytesPerSecond(int64_t bytes, int64_t elapsedMicros) noexcept {
    if (0 == elapsedMicros) {
        return 0.0;
    }
    return static_cast<double>(bytes) * kMicrosPerSecond / static_cast<double>(elapsedMicros);
}

/** @brief Calculate bandwidth in megabits per second from byte count and elapsed time.
 *  @param bytes          Number of bytes transferred.
 *  @param elapsedMicros  Time elapsed during the transfer in microseconds.
 *  @return Bandwidth in megabits per second, or 0.0 if elapsedMicros is zero. */
inline double CalculateBandwidthMegabitsPerSecond(int64_t bytes, int64_t elapsedMicros) noexcept {
    return CalculateBandwidthBytesPerSecond(bytes, elapsedMicros) * kBitsPerByte / kMicrosPerSecond;
}

} // namespace ucp
