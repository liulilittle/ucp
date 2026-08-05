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

/** @file ucp_enums.h
 *  @brief Core enumeration types for the UCP protocol -- mirrors C# Ucp.Enums and Ucp.Internal enums.
 *
 *  Defines the on-wire packet types, flag bits, connection state machine states,
 *  QoS priority levels, and the UCP mode enumeration.
 */

#include <cstdint>

namespace ucp {

/** @brief Type tag stored in the first byte (byte 0) of every UCP packet header.
 *
 *  The type field occupies the full first byte.  The decoder uses this tag
 *  to determine which concrete packet class to instantiate.  Values are chosen
 *  to leave room for future control types between the assigned codes.
 *
 *  C# equivalent: internal enum UcpPacketType : byte in UcpEnums.cs.
 */
enum class UcpPacketType : uint8_t {
    Syn = 0x01,
    SynAck = 0x02,
    Ack = 0x03,
    Nak = 0x04,
    Data = 0x05,
    Fin = 0x06,
    Rst = 0x07,
    FecRepair = 0x08,
};

/** @brief Bitfield flags stored in byte 1 of the common header.
 *
 *  Flags control piggybacked-ACK presence, retransmit marking, handshake
 *  completion signalling, and priority levels embedded in the header.
 *  Multiple flags may be OR'd together (e.g., Retransmit | HasAckNumber).
 *
 *  C# equivalent: [Flags] internal enum UcpPacketFlags : byte in UcpEnums.cs.
 */
enum UcpPacketFlags : uint8_t {
    None = 0x00,
    NeedAck = 0x01,
    Retransmit = 0x02,
    FinAck = 0x04,
    HasAckNumber = 0x08,
    PriorityMask = 0x30,
    MtuProbe = 0x40,
    PathChallenge = 0x80,
};

/** @brief State machine states for a UCP connection.
 *
 *  Follows TCP-style transition diagram:
 *  Init -> HandshakeSynSent/SynReceived -> Established -> ClosingFinSent/Received -> Closed.
 *  Each connection transitions through these states exactly once in its lifetime
 *  (unless RST short-circuits the state machine).
 *
 *  C# equivalent: internal enum UcpConnectionState in UcpEnums.cs.
 */
enum class UcpConnectionState {
    Init,
    HandshakeSynSent,
    HandshakeSynReceived,
    Established,
    ClosingFinSent,
    ClosingFinReceived,
    Closed,
};

/** @brief Quality-of-service priority level for outbound segments.
 *
 *  Higher-priority segments are transmitted before lower-priority ones when
 *  the send buffer contains segments at multiple priority levels.  The priority
 *  is encoded in bits [5:4] of the Flags byte (extracted via PriorityMask).
 *
 *  C# equivalent: public enum UcpPriority : byte in UcpEnums.cs.
 */
enum class UcpPriority : uint8_t {
    Background = 0,
    Normal = 1,
    Interactive = 2,
    Urgent = 3,
};

/** @brief UCP congestion-control operating mode.
 *
 *  UCP cycles through three modes: Startup (exponential probing), Drain
 *  (drain the queue built during Startup), and ProbeBw (steady-state cycling
 *  with periodic gain pulses).  This mirrors the KCC (Geodesic Congestion Control)
 *  3-state state machine from tcp_kcc.c (STARTUP/DRAIN/PROBE_BW, no PROBE_RTT).
 *
 *  C# equivalent: internal enum UcpMode in UcpEnums.cs (also referenced in UcpCongestionControl.cs).
 */
enum class UcpMode {
    Startup = 0,
    Drain = 1,
    ProbeBw = 2,
};

} // namespace ucp
