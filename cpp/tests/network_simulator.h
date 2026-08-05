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

/** @file network_simulator.h
 *  @brief In-process network simulator for UCP integration tests.
 *
 *  Provides deterministic packet routing, delay, jitter, bandwidth serialization,
 *  loss, duplication, and reordering without real sockets.  Multiple simulated
 *  transports share a single simulator instance so multi-connection tests run
 *  on one logical network.
 *
 *  Modeled after the C# NetworkSimulator in Ucp.Tests/TestTransport/NetworkSimulator.cs.
 */

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <thread>

#include "ucp/ucp_vector.h"

namespace ucp_test {

constexpr int DEFAULT_SIMULATOR_SEED = 1234;

constexpr int HIGH_BANDWIDTH_THRESHOLD = 10 * 1024 * 1024;

/** @brief A single packet in transit through the simulated network.
 *
 *  The raw payload is deep-copied at send time so callers may reuse or free
 *  their buffer immediately after Send(). */
struct SimulatedDatagram {
    ucp::vector<uint8_t> buffer;
    int count = 0;
    int source_port = 0;
    int destination_port = 0;
    int64_t send_micros = 0;
    int64_t logical_due_micros = 0;
    bool forward_direction = true;

    /** @brief Creates a deep copy of this datagram.
     *
     *  The buffer vector is deep-copied by ucp::vector's copy constructor.
     *  @return A new SimulatedDatagram with an independent copy of the buffer. */
    SimulatedDatagram Clone() const noexcept {
        SimulatedDatagram d = *this;
        return d;
    }
};

/** @brief Custom predicate that decides whether a specific datagram should be dropped.
 *
 *  Return true to drop the datagram, false to keep it. */
using DropRule = ucp::function<bool(const SimulatedDatagram&)>;

/** @brief Deterministic in-process network simulator.
 *
 *  Models bidirectional packet routing with independent forward/reverse delay,
 *  jitter, bandwidth shaping, uniform random loss, custom drop rules, packet
 *  duplication, and reordering. */
class NetworkSimulator {
  public:
    NetworkSimulator(const NetworkSimulator&) = delete;
    NetworkSimulator& operator=(const NetworkSimulator&) = delete;
    NetworkSimulator(NetworkSimulator&&) = delete;
    NetworkSimulator& operator=(NetworkSimulator&&) = delete;

    /** @brief Constructs the simulator with configurable impairment parameters.
     *
     *  All directional parameters (forward/backward delay/jitter) fall back to
     *  their symmetric counterparts when passed as -1.
     *  @param loss_rate Uniform random packet loss probability (0.0 to 1.0).
     *  @param fixed_delay_ms Base one-way propagation delay in milliseconds.
     *  @param jitter_ms Random jitter range (+/-) in milliseconds.
     *  @param bandwidth_bytes_per_sec Serialized link bandwidth; 0 disables bandwidth shaping.
     *  @param seed Deterministic PRNG seed.
     *  @param drop_rule Optional per-packet drop predicate (takes precedence over uniform loss).
     *  @param duplicate_rate Probability (0-1) of duplicating each packet.
     *  @param reorder_rate Probability (0-1) of reordering each packet (adds extra delay).
     *  @param forward_delay_ms One-way forward delay; -1 falls back to fixed_delay_ms.
     *  @param backward_delay_ms One-way reverse delay; -1 falls back to fixed_delay_ms.
     *  @param forward_jitter_ms Forward jitter range; -1 falls back to jitter_ms.
     *  @param backward_jitter_ms Reverse jitter range; -1 falls back to jitter_ms.
     *  @param dynamic_jitter_range_ms Per-packet dynamic jitter range.
     *  @param dynamic_wave_amp_ms Sinusoidal wave jitter amplitude.
     *  @param direction_skew_ms Additional skew (positive forward, negative reverse). */
    NetworkSimulator(double loss_rate = 0, int fixed_delay_ms = 0, int jitter_ms = 0, int bandwidth_bytes_per_sec = 0,
                     int seed = DEFAULT_SIMULATOR_SEED, DropRule drop_rule = NULLPTR, double duplicate_rate = 0, double reorder_rate = 0,
                     int forward_delay_ms = -1, int backward_delay_ms = -1, int forward_jitter_ms = -1, int backward_jitter_ms = -1,
                     int dynamic_jitter_range_ms = 1, int dynamic_wave_amp_ms = 0, int direction_skew_ms = 0) noexcept;

    ~NetworkSimulator() noexcept;

    /** @brief Stops the background scheduler thread and waits for it to join.
     *
     *  After this call returns, no further deliveries will occur. Must be called
     *  before deleting transports that were registered with this simulator. */
    void StopScheduler() noexcept;

    double LossRate() const noexcept { return _loss_rate; }
    int FixedDelayMilliseconds() const noexcept { return _fixed_delay_ms; }
    int JitterMilliseconds() const noexcept { return _jitter_ms; }
    int ForwardDelayMilliseconds() const noexcept { return _forward_delay_ms; }
    int BackwardDelayMilliseconds() const noexcept { return _backward_delay_ms; }
    int ForwardJitterMilliseconds() const noexcept { return _forward_jitter_ms; }
    int BackwardJitterMilliseconds() const noexcept { return _backward_jitter_ms; }
    int BandwidthBytesPerSecond() const noexcept { return _bandwidth_bytes_per_sec; }

    int64_t SentPackets() const noexcept { return _sent_packets; }
    int64_t SentDataPackets() const noexcept { return _sent_data_packets; }
    int64_t DroppedPackets() const noexcept { return _dropped_packets; }
    int64_t DroppedDataPackets() const noexcept { return _dropped_data_packets; }
    int64_t DeliveredPackets() const noexcept { return _delivered_packets; }
    int64_t DeliveredDataPackets() const noexcept { return _delivered_data_packets; }
    int64_t DeliveredBytes() const noexcept { return _delivered_bytes; }
    int64_t DuplicatedPackets() const noexcept { return _duplicated_packets; }
    int64_t ReorderedPackets() const noexcept { return _reordered_packets; }

    /** @brief Percentage of total packets dropped (requires lock).
     *  @return (dropped / sent) * 100, or 0.0 if no packets were sent. */
    double ObservedPacketLossPercent() const noexcept;

    /** @brief Percentage of DATA packets dropped (requires lock).
     *  @return (dropped_data / sent_data) * 100, or 0.0 if no DATA packets were sent. */
    double ObservedDataLossPercent() const noexcept;

    /** @brief Logical throughput using a virtual clock to avoid OS scheduling jitter.
     *
     *  For high-bandwidth links (>= 10 MB/s), uses a virtual logical clock that
     *  factors out OS scheduling jitter but still respects serialization and
     *  propagation delays.  Capped at the configured bottleneck bandwidth.
     *  @return Effective throughput in bytes per second. */
    double LogicalThroughputBytesPerSecond() const noexcept;

    /** @brief Average one-way forward delay in microseconds.
     *  @return Arithmetic mean of collected forward latency samples, or 0 if none. */
    int64_t AverageForwardDelayMicros() const noexcept;

    /** @brief Average one-way reverse delay in microseconds.
     *  @return Arithmetic mean of collected reverse latency samples, or 0 if none. */
    int64_t AverageReverseDelayMicros() const noexcept;

    /** @brief Snapshot of all collected end-to-end latency samples.
     *  @return A copy of the internal latency-samples vector (thread-safe). */
    ucp::vector<int64_t> LatencySamplesMicros() const noexcept;

    /** @brief Runtime reconfiguration -- resets directional params to symmetric values.
     *  @param loss_rate New uniform loss rate.
     *  @param fixed_delay_ms New symmetric base delay.
     *  @param jitter_ms New symmetric jitter range.
     *  @param bandwidth_bytes_per_sec New bottleneck bandwidth.
     *  @param duplicate_rate New duplication probability.
     *  @param reorder_rate New reorder probability. */
    void Reconfigure(double loss_rate, int fixed_delay_ms, int jitter_ms, int bandwidth_bytes_per_sec, double duplicate_rate,
                     double reorder_rate) noexcept;

    struct SimulatedTransport;

    /** @brief Allocates a new endpoint on this simulator.
     *
     *  The caller owns the returned pointer and must eventually delete it.
     *  @param name Human-readable debug identifier for the transport.
     *  @return Heap-allocated SimulatedTransport bound to this simulator. */
    SimulatedTransport* CreateTransport(const ucp::string& name) noexcept;

    /** @brief Registers a transport in the port registry.
     *
     *  If @p port is 0, an auto-assigned port is chosen from a monotonic counter.
     *  @param transport The transport to bind.
     *  @param port Desired port (0 = auto-assign).
     *  @return The actual port number assigned. */
    int BindTransport(SimulatedTransport* transport, int port) noexcept;

    /** @brief Removes a transport from the registry.
     *  @param port The port number to unbind. */
    void UnbindTransport(int port) noexcept;

    /** @brief Injects a datagram into the simulated network.
     *
     *  Called by SimulatedTransport::Send().  Copies the buffer, applies all
     *  impairments, and schedules delivery via the background scheduler.
     *  @param sender The sending transport.
     *  @param data Pointer to raw packet bytes (deep-copied immediately).
     *  @param length Number of valid bytes in @p data.
     *  @param remote_port Destination port number. */
    void SendAsync(SimulatedTransport* sender, const uint8_t* data, int length, int remote_port) noexcept;

    /** @brief Waits until at least @p minPackets packets have been delivered (event-driven).
     *
     *  Uses a condition_variable that is notified on every delivery, so this
     *  does NOT busy-wait.  Returns true if the threshold was reached within
     *  the timeout; false on timeout.  Also aborts early if the optional abort
     *  signal is set (for test timeout handling).
     *  @param minPackets Minimum number of delivered packets to wait for.
     *  @param timeoutMilliseconds Maximum wait time in milliseconds.
     *  @return true if delivered >= minPackets within the timeout. */
    bool WaitForDeliveryCount(int64_t minPackets, int timeoutMilliseconds) noexcept;

    /** @brief Sets an optional abort signal pointer. When non-null and the
     *  pointed-to atomic is true, WaitForDeliveryCount returns false immediately.
     *  Used by the test framework to break out of waits on global timeout. */
    void SetAbortSignal(const std::atomic<bool>* signal) noexcept { _abort_signal = signal; }

  private:
    /** @brief Coalescing window in microseconds.
     *
     *  Datagrams due within this many microseconds of "now" are delivered
     *  immediately without sleeping. */
    static constexpr int64_t kSchedulerCoalescingMicros = 1000;

    /** @brief Idle-gap threshold for the logical clock in microseconds.
     *
     *  If a logical sender has been idle longer than this, its clock resets
     *  to the current wall-clock time. */
    static constexpr int64_t kLogicalSenderIdleGapMicros = 500000;

    /** @brief Bandwidth threshold above which the virtual logical clock is used.
     *
     *  When the configured bandwidth meets or exceeds 10 MB/s, the throughput
     *  computation switches from real-clock to virtual-logical-clock. */
    static constexpr int kHighBandwidthLogicalClockThreshold = HIGH_BANDWIDTH_THRESHOLD;

    static constexpr int kDynamicWavePeriodMs = 5000;

    /** @brief Decides whether a datagram should be dropped.
     *
     *  Custom drop rules take precedence over uniform random loss.
     *  @param datagram The datagram to evaluate.
     *  @return true if the datagram should be dropped. */
    bool ShouldDrop(const SimulatedDatagram& datagram) noexcept;

    /** @brief Computes real-clock and logical-clock delivery due times.
     *
     *  Accounts for fixed delay, random jitter, dynamic jitter, sinusoidal wave
     *  jitter, directional skew, and bandwidth serialization.
     *  @param bytes Number of bytes in the packet.
     *  @param forward true if this is a forward-direction transmission.
     *  @param now_us Current wall-clock time (captured by caller to avoid double-call to WallClockMicros).
     *  @param[out] due_micros Real-clock delivery due timestamp.
     *  @param[out] logical_due_micros Logical-clock delivery due timestamp. */
    void CalculateDueMicros(int bytes, bool forward, int64_t now_us, int64_t& due_micros, int64_t& logical_due_micros) noexcept;

    /** @brief Inserts a datagram into the sorted delivery schedule.
     *
     *  Starts the background scheduler thread on the first delivery and signals
     *  the scheduler condition variable.
     *  @param datagram The datagram to schedule (moved into the schedule).
     *  @param due_micros Real-clock delivery due timestamp. */
    void ScheduleDelivery(SimulatedDatagram datagram, int64_t due_micros) noexcept;

    /** @brief Routes a datagram to its destination transport and records stats.
     *  @param datagram The datagram to deliver. */
    void Deliver(const SimulatedDatagram& datagram) noexcept;

    /** @brief Checks whether a buffer contains a UCP DATA packet.
     *
     *  A DATA packet is identified by having its first byte set to 0x05.
     *  @param buffer Raw packet bytes.
     *  @param count Number of valid bytes.
     *  @return true if this is a DATA packet. */
    static bool IsDataPacket(const uint8_t* buffer, int count) noexcept;

    /** @brief Extracts (connectionId:sequenceNumber) key from a DATA packet.
     *
     *  Used for deduplication in logical-throughput tracking.  The key has the
     *  format "connId:seqNum".  Payload bytes = total bytes - 20 (header size).
     *  @param buffer Raw packet bytes.
     *  @param count Number of valid bytes.
     *  @param[out] key The composite dedup key.
     *  @param[out] payload_bytes Number of payload bytes extracted.
     *  @return true if the buffer was a valid DATA packet. */
    static bool TryGetDataPacketIdentity(const uint8_t* buffer, int count, ucp::string& key, int& payload_bytes) noexcept;

    /** @brief Reads a 32-bit big-endian unsigned integer from a buffer.
     *  @param buffer The byte buffer.
     *  @param offset Starting offset in the buffer.
     *  @return The decoded uint32_t value. */
    static uint32_t ReadUInt32BigEndian(const uint8_t* buffer, int offset) noexcept;

    /** @brief Computes the arithmetic mean of a vector of int64_t samples.
     *  @param samples The sample vector.
     *  @return The arithmetic mean, or 0 if the vector is empty. */
    static int64_t AverageMicros(const ucp::vector<int64_t>& samples) noexcept;

    /** @brief Background thread entry point -- polls the delivery schedule.
     *
     *  Wakes periodically or when signalled, delivers packets whose due time
     *  has arrived within the coalescing window, and exits when the stop flag
     *  is set and the schedule is empty. */
    void SchedulerLoop() noexcept;

    const std::atomic<bool>* _abort_signal{nullptr};
    mutable std::mutex _sync;

    std::mt19937 _rng;

    double _loss_rate = 0;
    int _fixed_delay_ms = 0;
    int _jitter_ms = 0;
    int _forward_delay_ms = 0;
    int _backward_delay_ms = 0;
    int _forward_jitter_ms = 0;
    int _backward_jitter_ms = 0;
    int _dynamic_jitter_range_ms = 1;
    int _dynamic_wave_amp_ms = 0;
    int _direction_skew_ms = 0;
    int _bandwidth_bytes_per_sec = 0;
    double _duplicate_rate = 0;
    double _reorder_rate = 0;

    DropRule _drop_rule;

    ucp::unordered_map<int, SimulatedTransport*> _transports;
    ucp::vector<int64_t> _latency_samples;
    ucp::vector<int64_t> _forward_latency_samples;
    ucp::vector<int64_t> _reverse_latency_samples;
    ucp::unordered_set<ucp::string> _logical_data_keys;

    ucp::map<int64_t, ucp::vector<SimulatedDatagram>> _scheduled;
    int _next_port = 30000;

    int64_t _next_forward_tx_available = 0;
    int64_t _next_reverse_tx_available = 0;

    int64_t _forward_serial_rem_ns = 0;
    int64_t _reverse_serial_rem_ns = 0;

    int64_t _next_forward_logical_tx = 0;
    int64_t _next_reverse_logical_tx = 0;

    int64_t _forward_logical_rem_ns = 0;
    int64_t _reverse_logical_rem_ns = 0;

    std::atomic<int64_t> _sent_packets{0};
    std::atomic<int64_t> _sent_data_packets{0};
    std::atomic<int64_t> _dropped_packets{0};
    std::atomic<int64_t> _dropped_data_packets{0};
    std::atomic<int64_t> _delivered_packets{0};
    std::atomic<int64_t> _delivered_data_packets{0};
    std::atomic<int64_t> _delivered_bytes{0};
    std::atomic<int64_t> _duplicated_packets{0};
    std::atomic<int64_t> _reordered_packets{0};

    std::atomic<int64_t> _first_data_send_micros{0};
    std::atomic<int64_t> _last_data_scheduled_micros{0};
    std::atomic<int64_t> _logical_data_bytes{0};

    bool _scheduler_running = false;
    std::thread _scheduler_thread;
    std::condition_variable _scheduler_cv;
    std::condition_variable _delivery_cv;
    bool _stop_scheduler = false;
    std::atomic<bool> _force_stop{false};
    std::atomic<bool> _disposed{false};
};

/** @brief An endpoint (transport) on the simulated network.
 *
 *  Owned by the test code (heap-allocated via NetworkSimulator::CreateTransport).
 *  Injects data into the simulated network via Send() and receives inbound data
 *  through an optional callback. */
struct NetworkSimulator::SimulatedTransport {
    NetworkSimulator* simulator;
    ucp::string name;
    int local_port = 0;
    bool disposed = false;

    using OnDatagramFn = ucp::function<void(const uint8_t*, int, int)>;
    OnDatagramFn on_datagram;

    SimulatedTransport(const SimulatedTransport&) = delete;
    SimulatedTransport& operator=(const SimulatedTransport&) = delete;
    SimulatedTransport(SimulatedTransport&&) = delete;
    SimulatedTransport& operator=(SimulatedTransport&&) = delete;

    /** @brief Constructs a transport bound to the given simulator.
     *  @param sim The parent NetworkSimulator instance.
     *  @param n Human-readable debug name. */
    SimulatedTransport(NetworkSimulator* sim, const ucp::string& n) noexcept;

    /** @brief Binds this transport to a port (0 = auto-assign).
     *
     *  Idempotent -- subsequent calls on an already-bound transport are no-ops.
     *  @param port Desired port, or 0 for automatic assignment. */
    void Start(int port) noexcept;

    /** @brief Sends data through the parent simulator.
     *
     *  Auto-binds to an ephemeral port if Start() has not been called yet.
     *  Silently discards the data if the transport has been disposed.
     *  @param data Raw bytes to send (deep-copied immediately).
     *  @param length Number of valid bytes.
     *  @param remote_port Destination port number. */
    void Send(const uint8_t* data, int length, int remote_port) noexcept;

    void Stop() noexcept;

    /** @brief Marks this transport as disposed and unbinds it.
     *
     *  Idempotent -- safe to call multiple times. */
    void Dispose() noexcept;

    /** @brief Called by the simulator to deliver inbound data.
     *
     *  Invokes the on_datagram callback if set; discards the data if the
     *  transport has been disposed.
     *  @param datagram The inbound datagram to enqueue. */
    void Enqueue(const SimulatedDatagram& datagram) noexcept;
};

} // namespace ucp_test
