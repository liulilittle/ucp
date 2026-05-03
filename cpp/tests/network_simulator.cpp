// network_simulator.cpp — Implementation of the in-process UCP network simulator
//
// Models bidirectional packet routing with:
//   - Independent forward/reverse delay, jitter, and bandwidth shaping
//   - Uniform random loss + custom drop rules
//   - Packet duplication and reordering
//   - Bandwidth serialization via token-bucket at byte granularity
//   - Virtual logical clock for high-bandwidth throughput measurement
//   - Background scheduler thread for deferred delivery

#include "network_simulator.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <unordered_set>

namespace ucp_test {

// Base wall-clock time used for all microsecond/millisecond timestamps.
// All times are relative to this point to avoid large absolute values.
static std::chrono::steady_clock::time_point g_base_time = std::chrono::steady_clock::now();

// Returns elapsed wall-clock microseconds since process start.
static int64_t WallClockMicros() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now - g_base_time).count();
}

// Returns elapsed wall-clock milliseconds since process start.
static int64_t WallClockMillis() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - g_base_time).count();
}

// ---------------------------------------------------------------------------
// Constructor — initializes all impairment parameters and the deterministic PRNG
// ---------------------------------------------------------------------------
NetworkSimulator::NetworkSimulator(
    double loss_rate, int fixed_delay_ms, int jitter_ms,
    int bandwidth_bytes_per_sec, int seed,
    DropRule drop_rule, double duplicate_rate, double reorder_rate,
    int forward_delay_ms, int backward_delay_ms,
    int forward_jitter_ms, int backward_jitter_ms,
    int dynamic_jitter_range_ms, int dynamic_wave_amp_ms, int direction_skew_ms)
    : _rng(seed)                                         // Seed the deterministic PRNG
    , _loss_rate(loss_rate)                              // Uniform random loss probability
    , _fixed_delay_ms(fixed_delay_ms)                    // Symmetric base delay
    , _jitter_ms(jitter_ms)                              // Symmetric jitter range
    , _forward_delay_ms(forward_delay_ms >= 0 ? forward_delay_ms : fixed_delay_ms)   // Falls back to symmetric
    , _backward_delay_ms(backward_delay_ms >= 0 ? backward_delay_ms : fixed_delay_ms) // Falls back to symmetric
    , _forward_jitter_ms(forward_jitter_ms >= 0 ? forward_jitter_ms : jitter_ms)     // Falls back to symmetric
    , _backward_jitter_ms(backward_jitter_ms >= 0 ? backward_jitter_ms : jitter_ms)   // Falls back to symmetric
    , _dynamic_jitter_range_ms(dynamic_jitter_range_ms)
    , _dynamic_wave_amp_ms(dynamic_wave_amp_ms)
    , _direction_skew_ms(direction_skew_ms)
    , _bandwidth_bytes_per_sec(bandwidth_bytes_per_sec)
    , _duplicate_rate(duplicate_rate)
    , _reorder_rate(reorder_rate)
    , _drop_rule(std::move(drop_rule))                   // Take ownership of the custom drop predicate
{
}

// ---------------------------------------------------------------------------
// Destructor — signals the scheduler thread to stop and joins it
// ---------------------------------------------------------------------------
NetworkSimulator::~NetworkSimulator() {
    {
        std::lock_guard<std::mutex> lock(_sync);  // Acquire lock to set the stop flag
        _stop_scheduler = true;                   // Signal the scheduler loop to exit
    }
    _scheduler_cv.notify_all();   // Wake the scheduler thread so it sees the stop flag
    if (_scheduler_thread.joinable()) {
        _scheduler_thread.join(); // Wait for background thread to finish
    }
}

// ---------------------------------------------------------------------------
// ObservedPacketLossPercent — percentage of total packets dropped
// ---------------------------------------------------------------------------
double NetworkSimulator::ObservedPacketLossPercent() const {
    std::lock_guard<std::mutex> lock(_sync);  // Thread-safe read of counters
    if (_sent_packets == 0) return 0.0;       // Avoid division by zero
    return static_cast<double>(_dropped_packets) * 100.0 / static_cast<double>(_sent_packets);
}

// ---------------------------------------------------------------------------
// ObservedDataLossPercent — percentage of DATA packets dropped
// ---------------------------------------------------------------------------
double NetworkSimulator::ObservedDataLossPercent() const {
    std::lock_guard<std::mutex> lock(_sync);
    if (_sent_data_packets == 0) return 0.0;
    return static_cast<double>(_dropped_data_packets) * 100.0 / static_cast<double>(_sent_data_packets);
}

// ---------------------------------------------------------------------------
// LogicalThroughputBytesPerSecond — computes effective throughput using a
// virtual logical clock for high-bandwidth scenarios to factor out OS
// scheduling jitter while still accounting for serialization and propagation.
// Capped at the configured bottleneck bandwidth.
// ---------------------------------------------------------------------------
double NetworkSimulator::LogicalThroughputBytesPerSecond() const {
    std::lock_guard<std::mutex> lock(_sync);
    if (_logical_data_bytes <= 0) return 0.0;  // No data tracked yet

    double raw = 0.0;

    // Compute raw throughput from wall-clock span if we have timing data
    if (_first_data_send_micros > 0 && _last_data_scheduled_micros > _first_data_send_micros) {
        raw = static_cast<double>(_logical_data_bytes) * 1000000.0
            / static_cast<double>(_last_data_scheduled_micros - _first_data_send_micros);
    }

    // For high-bandwidth links, use the virtual logical clock that factors
    // out OS scheduling jitter but still respects serialization + propagation
    if (_bandwidth_bytes_per_sec >= kHighBandwidthLogicalClockThreshold) {
        int64_t serialization = static_cast<int64_t>(
            std::ceil(static_cast<double>(_logical_data_bytes) * 1000000.0
                      / static_cast<double>(_bandwidth_bytes_per_sec)));
        int64_t duration = std::max<int64_t>(1, serialization + AverageForwardDelayMicros());
        return static_cast<double>(_logical_data_bytes) * 1000000.0 / static_cast<double>(duration);
    }

    // For lower-bandwidth links, cap at the configured bottleneck
    if (_bandwidth_bytes_per_sec > 0 && raw > static_cast<double>(_bandwidth_bytes_per_sec)) {
        return static_cast<double>(_bandwidth_bytes_per_sec);
    }
    return raw;
}

// ---------------------------------------------------------------------------
// Average forward/reverse one-way delay in microseconds
// ---------------------------------------------------------------------------
int64_t NetworkSimulator::AverageForwardDelayMicros() const {
    std::lock_guard<std::mutex> lock(_sync);
    return AverageMicros(_forward_latency_samples);
}

int64_t NetworkSimulator::AverageReverseDelayMicros() const {
    std::lock_guard<std::mutex> lock(_sync);
    return AverageMicros(_reverse_latency_samples);
}

// ---------------------------------------------------------------------------
// LatencySamplesMicros — snapshot of all collected end-to-end RTT samples
// ---------------------------------------------------------------------------
std::vector<int64_t> NetworkSimulator::LatencySamplesMicros() const {
    std::lock_guard<std::mutex> lock(_sync);
    return _latency_samples;  // Returns a copy (thread-safe)
}

// ---------------------------------------------------------------------------
// Reconfigure — runtime update of impairment parameters (resets to symmetric)
// ---------------------------------------------------------------------------
void NetworkSimulator::Reconfigure(double loss_rate, int fixed_delay_ms, int jitter_ms,
                                    int bandwidth_bytes_per_sec, double duplicate_rate, double reorder_rate) {
    std::lock_guard<std::mutex> lock(_sync);
    _loss_rate = loss_rate;
    _fixed_delay_ms = fixed_delay_ms;
    _jitter_ms = jitter_ms;
    _forward_delay_ms = fixed_delay_ms;    // Reset directional params to symmetric
    _backward_delay_ms = fixed_delay_ms;
    _forward_jitter_ms = jitter_ms;
    _backward_jitter_ms = jitter_ms;
    _dynamic_jitter_range_ms = 1;
    _dynamic_wave_amp_ms = 0;
    _direction_skew_ms = 0;
    _bandwidth_bytes_per_sec = bandwidth_bytes_per_sec;
    _duplicate_rate = duplicate_rate;
    _reorder_rate = reorder_rate;
}

// ---------------------------------------------------------------------------
// CreateTransport — allocates a new SimulatedTransport for this simulator
// ---------------------------------------------------------------------------
NetworkSimulator::SimulatedTransport* NetworkSimulator::CreateTransport(const std::string& name) {
    auto* t = new SimulatedTransport(this, name);  // Heap-allocated; caller owns and must delete
    return t;
}

// ---------------------------------------------------------------------------
// BindTransport — registers a transport in the port registry
// ---------------------------------------------------------------------------
int NetworkSimulator::BindTransport(SimulatedTransport* transport, int port) {
    std::lock_guard<std::mutex> lock(_sync);
    if (port == 0) {
        port = ++_next_port;  // Auto-assign from the monotonic counter
    }
    _transports[port] = transport;  // Register in the port -> transport map
    return port;
}

// ---------------------------------------------------------------------------
// UnbindTransport — removes a transport from the registry
// ---------------------------------------------------------------------------
void NetworkSimulator::UnbindTransport(int port) {
    std::lock_guard<std::mutex> lock(_sync);
    _transports.erase(port);
}

// ---------------------------------------------------------------------------
// SendAsync — the main entry point for injecting datagrams into the simulator.
// Copies the buffer immediately, applies all impairments (drop, duplicate,
// reorder), computes the delivery due time including bandwidth serialization,
// and schedules delivery via the background scheduler.
// ---------------------------------------------------------------------------
void NetworkSimulator::SendAsync(SimulatedTransport* sender, const uint8_t* data, int length, int remote_port) {
    // Build the datagram metadata
    SimulatedDatagram datagram;
    datagram.buffer.assign(data, data + length);           // Deep-copy the payload
    datagram.count = length;
    datagram.source_port = sender->local_port;
    datagram.destination_port = remote_port;
    datagram.send_micros = WallClockMicros();               // Record injection time
    datagram.forward_direction = (sender->local_port <= remote_port);  // Port-based direction heuristic

    bool drop = false;
    int64_t due_micros = 0;
    int64_t logical_due = 0;
    bool duplicate = false;
    bool reorder = false;

    {
        std::lock_guard<std::mutex> lock(_sync);
        bool is_data = IsDataPacket(data, length);  // Check first byte == 0x05

        _sent_packets++;                            // Increment total send counter
        if (is_data) _sent_data_packets++;          // Increment data packet counter

        // Step 1: Decide whether to drop this packet
        drop = ShouldDrop(datagram);
        if (drop) {
            _dropped_packets++;
            if (is_data) _dropped_data_packets++;
            return;  // Dropped — don't schedule delivery
        }

        // Step 2: Compute delivery due time (delay + jitter + bandwidth serialization)
        CalculateDueMicros(length, datagram.forward_direction, due_micros, logical_due);
        datagram.logical_due_micros = logical_due;

        // Step 3: Randomly decide to duplicate (with uniform probability check)
        if (_duplicate_rate > 0) {
            std::uniform_real_distribution<double> dist(0.0, 1.0);
            duplicate = dist(_rng) < _duplicate_rate;
            if (duplicate) _duplicated_packets++;
        }

        // Step 4: Randomly decide to reorder (adds extra delay to the primary delivery)
        if (_reorder_rate > 0) {
            std::uniform_real_distribution<double> dist(0.0, 1.0);
            reorder = dist(_rng) < _reorder_rate;
            if (reorder) {
                _reordered_packets++;
                // Extra delay: at least 1ms more than the maximum expected propagation
                due_micros += std::max<int64_t>(1000,
                    static_cast<int64_t>(_fixed_delay_ms + _jitter_ms + 1) * 1000);
            }
        }
    }  // Release _sync lock before scheduling to avoid deadlock

    // Schedule the primary delivery
    ScheduleDelivery(datagram, due_micros);

    // If duplicating, schedule a second copy with a slight time offset (+1ms)
    if (duplicate) {
        SimulatedDatagram dup = datagram.Clone();  // Clone metadata (buffer is re-copied)
        ScheduleDelivery(dup, due_micros + 1000);
    }
}

// ---------------------------------------------------------------------------
// ShouldDrop — evaluates whether a datagram should be dropped.
// Custom drop rules take precedence over uniform random loss.
// ---------------------------------------------------------------------------
bool NetworkSimulator::ShouldDrop(const SimulatedDatagram& datagram) {
    if (_drop_rule && _drop_rule(datagram)) return true;  // Custom rule says drop
    if (_loss_rate <= 0) return false;                     // No uniform loss configured
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(_rng) < _loss_rate;                         // Uniform random check
}

// ---------------------------------------------------------------------------
// CalculateDueMicros — computes the real-clock and logical-clock delivery due
// times for a packet, accounting for:
//   1. Fixed + random jitter + dynamic jitter + sinusoidal wave + directional skew
//   2. Bandwidth serialization (token-bucket at byte granularity)
//   3. High-bandwidth virtual logical clock
// ---------------------------------------------------------------------------
void NetworkSimulator::CalculateDueMicros(int bytes, bool forward,
                                           int64_t& due_micros, int64_t& logical_due_micros) {
    // Select directional delay and jitter values
    int fixed_ms = forward ? _forward_delay_ms : _backward_delay_ms;
    int jit_ms   = forward ? _forward_jitter_ms  : _backward_jitter_ms;

    // === Random jitter: uniform distribution ± range ===
    int jitter = 0;
    if (jit_ms > 0) {
        std::uniform_int_distribution<int> dist(-jit_ms, jit_ms);  // Range [-jit, +jit]
        jitter = dist(_rng);
    }

    // === Dynamic jitter: additional random component capped at 1/3 of fixed delay ===
    int dyn_jitter = 0;
    if (_dynamic_jitter_range_ms > 0) {
        int cap = std::min(_dynamic_jitter_range_ms, std::max(1, fixed_ms / 3));
        std::uniform_int_distribution<int> dist(-cap, cap);
        dyn_jitter = dist(_rng);
    }

    // === Sinusoidal wave jitter: periodic route fluctuation ===
    // Phase offset: 0 for forward, π/2 for reverse (90° phase shift)
    double phase_offset = forward ? 0.0 : 1.57079632679;
    double wave = 0.0;
    if (_dynamic_wave_amp_ms > 0) {
        int64_t now_us = WallClockMicros();
        // Compute phase based on wall-clock time modulo the wave period
        double phase = (static_cast<double>(now_us % (kDynamicWavePeriodMs * 1000LL))
                       / static_cast<double>(kDynamicWavePeriodMs * 1000LL))
                      * 3.14159265359 * 2.0;
        wave = std::sin(phase + phase_offset) * static_cast<double>(_dynamic_wave_amp_ms);
    }

    // === Directional skew: positive adds to forward, subtracts from reverse ===
    int skew = forward ? _direction_skew_ms : -_direction_skew_ms;
    int eff_skew = std::min(std::abs(skew), fixed_ms * 80 / 100) * (skew >= 0 ? 1 : -1);  // Cap at 80% of fixed delay

    // === Cap wave amplitude relative to fixed delay ===
    double eff_wave = wave * std::min(1.0, static_cast<double>(fixed_ms) / 30.0);

    // === Combine all propagation components ===
    int64_t propagation = static_cast<int64_t>(std::round(
        static_cast<double>(fixed_ms + jitter + dyn_jitter) + eff_wave
        + static_cast<double>(eff_skew)) * 1000.0);
    if (propagation < 0) propagation = 0;  // Clamp to avoid negative propagation

    // Collect direction-specific latency samples
    if (forward) {
        _forward_latency_samples.push_back(propagation);
    } else {
        _reverse_latency_samples.push_back(propagation);
    }

    int64_t now_us = WallClockMicros();
    int64_t tx_complete = now_us;
    int64_t logical_tx_complete = now_us;

    // === Bandwidth serialization (token-bucket at byte granularity) ===
    if (_bandwidth_bytes_per_sec > 0) {
        // Time needed to serialize this packet at the configured bandwidth
        int64_t serial = static_cast<int64_t>(
            std::ceil(static_cast<double>(bytes) * 1000000.0 / static_cast<double>(_bandwidth_bytes_per_sec)));

        // Real-clock token bucket
        int64_t& next_avail = forward ? _next_forward_tx_available : _next_reverse_tx_available;
        if (next_avail < now_us) next_avail = now_us;  // Reset if pipeline is idle
        next_avail += serial;
        tx_complete = next_avail;

        // Virtual logical clock (for high-bandwidth throughput measurement)
        bool use_logical = _bandwidth_bytes_per_sec >= kHighBandwidthLogicalClockThreshold;
        int64_t& next_logical = forward ? _next_forward_logical_tx : _next_reverse_logical_tx;

        if (!use_logical) {
            logical_tx_complete = tx_complete;  // Use real clock for lower-bandwidth links
        } else {
            // Reset logical clock if sender has been idle too long
            if (next_logical == 0 || (now_us - next_logical) > kLogicalSenderIdleGapMicros) {
                next_logical = now_us;
            }
            next_logical += serial;
            logical_tx_complete = next_logical;
        }
    }

    // Final due times: transmit completion + propagation delay
    logical_due_micros = logical_tx_complete + propagation;
    due_micros = tx_complete + propagation;
}

// ---------------------------------------------------------------------------
// ScheduleDelivery — inserts a datagram into the sorted delivery schedule,
// starts the scheduler if needed, and signals the scheduler thread.
// Also tracks logical data bytes for throughput computation (deduplicated).
// ---------------------------------------------------------------------------
void NetworkSimulator::ScheduleDelivery(SimulatedDatagram datagram, int64_t due_micros) {
    int64_t now_us = WallClockMicros();

    {
        std::lock_guard<std::mutex> lock(_sync);
        std::string key;
        int payload_bytes = 0;

        // Track each unique logical DATA packet by (connectionId:sequenceNumber).
        // Retransmissions are deduplicated so throughput is not inflated.
        if (TryGetDataPacketIdentity(datagram.buffer.data(), datagram.count, key, payload_bytes)
            && _logical_data_keys.insert(key).second) {
            if (payload_bytes > 0) _logical_data_bytes += payload_bytes;               // Count payload bytes
            if (_first_data_send_micros == 0) _first_data_send_micros = now_us;         // Record first packet time
            int64_t logical = datagram.logical_due_micros > 0 ? datagram.logical_due_micros : due_micros;
            if (logical > _last_data_scheduled_micros) _last_data_scheduled_micros = logical;  // Latest due time
        }

        // Insert into the sorted delivery schedule
        _scheduled[due_micros].push_back(std::move(datagram));

        // Start the background scheduler thread on first delivery
        if (!_scheduler_running) {
            _scheduler_running = true;
            _stop_scheduler = false;
            _scheduler_thread = std::thread(&NetworkSimulator::SchedulerLoop, this);
        }
    }

    _scheduler_cv.notify_one();  // Wake the scheduler so it checks the new entry
}

// ---------------------------------------------------------------------------
// Deliver — routes a datagram to its destination transport and records stats
// ---------------------------------------------------------------------------
void NetworkSimulator::Deliver(const SimulatedDatagram& datagram) {
    SimulatedTransport* target = nullptr;
    {
        std::lock_guard<std::mutex> lock(_sync);
        auto it = _transports.find(datagram.destination_port);  // Look up by destination port
        if (it != _transports.end()) target = it->second;
    }

    if (target == nullptr) return;  // Destination not registered — silently discard
    target->Enqueue(datagram);      // Push into the transport's inbound queue

    {
        std::lock_guard<std::mutex> lock(_sync);
        _delivered_packets++;
        _delivered_bytes += datagram.count;
        if (IsDataPacket(datagram.buffer.data(), datagram.count)) {
            _delivered_data_packets++;
        }

        // Record end-to-end latency sample (now - send_time)
        int64_t now_us = WallClockMicros();
        int64_t lat = now_us - datagram.send_micros;
        if (lat >= 0) _latency_samples.push_back(lat);
    }
}

// ---------------------------------------------------------------------------
// IsDataPacket — checks whether a buffer contains a UCP DATA packet (first byte 0x05)
// ---------------------------------------------------------------------------
bool NetworkSimulator::IsDataPacket(const uint8_t* buffer, int count) {
    return buffer != nullptr && count > 0 && buffer[0] == 0x05;
}

// ---------------------------------------------------------------------------
// TryGetDataPacketIdentity — extracts (connectionId:sequenceNumber) from a DATA
// packet header for deduplication. Format: buffer[0]=0x05 (DATA type),
// buffer[2..5]=ConnectionId (big-endian), buffer[12..15]=SequenceNumber (big-endian).
// Payload bytes = total bytes - 20 (header size).
// ---------------------------------------------------------------------------
bool NetworkSimulator::TryGetDataPacketIdentity(const uint8_t* buffer, int count,
                                                  std::string& key, int& payload_bytes) {
    key.clear();
    payload_bytes = 0;

    // Must have at least 20 bytes and start with DATA type byte
    if (buffer == nullptr || count <= 20 || buffer[0] != 0x05) return false;

    uint32_t conn_id  = ReadUInt32BigEndian(buffer, 2);   // Connection ID at offset 2
    uint32_t seq_num  = ReadUInt32BigEndian(buffer, 12);  // Sequence number at offset 12
    key = std::to_string(conn_id) + ":" + std::to_string(seq_num);  // Composite key
    payload_bytes = count - 20;  // Everything after 20-byte header is payload
    return true;
}

// ---------------------------------------------------------------------------
// ReadUInt32BigEndian — reads a 32-bit big-endian unsigned integer from a buffer
// ---------------------------------------------------------------------------
uint32_t NetworkSimulator::ReadUInt32BigEndian(const uint8_t* buffer, int offset) {
    return (static_cast<uint32_t>(buffer[offset])     << 24)
         | (static_cast<uint32_t>(buffer[offset + 1]) << 16)
         | (static_cast<uint32_t>(buffer[offset + 2]) << 8)
         |  static_cast<uint32_t>(buffer[offset + 3]);
}

// ---------------------------------------------------------------------------
// AverageMicros — arithmetic mean of int64_t samples (returns 0 for empty set)
// ---------------------------------------------------------------------------
int64_t NetworkSimulator::AverageMicros(const std::vector<int64_t>& samples) {
    if (samples.empty()) return 0;
    int64_t total = 0;
    for (int64_t s : samples) total += s;
    return total / static_cast<int64_t>(samples.size());
}

// ---------------------------------------------------------------------------
// SchedulerLoop — background thread that polls the sorted delivery schedule
// and delivers packets when their due time arrives. Exits when signalled to
// stop and the schedule is empty.
// ---------------------------------------------------------------------------
void NetworkSimulator::SchedulerLoop() {
    while (true) {
        std::vector<SimulatedDatagram> due;
        int wait_ms = -1;

        {
            std::lock_guard<std::mutex> lock(_sync);

            // Exit condition: stop requested AND no more pending deliveries
            if (_stop_scheduler && _scheduled.empty()) {
                _scheduler_running = false;
                return;
            }

            if (!_scheduled.empty()) {
                auto it = _scheduled.begin();
                int64_t due_us = it->first;       // Earliest due timestamp
                int64_t now_us = WallClockMicros();

                // If the due time is within the coalescing window, deliver immediately
                if (due_us <= now_us + kSchedulerCoalescingMicros) {
                    due = std::move(it->second);  // Take ownership of the bucket
                    _scheduled.erase(it);         // Remove from schedule
                } else {
                    // Calculate how long to sleep before the next delivery is due
                    wait_ms = std::max(1,
                        static_cast<int>(std::ceil(static_cast<double>(due_us - now_us) / 1000.0)));
                }
            }
        }

        // Deliver all packets in the due bucket
        if (!due.empty()) {
            for (const auto& d : due) Deliver(d);
            continue;  // Re-check schedule immediately — more may be due
        }

        // Sleep until a signal or timeout
        if (wait_ms < 0) {
            // No known wait time — wait for a signal with a 100ms timeout
            std::unique_lock<std::mutex> cv_lock(_sync);
            _scheduler_cv.wait_for(cv_lock, std::chrono::milliseconds(100));
        } else {
            // Wait until the next delivery is due
            std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
        }
    }
}

// ---------------------------------------------------------------------------
// SimulatedTransport constructor — binds to a simulator with a debug name
// ---------------------------------------------------------------------------
NetworkSimulator::SimulatedTransport::SimulatedTransport(NetworkSimulator* sim, const std::string& n)
    : simulator(sim), name(n)
{
}

// ---------------------------------------------------------------------------
// SimulatedTransport::Start — binds to a port on the parent simulator
// ---------------------------------------------------------------------------
void NetworkSimulator::SimulatedTransport::Start(int port) {
    if (local_port != 0) return;                      // Already bound — no-op
    local_port = simulator->BindTransport(this, port); // Register in simulator's port map
}

// ---------------------------------------------------------------------------
// SimulatedTransport::Send — injects data into the simulated network
// ---------------------------------------------------------------------------
void NetworkSimulator::SimulatedTransport::Send(const uint8_t* data, int length, int remote_port) {
    if (disposed) return;               // Silently discard if disposed
    if (local_port == 0) Start(0);      // Auto-bind if not yet started
    simulator->SendAsync(this, data, length, remote_port);  // Route through the simulator
}

// ---------------------------------------------------------------------------
// SimulatedTransport::Stop — unbinds from the simulator's port registry
// ---------------------------------------------------------------------------
void NetworkSimulator::SimulatedTransport::Stop() {
    if (local_port != 0) {
        simulator->UnbindTransport(local_port);  // Remove from registry
        local_port = 0;
    }
}

// ---------------------------------------------------------------------------
// SimulatedTransport::Dispose — marks as disposed and unbinds
// ---------------------------------------------------------------------------
void NetworkSimulator::SimulatedTransport::Dispose() {
    if (disposed) return;  // Idempotent
    disposed = true;
    Stop();
}

// ---------------------------------------------------------------------------
// SimulatedTransport::Enqueue — delivers inbound data via the callback
// ---------------------------------------------------------------------------
void NetworkSimulator::SimulatedTransport::Enqueue(const SimulatedDatagram& datagram) {
    if (disposed) return;  // Discard if disposed
    if (on_datagram) {
        on_datagram(datagram.buffer.data(), datagram.count, datagram.source_port);
    }
}

} // namespace ucp_test
