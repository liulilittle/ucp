#include "network_simulator.h"

#include "ucp/ucp_vector.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>

std::atomic<bool> g_test_timeout_flag{false};

namespace ucp_test {

static std::chrono::steady_clock::time_point g_base_time = std::chrono::steady_clock::now();

static int64_t WallClockMicros() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now - g_base_time).count();
}

NetworkSimulator::NetworkSimulator(double loss_rate, int fixed_delay_ms, int jitter_ms, int bandwidth_bytes_per_sec, int seed,
                                   DropRule drop_rule, double duplicate_rate, double reorder_rate, int forward_delay_ms,
                                   int backward_delay_ms, int forward_jitter_ms, int backward_jitter_ms, int dynamic_jitter_range_ms,
                                   int dynamic_wave_amp_ms, int direction_skew_ms) noexcept
    : _rng(seed), _loss_rate(loss_rate), _fixed_delay_ms(fixed_delay_ms), _jitter_ms(jitter_ms),
      _forward_delay_ms(0 <= forward_delay_ms ? forward_delay_ms : fixed_delay_ms),
      _backward_delay_ms(0 <= backward_delay_ms ? backward_delay_ms : fixed_delay_ms),
      _forward_jitter_ms(0 <= forward_jitter_ms ? forward_jitter_ms : jitter_ms),
      _backward_jitter_ms(0 <= backward_jitter_ms ? backward_jitter_ms : jitter_ms), _dynamic_jitter_range_ms(dynamic_jitter_range_ms),
      _dynamic_wave_amp_ms(dynamic_wave_amp_ms), _direction_skew_ms(direction_skew_ms), _bandwidth_bytes_per_sec(bandwidth_bytes_per_sec),
      _duplicate_rate(duplicate_rate), _reorder_rate(reorder_rate), _drop_rule(std::move(drop_rule)) {}

NetworkSimulator::~NetworkSimulator() noexcept {
    _disposed = true;
    StopScheduler();
    {
        std::lock_guard<std::mutex> lock(_sync);
        _transports.clear();
    }
}

void NetworkSimulator::StopScheduler() noexcept {
    {
        std::lock_guard<std::mutex> lock(_sync);
        _stop_scheduler = true;
        _force_stop = true;
        _scheduled.clear();
    }
    _scheduler_cv.notify_all();
    if (_scheduler_thread.joinable()) {
        _scheduler_thread.join();
    }
}

double NetworkSimulator::ObservedPacketLossPercent() const noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    if (0 == _sent_packets) {
        return 0.0;
    }
    return static_cast<double>(_dropped_packets) * 100.0 / static_cast<double>(_sent_packets);
}

double NetworkSimulator::ObservedDataLossPercent() const noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    if (0 == _sent_data_packets) {
        return 0.0;
    }
    return static_cast<double>(_dropped_data_packets) * 100.0 / static_cast<double>(_sent_data_packets);
}

double NetworkSimulator::LogicalThroughputBytesPerSecond() const noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    if (0 >= _logical_data_bytes) {
        return 0.0;
    }

    double raw = 0.0;

    if (0 < _first_data_send_micros && _last_data_scheduled_micros > _first_data_send_micros) {
        int64_t elapsed = _last_data_scheduled_micros - _first_data_send_micros;
        raw = static_cast<double>(_logical_data_bytes) * 1000000.0 / static_cast<double>(elapsed);
    }

    if (_bandwidth_bytes_per_sec >= kHighBandwidthLogicalClockThreshold) {

        int64_t serialization = static_cast<int64_t>(
            std::ceil(static_cast<double>(_logical_data_bytes) * 1000000.0 / static_cast<double>(_bandwidth_bytes_per_sec)));

        int64_t avg_fwd_delay = AverageMicros(_forward_latency_samples);

        int64_t duration = std::max<int64_t>(1, serialization + avg_fwd_delay);
        return static_cast<double>(_logical_data_bytes) * 1000000.0 / static_cast<double>(duration);
    }

    if (0 < _bandwidth_bytes_per_sec && raw > static_cast<double>(_bandwidth_bytes_per_sec)) {
        return static_cast<double>(_bandwidth_bytes_per_sec);
    }
    return raw;
}

int64_t NetworkSimulator::AverageForwardDelayMicros() const noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    return AverageMicros(_forward_latency_samples);
}

int64_t NetworkSimulator::AverageReverseDelayMicros() const noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    return AverageMicros(_reverse_latency_samples);
}

ucp::vector<int64_t> NetworkSimulator::LatencySamplesMicros() const noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    return _latency_samples;
}

void NetworkSimulator::Reconfigure(double loss_rate, int fixed_delay_ms, int jitter_ms, int bandwidth_bytes_per_sec, double duplicate_rate,
                                   double reorder_rate) noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    _loss_rate = loss_rate;
    _fixed_delay_ms = fixed_delay_ms;
    _jitter_ms = jitter_ms;
    _forward_delay_ms = fixed_delay_ms;
    _backward_delay_ms = fixed_delay_ms;
    _forward_jitter_ms = jitter_ms;
    _backward_jitter_ms = jitter_ms;
    _dynamic_jitter_range_ms = 1;
    _dynamic_wave_amp_ms = 0;
    _direction_skew_ms = 0;
    _bandwidth_bytes_per_sec = bandwidth_bytes_per_sec;
    _forward_serial_rem_ns = 0;
    _reverse_serial_rem_ns = 0;
    _forward_logical_rem_ns = 0;
    _reverse_logical_rem_ns = 0;
    _duplicate_rate = duplicate_rate;
    _reorder_rate = reorder_rate;
}

NetworkSimulator::SimulatedTransport* NetworkSimulator::CreateTransport(const ucp::string& name) noexcept {
    auto* t = new SimulatedTransport(this, name);
    return t;
}

int NetworkSimulator::BindTransport(SimulatedTransport* transport, int port) noexcept {
    if (_disposed.load()) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(_sync);
    if (0 == port) {
        port = ++_next_port;
    }
    _transports[port] = transport;
    return port;
}

void NetworkSimulator::UnbindTransport(int port) noexcept {
    std::lock_guard<std::mutex> lock(_sync);
    _transports.erase(port);
}

void NetworkSimulator::SendAsync(SimulatedTransport* sender, const uint8_t* data, int length, int remote_port) noexcept {
    if (_disposed.load()) {
        return;
    }
    int64_t now_us = WallClockMicros();

    SimulatedDatagram datagram;
    datagram.buffer.assign(data, data + length);
    datagram.count = length;
    datagram.source_port = sender->local_port;
    datagram.destination_port = remote_port;
    datagram.send_micros = now_us;

    bool drop = false;
    int64_t due_micros = 0;
    int64_t logical_due = 0;
    bool duplicate = false;
    bool reorder = false;

    {
        std::lock_guard<std::mutex> lock(_sync);

        bool is_data = IsDataPacket(data, length);

        _sent_packets++;
        if (is_data) {
            _sent_data_packets++;
        }

        drop = ShouldDrop(datagram);
        if (drop) {
            _dropped_packets++;
            if (is_data) {
                _dropped_data_packets++;
            }
            return;
        }

        CalculateDueMicros(length, datagram.forward_direction, now_us, due_micros, logical_due);
        datagram.logical_due_micros = logical_due;

        if (0 < _duplicate_rate) {
            std::uniform_real_distribution<double> dist(0.0, 1.0);
            duplicate = dist(_rng) < _duplicate_rate;
            if (duplicate) {
                _duplicated_packets++;
            }
        }

        if (0 < _reorder_rate) {
            std::uniform_real_distribution<double> dist(0.0, 1.0);
            reorder = dist(_rng) < _reorder_rate;
            if (reorder) {
                _reordered_packets++;

                due_micros += std::max<int64_t>(1000, static_cast<int64_t>(_fixed_delay_ms + _jitter_ms + 1) * 1000);
            }
        }
    }

    ScheduleDelivery(datagram, due_micros);

    if (duplicate) {
        SimulatedDatagram dup = datagram.Clone();
        ScheduleDelivery(dup, due_micros + 1000);
    }
}

bool NetworkSimulator::ShouldDrop(const SimulatedDatagram& datagram) noexcept {
    if (_drop_rule && _drop_rule(datagram)) {
        return true;
    }
    if (0 >= _loss_rate) {
        return false;
    }
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(_rng) < _loss_rate;
}

void NetworkSimulator::CalculateDueMicros(int bytes, bool forward, int64_t now_us, int64_t& due_micros,
                                          int64_t& logical_due_micros) noexcept {

    int fixed_ms = forward ? _forward_delay_ms : _backward_delay_ms;
    int jit_ms = forward ? _forward_jitter_ms : _backward_jitter_ms;

    int jitter = 0;
    if (0 < jit_ms) {
        std::uniform_int_distribution<int> dist(-jit_ms, jit_ms);
        jitter = dist(_rng);
    }

    int dyn_jitter = 0;
    if (0 < _dynamic_jitter_range_ms) {
        int cap = std::min(_dynamic_jitter_range_ms, (fixed_ms > 0 ? std::max(1, fixed_ms / 3) : 0));
        std::uniform_int_distribution<int> dist(-cap, cap);
        dyn_jitter = dist(_rng);
    }

    double phase_offset = forward ? 0.0 : 1.57079632679;
    double wave = 0.0;
    if (0 < _dynamic_wave_amp_ms) {

        double phase =
            (static_cast<double>(now_us % (kDynamicWavePeriodMs * 1000LL)) / static_cast<double>(kDynamicWavePeriodMs * 1000LL)) *
            3.14159265359 * 2.0;
        wave = std::sin(phase + phase_offset) * static_cast<double>(_dynamic_wave_amp_ms);
    }

    int skew = forward ? _direction_skew_ms : -_direction_skew_ms;
    int eff_skew = std::min(std::abs(skew), fixed_ms * 80 / 100) * (0 <= skew ? 1 : -1);

    double eff_wave = wave * std::min(1.0, static_cast<double>(fixed_ms) / 30.0);

    int64_t propagation = static_cast<int64_t>(
        std::round(static_cast<double>(fixed_ms + jitter + dyn_jitter) + eff_wave + static_cast<double>(eff_skew)) * 1000.0);
    if (0 > propagation) {
        propagation = 0;
    }

    if (forward) {
        _forward_latency_samples.push_back(propagation);
    } else {
        _reverse_latency_samples.push_back(propagation);
    }

    int64_t tx_complete = now_us;
    int64_t logical_tx_complete = now_us;

    if (0 < _bandwidth_bytes_per_sec) {

        int64_t serial_ns = static_cast<int64_t>(static_cast<double>(bytes) * 1000000000.0 / static_cast<double>(_bandwidth_bytes_per_sec));
        int64_t serial = serial_ns / 1000;
        int64_t& rem = forward ? _forward_serial_rem_ns : _reverse_serial_rem_ns;
        rem += serial_ns % 1000;
        serial += rem / 1000;
        rem %= 1000;

        int64_t& next_avail = forward ? _next_forward_tx_available : _next_reverse_tx_available;
        if (next_avail < now_us) {
            next_avail = now_us;
        }
        next_avail += serial;
        tx_complete = next_avail;

        bool use_logical = _bandwidth_bytes_per_sec >= kHighBandwidthLogicalClockThreshold;
        int64_t& next_logical = forward ? _next_forward_logical_tx : _next_reverse_logical_tx;
        int64_t& logical_rem = forward ? _forward_logical_rem_ns : _reverse_logical_rem_ns;

        if (!use_logical) {
            logical_tx_complete = tx_complete;
        } else {

            if (0 == next_logical || (now_us - next_logical) > kLogicalSenderIdleGapMicros) {
                next_logical = now_us;
                logical_rem = 0;
            }
            int64_t log_serial = serial_ns / 1000;
            logical_rem += serial_ns % 1000;
            log_serial += logical_rem / 1000;
            logical_rem %= 1000;
            next_logical += log_serial;
            logical_tx_complete = next_logical;
        }
    }

    logical_due_micros = logical_tx_complete + propagation;
    due_micros = tx_complete + propagation;
}

void NetworkSimulator::ScheduleDelivery(SimulatedDatagram datagram, int64_t due_micros) noexcept {
    if (_disposed.load()) {
        return;
    }
    int64_t now_us = WallClockMicros();

    {
        std::lock_guard<std::mutex> lock(_sync);
        if (_stop_scheduler || _force_stop) {
            return;
        }
        ucp::string key;
        int payload_bytes = 0;

        if (TryGetDataPacketIdentity(datagram.buffer.data(), datagram.count, key, payload_bytes) && _logical_data_keys.insert(key).second) {
            if (0 < payload_bytes) {
                _logical_data_bytes += payload_bytes;
            }
            if (0 == _first_data_send_micros) {
                _first_data_send_micros = now_us;
            }
            int64_t logical = 0 < datagram.logical_due_micros ? datagram.logical_due_micros : due_micros;
            if (logical > _last_data_scheduled_micros) {
                _last_data_scheduled_micros = logical;
            }
        }

        _scheduled[due_micros].push_back(std::move(datagram));

        if (!_scheduler_running && !_stop_scheduler && !_force_stop) {
            _scheduler_running = true;
            _scheduler_thread = std::thread(&NetworkSimulator::SchedulerLoop, this);
        }
    }

    _scheduler_cv.notify_one();
}

bool NetworkSimulator::WaitForDeliveryCount(int64_t minPackets, int timeoutMilliseconds) noexcept {
    if (g_test_timeout_flag.load()) {
        return false;
    }
    if (_abort_signal && _abort_signal->load()) {
        return false;
    }
    std::unique_lock<std::mutex> lock(_sync);
    bool abort_checked = false;
    auto result =
        _delivery_cv.wait_for(lock, std::chrono::milliseconds(timeoutMilliseconds), [this, minPackets, &abort_checked]() noexcept -> bool {
            if (_abort_signal && _abort_signal->load()) {
                abort_checked = true;
                return true;
            }
            if (g_test_timeout_flag.load()) {
                abort_checked = true;
                return true;
            }
            return _delivered_packets >= minPackets || _stop_scheduler;
        });
    if (abort_checked || g_test_timeout_flag.load()) {
        return false;
    }
    return result;
}

void NetworkSimulator::Deliver(const SimulatedDatagram& datagram) noexcept {
    if (_disposed.load()) {
        return;
    }
    SimulatedTransport* target = NULLPTR;
    {
        std::lock_guard<std::mutex> lock(_sync);
        auto it = _transports.find(datagram.destination_port);
        if (it != _transports.end()) {
            target = it->second;
        }
    }

    if (NULLPTR == target) {
        return;
    }
    target->Enqueue(datagram);

    {
        std::lock_guard<std::mutex> lock(_sync);
        _delivered_packets++;
        _delivered_bytes += datagram.count;
        if (IsDataPacket(datagram.buffer.data(), datagram.count)) {
            _delivered_data_packets++;
        }

        int64_t now_us = WallClockMicros();
        int64_t lat = now_us - datagram.send_micros;
        if (0 <= lat) {
            _latency_samples.push_back(lat);
        }

        _delivery_cv.notify_all();
    }
}

bool NetworkSimulator::IsDataPacket(const uint8_t* buffer, int count) noexcept {
    return NULLPTR != buffer && 0 < count && 0x05 == buffer[0];
}

bool NetworkSimulator::TryGetDataPacketIdentity(const uint8_t* buffer, int count, ucp::string& key, int& payload_bytes) noexcept {
    key.clear();
    payload_bytes = 0;

    if (NULLPTR == buffer || 20 > count || 0x05 != buffer[0]) {
        return false;
    }

    uint32_t conn_id = ReadUInt32BigEndian(buffer, 2);
    uint32_t seq_num = ReadUInt32BigEndian(buffer, 12);
    key = std::to_string(conn_id) + ":" + std::to_string(seq_num);
    payload_bytes = count - 20;
    return true;
}

uint32_t NetworkSimulator::ReadUInt32BigEndian(const uint8_t* buffer, int offset) noexcept {
    return (static_cast<uint32_t>(buffer[offset]) << 24) | (static_cast<uint32_t>(buffer[offset + 1]) << 16) |
           (static_cast<uint32_t>(buffer[offset + 2]) << 8) | static_cast<uint32_t>(buffer[offset + 3]);
}

int64_t NetworkSimulator::AverageMicros(const ucp::vector<int64_t>& samples) noexcept {
    if (samples.empty()) {
        return 0;
    }
    double total = 0.0;
    for (int64_t s : samples) {
        total += static_cast<double>(s);
    }
    return static_cast<int64_t>(total / static_cast<double>(samples.size()));
}

void NetworkSimulator::SchedulerLoop() noexcept {
    auto stop_seen_at = std::chrono::steady_clock::time_point{};

    while (true) {

        if (_force_stop.load()) {
            _scheduler_running = false;
            return;
        }
        ucp::vector<SimulatedDatagram> due;
        int wait_ms = -1;

        {
            std::lock_guard<std::mutex> lock(_sync);

            if (_stop_scheduler && _scheduled.empty()) {
                _scheduler_running = false;
                return;
            }

            if (_stop_scheduler) {
                if (stop_seen_at == std::chrono::steady_clock::time_point{}) {
                    stop_seen_at = std::chrono::steady_clock::now();
                } else if (std::chrono::steady_clock::now() - stop_seen_at > std::chrono::seconds(1)) {
                    _scheduled.clear();
                    _scheduler_running = false;
                    return;
                }
            } else {
                stop_seen_at = {};
            }

            if (!_scheduled.empty()) {
                auto it = _scheduled.begin();
                int64_t due_us = it->first;
                int64_t now_us = WallClockMicros();

                if (due_us <= now_us + kSchedulerCoalescingMicros) {
                    due = std::move(it->second);
                    _scheduled.erase(it);
                } else {
                    wait_ms = std::max(1, static_cast<int>(std::ceil(static_cast<double>(due_us - now_us) / 1000.0)));
                }
            }
        }

        if (!due.empty()) {
            for (size_t i = 0; i < due.size(); ++i) {
                Deliver(due[i]);
            }
            continue;
        }

        {
            std::unique_lock<std::mutex> cv_lock(_sync);
            int pollMs = _stop_scheduler ? 50 : (0 > wait_ms ? 100 : std::min(wait_ms, 100));

            if (_force_stop.load()) {
                _scheduled.clear();
                _scheduler_running = false;
                return;
            }
            _scheduler_cv.wait_for(cv_lock, std::chrono::milliseconds(pollMs));
        }
    }
}

NetworkSimulator::SimulatedTransport::SimulatedTransport(NetworkSimulator* sim, const ucp::string& n) noexcept : simulator(sim), name(n) {}

void NetworkSimulator::SimulatedTransport::Start(int port) noexcept {
    if (0 != local_port) {
        return;
    }
    local_port = simulator->BindTransport(this, port);
}

void NetworkSimulator::SimulatedTransport::Send(const uint8_t* data, int length, int remote_port) noexcept {
    if (simulator == NULLPTR) {
        return;
    }
    if (disposed) {
        return;
    }
    if (0 == local_port) {
        Start(0);
    }
    simulator->SendAsync(this, data, length, remote_port);
}

void NetworkSimulator::SimulatedTransport::Stop() noexcept {
    if (simulator == NULLPTR) {
        return;
    }
    if (0 != local_port) {
        simulator->UnbindTransport(local_port);
        local_port = 0;
    }
}

void NetworkSimulator::SimulatedTransport::Dispose() noexcept {
    if (disposed) {
        return;
    }
    disposed = true;
    Stop();
}

void NetworkSimulator::SimulatedTransport::Enqueue(const SimulatedDatagram& datagram) noexcept {
    if (disposed) {
        return;
    }
    if (on_datagram) {
        on_datagram(datagram.buffer.data(), datagram.count, datagram.source_port);
    }
}

} // namespace ucp_test
