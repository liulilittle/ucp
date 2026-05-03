#include "network_simulator.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <unordered_set>

namespace ucp_test {

static std::chrono::steady_clock::time_point g_base_time = std::chrono::steady_clock::now();

static int64_t WallClockMicros() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now - g_base_time).count();
}

static int64_t WallClockMillis() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - g_base_time).count();
}

NetworkSimulator::NetworkSimulator(
    double loss_rate, int fixed_delay_ms, int jitter_ms,
    int bandwidth_bytes_per_sec, int seed,
    DropRule drop_rule, double duplicate_rate, double reorder_rate,
    int forward_delay_ms, int backward_delay_ms,
    int forward_jitter_ms, int backward_jitter_ms,
    int dynamic_jitter_range_ms, int dynamic_wave_amp_ms, int direction_skew_ms)
    : _rng(seed)
    , _loss_rate(loss_rate)
    , _fixed_delay_ms(fixed_delay_ms)
    , _jitter_ms(jitter_ms)
    , _forward_delay_ms(forward_delay_ms >= 0 ? forward_delay_ms : fixed_delay_ms)
    , _backward_delay_ms(backward_delay_ms >= 0 ? backward_delay_ms : fixed_delay_ms)
    , _forward_jitter_ms(forward_jitter_ms >= 0 ? forward_jitter_ms : jitter_ms)
    , _backward_jitter_ms(backward_jitter_ms >= 0 ? backward_jitter_ms : jitter_ms)
    , _dynamic_jitter_range_ms(dynamic_jitter_range_ms)
    , _dynamic_wave_amp_ms(dynamic_wave_amp_ms)
    , _direction_skew_ms(direction_skew_ms)
    , _bandwidth_bytes_per_sec(bandwidth_bytes_per_sec)
    , _duplicate_rate(duplicate_rate)
    , _reorder_rate(reorder_rate)
    , _drop_rule(std::move(drop_rule))
{
}

NetworkSimulator::~NetworkSimulator() {
    {
        std::lock_guard<std::mutex> lock(_sync);
        _stop_scheduler = true;
    }
    _scheduler_cv.notify_all();
    if (_scheduler_thread.joinable()) {
        _scheduler_thread.join();
    }
}

double NetworkSimulator::ObservedPacketLossPercent() const {
    std::lock_guard<std::mutex> lock(_sync);
    if (_sent_packets == 0) return 0.0;
    return static_cast<double>(_dropped_packets) * 100.0 / static_cast<double>(_sent_packets);
}

double NetworkSimulator::ObservedDataLossPercent() const {
    std::lock_guard<std::mutex> lock(_sync);
    if (_sent_data_packets == 0) return 0.0;
    return static_cast<double>(_dropped_data_packets) * 100.0 / static_cast<double>(_sent_data_packets);
}

double NetworkSimulator::LogicalThroughputBytesPerSecond() const {
    std::lock_guard<std::mutex> lock(_sync);
    if (_logical_data_bytes <= 0) return 0.0;

    double raw = 0.0;
    if (_first_data_send_micros > 0 && _last_data_scheduled_micros > _first_data_send_micros) {
        raw = static_cast<double>(_logical_data_bytes) * 1000000.0
            / static_cast<double>(_last_data_scheduled_micros - _first_data_send_micros);
    }

    if (_bandwidth_bytes_per_sec >= kHighBandwidthLogicalClockThreshold) {
        int64_t serialization = static_cast<int64_t>(
            std::ceil(static_cast<double>(_logical_data_bytes) * 1000000.0
                      / static_cast<double>(_bandwidth_bytes_per_sec)));
        int64_t duration = std::max<int64_t>(1, serialization + AverageForwardDelayMicros());
        return static_cast<double>(_logical_data_bytes) * 1000000.0 / static_cast<double>(duration);
    }

    if (_bandwidth_bytes_per_sec > 0 && raw > static_cast<double>(_bandwidth_bytes_per_sec)) {
        return static_cast<double>(_bandwidth_bytes_per_sec);
    }
    return raw;
}

int64_t NetworkSimulator::AverageForwardDelayMicros() const {
    std::lock_guard<std::mutex> lock(_sync);
    return AverageMicros(_forward_latency_samples);
}

int64_t NetworkSimulator::AverageReverseDelayMicros() const {
    std::lock_guard<std::mutex> lock(_sync);
    return AverageMicros(_reverse_latency_samples);
}

std::vector<int64_t> NetworkSimulator::LatencySamplesMicros() const {
    std::lock_guard<std::mutex> lock(_sync);
    return _latency_samples;
}

void NetworkSimulator::Reconfigure(double loss_rate, int fixed_delay_ms, int jitter_ms,
                                    int bandwidth_bytes_per_sec, double duplicate_rate, double reorder_rate) {
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
    _duplicate_rate = duplicate_rate;
    _reorder_rate = reorder_rate;
}

NetworkSimulator::SimulatedTransport* NetworkSimulator::CreateTransport(const std::string& name) {
    auto* t = new SimulatedTransport(this, name);
    return t;
}

int NetworkSimulator::BindTransport(SimulatedTransport* transport, int port) {
    std::lock_guard<std::mutex> lock(_sync);
    if (port == 0) {
        port = ++_next_port;
    }
    _transports[port] = transport;
    return port;
}

void NetworkSimulator::UnbindTransport(int port) {
    std::lock_guard<std::mutex> lock(_sync);
    _transports.erase(port);
}

void NetworkSimulator::SendAsync(SimulatedTransport* sender, const uint8_t* data, int length, int remote_port) {
    SimulatedDatagram datagram;
    datagram.buffer.assign(data, data + length);
    datagram.count = length;
    datagram.source_port = sender->local_port;
    datagram.destination_port = remote_port;
    datagram.send_micros = WallClockMicros();
    datagram.forward_direction = (sender->local_port <= remote_port);

    bool drop = false;
    int64_t due_micros = 0;
    int64_t logical_due = 0;
    bool duplicate = false;
    bool reorder = false;

    {
        std::lock_guard<std::mutex> lock(_sync);
        bool is_data = IsDataPacket(data, length);
        _sent_packets++;
        if (is_data) _sent_data_packets++;

        drop = ShouldDrop(datagram);
        if (drop) {
            _dropped_packets++;
            if (is_data) _dropped_data_packets++;
            return;
        }

        CalculateDueMicros(length, datagram.forward_direction, due_micros, logical_due);
        datagram.logical_due_micros = logical_due;

        if (_duplicate_rate > 0) {
            std::uniform_real_distribution<double> dist(0.0, 1.0);
            duplicate = dist(_rng) < _duplicate_rate;
            if (duplicate) _duplicated_packets++;
        }

        if (_reorder_rate > 0) {
            std::uniform_real_distribution<double> dist(0.0, 1.0);
            reorder = dist(_rng) < _reorder_rate;
            if (reorder) {
                _reordered_packets++;
                due_micros += std::max<int64_t>(1000,
                    static_cast<int64_t>(_fixed_delay_ms + _jitter_ms + 1) * 1000);
            }
        }
    }

    ScheduleDelivery(datagram, due_micros);

    if (duplicate) {
        SimulatedDatagram dup = datagram.Clone();
        ScheduleDelivery(dup, due_micros + 1000);
    }
}

bool NetworkSimulator::ShouldDrop(const SimulatedDatagram& datagram) {
    if (_drop_rule && _drop_rule(datagram)) return true;
    if (_loss_rate <= 0) return false;
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(_rng) < _loss_rate;
}

void NetworkSimulator::CalculateDueMicros(int bytes, bool forward,
                                           int64_t& due_micros, int64_t& logical_due_micros) {
    int fixed_ms = forward ? _forward_delay_ms : _backward_delay_ms;
    int jit_ms   = forward ? _forward_jitter_ms  : _backward_jitter_ms;

    int jitter = 0;
    if (jit_ms > 0) {
        std::uniform_int_distribution<int> dist(-jit_ms, jit_ms);
        jitter = dist(_rng);
    }

    int dyn_jitter = 0;
    if (_dynamic_jitter_range_ms > 0) {
        int cap = std::min(_dynamic_jitter_range_ms, std::max(1, fixed_ms / 3));
        std::uniform_int_distribution<int> dist(-cap, cap);
        dyn_jitter = dist(_rng);
    }

    double phase_offset = forward ? 0.0 : 1.57079632679;
    double wave = 0.0;
    if (_dynamic_wave_amp_ms > 0) {
        int64_t now_us = WallClockMicros();
        double phase = (static_cast<double>(now_us % (kDynamicWavePeriodMs * 1000LL))
                       / static_cast<double>(kDynamicWavePeriodMs * 1000LL))
                      * 3.14159265359 * 2.0;
        wave = std::sin(phase + phase_offset) * static_cast<double>(_dynamic_wave_amp_ms);
    }

    int skew = forward ? _direction_skew_ms : -_direction_skew_ms;
    int eff_skew = std::min(std::abs(skew), fixed_ms * 80 / 100) * (skew >= 0 ? 1 : -1);
    double eff_wave = wave * std::min(1.0, static_cast<double>(fixed_ms) / 30.0);

    int64_t propagation = static_cast<int64_t>(std::round(
        static_cast<double>(fixed_ms + jitter + dyn_jitter) + eff_wave
        + static_cast<double>(eff_skew)) * 1000.0);
    if (propagation < 0) propagation = 0;

    if (forward) {
        _forward_latency_samples.push_back(propagation);
    } else {
        _reverse_latency_samples.push_back(propagation);
    }

    int64_t now_us = WallClockMicros();
    int64_t tx_complete = now_us;
    int64_t logical_tx_complete = now_us;

    if (_bandwidth_bytes_per_sec > 0) {
        int64_t serial = static_cast<int64_t>(
            std::ceil(static_cast<double>(bytes) * 1000000.0 / static_cast<double>(_bandwidth_bytes_per_sec)));

        int64_t& next_avail = forward ? _next_forward_tx_available : _next_reverse_tx_available;
        if (next_avail < now_us) next_avail = now_us;
        next_avail += serial;
        tx_complete = next_avail;

        bool use_logical = _bandwidth_bytes_per_sec >= kHighBandwidthLogicalClockThreshold;
        int64_t& next_logical = forward ? _next_forward_logical_tx : _next_reverse_logical_tx;

        if (!use_logical) {
            logical_tx_complete = tx_complete;
        } else {
            if (next_logical == 0 || (now_us - next_logical) > kLogicalSenderIdleGapMicros) {
                next_logical = now_us;
            }
            next_logical += serial;
            logical_tx_complete = next_logical;
        }
    }

    logical_due_micros = logical_tx_complete + propagation;
    due_micros = tx_complete + propagation;
}

void NetworkSimulator::ScheduleDelivery(SimulatedDatagram datagram, int64_t due_micros) {
    int64_t now_us = WallClockMicros();

    {
        std::lock_guard<std::mutex> lock(_sync);
        std::string key;
        int payload_bytes = 0;
        if (TryGetDataPacketIdentity(datagram.buffer.data(), datagram.count, key, payload_bytes)
            && _logical_data_keys.insert(key).second) {
            if (payload_bytes > 0) _logical_data_bytes += payload_bytes;
            if (_first_data_send_micros == 0) _first_data_send_micros = now_us;
            int64_t logical = datagram.logical_due_micros > 0 ? datagram.logical_due_micros : due_micros;
            if (logical > _last_data_scheduled_micros) _last_data_scheduled_micros = logical;
        }

        _scheduled[due_micros].push_back(std::move(datagram));

        if (!_scheduler_running) {
            _scheduler_running = true;
            _stop_scheduler = false;
            _scheduler_thread = std::thread(&NetworkSimulator::SchedulerLoop, this);
        }
    }

    _scheduler_cv.notify_one();
}

void NetworkSimulator::Deliver(const SimulatedDatagram& datagram) {
    SimulatedTransport* target = nullptr;
    {
        std::lock_guard<std::mutex> lock(_sync);
        auto it = _transports.find(datagram.destination_port);
        if (it != _transports.end()) target = it->second;
    }

    if (target == nullptr) return;
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
        if (lat >= 0) _latency_samples.push_back(lat);
    }
}

bool NetworkSimulator::IsDataPacket(const uint8_t* buffer, int count) {
    return buffer != nullptr && count > 0 && buffer[0] == 0x05;
}

bool NetworkSimulator::TryGetDataPacketIdentity(const uint8_t* buffer, int count,
                                                  std::string& key, int& payload_bytes) {
    key.clear();
    payload_bytes = 0;
    if (buffer == nullptr || count <= 20 || buffer[0] != 0x05) return false;

    uint32_t conn_id  = ReadUInt32BigEndian(buffer, 2);
    uint32_t seq_num  = ReadUInt32BigEndian(buffer, 12);
    key = std::to_string(conn_id) + ":" + std::to_string(seq_num);
    payload_bytes = count - 20;
    return true;
}

uint32_t NetworkSimulator::ReadUInt32BigEndian(const uint8_t* buffer, int offset) {
    return (static_cast<uint32_t>(buffer[offset])     << 24)
         | (static_cast<uint32_t>(buffer[offset + 1]) << 16)
         | (static_cast<uint32_t>(buffer[offset + 2]) << 8)
         |  static_cast<uint32_t>(buffer[offset + 3]);
}

int64_t NetworkSimulator::AverageMicros(const std::vector<int64_t>& samples) {
    if (samples.empty()) return 0;
    int64_t total = 0;
    for (int64_t s : samples) total += s;
    return total / static_cast<int64_t>(samples.size());
}

void NetworkSimulator::SchedulerLoop() {
    while (true) {
        std::vector<SimulatedDatagram> due;
        int wait_ms = -1;

        {
            std::lock_guard<std::mutex> lock(_sync);
            if (_stop_scheduler && _scheduled.empty()) {
                _scheduler_running = false;
                return;
            }

            if (!_scheduled.empty()) {
                auto it = _scheduled.begin();
                int64_t due_us = it->first;
                int64_t now_us = WallClockMicros();

                if (due_us <= now_us + kSchedulerCoalescingMicros) {
                    due = std::move(it->second);
                    _scheduled.erase(it);
                } else {
                    wait_ms = std::max(1,
                        static_cast<int>(std::ceil(static_cast<double>(due_us - now_us) / 1000.0)));
                }
            }
        }

        if (!due.empty()) {
            for (const auto& d : due) Deliver(d);
            continue;
        }

        if (wait_ms < 0) {
            std::unique_lock<std::mutex> cv_lock(_sync);
            _scheduler_cv.wait_for(cv_lock, std::chrono::milliseconds(100));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
        }
    }
}

NetworkSimulator::SimulatedTransport::SimulatedTransport(NetworkSimulator* sim, const std::string& n)
    : simulator(sim), name(n)
{
}

void NetworkSimulator::SimulatedTransport::Start(int port) {
    if (local_port != 0) return;
    local_port = simulator->BindTransport(this, port);
}

void NetworkSimulator::SimulatedTransport::Send(const uint8_t* data, int length, int remote_port) {
    if (disposed) return;
    if (local_port == 0) Start(0);
    simulator->SendAsync(this, data, length, remote_port);
}

void NetworkSimulator::SimulatedTransport::Stop() {
    if (local_port != 0) {
        simulator->UnbindTransport(local_port);
        local_port = 0;
    }
}

void NetworkSimulator::SimulatedTransport::Dispose() {
    if (disposed) return;
    disposed = true;
    Stop();
}

void NetworkSimulator::SimulatedTransport::Enqueue(const SimulatedDatagram& datagram) {
    if (disposed) return;
    if (on_datagram) {
        on_datagram(datagram.buffer.data(), datagram.count, datagram.source_port);
    }
}

} // namespace ucp_test
