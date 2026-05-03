#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ucp_test {

struct SimulatedDatagram {
    std::vector<uint8_t> buffer;
    int                count              = 0;
    int                source_port        = 0;
    int                destination_port   = 0;
    int64_t            send_micros        = 0;
    int64_t            logical_due_micros = 0;
    bool               forward_direction  = true;

    SimulatedDatagram Clone() const {
        SimulatedDatagram d = *this;
        return d;
    }
};

using DropRule = std::function<bool(const SimulatedDatagram&)>;

class NetworkSimulator {
public:
    NetworkSimulator(
        double loss_rate                 = 0,
        int    fixed_delay_ms            = 0,
        int    jitter_ms                 = 0,
        int    bandwidth_bytes_per_sec   = 0,
        int    seed                      = 1234,
        DropRule drop_rule               = nullptr,
        double duplicate_rate            = 0,
        double reorder_rate              = 0,
        int    forward_delay_ms          = -1,
        int    backward_delay_ms         = -1,
        int    forward_jitter_ms         = -1,
        int    backward_jitter_ms        = -1,
        int    dynamic_jitter_range_ms   = 1,
        int    dynamic_wave_amp_ms       = 0,
        int    direction_skew_ms         = 0);

    ~NetworkSimulator();

    double LossRate()                   const { return _loss_rate; }
    int    FixedDelayMilliseconds()     const { return _fixed_delay_ms; }
    int    JitterMilliseconds()         const { return _jitter_ms; }
    int    ForwardDelayMilliseconds()   const { return _forward_delay_ms; }
    int    BackwardDelayMilliseconds()  const { return _backward_delay_ms; }
    int    ForwardJitterMilliseconds()  const { return _forward_jitter_ms; }
    int    BackwardJitterMilliseconds() const { return _backward_jitter_ms; }
    int    BandwidthBytesPerSecond()    const { return _bandwidth_bytes_per_sec; }

    int64_t SentPackets()        const { return _sent_packets; }
    int64_t SentDataPackets()    const { return _sent_data_packets; }
    int64_t DroppedPackets()     const { return _dropped_packets; }
    int64_t DroppedDataPackets() const { return _dropped_data_packets; }
    int64_t DeliveredPackets()   const { return _delivered_packets; }
    int64_t DeliveredDataPackets() const { return _delivered_data_packets; }
    int64_t DeliveredBytes()     const { return _delivered_bytes; }
    int64_t DuplicatedPackets()  const { return _duplicated_packets; }
    int64_t ReorderedPackets()   const { return _reordered_packets; }

    double ObservedPacketLossPercent() const;
    double ObservedDataLossPercent()  const;
    double LogicalThroughputBytesPerSecond() const;

    int64_t AverageForwardDelayMicros() const;
    int64_t AverageReverseDelayMicros() const;

    std::vector<int64_t> LatencySamplesMicros() const;

    void Reconfigure(double loss_rate, int fixed_delay_ms, int jitter_ms,
                     int bandwidth_bytes_per_sec, double duplicate_rate, double reorder_rate);

    struct SimulatedTransport;

    SimulatedTransport* CreateTransport(const std::string& name);

    int  BindTransport(SimulatedTransport* transport, int port);
    void UnbindTransport(int port);

    void SendAsync(SimulatedTransport* sender, const uint8_t* data, int length, int remote_port);

private:
    static constexpr int64_t kSchedulerCoalescingMicros    = 1000;
    static constexpr int64_t kLogicalSenderIdleGapMicros   = 500000;
    static constexpr int     kHighBandwidthLogicalClockThreshold = 10 * 1024 * 1024;
    static constexpr int     kDynamicWavePeriodMs          = 5000;

    bool ShouldDrop(const SimulatedDatagram& datagram);
    void CalculateDueMicros(int bytes, bool forward, int64_t& due_micros, int64_t& logical_due_micros);
    void ScheduleDelivery(SimulatedDatagram datagram, int64_t due_micros);
    void Deliver(const SimulatedDatagram& datagram);
    static bool IsDataPacket(const uint8_t* buffer, int count);
    static bool TryGetDataPacketIdentity(const uint8_t* buffer, int count,
                                          std::string& key, int& payload_bytes);
    static uint32_t ReadUInt32BigEndian(const uint8_t* buffer, int offset);
    static int64_t AverageMicros(const std::vector<int64_t>& samples);
    void SchedulerLoop();

    mutable std::mutex _sync;
    std::mt19937 _rng;

    double _loss_rate       = 0;
    int    _fixed_delay_ms  = 0;
    int    _jitter_ms       = 0;
    int    _forward_delay_ms  = 0;
    int    _backward_delay_ms = 0;
    int    _forward_jitter_ms  = 0;
    int    _backward_jitter_ms = 0;
    int    _dynamic_jitter_range_ms = 1;
    int    _dynamic_wave_amp_ms     = 0;
    int    _direction_skew_ms      = 0;
    int    _bandwidth_bytes_per_sec = 0;
    double _duplicate_rate = 0;
    double _reorder_rate   = 0;

    DropRule _drop_rule;

    std::unordered_map<int, SimulatedTransport*> _transports;
    std::vector<int64_t> _latency_samples;
    std::vector<int64_t> _forward_latency_samples;
    std::vector<int64_t> _reverse_latency_samples;
    std::unordered_set<std::string> _logical_data_keys;

    std::map<int64_t, std::vector<SimulatedDatagram>> _scheduled;
    int _next_port = 30000;

    int64_t _next_forward_tx_available  = 0;
    int64_t _next_reverse_tx_available  = 0;
    int64_t _next_forward_logical_tx    = 0;
    int64_t _next_reverse_logical_tx    = 0;

    int64_t _sent_packets       = 0;
    int64_t _sent_data_packets  = 0;
    int64_t _dropped_packets    = 0;
    int64_t _dropped_data_packets = 0;
    int64_t _delivered_packets  = 0;
    int64_t _delivered_data_packets = 0;
    int64_t _delivered_bytes    = 0;
    int64_t _duplicated_packets = 0;
    int64_t _reordered_packets  = 0;

    int64_t _first_data_send_micros    = 0;
    int64_t _last_data_scheduled_micros = 0;
    int64_t _logical_data_bytes        = 0;

    bool _scheduler_running = false;
    std::thread _scheduler_thread;
    std::condition_variable _scheduler_cv;
    bool _stop_scheduler = false;
};

struct NetworkSimulator::SimulatedTransport {
    NetworkSimulator* simulator;
    std::string       name;
    int               local_port = 0;
    bool              disposed   = false;

    using OnDatagramFn = std::function<void(const uint8_t*, int, int)>;
    OnDatagramFn on_datagram;

    SimulatedTransport(NetworkSimulator* sim, const std::string& n);

    void Start(int port);
    void Send(const uint8_t* data, int length, int remote_port);
    void Stop();
    void Dispose();

    void Enqueue(const SimulatedDatagram& datagram);
};

} // namespace ucp_test
