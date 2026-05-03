// network_simulator.h — In-process network simulator for UCP integration tests
//
// Provides deterministic packet routing, delay, jitter, bandwidth serialization,
// loss, duplication, and reordering without real sockets. Multiple simulated
// transports share a single simulator instance so multi-connection tests run
// on one logical network.
//
// Modeled after the C# NetworkSimulator in Ucp.Tests/TestTransport/NetworkSimulator.cs.

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
#include <unordered_set>
#include <vector>

namespace ucp_test {

// ---------------------------------------------------------------------------
// SimulatedDatagram — a single packet in transit through the simulated network
// ---------------------------------------------------------------------------
struct SimulatedDatagram {
    std::vector<uint8_t> buffer;            // Raw packet bytes (copied at send time)
    int                count              = 0;    // Number of valid bytes in buffer
    int                source_port        = 0;    // Sender's local port
    int                destination_port   = 0;    // Recipient's local port
    int64_t            send_micros        = 0;    // Wall-clock timestamp when the packet was injected
    int64_t            logical_due_micros = 0;    // Logical-clock due time (for high-bandwidth throughput calc)
    bool               forward_direction  = true; // True if port direction heuristic considers this forward

    // Creates a shallow copy (the buffer vector is deep-copied by std::vector).
    SimulatedDatagram Clone() const {
        SimulatedDatagram d = *this;
        return d;
    }
};

// DropRule — custom predicate that decides whether a specific datagram should be dropped
using DropRule = std::function<bool(const SimulatedDatagram&)>;

// ---------------------------------------------------------------------------
// NetworkSimulator — deterministic in-process network
// ---------------------------------------------------------------------------
class NetworkSimulator {
public:
    // Constructor parameters match the C# constructor 1:1.
    //   loss_rate:         Uniform random packet loss probability (0.0 to 1.0).
    //   fixed_delay_ms:    Base one-way propagation delay in milliseconds.
    //   jitter_ms:         Random jitter range (±) in milliseconds.
    //   bandwidth_bytes_per_sec: Serialized link bandwidth; 0 disables bandwidth shaping.
    //   seed:              Deterministic PRNG seed.
    //   drop_rule:         Optional per-packet drop predicate (takes precedence over uniform loss).
    //   duplicate_rate:    Probability (0-1) of duplicating each packet.
    //   reorder_rate:      Probability (0-1) of reordering each packet (adds extra delay).
    //   forward_delay_ms:  One-way forward delay; -1 falls back to fixed_delay_ms.
    //   backward_delay_ms: One-way reverse delay; -1 falls back to fixed_delay_ms.
    //   forward_jitter_ms: Forward jitter range; -1 falls back to jitter_ms.
    //   backward_jitter_ms: Reverse jitter range; -1 falls back to jitter_ms.
    //   dynamic_jitter_range_ms: Per-packet dynamic jitter range.
    //   dynamic_wave_amp_ms: Sinusoidal wave jitter amplitude.
    //   direction_skew_ms: Additional skew (positive forward, negative reverse).
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

    ~NetworkSimulator();  // Stops the scheduler thread and cleans up

    // --- Configuration accessors ---
    double LossRate()                   const { return _loss_rate; }
    int    FixedDelayMilliseconds()     const { return _fixed_delay_ms; }
    int    JitterMilliseconds()         const { return _jitter_ms; }
    int    ForwardDelayMilliseconds()   const { return _forward_delay_ms; }
    int    BackwardDelayMilliseconds()  const { return _backward_delay_ms; }
    int    ForwardJitterMilliseconds()  const { return _forward_jitter_ms; }
    int    BackwardJitterMilliseconds() const { return _backward_jitter_ms; }
    int    BandwidthBytesPerSecond()    const { return _bandwidth_bytes_per_sec; }

    // --- Statistics counters ---
    int64_t SentPackets()        const { return _sent_packets; }        // Total packets injected
    int64_t SentDataPackets()    const { return _sent_data_packets; }    // DATA packets (first byte 0x05)
    int64_t DroppedPackets()     const { return _dropped_packets; }     // Total packets dropped
    int64_t DroppedDataPackets() const { return _dropped_data_packets; } // DATA packets dropped
    int64_t DeliveredPackets()   const { return _delivered_packets; }   // Total packets delivered
    int64_t DeliveredDataPackets() const { return _delivered_data_packets; } // DATA packets delivered
    int64_t DeliveredBytes()     const { return _delivered_bytes; }     // Total bytes delivered
    int64_t DuplicatedPackets()  const { return _duplicated_packets; }  // Packets duplicated by the duplication feature
    int64_t ReorderedPackets()   const { return _reordered_packets; }   // Packets reordered via extra delay

    // Loss percentages (percentage, not ratio)
    double ObservedPacketLossPercent() const;  // (dropped / sent) * 100
    double ObservedDataLossPercent()  const;   // (dropped_data / sent_data) * 100

    // Logical throughput: uses a virtual clock to avoid OS scheduling jitter for high-BW links
    double LogicalThroughputBytesPerSecond() const;

    // Average one-way delay in microseconds for each direction
    int64_t AverageForwardDelayMicros() const;
    int64_t AverageReverseDelayMicros() const;

    // Snapshot of all collected end-to-end latency samples
    std::vector<int64_t> LatencySamplesMicros() const;

    // Runtime reconfiguration (resets directional params to symmetric values)
    void Reconfigure(double loss_rate, int fixed_delay_ms, int jitter_ms,
                     int bandwidth_bytes_per_sec, double duplicate_rate, double reorder_rate);

    // Forward-declare the transport type
    struct SimulatedTransport;

    // Creates a new transport bound to this simulator (not yet bound to a port)
    SimulatedTransport* CreateTransport(const std::string& name);

    // Binds a transport to a specific port (0 = auto-assign)
    int  BindTransport(SimulatedTransport* transport, int port);

    // Removes a transport from the registry
    void UnbindTransport(int port);

    // Injects a datagram into the simulated network (called by SimulatedTransport::Send)
    void SendAsync(SimulatedTransport* sender, const uint8_t* data, int length, int remote_port);

private:
    // Coalescing window: datagrams due within this many microseconds of now are delivered immediately
    static constexpr int64_t kSchedulerCoalescingMicros    = 1000;

    // If logical sender has been idle longer than this, its clock resets to wall-clock time
    static constexpr int64_t kLogicalSenderIdleGapMicros   = 500000;

    // Bandwidth threshold above which the virtual logical clock is used for throughput measurement
    static constexpr int     kHighBandwidthLogicalClockThreshold = 10 * 1024 * 1024;  // 10 MB/s

    // Period of the sinusoidal jitter wave in milliseconds
    static constexpr int     kDynamicWavePeriodMs          = 5000;

    bool ShouldDrop(const SimulatedDatagram& datagram);  // Decides drop based on custom rule + uniform loss

    // Computes real-clock due time and logical-clock due time for a packet
    void CalculateDueMicros(int bytes, bool forward, int64_t& due_micros, int64_t& logical_due_micros);

    void ScheduleDelivery(SimulatedDatagram datagram, int64_t due_micros);  // Inserts into delivery schedule
    void Deliver(const SimulatedDatagram& datagram);                        // Routes to destination transport

    static bool IsDataPacket(const uint8_t* buffer, int count);  // Checks for 0x05 first byte

    // Extracts (connectionId:sequenceNumber) key from a DATA packet for dedup
    static bool TryGetDataPacketIdentity(const uint8_t* buffer, int count,
                                          std::string& key, int& payload_bytes);

    static uint32_t ReadUInt32BigEndian(const uint8_t* buffer, int offset);  // Big-endian uint32 reader
    static int64_t AverageMicros(const std::vector<int64_t>& samples);       // Arithmetic mean helper

    void SchedulerLoop();  // Background thread that delivers packets when due

    mutable std::mutex _sync;  // Protects all mutable state below
    std::mt19937 _rng;          // Deterministic PRNG

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

    DropRule _drop_rule;  // Optional custom drop predicate

    std::unordered_map<int, SimulatedTransport*> _transports;  // Registry: port -> transport
    std::vector<int64_t> _latency_samples;                     // End-to-end RTT samples (microseconds)
    std::vector<int64_t> _forward_latency_samples;             // Forward-direction one-way latency samples
    std::vector<int64_t> _reverse_latency_samples;             // Reverse-direction one-way latency samples
    std::unordered_set<std::string> _logical_data_keys;        // Dedup set for throughput tracking

    // Sorted delivery schedule: due_timestamp -> list of datagrams
    std::map<int64_t, std::vector<SimulatedDatagram>> _scheduled;
    int _next_port = 30000;  // Auto-incrementing port counter

    // Bandwidth serialization: next available time for each direction
    int64_t _next_forward_tx_available  = 0;
    int64_t _next_reverse_tx_available  = 0;

    // Virtual logical clock times for throughput calculation (high-bandwidth only)
    int64_t _next_forward_logical_tx    = 0;
    int64_t _next_reverse_logical_tx    = 0;

    // Statistics counters
    int64_t _sent_packets       = 0;
    int64_t _sent_data_packets  = 0;
    int64_t _dropped_packets    = 0;
    int64_t _dropped_data_packets = 0;
    int64_t _delivered_packets  = 0;
    int64_t _delivered_data_packets = 0;
    int64_t _delivered_bytes    = 0;
    int64_t _duplicated_packets = 0;
    int64_t _reordered_packets  = 0;

    // Logical throughput tracking (deduplicated by connectionId:sequenceNumber)
    int64_t _first_data_send_micros    = 0;
    int64_t _last_data_scheduled_micros = 0;
    int64_t _logical_data_bytes        = 0;

    // Scheduler background thread state
    bool _scheduler_running = false;
    std::thread _scheduler_thread;
    std::condition_variable _scheduler_cv;
    bool _stop_scheduler = false;
};

// ---------------------------------------------------------------------------
// NetworkSimulator::SimulatedTransport — an endpoint on the simulated network
// ---------------------------------------------------------------------------
struct NetworkSimulator::SimulatedTransport {
    NetworkSimulator* simulator;  // Parent simulator for routing and scheduling
    std::string       name;       // Human-readable debug identifier
    int               local_port = 0;  // Port this transport is bound to (0 = unbound)
    bool              disposed   = false;

    // Callback invoked when a datagram is delivered to this transport
    using OnDatagramFn = std::function<void(const uint8_t*, int, int)>;
    OnDatagramFn on_datagram;

    SimulatedTransport(NetworkSimulator* sim, const std::string& n);

    void Start(int port);                                  // Bind to a port (0 = auto-assign)
    void Send(const uint8_t* data, int length, int remote_port);  // Send data through the simulator
    void Stop();                                           // Unbind from port
    void Dispose();                                        // Mark disposed and stop

    void Enqueue(const SimulatedDatagram& datagram);       // Called by simulator to deliver inbound data
};

} // namespace ucp_test
