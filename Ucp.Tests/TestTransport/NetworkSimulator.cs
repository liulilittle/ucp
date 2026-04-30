using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Ucp.Transport;

namespace UcpTest.TestTransport
{
    /// <summary>
    /// Deterministic in-process network simulator for UCP integration tests.
    ///
    /// Simulates: bidirectional delay with independent forward/reverse paths,
    /// per-packet random jitter, sinusoidal wave jitter for route fluctuation,
    /// bandwidth serialization (token-bucket at byte granularity), packet loss
    /// (uniform random + custom drop rules), duplication, and reordering.
    ///
    /// For high-bandwidth (>10 MB/s) no-loss scenarios, a virtual logical clock
    /// is used to compute throughput independently of OS thread scheduling jitter.
    ///
    /// Multiple <see cref="SimulatedTransport"/> instances share the same simulator,
    /// enabling multi-connection tests on a single logical network.
    /// </summary>
    internal sealed class NetworkSimulator
    {
        /// <summary>Primary lock protecting all mutable simulator state.</summary>
        private readonly object _sync = new object();

        /// <summary>Deterministic random number generator used for jitter, loss, duplication, and reordering decisions.</summary>
        private readonly Random _random;

        /// <summary>Registry of all simulated transports, keyed by stringified endpoint.</summary>
        private readonly Dictionary<string, SimulatedTransport> _transports = new Dictionary<string, SimulatedTransport>();

        /// <summary>Optional custom drop rule delegate for scenario-specific packet losses.</summary>
        private readonly Func<SimulatedDatagram, bool>? _dropRule;

        /// <summary>Collected RTT latency samples for statistical analysis.</summary>
        private readonly List<long> _latencySamplesMicros = new List<long>();

        /// <summary>Collected one-way forward latency samples.</summary>
        private readonly List<long> _forwardLatencySamplesMicros = new List<long>();

        /// <summary>Collected one-way reverse latency samples.</summary>
        private readonly List<long> _reverseLatencySamplesMicros = new List<long>();

        /// <summary>Set of logical packet keys (connectionId:sequenceNumber) already counted, preventing double-counting of retransmissions.</summary>
        private readonly HashSet<string> _logicalDataPacketKeys = new HashSet<string>();

        /// <summary>Future delivery schedule: maps due timestamps to lists of datagrams awaiting delivery.</summary>
        private readonly SortedDictionary<long, List<SimulatedDatagram>> _scheduledDeliveries = new SortedDictionary<long, List<SimulatedDatagram>>();

        /// <summary>Semaphore used to wake the scheduler loop when new datagrams are scheduled.</summary>
        private readonly SemaphoreSlim _schedulerSignal = new SemaphoreSlim(0, int.MaxValue);

        /// <summary>Coalescing window in microseconds: datagrams due within this window are delivered immediately.</summary>
        private const long SchedulerCoalescingMicros = 1000;

        /// <summary>If the logical sender has been idle longer than this, the logical clock resets to current wall-clock time.</summary>
        private const long LogicalSenderIdleGapMicros = 500000;

        /// <summary>Threshold above which the virtual logical clock is activated for throughput measurement.</summary>
        private const int HighBandwidthLogicalClockThresholdBytesPerSecond = 10 * 1024 * 1024;

        /// <summary>Default range (in ms) for per-packet dynamic jitter.</summary>
        private const int DefaultDynamicJitterRangeMilliseconds = 1;

        /// <summary>Default amplitude (in ms) for sinusoidal wave jitter.</summary>
        private const int DefaultDynamicWaveAmplitudeMilliseconds = 0;

        /// <summary>Period of the sinusoidal jitter wave in milliseconds.</summary>
        private const int DynamicWavePeriodMilliseconds = 5000;

        /// <summary>Default directional skew in milliseconds.</summary>
        private const int DefaultDirectionSkewMilliseconds = 0;

        /// <summary>Next auto-assigned port number for transports that bind without specifying a port.</summary>
        private int _nextPort = 30000;

        /// <summary>Next available microsecond timestamp for forward-direction bandwidth serialization.</summary>
        private long _nextForwardTransmitAvailableMicros;

        /// <summary>Next available microsecond timestamp for reverse-direction bandwidth serialization.</summary>
        private long _nextReverseTransmitAvailableMicros;

        /// <summary>Logical clock next-available time for forward direction (used only for high-bandwidth no-loss scenarios).</summary>
        private long _nextForwardLogicalTransmitAvailableMicros;

        /// <summary>Logical clock next-available time for reverse direction (used only for high-bandwidth no-loss scenarios).</summary>
        private long _nextReverseLogicalTransmitAvailableMicros;

        /// <summary>Rate at which datagrams are duplicated (0 to 1).</summary>
        private double _duplicateRate;

        /// <summary>Rate at which datagrams are reordered (0 to 1).</summary>
        private double _reorderRate;

        /// <summary>Whether the background scheduler loop has been started.</summary>
        private bool _schedulerStarted;

        /// <summary>Wall-clock timestamp of the first DATA packet send, for throughput calculation.</summary>
        private long _firstDataSendMicros;

        /// <summary>Timestamp of the latest scheduled logical delivery, for throughput span calculation.</summary>
        private long _lastDataScheduledMicros;

        /// <summary>Total logical payload bytes tracked (deduplicated by sequence number).</summary>
        private long _logicalDataBytes;

        /// <summary>
        /// Creates a new network simulator with the specified impairment parameters.
        /// </summary>
        /// <param name="lossRate">Uniform random packet loss probability (0 to 1).</param>
        /// <param name="fixedDelayMilliseconds">Base one-way propagation delay in milliseconds.</param>
        /// <param name="jitterMilliseconds">Random jitter range (±) in milliseconds.</param>
        /// <param name="bandwidthBytesPerSecond">Serialized link bandwidth; 0 disables bandwidth serialization.</param>
        /// <param name="seed">Seed for the deterministic random number generator.</param>
        /// <param name="dropRule">Optional custom predicate for per-packet drop decisions.</param>
        /// <param name="duplicateRate">Probability of duplicating each packet.</param>
        /// <param name="reorderRate">Probability of reordering each packet by adding extra delay.</param>
        /// <param name="forwardDelayMilliseconds">One-way forward delay; -1 falls back to <paramref name="fixedDelayMilliseconds"/>.</param>
        /// <param name="backwardDelayMilliseconds">One-way reverse delay; -1 falls back to <paramref name="fixedDelayMilliseconds"/>.</param>
        /// <param name="forwardJitterMilliseconds">Forward-direction jitter range; -1 falls back to <paramref name="jitterMilliseconds"/>.</param>
        /// <param name="backwardJitterMilliseconds">Reverse-direction jitter range; -1 falls back to <paramref name="jitterMilliseconds"/>.</param>
        /// <param name="dynamicJitterRangeMilliseconds">Range for per-packet dynamic jitter component.</param>
        /// <param name="dynamicWaveAmplitudeMilliseconds">Amplitude of sinusoidal wave jitter.</param>
        /// <param name="directionSkewMilliseconds">Additional skew applied positively to forward, negatively to reverse.</param>
        public NetworkSimulator(double lossRate = 0, int fixedDelayMilliseconds = 0, int jitterMilliseconds = 0, int bandwidthBytesPerSecond = 0, int seed = 1234, Func<SimulatedDatagram, bool>? dropRule = null, double duplicateRate = 0, double reorderRate = 0, int forwardDelayMilliseconds = -1, int backwardDelayMilliseconds = -1, int forwardJitterMilliseconds = -1, int backwardJitterMilliseconds = -1, int dynamicJitterRangeMilliseconds = DefaultDynamicJitterRangeMilliseconds, int dynamicWaveAmplitudeMilliseconds = DefaultDynamicWaveAmplitudeMilliseconds, int directionSkewMilliseconds = DefaultDirectionSkewMilliseconds)
        {
            LossRate = lossRate;
            FixedDelayMilliseconds = fixedDelayMilliseconds;
            JitterMilliseconds = jitterMilliseconds;

            // Initialize directional delays; fall back to symmetric values when not specified.
            ForwardDelayMilliseconds = forwardDelayMilliseconds >= 0 ? forwardDelayMilliseconds : fixedDelayMilliseconds;
            BackwardDelayMilliseconds = backwardDelayMilliseconds >= 0 ? backwardDelayMilliseconds : fixedDelayMilliseconds;
            ForwardJitterMilliseconds = forwardJitterMilliseconds >= 0 ? forwardJitterMilliseconds : jitterMilliseconds;
            BackwardJitterMilliseconds = backwardJitterMilliseconds >= 0 ? backwardJitterMilliseconds : jitterMilliseconds;

            DynamicJitterRangeMilliseconds = dynamicJitterRangeMilliseconds;
            DynamicWaveAmplitudeMilliseconds = dynamicWaveAmplitudeMilliseconds;
            DirectionSkewMilliseconds = directionSkewMilliseconds;
            BandwidthBytesPerSecond = bandwidthBytesPerSecond;
            _random = new Random(seed);
            _dropRule = dropRule;
            _duplicateRate = duplicateRate;
            _reorderRate = reorderRate;
        }

        /// <summary>Uniform random packet loss probability.</summary>
        public double LossRate { get; private set; }

        /// <summary>Base one-way propagation delay in milliseconds.</summary>
        public int FixedDelayMilliseconds { get; private set; }

        /// <summary>Random jitter range (±) in milliseconds.</summary>
        public int JitterMilliseconds { get; private set; }

        /// <summary>One-way forward (client-to-server) propagation delay in milliseconds.</summary>
        public int ForwardDelayMilliseconds { get; private set; }

        /// <summary>One-way backward (server-to-client) propagation delay in milliseconds.</summary>
        public int BackwardDelayMilliseconds { get; private set; }

        /// <summary>Forward-direction jitter range in milliseconds.</summary>
        public int ForwardJitterMilliseconds { get; private set; }

        /// <summary>Backward-direction jitter range in milliseconds.</summary>
        public int BackwardJitterMilliseconds { get; private set; }

        /// <summary>Range for per-packet dynamic jitter component in milliseconds.</summary>
        public int DynamicJitterRangeMilliseconds { get; private set; }

        /// <summary>Amplitude of sinusoidal wave jitter in milliseconds.</summary>
        public int DynamicWaveAmplitudeMilliseconds { get; private set; }

        /// <summary>Additional skew in milliseconds (positive forward, negative reverse).</summary>
        public int DirectionSkewMilliseconds { get; private set; }

        /// <summary>Serialized link bandwidth in bytes per second; 0 means unlimited.</summary>
        public int BandwidthBytesPerSecond { get; private set; }

        /// <summary>Total number of packets sent through the simulator.</summary>
        public long SentPackets { get; private set; }

        /// <summary>Number of DATA packets sent through the simulator.</summary>
        public long SentDataPackets { get; private set; }

        /// <summary>Total number of packets dropped (uniform loss or custom drop rule).</summary>
        public long DroppedPackets { get; private set; }

        /// <summary>Number of DATA packets dropped.</summary>
        public long DroppedDataPackets { get; private set; }

        /// <summary>Total number of packets successfully delivered to the target transport.</summary>
        public long DeliveredPackets { get; private set; }

        /// <summary>Number of DATA packets delivered.</summary>
        public long DeliveredDataPackets { get; private set; }

        /// <summary>Total bytes delivered across all packets.</summary>
        public long DeliveredBytes { get; private set; }

        /// <summary>Number of duplicate packets generated by the duplication feature.</summary>
        public long DuplicatedPackets { get; private set; }

        /// <summary>Number of packets subjected to reordering (extra delay).</summary>
        public long ReorderedPackets { get; private set; }

        /// <summary>
        /// Computes the effective logical throughput in bytes per second.
        /// For high-bandwidth shaped links, uses a virtual logical clock to factor
        /// out OS scheduling jitter while still accounting for bottleneck
        /// serialization and one-way propagation. For lower-bandwidth and unshaped
        /// links, falls back to wall-clock elapsed measurement.
        /// Throughput is always capped at the configured bottleneck bandwidth so the
        /// report never claims more payload bandwidth than physically possible.
        /// </summary>
        public double LogicalThroughputBytesPerSecond
        {
            get
            {
                lock (_sync)
                {
                    if (_logicalDataBytes <= 0)
                    {
                        return 0;
                    }

                    double rawThroughput = 0;

                    if (_firstDataSendMicros > 0 && _lastDataScheduledMicros > _firstDataSendMicros)
                    {
                        rawThroughput = _logicalDataBytes * 1000000d / (_lastDataScheduledMicros - _firstDataSendMicros);
                    }

                    if (BandwidthBytesPerSecond >= HighBandwidthLogicalClockThresholdBytesPerSecond)
                    {
                        long serializationMicros = (long)Math.Ceiling(_logicalDataBytes * 1000000d / BandwidthBytesPerSecond);
                        long durationMicros = Math.Max(1, serializationMicros + AverageForwardDelayMicros);
                        return _logicalDataBytes * 1000000d / durationMicros;
                    }

                    return BandwidthBytesPerSecond > 0 ? Math.Min(rawThroughput, BandwidthBytesPerSecond) : rawThroughput;
                }
            }
        }

        /// <summary>Observed packet loss percentage across all packets.</summary>
        public double ObservedPacketLossPercent
        {
            get
            {
                lock (_sync)
                {
                    return SentPackets == 0 ? 0d : DroppedPackets * 100d / SentPackets;
                }
            }
        }

        /// <summary>Observed data packet loss percentage (DATA packets only).</summary>
        public double ObservedDataLossPercent
        {
            get
            {
                lock (_sync)
                {
                    return SentDataPackets == 0 ? 0d : DroppedDataPackets * 100d / SentDataPackets;
                }
            }
        }

        /// <summary>Snapshot of all collected RTT latency samples.</summary>
        public IList<long> LatencySamplesMicros
        {
            get
            {
                lock (_sync)
                {
                    return new List<long>(_latencySamplesMicros);
                }
            }
        }

        /// <summary>Average one-way forward propagation delay in microseconds.</summary>
        public long AverageForwardDelayMicros
        {
            get
            {
                lock (_sync)
                {
                    return AverageMicros(_forwardLatencySamplesMicros);
                }
            }
        }

        /// <summary>Average one-way reverse propagation delay in microseconds.</summary>
        public long AverageReverseDelayMicros
        {
            get
            {
                lock (_sync)
                {
                    return AverageMicros(_reverseLatencySamplesMicros);
                }
            }
        }

        /// <summary>
        /// Reconfigures the simulator's impairment parameters at runtime.
        /// Resets all directional parameters to symmetric values.
        /// </summary>
        public void Configure(double lossRate, int fixedDelayMilliseconds, int jitterMilliseconds, int bandwidthBytesPerSecond, double duplicateRate, double reorderRate)
        {
            lock (_sync)
            {
                LossRate = lossRate;
                FixedDelayMilliseconds = fixedDelayMilliseconds;
                JitterMilliseconds = jitterMilliseconds;
                ForwardDelayMilliseconds = fixedDelayMilliseconds;
                BackwardDelayMilliseconds = fixedDelayMilliseconds;
                ForwardJitterMilliseconds = jitterMilliseconds;
                BackwardJitterMilliseconds = jitterMilliseconds;
                DynamicJitterRangeMilliseconds = DefaultDynamicJitterRangeMilliseconds;
                DynamicWaveAmplitudeMilliseconds = DefaultDynamicWaveAmplitudeMilliseconds;
                DirectionSkewMilliseconds = DefaultDirectionSkewMilliseconds;
                BandwidthBytesPerSecond = bandwidthBytesPerSecond;
                _duplicateRate = duplicateRate;
                _reorderRate = reorderRate;
            }
        }

        /// <summary>
        /// Creates a new <see cref="SimulatedTransport"/> bound to this simulator.
        /// </summary>
        /// <param name="name">A human-readable identifier for debugging.</param>
        /// <returns>A new simulated transport instance.</returns>
        public SimulatedTransport CreateTransport(string name)
        {
            return new SimulatedTransport(this, name);
        }

        /// <summary>
        /// Registers a transport in the peer registry. Normalizes wildcard addresses to loopback
        /// and auto-assigns a port if zero.
        /// </summary>
        /// <param name="transport">The transport to bind.</param>
        /// <param name="local">The desired local endpoint.</param>
        /// <returns>The actual bound endpoint (with resolved port).</returns>
        internal IPEndPoint BindTransport(SimulatedTransport transport, IPEndPoint local)
        {
            IPEndPoint normalized = Normalize(local);
            lock (_sync)
            {
                int port = normalized.Port;

                // Auto-assign port from the incrementing counter if not specified.
                if (port == 0)
                {
                    port = Interlocked.Increment(ref _nextPort);
                }

                normalized = new IPEndPoint(normalized.Address, port);
                _transports[CreateKey(normalized)] = transport;
            }

            return normalized;
        }

        /// <summary>
        /// Removes a transport from the peer registry by its local endpoint.
        /// </summary>
        /// <param name="local">The local endpoint to unbind.</param>
        internal void UnbindTransport(IPEndPoint local)
        {
            if (local == null)
            {
                return;
            }

            lock (_sync)
            {
                _transports.Remove(CreateKey(Normalize(local)));
            }
        }

        /// <summary>
        /// Sends a datagram through the simulated network asynchronously. The buffer is
        /// copied immediately so the caller can reuse it. This method computes the
        /// delivery due time, applies all impairments, and schedules delivery.
        /// </summary>
        /// <param name="sender">The sending transport.</param>
        /// <param name="buffer">The data buffer to send.</param>
        /// <param name="remote">The destination endpoint.</param>
        /// <param name="cancellationToken">Cancellation token (currently unused in simulation).</param>
        internal async Task SendAsync(SimulatedTransport sender, ArraySegment<byte> buffer, IPEndPoint remote, CancellationToken cancellationToken)
        {
            // Copy the buffer so the sender can immediately reuse it.
            byte[] copy = new byte[buffer.Count];
            if (buffer.Array == null)
            {
                throw new ArgumentException("Send buffer cannot be null.", nameof(buffer));
            }

            Buffer.BlockCopy(buffer.Array, buffer.Offset, copy, 0, buffer.Count);

            IPEndPoint source = (IPEndPoint)sender.LocalEndPoint;
            IPEndPoint destination = Normalize(remote);
            long sendMicros = DateTime.UtcNow.Ticks / 10L;

            // Build the simulated datagram with all metadata.
            SimulatedDatagram datagram = new SimulatedDatagram();
            datagram.Buffer = copy;
            datagram.Count = copy.Length;
            datagram.Source = source;
            datagram.Destination = destination;
            datagram.SendMicros = sendMicros;

            // Determine direction: lower source port -> forward direction heuristic.
            datagram.ForwardDirection = source.Port <= destination.Port;

            bool drop;
            long dueMicros;
            bool duplicate;
            bool reorder;

            lock (_sync)
            {
                // Track send statistics.
                bool isDataPacket = IsDataPacket(datagram.Buffer, datagram.Count);
                SentPackets++;
                if (isDataPacket)
                {
                    SentDataPackets++;
                }

                // Decide whether to drop this packet.
                drop = ShouldDrop(datagram);
                if (drop)
                {
                    DroppedPackets++;
                    if (isDataPacket)
                    {
                        DroppedDataPackets++;
                    }

                    return;
                }

                // Calculate the delivery due time including bandwidth serialization.
                long logicalDueMicros;
                dueMicros = CalculateDueMicros(copy.Length, source.Port <= destination.Port, out logicalDueMicros);
                datagram.LogicalDueMicros = logicalDueMicros;

                // Decide whether to duplicate or reorder this packet.
                duplicate = _duplicateRate > 0 && _random.NextDouble() < _duplicateRate;
                reorder = _reorderRate > 0 && _random.NextDouble() < _reorderRate;

                if (duplicate)
                {
                    DuplicatedPackets++;
                }

                if (reorder)
                {
                    ReorderedPackets++;
                    // Add extra delay to simulate reordering: at least 1ms beyond max expected delay.
                    dueMicros += Math.Max(1000L, (FixedDelayMilliseconds + JitterMilliseconds + 1) * 1000L);
                }
            }

            // Schedule the primary delivery.
            ScheduleDelivery(datagram, dueMicros, cancellationToken);

            // If duplicating, schedule a second copy with a slight offset.
            if (duplicate)
            {
                SimulatedDatagram duplicateDatagram = datagram.Clone();
                ScheduleDelivery(duplicateDatagram, dueMicros + 1000L, cancellationToken);
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }

        /// <summary>
        /// Inserts a datagram into the scheduled-deliveries map and signals the scheduler loop.
        /// Also tracks logical data bytes for throughput computation.
        /// </summary>
        /// <param name="datagram">The datagram to schedule.</param>
        /// <param name="dueMicros">The microsecond timestamp when this datagram should be delivered.</param>
        /// <param name="cancellationToken">Cancellation token (currently unused).</param>
        private void ScheduleDelivery(SimulatedDatagram datagram, long dueMicros, CancellationToken cancellationToken)
        {
            long nowMicros = DateTime.UtcNow.Ticks / 10L;
            bool shouldSignal = false;

            lock (_sync)
            {
                int logicalPayloadBytes;
                string logicalPacketKey;

                // Track each unique logical DATA packet exactly once (by connectionId:sequenceNumber)
                // so retransmissions do not inflate throughput measurements.
                if (TryGetDataPacketIdentity(datagram.Buffer, datagram.Count, out logicalPacketKey, out logicalPayloadBytes) && _logicalDataPacketKeys.Add(logicalPacketKey))
                {
                    if (logicalPayloadBytes > 0)
                    {
                        _logicalDataBytes += logicalPayloadBytes;
                    }

                    // Record the first and last data packet timestamps for span calculation.
                    if (_firstDataSendMicros == 0)
                    {
                        _firstDataSendMicros = nowMicros;
                    }

                    long logicalDueMicros = datagram.LogicalDueMicros > 0 ? datagram.LogicalDueMicros : dueMicros;
                    if (logicalDueMicros > _lastDataScheduledMicros)
                    {
                        _lastDataScheduledMicros = logicalDueMicros;
                    }
                }

                bool wasEmpty = _scheduledDeliveries.Count == 0;

                // Get the current earliest scheduled key if any.
                long previousFirstKey = 0;
                foreach (KeyValuePair<long, List<SimulatedDatagram>> pair in _scheduledDeliveries)
                {
                    previousFirstKey = pair.Key;
                    break;
                }

                // Add the datagram to the bucket for its due time.
                List<SimulatedDatagram>? bucket;
                if (!_scheduledDeliveries.TryGetValue(dueMicros, out bucket))
                {
                    bucket = new List<SimulatedDatagram>();
                    _scheduledDeliveries[dueMicros] = bucket;
                }

                bucket.Add(datagram);

                // Start the scheduler loop if this is the first delivery.
                if (!_schedulerStarted)
                {
                    _schedulerStarted = true;
                    Task.Run(SchedulerLoopAsync);
                    shouldSignal = true;
                }
                else if (wasEmpty || previousFirstKey == 0 || dueMicros < previousFirstKey)
                {
                    // Signal if this new entry is earlier than the previously earliest entry.
                    shouldSignal = true;
                }
            }

            if (shouldSignal)
            {
                _schedulerSignal.Release();
            }
        }

        /// <summary>
        /// Background loop that delivers scheduled datagrams when their due time arrives.
        /// Runs until the schedule is empty, then exits to save resources.
        /// </summary>
        private async Task SchedulerLoopAsync()
        {
            while (true)
            {
                List<SimulatedDatagram>? due = null;
                int waitMilliseconds = -1;

                lock (_sync)
                {
                    if (_scheduledDeliveries.Count > 0)
                    {
                        // Peek at the earliest scheduled delivery timestamp.
                        long firstKey = 0;
                        foreach (KeyValuePair<long, List<SimulatedDatagram>> pair in _scheduledDeliveries)
                        {
                            firstKey = pair.Key;
                            break;
                        }

                        long dueMicros = firstKey;
                        long nowMicros = DateTime.UtcNow.Ticks / 10L;

                        // If the due time is within the coalescing window, deliver immediately.
                        if (dueMicros <= nowMicros + SchedulerCoalescingMicros)
                        {
                            due = _scheduledDeliveries[firstKey];
                            _scheduledDeliveries.Remove(firstKey);
                        }
                        else
                        {
                            // Calculate how long to wait before the next delivery.
                            waitMilliseconds = Math.Max(1, (int)Math.Ceiling((dueMicros - nowMicros) / 1000d));
                        }
                    }
                }

                if (due != null)
                {
                    // Deliver all datagrams in the due bucket.
                    for (int i = 0; i < due.Count; i++)
                    {
                        Deliver(due[i]);
                    }

                    continue;
                }

                // If nothing is due and no wait time was computed, wait for a signal or timeout.
                if (waitMilliseconds < 0)
                {
                    bool signaled = await _schedulerSignal.WaitAsync(100).ConfigureAwait(false);

                    // If no signal and the schedule is still empty, exit the loop.
                    if (!signaled)
                    {
                        lock (_sync)
                        {
                            if (_scheduledDeliveries.Count == 0)
                            {
                                _schedulerStarted = false;
                                return;
                            }
                        }
                    }
                }
                else
                {
                    // Wait until the next delivery is due, then re-check.
                    await Task.Delay(waitMilliseconds).ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// Delivers a single datagram to its destination transport and records delivery statistics.
        /// </summary>
        /// <param name="datagram">The datagram to deliver.</param>
        private void Deliver(SimulatedDatagram datagram)
        {
            SimulatedTransport? target = null;

            // Look up the destination transport in the registry.
            lock (_sync)
            {
                _transports.TryGetValue(CreateKey(datagram.Destination), out target);
            }

            if (target == null)
            {
                return;
            }

            // Route the datagram into the target transport's inbound queue.
            target.Enqueue(datagram);

            // Update delivery statistics under the lock.
            lock (_sync)
            {
                DeliveredPackets++;
                DeliveredBytes += datagram.Count;

                if (IsDataPacket(datagram.Buffer, datagram.Count))
                {
                    DeliveredDataPackets++;
                }

                // Record the end-to-end latency for this delivery.
                long nowMicros = DateTime.UtcNow.Ticks / 10L;
                long latencyMicros = nowMicros - datagram.SendMicros;
                if (latencyMicros >= 0)
                {
                    _latencySamplesMicros.Add(latencyMicros);
                }
            }
        }

        /// <summary>
        /// Computes the arithmetic mean of a list of long values. Returns 0 for null or empty lists.
        /// </summary>
        /// <param name="samples">The list of samples to average.</param>
        /// <returns>The arithmetic mean, or 0 if no samples exist.</returns>
        private static long AverageMicros(List<long> samples)
        {
            if (samples == null || samples.Count == 0)
            {
                return 0;
            }

            long total = 0;
            for (int i = 0; i < samples.Count; i++)
            {
                total += samples[i];
            }

            return total / samples.Count;
        }

        /// <summary>
        /// Determines whether a datagram should be dropped, first checking the custom drop rule,
        /// then falling back to uniform random loss.
        /// </summary>
        /// <param name="datagram">The datagram to evaluate.</param>
        /// <returns>True if the datagram should be dropped.</returns>
        private bool ShouldDrop(SimulatedDatagram datagram)
        {
            // Custom drop rules take precedence over uniform random loss.
            if (_dropRule != null && _dropRule(datagram))
            {
                return true;
            }

            if (LossRate <= 0)
            {
                return false;
            }

            return _random.NextDouble() < LossRate;
        }

        /// <summary>
        /// Calculates the delivery due timestamp for a packet, accounting for:
        /// fixed delay, random jitter, dynamic jitter, sinusoidal wave jitter, directional skew,
        /// and bandwidth serialization (token-bucket at byte granularity).
        /// </summary>
        /// <param name="bytes">Size of the packet in bytes.</param>
        /// <param name="forwardDirection">True if this is a forward-direction packet.</param>
        /// <param name="logicalDueMicros">Output: the logical-clock due time for throughput measurement.</param>
        /// <returns>The real-clock delivery due timestamp in microseconds.</returns>
        private long CalculateDueMicros(int bytes, bool forwardDirection, out long logicalDueMicros)
        {
            // Select directional delay and jitter values.
            int fixedDelayMilliseconds = forwardDirection ? ForwardDelayMilliseconds : BackwardDelayMilliseconds;
            int jitterMilliseconds = forwardDirection ? ForwardJitterMilliseconds : BackwardJitterMilliseconds;

            // Random jitter: uniform ± range.
            int jitter = 0;
            if (jitterMilliseconds > 0)
            {
                jitter = _random.Next(-jitterMilliseconds, jitterMilliseconds + 1);
            }

            // Dynamic jitter: additional random component capped at 1/3 of fixed delay.
            int dynamicJitter = 0;
            if (DynamicJitterRangeMilliseconds > 0)
            {
                int cappedRange = Math.Min(DynamicJitterRangeMilliseconds, Math.Max(1, fixedDelayMilliseconds / 3));
                dynamicJitter = _random.Next(-cappedRange, cappedRange + 1);
            }

            // Phase offset: 0 for forward, π/2 for reverse, producing 90° out-of-phase waves.
            double phaseOffset = forwardDirection ? 0d : Math.PI / 2d;

            // Sinusoidal wave jitter: simulates periodic route fluctuation.
            double wave = 0d;
            if (DynamicWaveAmplitudeMilliseconds > 0)
            {
                long nowForWaveMicros = DateTime.UtcNow.Ticks / 10L;
                double phase = ((nowForWaveMicros % (DynamicWavePeriodMilliseconds * 1000L)) / (double)(DynamicWavePeriodMilliseconds * 1000L)) * Math.PI * 2d;
                wave = Math.Sin(phase + phaseOffset) * DynamicWaveAmplitudeMilliseconds;
            }

            // Directional skew: positive adds to forward, subtracts from reverse.
            int skew = forwardDirection ? DirectionSkewMilliseconds : -DirectionSkewMilliseconds;

            // Cap skew at 80% of fixed delay to avoid negative propagation.
            int effectiveSkew = Math.Min(Math.Abs(skew), fixedDelayMilliseconds * 80 / 100) * (skew >= 0 ? 1 : -1);

            // Cap wave amplitude relative to fixed delay.
            double effectiveWave = wave * Math.Min(1d, fixedDelayMilliseconds / 30d);

            // Combine all delay components into the propagation time.
            long propagationMicros = (long)Math.Round((fixedDelayMilliseconds + jitter + dynamicJitter + effectiveWave + effectiveSkew) * 1000d);
            if (propagationMicros < 0)
            {
                propagationMicros = 0;
            }

            // Collect latency samples for direction-specific statistics.
            if (forwardDirection)
            {
                _forwardLatencySamplesMicros.Add(propagationMicros);
            }
            else
            {
                _reverseLatencySamplesMicros.Add(propagationMicros);
            }

            long nowMicros = DateTime.UtcNow.Ticks / 10L;
            long transmitCompleteMicros = nowMicros;
            long logicalTransmitCompleteMicros = nowMicros;

            // Bandwidth serialization: compute the time needed to serialize this packet's bytes.
            if (BandwidthBytesPerSecond > 0)
            {
                long serializationMicros = (long)Math.Ceiling(bytes * 1000000d / BandwidthBytesPerSecond);

                // Real clock: ensure serialization respects the token-bucket pipeline.
                long nextTransmitAvailableMicros = forwardDirection ? _nextForwardTransmitAvailableMicros : _nextReverseTransmitAvailableMicros;
                if (nextTransmitAvailableMicros < nowMicros)
                {
                    nextTransmitAvailableMicros = nowMicros;
                }

                nextTransmitAvailableMicros += serializationMicros;
                transmitCompleteMicros = nextTransmitAvailableMicros;

                if (forwardDirection)
                {
                    _nextForwardTransmitAvailableMicros = nextTransmitAvailableMicros;
                }
                else
                {
                    _nextReverseTransmitAvailableMicros = nextTransmitAvailableMicros;
                }

                // Virtual logical clock: used for high-bandwidth scenarios to
                // compute throughput independently of OS scheduling jitter while
                // still accounting for bottleneck serialization.
                bool useVirtualLogicalClock = BandwidthBytesPerSecond >= HighBandwidthLogicalClockThresholdBytesPerSecond;
                long nextLogicalTransmitAvailableMicros = forwardDirection ? _nextForwardLogicalTransmitAvailableMicros : _nextReverseLogicalTransmitAvailableMicros;

                if (!useVirtualLogicalClock)
                {
                    logicalTransmitCompleteMicros = transmitCompleteMicros;
                }
                else
                {
                    // If the logical clock has been idle longer than the gap threshold, reset to now.
                    if (nextLogicalTransmitAvailableMicros == 0 || nowMicros - nextLogicalTransmitAvailableMicros > LogicalSenderIdleGapMicros)
                    {
                        nextLogicalTransmitAvailableMicros = nowMicros;
                    }

                    nextLogicalTransmitAvailableMicros += serializationMicros;
                    logicalTransmitCompleteMicros = nextLogicalTransmitAvailableMicros;

                    if (forwardDirection)
                    {
                        _nextForwardLogicalTransmitAvailableMicros = nextLogicalTransmitAvailableMicros;
                    }
                    else
                    {
                        _nextReverseLogicalTransmitAvailableMicros = nextLogicalTransmitAvailableMicros;
                    }
                }
            }

            logicalDueMicros = logicalTransmitCompleteMicros + propagationMicros;
            return transmitCompleteMicros + propagationMicros;
        }

        /// <summary>
        /// Normalizes an endpoint by replacing wildcard addresses with loopback.
        /// </summary>
        /// <param name="endPoint">The endpoint to normalize.</param>
        /// <returns>A normalized endpoint with a concrete IP address.</returns>
        private static IPEndPoint Normalize(IPEndPoint endPoint)
        {
            if (endPoint == null)
            {
                throw new ArgumentNullException(nameof(endPoint));
            }

            IPAddress address = endPoint.Address;

            // Map wildcard addresses (0.0.0.0, [::]) to loopback for in-process simulation.
            if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address))
            {
                address = IPAddress.Loopback;
            }

            return new IPEndPoint(address, endPoint.Port);
        }

        /// <summary>
        /// Creates a string key for an endpoint suitable for use in the transport registry.
        /// </summary>
        /// <param name="endPoint">The endpoint to key.</param>
        /// <returns>A string in the format "address:port".</returns>
        private static string CreateKey(IPEndPoint endPoint)
        {
            return endPoint.Address + ":" + endPoint.Port;
        }

        /// <summary>
        /// Determines whether a buffer contains a UCP DATA packet by checking the first byte (0x05).
        /// </summary>
        /// <param name="buffer">The packet buffer.</param>
        /// <param name="count">Number of valid bytes in the buffer.</param>
        /// <returns>True if the buffer starts with the DATA packet type byte.</returns>
        private static bool IsDataPacket(byte[] buffer, int count)
        {
            return buffer != null && count > 0 && buffer[0] == 0x05;
        }

        /// <summary>
        /// Attempts to extract the logical identity of a DATA packet for deduplication.
        /// Returns the connection ID and sequence number as a composite key, and the payload size.
        /// </summary>
        /// <param name="buffer">The packet buffer.</param>
        /// <param name="count">Number of valid bytes in the buffer.</param>
        /// <param name="key">Output: "connectionId:sequenceNumber" string.</param>
        /// <param name="payloadBytes">Output: payload size in bytes (total - 20 header bytes).</param>
        /// <returns>True if the buffer is a well-formed DATA packet with extractable identity.</returns>
        private static bool TryGetDataPacketIdentity(byte[] buffer, int count, out string key, out int payloadBytes)
        {
            key = string.Empty;
            payloadBytes = 0;

            // Must be a DATA packet with at least 20 header bytes.
            if (buffer == null || count <= 20 || buffer[0] != 0x05)
            {
                return false;
            }

            // Extract ConnectionId at offset 2 and SequenceNumber at offset 12 (big-endian).
            uint connectionId = ReadUInt32BigEndian(buffer, 2);
            uint sequenceNumber = ReadUInt32BigEndian(buffer, 12);
            key = connectionId.ToString() + ":" + sequenceNumber.ToString();

            // Payload is everything after the 20-byte header.
            payloadBytes = count - 20;
            return true;
        }

        /// <summary>
        /// Reads a 32-bit unsigned integer in big-endian byte order from a buffer.
        /// </summary>
        /// <param name="buffer">The byte buffer.</param>
        /// <param name="offset">The starting offset in the buffer.</param>
        /// <returns>The decoded uint value.</returns>
        private static uint ReadUInt32BigEndian(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset] << 24)
                | ((uint)buffer[offset + 1] << 16)
                | ((uint)buffer[offset + 2] << 8)
                | buffer[offset + 3];
        }

        /// <summary>
        /// Represents a single datagram in flight through the simulated network,
        /// including metadata for delivery scheduling and statistics tracking.
        /// </summary>
        internal sealed class SimulatedDatagram
        {
            /// <summary>The raw bytes of the datagram.</summary>
            public byte[] Buffer = Array.Empty<byte>();

            /// <summary>Number of valid bytes in <see cref="Buffer"/>.</summary>
            public int Count;

            /// <summary>The source endpoint that sent this datagram.</summary>
            public IPEndPoint Source = new IPEndPoint(IPAddress.Loopback, 0);

            /// <summary>The destination endpoint this datagram is addressed to.</summary>
            public IPEndPoint Destination = new IPEndPoint(IPAddress.Loopback, 0);

            /// <summary>Wall-clock timestamp (microseconds) when the datagram was sent.</summary>
            public long SendMicros;

            /// <summary>True if this is a forward-direction datagram (source port ≤ destination port).</summary>
            public bool ForwardDirection;

            /// <summary>Logical-clock due timestamp used for throughput computation in high-bandwidth scenarios.</summary>
            public long LogicalDueMicros;

            /// <summary>
            /// Creates a shallow copy of this datagram. The buffer reference is shared.
            /// </summary>
            /// <returns>A new <see cref="SimulatedDatagram"/> with the same field values.</returns>
            public SimulatedDatagram Clone()
            {
                SimulatedDatagram clone = new SimulatedDatagram();
                clone.Buffer = Buffer;
                clone.Count = Count;
                clone.Source = Source;
                clone.Destination = Destination;
                clone.SendMicros = SendMicros;
                clone.ForwardDirection = ForwardDirection;
                clone.LogicalDueMicros = LogicalDueMicros;
                return clone;
            }
        }

        /// <summary>
        /// An in-process transport implementation that routes datagrams through a
        /// <see cref="NetworkSimulator"/> instead of real sockets.
        /// Implements <see cref="IBindableTransport"/> for integration with UCP core.
        /// </summary>
        internal sealed class SimulatedTransport : IBindableTransport
        {
            /// <summary>The parent simulator that manages this transport's routing and scheduling.</summary>
            private readonly NetworkSimulator _simulator;

            /// <summary>Human-readable identifier for debugging.</summary>
            private readonly string _name;

            /// <summary>Whether this transport has been disposed.</summary>
            private bool _disposed;

            /// <summary>Event raised when a datagram arrives at this transport from the simulator.</summary>
            public event Action<byte[], IPEndPoint>? OnDatagram;

            /// <summary>
            /// Creates a new simulated transport bound to the specified simulator.
            /// </summary>
            /// <param name="simulator">The parent simulator instance.</param>
            /// <param name="name">A human-readable name for debugging output.</param>
            public SimulatedTransport(NetworkSimulator simulator, string name)
            {
                _simulator = simulator;
                _name = name;
            }

            /// <summary>The local endpoint this transport is bound to.</summary>
            public EndPoint LocalEndPoint { get; private set; } = null!;

            /// <summary>
            /// Binds this transport to a local port. If already bound, this is a no-op.
            /// </summary>
            /// <param name="port">The port to bind to; 0 for auto-assignment.</param>
            public void Start(int port)
            {
                if (LocalEndPoint != null)
                {
                    return;
                }

                LocalEndPoint = _simulator.BindTransport(this, new IPEndPoint(IPAddress.Any, port));
            }

            /// <summary>
            /// Sends a buffer to the specified remote endpoint through the simulator.
            /// If not yet bound, auto-binds to port 0.
            /// </summary>
            /// <param name="data">The data bytes to send.</param>
            /// <param name="remote">The destination endpoint.</param>
            public void Send(byte[] data, IPEndPoint remote)
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(_name);
                }

                if (LocalEndPoint == null)
                {
                    Start(0);
                }

                // Fire-and-forget: the simulator handles delivery asynchronously.
                _ = _simulator.SendAsync(this, new ArraySegment<byte>(data), remote, CancellationToken.None);
            }

            /// <summary>
            /// Unbinds this transport from the simulator registry.
            /// </summary>
            public void Stop()
            {
                if (LocalEndPoint != null)
                {
                    _simulator.UnbindTransport((IPEndPoint)LocalEndPoint);
                }
            }

            /// <summary>
            /// Disposes this transport, stopping it and marking it as disposed.
            /// </summary>
            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                Stop();
            }

            /// <summary>
            /// Called by the simulator to deliver an inbound datagram to this transport.
            /// Raises the <see cref="OnDatagram"/> event if any handler is subscribed.
            /// </summary>
            /// <param name="datagram">The inbound datagram to deliver.</param>
            internal void Enqueue(SimulatedDatagram datagram)
            {
                if (_disposed)
                {
                    return;
                }

                Action<byte[], IPEndPoint>? handler = OnDatagram;
                if (handler != null)
                {
                    handler(datagram.Buffer, datagram.Source);
                }
            }
        }
    }
}
