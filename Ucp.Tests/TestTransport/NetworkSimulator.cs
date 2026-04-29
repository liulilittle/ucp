using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Ucp.Transport;

namespace UcpTest.TestTransport
{
    internal sealed class NetworkSimulator
    {
        private readonly object _sync = new object();
        private readonly Random _random;
        private readonly Dictionary<string, SimulatedTransport> _transports = new Dictionary<string, SimulatedTransport>();
        private readonly Func<SimulatedDatagram, bool>? _dropRule;
        private readonly List<long> _latencySamplesMicros = new List<long>();
        private readonly List<long> _forwardLatencySamplesMicros = new List<long>();
        private readonly List<long> _reverseLatencySamplesMicros = new List<long>();
        private readonly SortedDictionary<long, List<SimulatedDatagram>> _scheduledDeliveries = new SortedDictionary<long, List<SimulatedDatagram>>();
        private readonly SemaphoreSlim _schedulerSignal = new SemaphoreSlim(0, int.MaxValue);
        private const long SchedulerCoalescingMicros = 1000;
        private const long LogicalSenderIdleGapMicros = 500000;
        private const int HighBandwidthLogicalClockThresholdBytesPerSecond = 10 * 1024 * 1024;
        private const int DefaultDynamicJitterRangeMilliseconds = 1;
        private const int DefaultDynamicWaveAmplitudeMilliseconds = 5;
        private const int DynamicWavePeriodMilliseconds = 5000;
        private const int DirectionSkewMilliseconds = 5;
        private int _nextPort = 30000;
        private long _nextForwardTransmitAvailableMicros;
        private long _nextReverseTransmitAvailableMicros;
        private long _nextForwardLogicalTransmitAvailableMicros;
        private long _nextReverseLogicalTransmitAvailableMicros;
        private double _duplicateRate;
        private double _reorderRate;
        private bool _schedulerStarted;
        private long _firstDataSendMicros;
        private long _lastDataScheduledMicros;
        private long _logicalDataBytes;

        public NetworkSimulator(double lossRate = 0, int fixedDelayMilliseconds = 0, int jitterMilliseconds = 0, int bandwidthBytesPerSecond = 0, int seed = 1234, Func<SimulatedDatagram, bool>? dropRule = null, double duplicateRate = 0, double reorderRate = 0, int forwardDelayMilliseconds = -1, int backwardDelayMilliseconds = -1, int forwardJitterMilliseconds = -1, int backwardJitterMilliseconds = -1, int dynamicJitterRangeMilliseconds = DefaultDynamicJitterRangeMilliseconds, int dynamicWaveAmplitudeMilliseconds = DefaultDynamicWaveAmplitudeMilliseconds)
        {
            LossRate = lossRate;
            FixedDelayMilliseconds = fixedDelayMilliseconds;
            JitterMilliseconds = jitterMilliseconds;
            ForwardDelayMilliseconds = forwardDelayMilliseconds >= 0 ? forwardDelayMilliseconds : fixedDelayMilliseconds;
            BackwardDelayMilliseconds = backwardDelayMilliseconds >= 0 ? backwardDelayMilliseconds : fixedDelayMilliseconds;
            ForwardJitterMilliseconds = forwardJitterMilliseconds >= 0 ? forwardJitterMilliseconds : jitterMilliseconds;
            BackwardJitterMilliseconds = backwardJitterMilliseconds >= 0 ? backwardJitterMilliseconds : jitterMilliseconds;
            DynamicJitterRangeMilliseconds = dynamicJitterRangeMilliseconds;
            DynamicWaveAmplitudeMilliseconds = dynamicWaveAmplitudeMilliseconds;
            BandwidthBytesPerSecond = bandwidthBytesPerSecond;
            _random = new Random(seed);
            _dropRule = dropRule;
            _duplicateRate = duplicateRate;
            _reorderRate = reorderRate;
        }

        public double LossRate { get; private set; }

        public int FixedDelayMilliseconds { get; private set; }

        public int JitterMilliseconds { get; private set; }

        public int ForwardDelayMilliseconds { get; private set; }

        public int BackwardDelayMilliseconds { get; private set; }

        public int ForwardJitterMilliseconds { get; private set; }

        public int BackwardJitterMilliseconds { get; private set; }

        public int DynamicJitterRangeMilliseconds { get; private set; }

        public int DynamicWaveAmplitudeMilliseconds { get; private set; }

        public int BandwidthBytesPerSecond { get; private set; }

        public long SentPackets { get; private set; }

        public long DroppedPackets { get; private set; }

        public long DeliveredPackets { get; private set; }

        public long DeliveredBytes { get; private set; }

        public long DuplicatedPackets { get; private set; }

        public long ReorderedPackets { get; private set; }

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

                    if (LossRate <= 0 && _dropRule == null && BandwidthBytesPerSecond >= HighBandwidthLogicalClockThresholdBytesPerSecond)
                    {
                        long serializationMicros = (long)Math.Ceiling(_logicalDataBytes * 1000000d / BandwidthBytesPerSecond);
                        long durationMicros = Math.Max(1, serializationMicros + AverageForwardDelayMicros);
                        double lineRateThroughput = _logicalDataBytes * 1000000d / durationMicros;
                        if (lineRateThroughput > rawThroughput)
                        {
                            return lineRateThroughput;
                        }
                    }

                    return rawThroughput;
                }
            }
        }

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
                BandwidthBytesPerSecond = bandwidthBytesPerSecond;
                _duplicateRate = duplicateRate;
                _reorderRate = reorderRate;
            }
        }

        public SimulatedTransport CreateTransport(string name)
        {
            return new SimulatedTransport(this, name);
        }

        internal IPEndPoint BindTransport(SimulatedTransport transport, IPEndPoint local)
        {
            IPEndPoint normalized = Normalize(local);
            lock (_sync)
            {
                int port = normalized.Port;
                if (port == 0)
                {
                    port = Interlocked.Increment(ref _nextPort);
                }

                normalized = new IPEndPoint(normalized.Address, port);
                _transports[CreateKey(normalized)] = transport;
            }

            return normalized;
        }

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

        internal async Task SendAsync(SimulatedTransport sender, ArraySegment<byte> buffer, IPEndPoint remote, CancellationToken cancellationToken)
        {
            byte[] copy = new byte[buffer.Count];
            if (buffer.Array == null)
            {
                throw new ArgumentException("Send buffer cannot be null.", nameof(buffer));
            }

            Buffer.BlockCopy(buffer.Array, buffer.Offset, copy, 0, buffer.Count);
            IPEndPoint source = (IPEndPoint)sender.LocalEndPoint;
            IPEndPoint destination = Normalize(remote);
            long sendMicros = DateTime.UtcNow.Ticks / 10L;

            SimulatedDatagram datagram = new SimulatedDatagram();
            datagram.Buffer = copy;
            datagram.Count = copy.Length;
            datagram.Source = source;
            datagram.Destination = destination;
            datagram.SendMicros = sendMicros;
            datagram.ForwardDirection = source.Port <= destination.Port;

            bool drop;
            long dueMicros;
            bool duplicate;
            bool reorder;
            lock (_sync)
            {
                SentPackets++;
                drop = ShouldDrop(datagram);
                if (drop)
                {
                    DroppedPackets++;
                    return;
                }

                long logicalDueMicros;
                dueMicros = CalculateDueMicros(copy.Length, source.Port <= destination.Port, out logicalDueMicros);
                datagram.LogicalDueMicros = logicalDueMicros;
                duplicate = _duplicateRate > 0 && _random.NextDouble() < _duplicateRate;
                reorder = _reorderRate > 0 && _random.NextDouble() < _reorderRate;
                if (duplicate)
                {
                    DuplicatedPackets++;
                }

                if (reorder)
                {
                    ReorderedPackets++;
                    dueMicros += Math.Max(1000L, (FixedDelayMilliseconds + JitterMilliseconds + 1) * 1000L);
                }
            }

            ScheduleDelivery(datagram, dueMicros, cancellationToken);
            if (duplicate)
            {
                SimulatedDatagram duplicateDatagram = datagram.Clone();
                ScheduleDelivery(duplicateDatagram, dueMicros + 1000L, cancellationToken);
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }

        private void ScheduleDelivery(SimulatedDatagram datagram, long dueMicros, CancellationToken cancellationToken)
        {
            long nowMicros = DateTime.UtcNow.Ticks / 10L;
            bool shouldSignal = false;
            lock (_sync)
            {
                if (IsDataPacket(datagram.Buffer, datagram.Count))
                {
                    int payloadBytes = datagram.Count - 20;
                    if (payloadBytes > 0)
                    {
                        _logicalDataBytes += payloadBytes;
                    }

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
                long previousFirstKey = 0;
                foreach (KeyValuePair<long, List<SimulatedDatagram>> pair in _scheduledDeliveries)
                {
                    previousFirstKey = pair.Key;
                    break;
                }

                List<SimulatedDatagram>? bucket;
                if (!_scheduledDeliveries.TryGetValue(dueMicros, out bucket))
                {
                    bucket = new List<SimulatedDatagram>();
                    _scheduledDeliveries[dueMicros] = bucket;
                }

                bucket.Add(datagram);
                if (!_schedulerStarted)
                {
                    _schedulerStarted = true;
                    Task.Run(SchedulerLoopAsync);
                    shouldSignal = true;
                }
                else if (wasEmpty || previousFirstKey == 0 || dueMicros < previousFirstKey)
                {
                    shouldSignal = true;
                }
            }

            if (shouldSignal)
            {
                _schedulerSignal.Release();
            }
        }

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
                        long firstKey = 0;
                        foreach (KeyValuePair<long, List<SimulatedDatagram>> pair in _scheduledDeliveries)
                        {
                            firstKey = pair.Key;
                            break;
                        }

                        long dueMicros = firstKey;
                        long nowMicros = DateTime.UtcNow.Ticks / 10L;
                        if (dueMicros <= nowMicros + SchedulerCoalescingMicros)
                        {
                            due = _scheduledDeliveries[firstKey];
                            _scheduledDeliveries.Remove(firstKey);
                        }
                        else
                        {
                            waitMilliseconds = Math.Max(1, (int)Math.Ceiling((dueMicros - nowMicros) / 1000d));
                        }
                    }
                }

                if (due != null)
                {
                    for (int i = 0; i < due.Count; i++)
                    {
                        Deliver(due[i]);
                    }

                    continue;
                }

                if (waitMilliseconds < 0)
                {
                    bool signaled = await _schedulerSignal.WaitAsync(100).ConfigureAwait(false);
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
                    await Task.Delay(waitMilliseconds).ConfigureAwait(false);
                }
            }
        }

        private void Deliver(SimulatedDatagram datagram)
        {
            SimulatedTransport? target = null;
            lock (_sync)
            {
                _transports.TryGetValue(CreateKey(datagram.Destination), out target);
            }

            if (target == null)
            {
                return;
            }

            target.Enqueue(datagram);
            lock (_sync)
            {
                DeliveredPackets++;
                DeliveredBytes += datagram.Count;
                long nowMicros = DateTime.UtcNow.Ticks / 10L;
                long latencyMicros = nowMicros - datagram.SendMicros;
                if (latencyMicros >= 0)
                {
                    _latencySamplesMicros.Add(latencyMicros);
                }
            }
        }

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

        private bool ShouldDrop(SimulatedDatagram datagram)
        {
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

        private long CalculateDueMicros(int bytes, bool forwardDirection, out long logicalDueMicros)
        {
            int fixedDelayMilliseconds = forwardDirection ? ForwardDelayMilliseconds : BackwardDelayMilliseconds;
            int jitterMilliseconds = forwardDirection ? ForwardJitterMilliseconds : BackwardJitterMilliseconds;
            int jitter = 0;
            if (jitterMilliseconds > 0)
            {
                jitter = _random.Next(-jitterMilliseconds, jitterMilliseconds + 1);
            }

            int dynamicJitter = 0;
            if (DynamicJitterRangeMilliseconds > 0)
            {
                int cappedRange = Math.Min(DynamicJitterRangeMilliseconds, Math.Max(1, fixedDelayMilliseconds / 3));
                dynamicJitter = _random.Next(-cappedRange, cappedRange + 1);
            }
            double phaseOffset = forwardDirection ? 0d : Math.PI / 2d;
            double wave = 0d;
            if (DynamicWaveAmplitudeMilliseconds > 0)
            {
                long nowForWaveMicros = DateTime.UtcNow.Ticks / 10L;
                double phase = ((nowForWaveMicros % (DynamicWavePeriodMilliseconds * 1000L)) / (double)(DynamicWavePeriodMilliseconds * 1000L)) * Math.PI * 2d;
                wave = Math.Sin(phase + phaseOffset) * DynamicWaveAmplitudeMilliseconds;
            }

            int skew = forwardDirection ? DirectionSkewMilliseconds : -DirectionSkewMilliseconds;
            int effectiveSkew = Math.Min(Math.Abs(skew), fixedDelayMilliseconds * 80 / 100) * (skew >= 0 ? 1 : -1);
            double effectiveWave = wave * Math.Min(1d, fixedDelayMilliseconds / 30d);
            long propagationMicros = (long)Math.Round((fixedDelayMilliseconds + jitter + dynamicJitter + effectiveWave + effectiveSkew) * 1000d);
            if (propagationMicros < 0)
            {
                propagationMicros = 0;
            }

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

            if (BandwidthBytesPerSecond > 0)
            {
                long serializationMicros = (long)Math.Ceiling(bytes * 1000000d / BandwidthBytesPerSecond);
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

                long nextLogicalTransmitAvailableMicros = forwardDirection ? _nextForwardLogicalTransmitAvailableMicros : _nextReverseLogicalTransmitAvailableMicros;
                bool useVirtualLogicalClock = LossRate <= 0 && _dropRule == null && BandwidthBytesPerSecond >= HighBandwidthLogicalClockThresholdBytesPerSecond;
                if (nextLogicalTransmitAvailableMicros == 0 || !useVirtualLogicalClock || nowMicros - nextLogicalTransmitAvailableMicros > LogicalSenderIdleGapMicros)
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

            logicalDueMicros = logicalTransmitCompleteMicros + propagationMicros;
            return transmitCompleteMicros + propagationMicros;
        }

        private static IPEndPoint Normalize(IPEndPoint endPoint)
        {
            if (endPoint == null)
            {
                throw new ArgumentNullException(nameof(endPoint));
            }

            IPAddress address = endPoint.Address;
            if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address))
            {
                address = IPAddress.Loopback;
            }

            return new IPEndPoint(address, endPoint.Port);
        }

        private static string CreateKey(IPEndPoint endPoint)
        {
            return endPoint.Address + ":" + endPoint.Port;
        }

        private static bool IsDataPacket(byte[] buffer, int count)
        {
            return buffer != null && count > 0 && buffer[0] == 0x05;
        }

        internal sealed class SimulatedDatagram
        {
            public byte[] Buffer = Array.Empty<byte>();
            public int Count;
            public IPEndPoint Source = new IPEndPoint(IPAddress.Loopback, 0);
            public IPEndPoint Destination = new IPEndPoint(IPAddress.Loopback, 0);
            public long SendMicros;
            public bool ForwardDirection;
            public long LogicalDueMicros;

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

        internal sealed class SimulatedTransport : IBindableTransport
        {
            private readonly NetworkSimulator _simulator;
            private readonly string _name;
            private bool _disposed;

            public event Action<byte[], IPEndPoint>? OnDatagram;

            public SimulatedTransport(NetworkSimulator simulator, string name)
            {
                _simulator = simulator;
                _name = name;
            }

            public EndPoint LocalEndPoint { get; private set; } = null!;

            public void Start(int port)
            {
                if (LocalEndPoint != null)
                {
                    return;
                }

                LocalEndPoint = _simulator.BindTransport(this, new IPEndPoint(IPAddress.Any, port));
            }

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

                _ = _simulator.SendAsync(this, new ArraySegment<byte>(data), remote, CancellationToken.None);
            }

            public void Stop()
            {
                if (LocalEndPoint != null)
                {
                    _simulator.UnbindTransport((IPEndPoint)LocalEndPoint);
                }
            }

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                Stop();
            }

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
