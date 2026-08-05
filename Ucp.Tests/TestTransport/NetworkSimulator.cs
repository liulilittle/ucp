using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using Ucp.Transport;

namespace UcpTest.TestTransport
{
    public sealed class SimulatedDatagram
    {
        public byte[] Buffer { get; set; } = Array.Empty<byte>();
        public int Length { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public long SendMicros { get; set; }
        public long LogicalDueMicros { get; set; }
        public bool ForwardDirection { get; set; } = true;
        public bool AlreadyReordered { get; set; }
    }

    public sealed class SimulatedTransport : IBindableTransport
    {
        private readonly NetworkSimulator _simulator;
        private bool _disposed;
        private bool _started;

        public string Name { get; }
        public int LocalPort { get; private set; }

        EndPoint? IBindableTransport.LocalEndPoint =>
            LocalPort > 0 ? new IPEndPoint(IPAddress.Loopback, LocalPort) : null;

        public IPEndPoint? LocalEndPoint =>
            LocalPort > 0 ? new IPEndPoint(IPAddress.Loopback, LocalPort) : null;

        public event Action<byte[], IPEndPoint>? OnDatagram;

        event Action<byte[], IPEndPoint>? ITransport.OnDatagram
        {
            add => OnDatagram += value;
            remove => OnDatagram -= value;
        }

        internal SimulatedTransport(NetworkSimulator simulator, string name)
        {
            _simulator = simulator;
            Name = name;
        }

        public void Start(int port)
        {
            if (_disposed) return;
            if (_started) return;
            LocalPort = _simulator.BindTransport(this, port);
            _started = true;
        }

        public void Send(byte[] data, IPEndPoint remote)
        {
            if (_disposed || data == null || data.Length == 0) return;
            _simulator.SendAsync(this, data, remote.Port);
        }

        void ITransport.Send(byte[] data, IPEndPoint remote) => Send(data, remote);

        internal void Deliver(SimulatedDatagram datagram)
        {
            if (_disposed) return;
            var ep = new IPEndPoint(IPAddress.Loopback, datagram.SourcePort);
            OnDatagram?.Invoke(datagram.Buffer, ep);
        }

        public void Stop()
        {
            if (_disposed) return;
            _simulator.UnbindTransport(LocalPort);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
        }
    }

    public delegate bool DropRuleDelegate(SimulatedDatagram datagram);

    public sealed class NetworkSimulator
    {
        private readonly object _sync = new();
        private readonly Random _rng;
        private readonly SortedDictionary<long, List<SimulatedDatagram>> _scheduled = new();
        private readonly Dictionary<int, SimulatedTransport> _transports = new();
        private readonly List<long> _latencySamples = new();
        private readonly List<long> _forwardLatencySamples = new();
        private readonly List<long> _reverseLatencySamples = new();
        private readonly HashSet<string> _logicalDataKeys = new();
        private readonly DropRuleDelegate? _dropRule;
        private int _nextPort = 30000;

        private double _lossRate;
        private int _fixedDelayMs;
        private int _jitterMs;
        private int _forwardDelayMs;
        private int _backwardDelayMs;
        private int _forwardJitterMs;
        private int _backwardJitterMs;
        private int _dynamicJitterRangeMs = 1;
        private int _dynamicWaveAmpMs;
        private int _directionSkewMs;
        private int _bandwidthBps;
        private double _duplicateRate;
        private double _reorderRate;

        private long _nextForwardTxAvailable;
        private long _nextReverseTxAvailable;
        private long _nextForwardLogicalTx;
        private long _nextReverseLogicalTx;

        private long _sentPackets;
        private long _sentDataPackets;
        private long _droppedPackets;
        private long _droppedDataPackets;
        private long _deliveredPackets;
        private long _deliveredDataPackets;
        private long _deliveredBytes;
        private long _duplicatedPackets;
        private long _reorderedPackets;
        private long _firstDataSendMicros;
        private long _lastDataScheduledMicros;
        private long _logicalDataBytes;

        private bool _schedulerRunning;
        private bool _stopScheduler;
        private volatile bool _forceStop;
        private Thread? _schedulerThread;
        private readonly AutoResetEvent _schedulerEvent = new(false);

        private const long SchedulerCoalescingMicros = 1000;
        private const long LogicalSenderIdleGapMicros = 500000;
        private const int HighBandwidthThreshold = 10 * 1024 * 1024;
        private const int DynamicWavePeriodMs = 5000;

        public NetworkSimulator(
            double lossRate = 0,
            int fixedDelayMilliseconds = 0,
            int jitterMilliseconds = 0,
            int bandwidthBytesPerSecond = 0,
            int seed = 1234,
            DropRuleDelegate? dropRule = null,
            double duplicateRate = 0,
            double reorderRate = 0,
            int forwardDelayMilliseconds = -1,
            int backwardDelayMilliseconds = -1,
            int forwardJitterMilliseconds = -1,
            int backwardJitterMilliseconds = -1,
            int dynamicJitterRangeMilliseconds = 1,
            int dynamicWaveAmplitudeMilliseconds = 0,
            int directionSkewMilliseconds = 0)
        {
            _rng = new Random(seed);
            _lossRate = lossRate;
            _fixedDelayMs = fixedDelayMilliseconds;
            _jitterMs = jitterMilliseconds;
            _bandwidthBps = bandwidthBytesPerSecond;
            _dropRule = dropRule;
            _duplicateRate = duplicateRate;
            _reorderRate = reorderRate;
            _dynamicJitterRangeMs = dynamicJitterRangeMilliseconds;
            _dynamicWaveAmpMs = dynamicWaveAmplitudeMilliseconds;
            _directionSkewMs = directionSkewMilliseconds;

            _forwardDelayMs = forwardDelayMilliseconds >= 0 ? forwardDelayMilliseconds : _fixedDelayMs;
            _backwardDelayMs = backwardDelayMilliseconds >= 0 ? backwardDelayMilliseconds : _fixedDelayMs;
            _forwardJitterMs = forwardJitterMilliseconds >= 0 ? forwardJitterMilliseconds : _jitterMs;
            _backwardJitterMs = backwardJitterMilliseconds >= 0 ? backwardJitterMilliseconds : _jitterMs;
        }

        public double LossRate => _lossRate;
        public int ForwardDelayMilliseconds => _forwardDelayMs;
        public int BackwardDelayMilliseconds => _backwardDelayMs;
        public int BandwidthBytesPerSecond => _bandwidthBps;

        public long SentPackets => Interlocked.Read(ref _sentPackets);
        public long SentDataPackets => Interlocked.Read(ref _sentDataPackets);
        public long DroppedPackets => Interlocked.Read(ref _droppedPackets);
        public long DroppedDataPackets => Interlocked.Read(ref _droppedDataPackets);
        public long DeliveredPackets => Interlocked.Read(ref _deliveredPackets);
        public long DeliveredDataPackets => Interlocked.Read(ref _deliveredDataPackets);
        public long DeliveredBytes => Interlocked.Read(ref _deliveredBytes);
        public long DuplicatedPackets => Interlocked.Read(ref _duplicatedPackets);
        public long ReorderedPackets => Interlocked.Read(ref _reorderedPackets);

        public double ObservedPacketLossPercent
        {
            get
            {
                long sent = SentPackets;
                if (sent == 0) return 0.0;
                return (double)DroppedPackets * 100.0 / sent;
            }
        }

        public double ObservedDataLossPercent
        {
            get
            {
                long sent = SentDataPackets;
                if (sent == 0) return 0.0;
                return (double)DroppedDataPackets * 100.0 / sent;
            }
        }

        public double LogicalThroughputBytesPerSecond
        {
            get
            {
                long firstSend = Interlocked.Read(ref _firstDataSendMicros);
                long lastScheduled = Interlocked.Read(ref _lastDataScheduledMicros);
                long dataBytes = Interlocked.Read(ref _logicalDataBytes);
                if (firstSend == 0 || lastScheduled <= firstSend) return 0.0;
                double elapsedSec = (lastScheduled - firstSend) / 1000000.0;
                if (elapsedSec <= 0) return 0.0;
                double tput = dataBytes / elapsedSec;
                if (_bandwidthBps > 0 && tput > _bandwidthBps * 1.01)
                    tput = _bandwidthBps;
                return tput;
            }
        }

        public long[] LatencySamplesMicros
        {
            get { lock (_sync) { return _latencySamples.ToArray(); } }
        }

        public long AverageForwardDelayMicros
        {
            get
            {
                lock (_sync)
                {
                    if (_forwardLatencySamples.Count == 0) return 0;
                    return (long)_forwardLatencySamples.Average();
                }
            }
        }

        public long AverageReverseDelayMicros
        {
            get
            {
                lock (_sync)
                {
                    if (_reverseLatencySamples.Count == 0) return 0;
                    return (long)_reverseLatencySamples.Average();
                }
            }
        }

        internal SimulatedTransport CreateTransport(string name)
        {
            return new SimulatedTransport(this, name);
        }

        internal int BindTransport(SimulatedTransport transport, int port)
        {
            lock (_sync)
            {
                if (port == 0)
                    port = _nextPort++;
                _transports[port] = transport;
                return port;
            }
        }

        internal void UnbindTransport(int port)
        {
            lock (_sync)
            {
                _transports.Remove(port);
            }
        }

        internal void SendAsync(SimulatedTransport sender, byte[] data, int remotePort)
        {
            if (_forceStop) return;

            int length = data.Length;
            Interlocked.Increment(ref _sentPackets);

            bool isData = length > 0 && data[0] == 0x05;
            if (isData)
                Interlocked.Increment(ref _sentDataPackets);

            long nowUs = DateTime.UtcNow.Ticks / 10;
            var datagram = new SimulatedDatagram
            {
                Buffer = (byte[])data.Clone(),
                Length = length,
                SourcePort = sender.LocalPort,
                DestinationPort = remotePort,
                SendMicros = nowUs
            };

            bool forward = DetermineDirection(sender.LocalPort, remotePort);
            datagram.ForwardDirection = forward;

            if (ShouldDrop(datagram))
            {
                Interlocked.Increment(ref _droppedPackets);
                if (isData)
                    Interlocked.Increment(ref _droppedDataPackets);
                return;
            }

            CalculateDueMicros(length, forward, nowUs, out long dueMicros, out long logicalDueMicros);
            datagram.LogicalDueMicros = logicalDueMicros;

            if (isData)
            {
                string? key = GetDataPacketKey(data, length);
                lock (_sync)
                {
                    if (!string.IsNullOrEmpty(key) && _logicalDataKeys.Add(key))
                    {
                        int payloadBytes = Math.Max(0, length - 20);
                        Interlocked.Add(ref _logicalDataBytes, payloadBytes);
                    }
                }
                if (Interlocked.Read(ref _firstDataSendMicros) == 0)
                    Interlocked.Exchange(ref _firstDataSendMicros, nowUs);
                Interlocked.Exchange(ref _lastDataScheduledMicros, logicalDueMicros);
            }

            ScheduleDelivery(datagram, dueMicros);

            if (_duplicateRate > 0 && _rng.NextDouble() < _duplicateRate)
            {
                var dup = new SimulatedDatagram
                {
                    Buffer = (byte[])data.Clone(),
                    Length = length,
                    SourcePort = sender.LocalPort,
                    DestinationPort = remotePort,
                    SendMicros = nowUs,
                    LogicalDueMicros = logicalDueMicros,
                    ForwardDirection = forward
                };
                Interlocked.Increment(ref _duplicatedPackets);
                ScheduleDelivery(dup, dueMicros + _rng.Next(1000, 10000));
            }
        }

        private bool DetermineDirection(int srcPort, int dstPort)
        {
            return srcPort < dstPort;
        }

        private bool ShouldDrop(SimulatedDatagram datagram)
        {
            if (_dropRule != null && _dropRule(datagram))
                return true;
            if (_lossRate > 0 && _rng.NextDouble() < _lossRate)
                return true;
            return false;
        }

        private void CalculateDueMicros(int bytes, bool forward, long nowUs,
            out long dueMicros, out long logicalDueMicros)
        {
            int delayMs = forward ? _forwardDelayMs : _backwardDelayMs;
            int jitterMs = forward ? _forwardJitterMs : _backwardJitterMs;

            int totalJitterMs = jitterMs;
            if (_dynamicJitterRangeMs > 0)
                totalJitterMs += _rng.Next(-_dynamicJitterRangeMs, _dynamicJitterRangeMs + 1);
            if (_dynamicWaveAmpMs > 0)
            {
                double phase = (nowUs % (DynamicWavePeriodMs * 1000)) / (double)(DynamicWavePeriodMs * 1000);
                totalJitterMs += (int)(Math.Sin(phase * 2 * Math.PI) * _dynamicWaveAmpMs);
            }
            if (_directionSkewMs != 0)
                delayMs += forward ? _directionSkewMs : -_directionSkewMs;

            int jitterOffset = totalJitterMs > 0 ? _rng.Next(-totalJitterMs, totalJitterMs + 1) : 0;
            long totalDelayUs = (Math.Max(0, delayMs + jitterOffset)) * 1000L;

            dueMicros = nowUs + totalDelayUs;
            logicalDueMicros = dueMicros;

            if (_bandwidthBps > 0 && bytes > 0)
            {
                long serialUs = (long)bytes * 1000000L / _bandwidthBps;
                long directionKey = forward ? 0 : 1;

                long nextAvail = forward
                    ? Interlocked.Read(ref _nextForwardTxAvailable)
                    : Interlocked.Read(ref _nextReverseTxAvailable);
                long nextLogAvail = forward
                    ? Interlocked.Read(ref _nextForwardLogicalTx)
                    : Interlocked.Read(ref _nextReverseLogicalTx);

                long startUs = Math.Max(dueMicros, nextAvail);
                dueMicros = startUs + serialUs;

                long logStartUs = Math.Max(dueMicros, nextLogAvail);
                if (nowUs - logStartUs > LogicalSenderIdleGapMicros)
                    logStartUs = dueMicros;
                logicalDueMicros = logStartUs + serialUs;

                if (forward)
                {
                    Interlocked.Exchange(ref _nextForwardTxAvailable, dueMicros);
                    Interlocked.Exchange(ref _nextForwardLogicalTx, logicalDueMicros);
                }
                else
                {
                    Interlocked.Exchange(ref _nextReverseTxAvailable, dueMicros);
                    Interlocked.Exchange(ref _nextReverseLogicalTx, logicalDueMicros);
                }
            }
        }

        private static string? GetDataPacketKey(byte[] buffer, int length)
        {
            if (length < 20 || buffer[0] != 0x05) return null;
            uint connId = (uint)(buffer[2] << 24) | (uint)(buffer[3] << 16) |
                          (uint)(buffer[4] << 8) | buffer[5];
            uint seqNum = (uint)(buffer[12] << 24) | (uint)(buffer[13] << 16) |
                          (uint)(buffer[14] << 8) | buffer[15];
            return $"{connId}:{seqNum}";
        }

        private void ScheduleDelivery(SimulatedDatagram datagram, long dueMicros)
        {
            lock (_sync)
            {
                if (!_scheduled.TryGetValue(dueMicros, out var list))
                {
                    list = new List<SimulatedDatagram>();
                    _scheduled[dueMicros] = list;
                }
                list.Add(datagram);

                if (!_schedulerRunning && !_stopScheduler)
                {
                    _schedulerRunning = true;
                    _stopScheduler = false;
                    _schedulerThread = new Thread(SchedulerLoop)
                    {
                        IsBackground = true,
                        Name = "NetworkSimulator"
                    };
                    _schedulerThread.Start();
                }
            }
            _schedulerEvent.Set();
        }

        public bool WaitForDeliveryCount(long minPackets, int timeoutMilliseconds)
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
            while (DateTime.UtcNow < deadline)
            {
                if (Interlocked.Read(ref _deliveredPackets) >= minPackets)
                    return true;
                Thread.Sleep(1);
            }
            return Interlocked.Read(ref _deliveredPackets) >= minPackets;
        }

        public void StopScheduler()
        {
            _forceStop = true;
            lock (_sync)
            {
                _stopScheduler = true;
            }
            _schedulerEvent.Set();
            _schedulerThread?.Join(5000);
        }

        private void SchedulerLoop()
        {
            while (true)
            {
                bool hasWork = false;
                long nowUs = DateTime.UtcNow.Ticks / 10;
                List<SimulatedDatagram> toDeliver = new();

                lock (_sync)
                {
                    if (_stopScheduler && _scheduled.Count == 0)
                    {
                        _schedulerRunning = false;
                        return;
                    }

                    while (_scheduled.Count > 0)
                    {
                        var first = _scheduled.First();
                        if (first.Key <= nowUs + SchedulerCoalescingMicros)
                        {
                            toDeliver.AddRange(first.Value);
                            _scheduled.Remove(first.Key);
                            hasWork = true;
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                if (toDeliver.Count > 0)
                {
                    foreach (var dg in toDeliver)
                    {
                        Deliver(dg);
                    }
                }

                bool reorderThisRound = false;
                if (_reorderRate > 0)
                {
                    lock (_sync)
                    {
                        foreach (var kvp in _scheduled.ToList())
                        {
                            var remaining = kvp.Value.Where(dg => !dg.AlreadyReordered).ToList();
                            foreach (var dg in remaining)
                            {
                                if (_rng.NextDouble() < _reorderRate)
                                {
                                    dg.AlreadyReordered = true;
                                    kvp.Value.Remove(dg);
                                    long extraDelay = _rng.Next(5000, 30000);
                                    long newKey = kvp.Key + extraDelay;
                                    if (!_scheduled.TryGetValue(newKey, out var list))
                                    {
                                        list = new List<SimulatedDatagram>();
                                        _scheduled[newKey] = list;
                                    }
                                    list.Add(dg);
                                    Interlocked.Increment(ref _reorderedPackets);
                                    reorderThisRound = true;
                                }
                            }
                        }
                    }
                }

                if (!hasWork && !reorderThisRound)
                {
                    long nextDue;
                    lock (_sync)
                    {
                        nextDue = _scheduled.Count > 0 ? _scheduled.Keys.First() : long.MaxValue;
                    }
                    int waitMs = 1;
                    if (nextDue < long.MaxValue)
                    {
                        waitMs = Math.Max(0, (int)((nextDue - nowUs) / 1000));
                    }
                    _schedulerEvent.WaitOne(Math.Max(1, Math.Min(waitMs, 10)));
                }
            }
        }

        private void Deliver(SimulatedDatagram datagram)
        {
            SimulatedTransport? transport;
            lock (_sync)
            {
                _transports.TryGetValue(datagram.DestinationPort, out transport);
            }

            if (transport == null)
            {
                Interlocked.Increment(ref _droppedPackets);
                return;
            }

            Interlocked.Increment(ref _deliveredPackets);
            Interlocked.Add(ref _deliveredBytes, datagram.Length);

            bool isData = datagram.Buffer.Length > 0 && datagram.Buffer[0] == 0x05;
            if (isData)
                Interlocked.Increment(ref _deliveredDataPackets);

            long latency = DateTime.UtcNow.Ticks / 10 - datagram.SendMicros;
            lock (_sync)
            {
                _latencySamples.Add(latency);
                if (datagram.ForwardDirection)
                    _forwardLatencySamples.Add(latency);
                else
                    _reverseLatencySamples.Add(latency);
            }

            transport.Deliver(datagram);
        }

        public void Configure(double lossRate, int fixedDelayMilliseconds, int jitterMilliseconds,
            int bandwidthBytesPerSecond, double duplicateRate, double reorderRate)
        {
            lock (_sync)
            {
                _lossRate = lossRate;
                _fixedDelayMs = fixedDelayMilliseconds;
                _jitterMs = jitterMilliseconds;
                _forwardDelayMs = fixedDelayMilliseconds;
                _backwardDelayMs = fixedDelayMilliseconds;
                _forwardJitterMs = jitterMilliseconds;
                _backwardJitterMs = jitterMilliseconds;
                _bandwidthBps = bandwidthBytesPerSecond;
                _duplicateRate = duplicateRate;
                _reorderRate = reorderRate;
            }
        }
    }
}
