using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using Ucp.Internal;
using Ucp.Transport;

namespace Ucp
{
    /// <summary>
    /// UCP network engine. External transports feed UDP datagrams through Input,
    /// while concrete network implementations send encoded packets through Output.
    /// </summary>
    public abstract class UcpNetwork : IDisposable
    {
        private sealed class TimerRegistration
        {
            public uint Id;
            public long ExpireMicros;
            public Action Callback;
        }

        private sealed class NetworkTransportAdapter : IBindableTransport, IUcpObject
        {
            private readonly UcpNetwork network;

            public NetworkTransportAdapter(UcpNetwork network)
            {
                this.network = network;
            }

            public event Action<byte[], IPEndPoint> OnDatagram;

            public EndPoint LocalEndPoint
            {
                get { return network.LocalEndPoint; }
            }

            public uint ConnectionId
            {
                get { return 0; }
            }

            public UcpNetwork Network
            {
                get { return network; }
            }

            public void Start(int port)
            {
                network.Start(port);
            }

            public void Stop()
            {
                network.Stop();
            }

            public void Send(byte[] data, IPEndPoint remote)
            {
                network.Output(data, remote, this);
            }

            public void Dispose()
            {
            }

            public void Raise(byte[] datagram, IPEndPoint remote)
            {
                Action<byte[], IPEndPoint> handler = OnDatagram;
                if (handler != null)
                {
                    handler(datagram, remote);
                }
            }
        }

        private readonly object _timerSync = new object();
        private readonly object _pcbSync = new object();
        private readonly SortedDictionary<long, List<Action>> _timerHeap = new SortedDictionary<long, List<Action>>();
        private readonly Dictionary<uint, TimerRegistration> _activeTimers = new Dictionary<uint, TimerRegistration>();
        private readonly Dictionary<uint, UcpPcb> _pcbsByConnectionId = new Dictionary<uint, UcpPcb>();
        private readonly List<UcpPcb> _activePcbs = new List<UcpPcb>();
        private readonly NetworkTransportAdapter _transportAdapter;
        private int _nextTimerId;
        private long _currentTimeUs;
        private long _currentTimeMs;
        private bool _disposed;

        protected UcpNetwork()
            : this(new UcpConfiguration())
        {
        }

        protected UcpNetwork(UcpConfiguration configuration)
        {
            Configuration = configuration == null ? new UcpConfiguration() : configuration.Clone();
            _transportAdapter = new NetworkTransportAdapter(this);
            _currentTimeUs = UcpTime.ReadStopwatchMicroseconds();
            _currentTimeMs = _currentTimeUs / UcpConstants.MICROS_PER_MILLI;
        }

        public UcpConfiguration Configuration { get; private set; }

        internal IBindableTransport TransportAdapter
        {
            get { return _transportAdapter; }
        }

        public long NowMicroseconds
        {
            get { return Volatile.Read(ref _currentTimeUs); }
        }

        /// <summary>
        /// Cached network clock in microseconds. Protocol code uses this value so
        /// all timers, RTT samples, and pacing decisions advance from one logical
        /// clock owned by DoEvents rather than from scattered system time reads.
        /// </summary>
        public long CurrentTimeUs
        {
            get { return Volatile.Read(ref _currentTimeUs); }
        }

        public virtual EndPoint LocalEndPoint
        {
            get { return null; }
        }

        public UcpServer CreateServer(int port)
        {
            UcpServer server = new UcpServer(_transportAdapter, false, Configuration.Clone(), this);
            server.Start(port);
            return server;
        }

        public UcpConnection CreateConnection()
        {
            return CreateConnection(Configuration);
        }

        public UcpConnection CreateConnection(UcpConfiguration configuration)
        {
            UcpConfiguration config = configuration == null ? Configuration.Clone() : configuration.Clone();
            return new UcpConnection(_transportAdapter, false, config, this);
        }

        public virtual void Start(int port)
        {
        }

        public virtual void Stop()
        {
        }

        public void Input(byte[] datagram, IPEndPoint remote)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }

            if (datagram == null)
            {
                throw new ArgumentNullException(nameof(datagram));
            }

            if (remote == null)
            {
                throw new ArgumentNullException(nameof(remote));
            }

            if (datagram.Length < UcpConstants.CommonHeaderSize)
            {
                return;
            }

            UcpPacket packet;
            if (UcpPacketCodec.TryDecode(datagram, 0, datagram.Length, out packet))
            {
                UcpPcb pcb;
                lock (_pcbSync)
                {
                    _pcbsByConnectionId.TryGetValue(packet.Header.ConnectionId, out pcb);
                }

                if (pcb != null)
                {
                    pcb.DispatchFromNetwork(packet, remote);
                    return;
                }

                if (packet.Header.Type != UcpPacketType.Syn)
                {
                    return;
                }
            }

            _transportAdapter.Raise(datagram, remote);
        }

        public void Output(byte[] datagram, IPEndPoint remote)
        {
            Output(datagram, remote, null);
        }

        public abstract void Output(byte[] datagram, IPEndPoint remote, IUcpObject sender);

        public uint AddTimer(long expireUs, Action callback)
        {
            if (callback == null)
            {
                throw new ArgumentNullException(nameof(callback));
            }

            uint timerId = unchecked((uint)Interlocked.Increment(ref _nextTimerId));
            TimerRegistration registration = new TimerRegistration();
            registration.Id = timerId;
            registration.ExpireMicros = expireUs;

            Action wrappedCallback = delegate
            {
                bool shouldRun = false;
                lock (_timerSync)
                {
                    TimerRegistration active;
                    if (_activeTimers.TryGetValue(timerId, out active) && object.ReferenceEquals(active, registration))
                    {
                        _activeTimers.Remove(timerId);
                        shouldRun = true;
                    }
                }

                if (shouldRun)
                {
                    callback();
                }
            };

            registration.Callback = wrappedCallback;
            lock (_timerSync)
            {
                _activeTimers[timerId] = registration;
                List<Action> callbacks;
                if (!_timerHeap.TryGetValue(expireUs, out callbacks))
                {
                    callbacks = new List<Action>();
                    _timerHeap[expireUs] = callbacks;
                }

                callbacks.Add(wrappedCallback);
            }

            return timerId;
        }

        public bool CancelTimer(uint timerId)
        {
            lock (_timerSync)
            {
                return _activeTimers.Remove(timerId);
            }
        }

        public virtual int DoEvents()
        {
            if (_disposed)
            {
                return 0;
            }

            UpdateCachedClock();

            List<Action> dueCallbacks = new List<Action>();
            long nowMicros = CurrentTimeUs;
            lock (_timerSync)
            {
                while (_timerHeap.Count > 0)
                {
                    long firstKey;
                    List<Action> firstCallbacks;
                    GetFirstTimerUnsafe(out firstKey, out firstCallbacks);
                    if (firstKey > nowMicros)
                    {
                        break;
                    }

                    _timerHeap.Remove(firstKey);
                    for (int i = 0; i < firstCallbacks.Count; i++)
                    {
                        dueCallbacks.Add(firstCallbacks[i]);
                    }
                }
            }

            for (int i = 0; i < dueCallbacks.Count; i++)
            {
                dueCallbacks[i]();
            }

            List<UcpPcb> snapshot = SnapshotPcbs();
            int pcbWork = 0;
            for (int i = 0; i < snapshot.Count; i++)
            {
                pcbWork += snapshot[i].OnTick(CurrentTimeUs);
            }

            if (dueCallbacks.Count == 0 && pcbWork == 0)
            {
                YieldWhenIdle();
            }

            return dueCallbacks.Count + pcbWork;
        }

        internal void RegisterPcb(UcpPcb pcb)
        {
            if (pcb == null)
            {
                return;
            }

            lock (_pcbSync)
            {
                if (!_activePcbs.Contains(pcb))
                {
                    _activePcbs.Add(pcb);
                }

                if (pcb.ConnectionId != 0)
                {
                    _pcbsByConnectionId[pcb.ConnectionId] = pcb;
                }
            }
        }

        internal void UpdatePcbConnectionId(UcpPcb pcb, uint oldConnectionId, uint newConnectionId)
        {
            if (pcb == null || newConnectionId == 0)
            {
                return;
            }

            lock (_pcbSync)
            {
                if (oldConnectionId != 0)
                {
                    UcpPcb existing;
                    if (_pcbsByConnectionId.TryGetValue(oldConnectionId, out existing) && object.ReferenceEquals(existing, pcb))
                    {
                        _pcbsByConnectionId.Remove(oldConnectionId);
                    }
                }

                _pcbsByConnectionId[newConnectionId] = pcb;
                if (!_activePcbs.Contains(pcb))
                {
                    _activePcbs.Add(pcb);
                }
            }
        }

        internal void UnregisterPcb(UcpPcb pcb)
        {
            if (pcb == null)
            {
                return;
            }

            lock (_pcbSync)
            {
                _activePcbs.Remove(pcb);
                uint connectionId = pcb.ConnectionId;
                if (connectionId != 0)
                {
                    UcpPcb existing;
                    if (_pcbsByConnectionId.TryGetValue(connectionId, out existing) && object.ReferenceEquals(existing, pcb))
                    {
                        _pcbsByConnectionId.Remove(connectionId);
                    }
                }
            }
        }

        public virtual void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            Stop();
            lock (_timerSync)
            {
                _activeTimers.Clear();
                _timerHeap.Clear();
            }
        }

        private void GetFirstTimerUnsafe(out long expireUs, out List<Action> callbacks)
        {
            foreach (KeyValuePair<long, List<Action>> pair in _timerHeap)
            {
                expireUs = pair.Key;
                callbacks = pair.Value;
                return;
            }

            expireUs = 0;
            callbacks = null;
        }

        private void YieldWhenIdle()
        {
            long nextExpireUs = 0;
            bool hasTimer = false;
            lock (_timerSync)
            {
                if (_timerHeap.Count > 0)
                {
                    List<Action> ignored;
                    GetFirstTimerUnsafe(out nextExpireUs, out ignored);
                    hasTimer = true;
                }
            }

            if (hasTimer && nextExpireUs - CurrentTimeUs <= UcpConstants.MICROS_PER_MILLI)
            {
                Thread.Yield();
                return;
            }

            Thread.Sleep(1);
        }

        private void UpdateCachedClock()
        {
            long stopwatchUs = UcpTime.ReadStopwatchMicroseconds();
            long stopwatchMs = stopwatchUs / UcpConstants.MICROS_PER_MILLI;
            long cachedMs = Volatile.Read(ref _currentTimeMs);
            if (stopwatchMs != cachedMs)
            {
                Volatile.Write(ref _currentTimeUs, stopwatchUs);
                Volatile.Write(ref _currentTimeMs, stopwatchMs);
            }
        }

        private List<UcpPcb> SnapshotPcbs()
        {
            lock (_pcbSync)
            {
                return new List<UcpPcb>(_activePcbs);
            }
        }
    }
}
