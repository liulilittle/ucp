using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Ucp;
using Ucp.Internal;
using UcpTest.TestTransport;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpKccTests
    {
        private readonly ITestOutputHelper _output;
        public UcpKccTests(ITestOutputHelper output) { _output = output; }

        // ================================================================
        //  SECTION 1: SequenceComparer (~4 tests, matches C++ sections 1+16)
        // ================================================================

        [Fact]
        public void SeqCmp_HandlesWrapAround()
        {
            uint max = uint.MaxValue;
            Assert.True(UcpSequenceComparer.IsAfter(0u, max));
            Assert.True(UcpSequenceComparer.IsAfter(1u, max));
            Assert.True(UcpSequenceComparer.IsBefore(max, 0u));
            Assert.Equal(1, UcpSequenceComparer.Instance.Compare(0u, max));
            Assert.Equal(-1, UcpSequenceComparer.Instance.Compare(max, 0u));
        }

        [Fact]
        public void SeqCmp_MutuallyExclusive()
        {
            Assert.True(UcpSequenceComparer.IsAfter(1000u, 500u));
            Assert.True(UcpSequenceComparer.IsBefore(500u, 1000u));
            Assert.False(UcpSequenceComparer.IsAfter(500u, 500u));
            Assert.False(UcpSequenceComparer.IsBefore(500u, 500u));
        }

        [Fact]
        public void SeqCmp_IsAfterOrEqual()
        {
            Assert.True(UcpSequenceComparer.IsAfterOrEqual(2u, 1u));
            Assert.True(UcpSequenceComparer.IsBeforeOrEqual(1u, 2u));
            Assert.True(UcpSequenceComparer.IsAfterOrEqual(1u, 1u));
            Assert.True(UcpSequenceComparer.IsBeforeOrEqual(1u, 1u));
        }

        [Fact]
        public void SeqCmp_WrapAroundEdge()
        {
            uint max = uint.MaxValue;
            uint half = 0x80000000U;
            Assert.True(UcpSequenceComparer.IsAfter(max, half));
            Assert.True(UcpSequenceComparer.IsBefore(half, max));
            Assert.Equal(0, UcpSequenceComparer.Instance.Compare(0u, 0u));
            Assert.Equal(0, UcpSequenceComparer.Instance.Compare(max, max));
        }

        // ================================================================
        //  SECTION 2: PacketCodec (~6 tests, matches C++ section 2)
        // ================================================================

        [Fact]
        public void Codec_DataPacketRoundTrip()
        {
            var p = new UcpDataPacket
            {
                Header = new UcpCommonHeader { Type = UcpPacketType.Data, Flags = UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber, ConnectionId = 1, Timestamp = 100000 },
                SequenceNumber = 50,
                FragmentTotal = 1,
                FragmentIndex = 0,
                Payload = Encoding.ASCII.GetBytes("HelloUCP"),
                AckNumber = 30,
                WindowSize = 65535,
                EchoTimestamp = 90000
            };
            p.SackBlocks.Add(new SackBlock { Start = 8, End = 9 });
            byte[] enc = UcpPacketCodec.Encode(p);
            Assert.True(UcpPacketCodec.TryDecode(enc, 0, enc.Length, out var d));
            var data = Assert.IsType<UcpDataPacket>(d);
            Assert.Equal(p.SequenceNumber, data.SequenceNumber);
            Assert.Equal(p.Payload, data.Payload);
            Assert.Equal(p.AckNumber, data.AckNumber);
            Assert.Single(data.SackBlocks);
        }

        [Fact]
        public void Codec_ControlPacketRoundTrip()
        {
            var syn = new UcpControlPacket
            {
                Header = new UcpCommonHeader { Type = UcpPacketType.Syn, ConnectionId = 0, Timestamp = 1000 },
                HasSequenceNumber = true,
                SequenceNumber = 12345,
                SessionKey = 98765
            };
            byte[] enc = UcpPacketCodec.Encode(syn);
            Assert.True(UcpPacketCodec.TryDecode(enc, 0, enc.Length, out var d));
            var s = Assert.IsType<UcpControlPacket>(d);
            Assert.Equal(UcpPacketType.Syn, s.Header.Type);
            Assert.Equal(syn.SequenceNumber, s.SequenceNumber);
            Assert.Equal(syn.SessionKey, s.SessionKey);
        }

        [Fact]
        public void Codec_NakPacketRoundTrip()
        {
            var p = new UcpNakPacket
            {
                Header = new UcpCommonHeader { Type = UcpPacketType.Nak, ConnectionId = 1, Timestamp = 5000 },
                AckNumber = 100,
                MissingSequences = { 101, 105, 110 }
            };
            byte[] enc = UcpPacketCodec.Encode(p);
            Assert.True(UcpPacketCodec.TryDecode(enc, 0, enc.Length, out var d));
            var nak = Assert.IsType<UcpNakPacket>(d);
            Assert.Equal(p.MissingSequences, nak.MissingSequences);
        }

        [Fact]
        public void Codec_FecRepairRoundTrip()
        {
            var p = new UcpFecRepairPacket
            {
                Header = new UcpCommonHeader { Type = UcpPacketType.FecRepair, ConnectionId = 1, Timestamp = 5000 },
                GroupId = 16,
                GroupIndex = 0,
                Payload = new byte[] { 1, 2, 3, 4 }
            };
            byte[] enc = UcpPacketCodec.Encode(p);
            Assert.True(UcpPacketCodec.TryDecode(enc, 0, enc.Length, out var d));
            var fec = Assert.IsType<UcpFecRepairPacket>(d);
            Assert.Equal(p.Payload, fec.Payload);
        }

        [Fact]
        public void Codec_FinAndRstRoundTrip()
        {
            var fin = new UcpControlPacket
            {
                Header = new UcpCommonHeader { Type = UcpPacketType.Fin, Flags = UcpPacketFlags.HasAckNumber, ConnectionId = 1, Timestamp = 3000 },
                AckNumber = 200
            };
            byte[] en = UcpPacketCodec.Encode(fin);
            Assert.True(UcpPacketCodec.TryDecode(en, 0, en.Length, out var df));
            Assert.Equal(UcpPacketType.Fin, df.Header.Type);

            var rst = new UcpControlPacket
            {
                Header = new UcpCommonHeader { Type = UcpPacketType.Rst, ConnectionId = 1, Timestamp = 4000 }
            };
            en = UcpPacketCodec.Encode(rst);
            Assert.True(UcpPacketCodec.TryDecode(en, 0, en.Length, out var dr));
            Assert.Equal(UcpPacketType.Rst, dr.Header.Type);
        }

        [Fact]
        public void Codec_ErrorHandling()
        {
            Assert.False(UcpPacketCodec.TryDecode(null, 0, 0, out _));
            Assert.False(UcpPacketCodec.TryDecode(Array.Empty<byte>(), 0, 0, out _));
            Assert.Throws<ArgumentNullException>(() => UcpPacketCodec.Encode(null));
            byte[] buf = new byte[20]; buf[0] = 0xFF;
            Assert.False(UcpPacketCodec.TryDecode(buf, 0, buf.Length, out _));
        }

        // ================================================================
        //  SECTION 3: SackGenerator (~4 tests, matches C++ section 3)
        // ================================================================

        [Fact]
        public void SackGen_ContinuousBlocks()
        {
            var gen = new UcpSackGenerator();
            var r = gen.Generate(100, new uint[] { 101, 102, 103 }, 4);
            Assert.Single(r);
            Assert.Equal(101u, r[0].Start);
            Assert.Equal(103u, r[0].End);
        }

        [Fact]
        public void SackGen_MultipleGaps()
        {
            var gen = new UcpSackGenerator();
            var r = gen.Generate(100, new uint[] { 101, 102, 105, 106, 110 }, 4);
            Assert.Equal(3, r.Count);
        }

        [Fact]
        public void SackGen_MaxBlocksTrims()
        {
            var gen = new UcpSackGenerator();
            var seq = new List<uint>();
            for (uint i = 0; i < 20; i++) seq.Add(100 + i * 3);
            var r = gen.Generate(100, seq, 3);
            Assert.True(r.Count <= 3);
        }

        [Fact]
        public void SackGen_WrapAndOrder()
        {
            var gen = new UcpSackGenerator();
            var r = gen.Generate(uint.MaxValue, new uint[] { 0, 1, 2 }, 4);
            Assert.Single(r);
            r = gen.Generate(100, new uint[] { 105, 101, 103, 102, 104 }, 4);
            Assert.Single(r);
            Assert.Equal(101u, r[0].Start);
        }

        // ================================================================
        //  SECTION 4: RtoEstimator (~8 tests, matches C++ sections 4+19)
        // ================================================================

        [Fact]
        public void Rto_DefaultConstructorIsValid()
        {
            var est = new UcpRtoEstimator(new UcpConfiguration());
            Assert.True(est.CurrentRtoMicros > 0);
            Assert.True(est.SmoothedRttMicros >= 0);
            Assert.True(est.RttVarianceMicros >= 0);
        }

        [Fact]
        public void Rto_UpdateWithSamples()
        {
            var est = new UcpRtoEstimator(new UcpConfiguration());
            est.Update(50000);
            Assert.True(est.CurrentRtoMicros > 0);
            Assert.Equal(50000, est.SmoothedRttMicros);
        }

        [Fact]
        public void Rto_ZeroAndNegativeIgnored()
        {
            var est = new UcpRtoEstimator(new UcpConfiguration());
            est.Update(50000);
            long before = est.CurrentRtoMicros;
            est.Update(0);
            Assert.Equal(before, est.CurrentRtoMicros);
            est.Update(-100);
            Assert.Equal(before, est.CurrentRtoMicros);
        }

        [Fact]
        public void Rto_BackoffCapped()
        {
            var config = new UcpConfiguration { MinRtoMicros = 1000000, MaxRtoMicros = 60000000, RetransmitBackoffFactor = 1.5 };
            var est = new UcpRtoEstimator(config);
            est.Update(100000);
            long floor = Math.Max(est.CurrentRtoMicros, config.EffectiveMinRtoMicros * 2);
            est.Backoff();
            Assert.True(est.CurrentRtoMicros >= floor);
        }

        [Fact]
        public void Rto_BackoffPlateaus()
        {
            var est = new UcpRtoEstimator(new UcpConfiguration());
            long prev = est.CurrentRtoMicros;
            for (int i = 0; i < 10; i++)
            {
                est.Backoff();
                Assert.True(est.CurrentRtoMicros >= prev);
                prev = est.CurrentRtoMicros;
            }
            Assert.True(est.CurrentRtoMicros <= new UcpConfiguration().EffectiveMaxRtoMicros);
        }

        [Fact]
        public void Rto_ClampsInvalidConfig()
        {
            var config = new UcpConfiguration { MinRtoMicros = 0, MaxRtoMicros = 1, RetransmitBackoffFactor = 0.5 };
            var est = new UcpRtoEstimator(config);
            est.Update(1000);
            Assert.True(est.CurrentRtoMicros >= UcpConstants.MIN_RTO_MICROS);
            long beforeBackoff = est.CurrentRtoMicros;
            est.Backoff();
            Assert.True(est.CurrentRtoMicros >= beforeBackoff);
        }

        [Fact]
        public void Rto_SmoothedRttWorks()
        {
            var config = new UcpConfiguration { MinRtoMicros = 20000 };
            var est = new UcpRtoEstimator(config);
            est.Update(100000); est.Update(120000); est.Update(110000); est.Update(105000);
            Assert.True(est.CurrentRtoMicros >= config.MinRtoMicros);
            Assert.True(est.CurrentRtoMicros <= config.MaxRtoMicros);
            Assert.True(est.SmoothedRttMicros > 0);
        }

        [Fact]
        public void Rto_UpdateAfterBackoff()
        {
            var est = new UcpRtoEstimator(new UcpConfiguration());
            est.Update(50000);
            est.Backoff();
            est.Update(60000);
            Assert.True(est.CurrentRtoMicros < 500000);
            Assert.True(est.SmoothedRttMicros > 0);
        }

        // ================================================================
        //  SECTION 5: PacingController (~4 tests, matches C++ section 5)
        // ================================================================

        [Fact]
        public void Pacing_ComputesWaitTime()
        {
            var config = new UcpConfiguration { PacingBucketDurationMicros = 1000000 };
            var ctrl = new PacingController(config, 1000);
            ctrl.SetRate(1000, 1000000);
            Assert.True(ctrl.TryConsume(1236, 1000000));
            Assert.False(ctrl.TryConsume(500, 1000000));
            long wait = ctrl.GetWaitTimeMicros(500, 1000000);
            Assert.InRange(wait, 499000, 501000);
        }

        [Fact]
        public void Pacing_ForceConsume()
        {
            var config = new UcpConfiguration { PacingBucketDurationMicros = 1000000 };
            var ctrl = new PacingController(config, 1000);
            ctrl.SetRate(1000, 1000000);
            Assert.True(ctrl.TryConsume(1236, 1000000));
            Assert.False(ctrl.TryConsume(1, 1000000));
            ctrl.ForceConsume(500, 1000000);
            Assert.False(ctrl.TryConsume(1, 1000000));
            Assert.True(ctrl.TryConsume(1, 1001000));
        }

        [Fact]
        public void Pacing_TinyBucket()
        {
            var config = new UcpConfiguration { PacingBucketDurationMicros = 1, SendQuantumBytes = 1 };
            var ctrl = new PacingController(config, 1);
            Assert.True(ctrl.TryConsume(UcpConstants.DATA_HEADER_SIZE + config.MaxPayloadSize, 0));
        }

        [Fact]
        public void Pacing_ZeroRateDoesNotCrash()
        {
            var ctrl = new PacingController(new UcpConfiguration(), 0);
            ctrl.SetRate(0, 0);
            int cap = 1220 + 1460 + 20;
            int safety = 0;
            while (ctrl.TryConsume(cap, 0) && safety++ < 10000) { }
            Assert.True(ctrl.GetWaitTimeMicros(cap, 0) > 0);
        }

        // ================================================================
        //  SECTION 6: KCC Congestion Control (~30 tests, matches C++ section 6)
        // ================================================================

        private static UcpCongestionControl CreateCc(UcpConfiguration? config = null)
        {
            UcpCongestionControl.ResetGlobalKf();
            config ??= new UcpConfiguration();
            if (config.InitialBandwidthBytesPerSecond <= 0) config.InitialBandwidthBytesPerSecond = 12500000;
            if (config.InitialCwndBytes <= 0) config.InitialCwndBytes = 65536;
            if (config.MaxCongestionWindowBytes <= 0) config.MaxCongestionWindowBytes = int.MaxValue;
            return new UcpCongestionControl(config);
        }

        [Fact]
        public void Cc_InitialStateIsStartup()
        {
            var cc = CreateCc();
            Assert.Equal(UcpMode.Startup, cc.Mode);
            Assert.True(cc.BtlBwBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingGainUnits > 256);
        }

        [Fact]
        public void Cc_TransitionsOutOfStartup()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 12; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            Assert.True(cc.CongestionWindowBytes >= 24400);
        }

        [Fact]
        public void Cc_ModeTransitionStartupToProbeBw()
        {
            var config = new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 120; i++) { cc.OnAck(now, 64000, 10000, 64000); now += 10000; }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            Assert.True(cc.FullBwReached);
        }

        [Fact]
        public void Cc_BandwidthResistsCliffs()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 100000, 100000, 100000);
            cc.OnAck(200000, 100000, 100000, 100000);
            double high = cc.BtlBwBytesPerSecond;
            Assert.True(high > 1.0);
            cc.OnAck(500000, 1000, 100000, 1000);
            cc.OnAck(700000, 1000, 100000, 1000);
            cc.OnAck(1050000, 1000, 100000, 1000);
            Assert.True(cc.BtlBwBytesPerSecond >= high * 0.75);
        }

        [Fact]
        public void Cc_BandwidthTracksDeliveryRate()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 500000, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 24000; }
            Assert.InRange((long)cc.BtlBwBytesPerSecond, 500000, 3000000);
        }

        [Fact]
        public void Cc_MinRttConvergesViaGeodesic()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 50; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            long minRtt = cc.MinRttMicros;
            Assert.True(minRtt > 0);
            Assert.InRange(minRtt, 40000, 60000);
        }

        [Fact]
        public void Cc_MinRttStickyFall()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 100000, 24000); now += 100000; }
            long baseline = cc.MinRttMicros;
            for (int i = 0; i < 4; i++) { cc.OnAck(now, 24000, 25000, 24000); now += 100000; }
            Assert.True(cc.MinRttMicros < baseline);
            Assert.True(cc.MinRttMicros <= 35000);
        }

        [Fact]
        public void Cc_MinRttReplacesAfterExpiry()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 10; i++) { cc.OnAck(now, 24000, 100000, 24000); now += 100000; }
            long baseline = cc.MinRttMicros;
            // After the min-RTT expiry window (well past the 10x RTT
            // retention), a fresh lower RTT sample must REPLACE min_rtt --
            // the value must drop toward the new sample, not stay at the old
            // baseline (that is the "replaces after expiry" behavior).
            now += 11000000;
            cc.OnAck(now, 24000, 80000, 24000);
            Assert.True(cc.MinRttMicros < baseline,
                $"min_rtt must be replaced by the newer lower sample: {cc.MinRttMicros} >= baseline {baseline}");
        }

        [Fact]
        public void Cc_ProbeBwGainCycle()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 16; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 100000; }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.InRange(cc.PacingGainUnits, 1, 1023);
            // The gain cycle must actually advance the phase index (the cycle
            // the name claims): further rounds move ProbeBwCycleIdx forward.
            int start = cc.ProbeBwCycleIdx & 7;
            for (int i = 0; i < 16; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 100000; }
            int end = cc.ProbeBwCycleIdx & 7;
            int steps = end - start;
            if (steps < 0) { steps += 8; }
            Assert.True(steps > 0,
                $"gain cycle must advance the phase index: {start} -> {end}");
        }

        [Fact]
        public void Cc_BdpReflectedInCwnd()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 30; i++) { cc.OnAck(now, 120000, 50000, 120000); now += 50000; }
            Assert.True(cc.MinRttMicros > 0);
            Assert.True(cc.CongestionWindowBytes > (cc.BtlBwBytesPerSecond * cc.MinRttMicros / 1000000) / 10);
        }

        [Fact]
        public void Cc_OnPathChangeResets()
        {
            var cc = CreateCc();
            cc.OnAck(1000, 100000, 50000, 100000);
            cc.OnPathChange(250000);
            Assert.Equal(UcpMode.Startup, cc.Mode);
        }

        [Fact]
        public void Cc_OnPacketLossUpdatesEstimate()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 5; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            long cwndBefore = cc.CongestionWindowBytes;
            cc.OnPacketLoss(now, 0.05, true);
            Assert.True(cc.EstimatedLossPercent > 0.0);
            Assert.True(cc.CongestionWindowBytes <= cwndBefore);
        }

        [Fact]
        public void Cc_OnFastRetransmitHandlesCongestion()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 8; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            long before = cc.CongestionWindowBytes;
            cc.OnFastRetransmit(now, true);
            Assert.True(cc.CongestionWindowBytes <= before);
        }

        [Fact]
        public void Cc_LtBwLossRecordsLossPercent()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 8; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            for (int i = 0; i < 3; i++) { cc.OnNakLoss(now, 24000); now += 100000; cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            Assert.True(cc.CongestionWindowBytes > 0);
            // NAK loss must register in the controller's loss estimate (this
            // is the loss signal LT-BW sampling consumes; full LT-BW
            // activation additionally requires a stable 4-RTT sampling
            // interval that unit-level NAK injection cannot drive here).
            Assert.True(cc.EstimatedLossPercent > 0,
                $"NAK loss must be recorded: loss={cc.EstimatedLossPercent}");
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void Cc_ProbeBwEighthGainCycle()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            long rttUs = 30000;
            for (int i = 0; i < 200; i++) { cc.OnAck(now, 12200, rttUs, 500000); now += rttUs; }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            int[] g = new int[8];
            var seen = new System.Collections.Generic.HashSet<int>();
            // Sample across a full cycle: each phase lasts several RTTs, so
            // use a long window and record distinct phase indices visited.
            for (int ph = 0; ph < 128; ph++)
            {
                int idx = cc.ProbeBwCycleIdx & 7;
                g[idx] = cc.PacingGainUnits;
                seen.Add(idx);
                cc.OnAck(now, 12200, rttUs, 500000);
                now += rttUs;
            }
            Assert.True(g[0] > 0);
            Assert.True(g.Any(v => v > 256) || g.Any(v => v < 256));
            // The 8-phase cycle claim: over a long window the cycle must
            // traverse distinct phases (not stay frozen on one index).
            Assert.True(seen.Count >= 3,
                $"8-phase cycle must advance through phases: got {seen.Count}/8 distinct");
        }

        [Fact]
        public void Cc_ProbeBwCycleIdxWraps()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            long rttUs = 30000;
            for (int i = 0; i < 200; i++) { cc.OnAck(now, 12200, rttUs, 500000); now += rttUs; }
            Assert.InRange(cc.ProbeBwCycleIdx, 0, 7);
            int start = cc.ProbeBwCycleIdx;
            for (int i = 0; i < 16; i++) { cc.OnAck(now, 12200, rttUs, 500000); now += rttUs; }
            int end = cc.ProbeBwCycleIdx;
            int steps = end - start;
            if (steps < 0) { steps += 8; }
            Assert.True(steps > 0);
        }

        [Fact]
        public void Cc_CwndGrowsDuringStartup()
        {
            // 100 Mbps with 20 ms RTT gives BDP ~250 KB; the 64 KB initial
            // cwnd sits below BDP so KCC 2.0's STARTUP phase must grow cwnd
            // (a 1 Mbps link would put the initial cwnd far above BDP, making
            // DRAIN contract instead — not a growth signal).
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            long cwndStart = cc.CongestionWindowBytes;
            long maxCwnd = cwndStart;
            for (int i = 0; i < 10; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; maxCwnd = Math.Max(maxCwnd, cc.CongestionWindowBytes); }
            // Startup must actually grow the window above its initial value
            // (the growth is the name's claim, not a lower bound).
            Assert.True(maxCwnd > cwndStart,
                $"cwnd must grow during Startup: max {maxCwnd} <= start {cwndStart}");
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void Cc_CwndDoesNotExceedMax()
        {
            const long maxCwnd = 256 * 1024;
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 100000000, InitialCwndBytes = 65536, MaxCongestionWindowBytes = (int)maxCwnd });
            long now = 100000;
            for (int i = 0; i < 100; i++) { cc.OnAck(now, 64000, 10000, 64000); now += 10000; }
            Assert.True(cc.CongestionWindowBytes <= maxCwnd + 1000);
        }

        [Fact]
        public void Cc_ReducedOnFastRetransmit()
        {
            var cc = CreateCc();
            long now = 100000; long rttUs = 10000;
            for (int i = 0; i < 12; i++) { cc.OnAck(now, 24000, rttUs, 24000); now += rttUs; }
            long before = cc.CongestionWindowBytes;
            cc.OnFastRetransmit(now, true, 24000);
            Assert.True(cc.CongestionWindowBytes <= before);
        }

        [Fact]
        public void Cc_PacketConservationOnLoss()
        {
            var cc = CreateCc();
            long now = 100000; long rttUs = 10000;
            for (int i = 0; i < 10; i++) { cc.OnAck(now, 24000, rttUs, 24000); now += rttUs; }
            long before = cc.CongestionWindowBytes;
            cc.OnPacketLoss(now, 0.1, true);
            Assert.True(cc.CongestionWindowBytes <= before);
        }

        [Fact]
        public void Cc_PacingRateGrowsDuringStartup()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000000, InitialCwndBytes = 65536, MaxPacingRateBytesPerSecond = 0 });
            long now = 100000;
            double before = cc.PacingRateBytesPerSecond;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 64000, 10000, 64000); now += 10000; }
            // Startup growth: sustained delivery must push the pacing rate
            // above its initial value.
            Assert.True(cc.PacingRateBytesPerSecond > before,
                $"pacing must grow during Startup: {cc.PacingRateBytesPerSecond} <= {before}");
        }

        [Fact]
        public void Cc_LossRecoveryEstimatedLossBounded()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            for (int i = 0; i < 5; i++) { now += 50000; cc.OnPacketLoss(now, 0.99, true); }
            Assert.InRange(cc.EstimatedLossPercent, 0.0, 100.0);
        }

        [Fact]
        public void Cc_EcnEwmaIncreasesWithCeMarks()
        {
            var cc = CreateCc(new UcpConfiguration { EcnEnabled = true });
            long now = 100000;
            cc.OnAck(now, 24000, 50000, 24000);
            long before = cc.EcnEwmaValue;
            cc.OnCeMark(2400);
            cc.OnAck(now + 50000, 24000, 50000, 24000);
            // CE marks must drive the EWMA up (the increase is the claim).
            Assert.True(cc.EcnEwmaValue > before,
                $"EWMA must increase with CE marks: {cc.EcnEwmaValue} <= {before}");
        }

        [Fact]
        public void Cc_EcnEwmaBounded()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 30; i++) { cc.OnCeMark(24000); cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            Assert.True(cc.EcnEwmaValue <= 256);
        }

        [Fact]
        public void Cc_RtoDoesNotChangeMode()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            var modeBefore = cc.Mode;
            cc.OnRto();
            Assert.Equal(modeBefore, cc.Mode);
            Assert.True(cc.CongestionWindowBytes >= 4 * 1220);
        }

        [Fact]
        public void Cc_OnFecRecoveryDoesNotInflateDelivered()
        {
            var cc = CreateCc();
            long before = cc.TotalDelivered;
            cc.OnFecRecovery(100000, 1000);
            Assert.Equal(before, cc.TotalDelivered);
        }

        [Fact]
        public void Cc_ColdStartSetsGeodesicState()
        {
            var cc = CreateCc();
            Assert.Equal(0, cc.GeodesicXEst);
            cc.OnAck(100000, 24000, 50000, 24000);
            Assert.True(cc.GeodesicXEst > 0);
            Assert.Equal(1, cc.GeodesicSampleCnt);
        }

        [Fact]
        public void Cc_CwndGainEqualsPacingGainInStartup()
        {
            var cc = CreateCc();
            Assert.Equal(cc.CwndGainUnits, cc.PacingGainUnits);
        }

        // ================================================================
        //  SECTION 7: FecCodec (~8 tests, matches C++ section 7+18)
        // ================================================================

        [Fact]
        public void Fec_SingleLostRecovers()
        {
            var enc = new UcpFecCodec(4, 1);
            byte[] data = { 1, 2, 3 };
            Assert.Null(enc.TryEncodeRepair(0, data));
            Assert.Null(enc.TryEncodeRepair(1, data));
            Assert.Null(enc.TryEncodeRepair(2, data));
            var repair = enc.TryEncodeRepair(3, data);
            Assert.NotNull(repair);

            var dec = new UcpFecCodec(4, 1);
            dec.FeedDataPacket(0, data);
            dec.FeedDataPacket(2, data);
            dec.FeedDataPacket(3, data);
            var recovered = dec.TryRecoverFromRepair(repair!, 0);
            Assert.NotNull(recovered);
            Assert.Equal(data, recovered);
        }

        [Fact]
        public void Fec_TwoLossesTwoRepairs()
        {
            var enc = new UcpFecCodec(8, 2);
            var payloads = new byte[8][];
            List<byte[]>? repairs = null;
            for (int i = 0; i < 8; i++)
            {
                payloads[i] = new[] { (byte)(i * 3 + 5) };
                repairs = enc.TryEncodeRepairs((uint)i, payloads[i]);
            }
            Assert.NotNull(repairs);
            Assert.Equal(2, repairs.Count);

            var dec = new UcpFecCodec(8, 2);
            for (int i = 0; i < 8; i++)
            {
                if (i != 1 && i != 6)
                    dec.FeedDataPacket((uint)i, payloads[i]);
            }
            var r0 = dec.TryRecoverPacketsFromRepair(repairs[0], 0, 0);
            var r1 = dec.TryRecoverPacketsFromRepair(repairs[1], 0, 1);
            Assert.True(r0.Count + r1.Count >= 2,
                $"Expected at least 2 recovered packets, got r0={r0.Count} r1={r1.Count}");
        }

        [Fact]
        public void Fec_GroupBoundary()
        {
            var enc = new UcpFecCodec(4, 1);
            Assert.Null(enc.TryEncodeRepair(0, new byte[] { 1 }));
            Assert.Null(enc.TryEncodeRepair(1, new byte[] { 2 }));
            Assert.Null(enc.TryEncodeRepair(2, new byte[] { 3 }));
            var r = enc.TryEncodeRepair(3, new byte[] { 4 });
            Assert.NotNull(r);
        }

        [Fact]
        public void Fec_GetGroupBaseAndSlot()
        {
            var fec = new UcpFecCodec(8, 2);
            Assert.Equal(0u, fec.GetGroupBase(0));
            Assert.Equal(0u, fec.GetGroupBase(7));
            Assert.Equal(8u, fec.GetGroupBase(8));
            Assert.Equal(0, fec.GetSlot(0));
            Assert.Equal(7, fec.GetSlot(7));
            Assert.Equal(0, fec.GetSlot(8));
        }

        [Fact]
        public void Fec_NullAndEmptySafe()
        {
            var fec = new UcpFecCodec(2, 1);
            Assert.Null(fec.TryEncodeRepairs(Array.Empty<byte>()));
            Assert.Null(fec.TryEncodeRepairs((byte[])null!));
        }

        [Fact]
        public void Fec_OutOfOrderSlots()
        {
            var dec = new UcpFecCodec(4, 1);
            dec.FeedDataPacket(3, new byte[] { 3 });
            dec.FeedDataPacket(0, new byte[] { 0 });
            dec.FeedDataPacket(2, new byte[] { 2 });

            var enc = new UcpFecCodec(4, 1);
            enc.TryEncodeRepair(0, new byte[] { 0 });
            enc.TryEncodeRepair(1, new byte[] { 1 });
            enc.TryEncodeRepair(2, new byte[] { 2 });
            var repair = enc.TryEncodeRepair(3, new byte[] { 3 });

            var dec2 = new UcpFecCodec(4, 1);
            dec2.FeedDataPacket(3, new byte[] { 3 });
            dec2.FeedDataPacket(0, new byte[] { 0 });
            dec2.FeedDataPacket(2, new byte[] { 2 });
            var recovered = dec2.TryRecoverFromRepair(repair!, 0);
            Assert.NotNull(recovered);
        }

        [Fact]
        public void Fec_DuplicateSlotSafe()
        {
            var dec = new UcpFecCodec(4, 1);
            dec.FeedDataPacket(0, new byte[] { 1 });
            dec.FeedDataPacket(0, new byte[] { 1 });
            var r = dec.TryRecoverFromRepair(new byte[] { 1, 2, 3 }, 0);
            Assert.Null(r);
        }

        [Fact]
        public void Fec_AllDataPresentNoRecovery()
        {
            var enc = new UcpFecCodec(4, 1);
            for (int i = 0; i < 4; i++) enc.TryEncodeRepair((uint)i, new[] { (byte)i });
            var dec = new UcpFecCodec(4, 1);
            for (int i = 0; i < 4; i++) dec.FeedDataPacket((uint)i, new[] { (byte)i });
            var result = dec.TryRecoverFromRepair(new byte[] { 1, 2, 3 }, 0);
            Assert.Null(result);
        }

        // ================================================================
        //  SECTION 8: KF Unit Tests (~15 tests, matches C++ sections 25-32)
        //  Geodesic estimator, MinRtt, LT BW, ECN, ACK aggregation
        // ================================================================

        [Fact]
        public void Kf_InitialSampleSetsXest()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 24000, 50000, 24000);
            Assert.Equal(50000 * 1024, cc.GeodesicXEst);
            Assert.True(cc.GeodesicPEst > 0);
            Assert.Equal(1, cc.GeodesicSampleCnt);
        }

        [Fact]
        public void Kf_ConvergesToTrueRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            long ratio = cc.GeodesicXEst * 100 / (10000 * 1024);
            Assert.InRange(ratio, 90, 110);
        }

        [Fact]
        public void Kf_ZeroInnovationKeepsXest()
        {
            var cc = CreateCc();
            long now = 100000;
            cc.OnAck(now, 24000, 10000, 24000);
            long x1 = cc.GeodesicXEst;
            now += 10000; cc.OnAck(now, 24000, 10000, 24000);
            now += 10000; cc.OnAck(now, 24000, 10000, 24000);
            Assert.Equal(x1, cc.GeodesicXEst);
        }

        [Fact]
        public void Kf_LargeInnovationRaisesJitterEwma()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 5; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            long jitterBefore = cc.GeodesicJitterEwma;
            cc.OnAck(now, 24000, 15000, 24000);
            // A large RTT innovation (10ms -> 15ms) must register in the
            // jitter EWMA (the observable effect this test drives).
            Assert.True(cc.GeodesicJitterEwma > jitterBefore);
        }

        [Fact]
        public void Kf_PEstStaysAboveFloor()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 50; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            Assert.True(cc.GeodesicPEst >= 10);
        }

        [Fact]
        public void Kf_PEstDoesNotExceedMax()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 10; i++) { cc.OnAck(now, 24000, 50000, 24000); now += 50000; }
            Assert.True(cc.GeodesicPEst <= 1000000);
        }

        [Fact]
        public void Kf_SampleCntIncrements()
        {
            var cc = CreateCc();
            long now = 100000;
            Assert.Equal(0, cc.GeodesicSampleCnt);
            for (int i = 0; i < 10; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            Assert.Equal(10, cc.GeodesicSampleCnt);
            cc.OnAck(now, 24000, 0, 24000);
            Assert.Equal(10, cc.GeodesicSampleCnt);
        }

        [Fact]
        public void Kf_NegativeRttIgnored()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 24000, 50000, 24000);
            long x = cc.GeodesicXEst;
            cc.OnAck(150000, 24000, -1000, 24000);
            Assert.Equal(x, cc.GeodesicXEst);
        }

        [Fact]
        public void Kf_VeryLowRttConverges()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 100, 24000); now += 100; }
            Assert.True(cc.GeodesicXEst > 0);
            Assert.True(cc.GeodesicPEst >= 10);
        }

        [Fact]
        public void Kf_VeryHighRttConverges()
        {
            var cc = CreateCc();
            long now = 100000;
            long rttUs = 500000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, rttUs, 24000); now += rttUs; }
            long ratio = cc.GeodesicXEst * 100 / (rttUs * 1024);
            Assert.InRange(ratio, 50, 150);
        }

        [Fact]
        public void Kf_JitterEwmaTracksVariation()
        {
            var cc = CreateCc();
            long now = 100000; var rng = new Random(42);
            for (int i = 0; i < 30; i++) { long n = rng.Next(-10000, 10001); cc.OnAck(now, 24000, 50000 + n, 24000); now += 50000; }
            Assert.InRange(cc.GeodesicJitterEwma, 1, 50000);
        }

        [Fact]
        public void Kf_QDelayAvgNearZeroForStableRtt()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            Assert.True(cc.GeodesicQDelayAvg < 2000);
        }

        [Fact]
        public void LtBw_NotActiveOnCleanPath()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            Assert.False(cc.IsLtUseBw);
        }



        // ================================================================
        //  SECTION 9: Integration (~10 tests, matches C++ sections 9-10)
        //  All use NetworkSimulator, no real UDP
        // ================================================================

        [Fact]
        public async Task Integration_NoLossCanConnectAndTransfer()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43001);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43001));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('A', 16 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;
                Assert.True(writeOk);
                Assert.True(readOk);
                Assert.True(payload.SequenceEqual(received));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_Loss1Percent()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: 100_000_000 / 8, lossRate: 0.01, seed: 23002);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, InitialBandwidthBytesPerSecond = 100_000_000 / 8, MaxPacingRateBytesPerSecond = 100_000_000 / 8, MaxRetransmissions = 200 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43002);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43002));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('B', 32 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;
                Assert.True(writeOk && readOk);
                Assert.True(payload.SequenceEqual(received));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_Loss5PercentWithFec()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 15, bandwidthBytesPerSecond: 20_000_000 / 8, lossRate: 0.05, seed: 23003);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, InitialBandwidthBytesPerSecond = 20_000_000 / 8, MaxPacingRateBytesPerSecond = 20_000_000 / 8, MaxRetransmissions = 300, FecGroupSize = 8, FecRedundancy = 0.5 };
            var server = new UcpServer(sim.CreateTransport("server"), config.Clone());
            var client = new UcpConnection(sim.CreateTransport("client"), true, config.Clone(), null);
            server.Start(43003);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43003));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('C', 32 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await readTask;
                Assert.True(writeOk && readOk);
                Assert.True(payload.SequenceEqual(received));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_VariableRtt()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: 100_000_000 / 8, jitterMilliseconds: 2);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, InitialBandwidthBytesPerSecond = 100_000_000 / 8, MaxPacingRateBytesPerSecond = 100_000_000 / 8 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43004);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43004));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('D', 32 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                await client.WriteAsync(payload, 0, payload.Length);
                Assert.True(await readTask);
                Assert.True(payload.SequenceEqual(received));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_BandwidthChange()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 5, bandwidthBytesPerSecond: 100_000_000 / 8);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, InitialBandwidthBytesPerSecond = 100_000_000 / 8, MaxPacingRateBytesPerSecond = 100_000_000 / 8 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43005);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43005));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('E', 16 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                sim.Configure(0, 5, 0, 5_000_000 / 8, 0, 0);
                await client.WriteAsync(payload, 0, payload.Length);
                Assert.True(await readTask);
                Assert.True(payload.SequenceEqual(received));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_SendBufferPartial()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1024 * 1024);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, SendBufferSize = 64 * 1024 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43006);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43006));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('S', 16 * 1024));
                byte[] received = new byte[payload.Length];
                int sent = await client.SendAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                Assert.InRange(sent, 1, payload.Length);
                // The transfer must actually deliver the full payload (this is
                // what the test exercises: sending into a 64KB send buffer).
                Assert.True(readOk, "server must receive the full payload");
                Assert.True(payload.SequenceEqual(received), "payload must arrive intact");
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_FullDuplex()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 4, bandwidthBytesPerSecond: 8 * 1024 * 1024, jitterMilliseconds: 2);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43007);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43007));
                UcpConnection srvConn = await acceptTask;
                byte[] cp = Encoding.ASCII.GetBytes(new string('C', 8 * 1024));
                byte[] sp = Encoding.ASCII.GetBytes(new string('S', 8 * 1024));
                byte[] rc = new byte[cp.Length], rs = new byte[sp.Length];
                await client.WriteAsync(cp, 0, cp.Length);
                bool r1 = await UcpTestHelpers.ReadWithTimeout(srvConn, rc, 5000);
                Assert.True(r1); Assert.True(cp.SequenceEqual(rc));
                await srvConn.WriteAsync(sp, 0, sp.Length);
                bool r2 = await UcpTestHelpers.ReadWithTimeout(client, rs, 5000);
                Assert.True(r2); Assert.True(sp.SequenceEqual(rs));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_JitterDoesNotBreakDelivery()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: 10 * 1024 * 1024, jitterMilliseconds: 5);
            var server = new UcpServer(sim.CreateTransport("server"));
            var client = new UcpConnection(sim.CreateTransport("client"), true, new UcpConfiguration(), null);
            server.Start(43008);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43008));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('J', 16 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                await client.WriteAsync(payload, 0, payload.Length);
                Assert.True(await readTask);
                Assert.Equal(payload, received);
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Integration_RttMeasurement()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: 10 * 1024 * 1024);
            var server = new UcpServer(sim.CreateTransport("server"));
            var client = new UcpConnection(sim.CreateTransport("client"), true, new UcpConfiguration(), null);
            server.Start(43009);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43009));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('R', 32 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = UcpTestHelpers.ReadWithTimeout(srvConn, received, 5000);
                await client.WriteAsync(payload, 0, payload.Length);
                Assert.True(await readTask);
                // RTT samples are recorded on the ACK-processing strand after the
                // final ACK arrives; wait (condition-based, bounded) for at least
                // one sample instead of racing the report snapshot.
                var report = client.GetReport();
                for (int i = 0; i < 100 && report.RttSamplesMicros.Count == 0; i++)
                {
                    await Task.Delay(5);
                    report = client.GetReport();
                }
                Assert.True(report.RttSamplesMicros.Count >= 1);
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        // ================================================================
        //  SECTION 10: Benchmarks (~6 tests, matches C++ sections 11-12)
        //  Reduced payloads for ≤10s completion
        // ================================================================

        private static byte[] BuildPayload(char value, int size)
        {
            var buf = new byte[size];
            Array.Fill(buf, (byte)value);
            return buf;
        }

        [Fact]
        public void Bench_RttTrackingGeodesicConvergence()
        {
            var cc = new UcpCongestionControl(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000; long targetRtt = 50000; int convergeIter = -1;
            for (int i = 0; i < 50; i++)
            {
                cc.OnAck(now, 24000, targetRtt, 24000); now += 50000;
                if (convergeIter < 0 && cc.MinRttMicros > 0 && cc.MinRttMicros >= targetRtt * 90 / 100 && cc.MinRttMicros <= targetRtt * 110 / 100)
                    convergeIter = i;
            }
            Assert.True(convergeIter >= 0 && convergeIter < 50);
            Assert.InRange(cc.MinRttMicros, targetRtt * 70 / 100, targetRtt * 110 / 100);
        }

        [Fact]
        public void Bench_ProbeBwGainCycle()
        {
            var cc = new UcpCongestionControl(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 20000; }
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            Assert.InRange(cc.PacingGainUnits, 1, 1023);
            for (int i = 0; i < 20; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 20000; }
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void Bench_ConvergenceFrom1MTo100M()
        {
            const long target = 100000000 / 8;
            var cc = new UcpCongestionControl(new UcpConfiguration { InitialBandwidthBytesPerSecond = 1000000 / 8, InitialCwndPackets = 20, MaxCongestionWindowBytes = 64 * 1024 * 1024, MaxPacingRateBytesPerSecond = target });
            long now = 100000;
            bool converged = false;
            for (int r = 0; r < 64; r++)
            {
                long d = Math.Max(1, target * 20000 / 1000000);
                cc.OnAck(now, d, 20000, d); now += 20000;
                if (cc.PacingRateBytesPerSecond >= target * 0.50) { converged = true; break; }
            }
            Assert.True(converged);
        }

        [Fact]
        public async Task Bench_SimulatorNoLoss100M()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: bw);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, InitialBandwidthBytesPerSecond = bw, MaxPacingRateBytesPerSecond = bw };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43051);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43051));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('N', 32 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);
                Assert.True(writeOk && readOk);
                Assert.True(payload.SequenceEqual(received));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Bench_SimulatorLoss1Percent()
        {
            const int bw = 100_000_000 / 8;
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 10, bandwidthBytesPerSecond: bw, lossRate: 0.01, seed: 23002);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, InitialBandwidthBytesPerSecond = bw, MaxPacingRateBytesPerSecond = bw, MaxRetransmissions = 200 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43052);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43052));
                UcpConnection srvConn = await acceptTask;
                byte[] payload = Encoding.ASCII.GetBytes(new string('L', 32 * 1024));
                byte[] received = new byte[payload.Length];
                Task<bool> readTask = srvConn.ReadAsync(received, 0, received.Length);
                bool writeOk = await client.WriteAsync(payload, 0, payload.Length);
                bool readOk = await UcpTestHelpers.ReadWithTimeoutTask(readTask, 5000);
                Assert.True(writeOk && readOk);
                Assert.True(payload.SequenceEqual(received));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        [Fact]
        public async Task Bench_BwConvergence1MTo100M()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 2, bandwidthBytesPerSecond: 1_000_000 / 8);
            var config = new UcpConfiguration { TimerIntervalMilliseconds = 1, InitialBandwidthBytesPerSecond = 1_000_000 / 8, MaxPacingRateBytesPerSecond = 0 };
            var server = new UcpServer(sim.CreateTransport("server"), config);
            var client = new UcpConnection(sim.CreateTransport("client"), true, config, null);
            server.Start(43053);
            try
            {
                Task<UcpConnection> acceptTask = server.AcceptAsync();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 43053));
                UcpConnection srvConn = await acceptTask;
                byte[] p1 = Encoding.ASCII.GetBytes(new string('A', 16 * 1024));
                byte[] r1 = new byte[p1.Length];
                Task<bool> rt1 = srvConn.ReadAsync(r1, 0, r1.Length);
                await client.WriteAsync(p1, 0, p1.Length);
                Assert.True(await UcpTestHelpers.ReadWithTimeoutTask(rt1, 5000));
                sim.Configure(0, 2, 0, 100_000_000 / 8, 0, 0);
                byte[] p2 = Encoding.ASCII.GetBytes(new string('B', 16 * 1024));
                byte[] r2 = new byte[p2.Length];
                Task<bool> rt2 = srvConn.ReadAsync(r2, 0, r2.Length);
                await client.WriteAsync(p2, 0, p2.Length);
                Assert.True(await UcpTestHelpers.ReadWithTimeoutTask(rt2, 5000));
            }
            finally { await UcpTestHelpers.CloseWithTimeout(client); server.Stop(); }
        }

        // ================================================================
        //  SECTION 11: Misc (~8 tests, PCB state, migration, simulator)
        //  Matches C++ sections 8, 15, 17, 22
        // ================================================================


        [Fact]
        public void Misc_GainStaysPositive()
        {
            var cc = CreateCc();
            long now = 100000;
            for (int i = 0; i < 50; i++) { cc.OnAck(now, 24000, 10000, 24000); now += 10000; }
            Assert.True(cc.PacingGainUnits >= 256);
            Assert.True(cc.CwndGainUnits > 0);
        }

        [Fact]
        public void Misc_ProbeBwVisitsMultiplePhases()
        {
            var cc = CreateCc(new UcpConfiguration { InitialBandwidthBytesPerSecond = 12500000, InitialCwndPackets = 20, MaxCongestionWindowBytes = int.MaxValue });
            long now = 100000;
            long rttUs = 30000;
            for (int i = 0; i < 200; i++) { cc.OnAck(now, 12200, rttUs, 500000); now += rttUs; }
            Assert.Equal(UcpMode.ProbeBw, cc.Mode);
            int[] gains = new int[8];
            var seen = new System.Collections.Generic.HashSet<int>();
            for (int ph = 0; ph < 128; ph++)
            {
                int idx = cc.ProbeBwCycleIdx & 7;
                gains[idx] = cc.PacingGainUnits;
                seen.Add(idx);
                Assert.InRange(cc.PacingGainUnits, 0, 1023);
                cc.OnAck(now, 12200, rttUs, 500000); now += rttUs;
            }
            Assert.True(gains[0] > 0);
            // The 8-phase claim: over a long window the cycle must traverse
            // distinct phases.
            Assert.True(seen.Count >= 3,
                $"ProbeBw cycle must traverse multiple phases: got {seen.Count}/8");
        }

        [Fact]
        public void Misc_NetworkSimulatorStats()
        {
            var sim = new NetworkSimulator(bandwidthBytesPerSecond: 1024 * 1024);
            Assert.Equal(0, sim.SentPackets);
            Assert.Equal(0, sim.DeliveredPackets);
        }

        [Fact]
        public void Misc_NetworkSimulatorReconfigure()
        {
            var sim = new NetworkSimulator(lossRate: 0.1, fixedDelayMilliseconds: 10, jitterMilliseconds: 5, bandwidthBytesPerSecond: 1024, seed: 42);
            Assert.Equal(0.1, sim.LossRate);
            sim.Configure(0.01, 20, 0, 100000, 0.1, 0.1);
            Assert.Equal(0.01, sim.LossRate);
            Assert.Equal(20, sim.ForwardDelayMilliseconds);
        }

        [Fact]
        public async Task Misc_NetworkSimulatorFixedDelay()
        {
            var sim = new NetworkSimulator(fixedDelayMilliseconds: 20, bandwidthBytesPerSecond: 1024 * 1024);
            var t1 = sim.CreateTransport("a");
            var t2 = sim.CreateTransport("b");
            t1.Start(31100); t2.Start(31101);
            var tcs = new TaskCompletionSource();
            t2.OnDatagram += (_, _) => tcs.TrySetResult();
            t1.Send(new byte[50], new IPEndPoint(IPAddress.Loopback, t2.LocalPort));
            var done = await Task.WhenAny(tcs.Task, Task.Delay(200));
            Assert.True(done == tcs.Task);
        }
    }
}
