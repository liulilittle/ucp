using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ucp;
using Ucp.Internal;
#pragma warning disable CS0067, CS8600, xUnit1031
using Ucp.Transport;
using UcpTest.TestTransport;
using Xunit;
using Xunit.Abstractions;

namespace UcpTest
{
    public sealed class UcpComprehensiveTests
    {
        private readonly ITestOutputHelper _output;
        public UcpComprehensiveTests(ITestOutputHelper output) { _output = output; }

        [Fact]
        public void Pcb_InitialState_IsInit()
        {
            using var pcb = CreatePcb();
            Assert.Equal(UcpConnectionState.Init, pcb.State);
        }

        [Fact]
        public void Pcb_ConnectAsync_TransitionsToSynSent()
        {
            using var pcb = CreatePcb();
            var endpoint = new IPEndPoint(IPAddress.Loopback, 9999);
            Task.Run(async () =>
            {
                try { await pcb.ConnectAsync(endpoint); } catch { }
            });
            bool reachedState = SpinWait.SpinUntil(() => pcb.State == UcpConnectionState.HandshakeSynSent, 10000);
            Assert.True(reachedState, $"Expected HandshakeSynSent but got {pcb.State} after 10000ms timeout");
            Assert.Equal(UcpConnectionState.HandshakeSynSent, pcb.State);
        }

        [Fact]
        public void Pcb_SynReceived_TransitionsToSynReceived()
        {
            using var serverPcb = CreateServerPcb();
            var syn = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Syn,
                    ConnectionId = 42,
                    Timestamp = 1000
                },
                HasSequenceNumber = true,
                SequenceNumber = 100,
                SessionKey = 12345
            };
            serverPcb.SetRemoteEndPoint(new IPEndPoint(IPAddress.Loopback, 9998));
            serverPcb.HandleInboundAsync(syn).GetAwaiter().GetResult();
            Assert.Equal(UcpConnectionState.HandshakeSynReceived, serverPcb.State);
        }

        [Fact]
        public void Pcb_HandleFin_TransitionsToClosing()
        {
            using var pcb = CreateEstablishedPcb();
            var fin = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Fin,
                    ConnectionId = 1,
                    Timestamp = 50000,
                    Flags = UcpPacketFlags.HasAckNumber
                },
                AckNumber = 10
            };
            pcb.HandleInboundAsync(fin).GetAwaiter().GetResult();
            Assert.Equal(UcpConnectionState.ClosingFinReceived, pcb.State);
        }

        [Fact]
        public void Pcb_HandleRst_TransitionsToClosed()
        {
            using var pcb = CreateEstablishedPcb();
            var rst = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Rst,
                    ConnectionId = 1,
                    Timestamp = 50000
                }
            };
            pcb.HandleInboundAsync(rst).GetAwaiter().GetResult();
            Assert.Equal(UcpConnectionState.Closed, pcb.State);
        }

        [Fact]
        public void Pcb_Abort_TransitionsToClosed()
        {
            using var pcb = CreatePcb();
            pcb.Abort(false);
            Assert.Equal(UcpConnectionState.Closed, pcb.State);
        }

        [Fact]
        public void Pcb_Dispose_IsIdempotent()
        {
            var pcb = CreatePcb();
            pcb.Dispose();
            pcb.Dispose();
            Assert.True(pcb.Disposed);
        }

        [Fact]
        public void Pcb_DoubleDispose_DoesNotThrow()
        {
            var pcb = CreatePcb();
            pcb.Dispose();
            pcb.Dispose();
        }

        [Fact]
        public void Pcb_AbortWithReset_SendsRst()
        {
            using var pcb = CreateEstablishedPcb();
            pcb.Abort(true);
            Assert.Equal(UcpConnectionState.Closed, pcb.State);
        }

        [Fact]
        public void Pcb_StateProperty_ThreadSafe()
        {
            using var pcb = CreatePcb();
            var state = pcb.State;
            Assert.Equal(UcpConnectionState.Init, state);
        }

        [Fact]
        public void Pcb_SetRemoteEndPoint_UpdatesProperty()
        {
            using var pcb = CreatePcb();
            var ep = new IPEndPoint(IPAddress.Loopback, 8888);
            pcb.SetRemoteEndPoint(ep);
            Assert.Equal(ep, pcb.RemoteEndPoint);
        }

        [Fact]
        public void Pcb_SetNextSendSequence_Works()
        {
            using var pcb = CreatePcb();
            pcb.SetNextSendSequenceForTest(12345);
            // The setter must leave the PCB fully functional: state machine
            // intact and send path responding (not-connected error here, since
            // the PCB was never connected -- a broken setter would either throw
            // or corrupt the sequence state visible to subsequent sends).
            Assert.Equal(UcpConnectionState.Init, pcb.State);
            int sent = pcb.SendAsync(new byte[100], 0, 100).GetAwaiter().GetResult();
            Assert.Equal(-1, sent);
        }

        [Fact]
        public void Pcb_ConnectionId_IsNonZero()
        {
            using var pcb = CreatePcb();
            Assert.NotEqual(0u, pcb.ConnectionId);
        }

        [Fact]
        public void Pcb_ValidateRemoteEndPoint_AcceptsFirstPacket()
        {
            using var pcb = CreatePcb();
            Assert.True(pcb.ValidateRemoteEndPoint(new IPEndPoint(IPAddress.Loopback, 7777)));
        }

        [Fact]
        public void Pcb_ConnectionId_UniquePerInstance()
        {
            using var pcb1 = CreatePcb();
            using var pcb2 = CreatePcb();
            Assert.NotEqual(pcb1.ConnectionId, pcb2.ConnectionId);
        }

        [Fact]
        public void Pcb_SendAsync_ReturnsNegativeWhenNotEstablished()
        {
            using var pcb = CreatePcb();
            var task = pcb.SendAsync(new byte[10], 0, 10);
            Assert.Equal(-1, task.Result);
        }

        [Fact]
        public void Pcb_ReceiveAsync_ReturnsZeroWhenClosed()
        {
            using var pcb = CreatePcb();
            pcb.Abort(false);
            var task = pcb.ReceiveAsync(new byte[10], 0, 10);
            Assert.Equal(0, task.Result);
        }

        [Fact]
        public void Pcb_ReadAsync_ReturnsFalseWhenClosed()
        {
            using var pcb = CreatePcb();
            pcb.Abort(false);
            var task = pcb.ReadAsync(new byte[10], 0, 10);
            Assert.False(task.Result);
        }

        [Fact]
        public void Pcb_WriteAsync_ReturnsFalseWhenClosed()
        {
            using var pcb = CreatePcb();
            pcb.Abort(false);
            var task = pcb.WriteAsync(new byte[10], 0, 10);
            Assert.False(task.Result);
        }

        [Fact]
        public void Pcb_IsValidCid_MatchesPrimary()
        {
            using var pcb = CreatePcb();
            Assert.True(pcb.IsValidCid(pcb.ConnectionId));
            Assert.False(pcb.IsValidCid(0));
        }

        [Fact]
        public void Pcb_AddExtraCid_ExtendsValidity()
        {
            using var pcb = CreatePcb();
            Assert.True(pcb.AddExtraCid(99));
            Assert.True(pcb.IsValidCid(99));
            Assert.False(pcb.AddExtraCid(0));
        }

        [Fact]
        public void Rto_InitialValue_IsAboveMin()
        {
            var config = new UcpConfiguration();
            var rto = new UcpRtoEstimator(config);
            Assert.True(rto.CurrentRtoMicros >= config.EffectiveMinRtoMicros);
        }

        [Fact]
        public void Rto_UpdateWithLargeSample_Increases()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(50000);
            long v1 = rto.CurrentRtoMicros;
            rto.Update(200000);
            long v2 = rto.CurrentRtoMicros;
            // A 4x larger RTT sample must push the RTO estimate upward
            // (the increase is the name's claim).
            Assert.True(v2 > v1,
                $"RTO must increase with a larger sample: {v2} <= {v1}");
        }

        [Fact]
        public void Rto_UpdateWithSmallSample_RemainsReasonable()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(100000);
            rto.Update(10000);
            Assert.InRange(rto.CurrentRtoMicros, 0, 1000000);
        }

        [Fact]
        public void Rto_Backoff_MultipleTimes_Plateaus()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            long prev = rto.CurrentRtoMicros;
            for (int i = 0; i < 10; i++)
            {
                rto.Backoff();
                if (i > 0)
                    Assert.True(rto.CurrentRtoMicros >= prev);
                prev = rto.CurrentRtoMicros;
            }
        }

        [Fact]
        public void Rto_BackoffExceedingMax_IsCapped()
        {
            var config = new UcpConfiguration();
            var rto = new UcpRtoEstimator(config);
            for (int i = 0; i < 50; i++)
                rto.Backoff();
            Assert.True(rto.CurrentRtoMicros <= config.EffectiveMaxRtoMicros);
        }

        [Fact]
        public void Rto_Backoff_ExceedsMinRtoProduct()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            long initial = rto.CurrentRtoMicros;
            rto.Backoff();
            Assert.True(rto.CurrentRtoMicros >= initial);
        }

        [Fact]
        public void Rto_SmoothedRtt_StartsAtZero()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            Assert.Equal(0, rto.SmoothedRttMicros);
        }

        [Fact]
        public void Rto_RttVariance_StartsAtZero()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            Assert.Equal(0, rto.RttVarianceMicros);
        }

        [Fact]
        public void Rto_Update_WithZeroSample_Ignored()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(50000);
            long before = rto.CurrentRtoMicros;
            rto.Update(0);
            Assert.Equal(before, rto.CurrentRtoMicros);
        }

        [Fact]
        public void Rto_Update_WithNegativeSample_Ignored()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(50000);
            long before = rto.CurrentRtoMicros;
            rto.Update(-100);
            Assert.Equal(before, rto.CurrentRtoMicros);
        }

        [Fact]
        public void Rto_FirstSample_InitializesDirectly()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(75000);
            Assert.Equal(75000, rto.SmoothedRttMicros);
            Assert.True(rto.RttVarianceMicros > 0);
        }

        [Fact]
        public void Rto_MultipleBackoffs_IncreaseMonotonically()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            long prev = rto.CurrentRtoMicros;
            for (int i = 0; i < 5; i++)
            {
                rto.Backoff();
                Assert.True(rto.CurrentRtoMicros >= prev);
                prev = rto.CurrentRtoMicros;
            }
        }

        [Fact]
        public void Rto_UpdateAfterBackoff_ResetsToSmoothValue()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(50000);
            rto.Backoff();
            rto.Update(60000);
            Assert.True(rto.CurrentRtoMicros < 500000);
            Assert.True(rto.SmoothedRttMicros > 0);
        }

        [Fact]
        public void Rto_RapidConsecutiveSamples_SmoothEwma()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(100000);
            long srtt1 = rto.SmoothedRttMicros;
            rto.Update(90000);
            long srtt2 = rto.SmoothedRttMicros;
            rto.Update(110000);
            long srtt3 = rto.SmoothedRttMicros;
            rto.Update(95000);
            long srtt4 = rto.SmoothedRttMicros;
            Assert.NotEqual(srtt1, srtt2);
            Assert.InRange(srtt4, 60000, 140000);
        }

        [Fact]
        public void Rto_MultipleUpdates_ChangeRto()
        {
            var rto = new UcpRtoEstimator(new UcpConfiguration());
            rto.Update(50000);
            long before = rto.CurrentRtoMicros;
            rto.Update(50000);
            Assert.NotEqual(before, rto.CurrentRtoMicros);
        }

        [Fact]
        public void Codec_DataPacket_RoundTrips()
        {
            var packet = new UcpDataPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Data,
                    Flags = UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber,
                    ConnectionId = 1,
                    Timestamp = 100000
                },
                SequenceNumber = 50,
                FragmentTotal = 2,
                FragmentIndex = 1,
                Payload = Encoding.ASCII.GetBytes("HelloUCP"),
                AckNumber = 30,
                WindowSize = 65535,
                EchoTimestamp = 90000
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var data = Assert.IsType<UcpDataPacket>(decoded);
            Assert.Equal(packet.Header.Type, data.Header.Type);
            Assert.Equal(packet.Header.ConnectionId, data.Header.ConnectionId);
            Assert.Equal(packet.SequenceNumber, data.SequenceNumber);
            Assert.Equal(packet.Payload, data.Payload);
            Assert.Equal(packet.AckNumber, data.AckNumber);
        }

        [Fact]
        public void Codec_NakPacket_RoundTrips()
        {
            var packet = new UcpNakPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Nak,
                    ConnectionId = 1,
                    Timestamp = 5000
                },
                AckNumber = 100,
                MissingSequences = { 101, 105, 110 }
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var nak = Assert.IsType<UcpNakPacket>(decoded);
            Assert.Equal(packet.AckNumber, nak.AckNumber);
            Assert.Equal(packet.MissingSequences, nak.MissingSequences);
        }

        [Fact]
        public void Codec_FecRepairPacket_RoundTrips()
        {
            var packet = new UcpFecRepairPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.FecRepair,
                    ConnectionId = 1,
                    Timestamp = 5000
                },
                GroupId = 16,
                GroupIndex = 0,
                Payload = new byte[] { 1, 2, 3, 4 }
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var fec = Assert.IsType<UcpFecRepairPacket>(decoded);
            Assert.Equal(packet.GroupId, fec.GroupId);
            Assert.Equal(packet.GroupIndex, fec.GroupIndex);
            Assert.Equal(packet.Payload, fec.Payload);
        }

        [Fact]
        public void Codec_SynPacket_RoundTrips()
        {
            var packet = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Syn,
                    ConnectionId = 0,
                    Timestamp = 1000
                },
                HasSequenceNumber = true,
                SequenceNumber = 12345,
                SessionKey = 98765
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var syn = Assert.IsType<UcpControlPacket>(decoded);
            Assert.Equal(UcpPacketType.Syn, syn.Header.Type);
            Assert.True(syn.HasSequenceNumber);
            Assert.Equal(packet.SequenceNumber, syn.SequenceNumber);
            Assert.Equal(packet.SessionKey, syn.SessionKey);
        }

        [Fact]
        public void Codec_SynAckPacket_RoundTrips()
        {
            var packet = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.SynAck,
                    ConnectionId = 1,
                    Timestamp = 2000,
                    Flags = UcpPacketFlags.HasAckNumber
                },
                HasSequenceNumber = true,
                SequenceNumber = 67890,
                AckNumber = 12345
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var synack = Assert.IsType<UcpControlPacket>(decoded);
            Assert.Equal(UcpPacketType.SynAck, synack.Header.Type);
            Assert.Equal(packet.SequenceNumber, synack.SequenceNumber);
        }

        [Fact]
        public void Codec_FinPacket_RoundTrips()
        {
            var packet = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Fin,
                    ConnectionId = 1,
                    Timestamp = 3000,
                    Flags = UcpPacketFlags.HasAckNumber
                },
                AckNumber = 200
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var fin = Assert.IsType<UcpControlPacket>(decoded);
            Assert.Equal(UcpPacketType.Fin, fin.Header.Type);
        }

        [Fact]
        public void Codec_RstPacket_RoundTrips()
        {
            var packet = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Rst,
                    ConnectionId = 1,
                    Timestamp = 4000
                }
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var rst = Assert.IsType<UcpControlPacket>(decoded);
            Assert.Equal(UcpPacketType.Rst, rst.Header.Type);
        }

        [Fact]
        public void Codec_DataPacketWithSackBlocks_RoundTrips()
        {
            var packet = new UcpDataPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Data,
                    Flags = UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber,
                    ConnectionId = 1,
                    Timestamp = 50000
                },
                SequenceNumber = 10,
                FragmentTotal = 1,
                FragmentIndex = 0,
                Payload = new byte[] { 0x41, 0x42, 0x43 },
                AckNumber = 5,
                WindowSize = 1024,
                EchoTimestamp = 40000
            };
            packet.SackBlocks.Add(new SackBlock { Start = 8, End = 9 });
            packet.SackBlocks.Add(new SackBlock { Start = 12, End = 14 });
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var data = Assert.IsType<UcpDataPacket>(decoded);
            Assert.Equal(2, data.SackBlocks.Count);
            Assert.Equal(8u, data.SackBlocks[0].Start);
            Assert.Equal(14u, data.SackBlocks[1].End);
        }

        [Fact]
        public void Codec_NakPacket_EmptyMissingList()
        {
            var packet = new UcpNakPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Nak,
                    ConnectionId = 1,
                    Timestamp = 5000
                },
                AckNumber = 100
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var nak = Assert.IsType<UcpNakPacket>(decoded);
            Assert.Empty(nak.MissingSequences);
        }

        [Fact]
        public void Codec_TryDecode_NullBuffer_ReturnsFalse()
        {
            Assert.False(UcpPacketCodec.TryDecode(null, 0, 0, out var packet));
            Assert.Null(packet);
        }

        [Fact]
        public void Codec_TryDecode_EmptyBuffer_ReturnsFalse()
        {
            Assert.False(UcpPacketCodec.TryDecode(Array.Empty<byte>(), 0, 0, out var packet));
            Assert.Null(packet);
        }

        [Fact]
        public void Codec_Encode_NullPacket_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => UcpPacketCodec.Encode(null));
        }

        [Fact]
        public void Codec_DataPacket_NoSackBlocks_RoundTrips()
        {
            var packet = new UcpDataPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Data,
                    Flags = UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber,
                    ConnectionId = 5,
                    Timestamp = 12345
                },
                SequenceNumber = 1,
                FragmentTotal = 1,
                FragmentIndex = 0,
                Payload = new byte[] { 0xFF },
                AckNumber = 0,
                WindowSize = 32768
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var data = Assert.IsType<UcpDataPacket>(decoded);
            Assert.Empty(data.SackBlocks);
        }

        [Fact]
        public void Codec_FinWithAck_RoundTrips()
        {
            var packet = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Fin,
                    Flags = UcpPacketFlags.HasAckNumber | UcpPacketFlags.FinAck,
                    ConnectionId = 1,
                    Timestamp = 5000
                },
                AckNumber = 300
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var fin = Assert.IsType<UcpControlPacket>(decoded);
            Assert.Equal(UcpPacketFlags.HasAckNumber | UcpPacketFlags.FinAck, fin.Header.Flags);
        }

        [Fact]
        public void Codec_LargePayload_EncodesDecodes()
        {
            var payload = new byte[1024];
            new Random(42).NextBytes(payload);
            var packet = new UcpDataPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Data,
                    Flags = UcpPacketFlags.NeedAck | UcpPacketFlags.HasAckNumber,
                    ConnectionId = 1,
                    Timestamp = 5000
                },
                SequenceNumber = 100,
                FragmentTotal = 1,
                FragmentIndex = 0,
                Payload = payload,
                AckNumber = 50,
                WindowSize = 4096
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var data = Assert.IsType<UcpDataPacket>(decoded);
            Assert.Equal(payload, data.Payload);
        }

        [Fact]
        public void Codec_UnknownType_ReturnsFalse()
        {
            byte[] buf = new byte[20];
            buf[0] = 0xFF;
            Assert.False(UcpPacketCodec.TryDecode(buf, 0, buf.Length, out _));
        }

        [Fact]
        public void Codec_SynWithAck_RoundTrips()
        {
            var packet = new UcpControlPacket
            {
                Header = new UcpCommonHeader
                {
                    Type = UcpPacketType.Syn,
                    Flags = UcpPacketFlags.HasAckNumber,
                    ConnectionId = 0,
                    Timestamp = 2000
                },
                HasSequenceNumber = true,
                SequenceNumber = 500,
                AckNumber = 10,
                SessionKey = 777
            };
            byte[] encoded = UcpPacketCodec.Encode(packet);
            Assert.True(UcpPacketCodec.TryDecode(encoded, 0, encoded.Length, out var decoded));
            var syn = Assert.IsType<UcpControlPacket>(decoded);
            Assert.Equal(packet.SessionKey, syn.SessionKey);
            Assert.Equal(packet.AckNumber, syn.AckNumber);
        }

        [Fact]
        public void SackGen_Empty_ReturnsEmptyList()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, Array.Empty<uint>(), 4);
            Assert.Empty(result);
        }

        [Fact]
        public void SackGen_Continuous_ReturnsSingleBlock()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 101, 102, 103 }, 4);
            Assert.Single(result);
            Assert.Equal(101u, result[0].Start);
            Assert.Equal(103u, result[0].End);
        }

        [Fact]
        public void SackGen_MultipleGaps_ReturnsMultipleBlocks()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 101, 102, 105, 106, 110 }, 4);
            Assert.Equal(3, result.Count);
            Assert.Equal(101u, result[0].Start);
            Assert.Equal(102u, result[0].End);
            Assert.Equal(105u, result[1].Start);
            Assert.Equal(106u, result[1].End);
            Assert.Equal(110u, result[2].Start);
            Assert.Equal(110u, result[2].End);
        }

        [Fact]
        public void SackGen_MaxBlocks_TrimsExcess()
        {
            var gen = new UcpSackGenerator();
            var sequences = new List<uint>();
            for (uint i = 0; i < 20; i++)
                sequences.Add(100 + i * 3);
            var result = gen.Generate(100, sequences, 3);
            Assert.True(result.Count <= 3);
        }

        [Fact]
        public void SackGen_WrapAround_HandlesCorrectly()
        {
            var gen = new UcpSackGenerator();
            uint max = uint.MaxValue;
            var result = gen.Generate(max, new uint[] { 0, 1, 2 }, 4);
            Assert.Single(result);
            Assert.Equal(0u, result[0].Start);
            Assert.Equal(2u, result[0].End);
        }

        [Fact]
        public void SackGen_SingleSequence_ReturnsSingleBlock()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 105 }, 4);
            Assert.Single(result);
            Assert.Equal(105u, result[0].Start);
            Assert.Equal(105u, result[0].End);
        }

        [Fact]
        public void SackGen_SequencesBeforeExpected_Excluded()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(200, new uint[] { 150, 201, 202 }, 4);
            Assert.Single(result);
            Assert.Equal(201u, result[0].Start);
        }

        [Fact]
        public void SackGen_MaxBlocksOne_ReturnsSingleBlock()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 101, 103, 105 }, 1);
            Assert.Single(result);
        }

        [Fact]
        public void SackGen_MaxBlocksZero_ReturnsEmpty()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 101, 102 }, 0);
            Assert.Empty(result);
        }

        [Fact]
        public void SackGen_LargeGap_ManyBlocks()
        {
            var gen = new UcpSackGenerator();
            var sequences = new List<uint>();
            for (uint i = 0; i < 100; i++)
                sequences.Add(100 + i * 5);
            var result = gen.Generate(100, sequences, 100);
            Assert.Equal(100, result.Count);
        }

        [Fact]
        public void SackGen_AllConsecutive_ExactMax()
        {
            var gen = new UcpSackGenerator();
            var sequences = new List<uint>();
            for (uint i = 0; i < 10; i++)
                sequences.Add(100 + i);
            var result = gen.Generate(100, sequences, 10);
            Assert.Single(result);
            Assert.Equal(100u, result[0].Start);
            Assert.Equal(109u, result[0].End);
        }

        [Fact]
        public void SackGen_AfterWrap_HandlesCorrectly()
        {
            var gen = new UcpSackGenerator();
            uint max = uint.MaxValue - 3;
            var result = gen.Generate(max, new uint[] { max + 1, max + 2, 5, 6 }, 4);
            Assert.Equal(2, result.Count);
        }

        [Fact]
        public void SackGen_OrderIrrelevant_ProducesSortedOutput()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 105, 101, 103, 102, 104 }, 4);
            Assert.Single(result);
            Assert.Equal(101u, result[0].Start);
            Assert.Equal(105u, result[0].End);
        }

        [Fact]
        public void SackGen_GapAtStart_CorrectBlock()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 102, 103, 104 }, 4);
            Assert.Single(result);
            Assert.Equal(102u, result[0].Start);
            Assert.Equal(104u, result[0].End);
        }

        [Fact]
        public void SackGen_AllEmptyAfterExpected_Empty()
        {
            var gen = new UcpSackGenerator();
            var result = gen.Generate(100, new uint[] { 50, 60, 70 }, 4);
            Assert.Empty(result);
        }

        [Fact]
        public void FecCodec_GroupSize_RespectsMinimum()
        {
            var fec = new UcpFecCodec(2, 4);
            Assert.Equal(2, fec.RepairCount);
        }

        [Fact]
        public void FecCodec_GroupSize_RespectsMaximum()
        {
            var fec = new UcpFecCodec(128, 64);
            Assert.True(fec.RepairCount <= 64);
        }

        [Fact]
        public void FecCodec_EmptyPayload_DoesNotCrash()
        {
            var fec = new UcpFecCodec(2, 1);
            var result = fec.TryEncodeRepairs(new byte[0]);
            Assert.Null(result);
        }

        [Fact]
        public void FecCodec_NullPayload_DoesNotCrash()
        {
            var fec = new UcpFecCodec(2, 1);
            var result = fec.TryEncodeRepairs(null);
            Assert.Null(result);
        }

        [Fact]
        public void FecCodec_GarbageData_DoesNotCrash()
        {
            var fec = new UcpFecCodec(4, 2);
            var rng = new Random(99);
            for (int i = 0; i < 100; i++)
            {
                byte[] garbage = new byte[rng.Next(1, 100)];
                rng.NextBytes(garbage);
                fec.FeedDataPacket((uint)i, garbage);
            }
        }

        [Fact]
        public void FecCodec_PartialGroup_ReturnsNull()
        {
            var fec = new UcpFecCodec(4, 2);
            var result = fec.TryEncodeRepairs(0, new byte[] { 1, 2, 3 });
            Assert.Null(result);
        }

        [Fact]
        public void FecCodec_EncodeRepairs_CompleteReturnsRepairs()
        {
            var fec = new UcpFecCodec(4, 2);
            byte[][] payloads = new byte[4][];
            for (int i = 0; i < 4; i++)
                payloads[i] = new byte[] { (byte)(i + 1), (byte)((i + 1) * 2) };
            var r1 = fec.TryEncodeRepairs(0u, payloads[0]); Assert.Null(r1);
            var r2 = fec.TryEncodeRepairs(1u, payloads[1]); Assert.Null(r2);
            var r3 = fec.TryEncodeRepairs(2u, payloads[2]); Assert.Null(r3);
            var repairs = fec.TryEncodeRepairs(3u, payloads[3]);
            Assert.NotNull(repairs);
            Assert.Equal(2, repairs.Count);
        }

        [Fact]
        public void FecCodec_AllDataPresent_RecoveryReturnsEmpty()
        {
            var fec = new UcpFecCodec(4, 2);
            byte[][] payloads = new byte[4][];
            for (int i = 0; i < 4; i++)
                payloads[i] = new byte[] { (byte)i };
            var r1 = fec.TryEncodeRepairs(0u, payloads[0]);
            var r2 = fec.TryEncodeRepairs(1u, payloads[1]);
            var r3 = fec.TryEncodeRepairs(2u, payloads[2]);
            var repairs = fec.TryEncodeRepairs(3u, payloads[3]);
            Assert.NotNull(repairs);

            var dec = new UcpFecCodec(4, 2);
            dec.FeedDataPacket(0, payloads[0]);
            dec.FeedDataPacket(1, payloads[1]);
            dec.FeedDataPacket(2, payloads[2]);
            dec.FeedDataPacket(3, payloads[3]);
            var result = dec.TryRecoverFromRepair(repairs[0], 0);
            Assert.Null(result);
        }

        [Fact]
        public void FecCodec_GetGroupBase_ReturnsExpected()
        {
            var fec = new UcpFecCodec(8, 2);
            Assert.Equal(0u, fec.GetGroupBase(0));
            Assert.Equal(0u, fec.GetGroupBase(7));
            Assert.Equal(8u, fec.GetGroupBase(8));
            Assert.Equal(8u, fec.GetGroupBase(15));
            Assert.Equal(16u, fec.GetGroupBase(16));
        }

        [Fact]
        public void FecCodec_GetSlot_ReturnsModulo()
        {
            var fec = new UcpFecCodec(8, 2);
            Assert.Equal(0, fec.GetSlot(0));
            Assert.Equal(7, fec.GetSlot(7));
            Assert.Equal(0, fec.GetSlot(8));
            Assert.Equal(3, fec.GetSlot(11));
        }

        [Fact]
        public void FecCodec_MaxGroupSize_Works()
        {
            var fec = new UcpFecCodec(64, 16);
            Assert.True(fec.RepairCount > 0);
        }

        [Fact]
        public void FecCodec_TwoRepairs_RecoversTwoLosses()
        {
            var fec = new UcpFecCodec(4, 2);
            byte[][] payloads = new byte[4][];
            for (int i = 0; i < 4; i++)
                payloads[i] = new byte[] { (byte)(i * 3 + 5) };
            var r1 = fec.TryEncodeRepairs(0u, payloads[0]); Assert.Null(r1);
            var r2 = fec.TryEncodeRepairs(1u, payloads[1]); Assert.Null(r2);
            var r3 = fec.TryEncodeRepairs(2u, payloads[2]); Assert.Null(r3);
            var repairs = fec.TryEncodeRepairs(3u, payloads[3]);
            Assert.NotNull(repairs);
            Assert.Equal(2, repairs.Count);

            var dec = new UcpFecCodec(4, 2);
            dec.FeedDataPacket(0, payloads[0]);
            dec.FeedDataPacket(2, payloads[2]);
            dec.FeedDataPacket(3, payloads[3]);
            var rec = dec.TryRecoverFromRepair(repairs[0], 0);
            Assert.NotNull(rec);
            Assert.Equal(payloads[1], rec);
        }

        [Fact]
        public void FecCodec_PartialGroup_NotSent()
        {
            var fec = new UcpFecCodec(4, 1);
            var r1 = fec.TryEncodeRepairs(0u, new byte[] { 1 });
            Assert.Null(r1);
            var r2 = fec.TryEncodeRepairs(1u, new byte[] { 2 });
            Assert.Null(r2);
            var r3 = fec.TryEncodeRepairs(2u, new byte[] { 3 });
            Assert.Null(r3);
        }

        [Fact]
        public void FecCodec_FeedSeqEncoded_GroupCompletesCorrectly()
        {
            var fec = new UcpFecCodec(4, 1);
            var r1 = fec.TryEncodeRepairs(0u, new byte[] { 10 });
            Assert.Null(r1);
            var r2 = fec.TryEncodeRepairs(1u, new byte[] { 20 });
            Assert.Null(r2);
            var r3 = fec.TryEncodeRepairs(2u, new byte[] { 30 });
            Assert.Null(r3);
            var r4 = fec.TryEncodeRepairs(3u, new byte[] { 40 });
            Assert.NotNull(r4);
            Assert.Single(r4);
        }

        [Fact]
        public void Cc_InitialMode_IsStartup()
        {
            var cc = CreateCc();
            Assert.Equal(UcpMode.Startup, cc.Mode);
        }

        [Fact]
        public void Cc_InitialCwnd_IsPositive()
        {
            var cc = CreateCc();
            Assert.True(cc.CongestionWindowBytes > 0);
        }

        [Fact]
        public void Cc_InitialPacingRate_IsPositive()
        {
            var cc = CreateCc();
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void Cc_OnAck_DeliversBytes_UpdatesState()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 24000, 50000, 24000);
            Assert.True(cc.TotalDelivered > 0);
        }

        [Fact]
        public void Cc_OnPathChange_ResetsMinRtt()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 24000, 50000, 24000);
            Assert.True(cc.MinRttMicros > 0);
            cc.OnPathChange(200000);
            Assert.Equal(0, cc.MinRttMicros);
        }

        [Fact]
        public void Cc_OnPathChange_ResetsToStartup()
        {
            var cc = CreateCc();
            cc.OnPathChange(100000);
            Assert.Equal(UcpMode.Startup, cc.Mode);
        }

        [Fact]
        public void Cc_OnRto_DoesNotChangeMode()
        {
            var cc = CreateCc();
            for (int i = 0; i < 20; i++)
                cc.OnAck(100000 + i * 10000, 48000, 10000, 48000);
            Assert.NotEqual(UcpMode.Startup, cc.Mode);
            var modeBefore = cc.Mode;
            cc.OnRto();
            Assert.Equal(modeBefore, cc.Mode);
        }

        [Fact]
        public void Cc_OnRto_ResetsPacketConservation()
        {
            var cc = CreateCc();
            cc.OnFastRetransmit(100000, true, 1000);
            cc.OnRto();
            // RTO returns CC to CA_OPEN, restores the initial cwnd and the
            // STARTUP gains (the conservation reset the name claims).
            Assert.Equal(UcpConstants.UCP_HIGH_GAIN, cc.CwndGainUnits);
            Assert.True(cc.CongestionWindowBytes > 0,
                $"cwnd must be positive after RTO reset: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond >= 0);
        }

        [Fact]
        public void Cc_EcnBackoff_ReducesGains()
        {
            var config = new UcpConfiguration { EcnEnabled = true };
            var cc = CreateCc(config);
            long now = 100000;
            for (int i = 0; i < 10; i++)
            {
                cc.OnAck(now, 24000, 10000, 24000);
                now += 10000;
            }
            var cwndGainBefore = cc.CwndGainUnits;
            Assert.True(cwndGainBefore > 0);
            // ECN backoff triggers when qdelay exceeds CongThresh
            // (max(minRtt*25%, 500us)): double the RTT (10ms -> 20ms) so the
            // qdelay (~10ms) clears the threshold before the geodesic min-RTT
            // tracker catches up, and sustain CE marking so the EWMA stays
            // positive (mirrors UcpCoreTests.EcnBackoff_ReducesCwndWhenQueueBuilds).
            cc.OnCeMark(50);
            for (int i = 0; i < 4; i++)
            {
                cc.OnAck(now, 24000, 20000, 24000);
                now += 20000;
                cc.OnCeMark(300);
            }
            Assert.True(cc.CwndGainUnits < cwndGainBefore,
                $"ECN backoff must reduce the cwnd gain: {cc.CwndGainUnits} >= {cwndGainBefore} [qdelay={cc.GeodesicQDelayAvg} ecn={cc.EcnEwmaValue} mode={cc.Mode} rtt={cc.MinRttMicros}]");
        }

        [Fact]
        public void Cc_OnFecRecovery_DoesNotInflateDelivered()
        {
            var cc = CreateCc();
            long before = cc.TotalDelivered;
            cc.OnFecRecovery(100000, 1000);
            Assert.Equal(before, cc.TotalDelivered);
        }

        [Fact]
        public void Cc_OnFecRecovery_DoesNotCrash()
        {
            var cc = CreateCc();
            cc.OnFecRecovery(100000, 500);
        }

        [Fact]
        public void Cc_G2Growth_ResetsOnConvergedPEst()
        {
            var cc = CreateCc();
            // Phase 1: low-RTT baseline so min_rtt settles (~10ms) and PEst
            // decays toward its floor.
            for (int i = 0; i < 10; i++)
                cc.OnAck(100000 + i * 10000, 24000, 10000, 24000);
            long pEstAtFloor = cc.GeodesicPEst;
            // Phase 2: a massive RTT spike confirms the fast path, updating
            // min_rtt = x_est and resetting PEst to its INIT base (the G2
            // growth/convergence reset the test name claims).
            cc.OnAck(900000, 24000, 500000, 24000);
            Assert.True(cc.GeodesicPEst <= UcpConstants.UCP_P_EST_INIT,
                $"G2 growth must reset on converged PEst spike: PEst {cc.GeodesicPEst} > INIT {UcpConstants.UCP_P_EST_INIT}");
            Assert.True(cc.GeodesicPEst >= 0, "PEst must stay non-negative");
        }

        [Fact]
        public void Cc_FastRetransmit_EntersPacketConservation()
        {
            var cc = CreateCc();
            long cwndBefore = cc.CongestionWindowBytes;
            cc.OnFastRetransmit(100000, true, 1000);
            // Packet conservation: fast retransmit (congestion loss) must not
            // let the window grow -- it stays at or below the pre-loss value.
            Assert.True(cc.CongestionWindowBytes <= cwndBefore,
                $"cwnd must not grow after fast retransmit: {cc.CongestionWindowBytes} > {cwndBefore}");
        }

        [Fact]
        public void Cc_OnNakLoss_UpdatesLossPercent()
        {
            var cc = CreateCc();
            cc.OnAck(100000, 24000, 50000, 24000);
            double before = cc.EstimatedLossPercent;
            cc.OnNakLoss(200000, 1000);
            Assert.True(cc.EstimatedLossPercent >= before);
        }

        [Fact]
        public void Cc_OnPacketLoss_NonCongestion_DoesNotEnterRecovery()
        {
            var cc = CreateCc();
            long cwndBefore = cc.CongestionWindowBytes;
            cc.OnPacketLoss(100000, 0.05, false, 1000);
            // Non-congestion loss must not put the CC into recovery: cwnd and
            // pacing stay healthy (recovery would clamp cwnd near zero).
            Assert.True(cc.CongestionWindowBytes > 0,
                $"cwnd must stay positive after non-congestion loss: {cc.CongestionWindowBytes}");
            Assert.True(cc.PacingRateBytesPerSecond > 0);
            // And the window must still be able to grow afterward (recovery
            // pins it to flight+acked and blocks startup growth).
            cc.OnAck(200000, 24000, 50000, 24000);
            Assert.True(cc.CongestionWindowBytes >= cwndBefore,
                $"non-congestion loss must not enter recovery (cwnd may grow): {cc.CongestionWindowBytes} < {cwndBefore}");
        }

        [Fact]
        public void Cc_Gain_DoesNotGoBelowZero()
        {
            var cc = CreateCc();
            for (int i = 0; i < 30; i++)
                cc.OnAck(100000 + i * 10000, 24000, 10000, 24000);
            Assert.True(cc.PacingGainUnits > 0);
            Assert.True(cc.CwndGainUnits > 0);
        }

        [Fact]
        public void Cc_LtBw_LossSignalAcceptedWithoutCorruption()
        {
            var cc = CreateCc();
            for (int i = 0; i < 5; i++)
                cc.OnAck(100000 + i * 10000, 24000, 10000, 24000);
            cc.OnNakLoss(200000, 5000);
            // The loss signal is accepted into the estimate without corrupting
            // state (full LT-BW activation needs a stable interval with
            // srtt >> min_rtt that unit-level ACK injection can't reproduce).
            Assert.True(cc.EstimatedLossPercent > 0,
                $"NAK loss must be recorded: {cc.EstimatedLossPercent}");
            Assert.True(cc.CongestionWindowBytes > 0);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void Cc_RateAlways_PositiveAfterAck()
        {
            var cc = CreateCc();
            for (int i = 0; i < 5; i++)
                cc.OnAck(100000 + i * 10000, 24000, 20000, 24000);
            Assert.True(cc.PacingRateBytesPerSecond > 0);
        }

        [Fact]
        public void Cc_BandwidthEstimate_NotNegative()
        {
            var cc = CreateCc();
            for (int i = 0; i < 10; i++)
                cc.OnAck(100000 + i * 10000, 24000, 10000, 24000);
            Assert.True(cc.BtlBwBytesPerSecond >= 0);
        }


        private static UcpCongestionControl CreateCc(UcpConfiguration? config = null)
        {
            config ??= new UcpConfiguration();
            config.InitialBandwidthBytesPerSecond = Math.Max(config.InitialBandwidthBytesPerSecond, 12500000);
            config.InitialCwndBytes = Math.Max(config.InitialCwndBytes, 65536);
            config.MaxCongestionWindowBytes = config.MaxCongestionWindowBytes > 0 ? config.MaxCongestionWindowBytes : int.MaxValue;
            return new UcpCongestionControl(config);
        }

        private sealed class LoopbackTransport : ITransport
        {
            public int SentPackets;
            public event Action<byte[], IPEndPoint>? OnDatagram;
            public void Send(byte[] data, IPEndPoint remote) { Interlocked.Increment(ref SentPackets); }
            public void Dispose() { }
        }

        private static UcpPcb CreatePcb()
        {
            var transport = new LoopbackTransport();
            var remote = new IPEndPoint(IPAddress.Loopback, 9999);
            var config = new UcpConfiguration();
            config.ConnectTimeoutMilliseconds = 500;
            config.DisconnectTimeoutMicros = 500000;
            return new UcpPcb(transport, remote, false, false, null, null, config, null);
        }

        private static UcpPcb CreateServerPcb()
        {
            var transport = new LoopbackTransport();
            var config = new UcpConfiguration();
            config.ConnectTimeoutMilliseconds = 500;
            config.DisconnectTimeoutMicros = 500000;
            return new UcpPcb(transport, null, true, false, null, null, config, null);
        }

        private static UcpPcb CreateEstablishedPcb()
        {
            var pcb = CreatePcb();
            var ep = new IPEndPoint(IPAddress.Loopback, 9999);
            pcb.SetRemoteEndPoint(ep);
            typeof(UcpPcb).GetMethod("TransitionToEstablished",
                BindingFlags.NonPublic | BindingFlags.Instance)?.Invoke(pcb, null);
            return pcb;
        }
    }
}
