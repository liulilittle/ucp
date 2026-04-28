using System;

namespace Ucp
{
    internal enum UcpPacketType : byte
    {
        Syn = 0x01,
        SynAck = 0x02,
        Ack = 0x03,
        Nak = 0x04,
        Data = 0x05,
        Fin = 0x06,
        Rst = 0x07
    }

    [Flags]
    internal enum UcpPacketFlags : byte
    {
        None = 0x00,
        NeedAck = 0x01,
        Retransmit = 0x02,
        FinAck = 0x04
    }

    internal enum UcpConnectionState
    {
        Init,
        HandshakeSynSent,
        HandshakeSynReceived,
        Established,
        ClosingFinSent,
        ClosingFinReceived,
        Closed
    }

    internal enum BbrMode
    {
        Startup,
        Drain,
        ProbeBw,
        ProbeRtt
    }
}
