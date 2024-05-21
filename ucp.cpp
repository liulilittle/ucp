#include "ucp.h"

static constexpr int32_t                                        UCP_CMD_SYN = 1;
static constexpr int32_t                                        UCP_CMD_PSH = 2;
static constexpr int32_t                                        UCP_CMD_ACK = 3;
static constexpr int32_t                                        UCP_CMD_FIN = 4;
static constexpr int32_t                                        UCP_CMD_RST = 5;
static constexpr int32_t                                        UCP_CMD_NAK = 6;
static constexpr int32_t                                        UCP_CMD_SYNACK = 7;
static constexpr int32_t                                        UCP_RTO_MAX = 60000;
static constexpr int32_t                                        UCP_STATE_CLOSED = 0;
static constexpr int32_t                                        UCP_STATE_SYN_SENT = 1;
static constexpr int32_t                                        UCP_STATE_SYN_RECVED = 2;
static constexpr int32_t                                        UCP_STATE_ESTABLISHED = 3;
static constexpr int32_t                                        UCP_STATE_CLOSE_WAIT = 4;
static constexpr int32_t                                        UCP_STATE_LAST_ACK = 5;
static constexpr int32_t                                        UCP_BUFFER_SIZE = 1500;

#define before(seq1, seq2)                                      ((int32_t)(seq1 - seq2) < 0)
#define after(seq2, seq1)                                       (before(seq1, seq2))
#define before_eq(seq1, seq2)                                   ((int32_t)(seq1 - seq2) <= 0)
#define after_eq(seq2, seq1)                                    (before_eq(seq1, seq2))

#pragma pack(push, 1)
typedef struct                                                  UcpHeader
{
    uint16_t                                                    session_id;
    uint8_t                                                     cmd;
    uint16_t                                                    wnd;
    uint32_t                                                    local_ts;
    uint32_t                                                    remote_ts;
}                                                               UcpHeader;

typedef struct UcpPshHeader : UcpHeader
{
    uint32_t                                                    seq;
    uint32_t                                                    ack;
}                                                               UcpPshHeader;

typedef struct UcpAckHeader : UcpHeader
{
    uint32_t                                                    ack;
}                                                               UcpAckHeader;
#pragma pack(pop)

namespace ucp
{
    UcpConnection::UcpConnection(const std::shared_ptr<UcpEthernet>& ethernet) noexcept
        : ethernet_(ethernet)
        , session_id_(0)
        , snd_backlog_(0)
        , snd_seq_(0)
        , snd_wnd_(0)
        , rcv_wnd_(ethernet->ReceiveBufferSize)
        , lasted_ts_(0)
        , rcv_ack_(0)
        , rcv_ack2_(0)
        , rcv_nxt_(0)
        , rcv_ann_right_edge_(0)
        , rcv_rto_(ethernet->DefaultRto)
        , rcv_srtt_(0)
        , rcv_rttval_(0)
        , rcv_frt_(0)
        , trx_seq_(0)
        , trx_last_(0)
        , state_(UCP_STATE_CLOSED)
    {
        tf_.fst = true;
        tf_.fin = false;
        tf_.ack = false;
        tf_.nak = false;
        tf_.server = false;
        tf_.delack = false;
        tf_.delack_ts = 0;
        tf_.fin_seq = 0;

        tf_.snd_last = 0;
        tf_.snd_when = 0;
        tf_.snd_retries = 0;

        rcv_event_.ac = NULL;
        rcv_event_.length = 0;
        rcv_event_.buffer = NULL;
    }

    UcpConnection::~UcpConnection() noexcept
    {
        Finalize();
    }

    bool UcpConnection::PacketSequenceOrder::operator()(const uint32_t& _Left, const uint32_t& _Right) const noexcept
    {
        return before(_Left, _Right);
    }

    void UcpConnection::Rto(int32_t rtt) noexcept
    {
        rtt = std::max<int32_t>(1, rtt);
        if (rcv_srtt_ == 0)
        {
            rcv_srtt_ = rtt;
            rcv_rttval_ = std::max<int32_t>(1, rtt / 2);
        }
        else
        {
            int32_t delta = rtt - rcv_srtt_;
            if (delta < 0)
            {
                delta = -delta;
            }

            rcv_rttval_ = std::max<int32_t>(1, (3 * rcv_rttval_ + delta) / 4);
            rcv_srtt_ = std::max<int32_t>(1, (7 * rcv_srtt_ + rtt) / 8);
        }

        int32_t rto = rcv_srtt_ + std::max<int32_t>(ethernet_->Interval, 4 * rcv_rttval_);
        rcv_rto_ = std::min<int32_t>(std::max<int32_t>(ethernet_->MinRto, rto), UCP_RTO_MAX);
    }

    int32_t UcpConnection::Rtt(uint64_t now, uint64_t local_ts) noexcept
    {
        if (before(local_ts, now))
        {
            now += 1ULL << 32;
        }

        int32_t rtt = static_cast<int32_t>(now - local_ts);
        return rtt >= 0 ? rtt : -1;
    }

    bool UcpConnection::ProcessAckRange(uint32_t min, uint32_t max, int origin) noexcept
    {
        uint32_t now = ethernet_->Now();
        bool any = false;
        bool fin = false;
        auto ack = [this, &any, &fin, now]() noexcept -> bool
            {
                if (state_ == UCP_STATE_SYN_RECVED)
                {
                    state_ = UCP_STATE_ESTABLISHED;
                    rcv_ack2_ = ++rcv_ack_;
                    rcv_duplicate_ack_ = rcv_ack2_;
                    trx_last_ = now;

                    tf_.snd_last = 0;
                    tf_.snd_when = 0;
                    tf_.snd_retries = 0;

                    fin = !ethernet_->Accept(shared_from_this());
                    return true;
                }
                else if (state_ == UCP_STATE_CLOSE_WAIT)
                {
                    ProcessAckShutdown(false, true);
                    return true;
                }
                else if (state_ == UCP_STATE_LAST_ACK)
                {
                    ProcessAckShutdown(true, true);
                    return true;
                }
                else
                {
                    return false;
                }
            };

        uint32_t next = after_eq(max, trx_seq_) ? trx_seq_ : max;
        for (uint32_t i = min; before_eq(i, next); i++)
        {
            auto tail = snd_packets_.find(i);
            auto endl = snd_packets_.end();
            if (tail == endl)
            {
                continue;
            }

            SendPacketPtr left = std::move(tail->second);
            tail = snd_packets_.erase(tail);

            any = true;
            trx_last_ = now;

            (*left)();
            if (tail == endl)
            {
                break;
            }
            else
            {
                SendPacketPtr& reft = tail->second;
                if (reft->packet_length == 0 || after(left->seq, next))
                {
                    break;
                }
            }
        }

        if (after_eq(next, snd_seq_))
        {
            any |= ack();
        }

        if (fin)
        {
            Close();
        }

        return any;
    }

    bool UcpConnection::ProcessAckAccumulation(uint32_t ack) noexcept
    {
        auto tail = snd_packets_.begin();
        auto endl = snd_packets_.end();
        if (tail != endl)
        {
            SendPacketPtr& pkg = tail->second;
            if (after(ack, pkg->seq))
            {
                return ProcessAckRange(pkg->seq, ack - 1, 4);
            }
        }
        elif(before(snd_seq_, ack))
        {
            uint32_t max = ack - 1;
            return ProcessAckRange(snd_seq_, max, 4);
        }
        else if (tail != endl)
        {
            SendPacketPtr& pkg = tail->second;
            if (after(ack, pkg->seq))
            {
                return ProcessAckRange(pkg->seq, ack, 2);
            }
        }

        return false;
    }

    bool UcpConnection::ProcessAck(uint32_t ack_no, const uint8_t* packet, uint32_t packet_length, uint8_t cmd, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts, bool nak) noexcept
    {
        typedef std::pair<uint32_t, uint32_t> U32U32KeyPair;

        uint32_t now = ethernet_->Now();
        if (!Rto(now, wnd, remote_ts, local_ts))
        {
            return false;
        }

        bool any = false;
        uint8_t* p = (uint8_t*)packet;
        uint32_t len = packet_length;

        if (len == 0 && rcv_duplicate_ack_ == ack_no)
        {
            if (rcv_frt_++ >= ethernet_->SackRenegBytes)
            {
                rcv_frt_ = 0;
                tf_.ack = true;
                tf_.nak = true;
                tf_.delack = false;
                tf_.delack_ts = 0;
            }
        }
        else
        {
            rcv_duplicate_ack_ = ack_no;
        }

        any |= ProcessAckAccumulation(ack_no);
        while (len > 0)
        {
            len--;
            if (*p++)
            {
                if (len < 8)
                {
                    break;
                }

                uint32_t* u = (uint32_t*)p;
                p += 8;
                len -= 8;

                uint32_t min = ntohl(u[0]);
                uint32_t max = ntohl(u[1]);
                any |= ProcessAckRange(min, max, 1);
            }
            else
            {
                if (len < 4)
                {
                    break;
                }

                uint32_t* u = (uint32_t*)p;
                p += 4;
                len -= 4;

                uint32_t key = htonl(*u);
                any |= ProcessAckRange(key, key, 1);
            }
        }

        Flush(nak);
        return any;
    }

    bool UcpConnection::Cmd(int32_t cmd) noexcept
    {
        std::shared_ptr<Byte> packet;
        uint32_t packet_length;

        return Cmd(cmd, snd_seq_, NULL, 0, packet, packet_length);
    }

    bool UcpConnection::Cmd(int32_t cmd, uint32_t seq, const void* buffer, uint32_t buffer_size, std::shared_ptr<Byte>& packet, uint32_t& packet_length) noexcept
    {
        bool PSH = false;
        bool ACK = false;

        packet_length = sizeof(UcpHeader);
        if (cmd == UCP_CMD_PSH)
        {
            if (NULL == buffer || buffer_size == 0)
            {
                return false;
            }

            PSH = true;
            packet_length = sizeof(UcpPshHeader) + buffer_size;
        }
        else if (cmd == UCP_CMD_ACK || cmd == UCP_CMD_NAK || cmd == UCP_CMD_SYN || cmd == UCP_CMD_RST)
        {
            ACK = true;
            packet_length = sizeof(UcpAckHeader);
        }
        else if (cmd == UCP_CMD_FIN || cmd == UCP_CMD_SYNACK)
        {
            PSH = true;
            buffer = NULL;
            buffer_size = 0;
            packet_length = sizeof(UcpPshHeader);
        }

        packet = ethernet_->MakeByteArray(packet_length);
        if (NULL == packet)
        {
            return false;
        }

        UcpHeader* h = (UcpHeader*)packet.get();
        h->cmd = cmd;
        h->local_ts = htonl(lasted_ts_);
        h->remote_ts = htonl(ethernet_->Now());
        h->wnd = htons(rcv_wnd_);
        h->session_id = htons(session_id_);

        if (PSH)
        {
            UcpPshHeader* h2 = (UcpPshHeader*)h;
            h2->ack = htonl(rcv_ack_);
            h2->seq = htonl(seq);

            Byte* payload = (Byte*)(h2 + 1);
            memcpy(payload, buffer, buffer_size);

            if (NULL == buffer || buffer_size == 0)
            {
                ethernet_->Output(packet, packet_length, remote_endpoint_);
            }
        }
        else
        {
            if (ACK)
            {
                UcpAckHeader* h2 = (UcpAckHeader*)h;
                h2->ack = htonl(cmd != UCP_CMD_SYN ? rcv_ack_ : snd_seq_);
            }

            ethernet_->Output(packet, packet_length, remote_endpoint_);
            if (cmd == UCP_CMD_RST)
            {
                ProcessAckShutdown(true, true);
            }
        }

        return true;
    }

    bool UcpConnection::Cmd(const SendPacketPtr& packet) noexcept
    {
        std::shared_ptr<Byte> buffer;
        uint32_t buffer_size;

        Cmd(UCP_CMD_PSH, packet->seq, packet->buffer.get(), packet->length, buffer, buffer_size);
        if (NULL == buffer || buffer_size == 0)
        {
            return false;
        }

        packet->buffer = buffer;
        packet->packet_length = buffer_size;
        return true;
    }

    void UcpConnection::Finalize() noexcept
    {
        ReceiveAsyncCallback ac = std::move(rcv_event_.ac);
        rcv_event_.ac = NULL;
        rcv_event_.length = 0;
        rcv_event_.buffer = NULL;

        if (NULL != ac)
        {
            ac(0);
        }

        ConnectEventHandler connect_event = std::move(connect_event_);
        connect_event_ = NULL;

        if (NULL != connect_event)
        {
            connect_event(this, false);
        }

        state_ = UCP_STATE_CLOSED;
        tf_.snd_last = 0;
        tf_.snd_when = 0;
        tf_.snd_retries = 0;

        snd_packets_.clear();
        rcv_packets_.clear();

        ethernet_->DeleteConnection(this);
    }

    void UcpConnection::ProcessAckShutdown(bool rx, bool tx) noexcept
    {
        if (rx && tx)
        {
            Finalize();
        }
        else if (tx)
        {
            uint32_t now = ethernet_->Now();
            tf_.snd_last = now;
            tf_.snd_when = now;
            tf_.snd_retries = 1;

            state_ = UCP_STATE_LAST_ACK;
        }
    }

    void UcpConnection::DeleteAllUnsendPacket() noexcept
    {
        bool f = false;
        auto tail = snd_packets_.begin();
        auto endl = snd_packets_.end();
        for (; tail != endl; )
        {
            SendPacketPtr& packet = tail->second;
            if (packet->packet_length != 0)
            {
                tail++;
            }
            else
            {
                if (!f && before(packet->seq, snd_seq_))
                {
                    f = true;
                    snd_seq_ = packet->seq;
                }

                tail = snd_packets_.erase(tail);
            }
        }
    }

    void UcpConnection::Close() noexcept
    {
        if (state_ == UCP_STATE_ESTABLISHED)
        {
            uint32_t now = ethernet_->Now();
            ++snd_seq_;

            DeleteAllUnsendPacket();
            tf_.snd_last = now;
            tf_.snd_when = now;
            tf_.snd_retries = 1;

            trx_seq_ = snd_seq_;
            state_ = UCP_STATE_CLOSE_WAIT;

            Cmd(UCP_CMD_FIN);
        }
        else if (state_ != UCP_STATE_CLOSE_WAIT && state_ != UCP_STATE_LAST_ACK && state_ != UCP_STATE_CLOSED)
        {
            Cmd(UCP_CMD_RST);
        }
    }

    bool UcpConnection::IsOpen() noexcept
    {
        return state_ != UCP_STATE_CLOSED;
    }

    bool UcpConnection::Flush(bool retransmissions) noexcept /* 1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7 */
    {
        uint32_t now = ethernet_->Now();
        int32_t rtt = -1;
        bool delack = false;

        ProcessAckReceived();
        if (tf_.delack)
        {
            uint32_t next = tf_.delack_ts + ethernet_->DelackMin;
            if (before(now, next))
            {
                delack = true;
            }
            else
            {
                int32_t delta = Rtt(now, next);
                if (delta > 0)
                {
                    lasted_ts_ -= delta;
                }

                tf_.ack = true;
                tf_.delack = false;
                tf_.delack_ts = 0;
            }
        }

        if (state_ >= UCP_STATE_ESTABLISHED)
        {
            for (auto&& kv : snd_packets_)
            {
                bool sent = false;
                SendPacketPtr& packet = kv.second;
                if (state_ == UCP_STATE_ESTABLISHED && packet->packet_length == 0)
                {
                    if (snd_wnd_ >= packet->length)
                    {
                        sent = true;
                        snd_wnd_ -= packet->length;
                    }
                    else if (snd_wnd_ > 0)
                    {
                        sent = true;
                        snd_wnd_ = 0;
                    }

                    if (sent && Cmd(packet))
                    {
                        int64_t snd_backlog_new = (int64_t)snd_backlog_ - (int64_t)packet->length;
                        snd_backlog_new = std::max<int64_t>(snd_backlog_new, 0);

                        if (before(trx_seq_, packet->seq))
                        {
                            trx_seq_ = packet->seq;
                        }

                        packet->when = now;
                        packet->last = now;
                        snd_backlog_ = static_cast<uint32_t>(snd_backlog_new);
                    }
                    else
                    {
                        if (snd_wnd_ == 0)
                        {
                            tf_.ack = true;
                        }
                    }
                }
                else if (packet->retries <= ethernet_->Retries2)
                {
                    uint32_t next = packet->when + rcv_rto_;
                    if (retransmissions)
                    {
                        sent = true;
                    }
                    else if (after_eq(now, next))
                    {
                        uint32_t when = ethernet_->Turbo ? packet->when : packet->last;
                        sent = true;
                        rtt = std::max<int32_t>(rtt, std::max<int32_t>(0, Rtt(now, when)));
                    }

                    if (sent)
                    {
                        UcpHeader* h = (UcpHeader*)packet->buffer.get();
                        h->wnd = htons(rcv_wnd_);
                        h->remote_ts = htonl(now);
                        h->local_ts = htonl(lasted_ts_);
                    }
                }
                else
                {
                    Cmd(UCP_CMD_RST);
                    return false;
                }

                if (sent)
                { 
                    packet->when = now;
                    packet->retries++;
                    ethernet_->Output(packet->buffer, packet->packet_length, remote_endpoint_);
                }
            }
        }

        if (state_ == UCP_STATE_ESTABLISHED)
        {
            uint32_t next = trx_last_ + ethernet_->RestTimeMaxLimit;
            if (after_eq(now, next))
            {
                Close();
            }
        }
        else if (state_ == UCP_STATE_CLOSE_WAIT)
        {
            if (tf_.snd_retries <= ethernet_->OrphanRetries)
            {
                uint32_t next = tf_.snd_when + rcv_rto_;
                if (after_eq(now, next))
                {
                    uint32_t when = ethernet_->Turbo ? tf_.snd_when : tf_.snd_last;
                    tf_.snd_when = now;
                    tf_.snd_retries++;
                    rtt = std::max<int32_t>(rtt, std::max<int32_t>(0, Rtt(now, when)));

                    Cmd(UCP_CMD_FIN);
                }
            }
            else
            {
                Cmd(UCP_CMD_RST);
                return false;
            }
        }
        else if (state_ == UCP_STATE_LAST_ACK)
        {
            uint32_t next = tf_.snd_when + ethernet_->FinTimeout;
            if (after_eq(now, next))
            {
                tf_.snd_when = now;
                tf_.snd_retries++;

                ProcessAckShutdown(true, true);
                return false;
            }
        }
        else if (state_ > UCP_STATE_CLOSED && state_ < UCP_STATE_ESTABLISHED)
        {
            bool synack = (state_ == UCP_STATE_SYN_RECVED);
            if (tf_.snd_retries <= (synack ? ethernet_->SynAckRetries : ethernet_->SynRetries))
            {
                uint32_t next = tf_.snd_when + rcv_rto_;
                if (after_eq(now, next))
                {
                    uint32_t when = ethernet_->Turbo ? tf_.snd_when : tf_.snd_last;
                    tf_.snd_when = now;
                    tf_.snd_retries++;
                    rtt = std::max<int32_t>(rtt, std::max<int32_t>(0, Rtt(now, when)));

                    Cmd(synack ? UCP_CMD_SYNACK : UCP_CMD_SYN);
                }
            }
            else
            {
                Cmd(UCP_CMD_RST);
                return false;
            }
        }

        if (!delack && tf_.ack)
        {
            AckNow();
            tf_.ack = false;
            tf_.nak = false;
            tf_.delack = false;
            tf_.delack_ts = 0;
        }

        auto& flush_list = ethernet_->flush_list_;
        for (;;)
        {
            auto tail = flush_list.find(shared_from_this());
            auto endl = flush_list.end();
            if (tail != endl)
            {
                flush_list.erase(tail);
            }

            break;
        }

        if (rtt >= 0)
        {
            Rto(rtt);
        }

        return true;
    }

    void UcpConnection::Received(uint16_t len) noexcept
    {
        uint32_t rcv_wnd = rcv_wnd_ + len;
        rcv_nxt_ += len;

        if (rcv_wnd > ethernet_->ReceiveBufferSize || rcv_wnd < rcv_wnd_)
        {
            rcv_wnd_ = ethernet_->ReceiveBufferSize;
        }
        else
        {
            rcv_wnd_ = rcv_wnd;
        }

        uint32_t rcv_ann_right_edge = rcv_ann_right_edge_ +
            std::min<uint32_t>(ethernet_->ReceiveBufferSize >> 2, ethernet_->Mss << 2);
        if (after_eq(rcv_nxt_, rcv_ann_right_edge))
        {
            tf_.ack = true;
            rcv_ann_right_edge_ = rcv_ann_right_edge;
        }
    }

    bool UcpConnection::AckNow() noexcept
    {
        typedef std::pair<uint32_t, uint32_t> U32U32KeyPair;

        ProcessAckReceived();
        if (state_ == UCP_STATE_CLOSED)
        {
            Cmd(UCP_CMD_RST);
            return false;
        }

        std::list<uint32_t> aszs;
        std::list<U32U32KeyPair> acks;

        auto ack_tail = acks.rbegin();
        auto ack_endl = acks.rend();
        auto ack_setp =
            [](U32U32KeyPair& kv, UcpAckHeader* h, uint32_t offset) noexcept
            {
                Byte* p = ((Byte*)(h + 1)) + offset;
                if (kv.first != kv.second)
                {
                    *p++ = 1;
                    *(uint32_t*)p = htonl(kv.first);
                    *(uint32_t*)(p + 4) = htonl(kv.second);
                }
                else
                {
                    *p++ = 0;
                    *(uint32_t*)p = htonl(kv.first);
                }
            };

        for (auto&& kv : rcv_packets_)
        {
            ReceivePacketPtr& node = kv.second;
            ack_tail = acks.rbegin();
            ack_endl = acks.rend();

            if (ack_tail == ack_endl)
            {
                acks.emplace_back(
                    std::make_pair(node->seq, node->seq));
            }
            else
            {
                U32U32KeyPair& ukv = *ack_tail;
                if ((ukv.second + 1) == node->seq)
                {
                    ukv.second = node->seq;
                }
                else
                {
                    acks.emplace_back(
                        std::make_pair(node->seq, node->seq));
                }
            }
        }

        bool f = true;
        ack_tail = acks.rbegin();
        ack_endl = acks.rend();

        if (ack_tail != ack_endl)
        {
            U32U32KeyPair& ukv = *ack_tail;
            if (tf_.fin)
            {
                uint32_t nxt = (ukv.second + 1);
                if (nxt == tf_.fin_seq)
                {
                    f = false;
                    ukv.second = tf_.fin_seq;
                }
            }
        }

        if (f && tf_.fin)
        {
            acks.emplace_back(
                std::make_pair(tf_.fin_seq, tf_.fin_seq));
        }

        uint32_t mss = ethernet_->Mss;
        for (U32U32KeyPair& ukv : acks)
        {
            uint32_t block_size =
                ukv.first == ukv.second ? 5 : 9;

            auto asz_tail = aszs.rbegin();
            auto asz_endl = aszs.rend();
            if (asz_tail == asz_endl)
            {
                aszs.emplace_back(block_size);
            }
            else
            {
                uint32_t& size = (*asz_tail);
                uint32_t temp = size + block_size;
                if (temp <= mss)
                {
                    size = temp;
                }
                else
                {
                    aszs.emplace_back(block_size);
                }
            }
        }

        uint32_t now = ethernet_->Now();
        if (aszs.empty())
        {
            std::shared_ptr<Byte> packet = make_shared_alloc<Byte>(sizeof(UcpAckHeader));
            if (NULL != packet)
            {
                UcpAckHeader* h = (UcpAckHeader*)packet.get();
                h->cmd = UCP_CMD_ACK;
                h->local_ts = htonl(lasted_ts_);
                h->remote_ts = htonl(now);
                h->wnd = htons(rcv_wnd_);
                h->session_id = htons(session_id_);
                h->ack = htonl(rcv_ack_);

                ethernet_->Output(packet, sizeof(UcpAckHeader), remote_endpoint_);
            }
        }
        else
        {
            auto asz_tail = aszs.begin();
            auto asz_endl = aszs.end();

            uint32_t offset = 0;
            std::shared_ptr<Byte> packet;

            for (U32U32KeyPair& kv : acks)
            {
            retry:
                if (asz_tail == asz_endl)
                {
                    break;
                }

                uint32_t packet_size = *asz_tail + sizeof(UcpAckHeader);
                UcpAckHeader* h = NULL;
                if (NULL != packet)
                {
                    h = (UcpAckHeader*)packet.get();
                }
                else
                {
                    packet = make_shared_alloc<Byte>(packet_size);
                    if (NULL == packet)
                    {
                        break;
                    }

                    h = (UcpAckHeader*)packet.get();
                    h->cmd = UCP_CMD_ACK;
                    h->local_ts = htonl(lasted_ts_);
                    h->remote_ts = htonl(now);
                    h->wnd = htons(rcv_wnd_);
                    h->session_id = htons(session_id_);
                    h->ack = htonl(rcv_ack_);
                }

                uint32_t next = kv.first != kv.second ? offset + 9 : offset + 5;
                if (next > mss)
                {
                    uint32_t packet_size = *asz_tail + sizeof(UcpAckHeader);
                    ethernet_->Output(packet, packet_size, remote_endpoint_);

                    asz_tail++;
                    offset = 0;
                    packet = NULL;
                    goto retry;
                }
                else
                {
                    ack_setp(kv, h, offset);
                    offset = next;
                }
            }

            if (offset > 0)
            {
                UcpAckHeader* h = (UcpAckHeader*)packet.get();
                if (tf_.nak)
                {
                    tf_.nak = false;
                    h->cmd = UCP_CMD_NAK;
                }

                uint32_t packet_size = *asz_tail + sizeof(UcpAckHeader);
                ethernet_->Output(packet, packet_size, remote_endpoint_);
            }
        }

        return true;
    }

    bool UcpConnection::Send(const void* buffer, int buffer_size, SendAsyncCallback ac) noexcept
    {
        if (NULL == buffer || buffer_size < 1)
        {
            return false;
        }

        if (NULL == ac)
        {
            return false;
        }

        if (state_ != UCP_STATE_ESTABLISHED)
        {
            return false;
        }

        if (tf_.fin)
        {
            Flush();
            return false;
        }

        uint32_t buffer_offset = 0;
        uint32_t mss = ethernet_->Mss;
        uint32_t buffer_size_raw = static_cast<uint32_t>(buffer_size);

        auto send_tail = snd_packets_.rbegin();
        auto send_endl = snd_packets_.rend();
        if (send_tail != send_endl)
        {
            SendPacketPtr& left_packet = send_tail->second;
            if (left_packet->packet_length == 0)
            {
                uint32_t available_size = mss - left_packet->length;
                if (available_size > 0)
                {
                    uint32_t fragment_size = buffer_size_raw;
                    if (buffer_size_raw > available_size)
                    {
                        fragment_size = available_size;
                        buffer_offset = available_size;
                    }

                    uint32_t packet_new_size = left_packet->length + fragment_size;
                    std::shared_ptr<Byte> packet_new = make_shared_alloc<Byte>(packet_new_size);
                    if (NULL == packet_new)
                    {
                        return false;
                    }
                    else
                    {
                        (*left_packet)();
                    }

                    memcpy(packet_new.get(), left_packet->buffer.get(), left_packet->length);
                    memcpy(packet_new.get() + left_packet->length, buffer, fragment_size);

                    left_packet->ac_length = fragment_size;
                    left_packet->ac = std::move(ac);
                    left_packet->buffer = packet_new;
                    left_packet->length = packet_new_size;

                    ac = NULL;
                    if (buffer_offset == 0)
                    {
                        buffer_size_raw = 0;
                    }
                    else
                    {
                        buffer_size_raw = buffer_size_raw - buffer_offset;
                    }
                }
            }
        }

        uint32_t snd_seq_raw = snd_seq_;
        static auto clean_err_packets =
            [](UcpConnection* my, uint32_t n) noexcept
            {
                auto& snd_packets = my->snd_packets_;
                for (;;)
                {
                    auto tail = snd_packets.find(n++);
                    auto endl = snd_packets.end();
                    if (tail == endl)
                    {
                        break;
                    }

                    snd_packets.erase(tail);
                }
            };

        bool flush = false;
        while (buffer_size_raw > 0)
        {
            SendPacketPtr send_packet = make_shared_object<SendPacket>();
            if (NULL == send_packet)
            {
                clean_err_packets(this, snd_seq_raw);
                return false;
            }

            send_packet->seq = ++snd_seq_;
            send_packet->retries = 0;
            send_packet->length = 0;
            send_packet->when = 0;
            send_packet->last = 0;
            send_packet->ac_length = 0;
            send_packet->packet_length = 0;

            if (buffer_size_raw > mss)
            {
                std::shared_ptr<Byte> buffer_new = make_shared_alloc<Byte>(mss);
                if (NULL == buffer_new)
                {
                    clean_err_packets(this, snd_seq_raw);
                    return false;
                }

                memcpy(buffer_new.get(), (Byte*)buffer + buffer_offset, mss);
                send_packet->length = mss;
                send_packet->buffer = buffer_new;

                if (NULL != ac)
                {
                    send_packet->ac = std::move(ac);
                    ac = NULL;

                    send_packet->ac_length = mss;
                }

                buffer_offset += mss;
                buffer_size_raw -= mss;
                if (!snd_packets_.emplace(send_packet->seq, send_packet).second)
                {
                    clean_err_packets(this, snd_seq_raw);
                    return false;
                }
            }
            else
            {
                send_packet->length = buffer_size_raw;
                if (buffer_offset == 0)
                {
                    std::shared_ptr<Byte> chunk = make_shared_alloc<Byte>(buffer_size);
                    if (NULL == chunk)
                    {
                        clean_err_packets(this, snd_seq_raw);
                        return false;
                    }

                    memcpy(chunk.get(), buffer, buffer_size);
                    send_packet->buffer = chunk;
                    send_packet->length = buffer_size_raw;
                    send_packet->ac = ac;
                    send_packet->ac_length = buffer_size_raw;
                }
                else
                {
                    std::shared_ptr<Byte> buffer_new = make_shared_alloc<Byte>(buffer_size_raw);
                    if (NULL == buffer_new)
                    {
                        clean_err_packets(this, snd_seq_raw);
                        return false;
                    }

                    memcpy(buffer_new.get(), (Byte*)buffer + buffer_offset, buffer_size_raw);
                    send_packet->buffer = buffer_new;
                    send_packet->length = buffer_size_raw;

                    if (NULL != ac)
                    {
                        send_packet->ac = std::move(ac);
                        ac = NULL;

                        send_packet->ac_length = buffer_size_raw;
                    }
                }

                buffer_offset += buffer_size_raw;
                buffer_size_raw = 0;
                if (!snd_packets_.emplace(send_packet->seq, send_packet).second)
                {
                    clean_err_packets(this, snd_seq_raw);
                    return false;
                }
            }
        }

        uint32_t snd_threshold = std::min<uint32_t>(ethernet_->ReceiveBufferSize >> 1, mss);
        snd_backlog_ += static_cast<uint32_t>(buffer_size);

        std::shared_ptr<boost::asio::io_context>& context = ethernet_->context_;
        if (snd_backlog_ < snd_threshold)
        {
            auto packet_tail = snd_packets_.begin();
            auto packet_endl = snd_packets_.end();
            for (; packet_tail != packet_endl; packet_tail++)
            {
                SendPacketPtr& packet = packet_tail->second;
                if (packet->ac_length != 0)
                {
                    (*packet)();
                    if (snd_backlog_ >= snd_threshold)
                    {
                        break;
                    }
                }
            }
        }
        else
        {
            flush = snd_wnd_ > 0;
        }

        if (tf_.fst)
        {
            flush = true;
            tf_.fst = false;
        }

        if (flush)
        {
            Flush();
        }
        else
        {
            auto self = shared_from_this();
            ethernet_->flush_list_.emplace(self);
        }

        return true;
    }

    uint32_t UcpConnection::SendBacklogBytesSize(bool all) noexcept
    {
        if (all)
        {
            uint32_t packet_count = snd_packets_.size();
            if (packet_count == 0)
            {
                return 0;
            }

            auto tail = snd_packets_.rbegin();
            SendPacketPtr packet = tail->second;

            if (packet_count == 1)
            {
                return packet->length;
            }

            uint32_t fragment_size = (packet_count - 1) * ethernet_->Mss;
            return fragment_size + packet->length;
        }
        else
        {
            return snd_backlog_;
        }
    }

    void UcpConnection::SendPacket::operator()() noexcept
    {
        SendPacket* my = this;
        SendAsyncCallback ac = std::move(my->ac);
        if (NULL != ac)
        {
            uint32_t length = my->ac_length;
            my->ac_length = 0;

            ac(length);
        }
    }

    bool UcpConnection::ReadNative(const void* buffer, uint32_t buffer_size, uint32_t length, const ReceiveAsyncCallback& ac) noexcept
    {
        if (NULL == ac)
        {
            return false;
        }

        return ReadSome(buffer, length,
            [this, buffer, buffer_size, length, ac](uint32_t bytes_transferred) noexcept
            {
                std::shared_ptr<boost::asio::io_context>& context = ethernet_->context_;
                if (bytes_transferred == 0)
                {
                    ac(0);
                }
                else if (length <= bytes_transferred)
                {
                    context->post(
                        [ac, buffer_size]() noexcept
                        {
                            ac(buffer_size);
                        });
                }
                else
                {
                    uint8_t* next = ((uint8_t*)buffer) + bytes_transferred;
                    uint32_t size = length - bytes_transferred;
                    context->post(
                        [this, next, buffer_size, size, ac]() noexcept
                        {
                            if (size == 0 || !ReadNative(next, buffer_size, size, ac))
                            {
                                ac(buffer_size);
                            }
                        });
                }
            });
    }

    bool UcpConnection::ReadSome(const void* buffer, uint32_t length, const ReceiveAsyncCallback& ac) noexcept
    {
        if (NULL == buffer || length == 0)
        {
            return false;
        }

        if (NULL == ac)
        {
            return false;
        }

        if (state_ < UCP_STATE_ESTABLISHED)
        {
            return false;
        }

        ProcessAckReceived();
        if (rcv_event_.length != 0)
        {
            return false;
        }

        rcv_event_.ac = ac;
        rcv_event_.length = length;
        rcv_event_.buffer = (void*)buffer;

        ProcessAckReceived();
        Flush();
        return true;
    }

    bool UcpConnection::ProcessAckReceived() noexcept
    {
        bool fin = false;
        bool any = false;
        uint32_t length = 0;

        if (rcv_event_.length != 0)
        {
            uint32_t remain = rcv_event_.length;
            for (;;)
            {
                auto tail = rcv_packets_.begin();
                auto endl = rcv_packets_.end();
                if (tail == endl)
                {
                    break;
                }

                ReceivePacketPtr pkg = tail->second;
                if (pkg->seq != rcv_ack2_)
                {
                    break;
                }

                uint32_t bytes_transferred = std::min<uint32_t>(pkg->length - pkg->offset, remain);
                if (bytes_transferred == 0)
                {
                    break;
                }
                else
                {
                    any = true;
                    memcpy(rcv_event_.buffer, pkg->packet.get() + pkg->offset, bytes_transferred);
                }

                pkg->offset += bytes_transferred;
                if (pkg->offset >= pkg->length)
                {
                    rcv_ack2_++;
                    rcv_packets_.erase(tail);
                }

                remain -= bytes_transferred;
                length += bytes_transferred;
            }
        }

        if ((length == 0) && (tf_.fin && state_ >= UCP_STATE_ESTABLISHED) && (before_eq(rcv_ack_, tf_.fin_seq)))
        {
            auto recv_tail = rcv_packets_.begin();
            auto recv_endl = rcv_packets_.end();
            if (recv_tail == recv_endl)
            {
                any = true;
                fin = true;
                rcv_ack_ = tf_.fin_seq;
            }
        }

        while (state_ == UCP_STATE_LAST_ACK && tf_.fin && after_eq(rcv_ack_, tf_.fin_seq))
        {
            auto rcv_tail = rcv_packets_.begin();
            auto rcv_endl = rcv_packets_.end();
            if (rcv_tail != rcv_endl && rcv_event_.length != 0)
            {
                break;
            }

            auto snd_tail = snd_packets_.begin();
            auto snd_endl = snd_packets_.end();
            if (snd_tail != snd_endl)
            {
                break;
            }
            else
            {
                any = true;
                fin = true;
            }

            ProcessAckShutdown(true, true);
            break;
        }

        if (any)
        {
            ReceiveAsyncCallback ac = std::move(rcv_event_.ac);
            rcv_event_.ac = NULL;
            rcv_event_.length = 0;
            rcv_event_.buffer = NULL;
            if (length > 0)
            {
                uint32_t now = ethernet_->Now();
                trx_last_ = now;

                Received(length);
            }

            if (NULL != ac)
            {
                ac(length);
            }
        }

        if (fin)
        {
            Close();
        }

        return any;
    }

    bool UcpConnection::Rto(uint32_t now, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts) noexcept
    {
        int32_t rtt = Rtt(now, local_ts);
        if (rtt >= 0)
        {
            Rto(rtt);
        }

        snd_wnd_ = wnd;
        lasted_ts_ = remote_ts;
        return true;
    }

    bool UcpConnection::ProcessPush(uint32_t seq, uint32_t ack_no, const uint8_t* payload, uint32_t payload_size, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts) noexcept
    {
        if (NULL == payload || payload_size < 1)
        {
            return false;
        }

        return ProcessCommon(seq, ack_no, wnd, remote_ts, local_ts,
            [this, payload, payload_size, seq](uint32_t now, bool* delay) noexcept
            {
                ReceivePacketPtr packet = make_shared_object<ReceivePacket>();
                if (NULL == packet)
                {
                    return false;
                }

                std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(payload_size);
                if (NULL == buffer)
                {
                    return false;
                }

                packet->seq = seq;
                packet->offset = 0;
                packet->packet = buffer;
                packet->length = payload_size;
                memcpy(buffer.get(), payload, payload_size);

                if (rcv_packets_.emplace(seq, packet).second)
                {
                    if (rcv_wnd_ < payload_size)
                    {
                        rcv_wnd_ = 0;
                    }
                    else
                    {
                        rcv_wnd_ -= payload_size;
                    }

                    if (tf_.delack)
                    {
                        tf_.delack = false;
                        tf_.delack_ts = 0;
                    }
                    else
                    {
                        *delay = rcv_wnd_ > 0;
                    }
                }
               
                return true;
            });
    }

    bool UcpConnection::ProcessHalfoff(uint32_t seq, uint32_t ack, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts) noexcept
    {
        return ProcessCommon(seq, ack, wnd, remote_ts, local_ts,
            [this, seq](uint32_t now, bool*) noexcept -> bool
            {
                for (;;)
                {
                    if (state_ < UCP_STATE_ESTABLISHED)
                    {
                        return false;
                    }

                    if (tf_.fin)
                    {
                        return true;
                    }

                    tf_.ack = true;
                    tf_.fin = true;
                    tf_.fin_seq = seq;
                    DeleteAllUnsendPacket();
                    return true;
                }
            });
    }

    bool UcpConnection::ProcessCommon(uint32_t seq, uint32_t ack_no, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts, const std::function<bool(uint32_t, bool*)>& h1) noexcept
    {
        uint32_t now = ethernet_->Now();
        if (!Rto(now, wnd, remote_ts, local_ts))
        {
            return false;
        }

        ProcessAckAccumulation(ack_no);
        ProcessAckReceived();

        bool ack = false;
        bool nak = false;
        bool delack = false;
        if ((before_eq(rcv_ack_, seq)) && (ack = h1(now, &delack)))
        {
            auto tail = rcv_packets_.begin();
            auto endl = rcv_packets_.end();
            if (rcv_ack_ == seq)
            {
                rcv_frt_ = 0;
            }

            for (; tail != endl; tail++)
            {
                ReceivePacketPtr& i = tail->second;
                if (i->seq != rcv_ack_)
                {
                    if (after(i->seq, rcv_ack_))
                    {
                        break;
                    }
                }
                else
                {
                    rcv_ack_++;
                }
            }
        }

        ProcessAckReceived();
        if (rcv_wnd_ == 0)
        {
            ack = true;
            delack = false;

            tf_.delack = false;
            tf_.delack_ts = 0;
        }

        if (ack)
        {
            tf_.ack = ack;
            tf_.nak = nak;
            if (delack && !tf_.delack)
            {
                if (rcv_wnd_ > 0)
                {
                    tf_.delack = true;
                    tf_.delack_ts = now;
                }
            }

            Flush();
        }

        return true;
    }

    UcpEthernet::UcpEthernet(const std::shared_ptr<boost::asio::io_context>& context, const boost::asio::ip::address& interface_ip, int bind_port, const std::shared_ptr<Byte>& buffer, uint32_t buffer_size) noexcept
        : context_(context)
        , socket_(*context)
        , timeout_(*context)
        , now_(0)
        , buffer_(buffer)
        , buffer_size_(buffer_size)
    {
        if (bind_port < 0 || bind_port > UINT16_MAX)
        {
            bind_port = 0;
        }

        in_ = true;
        if (NULL != buffer && buffer_size > 0)
        {
            boost::system::error_code ec;
            boost::asio::ip::udp::endpoint bind_endpoint(interface_ip, bind_port);

            if (OpenDatagramSocket(socket_, interface_ip, bind_port, bind_endpoint))
            {
                boost::asio::ip::udp::endpoint local_endpoint = socket_.local_endpoint(ec);
                boost::asio::ip::address local_ip = local_endpoint.address();
                in_ = local_ip.is_v4();
            }
            else
            {
                socket_.close(ec);
            }
        }

        now_ = GetTickCount();
    }

    UcpEthernet::UcpEthernet(const std::shared_ptr<boost::asio::io_context>& context, const boost::asio::ip::address& interface_ip, int bind_port) noexcept
        : UcpEthernet(context, interface_ip, bind_port, make_shared_alloc<Byte>(UINT16_MAX), UINT16_MAX)
    {

    }

    UcpEthernet::UcpEthernet(const std::shared_ptr<boost::asio::io_context>& context, int bind_port) noexcept
        :UcpEthernet(context, boost::asio::ip::address_v6::any(), bind_port)
    {

    }

    UcpEthernet::~UcpEthernet() noexcept
    {
        Close();
    }

    void UcpEthernet::Exit() noexcept
    {
        auto self = shared_from_this();
        context_->post(
            [self]() noexcept {
                self->Close();
            });
    }

    void UcpEthernet::Close() noexcept
    {
        ClosedEventHandler closed_event = ClosedEvent;
        AcceptEvent = NULL;
        ClosedEvent = NULL;

        ConnectionTable connections = connections_;
        connections_.clear();

        for (auto&& kv : connections)
        {
            ConnectionPtr& connection = kv.second;
            connection->Cmd(UCP_CMD_RST);
        }

        boost::system::error_code ec;
        socket_.close(ec);
        timeout_.cancel(ec);

        flush_list_.clear();
        if (NULL != closed_event)
        {
            closed_event();
        }
    }

    std::shared_ptr<Byte> UcpEthernet::MakeByteArray(std::size_t length) noexcept
    {
        return make_shared_alloc<Byte>(length);
    }

    void UcpEthernet::DeleteConnection(UcpConnection* connection) noexcept
    {
        UcpEthernet::ConnectionKey key;
        key.session_id = connection->session_id_;
        key.host = connection->remote_endpoint_.address();
        key.port = connection->remote_endpoint_.port();

        auto tail = connections_.find(key);
        auto endl = connections_.end();
        if (tail != endl)
        {
            connections_.erase(tail);
        }
    }

    UcpEthernet::ConnectionPtr UcpEthernet::FindConnection(uint16_t session_id) noexcept
    {
        if (session_id == 0)
        {
            return NULL;
        }

        ConnectionKey key;
        key.host = source_endpoint_.address();
        key.port = source_endpoint_.port();
        key.session_id = session_id;

        ConnectionTable::iterator tail = connections_.find(key);
        ConnectionTable::iterator endl = connections_.end();
        return tail != endl ? tail->second : NULL;
    }

    bool UcpEthernet::PacketInput(const void* packet, uint32_t packet_length) noexcept
    {
        if (NULL == packet || packet_length < sizeof(UcpHeader))
        {
            return false;
        }
        else
        {
            uint32_t rx_packet_loss_rate = RxPacketLossRate;
            if (rx_packet_loss_rate > 0)
            {
                uint32_t rate = (uint32_t)RandomNext(0, 100);
                if (rate < rx_packet_loss_rate)
                {
                    return false;
                }
            }
        }

        UcpHeader* h = (UcpHeader*)packet;
        uint8_t cmd = h->cmd;
        uint16_t wnd = ntohs(h->wnd);
        uint16_t session_id = ntohs(h->session_id);
        uint32_t local_ts = ntohl(h->local_ts);
        uint32_t remote_ts = ntohl(h->remote_ts);

        if (cmd == UCP_CMD_PSH)
        {
            if (packet_length < sizeof(UcpAckHeader))
            {
                Rst(session_id, remote_ts);
                return false;
            }

            ConnectionPtr connection = FindConnection(session_id);
            if (NULL == connection)
            {
                Rst(session_id, remote_ts);
                return false;
            }

            UcpPshHeader* h2 = (UcpPshHeader*)h;
            uint32_t ack = htonl(h2->ack);
            uint32_t seq = htonl(h2->seq);

            uint8_t* payload = (uint8_t*)(h2 + 1);
            uint32_t payload_size = packet_length - sizeof(*h2);
            return connection->ProcessPush(seq, ack, payload, payload_size, wnd, remote_ts, local_ts);
        }

        bool nak = false;
        if ((cmd == UCP_CMD_ACK) || (nak = (cmd == UCP_CMD_NAK)))
        {
            if (packet_length < sizeof(UcpAckHeader))
            {
                Rst(session_id, remote_ts);
                return false;
            }

            ConnectionPtr connection = FindConnection(session_id);
            if (NULL == connection)
            {
                Rst(session_id, remote_ts);
                return false;
            }

            UcpAckHeader* h2 = (UcpAckHeader*)h;
            uint32_t ack = htonl(h2->ack);

            uint8_t* acks = (uint8_t*)(h2 + 1);
            uint32_t ack_size = packet_length - sizeof(*h2);
            return connection->ProcessAck(ack, acks, ack_size, cmd, wnd, remote_ts, local_ts, nak);
        }
        else if (cmd == UCP_CMD_FIN)
        {
            ConnectionPtr connection = FindConnection(session_id);
            if (NULL == connection)
            {
                Rst(session_id, remote_ts);
                return false;
            }

            UcpPshHeader* h2 = (UcpPshHeader*)h;
            uint32_t ack = htonl(h2->ack);
            uint32_t seq = htonl(h2->seq);

            return connection->ProcessHalfoff(seq, ack, wnd, remote_ts, local_ts);
        }
        else if (cmd == UCP_CMD_SYN)
        {
            if (session_id == 0 || packet_length < sizeof(UcpAckHeader))
            {
                Rst(session_id, remote_ts);
                return false;
            }

            UcpAckHeader* h2 = (UcpAckHeader*)h;
            uint32_t ack = htonl(h2->ack);

            ConnectionPtr connection = FindConnection(session_id);
            if (NULL == connection)
            {
                connection = make_shared_object<UcpConnection>(shared_from_this());
                if (NULL == connection)
                {
                    Rst(session_id, remote_ts);
                    return false;
                }

                uint32_t now = Now();
                connection->session_id_ = session_id;
                connection->rcv_ack_ = ack + 1;
                connection->rcv_ack2_ = connection->rcv_ack_;
                connection->rcv_duplicate_ack_ = connection->rcv_ack2_;
                connection->snd_seq_ = RandomNext(1, INT32_MAX);
                connection->trx_seq_ = connection->snd_seq_;
                connection->remote_endpoint_ = source_endpoint_;

                connection->tf_.server = true;
                connection->tf_.snd_last = now;
                connection->tf_.snd_when = now;
                connection->tf_.snd_retries = 1;
                connection->state_ = UCP_STATE_SYN_RECVED;

                ConnectionKey key;
                key.session_id = session_id;
                key.host = source_endpoint_.address();
                key.port = source_endpoint_.port();

                connections_.emplace(key, connection);
            }

            connection->lasted_ts_ = remote_ts;
            connection->snd_wnd_ = wnd;
            connection->rcv_nxt_ = 0;
            connection->rcv_ann_right_edge_ = 0;

            return connection->Cmd(UCP_CMD_SYNACK);
        }
        else if (cmd == UCP_CMD_SYNACK)
        {
            if (packet_length < sizeof(UcpPshHeader))
            {
                Rst(session_id, remote_ts);
                return false;
            }

            for (;;)
            {
                ConnectionPtr connection = FindConnection(session_id);
                if (NULL != connection)
                {
                    UcpPshHeader* h2 = (UcpPshHeader*)h;
                    uint32_t ack = htonl(h2->ack);
                    uint32_t seq = htonl(h2->seq);
                    uint32_t nxt = connection->snd_seq_ + 1;
                    if (ack == nxt)
                    {
                        uint32_t now = Now();
                        if (connection->state_ == UCP_STATE_SYN_SENT || connection->state_ == UCP_STATE_ESTABLISHED)
                        {
                            if (connection->Rto(now, wnd, remote_ts, local_ts))
                            {
                                if (connection->state_ != UCP_STATE_SYN_SENT)
                                {
                                    connection->AckNow();
                                }
                                else
                                {
                                    connection->trx_last_ = now;
                                    connection->snd_seq_ = nxt;
                                    connection->trx_seq_ = connection->snd_seq_;
                                    connection->rcv_ack_ = seq + 1;
                                    connection->rcv_ack2_ = connection->rcv_ack_;
                                    connection->rcv_duplicate_ack_ = connection->rcv_ack2_;
                                    connection->state_ = UCP_STATE_ESTABLISHED;
                                    connection->AckNow();

                                    ConnectEventHandler connect_event = std::move(connection->connect_event_);
                                    connection->connect_event_ = NULL;

                                    if (NULL != connect_event)
                                    {
                                        connect_event(connection.get(), true);
                                    }
                                }

                                return true;
                            }
                        }
                    }
                    else if (before(ack, connection->snd_seq_))
                    {
                        if (connection->state_ == UCP_STATE_ESTABLISHED)
                        {
                            connection->AckNow();
                            return true;
                        }
                    }
                }

                Rst(session_id, remote_ts);
                return false;
            }
        }
        else if (cmd == UCP_CMD_RST)
        {
            ConnectionPtr connection = FindConnection(session_id);
            if (NULL == connection)
            {
                return false;
            }

            if (packet_length >= sizeof(UcpAckHeader))
            {
                UcpAckHeader* h2 = (UcpAckHeader*)h;
                uint32_t ack = htonl(h2->ack);

                uint32_t now = Now();
                if (connection->Rto(now, wnd, remote_ts, local_ts))
                {
                    connection->ProcessAckAccumulation(ack);
                    connection->ProcessAckReceived();
                }
            }

            connection->ProcessAckShutdown(true, true);
            return true;
        }
        else
        {
            Rst(session_id, remote_ts);
            return false;
        }
    }

    bool UcpEthernet::Rst(uint32_t session_id, uint32_t remote_ts) noexcept
    {
        ConnectionPtr connection = FindConnection(session_id);
        if (NULL != connection)
        {
            return connection->Cmd(UCP_CMD_RST);
        }
        else
        {
            UcpHeader h;
            h.cmd = UCP_CMD_RST;
            h.local_ts = htonl(remote_ts);
            h.remote_ts = htonl(Now());
            h.wnd = htons(0);
            h.session_id = htons(session_id);

            return Output(&h, sizeof(UcpHeader), source_endpoint_);
        }
    }

    void UcpEthernet::Update() noexcept
    {
        ConnectionTable::iterator tail = connections_.begin();
        ConnectionTable::iterator endl = connections_.end();
        now_ = GetTickCount();

        for (; tail != endl;)
        {
            ConnectionPtr connection = tail->second;
            tail++;

            connection->Flush();
            if (connection->state_ == UCP_STATE_CLOSED)
            {
                DeleteConnection(connection.get());
            }
        }
    }

    void UcpEthernet::FlushAll() noexcept
    {
        auto flush_list = std::move(flush_list_);
        flush_list_.clear();

        for (const ConnectionPtr& connection : flush_list)
        {
            connection->Flush();
        }
    }

    bool UcpEthernet::Output(const void* packet, uint32_t packet_length, const boost::asio::ip::udp::endpoint& remote_endpoint) noexcept
    {
        if (NULL == packet || packet_length < 1)
        {
            return false;
        }

        bool opened = socket_.is_open();
        if (opened)
        {
            uint32_t tx_packet_loss_rate = TxPacketLossRate;
            if (tx_packet_loss_rate > 0)
            {
                uint32_t rate = (uint32_t)RandomNext(0, 100);
                if (rate < tx_packet_loss_rate)
                {
                    return true;
                }
            }

            boost::system::error_code ec;
            socket_.send_to(boost::asio::buffer(packet, packet_length), remote_endpoint, boost::asio::socket_base::message_end_of_record, ec);

            if (ec == boost::system::errc::success)
            {
                return true;
            }
        }

        return false;
    }

    bool UcpEthernet::IsOpen() noexcept
    {
        return socket_.is_open();
    }

    bool UcpEthernet::Run() noexcept
    {
        bool opened = socket_.is_open();
        if (!opened)
        {
            return false;
        }

        if (!NextTimeout())
        {
            return false;
        }

        if (ReceiveLoopback())
        {
            return true;
        }

        Close();
        return false;
    }

    bool UcpEthernet::NextTimeout() noexcept
    {
        bool opened = socket_.is_open();
        if (!opened)
        {
            return false;
        }

        auto self = shared_from_this();
        now_ = GetTickCount();

        timeout_.expires_from_now(boost::posix_time::milliseconds(1));
        timeout_.async_wait(
            [self, this](boost::system::error_code ec) noexcept
            {
                if (ec == boost::system::errc::operation_canceled)
                {
                    return false;
                }
                else if (ec == boost::system::errc::success)
                {
                    uint32_t next = std::max<uint32_t>(Interval >> 1, IntervalMin);
                    if (after_eq(now_, next))
                    {
                        Update();
                    }

                    FlushAll();
                }

                NextTimeout();
                return true;
            });
        return true;
    }

    bool UcpEthernet::ReceiveLoopback() noexcept
    {
        bool opened = socket_.is_open();
        if (!opened)
        {
            return false;
        }

        auto self = shared_from_this();
        socket_.async_receive_from(boost::asio::buffer(buffer_.get(), buffer_size_), source_endpoint_,
            [self, this](boost::system::error_code ec, std::size_t sz) noexcept
            {
                if (ec != boost::system::errc::operation_canceled)
                {
                    if (ec == boost::system::errc::success)
                    {
                        PacketInput(buffer_.get(), sz);
                    }

                    ReceiveLoopback();
                }
            });
        return true;
    }

    bool UcpEthernet::Accept(const ConnectionPtr& connection) noexcept
    {
        AcceptEventHandler event_handler = AcceptEvent;
        if (NULL != event_handler)
        {
            return event_handler(connection);
        }

        return false;
    }

    UcpEthernet::DefaultScheduler::DefaultScheduler() noexcept
    {
        std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
        if (NULL != context)
        {
            std::thread t(
                [context]() noexcept
                {
                    SetThreadPriorityToMaxLevel();

                    boost::system::error_code ec;
                    boost::asio::io_context::work work(*context);
                    context->run(ec);
                });
            t.detach();
            context_ = context;
        }
    }

    UcpEthernet::DefaultScheduler::~DefaultScheduler() noexcept
    {
        Reset();
    }

    void UcpEthernet::DefaultScheduler::Reset() noexcept
    {
        std::shared_ptr<boost::asio::io_context> context = std::move(context_);
        context_.reset();

        if (NULL != context)
        {
            context->stop();
        }
    }

    UcpEthernet::ConnectionPtr UcpEthernet::Connect(boost::asio::ip::address host, int port, const ConnectEventHandler& ac) noexcept
    {
        static std::atomic<uint16_t> session_id = RandomNext(1, INT16_MAX);

        if (NULL == ac)
        {
            return NULL;
        }

        if (host.is_multicast() || host.is_unspecified())
        {
            return NULL;
        }

        if (port <= 0 || port > UINT16_MAX)
        {
            return NULL;
        }

        bool opened = socket_.is_open();
        if (!opened)
        {
            return NULL;
        }

        if (in_)
        {
            if (!host.is_v4())
            {
                boost::asio::ip::udp::endpoint remote_endpoint = ip_v6_to_v4(boost::asio::ip::udp::endpoint(host, port));
                boost::asio::ip::address remote_ip = remote_endpoint.address();
                if (!remote_ip.is_v4())
                {
                    return NULL;
                }
                else
                {
                    host = remote_ip;
                }
            }
        }
        else
        {
            if (!host.is_v6())
            {
                boost::asio::ip::udp::endpoint remote_endpoint = ip_v4_to_v6(boost::asio::ip::udp::endpoint(host, port));
                boost::asio::ip::address remote_ip = remote_endpoint.address();
                if (!remote_ip.is_v6())
                {
                    return NULL;
                }
                else
                {
                    host = remote_ip;
                }
            }
        }
        
        for (;;)
        {
            uint16_t id = ++session_id;
            if (id == 0)
            {
                session_id = 0;
                continue;
            }

            ConnectionKey key;
            key.session_id = id;
            key.host = host;
            key.port = port;

            auto tail = connections_.find(key);
            auto endl = connections_.end();
            if (tail != endl)
            {
                continue;
            }

            std::shared_ptr<UcpConnection> connection = make_shared_object<UcpConnection>(shared_from_this());
            if (NULL == connection)
            {
                return NULL;
            }

            uint32_t now = Now();
            connection->tf_.snd_last = now;
            connection->tf_.snd_when = now;
            connection->tf_.snd_retries = 1;

            connection->connect_event_ = ac;
            connection->lasted_ts_ = 0;
            connection->session_id_ = id;
            connection->state_ = UCP_STATE_SYN_SENT;
            connection->rcv_ack_ = 0;
            connection->rcv_ack2_ = 0;
            connection->rcv_duplicate_ack_ = 0;
            connection->snd_seq_ = RandomNext(1, INT32_MAX);
            connection->trx_seq_ = connection->snd_seq_;

            connection->rcv_ann_right_edge_ = 0;
            connection->rcv_nxt_ = 0;
            connection->rcv_wnd_ = ReceiveBufferSize;
            connection->remote_endpoint_ = boost::asio::ip::udp::endpoint(host, port);

            if (!connections_.emplace(key, connection).second)
            {
                connection->connect_event_ = NULL;
                return NULL;
            }

            connection->Cmd(UCP_CMD_SYN);
            return connection;
        }
    }

    std::shared_ptr<UcpEthernet::DefaultScheduler> UcpEthernet::GetDefaultScheduler() noexcept
    {
        static std::shared_ptr<DefaultScheduler> scheduler_ =
            make_shared_object<DefaultScheduler>();

        return scheduler_;
    }

    boost::asio::ip::udp::endpoint UcpEthernet::GetLocalEndPoint() noexcept
    {
        boost::asio::ip::udp::endpoint default_endpoint;
        if (socket_.is_open())
        {
            boost::system::error_code ec;
            boost::asio::ip::udp::endpoint r = socket_.local_endpoint(ec);
            if (!ec)
            {
                return r;
            }
        }

        return default_endpoint;
    }

    std::shared_ptr<UcpEthernet> UcpEthernet::NewWithRun(const std::shared_ptr<UcpConfiguration>& configuration, const boost::asio::ip::address& interface_ip, int bind_port) noexcept
    {
        std::shared_ptr<UcpEthernet> ethernet = New(configuration, interface_ip, bind_port);
        if (NULL == ethernet)
        {
            return NULL;
        }
        elif(ethernet->Run())
        {
            return ethernet;
        }
        else
        {
            ethernet->Close();
            return NULL;
        }
    }

    std::shared_ptr<UcpEthernet> UcpEthernet::New(const std::shared_ptr<UcpConfiguration>& configuration, const boost::asio::ip::address& interface_ip, int bind_port) noexcept
    {
        if (NULL == configuration)
        {
            return NULL;
        }

        if (!interface_ip.is_unspecified())
        {
            if (ip_is_invalid(interface_ip))
            {
                return NULL;
            }
        }

        auto& ucp = *configuration;
        if (ucp.retries2 < 1 ||
            ucp.syn_retries < 1 ||
            ucp.syn_ack_retries < 1 ||
            ucp.orphan_retries < 1 ||
            ucp.sack_reneg_bytes < 1 ||
            ucp.delack_min < 1 ||
            ucp.mss < 1 ||
            ucp.min_rto < 1 ||
            ucp.fin_timeout < 1 ||
            ucp.inactive.timeout < 1 ||
            ucp.connect.timeout < 1)
        {
            return NULL;
        }

        if (bind_port < 0 || bind_port > UINT16_MAX)
        {
            bind_port = 0;
        }

        std::shared_ptr<DefaultScheduler> scheduler = GetDefaultScheduler();
        if (NULL == scheduler)
        {
            return NULL;
        }

        std::shared_ptr<boost::asio::io_context> context = scheduler->Context();
        if (NULL == context)
        {
            return NULL;
        }

        std::shared_ptr<Byte> buffer = scheduler->Buffer();
        if (NULL == buffer)
        {
            buffer = make_shared_alloc<Byte>(UCP_BUFFER_SIZE);
            if (NULL == buffer)
            {
                return NULL;
            }
        }

        std::shared_ptr<UcpEthernet> ethernet = make_shared_object<UcpEthernet>(context, interface_ip, bind_port, buffer, UCP_BUFFER_SIZE);
        if (NULL == ethernet)
        {
            return NULL;
        }

        ethernet->RestTimeMaxLimit = ucp.inactive.timeout * 1000;
        ethernet->Turbo = ucp.turbo;
        ethernet->Retries2 = ucp.retries2;
        ethernet->SynRetries = ucp.syn_retries;
        ethernet->SynAckRetries = ucp.syn_ack_retries;
        ethernet->OrphanRetries = ucp.orphan_retries;
        ethernet->SackRenegBytes = ucp.sack_reneg_bytes;
        ethernet->DelackMin = ucp.delack_min;
        ethernet->Mss = ucp.mss;
        ethernet->MinRto = ucp.min_rto;
        ethernet->FinTimeout = ucp.fin_timeout * 1000;
        ethernet->Interval = ucp.min_rto;
        ethernet->IntervalMin = std::max<int32_t>(1, ucp.min_rto >> 1);
        return ethernet;
    }
}