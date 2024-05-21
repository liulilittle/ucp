#pragma once

#include "stdafx.h"

namespace ucp
{
    class UcpConnection;

    struct UcpConfiguration
    {
        bool                                                        turbo;
        int                                                         retries2;
        int                                                         syn_retries;
        int                                                         syn_ack_retries;
        int                                                         orphan_retries;
        int                                                         sack_reneg_bytes;
        int                                                         delack_min;
        int                                                         mss;
        int                                                         min_rto;
        int                                                         fin_timeout;
        struct
        {
            int                                                     timeout;
        }                                                           inactive;
        struct
        {
            int                                                     timeout;
        }                                                           connect;
    };

    class UcpEthernet : public std::enable_shared_from_this<UcpEthernet>
    {
        friend class                                                UcpConnection;

    public:
        class ConnectionKey
        {
        public:
            boost::asio::ip::address                                host;
            int                                                     port;
            uint16_t                                                session_id;

        public:
            std::size_t                                             operator()(const ConnectionKey& k) const
            {
                return std::hash<boost::asio::ip::address>{}(host) ^ (port << 16 | session_id);
            }

        public:
            bool                                                    operator()(const ConnectionKey& lhs, const ConnectionKey& rhs) const
            {
                return lhs.port == rhs.port && lhs.session_id == rhs.session_id && lhs.host == rhs.host;
            }
        };

        typedef std::shared_ptr<UcpConnection>                      ConnectionPtr;
        typedef std::unordered_map<ConnectionKey,
            ConnectionPtr, ConnectionKey, ConnectionKey>            ConnectionTable;
        typedef std::function<bool(const ConnectionPtr&)>           AcceptEventHandler;
        typedef std::function<void()>                               ClosedEventHandler;
        typedef std::function<void(UcpConnection*, bool)>           ConnectEventHandler;

    public:
        AcceptEventHandler                                          AcceptEvent;
        ClosedEventHandler                                          ClosedEvent;

    public:
        bool                                                        Turbo = false;
        uint32_t                                                    Retries2 = 15;
        uint32_t                                                    SynRetries = 3;
        uint32_t                                                    SynAckRetries = 3;
        uint32_t                                                    OrphanRetries = 5;
        uint32_t                                                    SackRenegBytes = 3;
        uint32_t                                                    Mss = 1400;
        uint32_t                                                    MinRto = 100;
        uint32_t                                                    MaxRto = 60000;
        uint32_t                                                    DefaultRto = 1000;
        uint32_t                                                    FinTimeout = 10000;
        uint32_t                                                    Interval = MinRto;
        uint32_t                                                    IntervalMin = 40;
        uint32_t                                                    DelackMin = IntervalMin >> 1;
        uint16_t                                                    ReceiveBufferSize = UINT16_MAX;
        uint32_t                                                    RxPacketLossRate = 0;
        uint32_t                                                    TxPacketLossRate = 20;
        uint32_t                                                    RestTimeMaxLimit = 300000;

    public:
        UcpEthernet(const std::shared_ptr<boost::asio::io_context>& context, int bind_port) noexcept;
        UcpEthernet(const std::shared_ptr<boost::asio::io_context>& context, const boost::asio::ip::address& interface_ip, int bind_port) noexcept;
        UcpEthernet(const std::shared_ptr<boost::asio::io_context>& context, const boost::asio::ip::address& interface_ip, int bind_port, const std::shared_ptr<Byte>& buffer, uint32_t buffer_size) noexcept;
        virtual ~UcpEthernet() noexcept;

    public:
        std::shared_ptr<boost::asio::io_context>                    GetContext() noexcept { return context_; }
        uint32_t                                                    Now() const noexcept { return now_; }
        virtual bool                                                Run() noexcept;
        void                                                        Close() noexcept;
        void                                                        Exit() noexcept;
        ConnectionPtr                                               Connect(boost::asio::ip::address host, int port, const ConnectEventHandler& ac) noexcept;
        bool                                                        IsOpen() noexcept;
        boost::asio::ip::udp::endpoint                              GetLocalEndPoint() noexcept;

    public:
        class DefaultScheduler final
        {
        public:
            DefaultScheduler() noexcept;
            ~DefaultScheduler() noexcept;

        public:
            std::shared_ptr<boost::asio::io_context>&               Context() noexcept { return context_; }
            void                                                    Reset() noexcept;
            std::shared_ptr<Byte>&                                  Buffer() noexcept { return buffer_; }

        private:
            std::shared_ptr<Byte>                                   buffer_;
            std::shared_ptr<boost::asio::io_context>                context_;
        };
        static std::shared_ptr<DefaultScheduler>                    GetDefaultScheduler() noexcept;
        static std::shared_ptr<UcpEthernet>                         New(const std::shared_ptr<UcpConfiguration>& configuration, const boost::asio::ip::address& interface_ip, int bind_port) noexcept;
        static std::shared_ptr<UcpEthernet>                         NewWithRun(const std::shared_ptr<UcpConfiguration>& configuration, const boost::asio::ip::address& interface_ip, int bind_port) noexcept;

    protected:
        virtual bool                                                Accept(const ConnectionPtr& connection) noexcept;

    private:
        std::shared_ptr<Byte>                                       MakeByteArray(std::size_t length) noexcept;
        void                                                        FlushAll() noexcept;
        void                                                        Update() noexcept;
        bool                                                        Rst(uint32_t session_id, uint32_t remote_ts) noexcept;
        bool                                                        PacketInput(const void* packet, uint32_t packet_length) noexcept;
        bool                                                        NextTimeout() noexcept;
        bool                                                        ReceiveLoopback() noexcept;
        ConnectionPtr                                               FindConnection(uint16_t session_id) noexcept;
        void                                                        DeleteConnection(UcpConnection* connection) noexcept;

    private:
        bool                                                        Output(const void* packet, uint32_t packet_length, const boost::asio::ip::udp::endpoint& remote_endpoint) noexcept;
        bool                                                        Output(const std::shared_ptr<Byte>& packet, uint32_t packet_length, const boost::asio::ip::udp::endpoint& remote_endpoint) noexcept { return Output(packet.get(), packet_length, remote_endpoint); }

    private:
        std::shared_ptr<boost::asio::io_context>                    context_;
        boost::asio::ip::udp::socket                                socket_;
        boost::asio::deadline_timer                                 timeout_;
        bool                                                        in_;
        uint32_t                                                    now_;
        ConnectionTable                                             connections_;
        std::unordered_set<ConnectionPtr>                           flush_list_;
        std::shared_ptr<Byte>                                       buffer_;
        uint32_t                                                    buffer_size_;
        boost::asio::ip::udp::endpoint                              source_endpoint_;
    };

    class UcpConnection final : public std::enable_shared_from_this<UcpConnection>
    {
        friend class                                                UcpEthernet;
        typedef UcpEthernet::ConnectEventHandler                    ConnectEventHandler;

    public:
        typedef std::function<void(uint32_t)>                       SendAsyncCallback;
        typedef std::function<void(uint32_t)>                       ReceiveAsyncCallback;

    private:
        struct SendPacket
        {
        public:
            uint32_t                                                seq;
            uint32_t                                                retries;
            uint32_t                                                length;
            std::shared_ptr<Byte>                                   buffer;
            SendAsyncCallback                                       ac;
            uint32_t                                                ac_length;
            uint32_t                                                when;
            uint32_t                                                last;
            uint32_t                                                packet_length;

        public:
            void                                                    operator()() noexcept;
        };

        struct ReceivePacket
        {
            uint32_t                                                seq;
            uint32_t                                                offset;
            std::shared_ptr<Byte>                                   packet;
            uint32_t                                                length;
        };

        struct PacketSequenceOrder                                  /* _NODISCARD */
        {
            bool                                                    operator()(const uint32_t& _Left, const uint32_t& _Right) const noexcept /* strengthened */;
        };

        typedef std::shared_ptr<SendPacket>                         SendPacketPtr;
        typedef std::shared_ptr<ReceivePacket>                      ReceivePacketPtr;

        template <typename TKey, typename TValue>
        using map                                                   = std::map<TKey, TValue, PacketSequenceOrder, std::allocator<std::pair<const TKey, TValue>>>;

    public:
        UcpConnection(const std::shared_ptr<UcpEthernet>& ethernet) noexcept;
        ~UcpConnection() noexcept;

    private:
        void                                                        ProcessAckShutdown(bool rx, bool tx) noexcept;
        bool                                                        ProcessAckAccumulation(uint32_t ack) noexcept;
        bool                                                        ProcessAck(uint32_t ack_no, const uint8_t* packet, uint32_t packet_length, uint8_t cmd, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts, bool nak) noexcept;
        bool                                                        ProcessHalfoff(uint32_t seq, uint32_t ack, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts) noexcept;
        bool                                                        ProcessPush(uint32_t seq, uint32_t ack_no, const uint8_t* payload, uint32_t payload_size, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts) noexcept;

    private:
        bool                                                        ProcessAckRange(uint32_t min, uint32_t max, int origin) noexcept;
        bool                                                        ProcessCommon(uint32_t seq, uint32_t ack, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts, const std::function<bool(uint32_t, bool*)>& h1) noexcept;
        bool                                                        AckNow() noexcept;
        bool                                                        Flush(bool retransmissions) noexcept;

    private:
        bool                                                        Rto(uint32_t now, uint32_t wnd, uint32_t remote_ts, uint32_t local_ts) noexcept;
        void                                                        Rto(int32_t rtt) noexcept;
        int32_t                                                     Rtt(uint64_t now, uint64_t local_ts) noexcept;
        bool                                                        Cmd(int32_t cmd) noexcept;
        bool                                                        Cmd(const SendPacketPtr& packet) noexcept;
        bool                                                        Cmd(int32_t cmd, uint32_t seq, const void* buffer, uint32_t buffer_size, std::shared_ptr<Byte>& packet, uint32_t& packet_length) noexcept;
        bool                                                        ReadNative(const void* buffer, uint32_t buffer_size, uint32_t length, const ReceiveAsyncCallback& ac) noexcept;

    private:
        void                                                        Finalize() noexcept;
        void                                                        Received(uint16_t len) noexcept;
        bool                                                        ProcessAckReceived() noexcept;

    public:
        bool                                                        ReadSome(const void* buffer, uint32_t length, const ReceiveAsyncCallback& ac) noexcept;
        bool                                                        Read(const void* buffer, uint32_t length, const ReceiveAsyncCallback& ac) noexcept { return ReadNative(buffer, length, length, ac); }
        void                                                        Close() noexcept;
        bool                                                        IsOpen() noexcept;
        void                                                        DeleteAllUnsendPacket() noexcept;
        void                                                        Flush() noexcept { Flush(false); }
        bool                                                        Send(const void* buffer, int buffer_size, SendAsyncCallback ac) noexcept;
        uint32_t                                                    State() const noexcept { return state_; }
        bool                                                        IsSMode() const noexcept { return tf_.server; }
        uint32_t                                                    SendBacklogBytesSize() noexcept { return SendBacklogBytesSize(false); }
        uint32_t                                                    SendBacklogBytesSize(bool all) noexcept;
        std::shared_ptr<boost::asio::io_context>&                   GetContext() noexcept { return ethernet_->context_; }
        boost::asio::ip::udp::endpoint&                             GetRemoteEndPoint() noexcept { return remote_endpoint_; }

    private:
        std::shared_ptr<UcpEthernet>                                ethernet_;
        uint16_t                                                    session_id_;
        map<uint32_t, ReceivePacketPtr>                             rcv_packets_;
        map<uint32_t, SendPacketPtr>                                snd_packets_;
        uint32_t                                                    snd_backlog_;
        uint32_t                                                    snd_seq_;
        uint32_t                                                    snd_wnd_;
        uint32_t                                                    rcv_wnd_;
        uint32_t                                                    lasted_ts_;
        uint32_t                                                    rcv_ack_;
        uint32_t                                                    rcv_ack2_;
        uint32_t                                                    rcv_nxt_;
        uint32_t                                                    rcv_rto_;
        uint32_t                                                    rcv_srtt_;
        uint32_t                                                    rcv_rttval_;
        uint32_t                                                    rcv_frt_;
        uint32_t                                                    rcv_ann_right_edge_;
        uint32_t                                                    rcv_duplicate_ack_;
        uint32_t                                                    trx_seq_;
        uint32_t                                                    trx_last_;
        struct
        {
            uint32_t                                                delack_ts;
            uint32_t                                                snd_last;
            uint32_t                                                snd_when;
            uint32_t                                                snd_retries;
            uint32_t                                                fin_seq;
            struct
            {
                bool                                                ack : 1;
                bool                                                nak : 1;
                bool                                                fin : 1;
                bool                                                fst : 1;
                bool                                                server : 1;
                bool                                                delack : 3;
            };
        }                                                           tf_;
        int32_t                                                     state_;
        struct
        {
            void* buffer;
            uint32_t                                                length;
            ReceiveAsyncCallback                                    ac;
        }                                                           rcv_event_;
        ConnectEventHandler                                         connect_event_;
        boost::asio::ip::udp::endpoint                              remote_endpoint_;
    };
}