#include "ucp.h"

using namespace ucp;

static void receive_loop(UcpEthernet::ConnectionPtr connection, char* buff, int* count, int* i, uint64_t start) noexcept
{
    connection->Read(buff, 10000,
        [connection, buff, count, i, start](uint32_t bytes_transferred) noexcept
        {
            buff[bytes_transferred] = '\x0';
            printf("%s-recv: i=%d, tick=%llu, bytes_transferred: %u\n", connection->IsSMode() ? "server" : "client" , ++(*i), ucp::GetTickCount() - start, bytes_transferred);

            if (bytes_transferred > 0)
            {
                receive_loop(connection, buff, count, i, start);
                if ((*count)++ >= 1000)
                {
                    connection->Close();
                }
            }
            else
            {
                printf("recv: 0字节，中断链接\n");
            }
        });
}

static void sent_loop(UcpEthernet::ConnectionPtr connection, const char* buffer, int buffer_size) noexcept
{
    connection->Send(buffer, buffer_size,
        [connection, buffer, buffer_size](uint32_t bytes_transferred) noexcept
        {
            if (bytes_transferred != 0)
            {
                sent_loop(connection, buffer, buffer_size);
            }
        });
    connection->Flush();
}

int main(int argc, const char* argv[])
{
    std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
    boost::asio::io_context::work work(*context);

    std::shared_ptr<UcpEthernet> server = make_shared_object<UcpEthernet>(context, 55555);
    server->Run();
    server->AcceptEvent =
        [](const UcpEthernet::ConnectionPtr& connection) noexcept
        {
            static char buff[65536];
            static int count = 0;
            static int i = 0;

            receive_loop(connection, buff, &count, &i, ucp::GetTickCount());
            sent_loop(connection->shared_from_this(), buff, sizeof(buff));
            return true;
        };

    std::shared_ptr<UcpEthernet> client = make_shared_object<UcpEthernet>(context, 0);
    client->Run();
    client->Connect(boost::asio::ip::address_v6::loopback(), 55555,
        [](UcpConnection* connection, bool connected) noexcept
        {
            printf("connected is %d\n", connected);
            if (connected)
            {
                static char buff[65536];
                static int count = 0;
                static int i = 0;

                receive_loop(connection->shared_from_this(), buff, &count, &i, ucp::GetTickCount());
                sent_loop(connection->shared_from_this(), buff, sizeof(buff));
            }
        });

    context->run();
    return 0;
}