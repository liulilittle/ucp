/** @file ucp_connection.cpp
 *  @brief High-level public UCP connection implementation — mirrors C# Ucp.UcpConnection.
 *
 *  Wraps a UcpPcb behind a thread-safe async API with a serial worker
 *  queue.  All public-facing operations (connect, send, receive, close)
 *  are enqueued onto a single worker thread that executes them in order,
 *  avoiding the need for the caller to manage thread safety internally.
 *
 *  Note:  some PCB interactions are currently placeholder/disabled while
 *  the transport binding layer is being finalized.  See comments inline.
 */

#include "ucp/ucp_connection.h"
#include "ucp/ucp_network.h"
#include "ucp/ucp_pcb.h"
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace ucp {

class UdpSocketTransport;  //< Forward declaration of the UDP transport (not yet integrated).

// ====================================================================================================
// Endpoint helper methods
// ====================================================================================================

Endpoint Endpoint::Parse(const std::string& str) {
    Endpoint ep;
    auto colon = str.rfind(':');
    if (colon != std::string::npos) {
        ep.address = str.substr(0, colon);
        ep.port = static_cast<uint16_t>(std::stoi(str.substr(colon + 1)));
    } else {
        ep.address = str;
        ep.port = 0;
    }
    return ep;
}

std::string Endpoint::ToString() const {
    return address + ":" + std::to_string(port);
}

// ====================================================================================================
// Construction / destruction
// ====================================================================================================

UcpConnection::UcpConnection()
    : UcpConnection(UcpConfiguration())
{
}

UcpConnection::UcpConnection(const UcpConfiguration& config)
    : config_(config)
{
}

UcpConnection::~UcpConnection()
{
    Dispose();
}

// ====================================================================================================
// Worker thread (serial queue)
// ====================================================================================================

void UcpConnection::StartWorker()
{
    if (worker_should_start_.exchange(true)) return;  //< Idempotent: only start once.
    stopped_ = false;
    worker_thread_ = std::thread(&UcpConnection::WorkerLoop, this);
}

void UcpConnection::StopWorker()
{
    stopped_ = true;
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void UcpConnection::WorkerLoop()
{
    while (!stopped_) {
        std::function<void()> work;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] {
                return !queue_.empty() || stopped_;
            });
            if (stopped_ && queue_.empty()) break;
            if (!queue_.empty()) {
                work = std::move(queue_.front());
                queue_.pop_front();
            }
        }
        if (work) {
            work();
        }
    }
}

void UcpConnection::Enqueue(std::function<void()> work)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(std::move(work));
    }
    cv_.notify_one();  //< Wake the worker thread.
}

void UcpConnection::EnsureWorkerStarted()
{
    if (!worker_should_start_) {
        StartWorker();
    }
}

// ====================================================================================================
// Connect
// ====================================================================================================

std::future<bool> UcpConnection::ConnectAsync(const std::string& remoteEndpoint)
{
    EnsureWorkerStarted();

    auto pending = std::make_shared<PendingConnect>();
    pending->remote = remoteEndpoint;
    pending->network = nullptr;
    auto future = pending->promise.get_future();

    Enqueue([this, pending]() {
        try {
            Endpoint ep = Endpoint::Parse(pending->remote);
            remote_endpoint_ = ep;

            if (!pcb_) {
                // Create PCB
                // pcb_ = new UcpPcb(transport, ep, false, false, config_.Clone(), network_);
                // AttachPcb(pcb_);
            }

            // pcb_->ConnectAsync(ep);
            // Wait for connection to complete
            pending->promise.set_value(true);
        } catch (const std::exception&) {
            pending->promise.set_value(false);
        }
    });

    return future;
}

std::future<bool> UcpConnection::ConnectAsync(UcpNetwork* network, const std::string& remoteEndpoint)
{
    if (!network) {
        std::promise<bool> p;
        p.set_value(false);
        return p.get_future();
    }

    EnsureWorkerStarted();

    auto pending = std::make_shared<PendingConnect>();
    pending->remote = remoteEndpoint;
    pending->network = network;
    auto future = pending->promise.get_future();

    Enqueue([this, pending]() {
        try {
            network_ = pending->network;
            // Swap transport to network's transport adapter
            // Re-create PCB with network context
            Endpoint ep = Endpoint::Parse(pending->remote);
            remote_endpoint_ = ep;

            // Connect via network
            pending->promise.set_value(true);
        } catch (const std::exception&) {
            pending->promise.set_value(false);
        }
    });

    return future;
}

// ====================================================================================================
// Send (sync + async)
// ====================================================================================================

int UcpConnection::Send(const uint8_t* buf, size_t offset, size_t count)
{
    return Send(buf, offset, count, UcpPriority::Normal);
}

int UcpConnection::Send(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority)
{
    try {
        auto f = SendAsync(buf, offset, count, priority);
        return f.get();
    } catch (const std::exception&) {
        return -1;
    }
}

std::future<int> UcpConnection::SendAsync(const uint8_t* buf, size_t offset, size_t count)
{
    return SendAsync(buf, offset, count, UcpPriority::Normal);
}

std::future<int> UcpConnection::SendAsync(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority)
{
    EnsureWorkerStarted();

    if (!pcb_) {
        std::promise<int> p;
        p.set_value(-1);
        return p.get_future();
    }

    auto promise = std::make_shared<std::promise<int>>();
    auto future = promise->get_future();

    // Copy the buffer for async safety (caller's buffer may go out of scope)
    size_t dataLen = offset + count;
    auto data = std::make_shared<std::vector<uint8_t>>(buf, buf + dataLen);

    Enqueue([this, data, offset, count, priority, promise]() {
        try {
            // int result = pcb_->SendAsync(data->data(), offset, count, priority);
            int result = static_cast<int>(count);
            promise->set_value(result);
        } catch (const std::exception&) {
            promise->set_value(-1);
        }
    });

    return future;
}

// ====================================================================================================
// Receive (sync + async)
// ====================================================================================================

int UcpConnection::Receive(uint8_t* buf, size_t offset, size_t count)
{
    try {
        auto f = ReceiveAsync(buf, offset, count);
        return f.get();
    } catch (const std::exception&) {
        return -1;
    }
}

std::future<int> UcpConnection::ReceiveAsync(uint8_t* buf, size_t offset, size_t count)
{
    EnsureWorkerStarted();

    if (!pcb_) {
        std::promise<int> p;
        p.set_value(-1);
        return p.get_future();
    }

    auto promise = std::make_shared<std::promise<int>>();
    auto future = promise->get_future();

    // buf is caller-owned, we need to be careful. Use a shared_ptr copy.
    auto bufCopy = std::make_shared<std::vector<uint8_t>>(count);
    auto dstBuf = buf;  // Will write directly to caller's buffer on worker thread

    Enqueue([this, dstBuf, offset, count, promise]() {
        try {
            // int result = pcb_->ReceiveAsync(dstBuf, offset, count);
            int result = 0;  // Placeholder
            promise->set_value(result);
        } catch (const std::exception&) {
            promise->set_value(-1);
        }
    });

    return future;
}

// ====================================================================================================
// Read / Write (exact-byte-count wrappers)
// ====================================================================================================

bool UcpConnection::Read(uint8_t* buf, size_t off, size_t count)
{
    try {
        auto f = ReadAsync(buf, off, count);
        return f.get();
    } catch (const std::exception&) {
        return false;
    }
}

std::future<bool> UcpConnection::ReadAsync(uint8_t* buf, size_t off, size_t count)
{
    EnsureWorkerStarted();

    if (!pcb_) {
        std::promise<bool> p;
        p.set_value(false);
        return p.get_future();
    }

    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();

    Enqueue([this, buf, off, count, promise]() {
        try {
            // bool result = pcb_->ReadAsync(buf, off, count);
            bool result = true;
            promise->set_value(result);
        } catch (const std::exception&) {
            promise->set_value(false);
        }
    });

    return future;
}

bool UcpConnection::Write(const uint8_t* buf, size_t off, size_t count)
{
    return Write(buf, off, count, UcpPriority::Normal);
}

bool UcpConnection::Write(const uint8_t* buf, size_t off, size_t count, UcpPriority priority)
{
    try {
        auto f = WriteAsync(buf, off, count, priority);
        return f.get();
    } catch (const std::exception&) {
        return false;
    }
}

std::future<bool> UcpConnection::WriteAsync(const uint8_t* buf, size_t off, size_t count)
{
    return WriteAsync(buf, off, count, UcpPriority::Normal);
}

std::future<bool> UcpConnection::WriteAsync(const uint8_t* buf, size_t off, size_t count, UcpPriority priority)
{
    EnsureWorkerStarted();

    if (!pcb_) {
        std::promise<bool> p;
        p.set_value(false);
        return p.get_future();
    }

    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();

    size_t totalLen = off + count;
    auto data = std::make_shared<std::vector<uint8_t>>(buf, buf + totalLen);

    Enqueue([this, data, off, count, priority, promise]() {
        try {
            // bool result = pcb_->WriteAsync(data->data(), off, count, priority);
            bool result = true;
            promise->set_value(result);
        } catch (const std::exception&) {
            promise->set_value(false);
        }
    });

    return future;
}

// ====================================================================================================
// Close / Dispose
// ====================================================================================================

void UcpConnection::Close()
{
    try {
        auto f = CloseAsync();
        f.get();
    } catch (const std::exception&) {
        CleanupTransport();
    }
}

std::future<void> UcpConnection::CloseAsync()
{
    auto promise = std::make_shared<std::promise<void>>();
    auto future = promise->get_future();

    Enqueue([this, promise]() {
        try {
            if (pcb_) {
                // pcb_->CloseAsync();
            }
            CleanupTransport();
            promise->set_value();
        } catch (const std::exception&) {
            CleanupTransport();
            promise->set_exception(std::current_exception());
        }
    });

    return future;
}

void UcpConnection::Dispose()
{
    try {
        Close();
    } catch (const std::exception&) {
        CleanupTransport();
    }
    StopWorker();
}

// ====================================================================================================
// Diagnostics and accessors
// ====================================================================================================

UcpTransferReport UcpConnection::GetReport() const
{
    UcpTransferReport report;
    if (pcb_) {
        // auto diag = pcb_->GetDiagnosticsSnapshot();
        // report.BytesSent = diag.BytesSent;
        // report.BytesReceived = diag.BytesReceived;
        // report.DataPacketsSent = diag.SentDataPackets;
        // report.RetransmittedPackets = diag.RetransmittedPackets;
        // report.AckPacketsSent = diag.SentAckPackets;
        // report.NakPacketsSent = diag.SentNakPackets;
        // report.FastRetransmissions = diag.FastRetransmissions;
        // report.TimeoutRetransmissions = diag.TimeoutRetransmissions;
        // report.LastRttMicros = diag.LastRttMicros;
        // report.RttSamplesMicros = diag.RttSamplesMicros;
        // report.CongestionWindowBytes = diag.CongestionWindowBytes;
        // report.PacingRateBytesPerSecond = diag.PacingRateBytesPerSecond;
        // report.EstimatedLossPercent = diag.EstimatedLossPercent;
        // report.RemoteWindowBytes = diag.RemoteWindowBytes;
    }
    return report;
}

std::string UcpConnection::GetRemoteEndPoint() const
{
    return remote_endpoint_.ToString();
}

uint32_t UcpConnection::GetConnectionId() const
{
    return connection_id_;
}

UcpNetwork* UcpConnection::GetNetwork() const
{
    return network_;
}

UcpConnectionState UcpConnection::GetState() const
{
    if (!pcb_) return UcpConnectionState::Init;
    return UcpConnectionState::Init; // Placeholder
}

// ====================================================================================================
// Callback registration
// ====================================================================================================

void UcpConnection::SetOnData(DataCallback cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    on_data_callbacks_.push_back(std::move(cb));
}

void UcpConnection::SetOnConnected(StateCallback cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    on_connected_callbacks_.push_back(std::move(cb));
}

void UcpConnection::SetOnDisconnected(StateCallback cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    on_disconnected_callbacks_.push_back(std::move(cb));
}

// ====================================================================================================
// Internal helpers (PCB attachment, dispatch, transport)
// ====================================================================================================

void UcpConnection::AttachPcb(UcpPcb* pcb)
{
    pcb_ = pcb;
    if (pcb_) {
        connection_id_ = pcb_->GetConnectionId();
    }
}

void UcpConnection::DispatchPacket(const uint8_t* data, size_t length, const Endpoint& remote)
{
    if (!data || !pcb_) return;

    // Decode packet and dispatch to PCB on the serial queue
    auto packet = std::make_shared<std::vector<uint8_t>>(data, data + length);
    Endpoint ep = remote;

    Enqueue([this, packet, ep]() {
        // Decode packet
        // pcb_->SetRemoteEndPoint(ep);
        // pcb_->HandleInboundAsync(*decodedPacket);
    });
}

void UcpConnection::OnTransportDatagram(const uint8_t* datagram, size_t length, const Endpoint& remote)
{
    if (!pcb_ || !datagram) return;

    // Decode and validate
    // if (!UcpPacketCodec::TryDecode(...)) return;
    // if (pcb_->ConnectionId != 0 && packet->ConnectionId != pcb_->ConnectionId) return;
    // if (!pcb_->ValidateRemoteEndPoint(remote)) return;

    DispatchPacket(datagram, length, remote);
}

void UcpConnection::CleanupTransport()
{
    // Release transport resources
}

} // namespace ucp
