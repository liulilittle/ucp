#pragma once

/** @file ucp_connection.h
 *  @brief High-level UCP connection (public API) -- mirrors C# Ucp.UcpConnection.
 *
 *  UcpConnection wraps the internal UcpPcb protocol engine behind a
 *  callback-based async API (Proactor pattern).  The connection runs a dedicated
 *  worker thread that dequeues work items from a serial queue with
 *  priority support (NAK packets jump the queue).  This guarantees
 *  sequential PCB access without locking in the caller.
 *
 *  All public async methods (ConnectAsync, SendAsync, ReceiveAsync,
 *  WriteAsync, CloseAsync) use callback pattern instead of std::future
 *  to avoid blocking and enable true asynchronous I/O in single-threaded
 *  or thread-pool based applications.
 *
 *  Implements IUcpObject so that connections created through a UcpNetwork
 *  are visible to the network's routing and timer infrastructure.
 *
 *  Callback registration (OnData, OnConnected, OnDisconnected) is forwarded
 *  to the underlying PCB when it exists.
 *
 *  MIT License -- Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 */

#include "ucp_types.h"
#include "ucp_configuration.h"
#include "ucp_enums.h"
#include "ucp/transport/itransport.h"
#include "ucp/ucp_network.h"
#include <cstdint>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>

namespace ucp {

class UcpPcb;
class UcpPacket;
/** @brief Public-facing UCP connection with callback-based async API and internal serial worker thread.
 *
 *  Each UcpConnection creates a dedicated worker thread that processes a
 *  serial queue of work items.  Priority items (NAK dispatch) are inserted
 *  at the front of the queue.  All async methods use callback pattern
 *  (ConnectAsyncCallback, SendAsyncCallback, etc.) for non-blocking operation. */
class UcpConnection : public IUcpObject {
  public:
    using DataCallback = ucp::function<void(const uint8_t* data, size_t offset, size_t length)>;

    using StateCallback = ucp::function<void()>;

    UcpConnection() noexcept;

    /** @brief Construct with specific config, standalone transport created internally.
     *  @param config  UcpConfiguration to clone. */
    explicit UcpConnection(const UcpConfiguration& config) noexcept;

    /** @brief Construct wrapping an existing transport, default config, owns transport.
     *  @param transport  Existing transport instance. */
    explicit UcpConnection(transport::ITransport* transport) noexcept;

    /** @brief Construct wrapping transport with ownership flag.
     *  @param transport     Existing transport instance.
     *  @param ownsTransport  True to take ownership of the transport. */
    UcpConnection(transport::ITransport* transport, bool ownsTransport) noexcept;

    /** @brief Construct for multiplexed network use (internal).
     *  @param transport     Transport instance.
     *  @param ownsTransport  Ownership flag.
     *  @param config         Connection configuration.
     *  @param network        Owning UcpNetwork. */
    UcpConnection(transport::ITransport* transport, bool ownsTransport, const UcpConfiguration& config, UcpNetwork* network) noexcept;

    /** @brief Internal constructor with explicit server-managed flag.
     *  @param transport       Transport instance.
     *  @param ownsTransport    Ownership flag.
     *  @param serverManaged    True if server dispatches packets.
     *  @param config           Connection configuration.
     *  @param network          Owning UcpNetwork (NULLPTR for standalone). */
    UcpConnection(transport::ITransport* transport, bool ownsTransport, bool serverManaged, const UcpConfiguration& config,
                  UcpNetwork* network = NULLPTR) noexcept;

    /** @brief Server-side accept constructor: wraps an existing PCB (internal).
     *  @param pcb        Pre-existing protocol control block.
     *  @param transport  Transport instance.
     *  @param config     Connection configuration. */
    UcpConnection(UcpPcb* pcb, transport::ITransport* transport, const UcpConfiguration& config) noexcept;

    /** @brief Server-side accept constructor with owning network context.
     *  @param pcb        Pre-existing protocol control block.
     *  @param transport  Transport instance.
     *  @param config     Connection configuration.
     *  @param network    Owning network, or NULLPTR for standalone. */
    UcpConnection(UcpPcb* pcb, transport::ITransport* transport, const UcpConfiguration& config, UcpNetwork* network) noexcept;

    ~UcpConnection() noexcept;

    UcpConnection(const UcpConnection&) = delete;
    UcpConnection& operator=(const UcpConnection&) = delete;
    UcpConnection(UcpConnection&&) = delete;
    UcpConnection& operator=(UcpConnection&&) = delete;

    /** @brief Connect to a remote endpoint (standalone transport) - non-blocking callback.
     *  @param remoteEndpoint  "address:port" string of the remote peer.
     *  @param callback        Callback invoked when handshake completes (error=None on success). */
    void ConnectAsync(const ucp::string& remoteEndpoint, ConnectAsyncCallback callback) noexcept;

    /** @brief Connect via a specific UcpNetwork (multiplexed transport) - non-blocking callback.
     *  @param network         The UcpNetwork to route through.
     *  @param remoteEndpoint  "address:port" string of the remote peer.
     *  @param callback        Callback invoked when handshake completes. */
    void ConnectAsync(UcpNetwork* network, const ucp::string& remoteEndpoint, ConnectAsyncCallback callback) noexcept;

    /** @brief Synchronous send (default Normal priority) - may block caller thread.
     *  @param  buf    Source buffer.
     *  @param  offset Byte offset in buffer.
     *  @param  count  Number of bytes to send.
     *  @return Bytes accepted or -1 on error. */
    int Send(const uint8_t* buf, size_t offset, size_t count) noexcept;

    /** @brief Synchronous send with explicit priority - may block caller thread.
     *  @param  buf      Source buffer.
     *  @param  offset   Byte offset in buffer.
     *  @param  count    Number of bytes to send.
     *  @param  priority QoS priority.
     *  @return Bytes accepted or -1 on error. */
    int Send(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority) noexcept;

    /** @brief Asynchronous send - non-blocking callback.
     *  @param  buf      Source buffer.
     *  @param  offset   Byte offset in buffer.
     *  @param  count    Number of bytes to send.
     *  @param  callback Callback invoked when send operation completes. */
    void SendAsync(const uint8_t* buf, size_t offset, size_t count, SendAsyncCallback callback) noexcept;

    /** @brief Asynchronous send with explicit priority - non-blocking callback.
     *  @param  buf      Source buffer.
     *  @param  offset   Byte offset in buffer.
     *  @param  count    Number of bytes to send.
     *  @param  priority QoS priority.
     *  @param  callback Callback invoked when send operation completes. */
    void SendAsync(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority, SendAsyncCallback callback) noexcept;

    /** @brief Sync receive - may block caller thread.
     *  @param  buf    Destination buffer.
     *  @param  offset Write offset in destination.
     *  @param  count  Maximum bytes to receive.
     *  @return Bytes copied, 0 if closed, -1 on error. */
    int Receive(uint8_t* buf, size_t offset, size_t count) noexcept;

    /** @brief Asynchronous receive - non-blocking callback.
     *  @param  buf      Destination buffer.
     *  @param  offset   Write offset in destination.
     *  @param  count    Maximum bytes to receive.
     *  @param  callback Callback invoked when receive operation completes (0 bytes = closed).
     *  @note The caller MUST keep `buf` valid until the callback fires.  When no
     *        data is pending, the raw pointer is stored and written later by the
     *        receive completer; a stack buffer that goes out of scope first is
     *        use-after-free.  Use a heap/owned buffer when the callback may be
     *        deferred. */
    void ReceiveAsync(uint8_t* buf, size_t offset, size_t count, ReceiveAsyncCallback callback) noexcept;

    /** @brief Sync exact-byte read - may block caller thread.
     *  @param  buf   Destination buffer.
     *  @param  off   Write offset in destination.
     *  @param  count Number of bytes to read.
     *  @return True if count bytes were received, false on error or close. */
    bool Read(uint8_t* buf, size_t off, size_t count) noexcept;

    /** @brief Async exact-byte read - non-blocking callback. Loops ReceiveAsync until count bytes accumulated.
     *  @param  buf      Destination buffer.
     *  @param  off      Write offset in destination.
     *  @param  count    Number of bytes to read.
     *  @param  callback Callback invoked when read completes (success=false if closed before full read). */
    void ReadAsync(uint8_t* buf, size_t off, size_t count, ReadAsyncCallback callback) noexcept;

    /** @brief Sync exact-byte write (default Normal priority) - may block caller thread.
     *  @param  buf   Source buffer.
     *  @param  off   Byte offset in buffer.
     *  @param  count Number of bytes to write.
     *  @return True if all bytes were accepted for sending. */
    bool Write(const uint8_t* buf, size_t off, size_t count) noexcept;

    /** @brief Sync exact-byte write with explicit priority - may block caller thread.
     *  @param  buf      Source buffer.
     *  @param  off      Byte offset in buffer.
     *  @param  count    Number of bytes to write.
     *  @param  priority QoS priority.
     *  @return True if all bytes were accepted for sending. */
    bool Write(const uint8_t* buf, size_t off, size_t count, UcpPriority priority) noexcept;

    /** @brief Async exact-byte write - non-blocking callback. Loops SendAsync until all bytes sent.
     *  @param  buf      Source buffer.
     *  @param  off      Byte offset in buffer.
     *  @param  count    Number of bytes to write.
     *  @param  callback Callback invoked when write completes (success=true if all bytes sent). */
    void WriteAsync(const uint8_t* buf, size_t off, size_t count, WriteAsyncCallback callback) noexcept;

    /** @brief Async exact-byte write with explicit priority - non-blocking callback.
     *  @param  buf      Source buffer.
     *  @param  off      Byte offset in buffer.
     *  @param  count    Number of bytes to write.
     *  @param  priority QoS priority.
     *  @param  callback Callback invoked when write completes. */
    void WriteAsync(const uint8_t* buf, size_t off, size_t count, UcpPriority priority, WriteAsyncCallback callback) noexcept;

    void Close() noexcept;

    /** @brief Async close - non-blocking callback. Drains send buffer, sends FIN, awaits FIN-ACK, cleans transport.
     *  @param callback Callback invoked when connection is fully closed. */
    void CloseAsync(CloseAsyncCallback callback) noexcept;

    void Dispose() noexcept;

    /** @brief Build a UcpTransferReport from the PCB's diagnostics snapshot.
     *  @return Transfer statistics snapshot. */
    UcpTransferReport GetReport() const noexcept;

    /** @brief Get the remote endpoint as "address:port".
     *  @return Remote endpoint string. */
    ucp::string GetRemoteEndpoint() const noexcept;

    /** @brief Explicitly migrate the connection to a new remote endpoint.
     *
     *  Triggers path-change logic in the PCB and resets UCP congestion control state.
     *  If the connection is in Established state, also triggers CID rotation.
     *  @param newEndpoint  The new remote endpoint (address + port). */
    void MigrateRemote(const Endpoint& newEndpoint) noexcept;

    /** @brief Return the connection ID.
     *  @return Assigned connection ID. */
    uint32_t GetConnectionId() const noexcept override;

    /** @brief Return the owning UcpNetwork.
     *  @return Network pointer, NULLPTR for standalone. */
    UcpNetwork* GetNetwork() const noexcept override;

    /** @brief Get current connection state.
     *  @return UcpConnectionState enum value. */
    UcpConnectionState GetState() const noexcept;

    /** @brief Get current pacing rate in bytes/second.
     *  @return UCP pacing rate. */
    double GetCurrentPacingRateBytesPerSecond() const noexcept;

    /** @brief Check if send buffer has pending data.
     *  @return True if there is unsent data. */
    bool HasPendingSendData() const noexcept;

    /** @brief Register a callback for received application data.
     *  @param cb  Callback invoked with data pointer, offset, and length. */
    void SetOnData(DataCallback cb) noexcept;

    /** @brief Register a callback for connection established.
     *  @param cb  Callback invoked when the handshake completes. */
    void SetOnConnected(StateCallback cb) noexcept;

    /** @brief Register a callback for connection lost/closed.
     *  @param cb  Callback invoked when the connection is torn down. */
    void SetOnDisconnected(StateCallback cb) noexcept;

    /** @brief Dispatch a received datagram to the PCB through the serial queue.
     *  @param datagram  Received byte buffer.
     *  @param remote    Source endpoint. */
    void DispatchPacket(const ucp::vector<uint8_t>& datagram, const Endpoint& remote) noexcept;

    /** @brief Dispatch an already-decoded packet to the PCB through the serial queue.
     *  Avoids a second decode when the caller (UcpServer) has already decoded.
     *  @param decoded  The decoded packet (must be non-null).
     *  @param remote   Source endpoint. */
    void DispatchPacket(const ucp::shared_ptr<UcpPacket>& decoded, const Endpoint& remote) noexcept;

    /** @brief Handle an inbound datagram from the transport: decode, validate, dispatch.
     *  @param datagram  Received byte buffer.
     *  @param remote    Source endpoint. */
    void OnTransportDatagram(const ucp::vector<uint8_t>& datagram, const Endpoint& remote) noexcept;

    /** @brief Add fair-queue credit to the PCB through the serial queue.
     *  @param bytes  Credit amount in bytes. */
    void AddFairQueueCredit(double bytes) noexcept;

    /** @brief Set uncapped fair-queue credit (bypasses cap, used for single connection).
     *  @note Prevents credit starvation when only one connection is active. */
    void SetUncappedFairQueueCredit() noexcept;

    void RequestFlush() noexcept;

    /** @brief Get measured throughput in bytes/sec from the PCB diagnostics.
     *  @return Measured throughput in bytes/second. */
    double GetMeasuredBandwidthBytesPerSecond() const noexcept;

    /** @brief Get diagnostics snapshot from the PCB.
     *  @return UcpConnectionDiagnostics struct. */
    UcpConnectionDiagnostics GetDiagnostics() const noexcept;

    /** @brief Test helper: abruptly abort this connection and optionally send RST.
     *  @param sendReset  True to notify the peer with a reset packet. */
    void AbortForTest(bool sendReset) noexcept;

  private:
    void StartWorker() noexcept;
    /** @brief Snapshot the current pcb as a shared_ptr (safe across a
     *  concurrent Dispose()); returns null when disposed/not attached. */
    ucp::shared_ptr<ucp::UcpPcb> GetPcbSnapshot() const noexcept;

  public:
    /** @brief Stop the worker thread and join (drains pending queue items).
     *  Made public so callers can drain the queue before Dispose() when
     *  a connect work item may still be enqueued (see echo_client timeout path). */
    void StopWorker() noexcept;

  private:
    void WorkerLoop() noexcept;

    /** @brief Enqueue a work item at the back of the queue (normal priority).
     *  @param work  Work function to execute. */
    void Enqueue(ucp::function<void()> work) noexcept;

    /** @brief Enqueue a work item at the front of the queue (priority / NAK).
     *  @param work  Work function to execute. */
    void EnqueuePriority(ucp::function<void()> work) noexcept;

    void EnsureWorkerStarted() noexcept;

    /** @brief Bind a UcpPcb to this connection and wire up event callbacks.
     *  @param pcb  Protocol control block to attach. */
    void AttachPcb(UcpPcb* pcb) noexcept;

    void SetServerPcbHolder(const ucp::shared_ptr<UcpPcb>& holder) noexcept;

    void SubscribeTransport() noexcept;

    void CleanupTransport() noexcept;

    mutable std::mutex mutex_;
    ucp::deque<ucp::function<void()>> queue_;
    std::condition_variable cv_;
    std::thread worker_thread_;
    std::atomic<std::thread::id> worker_thread_id_{};
    std::atomic<bool> stopped_{false};
    std::atomic<bool> worker_should_start_{false};
    std::atomic<bool> disposed_{false};
    /** @brief Set by StopWorker on a non-worker thread before it joins; the
     *  worker loop checks this before self-detaching so join() and detach()
     *  never race on the same std::thread object. */
    std::atomic<bool> joining_{false};

    transport::ITransport* transport_ = NULLPTR;
    transport::IBindableTransport* bindable_transport_ = NULLPTR;
    ucp::shared_ptr<transport::ITransport> owned_transport_holder_;
    bool owns_transport_ = true;
    bool server_managed_ = false;
    bool transport_subscribed_ = false;
    uint64_t transport_token_ = 0;

    UcpConfiguration config_;
    UcpPcb* pcb_ = NULLPTR; /**< Underlying protocol control block.
                               @note Dispose() orders StopWorker() BEFORE pcb_ close,
                                     then CleanupTransport() last, so the worker thread
                                     is joined before pcb_ is modified -- no race. */
    ucp::shared_ptr<UcpPcb> pcb_holder_;
    UcpNetwork* network_ = NULLPTR;
    bool initial_send_sequence_pending_ = false;
    uint32_t pending_initial_send_sequence_ = 0;

    Endpoint remote_endpoint_;
    uint32_t connection_id_ = 0;

    ucp::vector<DataCallback> on_data_callbacks_;
    ucp::vector<StateCallback> on_connected_callbacks_;
    ucp::vector<StateCallback> on_disconnected_callbacks_;

    int64_t total_bytes_received_ = 0;

    ucp::shared_ptr<std::atomic<bool>> alive_flag_{ucp::make_shared_object<std::atomic<bool>>(true)};

    friend class UcpServer;
    friend class UcpNetwork;
};

} // namespace ucp
