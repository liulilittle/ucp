#pragma once

/** @file ucp_connection.h
 *  @brief High-level UCP connection (public API) — mirrors C# Ucp.UcpConnection.
 *
 *  UcpConnection wraps the internal UcpPcb protocol engine behind a
 *  thread-safe, future-based async API.  The connection runs its own
 *  worker thread (serial queue) to process inbound packets and execute
 *  API calls without blocking the caller's thread.
 *
 *  Applications interact with UcpConnection through its async Send/Receive/
 *  Connect/Close methods, optionally registering callback delegates for
 *  data arrival, connection established, and disconnection events.
 */

#include "ucp_types.h"
#include "ucp_configuration.h"
#include "ucp_enums.h"
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <deque>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <string>
#include <vector>

namespace ucp {

class UcpPcb;
class UcpNetwork;

/** @brief Public-facing UCP connection with async API and internal worker thread.
 *
 *  Each UcpConnection creates a dedicated worker thread (WorkerLoop) that
 *  processes a serial queue of work items.  Async methods (ConnectAsync,
 *  SendAsync, ReceiveAsync, CloseAsync) enqueue the work and return a
 *  std::future for the result.  This design avoids blocking the application
 *  thread and ensures all protocol operations are serialized.
 *
 *  The connection holds a pointer to a UcpPcb (the protocol engine) and
 *  optional callback delegates for data and state-change notifications.
 */
class UcpConnection {
public:
    /** @brief Callback type for received data: (data_buffer, offset, length). */
    using DataCallback = std::function<void(const uint8_t* data, size_t offset, size_t length)>;
    /** @brief Callback type for state transitions (connected, disconnected). */
    using StateCallback = std::function<void()>;

    UcpConnection();
    /** @brief Construct with a custom configuration.
     *  @param config  Configuration for the underlying UcpPcb. */
    explicit UcpConnection(const UcpConfiguration& config);
    ~UcpConnection();

    UcpConnection(const UcpConnection&) = delete;
    UcpConnection& operator=(const UcpConnection&) = delete;

    /** @brief Initiate an async connection to a remote endpoint (standalone transport).
     *  @param remoteEndpoint  String in "address:port" format.
     *  @return Future that resolves to true on success, false on failure. */
    std::future<bool> ConnectAsync(const std::string& remoteEndpoint);

    /** @brief Initiate an async connection via a specific UcpNetwork.
     *  @param network         The UcpNetwork to route through.
     *  @param remoteEndpoint  String in "address:port" format.
     *  @return Future that resolves to true on success, false on failure. */
    std::future<bool> ConnectAsync(UcpNetwork* network, const std::string& remoteEndpoint);

    /** @brief Synchronous send (default normal priority).
     *  @param buf     Source buffer.
     *  @param offset  Start offset in buf.
     *  @param count   Number of bytes to send.
     *  @return Bytes accepted; -1 on error. */
    int Send(const uint8_t* buf, size_t offset, size_t count);

    /** @brief Synchronous send with priority.
     *  @param buf      Source buffer.
     *  @param offset   Start offset in buf.
     *  @param count    Number of bytes to send.
     *  @param priority QoS priority.
     *  @return Bytes accepted; -1 on error. */
    int Send(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority);

    /** @brief Async send (default normal priority).
     *  @param buf     Source buffer.
     *  @param offset  Start offset.
     *  @param count   Number of bytes.
     *  @return Future resolving to bytes accepted; -1 on error. */
    std::future<int> SendAsync(const uint8_t* buf, size_t offset, size_t count);

    /** @brief Async send with priority.
     *  @param buf      Source buffer.
     *  @param offset   Start offset.
     *  @param count    Number of bytes.
     *  @param priority QoS priority.
     *  @return Future resolving to bytes accepted; -1 on error. */
    std::future<int> SendAsync(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority);

    /** @brief Synchronous receive.
     *  @param buf     Destination buffer.
     *  @param offset  Start offset in buf.
     *  @param count   Maximum bytes to receive.
     *  @return Bytes received; 0 = connection closed; -1 on error. */
    int Receive(uint8_t* buf, size_t offset, size_t count);

    /** @brief Async receive.
     *  @param buf     Destination buffer.
     *  @param offset  Start offset.
     *  @param count   Maximum bytes to receive.
     *  @return Future resolving to bytes received; -1 on error. */
    std::future<int> ReceiveAsync(uint8_t* buf, size_t offset, size_t count);

    /** @brief Synchronous read (receive exactly count bytes).
     *  @param buf   Destination buffer.
     *  @param off   Start offset.
     *  @param count Exact number of bytes to read.
     *  @return true if exactly count bytes were received; false on error or disconnect. */
    bool Read(uint8_t* buf, size_t off, size_t count);

    /** @brief Async read (exactly count bytes).
     *  @param buf   Destination buffer.
     *  @param off   Start offset.
     *  @param count Exact number of bytes to read.
     *  @return Future resolving to true on success. */
    std::future<bool> ReadAsync(uint8_t* buf, size_t off, size_t count);

    /** @brief Synchronous write (send exactly count bytes, default priority).
     *  @param buf   Source buffer.
     *  @param off   Start offset.
     *  @param count Exact number of bytes to write.
     *  @return true if all bytes were accepted for transmission. */
    bool Write(const uint8_t* buf, size_t off, size_t count);

    /** @brief Synchronous write with priority.
     *  @param buf      Source buffer.
     *  @param off      Start offset.
     *  @param count    Exact number of bytes.
     *  @param priority QoS priority.
     *  @return true if all bytes were accepted. */
    bool Write(const uint8_t* buf, size_t off, size_t count, UcpPriority priority);

    /** @brief Async write (default priority).
     *  @param buf   Source buffer.
     *  @param off   Start offset.
     *  @param count Number of bytes to write.
     *  @return Future resolving to true on success. */
    std::future<bool> WriteAsync(const uint8_t* buf, size_t off, size_t count);

    /** @brief Async write with priority.
     *  @param buf      Source buffer.
     *  @param off      Start offset.
     *  @param count    Number of bytes.
     *  @param priority QoS priority.
     *  @return Future resolving to true on success. */
    std::future<bool> WriteAsync(const uint8_t* buf, size_t off, size_t count, UcpPriority priority);

    /** @brief Synchronously close the connection (graceful FIN exchange). */
    void Close();

    /** @brief Async close (graceful FIN exchange).
     *  @return Future that resolves when the connection is fully closed. */
    std::future<void> CloseAsync();

    /** @brief Release all connection resources and stop the worker thread. */
    void Dispose();

    /** @brief Get transfer statistics for this connection.
     *  @return An UcpTransferReport snapshot. */
    UcpTransferReport GetReport() const;

    /** @brief Remote endpoint as "address:port" string.
     *  @return String representation of the peer endpoint. */
    std::string GetRemoteEndPoint() const;

    /** @brief This connection's unique identifier.
     *  @return 32-bit connection ID. */
    uint32_t GetConnectionId() const;

    /** @brief The UcpNetwork managing this connection (or nullptr).
     *  @return Pointer to UcpNetwork or null. */
    UcpNetwork* GetNetwork() const;

    /** @brief Current state of the underlying PCB.
     *  @return UcpConnectionState value. */
    UcpConnectionState GetState() const;

    /** @brief Register a callback invoked when data arrives in-order.
     *  @param cb  Function (data, offset, length). */
    void SetOnData(DataCallback cb);

    /** @brief Register a callback invoked when the connection is established.
     *  @param cb  Function with no arguments. */
    void SetOnConnected(StateCallback cb);

    /** @brief Register a callback invoked when the connection is closed/disconnected.
     *  @param cb  Function with no arguments. */
    void SetOnDisconnected(StateCallback cb);

private:
    /** @brief Start the worker thread if not already running. */
    void StartWorker();
    /** @brief Signal the worker thread to stop and join it. */
    void StopWorker();
    /** @brief Main worker loop: dequeue tasks and execute them. */
    void WorkerLoop();
    /** @brief Enqueue a work item onto the serial queue and notify the worker. */
    void Enqueue(std::function<void()> work);
    /** @brief Ensure the worker thread is started (idempotent). */
    void EnsureWorkerStarted();
    /** @brief Bind a UcpPcb to this connection. */
    void AttachPcb(UcpPcb* pcb);
    /** @brief Decode and dispatch an inbound packet to the PCB. */
    void DispatchPacket(const uint8_t* data, size_t length, const Endpoint& remote);
    /** @brief Handle a datagram received from the transport layer. */
    void OnTransportDatagram(const uint8_t* datagram, size_t length, const Endpoint& remote);
    /** @brief Release transport-related resources. */
    void CleanupTransport();

    mutable std::mutex mutex_;                         //< Protects the serial queue and connection state.
    std::deque<std::function<void()>> queue_;          //< Serial work queue consumed by WorkerLoop.
    std::condition_variable cv_;                       //< CV used to wake the worker thread.
    std::thread worker_thread_;                        //< Background worker thread.
    std::atomic<bool> stopped_{false};                 //< Signal to stop the worker thread.
    std::atomic<bool> worker_should_start_{false};     //< Flag to avoid double-starting the worker.

    UcpPcb* pcb_ = nullptr;             //< Owning pointer to the underlying protocol control block.
    UcpNetwork* network_ = nullptr;     //< Network used for transport (null if standalone).
    UcpConfiguration config_;           //< Configuration for this connection.
    bool owns_transport_ = true;        //< Whether this connection owns its transport layer.
    bool server_managed_ = false;       //< Whether this connection is managed by a UcpServer.

    std::vector<DataCallback> on_data_callbacks_;           //< Registered data-arrival callbacks.
    std::vector<StateCallback> on_connected_callbacks_;     //< Registered connected callbacks.
    std::vector<StateCallback> on_disconnected_callbacks_;  //< Registered disconnected callbacks.

    /** @brief Pending connect operation waiting for the worker. */
    struct PendingConnect {
        std::promise<bool> promise;    //< Promise to fulfill on connect result.
        std::string remote;            //< Target endpoint string.
        UcpNetwork* network = nullptr; //< Network to use (null for standalone).
    };

    Endpoint remote_endpoint_;         //< Remote peer endpoint after connection.
    uint32_t connection_id_ = 0;       //< Assigned connection ID (from PCB).

    friend class UcpServer;
    friend class UcpNetwork;
};

} // namespace ucp
