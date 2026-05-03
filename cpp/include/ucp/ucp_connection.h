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
 *
 *  This class contains NO socket or ASIO code — network I/O is delegated
 *  to the UcpNetwork's Output() or to a standalone transport layer.
 */

#include "ucp_types.h"         // Endpoint, UcpTransferReport, UcpConnectionDiagnostics (includes ucp_vector.h and ucp_memory.h)
#include "ucp_configuration.h" // Connection-level protocol configuration (RTO, MSS, window sizes, pacing, etc.)
#include "ucp_enums.h"         // UcpPriority, UcpConnectionState, UcpPacketType enumeration types
#include <cstdint>             // Fixed-width integers: uint8_t, uint32_t, int64_t, size_t
#include <functional>          // std::function for callback delegates (DataCallback, StateCallback, work items)
#include <future>              // std::future, std::promise for async Connect/Send/Receive/Close return values
#include <mutex>               // std::mutex for thread-safe serial queue and connection state access
#include <deque>               // std::deque as the underlying serial work queue container
#include <condition_variable>  // std::condition_variable to wake the worker thread when new work is enqueued
#include <thread>              // std::thread for the background worker thread (WorkerLoop)
#include <atomic>              // std::atomic<bool> for lock-free stopped_ and worker_should_start_ flags

namespace ucp {

class UcpPcb;     // Forward declaration — the internal protocol control block (defined in internal/ucp_pcb.h)
class UcpNetwork; // Forward declaration — the owning network event loop (null for standalone connections)

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
 *  All network I/O is performed through the registered UcpNetwork or a
 *  standalone transport — no ASIO/socket code exists in this class.
 */
class UcpConnection {
public:
    /** @brief Callback type for received data: parameters are (data_buffer, offset, length).
     *
     *  Called when in-order data arrives from the peer.  The buffer is owned
     *  by the protocol stack; the callback should consume or copy the data. */
    using DataCallback = std::function<void(const uint8_t* data, size_t offset, size_t length)>; // Mirrors C# Action<byte[], int, int>

    /** @brief Callback type for connection state transitions (connected, disconnected).
     *
     *  Takes no arguments — the callback can query the connection for details. */
    using StateCallback = std::function<void()>; // Mirrors C# Action (parameterless delegate)

    UcpConnection(); // Default constructor: creates with default configuration, standalone transport

    /** @brief Construct with a custom configuration.
     *  @param config  Configuration for the underlying UcpPcb (cloned internally). */
    explicit UcpConnection(const UcpConfiguration& config); // Stores a copy; no network context (standalone mode)

    ~UcpConnection(); // Stops the worker thread, disposes the PCB, cleans up transport if owned

    UcpConnection(const UcpConnection&) = delete; // Non-copyable — each connection manages unique PCB and thread state
    UcpConnection& operator=(const UcpConnection&) = delete; // Non-copyable — prevents shallow copies of thread/PCB resources

    /** @brief Initiate an async connection to a remote endpoint (standalone transport).
     *  @param remoteEndpoint  String in "address:port" format (e.g. "127.0.0.1:9000").
     *  @return Future that resolves to true on successful handshake, false on failure. */
    std::future<bool> ConnectAsync(const ucp::string& remoteEndpoint); // Parses endpoint, creates PCB if needed, performs SYN/SYN-ACK handshake

    /** @brief Initiate an async connection via a specific UcpNetwork (multiplexed transport).
     *  @param network         The UcpNetwork to route through (replaces standalone transport).
     *  @param remoteEndpoint  String in "address:port" format.
     *  @return Future that resolves to true on successful handshake, false on failure. */
    std::future<bool> ConnectAsync(UcpNetwork* network, const ucp::string& remoteEndpoint); // Swaps transport to network's adapter, then connects

    /** @brief Synchronous send (default Normal priority).  Blocks until data is enqueued.
     *  @param buf     Source buffer containing data to send.
     *  @param offset  Start offset in buf (bytes from the beginning).
     *  @param count   Number of bytes to send from offset.
     *  @return Number of bytes accepted for transmission; -1 on error. */
    int Send(const uint8_t* buf, size_t offset, size_t count); // Delegates to Send with UcpPriority::Normal

    /** @brief Synchronous send with explicit QoS priority.
     *  @param buf      Source buffer containing data to send.
     *  @param offset   Start offset in buf.
     *  @param count    Number of bytes to send.
     *  @param priority QoS priority level (Normal, Urgent, etc.).
     *  @return Number of bytes accepted for transmission; -1 on error. */
    int Send(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority); // Blocks synchronously on SendAsync via future.get()

    /** @brief Async send (default Normal priority).  Returns immediately with a future.
     *  @param buf     Source buffer containing data to send.
     *  @param offset  Start offset in buf.
     *  @param count   Number of bytes to send.
     *  @return Future resolving to bytes accepted; -1 on error. */
    std::future<int> SendAsync(const uint8_t* buf, size_t offset, size_t count); // Delegates to the priority overload with UcpPriority::Normal

    /** @brief Async send with explicit QoS priority.
     *  @param buf      Source buffer containing data to send.
     *  @param offset   Start offset in buf.
     *  @param count    Number of bytes to send.
     *  @param priority QoS priority level.
     *  @return Future resolving to bytes accepted; -1 on error. */
    std::future<int> SendAsync(const uint8_t* buf, size_t offset, size_t count, UcpPriority priority); // Enqueues send on serial queue; returns future

    /** @brief Synchronous receive.  Blocks until data is available.
     *  @param buf     Destination buffer to copy received data into.
     *  @param offset  Start offset in buf.
     *  @param count   Maximum number of bytes to receive.
     *  @return Bytes actually received (up to count); 0 = connection closed; -1 on error. */
    int Receive(uint8_t* buf, size_t offset, size_t count); // Blocks on ReceiveAsync via future.get()

    /** @brief Async receive.  Returns a future that resolves when data or close occurs.
     *  @param buf     Destination buffer.
     *  @param offset  Start offset in buf.
     *  @param count   Maximum bytes to receive.
     *  @return Future resolving to bytes received; 0 = closed; -1 on error. */
    std::future<int> ReceiveAsync(uint8_t* buf, size_t offset, size_t count); // Delegates to PCB's in-order receive queue; returns future

    /** @brief Synchronous read: receive exactly count bytes (loops until satisfied or closed).
     *  @param buf   Destination buffer.
     *  @param off   Start offset in buf.
     *  @param count Exact number of bytes to read.
     *  @return true if exactly count bytes were received; false on error or premature close. */
    bool Read(uint8_t* buf, size_t off, size_t count); // Blocks on ReadAsync via future.get()

    /** @brief Async read: receive exactly count bytes (loops ReceiveAsync until satisfied).
     *  @param buf   Destination buffer.
     *  @param off   Start offset in buf.
     *  @param count Exact number of bytes to read.
     *  @return Future resolving to true on success (all bytes received). */
    std::future<bool> ReadAsync(uint8_t* buf, size_t off, size_t count); // Loops ReceiveAsync internally; returns future that resolves when done

    /** @brief Synchronous write: send exactly count bytes (default Normal priority).
     *  @param buf   Source buffer.
     *  @param off   Start offset in buf.
     *  @param count Exact number of bytes to write.
     *  @return true if all bytes were accepted for transmission. */
    bool Write(const uint8_t* buf, size_t off, size_t count); // Delegates to Write with UcpPriority::Normal

    /** @brief Synchronous write with explicit QoS priority.
     *  @param buf      Source buffer.
     *  @param off      Start offset in buf.
     *  @param count    Exact number of bytes to write.
     *  @param priority QoS priority level.
     *  @return true if all bytes were accepted. */
    bool Write(const uint8_t* buf, size_t off, size_t count, UcpPriority priority); // Blocks on WriteAsync via future.get()

    /** @brief Async write: send exactly count bytes (default Normal priority).
     *  @param buf   Source buffer.
     *  @param off   Start offset in buf.
     *  @param count Number of bytes to write.
     *  @return Future resolving to true on success (all bytes accepted). */
    std::future<bool> WriteAsync(const uint8_t* buf, size_t off, size_t count); // Delegates to the priority overload with UcpPriority::Normal

    /** @brief Async write with explicit QoS priority.
     *  @param buf      Source buffer.
     *  @param off      Start offset in buf.
     *  @param count    Number of bytes to write.
     *  @param priority QoS priority level.
     *  @return Future resolving to true on success (all bytes accepted). */
    std::future<bool> WriteAsync(const uint8_t* buf, size_t off, size_t count, UcpPriority priority); // Loops SendAsync internally; resolves when all bytes are enqueued

    /** @brief Synchronously close the connection (graceful FIN exchange).
     *
     *  Drains the send buffer, sends a FIN packet, and waits for the peer's
     *  FIN-ACK before cleaning up transport resources. */
    void Close(); // Blocks on CloseAsync via future.get()

    /** @brief Async close (graceful FIN exchange).
     *  @return Future that resolves when the connection is fully closed and transport is cleaned up. */
    std::future<void> CloseAsync(); // Initiates FIN sequence on the PCB; future resolves when the close handshake completes

    /** @brief Release all connection resources and stop the worker thread.
     *
     *  Calls Close() first to attempt graceful shutdown, then cleans up
     *  transport even if Close throws.  Stops the worker thread and joins it. */
    void Dispose(); // Best-effort cleanup: tries graceful close, always releases transport and stops worker

    /** @brief Get transfer statistics for this connection.
     *  @return An UcpTransferReport snapshot (bytes sent/received, RTT, loss, etc.). */
    UcpTransferReport GetReport() const; // Builds a report from the PCB's diagnostic snapshot

    /** @brief Remote endpoint as "address:port" string.
     *  @return String representation of the peer endpoint (e.g. "127.0.0.1:9000"). */
    ucp::string GetRemoteEndPoint() const; // Returns the string form of the remote endpoint for display/logging

    /** @brief This connection's unique protocol-level identifier.
     *  @return 32-bit connection ID assigned during the handshake (0 = not yet assigned). */
    uint32_t GetConnectionId() const; // Delegates to PCB; returns 0 if PCB is null

    /** @brief The UcpNetwork managing this connection (or nullptr if standalone).
     *  @return Pointer to UcpNetwork or nullptr. */
    UcpNetwork* GetNetwork() const; // Returns the stored network_ pointer (set at construction or via ConnectAsync(network, ...))

    /** @brief Current state of the underlying PCB's connection state machine.
     *  @return UcpConnectionState value (Init, SynSent, Established, ClosingFinSent, etc.). */
    UcpConnectionState GetState() const; // Returns Init if no PCB exists; otherwise delegates to PCB's state

    /** @brief Register a callback invoked when in-order data arrives from the peer.
     *  @param cb  Function with signature (data_buffer, offset, length). */
    void SetOnData(DataCallback cb); // Stores the callback; forwards to PCB if it already exists

    /** @brief Register a callback invoked when the connection handshake completes.
     *  @param cb  Function with no arguments; called when state transitions to Established. */
    void SetOnConnected(StateCallback cb); // Stores the callback; forwards to PCB if it already exists

    /** @brief Register a callback invoked when the connection is closed or disconnected.
     *  @param cb  Function with no arguments; called on FIN completion or RST. */
    void SetOnDisconnected(StateCallback cb); // Stores the callback; forwards to PCB if it already exists

private:
    /** @brief Start the worker thread if not already running (idempotent). */
    void StartWorker(); // Uses worker_should_start_ flag to prevent double-start; spawns WorkerLoop thread

    /** @brief Signal the worker thread to stop and join it. */
    void StopWorker(); // Sets stopped_ = true, notifies CV, joins worker_thread_ (blocks until exit)

    /** @brief Main worker loop: dequeue tasks from the serial queue and execute them. */
    void WorkerLoop(); // Blocks on CV, pops work items from the deque, executes each (the "strand" pattern)

    /** @brief Enqueue a work item onto the serial queue and notify the worker thread.
     *  @param work  The function to execute on the worker thread. */
    void Enqueue(std::function<void()> work); // Pushes to back of deque, notifies CV

    /** @brief Ensure the worker thread is started (idempotent — safe to call multiple times). */
    void EnsureWorkerStarted(); // Checks worker_should_start_, calls StartWorker if needed

    /** @brief Bind a UcpPcb to this connection and wire up event callbacks.
     *  @param pcb  The protocol control block to attach (ownership transfers). */
    void AttachPcb(UcpPcb* pcb); // Stores pcb_ pointer; forwards on_data_, on_connected_, on_disconnected_ callbacks

    /** @brief Decode and dispatch an inbound packet to the PCB via the serial queue.
     *  @param data    Raw byte buffer of the received datagram.
     *  @param length  Number of bytes in data.
     *  @param remote  Endpoint that sent the datagram. */
    void DispatchPacket(const uint8_t* data, size_t length, const Endpoint& remote); // Enqueues packet handling on serial queue

    /** @brief Handle a datagram received from the transport layer.
     *  @param datagram  Raw datagram bytes.
     *  @param length    Number of bytes in datagram.
     *  @param remote    Source endpoint of the datagram. */
    void OnTransportDatagram(const uint8_t* datagram, size_t length, const Endpoint& remote); // Validates connection ID, decodes, dispatches

    /** @brief Release transport-related resources: unsubscribe from events, stop and dispose if owned. */
    void CleanupTransport(); // Unsubscribes from transport datagrams, stops bindable transport, disposes if owned

    mutable std::mutex mutex_;                         // Protects the serial work queue and connection state from concurrent access
    std::deque<std::function<void()>> queue_;          // Serial work queue consumed by WorkerLoop (FIFO order for fairness)
    std::condition_variable cv_;                       // CV signaled when work is enqueued or the worker should stop
    std::thread worker_thread_;                        // Background worker thread executing WorkerLoop in a loop
    std::atomic<bool> stopped_{false};                 // Atomic flag — set to true to signal the worker thread to exit
    std::atomic<bool> worker_should_start_{false};     // Atomic flag — prevents starting the worker thread multiple times

    UcpPcb* pcb_ = nullptr;             // Owning pointer to the underlying protocol control block (created during ConnectAsync)
    UcpNetwork* network_ = nullptr;     // Network used for transport routing (null if standalone, non-null if multiplexed)
    UcpConfiguration config_;           // Configuration for this connection (stored copy, cloned from the source)
    bool owns_transport_ = true;        // True if this connection created and owns its transport (should dispose on close)
    bool server_managed_ = false;       // True if this connection was created by UcpServer (dispatch handled by server)

    ucp::vector<DataCallback> on_data_callbacks_;           // Registered callbacks for in-order data arrival events
    ucp::vector<StateCallback> on_connected_callbacks_;     // Registered callbacks for handshake-complete (Connected) events
    ucp::vector<StateCallback> on_disconnected_callbacks_;  // Registered callbacks for connection-closed (Disconnected) events

    /** @brief Pending connect operation waiting for the worker thread to execute.
     *
     *  Created when ConnectAsync(network, endpoint) is called.  The worker
     *  thread picks up the pending connect and performs the actual handshake. */
    struct PendingConnect {
        std::promise<bool> promise;     // Promise fulfilled when the connect succeeds (true) or fails (false)
        ucp::string remote;              // Target endpoint string in "address:port" format
        UcpNetwork* network = nullptr;  // Network to route through (null for standalone transport connect)
    };

    Endpoint remote_endpoint_;         // Remote peer endpoint (address + port) resolved after connection is established
    uint32_t connection_id_ = 0;       // Assigned connection ID from the PCB (0 until handshake completes)

    friend class UcpServer;  // UcpServer creates connections via internal constructor and calls AttachPcb/DispatchPacket
    friend class UcpNetwork; // UcpNetwork creates connections via CreateConnection factory methods
};

} // namespace ucp
