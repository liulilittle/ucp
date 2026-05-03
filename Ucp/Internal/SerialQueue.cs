using System; // Provides ArgumentNullException for parameter validation
using System.Collections.Generic; // Provides Queue<T> for the FIFO work item queue
using System.Threading.Tasks; // Provides Task, TaskCompletionSource<T> for async patterns

namespace Ucp.Internal
{
    /// <summary>
    /// Lightweight serial execution queue implementing a per-connection strand.
    /// All posted work (sync actions, async delegates, prioritized items) is
    /// processed sequentially in FIFO order (or priority-first for NAK packets).
    /// This eliminates lock contention on per-connection state while allowing
    /// different connections to execute concurrently on separate threads.
    /// </summary>
    internal sealed class SerialQueue
    {
        /// <summary>Synchronization object for queue operations.</summary>
        private readonly object _sync = new object(); // Lock object protecting the shared _queue and _processing flag

        /// <summary>Queue of pending work items, each returning a Task.</summary>
        private readonly Queue<Func<Task>> _queue = new Queue<Func<Task>>(); // FIFO (or priority-inserted) collection of async delegates awaiting execution

        /// <summary>Whether the ProcessLoopAsync is currently draining the queue.</summary>
        private bool _processing; // Guard flag; only one processing loop may run at a time to guarantee sequential execution

        /// <summary>
        /// Posts a synchronous action for sequential execution.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        public void Post(Action action)
        {
            if (action == null) // Validate that a non-null action was provided
            {
                throw new ArgumentNullException(nameof(action)); // Fail fast with a clear diagnostic
            }

            Enqueue(delegate // Wrap the synchronous action into a Func<Task> so it fits the unified queue signature
            {
                action(); // Execute the user's synchronous work on the strand thread
                return Task.CompletedTask; // Signal completion; required by Func<Task> return type
            });
        }

        /// <summary>
        /// Posts an asynchronous delegate for sequential execution.
        /// </summary>
        /// <param name="action">The async function to execute.</param>
        public void Post(Func<Task> action)
        {
            if (action == null) // Validate that a non-null delegate was provided
            {
                throw new ArgumentNullException(nameof(action)); // Fail fast with a clear diagnostic
            }

            Enqueue(action); // Enqueue the async delegate directly; no wrapping needed since it already returns Task
        }

        /// <summary>
        /// Posts an asynchronous delegate that will be executed before normal
        /// FIFO items. Used for high-priority NAK processing.
        /// </summary>
        /// <param name="action">The async function to execute with priority.</param>
        public void PostPriority(Func<Task> action)
        {
            if (action == null) // Validate that a non-null delegate was provided
            {
                throw new ArgumentNullException(nameof(action)); // Fail fast with a clear diagnostic
            }

            Enqueue(action, true); // Enqueue with priority flag set; inserts at front to skip ahead of normal FIFO items
        }

        /// <summary>
        /// Enqueues a synchronous action and returns a Task that completes when
        /// the action finishes.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        /// <returns>A Task representing the completion of the action.</returns>
        public Task EnqueueAsync(Action action)
        {
            if (action == null) // Validate that a non-null action was provided
            {
                throw new ArgumentNullException(nameof(action)); // Fail fast with a clear diagnostic
            }

            TaskCompletionSource<bool> completion = new TaskCompletionSource<bool>(); // Create a TCS to bridge strand execution back to the caller's await
            Enqueue(delegate // Wrap the action into a Func<Task> compatible with the unified queue
            {
                try
                {
                    action(); // Execute the user's synchronous work on the strand thread
                    completion.TrySetResult(true); // Signal success to the awaiting caller via the TaskCompletionSource
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex); // Propagate the exception to the awaiting caller via the TCS
                }

                return Task.CompletedTask; // Satisfy the Func<Task> return type; the actual result flows through TCS
            });
            return completion.Task; // Return the Task that the caller can await for completion or fault
        }

        /// <summary>
        /// Enqueues a synchronous function and returns a Task&lt;T&gt; that
        /// completes with the function's return value when executed.
        /// </summary>
        /// <typeparam name="T">Return type of the function.</typeparam>
        /// <param name="action">The function to execute.</param>
        /// <returns>A Task that completes with the function's result.</returns>
        public Task<T> EnqueueAsync<T>(Func<T> action)
        {
            if (action == null) // Validate that a non-null function was provided
            {
                throw new ArgumentNullException(nameof(action)); // Fail fast with a clear diagnostic
            }

            TaskCompletionSource<T> completion = new TaskCompletionSource<T>(); // Create a typed TCS to relay both result and exceptions
            Enqueue(delegate // Wrap the function into a Func<Task> compatible with the unified queue
            {
                try
                {
                    completion.TrySetResult(action()); // Execute the function and relay its return value to the awaiting caller
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex); // Propagate the exception to the awaiting caller via the TCS
                }

                return Task.CompletedTask; // Satisfy the Func<Task> return type; the actual result flows through TCS
            });
            return completion.Task; // Return the typed Task that the caller can await for result or fault
        }

        /// <summary>
        /// Enqueues an asynchronous function and returns a Task&lt;T&gt; that
        /// completes with the result when the async function finishes.
        /// </summary>
        /// <typeparam name="T">Return type of the function.</typeparam>
        /// <param name="action">The async function to execute.</param>
        /// <returns>A Task that completes with the async function's result.</returns>
        public Task<T> EnqueueAsync<T>(Func<Task<T>> action)
        {
            if (action == null) // Validate that a non-null async function was provided
            {
                throw new ArgumentNullException(nameof(action)); // Fail fast with a clear diagnostic
            }

            TaskCompletionSource<T> completion = new TaskCompletionSource<T>(); // Create a typed TCS to relay the async result to the caller
            Enqueue(async delegate // Enqueue an async anonymous method that will be invoked by the processing loop
            {
                try
                {
                    completion.TrySetResult(await action().ConfigureAwait(false)); // Await the user's async function and relay its result; ConfigureAwait(false) avoids capturing the strand context
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex); // Propagate the exception from the async function to the awaiting caller
                }
            });
            return completion.Task; // Return the typed Task that the caller can await for the async result or fault
        }

        /// <summary>
        /// Adds a work item to the end of the queue. If no processing loop is
        /// active, starts one on a background thread.
        /// </summary>
        /// <param name="action">The async work item.</param>
        private void Enqueue(Func<Task> action)
        {
            Enqueue(action, false); // Delegate to the priority-aware overload with default FIFO (non-priority) behavior
        }

        /// <summary>
        /// Adds a work item to the queue. If priority is true, the item is
        /// inserted at the front of the FIFO queue.
        /// </summary>
        /// <param name="action">The async work item.</param>
        /// <param name="priority">If true, insert at front; otherwise append.</param>
        private void Enqueue(Func<Task> action, bool priority)
        {
            bool shouldStart = false; // Track whether we need to start a new processing loop after releasing the lock
            lock (_sync) // Acquire the lock to safely mutate the shared queue and _processing flag
            {
                if (priority && _queue.Count > 0) // If this item has priority and the queue is non-empty
                {
                    // Insert at front by moving all existing items after this one.
                    Queue<Func<Task>> reordered = new Queue<Func<Task>>(); // Create a temporary queue to rebuild the order
                    reordered.Enqueue(action); // Put the priority item first in the temporary queue
                    while (_queue.Count > 0) // Drain all existing items from the original queue
                    {
                        reordered.Enqueue(_queue.Dequeue()); // Move each existing item after the priority item, preserving FIFO among them
                    }

                    while (reordered.Count > 0) // Rebuild the original queue from the temporary reordered queue
                    {
                        _queue.Enqueue(reordered.Dequeue()); // Populate _queue with the correct priority-first ordering
                    }
                }
                else
                {
                    _queue.Enqueue(action); // Append the item to the end of the FIFO queue (normal case or empty queue)
                }

                if (!_processing) // Check if the processing loop is not currently running
                {
                    _processing = true; // Mark the loop as active so no duplicate loops are created
                    shouldStart = true; // Signal that we need to start the processing loop after releasing the lock
                }
            }

            if (shouldStart) // If we marked shouldStart while holding the lock
            {
                // Start the processing loop on a background thread.
                Task.Run(ProcessLoopAsync); // Fire-and-forget the processing loop on a threadpool thread; it drains until queue is empty
            }
        }

        /// <summary>
        /// Continuously dequeues and executes work items until the queue is empty,
        /// then marks processing as complete so the next Enqueue can restart it.
        /// Exceptions are silently swallowed since they have already been recorded
        /// on the caller's TaskCompletionSource.
        /// </summary>
        private async Task ProcessLoopAsync()
        {
            while (true) // Loop indefinitely until the queue is empty; exits via return inside the lock
            {
                Func<Task> next; // Will hold the next work item to execute after releasing the lock
                lock (_sync) // Acquire the lock to safely check queue state and dequeue the next item
                {
                    if (_queue.Count == 0) // If the queue has been fully drained
                    {
                        _processing = false; // Mark processing as inactive so the next Enqueue can restart the loop
                        return; // Exit the processing loop; a new loop will be started by the next Enqueue call
                    }

                    next = _queue.Dequeue(); // Remove and capture the next work item from the front of the FIFO queue
                }

                try
                {
                    await next().ConfigureAwait(false); // Execute the dequeued async work item; ConfigureAwait(false) avoids capturing the strand context
                }
                catch
                {
                    // The concrete exception has already been recorded on the task source.
                    // Silently swallow here; the caller's TaskCompletionSource was already populated in the Enqueue wrapper.
                }
            }
        }
    }
}
