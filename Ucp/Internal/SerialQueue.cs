using System;
using System.Collections.Generic;
using System.Threading.Tasks;

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
        private readonly object _sync = new object();

        /// <summary>Queue of pending work items, each returning a Task.</summary>
        private readonly Queue<Func<Task>> _queue = new Queue<Func<Task>>();

        /// <summary>Whether the ProcessLoopAsync is currently draining the queue.</summary>
        private bool _processing;

        /// <summary>
        /// Posts a synchronous action for sequential execution.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        public void Post(Action action)
        {
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            Enqueue(delegate
            {
                action();
                return Task.CompletedTask;
            });
        }

        /// <summary>
        /// Posts an asynchronous delegate for sequential execution.
        /// </summary>
        /// <param name="action">The async function to execute.</param>
        public void Post(Func<Task> action)
        {
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            Enqueue(action);
        }

        /// <summary>
        /// Posts an asynchronous delegate that will be executed before normal
        /// FIFO items. Used for high-priority NAK processing.
        /// </summary>
        /// <param name="action">The async function to execute with priority.</param>
        public void PostPriority(Func<Task> action)
        {
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            Enqueue(action, true);
        }

        /// <summary>
        /// Enqueues a synchronous action and returns a Task that completes when
        /// the action finishes.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        /// <returns>A Task representing the completion of the action.</returns>
        public Task EnqueueAsync(Action action)
        {
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            TaskCompletionSource<bool> completion = new TaskCompletionSource<bool>();
            Enqueue(delegate
            {
                try
                {
                    action();
                    completion.TrySetResult(true);
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }

                return Task.CompletedTask;
            });
            return completion.Task;
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
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            TaskCompletionSource<T> completion = new TaskCompletionSource<T>();
            Enqueue(delegate
            {
                try
                {
                    completion.TrySetResult(action());
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }

                return Task.CompletedTask;
            });
            return completion.Task;
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
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            TaskCompletionSource<T> completion = new TaskCompletionSource<T>();
            Enqueue(async delegate
            {
                try
                {
                    completion.TrySetResult(await action().ConfigureAwait(false));
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }
            });
            return completion.Task;
        }

        /// <summary>
        /// Adds a work item to the end of the queue. If no processing loop is
        /// active, starts one on a background thread.
        /// </summary>
        /// <param name="action">The async work item.</param>
        private void Enqueue(Func<Task> action)
        {
            Enqueue(action, false);
        }

        /// <summary>
        /// Adds a work item to the queue. If priority is true, the item is
        /// inserted at the front of the FIFO queue.
        /// </summary>
        /// <param name="action">The async work item.</param>
        /// <param name="priority">If true, insert at front; otherwise append.</param>
        private void Enqueue(Func<Task> action, bool priority)
        {
            bool shouldStart = false;
            lock (_sync)
            {
                if (priority && _queue.Count > 0)
                {
                    // Insert at front by moving all existing items after this one.
                    Queue<Func<Task>> reordered = new Queue<Func<Task>>();
                    reordered.Enqueue(action);
                    while (_queue.Count > 0)
                    {
                        reordered.Enqueue(_queue.Dequeue());
                    }

                    while (reordered.Count > 0)
                    {
                        _queue.Enqueue(reordered.Dequeue());
                    }
                }
                else
                {
                    _queue.Enqueue(action);
                }

                if (!_processing)
                {
                    _processing = true;
                    shouldStart = true;
                }
            }

            if (shouldStart)
            {
                // Start the processing loop on a background thread.
                Task.Run(ProcessLoopAsync);
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
            while (true)
            {
                Func<Task> next;
                lock (_sync)
                {
                    if (_queue.Count == 0)
                    {
                        _processing = false;
                        return;
                    }

                    next = _queue.Dequeue();
                }

                try
                {
                    await next().ConfigureAwait(false);
                }
                catch
                {
                    // The concrete exception has already been recorded on the task source.
                }
            }
        }
    }
}
