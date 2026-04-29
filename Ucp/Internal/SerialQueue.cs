using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Ucp.Internal
{
    /// <summary>
    /// Lightweight serial execution queue used to implement a per-connection strand.
    /// All posted work is processed in logical order to avoid concurrent protocol-state mutation.
    /// </summary>
    internal sealed class SerialQueue
    {
        private readonly object _sync = new object();
        private readonly Queue<Func<Task>> _queue = new Queue<Func<Task>>();
        private bool _processing;

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

        public void Post(Func<Task> action)
        {
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            Enqueue(action);
        }

        public void PostPriority(Func<Task> action)
        {
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            Enqueue(action, true);
        }

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

        private void Enqueue(Func<Task> action)
        {
            Enqueue(action, false);
        }

        private void Enqueue(Func<Task> action, bool priority)
        {
            bool shouldStart = false;
            lock (_sync)
            {
                if (priority && _queue.Count > 0)
                {
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
                Task.Run(ProcessLoopAsync);
            }
        }

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
