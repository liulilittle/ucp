using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Ucp.Internal
{

    internal sealed class SerialQueue
    {

        private readonly object _sync = new object();

        private readonly LinkedList<Func<Task>> _queue = new LinkedList<Func<Task>>();

        private bool _processing;

        private volatile int _processingThreadId;

        internal bool IsCurrentThreadProcessing => _processingThreadId == Thread.CurrentThread.ManagedThreadId;

        private volatile bool _stopped;

        private int _consecutiveFrontItemCount;

        private int _processorGeneration;

        public void Stop()
        {
            List<Func<Task>> pendingItems = null;
            lock (_sync)
            {
                _stopped = true;
                if (_queue.Count > 0)
                {
                    pendingItems = new List<Func<Task>>(_queue);
                }
                _queue.Clear();
                _processing = false;
#pragma warning disable CS0420
                Volatile.Write(ref _processingThreadId, -1);
#pragma warning restore CS0420
            }

            if (null != pendingItems)
            {
                foreach (Func<Task> item in pendingItems)
                {
                    try
                    {
                        Task t = item();
                        t.ContinueWith(_ => { }, TaskContinuationOptions.OnlyOnFaulted);
                    }
                    catch
                    {

                    }
                }
            }
        }

        public void Post(Action action)
        {
            if (null == action)
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
            if (null == action)
            {
                throw new ArgumentNullException(nameof(action));
            }

            Enqueue(action);
        }

        public void PostPriority(Func<Task> action)
        {
            if (null == action)
            {
                throw new ArgumentNullException(nameof(action));
            }

            Enqueue(action, true);
        }

        public Task EnqueueAsync(Action action)
        {
            if (null == action)
            {
                throw new ArgumentNullException(nameof(action));
            }

            TaskCompletionSource<bool> completion = new TaskCompletionSource<bool>();
            if (!Enqueue(delegate
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
            }))
            {

                completion.TrySetCanceled();
            }
            return completion.Task;
        }

        public Task<T> EnqueueAsync<T>(Func<T> action)
        {
            if (null == action)
            {
                throw new ArgumentNullException(nameof(action));
            }

            TaskCompletionSource<T> completion = new TaskCompletionSource<T>();
            if (!Enqueue(delegate
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
            }))
            {

                completion.TrySetCanceled();
            }
            return completion.Task;
        }

        public Task<T> EnqueueAsync<T>(Func<Task<T>> action)
        {
            if (null == action)
            {
                throw new ArgumentNullException(nameof(action));
            }

            TaskCompletionSource<T> completion = new TaskCompletionSource<T>();
            if (!Enqueue(async delegate
            {
                try
                {
                    completion.TrySetResult(await action().ConfigureAwait(false));
                }
                catch (Exception ex)
                {
                    completion.TrySetException(ex);
                }
            }))
            {

                completion.TrySetCanceled();
            }
            return completion.Task;
        }

        private bool Enqueue(Func<Task> action)
        {
            return Enqueue(action, false);
        }

        private bool Enqueue(Func<Task> action, bool priority)
        {
            bool shouldStart = false;
            lock (_sync)
            {
                if (_stopped) return false;
                if (priority)
                {
                    _queue.AddFirst(action);
                }
                else
                {
                    _queue.AddLast(action);
                }

                if (!_processing)
                {
                    _processing = true;
                    shouldStart = true;
                    _processorGeneration++;
                }
            }

            if (shouldStart)
            {

                int generation = _processorGeneration;
                Task.Run(() => ProcessLoopAsync(generation));
            }
            return true;
        }

        private const int MaxConsecutiveFrontItems = 8;

        private async Task ProcessLoopAsync(int generation)
        {
            int originalThreadId = Thread.CurrentThread.ManagedThreadId;
            _processingThreadId = originalThreadId;

            try
            {
                while (true)
                {
                    Func<Task> next;

                    lock (_sync)
                    {
                        if (0 == _queue.Count)
                        {
                            _processing = false;
                            return;
                        }

                        if (_consecutiveFrontItemCount >= MaxConsecutiveFrontItems && _queue.Count > 1)
                        {

                            next = _queue.Last.Value;
                            _queue.RemoveLast();
                            _consecutiveFrontItemCount = 0;
                        }
                        else
                        {
                            next = _queue.First.Value;
                            _queue.RemoveFirst();
                            _consecutiveFrontItemCount++;
                        }
                    }

                    if (_stopped)
                    {

                        try
                        {
                            Task t = next();
                            _ = t.ContinueWith(_ => { }, TaskContinuationOptions.OnlyOnFaulted);
                        }
                        catch { }
                        break;
                    }

                    try
                    {
                        await next().ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {

                        Trace.WriteLine("[UCP SerialQueue] OperationCanceledException in processing loop (expected during shutdown).");
                    }
                    catch (ObjectDisposedException)
                    {

                        Trace.WriteLine("[UCP SerialQueue] ObjectDisposedException in processing loop (expected during shutdown).");
                    }
                    catch (InvalidOperationException)
                    {

                        Trace.WriteLine("[UCP SerialQueue] InvalidOperationException in processing loop (may occur during shutdown).");
                    }
                    catch (TimeoutException)
                    {

                        Trace.WriteLine("[UCP SerialQueue] TimeoutException in processing loop (may occur during handshake/close).");
                    }
                    catch (Exception ex)
                    {
                        Trace.TraceError("[UCP SerialQueue] Unexpected exception in processing loop: {0}", ex.ToString());
                    }
                }
            }
            finally
            {
                // Only clear _processing if THIS loop still owns the processor:
                // a newer loop (higher generation) may have been started by an
                // Enqueue that observed _processing==false between our
                // empty-queue return and this finally.  Clearing unconditionally
                // would let yet another loop start and break the strand's
                // serialization guarantee (two processors draining one queue).
                // Likewise only reset the processing-thread id when we still
                // own it, otherwise we would clobber the newer loop's id and
                // break the re-entrancy guard.
                lock (_sync)
                {
                    if (generation == _processorGeneration)
                    {
                        _processing = false;
#pragma warning disable CS0420
                        Volatile.Write(ref _processingThreadId, -1);
#pragma warning restore CS0420
                    }
                }
            }
        }
    }
}
