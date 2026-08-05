#pragma once

/** @file ucp_memory.h
 *  @brief Memory allocation primitives and shared-pointer factory helpers for the UCP library.
 *
 *  All heap allocations inside the UCP library are routed through ucp::Malloc / ucp::Mfree
 *  so that the allocator can be swapped out later (e.g. for OpenPPP2 memory-pool integration).
 *  The make_shared_object / make_shared_alloc templates provide placement-new construction
 *  with automatic cleanup via custom deleters, matching the PPP memory conventions.
 *
 *  MIT License -- Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 */

#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <memory>
#include <utility>
#include <new>
#include <type_traits>
#include <limits>

#ifndef NULLPTR
#define NULLPTR nullptr
#endif

namespace ucp {

template <typename T> using shared_ptr = std::shared_ptr<T>;

template <typename T> using unique_ptr = std::unique_ptr<T>;

template <typename T> using weak_ptr = std::weak_ptr<T>;

/** @brief Allocates raw memory from the system heap.
 *  @param size  Number of bytes to allocate.
 *  @return Pointer to the allocated memory, or NULLPTR on failure. */
inline void* Malloc(std::size_t size) noexcept {
    return std::malloc(size);
}

/** @brief Frees a memory block previously allocated by ucp::Malloc.
 *  @param ptr  Pointer to the memory block to free. */
inline void Mfree(void* ptr) noexcept {
    std::free(ptr);
}

/** @brief Frees a memory block previously allocated by a platform-aligned allocator.
 *  @param ptr  Pointer to the aligned memory block to free. */
inline void FreeAligned(void* ptr) noexcept {
#if defined(_MSC_VER) || defined(__MINGW32__)
    _aligned_free(ptr);
#else
    std::free(ptr);
#endif
}

/** @brief Allocates a shared array-like buffer with PPP allocator semantics.
 *  @tparam T        Element type.
 *  @param  length   Number of elements to allocate.
 *  @return Shared pointer with custom deleter, or empty shared_ptr on failure. */
template <typename T> shared_ptr<T> make_shared_alloc(int length) noexcept {
    static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

    if (1 > length) {
        return shared_ptr<T>();
    }

    std::size_t bytes;
    if (__builtin_mul_overflow(static_cast<std::size_t>(length), sizeof(T), &bytes)) {
        return shared_ptr<T>();
    }

    T* p = static_cast<T*>(Malloc(bytes));
    if (NULLPTR == p) {
        return shared_ptr<T>();
    }

    return shared_ptr<T>(p, [](T* ptr) noexcept { Mfree(ptr); });
}

/** @brief Constructs an object in PPP-managed memory and wraps it in shared_ptr.
 *
 *  For trivially-constructible types the raw memory is zero-initialised before
 *  placement-new runs.  For non-trivial types (those with std::string, std::vector,
 *  std::mutex members, etc.) zero-initialisation would be undefined behaviour, so
 *  only the constructor is called.
 *
 *  @tparam T    Object type to construct.
 *  @tparam A    Constructor argument types.
 *  @param  args  Forwarded constructor arguments.
 *  @return Shared pointer to the constructed object, or empty shared_ptr on failure. */
template <typename T, typename... A> shared_ptr<T> make_shared_object(A&&... args) noexcept {
    static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

    void* memory = Malloc(sizeof(T));
    if (NULLPTR == memory) {
        return shared_ptr<T>();
    }

    if (std::is_trivially_constructible<T>::value) {
        std::memset(memory, 0, sizeof(T));
    }

    T* object = NULLPTR;
    try {
        object = new (memory) T(std::forward<A>(args)...);
    } catch (...) {
        Mfree(memory);
        return shared_ptr<T>();
    }

    return shared_ptr<T>(object, [](T* p) noexcept {
        p->~T();
        Mfree(p);
    });
}

} // namespace ucp
