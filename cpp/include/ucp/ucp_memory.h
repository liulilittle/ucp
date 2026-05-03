#pragma once
/** @file ucp_memory.h
 *  @brief Memory allocation abstraction layer for UCP protocol stack.
 *
 *  Provides ucp::Malloc / ucp::Mfree as drop-in replacements for standard
 *  C malloc/free.  The indirection through these inline functions allows
 *  future integration with OpenPPP2's custom std::allocator which provides
 *  memory-pool-based allocation for std::vector, std::map, std::set, etc.
 *
 *  All memory allocations within the UCP protocol stack MUST use these
 *  functions rather than calling malloc/free directly. This ensures a
 *  single point of control for switching to pool-based allocators.
 */

#include <cstdlib>
#include <cstddef>

namespace ucp {

/** @brief Allocate a block of memory from the system heap.
 *  @param size  Number of bytes to allocate (must be > 0).
 *  @return Pointer to allocated memory, or nullptr on failure.
 *
 *  Currently delegates to std::malloc. When integrating with OpenPPP2,
 *  replace this call with the pool allocator's allocate function. */
inline void* Malloc(size_t size) {
    return std::malloc(size);
}

/** @brief Free a block of memory previously allocated by ucp::Malloc.
 *  @param ptr  Pointer to the memory block to free (may be nullptr).
 *
 *  Currently delegates to std::free. When integrating with OpenPPP2,
 *  replace this call with the pool allocator's deallocate function. */
inline void Mfree(void* ptr) {
    std::free(ptr);
}

} // namespace ucp
