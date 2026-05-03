#pragma once
/** @file ucp_vector.h
 *  @brief Container type aliases for UCP protocol stack.
 *
 *  Defines ucp::vector<T> as an alias for std::vector<T>. This indirection
 *  allows future replacement of the underlying container implementation
 *  without modifying any protocol-stack source files. When OpenPPP2
 *  provides a custom std::allocator with memory-pool management, simply
 *  change the alias here and all ucp::vector<T> instances automatically
 *  benefit from pool-based allocation.
 *
 *  Similarly, ucp::array<T,N> aliases std::array<T,N>, ucp::string
 *  aliases std::string, and ucp::unique_ptr<T> aliases
 *  std::unique_ptr<T>.
 *
 *  Usage rule: ALL container types in ucp/ headers and sources MUST
 *  use the ucp:: aliases. Direct use of std::vector, std::string,
 *  std::unique_ptr, etc. in protocol-stack code is forbidden.
 */

#include <vector>
#include <array>
#include <string>
#include <memory>
#include <cstdint>

namespace ucp {

/** @brief Dynamic array alias — replaceable with custom allocator vector. */
template <typename T>
using vector = std::vector<T>;

/** @brief Fixed-size array alias. */
template <typename T, std::size_t N>
using array = std::array<T, N>;

/** @brief String alias — replaceable with custom allocator string. */
using string = std::string;

/** @brief Unique pointer alias — replaceable with custom deleter. */
template <typename T>
using unique_ptr = std::unique_ptr<T>;

/** @brief Shared pointer alias. */
template <typename T>
using shared_ptr = std::shared_ptr<T>;

/** @brief Weak pointer alias. */
template <typename T>
using weak_ptr = std::weak_ptr<T>;

struct nullopt_t {};

constexpr nullopt_t nullopt{};

template <typename T>
class optional {
    T value_;
    bool has_value_;
public:
    optional() : value_(), has_value_(false) {}
    optional(nullopt_t) : value_(), has_value_(false) {}
    optional(const T& v) : value_(v), has_value_(true) {}
    bool has_value() const { return has_value_; }
    T& value() { return value_; }
    const T& value() const { return value_; }
    T value_or(const T& def) const { return has_value_ ? value_ : def; }
    explicit operator bool() const { return has_value_; }
    T* operator->() { return &value_; }
    const T* operator->() const { return &value_; }
    T& operator*() { return value_; }
    const T& operator*() const { return value_; }
};

} // namespace ucp
