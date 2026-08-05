#pragma once

/**
 * MIT License
 *
 * Copyright (c) 2026 PPP PRIVATE NETWORK™ X
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file ucp_vector.h
 *  @brief Standard library type aliases for the UCP namespace.
 *
 *  Provides ucp-namespaced aliases for std containers (vector, array, string,
 *  unique_ptr, shared_ptr, weak_ptr, map, unordered_map, set, unordered_set,
 *  deque, queue, multimap) plus a minimal optional<T> implementation.
 *
 *  Defines the NULLPTR macro as a portable nullptr replacement so that all
 *  UCP code uses the same null-pointer constant regardless of C++ standard level.
 */

#include <vector>
#include <array>
#include <string>
#include <memory>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <deque>
#include <queue>
#include <functional>
#include <utility>
#include <type_traits>
#include <new>
#include "ucp_memory.h"

#ifndef NULLPTR
#define NULLPTR nullptr
#endif

namespace ucp {

template <typename T> using vector = std::vector<T>;

template <typename T, std::size_t N> using array = std::array<T, N>;

using string = std::string;

template <typename K, typename V, typename Compare = std::less<K>> using map = std::map<K, V, Compare>;

template <typename K, typename V> using unordered_map = std::unordered_map<K, V>;

template <typename K> using set = std::set<K>;

template <typename K> using unordered_set = std::unordered_set<K>;

template <typename T> using deque = std::deque<T>;

template <typename T> using queue = std::queue<T>;

template <typename K, typename V, typename Compare = std::less<K>> using multimap = std::multimap<K, V, Compare>;

template <typename Sig> using function = std::function<Sig>;

template <typename T1, typename T2> using pair = std::pair<T1, T2>;

struct nullopt_t {};

constexpr nullopt_t nullopt{};

template <typename T> class optional {

    typename std::aligned_storage<sizeof(T), alignof(T)>::type storage_;

    bool engaged_;

    T* ptr() noexcept { return reinterpret_cast<T*>(&storage_); }

    const T* ptr() const noexcept { return reinterpret_cast<const T*>(&storage_); }

  public:
    optional() noexcept : engaged_(false) {}

    optional(nullopt_t) noexcept : engaged_(false) {}

    optional(const T& v) : engaged_(false) {
        ::new (ptr()) T(v);
        engaged_ = true;
    }

    ~optional() noexcept {
        if (engaged_) {
            ptr()->~T();
        }
    }

    optional(const optional& other) : engaged_(false) {
        if (other.engaged_) {
            ::new (ptr()) T(*other.ptr());
            engaged_ = true;
        }
    }

    optional& operator=(const optional& other) {
        if (this != &other) {
            if (engaged_) {
                ptr()->~T();
                engaged_ = false;
            }
            if (other.engaged_) {
                ::new (ptr()) T(*other.ptr());
                engaged_ = true;
            }
        }
        return *this;
    }

    optional& operator=(const T& v) {
        if (engaged_) {
            *ptr() = v;
        } else {
            ::new (ptr()) T(v);
            engaged_ = true;
        }
        return *this;
    }

    bool has_value() const noexcept { return engaged_; }

    T& value() noexcept { return *ptr(); }

    const T& value() const noexcept { return *ptr(); }

    T value_or(const T& def) const noexcept { return engaged_ ? *ptr() : def; }

    explicit operator bool() const noexcept { return engaged_; }

    T* operator->() noexcept { return ptr(); }

    const T* operator->() const noexcept { return ptr(); }

    T& operator*() noexcept { return *ptr(); }

    const T& operator*() const noexcept { return *ptr(); }
};

} // namespace ucp
