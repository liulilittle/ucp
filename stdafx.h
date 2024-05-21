#pragma once

#include <stdio.h>
#include <stddef.h>

#if !defined(NULL)
#define NULL 0
#endif

#if defined(_DEBUG)
#if !defined(DEBUG)
#define DEBUG 1
#endif
#endif

#if defined(DEBUG)
#if !defined(_DEBUG)
#define _DEBUG 1
#endif
#endif

#if defined(_WIN64)
#if !defined(WIN64)
#define WIN64 1
#endif
#endif

#if defined(WIN64)
#if !defined(_WIN64)
#define _WIN64 1
#endif
#endif

#if defined(_WIN64)
#if !defined(_WIN32)
#define _WIN32 1
#endif
#endif

#if defined(_WIN32)
#if !defined(WIN32)
#define WIN32 1
#endif
#endif

#if defined(WIN32)
#if !defined(_WIN32)
#define _WIN32 1
#endif
#endif

#if defined(__linux__)
#if !defined(_LINUX)
#define _LINUX 1
#endif

#if !defined(LINUX)
#define LINUX 1
#endif
#elif defined(__APPLE__) && defined(__MACH__)
#if !defined(_MACOS)
#define _MACOS 1
#endif

#if !defined(MACOS)
#define MACOS 1
#endif
#endif

#if defined(__ANDROID__) || __ANDROID_API__ > 0
#if !defined(_ANDROID)
#define _ANDROID 1
#endif
#endif

#if defined(_ANDROID)
#if !defined(ANDROID)
#define ANDROID 1
#endif
#endif

#if defined(ANDROID)
#if !defined(_ANDROID)
#define _ANDROID 1
#endif
#endif

#if defined(_ANDROID)
#if !defined(_LINUX)
#define _LINUX 1
#endif

#if !defined(LINUX)
#define LINUX 1
#endif

#if !defined(__clang__)
#define __clang__ 1
#endif
#endif

#if defined(__harmony__)
#if !defined(_HARMONYOS)
#define _HARMONYOS 1
#endif
#endif

#if defined(_HARMONYOS)
#if !defined(HARMONYOS)
#define HARMONYOS 1
#endif
#endif

#if defined(HARMONYOS)
#if !defined(_HARMONYOS)
#define _HARMONYOS 1
#endif
#endif

#if ((defined(__IPHONE_OS_VERSION_MIN_REQUIRED)) || (defined(__APPLE__) && defined(__MACH__) && defined(TARGET_OS_IOS)))
#if !defined(_IPHONE)
#define _IPHONE 1
#endif

#if !defined(IPHONE)
#define IPHONE 1
#endif
#endif

#if defined(_WIN32)
#if defined(_MSC_VER) && defined(_M_IX86) && !defined(_M_IA64) && !defined(_M_X64)
#define __ORDER_LITTLE_ENDIAN__     1
#define __ORDER_BIG_ENDIAN__        0
#define __BYTE_ORDER__              __ORDER_LITTLE_ENDIAN__
#elif defined(_MSC_VER) && (defined(_M_IA64) || defined(_M_X64))
#define __ORDER_LITTLE_ENDIAN__     1
#define __ORDER_BIG_ENDIAN__        0
#define __BYTE_ORDER__              __ORDER_LITTLE_ENDIAN__
#else
#define __ORDER_LITTLE_ENDIAN__     0
#define __ORDER_BIG_ENDIAN__        1
#define __BYTE_ORDER__              __ORDER_LITTLE_ENDIAN__
#endif
#endif

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#ifndef R_OK
#define R_OK 4 /* Test for read permission. */
#endif

#ifndef W_OK
#define W_OK 2 /* Test for write permission. */
#endif

#ifndef X_OK
#define X_OK 1 /* Test for execute permission. */
#endif

#ifndef F_OK
#define F_OK 0 /* Test for existence. */
#endif

#ifndef elif
#define elif else if
#endif

#ifndef nameof
#define nameof(variable) #variable
#endif

#ifndef arraysizeof
#define arraysizeof(array_) (sizeof(array_) / sizeof(*array_))
#endif

#if !defined(_WIN32)
#define sscanf_s sscanf
#endif

// stddef.h
// offsetof
#ifndef offset_of
#define offset_of(s,m) ((::size_t)&reinterpret_cast<char const volatile&>((((s*)0)->m)))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type*)((char*)static_cast<const decltype(((type*)0)->member)*>(ptr) - offset_of(type,member))) 
#endif

#include <stdint.h>
#include <signal.h>
#include <limits.h>
#include <time.h>

#if defined(_MACOS)
#include <stdlib.h>
#else
#include <malloc.h>
#endif

#include <type_traits>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <atomic>
#include <thread>
#include <utility>
#include <functional>
#include <memory>
#include <string>
#include <list>
#include <map>
#include <set>
#include <regex>
#include <vector>
#include <fstream>
#include <unordered_set>
#include <unordered_map>

#ifndef BOOST_BEAST_VERSION_HPP
#define BOOST_BEAST_VERSION_HPP

#include <boost/beast/core/detail/config.hpp>
#include <boost/config.hpp>

/*  BOOST_BEAST_VERSION

    Identifies the API version of Beast.

    This is a simple integer that is incremented by one every
    time a set of code changes is merged to the develop branch.
*/
#define BOOST_BEAST_VERSION 322
#define BOOST_BEAST_VERSION_STRING "ucp"
#endif

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>

#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>

#include <boost/lockfree/queue.hpp>
#include <boost/lockfree/stack.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if defined(__GNUC__) /* __FUNCTION__ */
#define __FUNC__ __PRETTY_FUNCTION__
#elif defined(_MSC_VER)
#define __FUNC__ __FUNCSIG__
#else
#define __FUNC__ __func__
#endif

#if defined(_WIN32)
namespace boost { // boost::asio::posix::stream_descriptor
    namespace asio {
        namespace posix {
            typedef boost::asio::windows::stream_handle stream_descriptor;
        }
    }
}
#include <WinSock2.h>
#else
namespace boost {
    namespace asio {
        typedef io_service io_context;
    }
}
#endif

#if defined(JEMALLOC)
#if defined(_WIN32)
#ifdef __cplusplus 
extern "C" {
#endif
    void* je_malloc(size_t size);
    void                                                                    je_free(void* size);
    int                                                                     je_mallctl(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
#ifdef __cplusplus 
}
#endif
#else
#define JEMALLOC_NO_DEMANGLE
#include <jemalloc/jemalloc.h>
#endif
#endif

namespace ucp {
    using Byte                                                              = unsigned char;
    using acceptor                                                          = std::shared_ptr<boost::asio::ip::tcp::acceptor>;
    using deadline_timer                                                    = std::shared_ptr<boost::asio::deadline_timer>;

    using string                                                            = std::string;

    template <class TValue>
    using unordered_set                                                     = std::unordered_set<TValue>;

    template <class TKey, class TValue>
    using unordered_map                                                     = std::unordered_map<TKey, TValue>;

    template <class TValue>
    using list                                                              = std::list<TValue>;

    template <class TValue>
    using queue                                                             = list<TValue>;

    template <class TValue>
    using vector                                                            = std::vector<TValue>;

    template <typename T>
    constexpr T                                                             Malign(const T size, int alignment) noexcept {
        return (T)(((uint64_t)size + alignment - 1) & ~(static_cast<unsigned long long>(alignment) - 1));
    }

    inline void* Malloc(size_t size) noexcept {
        if (!size) {
            return NULL;
        }

        size = Malign(size, 16);
#if defined(JEMALLOC)
        return (void*)::je_malloc(size);
#else
        return (void*)::malloc(size);
#endif
    }

    inline void                                                             Mfree(const void* p) noexcept {
        if (p) {
#if defined(JEMALLOC)
            ::je_free((void*)p);
#else
            ::free((void*)p);
#endif
        }
    }

    template <typename T>
    std::shared_ptr<T>                                                      make_shared_alloc(int length) noexcept {
        static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

        // https://pkg.go.dev/github.com/google/agi/core/os/device
        // ARM64v8a: __ALIGN(8)
        // ARMv7a  : __ALIGN(4)
        // X86_64  : __ALIGN(8)
        // X64     : __ALIGN(4)
        if (length < 1) {
            return NULL;
        }

        T* p = (T*)Malloc(length * sizeof(T));
        return std::shared_ptr<T>(p, Mfree);
    }

    template <typename T, typename... A>
    std::shared_ptr<T>                                                      make_shared_object(A&&... args) noexcept {
        static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

        void* memory = Malloc(sizeof(T));
        if (NULL == memory) {
            return NULL;
        }

        T* m = new (memory) T(std::forward<A&&>(args)...);
        return std::shared_ptr<T>(m,
            [](T* p) noexcept {
                if (NULL != p) {
                    p->~T();
                    Mfree(p);
                }
            });
    }

    void                                                                    SetThreadPriorityToMaxLevel() noexcept;

    void                                                                    SetProcessPriorityToMaxLevel() noexcept;

    int                                                                     RandomNext(volatile unsigned int* seed) noexcept;

    int                                                                     RandomNext(int min, int max) noexcept;

    uint64_t                                                                GetTickCount(bool microseconds = false) noexcept;

    boost::asio::ip::address                                                StringToAddress(const char* s, boost::system::error_code& ec) noexcept;

    bool                                                                    FileWriteAllBytes(const char* path, const void* data, int length) noexcept;

    std::string                                                             GetFullExecutionFilePath() noexcept;

    std::string                                                             GetCurrentDirectoryPath() noexcept;

    std::string                                                             GetApplicationStartupPath() noexcept;

    std::string                                                             GetExecutionFileName() noexcept;

    int                                                                     GetCurrentProcessId() noexcept;

    std::string                                                             StrFormatByteSize(int64_t size) noexcept;

    template <typename _Ty>
    _Ty                                                                     PaddingLeft(const _Ty& s, int count, char padding_char) noexcept
    {
        int string_length = (int)s.size();
        if (count < 1 || count <= string_length)
        {
            return s;
        }

        _Ty c = _Ty(1ul, padding_char);
        _Ty r = s;
        for (int i = 0, loop = count - string_length; i < loop; i++)
        {
            r = c + r;
        }

        return r;
    }

    template <typename _Ty>
    _Ty                                                                     PaddingRight(const _Ty& s, int count, char padding_char) noexcept
    {
        int string_length = (int)s.size();
        if (count < 1 || count <= string_length)
        {
            return s;
        }

        _Ty c = _Ty(1ul, padding_char);
        _Ty r = s;
        for (int i = 0, loop = count - string_length; i < loop; i++)
        {
            r = r + c;
        }

        return r;
    }

    bool                                                                    HideConsoleCursor(bool value) noexcept;

    bool                                                                    SetConsoleCursorPosition(int x, int y) noexcept;

    bool                                                                    GetConsoleWindowSize(int& x, int& y) noexcept;

    bool                                                                    ClearConsoleOutputCharacter() noexcept;

    bool                                                                    AddShutdownApplicationEventHandler(std::function<bool()> e) noexcept;

    bool                                                                    ToBoolean(const char* s) noexcept;

    bool                                                                    GetCommandArgument(const char* name, int argc, const char** argv, bool defaultValue) noexcept;

    std::string                                                             GetCommandArgument(const char* name, int argc, const char** argv, const char* defaultValue) noexcept;

    std::string                                                             GetCommandArgument(const char* name, int argc, const char** argv, const std::string& defaultValue) noexcept;

    bool                                                                    IsInputHelpCommand(int argc, const char* argv[]) noexcept;

    bool                                                                    HasCommandArgument(const char* name, int argc, const char** argv) noexcept;

    std::string                                                             GetCommandArgument(int argc, const char** argv) noexcept;

    std::string                                                             GetCommandArgument(const char* name, int argc, const char** argv) noexcept;

    bool                                                                    Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;

    bool                                                                    Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;

    bool                                                                    Closesocket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

    bool                                                                    Closesocket(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;

    bool                                                                    Closesocket(const boost::asio::ip::tcp::socket& socket) noexcept;

    bool                                                                    Closesocket(const boost::asio::ip::udp::socket& socket) noexcept;

    bool                                                                    OpenDatagramSocket(boost::asio::ip::udp::socket& socket, const boost::asio::ip::address& address, int port, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

    bool                                                                    OpenDatagramSocket(
        const boost::asio::ip::udp::socket&                                 socket,
        const boost::asio::ip::address&                                     listenIP,
        int                                                                 listenPort,
        bool                                                                opened) noexcept;

    inline bool                                                             OpenDatagramSocket(
        const boost::asio::ip::udp::socket&                                 socket,
        const boost::asio::ip::address&                                     listenIP,
        int                                                                 listenPort) noexcept { return OpenDatagramSocket(socket, listenIP, listenPort, false); }

#if defined(JEMALLOC)
    void                                                                    jemaillc_areans_set_default() noexcept;
#endif

    boost::asio::ip::udp::endpoint                                          ip_v6_to_v4(const boost::asio::ip::udp::endpoint& ep) noexcept;

    boost::asio::ip::udp::endpoint                                          ip_v4_to_v6(const boost::asio::ip::udp::endpoint& ep) noexcept;

    boost::asio::ip::tcp::endpoint                                          ip_v6_to_v4(const boost::asio::ip::tcp::endpoint& ep) noexcept;

    boost::asio::ip::tcp::endpoint                                          ip_v4_to_v6(const boost::asio::ip::tcp::endpoint& ep) noexcept;

    bool                                                                    ip_is_invalid(const boost::asio::ip::address& address) noexcept;

    void                                                                    socket_flash_mode(bool value) noexcept;

    void                                                                    socket_adjust(int sockfd, bool in4) noexcept;

    bool                                                                    socket_adjust(boost::asio::ip::udp::socket& socket) noexcept;

    bool                                                                    socket_adjust(boost::asio::ip::tcp::socket& socket) noexcept;

    bool                                                                    socket_adjust(boost::asio::ip::tcp::acceptor& socket) noexcept;

    template <typename T>
    constexpr T&                                                            constantof(const T& v) noexcept
    {
        return const_cast<T&>(v);
    }

    template <typename T>
    constexpr T*                                                            constantof(const T* v) noexcept
    {
        return const_cast<T*>(v);
    }

    template <typename T>
    constexpr T&&                                                           constant0f(const T&& v) noexcept
    {
        return const_cast<T&&>(v);
    }

    template <typename _Ty> /* 65279u */
    _Ty                                                                     ZTrim(const _Ty& s) noexcept
    {
        std::size_t length = s.size();
        if (length == 0)
        {
            return _Ty();
        }

        char* r = (char*)Malloc(length);
        char* p = (char*)s.data();

        std::size_t l = 0;
        for (std::size_t i = 0; i < length;)
        {
            std::size_t c0 = (unsigned char)p[i];
            std::size_t c1 = c0;
            std::size_t c2 = c0;

            std::size_t n = i + 1;
            if (n < length)
            {
                c1 = c0 | (unsigned char)p[n] << 8; // LE
                c2 = c0 << 8 | (unsigned char)p[n]; // BE
            }

            if (c1 == 65279u || c2 == 65279u)
            {
                i += 2;
            }
            else
            {
                i++;
                r[l++] = (signed char)c0;
            }
        }

        _Ty result(r, l);
        Mfree(r);
        return result;
    }

    template <typename _Ty>
    _Ty                                                                     ATrim(const _Ty& s) noexcept
    {
        if (s.empty())
        {
            return s;
        }

        _Ty r;
        for (size_t i = 0, l = s.size(); i < l; ++i)
        {
            unsigned char ch = (unsigned char)s[i];
            if (isspace(ch))
            {
                continue;
            }
            else
            {
                r.append(1, ch);
            }
        }
        return r;
    }

    template <typename _Ty>
    _Ty                                                                     LTrim(const _Ty& s) noexcept
    {
        _Ty str = s;
        if (str.empty())
        {
            return str;
        }

        int64_t pos = -1;
        for (size_t i = 0, l = str.size(); i < l; ++i)
        {
            unsigned char ch = (unsigned char)str[i];
            if (isspace(ch))
            {
                pos = (static_cast<int64_t>(i) + 1);
            }
            else
            {
                break;
            }
        }

        if (pos >= 0)
        {
            if (pos >= (int64_t)str.size())
            {
                return "";
            }

            str = str.substr((size_t)pos);
        }
        return str;
    }

    template <typename _Ty>
    _Ty                                                                     RTrim(const _Ty& s) noexcept
    {
        _Ty str = s;
        if (str.empty())
        {
            return str;
        }

        int64_t pos = -1;
        int64_t i = (int64_t)str.size();
        i--;
        for (; i >= 0u; --i)
        {
            unsigned char ch = (unsigned char)str[(size_t)i];
            if (isspace(ch))
            {
                pos = i;
            }
            else
            {
                break;
            }
        }

        if (pos >= 0)
        {
            if (0 >= pos)
            {
                return "";
            }

            str = str.substr(0, (size_t)pos);
        }
        return str;
    }

    template <typename _Ty>
    _Ty                                                                     ToUpper(const _Ty& s) noexcept
    {
        _Ty r = s;
        if (!r.empty())
        {
            std::transform(s.begin(), s.end(), r.begin(), toupper);
        }
        return r;
    }

    template <typename _Ty>
    _Ty                                                                     ToLower(const _Ty& s) noexcept
    {
        _Ty r = s;
        if (!r.empty())
        {
            std::transform(s.begin(), s.end(), r.begin(), tolower);
        }
        return r;
    }

    template <typename _Ty>
    _Ty                                                                     Replace(const _Ty& s, const _Ty& old_value, const _Ty& new_value) noexcept
    {
        _Ty r = s;
        if (r.empty() || old_value.empty())
        {
            return r;
        }

        do
        {
            typename _Ty::size_type pos = r.find(old_value);
            if (pos != _Ty::npos)
            {
                r.replace(pos, old_value.length(), new_value);
            }
            else
            {
                break;
            }
        } while (1);
        return r;
    }

    template <typename _Ty>
    int                                                                     Tokenize(const _Ty& str, vector<_Ty>& tokens, const _Ty& delimiters) noexcept
    {
        if (str.empty())
        {
            return 0;
        }
        elif(delimiters.empty())
        {
            tokens.emplace_back(str);
            return 1;
        }

        char* deli_ptr = (char*)delimiters.data();
        char* deli_endptr = deli_ptr + delimiters.size();
        char* data_ptr = (char*)str.data();
        char* data_endptr = data_ptr + str.size();
        char* last_ptr = NULL;

        int length = 0;
        int seg = 0;
        while (data_ptr < data_endptr)
        {
            int ch = *data_ptr;
            int b = 0;
            for (char* p = deli_ptr; p < deli_endptr; p++)
            {
                if (*p == ch)
                {
                    b = 1;
                    break;
                }
            }

            if (b)
            {
                if (seg)
                {
                    int sz = data_ptr - last_ptr;
                    if (sz > 0)
                    {
                        length++;
                        tokens.emplace_back(_Ty(last_ptr, sz));
                    }
                    seg = 0;
                }
            }
            elif(!seg)
            {
                seg = 1;
                last_ptr = data_ptr;
            }

            data_ptr++;
        }

        if ((seg && last_ptr) && last_ptr < data_ptr)
        {
            length++;
            tokens.emplace_back(_Ty(last_ptr, data_ptr - last_ptr));
        }
        return length;
    }
}