// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
// #define ENOENT           2      /* No such file or directory */
// #define EAGAIN          11      /* Try again */

#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <assert.h>

#include <sys/types.h>

#if defined(_WIN32)
#include <stdint.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <qos2.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "qwave.lib")
#pragma comment(lib, "crypt32.lib")
#else
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

#include <fcntl.h>
#include <errno.h>

#if defined(_MACOS)
#include <errno.h>
#elif defined(_LINUX)
#include <error.h>
#endif

#if defined(_WIN32)
#include <io.h>
#include <Windows.h>
#include <timeapi.h>
#include <mmsystem.h>
#else
#include <unistd.h>
#include <sched.h>
#include <pthread.h>

#if defined(_MACOS)
#include <libproc.h>
#endif

#if defined(_LINUX)
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/syscall.h>
#else
#include <mach-o/dyld.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#endif

#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#endif

#include <stdio.h>
#include <math.h>

#include <cmath>
#include <memory>
#include <cstdlib>
#include <chrono>

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ip.h#L26
// https://man7.org/linux/man-pages/man7/ip.7.html
#if defined(_WIN32)
#define IPTOS_TOS_MASK      0x1E
#define IPTOS_TOS(tos)      ((tos) & IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_MINCOST       0x02
#endif

namespace ucp
{
    static bool                                                         SOCKET_FLASH_MODE = false;

#if defined(JEMALLOC)
    void jemaillc_areans_set_default() noexcept
    {
        size_t dirty_decay_ms = 0;
        size_t muzzy_decay_ms = 0;

        je_mallctl("arenas.dirty_decay_ms", NULL, 0, reinterpret_cast<void*>(&dirty_decay_ms), sizeof(dirty_decay_ms));
        je_mallctl("arenas.muzzy_decay_ms", NULL, 0, reinterpret_cast<void*>(&muzzy_decay_ms), sizeof(muzzy_decay_ms));
    }
#endif

    bool FileWriteAllBytes(const char* path, const void* data, int length) noexcept
    {
        if (NULL == path || length < 0)
        {
            return false;
        }

        if (NULL == data && length != 0)
        {
            return false;
        }

        FILE* f = fopen(path, "wb+");
        if (NULL == f)
        {
            return false;
        }

        if (length > 0)
        {
            fwrite((char*)data, length, 1, f);
        }

        fflush(f);
        fclose(f);
        return true;
    }

    void SetThreadPriorityToMaxLevel() noexcept
    {
#if defined(_WIN32)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#else
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_;
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); /* SCHED_RR */
        pthread_setschedparam(pthread_self(), SCHED_FIFO, &param_); /* pthread_getthreadid_np() */
#endif
    }

    void SetProcessPriorityToMaxLevel() noexcept
    {
#if defined(_WIN32)
        SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
#else
#if defined(_LINUX)
        char path_[PATH_MAX];
        snprintf(path_, sizeof(path_), "/proc/%d/oom_adj", getpid());

        char level_[] = "-17";
        FileWriteAllBytes(path_, level_, sizeof(level_));
#endif

        /* Processo pai deve ter prioridade maior que os filhos. */
        setpriority(PRIO_PROCESS, getpid(), -20);

#if defined(_LINUX)
        /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
        struct sched_param param_;
        param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR

        if (sched_setscheduler(getpid(), SCHED_RR, &param_) < 0) {
            sched_setscheduler(getpid(), SCHED_FIFO, &param_);
        }
#endif
#endif
    }

    // On the Android platform, call: boost::asio::ip::address::from_string function will lead to collapse, 
    // Only is to compile the Release code and opened the compiler code optimization.
    boost::asio::ip::address StringToAddress(const char* s, boost::system::error_code& ec) noexcept
    {
        ec = boost::asio::error::invalid_argument;
        if (NULL == s || *s == '\x0')
        {
            return boost::asio::ip::address_v4::any();
        }

        struct in_addr addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, s, &addr6) > 0)
        {
            boost::asio::ip::address_v6::bytes_type bytes;
            memcpy(bytes.data(), addr6.s6_addr, bytes.size());

            ec.clear();
            return boost::asio::ip::address_v6(bytes);
        }
        else if (inet_pton(AF_INET, s, &addr4) > 0)
        {
            ec.clear();
            return boost::asio::ip::address_v4(htonl(addr4.s_addr));
        }
        else
        {
            return boost::asio::ip::address_v4::any();
        }
    }

    int RandomNext(volatile unsigned int* seed) noexcept
    {
        unsigned int next = *seed;
        int result;

        next *= 1103515245;
        next += 12345;
        result = (unsigned int)(next / 65536) % 2048;

        next *= 1103515245;
        next += 12345;
        result <<= 10;
        result ^= (unsigned int)(next / 65536) % 1024;

        next *= 1103515245;
        next += 12345;
        result <<= 10;
        result ^= (unsigned int)(next / 65536) % 1024;

        *seed = next;
        return result;
    }

    int RandomNext(int min, int max) noexcept
    {
        static volatile unsigned int seed = (unsigned int)(GetTickCount() / 1000);

        int v = RandomNext(&seed);
        return v % (max - min + 1) + min;
    }

    uint64_t GetTickCount(bool microseconds) noexcept
    {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t tick = 0;
        if (microseconds)
        {
            tick = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
        }
        else
        {
            tick = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        }
        return tick;
    }

    std::string GetFullExecutionFilePath() noexcept
    {
#if defined(_WIN32)
        char exe[8096]; /* MAX_PATH */
        GetModuleFileNameA(NULL, exe, sizeof(exe));
        return exe;
#elif defined(_MACOS)
        char path[PATH_MAX];
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0)
        {
            return path;
        }

#if defined(PROC_PIDPATHINFO_MAXSIZE)
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        proc_pidpath(getpid(), pathbuf, sizeof(pathbuf));
        return pathbuf;
#else
        return "";
#endif
#else
        char sz[PATH_MAX + 1];
        int dw = readlink("/proc/self/exe", sz, PATH_MAX);
        sz[dw] = '\x0';
        return dw < 1 ? "" : sz;
#endif
    }

    std::string GetCurrentDirectoryPath() noexcept
    {
#if defined(_WIN32)
        char cwd[8096];
        ::GetCurrentDirectoryA(sizeof(cwd), cwd);
        return cwd;
#else
        char sz[PATH_MAX + 1];
        return ::getcwd(sz, PATH_MAX);
#endif
    }

    std::string GetApplicationStartupPath() noexcept
    {
        std::string exe = GetFullExecutionFilePath();
#if defined(_WIN32)
        std::size_t pos = exe.rfind('\\');
#else
        std::size_t pos = exe.rfind('/');
#endif
        if (pos == std::string::npos)
        {
            return exe;
        }
        else
        {
            return exe.substr(0, pos);
        }
    }

    std::string GetExecutionFileName() noexcept
    {
        std::string exe = GetFullExecutionFilePath();
#if defined(_WIN32)
        std::size_t pos = exe.rfind('\\');
#else
        std::size_t pos = exe.rfind('/');
#endif
        if (pos == std::string::npos)
        {
            return exe;
        }
        else
        {
            return exe.substr(pos + 1);
        }
    }

    int GetCurrentProcessId() noexcept
    {
#if defined(_WIN32) || defined(_WIN64)
        return ::GetCurrentProcessId();
#else
        return ::getpid();
#endif
    }

    std::string StrFormatByteSize(int64_t size) noexcept
    {
        static const char* aszByteUnitsNames[] = { "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB", "DB", "NB" };

        long double d = (long double)llabs(size);
        unsigned int i = 0;
        while (i < 10 && d > 1024)
        {
            d /= 1024;
            i++;
        }

        char sz[1000 + 1];
        snprintf(sz, 1000, "%Lf %s", d, aszByteUnitsNames[i]);
        return sz;
    }

    bool SetConsoleCursorPosition(int x, int y) noexcept
    {
#if defined(_WIN32)
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL == hConsole)
        {
            return false;
        }

        COORD coord = { (SHORT)x, (SHORT)y };
        return ::SetConsoleCursorPosition(hConsole, coord);
#else
        return ::fprintf(stdout, "\033[%d;%dH", x, y) > 0;
#endif
    }

    bool GetConsoleWindowSize(int& x, int& y) noexcept
    {
        x = 0;
        y = 0;

#if defined(_WIN32)
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL == hConsole)
        {
            return false;
        }

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!::GetConsoleScreenBufferInfo(hConsole, &csbi))
        {
            return false;
        }

        y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        x = csbi.srWindow.Right - csbi.srWindow.Left + 1;
#else
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1)
        {
            return false;
        }

        x = w.ws_col;
        y = w.ws_row;
#endif
        return true;
    }

    bool ClearConsoleOutputCharacter() noexcept
    {
#if defined(_WIN32)
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL != hStdOut)
        {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(hStdOut, &csbi))
            {
                DWORD consoleSize = csbi.dwSize.X * csbi.dwSize.Y;
                DWORD charsWritten;

                FillConsoleOutputCharacter(hStdOut, ' ', consoleSize, { 0, 0 }, &charsWritten);
                FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, consoleSize, { 0, 0 }, &charsWritten);

                if (::SetConsoleCursorPosition(hStdOut, { 0, 0 }))
                {
                    return true;
                }
            }
        }

        return system("cls") == 0;
#else
        return system("clear") == 0;
#endif
    }

    bool HideConsoleCursor(bool value) noexcept
    {
#if defined(_WIN32)
        HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (NULL != consoleHandle)
        {
            CONSOLE_CURSOR_INFO cursorInfo;
            if (GetConsoleCursorInfo(consoleHandle, &cursorInfo))
            {
                cursorInfo.bVisible = !value;
                if (SetConsoleCursorInfo(consoleHandle, &cursorInfo))
                {
                    return true;
                }
            }
        }

        return false;
#else
        if (value)
        {
            fprintf(stdout, "\033[?25l");
        }
        else
        {
            fprintf(stdout, "\033[?25h");
        }
        return true;
#endif
    }

    bool AddShutdownApplicationEventHandler(std::function<bool()> e) noexcept
    {
        static std::function<bool()> eeh = NULL;

        auto SIG_EEH =
            [](int signo) noexcept -> void
            {
                std::function<bool()> e = std::move(eeh);
                if (NULL != e)
                {
                    eeh = NULL;
                    e();
                }
                else
                {
                    signal(signo, SIG_DFL);
                    raise(signo);
                }
            };

        typedef void (*__sa_handler_unix__) (int); /* __sighandler_t */

        __sa_handler_unix__ SIG_IGN_V = SIG_IGN;
        __sa_handler_unix__ SIG_EEH_V = SIG_EEH;

        if (NULL != e)
        {
            eeh = e;
        }
        else
        {
            eeh = NULL;
            SIG_EEH_V = SIG_DFL;
            SIG_IGN_V = SIG_DFL;
        }

        /* retrieve old and set new handlers */
        /* restore prevouis signal actions   */
#ifdef _ANDROID
        signal(35, SIG_IGN_V); // FDSCAN(SI_QUEUE)
#endif

#ifdef SIGPIPE
        signal(SIGPIPE, SIG_IGN_V);
#endif

#ifdef SIGHUP
        signal(SIGHUP, SIG_IGN_V);
#endif

#ifdef SIGINT
        signal(SIGINT, SIG_EEH_V);
#endif

#ifdef SIGTERM
        signal(SIGTERM, SIG_EEH_V);
#endif

#ifdef SIGSYS
        signal(SIGSYS, SIG_EEH_V);
#endif

#ifdef SIGIOT
        signal(SIGIOT, SIG_EEH_V);
#endif

#ifdef SIGUSR1
        signal(SIGUSR1, SIG_EEH_V);
#endif

#ifdef SIGUSR2
        signal(SIGUSR2, SIG_EEH_V);
#endif

#ifdef SIGXCPU
        signal(SIGXCPU, SIG_EEH_V);
#endif

#ifdef SIGXFSZ
        signal(SIGXFSZ, SIG_EEH_V);
#endif

#ifdef SIGTRAP
        signal(SIGTRAP, SIG_EEH_V);
#endif

#ifdef SIGBUS
        signal(SIGBUS, SIG_EEH_V);
#endif

#ifdef SIGQUIT
        signal(SIGQUIT, SIG_EEH_V);
#endif

        /* Some specific cpu architecture platforms do not support this signal macro, */
        /* Such as mips and mips64 instruction set cpu architecture platforms.        */
#ifdef SIGSTKFLT
        signal(SIGSTKFLT, SIG_EEH_V);
#endif

#ifdef SIGSEGV
        signal(SIGSEGV, SIG_EEH_V);
#endif

#ifdef SIGFPE
        signal(SIGFPE, SIG_EEH_V);
#endif

#ifdef SIGABRT
        signal(SIGABRT, SIG_EEH_V);
#endif

#ifdef SIGILL
        signal(SIGILL, SIG_EEH_V);
#endif
        return true;
    }

    bool ToBoolean(const char* s) noexcept
    {
        if (NULL == s || *s == '\x0')
        {
            return false;
        }

        char ch = s[0];
        if (ch == '0' || ch == ' ')
        {
            return false;
        }

        if (ch == 'f' || ch == 'F')
        {
            return false;
        }

        if (ch == 'n' || ch == 'N')
        {
            return false;
        }

        if (ch == 'c' || ch == 'C')
        {
            return false;
        }

        return true;
    }

    bool GetCommandArgument(const char* name, int argc, const char** argv, bool defaultValue) noexcept
    {
        std::string str = GetCommandArgument(name, argc, argv);
        if (str.empty())
        {
            return defaultValue;
        }

        return ToBoolean(str.data());
    }

    std::string GetCommandArgument(const char* name, int argc, const char** argv, const char* defaultValue) noexcept
    {
        std::string defValue;
        if (defaultValue)
        {
            defValue = defaultValue;
        }

        return GetCommandArgument(name, argc, argv, defValue);
    }

    std::string GetCommandArgument(const char* name, int argc, const char** argv, const std::string& defaultValue) noexcept
    {
        std::string str = GetCommandArgument(name, argc, argv);
        return str.empty() ? defaultValue : str;
    }

    bool IsInputHelpCommand(int argc, const char* argv[]) noexcept
    {
        const int HELP_COMMAND_COUNT = 4;
        const char* HELP_COMMAND_LIST[HELP_COMMAND_COUNT] =
        {
            "-h",
            "--h",
            "-help",
            "--help"
        };

        for (int i = 0; i < HELP_COMMAND_COUNT; i++)
        {
            const char* command = HELP_COMMAND_LIST[i];
            if (HasCommandArgument(command, argc, argv))
            {
                return true;
            }
        }
        return false;
    }

    bool HasCommandArgument(const char* name, int argc, const char** argv) noexcept
    {
        if (NULL == name || *name == '\x0') {
            return false;
        }

        std::string commandText = GetCommandArgument(argc, argv);
        if (commandText.empty())
        {
            return false;
        }

        auto fx =
            [](std::string& commandText, const std::string& name) noexcept -> bool
            {
                std::size_t index = commandText.find(name);
                if (index == std::string::npos)
                {
                    return false;
                }

                if (index == 0)
                {
                    return true;
                }

                char ch = commandText[index - 1];
                if (ch == ' ')
                {
                    return true;
                }
                else
                {
                    return false;
                }
            };

        bool result = false;
        result = result || fx(commandText, name + std::string("="));
        result = result || fx(commandText, name + std::string(" "));
        return result;
    }

    std::string GetCommandArgument(int argc, const char** argv) noexcept
    {
        if (NULL == argv || argc <= 1)
        {
            return "";
        }

        std::string line;
        for (int i = 1; i < argc; i++)
        {
            line.append(RTrim(LTrim<std::string>(argv[i])));
            line.append(" ");
        }

        return line;
    }

    std::string GetCommandArgument(const char* name, int argc, const char** argv) noexcept
    {
        if (NULL == name || argc <= 1)
        {
            return "";
        }

        std::string key1 = name;
        if (key1.empty())
        {
            return "";
        }

        std::string key2 = key1 + " ";
        key1.append("=");

        std::string line = GetCommandArgument(argc, argv);
        if (line.empty()) {
            return "";
        }

        std::string* key = addressof(key1);
        std::size_t L = line.find(*key);
        if (L == std::string::npos)
        {
            key = addressof(key2);
            L = line.find(*key);
            if (L == std::string::npos)
            {
                return "";
            }
        }

        if (L)
        {
            char ch = line[L - 1];
            if (ch != ' ')
            {
                return "";
            }
        }

        std::string cmd;
        std::size_t M = L + key->size();
        std::size_t R = line.find(' ', L);
        if (M >= R)
        {
            R = std::string::npos;
            for (std::size_t I = M, SZ = line.size(); I < SZ; I++)
            {
                int ch = line[I];
                if (ch == ' ')
                {
                    R = I;
                    L = M;
                    break;
                }
            }

            if (!L || L == std::string::npos)
            {
                return "";
            }
        }

        if (R == std::string::npos)
        {
            if (M != line.size())
            {
                cmd = line.substr(M);
            }
        }
        else
        {
            int S = (int)(R - M);
            if (S > 0)
            {
                cmd = line.substr(M, S);
            }
        }
        return cmd;
    }

    boost::asio::ip::udp::endpoint ip_v6_to_v4(const boost::asio::ip::udp::endpoint& ep) noexcept
    {
        boost::asio::ip::address host = ep.address();
        if (host.is_v4())
        {
            return ep;
        }
        elif(host.is_v6())
        {
            boost::asio::ip::address_v6 in6 = host.to_v6();
            boost::asio::ip::address_v6::bytes_type bytes = in6.to_bytes();

#pragma pack(push, 1)
            struct IPV62V4ADDR
            {
                uint64_t R1;
                uint16_t R2;
                uint16_t R3;
                uint32_t R4;
            };
#pragma pack(pop)

            IPV62V4ADDR* in = (IPV62V4ADDR*)bytes.data();
            if (in->R1 || in->R2 || in->R3 != UINT16_MAX)
            {
                return ep;
            }

            boost::asio::ip::address_v4 r4(ntohl(in->R4));
            return boost::asio::ip::udp::endpoint(r4, ep.port());
        }
        else
        {
            return boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0);
        }
    }

    boost::asio::ip::udp::endpoint ip_v4_to_v6(const boost::asio::ip::udp::endpoint& ep) noexcept
    {
        boost::asio::ip::address host = ep.address();
        if (host.is_v4())
        {
#pragma pack(push, 1)
            struct IPV62V4ADDR
            {
                uint64_t R1;
                uint16_t R2;
                uint16_t R3;
                uint32_t R4;
            };
#pragma pack(pop)

            boost::asio::ip::address_v4 in4 = host.to_v4();
            boost::asio::ip::address_v4::bytes_type bytes = in4.to_bytes();

            IPV62V4ADDR in;
            in.R1 = 0;
            in.R2 = 0;
            in.R3 = UINT16_MAX;
            in.R4 = *(uint32_t*)bytes.data();

            boost::asio::ip::address_v6 in6(*(boost::asio::ip::address_v6::bytes_type*)&in);
            return boost::asio::ip::udp::endpoint(in6, ep.port());
        }
        elif(host.is_v6())
        {
            return ep;
        }
        else
        {
            return boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), 0);
        }
    }

    boost::asio::ip::tcp::endpoint ip_v6_to_v4(const boost::asio::ip::tcp::endpoint& ep) noexcept
    {
        auto r = ip_v6_to_v4(boost::asio::ip::udp::endpoint(ep.address(), ep.port()));
        return boost::asio::ip::tcp::endpoint(r.address(), r.port());
    }

    boost::asio::ip::tcp::endpoint ip_v4_to_v6(const boost::asio::ip::tcp::endpoint& ep) noexcept
    {
        auto r = ip_v4_to_v6(boost::asio::ip::udp::endpoint(ep.address(), ep.port()));
        return boost::asio::ip::tcp::endpoint(r.address(), r.port());
    }

    bool ip_is_invalid(const boost::asio::ip::address& address) noexcept
    {
        if (address.is_v4())
        {
            boost::asio::ip::address_v4 in = address.to_v4();
            if (in.is_multicast() || in.is_unspecified())
            {
                return true;
            }

            uint32_t ip = htonl(in.to_uint());
            return ip == INADDR_ANY || ip == INADDR_NONE;
        }
        elif(address.is_v6())
        {
            boost::asio::ip::address_v6 in = address.to_v6();
            if (in.is_multicast() || in.is_unspecified())
            {
                return true;
            }

            return false;
        }
        else
        {
            return true;
        }
    }

    static bool socket_native_adjust(int fd) noexcept
    {
        if (fd == -1)
        {
            return false;
        }

        bool any = false;
        int tos = SOCKET_FLASH_MODE ? IPTOS_LOWDELAY : 0;

#if defined(_MACOS)
#if defined(IPV6_TCLASS)
        any |= ::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
#endif
        any |= ::setsockopt(fd, IPPROTO_IP, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
#else
#if defined(IPV6_TCLASS)
        any |= ::setsockopt(fd, SOL_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
#endif
        any |= ::setsockopt(fd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos)) == 0;
#endif
        return any;
    }

    static void socket_native_adjust(int sockfd, bool in4) noexcept
    {
        if (sockfd != -1)
        {
            uint8_t tos = SOCKET_FLASH_MODE ? IPTOS_LOWDELAY : 0;
            if (in4)
            {
#if defined(_MACOS)
                ::setsockopt(sockfd, IPPROTO_IP, IP_TOS, (char*)&tos, sizeof(tos));
#else
                ::setsockopt(sockfd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos));
#endif

#if defined(IP_DONTFRAGMENT)
                int dont_frag = IP_PMTUDISC_NOT_SET; // IP_PMTUDISC
                ::setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif defined(IP_PMTUDISC_WANT)
                int dont_frag = IP_PMTUDISC_WANT;
                ::setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
            }
            else
            {
                // linux-user: Add missing IP_TOS, IPV6_TCLASS and IPV6_RECVTCLASS sockopts
                // QEMU:
                // https://patchwork.kernel.org/project/qemu-devel/patch/20170311195906.GA13187@ls3530.fritz.box/
#if defined(IPV6_TCLASS)
                ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)); /* SOL_IPV6 */
#endif

#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_WANT)
                int dont_frag = IPV6_PMTUDISC_WANT;
                ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
            }

#if defined(SO_NOSIGPIPE)
            int no_sigpipe = 1;
            ::setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
        }
    }

    void socket_flash_mode(bool value) noexcept
    {
        SOCKET_FLASH_MODE = value;
    }

    void socket_adjust(int sockfd, bool in4) noexcept
    {
        socket_native_adjust(sockfd, in4);
        socket_native_adjust(sockfd);
    }

    template <typename T>
    static bool ucp_socket_adjust(T& socket) noexcept
    {
        boost::system::error_code ec;
        if (!socket.is_open())
        {
            return false;
        }

        int sockfd = socket.native_handle();
        if (sockfd == -1)
        {
            return false;
        }

        auto ep = socket.local_endpoint(ec);
        if (ec)
        {
            socket_adjust(sockfd, true);
        }
        else
        {
            boost::asio::ip::address ip = ep.address();
            socket_adjust(sockfd, ip.is_v4());
        }

        return true;
    }

    template <typename T>
    static bool ucp_tcp_socket_adjust(T& socket) noexcept
    {
        if (ucp_socket_adjust(socket))
        {
            boost::system::error_code ec;
            socket.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
            socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
            socket.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec);
            return true;
        }

        return false;
    }

    bool socket_adjust(boost::asio::ip::udp::socket& socket) noexcept
    {
        if (ucp_socket_adjust(socket))
        {
            boost::system::error_code ec;
            socket.set_option(boost::asio::ip::udp::socket::reuse_address(true), ec);
            return true;
        }

        return false;
    }

    bool socket_adjust(boost::asio::ip::tcp::socket& socket) noexcept
    {
        return ucp_tcp_socket_adjust(socket);
    }

    bool socket_adjust(boost::asio::ip::tcp::acceptor& socket) noexcept
    {
        return ucp_tcp_socket_adjust(socket);
    }

    bool Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept 
    {
        if (NULL != socket) 
        {
            return Closesocket(*socket);
        }
        else 
        {
            return false;
        }
    }

    bool Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept 
    {
        if (NULL != socket) 
        {
            return Closesocket(*socket);
        }
        else 
        {
            return false;
        }
    }

    bool Closesocket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept 
    {
        if (NULL != acceptor) 
        {
            return Closesocket(*acceptor);
        }
        else 
        {
            return false;
        }
    }

    // https://source.android.google.cn/devices/tech/debug/native-crash?hl=zh-cn
    // https://android.googlesource.com/platform/bionic/+/master/docs/fdsan.md
    bool Closesocket(const boost::asio::ip::tcp::socket& socket) noexcept 
    {
        boost::asio::ip::tcp::socket& s = constantof(socket);
        if (s.is_open()) 
        {
            boost::system::error_code ec;
            try 
            {
                s.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            }
            catch (const std::exception&) {}

            try 
            {
                s.close(ec);
                return ec == boost::system::errc::success;
            }
            catch (const std::exception&) {}
        }
        return false;
    }

    bool Closesocket(const boost::asio::ip::tcp::acceptor& acceptor) noexcept 
    {
        boost::asio::ip::tcp::acceptor& s = constantof(acceptor);
        if (s.is_open()) 
        {
            boost::system::error_code ec;
            try 
            {
                s.close(ec);
                return ec == boost::system::errc::success;
            }
            catch (const std::exception&) {}
        }
        return false;
    }

    bool Closesocket(const boost::asio::ip::udp::socket& socket) noexcept 
    {
        boost::asio::ip::udp::socket& s = constantof(socket);
        if (s.is_open()) 
        {
            boost::system::error_code ec;
            try 
            {
                s.close(ec);
                return ec == boost::system::errc::success;
            }
            catch (const std::exception&) {}
        }
        return false;
    }
    
    bool OpenDatagramSocket(
        const boost::asio::ip::udp::socket&                     socket,
        const boost::asio::ip::address&                         listenIP,
        int                                                     listenPort,
        bool                                                    opened) noexcept {
        if (listenPort < 0 || listenPort > UINT16_MAX) {
            listenPort = 0;
        }

        boost::asio::ip::address address_ = listenIP;
        if (!address_.is_unspecified()) {
            if (ip_is_invalid(address_)) {
                address_ = boost::asio::ip::address_v6::any();
            }
        }

        boost::system::error_code ec;
        boost::asio::ip::udp::socket& socket_ = constantof(socket);
        if (!opened) {
            if (socket_.is_open()) {
                return false;
            }

            if (address_.is_v4()) {
                socket_.open(boost::asio::ip::udp::v4(), ec);
            }
            else {
                socket_.open(boost::asio::ip::udp::v6(), ec);
            }

            if (ec) {
                return false;
            }
        }

        int handle = socket_.native_handle();
        socket_adjust(socket_);

        socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true), ec);
        if (ec) {
            return false;
        }

        socket_.bind(boost::asio::ip::udp::endpoint(address_, listenPort), ec);
        if (ec) {
            if (listenPort != 0) {
                socket_.bind(boost::asio::ip::udp::endpoint(address_, 0), ec);
                if (ec) {
                    return false;
                }
            }
        }
        return true;
    }

    bool OpenDatagramSocket(boost::asio::ip::udp::socket& socket, const boost::asio::ip::address& address, int port, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
    {
        bool ok = false;
        if (address.is_v4() || address.is_v6())
        {
            ok = OpenDatagramSocket(socket, address, port);
            if (ok)
            {
                return true;
            }

            ok = Closesocket(socket);
            if (!ok)
            {
                return false;
            }

            goto opensocket_by_protocol;
        }

    opensocket_by_protocol: /* Label.s */
        if (sourceEP.protocol() == boost::asio::ip::udp::v4())
        {
            ok = OpenDatagramSocket(socket, boost::asio::ip::address_v4::any(), port);
        }
        else
        {
            ok = OpenDatagramSocket(socket, boost::asio::ip::address_v6::any(), port);
        }

        return ok;
    }
}