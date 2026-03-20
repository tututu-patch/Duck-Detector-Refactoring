#include "tee/common/syscall_facade.h"

#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace ducktee::common {

    namespace {

#if defined(__aarch64__) || defined(__arm__) || defined(__i386__) || defined(__x86_64__)
        extern "C" long tee_asm_syscall6(
                long number,
                long arg0,
                long arg1,
                long arg2,
                long arg3,
                long arg4,
                long arg5
        );

        constexpr bool kAsmBackendCompiled = true;
#else
        constexpr bool kAsmBackendCompiled = false;
#endif

        SyscallCallResult make_unavailable_result() {
            return SyscallCallResult{
                    .value = -1,
                    .error_number = ENOSYS,
                    .available = false,
            };
        }

        SyscallCallResult from_errno_result(long value, int error_number) {
            return SyscallCallResult{
                    .value = value,
                    .error_number = (value == -1) ? error_number : 0,
                    .available = true,
            };
        }

        SyscallCallResult from_raw_kernel_result(long raw_value) {
            if (raw_value < 0 && raw_value >= -4095) {
                return SyscallCallResult{
                        .value = -1,
                        .error_number = static_cast<int>(-raw_value),
                        .available = true,
                };
            }
            return SyscallCallResult{
                    .value = raw_value,
                    .error_number = 0,
                    .available = true,
            };
        }

        bool read_monotonic_via_result(
                const SyscallCallResult &call,
                const timespec &ts,
                std::uint64_t *out_ns
        ) {
            if (!call.available || call.value != 0 || out_ns == nullptr) {
                return false;
            }
            *out_ns = static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
                      static_cast<std::uint64_t>(ts.tv_nsec);
            return true;
        }

    }  // namespace

    const char *backend_label(SyscallBackend backend) {
        switch (backend) {
            case SyscallBackend::Libc:
                return "libc";
            case SyscallBackend::Syscall:
                return "syscall";
            case SyscallBackend::Asm:
                return "asm";
        }
        return "unknown";
    }

    bool backend_available(SyscallBackend backend) {
        return backend != SyscallBackend::Asm || kAsmBackendCompiled;
    }

    SyscallCallResult invoke_syscall6(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2,
            long arg3,
            long arg4,
            long arg5
    ) {
        switch (backend) {
            case SyscallBackend::Libc:
                return make_unavailable_result();
            case SyscallBackend::Syscall: {
                errno = 0;
                const long value = syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
                return from_errno_result(value, errno);
            }
            case SyscallBackend::Asm:
                if (!kAsmBackendCompiled) {
                    return make_unavailable_result();
                }
                return from_raw_kernel_result(
                        tee_asm_syscall6(number, arg0, arg1, arg2, arg3, arg4, arg5)
                );
        }
        return make_unavailable_result();
    }

    SyscallCallResult invoke_syscall3(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2
    ) {
        return invoke_syscall6(backend, number, arg0, arg1, arg2, 0, 0, 0);
    }

    SyscallCallResult invoke_open_readonly(SyscallBackend backend, const char *path) {
        switch (backend) {
            case SyscallBackend::Libc: {
                errno = 0;
                const int fd = open(path, O_RDONLY | O_CLOEXEC);
                return from_errno_result(fd, errno);
            }
            case SyscallBackend::Syscall:
            case SyscallBackend::Asm:
#if defined(__NR_openat)
                return invoke_syscall6(
                        backend,
                        __NR_openat,
                        AT_FDCWD,
                        reinterpret_cast<long>(path),
                        O_RDONLY | O_CLOEXEC,
                        0,
                        0,
                        0
                );
#else
                return make_unavailable_result();
#endif
        }
        return make_unavailable_result();
    }

    SyscallCallResult invoke_ioctl(
            SyscallBackend backend,
            int fd,
            unsigned long request,
            void *arg
    ) {
        switch (backend) {
            case SyscallBackend::Libc: {
                errno = 0;
                const int value = ioctl(fd, request, arg);
                return from_errno_result(value, errno);
            }
            case SyscallBackend::Syscall:
            case SyscallBackend::Asm:
#if defined(__NR_ioctl)
                return invoke_syscall3(
                        backend,
                        __NR_ioctl,
                        fd,
                        static_cast<long>(request),
                        reinterpret_cast<long>(arg)
                );
#else
                return make_unavailable_result();
#endif
        }
        return make_unavailable_result();
    }

    SyscallCallResult invoke_getpid(SyscallBackend backend) {
        switch (backend) {
            case SyscallBackend::Libc:
                return SyscallCallResult{
                        .value = static_cast<long>(getpid()),
                        .error_number = 0,
                        .available = true,
                };
            case SyscallBackend::Syscall:
            case SyscallBackend::Asm:
#if defined(__NR_getpid)
                return invoke_syscall3(backend, __NR_getpid, 0, 0, 0);
#else
                return make_unavailable_result();
#endif
        }
        return make_unavailable_result();
    }

    bool monotonic_time_ns(SyscallBackend backend, std::uint64_t *out_ns) {
        timespec ts{};
        switch (backend) {
            case SyscallBackend::Libc: {
                errno = 0;
                const int value = clock_gettime(CLOCK_MONOTONIC, &ts);
                return read_monotonic_via_result(from_errno_result(value, errno), ts, out_ns);
            }
            case SyscallBackend::Syscall:
            case SyscallBackend::Asm:
#if defined(__NR_clock_gettime)
                return read_monotonic_via_result(
                        invoke_syscall3(
                                backend,
                                __NR_clock_gettime,
                                CLOCK_MONOTONIC,
                                reinterpret_cast<long>(&ts),
                                0
                        ),
                        ts,
                        out_ns
                );
#else
                return false;
#endif
        }
        return false;
    }

    long raw_syscall3(long number, long arg0, long arg1, long arg2) {
        const SyscallCallResult result = invoke_syscall3(
                backend_available(SyscallBackend::Asm) ? SyscallBackend::Asm
                                                       : SyscallBackend::Syscall,
                number,
                arg0,
                arg1,
                arg2
        );
        errno = result.error_number;
        return result.value;
    }

    int raw_open_readonly(const char *path) {
        const SyscallCallResult result = invoke_open_readonly(
                backend_available(SyscallBackend::Asm) ? SyscallBackend::Asm
                                                       : SyscallBackend::Syscall,
                path
        );
        errno = result.error_number;
        return static_cast<int>(result.value);
    }

    long raw_ioctl(int fd, unsigned long request, void *arg) {
        const SyscallCallResult result = invoke_ioctl(
                backend_available(SyscallBackend::Asm) ? SyscallBackend::Asm
                                                       : SyscallBackend::Syscall,
                fd,
                request,
                arg
        );
        errno = result.error_number;
        return result.value;
    }

    bool bytes_equal(const void *lhs, const void *rhs, std::size_t length) {
        return std::memcmp(lhs, rhs, length) == 0;
    }

}  // namespace ducktee::common
