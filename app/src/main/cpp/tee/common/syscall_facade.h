#ifndef DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H
#define DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H

#include <cstddef>
#include <cstdint>

namespace ducktee::common {

    enum class SyscallBackend {
        Libc,
        Syscall,
        Asm,
    };

    struct SyscallCallResult {
        long value = -1;
        int error_number = 0;
        bool available = false;
    };

    const char *backend_label(SyscallBackend backend);

    bool backend_available(SyscallBackend backend);

    SyscallCallResult invoke_syscall3(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2
    );

    SyscallCallResult invoke_syscall6(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2,
            long arg3,
            long arg4,
            long arg5
    );

    SyscallCallResult invoke_open_readonly(SyscallBackend backend, const char *path);

    SyscallCallResult invoke_ioctl(
            SyscallBackend backend,
            int fd,
            unsigned long request,
            void *arg
    );

    SyscallCallResult invoke_getpid(SyscallBackend backend);

    bool monotonic_time_ns(SyscallBackend backend, std::uint64_t *out_ns);

    long raw_syscall3(long number, long arg0, long arg1, long arg2);

    int raw_open_readonly(const char *path);

    long raw_ioctl(int fd, unsigned long request, void *arg);

    bool bytes_equal(const void *lhs, const void *rhs, std::size_t length);

}  // namespace ducktee::common

#endif  // DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H
