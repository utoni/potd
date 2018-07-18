/*
 * pseccomp.c
 * potd is licensed under the BSD license:
 *
 * Copyright (c) 2018 Toni Uhlig <matzeton@googlemail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - The names of its contributors may not be used to endorse or promote
 *   products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <sys/prctl.h>
#ifdef HAVE_VALGRIND
#include <valgrind.h>
#endif

#include "pseccomp.h"
#include "log.h"
#include "utils.h"

static int pseccomp_using_valgrind(void);

static const int minimum_disabled_syscalls[] = {
    SCMP_SYS(reboot),
    SCMP_SYS(mount),
    SCMP_SYS(umount), SCMP_SYS(umount2),
    SCMP_SYS(ptrace),
    SCMP_SYS(kexec_load),
    SCMP_SYS(kexec_file_load),
    SCMP_SYS(open_by_handle_at),
    SCMP_SYS(create_module),
    SCMP_SYS(init_module),
    SCMP_SYS(finit_module),
    SCMP_SYS(delete_module),
    SCMP_SYS(iopl),
    SCMP_SYS(ioperm),
    SCMP_SYS(iopl),
    SCMP_SYS(swapon),
    SCMP_SYS(swapoff),
    SCMP_SYS(syslog) /* Flawfinder: ignore */,
    SCMP_SYS(nice),
    SCMP_SYS(kcmp),
    SCMP_SYS(unshare),
    SCMP_SYS(setns),
    SCMP_SYS(pivot_root),
    SCMP_SYS(chroot) /* Flawfinder: ignore */,
    SCMP_SYS(fchdir),
    SCMP_SYS(capset),
    SCMP_SYS(mknod),
    SCMP_SYS(mknodat)
};

static const int default_allowed_syscalls[] = {
    SCMP_SYS(restart_syscall),
    SCMP_SYS(signalfd), SCMP_SYS(signalfd4),
    SCMP_SYS(rt_sigreturn), SCMP_SYS(rt_sigprocmask),
    SCMP_SYS(rt_sigaction), SCMP_SYS(time), SCMP_SYS(nanosleep),
    SCMP_SYS(clock_gettime), SCMP_SYS(set_tid_address),
    SCMP_SYS(exit), SCMP_SYS(exit_group),
    SCMP_SYS(read), SCMP_SYS(readv), SCMP_SYS(write), SCMP_SYS(writev),
    SCMP_SYS(fcntl), SCMP_SYS(fcntl64),
    SCMP_SYS(close), SCMP_SYS(wait4),
    SCMP_SYS(sigprocmask), SCMP_SYS(tgkill), SCMP_SYS(gettid), SCMP_SYS(set_tls),
    SCMP_SYS(fork), SCMP_SYS(clone), SCMP_SYS(execve),
    SCMP_SYS(socket), SCMP_SYS(bind), SCMP_SYS(setsockopt), SCMP_SYS(shutdown),
    SCMP_SYS(listen), SCMP_SYS(connect), SCMP_SYS(getsockname),
    SCMP_SYS(accept), SCMP_SYS(sendto), SCMP_SYS(recvmsg), SCMP_SYS(recvfrom),
    SCMP_SYS(epoll_create1), SCMP_SYS(epoll_ctl), SCMP_SYS(epoll_pwait),
    SCMP_SYS(poll), SCMP_SYS(pipe), SCMP_SYS(pipe2),
    SCMP_SYS(set_robust_list), SCMP_SYS(getrlimit),
    SCMP_SYS(seccomp), SCMP_SYS(getrusage),
    SCMP_SYS(prlimit64),
    SCMP_SYS(prctl), SCMP_SYS(mmap), SCMP_SYS(mmap2), SCMP_SYS(brk), SCMP_SYS(madvise),
    SCMP_SYS(mlock), SCMP_SYS(getrandom),
    SCMP_SYS(mprotect), SCMP_SYS(munmap), SCMP_SYS(futex),
    /* operations on files */
    SCMP_SYS(open), SCMP_SYS(openat),
    SCMP_SYS(unlink), SCMP_SYS(fstat), SCMP_SYS(fstat64),
    SCMP_SYS(access) /* Flawfinder: ignore */,
    SCMP_SYS(_llseek), SCMP_SYS(lseek), SCMP_SYS(stat), SCMP_SYS(stat64),
    SCMP_SYS(readlink) /* Flawfinder: ignore */, SCMP_SYS(getcwd),
    SCMP_SYS(lstat), SCMP_SYS(sysinfo),
    /* operations on user/group */
    SCMP_SYS(setuid), SCMP_SYS(setuid32), SCMP_SYS(setgid), SCMP_SYS(setgid32),
    SCMP_SYS(setresuid), SCMP_SYS(setresuid32),  SCMP_SYS(setresgid), SCMP_SYS(setresgid32),
    SCMP_SYS(getuid), SCMP_SYS(getuid32), SCMP_SYS(geteuid), SCMP_SYS(geteuid32),
    SCMP_SYS(getgid), SCMP_SYS(getgid32), SCMP_SYS(getegid), SCMP_SYS(getegid),
    SCMP_SYS(getgroups), SCMP_SYS(getdents),
    /* operations on processes */
    SCMP_SYS(getpgrp), SCMP_SYS(setpgid), SCMP_SYS(getpid), SCMP_SYS(getppid),
    SCMP_SYS(kill),
    /* other */
    SCMP_SYS(unshare), SCMP_SYS(setns),
    SCMP_SYS(chroot) /* Flawfinder: ignore */, SCMP_SYS(chdir), SCMP_SYS(mount), SCMP_SYS(umount2),
    SCMP_SYS(mknod), SCMP_SYS(mkdir), SCMP_SYS(rmdir),
    SCMP_SYS(statfs), SCMP_SYS(ioctl),
    SCMP_SYS(umask), SCMP_SYS(chown) /* Flawfinder: ignore */,
    SCMP_SYS(chmod) /* Flawfinder: ignore */, SCMP_SYS(setsid),
    SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3),
    SCMP_SYS(sethostname), SCMP_SYS(uname), SCMP_SYS(arch_prctl)
};

static const int protocol_disabled_syscalls[] = {
    SCMP_SYS(execve), SCMP_SYS(execveat)
};

static const int jail_allowed_syscalls[] = {
    SCMP_SYS(restart_syscall),
    SCMP_SYS(signalfd), SCMP_SYS(signalfd4),
    SCMP_SYS(rt_sigreturn), SCMP_SYS(rt_sigprocmask),
    SCMP_SYS(rt_sigaction), SCMP_SYS(time), SCMP_SYS(nanosleep),
    SCMP_SYS(clock_gettime), SCMP_SYS(set_tid_address),
    SCMP_SYS(exit), SCMP_SYS(exit_group),
    SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(writev),
    SCMP_SYS(fcntl), SCMP_SYS(fcntl64),
    SCMP_SYS(close), SCMP_SYS(wait4),
    SCMP_SYS(sigprocmask), SCMP_SYS(tgkill), SCMP_SYS(gettid), SCMP_SYS(set_tls),
    SCMP_SYS(fork), SCMP_SYS(clone), SCMP_SYS(execve),
    SCMP_SYS(socket),
    SCMP_SYS(mmap), SCMP_SYS(mmap2), SCMP_SYS(brk), SCMP_SYS(madvise),
    SCMP_SYS(mprotect), SCMP_SYS(munmap), SCMP_SYS(futex),
    SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(fstat), SCMP_SYS(fstat64),
    SCMP_SYS(access) /* Flawfinder: ignore */,
    SCMP_SYS(poll), SCMP_SYS(pipe), SCMP_SYS(pipe2),
    SCMP_SYS(lseek), SCMP_SYS(stat), SCMP_SYS(stat64),
    SCMP_SYS(readlink) /* Flawfinder: ignore */, SCMP_SYS(getcwd),
    SCMP_SYS(lstat), SCMP_SYS(sysinfo),
    SCMP_SYS(setuid), SCMP_SYS(setgid),
    SCMP_SYS(setresuid), SCMP_SYS(setresgid),
    SCMP_SYS(getuid), SCMP_SYS(geteuid), SCMP_SYS(getgid), SCMP_SYS(getegid),
    SCMP_SYS(getgroups), SCMP_SYS(getdents),
    SCMP_SYS(getpgrp), SCMP_SYS(setpgid), SCMP_SYS(getpid), SCMP_SYS(getppid),
    SCMP_SYS(kill),
    SCMP_SYS(chdir), SCMP_SYS(mount),
    SCMP_SYS(umount2),
    SCMP_SYS(ioctl),
    SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3),
    SCMP_SYS(sethostname), SCMP_SYS(uname), SCMP_SYS(arch_prctl)
};


static int pseccomp_using_valgrind(void)
{
#ifdef HAVE_VALGRIND
    if (RUNNING_ON_VALGRIND) {
        W("%s", "SECCOMP: running on valgrind, disabled");
        return 1;
    }
#endif
    return 0;
}

int pseccomp_init(pseccomp_ctx **ctx, unsigned flags)
{
    assert(ctx);

    if (!*ctx)
        *ctx = (pseccomp_ctx *) malloc(sizeof(**ctx));
    assert(*ctx);

    memset(*ctx, 0, sizeof(**ctx));
    (*ctx)->sfilter = seccomp_init(
        (flags & PS_ALLOW || flags & PS_MINIMUM ?
            SCMP_ACT_ALLOW : SCMP_ACT_ERRNO(EINVAL))
    );

    return 0;
}

void pseccomp_free(pseccomp_ctx **ctx)
{
    assert(ctx && *ctx);

    seccomp_release((*ctx)->sfilter);
    free(*ctx);
    (*ctx) = NULL;
}

int pseccomp_set_immutable(void)
{
    if (prctl(PR_SET_DUMPABLE, 0) &&
        prctl(PR_SET_NO_NEW_PRIVS, 1))
    {
        FATAL("%s", "PR_SET_NO_NEW_PRIVS, PR_SET_DUMPABLE");
    }

    return 0;
}

int pseccomp_default_rules(pseccomp_ctx *ctx)
{
    size_t i;

    if (pseccomp_using_valgrind())
        return 0;

    if (ctx->flags & PS_MINIMUM) {
        for (i = 0; i < SIZEOF(minimum_disabled_syscalls); ++i)
            seccomp_rule_add(ctx->sfilter, SCMP_ACT_ERRNO(EINVAL),
                minimum_disabled_syscalls[i], 0);
    } else {
        for (i = 0; i < SIZEOF(default_allowed_syscalls); ++i)
            seccomp_rule_add(ctx->sfilter, SCMP_ACT_ALLOW,
                default_allowed_syscalls[i], 0);
    }

    return seccomp_load(ctx->sfilter);
}

int pseccomp_protocol_rules(pseccomp_ctx *ctx)
{
    size_t i;

    if (pseccomp_using_valgrind())
        return 0;

    for (i = 0; i < SIZEOF(protocol_disabled_syscalls); ++i)
        seccomp_rule_add(ctx->sfilter, SCMP_ACT_ERRNO(EINVAL),
            protocol_disabled_syscalls[i], 0);

    return seccomp_load(ctx->sfilter);
}

int pseccomp_jail_rules(pseccomp_ctx *ctx)
{
    size_t i;

    if (pseccomp_using_valgrind())
        return 0;

    for (i = 0; i < SIZEOF(jail_allowed_syscalls); ++i)
        seccomp_rule_add(ctx->sfilter, SCMP_ACT_ALLOW,
            jail_allowed_syscalls[i], 0);

    return seccomp_load(ctx->sfilter);
}
