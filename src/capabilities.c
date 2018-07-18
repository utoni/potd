/*
 * capabilities.c
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <linux/capability.h>
#include <sys/prctl.h>

#include "capabilities.h"
#include "utils.h"
#include "log.h"

typedef struct {
    const char *name;
    int nr;
} CapsEntry;

static CapsEntry capslist[] = {
#ifdef CAP_CHOWN
    {"chown", CAP_CHOWN },
#endif
#ifdef CAP_DAC_OVERRIDE
    {"dac_override", CAP_DAC_OVERRIDE },
#endif
#ifdef CAP_DAC_READ_SEARCH
    {"dac_read_search", CAP_DAC_READ_SEARCH },
#endif
#ifdef CAP_FOWNER
    {"fowner", CAP_FOWNER },
#endif
#ifdef CAP_FSETID
    {"fsetid", CAP_FSETID },
#endif
#ifdef CAP_KILL
    {"kill", CAP_KILL },
#endif
#ifdef CAP_SETGID
    {"setgid", CAP_SETGID },
#endif
#ifdef CAP_SETUID
    {"setuid", CAP_SETUID },
#endif
#ifdef CAP_SETPCAP
    {"setpcap", CAP_SETPCAP },
#endif
#ifdef CAP_LINUX_IMMUTABLE
    {"linux_immutable", CAP_LINUX_IMMUTABLE },
#endif
#ifdef CAP_NET_BIND_SERVICE
    {"net_bind_service", CAP_NET_BIND_SERVICE },
#endif
#ifdef CAP_NET_BROADCAST
    {"net_broadcast", CAP_NET_BROADCAST },
#endif
#ifdef CAP_NET_ADMIN
    {"net_admin", CAP_NET_ADMIN },
#endif
#ifdef CAP_NET_RAW
    {"net_raw", CAP_NET_RAW },
#endif
#ifdef CAP_IPC_LOCK
    {"ipc_lock", CAP_IPC_LOCK },
#endif
#ifdef CAP_IPC_OWNER
    {"ipc_owner", CAP_IPC_OWNER },
#endif
#ifdef CAP_SYS_MODULE
    {"sys_module", CAP_SYS_MODULE },
#endif
#ifdef CAP_SYS_RAWIO
    {"sys_rawio", CAP_SYS_RAWIO },
#endif
#ifdef CAP_SYS_CHROOT
    {"sys_chroot", CAP_SYS_CHROOT },
#endif
#ifdef CAP_SYS_PTRACE
    {"sys_ptrace", CAP_SYS_PTRACE },
#endif
#ifdef CAP_SYS_PACCT
    {"sys_pacct", CAP_SYS_PACCT },
#endif
#ifdef CAP_SYS_ADMIN
    {"sys_admin", CAP_SYS_ADMIN },
#endif
#ifdef CAP_SYS_BOOT
    {"sys_boot", CAP_SYS_BOOT },
#endif
#ifdef CAP_SYS_NICE
    {"sys_nice", CAP_SYS_NICE },
#endif
#ifdef CAP_SYS_RESOURCE
    {"sys_resource", CAP_SYS_RESOURCE },
#endif
#ifdef CAP_SYS_TIME
    {"sys_time", CAP_SYS_TIME },
#endif
#ifdef CAP_SYS_TTY_CONFIG
    {"sys_tty_config", CAP_SYS_TTY_CONFIG },
#endif
#ifdef CAP_MKNOD
    {"mknod", CAP_MKNOD },
#endif
#ifdef CAP_LEASE
    {"lease", CAP_LEASE },
#endif
#ifdef CAP_AUDIT_WRITE
    {"audit_write", CAP_AUDIT_WRITE },
#endif
#ifdef CAP_AUDIT_CONTROL
    {"audit_control", CAP_AUDIT_CONTROL },
#endif
#ifdef CAP_SETFCAP
    {"setfcap", CAP_SETFCAP },
#endif
#ifdef CAP_MAC_OVERRIDE
    {"mac_override", CAP_MAC_OVERRIDE },
#endif
#ifdef CAP_MAC_ADMIN
    {"mac_admin", CAP_MAC_ADMIN },
#endif
#ifdef CAP_SYSLOG
    {"syslog", CAP_SYSLOG },
#endif
#ifdef CAP_WAKE_ALARM
    {"wake_alarm", CAP_WAKE_ALARM },
#endif
#ifdef CAP_BLOCK_SUSPEND
    {"block_suspend", CAP_BLOCK_SUSPEND },
#else
    {"block_suspend", 36 },
#endif
#ifdef CAP_AUDIT_READ
    {"audit_read", CAP_AUDIT_READ },
#else
    {"audit_read", 37 },
#endif
}; // end of capslist


static int caps_find_name(const char *name)
{
    int i;
    int elems = SIZEOF(capslist);

    for (i = 0; i < elems; i++) {
        if (strcmp(name, capslist[i].name) == 0)
            return capslist[i].nr;
    }

    W2("Capability \"%s\" not found or not available on your system", name);
    return -1;
}

void caps_check_list(const char *clist, void (*callback)(int))
{
    char *str = NULL;
    char *ptr = NULL;
    char *start = NULL;
    int nr;

    assert(clist && *clist != '\0');
    str = strdup(clist);
    assert(str);

    ptr = str;
    start = str;
    while (*ptr != '\0') {
        if (islower(*ptr) || isdigit(*ptr) || *ptr == '_') {
        } else if (*ptr == ',') {
            *ptr = '\0';
            nr = caps_find_name(start);
            if (nr == -1)
                goto errexit;
            else if (callback != NULL)
                callback(nr);

            start = ptr + 1;
        }
        ptr++;
    }
    if (*start != '\0') {
        nr = caps_find_name(start);
        if (nr == -1)
            goto errexit;
        else if (callback != NULL)
            callback(nr);
    }

    free(str);
    return;

errexit:
	E2("Error: capability \"%s\" not found", start);
	exit(EXIT_FAILURE);
}

void caps_print(void)
{
    int i;
    int elems = SIZEOF(capslist);
    int cnt = 0;
    unsigned long cap;
    int code;

    for (cap=0; cap <= 63; cap++) {
        code = prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
        if (code == 0)
            cnt++;
    }
    D("Your kernel supports %d capabilities.", cnt);

    for (i = 0; i < elems; i++) {
        D("%d\t- %s", capslist[i].nr, capslist[i].name);
    }
}

void caps_drop_dac_override(int noprofile)
{
    if (getuid() == 0 && !noprofile) {
        if (prctl(PR_CAPBSET_DROP, CAP_DAC_OVERRIDE, 0, 0, 0)) {
        } else {
            D2("%s", "Drop CAP_DAC_OVERRIDE");
        }

        if (prctl(PR_CAPBSET_DROP, CAP_DAC_READ_SEARCH, 0, 0, 0)) {
        } else {
            D2("%s", "Drop CAP_DAC_READ_SEARCH");
        }
    }
}

int caps_default_filter(void)
{
    size_t i;
    int code;
    const char *const capstrs[] = {
        "sys_module", "sys_rawio", "sys_boot",
        "sys_nice", "sys_tty_config",
        "mknod", "sys_admin", "sys_resource",
        "sys_time"
    };

    for (i = 0; i < SIZEOF(capstrs); ++i ) {
        code = caps_find_name(capstrs[i]);
        if (code < 0)
            goto errexit;
        if (prctl(PR_CAPBSET_DROP, code, 0, 0, 0) < 0)
            goto errexit;
    }

    return 0;
errexit:
    E("%s", "Can not drop capabilities");
    exit(EXIT_FAILURE);
}

int caps_jail_filter(void)
{
    size_t i;
    int code;
    const char *const capstrs[] = {
#ifdef CAP_SYSLOG
        "syslog",
#endif
        "audit_control", "audit_read", "audit_write",
        "sys_ptrace", "sys_pacct", "sys_chroot", "sys_nice",
        "sys_tty_config"
    };

    for (i = 0; i < SIZEOF(capstrs); ++i) {
        code = caps_find_name(capstrs[i]);
        if (code < 0)
            goto errexit;
        if (prctl(PR_CAPBSET_DROP, code, 0, 0, 0) < 0)
            goto errexit;
    }

    return 0;
errexit:
    E("%s", "Can not drop capabilities");
    exit(EXIT_FAILURE);
}

void caps_drop_all(void)
{
    unsigned long cap;
    int code;

    D("%s", "Dropping all capabilities");
    for (cap = 0; cap <= 63; cap++) {
        code = prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
        if (code == -1 && errno != EINVAL) {
            FATAL("%s", "PR_CAPBSET_DROP");
        }
    }
}


void caps_set(uint64_t caps)
{
    unsigned long i;
    uint64_t mask = 1LLU;
    int code;

    D("Set caps filter %llx\n", (unsigned long long) caps);
    for (i = 0; i < 64; i++, mask <<= 1) {
        if ((mask & caps) == 0) {
            code = prctl(PR_CAPBSET_DROP, i, 0, 0, 0);
            if (code == -1 && errno != EINVAL)
                FATAL("%s", "PR_CAPBSET_DROP");
        }
    }
}

static uint64_t filter;

static void caps_set_bit(int nr)
{
	uint64_t mask = 1LLU << nr;
	filter |= mask;
}

static void caps_reset_bit(int nr)
{
	uint64_t mask = 1LLU << nr;
	filter &= ~mask;
}

void caps_drop_list(const char *clist)
{
	filter = 0;
	filter--;
	caps_check_list(clist, caps_reset_bit);
	caps_set(filter);
}

void caps_keep_list(const char *clist)
{
	filter = 0;
	caps_check_list(clist, caps_set_bit);
	caps_set(filter);
}
