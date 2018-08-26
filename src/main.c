/*
 * main.c
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

#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef HAVE_SECCOMP
#include "pseccomp.h"
#endif
#include "capabilities.h"
#include "log.h"
#include "log_colored.h"
#include "log_file.h"
#include "options.h"
#include "utils.h"
#include "redirector.h"
#include "protocol_ssh.h"
#include "forward.h"
#include "jail.h"

static size_t jl_siz = 0;
static jail_ctx **jl_ctx = NULL;
static pid_t jl_pid = -1;

static size_t prt_siz = 0;
static protocol_ctx **prt_ctx = NULL;

static size_t rdr_siz = 0;
static redirector_ctx **rdr_ctx = NULL;
static pid_t rdr_pid = -1;

static void jail_preinit(char jail_hosts[][2][NI_MAXHOST],
                         char jail_ports[][2][NI_MAXSERV],
                         jail_ctx *ctx[], const size_t siz);
static pid_t jail_init(jail_ctx *ctx[], const size_t siz);
static void ssh_protocol_preinit(char proto_hosts[][2][NI_MAXHOST],
                                 char proto_ports[][2][NI_MAXSERV],
                                 protocol_ctx *ctx[],
                                 const size_t siz);
static void ssh_protocol_init(protocol_ctx *ctx[], const size_t siz);
static void rdr_preinit(char rdr_hosts[][2][NI_MAXHOST],
                        char rdr_ports[][2][NI_MAXSERV],
                        redirector_ctx *ctx[],
                        const size_t siz);
static pid_t rdr_init(redirector_ctx *ctx[], const size_t siz);

static size_t validate_hostport_option(opt_name on, int process_forward);
static int process_options(int validate_only);


static void jail_preinit(char jail_hosts[][2][NI_MAXHOST],
                         char jail_ports[][2][NI_MAXSERV],
                         jail_ctx *ctx[], const size_t siz)
{
    for (size_t i = 0; i < siz; ++i) {
        D("Initialising jail service on port %s:%s",
            jail_hosts[i][0], jail_ports[i][0]);

        jail_init_ctx(&ctx[i], MAX_STACKSIZE);
        ctx[i]->newroot = getopt_str(OPT_ROOT);
        ABORT_ON_FATAL( jail_setup(ctx[i], jail_hosts[i][0], jail_ports[i][0]),
            "Jail daemon setup" );
        ABORT_ON_FATAL( jail_validate_ctx(ctx[i]),
            "Jail validation" );
    }
}

static pid_t jail_init(jail_ctx *ctx[], const size_t siz)
{
    pid_t jail_pid;
    event_ctx *event = NULL;

    ABORT_ON_FATAL( jail_setup_event( ctx, siz, &event ),
        "Jail daemon epoll setup" );
    jail_pid = jail_daemonize(&event, ctx, siz);
    ABORT_ON_FATAL( jail_pid < 1, "Jail daemon startup" );

    return jail_pid;
}

static void ssh_protocol_preinit(char proto_hosts[][2][NI_MAXHOST],
                                 char proto_ports[][2][NI_MAXSERV],
                                 protocol_ctx *ctx[],
                                 const size_t siz)
{
    for (size_t i = 0; i < siz; ++i) {
        ABORT_ON_FATAL( proto_init_ctx(&ctx[i], ssh_init_cb),
            "SSH Protocol init" );
        ABORT_ON_FATAL( proto_setup(ctx[i],
            proto_hosts[i][0], proto_ports[i][0],
            proto_hosts[i][1], proto_ports[i][1]),
            "SSH Protocol setup" );
        ABORT_ON_FATAL( proto_validate_ctx(ctx[i]),
            "SSH validation" );
    }
}

static void ssh_protocol_init(protocol_ctx *ctx[], const size_t siz)
{
    for (size_t i = 0; i < siz; ++i) {
        ABORT_ON_FATAL( proto_listen(ctx[i]),
            "SSH Protocol listen" );
    }
}

static void rdr_preinit(char rdr_hosts[][2][NI_MAXHOST],
                        char rdr_ports[][2][NI_MAXSERV],
                        redirector_ctx *ctx[],
                        const size_t siz)
{
    for (size_t i = 0; i < siz; ++i) {
        D("Initialising redirector service on %s:%s to %s:%s",
            rdr_hosts[i][0], rdr_ports[i][0],
            rdr_hosts[i][1], rdr_ports[i][1]);

        ABORT_ON_FATAL( redirector_init_ctx(&ctx[i]),
            "Redirector init" );
        ABORT_ON_FATAL( redirector_setup(ctx[i],
            rdr_hosts[i][0], rdr_ports[i][0],
            rdr_hosts[i][1], rdr_ports[i][1]),
            "Redirector setup" );
        ABORT_ON_FATAL( redirector_validate_ctx(ctx[i]),
            "Redirector validation" );
    }
}

static pid_t rdr_init(redirector_ctx *ctx[], const size_t siz)
{
    pid_t rdr_pid;
    event_ctx *event = NULL;

    D2("%s", "Redirector event setup");
    ABORT_ON_FATAL( redirector_setup_event( ctx, siz, &event ),
        "Redirector event setup" );

    N("%s", "Redirector epoll mainloop");
    rdr_pid = redirector_daemonize( &event, ctx, siz );
    ABORT_ON_FATAL( rdr_pid < 1, "Server epoll mainloop" );

    return rdr_pid;
}

static size_t validate_hostport_option(opt_name on, int process_forward)
{
    char *value;
    struct opt_list *ol = NULL;
    size_t rc = 0, siz, off;
    char hbuf[2][NI_MAXHOST];
    char sbuf[2][NI_MAXSERV];

    if (!getopt_used(on))
        return 0;

    while ((value = getopt_strlist(on, &ol))) {
        siz = parse_hostport_str(value, hbuf[0], sbuf[0]);
        if (!siz) {
            fprintf(stderr, "%s: invalid listen host:port "
                "combination: '%s'\n",
                arg0, value);
            return 0;
        }

        off = siz;
        siz = parse_hostport_str(value + off, hbuf[1], sbuf[1]);
        if (process_forward) {
            if (!siz) {
                fprintf(stderr, "%s: invalid forward host:port "
                    "combination: '%s'\n",
                    arg0, value + off);
                return 0;
            }
            if (*(value + off + siz)) {
                fprintf(stderr, "%s: garbage host:port string '%s'\n",
                    arg0, value + off + siz);
            }
        } else {
            if (siz) {
                fprintf(stderr, "%s: got a forward host:port string when none"
                                " is allowed '%s'\n", arg0, value + off);
                return 0;
            }
            if (*(value + off + siz)) {
                fprintf(stderr, "%s: got an invalid forward host:port string "
                                "when none"
                                " is allowed '%s'\n", arg0, value + off);
                return 0;
            }

            off = 0;
        }

        rc++;
    }

    return rc;
}

#define POSITIVE_VALIDATIONS 3
static int process_options(int validate_only)
{
    char *value = NULL;
    struct opt_list *ol;
    size_t i, siz, rc = 0;

    siz = validate_hostport_option(OPT_JAIL, 0);
    if (siz && !validate_only) {
        jl_siz = siz;
        jl_ctx = (jail_ctx **) calloc(siz, sizeof(jail_ctx));
        assert(jl_ctx);

        ol = NULL;
        i = 0;
        char hosts[jl_siz][2][NI_MAXHOST];
        char ports[jl_siz][2][NI_MAXSERV];
        while ((value = getopt_strlist(OPT_JAIL, &ol))) {
            memset(hosts[i], 0, sizeof hosts[i]);
            memset(ports[i], 0, sizeof ports[i]);

            siz = parse_hostport_str(value, hosts[i][0], ports[i][0]);
            i++;
        }

        jail_preinit(hosts, ports, jl_ctx, jl_siz);
        jl_pid = jail_init(jl_ctx, jl_siz);
    }
    if (siz)
        rc++;

    siz = validate_hostport_option(OPT_PROTOCOL, 1);
    if (siz && !validate_only) {
        prt_siz = siz;
        prt_ctx = (protocol_ctx **) calloc(siz, sizeof(protocol_ctx));
        assert(prt_ctx);

        ol = NULL;
        i = 0;
        char hosts[prt_siz][2][NI_MAXHOST];
        char ports[prt_siz][2][NI_MAXSERV];
        while ((value = getopt_strlist(OPT_PROTOCOL, &ol))) {
            memset(hosts[i], 0, sizeof hosts[i]);
            memset(ports[i], 0, sizeof ports[i]);

            siz = parse_hostport_str(value, hosts[i][0], ports[i][0]);
            siz = parse_hostport_str(value + siz, hosts[i][1], ports[i][1]);
            i++; 
        }

        ssh_protocol_preinit(hosts, ports, prt_ctx, prt_siz);
        ssh_protocol_init(prt_ctx, prt_siz);
    }
    if (siz)
        rc++;

    siz  = validate_hostport_option(OPT_REDIRECT, 1);
    if (siz && !validate_only) {
        rdr_siz = siz;
        rdr_ctx = (redirector_ctx **) calloc(siz, sizeof(redirector_ctx));
        assert(rdr_ctx);

        ol = NULL;
        i = 0;
        char hosts[rdr_siz][2][NI_MAXHOST];
        char ports[rdr_siz][2][NI_MAXSERV];
        while ((value = getopt_strlist(OPT_REDIRECT, &ol))) {
            memset(hosts[i], 0, sizeof hosts[i]);
            memset(ports[i], 0, sizeof ports[i]);

            siz = parse_hostport_str(value, hosts[i][0], ports[i][0]);
            siz = parse_hostport_str(value + siz, hosts[i][1], ports[i][1]);
            i++;
        }

        rdr_preinit(hosts, ports, rdr_ctx, rdr_siz);
        rdr_init(rdr_ctx, rdr_siz);
    }
    if (siz)
        rc++;

    return rc;
}

int main(int argc, char *argv[])
{
    char *value;
    int proc_status;
    pid_t daemon_pid, child_pid;
#ifdef HAVE_SECCOMP
    pseccomp_ctx *psc = NULL;
#endif

    (void) argc;
    (void) argv;
    arg0 = argv[0];

    if (parse_cmdline(argc, argv)) {
        fprintf(stderr, "%s: command line parsing failed\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (process_options(1) != POSITIVE_VALIDATIONS) {
        fprintf(stderr, "%s: invalid/missing config detected\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (getopt_used(OPT_LOGTOFILE) || getopt_used(OPT_LOGFILE)) {
        log_file = getopt_str(OPT_LOGFILE);
        LOG_SET_FUNCS_VA(LOG_FILE_FUNCS);
        fprintf(stderr, "Logfile: '%s'\n", log_file);
    } else {
        LOG_SET_FUNCS_VA(LOG_COLORED_FUNCS);
    }

    if (getopt_used(OPT_LOGLEVEL)) {
        value = getopt_str(OPT_LOGLEVEL);
        if (!strcasecmp(value, "debug"))
            log_prio = LP_DEBUG;
        else if (!strcasecmp(value, "protocol"))
            log_prio = PROTOCOL;
        else if (!strcasecmp(value, "notice"))
            log_prio = NOTICE;
        else if (!strcasecmp(value, "warning"))
            log_prio = WARNING;
        else if (!strcasecmp(value, "error"))
            log_prio = ERROR;
        else {
            fprintf(stderr, "%s: unknown loglevel '%s'\n", argv[0], value);
            exit(EXIT_FAILURE);
        }
    }

    if (log_open())
       exit(EXIT_FAILURE);

#ifdef HAVE_CONFIG_H
    N("%s (C) 2018 Toni Uhlig <%s>", PACKAGE_STRING, PACKAGE_BUGREPORT);
#endif

    if (selftest_minimal_requirements())
        exit(EXIT_FAILURE);

    if (geteuid() != 0) {
        E("%s", "I was made for root!");
        exit(EXIT_FAILURE);
    }

    caps_default_filter();
#ifdef HAVE_SECCOMP
    pseccomp_init(&psc,
        (getopt_used(OPT_SECCOMP_MINIMAL) ? PS_MINIMUM : 0));
    if (pseccomp_default_rules(psc))
        FATAL("%s", "SECCOMP: adding default rules");
    pseccomp_free(&psc);
#else
    W("%s", "Compiled without libseccomp, this may have a security impact.");
#endif

    D("%s", "Forking into background/foreground");
    daemon_pid = daemonize(!getopt_used(OPT_DAEMON));
    ABORT_ON_FATAL( daemon_pid > 0, "Forking" );
    if (daemon_pid == 0) {
        set_procname("[potd] main");
    } else {
        FATAL("Forking (fork returned %d)", daemon_pid);
    }
    D2("Master pid: %d", getpid());
    ABORT_ON_FATAL( set_master_sighandler(),
        "Master sighandler" );

    ABORT_ON_FATAL( process_options(0) != POSITIVE_VALIDATIONS,
        "Setup redirect/protocol/jail instances");

    while (1) {
        child_pid = wait(&proc_status);
        if (child_pid == jl_pid ||
            child_pid == rdr_pid) {
            E2("%s daemon with pid %d terminated, exiting",
                (child_pid == jl_pid ? "Jail" : "Redirector"),
                (child_pid == jl_pid ? jl_pid : rdr_pid));
        } else W2("Process with pid %d terminated", child_pid);
        break;
    }

    log_close();
    kill(getpid(), SIGTERM);
    return 0;
}
