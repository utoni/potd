/*
 * options.c
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
#else
#define POTD_LOGFILE "/tmp/potd.log"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <linux/limits.h>
#include <libgen.h>
#include <errno.h>

#include "options.h"

typedef enum opt_type {
    OT_INVALID = 0, OT_NOARG, OT_L, OT_LL, OT_STR,
    OT_PATH
} opt_type;

struct opt_list;

typedef union opt_ptr {
    long int l;
    long long int ll;
    const char *str;
    char *str_dup;
    struct opt_list *list;
} opt_ptr;

typedef struct opt_list {
    opt_ptr value;
    struct opt_list *next;
} opt_list;

struct opt {
    opt_type type;
    opt_ptr value;
    opt_ptr def_value;
    int used;
    int is_list;

    const char *arg_name;
    const char *short_help;
    const char *help;
};

#define OPT(type, def_value, arg, short_help, help) \
    { type, {0}, {def_value}, 0, 0, arg, short_help, help }
#define OPT_LIST(type, def_values, arg, short_help, help) \
    { type, {0}, {def_values}, 0, 1, arg, short_help, help }
#define OPT_NOARG(arg, short_help, help) \
    OPT(OT_NOARG, .ll = 0, arg, short_help, help)
static struct opt options[OPT_MAX+1] = {
    OPT_NOARG("log-to-file", "log to the default logfile path\n", NULL),
    OPT(OT_PATH, .str = POTD_LOGFILE, "log-file", "specify a logfile path\n",
        NULL),
    OPT(OT_STR,  .str = "notice", "log-level", "set the loglevel\n",
        "error    - log only errors\n"
        "warning  - log errors,warnings\n"
        "notice   - log errors,warnings,notices\n"
        "protocol - log errors,warnings,notices,protocol\n"
        "debug    - log all messages\n"),
    OPT_NOARG("daemon", "fork into background if possible\n", NULL),
    OPT_LIST(OT_STR, .str = NULL, "redirect", "setup redirector service\n",
        "format [listen]:[forward-to-protocol]\n"
        "where [listen] contains [listen-addr]:[listen-port]\n"
        "and [forward-to-protocol] contains [forward-addr]:[forward-port]\n"
        "Example: 0.0.0.0:2222:127.0.0.1:22222\n"),
    OPT_LIST(OT_STR, .str = NULL, "protocol", "setup (ssh) protocol service\n",
        "format [listen]:[forward-to-jail]\n"
        "where [listen] contains [listen-addr]:[listen-port]\n"
        "and [forward-to-jail] contains [forward-addr]:[forward-port]\n"
        "Example: 127.0.0.1:22222:127.0.0.1:33333\n"),
    OPT_LIST(OT_STR, .str = NULL, "jail", "setup jail service\n",
        "format [listen]\n"
        "where [listen] contains [listen-addr]:[listen-port]\n"
        "Example: 127.0.0.1:33333\n"),
    OPT(OT_PATH, .str = POTD_DEFROOT, "rootfs",
        "path to root directory/image\n", NULL),
    OPT(OT_PATH, .str = POTD_RODIR, "rodir",
        "path to an empty directory for ro-bind-mounts\n", NULL),
    OPT(OT_PATH, .str = POTD_ROFILE, "rofile",
        "path to an empty file for ro-bind-mounts\n", NULL),
    OPT(OT_PATH, .str = POTD_NETNS_RUN_DIR, "netns-rundir",
        "set the network namespace run directory\n", NULL),
    OPT(OT_PATH, .str = POTD_SSH_RUN_DIR, "ssh-rundir",
        "set the SSH runtime directory\n",
        "libssh will store its keys in this directory\n"),
    OPT(OT_STR, .str = POTD_DEFUSER, "user",
        "change user/group for redirector/protocol\n", NULL),
    OPT(OT_STR, .str = NULL, "group",
        "change group for redirector/protocol\n", NULL),
    OPT_NOARG("seccomp-minimal", "use a minimal seccomp ruleset\n",
        "instead of setting an allowed syscall ruleset\n"
        "use a minimal set of blocked syscalls e.g.\n"
        "mount, umount, ptrace, kernel module syscalls\n"
        "and some io syscalls\n"
        "(use this if you acknowledge errors on some platforms e.g. OpenWrt)\n"),
    OPT_NOARG("test", "test essential daemon functions and exit\n", NULL),

    OPT_NOARG("help", "this\n", NULL),
    OPT(OT_INVALID, .ll = 0, NULL, NULL, NULL)
};

static int opt_convert(opt_type t, opt_ptr *d);
static int setopt_list(struct opt *o, const char *optarg);
static int setopt(struct opt *o, const char *optarg);
static size_t snprint_multilined_ljust(const char *prefix,
                                       const char *multiline,
                                       char *buf, size_t siz);
static void usage(const char *arg0, int print_copyright);


static int parse_path(opt_ptr *d, char *some_path)
{
    int rc = 1;
    char path_dir[PATH_MAX] = {0};
    char path_base[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    char *dir, *base;

    d->str_dup = realpath(some_path, NULL);
    if (!d->str_dup && errno == ENOENT) {
        snprintf(path_dir, sizeof path_dir, "%s", some_path);
        dir = dirname(path_dir);
        if (!dir)
            return 1;
        dir = realpath(dir, NULL);
        if (!dir)
            return 1;

        snprintf(path_base, sizeof path_base, "%s", some_path);
        base = basename(path_base);
        if (!base)
            goto error;

        snprintf(path, sizeof path, "%s/%s", dir, base);
        d->str_dup = strndup(path, strnlen(path, sizeof path));
error:
        free(dir);
    }

    if (d->str_dup)
        rc = 0;

    return rc;
}

static int opt_convert(opt_type t, opt_ptr *d)
{
    char *endptr = NULL;

    switch (t) {
        case OT_L:
            d->l = strtol(optarg, &endptr, 10);
            break;
        case OT_LL:
            d->ll = strtoll(optarg, &endptr, 10);
            break;
        case OT_STR:
            d->str_dup = strdup(optarg);
            break;
        case OT_PATH:
            if (parse_path(d, optarg))
                return 1;
            break;
        case OT_NOARG:
        case OT_INVALID:
            return 1;
    }

    if (endptr && *endptr != 0)
        return 1;

    return 0;
}

static int setopt_list(struct opt *o, const char *optarg)
{
    opt_list **l;

    assert(o && o->type != OT_INVALID);

    if (!optarg || o->type == OT_NOARG || !o->is_list)
        return 1;

    l = &o->value.list;
    while (*l) l = &(*l)->next;
    *l = (opt_list *) calloc(1, sizeof **l);

    if (opt_convert(o->type, &(*l)->value))
        return 1;

    o->used = 1;

    return 0;
}

static int setopt(struct opt *o, const char *optarg)
{
    assert(o && o->type != OT_INVALID);
    if (o->used && !o->is_list)
        return 1;
    if (!optarg || o->type == OT_NOARG)
        goto noarg;

    if (opt_convert(o->type, &o->value))
        return 1;

noarg:
    o->used = 1;

    return 0;
}

static size_t snprint_multilined_ljust(const char *prefix,
                                       const char *multiline,
                                       char *buf, size_t siz)
{
    const char sep[] = "\n";
    const char *start, *end;
    size_t off;

    off = 0;
    start = multiline;
    end = NULL;
    do {
        if (start) {
            end = strstr(start, sep);
            if (end) {
                off += snprintf(buf + off, siz - off, "%s%.*s\n", prefix,
                    (int) (end-start), start);
                start = end + strlen(sep);
            }
        }
    } while (start && end);

    return off;
}

static void usage(const char *arg0, int print_copyright)
{
    int i, has_default;
    size_t off;
    char spaces[6];
    char spaces_long[28];
    char buf_arg[64];
    char buf_shorthelp[BUFSIZ];
    char buf_help[BUFSIZ];
    char value[32];

    (void) print_copyright;
#ifdef HAVE_CONFIG_H
    if (print_copyright)
        fprintf(stderr, "\n%s (C) 2018 Toni Uhlig <%s>\n\n",
            PACKAGE_STRING, PACKAGE_BUGREPORT);
    else
#endif
    if (1)
        fprintf(stderr, "%s", "\n");

    memset(spaces, ' ', sizeof spaces);
    spaces[sizeof spaces - 1] = 0;
    memset(spaces_long, ' ', sizeof spaces_long);
    spaces_long[sizeof spaces_long - 1] = 0;

    for (i = 0; i < OPT_MAX; ++i) {
        snprintf(buf_arg, sizeof buf_arg, "--%s", options[i].arg_name);

        memset(buf_shorthelp, 0, sizeof buf_shorthelp);
        if (options[i].short_help)
            snprint_multilined_ljust(spaces,
                                   options[i].short_help,
                                   buf_shorthelp,
                                   sizeof buf_shorthelp);

        memset(buf_help, 0, sizeof buf_help);
        off = 0;
        if (options[i].help)
            off = snprint_multilined_ljust(spaces_long, options[i].help,
                                         buf_help, sizeof buf_help);

        has_default = 0;
        switch (options[i].type) {
            case OT_L:
                snprintf(value, sizeof value, "default: %lld\n",
                    options[i].def_value.ll);
                has_default = 1;
                break;
            case OT_LL:
                snprintf(value, sizeof value, "default: %ld\n",
                    options[i].def_value.l);
                has_default = 1;
                break;
            case OT_STR:
            case OT_PATH:
                if (options[i].def_value.str) {
                    snprintf(value, sizeof value, "default: %s\n",
                        options[i].def_value.str);
                    has_default = 1;
                }
                break;
            case OT_INVALID:
            case OT_NOARG:
            default:
                break;
        }
        if (has_default)
            snprint_multilined_ljust(&spaces_long[5],
                value, buf_help + off, sizeof buf_help - off);

        fprintf(stderr, "%16s %s"
                        "%s\n", buf_arg,
                        buf_shorthelp, buf_help);
    }
    fprintf(stderr,
        "For example: %s \\\n"
        "                --redirect 0.0.0.0:2222:127.0.0.1:22222\n"
        "                --protocol 127.0.0.1:22222:127.0.0.1:33333\n"
        "                --jail 127.0.0.1:33333\n"
        "  will process/filter all incoming traffic\n"
        "  at 0.0.0.0:2222 and redirect it\n"
        "  to 127.0.0.1:22222 (libssh) which will redirect it finally\n"
        "  to 127.0.0.1:33333 (jail service).\n\n",
        arg0);
}

int parse_cmdline(int argc, char **argv)
{
    int rc, i, option, option_index;
    struct option *o = (struct option *) calloc(OPT_MAX+1, sizeof *o);

    assert(o);
    for (i = 0; i < OPT_MAX; ++i) {
        o[i].name = options[i].arg_name;
        if (options[i].def_value.ll)
            o[i].has_arg = required_argument;
        else
            o[i].has_arg =
                (options[i].type == OT_NOARG ? no_argument : required_argument);
    }

    rc = 0;
    while (1) {
        option_index = -1;
        option = getopt_long_only(argc, argv, "", o, &option_index);

        if (option_index == -1 && option != -1) {
            rc = 1;
            continue;
        }
        if (option == -1)
            break;

        if (!option) {
            if (!setopt_list(&options[option_index], optarg)) {
            } else if (setopt(&options[option_index], optarg)) {
                rc = 1;
                goto error;
            }
        } else {
            fprintf(stderr, "%s: unknown option '%c' [0x%X]\n",
                argv[0], option, option);
        }
    }

error:
    free(o);

    if (rc)
        usage(argv[0], 0);
    else if (getopt_used(OPT_HELP)) {
        usage(argv[0], 1);
        exit(EXIT_SUCCESS);
    }

    return rc;
}

int getopt_used(opt_name on)
{
    return options[on].used;
}

char *
getopt_str(opt_name on)
{
    char *str;

    assert(options[on].type == OT_STR ||
        options[on].type == OT_PATH);
    assert(getopt_used(on) || options[on].def_value.str);
    str = options[on].value.str_dup;
    if (!str)
        str = options[on].def_value.str_dup;
    assert(str);

    return str;
}

char *
getopt_strlist(opt_name on, opt_list **ol)
{
    opt_list *o;

    assert(options[on].is_list && ol);
    assert(options[on].type == OT_STR ||
        options[on].type == OT_PATH);
    assert(getopt_used(on) && !options[on].def_value.str);

    if (*ol) {
        o = (*ol)->next;
    } else {
        o = options[on].value.list;
    }
    *ol = o;

    return (o ? o->value.str_dup : NULL);
}
