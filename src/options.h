/*
 * options.h
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

#ifndef POTD_OPTIONS_H
#define POTD_OPTIONS_H 1

struct opt_list;

typedef enum opt_name {
    OPT_LOGTOFILE = 0, OPT_LOGFILE, OPT_LOGLEVEL,
    OPT_DAEMON,
    OPT_REDIRECT,
    OPT_PROTOCOL,
    OPT_JAIL,
    OPT_ROOT,
    OPT_RODIR,
    OPT_ROFILE,
    OPT_NETNS_RUN_DIR,
    OPT_SSH_RUN_DIR,
    OPT_CHUSER,
    OPT_CHGROUP,
    OPT_SECCOMP_MINIMAL,
    OPT_RUNTEST,

    OPT_HELP,
    OPT_MAX
} opt_name;

typedef int check_opt;


int parse_cmdline(int argc, char **argv);

int getopt_used(opt_name on);

char *
getopt_str(opt_name on);

char *
getopt_strlist(opt_name on, struct opt_list **ol);

#endif
