/*
 * log_file.h
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

#ifndef POTD_LOG_FILE_H
#define POTD_LOG_FILE_H 1

#include "log.h"

#define LOG_FILE_FUNCS log_open_file, log_close_file, \
    log_fmt_file, log_fmtex_file, log_fmtexerr_file

extern char *log_file;


int log_open_file(void);

void log_close_file(void);

void log_fmt_file(log_priority prio, const char *fmt, ...);

void log_fmtex_file(log_priority prio, const char *srcfile,
                    size_t line, const char *fmt, ...);

void log_fmtexerr_file(log_priority prio, const char *srcfile,
                       size_t line, const char *fmt, ...);

#endif
