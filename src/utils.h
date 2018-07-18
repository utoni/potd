/*
 * utils.h
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

#ifndef POTD_UTILS_H
#define POTD_UTILS_H 1

#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>

#ifndef SIZEOF
#define SIZEOF(arr) (sizeof(arr)/sizeof(arr[0]))
#endif

#define MIN(x, y) (x > y ? y : x)

extern char *arg0;


int set_fd_nonblock(int fd);

int set_child_sighandler(void);

int set_master_sighandler(void);

void set_procname(const char *new_arg0);

pid_t daemonize(int stay_foreground);

int close_fds_except(int fd, ...);

int redirect_devnull_to(int fds, ...);

int change_user_group(const char *user, const char *group);

int change_default_user_group(void);

int safe_chroot(const char *newroot);

void mkdir_attr(const char *fname, mode_t mode, uid_t uid, gid_t gid);

int is_dir(const char *fname);

int is_link(const char *fname);

int path_is_mountpoint(const char *path);

void chk_chroot(void);

void mount_root(void);

int mount_dev(const char *mount_path);

int mount_pts(const char *mount_path);

int setup_network_namespace(const char *name);

int switch_network_namespace(const char *name);

int create_device_file_checked(const char *mount_path, const char *device_file,
                               mode_t mode, int add_mode, dev_t dev);

int create_device_files(const char *mount_path);

int cgroups_set(void);

int cgroups_activate(void);

#if 0
int update_guid_map(pid_t pid, unsigned int uid_map[3], int update_uidmap);

int update_setgroups_self(int allow);
#endif

void escape_ascii_string(const char ascii[], size_t siz,
                         char **dest, size_t *newsiz);

size_t parse_hostport(const char *str, const char *result[2],
                      size_t siz[2]);

size_t parse_hostport_str(const char *str, char hbuf[NI_MAXHOST],
                          char sbuf[NI_MAXSERV]);

int selftest_minimal_requirements(void);

#endif
