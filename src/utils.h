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

int path_is_mountpoint(const char *path);

void chk_chroot(void);

void mount_root(void);

int mount_dev(const char *mount_path);

int mount_pts(const char *mount_path);

int mount_proc(const char *mount_path);

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
