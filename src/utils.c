#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <linux/limits.h>
#include <assert.h>

#include "utils.h"
#include "log.h"
#include "options.h"

#define _POSIX_PATH_MAX 256

char *arg0 = NULL;
static int null_fd = -1;
static const char cgmem[] = "/sys/fs/cgroup/memory/potd";
static const char cgcpu[] = "/sys/fs/cgroup/cpu/potd";
static const char cgpid[] = "/sys/fs/cgroup/pids/potd";
static const char cgdef[] = "/sys/fs/cgroup/potd";
static const char *_cgmem = NULL;
static const char *_cgcpu = NULL;
static const char *_cgpid = NULL;

static char *
sig_to_str(int signo, char *buf, size_t siz);
static void sighandler_child(int signo);
static void sighandler_master(int signo);
static int cgroups_write_file(const char *cdir, const char *csub,
                              const char *value, size_t siz);
static inline void bin2hex_char(unsigned char c, char hexc[5]);


int set_fd_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return 1;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1)
        return 1;

    return 0;
}

static char *
sig_to_str(int signo, char *buf, size_t siz)
{
    switch (signo) {
        case SIGCHLD:
            strncpy(buf, "SIGCHLD", siz-1); break;
        case SIGPIPE:
            strncpy(buf, "SIGPIPE", siz-1); break;
        case SIGABRT:
            strncpy(buf, "SIGABRT", siz-1); break;
        case SIGSEGV:
            strncpy(buf, "SIGSEGV", siz-1); break;
        case SIGTERM:
            strncpy(buf, "SIGTERM", siz-1); break;
        case SIGINT:
            strncpy(buf, "SIGINT", siz-1); break;
        case SIGHUP:
            strncpy(buf, "SIGHUP", siz-1); break;
        default:
            strncpy(buf, "UNKNOWN", siz-1); break;
    }
    buf[siz - 1] = 0;

    return buf;
}

static void sighandler_child(int signo)
{
    char buf[16] = {0};

    W("Got signal[%d]: %s", signo, sig_to_str(signo, &buf[0], sizeof buf));
    switch (signo) {
        case SIGABRT:
            exit(EXIT_FAILURE);
        case SIGHUP:
            if (getppid() == 1) {
                N("Master process %d died, exiting", getpgrp());
                exit(EXIT_SUCCESS);
            }
            break;
        case SIGSEGV:
#ifdef HAVE_CONFIG_H
            E("Segmentation fault .. please report to <%s>", PACKAGE_BUGREPORT);
#else
            E("%s", "Segmentation fault ..");
#endif
            exit(EXIT_FAILURE);
    }
}

int set_child_sighandler(void)
{
    if (prctl(PR_SET_PDEATHSIG, SIGHUP) != 0)
        return 1;
    assert( signal(SIGCHLD, SIG_IGN) != SIG_ERR );
    assert( signal(SIGPIPE, SIG_IGN) != SIG_ERR );
    assert( signal(SIGABRT, sighandler_child) != SIG_ERR );
    assert( signal(SIGSEGV, sighandler_child) != SIG_ERR );

    return signal(SIGHUP, sighandler_child) == SIG_ERR;
}

static void sighandler_master(int signo)
{
    static int exiting = 0;
    char buf[16] = {0};

    W("Got signal[%d]: %s", signo, sig_to_str(signo, &buf[0], sizeof buf));
    switch (signo) {
        case SIGSEGV:
        case SIGINT:
        case SIGTERM:
        case SIGABRT:
            if (exiting)
                break;
            exiting = 1;
            kill(0, SIGTERM);
            exit(EXIT_FAILURE);
    }
}

int set_master_sighandler(void)
{
    int s = 0;

    s |= signal(SIGSEGV, sighandler_master) == SIG_ERR;
    s |= signal(SIGINT, sighandler_master) == SIG_ERR;
    s |= signal(SIGTERM, sighandler_master) == SIG_ERR;
    s |= signal(SIGABRT, sighandler_master) == SIG_ERR;

    return s;
}

void set_procname(const char *new_arg0)
{
    assert(arg0);
	memset(arg0, 0, _POSIX_PATH_MAX);
	strncpy(arg0, new_arg0, _POSIX_PATH_MAX);
}

pid_t daemonize(int stay_foreground)
{
    int status = -1;
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0) {
        E_STRERR("%s", "fork");
        return pid;
    }

    /* Success: Let the parent terminate */
    if (pid > 0) {
        if (!stay_foreground)
            exit(EXIT_SUCCESS);
        waitpid(-1, &status, 0);
        exit(EXIT_SUCCESS);
    }

    /* On success: The child process becomes session leader */
    if (!stay_foreground && setsid() < 0) {
        E_STRERR("%s", "setsid");
        exit(EXIT_FAILURE);
    }

    /* Fork off for the second time*/
    if (!stay_foreground) {
        pid = fork();

        /* An error occurred */
        if (pid < 0)
            exit(EXIT_FAILURE);

        /* Success: Let the parent terminate */
        if (pid > 0)
            exit(EXIT_SUCCESS);
    }

    if (!stay_foreground && setpgrp()) {
        E_STRERR("%s", "setpgrp");
        exit(EXIT_FAILURE);
    }

    /* Set new file permissions */
    umask(0);

    if (!stay_foreground) {
        /* Change the working directory to the root directory */
        /* or another appropriated directory */
        chdir("/");
        /* Close all open file descriptors */
        assert( close_fds_except(-1) == 0 );
        assert( redirect_devnull_to(0, 1, 2, -1) == 0 );
    } else {
        assert( close_fds_except(0, 1, 2, -1) == 0 );
    }

    if (log_open())
        return -1;

    return pid;
}

int close_fds_except(int fds, ...)
{
    int fd;
    long max_fd;
    size_t i, except_count, found;
    va_list ap;

    max_fd = sysconf(_SC_OPEN_MAX) - 1;
    if (max_fd <= 0)
        max_fd = 1024;

    va_start(ap, fds);
    {
        int *all_fds = (int *) malloc((max_fd+1) * sizeof(*all_fds));
        assert(all_fds);
        memset(all_fds, -1, max_fd * sizeof(*all_fds));

        except_count = 0;
        while ( (fd = va_arg(ap, int)) >= 0 ) {
            all_fds[except_count++] = fd;
        }
        all_fds[except_count++] = fds;

        for (fd = max_fd; fd >= 0; --fd) {
            found = 0;
            for (i = 0; i < except_count && fds >= 0; ++i) {
                if (fd == all_fds[i])
                    found++;
            }
            if (!found) {
                close(fd);
            }
        }

        free(all_fds);
    }
    va_end(ap);

    return 0;
}

int redirect_devnull_to(int fds, ...)
{
    int fd, rc = 0;
    va_list ap;

    if (null_fd < 0)
        null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0)
        return -1;
    if (fds < -1)
        return -1;

    va_start(ap, fds);
    {
        while ( (fd = va_arg(ap, int)) >= 0 ) {
            if ( dup2(null_fd, fd) < 0 )
                rc++;
        }
    }
    va_end(ap);

    return rc;
}

int change_user_group(const char *user, const char *group)
{
    struct passwd *pwd = NULL;
    struct group *grp = NULL;
    gid_t gid;

    pwd = getpwnam(user);
    if (!pwd)
        return 1;

    if (!group) {
        gid = pwd->pw_gid;
    } else {
        grp = getgrnam(group);
        if (!grp)
            return 1;
        gid = grp->gr_gid;
    }

    if (setresgid(gid, gid, gid))
        return 1;
    if (setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid))
        return 1;

    return 0;
}

int change_default_user_group(void)
{
    return change_user_group("nobody", NULL);
}

int safe_chroot(const char *newroot)
{
    int s;

    s = chdir(newroot);
    if (s) {
        E_STRERR("Change directory to '%s'", newroot);
        return 1;
    }

    s = chroot(".");
    if (s) {
        E_STRERR("Change root directory to '%s'", ".");
        return 1;
    }

    s = chdir("/");
    if (s) {
        E_STRERR("Change directory inside new root to '%s'", "/");
        return 1;
    }

    return 0;
}

int dir_is_mountpoint(const char *path)
{
    struct stat current = {0}, parent = {0};
    size_t plen = strnlen(path, PATH_MAX);
    char parent_path[plen + 4];

    if (stat(path, &current))
        goto error;
    strncpy(parent_path, path, plen);
    parent_path[plen] = '/';
    parent_path[plen+1] = '.';
    parent_path[plen+2] = '.';
    parent_path[plen+3] = 0;

    if (stat(parent_path, &parent))
        goto error;

    return current.st_dev != parent.st_dev;
error:
    W_STRERR("Mountpoint check for '%s'", path);
    return -1;
}

void chk_chroot(void)
{
    struct stat s = {0};

    if (stat("/", &s) == 0) {
        if (s.st_ino != 2)
            return;
    }

    W2("%s", "Can not mount filesystem as slave/private");
}

void mount_root(void)
{
    int s;
    s = mount("", "/", "none", MS_SLAVE|MS_REC, NULL);
    if (s)
        s = mount("", "/", "none", MS_PRIVATE|MS_REC, NULL);
    if (s)
        chk_chroot();
}

int mount_dev(const char *mount_path)
{
    int s;

    s = mount("tmpfs", mount_path, "tmpfs",
              MS_NOSUID|MS_STRICTATIME|
              MS_NOEXEC|MS_REC,
              "size=4k,mode=755,gid=0");
    if (s) {
        E_STRERR("Mount devtmpfs filesystem to %s", mount_path);
        return 1;
    }

    return 0;
}

int mount_pts(const char *mount_path)
{
    int s;

    s = mount("devpts", mount_path, "devpts",
              MS_MGC_VAL,
              "newinstance,gid=5,mode=620,ptmxmode=0666");

    if (s) {
        E_STRERR("Mount devpts filesystem to %s", mount_path);
        return 1;
    }

    return 0;
}

int mount_proc(const char *mount_path)
{
    int s;

    umount(mount_path);
    s = mount("proc", mount_path, "proc",
              MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REC, NULL);
    if (s) {
        E_STRERR("Mount proc filesystem to %s", mount_path);
        return 1;
    }

    return 0;
}

int setup_network_namespace(const char *name)
{
    int fd;
    char netns_path[PATH_MAX];
    int made_netns_run_dir_mount = 0;

    snprintf(netns_path, sizeof netns_path, "%s/%s",
        getopt_str(OPT_NETNS_RUN_DIR), name);
    D2("Network Namespace path '%s'", netns_path);

    if (mkdir(getopt_str(OPT_NETNS_RUN_DIR),
        S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH))
    {
        if (errno != EEXIST) {
            E_STRERR("Create netns directory '%s'",
                getopt_str(OPT_NETNS_RUN_DIR));
            return 1;
        }
    }

    while (mount("", getopt_str(OPT_NETNS_RUN_DIR), "none",
        MS_SHARED|MS_REC, NULL))
    {
        /* Fail unless we need to make the mount point */
        if (errno != EINVAL || made_netns_run_dir_mount) {
            E_STRERR("Mount netns directory '%s' as shared",
                getopt_str(OPT_NETNS_RUN_DIR));
            return 1;
        }

        /* Upgrade NETNS_RUN_DIR to a mount point */
        if (mount(getopt_str(OPT_NETNS_RUN_DIR), getopt_str(OPT_NETNS_RUN_DIR),
            "none", MS_BIND | MS_REC, NULL))
        {
            E_STRERR("Bind mount netns directory '%s'",
                getopt_str(OPT_NETNS_RUN_DIR));
            return 1;
        }
        made_netns_run_dir_mount = 1;
    }

    /* Create the filesystem state */
    fd = open(netns_path, O_RDONLY|O_CREAT|O_EXCL, 0);
    if (fd < 0 && errno != EEXIST) {
        E_STRERR("Create namespace file '%s'", netns_path);
        return 1;
    }
    if (fd >= 0)
        close(fd);

    if (unshare(CLONE_NEWNET) < 0) {
        E_STRERR("Create network namespace '%s'", name);
        goto error;
    }

    /* Bind the netns last so I can watch for it */
    if (mount("/proc/self/ns/net", netns_path, "none", MS_BIND, NULL) < 0) {
        E_STRERR("Bind /proc/self/ns/net to '%s'", netns_path);
		goto error;
    }

    return 0;
error:
    /* cleanup netns? */
    return 1;
}

int switch_network_namespace(const char *name)
{
    char net_path[PATH_MAX];
    int netns;

    snprintf(net_path, sizeof(net_path), "%s/%s",
        getopt_str(OPT_NETNS_RUN_DIR), name);
    netns = open(net_path, O_RDONLY | O_CLOEXEC);
    if (netns < 0) {
        E_STRERR("Cannot open network namespace '%s'", name);
        return 1;
    }

    if (setns(netns, CLONE_NEWNET) < 0) {
        E_STRERR("Setting the network namespace '%s'", name);
        close(netns);
        return 1;
    }
    close(netns);

    return 0;
}

int create_device_file_checked(const char *mount_path, const char *device_file,
                               mode_t mode, int add_mode, dev_t dev)
{
    int s;
    mode_t defmode = S_IRUSR|S_IWUSR|
                     S_IRGRP|S_IWGRP|
                     S_IROTH;
    size_t plen = strnlen(mount_path, PATH_MAX);
    size_t dlen = strnlen(device_file, PATH_MAX);
    struct stat devbuf = {0};
    char devpath[plen+dlen+2];

    snprintf(devpath, plen+dlen+2, "%s/%s", mount_path, device_file);
    s = stat(devpath, &devbuf);

    if (s && errno != EEXIST && errno != ENOENT) {
        return 1;
    }
    if (errno == EEXIST) {
        if (unlink(devpath))
            return 1;
    }

    D2("Create device file: %s", devpath);
    if (!add_mode)
        defmode = 0;
    s = mknod(devpath, defmode|mode, dev);
    if (s) {
        E_STRERR("Device creation '%s'", devpath);
        return 1;
    }

    return 0;
}

int create_device_files(const char *mount_path)
{
    int s = 0;

    s |= create_device_file_checked(mount_path, "ptmx", S_IFCHR, 1, makedev(5,2));
    s |= create_device_file_checked(mount_path, "tty", S_IFCHR, 1, makedev(5,0));

    return s;
}

static int cgroups_write_file(const char *cdir, const char *csub,
                              const char *value, size_t siz)
{
    int fd, s = 0;
    char buf[BUFSIZ] = {0};

    assert(cdir && csub && value);

    D2("Write '%s' to '%s/%s'", value, cdir, csub);
    if (snprintf(buf, sizeof buf, "%s/%s", cdir, csub) > 0) {
        if ((fd = open(buf, O_WRONLY)) < 0 ||
             write(fd, value, siz) <= 0)
        {
            W_STRERR("Write '%s' to '%s/%s'",
                value, cdir, csub);
            s = 1;
        }
        close(fd);
    }

    return s;
}

int cgroups_set(void)
{
    int s = 0, fail = 0;

    const char maxmem[] = "memory.limit_in_bytes";
    const char maxmem_soft[] = "memory.soft_limit_in_bytes";
    const char kmem[] = "memory.kmem.limit_in_bytes";
    const char kmem_tcp[] = "memory.kmem.tcp.limit_in_bytes";
    const char maxmem_limit[] = "8388608"; /* 8*1024*1024 = 8MB */
    const char maxmem_soft_limit[] = "7340032"; /* 7*1024*1024 = 8MB */
    const char cpu_shares[] = "cpu.shares";
    const char cpu_shares_limit[] = "32";
    const char cfs_period[] = "cpu.cfs_period_us";
    const char cfs_period_limit[] = "50000";
    const char cfs_quota[] = "cpu.cfs_quota_us";
    const char cfs_quota_limit[] = "10000";
    const char pid_max[] = "pids.max";
    const char pid_max_limit[] = "10";
    const char rt_period[] = "cpu.rt_period_us";
    const char *rt_period_limit = cfs_period_limit;
    const char rt_runtime[] = "cpu.rt_runtime_us";
    const char *rt_runtime_limit = cfs_quota_limit;
    const char ccpus[] = "cpuset.cpus";
    const char cmems[] = "cpuset.mems";

    if (remove(cgmem) && errno != ENOENT)
        return 1;
    errno = 0;
    s |= mkdir(cgmem,
        S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH);
    if (errno)
        fail++;

    if (remove(cgcpu) && errno != ENOENT)
        return 1;
    errno = 0;
    s |= mkdir(cgcpu,
        S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH);
    if (errno)
        fail++;

    if (remove(cgpid) && errno != ENOENT)
        return 1;
    errno = 0;
    s |= mkdir(cgpid,
        S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH);
    if (errno)
        fail++;

    if (fail == 3) {
        if (remove(cgdef) && errno != ENOENT)
            return 1;
        s = mkdir(cgdef,
            S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH);
        if (s)
            return 1;

        s |= cgroups_write_file(cgdef, ccpus, "0", 1);
        s |= cgroups_write_file(cgdef, cmems, "0", 1);

        _cgmem = cgdef;
        _cgcpu = cgdef;
        _cgpid = cgdef;
    } else {
        _cgmem = cgmem;
        _cgcpu = cgcpu;
        _cgpid = cgpid;
    }

    s |= cgroups_write_file(_cgmem, maxmem, maxmem_limit, sizeof maxmem_limit);
    s |= cgroups_write_file(_cgmem, maxmem_soft, maxmem_soft_limit,
        sizeof maxmem_limit);
    s |= cgroups_write_file(_cgmem, kmem_tcp, maxmem_limit, sizeof maxmem_limit);
    s |= cgroups_write_file(_cgmem, kmem, maxmem_limit, sizeof maxmem_limit);
    s |= cgroups_write_file(_cgcpu, cpu_shares, cpu_shares_limit,
        sizeof cpu_shares_limit);

    errno = 0;
    cgroups_write_file(_cgcpu, cfs_period, cfs_period_limit,
        sizeof cfs_period_limit);
    if (errno) {
        s |= cgroups_write_file(_cgcpu, rt_period, rt_period_limit,
                sizeof cfs_period_limit);
    }

    errno = 0;
    cgroups_write_file(_cgcpu, cfs_quota, cfs_quota_limit,
        sizeof cfs_quota_limit);
    if (errno) {
        s |= cgroups_write_file(_cgcpu, rt_runtime, rt_runtime_limit,
                sizeof cfs_quota_limit);
    }

    s |= cgroups_write_file(_cgpid, pid_max, pid_max_limit,
        sizeof pid_max_limit);

    return s;
}

int cgroups_activate(void)
{
    pid_t p = getpid();
    int s;
    char buf[32] = {0};
    const char tasks[] = "tasks";

    s = snprintf(buf, sizeof buf, "%d", p);
    if (s <= 0)
        return 1;
    s = cgroups_write_file(_cgmem, tasks, buf, s);

    s = snprintf(buf, sizeof buf, "%d", p);
    if (s <= 0)
        return 1;
    s = cgroups_write_file(_cgcpu, tasks, buf, s);

    s = snprintf(buf, sizeof buf, "%d", p);
    if (s <= 0)
        return 1;
    s = cgroups_write_file(_cgpid, tasks, buf, s);

    return s;
}

#if 0
int update_guid_map(pid_t pid, unsigned int map[3], int update_uidmap)
{
    int s, fd;
    ssize_t written;
    const char path_pid[] = "/proc/%d/%s";
    const char path_self[] = "/proc/self/%s";
    char buf[64];

    if (pid < 0) {
        s = snprintf(buf, sizeof buf, path_self,
                (update_uidmap ? "uid_map" : "gid_map"));
    } else {
        s = snprintf(buf, sizeof buf, path_pid, pid,
                (update_uidmap ? "uid_map" : "gid_map"));
    }
    if (s <= 0)
        return 1;

    fd = open(buf, O_WRONLY);
    if (fd < 0)
        return 1;

    s = snprintf(buf, sizeof buf, "%u %u %u\n", map[0], map[1], map[2]);
    written = write(fd, buf, s);
    if (written <= 0)
        return 1;

    return 0;
}

int update_setgroups_self(int allow)
{
    int fd;
    ssize_t written;
    const char path_self[] = "/proc/self/setgroups";
    const char str_allow[] = "allow";
    const char str_deny[] = "deny";

    fd = open(path_self, O_WRONLY);
    if (fd < 0)
        return 1;

    if (allow) {
        written = write(fd, str_allow, sizeof(str_allow) - 1);
    } else {
        written = write(fd, str_deny, sizeof(str_deny) - 1);
    }
    if (written <= 0)
        return 1;

    return 0;
}
#endif

static inline void bin2hex_char(unsigned char c, char hexc[5])
{
    static const char hexalnum[] = "0123456789ABCDEF";

    hexc[0] = '\\';
    hexc[1] = 'x';
    hexc[2] = hexalnum[ (c >> 4)%16 ];
    hexc[3] = hexalnum[ (c & 0x0F)%16 ];
    hexc[4] = 0;
}

void escape_ascii_string(const char ascii[], size_t siz, char **dest, size_t *newsiz)
{
    char hexbyte[5];
    const size_t binsiz = 4;
    size_t i, j, ns;

    assert(ascii && dest && newsiz);

    ns = 0;
    for (i = 0; i < siz; ++i) {
        if (isprint(ascii[i]))
            ns++;
        else
            ns += binsiz;
    }

    if (ns > *newsiz) {
        if (*dest)
            free(*dest);
        *dest = (char *) malloc(sizeof(char) * (ns+1));
        assert(*dest);
        (*newsiz) = ns;
    }

    for (i = 0, j = 0; i < siz && j < ns; ++i) {
        if (isprint(ascii[i])) {
            (*dest)[j] = ascii[i];
            j++;
        } else {
            bin2hex_char(ascii[i], hexbyte);
            snprintf((*dest)+j, binsiz+1, "%s", hexbyte);
            j += binsiz;
        }
    }

    (*dest)[ns] = 0;
}

size_t parse_hostport(const char *str, const char *result[2],
                      size_t siz[2])
{
    size_t i;
    const char *hostend = strchr(str, ':');
    const char *portend;
    const char sep[] = ": \t\n\0";

    result[0] = NULL;
    result[1] = NULL;
    siz[0] = 0;
    siz[1] = 0;

    if (!hostend)
        return 0;
    hostend++;
    for (i = 0; i < SIZEOF(sep); ++i) {
        portend = strchr(hostend, sep[i]);
        if (portend)
            break;
    }
    if (!portend)
        return 0;

    result[0] = str;
    result[1] = hostend;
    siz[0] = hostend - str - 1;
    siz[1] = portend - hostend;

    return siz[0] + siz[1] + 1 + (*portend != 0 ? 1 : 0);
}

size_t parse_hostport_str(const char *str, char hbuf[NI_MAXHOST],
                          char sbuf[NI_MAXSERV])
{
    const char *hostport[2];
    size_t hostport_siz[2];
    size_t siz;

    siz = parse_hostport(str, hostport, hostport_siz);
    if (!siz)
        return 0;
    if (snprintf(hbuf, NI_MAXHOST, "%.*s", (int) hostport_siz[0],
        hostport[0]) <= 0)
    {
        return 0;
    }
    if (snprintf(sbuf, NI_MAXSERV, "%.*s", (int) hostport_siz[1],
        hostport[1]) <= 0)
    {
        return 0;
    }

    return siz;
}