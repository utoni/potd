#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define POTD_RODIR "/var/run/potd-rodir"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <assert.h>

#include "log.h"
#include "utils.h"

typedef struct MountData {
    /*
     * the pathname of the directory in the filesystem which
     * forms the root of this mount
     */
    char *fsname;
    /* mount destination */
    char *dir;
    /* filesystem type */
    char *fstype;
} MountData;

typedef enum {
	BLACKLIST_FILE,
	BLACKLIST_NOLOG,
	MOUNT_READONLY,
	MOUNT_TMPFS,
	MOUNT_NOEXEC,
	MOUNT_RDWR,
	OPERATION_MAX
} OPERATION;

typedef enum {
	UNSUCCESSFUL,
	SUCCESSFUL
} LAST_DISABLE_OPERATION;
LAST_DISABLE_OPERATION last_disable = UNSUCCESSFUL;

static void disable_file(OPERATION op, const char *filename);
static int get_mount_flags(const char *path, unsigned long *flags);
static MountData *
get_last_mount(void);
static void fs_rdonly(const char *dir);
static void fs_rdwr(const char *dir);
static void fs_noexec(const char *dir);

#define MAX_BUF 4096
static char mbuf[MAX_BUF];
static MountData mdata;


static void disable_file(OPERATION op, const char *filename)
{
    char *fname;
    struct stat s;

    assert(filename);
    assert(op <OPERATION_MAX);
    last_disable = UNSUCCESSFUL;

    // Resolve all symlinks
    fname = realpath(filename, NULL);
    if (fname == NULL && errno != EACCES) {
        return;
    }

    if (fname == NULL && errno == EACCES) {
        W2("%s: no access to file '%s', forcing mount", __func__, filename);
        // realpath and stat funtions will fail on FUSE filesystems
        // they don't seem to like a uid of 0
        // force mounting
        int rv = mount(POTD_RODIR, filename, "none", MS_BIND, "mode=400,gid=0");
        if (rv == 0) {
            last_disable = SUCCESSFUL;
        } else {
            rv = mount(POTD_RODIR, filename, "none", MS_BIND, "mode=400,gid=0");
            if (rv == 0)
                last_disable = SUCCESSFUL;
        }
        if (last_disable == SUCCESSFUL) {
            D("%s: disable '%s' successful", __func__, filename);
        } else {
            W2("%s: '%s' is an invalid file, skipping...", __func__, filename);
        }

        return;
    }

    // if the file is not present, do nothing
    if (fname == NULL)
        return;
    if (stat(fname, &s) == -1) {
        W2("%s: '%s' does not exist, skipping...", __func__, fname);
        free(fname);
        return;
    }

    // modify the file
    if (op == BLACKLIST_FILE || op == BLACKLIST_NOLOG) {
        // some distros put all executables under /usr/bin and make /bin a symbolic link
        if ((strcmp(fname, "/bin") == 0 || strcmp(fname, "/usr/bin") == 0) &&
            is_link(filename) &&
            S_ISDIR(s.st_mode))
        {
            W2("%s: '%s' directory link was not blacklisted", __func__, filename);
        } else {
            if (strcmp(filename, fname)) {
                D("%s: disable '%s' (requested '%s')", __func__, fname, filename);
            } else {
                D("%s: disable '%s'", __func__, fname);
            }

            if (S_ISDIR(s.st_mode)) {
                if (mount(POTD_RODIR, fname, "none", MS_BIND, "mode=400,gid=0") < 0)
                    FATAL("%s: disable dir '%s'", __func__, fname);
            } else {
                if (mount(POTD_RODIR, fname, "none", MS_BIND, "mode=400,gid=0") < 0)
                    FATAL("%s: disable file '%s'", __func__, fname);
            }
            last_disable = SUCCESSFUL;
        }
    } else if (op == MOUNT_READONLY) {
        D("%s: Mounting read-only '%s'", __func__, fname);
        fs_rdonly(fname);
        // TODO: last_disable = SUCCESSFUL;
    } else if (op == MOUNT_RDWR) {
        D("%s: Mounting read-only '%s'", __func__, fname);
        fs_rdwr(fname);
        // TODO: last_disable = SUCCESSFUL;
    } else if (op == MOUNT_NOEXEC) {
        D("%s: Mounting noexec '%s'", __func__, fname);
        fs_noexec(fname);
        // TODO: last_disable = SUCCESSFUL;
    } else if (op == MOUNT_TMPFS) {
        if (S_ISDIR(s.st_mode)) {
            D("%s: Mounting tmpfs on '%s'", __func__, fname);
            // preserve owner and mode for the directory
            if (mount("tmpfs", fname, "tmpfs", MS_NOSUID | MS_NODEV | MS_STRICTATIME | MS_REC,  0) < 0)
                FATAL("%s: mounting tmpfs '%s'", __func__, fname);
            /* coverity[toctou] */
            if (chown(fname, s.st_uid, s.st_gid) == -1)
                FATAL("%s: mounting tmpfs chown '%s'", __func__, fname);
            if (chmod(fname, s.st_mode) == -1)
                FATAL("%s: mounting tmpfs chmod '%s'", __func__, fname);
            last_disable = SUCCESSFUL;
        } else {
            W2("Disable: '%s' is not a directory; cannot mount a tmpfs on top of it.", fname);
        }
    } else assert(0);

    free(fname);
}

static int get_mount_flags(const char *path, unsigned long *flags)
{
    struct statvfs buf;

    if (statvfs(path, &buf) < 0)
        return -errno;
    *flags = buf.f_flag;
    return 0;
}

// Get info regarding the last kernel mount operation.
// The return value points to a static area, and will be overwritten by subsequent calls.
// The function does an exit(1) if anything goes wrong.
static MountData *
get_last_mount(void)
{
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    char *ptr;
    int cnt = 1;

    if (!fp)
        goto errexit;

    mbuf[0] = '\0';
    while (fgets(mbuf, MAX_BUF, fp)) {}
    fclose(fp);
    D("%s: %s", __func__, mbuf);

    // extract filesystem name, directory and filesystem type
    // examples:
    //	587 543 8:1 /tmp /etc rw,relatime master:1 - ext4 /dev/sda1 rw,errors=remount-ro,data=ordered
    //		mdata.fsname: /tmp
    //		mdata.dir: /etc
    //		mdata.fstype: ext4
    //	585 564 0:76 / /home/netblue/.cache rw,nosuid,nodev - tmpfs tmpfs rw
    //		mdata.fsname: /
    //		mdata.dir: /home/netblue/.cache
    //		mdata.fstype: tmpfs
    memset(&mdata, 0, sizeof(mdata));
    ptr = strtok(mbuf, " ");
    if (!ptr)
        goto errexit;

    while ((ptr = strtok(NULL, " ")) != NULL) {
        cnt++;
        if (cnt == 4) {
            mdata.fsname = ptr;
        } else if (cnt == 5) {
            mdata.dir = ptr;
            break;
        }
    }

    ptr = strtok(NULL, "-");
    if (!ptr)
        goto errexit;

    ptr = strtok(NULL, " ");
    if (!ptr)
        goto errexit;
    mdata.fstype = ptr++;

    if (mdata.fsname == NULL ||
        mdata.dir == NULL ||
        mdata.fstype == NULL)
    {
        goto errexit;
    }

    D("%s: fsname='%s' dir='%s' fstype=%s\n", __func__, mdata.fsname,
        mdata.dir, mdata.fstype);
    return &mdata;
errexit:
    E("%s: cannot read /proc/self/mountinfo", __func__);
    exit(1);
}

static void fs_rdonly(const char *dir)
{
    struct stat s;
    int rv;
    unsigned long flags = 0;

    assert(dir);
    // check directory exists
    rv = stat(dir, &s);
    if (rv == 0) {
        get_mount_flags(dir, &flags);
        if ((flags & MS_RDONLY) == MS_RDONLY)
            return;
        flags |= MS_RDONLY;
        // mount --bind /bin /bin
        // mount --bind -o remount,ro /bin
        if (mount(dir, dir, NULL, MS_BIND|MS_REC, NULL) < 0 ||
            mount(NULL, dir, NULL, flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
        {
            FATAL("%s: mount read-only '%s'", __func__, dir);
        }
    }
}

static void fs_rdwr(const char *dir)
{
    char *path;
    struct stat s;
    uid_t u;
    int rv;
    unsigned long flags = 0;
    MountData *mptr;

    assert(dir);

    // check directory exists and ensure we have a resolved path
    // the resolved path allows to run a sanity check after the mount
    path = realpath(dir, NULL);
    if (path == NULL)
        return;

    // allow only user owned directories, except the user is root
    u = getuid();
    rv = stat(path, &s);
    if (rv) {
        free(path);
        return;
    }
    if (u != 0 && s.st_uid != u) {
        W("%s: You are not allowed to change '%s' to read-write", __func__, path);
        free(path);
        return;
    }

    // mount --bind /bin /bin
    // mount --bind -o remount,rw /bin
    get_mount_flags(path, &flags);
    if ((flags & MS_RDONLY) == 0) {
        free(path);
        return;
    }
    flags &= ~MS_RDONLY;

    if (mount(path, path, NULL, MS_BIND|MS_REC, NULL) < 0 ||
        mount(NULL, path, NULL, flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
    {
        FATAL("%s: mount read-write '%s'", __func__, path);
    }

    // run a check on /proc/self/mountinfo to validate the mount
    mptr = get_last_mount();
    if (strncmp(mptr->dir, path, strlen(path)) != 0)
        FATAL("%s: invalid read-write mount for '%s'", __func__, path);

    free(path);
}

static void fs_noexec(const char *dir)
{
    struct stat s;
    int rv;
    unsigned long flags = 0;

    assert(dir);

    // check directory exists
    rv = stat(dir, &s);
    if (rv == 0) {
        // mount --bind /bin /bin
        // mount --bind -o remount,ro /bin
        get_mount_flags(dir, &flags);
        if ((flags & (MS_NOEXEC|MS_NODEV|MS_NOSUID)) == (MS_NOEXEC|MS_NODEV|MS_NOSUID))
            return;
        flags |= MS_NOEXEC|MS_NODEV|MS_NOSUID;

        if (mount(dir, dir, NULL, MS_BIND|MS_REC, NULL) < 0 ||
            mount(NULL, dir, NULL, flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
        {
            FATAL("%s: mount noexec for '%s'", __func__, dir);
        }
    }
}

// Disable /mnt, /media, /run/mount and /run/media access
void fs_mnt(void)
{
    disable_file(BLACKLIST_FILE, "/mnt");
    disable_file(BLACKLIST_FILE, "/media");
    disable_file(BLACKLIST_FILE, "/run/mount");
    disable_file(BLACKLIST_FILE, "//run/media");
}

// mount /proc and /sys directories
void fs_proc_sys(void)
{
    D("%s: Remounting /proc and /proc/sys filesystems", __func__);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_REC, NULL) < 0)
        FATAL("%s: mounting /proc", __func__);

    // remount /proc/sys readonly
    if (mount("/proc/sys", "/proc/sys", NULL, MS_BIND | MS_REC, NULL) < 0 ||
        mount(NULL, "/proc/sys", NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|
            MS_NOEXEC|MS_NODEV|MS_REC, NULL) < 0)
    {
        FATAL("%s: mounting /proc/sys", __func__);
    }

    /* Mount a version of /sys that describes the network namespace */
    D("%s: Remounting /sys directory", __func__);
    if (umount2("/sys", MNT_DETACH) < 0)
        W("%s: failed to unmount /sys", __func__);
    if (mount("sysfs", "/sys", "sysfs", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REC, NULL) < 0) {
        W("%s: failed to mount /sys", __func__);
    } else {
        W("%s: remount /sys", __func__);
    }

    disable_file(BLACKLIST_FILE, "/sys/firmware");
    disable_file(BLACKLIST_FILE, "/sys/hypervisor");
    disable_file(BLACKLIST_FILE, "/sys/power");
    disable_file(BLACKLIST_FILE, "/sys/kernel/debug");
    disable_file(BLACKLIST_FILE, "/sys/kernel/vmcoreinfo");
    disable_file(BLACKLIST_FILE, "/sys/kernel/uevent_helper");

    // various /proc/sys files
    disable_file(BLACKLIST_FILE, "/proc/sys/security");
    disable_file(BLACKLIST_FILE, "/proc/sys/efi/vars");
    disable_file(BLACKLIST_FILE, "/proc/sys/fs/binfmt_misc");
    disable_file(BLACKLIST_FILE, "/proc/sys/kernel/core_pattern");
    disable_file(BLACKLIST_FILE, "/proc/sys/kernel/modprobe");
    disable_file(BLACKLIST_FILE, "/proc/sysrq-trigger");
    disable_file(BLACKLIST_FILE, "/proc/sys/kernel/hotplug");
    disable_file(BLACKLIST_FILE, "/proc/sys/vm/panic_on_oom");

    // various /proc files
    disable_file(BLACKLIST_FILE, "/proc/irq");
    disable_file(BLACKLIST_FILE, "/proc/bus");
    disable_file(BLACKLIST_FILE, "/proc/config.gz");
    disable_file(BLACKLIST_FILE, "/proc/sched_debug");
    disable_file(BLACKLIST_FILE, "/proc/timer_list");
    disable_file(BLACKLIST_FILE, "/proc/timer_stats");
    disable_file(BLACKLIST_FILE, "/proc/kcore");
    disable_file(BLACKLIST_FILE, "/proc/kallsyms");
    disable_file(BLACKLIST_FILE, "/proc/mem");
    disable_file(BLACKLIST_FILE, "/proc/kmem");

    // remove kernel symbol information
    disable_file(BLACKLIST_FILE, "/usr/src/linux");
    disable_file(BLACKLIST_FILE, "/lib/modules");
    disable_file(BLACKLIST_FILE, "/usr/lib/debug");
    disable_file(BLACKLIST_FILE, "/boot");

    // disable /selinux
    disable_file(BLACKLIST_FILE, "/selinux");

    // disable /dev/port
    disable_file(BLACKLIST_FILE, "/dev/port");

    // disable /dev/kmsg and /proc/kmsg
    disable_file(BLACKLIST_FILE, "/dev/kmsg");
    disable_file(BLACKLIST_FILE, "/proc/kmsg");
}

void fs_var_lock(void)
{
    char *lnk;

    if (is_dir("/var/lock")) {
        D("%s: Mounting tmpfs on /var/lock", __func__);
        if (mount("tmpfs", "/var/lock", "tmpfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|
            MS_STRICTATIME | MS_REC,  "mode=1777,gid=0") < 0)
        {
            FATAL("%s: mounting /lock", __func__);
        }
    } else {
        lnk = realpath("/var/lock", NULL);
        if (lnk) {
            if (!is_dir(lnk)) {
                // create directory
                mkdir_attr(lnk, S_IRWXU|S_IRWXG|S_IRWXO, 0, 0);
            }
            D("%s: Mounting tmpfs on %s on behalf of /var/lock", __func__, lnk);
            if (mount("tmpfs", lnk, "tmpfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|
                MS_STRICTATIME | MS_REC,  "mode=1777,gid=0") < 0)
            {
                FATAL("%s: mounting /var/lock", __func__);
            }
            free(lnk);
        } else {
            W("%s: /var/lock not mounted", __func__);
        }
    }
}

void fs_var_tmp(void)
{
    struct stat s;

    if (stat("/var/tmp", &s) == 0) {
        if (!is_link("/var/tmp")) {
            D("%s: Mounting tmpfs on /var/tmp", __func__);
            if (mount("tmpfs", "/var/tmp", "tmpfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|
                MS_STRICTATIME | MS_REC,  "mode=1777,gid=0") < 0)
            {
                FATAL("%s: mounting /var/tmp", __func__);
            }
        }
    } else {
        W("%s: /var/tmp not mounted", __func__);
    }
}

// build a basic read-only filesystem
void fs_basic_fs(void)
{
    D("%s: Mounting read-only /etc, /var, /bin, /sbin, /lib, /lib32, "
        "/lib64, /usr", __func__);
    fs_rdonly("/etc");
    fs_rdonly("/var");
    fs_rdonly("/bin");
    fs_rdonly("/sbin");
    fs_rdonly("/lib");
    fs_rdonly("/lib64");
    fs_rdonly("/lib32");
    fs_rdonly("/libx32");
    fs_rdonly("/usr");

    // update /var directory in order to support multiple sandboxes running on the same root directory
	fs_var_lock();
    fs_var_tmp();
    fs_rdwr("/var/log");
    fs_rdwr("/var/lib");
    fs_rdwr("/var/cache");
    fs_rdwr("/var/utmp");
}

