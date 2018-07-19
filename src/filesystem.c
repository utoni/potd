/*
 * filesystem.c
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
#define POTD_RODIR "/var/run/potd-rodir"
#define POTD_ROFILE "/var/run/potd-rofile"
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
#include "compat.h"
#include "utils.h"
#include "options.h"

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

typedef enum fs_oper {
	BLACKLIST_FILE,
	MOUNT_READONLY,
	MOUNT_TMPFS,
	MOUNT_NOEXEC,
	MOUNT_RDWR,
	OPERATION_MAX
} fs_oper;

typedef enum {
	UNSUCCESSFUL,
	SUCCESSFUL
} last_disable_oper;
last_disable_oper last_disable = UNSUCCESSFUL;

static void disable_file(fs_oper op, const char *filename);
static void disable_file_newroot(fs_oper op, const char *filename,
                                 const char *newroot);
static int get_mount_flags(const char *path, unsigned long *flags);
static MountData *
get_last_mount(void);
static void fs_rdonly(const char *dir);
static void fs_rdwr(const char *dir);
static void fs_noexec(const char *dir);
static void fs_var_lock(void);
static void fs_var_tmp(void);

static char mbuf[BUFSIZ];
static MountData mdata;


static void disable_file(fs_oper op, const char *filename)
{
    char *fname;
    struct stat s;
    int rv;

    assert(filename);
    assert(op < OPERATION_MAX);
    last_disable = UNSUCCESSFUL;

    // Resolve all symlinks
    fname = realpath(filename, NULL);
    if (fname == NULL && errno != EACCES) {
        if (errno == ENOENT)
            W_STRERR("%s: realpath '%s'", __func__, filename);
        else
            E_STRERR("%s: realpath '%s'", __func__, filename);
        return;
    }

    if (fname == NULL && errno == EACCES) {
        W2("%s: no access to file '%s', forcing mount", __func__, filename);
        // realpath and stat funtions will fail on FUSE filesystems
        // they don't seem to like a uid of 0
        // force mounting
        rv = mount(getopt_str(OPT_RODIR), filename, "none",
            MS_BIND, "mode=400,gid=0");
        if (rv == 0) {
            last_disable = SUCCESSFUL;
        } else {
            rv = mount(getopt_str(OPT_ROFILE), filename, "none", MS_BIND,
                "mode=400,gid=0");
            if (rv == 0)
                last_disable = SUCCESSFUL;
        }
        if (last_disable == SUCCESSFUL) {
            D("%s: disable '%s' forced", __func__, filename);
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
    if (op == BLACKLIST_FILE) {
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
                if (mount(getopt_str(OPT_RODIR), fname, "none", MS_BIND,
                    "mode=400,gid=0") < 0)
                {
                    FATAL("%s: disable dir '%s'", __func__, fname);
                }
            } else {
                if (mount(getopt_str(OPT_ROFILE), fname, "none", MS_BIND,
                    "mode=400,gid=0") < 0)
                {
                    FATAL("%s: disable file '%s'", __func__, fname);
                }
            }
            last_disable = SUCCESSFUL;
        }
    } else if (op == MOUNT_READONLY) {
        D("%s: Mounting read-only '%s'", __func__, fname);
        fs_rdonly(fname);
        // TODO: last_disable = SUCCESSFUL;
    } else if (op == MOUNT_RDWR) {
        D("%s: Mounting read-write '%s'", __func__, fname);
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
            if (mount("tmpfs", fname, "tmpfs", MS_NOSUID|MS_NODEV|
                MS_STRICTATIME|MS_REC,  0) < 0)
            {
                FATAL("%s: mounting tmpfs '%s'", __func__, fname);
            }
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

static void disable_file_newroot(fs_oper op, const char *filename,
                                 const char *newroot)
{
    char path[PATH_MAX];

    snprintf(path, sizeof path, "%s%s", newroot, filename);
    disable_file(op, path);
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
    char *ptr, *saveptr = NULL;
    int cnt = 1;
    size_t len;

    if (!fp)
        goto errexit;

    mbuf[0] = '\0';
    while (fgets(mbuf, BUFSIZ, fp)) {}
    fclose(fp);
    len = strnlen(mbuf, BUFSIZ);
    if (mbuf[len - 1] == '\n')
        mbuf[len - 1] = 0;
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
    ptr = potd_strtok(mbuf, " ", &saveptr);
    if (!ptr)
        goto errexit;

    while ((ptr = potd_strtok(NULL, " ", &saveptr)) != NULL) {
        cnt++;
        if (cnt == 4) {
            mdata.fsname = ptr;
        } else if (cnt == 5) {
            mdata.dir = ptr;
            break;
        }
    }

    ptr = potd_strtok(NULL, "-", &saveptr);
    if (!ptr)
        goto errexit;

    ptr = potd_strtok(NULL, " ", &saveptr);
    if (!ptr)
        goto errexit;
    mdata.fstype = ptr++;

    if (mdata.fsname == NULL ||
        mdata.dir == NULL ||
        mdata.fstype == NULL)
    {
        goto errexit;
    }

    D("%s: fsname='%s' dir='%s' fstype=%s", __func__, mdata.fsname,
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
        if (mount(dir, dir, "none", MS_BIND|MS_REC, NULL) < 0 ||
            mount("none", dir, "none", flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
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

    if (mount(path, path, "none", MS_BIND|MS_REC, NULL) < 0 ||
        mount("none", path, "none", flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
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

        if (mount(dir, dir, "none", MS_BIND|MS_REC, NULL) < 0 ||
            mount("none", dir, "none", flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
        {
            FATAL("%s: mount noexec for '%s'", __func__, dir);
        }
    }
}

// mount /proc and /sys directories
void fs_proc_sys(const char *newroot)
{
    char path[PATH_MAX] = {0};

    assert(newroot);

    snprintf(path, sizeof path, "%s/proc", newroot);
    D("%s: Remounting '%s'", __func__, path);
    if (mount("proc", path, "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REC,
            NULL) < 0)
    {
        FATAL("%s: mounting %s", __func__, path);
    }

    // remount /proc/sys readonly
    snprintf(path, sizeof path, "%s/proc/sys", newroot);
    D("%s: Remounting '%s'", __func__, path);
    if (mount(path, path, "none", MS_BIND|MS_REC, NULL) < 0 ||
        mount(NULL, path, "none", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|
            MS_NOEXEC|MS_NODEV|MS_REC, NULL) < 0)
    {
        FATAL("%s: mounting %s", __func__, path);
    }

    /* Mount a version of /sys that describes the network namespace */
    snprintf(path, sizeof path, "%s/sys", newroot);
    D("%s: Remounting '%s'", __func__, path);
    umount2(path, MNT_DETACH);
    if (mount("sysfs", path, "sysfs", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|
            MS_REC, NULL) < 0)
    {
        FATAL("%s: mounting '%s'", __func__, path);
    }
}

void fs_disable_files(const char *newroot)
{
    size_t i;
    const char *blacklist_objects[] = {
        "/sys/firmware", "/sys/hypervisor", "/sys/power", "/sys/kernel/debug",
        "/sys/kernel/vmcoreinfo", "/sys/kernel/uevent_helper", "/proc/modules",
        /* various /proc/sys files */
        "/proc/sys/security", "/proc/sys/efi/vars", "/proc/sys/fs/binfmt_misc",
        "/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe",
        "/proc/sysrq-trigger", "/proc/sys/kernel/hotplug",
        "/proc/sys/vm/panic_on_oom",
        /* various /proc files */
        "/proc/acpi", "/proc/apm", "/proc/asound", "/proc/fs", "/proc/scsi",
        "/proc/irq", "/proc/bus", "/proc/config.gz", "/proc/sched_debug",
        "/proc/timer_list", "/proc/timer_stats", "/proc/kcore", "/proc/keys",
        "/proc/kallsyms", "/proc/mem", "/proc/kmem",
        /* remove kernel symbol information */
        "/usr/src/linux", "/lib/modules", "/usr/lib/debug", "/boot",
        /* other */
        "/sys/fs/selinux", "/selinux",
        "/dev/port", "/dev/kmsg", "/proc/kmsg",
        "/mnt", "/media", "/run/mount", "/run/media"
    };

    for (i = 0; i < SIZEOF(blacklist_objects); ++i) {
        disable_file_newroot(BLACKLIST_FILE, blacklist_objects[i], newroot);
    }
}

static void fs_var_lock(void)
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

static void fs_var_tmp(void)
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
    D("%s: mounting read-only /proc/sys/net ", __func__);
    fs_rdonly("/proc/sys/net");

    // update /var directory in order to support multiple sandboxes running on the same root directory
	fs_var_lock();
    fs_var_tmp();
    fs_rdwr("/var/log");
    fs_rdwr("/var/lib");
    fs_rdwr("/var/cache");
    fs_rdwr("/var/utmp");
}
