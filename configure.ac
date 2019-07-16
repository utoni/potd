AC_PREREQ([2.69])
AC_INIT([potd],
        [m4_esyscmd([build-aux/git-version-gen])],
        [matzeton@googlemail.com])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE

AS_IF([test -z "$CFLAGS"], [CFLAGS="-Os -g"])

AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_TYPE_SIZE_T

AC_MSG_CHECKING([if your os is supported])
case ${host_os} in
    *linux*|*BSD*)
        AC_MSG_RESULT([yes, ${host_os}])
        ;;
    *)
        AC_MSG_RESULT([no, ${host_os}])
        AC_MSG_ERROR([Your operating system ${host_os} is currently not supported, sorry.])
        ;;
esac

AC_CHECK_TOOL([PKGCONFIG], [pkg-config], [:])
AS_IF([test "x${PKGCONFIG}" = x], [ AC_MSG_ERROR([pkg-config not found]) ])

dnl check for -std=gnu99
CFLAGS="-pedantic -Wall -std=gnu99 -D_GNU_SOURCE=1 $CFLAGS"
AC_MSG_CHECKING([if ${CC} supports gnu99])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      AC_MSG_RESULT([yes]),
      [ AC_MSG_RESULT([no])
        AC_MSG_ERROR([a gnu99 compatible platform is required]) ]
      )

dnl check for spectre mitigation
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -mindirect-branch=thunk"
AC_MSG_CHECKING([if ${CC} supports -mindirect-branch=thunk spectre mitigation])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes]) ],
      [ AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS" ])

dnl check for -fstrict-aliasing compilter support
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fstrict-aliasing"
AC_MSG_CHECKING([if ${CC} supports -fstrict-aliasing])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes]) ],
      [ AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS" ])

dnl check for -ffunction-sections compiler support
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -ffunction-sections"
AC_MSG_CHECKING([if ${CC} supports -ffunctions-sections])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes]) ],
      [ AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS" ])

dnl check for -fdata-sections compiler support
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fdata-sections"
AC_MSG_CHECKING([if ${CC} supports -fdata-sections])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes]) ],
      [ AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS" ])

dnl check for -flto compiler support
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -flto"
AC_MSG_CHECKING([if ${CC} supports -flto])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes]) ],
      [ AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS" ])

dnl check for -fstack-protector-strong compiler support
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fstack-protector-strong"
AC_MSG_CHECKING([if ${CC} supports -fstack-protector-strong])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes]) ],
      [ AC_MSG_RESULT([no])
        CFLAGS="$saved_CFLAGS" ])

dnl check if linker supports -Wl,-z,relro
AC_MSG_CHECKING([if linker supports -Wl,-z,relro])
saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-z,relro"
AC_TRY_LINK([],
      [ char tmp; ],
      [ relro_support="yes" ],
      [ relro_support="no"
        LDFLAGS="$saved_LDFLAGS" ])
AC_MSG_RESULT([${relro_support}])

dnl check if linker supports -Wl,-z,now
AC_MSG_CHECKING([if linker supports -Wl,-z,now])
saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-z,now"
AC_TRY_LINK([],
      [ char tmp; ],
      [ lnow_support="yes" ],
      [ lnow_support="no"
        LDFLAGS="$saved_LDFLAGS" ])
AC_MSG_RESULT([${lnow_support}])

dnl check if linker supports -Wl,-z,noexecstack
AC_MSG_CHECKING([if linker supports -Wl,-z,noexecstack])
saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-z,noexecstack"
AC_TRY_LINK([],
      [ char tmp; ],
      [ noexecstack_support="yes" ],
      [ noexecstack_support="no"
        LDFLAGS="$saved_LDFLAGS" ])
AC_MSG_RESULT([${noexecstack_support}])

AX_PTHREAD([],[ AC_MSG_ERROR([pthread required and not found]) ])
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

dnl Check for std header files
AC_CHECK_HEADERS([stdio.h ctype.h assert.h sched.h signal.h time.h errno.h pwd.h limits.h pty.h utmp.h], [],
      [ AC_MSG_ERROR([required std header not available]) ])

dnl Check for system specific header files
AC_CHECK_HEADERS([linux/capability.h linux/securebits.h sys/signalfd.h sys/wait.h sys/ioctl.h net/if.h netinet/in.h libgen.h sys/prctl.h], [],
      [ AC_MSG_ERROR([required system specific header not available]) ])
AC_CHECK_HEADERS([libutil.h pthread.h semaphore.h syslog.h linux/limits.h \
                  sys/uio.h poll.h sys/epoll.h sys/sysmacros.h sys/mount.h sys/mman.h \
                  util.h execinfo.h syslog.h])

dnl Check for GAI header
AC_CHECK_HEADERS([netdb.h])

dnl minimum required functions
AC_CHECK_FUNCS([open read write close mmap munmap malloc free memset memcpy fork unshare \
                getpwnam getgrnam setreuid setregid \
                wait waitpid isprint remove unlink mkdir access stat chroot chdir mount umount mknod \
                strdup strcasecmp strncat strncpy printf fprintf getpid \
                prctl signal signalfd fcntl getenv kill exit \
                setsockopt socket connect accept bind listen \
                time localtime difftime strtol strtoll getopt_long_only], [],
      [ AC_MSG_ERROR([required function not available]) ])
dnl check reentrant function availability
AC_CHECK_FUNCS([strtok_r localtime_r getpwnam_r getgrnam_r])
dnl GAI functions
AC_CHECK_FUNCS([getaddrinfo getnameinfo freeaddrinfo], [],
      [ AC_MSG_ERROR([required GAI function not available]) ])
dnl epoll functions
AC_CHECK_FUNCS([epoll_create1 epoll_ctl epoll_pwait], [],
      [ AC_MSG_ERROR([required epoll function not available]) ])
dnl backtrace* functions
AC_CHECK_FUNCS([backtrace backtrace_symbols], [ backtrace_avail="yes" ],
                                              [ backtrace_avail="no"  ])
dnl syslog functions
AC_CHECK_FUNCS([openlog closelog syslog vsyslog], [ syslog_avail="yes" ],
                                                  [ syslog_avail="no"  ])
AM_CONDITIONAL([HAVE_SYSLOG], [test "x${syslog_avail}" = xyes])

AC_CHECK_LIB([execinfo], [backtrace],
      [ LIBS="-lexecinfo $LIBS"
        backtrace_avail="yes" ])
AS_IF([test "x${backtrace_avail}" = xyes],
      [ AC_DEFINE([HAVE_EXECINFO], [1], [backtrace and backtrace_symbols are available on your system]) ])

AC_CHECK_LIB([socket], [connect])
AC_CHECK_LIB([pthread], [pthread_create])

dnl libssh-dev
PKG_CHECK_MODULES([libssh], [libssh >= 0.7.3], [],
      [ AC_MSG_ERROR([pkg-config: libssh >= 0.7.3 not found]) ])
saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
CFLAGS="$CFLAGS $libssh_CFLAGS"
LIBS="$LIBS $libssh_LIBS"
dnl Some libssh versions require libssl,libcrypto,zlib,libdl.
AC_MSG_CHECKING([if libssh requires -lcrypto])
AC_TRY_LINK([#include <libssh/libssh.h>],
      [ return ssh_init(); ], [ libssh_require_libcrypto="no" ],
                              [ libssh_require_libcrypto="yes"])
CFLAGS="$saved_CFLAGS"
LIBS="$saved_LIBS"

AC_MSG_RESULT([${libssh_require_libcrypto}])
AS_IF([test "x${libssh_require_libcrypto}" = xyes],
      [ saved_CFLAGS="$CFLAGS"
        saved_LIBS="$LIBS"
        PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.2], [],
            [ AC_MSG_ERROR([pkg-config: libcrypto >= 1.0.2 not found]) ])
        AC_CHECK_LIB([crypto], [RSA_new], [ libcrypto_require_zlib="no" ],
                                          [ libcrypto_require_zlib="yes"])
        CFLAGS="$saved_CFLAGS $libcrypto_CFLAGS"
        LIBS="$saved_LIBS $libcrypto_LIBS"
	  ])

AS_IF([test "x${libcrypto_require_zlib}" = xyes],
      [ saved_CFLAGS="$CFLAGS"
        saved_LIBS="$LIBS"
        PKG_CHECK_MODULES([zlib], [zlib >= 1.2.8], [],
            [ AC_MSG_ERROR([pkg-config: zlib >= 1.2.8 not found]) ])
        AC_CHECK_LIB([z], [inflate], [],
            [ AC_MSG_ERROR([libz link failed]) ])
        AC_CHECK_LIB([crypto], [RSA_free], [ libcrypto_require_libdl="no" ],
                                           [ libcrypto_require_libdl="yes"])
        CFLAGS="$saved_CFLAGS $zlib_CFLAGS"
        LIBS="$saved_LIBS $zlib_LIBS"
      ])

AS_IF([test "x${libcrypto_require_libdl}" = xyes],
      [ saved_CFLAGS="$CFLAGS"
        saved_LIBS="$LIBS"
        AC_CHECK_LIB([dl], [dlopen], [],
            [ AC_MSG_ERROR([libdl link failed]) ])
        AC_CHECK_LIB([crypto], [RSA_generate_key], [],
            [ AC_MSG_ERROR([libcrypto link failed]) ])
        CFLAGS="$saved_CFLAGS"
        LIBS="$saved_LIBS -dl"
        libdl_found="yes"
      ])

AC_MSG_CHECKING([if libssh requires -lssl])
AC_TRY_LINK([#include <libssh/libssh.h>],
      [ return ssh_init(); ], [ libssh_require_libssl="no" ],
                              [ libssh_require_libssl="yes"])
AC_MSG_RESULT([${libssh_require_libssl}])
AS_IF([test "x${libssh_require_libssl}" = xyes],
      [ saved_CFLAGS="$CFLAGS"
        saved_LIBS="$LIBS"
        PKG_CHECK_MODULES([libssl], [libssl >= 1.0.1f], [],
            [ AC_MSG_ERROR([pkg-config: libssl >= 1.0.1f not found]) ])
        CFLAGS="$saved_CFLAGS $libssl_CFLAGS"
        LIBS="$saved_LIBS $libssl_LIBS"
        AC_CHECK_LIB([ssl], [SSL_new], [ libssl_require_libdl="no" ],
                                       [ libssl_require_libdl="yes"])
	  ])

AS_IF([test "x${libssl_require_libdl}" = xyes
       test "x${libdl_found}" != xyes],
      [ saved_CFLAGS="$CFLAGS"
        saved_LIBS="$LIBS"
        AC_CHECK_LIB([dl], [dlopen], [],
            [ AC_MSG_ERROR([libdl link failed]) ])
        AC_CHECK_LIB([ssl], [SSL_free], [],
            [ AC_MSG_ERROR([libssl link failed]) ])
        CFLAGS="$saved_CFLAGS"
        LIBS="$saved_LIBS -ldl"
      ])

AC_MSG_CHECKING([if libssh requires -lz])
AC_TRY_LINK([#include <libssh/libssh.h>],
      [ return ssh_init(); ], [ libssh_require_libz="no" ],
                              [ libssh_require_libz="yes"])
AC_MSG_RESULT([${libssh_require_libz}])
AS_IF([test "x${libssh_require_libz}" = xyes -a "x${libcrypto_require_zlib}" != xyes],
      [ saved_CFLAGS="$CFLAGS"
        saved_LIBS="$LIBS"
        PKG_CHECK_MODULES([zlib], [zlib >= 1.2.8], [],
            [ AC_MSG_ERROR([pkg-config: zlib >= 1.2.8 not found]) ])
        AC_CHECK_LIB([z], [inflate], [],
            [AC_MSG_ERROR([zlib link failed])])
        CFLAGS="$saved_CFLAGS $zlib_CFLAGS"
        LIBS="$saved_LIBS $zlib_LIBS"
      ])

AC_CHECK_LIB([ssh], [ssh_init], [ libssh_require_gssapi="no" ],
                                [ libssh_require_gssapi="yes"])
AC_MSG_CHECKING([if libssh requires -lkrb5-gssapi])
AC_MSG_RESULT([$libssh_require_gssapi])
AS_IF([test "x${libssh_require_gssapi}" = xyes],
      [ saved_CFLAGS="$CFLAGS"
        saved_LIBS="$LIBS"
        PKG_CHECK_MODULES([gssapi], [krb5-gssapi >= 1.15], [],
            [ AC_MSG_ERROR([pkg-config: krb5-gssapi >= 1.15 not found]) ])
        CFLAGS="$saved_CFLAGS $gssapi_CFLAGS "
        LIBS="$saved_LIBS $gssapi_LIBS"
        AC_CHECK_LIB([ssh], [ssh_free],
            [ AC_MSG_ERROR([final link against libssh failed]) ])
        CFLAGS="$saved_CFLAGS $gssapi_CFLAGS"
        LIBS="$saved_LIBS $gssapi_LIBS"
      ])

CFLAGS="$libssh_CFLAGS $CFLAGS"
LIBS="$libssh_LIBS $LIBS"

dnl libseccomp-dev
PKG_CHECK_MODULES([libseccomp], [libseccomp >= 2.2.1],
      [ have_seccomp="yes" ],
      [ have_seccomp="no"  ])
saved_CFLAGS="$CFLAGS $libseccomp_CFLAGS"
saved_LIBS="$LIBS $libseccomp_LIBS"
AC_CHECK_LIB([seccomp], [seccomp_init],
      [ have_seccomp="yes"
        AC_DEFINE([HAVE_SECCOMP], [1], [Define to 1 if you have a working libseccomp])
      ],
      [ have_seccomp="no" ])
AM_CONDITIONAL([HAVE_SECCOMP], [test "x${have_seccomp}" = xyes])
CFLAGS="$saved_CFLAGS"
LIBS="$saved_LIBS"

dnl Check for valgrind
PKG_CHECK_MODULES([valgrind], [valgrind >= 3.12.0],
      [ AC_DEFINE([HAVE_VALGRIND], [1],
        [Define to 1 if you have/want valgrind support])
        valgrind_enabled="yes" ],
      [ valgrind_enabled="no" ])
CFLAGS="$CFLAGS $valgrind_CFLAGS"

AC_MSG_CHECKING([working time])
AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([#include <time.h>
        int fn(void) \
        { time_t s0 = time(NULL); \
          time_t s1 = time(NULL); \
		  double r = difftime(s0, s1); }])
      ],
      AC_MSG_RESULT([yes]),
      [ AC_MSG_RESULT([no])
        AC_MSG_ERROR([time is not available on your platform]) ])

AC_MSG_CHECKING([for working epoll])
AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([#include <sys/epoll.h>
                      #include <signal.h>
        int fn(void) \
        { int fd = epoll_create1(0); \
          struct epoll_event ev = {0,{0}}; \
          struct epoll_event polled[[16]]; \
          sigset_t eset; sigemptyset(&eset); \
          epoll_ctl(fd, EPOLL_CTL_ADD, 0, &ev); \
          epoll_pwait(fd, polled, 16, -1, &eset); \
          close(fd); }])
      ],
      AC_MSG_RESULT([yes]),
      [ AC_MSG_RESULT([no])
        AC_MSG_ERROR([epoll is not available on your platform]) ])

AC_MSG_CHECKING([for working va_arg])
AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([#include <stdio.h>
                      #include <stdarg.h>
        int fn(const char *fmt, ...) \
        { char buf[[32]] = {0}; va_list arglist; \
          va_start(arglist, fmt); \
          vsnprintf(buf, sizeof buf, fmt, arglist); \
          va_end(arglist); return 0; }])
      ],
      AC_MSG_RESULT([yes]),
      [ AC_MSG_RESULT([no])
        AC_MSG_ERROR([va_arg does not work as expected]) ])

AC_MSG_CHECKING([for assert])
AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([#include <assert.h>
        int fn(void) \
        { assert(0); return 0; }])
      ],
      AC_MSG_RESULT([yes]),
      [ AC_MSG_RESULT([no])
        AC_MSG_ERROR([assertion macro missing]) ])

AC_MSG_CHECKING([if ambient raise securebits available])
AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([#include <sys/prctl.h>
                      #include <linux/securebits.h>
        int fn(void) \
        { prctl(SECBIT_NO_CAP_AMBIENT_RAISE | \
                SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED); \
          return 0; }])
      ],
      [ AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_SECUREBITS_AMBIENT], [1],
                  [Set to 1 if securebits are available.]) ],
      [ AC_MSG_RESULT([no]) ])

AC_MSG_CHECKING([for working capability drop])
AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([#include <sys/prctl.h>
                      #include <linux/capability.h>
        int fn(void) \
        { int caps[[]] = {CAP_SYS_MODULE,CAP_SYS_RAWIO,CAP_SYS_BOOT, \
            CAP_SYS_NICE, CAP_SYS_TTY_CONFIG, CAP_MKNOD, CAP_SYS_ADMIN, \
            CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_AUDIT_CONTROL, \
            CAP_AUDIT_READ, CAP_AUDIT_WRITE, CAP_SYS_PTRACE, \
            CAP_SYS_PACCT, CAP_SYS_CHROOT}; \
          int i; \
          for (i = 0; i < sizeof(caps)/sizeof(caps[[0]]); ++i) \
              prctl(PR_CAPBSET_DROP, caps[[i]], 0, 0, 0); \
          return 0; }])
      ],
      AC_MSG_RESULT([yes]),
      [ AC_MSG_RESULT([no])
        AC_MSG_ERROR([required capability drop does not work]) ])

AC_MSG_CHECKING([for working unshare])
AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([#define _GNU_SOURCE 1
                      #include <sched.h>
        int fn(void) \
        { int unshare_flags = CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWIPC| \
			CLONE_NEWNS|CLONE_NEWNET; \
          return unshare(unshare_flags); }])
      ],
      AC_MSG_RESULT([yes]),
      [ AC_MSG_RESULT([no])
        AC_MSG_ERROR([required unshare function does not work]) ])

AC_MSG_CHECKING([for secure_getenv])
AC_TRY_LINK([#include <stdlib.h>],
      [ secure_getenv("TERM"); return 0; ],
      [ AC_MSG_RESULT([yes])
        getenv_func="secure_getenv" ],
      [ AC_MSG_RESULT([no])
        getenv_func="getenv" ])
AC_DEFINE_UNQUOTED([GETENV_FUNC], [$getenv_func],
      [set it to the getenv function e.g. secure_getenv or getenv])

dnl Most systems require linking against libutil.so in order to get forkpty()
AC_CHECK_FUNCS([openpty login_tty], [],
               [AC_CHECK_LIB([util], [openpty],
                   [LIBS="-lutil $LIBS"
                    AC_DEFINE([HAVE_LIBUTIL], [1], [openpty and login_tty require linking against libutil])
                   ])])

dnl C99 snprintf checks
HW_FUNC_VSNPRINTF
HW_FUNC_SNPRINTF
AS_IF([test "x${hw_cv_func_snprintf}" != xyes
       test "x${hw_cv_func_snprintf_c99}" != xyes
       test "x${hw_cv_func_vsnprintf}" != xyes
       test "x${hw_cv_func_vsnprintf_c99}" != xyes],
      [ AC_MSG_ERROR([snprintf or vsnprintf missing or not C99 compatible]) ],
      [])


potd_LIBS="$LIBS"
AC_SUBST(potd_LIBS, ["$potd_LIBS"])
LIBS=""

potd_logfile="/var/log/potd.log"
AC_DEFINE_UNQUOTED([POTD_LOGFILE], ["$potd_logfile"],
      [default path to the log file])
potd_defroot="/var/run/potd-root"
AC_DEFINE_UNQUOTED([POTD_DEFROOT], ["$potd_defroot"],
      [default path to potd rootfs image/directory])
potd_netns_run_dir="/var/run/potd-netns"
AC_DEFINE_UNQUOTED([POTD_NETNS_RUN_DIR], ["$potd_netns_run_dir"],
      [default path to network namespace run directory])
potd_ssh_run_dir="/var/run/potd-ssh"
AC_DEFINE_UNQUOTED([POTD_SSH_RUN_DIR], ["$potd_ssh_run_dir"],
      [default path to ssh run directory])
potd_ssh_chuser="nobody"
AC_DEFINE_UNQUOTED([POTD_DEFUSER], ["$potd_ssh_chuser"],
      [default value for option --user])
potd_rodir="/var/run/potd-rodir"
AC_DEFINE_UNQUOTED([POTD_RODIR], ["$potd_rodir"],
      [default path to a directory for readonly bind mounts])
potd_rofile="/var/run/potd-rofile"
AC_DEFINE_UNQUOTED([POTD_ROFILE], ["$potd_rofile"],
      [default path to a file for readonly bind mounts])
potd_dbgdir="/tmp/potd-debug"
AC_DEFINE_UNQUOTED([POTD_DBGDIR], ["$potd_dbgdir"],
      [default path to a directory for debugging output])
potd_enable_ptrace=no
AS_IF([test "x${potd_enable_ptrace}" = xyes],
      [AC_DEFINE([ENABLE_PTRACE], [1],
      [Enable this if you want (unsecure) ptrace support in your sandbox (for debugging).])], [])

AC_OUTPUT(Makefile src/Makefile)

cat <<EOF

--------- Configuration ---------
global CFlags.: ${CFLAGS}
global LDFlags: ${LDFLAGS}
potd Libs.....: ${potd_LIBS}

EOF
