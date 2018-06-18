AC_PREREQ([2.69])
AC_INIT(potd, 1.0, matzeton@googlemail.com)
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

AC_CHECK_TOOL([PKGCONFIG], [pkg-config], [:])
AS_IF([test "x${PKGCONFIG}" = x], [ AC_MSG_ERROR([pkg-config not found]) ])

dnl check for -std=gnu99
CFLAGS="-std=gnu99 $CFLAGS"
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
      [ AC_MSG_RESULT([yes])
        SPECTRE_MIT="-mindirect-branch=thunk" ],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST([SPECTRE_MIT])

dnl check for -fvisibility=hidden compiler support (GCC >= 4)
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden -fvisibility-inlines-hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden" ],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST([SYMBOL_VISIBILITY])

AC_CHECK_LIB([socket], [connect])
AC_CHECK_LIB([pthread], [pthread_create])

dnl libssh-dev
PKG_CHECK_MODULES([libssh], [libssh >= 0.7.3], [],
      [ AC_MSG_ERROR([libssh >= 0.7.3 not found]) ])
AC_SUBST([libssh_CFLAGS])
LIBS="$libssh_LIBS"
dnl Some libssh versions require libssl,libcrypto,zlib.
dnl This is because the libssh.pc file does not sets additional required shlibs.
additional_libssh_libs=""

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
CFLAGS="$CFLAGS $libssh_CFLAGS"
AC_MSG_CHECKING([if libssh requires -lcrypto])
AC_TRY_LINK([#include <libssh/libssh.h>],
      [ return ssh_init(); ], [ libssh_require_libcrypto="no" ],
                              [ libssh_require_libcrypto="yes"])
CFLAGS="$saved_CFLAGS"
LIBS="$saved_LIBS"

AC_MSG_RESULT([${libssh_require_libcrypto}])
AS_IF([test "x${libssh_require_libcrypto}" = xyes],
      [ additional_libssh_libs="${additional_libssh_libs} -lcrypto"
        LIBS="$LIBS -lcrypto"
        AC_CHECK_LIB([crypto], [RSA_new], [ libcrypto_require_zlib="no" ],
                                          [ libcrypto_require_zlib="yes"])
	  ])

AS_IF([test "x${libcrypto_require_zlib}" = xyes],
      [ additional_libssh_libs="${additional_libssh_libs} -lz"
        LIBS="$LIBS -lz"
        AC_CHECK_LIB([z], [inflate], [],
            [ AC_MSG_ERROR([libz not found]) ])
        AC_CHECK_LIB([crypto], [RSA_new],
            [ AC_MSG_ERROR([libcrypto not found]) ])
      ])

AC_MSG_CHECKING([if libssh requires -lssl])
AC_TRY_LINK([#include <libssh/libssh.h>],
      [ return ssh_init(); ], [ libssh_require_libssl="no" ],
                              [ libssh_require_libssl="yes"])
AC_MSG_RESULT([${libssh_require_libssl}])
AS_IF([test "x${libssh_require_libssl}" = xyes],
      [ additional_libssh_libs="${additional_libssh_libs} -lssl"
        LIBS="$LIBS -lssl"
        AC_CHECK_LIB([ssl], [SSL_new], [],
            [AC_MSG_ERROR([libssl not found])])
	  ])

AC_MSG_CHECKING([if libssh requires -lz])
AC_TRY_LINK([#include <libssh/libssh.h>],
      [ return ssh_init(); ], [ libssh_require_libz="no" ],
                              [ libssh_require_libz="yes"])
AC_MSG_RESULT([${libssh_require_libz}])
AS_IF([test "x${libssh_require_libz}" = xyes -a "x${libcrypto_require_zlib}" != xyes],
      [ additional_libssh_libs="${additional_libssh_libs} -lz"
        LIBS="$LIBS -lz"
        AC_CHECK_LIB([z], [inflate], [],
            [AC_MSG_ERROR([libz not found])])
      ])

LIBS="$saved_LIBS $additional_libssh_libs"
AC_CHECK_LIB([ssh], [ssh_init], [], [AC_MSG_ERROR([final link against libssh failed])])
AC_CHECK_LIB([seccomp], [seccomp_init], [], [AC_MSG_ERROR([final link against libseccomp failed])])
LIBS="$saved_LIBS $additional_libssh_libs"

dnl libseccomp-dev
PKG_CHECK_MODULES([libseccomp], [libseccomp >= 2.2.1], [],
      [ AC_MSG_ERROR([libseccomp >= 2.2.1 not found]) ])
AC_SUBST([libseccomp_CFLAGS])
LIBS="$LIBS $libseccomp_LIBS"

dnl Check for valgrind
PKG_CHECK_MODULES([valgrind], [valgrind >= 3.12.0],
      [ AC_DEFINE([HAVE_VALGRIND], [1],
        [Define to 1 if you have/want valgrind support])
        valgrind_enabled="yes" ],
      [ valgrind_enabled="no" ])
AC_SUBST([valgrind_CFLAGS])
LIBS="$LIBS $valgrind_LIBS"

dnl Check for std header files
AC_CHECK_HEADERS([stdio.h ctype.h assert.h sched.h signal.h time.h errno.h pwd.h], [],
      [ AC_MSG_ERROR([required std header not available]) ])

dnl Check for system specific header files
AC_CHECK_HEADERS([pty.h linux/capability.h sys/wait.h sys/ioctl.h net/if.h netinet/in.h libgen.h], [],
      [ AC_MSG_ERROR([required system specific header not available]) ])
AC_CHECK_HEADERS([libutil.h pthread.h syslog.h sys/prctl.h linux/limits.h \
                  sys/uio.h poll.h sys/epoll.h sys/sysmacros.h sys/mount.h util.h])

dnl Check for GAI header
AC_CHECK_HEADERS([netdb.h])

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
AC_CHECK_FUNCS([forkpty], [],
               [AC_CHECK_LIB(util, forkpty,
               [LIBS="-lutil $LIBS"
                AC_DEFINE(HAVE_FORKPTY)])])
dnl minimum required functions
AC_CHECK_FUNCS([open read write close malloc free memset memcpy fork unshare \
                getpwnam getgrnam setreuid setregid \
                wait waitpid isprint remove unlink mkdir access stat chroot chdir mount umount mknod \
                strdup strcasecmp strncat strncpy printf fprintf getpid \
                prctl signal signalfd fcntl getenv kill exit \
                setsockopt socket connect accept bind listen \
                time difftime strtol strtoll getopt_long_only], [],
      [ AC_MSG_ERROR([required function not available]) ])
dnl GAI functions
AC_CHECK_FUNCS([getaddrinfo getnameinfo freeaddrinfo], [],
      [ AC_MSG_ERROR([required GAI function not available]) ])
dnl epoll functions
AC_CHECK_FUNCS([epoll_create1 epoll_ctl epoll_pwait], [],
      [ AC_MSG_ERROR([required epoll function not available]) ])

dnl C99 snprintf checks
HW_FUNC_VSNPRINTF
HW_FUNC_SNPRINTF
AS_IF([test "x${hw_cv_func_snprintf}" != xyes
       test "x${hw_cv_func_snprintf_c99}" != xyes
       test "x${hw_cv_func_vsnprintf}" != xyes
       test "x${hw_cv_func_vsnprintf_c99}" != xyes],
      [ AC_MSG_ERROR([snprintf or vsnprintf missing or not C99 compatible]) ],
      [])

potd_logfile="/var/log/potd.log"
AC_DEFINE_UNQUOTED([POTD_LOGFILE], ["$potd_logfile"],
      [default path to the log file])
potd_defroot="/var/run/potd-root"
AC_DEFINE_UNQUOTED([POTD_DEFROOT], ["$potd_defroot"],
      [default path to potd rootfs image/directory])
potd_netns_run_dir="/var/run/potd-netns"
AC_DEFINE_UNQUOTED([POTD_NETNS_RUN_DIR], ["$potd_netns_run_dir"],
      [default path to network namespace run directory])

CFLAGS="-pedantic -Wall -fstrict-aliasing -D_GNU_SOURCE=1 $CFLAGS"

AC_OUTPUT(Makefile src/Makefile)
