AC_INIT(potd, 1.0, matzeton@googlemail.com)
AC_CONFIG_HEADERS([src/config.h])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE
AC_PROG_CC
AC_PROG_CC_STDC

PKG_CHECK_MODULES([libssh], [libssh >= 0.7.3])

AC_OUTPUT(Makefile src/Makefile)
