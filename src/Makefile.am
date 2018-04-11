AM_CFLAGS = -pedantic -Wall -std=gnu99 -fstrict-aliasing -D_GNU_SOURCE=1 $(libssh_CFLAGS) $(libseccomp_CFLAGS) $(valgrind_CFLAGS) $(SPECTRE_MIT) $(SYMBOL_VISIBILITY)
AM_LDFLAGS = $(libssh_LIBS) $(libseccomp_LIBS) $(valgrind_LIBS)

sbin_PROGRAMS = potd
potd_SOURCES = utils.c options.c log.c log_colored.c log_file.c socket.c pevent.c capabilities.c pseccomp.c jail.c forward.c redirector.c protocol.c protocol_ssh.c main.c
