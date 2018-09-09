sbin_PROGRAMS = potd potd-init
potd_SOURCES = compat.c utils.c options.c log.c log_colored.c log_file.c socket.c pevent.c capabilities.c filesystem.c jail.c forward.c redirector.c protocol.c protocol_ssh.c main.c
potd_init_SOURCES = potd-init.c
potd_init_LDFLAGS = -static
if HAVE_SECCOMP
potd_SOURCES += pseccomp.c
endif
if HAVE_SYSLOG
potd_SOURCES += log_syslog.c
endif
