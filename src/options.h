#ifndef POTD_OPTIONS_H
#define POTD_OPTIONS_H 1

struct opt_list;

typedef enum opt_name {
    OPT_LOGTOFILE = 0, OPT_LOGFILE, OPT_LOGLEVEL,
    OPT_DAEMON,
    OPT_REDIRECT,
    OPT_PROTOCOL,
    OPT_JAIL,
    OPT_ROOT,
    OPT_RODIR,
    OPT_ROFILE,
    OPT_NETNS_RUN_DIR,
    OPT_SSH_RUN_DIR,
    OPT_CHUSER,
    OPT_CHGROUP,
    OPT_SECCOMP_MINIMAL,
    OPT_RUNTEST,

    OPT_HELP,
    OPT_MAX
} opt_name;

typedef int check_opt;


int parse_cmdline(int argc, char **argv);

int getopt_used(opt_name on);

char *
getopt_str(opt_name on);

char *
getopt_strlist(opt_name on, struct opt_list **ol);

#endif
