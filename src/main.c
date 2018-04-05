#include "log.h"
#include "log_colored.h"
#include "server.h"
#include "server_ssh.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


int main(int argc, char *argv[])
{
    static server_ctx srv = {0};

    (void)argc;
    (void)argv;

    LOG_SET_FUNCS_VA(LOG_COLORED_FUNCS);
    N("%s (C) 2018 Toni Uhlig (%s)", PACKAGE_STRING, PACKAGE_BUGREPORT);

    ABORT_ON_FATAL( server_init_ctx(&srv, ssh_init_cb),
        "Server initialisation" );
    server_validate_ctx(&srv);

    ABORT_ON_FATAL( socket_init_in(&srv.sock, "127.0.0.1", 2222),
        "Socket initialisation" );
    ABORT_ON_FATAL( socket_bind_listen(&srv.sock),
        "Socket bind and listen" );
    ABORT_ON_FATAL( srv.server_cbs.on_listen(&srv.server_dat),
        "Socket on listen callback" );

    D2("%s", "Server mainloop");
    ABORT_ON_FATAL( server_mainloop(&srv),
        "Server mainloop" );
    return 0;
}
