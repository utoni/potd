#ifndef POTD_SERVER_H
#define POTD_SERVER_H 1

#include "socket.h"

typedef struct server_data {
	void *data;
} server_data;

typedef struct server_session {
    void *data;
} server_session;

typedef int (*on_connect_cb) (struct server_data *data, struct server_session *ses);
typedef int (*on_disconnect_cb) (struct server_data *data, struct server_session *ses);
typedef int (*on_data_cb) (struct server_data *data, struct server_session *ses);
typedef int (*on_free_cb) (struct server_data *data);
typedef int (*on_listen_cb) (struct server_data *data);
typedef int (*on_shutdown_cb) (struct server_data *data);

typedef struct server_callbacks {
    on_connect_cb on_connect;
    on_disconnect_cb on_disconnect;
    on_data_cb mainloop;
    on_free_cb on_free;
    on_listen_cb on_listen;
    on_shutdown_cb on_shutdown;
} server_callbacks;

typedef struct server_ctx { 
    server_callbacks server_cbs;
    server_data server_dat;
    psocket sock;
} server_ctx;

typedef int (*init_cb) (struct server_ctx *ctx);
  

server_ctx *
server_init_ctx(server_ctx *ctx, init_cb init_fn);

int server_validate_ctx(server_ctx *ctx);

int server_mainloop(server_ctx *ctx);

#endif
