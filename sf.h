#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ev.h>

enum sf_reasons {
	CLIENT_VAL,
	CONNECTED,
	RECEIVED,
	WRITABLE,
	CLOSING
};

enum sf_intances {
	SERVER,
	CLIENT
};

char *reasonsstr[] = { "CLIENT_VAL", 
						"CONNECTED",
						"RECEIVED",
						"WRITABLE",
						"CLOSING" };

struct sf_str;
struct sf_msg;
struct sf_msginfo;
struct sf_msglist;
struct sf_instance;
struct sf_connection;
struct sf_to;
struct sf_toarray;
struct sf_timer;
struct sf_conntimer;
struct sf_io;
struct sf_socket;
struct sf_ctx;

struct sf_str {
	unsigned char *data;
	size_t len;
	struct sf_msg *parent;
	struct sf_str *next;
	struct sf_str *prev;
};

struct sf_msg_info {
	int status;
	unsigned int uid;
	int *persistence;
};

struct sf_msg {
	struct sf_str *parts;
	void *info;
	size_t infosize;
	void (*freeinfo)(void *info);
	struct sf_msglist *msglist;
	struct sf_msg *prev;
	struct sf_msg *next;
};

struct sf_server {
	int port;
	int socket;
	struct sf_io *w_accept;
};

struct sf_instance {
	struct sf_server *server;
	struct sf_ctx *context;
	void *dataptr;
	struct sf_connection *connections;
	void (*validate)(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *msg, int *ret);
	void (*callback)(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *msg, int *ret);
	struct sf_instance *prev;
	struct sf_instance *next;
};

struct sf_connection {
	enum sf_intances type; //acceptor:server/connector:client
	struct sf_socket *socket;
	struct sockaddr_storage addr;
	struct sf_instance *instance;
	void *dataptr;
	int validated;
	struct sf_conntimer *validate_timeout;
	struct timeval *connect_timeout;
	struct sf_io *w;
	struct sf_msglist *receive;
	struct sf_msglist *send;
	int send_count;
	int send_holes;
	int writable;
	int beat;
	struct sf_connection *prev;
	struct sf_connection *next;
};

struct sf_to {
	struct sf_connection *connection;
	struct sf_toarray *parent;
	struct sf_to *next;
	struct sf_to *prev;
};

struct sf_toarray {
	struct sf_to *array;
};

struct sf_socket {
	int sd;
	struct sf_connection *connection;
	struct timeval beat;
	struct timeval lastbeat;
	unsigned int latency; //ns
	struct sf_socket *next;
	struct sf_socket *prev;
};

struct sf_msglist {
	struct sf_msg *msgs;
};

struct sf_timer {
	struct ev_timer timer;
	struct sf_ctx *context;
};

struct sf_conntimer {
	struct ev_timer timer;
	struct sf_connection *connection;
};

struct sf_io {
	struct ev_io io;
	void *ptr;
};

struct sf_timers {
	unsigned int socketbeat_interval;
	unsigned int socketbeat_timeout;
	unsigned int connectretry_interval;
	unsigned int connect_timeout;
	unsigned int validation_timeout;
};

struct sf_ctx {
	struct ev_loop *loop;
	struct sf_socket *sockets;
	struct sf_timer sockets_timer;
	struct sf_timers timers;
	struct sf_instance *instances;
};

void packi16(unsigned char *buf, unsigned short i);
void packi32(unsigned char *buf, unsigned int i);
unsigned short unpacki16(unsigned char *buf);
unsigned int unpacki32(unsigned char *buf);

struct sf_ctx *sf_newcontext(struct ev_loop *loop, struct sf_timers timers);
void sf_delcontext(struct sf_ctx *context);

struct sf_socket *sf_sockets_add(struct sf_connection *connection, int socket);
void sf_sockets_beat(struct sf_socket *socket);
void sf_sockets_monitor_cb(struct ev_loop *loop, struct ev_timer *t, int revents);
void sf_sockets_remove(struct sf_connection *connection);

void sf_str_add(struct sf_str *str);
void sf_str_remove(struct sf_str *str);
struct sf_msg *sf_msg_new();
struct sf_str *sf_msg_pop(struct sf_msg *msg);
void sf_msg_push(struct sf_msg *msg, void *data, size_t len);
struct sf_msg *sf_msg_dup(struct sf_msg *msg);

struct sf_msglist *sf_msglist_new();
void sf_msglist_add(struct sf_msg *msg);
void sf_msglist_remove(struct sf_msg *msg);
void sf_msglist_del(struct sf_msglist *msglist);

struct sf_toarray *sf_toarray_new();
void sf_toarray_push(struct sf_toarray *toarray, struct sf_connection *connection);
void sf_toarray_remove(struct sf_to *to);
void sf_toarray_del(struct sf_toarray *toarray);

void sf_connection_add(struct sf_connection *connection);
void sf_connection_remove(struct sf_connection *connection);

struct sf_instance *sf_instance_new(struct sf_ctx *context, int port, void (*validate)(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret), void (*callback)(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret));
void sf_instance_accept(struct ev_loop *loop, struct ev_io *w_, int revents);
struct sf_connection *sf_instance_connect(struct sf_instance *instance, char *ip, int port);
void sf_instance_getwritable(struct sf_connection *connection);
void sf_instance_getwritableall(struct sf_instance *instance);
struct sf_msg *sf_send_encode(struct sf_msg *msg);
void sf_instance_sendto(struct sf_connection *connection, struct sf_msg *msg);
void sf_instance_sendtoarray(struct sf_toarray *toarray, struct sf_msg *msg);
void sf_instance_sendtoall(struct sf_instance *instance, struct sf_msg *msg);
void sf_instance_connection(struct ev_loop *loop, struct ev_io *w_, int revents);
int sf_instance_write(struct sf_connection *connection);
int sf_instance_read(struct sf_connection *connection);
int sf_instance_close(struct sf_connection *connection);
int sf_instance_callback(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in);
int sf_instance_validate(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in);
void sf_instance_del(struct sf_instance *instance);
