#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#include "sf.h"

void printbincharpad(char c) {
	int i;
	for (i = 7; i >= 0; --i) {
		putchar((c & (1 << i)) ? '1' : '0' );
	}
	printf("..%c\n", c);
}

void binary_dump(void* data, size_t len) {
	size_t i;
	//printf("Data in [%p..%p): \n",data,data+len);
	for (i=0;i<len/sizeof(char);i++)
		printbincharpad(((char*)data)[i]);
	printf("\n");
}

void log2file(char *path, char *log, size_t len) {
	FILE *file; 
	file = fopen(path,"a+");
	fwrite(log, 1, len, file);
	fclose(file);
}

unsigned int urand() {
	struct timeval now;
	gettimeofday(&now, NULL);
	srand(now.tv_sec*1000000 + now.tv_usec);
	return rand() + rand();
}

inline void packi16(unsigned char *buf, unsigned short i) {
   *buf++ = i>>8;
	*buf++ = i;
}

inline void packi32(unsigned char *buf, unsigned int i) {
   *buf++ = i>>24;
	*buf++ = i>>16;
   *buf++ = i>>8;
	*buf++ = i;
}

inline unsigned short unpacki16(unsigned char *buf) {
   return (buf[0]<<8) | buf[1];
}

inline unsigned int unpacki32(unsigned char *buf) {
   return (buf[0]<<24) | (buf[1]<<16) | (buf[2]<<8) | buf[3];
}

struct sf_ctx *sf_newcontext(struct ev_loop *loop, struct sf_timers timers) {
	struct sf_ctx *context = malloc(sizeof(struct sf_ctx));
	context->loop = loop;
	context->sockets = NULL;
	context->sockets_timer.context = context;
	context->timers = timers;
	ev_timer_init(&context->sockets_timer.timer, sf_sockets_monitor_cb, timers.socketbeat_interval/1000000.0, timers.socketbeat_interval/1000000.0);
	ev_timer_start(loop, &context->sockets_timer.timer);
	return context;
}

void sf_delcontext(struct sf_ctx *context) {
	ev_timer_stop(context->loop, &context->sockets_timer.timer);
	while(context->sockets != NULL)
		sf_instance_del(context->sockets->connection->instance);
	free(context);
}


struct sf_socket *sf_sockets_add(struct sf_connection *connection, int socket_i) {
	struct sf_ctx *context = connection->instance->context;
	struct sf_socket *socket_s = malloc(sizeof(struct sf_socket));
	if(context->sockets == NULL) {
		socket_s->next = socket_s;
		socket_s->prev = socket_s;
		context->sockets = socket_s;
	}
	else {
		context->sockets->prev->next = socket_s;
		socket_s->prev = context->sockets->prev;
		context->sockets->prev = socket_s;
		socket_s->next = context->sockets;
	}
	socket_s->sd = socket_i;
	socket_s->connection = connection;
	gettimeofday(&socket_s->lastbeat, NULL);
	return socket_s;
}

inline void sf_sockets_beat(struct sf_socket *socket) {
	gettimeofday(&socket->lastbeat, NULL);
	socket->connection->beat = 0;
	//printf("Beat received at %ld.%06ld\n",  (long int)(socket->lastbeat.tv_sec), (long int)(socket->lastbeat.tv_usec));
	//incorrect, for minimal bandwidth usage, only a keep-alive beat is sent, not a request/reply beat
	//this number will fall somewhere in the peer beat interval, delayed by when the beat was sent vs the interval beat
	socket->latency = (socket->lastbeat.tv_usec + 1000000 * socket->lastbeat.tv_sec) - (socket->beat.tv_usec + 1000000 * socket->beat.tv_sec);
}

void sf_sockets_monitor_cb(struct ev_loop *loop, struct ev_timer *t, int revents) {
	struct sf_timer *timer = (struct sf_timer *)t;
	if(timer->context->sockets == NULL)
		return;
	struct sf_socket *next;
	struct sf_socket *current = timer->context->sockets;
	struct timeval now;
	int x = 1;
	gettimeofday(&now, NULL);
	do {
		next = current->next;
		if(current->connection->beat != -1) {
			if((now.tv_sec-current->lastbeat.tv_sec)*1000000 + (now.tv_usec-current->lastbeat.tv_usec) > timer->context->timers.socketbeat_timeout) {
				if(next == timer->context->sockets)
					x = 0;
				printf("connection timed-out, %uns\n", (unsigned int)((now.tv_sec-current->lastbeat.tv_sec)*1000000 + (now.tv_usec-current->lastbeat.tv_usec)));
				sf_instance_close(current->connection);
			}
			else if(current->connection->beat == 0) {
				current->connection->beat = 1;
				sf_instance_getwritable(current->connection);
				//printf("Get writeable for beat\n");
			}
		}
		if(timer->context->sockets == NULL)
			x = 0;
		else if(next->prev == current && next == timer->context->sockets)
			x = 0;
		current = next;
	}
	while(x);
}

void sf_sockets_remove(struct sf_connection *connection) {
	connection->socket->prev->next = connection->socket->next;
	connection->socket->next->prev = connection->socket->prev;
	if(connection->socket == connection->instance->context->sockets) {
		if(connection->socket->next == connection->instance->context->sockets)
			connection->instance->context->sockets = NULL;
		else
			connection->instance->context->sockets = connection->socket->next;
	}
	free(connection->socket);
}

void sf_freeinfo(void *info) {
	struct sf_msg_info *msginfo = info;
	free(msginfo);
}

inline void sf_str_add(struct sf_str *str) {
	struct sf_msg *msg = str->parent;
	if(msg->parts == NULL) {
		str->next = str;
		str->prev = str;
		msg->parts = str;
	}
	else {
		msg->parts->prev->next = str;
		str->prev = msg->parts->prev;
		msg->parts->prev = str;
		str->next = msg->parts;
	}
}

inline void sf_str_remove(struct sf_str *str) {
	struct sf_msg *msg = str->parent;
	str->prev->next = str->next;
	str->next->prev = str->prev;
	if(str == msg->parts) {
		if(str->next == msg->parts)
			msg->parts = NULL;
		else
			msg->parts = str->next;
	}
	free(str->data);
	free(str);
}

inline struct sf_msg *sf_msg_new() {
	struct sf_msg *msg = malloc(sizeof(struct sf_msg));
	msg->parts = NULL;
	msg->info = NULL;
	msg->infosize = 0;
	msg->freeinfo = NULL;
	return msg;
}

inline struct sf_str *sf_msg_pop(struct sf_msg *msg) {
	struct sf_str *str = msg->parts;
	str->prev->next = str->next;
	str->next->prev = str->prev;
	if(str == msg->parts) {
		if(str->next == msg->parts)
			msg->parts = NULL;
		else
			msg->parts = str->next;
	}
	return str;
}

inline void sf_msg_push(struct sf_msg *msg, void *data, size_t len) {
	struct sf_str *str = malloc(sizeof(struct sf_str));
	str->parent = msg;
	str->data = malloc(sizeof(char) * len);
	memcpy(str->data, data, len);
	str->len = len;
	sf_str_add(str);
}

struct sf_msg *sf_msg_dup(struct sf_msg *msg) {
	struct sf_msg *copy = sf_msg_new();
	if(msg->info != NULL && msg->infosize != 0) {
		copy->info = malloc(msg->infosize);
		memcpy(copy->info, msg->info, msg->infosize);
		copy->infosize = msg->infosize;
	}
	if(msg->parts != NULL) {
		struct sf_str *strcopy;
		struct sf_str *current = msg->parts;
		do {
			strcopy = malloc(sizeof(struct sf_str));
			strcopy->parent = copy;
			sf_str_add(strcopy);
			strcopy->len = current->len;
			strcopy->data = malloc(strcopy->len);
			memcpy(strcopy->data, current->data, strcopy->len);
			current = current->next;
		}
		while(current != msg->parts);
	}
	return copy;
}

struct sf_msglist *sf_msglist_new() {
		struct sf_msglist *msglist= malloc(sizeof(struct sf_msglist));
		msglist->msgs = NULL;
		return msglist;
}

inline void sf_msglist_add(struct sf_msg *msg) {
	struct sf_msglist *msglist = msg->msglist;
	if(msglist->msgs == NULL) {
		msg->next = msg;
		msg->prev = msg;
		msglist->msgs = msg;
	}
	else {
		msglist->msgs->prev->next = msg;
		msg->prev = msglist->msgs->prev;
		msglist->msgs->prev = msg;
		msg->next = msglist->msgs;
	}
}

inline void sf_msglist_remove(struct sf_msg *msg) {
	int x;
	struct sf_msglist *msglist = msg->msglist;
	if(msg->info != NULL) {
		if(msg->freeinfo != NULL)
			msg->freeinfo(msg->info);
		else
			free(msg->info);
	}
	if(msg->parts != NULL) {
		struct sf_str *next;
		struct sf_str *prev;
		struct sf_str *current = msg->parts;
		x = 1;
		do {
			next = current->next;
			prev = next->prev;
			if(next == msg->parts)
				x = 0;
			sf_str_remove(current);
			if(msg->parts == NULL)
				x = 0;
			else if(prev == current && next == msg->parts)
				x = 0;
			current = next;
		}
		while(x);
	}
	msg->prev->next = msg->next;
	msg->next->prev = msg->prev;
	if(msg == msglist->msgs) {
		if(msg->next == msglist->msgs)
			msglist->msgs = NULL;
		else
			msglist->msgs = msg->next;
	}
	free(msg);
}

inline void sf_msglist_remove_keep(struct sf_msg *msg) {
	int x;
	struct sf_msglist *msglist = msg->msglist;
	if(msg->info != NULL) {
		if(msg->freeinfo != NULL)
			msg->freeinfo(msg->info);
		else
			free(msg->info);
	}
	msg->prev->next = msg->next;
	msg->next->prev = msg->prev;
	if(msg == msglist->msgs) {
		if(msg->next == msglist->msgs)
			msglist->msgs = NULL;
		else
			msglist->msgs = msg->next;
	}
	free(msg);
}

void sf_msglist_del(struct sf_msglist *msglist) {
	if(msglist->msgs != NULL) {
		int x = 1;
		struct sf_msg *next;
		struct sf_msg *current = msglist->msgs;
		do {
			next = current->next;
			if(next == msglist->msgs)
				x = 0;
			sf_msglist_remove(current);
			if(msglist->msgs == NULL)
				x = 0;
			else if(next->prev == current && next == msglist->msgs)
				x = 0;
			current = next;
		}
		while(x);
	}
	free(msglist);
}

struct sf_toarray *sf_toarray_new() {
	struct sf_toarray *toarray = malloc(sizeof(struct sf_toarray));
	toarray->array = NULL;
	return toarray;
}

void sf_toarray_push(struct sf_toarray *toarray, struct sf_connection *connection) {
	struct sf_to *to = toarray->array;
	struct sf_to *newto = malloc(sizeof(struct sf_to));
	newto->connection = connection;
	newto->parent = toarray;
	if(toarray->array == NULL) {
		newto->next = newto;
		newto->prev = newto;
		toarray->array = newto;
	}
	else {
		toarray->array->prev->next = newto;
		newto->prev = toarray->array->prev;
		toarray->array->prev = newto;
		newto->next = toarray->array;
	}
}

void sf_toarray_remove(struct sf_to *to) {
	to->prev->next = to->next;
	to->next->prev = to->prev;
	if(to == to->parent->array) {
		if(to->next == to->parent->array)
			to->parent->array = NULL;
		else
			to->parent->array = to->next;
	}
	free(to);
}


void sf_toarray_del(struct sf_toarray *toarray) {
	if(toarray->array != NULL) {
		int x = 1;
		struct sf_to *next;
		struct sf_to *current = toarray->array;
		do {
			next = current->next;
			if(next == toarray->array)
				x = 0;
			sf_toarray_remove(current);
			if(toarray->array == NULL)
				x = 0;
			else if(next->prev == current && next == toarray->array)
				x = 0;
			current = next;
		}
		while(x);
	}
	free(toarray);
}


void sf_connection_add(struct sf_connection *connection) {
	struct sf_instance *instance = connection->instance;
	if(instance->connections == NULL) {
		connection->next = connection;
		connection->prev = connection;
		instance->connections = connection;
	}
	else {
		instance->connections->prev->next = connection;
		connection->prev = instance->connections->prev;
		instance->connections->prev = connection;
		connection->next = instance->connections;
	}
}

void sf_connection_remove(struct sf_connection *connection) {
	struct sf_instance *instance = connection->instance;
	connection->prev->next = connection->next;
	connection->next->prev = connection->prev;
	if(connection == instance->connections) {
		if(connection->next == instance->connections)
			instance->connections = NULL;
		else
			instance->connections = connection->next;
	}
	free(connection);
}


struct sf_instance *sf_instance_new(struct sf_ctx *context, int port, void (*validate)(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret), void (*callback)(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret)) {
	struct sf_instance *instance = malloc(sizeof(struct sf_instance));
	instance->context = context;
	instance->connections = NULL;
	instance->dataptr = NULL;
	instance->validate = validate;
	instance->callback = callback;
	instance->server = NULL;
	
	if(port != -1) {
		int optval = 1;
		struct sockaddr_in6 addr;
		socklen_t addr_len = sizeof(addr);
		instance->server = malloc(sizeof(struct sf_server));

		if((instance->server->socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
			perror("socket error");
			free(instance->server);
			free(instance);
			return NULL;
		}
		
		int fl = fcntl(instance->server->socket, F_GETFL);
		if(fcntl(instance->server->socket, F_SETFL, fl | O_NONBLOCK) < 0)
			printf("error on setting socket flags.");
			
		if(setsockopt(instance->server->socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
			perror("error setting SO_REUSEADDR");
		
		optval = 0;
		if(setsockopt(instance->server->socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&optval, sizeof(optval)) < 0)
			perror("error setting IPV6_V6ONLY");

		memset(&addr, '\0', addr_len);
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(port);
		addr.sin6_addr = in6addr_any;

		if(bind(instance->server->socket, (struct sockaddr*)&addr, addr_len) != 0) {
			perror("bind error");
			close(instance->server->socket);
			free(instance->server);
			free(instance);
			return NULL;
		}
		
		if(getsockname(instance->server->socket, (struct sockaddr *)&addr, &addr_len) == -1) {
			perror("getsockname error");
			close(instance->server->socket);
			free(instance->server);
			free(instance);
			return NULL;
		}
		instance->server->port = ntohs(addr.sin6_port);

		if(listen(instance->server->socket, 2) < 0) {
			perror("listen error");
			close(instance->server->socket);
			free(instance->server);
			free(instance);
			return NULL;
		}
		
		char address[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr.sin6_addr, address, INET6_ADDRSTRLEN);
		printf("Server listening on %s %d\n", address, instance->server->port);
		
		instance->server->w_accept = malloc(sizeof(struct sf_io));
		instance->server->w_accept->ptr = instance;
		ev_io_init(&instance->server->w_accept->io, sf_instance_accept, instance->server->socket, EV_READ);
		ev_io_start(context->loop, &instance->server->w_accept->io);
	}
	return instance;
}

void sf_instance_validate_timeout(struct ev_loop *loop, struct ev_timer *w_, int revents) {
	struct sf_conntimer *w = (struct sf_conntimer *)w_;
	struct sf_connection *connection = w->connection;
	printf("Validation timed-out\n");
	ev_timer_stop(connection->instance->context->loop, &w->timer);
	free(w);
	connection->validate_timeout = NULL;
	sf_instance_close(connection);
}

void sf_instance_accept(struct ev_loop *loop, struct ev_io *w_, int revents) {
	struct sf_io *w_accept = (struct sf_io *)w_;
	socklen_t addr_len = sizeof(struct sockaddr_storage);

	if(revents & EV_ERROR) {
		perror("got invalid event");
		return;
	}
	
	struct sf_connection *connection = malloc(sizeof(struct sf_connection));
	connection->type = SERVER;
	connection->instance = w_accept->ptr;
	if(&connection->instance->validate == NULL)
		connection->validated = 1;
	else {
		connection->validated = 0;
	}
	connection->receive = sf_msglist_new();
	connection->send = sf_msglist_new();
	connection->writable = 0;
	connection->beat = 0;
	connection->dataptr = NULL;
	connection->validate_timeout = NULL;
	
	int sd = accept(w_accept->io.fd, (struct sockaddr *)&connection->addr, &addr_len);
	if (sd < 0) {
		perror("accept error");
		return;
	}

	int optval = 1;
	if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
		perror("error setting SO_REUSEADDR");

	char address[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&connection->addr)->sin6_addr, address, INET6_ADDRSTRLEN);
	printf("Client %s %d accepted\n", address, (int)ntohs(((struct sockaddr_in6 *)&connection->addr)->sin6_port));
	
	connection->socket = sf_sockets_add(connection, sd);
	
	struct sf_io *w_server = malloc(sizeof(struct sf_io));
	w_server->ptr = (void *)connection;
	ev_io_init(&w_server->io, sf_instance_connection, sd, EV_READ);
	ev_io_start(loop, &w_server->io);
	connection->w = w_server;
	
	sf_connection_add(connection);
	
	int ret;
	if(connection->validated) {
		ret = sf_instance_callback(connection, CONNECTED, NULL);
		if(ret < 0)
			sf_instance_close(connection);
	}
	else {
		connection->validate_timeout = malloc(sizeof(struct sf_conntimer));
		connection->validate_timeout->connection = connection;
		ev_timer_init(&connection->validate_timeout->timer, sf_instance_validate_timeout, connection->instance->context->timers.validation_timeout/1000000.0, 0.0);
		ev_timer_start(connection->instance->context->loop, &connection->validate_timeout->timer);
	}
}

void sf_instance_connecting(struct ev_loop *loop, struct ev_timer *w_, int revents) {
	struct sf_conntimer *w = (struct sf_conntimer *)w_;
	int addr_len = sizeof(struct sockaddr_storage);
	struct sf_connection *connection = w->connection;
	
	struct timeval now;
	gettimeofday(&now, NULL);
	if((now.tv_sec-connection->connect_timeout->tv_sec)*1000000 + (now.tv_usec-connection->connect_timeout->tv_usec) > connection->instance->context->timers.connect_timeout) {
		printf("Connect timed-out\n");
		ev_timer_stop(connection->instance->context->loop, &w->timer);
		free(w);
		free(connection->connect_timeout);
		sf_instance_close(connection);
		return;
	}
	
	int e = connect(connection->w->io.fd, (struct sockaddr *)&connection->addr, addr_len);
	int errsv = errno;
	if(e < 0 && errsv != EINPROGRESS && errsv != EALREADY && errsv != EISCONN) {
		perror("Connect error");
		ev_timer_stop(connection->instance->context->loop, &w->timer);
		free(w);
		free(connection->connect_timeout);
		sf_instance_close(connection);
		return;
	}
	if(errsv == EISCONN || e >= 0) {
		free(connection->connect_timeout);
		ev_timer_stop(connection->instance->context->loop, &w->timer);
		free(w);
		
		ev_io_start(connection->instance->context->loop, &connection->w->io);
		connection->beat = 0;
		printf("Successfully connected to server\n");
		int ret;
		if(connection->validated) {
			ret = sf_instance_callback(connection, CONNECTED, NULL);

			if(ret < 0)
				sf_instance_close(connection);
		}
		else {
			ret = sf_instance_validate(connection, CLIENT_VAL, NULL);
			if(ret == 1) {
				connection->validated = 1;
				ret = sf_instance_callback(connection, CONNECTED, NULL);
				if(ret < 0)
					sf_instance_close(connection);
			}
			else {
				connection->validate_timeout = malloc(sizeof(struct sf_conntimer));
				connection->validate_timeout->connection = connection;
				ev_timer_init(&connection->validate_timeout->timer, sf_instance_validate_timeout, connection->instance->context->timers.validation_timeout/1000000.0, 0.0);
				ev_timer_start(connection->instance->context->loop, &connection->validate_timeout->timer);
			}
		}
	}
}

struct sf_connection *sf_instance_connect(struct sf_instance *instance, char *ip, int port) {
	int addr_len = sizeof(struct sockaddr_storage);
	int e, errsv, sd;
	//char *address = malloc(INET6_ADDRSTRLEN);
		
	struct sf_connection *connection = malloc(sizeof(struct sf_connection));
	connection->type = CLIENT;
	connection->instance = instance;
	if(&connection->instance->validate == NULL)
		connection->validated = 1;
	else {
		connection->validated = 0;
	}
	
	char szHost[256], szPort[16];
	struct addrinfo ai_hints, *ai_list, *ai;
	memset(&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = SOCK_STREAM;
	ai_hints.ai_protocol = IPPROTO_TCP;
	char *service = malloc(16);
	snprintf(service, 16, "%d", port);
	e = getaddrinfo(ip, service, &ai_hints, &ai_list);
	if (e != 0) {
		perror("getaddrinfo error");
		free(connection);
		return NULL;
	}
	free(service);
	
	for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
		getnameinfo(ai->ai_addr, ai->ai_addrlen, szHost, sizeof(szHost), szPort, sizeof(szPort), NI_NUMERICHOST | NI_NUMERICSERV);
		printf("host=%s, port=%s, family=%d\n", szHost, szPort, ai->ai_family);

		sd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sd < 0)	{
			perror("socket error");
			free(connection);
			return NULL;
		}
		
		int fl = fcntl(sd, F_GETFL);
		if (fcntl(sd, F_SETFL, fl | O_NONBLOCK) < 0)
			printf("error on setting socket flags.\n");

		int optval = 1;
		if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
			perror("error setting SO_REUSEADDR");
		
		e = connect(sd, ai->ai_addr, ai->ai_addrlen);
		errsv = errno;
		if(e < 0 && errsv != EINPROGRESS) {
			perror("Connect error");
			continue;
		}
		memcpy(&connection->addr, ai->ai_addr, ai->ai_addrlen);
		break;
   }
   freeaddrinfo(ai_list);
	
	connection->receive = sf_msglist_new();
	connection->send = sf_msglist_new();
	connection->writable = 0;
	connection->beat = -1;
	connection->dataptr = NULL;
	connection->validate_timeout = NULL;
	
	connection->socket = sf_sockets_add(connection, sd);
	
	struct sf_io *w_conn = malloc(sizeof(struct sf_io));
	w_conn->ptr = (void *)connection;
	ev_io_init(&w_conn->io, sf_instance_connection, sd, EV_READ);
	connection->w = w_conn;
	
	sf_connection_add(connection);
	
	if(errsv == EINPROGRESS) {
		struct sf_conntimer *connecting = malloc(sizeof(struct sf_conntimer));
		connecting->connection = connection;
		connection->connect_timeout = malloc(sizeof(struct timeval));
		gettimeofday(connection->connect_timeout, NULL);
		ev_timer_init(&connecting->timer, sf_instance_connecting, instance->context->timers.connectretry_interval/1000000.0, instance->context->timers.connectretry_interval/1000000.0);
		ev_timer_start(instance->context->loop, &connecting->timer);
	}
	else {
		ev_io_start(instance->context->loop, &w_conn->io);
		connection->beat = 0;
		printf("Successfully connected to server\n");
		int ret;
		if(connection->validated) {
			ret = sf_instance_callback(connection, CONNECTED, NULL);
			if(ret < 0)
				sf_instance_close(connection);
		}
		else {
			ret = sf_instance_validate(connection, CLIENT_VAL, NULL);
			if(ret == 1) {
				connection->validated = 1;
				ret = sf_instance_callback(connection, CONNECTED, NULL);
				if(ret < 0)
					sf_instance_close(connection);
			}
			else {
				connection->validate_timeout = malloc(sizeof(struct sf_conntimer));
				connection->validate_timeout->connection = connection;
				ev_timer_init(&connection->validate_timeout->timer, sf_instance_validate_timeout, connection->instance->context->timers.validation_timeout/1000000.0, 0.0);
				ev_timer_start(connection->instance->context->loop, &connection->validate_timeout->timer);
			}
		}
	}
	
	return connection;
}

void sf_instance_getwritable(struct sf_connection *connection) {
	ev_io_stop(connection->instance->context->loop, &connection->w->io);
	ev_io_set(&connection->w->io, connection->w->io.fd, EV_READ|EV_WRITE);
	ev_io_start(connection->instance->context->loop, &connection->w->io);
}

void sf_instance_getwritableall(struct sf_instance *instance) {
	if(instance->connections != NULL) {
		struct sf_connection *current = instance->connections;
		do {
			sf_instance_getwritable(current);
			current = current->next;
		}
		while(current != instance->connections);
	}
}

unsigned int power(unsigned int base, unsigned int expo) {
	unsigned int ret = base;
	while(expo > 1) {
		ret *= base;
		expo--;
	}
	return ret;
}

#define HEADWIDTH 2
#define CHUNKSIZE power(2, 2*8-1)

inline struct sf_msg *sf_send_encode(struct sf_msg *msg) {
	int x, n, b;
	unsigned int l, c = 0, uid = urand();
	//printf("UID: %u\n", uid);
	unsigned char *p;
	struct sf_msg *send_s = sf_msg_new();
	struct sf_str *sendstr = malloc(sizeof(struct sf_str));
	sendstr->parent = send_s;
	sf_str_add(sendstr);
	sendstr->data = malloc(sizeof(char) * 10);
	sendstr->len = HEADWIDTH+8; //head:2 bytes, uid:4bytes, segcount:4bytes
	packi32(&sendstr->data[HEADWIDTH], uid);
	b = CHUNKSIZE - sendstr->len;
	if(msg->parts != NULL) {
		struct sf_str *msgstr = msg->parts;
		do {
			n = msgstr->len;
			if(n == 0) {
				if(b == CHUNKSIZE) {
					sendstr = malloc(sizeof(struct sf_str));
					sendstr->parent = send_s;
					sf_str_add(sendstr);
					sendstr->data = calloc(sizeof(char), 6);
					sendstr->len = HEADWIDTH+4;
					packi32(&sendstr->data[HEADWIDTH], uid);
					b = CHUNKSIZE - sendstr->len;
				}
				sendstr->data = realloc(sendstr->data, sizeof(char) * (sendstr->len + HEADWIDTH));
				memset(sendstr->data + sendstr->len, '\0', HEADWIDTH);
				packi16(&sendstr->data[sendstr->len], 0);	
				sendstr->data[sendstr->len] &= ~(1 << 7);
				sendstr->len += HEADWIDTH;
				b = CHUNKSIZE - sendstr->len;
				if(b == 0) {
					b = CHUNKSIZE;
					packi16(sendstr->data, (unsigned short)(sendstr->len-HEADWIDTH));
					sendstr->data[0] |= 1 << 7;
					//printf("send len:%d\n", (int)sendstr->len-HEADWIDTH);
				}
				c++;
			}
			while(n > 0) {
				if(b == CHUNKSIZE) {
					sendstr = malloc(sizeof(struct sf_str));
					sendstr->parent = send_s;
					sf_str_add(sendstr);
					sendstr->data = calloc(sizeof(char), 6);
					sendstr->len = HEADWIDTH+4;
					packi32(&sendstr->data[HEADWIDTH], uid);
					b = CHUNKSIZE - sendstr->len;
				}
				if(n + HEADWIDTH > b)
					p = &msgstr->data[msgstr->len - n + (b - (HEADWIDTH)) - 1];
				else
					p = &msgstr->data[msgstr->len - 1];
				l = p - &msgstr->data[msgstr->len - n] + 1;
				sendstr->data = realloc(sendstr->data, sizeof(char) * (sendstr->len + l + HEADWIDTH));
				memset(sendstr->data + sendstr->len, '\0', l + HEADWIDTH);
				packi16(&sendstr->data[sendstr->len], (unsigned short)l);
				//printf("%u %u\n", (unsigned int)msgstr->len - n, l);
				memcpy(&sendstr->data[sendstr->len + HEADWIDTH], &msgstr->data[msgstr->len - n], l);
				n -= l;
				if(n == 0)
					sendstr->data[sendstr->len] &= ~(1 << 7);
				else
					sendstr->data[sendstr->len] |= 1 << 7;
				sendstr->len += l + HEADWIDTH;
				b = CHUNKSIZE - sendstr->len;
				if(b == 0) {
					b = CHUNKSIZE;
					packi16(sendstr->data, (unsigned short)(sendstr->len-HEADWIDTH));
					sendstr->data[0] |= 1 << 7;
					//printf("send len:%d\n", (int)sendstr->len-HEADWIDTH);
				}
				c++;
			}
			msgstr = msgstr->next;
		}
		while(msgstr != msg->parts);
	}
	if(b != 0) {
		packi16(sendstr->data, (unsigned short)(sendstr->len-HEADWIDTH));
		sendstr->data[0] |= 1 << 7;
		//printf("send len:%d\n", (int)sendstr->len-HEADWIDTH);
	}
	//printf("segcount: %u\n", c);
	packi32(&send_s->parts->data[HEADWIDTH+4], c);
	
	if(msg->parts != NULL) {
		struct sf_str *next;
		struct sf_str *current = msg->parts;
		x = 1;
		do {
			next = current->next;
			if(next == msg->parts)
				x = 0;
			sf_str_remove(current);
			if(msg->parts == NULL)
				x = 0;
			else if(next->prev == current && next == msg->parts)
				x = 0;
			current = next;
		}
		while(x);
	}
	free(msg);
	
	return send_s;
}

void sf_instance_sendto(struct sf_connection *connection, struct sf_msg *msg) {
	struct sf_toarray *toarray = sf_toarray_new();
	sf_toarray_push(toarray, connection);
	sf_instance_sendtoarray(toarray, msg);
	sf_toarray_del(toarray);
}

void sf_instance_sendtoarray(struct sf_toarray *toarray, struct sf_msg *msg) {
	if(msg->parts == NULL)
		return;
	if(toarray == NULL)
		return;
	if(toarray->array == NULL)
		return;
	int count = 0;
	struct sf_to *current = toarray->array;
	do {
		count++;
		current = current->next;
	}
	while(current != toarray->array);
	int *persistence = malloc(sizeof(int));
	*persistence = count;
	struct sf_msg *temp;
	struct sf_str *tempstr;
	struct sf_msg *send_s = sf_send_encode(msg);
	current = toarray->array;
	do {
		temp = sf_msg_new();
		temp->parts = send_s->parts;
		tempstr = temp->parts;
		do {
			tempstr->parent = temp;
			tempstr = tempstr->next;
		}
		while(tempstr != temp->parts);
		temp->msglist = current->connection->send;
		temp->infosize = sizeof(struct sf_msg_info);
		temp->freeinfo = sf_freeinfo;
		struct sf_msg_info *info = malloc(temp->infosize);
		info->persistence = persistence;
		info->uid = 0;
		info->status = 0;
		temp->info = info;
		sf_msglist_add(temp);
		if (!current->connection->writable)
			sf_instance_getwritable(current->connection);
		current = current->next;
	}
	while(current != toarray->array);
	free(send_s);
}	

void sf_instance_sendtoall(struct sf_instance *instance, struct sf_msg *msg) {
	if(instance->connections == NULL)
		return;
	int count = 0;
	struct sf_connection *current = instance->connections;
	do {
		count++;
		current = current->next;
	}
	while(current != instance->connections);
	int *persistence = malloc(sizeof(int));
	*persistence = count;
	struct sf_msg *temp;
	struct sf_str *tempstr;
	struct sf_msg *send_s = sf_send_encode(msg);
	current = instance->connections;
	do {
		temp = sf_msg_new();
		temp->parts = send_s->parts;
		tempstr = temp->parts;
		do {
			tempstr->parent = temp;
			tempstr = tempstr->next;
		}
		while(tempstr != temp->parts);
		temp->msglist = current->send;
		temp->infosize = sizeof(struct sf_msg_info);
		temp->freeinfo = sf_freeinfo;
		struct sf_msg_info *info = malloc(temp->infosize);
		info->persistence = persistence;
		info->uid = 0;
		info->status = 0;
		temp->info = info;
		sf_msglist_add(temp);
		if (!current->writable)
			sf_instance_getwritable(current);
		current = current->next;
	}
	while(current != instance->connections);
	free(send_s);
}

void sf_instance_connection(struct ev_loop *loop, struct ev_io *w_, int revents) {
	struct sf_io *w = (struct sf_io *)w_;
	if(revents & EV_ERROR) {
		sf_instance_close(w->ptr);
		perror("got invalid event");
		return;
	}
	if(revents & EV_READ) {
		if(sf_instance_read(w->ptr) == -1)
			return;
	}
	if(revents & EV_WRITE)
		sf_instance_write(w->ptr);
}

int sf_instance_write(struct sf_connection *connection) {
	ev_io_stop(connection->instance->context->loop, &connection->w->io);
	ev_io_set(&connection->w->io, connection->w->io.fd, EV_READ);
	ev_io_start(connection->instance->context->loop, &connection->w->io);
	int x, y, at, ret = -1;
	int len;
	if(connection->send->msgs != NULL) {
		struct sf_msg *next;
		struct sf_msg *current = connection->send->msgs;
		do {
			if(((struct sf_msg_info *)current->info)->status == 0) {
				ret = 1;
				break;
			}
			current = current->next;
		}
		while(current != connection->send->msgs);
	}
	if(ret != -1) {
		connection->writable = 1;
		if(connection->validated)
			ret = sf_instance_callback(connection, WRITABLE, NULL);
		else {
			ret = sf_instance_validate(connection, WRITABLE, NULL);
			if(ret == 1) {
				ev_timer_stop(connection->instance->context->loop, &connection->validate_timeout->timer);
				free(connection->validate_timeout);
				connection->validated = 1;
				ret = sf_instance_callback(connection, CONNECTED, NULL);
				if(ret < 0) {
					sf_instance_close(connection);
					return -1;
				}
			}
		}
		if(ret < 0) {
			sf_instance_close(connection);
			return -1;
		}
		connection->writable = 0;
	}
	if(connection->beat == 1) {
		unsigned char beat = 0;
		len = send(connection->w->io.fd, &beat, 1, 0);
		if(len == -1) {
			sf_instance_close(connection);
			return -1;
		}
		gettimeofday(&connection->socket->beat, NULL);
		connection->beat = 2;
		//printf("Beat sent at <%ld.%06ld>\n",  (long int)(connection->socket->beat.tv_sec), (long int)(connection->socket->beat.tv_usec));
	}
	if(connection->send->msgs != NULL) {
		struct sf_msg *next;
		struct sf_msg *current = connection->send->msgs;
		struct sf_msg_info *info;
		struct sf_str * sendstr_next;
		y = 1;
		do {
			next = current->next;
			info = current->info;
			info->status++;
			at = 0;
			if(current->parts != NULL) {
				struct sf_str *sendstr = current->parts;
				do {
					sendstr_next = sendstr->next;
					//printf("header: \n");
					//binary_dump(sendstr->data, 16);
					ret = info->uid - at;
					if(ret < sendstr->len && sendstr->len > 0) {
						len = send(connection->w->io.fd, &sendstr->data[ret], sendstr->len - ret, 0);
						if(len < 1) {
							perror("send error");
							sf_instance_getwritable(connection);
							y = 0;
							break;
						}
						/*
						if(connection->type == 0)
							log2file("server-send.txt", &sendstr->data[ret], len);
						else
							log2file("client-send.txt", &sendstr->data[ret], len);
						
						printf("len: %d strlen:%u ret:%d, persistence: %d\n", len, (unsigned int)sendstr->len, ret, *info->persistence);
						*/
						info->uid += len;
						if(len < sendstr->len - ret) {
							sf_instance_getwritable(connection);
							y = 0;
							break;
						}
						if(sendstr_next == current->parts) {
							x = 0;
							if(next == connection->send->msgs)
								y = 0;
							*info->persistence = *info->persistence - 1;
							if(*info->persistence == 0) {
								free(info->persistence);
								sf_msglist_remove(current);
								break;
							}
							else {
								sf_msglist_remove_keep(current);
								break;
							}
						}
					}
					else if(ret <= 0)
						break;
					else if(sendstr->len - ret <= 0) {
						connection->send->msgs = NULL;
						current->parts = NULL;
						printf("WTF!\n");
						break;
					}
					at += sendstr->len;
					if(current->parts == NULL) 
						x = 0;
					else if(sendstr_next->prev == sendstr && sendstr_next == current->parts)
						x = 0;
					sendstr = sendstr_next;
				}
				while(x);
			}
			if(connection->send->msgs == NULL)
				y = 0;
			else if(next->prev == current && next == connection->send->msgs)
				y = 0;
			current = next;
		}
		while(y);
	}
	return 0;
}

int sf_instance_read(struct sf_connection *connection) {
	int x, ret, type;
	char flag;
	unsigned char *pointer, *req = calloc(2, sizeof(char));
	unsigned int count, bytes, uid;
	ssize_t rlen, len = 0;
	void *in = NULL;
	struct sf_msg *msg = NULL;
	struct sf_msg *current;
	struct sf_str *part;
	struct sf_msg_info *info;

	rlen = recv(connection->w->io.fd, &req[0], 1, 0);
	if(rlen < 1) {
		sf_instance_close(connection);
		free(req);
		return -1;
	}
	type = req[0] >> 7;
	switch(type) {
		case 0: //Beat
			sf_sockets_beat(connection->socket);
			free(req);
			return 0;
			break;
		case 1: //Multipart (wont make available to callback until all parts are received) Asynchronous
			gettimeofday(&connection->socket->lastbeat, NULL);
			rlen = recv(connection->w->io.fd, &req[1], 1, 0);
			if(rlen < 1) {
				free(req);
				sf_instance_close(connection);
				return -1;
			}
			//printf("req bin: \n");
			//binary_dump(req, 1);
			req[0] &= ~(1 << 7);
			bytes = (unsigned int)unpacki16(req) - 4;
			//printf("%u bytes\n", bytes); 
			if(bytes < 7) {
				free(req);
				sf_instance_close(connection);
				return -1;
			}
			
			in = malloc(sizeof(char) * 4);
			len = read(connection->w->io.fd, in, 4);
			//printf("uid bin: \n");
			//binary_dump(in, 4);
			if(len < 1) {
				free(req);
				free(in);
				sf_instance_close(connection);
				return -1;
			}
			uid = unpacki32((unsigned char *)in);
			free(in);
			if(connection->receive->msgs != NULL) {
				current = connection->receive->msgs;
				do {
					info = current->info;
					if(uid == info->uid) {
						msg = current;
						break;
					}
					current = current->next;
				}
				while(current != connection->receive->msgs);
			}
			if (msg == NULL) {
				msg = sf_msg_new();
				msg->freeinfo = sf_freeinfo;
				msg->infosize = sizeof(struct sf_msg_info);
				info = malloc(msg->infosize);
				info->status = 0;
				info->uid = uid;
				info->persistence = NULL;
				msg->info = info;
				msg->msglist = connection->receive;
				sf_msglist_add(msg);
				part = malloc(sizeof(struct sf_str));
				part->parent = msg;
				sf_str_add(part);
				msg->parts->len = 0;
				msg->parts->data = NULL;
			}
			msg->parts->data = realloc(msg->parts->data, sizeof(char) * (msg->parts->len + bytes + 1));
			memset(&msg->parts->data[msg->parts->len], '\0', bytes + 1);
			len = 0;
			while(len != bytes) {
				rlen = read(connection->w->io.fd, &msg->parts->data[msg->parts->len + len], bytes-len);
				if(rlen < 1) {
					if(rlen == 0 || errno == EAGAIN)
						continue;
					perror("read error");
					free(req);
					sf_instance_close(connection);
					return -1;
				}
				len += rlen;
				//printf("len:%d rlen:%d\n", (int)len, (int)rlen);
			}
			msg->parts->len += len;
			//fast read to check if its complete
			in = msg->parts->data;
			/*
			if(msg->parts->len > 32) {
				printf("segment 32 bin: \n");
				binary_dump(in, 10);
			}
			*/
			count = unpacki32((unsigned char *)in);
			//printf("%u messages\n", count);
			pointer = &((unsigned char *)in)[4];
			x = count;
			while(x > 0) {
				flag = 1;
				while(flag == 1) {
					if((int)((void *)pointer - in) == msg->parts->len) {
						free(req);
						//printf("0 length part\n");
						return 0;
					}
					flag = pointer[0] >> 7;
					req[0] = pointer[0] & ~(1 << 7);
					req[1] = pointer[1];
					bytes = unpacki16(req);
					pointer += HEADWIDTH;
					/*
					if(bytes > 0)
						printf("x:%d flag:%d  %u bytes msglen:%d\n", x, flag, bytes, (int)msg->parts->len);
					*/
					if((int)((void *)pointer - in + bytes) > msg->parts->len) {
						printf("length error for multipart message, %d\n", (int)(msg->parts->len - (int)((void *)pointer - in + bytes)));
						/*
						if(connection->type == 0)
							log2file("server-read.txt", in, msg->parts->len);
						else
							log2file("client-read.txt", in, msg->parts->len);
						*/
						sf_instance_close(connection);
						free(req);
						return -1;
					}
					pointer += bytes;
					x--;
				}
				if((int)((void *)pointer - in) >= msg->parts->len && x > 0) {
					printf("%p %p %d\n", pointer, in, (int)((void *)pointer - in));
					free(req);
					return 0;
				}
			}
			//complete process
			free(sf_msg_pop(msg));
			pointer = &((unsigned char *)in)[4];
			while(count > 0) {
				part = malloc(sizeof(struct sf_str));
				part->parent = msg;
				part->data = malloc(sizeof(char) * 4);
				part->len = 0;
				sf_str_add(part);
				flag = 1;
				while(flag == 1 && count > 0) {
					flag = pointer[0] >> 7;
					pointer[0] &= ~(1 << 7);
					bytes = unpacki16(pointer);
					pointer += HEADWIDTH;
					part->data = realloc(part->data, sizeof(char) * (part->len + bytes));
					memcpy(&part->data[part->len], pointer, bytes);
					part->len += bytes;
					pointer += bytes;
					count--;
				}
			}
			free(in);
			break;
		default:
			printf("whats this? \n");
			break;
	}
	free(req);
	if(connection->validated)
		ret = sf_instance_callback(connection, RECEIVED, msg);
	else {
		ret = sf_instance_validate(connection, RECEIVED, msg);
		if(ret == 1) {
			ev_timer_stop(connection->instance->context->loop, &connection->validate_timeout->timer);
			free(connection->validate_timeout);
			connection->validated = 1;
			ret = sf_instance_callback(connection, CONNECTED, NULL);
			if(ret < 0) {
				if(msg != NULL)
					sf_msglist_remove(msg);
				sf_instance_close(connection);
				return -1;
			}
		}
	}
	if(msg != NULL)
		sf_msglist_remove(msg);
	if(ret < 0) {
		sf_instance_close(connection);
		return -1;
	}
	if(ret < 0)
		sf_instance_close(connection);
	return 0;
}

int sf_instance_close(struct sf_connection *connection) {
	ev_io_stop(connection->instance->context->loop, &connection->w->io);
	close(connection->w->io.fd);
	free(connection->w);
	if(connection->validated)
		sf_instance_callback(connection, CLOSING, NULL);
	else {
		if(connection->validate_timeout != NULL) {
			ev_timer_stop(connection->instance->context->loop, &connection->validate_timeout->timer);
			free(connection->validate_timeout);
		}
		sf_instance_validate(connection, CLOSING, NULL);
	}
	sf_msglist_del(connection->receive);
	sf_msglist_del(connection->send);
	sf_sockets_remove(connection);
	sf_connection_remove(connection);
	return 0;
}

int sf_instance_callback(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in) {
	int e = 0;
	connection->instance->callback(connection, reason, in, &e);
	return e;
}

int sf_instance_validate(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in) {
	int e = 0;
	connection->instance->validate(connection, reason, in, &e);
	return e;
}

void sf_instance_del(struct sf_instance *instance) {
	if(instance->server != NULL) {
		ev_io_stop(instance->context->loop, &instance->server->w_accept->io);
		close(instance->server->w_accept->io.fd);
		free(instance->server->w_accept);
		free(instance->server);
	}
	if(instance->connections != NULL) {
		int x = 1;
		struct sf_connection *next;
		struct sf_connection *current = instance->connections;
		do {
			next = current->next;
			if(next == instance->connections)
				x = 0;
			sf_instance_close(current);
			if(instance->connections == NULL)
				x = 0;
			else if(next->prev == current && next == instance->connections)
				x = 0;
			current = next;
		}
		while(x);
	}
	free(instance);
}
