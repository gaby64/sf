#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "sf.h"

int force_exit = 0;

char *mkrndstr(size_t length) {
	static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
	char *randomString;

	if(length) {
		randomString = malloc(length + 1);
		int l = (int)(sizeof(charset) -1);
		int key, n;
		for (n = 0; n < length; n++) {        
			key = rand() % l;
			randomString[n] = charset[key];
		}

		randomString[length] = '\0';
	}

	return randomString;
}

void validate_server(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret) {
	printf("Server validate, reason: %s\n", reasonsstr[reason]);
	switch(reason) {
		case RECEIVED:
			printf("Client sent validation initiation byte\n");
			*ret = 1;
			break;
		case WRITABLE:
		
			break;
		case CLOSING:
			break;
		default:
			break;
	}
}

void callback_server(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret) {
	int x;
	char *rndstr;
	printf("Server callback, reason: %s\n", reasonsstr[reason]);
	switch(reason) {
		case CONNECTED:
			printf("validated\n");
			struct sf_msg *msg = sf_msg_new();
			sf_msg_push(msg, "TEST", 5);
			sf_msg_push(msg, "BLAH", 5);
			sf_msg_push(msg, "MULTIPART", 10);
			sf_msg_push(msg, "123456789012345678901234567890123456789", 40);
			sf_instance_sendtoall(connection->instance, msg);
			//msg consumed by instance_send, do not free or sf_msg_del
			break;
		case RECEIVED:
			if(in->parts != NULL) {
				struct sf_str *next;
				struct sf_str *current = in->parts;
				do {
					if(current->data[current->len - 1] == '\0')
						printf("%s\n", current->data);
					current = current->next;
				}
				while(current != in->parts);
			}
			break;
		case WRITABLE:
			
			break;
		case CLOSING:
			break;
		default:
			break;
	}
}

void validate_client(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret) {
	printf("Client validate, reason: %s\n", reasonsstr[reason]);
	switch(reason) {
		case CLIENT_VAL:
			;
			struct sf_msg *msg = sf_msg_new();
			sf_msg_push(msg, "0", 1);
			sf_instance_sendto(connection, msg);
			//msg consumed by instance_send, do not free or sf_msg_del
			break;
		case RECEIVED:
			
			break;
		case WRITABLE:
			*ret = 1;
			break;
		case CLOSING:
			break;
		default:
			break;
	}
}

void callback_client(struct sf_connection *connection, enum sf_reasons reason, struct sf_msg *in, int *ret) {
	int x;
	printf("Client callback, reason: %s\n", reasonsstr[reason]);
	switch(reason) {
		case CONNECTED:
			printf("validated\n");
			break;
		case RECEIVED:
			if(in->parts != NULL) {
				struct sf_str *current = in->parts;
				do {
					if(current->data[current->len - 1] == '\0')
						printf("%s\n", current->data);
					current = current->next;
				}
				while(current != in->parts);
			}
			break;
		case WRITABLE:
		
			break;
		case CLOSING:
			break;
		default:
			break;
	}
}

void signal_cb(struct ev_loop *loop, struct ev_signal* watcher, int revents) {
	force_exit = 1;
	switch (watcher->signum) {
		case SIGTERM:
		case SIGINT:
			ev_break(loop, EVBREAK_ALL);
			ev_unloop(loop, EVUNLOOP_ALL);
			break;
		default:
			signal(SIGABRT, SIG_DFL);
			abort();
			break;
	}
}

int main(int argc, char **argv) {
	struct ev_signal sigint, sigkill, sigterm, sigsegv, sigfpe;
	struct ev_loop *loop = ev_default_loop(0);
	
	ev_signal_init(&sigint,  signal_cb, SIGINT);
	ev_signal_init(&sigkill, signal_cb, SIGKILL);
	ev_signal_init(&sigterm, signal_cb, SIGTERM);
	ev_signal_init(&sigsegv, signal_cb, SIGSEGV);
	ev_signal_init(&sigfpe,  signal_cb, SIGFPE);
	
	ev_signal_start(loop, &sigint);
	ev_signal_start(loop, &sigkill);
	ev_signal_start(loop, &sigterm);
	ev_signal_start(loop, &sigsegv);
	ev_signal_start(loop, &sigfpe);
	
	
	printf("Creating context\n");
	struct sf_timers timers;
	timers.socketbeat_interval = 1000000;
	timers.socketbeat_timeout = 2000000;
	timers.connectretry_interval = 300000;
	timers.connect_timeout = 5000000;
	timers.validation_timeout = 10000000;
	struct sf_ctx *sf_context = sf_newcontext(loop, timers);
	struct sf_instance *server = sf_instance_new(sf_context, 6666, validate_server, callback_server);
	if(server == NULL)
		exit(0);
	struct sf_instance *client = sf_instance_new(sf_context, -1, validate_client, callback_client);
	if(client == NULL)
		exit(0);
	struct sf_connection *client_server = sf_instance_connect(client, "127.0.0.1", server->server->port);
	
	printf("Starting ev loop\n");
	
	while(!force_exit) {
		ev_run(loop, 0);
	}

	printf("Exiting\n");
	
	sf_instance_del(server);
	sf_instance_del(client);
	sf_delcontext(sf_context);
	
	ev_loop_destroy(loop);
	
	usleep(100000);
	return 0;
}
