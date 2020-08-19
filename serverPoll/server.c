#include<sys/wait.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<unistd.h>
#include<errno.h>

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<signal.h>

#define PORT "8080"
#define BACK_LOG 10

void sigchld_handler(int s) {
	int saved_errno = errno;
	while(waitpid(-1, NULL, WNOHANG) > 0);
	errno = saved_errno;
}

int main(){
	printf("Configuring local address...\n");

	struct addrinfo hints, *bind_address = 0, *b = 0;
	struct sockaddr_storage client_address;
	struct sigaction sa;
	socklen_t client_len;
    	int socket_client, socket_listen, s, yes = 1;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

    	if ((s = getaddrinfo(0, PORT, &hints, &bind_address)) != 0) {
        	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        	exit(EXIT_FAILURE);
    	}

	printf("Creating socket and binding...\n");
    	for (b = bind_address; b; b = b->ai_next) {
	    	socket_listen = socket(b->ai_family, b->ai_socktype, b->ai_protocol);
        	if (socket_listen != -1) {
			if (setsockopt(socket_listen, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        			fprintf(stderr, "sockopt error: %s\n", errno);
        			exit(EXIT_FAILURE);
			}
            		if (bind(socket_listen, b->ai_addr, b->ai_addrlen) == 0) 
                		break;
            		close(socket_listen);
        	}
    	}
	freeaddrinfo(bind_address);
	if (b == NULL) {
		fprintf(stderr, "Could not bind\n");
		exit(EXIT_FAILURE);
	}

	printf("Listening...\n");
	if (listen(socket_listen, BACK_LOG) == -1) {
		fprintf(stderr, "listen() failed. (%d)\n", errno);
		exit(EXIT_FAILURE);
	}

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		fprintf(stderr, "sigaction() failed. (%d)\n", errno);
		exit(EXIT_FAILURE);
	}

	printf("Waiting for connection...\n");

	while(1) {
		client_len = sizeof(struct sockaddr_storage);
		socket_client = accept(socket_listen, (struct sockaddr*) &client_address, &client_len);
       		if (socket_client == -1) {
			fprintf(stderr, "accept() failed. (%d)\n", errno);
			continue;
		}
		printf("Client is connected...");
		char address_buffer[100];
		s = getnameinfo((struct sockaddr*) &client_address, client_len, address_buffer, sizeof address_buffer, 0, 0, NI_NUMERICHOST);
		if (s == 0 && strlen(address_buffer) > 0)
			printf("Client is connected from %s\n", address_buffer);
		else
			fprintf(stderr, "Client is connected, but name not resolved. (%d)\n", errno);

		if (!(s = fork())) {
			close(socket_listen);

			printf("Reading request...\n");
			char request[1024];
			int bytes_received = recv(socket_client, request, 1024, 0);
			printf("Received %d bytes. \n", bytes_received);
			printf("%.*s", bytes_received, request);

			printf("Sending response...\n");
			const char *response = 
				"HTTP/1.1 200 OK\r\n"
				"Connection: close\r\n"
				"Content-Type: text/plain\r\n\r\n"
				"Local time is: ";
			int bytes_sent = send(socket_client, response, strlen(response), 0);
			printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(response));

			time_t timer;
			time(&timer);
			char *time_msg = ctime(&timer);
			bytes_sent = send(socket_client, time_msg, strlen(time_msg), 0);
			printf("Sent %d of %d bytes. \n", bytes_sent, (int)strlen(time_msg));

			printf("Closing connection...\n");
			exit(EXIT_SUCCESS);
		}
		if (s == -1) fprintf(stderr, "fork() error: no child process is created. (%d)\n", errno);
		close(socket_client);
	}	
	close(socket_listen);
	printf("Finished.\n");

	return 0;
}
