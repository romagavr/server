#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<unistd.h>
#include<errno.h>

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>

int main(){
	printf("Configuring local address...\n");
	struct addrinfo hints;
	struct addrinfo *bind_address = 0, *b = 0;
    	int socket_listen, s;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(0, "8080", &hints, &bind_address);
    	if (s != 0) {
        	fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        	exit(EXIT_FAILURE);
    	}

	printf("Creating socket and binding...\n");
    	for (b = bind_address; b; b = b->ai_next) {
        	printf("Current protocol: %d\n", b->ai_protocol);
	    	socket_listen = socket(b->ai_family, b->ai_socktype, b->ai_protocol);
        	if (socket_listen != -1) {
            		if (bind(socket_listen, b->ai_addr, b->ai_addrlen) == 0) 
                		break;
            		close(socket_listen);
        	}
    	}
	if (b == NULL) {
		fprintf(stderr, "Could not bind\n");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(bind_address);

	printf("Listening...\n");
	if (listen(socket_listen, 10) < 0) {
		fprintf(stderr, "listen() failed. (%d)\n", errno);
		exit(EXIT_FAILURE);
	}

	printf("Waiting for connection...\n");
	struct sockaddr_storage client_address;
	socklen_t client_len = sizeof(struct sockaddr_storage);
	int socket_client = accept(socket_listen, (struct sockaddr*) &client_address, &client_len);
       	if (socket_client <= 0) {
		fprintf(stderr, "accept() failed. (%d)\n", errno);
		exit(EXIT_FAILURE);
	}
	
	printf("Client is connected...");
	char address_buffer[100];
	getnameinfo((struct sockaddr*) &client_address, client_len, address_buffer, sizeof address_buffer, 0, 0, NI_NUMERICHOST);
	printf("%s\n", address_buffer);
	
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
	close(socket_client);
	printf("Closing listening socket...\n");
	close(socket_listen);

	printf("Finished.\n");

	return 0;
}
