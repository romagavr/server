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

int main(int argc, char *argv[]){
    if (argc < 3) {
        fprintf(stderr, "usage: tcp_client hostname port\n");
        exit(EXIT_FAILURE);
    }

    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(argv[1], argv[2], &hints, &peer_address)) {
        fprintf(stderr, "geraddrinfo() failed. (%d)\n", errno);
        exit(EXIT_FAILURE);
    }
   
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, address_buffer, sizeof(address_buffer), service_buffer, sizeof(service_buffer), NI_NUMERICHOST);
    printf("%Remote address is: s %s\n", address_buffer, service_buffer);

    printf("Creating socket...\n");
    int socket_peer = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
    if (socket_peer < 0) {
        fprintf(stderr, "socket() failed. (%d)\n", errno);
        exit(EXIT_FAILURE);
    }
    
    printf("Connecting...\n");
    if (connect(socket_peer, peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", errno);
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(peer_address);

    printf("Connected.\n");
    printf("To send data, enter text followed by enter.\n");

    while (1) {
    	fd_set reads;
	FD_ZERO(&reads);
	FD_SET(socket_peer, &reads);
	FD_SET(0, &reads);

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 100000;
        
	if (select(socket_peer + 1, &reads, 0, 0, &timeout) < 0) {
        	fprintf(stderr, "select() failed. (%d)\n", errno);
        	exit(EXIT_FAILURE);
	}
	if (FD_ISSET(socket_peer, &reads)) {
		char read[4096];
		int bytes_received = recv(socket_peer, read, 4096, 0);
		if (bytes_received < 1) {
			printf("Connection closed by peer.\n");
			break;
		}
		printf("Received (%d bytes): %.*s", bytes_received, bytes_received, read);
	}	
	if (FD_ISSET(0, &reads)) {
		char read[4096];
		if (!fgets(read, 4096, stdin)) break;
		printf("Sending: %s", read);
		int bytes_sent = send(socket_peer, read, strlen(read), 0);
		printf("Sent %d bytes.\n", bytes_sent);
	}
    }	    
    printf("Closing socket...\n");
    close(socket_peer);
    printf("Finished.\n");
    return 0;
}
