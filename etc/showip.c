#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<netinet/in.h>

#define SERVICE "http"

int main(int argc, char *argv[]) {
	struct addrinfo hints;
	struct addrinfo *res = 0, *p = 0;
	int status;
	char ipstr[INET6_ADDRSTRLEN];

	if (argc != 2) {
		fprintf(stderr, "usage: showip hostname\n");
		exit(EXIT_FAILURE);
	}
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(argv[1], SERVICE, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}
	printf("Ip address for %s:\n\n", argv[1]);

	for (p = res; p; p = p->ai_next) {
		void *addr;
		char *ipver;
		unsigned short int port;
		
		if (p->ai_family == AF_INET) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
			port = ntohs(ipv4->sin_port);
			ipver = "IPv4";
		} else {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			addr = &(ipv6->sin6_addr);
			port = ntohs(ipv6->sin6_port);
			ipver = "IPv6";	
		}
		inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
		printf(" %s: %s:%d\n", ipver, ipstr, port);
	}
	freeaddrinfo(res);
	return 0;
}

