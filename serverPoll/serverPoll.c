#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netdb.h>
#include<unistd.h>
#include<poll.h>
#include<errno.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define PORT "8080"
#define CDATA_LEN 256
#define BACK_LOG 10
#define POLL_TIMEOUT -1

void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) 
		return &(((struct sockaddr_in *)sa)->sin_addr);
	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int get_listener_socket(void) {
	int listener, yes = 1, rv;
	struct addrinfo hints, *ai = 0, *p = 0;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((rv = getaddrinfo(0, PORT, &hints, &ai)) != 0) {
		fprintf(stderr, "Error: getaddrinfo error. (%d) - %s\n", rv,  gai_strerror(rv));
		return -1;
	}

	for (p = ai; p; p = p->ai_next) {
		if ((listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			continue;
		setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
			close(listener);
			continue;
		}
		break;
	}
	if (p == 0) {
		fprintf(stderr, "Error: binding failure\n");
		return -1;
	}

	freeaddrinfo(ai);

	if (listen(listener, BACK_LOG) == -1) {
		fprintf(stderr, "Error: listen failed. (%d) - %s\n", errno, strerror(errno));
		return -1;
	}

	return listener;
}

void add_to_pfds(struct pollfd **pfds, int newfd, int *fd_count, int *fd_size) {
	if (*fd_count == *fd_size) {
		*fd_size *= 2;
		*pfds = realloc(*pfds, sizeof **pfds * (*fd_size));
		if (*pfds == 0){
			free(*pfds);
			fprintf(stderr, "Error: reallocating error: (%d) - %s\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}	
	}

	(*pfds)[*fd_count].fd = newfd;
	(*pfds)[*fd_count].events = POLLIN;

	(*fd_count)++;
}

void del_from_pfds(struct pollfd **pfds, struct pollfd *del_el, int *fd_count) {
	*del_el = (*pfds)[*fd_count - 1];
	(*fd_count)--;
}

int main(void) {
	int listener, newfd, poll_count;
	struct sockaddr_storage remoteaddr;
	struct pollfd *pfds = 0, *p = 0, *s = 0;
	socklen_t addrlen;
	char buffer[CDATA_LEN];
        char remoteIP[INET6_ADDRSTRLEN];  

	int fd_count = 0;
	int fd_size = 5;
	pfds = malloc(sizeof *pfds * fd_size);
	if (pfds == 0) {
		fprintf(stderr, "Error: allocating memory (%d) - %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((listener = get_listener_socket()) == -1) {
		fprintf(stderr, "Error getting listener socket in function get_listener_socket.\n");
		exit(EXIT_FAILURE);
	}

	pfds[0].fd = listener;
	pfds[0].events = POLLIN;
	fd_count = 1;

	for (;;) {
		if ((poll_count = poll(pfds, fd_count, POLL_TIMEOUT)) <= 0) {
			if (poll_count == 0) {
				fprintf(stdout, "Message: poll timeout expired.\n");
			} else {
				fprintf(stderr, "Error: polling error (%d) - %s\n", errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		for (p = pfds; p < pfds + fd_count; ++p) {
			if ((*p).revents & POLLIN) {
				if ((*p).fd == listener) {
					addrlen = sizeof remoteaddr;
					newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
					if (newfd == -1) {
						fprintf(stderr, "Error: accept error (%d) - %s\n", errno, strerror(errno));
					} else {
						add_to_pfds(&pfds, newfd, &fd_count, &fd_size);
						fprintf(stdout, "Message: new connection from %s on "
						       "socket %d\n", inet_ntop(remoteaddr.ss_family,
						       get_in_addr((struct sockaddr *)&remoteaddr),
						       remoteIP, INET6_ADDRSTRLEN), newfd);
					}
				} else {
					memset(&buffer, '\0', CDATA_LEN);
					ssize_t nbytes = recv((*p).fd, buffer, sizeof buffer, 0);
					if (nbytes <=0) {
						if (nbytes == 0) {
							fprintf(stdout, "Message: socket %d hung up\n", (*p).fd);
						} else {
							fprintf(stderr, "Error: receive error on socket "
							       "(%d). (%d) - %s\n", (*p).fd, errno, strerror(errno));
						}
						close((*p).fd);
						del_from_pfds(&pfds, p, &fd_count);
					} else {
						fprintf(stdout, "Message: recived %zu bytes from socket %d.\n", nbytes, (*p).fd);
						for (s = pfds; s < pfds + fd_count; ++s) {
							if ((*s).fd != listener && (*s).fd != (*p).fd 
								&& send((*s).fd, buffer, nbytes, 0) == -1) 
									fprintf(stderr, "Error: sending error "
									"to socket %d. (%d) - %s\n", (*p).fd, errno, strerror(errno));
						}	
					}
				}
			}
		}
	}
        return 0;
}
