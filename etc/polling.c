#include<stdio.h>
#include<poll.h>

#define TIMEOUT 2500
#define POLL_SIZE 1

int main(void) {
	struct pollfd pfds[POLL_SIZE];

	pfds[0].fd = 0;
	pfds[0].events = POLLIN;

	printf("Hit RETURN or wait 2.5 seconds for timeout\n");

	int num_events = poll(pfds, sizeof pfds / sizeof(struct pollfd), TIMEOUT);
	if (num_events == 0) {
		printf("Poll time out!\n");
	} else {
		int pollin_happend = pfds[0].revents & POLLIN;

		if (pollin_happend) {
			printf("File descriptor %d id ready to read\n", pfds[0].fd);
		} else {
			printf("Unexpected event occurred: %d\n", pfds[0].fd);
		}
	}
	return 0;
}
