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

#include<openssl/ssl.h>
#include<openssl/err.h>

#define CLIENT_ID "9d2223ab8e334c92bf2584a1e9a9516b"
#define CLIENT_SECRET "ad81374363cf4a6ebd9aad69027615d5"
#define HOST "oauth.yandex.ru"
#define MAXLINE 4096
#define CODE "2411377"

//{"access_token": "AgAAAAAJfAwtAAaSXZEN657D4ETDiWSPzkL4oDE", "expires_in": 31536000, "refresh_token": "1:c0790JFluYo6AsrR:ZLZuX_KaVR_2EDeWof3G1zKDMne3DGeO-u8ywEe8VVwgd0JJEpr1:nOUDZvjgDg-U6hv3WgnUYQ", "token_type": "bearer"}

int main(int argc, char *argv[]){

    printf("Configuring remote address...\n");

    SSL *ssl = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(HOST, "https", &hints, &peer_address)) {
        fprintf(stderr, "geraddrinfo() failed. (%d)\n", errno);
        exit(EXIT_FAILURE);
    }
   
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, address_buffer, sizeof(address_buffer), service_buffer, sizeof(service_buffer), NI_NUMERICHOST);
    printf("Remote address is: %s %s\n", address_buffer, service_buffer);

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

    printf("Openning ssl connection.\n");
    OpenSSL_add_all_algorithms();
    SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == 0) {
        fprintf(stderr, "SSL init failed. (%d)\n", errno);
        exit(EXIT_FAILURE);
    }
    ssl = SSL_new(ctx); 
    SSL_set_fd(ssl, socket_peer); 
    if (SSL_connect(ssl) == -1) {
        fprintf(stderr, "SSL connect failed. (%d)\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Sending request...\n");
    char sendline[MAXLINE+1];
    snprintf(sendline, MAXLINE,
		"GET /authorize?response_type=code&client_id=%s HTTP/1.1\r\n"
		"Host: %s\r\n\r\n", CLIENT_ID, HOST);
    int bytes_sent = SSL_write(ssl, sendline, strlen(sendline));
    printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(sendline));

    char read[MAXLINE+1];
    int bytes_received = SSL_read(ssl, read, 10000);
    if (bytes_received < 1) 
	    printf("Connection closed by peer.\n");
    printf("Received (%d bytes): %.*s", bytes_received, bytes_received, read);

    // 
    const char *body = "grant_type=authorization_code&code="CODE"&client_id="CLIENT_ID"&client_secret="CLIENT_SECRET;
    snprintf(sendline, MAXLINE,
		"POST /token HTTP/1.1\r\n"
		"Host: %s\r\n"
                "Content-type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %d\r\n\r\n%s", HOST, (int)strlen(body), body);
    printf("\n%s\n", sendline);
    bytes_sent = SSL_write(ssl, sendline, strlen(sendline));
    printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(sendline));

    bytes_received = SSL_read(ssl, read, 10000);
    if (bytes_received < 1) 
	    printf("Connection closed by peer.\n");
    printf("Received (%d bytes): %.*s", bytes_received, bytes_received, read);

    printf("Closing socket...\n");
    SSL_free(ssl);
    close(socket_peer);
    SSL_CTX_free(ctx);
    printf("Finished.\n");

    const char *response = 
		"GET / HTTP/1.1\r\n"
		"Host: webdav.yandex.ru\r\n"
        //"Challenge: \"Basic\" realm\r\n"
        "Depth: 1\r\n"
        //"Content-Type: text/xml\r\n"
        "Authorization: Basic Z2F2cmlsYW5kaWE6NzVyb21hNTVwb21h\r\n"
        "Accept: */*\r\n\r\n";
        //"<D:propfind xmlns:D=\"DAV:\"><D:prop><D:quota-available-bytes/><D:quota-used-bytes/></D:prop></D:propfind>";

    return 0;
}
