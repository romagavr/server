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

#include<libxml/parser.h>
#include<libxml/tree.h>

#define CLIENT_ID "9d2223ab8e334c92bf2584a1e9a9516b"
#define CLIENT_SECRET "ad81374363cf4a6ebd9aad69027615d5"
#define CODE "1449649"
#define TOKEN "AgAAAAAJfAwtAAaSXZEN657D4ETDiWSPzkL4oDE"
#define HOST "oauth.yandex.ru"
#define WHOST "webdav.yandex.ru"

#define MAXLINE 54096

//{"access_token": "AgAAAAAJfAwtAAaSXZEN657D4ETDiWSPzkL4oDE", "expires_in": 31536000, "refresh_token": "1:c0790JFluYo6AsrR:ZLZuX_KaVR_2EDeWof3G1zKDMne3DGeO-u8ywEe8VVwgd0JJEpr1:nOUDZvjgDg-U6hv3WgnUYQ", "token_type": "bearer"}
int estTcpConn(SSL **ssl, SSL_CTX **ctx, int *socket_peer, const char *host, const char *service);
int getToken();

int getToken(){
    SSL *ssl = 0;
    SSL_CTX *ctx = 0; 
    int socket_peer = 0;

    estTcpConn(&ssl, &ctx, &socket_peer,  WHOST, "https");

    char sendline[MAXLINE+1];
    char read[MAXLINE+1];
    int bytes_sent, bytes_received; 

    /*snprintf(sendline, MAXLINE,
		"GET /authorize?response_type=code&client_id=%s HTTP/1.1\r\n"
		"Host: %s\r\n\r\n", CLIENT_ID, HOST);
    bytes_sent = SSL_write(ssl, sendline, strlen(sendline));
    //printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(sendline));

    bytes_received = SSL_read(ssl, read, 10000);
    if (bytes_received < 1) 
	    printf("Connection closed by peer.\n");
    printf("Received (%d bytes): %.*s", bytes_received, bytes_received, read);*/

    const char *body = "grant_type=authorization_code&code="CODE
                       "&client_id="CLIENT_ID"&client_secret="CLIENT_SECRET;
    snprintf(sendline, MAXLINE,
		"POST /token http/1.1\r\n"
		"Host: %s\r\n"
        "Content-type: application/x-www-form-urlencoded\r\n"
        "Content-length: %d\r\n\r\n%s", HOST, (int)strlen(body), body);
    //printf("\n%s\n", sendline);
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

    return 0;
}

int estTcpConn(SSL **ssl, SSL_CTX **ctx, int *socket_peer, const char *host, const char *service) {

    printf("Configuring remote address...\n");

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(host, service, &hints, &peer_address)) {
        fprintf(stderr, "geraddrinfo() failed. (%d)\n", errno);
        return -1;
    }
   
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, address_buffer, sizeof(address_buffer), service_buffer, sizeof(service_buffer), NI_NUMERICHOST);
    printf("Remote address is: %s %s\n", address_buffer, service_buffer);

    printf("Creating socket...\n");
    *socket_peer = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
    if (socket_peer < 0) {
        fprintf(stderr, "socket() failed. (%d)\n", errno);
        return -1;
    }
    
    printf("Connecting...\n");
    if (connect(*socket_peer, peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", errno);
        return -1;
    }
    freeaddrinfo(peer_address);

    printf("Connected.\n");

    printf("Openning ssl connection.\n");
    OpenSSL_add_all_algorithms();
    SSL_METHOD *method = SSLv23_client_method();
    *ctx = SSL_CTX_new(method);
    if (*ctx == 0) {
        fprintf(stderr, "SSL init failed. (%d)\n", errno);
        return -1;
    }
    *ssl = SSL_new(*ctx); 
    SSL_set_fd(*ssl, *socket_peer); 
    if (SSL_connect(*ssl) == -1) {
        fprintf(stderr, "SSL connect failed. (%d)\n", errno);
        return -1;
    }
    return 1;
}

static void print_element_names(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            printf("node type: Element, name: %s\n", cur_node->name);
        }
        print_element_names(cur_node->children);
    }
}

int main(int argc, char *argv[]){
    SSL *ssl = 0;
    SSL_CTX *ctx = 0; 
    int socket_peer = 0;

    if (estTcpConn(&ssl, &ctx, &socket_peer,  WHOST, "https") < 0) {
        exit(EXIT_FAILURE);
    };

    //getToken(ssl);

    char sendline[MAXLINE+1];
    char read[MAXLINE+1];
    int bytes_sent, bytes_received; 

    printf("Sending request...\n");

    snprintf(sendline, MAXLINE,
		"PROPFIND / HTTP/1.1\r\n"
		"Host: %s\r\n"
        "Accept: */*\r\n"
        "Depth: 1\r\n"
        "Authorization: OAuth %s\r\n\r\n", WHOST, TOKEN);

    printf("\n%s\n", sendline);
    bytes_sent = SSL_write(ssl, sendline, strlen(sendline));
    printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(sendline));

    bytes_received = SSL_read(ssl, read, 10000);
    if (bytes_received < 1) 
	    printf("Connection closed by peer.\n");
    //printf("Received (%d bytes): %.*s", bytes_received, bytes_received, read);
    char *httpbody = strstr(read, "\r\n\r\n");
    if(httpbody) httpbody += 10;
    printf("%s\n", httpbody);

    LIBXML_TEST_VERSION
    xmlNode *root_element = 0;
    xmlDoc *doc = 0;
    doc = xmlParseDoc(httpbody);
    root_element = xmlDocGetRootElement(doc);
    print_element_names(root_element);

    printf("Closing socket...\n");
    SSL_free(ssl);
    close(socket_peer);
    SSL_CTX_free(ctx);
    printf("Finished.\n");

    return 0;
}
