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
#include<openssl/md5.h>

#include<libxml/parser.h>
#include<libxml/tree.h>

#include"http-parser/http_parser.h"

#define CLIENT_ID "9d2223ab8e334c92bf2584a1e9a9516b"
#define CLIENT_SECRET "ad81374363cf4a6ebd9aad69027615d5"
#define CODE "1449649"
#define TOKEN "AgAAAAAJfAwtAAaSXZEN657D4ETDiWSPzkL4oDE"
#define HOST "oauth.yandex.ru"
#define WHOST "webdav.yandex.ru"

#define MAXLINE 5000
#define HEADER_LEN 1000

//{"access_token": "AgAAAAAJfAwtAAaSXZEN657D4ETDiWSPzkL4oDE", "expires_in": 31536000, "refresh_token": "1:c0790JFluYo6AsrR:ZLZuX_KaVR_2EDeWof3G1zKDMne3DGeO-u8ywEe8VVwgd0JJEpr1:nOUDZvjgDg-U6hv3WgnUYQ", "token_type": "bearer"}

#define MAX_ELEMENT_SIZE 500 
#define MAX_HEADERS 15
#define BODY_SIZE 3000
#define RAW_SIZE 5000
#define MAX_CHUNKS 16

struct network {
    http_parser_settings *settings;
    http_parser *parser;

    SSL *ssl;
    SSL_CTX *ctx; 
    int socket_peer;

    char *read;
};

struct message {
  const char *raw;  // add to complete
  enum http_parser_type type;
  int status_code;
  char *body;
  int content_length;
  int num_headers;
  enum { NONE=0, FIELD, VALUE } last_header_element;
  char headers[MAX_HEADERS][2][MAX_ELEMENT_SIZE];
  int should_keep_alive;

  int message_begin_cb_called;
  int headers_complete_cb_called;
  int message_complete_cb_called;

  int chunked;
  int chunk_length;

  int num_chunks;
  int num_chunks_complete;
  //int chunk_length[MAX_CHUNKS];
};

int on_chunk_header(http_parser *parser) {
    struct message *m = (struct message *)parser->data;
    if (m->chunked != 1)
        m->chunked = 1;
    m->chunk_length = parser->content_length;
    m->content_length += parser->content_length;
    printf("Chunk length: %d\n", parser->content_length);
    return 0;
}

int on_chunk_complete(http_parser *parser) {
    
    return 0;
}

int on_header_field(http_parser *parser, const char *data, size_t length) {
    struct message *m = (struct message *)parser->data;
    if (m->last_header_element != FIELD)
        m->num_headers++;
    strncat(m->headers[m->num_headers-1][0], data, length);
    m->last_header_element = FIELD;
    printf("Header field: %.*s\n", (int)length, data);
    return 0;
}

int on_header_value(http_parser *parser, const char *data, size_t length) {
    struct message *m = (struct message *)parser->data;
    strncat(m->headers[m->num_headers-1][1], data, length);
    m->last_header_element = VALUE;
    printf("Header value: %.*s\n", (int)length, data);
    return 0;
}

int on_message_begin(http_parser *parser) {
  struct message *m = (struct message *)parser->data;
  m->message_begin_cb_called = 1;
  printf("\n***MESSAGE BEGIN***\n\n");
  return 0;
}

int on_headers_complete(http_parser *parser) {
  struct message *m = (struct message *)parser->data;
  m->headers_complete_cb_called = 1;
  printf("\n***HEADERS COMPLETE***\n\n");
  return 0;
}

int on_message_complete(http_parser *parser) {
  struct message *m = (struct message *)parser->data;
  m->status_code = parser->status_code;
  m->message_complete_cb_called = 1;
  printf("\n***MESSAGE COMPLETE***\n\n");
  return 0;
}

int on_body(http_parser *parser, const char* data, size_t length) {
  struct message *m = (struct message *)parser->data;
  strncat(m->body, data, length);
  printf("Body: %.*s\n", (int)length, data);
  return 0;
}

int estTcpConn(struct network *net, const char *host, const char *service);
int getToken();
ssize_t getFolderStruct(const char *folder, struct network *net);
static ssize_t socketWrite(const char *req, size_t reqLen, struct network *net);
int fileUpload(const char *file, long int file_size, const char *remPath, struct network *net); 
int uploadFile(const char *localPath, const char *remotePath, struct network *net);

struct network* initNetworkStruct();
void freeNetworkStruct(struct network *net);

int getToken(){
    SSL *ssl = 0;
    SSL_CTX *ctx = 0; 
    int socket_peer = 0;

    //estTcpConn(&ssl, &ctx, &socket_peer,  WHOST, "https");

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

int estTcpConn(struct network *net, const char *host, const char *service) {
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
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, address_buffer,
                sizeof(address_buffer),
                service_buffer, sizeof(service_buffer),
                NI_NUMERICHOST);
    printf("Remote address is: %s %s\n", address_buffer, service_buffer);

    printf("Creating socket...\n");
    int socket_peer = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
    if (socket_peer < 0) {
        fprintf(stderr, "socket() failed. (%d)\n", errno);
        return -1;
    }
    
    printf("Connecting...\n");
    if (connect(socket_peer, peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", errno);
        return -1;
    }
    freeaddrinfo(peer_address);

    printf("Connected.\n");

    printf("Openning ssl connection.\n");

    OpenSSL_add_all_algorithms();
    SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == 0) {
        fprintf(stderr, "SSL init failed. (%d)\n", errno);
        return -1;
    }
    SSL *ssl = SSL_new(ctx); 
    SSL_set_fd(ssl, socket_peer); 
    if (SSL_connect(ssl) == -1) {
        fprintf(stderr, "SSL connect failed. (%d)\n", errno);
        return -1;
    }
    printf("SSL connected.\n");

    net->socket_peer = socket_peer;
    net->ctx = ctx;
    net->ssl = ssl;

    return 1;
}

static void print_element_names(xmlNode *a_node)
{
    xmlNode *cur_node = NULL;
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE && strcmp(cur_node->name, "href") == 0) {
            printf("%s\n", xmlNodeGetContent(cur_node));
        }
        print_element_names(cur_node->children);
    }
}

ssize_t getFolderStruct(const char *folder, struct network *net) {
    char *sendline = malloc(MAXLINE+1);
    snprintf(sendline, MAXLINE,
		"PROPFIND %s HTTP/1.1\r\n"
		"Host: %s\r\n"
        "Accept: */*\r\n"
        "Depth: 1\r\n"
        "Authorization: OAuth %s\r\n\r\n", folder, WHOST, TOKEN);

    ssize_t bytes_reseived = socketWrite(sendline, strlen(sendline), net);
    return bytes_reseived;
}

int fileUpload(const char *file, long int file_size, const char *remPath, struct network *net) {
    SSL *ssl = net->ssl;

    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    char md5_string[MD5_DIGEST_LENGTH * 2 + 1];
    MD5_CTX md5;
    if (MD5_Init(&md5) == 0){
        fprintf(stderr, "MD5_Init failed. (%d)\n", errno);
        return -1;
    };
    if (MD5_Update(&md5, file, strlen(file)) == 0){
        fprintf(stderr, "MD5_Update failed. (%d)\n", errno);
        return -1;
    };
    if (MD5_Final(md5_hash, &md5) == 0){
        fprintf(stderr, "MD5_Final failed. (%d)\n", errno);
        return -1;
    };
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        sprintf(&md5_string[i*2], "%02x", (unsigned int)md5_hash[i]);

    char sha256[SHA256_DIGEST_LENGTH];
    char sha256_string[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256_CTX sha;
    if (SHA256_Init(&sha) == 0){
        fprintf(stderr, "SHA256_Init failed. (%d)\n", errno);
        return -1;
    };
    if (SHA256_Update(&sha, file, strlen(file)) == 0){
        fprintf(stderr, "SHA256_Update failed. (%d)\n", errno);
        return -1;
    };
    if (SHA256_Final(sha256, &sha) == 0){
        fprintf(stderr, "SHA256_Final failed. (%d)\n", errno);
        return -1;
    };
    // TODO: как это получается
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        sprintf(&sha256_string[i*2], "%02x", (unsigned int)sha256[i]);

    const char *req = "PUT %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Accept: */*\r\n"
                      "Authorization: OAuth %s\r\n"
                      "Etag: %s\r\n"
                      "Sha256: %s\r\n"
                      "Expect: 100-continue\r\n"
                      "Content-Type: application/binary\r\n"
                      "Content-Length: %d\r\n\r\n";

    ssize_t headerLen = snprintf(NULL, 0, req, remPath, WHOST, TOKEN, md5_string, sha256_string, file_size);
    headerLen++; //For '\0'
    char *header = 0;
    if (HEADER_LEN < headerLen) {
        header = malloc(headerLen);
        if (header == 0){
            fprintf(stderr, "Malloc() failed. (%d)\n", errno);
            return -1;
        }
    } else {
        header = alloca(headerLen);
    }
    
    // TODO Обработка ошибок
    snprintf(header, headerLen, req, remPath, WHOST, TOKEN, md5_string, sha256_string, file_size);
    size_t packetLen = headerLen + file_size - 1;
    char *packet = 0;
    if (MAXLINE < packetLen) {
        packet = malloc(packetLen);
        if (packet == 0){
            fprintf(stderr, "Malloc() failed. (%d)\n", errno);
            return -1;
        }
    } else {
        packet = alloca(packetLen);
    }
    memcpy(packet, header, headerLen);
    memcpy(packet + headerLen, file, file_size);

    // TODO обработка ошибок чтения/записи в сокет
    // TODO парсинг ответа
    //  https://github.com/nodejs/http-parser
    char *read = malloc(MAXLINE+1);
    if (read == 0)
        return -1;

    ssize_t bytes_reseived = socketWrite(packet, packetLen, net);

    ////// 
    int bytes_sent, bytes_received; 

    bytes_sent = SSL_write(ssl, packet, packetLen);
    bytes_received = SSL_read(ssl, read, MAXLINE);
    printf("Received (%d bytes): %.*s", bytes_received, bytes_received, read);
    if (bytes_received < 1) 
	    printf("Connection closed by peer.\n");
    ////////

    return 0;
}


int uploadFile(const char *localPath, const char *remotePath, struct network *net){
    SSL *ssl = net->ssl;
    char *resp = 0;
    char *xml = malloc(10000);
    getFolderStruct(remotePath, net);
    //TODO: check remote path
    FILE *fd = fopen(localPath, "rb");
    if (fd == 0){
        fprintf(stderr, "fopen failed. (%d)\n", errno);
        return -1;
    }

    fseek(fd, 0, SEEK_END);
    long int file_size = ftell(fd);
    if (file_size == -1){
        fclose(fd);
        fprintf(stderr, "filesize getting error. (%d)\n", errno);
        return -1;
    }
    rewind(fd);
    unsigned char *file = malloc(file_size);
    if (file == 0){
        fclose(fd);
        fprintf(stderr, "Malloc() failed. (%d)\n", errno);
        return -1;
    }

    //TODO: Check bounds of size_t and long int
    size_t res = fread(file, 1, file_size, fd);
    fclose(fd);
    if (res != file_size) {
        free(file);
        fprintf(stderr, "fread error. (%d)\n", errno);
        return -1;
    }

    //TODO: Check is it folder of file
    int pos = 0;
    for (int i=0; i<strlen(localPath); i++){
        if (localPath[i] == '/')
            pos = i+1;
    }
    char dst[10];
    size_t dstPathLen = strlen(remotePath);
    memcpy(dst, remotePath, dstPathLen);
    if (dst[dstPathLen - 1] != '/'){
        dst[dstPathLen] = '/';
        dstPathLen++;
    }
    memcpy(dst + dstPathLen, localPath + pos, strlen(localPath) - pos);

/////
    printf("\n%s\n", dst);
    for (int i=0; i <= strlen(dst); i++){
        if (dst[i] == '\0')
            printf("%c - null\n", dst[i]); 
        printf("%c ", dst[i]); 
    }
    exit(EXIT_FAILURE);
/////

    //TODO: Manual set name of remote file
    int result = fileUpload(file, res, dst, net);
    free(file);
    if (result == -1) {
        fprintf(stderr, "File upload error.\n");
        return -1;
    }
    return 0;
}

/*            printf("\n%.*s\n", bytes_rec, read+total_rec);
            ssize_t nparsed = http_parser_execute(parser, settings, read + total_rec, bytes_rec);
             
            printf("\nStatus: %d\n", parser->status_code);
            printf("\nStatus: %d\n", nparsed);
            total_rec += bytes_rec;
            struct message *m = (struct message *)parser->data;

            printf("\n%d\n", m->status_code);
            for (int i=0; i < m->num_headers; i++) {
                printf("\nKey: %s; Value: %s\n", m->headers[i][0], m->headers[i][1]);
            }
            printf("\nRaw: %hhx", m->body); */

ssize_t socketWrite(const char *req, size_t reqLen, struct network *net){
    int bytes_sent = 0, bytes_rec = 0;
    struct message *m = (struct message *)net->parser->data;

    // TODO: Обработка отправки
    bytes_sent = SSL_write(net->ssl, req, reqLen);
    printf("Sent\n");
    while (1){
        // TODO: память - проверка на достаточность
        // TODO: проверка статуса ответа
        // TODO: разобраться, как определить, что всё сообщение пришло
        memset(net->read, 0, MAXLINE);
        bytes_rec = SSL_read(net->ssl, net->read, MAXLINE);
        if (bytes_rec > 0) {
            ssize_t nparsed = http_parser_execute(net->parser, net->settings, net->read, bytes_rec);
            printf("\nNparsed: %d\n", nparsed);
            if (m->chunked && m->chunk_length == 0) 
                break;

        } else {
            int err = SSL_get_error(net->ssl, bytes_rec);
            switch (err)
            {
                //TODO: check another errors
                case SSL_ERROR_ZERO_RETURN:
                {
                    fprintf(stderr, "SSL_ERROR_ZERO_RETURN (peer disconnected) %i\n", err);
                    break;
                }

                default:
                {
                    fprintf(stderr, "SSL read error: %i:%i\n", bytes_rec, err);
                    break;
                }
            }
            break;
        }
    }  
    return 1;
}

struct network* initNetworkStruct(){
    struct network *net = malloc(sizeof(struct network));
    if (net == 0) {
        fprintf(stderr,"initNetworkStruct(): struct network malloc error\n");
        return 0;
    }
    memset(net, 0, sizeof(struct network));
    net->read = malloc(MAXLINE);
    if (net == 0) {
        fprintf(stderr,"initNetworkStruct(): struct network data field malloc error\n");
        return 0;
    }

    http_parser_settings *settings;
    http_parser *parser;

    settings = malloc(sizeof(http_parser_settings));
    if (settings == 0) {
        fprintf(stderr,"initNetworkStruct(): http_parser_settings malloc error\n");
        return 0;
    }
    memset(settings, 0, sizeof(http_parser_settings));
    settings->on_header_field = on_header_field;
    settings->on_header_value = on_header_value;
    settings->on_message_begin = on_message_begin;
    settings->on_headers_complete = on_headers_complete;
    settings->on_body = on_body;
    settings->on_message_complete = on_message_complete;
    settings->on_chunk_header = on_chunk_header;
    settings->on_chunk_complete = on_chunk_complete;

    parser = malloc(sizeof(http_parser));
    if (parser == 0) {
        fprintf(stderr,"initNetworkStruct(): http_parser malloc error\n");
        return 0;
    }
    memset(parser, 0, sizeof(http_parser));
    http_parser_init(parser, HTTP_RESPONSE);

    struct message *m = malloc(sizeof(struct message));
    if (m == 0) {
        fprintf(stderr,"initNetworkStruct(): Message malloc error\n");
        return 0;
    }
    memset(m, 0, sizeof(struct message));
    m->body = malloc(BODY_SIZE);
    if (m->body == 0) {
        fprintf(stderr,"initNetworkStruct(): Message malloc error\n");
        return 0;
    }
    memset(m->body, 0, BODY_SIZE);
    m->raw = malloc(RAW_SIZE);
    if (m->raw == 0) {
        fprintf(stderr,"initNetworkStruct(): Message malloc error\n");
        return 0;
    }
    memset(m->raw, 0, RAW_SIZE);
    parser->data = m;

    net->parser = parser;
    net->settings = settings;

    return net;
}

void freeNetworkStruct(struct network *net){
    http_parser_settings *settings = net->settings;
    http_parser *parser = net->parser;

    struct message *m = (struct message *)parser->data;
    free(m->body);
    free(m->raw);
    free(m);
    free(parser);
    free(settings);

    free(net->read);
    free(net);
}

int main(int argc, char *argv[]){
    struct network *net = initNetworkStruct();
    if (net == 0){
        exit(EXIT_FAILURE);
    }
    if (estTcpConn(net,  WHOST, "https") < 0) {
        exit(EXIT_FAILURE);
    };
    struct message *m = (struct message *)net->parser->data;

    // без слэша в начале  - 400
    // если нет такой директории - 404
    // в остальных случаях - 207
    if (getFolderStruct("/booksd/", net) < 0) {
        exit(EXIT_FAILURE);
    }; 
    //getToken(ssl);

    //  Нужны тесты - на getFolderStruct("/books/", ssl, &xml)
    //  выдает ошибку Entity: line 1: parser error : Start tag expected, '<' not found
    // ?xml version='1.0' encoding='UTF-8'?><d:multistatus xmlns:d="DAV:">
    printf("MAIN: %s\n", m->body);
    LIBXML_TEST_VERSION
    xmlNode *root_element = 0;
    xmlDoc *doc = 0;
    doc = xmlParseDoc(m->body);
    root_element = xmlDocGetRootElement(doc);
    print_element_names(root_element);
    exit(1);
    /*
    int res = uploadFile("../res/2.png", "/", ssl);
    if (res == -1){
        fprintf(stderr, "File upload error.\n");
        exit(EXIT_FAILURE);
    }
    printf("Closing socket...\n");
    SSL_free(ssl);
    close(socket_peer);
    SSL_CTX_free(ctx);
    printf("Finished.\n");
    */
    //free(xml);
    freeNetworkStruct(net);
    return 0;
}
