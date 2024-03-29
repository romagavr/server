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

#define MAXLINE 54096
#define HEADER_LEN 1000

//{"access_token": "AgAAAAAJfAwtAAaSXZEN657D4ETDiWSPzkL4oDE", "expires_in": 31536000, "refresh_token": "1:c0790JFluYo6AsrR:ZLZuX_KaVR_2EDeWof3G1zKDMne3DGeO-u8ywEe8VVwgd0JJEpr1:nOUDZvjgDg-U6hv3WgnUYQ", "token_type": "bearer"}

typedef struct {
    char *body;
    char *headers;
    size_t body_len;
    size_t headers_len;

    char* status;
} parsedHttp;

int estTcpConn(SSL **ssl, SSL_CTX **ctx, int *socket_peer, const char *host, const char *service);
int getToken();
static ssize_t socketWrite(const char *req, size_t reqLen, parsedHttp *resp, SSL *ssl);

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
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, address_buffer,
                sizeof(address_buffer),
                service_buffer, sizeof(service_buffer),
                NI_NUMERICHOST);
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
    printf("SSL connected.\n");
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

ssize_t getFolderStruct(const char *folder, SSL *ssl, char **xml) {
    char *sendline = malloc(MAXLINE+1);
    char *read = malloc(MAXLINE+1);
    if (read == 0)
        return -1;
    int bytes_sent, bytes_received; 

    snprintf(sendline, MAXLINE,
		"PROPFIND %s HTTP/1.1\r\n"
		"Host: %s\r\n"
        "Accept: */*\r\n"
        "Depth: 1\r\n"
        "Authorization: OAuth %s\r\n\r\n", folder, WHOST, TOKEN);

    parsedHttp *response = malloc(sizeof(parsedHttp));
    ssize_t bytes_reseived = socketWrite(sendline, strlen(sendline), response, ssl);
    exit(1);
    bytes_sent = SSL_write(ssl, sendline, strlen(sendline));
    bytes_received = SSL_read(ssl, read, MAXLINE);
    if (bytes_received < 1) 
	    printf("Connection closed by peer.\n");

    //TODO: А заголовок?

    *xml = strstr(read, "\r\n\r\n");

    //printf("%.*s\n", *xml - read, read);
    //printf("%s\n", *xml);
    //exit(1);
    ssize_t len = -1;
    if (*xml) {
        len = strlen(*xml);
        if (len > 10) 
            *xml += 10;
        else
            len = -1;
    }

	printf("%d\n", len);
    return len;
}

int fileUpload(const char *file, long int file_size, const char *remPath, SSL *ssl) {

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

    parsedHttp *response = malloc(sizeof(parsedHttp));
    ssize_t bytes_reseived = socketWrite(packet, packetLen, response, ssl);

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


int uploadFile(const char *localPath, const char *remotePath, SSL *ssl){
    char *resp = 0;
    char *xml = malloc(10000);
    getFolderStruct(remotePath, ssl, &xml);
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
    int result = fileUpload(file, res, dst, ssl);
    free(file);
    if (result == -1) {
        fprintf(stderr, "File upload error.\n");
        return -1;
    }
    return 0;
}



ssize_t socketWrite(const char *req, size_t reqLen, parsedHttp *resp, SSL *ssl){
    int bytes_sent = 0, bytes_rec = 0;
    int total_rec = 0;

    char *read = malloc(MAXLINE+1);
    if (read == 0)
        return -1;

    bytes_sent = SSL_write(ssl, req, reqLen);
    printf("Sent\n");
    while (1){
        // TODO: память - проверка на достаточность
        bytes_rec = SSL_read(ssl, read + total_rec, MAXLINE);
        printf("bytes: %d\n", bytes_rec);
        if (bytes_rec > 0) {
            total_rec += bytes_rec;
        } else {
            int err = SSL_get_error(ssl, bytes_rec);
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
    *(read + total_rec) = '\0';
    printf("Received (%d bytes): %.*s", total_rec, total_rec, read);

    // Память - очистка + выделение для resp
    char *tmp = strstr(read, "\r\n\r\n");
    if (tmp) {
        printf("\nFull response: \n%s\n", read);
        printf("Headers: \n%.*s\n", tmp - read, read);
        char *ttmp = read;
        int count = 0;
        while (1) {
            ttmp = strstr(ttmp, "\r\n");
            if (ttmp && ttmp != read) {
                printf("%.*s\n", ttmp - read + count, read);
                count += ttmp - read + 4;
                ttmp += count;
            } else
                break;
        }
        //resp->headers_len = tmp - read;
        //memcpy(resp->headers, read, resp->headers_len);
        //resp->body_len = strlen(tmp);
        //memcpy(resp->body, read, resp->body_len);
    } else {
	    printf("Corrupted packet.\n");
    }
    exit(1);
}

int main(int argc, char *argv[]){
    SSL *ssl = 0;
    SSL_CTX *ctx = 0; 
    int socket_peer = 0;

    if (estTcpConn(&ssl, &ctx, &socket_peer,  WHOST, "https") < 0) {
        exit(EXIT_FAILURE);
    };

    char *xml = 0;
    // без слэша в начале  - 400
    // если нет такой директории - 404
    // в остальных случаях - 207
    if (getFolderStruct("/books/", ssl, &xml) < 0) {
        exit(EXIT_FAILURE);
    }; 
    //getToken(ssl);

    //  Нужны тесты - на getFolderStruct("/books/", ssl, &xml)
    //  выдает ошибку Entity: line 1: parser error : Start tag expected, '<' not found
    // ?xml version='1.0' encoding='UTF-8'?><d:multistatus xmlns:d="DAV:">
    LIBXML_TEST_VERSION
    xmlNode *root_element = 0;
    xmlDoc *doc = 0;
    doc = xmlParseDoc(xml);
    root_element = xmlDocGetRootElement(doc);
    print_element_names(root_element);
  
    exit(1);

    int res = uploadFile("../res/2.png", "/", ssl);
    if (res == -1){
        fprintf(stderr, "File upload error.\n");
        exit(EXIT_FAILURE);
    } */
    printf("Closing socket...\n");
    SSL_free(ssl);
    close(socket_peer);
    SSL_CTX_free(ctx);
    printf("Finished.\n");

    free(xml);

    return 0;
}
