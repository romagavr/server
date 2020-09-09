#include"network.h"

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
  m->status = parser->status_code;
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
    // TODO: очистка message структуры
    // TODO: Timeout - если долго нет ответа
    while (1){
        // TODO: память - проверка на достаточность
        // TODO: проверка статуса ответа
        memset(net->read, 0, RECEIVE_BUFFER_SIZE);
        bytes_rec = SSL_read(net->ssl, net->read, RECEIVE_BUFFER_SIZE);
        if (bytes_rec > 0) {
            ssize_t nparsed = http_parser_execute(net->parser, net->settings, net->read, bytes_rec);
            // Проверка ошибок http_parser
            printf("\nNparsed: %d\n", nparsed);
            if (m->message_complete_cb_called)
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

// TODO: при ошибке - очистка памяти
struct network* initNetworkStruct(){
    struct network *net = malloc(sizeof(struct network));
    if (net == 0) {
        fprintf(stderr,"initNetworkStruct(): struct network malloc error\n");
        return 0;
    }
    memset(net, 0, sizeof(struct network));
    net->read = malloc(RECEIVE_BUFFER_SIZE);
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