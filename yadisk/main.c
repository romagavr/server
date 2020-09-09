#include"src/client.h"

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
    if (getFolderStruct("/books/", net) < 0) {
        exit(EXIT_FAILURE);
    }; 
    //getToken(ssl);

    //  Нужны тесты - на getFolderStruct("/books/", ssl, &xml)
    //  выдает ошибку Entity: line 1: parser error : Start tag expected, '<' not found
    // ?xml version='1.0' encoding='UTF-8'?><d:multistatus xmlns:d="DAV:">
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