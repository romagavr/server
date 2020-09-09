#include<sys/types.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

// TODO: Add ifndef ?
#include<openssl/ssl.h>
#include<openssl/err.h>
#include<openssl/md5.h>

#include<libxml/parser.h>
#include<libxml/tree.h>

#include"../lib/http-parser/http_parser.h"
#include"network.h"

#define CLIENT_ID "9d2223ab8e334c92bf2584a1e9a9516b"
#define CLIENT_SECRET "ad81374363cf4a6ebd9aad69027615d5"
#define CODE "1449649"
#define TOKEN "AgAAAAAJfAwtAAaSXZEN657D4ETDiWSPzkL4oDE"
#define MAXLINE 5000
#define HEADER_LEN 1000


int getToken();
void print_element_names(xmlNode *a_node);
ssize_t getFolderStruct(const char *folder, struct network *net);
int fileUpload(const char *file, long int file_size, const char *remPath, struct network *net); 
int uploadFile(const char *localPath, const char *remotePath, struct network *net);