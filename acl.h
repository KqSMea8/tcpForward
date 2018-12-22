#ifndef ACL_H
#define ACL_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <regex.h>
#include "tcpForward.h"

#define STRING 0
#define URI 1
#define URL 2
#define METHOD 3
#define HDR 4
#define DST_IP 5
#define SRC_IP 6


struct acl_child {
    regex_t reg;
    char *method, *key;
    struct acl_child *next;
    int32_t ip;
    int key_len;
    unsigned type :3, negation :1, match_all :1, ip_bit_len :6;
};

typedef struct acl_module {
    struct sockaddr_in dstAddr;
    struct acl_child *acl_child_list;
    struct acl_module *next;
    int listenFd;
    time_t timeout_seconds;
} acl_module_t;

extern int match_acl_get_serverfd(struct clientConn *client);

extern acl_module_t *acl_list;

#endif