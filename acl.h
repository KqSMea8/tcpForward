#ifndef ACL_H
#define ACL_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <regex.h>

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
    unsigned long long maxSpeed,  // 最大网速
        sentDataSize,  // 当前秒数已发送字节
        maxDataSize;  // 最大传输流量
    struct acl_child *acl_child_list;
    struct acl_module *next;
    int listenFd;
    int timeout_seconds;
    unsigned isUseLimitMaxData :1;
} acl_module_t;
#include "tcpForward.h"

extern int match_acl_setServer();

extern acl_module_t *acl_list;

#endif