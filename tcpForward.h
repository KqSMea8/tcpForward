#ifndef TCP_FORWARD_H
#define TCP_FORWARD_H

#include "acl.h"

struct clientConn {
    struct sockaddr_in srcAddr, dstAddr;
    char *clientFirstData;
    int clientfd, serverfd, clientFirstDataLen;
};

extern int create_listen(char *ip, int port);
extern int is_http_request(char *req);
extern int connectionToDestAddr(struct sockaddr_in *dst);

extern int listenFd, worker_proc, isUseLimitSpeed, thread_pool_size;
extern struct sockaddr_in defDstAddr;
extern char *pid_path;
extern acl_module_t globalAcl;

#endif