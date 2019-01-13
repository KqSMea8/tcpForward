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
extern int connectToDestAddr(struct sockaddr_in *dst, struct sockaddr_in *ori_dst, int rcv_timeo_ms);
extern int read_first_data(struct clientConn *client);
extern int write_data(int fd, char *data, int data_len, acl_module_t *acl);

extern int listenFd, worker_proc, isUseLimitSpeed, thread_pool_size;
extern char *pid_path;
extern acl_module_t globalAcl;

#endif