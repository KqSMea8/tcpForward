#ifndef PORT_FORWARD_H
#define PORT_FORWARD_H

struct clientConn {
    struct sockaddr_in srcAddr, dstAddr;
    char *clientFirstData;
    time_t timeout_seconds;
    int clientfd, serverfd, clientFirstDataLen;
};

extern int create_listen(char *ip, int port);
extern int is_http_request(char *req);
extern int connectionToDestAddr(struct sockaddr_in *dst);

extern int listenFd, worker_proc;
extern struct sockaddr_in defDstAddr;
extern char *pid_path;
extern time_t globalTimeout;

#endif