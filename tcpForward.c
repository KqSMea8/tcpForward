#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <signal.h>
#include "tcpForward.h"
#include "acl.h"
#include "conf.h"

#define VERSION_MSG "tcp Forward(1.0):\nAuthor: CuteBi\nE-mail: 915445800@qq.com\n"
#define BUFFER_SIZE 4096

struct sockaddr_in defDstAddr;
char *pid_path;
time_t globalTimeout;
int listenFd, worker_proc;

void usage() {
    puts(VERSION_MSG
    "    -c    \033[20G config.conf path\n"
    "    -v    \033[20G display version message\n"
    "    -h    \033[20G display his message\n");
}

int connectionToDestAddr(struct sockaddr_in *dst) {
    int fd;
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)dst, sizeof(struct sockaddr_in)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* 判断请求类型 */
int is_http_request(char *req) {
    if (strncmp(req, "GET", 3) == 0 || 
    strncmp(req, "POST", 4) == 0 ||
    strncmp(req, "CONNECT", 7) == 0 ||
    strncmp(req, "HEAD", 4) == 0 ||
    strncmp(req, "PUT", 3) == 0 ||
    strncmp(req, "OPTIONS", 7) == 0 ||
    strncmp(req, "MOVE", 4) == 0 ||
    strncmp(req, "COPY", 4) == 0 ||
    strncmp(req, "TRACE", 5) == 0 ||
    strncmp(req, "DELETE", 6) == 0 ||
    strncmp(req, "LINK", 4) == 0 ||
    strncmp(req, "UNLINK", 6) == 0 ||
    strncmp(req, "PATCH", 5) == 0 ||
    strncmp(req, "WRAPPED", 7) == 0)
        return 1;
    else
        return 0;
}

static int read_first_data(struct clientConn *client) {
    char *new_data;
    int read_len;

    do {
        new_data = (char *)realloc(client->clientFirstData, client->clientFirstDataLen + BUFFER_SIZE + 1);
        if (new_data == NULL) {
            return 1;
        }
        client->clientFirstData = new_data;
        read_len = read(client->clientfd, client->clientFirstData + client->clientFirstDataLen, BUFFER_SIZE);
        /* 判断是否关闭连接 */
        if (read_len <= 0) {
            return 1;
        }
        client->clientFirstDataLen += read_len;
        client->clientFirstData[client->clientFirstDataLen] = '\0';
    } while (is_http_request(client->clientFirstData) && strstr(client->clientFirstData, "\n\r\n") == NULL);
   
   return 0;
}

int forwardData(int fromfd, int tofd, char *buff) {
    int read_len;
    
    do {
        read_len = recv(fromfd, buff, BUFFER_SIZE, MSG_DONTWAIT);
        /* 判断是否关闭连接 */
        if (read_len <= 0) {
            if (read_len == 0 || errno != EAGAIN)
                return 1;
            return 0;
        }
        if (write(tofd, buff, read_len) != read_len)
            return 1;
    } while (read_len == BUFFER_SIZE);
    
    return 0;
}

void *new_connection(void *ptr) {
    char buff[BUFFER_SIZE];
    struct pollfd pfds[2];
    struct clientConn *client;
    
    client = (struct clientConn *)ptr;
    client->clientFirstData = NULL;
    client->clientFirstDataLen = 0;
    if (read_first_data(client) == 0 && (client->serverfd = match_acl_get_serverfd(client)) > -1 && write(client->serverfd, client->clientFirstData, client->clientFirstDataLen) == client->clientFirstDataLen) {
        pfds[0].fd = client->clientfd;
        pfds[1].fd = client->serverfd;
        pfds[0].events = pfds[1].events = POLLIN;
        while (poll(pfds, 2, client->timeout_seconds) > 0) {
            if (pfds[0].revents & POLLIN) {
                if (forwardData(client->clientfd, client->serverfd, buff) != 0)
                    break;
            }
            if (pfds[1].revents & POLLIN) {
                if (forwardData(client->serverfd, client->clientfd, buff) != 0)
                    break;
            }
        }
    }

    close(client->clientfd);
    close(client->serverfd);
    free(client->clientFirstData);
    free(client);
    return NULL;
}

void server_start() {
    struct clientConn *client;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    pthread_t th_id;
    pthread_attr_t attr;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (1) {
        client = (struct clientConn *)malloc(sizeof(struct clientConn));
        if (client == NULL)
            continue;
        client->serverfd = -1;
        wait_new_connection:
        client->clientfd = accept(listenFd, (struct sockaddr *)&client->srcAddr, &addr_len);
        if (client->clientfd < 0) {
            perror("accept()");
            sleep(3);
            goto wait_new_connection;
        }
        getsockopt(client->clientfd, SOL_IP, SO_ORIGINAL_DST, &client->dstAddr, &addr_len);
        pthread_create(&th_id, &attr, &new_connection, (void *)client);
    }
}

int create_listen(char *ip, int port) {
    struct sockaddr_in addr;
    int optval = 1;
    int fd;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_family = AF_INET;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt()");
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind()");
        close(fd);
        return -1;
    }
    if (listen(fd, 500) != 0) {
        perror("listen()");
        close(fd);
        return -1;
    }
    
    return fd;
}

void initializate(int argc, char **argv) {
    int opt;
    
    listenFd = -1;
    worker_proc = 1;
    globalTimeout = DEFAULT_TIMEOUT;
    pid_path = NULL;
    memset(&defDstAddr, 0, sizeof(struct sockaddr_in));
    while ((opt = getopt(argc, argv, "c:vh")) != -1) {
        switch (opt) {
            case 'c':
                if (readConfig(optarg) != 0)
                    exit(1);
            break;
            
            case 'v':
                puts(VERSION_MSG);
            exit(0);
            
            case 'h':
                usage();
            exit(0);
            
            default:
                usage();
            exit(1);
        }
    }
    if (listenFd == -1) {
        fputs("error: no listen address\n", stderr);
        exit(1);
    }
    signal(SIGPIPE, SIG_IGN);
    while (worker_proc-- > 1 && fork() == 0);
    if (pid_path) {
        FILE *fp;
        if ((fp = fopen(pid_path, "a")) == NULL && (fp = fopen(pid_path, "w")) == NULL) {
            perror("fopen()");
            exit(1);
        } else {
            fprintf(fp, "%d ", getpid());
            fclose(fp);
        }
    }
}

int main(int argc, char **argv)
{
    initializate(argc, argv);
    if (daemon(1, 1)) {
        perror("daemon");
        return 1;
    }
    server_start();
    
    return 0;
}

