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
#include "limitSpeed.h"
#include "conf.h"

#define VERSION_MSG "tcp Forward(2.0):\nAuthor: CuteBi\nE-mail: 915445800@qq.com\n"
#define BUFFER_SIZE 4096
#define DEFAULT_THREAD_POOL_SIZE 30


struct sockaddr_in defDstAddr;
static struct clientConn publicConn;  //主线程设置该变量，子线程复制
static pthread_mutex_t thMutex;
static pthread_cond_t thCond;
static int *thPool_isBusy;  //线程执行繁忙值为1，空闲值为0
char *pid_path;
int listenFd, worker_proc, thread_pool_size, isUseLimitSpeed /* 判断是否使用限制网速功能 */;
acl_module_t globalAcl;

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

static int forwardData(int fromfd, int tofd, char *buff, acl_module_t *matchAcl) {
    int read_len;
    
    do {
        //达到最大流量，关闭连接
        if (matchAcl->isUseLimitMaxData && matchAcl->maxDataSize < BUFFER_SIZE)
           return 1;
        if (matchAcl->maxSpeed)
           //达到最大网速，暂停1秒再继续
            while (matchAcl->sentDataSize + BUFFER_SIZE > matchAcl->maxSpeed)
                sleep(1);
        read_len = recv(fromfd, buff, BUFFER_SIZE, MSG_DONTWAIT);
        /* 判断是否关闭连接 */
        if (read_len <= 0) {
            if (read_len == 0 || errno != EAGAIN)
                return 1;
            return 0;
        }
        if (write(tofd, buff, read_len) != read_len)
            return 1;
        matchAcl->sentDataSize += read_len;
        matchAcl->maxDataSize -= read_len;
    } while (read_len == BUFFER_SIZE);
    
    return 0;
}

void *new_connection(void *nullPtr) {
    char buff[BUFFER_SIZE];
    struct pollfd pfds[2];
    struct clientConn client;
    acl_module_t *matchAcl;
    
    memcpy(&client, &publicConn, sizeof(struct clientConn));
    publicConn.clientfd = -1;  //表示已复制数据，可以接收新客户端了
    if (read_first_data(&client) == 0 && match_acl_setServer(&client, &matchAcl) == 0) {
        if ((matchAcl->isUseLimitMaxData && matchAcl->maxDataSize >= client.clientFirstDataLen) || matchAcl->isUseLimitMaxData == 0) {
            /* 发送第一次读取到的数据 */
            if (matchAcl->maxSpeed)
               //达到最大网速，暂停1秒再继续
                while (matchAcl->sentDataSize + client.clientFirstDataLen > matchAcl->maxSpeed)
                    sleep(1);
            if (write(client.serverfd, client.clientFirstData, client.clientFirstDataLen) == client.clientFirstDataLen) {
                /* 开始转发数据 */
                pfds[0].fd = client.clientfd;
                pfds[1].fd = client.serverfd;
                pfds[0].events = pfds[1].events = POLLIN;
                while (poll(pfds, 2, matchAcl->timeout_seconds) > 0) {
                    if (pfds[0].revents & POLLIN) {
                        if (forwardData(client.clientfd, client.serverfd, buff, matchAcl) != 0)
                            break;
                    }
                    if (pfds[1].revents & POLLIN) {
                        if (forwardData(client.serverfd, client.clientfd, buff, matchAcl) != 0)
                            break;
                    }
                }
            }
        }
    }

    close(client.clientfd);
    close(client.serverfd);
    free(client.clientFirstData);
    return NULL;
}

static int accept_client() {
    static socklen_t addr_len = sizeof(struct sockaddr_in);
    
    publicConn.clientfd = accept(listenFd, (struct sockaddr *)&publicConn.srcAddr, &addr_len);
    if (publicConn.clientfd < 0) {
        perror("accept()");
        return 1;
    }
    getsockopt(publicConn.clientfd, SOL_IP, SO_ORIGINAL_DST, &publicConn.dstAddr, &addr_len);
    
    return 0;
}

void *pool_wait_task(void *intPtr) {
    int *isBusy;

    isBusy = (int *)intPtr;
    while (1) {
        pthread_cond_wait(&thCond, &thMutex);
        pthread_mutex_unlock(&thMutex);  //解锁让其他线程并发
        *isBusy = 1;
        new_connection(NULL);
        *isBusy = 0;
    }

    return NULL;
}

void server_start() {
    pthread_t th_id;
    pthread_attr_t attr;
    int i;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (isUseLimitSpeed)
        pthread_create(&th_id, &attr, &speedReset, NULL);
    /* 创建线程池 */
    thPool_isBusy = (int *)calloc(thread_pool_size, sizeof(int));
    if (!thPool_isBusy) {
        perror("calloc()");
        return;
    }
    pthread_mutex_init(&thMutex, NULL);
    pthread_cond_init(&thCond, NULL);
    for (i = 0; i < thread_pool_size; i++) {
        pthread_create(&th_id, &attr, &pool_wait_task, (void *)(thPool_isBusy + i));
    }
    /* 开始监控新客户端 */
    while (1) {
        if (accept_client() != 0) {
            sleep(3);
            continue;
        }
        //线程池中有空闲线程则运行线程池中的线程
        for (i = 0; i < thread_pool_size; i++) {
            if (thPool_isBusy[i] == 0) {
                pthread_cond_signal(&thCond);
                break;
            }
        }
        /* 线程池中无空闲线程，创建新线程处理 */
        if (i == thread_pool_size) {
            if (pthread_create(&th_id, &attr, &new_connection, NULL) != 0) {
                close(publicConn.clientfd);
                continue;
            }
        }
        /* 等待处理线程复制数据 */
        int j = 0;
        do {
            usleep(10);  //暂停10微秒给线程复制数据的时间
            j++;
        } while (publicConn.clientfd != -1);
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

    isUseLimitSpeed = 0;
    listenFd = -1;
    worker_proc = 1;
    thread_pool_size = DEFAULT_THREAD_POOL_SIZE;
    pid_path = NULL;
    publicConn.serverfd = -1;
    publicConn.clientFirstData = NULL;
    publicConn.clientFirstDataLen = 0;
    memset(&globalAcl, 0, sizeof(acl_module_t));
    memset(&defDstAddr, 0, sizeof(struct sockaddr_in));
    globalAcl.maxDataSize = globalAcl.timeout_seconds = -1;  //默认-1，不限制流量，不超时
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
    #ifdef DEBUG
    if (daemon(1, 1)) {
    #else
    if (daemon(1, 0)) {
    #endif
        perror("daemon");
        return 1;
    }
    server_start();
    
    return 0;
}

