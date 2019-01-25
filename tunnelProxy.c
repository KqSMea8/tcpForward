#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "tcpForward.h"
#include "acl.h"

#define CONNECT_REQUEST "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nUser-Agent: tcpForward_CuteBi\r\n\r\n"

int create_tunnel(struct clientConn *client, acl_module_t *acl) {
    char rsp[512 + 1], req[sizeof(CONNECT_REQUEST) + 16 + 16 +1], *p;
    int len;

    len = snprintf(req, 512, CONNECT_REQUEST, inet_ntoa(client->dstAddr.sin_addr), ntohs(client->dstAddr.sin_port), inet_ntoa(client->dstAddr.sin_addr), ntohs(client->dstAddr.sin_port));
    if (write_data(client->serverfd, req, len, acl) != 0)
        return 1;
    while (1) {
        len = read(client->serverfd, rsp, 512);
        if (len <= 0)
            return 1;
        rsp[len] = '\0';
        /* 接收CONNECT回应 */
        p = strstr(rsp, "\n\r\n");
        if (p) {
            if (p + 3 - rsp < len && write_data(client->clientfd, p + 3, len - (p + 3 - rsp), acl) != 0)
                return 1;
            return 0;
        }
    }
}