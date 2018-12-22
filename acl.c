#include <string.h>
#include <stdlib.h>
#include "acl.h"
#include "conf.h"
#include "tcpForward.h"

struct http_request {
    char *method, *uri, *url, *headerEnd, headerEndCharacter;
};

acl_module_t *acl_list = NULL;

void free_http_request(struct http_request *http_req) {
    free(http_req->method);
    free(http_req->url);
}

/* 处理http请求头 */
static int http_request_header(char *request, struct http_request *http_req) {
    char *p;

    memset(http_req, 0, sizeof(struct http_request));
    /* 分离请求头和请求数据 */
    if ((http_req->headerEnd = strstr(request, "\n\r\n")) != NULL) {
        http_req->headerEnd += 3;
        http_req->headerEndCharacter = *http_req->headerEnd;
        *http_req->headerEnd = '\0';
    } else {
        return 1;
    }
    /*获取method url version*/
    p = strchr(request, ' ');
    if (!p)
        return 1;
    http_req->method = strndup(request, p - request);
    char *cr = strchr(++p, '\r'); //http版本后的\r
    if (cr)
        http_req->url = strndup(p, cr - p - 9);
    if (!http_req->url)
        return 1;

    if (*http_req->url != '/' && (p = strstr(http_req->url, "//")) != NULL) {
        p = strchr(p+2, '/');
        if (p)
            http_req->uri = p;
        else
            http_req->uri = "/";
    } else {
        http_req->uri = http_req->url;
        //有些url是//开头
        while (*(http_req->uri+1) == '/')
            http_req->uri++;
    }

    *http_req->headerEnd = http_req->headerEndCharacter;
    return 0;
}

int match_acl_get_serverfd(struct clientConn *client) {
    regmatch_t pm[10];
    struct http_request http_req;
    acl_module_t *acl;
    struct acl_child *acl_child;
    struct sockaddr_in *dstAddrPtr;
    char *lineBegin, *lineEnd, *value;  //  type == HDR
    char *ip_ptr, *ip_reverse_ptr;
    int32_t ip_reverse;
    int is_http_req, match_ret;
    
    match_ret = 1;
    ip_reverse_ptr = (char *)&ip_reverse;
    dstAddrPtr = &defDstAddr;
    client->timeout_seconds = globalTimeout;
    is_http_req = is_http_request(client->clientFirstData);
    if (is_http_req && http_request_header(client->clientFirstData, &http_req) != 0)
        return -1;
    for (acl = acl_list; acl; acl = acl->next) {
        for (acl_child = acl->acl_child_list; acl_child; acl_child = acl_child->next) {
            switch (acl_child->type) {
                case STRING:
                    match_ret = regexec(&acl_child->reg, client->clientFirstData, 10, pm, 0);
                break;
                
                case METHOD:
                    if (is_http_req)
                        match_ret = strcmp(http_req.method, acl_child->method);
                break;
                
                case URI:
                    if (is_http_req)
                        match_ret = regexec(&acl_child->reg, http_req.uri, 10, pm, 0);
                break;
                
                case URL:
                    if (is_http_req)
                        match_ret = regexec(&acl_child->reg, http_req.url, 10, pm, 0);
                break;
                
                case HDR:
                    if (is_http_req) {
                        *(http_req.headerEnd) = '\0';
                        for (lineBegin = strchr(client->clientFirstData, '\n'); lineBegin; lineBegin = strchr(lineBegin, '\n')) {
                            lineBegin++;
                            if (strncasecmp(acl_child->key, lineBegin, acl_child->key_len) == 0 && lineBegin[acl_child->key_len] == ':' && (value = skipBlank(lineBegin + acl_child->key_len + 1)) != NULL) {;
                                lineEnd = strchr(value, '\r');
                                if (lineEnd)
                                    *lineEnd = '\0';
                                match_ret = regexec(&acl_child->reg, value, 10, pm, 0);
                                if (lineEnd)
                                    *lineEnd = '\r';
                                if (match_ret == 0)
                                    break;
                            }
                        }
                        *(http_req.headerEnd) = http_req.headerEndCharacter;
                    }
                break;
                
                //case SRC_IP:
                //case DST_IP:
                default:
                    if (acl_child->type == SRC_IP)
                        ip_ptr = ((char *)&client->srcAddr)+4;
                    else
                        ip_ptr = ((char *)&client->dstAddr)+4;
                    ip_reverse_ptr[0] = ip_ptr[3];
                    ip_reverse_ptr[1] = ip_ptr[2];
                    ip_reverse_ptr[2] = ip_ptr[1];
                    ip_reverse_ptr[3] = ip_ptr[0];
                    ip_reverse >>= 32 - acl_child->ip_bit_len;
                    match_ret = ip_reverse != acl_child->ip;
                break;
            }
            if ((match_ret == 0 && acl_child->negation == 0) || (match_ret != 0 && acl_child->negation == 1)) {
                if (acl_child->match_all == 0) {
                    client->timeout_seconds = acl->timeout_seconds;
                    dstAddrPtr = &acl->dstAddr;
                    goto matchEnd;
                }
            } else if (acl_child->match_all) {
                break;
            }
        }
    }
    
    matchEnd:
    if (is_http_req) {
        free_http_request(&http_req);
    }
    //设置0开头的转发ip使用原始目标地址
    if (*(((char *)dstAddrPtr)+4) == 0)
        return connectionToDestAddr(&client->dstAddr);
    return connectionToDestAddr(dstAddrPtr);
}