#include <string.h>
#include <stdlib.h>
#include "acl.h"
#include "conf.h"
#include "tunnelProxy.h"
#include "tcpForward.h"

struct http_request {
    char *method, *uri, *url, *headerEnd, headerEndCharacter;
};

acl_module_t *acl_list = NULL, *firstMatch_acl_list = NULL;

/* 匹配src_ip和dst_ip语法 */
static int match_ip(struct sockaddr_in *addr_p, struct acl_child *aclChi) {
    char *ip_ptr, *ip_reverse_ptr;
    int32_t ip_reverse;

    ip_reverse_ptr = (char *)&ip_reverse;
    ip_ptr = (char *)(addr_p) + 4;
    /* ip反过来储存才能正确匹配 */
    ip_reverse_ptr[0] = ip_ptr[3];
    ip_reverse_ptr[1] = ip_ptr[2];
    ip_reverse_ptr[2] = ip_ptr[1];
    ip_reverse_ptr[3] = ip_ptr[0];
    ip_reverse >>= 32 - aclChi->ip_bit_len;

    return ip_reverse != aclChi->ip;
}

/* 匹配hdr()语法 */
static int match_hdr(char *clientData, struct acl_child *aclChi, struct http_request *http_req, regmatch_t *pm) {
    char *lineBegin, *lineEnd, *value;
    int match_ret;

    *(http_req->headerEnd) = '\0';
    for (lineBegin = strchr(clientData, '\n'); lineBegin; lineBegin = strchr(lineBegin, '\n')) {
        lineBegin++;
        if (strncasecmp(aclChi->key, lineBegin, aclChi->key_len) == 0 && lineBegin[aclChi->key_len] == ':' && (value = skipBlank(lineBegin + aclChi->key_len + 1)) != NULL) {
            lineEnd = strchr(value, '\r');
            if (lineEnd)
                *lineEnd = '\0';
            match_ret = regexec(&aclChi->reg, value, 10, pm, 0);
            if (lineEnd)
                *lineEnd = '\r';
            if (match_ret == 0)
                return 0;
        }
    }
    *(http_req->headerEnd) = http_req->headerEndCharacter;

    return 1;
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
        http_req->uri = p ? p : "/";
    } else {
        http_req->uri = http_req->url;
    }

    *http_req->headerEnd = http_req->headerEndCharacter;
    return 0;
}

acl_module_t *first_match_acl_module(struct clientConn *client, acl_module_t *acl_start, int match_count) {
    acl_module_t *acl;
    struct acl_child *acl_child;
    int match_ret;

    match_ret = 1;  //1为匹配失败，0为匹配成功
    for (acl = acl_start; acl && (match_count < 0 || match_count-- > 0); acl = acl->next) {
        for (acl_child = acl->acl_child_list; acl_child; acl_child = acl_child->next) {
            switch (acl_child->type) {
                case DST_PORT:
match_ret = (acl_child->dstPort_max - acl_child->dstPort_min <= ntohs(client->dstAddr.sin_port) - acl_child->dstPort_min);
                break;

                case SRC_IP:
                    match_ret = match_ip(&client->srcAddr, acl_child);
                break;

                case DST_IP:
                    match_ret = match_ip(&client->dstAddr, acl_child);
                break;
                
                case INCLUDE_MODULE:
                    //使用递归函数，默认返回值为NULL，即没有成功匹配
                    match_ret = (first_match_acl_module(client, (acl_module_t *)acl_child->includeModule_acl, 1) == NULL);
                break;

                default:
                break;
            }
            if ((match_ret == 0 && acl_child->negation == 0) || (match_ret != 0 && acl_child->negation == 1)) {
                if (acl_child->match_all == 0) {
                    return acl;
                }
            } else if (acl_child->match_all) {
                break;
            }
        }
    }

    return NULL;
}

/* 返回匹配成功的acl_module_t结构体，match_count为匹配次数(小于0无限次匹配) */
acl_module_t *match_acl_module(struct clientConn *client, acl_module_t *acl_start, int match_count) {
    regmatch_t pm[10];
    struct http_request http_req;
    acl_module_t *acl_module, *match_acl_ptr;
    struct acl_child *acl_child;
    int is_http_req, match_ret;

    match_ret = 1;  //1为匹配失败，0为匹配成功
    match_acl_ptr = &globalAcl;  //默认使用global配置
    is_http_req = is_http_request(client->clientFirstData);
    if (is_http_req && http_request_header(client->clientFirstData, &http_req) != 0)
        return match_acl_ptr;
    for (acl_module = acl_start; \
        acl_module &&
        (match_count < 0 || match_count-- > 0) /* 匹配的次数 */ &&
        (acl_module->only_reMatch == 0 || client->serverfd > -1) /* 重新匹配规则的acl模块只有在serverfd大于-1时才匹配 */; \
        acl_module = acl_module->next) {
        for (acl_child = acl_module->acl_child_list; acl_child; acl_child = acl_child->next) {
            switch (acl_child->type) {
                case STRING:
                    match_ret = regexec(&acl_child->reg, client->clientFirstData, 10, pm, 0);
                break;

                case METHOD:
                    if (is_http_req)
                        match_ret = strcmp(http_req.method, acl_child->method);
                    else
                        match_ret = 1;
                break;

                case URI:
                    if (is_http_req)
                        match_ret = regexec(&acl_child->reg, http_req.uri, 10, pm, 0);
                    else
                        match_ret = 1;
                break;

                case URL:
                    if (is_http_req)
                        match_ret = regexec(&acl_child->reg, http_req.url, 10, pm, 0);
                    else
                        match_ret = 1;
                break;

                case HDR:
                    if (is_http_req)
                        match_ret = match_hdr(client->clientFirstData, acl_child, &http_req, pm);
                    else
                        match_ret = 1;
                break;

                case DST_PORT:
                    match_ret = (acl_child->dstPort_max - acl_child->dstPort_min <= ntohs(client->dstAddr.sin_port) - acl_child->dstPort_min);
                break;

                case SRC_IP:
                    match_ret = match_ip(&client->srcAddr, acl_child);
                break;

                case DST_IP:
                    match_ret = match_ip(&client->dstAddr, acl_child);
                break;
                
                case INCLUDE_MODULE:
                    //使用递归函数，默认返回值为&global，即没有成功匹配
                    match_ret = (match_acl_module(client, (acl_module_t *)acl_child->includeModule_acl, 1) == &globalAcl);
                break;
            }
            if ((match_ret == 0 && acl_child->negation == 0) || (match_ret != 0 && acl_child->negation == 1)) {
                if (acl_child->match_all == 0) {
                    match_acl_ptr = acl_module;
                    goto matchEnd;
                }
            } else if (acl_child->match_all) {
                break;
            }
        }
    }

    matchEnd:
    if (is_http_req) {
        free(http_req.method);
        free(http_req.url);
    }
    return match_acl_ptr;
}

/* 创建连接后重新匹配规则 */
acl_module_t *reMatchAcl(struct clientConn *client, acl_module_t *matchAcl) {
    //创建连接后再次匹配客户端数据
    while (matchAcl->reMatch_acl) {
        //如果没有读取客户端数据就已经创建连接了，先读取客户端数据
        if (client->clientFirstData == NULL && read_first_data(client) != 0)
            return NULL;
        if (match_acl_module(client, matchAcl->reMatch_acl, 1) == matchAcl->reMatch_acl) {
            matchAcl = matchAcl->reMatch_acl;  //使用重新匹配成功的模块的配置
            close(client->serverfd);
            if ((client->serverfd = connectToDestAddr(&matchAcl->dstAddr, &client->dstAddr, matchAcl->timeout_ms)) == -1)
                return NULL;
            if (matchAcl->tunnel_proxy && create_tunnel(client, matchAcl) != 0)
                return NULL;
        } else {
            //没有匹配到，跳出循环
            break;
        }
    }
    
    return matchAcl;
}