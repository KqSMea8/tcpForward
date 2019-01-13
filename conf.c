#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tcpForward.h"
#include "acl.h"

/* 字符串预处理，设置转义字符 */
static void string_pretreatment(char *str) {
    char *p,
        *ori_strs[] = {"\\r", "\\n", "\\b", "\\v", "\\f", "\\t", "\\a", "\\b"},
        to_chrs[] = {'\r', '\n', '\b', '\v', '\f', '\t', '\a', '\b'};
    int i;

    for (i = 0; i < sizeof(to_chrs); i++) {
        for (p = strstr(str, ori_strs[i]); p; p = strstr(p, ori_strs[i])) {
            *p = to_chrs[i];
            memmove(p+1, p+2, strlen(p+2));
        }
    }
}

/* 跳过空白字符 */
char *skipBlank(char *str) {
    while (*str == ' ' || *str == '\t' || *str == '\r' || *str == '\n' || *str == '\v' || *str == '\f' || *str == '\a' || *str == '\b')
        str++;
    if (*str == '\0')
        return NULL;
    return str;
}

static acl_module_t *aclModule_lookup(char *module_name) {
    acl_module_t *acl_p;

    for (acl_p = firstMatch_acl_list; acl_p; acl_p = acl_p->next)
        if (!strcmp(module_name, acl_p->module_name))
            return acl_p;
    for (acl_p = acl_list; acl_p; acl_p = acl_p->next)
        if (!strcmp(module_name, acl_p->module_name))
            return acl_p;

    return NULL;
}

/* 字符串转换为网络传输单位 */
static long long strToNet(char *speedStr) {
    long long speed;

    speed = (unsigned long long)atoi(speedStr);
    switch (*(speedStr + strlen(speedStr) - 1)) {
        case 'k':
        case 'K':
            speed <<= 10;
        break;

        case 'g':
        case 'G':
            speed <<= 30;
        break;

        //默认单位为m
        default:
            speed <<= 20;
        break;
    }

    return speed;
}

/* 添加一条acl控制规则 */
static int addAcl(char *line, acl_module_t *acl) {
    struct acl_child *aclChi;
    char *key, *value, *p;

    value = strchr(line, '=');
    if (!value)
        goto file_error;
    if (!strncasecmp(line, "destAddr", 8)) {
        char *ip, *port;
        if ((ip = skipBlank(value+1)) == NULL || (port = strchr(ip, ':')) == NULL)
            goto file_error;
        *port++ = '\0';
        acl->dstAddr.sin_addr.s_addr = inet_addr(ip);
        acl->dstAddr.sin_port = htons(atoi(port));
        acl->dstAddr.sin_family = AF_INET;
    } else if (!strncasecmp(line, "matchMode", 9)) {
        if ((value = skipBlank(value+1)) == NULL)
            goto file_error;
        if (!strcasecmp(value, "firstMatch")) {
            acl_list = acl_list->next;
            acl->next = firstMatch_acl_list;
            firstMatch_acl_list = acl;
        } else if (!strcasecmp(value, "only_reMatch")) {
            acl->only_reMatch = 1;
        }
    } else if (!strncasecmp(line, "reMatch", 7)) {
        if ((value = skipBlank(value+1)) == NULL || (acl->reMatch_acl = aclModule_lookup(value)) == NULL)
            goto file_error;
    } else if (!strncasecmp(line, "timeout", 7)) {
        if ((value = skipBlank(value+1)) == NULL)
            goto file_error;
        acl->timeout_ms = atoi(value) * 1000;
    } else if (!strncasecmp(line, "maxData", 7)) {
        acl->isUseLimitMaxData = 1;
        acl->maxDataSize = strToNet(value);
    } else if (!strncasecmp(line, "maxSpeed", 8)) {
        isUseLimitSpeed = 1;
        acl->maxSpeed = strToNet(value);
    } else if (!strncasecmp(line, "tunnel_proxy", 11)) {
        if ((value = skipBlank(value+1)) == NULL)
            goto file_error;
        if (!strcasecmp(value, "on"))
            acl->tunnel_proxy = 1;
    } else {
        aclChi = (struct acl_child *)calloc(1, sizeof(struct acl_child));
        if (!aclChi) {
            perror("calloc()");
            return 1;
        }
        aclChi->next = acl->acl_child_list;
        acl->acl_child_list = aclChi;
        if (!strncasecmp(line, "match_all:", 10)) {
            if ((line = skipBlank(line+10)) == NULL)
                goto file_error;
            aclChi->match_all = 1;
        }
        if (*(value-1) == '!')
            aclChi->negation = 1;
        if ((value = skipBlank(value+1)) == NULL)
            goto file_error;
        if (!strncasecmp(line, "hdr(", 4)) {
            key = line + 4;
            p = strchr(key, ')');
            if (!p)
                goto file_error;
            *p = '\0';
            aclChi->key_len = p - key;
            aclChi->key = strndup(key, aclChi->key_len);
            if (!aclChi->key) {
                perror("strndup()");
                return 1;
            }
            regcomp(&aclChi->reg, value, REG_NEWLINE|REG_ICASE|REG_EXTENDED);
            aclChi->type = HDR;
        } else if (!strncasecmp(line, "ur", 2) || !strncasecmp(line, "method", 6) || !strncasecmp(line, "string", 6)) {
            switch (*line) {
                case 'm':  //mnethod
                    aclChi->method = strdup(value);
                    if (!aclChi->method)
                        goto file_error;
                    aclChi->type = METHOD;
                break;

                case 's':  //string
                    string_pretreatment(value);
                    aclChi->type = STRING;
                break;

                default:
                    *(line+2) == 'i' ? (aclChi->type = URI) : (aclChi->type = URL);
                break;
            }
            if (aclChi->type != METHOD) {
                regcomp(&aclChi->reg, value, REG_NEWLINE|REG_ICASE|REG_EXTENDED);
            }
        } else if (!strncasecmp(line, "src_ip", 6) || !strncasecmp(line, "dst_ip", 6)) {
            char *ip;
            int i;

            ip = (char *)&aclChi->ip;
            memset(ip, 0, sizeof(int32_t));
            for (p = value, i = 3; p && i >= 0; p = strchr(p, '.'), i--) {
                if (i != 3)
                    p++;
                ip[i] = (char)atoi(p);
            }
            if ((p = strchr(value, '/')) != NULL) {
                aclChi->ip_bit_len = atoi(p+1);
                aclChi->ip >>= 32 - aclChi->ip_bit_len;
            } else {
                aclChi->ip_bit_len = 32;
            }
            *line == 's' ? (aclChi->type = SRC_IP) : (aclChi->type = DST_IP);
        } else if (!strncasecmp(line, "dst_port", 8)) {
            aclChi->dstPort_min = (unsigned short)atoi(value);
            if ((p = strchr(value, ':')))
                aclChi->dstPort_max = (unsigned short)atoi(p+1);
            else
                aclChi->dstPort_max = aclChi->dstPort_min;
            aclChi->type = DST_PORT;
        } else if (!strncasecmp(line, "include_module", 14)) {
            if ((aclChi->includeModule_acl = (void *)aclModule_lookup(value)) == NULL)
                goto file_error;
            aclChi->type = INCLUDE_MODULE;
        } else {
            goto file_error;
        }
    }

    return 0;
    file_error:
    fprintf(stderr, "error line: [%s]\n", line);
    return 1;
}

/* 读取全局模块 */
static int parseGlobal(char *line) {
    char *value;

    value = strchr(line, '=');
    if (!value || (value = skipBlank(value+1)) == NULL)
        goto file_error;
    if (!strncasecmp(line, "listen", 6)) {
        char *port;
        if ((port = strchr(value, ':')) == NULL)
            goto file_error;
        *port++ = '\0';
        listenFd = create_listen(value, atoi(port));
        if (listenFd < 0)
            return 1;
    } else if (!strncasecmp(line, "destAddr", 8)) {
        char *port;
        if ((port = strchr(value, ':')) == NULL)
            goto file_error;
        *port++ = '\0';
        globalAcl.dstAddr.sin_addr.s_addr = inet_addr(value);
        globalAcl.dstAddr.sin_port = htons(atoi(port));
        globalAcl.dstAddr.sin_family = AF_INET;
    } else if (!strncasecmp(line, "pid_path", 8)) {
        pid_path = strdup(value);
        if (pid_path == NULL) {
            perror("strdup()");
            return 1;
        }
        remove(pid_path);
    } else if (!strncasecmp(line, "uid", 3)) {
        if (setgid(atoi(value)) || setuid(atoi(value))) {
            perror("setgid(or setuid)()");
            goto file_error;
        }
    } else if (!strncasecmp(line, "procs", 5)) {
        worker_proc = atoi(value);
    } else if (!addAcl(line, &globalAcl)) {
        return 1;
    } else {
        goto file_error;
    }

    return 0;
    file_error:
    fprintf(stderr, "error line: [%s]\n", line);
    return 1;
}

/* 读取模块中的一行，交给其他函数解析该行，执行正常返回处理内容的长度，失败返回-1 */
static int parseArea(char *content, acl_module_t *acl) {
    char *lineBegin = NULL, *lineEnd = NULL;

    for (lineBegin = strchr(content, '\n'); lineBegin; lineBegin = lineEnd) {
        if ((lineBegin = skipBlank(lineBegin)) == NULL)
            return -1;
        else if (strncmp(lineBegin, "//", 2) == 0)
        {
            lineEnd = strchr(lineBegin, '\n');
            continue;
        }
        else if (*lineBegin == '}')
            break;
        if ((lineEnd = strchr(lineBegin, '\n')) != NULL) {
            if (*(lineEnd - 1) == ';')  //;作为一行的结束字符
                *(lineEnd++ - 1) = '\0';  //指向下一行
            else
                *lineEnd++ = '\0';
        }
        if (acl == &globalAcl) {
            if (parseGlobal(lineBegin) != 0)
                break;
        } else if (addAcl(lineBegin, acl) != 0) {
            return -1;
        }
    }

    //处理正常返回处理内容的长度
    return lineEnd ? (lineEnd - content) : (lineBegin ? (lineBegin - content) : 0);
}

/* 解析配置文件，得到模块名和模块内容的开始位置，传给其他函数处理 */
static int parseConfig(char *buff) {
    acl_module_t *acl;
    char *moduleName, *moduleName_end, *module_start, *p;
    int handle_len;

    moduleName = buff;
    while ((module_start = strchr(moduleName, '{')) != NULL) {
        *module_start++ = '\0';
        if ((p = strrchr(moduleName, '\n')) != NULL && (p = skipBlank(p)) != NULL)
            moduleName = p;
        for (moduleName_end = moduleName+1; *moduleName_end != ' ' && *moduleName_end != '\t' && *moduleName_end != '\n' && *moduleName_end != '\r' && *moduleName_end != '\0'; moduleName_end++);
        if (*moduleName_end == '\0')
            return 0;
        if (!strncasecmp(moduleName, "global", 6)) {
            if ((handle_len = parseArea(module_start, &globalAcl)) == -1)
                return 1;
        } else {
            acl = (acl_module_t *)malloc(sizeof(acl_module_t));
            if (!acl) {
                perror("malloc()");
                return 1;
            }
            memcpy(acl, &globalAcl, sizeof(acl_module_t));
            acl->next = acl_list;
            acl_list = acl;
            acl->module_name = strndup(moduleName, moduleName_end - moduleName);
            if (!acl->module_name) {
                perror("strndup()");
                return 1;
            }
            if ((handle_len = parseArea(module_start, acl)) == -1)
                return 1;
        }
        moduleName = strchr(module_start + handle_len,'}');
        if (!moduleName)
            return 0;
        moduleName++;
    }

    return 0;
}

/* 读取配置文件并解析 */
int readConfig(char *path) {
    char *buff;
    FILE *file;
    long file_size;

    /* 读取配置文件到缓冲区 */
    file = fopen(path, "r");
    if (file == NULL) {
        fputs("cannot open config file\n", stderr);
        return 1;
    }
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    buff = (char *)alloca(file_size + 1);
    if (buff == NULL) {
        perror("alloca()");
        return 1;
    }
    rewind(file);
    fread(buff, file_size, 1, file);
    fclose(file);
    buff[file_size] = '\0';

    return parseConfig(buff);
}
