#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tcpForward.h"
#include "acl.h"

void string_pretreatment(char *str) {
    char *p;
    
    for (p = strstr(str, "\\r"); p; p = strstr(p, "\\r")) {
        *p = '\r';
        memmove(p+1, p+2, strlen(p+2));
    }
    for (p = strstr(str, "\\n"); p; p = strstr(p, "\\n")) {
        *p = '\n';
        memmove(p+1, p+2, strlen(p+2));
    }
    for (p = strstr(str, "\\v"); p; p = strstr(p, "\\v")) {
        *p = '\v';
        memmove(p+1, p+2, strlen(p+2));
    }
    for (p = strstr(str, "\\f"); p; p = strstr(p, "\\f")) {
        *p = '\f';
        memmove(p+1, p+2, strlen(p+2));
    }
    for (p = strstr(str, "\\b"); p; p = strstr(p, "\\b")) {
        *p = '\b';
        memmove(p+1, p+2, strlen(p+2));
    }
    for (p = strstr(str, "\\t"); p; p = strstr(p, "\\t")) {
        *p = '\t';
        memmove(p+1, p+2, strlen(p+2));
    }
    for (p = strstr(str, "\\a"); p; p = strstr(p, "\\a")) {
        *p = '\a';
        memmove(p+1, p+2, strlen(p+2));
    }
}

char *skipBlank(char *str) {
    while (*str == ' ' || *str == '\t' || *str == '\r' || *str == '\n')
        str++;
    if (*str == '\0')
        return NULL;
    return str;
}

static int addAcl(char *line, acl_module_t *acl) {
    struct acl_child *aclChi;
    char *key, *value, *p;
    
    value = strchr(line, '=');
    if (!value)
        goto error;
    if (!strncasecmp(line, "destAddr", 8)) {
        char *ip, *port;

        if ((ip = skipBlank(value+1)) == NULL || (port = strchr(ip, ':')) == NULL)
            goto error;
        *port++ = '\0';
        acl->dstAddr.sin_addr.s_addr = inet_addr(ip);
        acl->dstAddr.sin_port = htons(atoi(port));
        acl->dstAddr.sin_family = AF_INET;
    } else if (!strncasecmp(line, "timeout", 7)) {
        if ((value = skipBlank(value+1)) == NULL)
            goto error;
        acl->timeout_seconds = atoi(value) * 1000;
    } else {
        aclChi = (struct acl_child *)calloc(sizeof(struct acl_child), 1);
        if (!aclChi) {
            perror("calloc()");
            return 1;
        }
        aclChi->next = acl->acl_child_list;
        acl->acl_child_list = aclChi;
        if (!strncasecmp(line, "match_all:", 10)) {
            if ((line = skipBlank(line+10)) == NULL)
                goto error;
            aclChi->match_all = 1;
        }
        if (*(value-1) == '!')
            aclChi->negation = 1;
        if ((value = skipBlank(value+1)) == NULL)
            goto error;
        if (!strncasecmp(line, "hdr(", 4)) {
            key = line + 4;
            p = strchr(key, ')');
            if (!p)
                goto error;
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
                case 'm':
                    aclChi->method = strdup(value);
                    if (!aclChi->method)
                        goto error;
                    aclChi->type = METHOD;
                break;
                
                case 's':
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
        } else {
            goto error;
        }
    }
    
    return 0;
    error:
    fprintf(stderr, "error line: [%s]\n", line);
    return 1;
}

static int readGlobal(char *line) {
    char *value;
    
    value = strchr(line, '=');
    if (!value || (value = skipBlank(value+1)) == NULL)
        goto error;
    if (!strncasecmp(line, "listen", 6)) {
        char *port;
        if ((port = strchr(value, ':')) == NULL)
            goto error;
        *port++ = '\0';
        listenFd = create_listen(value, atoi(port));
        if (listenFd < 0)
            return 1;
    } else if (!strncasecmp(line, "destAddr", 8)) {
        char *port;
        if ((port = strchr(value, ':')) == NULL)
            goto error;
        *port++ = '\0';
        defDstAddr.sin_addr.s_addr = inet_addr(value);
        defDstAddr.sin_port = htons(atoi(port));
        defDstAddr.sin_family = AF_INET;
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
            goto error;
        }
    } else if (!strncasecmp(line, "procs", 5)) {
        worker_proc = atoi(value);
    } else if (!strncasecmp(line, "timeout", 7)) {
        globalTimeout = atoi(value) * 1000;
    } else {
        goto error;
    }
    
    return 0;
    error:
    fprintf(stderr, "error line: [%s]\n", line);
    return 1;
}

static int readArea(char *content, acl_module_t *acl) {
    char *lineBegin, *lineEnd = NULL;
    
    for (lineBegin = strchr(content, '\n'); lineBegin; lineBegin = lineEnd) {
        if ((lineBegin = skipBlank(lineBegin)) == NULL)
            return 1;
        else if (strncmp(lineBegin, "//", 2) == 0)
        {
            lineEnd = strchr(lineBegin, '\n');
            continue;
        }
        else if (*lineBegin == '}')
            return 0;
        if ((lineEnd = strchr(lineBegin, '\n')) != NULL)
            *lineEnd++ = '\0';  //  ++指向下一行
        if (acl == NULL) {
            if (readGlobal(lineBegin) != 0)
                return 0;
        } else if (addAcl(lineBegin, acl) != 0) {
            return 1;
        }
    }
    
    return 0;
}

static int parseConfig(char *buff) {
    acl_module_t *acl;
    char *p, *p0;
    int firstRead;
    
    firstRead = 1;
    acl = NULL;
    for (p = buff; ; p = p0 + 1) {
        while (*p != '\0' && *p != '{')
            p++;
        if (*p == '\0')
            return 0;
        if ((p0 = strchr(++p, '}')) == NULL)
            return 1;
        if (firstRead == 0) {
            acl = (acl_module_t *)calloc(sizeof(acl_module_t), 1);
            if (!acl) {
                perror("calloc()");
                return 1;
            }
            acl->next = acl_list;
            acl_list = acl;
            acl->timeout_seconds = -1;
        } else {
            firstRead = 0;
        }
        if (readArea(p, acl) != 0)
            return 1;
    }
    
    return 0;
}

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
