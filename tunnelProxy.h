#ifndef TUNNEL_PROXY_H
#define TUNNEL_PROXY_H

#include "tcpForward.h"
#include "acl.h"

extern int create_tunnel(struct clientConn *client, acl_module_t *acl);

#endif