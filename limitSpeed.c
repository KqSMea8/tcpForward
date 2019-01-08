#include "limitSpeed.h"

void *speedReset(void *nullPtr) {
    acl_module_t *acl_ptr;

    while (1) {
        globalAcl.sentDataSize = 0;
        for (acl_ptr = acl_list; acl_ptr; acl_ptr = acl_ptr->next)
            acl_ptr->sentDataSize = 0;
        sleep(1);
    }
}