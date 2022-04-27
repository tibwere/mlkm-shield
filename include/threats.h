#ifndef _MLKM_SHIELD_THREATS_H
#define _MLKM_SHIELD_THREATS_H

#include <linux/module.h>
#include "safemem.h"

#define SHORT_NAME_LEN (24)

struct threat {
        char short_name[SHORT_NAME_LEN];
        unsigned long address;
        unsigned long saved;
        unsigned long hacked;
        struct list_head links;
};

struct work_metadata {
        struct threat *t;
        struct work_struct the_work;
};

#define ROW_LEN (91)
#define HDR_FMT "| %-24s | %-18s | %-18s | %-18s |\n"
#define ROW_FMT "| %-24s | %#018lx | %#018lx | %#018lx |\n"


extern struct kobject *mlkm_shield_sys_kobj;


int  init_threats_for_sys_audit(void);
void destroy_threats_for_sys_audit(void);
int  insert_new_threat(struct module *malicious_lkm, struct safe_area *sa, unsigned long hacked);

#endif // !_MLKM_SHIELD_THREATS_H
