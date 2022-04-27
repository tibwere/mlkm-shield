/**
 * @file threats.h
 * @brief header file for the IPI synchronization lookup stuffs (@see ${basedir}/src/threats.c)
 *
 * mlkm_shield - Taking advantage of the k[ret]probing mechanism offered by the Linux kernel,
 * several internal kernel functions are hooked (e.g. do_init_module, free_module) in order
 * to verify the behavior of the LKMs.
 *
 * If these modify some memory areas judged 'critical' (e.g. sys_call_table, IDT) we proceed
 * with the revert of the changes and with the disassembly of the module
 *
 * @author Simone Tiberi
 */
#ifndef _MLKM_SHIELD_THREATS_H
#define _MLKM_SHIELD_THREATS_H

#include <linux/module.h>
#include "safemem.h"


/**
 * abbreviated name length of the module
 * for printing to /sys
 */
#define SHORT_NAME_LEN (24)


/**
 * threat - structure containing all the information necessary
 * for the audit on /sys relating to an identified threat
 *
 * @member short_name: abbreviated name
 * @member address:    hacked address
 * @member saved:      good value for the address
 * @member hacked:     hacked value for the address
 * @member links:      field dedicated to the linked list mechanism
 */
struct threat {
        char short_name[SHORT_NAME_LEN];
        unsigned long address;
        unsigned long saved;
        unsigned long hacked;
        struct list_head links;
};


/**
 * work_metadata - structure to pass to the kworker
 */
struct work_metadata {
        struct threat *t;
        struct work_struct the_work;
};


/**
 * Stuff for fancy audit on /sys
 */
#define ROW_LEN (91)
#define HDR_FMT "| %-24s | %-18s | %-18s | %-18s |\n"
#define ROW_FMT "| %-24s | %#018lx | %#018lx | %#018lx |\n"


/* Variables declaration */
extern struct kobject *mlkm_shield_sys_kobj;


/* Prototypes */
int  init_threats_for_sys_audit(void);
void destroy_threats_for_sys_audit(void);
int  insert_new_threat(struct module *malicious_lkm, struct safe_area *sa, unsigned long hacked);

#endif // !_MLKM_SHIELD_THREATS_H
