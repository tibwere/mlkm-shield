/**
 * @file hooks.h
 * @brief header file for hooks stuffs (@see ${basedir}/src/hooks.c)
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
#ifndef _MLKM_SHIELD_HOOKS_H
#define _MLKM_SHIELD_HOOKS_H

#include "shield.h"


/**
 * post_do_init_module_activities - enumeration of possibile activities
 * to do after do_init_module is executed.
 *
 * - REMOVE_MODULE:           the module must be removed invoking on it
 *                            free_module function
 * - REMOVE_MONITORED_MODULE: the monitored_module must be removed invoking on
 *                            it remove_malicious_lkm function
 * - DONT_REMOVE:             a kretprobe is attached to each function inside
 *                            the module
 */
enum post_do_init_module_activities {
        REMOVE_MONITORED_MODULE,
        REMOVE_MODULE,
        DONT_REMOVE,
};


/**
 * krp_do_init_module_data - this structure allows to pass information from
 * pre-handler to post-handler of do_init_module. Depending on what_to_do field
 * the union field take a different semantic.
 *
 * @member remove_anyway: true if the module is in the black list
 * @member union:         module or monitored_module pointer
 */
struct krp_do_init_module_data {
        enum post_do_init_module_activities what_to_do;
        union {
                struct module *module;
                struct monitored_module *monitored_module;
        };
};


/* Variables declaration */
extern struct kretprobe do_init_module_kretprobe;
extern struct kprobe free_module_kprobe;


/* Prototypes */
bool attach_kretprobe_on_each_symbol(struct monitored_module *mm);
void remove_probes_from(struct monitored_module *mm);

#endif // !_MLKM_SHIELD_HOOKS_H
