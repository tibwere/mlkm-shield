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
 * kretprobe_private_data_fn - the structure is used to pass data from
 * the pre to the post handler of a kretprobe. Using the boolean variable
 * contained within in combination with the under_analysis member of the
 * monitored_module structure, it is possible to prevent nested analyzes
 * from starting
 *
 * @member do_verification: true if the function is the outermost,
 *                         false if it is invoked by another that is
 *                         already part of a test
 */
struct kretprobe_private_data_fn {
        bool do_verification;
};


/**
 * kretprobe_private_data_ins - this structure allows the realization of
 * the forced disassembly mechanism of a module present in the blacklist
 * as soon as the do_init_mount function ends (the init function of the
 * module is previously modified to point to a dummy).
 *
 * @member remove_anyway:        true if the module is in the black list
 * @member module_to_be_removed: pointer to module to be removed
 */
struct kretprobe_private_data_ins {
        bool remove_anyway;
        struct module *module_to_be_removed;
};


/* Variables declaration */
extern struct kretprobe do_init_module_kretprobe;
extern struct kprobe free_module_kprobe;


/* Prototypes */
int  attach_kretprobe_on_each_symbol(void);
void remove_probes_from(struct monitored_module *mm);

#endif // !_MLKM_SHIELD_HOOKS_H
