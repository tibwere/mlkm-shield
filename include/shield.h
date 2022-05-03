/**
 * @file shield.h
 * @brief header file for the removal stuffs (@see ${basedir}/src/shield.c)
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
#ifndef _MLKM_SHIELD_SHIELD_H
#define _MLKM_SHIELD_SHIELD_H

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include "symbols.h"


/**
 * monitored_module - structure containing some relevant metadata
 * for the management of the monitored modules
 * (e.g. list of probes linked to functions)
 *
 * @member module:         reference to the structure module
 * @member under_analysis: true if someone has started analysis, false otherwise
 * @member links:          members for managing the linked list
 * @member probes:         list of probes linked to the functions defined in the module
 */
struct monitored_module {
        struct module *module;
        bool under_analysis;
        struct list_head links;
        struct list_head probes;
};


/**
 * module_probe - structure used to manage the list of probes
 * attached to each function
 *
 * @member owner: reference to the module structure in which the function
 *               to which the probe has been applied is defined
 * @member probe: kretprobe structure
 * @member links: members for managing the linked list
 */
struct module_probe {
        struct monitored_module *owner;
        struct kretprobe probe;
        struct list_head links;
};


/* Variables declaration */
extern struct list_head monitored_modules_list;
extern free_module_t free_module;
extern int removed;


/* Prototypes */
inline void remove_module_from_list(struct monitored_module *mm);
inline void remove_malicious_lkm(struct monitored_module *the_module);

#endif // !_MLKM_SHIELD_SHIELD_H
