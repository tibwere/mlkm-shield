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
extern struct monitored_module *curr_module;
extern free_module_t free_module;


/* Prototypes */
inline void remove_module_from_list(struct monitored_module *mm);
inline void remove_malicious_lkm(struct monitored_module *the_module);

#endif // !_MLKM_SHIELD_SHIELD_H