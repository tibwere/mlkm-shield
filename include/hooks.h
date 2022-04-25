#ifndef _MLKM_SHIELD_HOOKS_H
#define _MLKM_SHIELD_HOOKS_H

#include "shield.h"


/**
 * kretprobe_private_data - the structure is used to pass data from the
 * pre to the post handler of a kretprobe. Using the Boolean variable
 * contained within in combination with the under_analysis member of the
 * monitored_module structure, it is possible to prevent nested analyzes
 * from starting
 *
 * @member do_verification: true if the function is the outermost,
 *                         false if it is invoked by another that is
 *                         already part of a test
 */
struct kretprobe_private_data {
        bool do_verification;
};

/* Variables declaration */
extern struct kretprobe do_init_module_kretprobe;
extern struct kprobe free_module_kprobe;


/* Prototypes */
int  attach_kretprobe_on_each_symbol(void);
void remove_probes_from(struct monitored_module *mm);

#endif // !_MLKM_SHIELD_HOOKS_H
