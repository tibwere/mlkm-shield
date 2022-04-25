#ifndef _MLKM_SHIELD_SYMBOLS_H
#define _MLKM_SHIELD_SYMBOLS_H

#include <linux/module.h>

/**
 * kallsyms_lookup_name_t - prototype of the kallsyms_lookup_name function
 * (from kernel version 5.7 no longer exposed)
 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/**
 * free_module_t - prototype of the free_module function (not exposed)
 */
typedef void (*free_module_t)(struct module *mod);


/* Prototypes */
inline unsigned long symbol_lookup(const char *name);
unsigned long *      get_system_call_table_address(void);


#endif // !_MLKM_SHIELD_SYMBOLS_H
