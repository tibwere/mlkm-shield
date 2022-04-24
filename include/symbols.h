#ifndef __H_MLKM_SHIELD_SYMBOLS__
#define __H_MLKM_SHIELD_SYMBOLS__


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


#endif // !__H_MLKM_SHIELD_SYMBOLS__
