/**
 * @file symbols.h
 * @brief header file for the symbol lookup stuffs (@see ${basedir}/src/symbols.c)
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
#ifndef _MLKM_SHIELD_SYMBOLS_H
#define _MLKM_SHIELD_SYMBOLS_H

#include <linux/module.h>


/**
 * Number of unsigned long inside an IDT
 */
#define IDT_ULONG_COUNT (IDT_ENTRIES * sizeof(gate_desc) / sizeof(unsigned long))


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
unsigned long *      get_idt_address(void);

#endif // !_MLKM_SHIELD_SYMBOLS_H
