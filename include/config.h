/**
 * @file config.h
 * @brief header file for configuration stuffs (@see ${basedir}/src/config.c)
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
#ifndef _MLKM_SHIELD_CONFIG_H
#define _MLKM_SHIELD_CONFIG_H

#include <linux/types.h>

/* Variables declaration */
extern const bool PROTECT_SYS_CALL_TABLE;
extern const bool PROTECT_IDT;
extern const char *SAFE_SYMBOLS[];
extern const char *MODULE_WHITE_LIST[];
extern const char *MODULE_BLACK_LIST[];

#endif // !_MLKM_SHIELD_CONFIG_H
