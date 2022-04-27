/**
 * @file bwlist.h
 * @brief header file for black/white list stuffs (@see ${basedir}/src/bwlist.c)
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
#ifndef _MLKM_SHIELD_BWLIST_H
#define _MLKM_SHIELD_BWLIST_H

#include <linux/types.h>
#include "config.h"

/* Prototypes */
inline bool is_in_list(const char **list, const char *name);

/**
 * utility macro to avoid specifying too many parameters
 * when invoking the in_in_list function
 */
#define is_in_white_list(name) is_in_list(MODULE_WHITE_LIST, name)
#define is_in_black_list(name) is_in_list(MODULE_BLACK_LIST, name)

#endif // !_MLKM_SHIELD_BWLIST_H
