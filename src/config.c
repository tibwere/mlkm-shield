/**
 * @file config.c
 * @brief configuration file.
 * Edit these variables before mounting the module to tune to your liking :)
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
#include <linux/types.h>

/**
 * PROTECT_SYS_CALL_TABLE - true if you want to enable protection
 * for the memory area where the system call table is defined,
 * false otherwise
 */
const bool PROTECT_SYS_CALL_TABLE = 1;

/**
 * PROTECT_IDT - true if you want to enable protection
 * for the memory area where the IDT is defined
 * false otherwise
 */
const bool PROTECT_IDT = 1;

/**
 * SAFE_SYMBOLS - null terminated list of additional symbols
 * to protect (you can identify the symbols by reading what
 * is returned from /proc/kallsyms)
 */
const char *SAFE_SYMBOLS[] = {
        NULL,
};

/**
 * MOMDULE_WHITE_LIST - null terminated list of LKM not to
 * be analyzed because they are considered 'good' a priori
 */
const char *MODULE_WHITE_LIST[] = {
        NULL,
};

/**
 * MODULE_BLACK_LIST - null terminated list of LKM by default
 * considered malicious (not mounted at all)
 */
const char *MODULE_BLACK_LIST[] = {
        NULL,
};
