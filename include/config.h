#ifndef _MLKM_SHIELD_CONFIG_H
#define _MLKM_SHIELD_CONFIG_H

/**
 * comment/uncomment to disable/enable protection for the
 * memory area where the system call table is defined
 */
#define PROTECT_SYS_CALL_TABLE

/**
 * comment/uncomment to disable/enable protection for the
 * memory area where the IDT is defined
 */
// #define PROTECT_IDT

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
 * INITIAL_BLACK_LIST - null terminated list of LKM by default
 * considered malicious (not mounted at all)
 */
const char *INITIAL_BLACK_LIST[] = {
        NULL,
};

#endif // !_MLKM_SHIELD_CONFIG_H
