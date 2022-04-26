/**
 * @file bwlist.c
 * @brief file for managing black & white lists
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
#include <linux/module.h>
#include <linux/string.h>
#include "config.h"


/**
 * is_in_list - function that checks whether a certain string belongs
 * to a null-terminated array of other strings
 *
 * @param list: null-terminated array of strings
 * @param name: string to search for
 * @return true if name belongs to list, false otherwise
 */
inline bool is_in_list(const char **list, const char *name)
{
        int i;
        for (i = 0; list[i] != NULL; ++i) {
                if (unlikely(strncmp(list[i], name, MODULE_NAME_LEN) == 0))
                        return true;
        }

        return false;
}
