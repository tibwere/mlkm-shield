/**
 * @file safemem.c
 * @brief file containing memory management routines (e.g. caching, verification)
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
#include <asm/unistd.h>
#include <linux/printk.h>
#include <linux/types.h>
#include "safemem.h"
#include "config.h"
#include "hooks.h"
#include "asm/x86.h"
#include "syncro.h"
#include "shield.h"
#include "symbols.h"
#include "threats.h"


/**
 * areas - matrix of safe_area structures. The first row is associated with
 * the structures that store the state of the memory associated with the system
 * call table, the second one with those for the IDT, the third one with those for the
 * additional symbols
 */
struct safe_area *areas[NUM_AREAS];


/**
 * num_additional_symbols - number of VALID additional symbols
 * specified in the configuration file
 */
size_t num_additional_symbols;


/**
 * cache_single_ulong - function that stores the status of a single memory location
 * by doing debug audits too
 *
 * @param sa:    array of safe_area structures
 * @param index: index of the array
 * @addr:        address to save
 */
static inline void cache_single_ulong(struct safe_area *sa, int index, unsigned long *addr)
{
        sa[index].addr = addr;
        sa[index].value = *addr;
        pr_debug(KBUILD_MODNAME ": address %#018lx -> value %#018lx", (unsigned long)addr, *addr);
}


/**
 * cache_mem_area - function that caches a specific memory area (system call table or IDT)
 *
 * @param audit:         string to print
 * @param start_address: address of the starting unsigned long
 * @param length:        length of the memory area in unsigned long
 * @param index:         row of the matrix
 * @return               0 if ok, -E otherwise
 */
int cache_mem_area(const char *audit, unsigned long *start_address, int length, int index)
{
        int i;

        if (unlikely(start_address == NULL))
                return -ENOMEM;

        pr_debug(KBUILD_MODNAME ": %s address is %#018lx", audit, (unsigned long)start_address);

        for (i=0; i<length; ++i)
                cache_single_ulong(areas[index], i, &(start_address[i]));

        return 0;
}


/**
 * cache_additional_symbols_mem_area - function that caches the status of the memory
 * zones specified as additional in the configuration file
 */
void cache_additional_symbols_mem_area(void)
{
        unsigned long *addr;
        int i, invalid;

        invalid = 0;

        for(i = 0; i < num_additional_symbols; ++i) {
                addr = (unsigned long *)symbol_lookup(SAFE_SYMBOLS[i]);
                pr_debug(KBUILD_MODNAME ": symbol \"%s\" address is %#018lx", SAFE_SYMBOLS[i], (unsigned long)addr);
                if (addr == NULL) {
                        pr_debug(KBUILD_MODNAME ": symbol \"%s\" not found, SKIP", SAFE_SYMBOLS[i]);
                        ++invalid;
                        continue;
                }

                cache_single_ulong(areas[SA_ADDITIONAL_SYMBOLS_IDX], i - invalid, addr);
        }

        num_additional_symbols -= invalid;
}


/**
 * revert_to_good_state - function that allows you to revert the changes
 * made by the malicious LKM before removing it
 *
 * @param a: address of the safe_area structure to be considered for revert
 */
inline void revert_to_good_state(struct safe_area *a)
{
        START_UNPROTECTED_EDITING;
        *(a->addr) = a->value;
        END_UNPROTECTED_EDITING;
        pr_alert(KBUILD_MODNAME ": memory state at %#018lx restored (value: %#018lx)",
                 (unsigned long)a->addr, *(a->addr));
}


/**
 * inspect_sa - function that inspects a single array of safe_area structures
 * to see if the memory has been tampered
 *
 * @param module: module under inspection
 * @param sa:     array of safe_area structures
 * @param length: length of the array
 * @return        true if the memory is unaffected, false otherwise
 */
static bool inspect_sa(struct module *module, struct safe_area *sa, int length)
{
        int i;
        if (sa == NULL)
                return true;

        for (i = 0; i < length; ++i) {
                if (*(sa[i].addr) != sa[i].value) {
                        pr_alert(KBUILD_MODNAME ": rootkit detected [memory at %#018lx has changed (previous: %#018lx, current: %#018lx)]",
                                (unsigned long)sa[i].addr,
                                sa[i].value,
                                *(sa[i].addr));

                        insert_new_threat(module, &(sa[i]), *(sa[i].addr));
                        revert_to_good_state(&(sa[i]));
                        return false;
                }
        }

        return true;
}


/**
 * verify_safe_areas - core function invoked by the various post-handlers
 * in which the status of the memory areas to be protected is checked and,
 * if necessary, the module is reverted and unmounted
 *
 * @param the_module:     module subjected to verification
 * @param need_to_attach: true if the function is called from do_init_module kretprobe,
 *                        false otherwise
 */
bool verify_safe_areas(struct monitored_module *the_module)
{
        int i;
        bool good = true;
        int lengths[] = {
                NR_syscalls,
                IDT_ULONG_COUNT,
                num_additional_symbols,
        };

        for (i = 0; i < 3 && good; ++i) {
                if (!inspect_sa(the_module->module, areas[i], lengths[i]))
                        good = false;
        }

        return good;
}


/**
 * count_additional_symbols - function that calculates the initial length
 * of the array of additional symbols to consider
 *
 * @return the length of the array
 */
inline size_t count_additional_symbols(void)
{
        int i;
        for (i = 0; SAFE_SYMBOLS[i] != NULL; ++i);

        return i;
}
