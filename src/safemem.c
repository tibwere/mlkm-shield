#include <asm/unistd.h>
#include <linux/printk.h>

#include "safemem.h"
#include "config.h"
#include "hooks.h"
#include "asm/x86.h"
#include "syncro.h"
#include "shield.h"
#include "symbols.h"


struct safe_area *areas;
size_t num_areas;


/**
 * __cache_single_ulong - function that stores the status of a single memory location
 * by doing debug audits too
 *
 * @param index: index of areas array
 * @addr:        address to save
 */
static inline void cache_single_ulong(int index, unsigned long *addr)
{
        areas[index].addr = addr;
        areas[index].value = *addr;
        pr_debug(KBUILD_MODNAME ": address 0x%lx -> value 0x%lx", (unsigned long)addr, *addr);
}

/**
 * cache_safe_areas - It stores the address-associated value pairs
 * in struct safe_areas for subsequent analyzes
 *
 * @return 0 if ok, -E otherwise
 */
int cache_safe_areas(void)
{
        int i, j, k;
        unsigned long *addr;
#ifdef PROTECT_SYS_CALL_TABLE
        unsigned long *system_call_table;
#endif

        i = j = k = 0;

#ifdef PROTECT_SYS_CALL_TABLE
        system_call_table = get_system_call_table_address();
        if (unlikely(system_call_table == NULL))
                return -ENOMEM;

        pr_debug(KBUILD_MODNAME ": system call table address is 0x%lx", (unsigned long)system_call_table);

        for (; i < NR_syscalls; ++i) {
                cache_single_ulong(i, &(system_call_table[i]));
        }
#endif

        for (; SAFE_SYMBOLS[k] != NULL; ++k) {
                addr = (unsigned long *)symbol_lookup(SAFE_SYMBOLS[k]);
                cache_single_ulong(i + j + k, addr);
        }

        return 0;
}


/**
 * revert_to_good_state - function that allows you to revert the changes
 * made by the malicious LKM before removing it
 *
 * @param: address of the safe_area structure to be considered for revert
 */
inline void revert_to_good_state(struct safe_area *a)
{
        START_UNPROTECTED_EDITING;
        *(a->addr) = a->value;
        END_UNPROTECTED_EDITING;
        pr_alert(KBUILD_MODNAME ": memory state at 0x%lx restored (value: 0x%lx)",
                 (unsigned long)a->addr, *(a->addr));
}


/**
 * verify_safe_areas - core function invoked by the various post-handlers
 * in which the status of the memory areas to be protected is checked and,
 * if necessary, the module is reverted and unmounted
 *
 * @param the_module: module subjected to verification
 */
void verify_safe_areas(struct monitored_module *the_module, bool need_to_attach)
{
        int i, good;

        /* Assume initially that module is not malicious */
        good = 1;

        pr_info(KBUILD_MODNAME ": start analysis");
        for (i = 0; i < NR_syscalls; ++i) {
                if (*(areas[i].addr) != areas[i].value) {
                        pr_alert(KBUILD_MODNAME ": rootkit detected [memory at 0x%lx has changed (previous: 0x%lx, current: 0x%lx)]",
                                (unsigned long)areas[i].addr,
                                areas[i].value,
                                *(areas[i].addr));
                        good = 0;
                        revert_to_good_state(&(areas[i]));
                }
        }


        if (good && need_to_attach && attach_kretprobe_on_each_symbol()) {
                pr_warn(KBUILD_MODNAME ": some symbol cannot be hooked, so this module cannot be monitored -> BAN");
                remove_malicious_lkm(the_module);
        } else {
                the_module->under_analysis = false;
                likely(good == 1) ? pr_info(KBUILD_MODNAME ": no threat detected") : remove_malicious_lkm(the_module);
        }

        atomic_set(&sync_leave, 0);
        preempt_enable();
}


/**
 * safe_areas_length - evaluates the length of the array of
 * memory areas to be protected
 *
 * @return length of array (as dwords)
 */
size_t safe_areas_length(void)
{
        int i;
        size_t length = 0;
#ifdef PROTECT_SYS_CALL_TABLE
        length += NR_syscalls;
#endif

#ifdef PROTECT_IDT
        length += (IDT_ENTRIES * sizeof(gate_desc) / sizeof(unsigned long));
#endif

        for (i=0; SAFE_SYMBOLS[i] != NULL; ++i);
        length += i;

        return length;
}
