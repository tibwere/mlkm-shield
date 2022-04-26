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

struct safe_area *areas[NUM_AREAS];
size_t num_additional_symbols;


/**
 * cache_single_ulong - function that stores the status of a single memory location
 * by doing debug audits too
 *
 * @param index: index of areas array
 * @addr:        address to save
 */
static inline void cache_single_ulong(struct safe_area *sa, int index, unsigned long *addr)
{
        sa[index].addr = addr;
        sa[index].value = *addr;
        pr_debug(KBUILD_MODNAME ": address 0x%lx -> value 0x%lx", (unsigned long)addr, *addr);
}

int cache_mem_area(const char *audit, unsigned long *start_address, int length, int index)
{
        int i;

        if (unlikely(start_address == NULL))
                return -ENOMEM;

        pr_debug(KBUILD_MODNAME ": %s address is 0x%lx", audit, (unsigned long)start_address);

        for (i=0; i<length; ++i)
                cache_single_ulong(areas[index], i, &(start_address[i]));

        return 0;
}


void cache_additional_symbols_mem_area(void)
{
        unsigned long *addr;
        int i, invalid;

        invalid = 0;

        for(i = 0; i < num_additional_symbols; ++i) {
                addr = (unsigned long *)symbol_lookup(SAFE_SYMBOLS[i]);
                if (addr == NULL) {
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


static bool inspect_sa(struct safe_area *sa, int length)
{
        int i;
        if (sa == NULL)
                return true;

        for (i = 0; i < length; ++i) {
                if (*(sa[i].addr) != sa[i].value) {
                        pr_alert(KBUILD_MODNAME ": rootkit detected [memory at 0x%lx has changed (previous: 0x%lx, current: 0x%lx)]",
                                (unsigned long)sa[i].addr,
                                sa[i].value,
                                *(sa[i].addr));
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
 * @param the_module: module subjected to verification
 */
void verify_safe_areas(struct monitored_module *the_module, bool need_to_attach)
{
        int i;
        bool good = true;
        int lengths[] = {
                NR_syscalls,
                IDT_ULONG_COUNT,
                num_additional_symbols,
        };

        for (i = 0; i < 3 && good; ++i) {
                if (!inspect_sa(areas[i], lengths[i]))
                        good = false;
        }

        if (good && need_to_attach && attach_kretprobe_on_each_symbol()) {
                pr_warn(KBUILD_MODNAME ": some symbol cannot be hooked, so this module cannot be monitored -> BAN");
                remove_malicious_lkm(the_module);
        } else {
                the_module->under_analysis = false;
                likely(good) ? pr_info(KBUILD_MODNAME ": no threat detected") : remove_malicious_lkm(the_module);
        }

        atomic_set(&sync_leave, 0);
        preempt_enable();
}

inline size_t count_additional_symbols(void)
{
        int i;
        for (i = 0; SAFE_SYMBOLS[i] != NULL; ++i);

        return i;
}
