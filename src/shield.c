#include <linux/module.h>
#include <linux/printk.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "shield.h"
#include "hooks.h"


/**
 * monitored_modules_list - head of the list of monitored modules
 */
LIST_HEAD(monitored_modules_list);


/**
 * curr_module - address associated with the module being mounted metadata
 */
struct monitored_module *curr_module;


/**
 * free_module: function pointer of free_module not exposed to LKMs
 */
free_module_t free_module;


/**
 * removed - number of LKMs removed
 */
int removed;


/**
 * remove_malicious_lkm - function that takes care of removing the
 * malicious module and freeing the pre-allocated management memory areas
 *
 * @param the_module: module to be removed
 */
inline void remove_malicious_lkm(struct monitored_module *the_module)
{
        struct module *mod;
        removed++;

        mod = the_module->module;
        remove_module_from_list(the_module);
        free_module(mod);
}


/**
 * remove_module_from_list - function that internally invokes the remove_probes_from
 * and subsequently also removes the module from the list
 *
 * @param mm: module to be removed
 */
inline void remove_module_from_list(struct monitored_module *mm)
{
        remove_probes_from(mm);
        pr_debug(KBUILD_MODNAME ": removed \"%s\" from monitored modules", mm->module->name);

        /*
         * If a rootkit eliminates itself from the module list by invoking free_module(),
         * a segmentation fault is obtained as described in the documentation linked below:
         *
         * https://elixir.bootlin.com/linux/v5.17/source/include/linux/poison.h#L23
         */
        list_del(&(mm->links));
        kfree(mm);
}
