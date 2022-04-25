/**
 * @file mlkm_shield.c
 * @brief This is the main source file for the MLKM_SHIELD (Malicious Loadable Kernel Module).
 *
 * Taking advantage of the k[ret]probing mechanism offered by the Linux kernel, several internal kernel
 * functions are hooked (e.g. do_init_module, free_module) in order to verify the
 * behavior of the LKMs.
 *
 * If these modify some memory areas judged 'critical' (e.g. sys_call_table, IDT) we proceed with
 * the revert of the changes and with the disassembly of the module
 *
 * @author Simone Tiberi
 */
#include <linux/module.h>
#include <linux/slab.h>

#include "asm/x86.h"
#include "safemem.h"
#include "hooks.h"


/**
 * mlkm_shield_init - initialization function
 */
static int __init mlkm_shield_init(void)
{
        int ret;

        cr0 = read_cr0();
        num_areas = safe_areas_length();
        areas = (struct safe_area *)kzalloc(num_areas * sizeof(struct safe_area), GFP_KERNEL);

        ret = cache_safe_areas();
        if (unlikely(ret != 0))
                return ret;

        free_module = (free_module_t)symbol_lookup("free_module");
        if (unlikely(free_module == NULL)) {
                pr_info(KBUILD_MODNAME ": free_module symbol not found so it would be impossibile to remove module if necessary -> ABORT");
                return -EINVAL;
        }

        do_init_module_kretprobe.kp.symbol_name = "do_init_module";
        if (unlikely(register_kretprobe(&do_init_module_kretprobe))) {
                pr_info(KBUILD_MODNAME ": impossibile to hook do_init_module function");
                return -EINVAL;
        }

        if (unlikely(register_kprobe(&(free_module_kprobe)))) {
                unregister_kretprobe(&(do_init_module_kretprobe));
                pr_info(KBUILD_MODNAME ": impossibile to hook free_module function");
                return -EINVAL;
        }

        pr_info(KBUILD_MODNAME ": successfully initialized");

        return 0;
}


/**
 * mlkm_shield_cleanup - cleanup function
 */
static void __exit mlkm_shield_cleanup(void)
{
        struct monitored_module *mm, *tmp_mm;
        unregister_kretprobe(&do_init_module_kretprobe);
        unregister_kprobe(&free_module_kprobe);

        list_for_each_entry_safe(mm, tmp_mm, &monitored_modules_list, links) {
                remove_module_from_list(mm);
        }

        kfree(areas);

        pr_info(KBUILD_MODNAME ": successfully removed");
}

/* Module stuffs */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Protection against malicious LKM (Loadable Kernel Module)");

module_init(mlkm_shield_init);
module_exit(mlkm_shield_cleanup);
