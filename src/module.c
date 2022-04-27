/**
 * @file module.c
 * @brief main source file
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
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "asm/x86.h"
#include "safemem.h"
#include "hooks.h"
#include "config.h"
#include "shield.h"
#include "threats.h"


/**
 * initialize_memory_protection - function responsible for caching
 * the status of the memory areas to be protected
 *
 * @return 0 if ok, -E otherwise
 */
static int initialize_memory_protection(void)
{
        if (PROTECT_SYS_CALL_TABLE) {
                areas[SA_SYS_CALL_TABLE_IDX] = (struct safe_area *)kmalloc(NR_syscalls * sizeof(struct safe_area), GFP_KERNEL);
                if (unlikely(areas[SA_SYS_CALL_TABLE_IDX] == NULL)) {
                        pr_info(KBUILD_MODNAME ": unable to allocate memory for sys_call_table protection -> ABORT");
                        return -ENOMEM;
                }

                if(unlikely(cache_sys_call_table_mem_area())) {
                        pr_info(KBUILD_MODNAME ": unable to cache valid state of memory for sys_call_table -> ABORT");
                        kfree(areas[SA_SYS_CALL_TABLE_IDX]);
                        return -ENOMEM;
                }
        }

        if (PROTECT_IDT) {
                areas[SA_IDT_IDX] = (struct safe_area *)kmalloc(IDT_ULONG_COUNT * sizeof(struct safe_area), GFP_KERNEL);
                if (unlikely(areas[SA_IDT_IDX] == NULL)) {
                        pr_info(KBUILD_MODNAME ": unable to allocate memory for IDT protection -> ABORT");
                        if (areas[SA_SYS_CALL_TABLE_IDX] != NULL)
                                kfree(areas[SA_SYS_CALL_TABLE_IDX]);

                        return -ENOMEM;
                }

                if(unlikely(cache_idt_mem_area())) {
                        pr_info(KBUILD_MODNAME ": unable to cache valid state of memory for IDT -> ABORT");
                        if (areas[SA_SYS_CALL_TABLE_IDX] != NULL)
                                kfree(areas[SA_SYS_CALL_TABLE_IDX]);

                        kfree(areas[SA_IDT_IDX]);

                        return -ENOMEM;
                }
        }

        num_additional_symbols = count_additional_symbols();
        areas[SA_ADDITIONAL_SYMBOLS_IDX] = (struct safe_area *)kmalloc(num_additional_symbols * sizeof(struct safe_area), GFP_KERNEL);
        if (unlikely(areas[SA_ADDITIONAL_SYMBOLS_IDX] == NULL)) {
                pr_info(KBUILD_MODNAME ": unable to allocate memory for additional symbols protection -> ABORT");
                if (areas[SA_SYS_CALL_TABLE_IDX] != NULL)
                        kfree(areas[SA_SYS_CALL_TABLE_IDX]);

                if (areas[SA_IDT_IDX] != NULL)
                        kfree(areas[SA_IDT_IDX]);

                return -ENOMEM;
        }

        cache_additional_symbols_mem_area();

        return 0;
}


/**
 * mlkm_shield_init - initialization function
 *
 * @return 0 if ok, -E otherwise
 */
static int __init mlkm_shield_init(void)
{
        cr0 = read_cr0();
        if (initialize_memory_protection())
                return -ENOMEM;

        free_module = (free_module_t)symbol_lookup("free_module");
        if (unlikely(free_module == NULL)) {
                pr_info(KBUILD_MODNAME ": free_module symbol not found so it would be impossibile to remove module if necessary");
                return -EINVAL;
        }

        if (unlikely(init_threats_for_sys_audit())) {
                pr_info(KBUILD_MODNAME ": impossibile to initialize sys audit");
                return -ENOMEM;
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
        int i;
        struct monitored_module *mm, *tmp_mm;

        destroy_threats_for_sys_audit();
        unregister_kretprobe(&do_init_module_kretprobe);
        unregister_kprobe(&free_module_kprobe);

        list_for_each_entry_safe(mm, tmp_mm, &monitored_modules_list, links) {
                remove_module_from_list(mm);
        }

        for (i = 0; i < 3; ++i) {
                if (areas[i] != NULL)
                        kfree(areas[i]);
        }

        pr_info(KBUILD_MODNAME ": successfully removed");
}


/* Module stuffs */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Protection against malicious LKM (Loadable Kernel Module)");

module_param(removed, int, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(removed, "A short integer");

module_init(mlkm_shield_init);
module_exit(mlkm_shield_cleanup);
