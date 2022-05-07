/**
 * @file hooks.c
 * @brief file containing the entire management of hooks linked to kernel and LKMs functions
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
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "hooks.h"
#include "safemem.h"
#include "shield.h"
#include "bwlist.h"


/**
 * barrier - spinlock used to avoid that more than one
 * function defined inside monitored modules
 * can run simultaneously.
 */
spinlock_t barrier;


/**
 * dummy_init - dummy init function for modules:
 *      - that are inside the blacklist,
 *      - for which it was not possible to allocate the data
 *        structures for monitoring
 */
static int dummy_init(void) {return 0;}


/**
 * dummy_cleanup - dummy cleanup function for modules:
 *      - that are inside the blacklist,
 *      - for which it was not possible to allocate the data
 *        structures for monitoring
 */
static void dummy_cleanup(void) {}


/**
 * acquire_barrier - function that once it returns allows
 * the module to execute in an atomic manner with respect
 * to the other modules monitored in the system
 *
 * @param module_name:   name of the module that wants to acquire the barrier
 * @param function_name: name of the function that is about to execute
 */
static inline void acquire_barrier(const char *module_name, const char *function_name)
{
        pr_info(KBUILD_MODNAME ": function \"%s\" (module \"%s\") will start after that the other modules to finish running",
                function_name, module_name);
        spin_lock(&barrier);
        pr_info(KBUILD_MODNAME ": function \"%s\" (module \"%s\") can now start execute", function_name, module_name);
}


/**
 * release_barrier - function that simply release the barrier
 *
 * @param module_name:   name of the module that wants to release the barrier
 * @param function_name: name of the function that has finished the execution
 */
static inline void release_barrier(const char *module_name, const char *function_name)
{
        pr_info(KBUILD_MODNAME ": function \"%s\" (module \"%s\") has finished to run, so normal execution is restored",
                function_name, module_name);
        spin_unlock(&barrier);
}


/**
 * get_monitored_module_from_kretprobe_instance - helper function to get the address
 * of the monitored_module structure starting from the kretprobe_instance
 *
 * @param ri: kretprobe from which to derive the monitored_module structure
 * @return    monitored module associated with the kretprobe
 */
static struct monitored_module * get_monitored_module_from_kretprobe_instance(struct kretprobe_instance *ri)
{
        struct kretprobe *kp;
        struct module_probe *mp;

        kp = get_kretprobe(ri);
        mp = container_of(kp, struct module_probe, probe);
        return mp->owner;
}


/**
 * verify_after_module_installation - post-handler of the do_init_module
 * function in which:
 *      - the module is removed if blacklisted or its monitoring structures
 *        cannot be allocated
 *      - the monitored module is removed if some of its functions cannot be hooked up
 *      - the memory areas are checked
 *
 * @param ri:   used to retrieve data associated with kretprobe
 * @param regs: not used
 * @return:     always 0
 */
static int verify_after_module_installation(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        const char *module_name;
        struct krp_do_init_module_data *data;

        data = (struct krp_do_init_module_data *)ri->data;
        module_name = kstrdup(data->monitored_module->module->name, GFP_KERNEL);

        if (unlikely(data->what_to_do == REMOVE_MODULE)) {
                free_module(data->module);
                goto out;
        }

        if (unlikely(data->what_to_do == REMOVE_MONITORED_MODULE)) {
                remove_malicious_lkm(data->monitored_module);
                goto out;
        }

        if (unlikely(!verify_safe_areas(data->monitored_module))) {
                remove_malicious_lkm(data->monitored_module);
                goto out;
        }

        pr_info(KBUILD_MODNAME ": no threat detected");
        data->monitored_module->under_analysis = false;

out:
        release_barrier(module_name, "mod->init");
        kfree(module_name);
        return 0;
}


/**
 * verify_after_function_execution - post-handler of each function defined
 * in the various modules in which verify_safe_areas is invoked
 * for the actual verification passing the reference to the metadata
 * structure using the appropriate function and finally multi-core execution
 * is restored
 *
 * @param ri:   used to retrieve data associated with kretprobe
 * @param regs: not used
 * @return:     always 0
 */
static int verify_after_function_execution(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        const char *module_name, *function_name;
        struct monitored_module *the_monitored_module;

        the_monitored_module = get_monitored_module_from_kretprobe_instance(ri);
        module_name = kstrdup(the_monitored_module->module->name, GFP_KERNEL);
        function_name = kstrdup(get_kretprobe(ri)->kp.symbol_name, GFP_KERNEL);

        if (unlikely(!verify_safe_areas(the_monitored_module))) {
                remove_malicious_lkm(the_monitored_module);
                goto out;
        }

        the_monitored_module->under_analysis = false;
        pr_info(KBUILD_MODNAME ": no threat detected");

out:
        release_barrier(module_name, function_name);
        kfree(module_name);
        kfree(function_name);
        return 0;
}


/**
 * stop_monitoring_module - pre-handler of the free_module function in which
 * the memory allocated for module management is freed and the previously
 * attached probes are removed
 *
 * @param kp:   not used
 * @param regs: used to retrieve first parameter
 *              (in x86_64 convention first parameter is stored in RDI register)
 * @return:     always 0
 */
static int stop_monitoring_module(struct kprobe *kp, struct pt_regs *regs)
{
        struct monitored_module *mm, *tmp_mm;
        struct module *the_module;

        the_module = (struct module *)regs_get_kernel_argument(regs, 0);

        list_for_each_entry_safe(mm, tmp_mm, &monitored_modules_list, links) {
                if (likely(strncmp(mm->module->name, the_module->name, MODULE_NAME_LEN) != 0))
                        continue;

                remove_module_from_list(mm);
        }

        return 0;
}


/**
 * invalid_module - macro used to request the removal of a module
 * in the post handler
 *
 * @param m:        module to be invalidated
 * @param krp_data: data associated with kretprobe
 */
#define invalid_module(m, data)                 \
({                                              \
        (m)->init = dummy_init;                 \
        (m)->exit = dummy_cleanup;              \
        (data)->what_to_do = REMOVE_MODULE;     \
        (data)->module = (m);                   \
})


/**
 * invalid_monitored_module - macro used to request
 * the removal of a monitored module in the post
 * handler
 *
 * @param mm:       monitored module to be invalidated
 * @param krp_data: data associated with kretprobe
 */
#define invalid_monitored_module(mm, data)              \
({                                                      \
        (mm)->module->init = dummy_init;                \
        (mm)->module->exit = dummy_cleanup;             \
        (data)->what_to_do = REMOVE_MONITORED_MODULE;   \
        (data)->monitored_module = (mm);                \
})


/**
 * start_monitoring_module - pre-handler of do_init_module function in which:
 *      - it is checked whether the module belongs to the black/white lists or not
 *      - data structures for monitoring are initialized
 *      - kretprobes are attached to each funcion defined inside the module
 *      - the barrier is acquired to isolated execution
 *
 * @param ri:   used to retrieve data associated with kretprobe_instance
 * @param regs: used to retrieve first parameter (in x86_64 convention
 *              first parameter is stored in RDI register)
 * @return:     always 0
 */
static int start_monitoring_module(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct monitored_module *the_monitored_module;
        struct module *module_to_be_inserted;
        struct krp_do_init_module_data *data;

        /* Initialiaze module and additional data struct */
        module_to_be_inserted = ((struct module *)regs_get_kernel_argument(regs, 0));
        data = (struct krp_do_init_module_data *)ri->data;

        /* Verify if the module is in white list */
        if (unlikely(is_in_white_list(module_to_be_inserted->name))) {
                pr_debug(KBUILD_MODNAME ": the module \"%s\" is inside the white list so it will not be monitored",
                        module_to_be_inserted->name);

                return -EINVAL;
        }

        /* Verify if the module is in black list */
        if (unlikely(is_in_black_list(module_to_be_inserted->name))) {
                pr_debug(KBUILD_MODNAME ": the module \"%s\" is in the black list so it will not be mounted",
                        module_to_be_inserted->name);

                invalid_module(module_to_be_inserted, data);
                return 0;
        }

        /* Allocate memory to monitor the module */
        the_monitored_module = (struct monitored_module *)kzalloc(sizeof(struct monitored_module), GFP_KERNEL);
        if (unlikely(the_monitored_module == NULL)) {
                pr_debug(KBUILD_MODNAME ": unable to allocate memory for module \"%s\" monitoring",
                        module_to_be_inserted->name);

                invalid_module(module_to_be_inserted, data);
                return 0;
        }

        pr_debug(KBUILD_MODNAME ": module \"%s\" (@ %#018lx) installation is taking place",
                module_to_be_inserted->name, (unsigned long)module_to_be_inserted);

        /* Initialize some field of the structure monitored_module */
        the_monitored_module->module = module_to_be_inserted;
        the_monitored_module->under_analysis = true;
        INIT_LIST_HEAD(&(the_monitored_module->probes));

        /* Inizialize fields of the additional data structure */
        data->what_to_do = DONT_REMOVE;
        data->monitored_module = the_monitored_module;

        /* Pre-attach kretprobe on each symbol to enhance security */
        if (unlikely(!attach_kretprobe_on_each_symbol(the_monitored_module))) {
                pr_warn(KBUILD_MODNAME ": some symbol cannot be hooked, so this module cannot be monitored and therefore it will be removed");
                invalid_monitored_module(the_monitored_module, data);
        }

        acquire_barrier(module_to_be_inserted->name, "mod->init");

        /* Add monitored module struct to the list of monitored modules */
        list_add(&(the_monitored_module->links), &monitored_modules_list);

        return 0;
}


/**
 * enable_single_core_execution - pre-handler of each function defined in the various
 * modules in which the barrier is acquired
 *
 * @param ri:   used to retrieve monitored_module struct associated with kretprobe instance
 * @param regs: not used
 * @return:     always 0
 */
static int enable_single_core_execution(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct kretprobe *krp;
        struct monitored_module *mm;

        krp = get_kretprobe(ri);
        mm = get_monitored_module_from_kretprobe_instance(ri);

        if (mm->under_analysis)
                return -EAGAIN;

        mm->under_analysis = true;

        acquire_barrier(mm->module->name, krp->kp.symbol_name);
        pr_info(KBUILD_MODNAME ": function \"%s\" in module \"%s\" has invoked", krp->kp.symbol_name, mm->module->name);
        return 0;
}


/**
 * attach_kretprobe_on - function used to hook a kretprobe to a specific symbol
 * received as parameter
 *
 * @param symbol_name: name of the symbol to be hooked
 * @return             0 if ok, -E otherwise
 */
static int attach_kretprobe_on(struct monitored_module *mm, const char *symbol_name)
{
        struct module_probe *mp;

        mp = (struct module_probe *)kzalloc(sizeof(struct module_probe), GFP_KERNEL);
        if (unlikely(mp == NULL)) {
                pr_debug(KBUILD_MODNAME ": unable to allocate memory for module_probe structure");
                return -ENOMEM;
        }

        mp->owner = mm;
        (mp->probe).kp.symbol_name = kstrdup(symbol_name, GFP_KERNEL);
        (mp->probe).entry_handler = enable_single_core_execution;
        (mp->probe).handler = verify_after_function_execution;

        if(register_kretprobe(&(mp->probe))) {
                pr_debug(KBUILD_MODNAME ": impossibile to hook \"%s\" (module: \"%s\")",
                        symbol_name, mm->module->name);

                return -EINVAL;
        }

        list_add(&(mp->links), &(mm->probes));
        pr_debug(KBUILD_MODNAME ": kretprobe successfully attached to \"%s\" (module: \"%s\")",
                symbol_name, mm->module->name);
        return 0;
}


/**
 * attach_kretprobe_on - function used to iterate inside the ELF looking for
 * the functions defined in it to hook a kretprobe to each one
 *
 * @return true if ok, false otherwise
 */
bool attach_kretprobe_on_each_symbol(struct monitored_module *mm)
{
        int i;
        bool ok;
        const Elf_Sym *sym;
        const char *symbol_name;
        struct mod_kallsyms *kallsyms;

        ok = true;
        kallsyms = mm->module->kallsyms;
        for (i = 0; i < kallsyms->num_symtab && ok; ++i) {
                sym = &(kallsyms->symtab[i]);
                symbol_name = kallsyms->strtab + kallsyms->symtab[i].st_name;
                if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC) {
                        pr_debug(KBUILD_MODNAME ": in the module \"%s\" the function \"%s\" was found",
                                 mm->module->name, symbol_name);

                        if (attach_kretprobe_on(mm, symbol_name) != 0)
                                ok = false;
                }
        }

        return ok;
}


/**
 * remove_probes_from - function responsible for removing the kretprobes registered
 * on the functions defined in the module received as a parameter and freeing the
 * memory areas allocated for management
 *
 * @param mm: module from which to remove the kretprobes
 */
void remove_probes_from(struct monitored_module *mm)
{
        struct module_probe *mp, *tmp_mp;

        list_for_each_entry_safe(mp, tmp_mp, &(mm->probes), links) {
                pr_debug(KBUILD_MODNAME ": removed the probe to \"%s\" in module \"%s\"",
                        (mp->probe).kp.symbol_name, mm->module->name);

                kfree(mp->probe.kp.symbol_name);
                unregister_kretprobe(&(mp->probe));
                list_del(&(mp->links));
                kfree(mp);
        }
}


/**
 * do_init_module_kretprobe - kretprobe to hook to do_init_module
 */
struct kretprobe do_init_module_kretprobe = {
        .entry_handler       = start_monitoring_module,
        .handler             = verify_after_module_installation,
        .data_size           = sizeof(struct krp_do_init_module_data),
};


/**
 * free_module_kretprobe - kretprobe to hook to do_init_module
 */
struct kprobe free_module_kprobe = {
        .symbol_name = "free_module",
        .pre_handler = stop_monitoring_module
};
