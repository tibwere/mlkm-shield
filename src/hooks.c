#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "hooks.h"
#include "safemem.h"
#include "shield.h"
#include "syncro.h"
#include "bwlist.h"


static int dummy_init(void)
{
        pr_debug("This is a dummy function. If you see this message it means that the module could not be mounted (either in blacklist or error in allocating memory for management)");
        return 0;
}


static void dummy_cleanup(void)
{
        pr_debug("This is a dummy function. If you see this message it means that the module could not be mounted (either in blacklist or error in allocating memory for management)");
}


/**
 * get_monitored_module_from_kretprobe_instance - helper function to get the address
 * of the monitored_module structure starting from the kretprobe_instance
 *
 * @param ri: kretprobe from which to derive the monitored_module structure
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
 * verify_safe_areas_mount - post-handler of the do_init_module function
 * in which verify_safe_areas is called for the actual verification and
 * the reference to the module currently being assembled is reset
 *
 * @param ri:   not used
 * @param regs: not used
 * @return:     always 0
 */
static int verify_safe_areas_mount(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        /* The module is in white list */
        if (unlikely(curr_module == NULL))
                return 0;

        verify_safe_areas(curr_module, true);
        curr_module = NULL;

        return 0;
}


/**
 * verify_safe_areas_modfn - post-handler of each function defined
 * in the various modules in which verify_safe_areas is invoked
 * for the actual verification passing the reference to the metadata
 * structure using the appropriate function
 *
 * @param ri:   used to retrieve monitored_module struct (by using container_of)
 * @param regs: not used
 * @return:     always 0
 */
static int verify_safe_areas_modfn(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct kretprobe_private_data *data;
        data = (struct kretprobe_private_data *)ri->data;

        if (data->do_verification)
                verify_safe_areas(get_monitored_module_from_kretprobe_instance(ri), false);
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


#define change_functions(malicious_module)              \
({                                                      \
        (malicious_module)->init = dummy_init;          \
        (malicious_module)->exit = dummy_cleanup;       \
})


/**
 * start_monitoring_module - pre-handler of the do_init_module function in which the dedicated
 * monitored_module structure is initialized and 'single core' execution is requested
 *
 * @param ri:   not used
 * @param regs: used to retrieve first parameter
 *              (in x86_64 convention first parameter is stored in RDI register)
 * @return:     always 0
 */
static int start_monitoring_module(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct monitored_module *the_monitored_module;
        struct module *module_to_be_inserted;

        module_to_be_inserted = ((struct module *)regs_get_kernel_argument(regs, 0));

        if (unlikely(is_in_white_list(module_to_be_inserted->name))) {
                pr_debug(KBUILD_MODNAME ": the module \"%s\" is inside the white list so it will not be monitored",
                        module_to_be_inserted->name);

                return 0;
        }

        if (unlikely(is_in_black_list(module_to_be_inserted->name))) {
                pr_debug(KBUILD_MODNAME ": the module \"%s\" is in the black list so it will not be mounted",
                        module_to_be_inserted->name);

                change_functions(module_to_be_inserted);
                return -EINVAL;
        }

        the_monitored_module = (struct monitored_module *)kzalloc(sizeof(struct monitored_module), GFP_KERNEL);
        if (unlikely(the_monitored_module == NULL)) {
                pr_debug(KBUILD_MODNAME ": unable to allocate memory for module \"%s\" monitoring", module_to_be_inserted->name);

                change_functions(module_to_be_inserted);
                return -ENOMEM;
        }

        the_monitored_module->module = module_to_be_inserted;
        INIT_LIST_HEAD(&(the_monitored_module->probes));

        list_add(&(the_monitored_module->links), &monitored_modules_list);
        sync_master();
        the_monitored_module->under_analysis = true;

        curr_module = the_monitored_module;
        pr_debug(KBUILD_MODNAME ": module \"%s\" (@ 0x%lx) installation is taking place on CPU core %d",
                curr_module->module->name, (unsigned long)curr_module->module->name, smp_processor_id());

        return 0;
}


/**
 * enable_single_core_execution - pre-handler of each function defined in the various
 * modules in which 'single core' execution is required
 *
 * @param ri:   used to retrieve monitored_module struct (by using container_of)
 * @param regs: not used
 * @return:     always 0
 */
static int enable_single_core_execution(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct kretprobe *krp;
        struct monitored_module *mm;
        struct kretprobe_private_data *data;

        data = (struct kretprobe_private_data *)ri->data;
        krp = get_kretprobe(ri);
        mm = get_monitored_module_from_kretprobe_instance(ri);

        if (mm->under_analysis) {
                data->do_verification = false;
                return 0;
        }

        mm->under_analysis = true;
        data->do_verification = true;

        pr_info(KBUILD_MODNAME ": function \"%s\" in module \"%s\" has invoked", krp->kp.symbol_name, mm->module->name);
        sync_master();
        return 0;
}


/**
 * attach_kretprobe_on - function used to hook a kretprobe to a specific symbol
 * received as parameter
 *
 * @param symbol_name: name of the symbol to be hooked
 * @return 0 if ok, -E otherwise
 */
static int attach_kretprobe_on(const char *symbol_name)
{
        struct module_probe *mp;

        mp = (struct module_probe *)kzalloc(sizeof(struct module_probe), GFP_KERNEL);
        if (unlikely(mp == NULL)) {
                pr_debug(KBUILD_MODNAME ": unable to allocate memory for module_probe structure");
                return -ENOMEM;
        }

        mp->owner = curr_module;
        (mp->probe).kp.symbol_name = symbol_name;
        (mp->probe).entry_handler = enable_single_core_execution;
        (mp->probe).handler = verify_safe_areas_modfn;
        (mp->probe).data_size = sizeof(struct kretprobe_private_data);

        if(register_kretprobe(&(mp->probe))) {
                pr_debug(KBUILD_MODNAME ": impossibile to hook \"%s\" (module: \"%s\")",
                         symbol_name, curr_module->module->name);

                return -EINVAL;
        }

        list_add(&(mp->links), &(curr_module->probes));
        pr_debug(KBUILD_MODNAME ": kretprobe successfully attached to \"%s\" (module: \"%s\")",
                symbol_name, curr_module->module->name);
        return 0;
}


/**
 * attach_kretprobe_on - function used to iterate inside the ELF looking for
 * the functions defined in it to hook a kretprobe to each one
 *
 * @return 0 if ok, -E otherwise
 */
int attach_kretprobe_on_each_symbol(void)
{
        int i, fail;
        const Elf_Sym *sym;
        const char *symbol_name;
        struct mod_kallsyms *kallsyms;

        fail = 0;
        kallsyms = curr_module->module->kallsyms;
        for (i = 0; i < kallsyms->num_symtab; ++i) {
                sym = &(kallsyms->symtab[i]);
                symbol_name = kallsyms->strtab + kallsyms->symtab[i].st_name;
                if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC) {
                        pr_debug(KBUILD_MODNAME ": in the module \"%s\" the function \"%s\" was found",
                                 curr_module->module->name, symbol_name);

                        if (attach_kretprobe_on(symbol_name) != 0)
                                fail = 1;
                }
        }

        return fail;
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
        .handler             = verify_safe_areas_mount,
        .data_size           = sizeof(struct kretprobe_private_data),
};

/**
 * free_module_kretprobe - kretprobe to hook to do_init_module
 */
struct kprobe free_module_kprobe = {
        .symbol_name = "free_module",
        .pre_handler = stop_monitoring_module
};
