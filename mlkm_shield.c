/**
 * @file mlkm_shield.c
 * @brief This is the source file for the MLKM_SHIELD (Malicious Loadable Kernel Module).
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
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP (1)
#endif


/**
 * safe_area - structure representing a good-state cache of memory
 *
 * @field addr:  address of a critical location
 * @field value: value of the critical memory location
 */
struct safe_area {
        unsigned long *addr;
        unsigned long value;
} areas[NR_syscalls];


/**
 * monitored_module - structure containing some relevant metadata
 * for the management of the monitored modules
 * (e.g. list of probes linked to functions)
 *
 * @field module:         reference to the structure module
 * @field under_analysis: true if someone has started analysis, false otherwise
 * @field links:          fields for managing the linked list
 * @field probes:         list of probes linked to the functions defined in the module
 */
struct monitored_module {
        struct module *module;
        bool under_analysis;
        struct list_head links;
        struct list_head probes;
};


/**
 * module_probe - structure used to manage the list of probes
 * attached to each function
 *
 * @field owner: reference to the module structure in which the function
 *               to which the probe has been applied is defined
 * @field probe: kretprobe structure
 * @field links: fields for managing the linked list
 */
struct module_probe {
        struct monitored_module *owner;
        struct kretprobe probe;
        struct list_head links;
};


/**
 * kretprobe_private_data - the structure is used to pass data from the
 * pre to the post handler of a kretprobe. Using the Boolean variable
 * contained within in combination with the under_analysis field of the
 * monitored_module structure, it is possible to prevent nested analyzes
 * from starting
 *
 * @field do_verification: true if the function is the outermost,
 *                         false if it is invoked by another that is
 *                         already part of a test
 */
struct kretprobe_private_data {
        bool do_verification;
};


/**
 * kallsyms_lookup_name_t - prototype of the kallsyms_lookup_name function
 * (from kernel version 5.7 no longer exposed)
 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/**
 * free_module_t - prototype of the free_module function (not exposed)
 */
typedef void (*free_module_t)(struct module *mod);


/**
 * monitored_modules_list - head of the list of monitored modules
 */
static LIST_HEAD(monitored_modules_list);

/**
 * sync_enter - synchronization barrier on which the master spins
 * until all workers have started executing the function
 */
static atomic_t sync_enter __attribute__((aligned(64)));

/**
 * sync_leave - synchronization barrier on which the worker spins
 * until the master has completed verification
 */
static atomic_t sync_leave __attribute__((aligned(64)));

/**
 * curr_module - address associated with the module being mounted metadata
 */
static struct monitored_module *curr_module;

/**
 * cr0 - cached value of CR0 register
 * (used to unprotect/protect memory mechanism)
 */
static unsigned long cr0;

/**
 * free_module: function pointer of free_module not exposed to LKMs
 */
static free_module_t free_module;


/* Prototypes */
static kallsyms_lookup_name_t                           __get_kallsyms_lookup_name(void);
static free_module_t                                    get_free_module(void);
static unsigned long *                                  get_system_call_table_address(void);
static int                                              cache_safe_areas(void);
static void                                             sync_worker(void *info);
static void __always_inline                             __write_to_cr0(unsigned long new);
static void __always_inline                             revert_to_good_state(struct safe_area *a);
static void                                             remove_malicious_lkm(struct monitored_module *the_module);
static int                                              verify_safe_areas_mount(struct kretprobe_instance *ri, struct pt_regs *regs);
static int                                              verify_safe_areas_modfn(struct kretprobe_instance *ri, struct pt_regs *regs);
static void                                             __verify_safe_areas(struct monitored_module *the_module, bool need_to_attach);
static void __always_inline                             sync_master(void);
static int                                              stop_monitoring_module(struct kprobe *kp, struct pt_regs *regs);
static int                                              start_monitoring_module(struct kretprobe_instance *ri, struct pt_regs *regs);
static int                                              enable_single_core_execution(struct kretprobe_instance *ri, struct pt_regs *regs);
static int                                              attach_kretprobe_on(const char *symbol_name);
static int                                              attach_kretprobe_on_each_symbol(void);
static struct monitored_module *                        get_monitored_module_from_kretprobe_instance(struct kretprobe_instance *ri);
static void                                             remove_probes_from(struct monitored_module *mm);
static void                                             remove_module_from_list(struct monitored_module *mm);


/**
 * __get_kallsyms_lookup_name - helper function for retrieving the address where the
 * kallsyms_lookup_name function is present in memory
 *
 * @return function pointer (kallsyms_lookup_name_t type)
 */
static kallsyms_lookup_name_t __get_kallsyms_lookup_name(void)
{
        struct kprobe kp = {
                .symbol_name = "kallsyms_lookup_name"
        };
	kallsyms_lookup_name_t symb;

        if (likely(!register_kprobe(&kp))) {
	        symb = (kallsyms_lookup_name_t) kp.addr;
	        unregister_kprobe(&kp);

                return (kallsyms_lookup_name_t)symb;
        }

        return NULL;
}


/**
 * get_free_module - helper function for retrieving the address where the
 * free_module function is present in memory
 *
 * @return function pointer (free_module_t type)
 */
static free_module_t get_free_module(void)
{
#if KPROBE_LOOKUP
        kallsyms_lookup_name_t kallsyms_lookup_name = __get_kallsyms_lookup_name();
        if (unlikely(kallsyms_lookup_name == NULL))
                return NULL;
#endif

        return (free_module_t)kallsyms_lookup_name("free_module");
}


/**
 * get_system_call_table_addres - function that allows to obtain the logical
 * address of the system call table in a differentiated way according to
 * the current version of the kernel
 *
 * @return sys_call_table address
 */
static unsigned long *get_system_call_table_address(void)
{
        unsigned long *addr;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
#ifdef KPROBE_LOOKUP
	kallsyms_lookup_name_t kallsyms_lookup_name = __get_kallsyms_lookup_name();
        if (unlikely(kallsyms_lookup_name == NULL))
                return NULL;
#endif
        addr = (unsigned long *)kallsyms_lookup_name("sys_call_table");
        return addr;
#else
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		addr = (unsigned long *)i;

		if (addr[__NR_close] == (unsigned long)sys_close)
			return addr;
	}
	return NULL;
#endif
}


/**
 * cache_safe_areas - It stores the address-associated value pairs
 * in struct safe_areas for subsequent analyzes
 *
 * @return 0 if ok, -E otherwise
 */
static int cache_safe_areas(void)
{
        int i;
        unsigned long *system_call_table = get_system_call_table_address();
        if (unlikely(system_call_table == NULL))
                return -ENOMEM;

        pr_debug(KBUILD_MODNAME ": system call table address is 0x%lx", (unsigned long)system_call_table);

        for (i = 0; i < NR_syscalls; ++i) {
                areas[i].addr = &(system_call_table[i]);
                areas[i].value = system_call_table[i];
                pr_debug(KBUILD_MODNAME ": address 0x%lx -> value 0x%lx",
                        (unsigned long)&(system_call_table[i]),
                        system_call_table[i]);
        }

        return 0;
}


/**
 * sync_worker - function used to make the other CPU cores wait actively
 * (via a spin on the barrier variable) as long as the module is being assembled
 *
 * @param info: not used
 */
static void sync_worker(void *info)
{
        unsigned int cpuid;
        cpuid = smp_processor_id();

        pr_debug(KBUILD_MODNAME ": core %d wait until verification is completed", cpuid);

        atomic_dec(&sync_enter);
        // preempt_disable();
        // while(atomic_read(&sync_leave) > 0);
        // preempt_enable();

        pr_debug(KBUILD_MODNAME ": core %d resumes work left earlier", cpuid);
}


/**
 * __write_to_cr0 - function that uses inline ASM to overwrite the CR0 register
 *
 * @param new: new value to store in CR0 register
 */
static void __always_inline __write_to_cr0(unsigned long new)
{
        /* See https://elixir.bootlin.com/linux/v5.17.3/source/arch/x86/include/asm/special_insns.h#L54 */
        asm volatile("mov %0,%%cr0": : "r" (new) : "memory");
}

/**
 * These macros allow you to delimit a portion of code that can be accessed
 * in an arbitrary way both on registers and in memory (thanks to the overwriting of cr0)
 */
#define START_UNPROTECTED_EDITING __write_to_cr0(cr0 & ~0x00010000)
#define END_UNPROTECTED_EDITING   __write_to_cr0(cr0)


/**
 * revert_to_good_state - function that allows you to revert the changes
 * made by the malicious LKM before removing it
 *
 * @param: address of the safe_area structure to be considered for revert
 */
static void __always_inline revert_to_good_state(struct safe_area *a)
{
        START_UNPROTECTED_EDITING;
        *(a->addr) = a->value;
        END_UNPROTECTED_EDITING;
        pr_alert(KBUILD_MODNAME ": memory state at 0x%lx restored (value: 0x%lx)",
                 (unsigned long)a->addr, *(a->addr));
}


/**
 * remove_malicious_lkm - function that takes care of removing the
 * malicious module and freeing the pre-allocated management memory areas
 *
 * @param the_module: module to be removed
 */
static void remove_malicious_lkm(struct monitored_module *the_module)
{
        struct module *mod;

        mod = the_module->module;
        remove_module_from_list(the_module);
        free_module(mod);
}


/**
 * verify_safe_areas_mount - post-handler of the do_init_module function
 * in which __verify_safe_areas is called for the actual verification and
 * the reference to the module currently being assembled is reset
 *
 * @param ri:   not used
 * @param regs: not used
 * @return:     always 0
 */
static int verify_safe_areas_mount(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        __verify_safe_areas(curr_module, true);
        curr_module = NULL;

        return 0;
}


/**
 * verify_safe_areas_modfn - post-handler of each function defined
 * in the various modules in which __verify_safe_areas is invoked
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
                __verify_safe_areas(get_monitored_module_from_kretprobe_instance(ri), false);
        return 0;
}


/**
 * __verify_safe_areas - core function invoked by the various post-handlers
 * in which the status of the memory areas to be protected is checked and,
 * if necessary, the module is reverted and unmounted
 *
 * @param the_module: module subjected to verification
 */
static void __verify_safe_areas(struct monitored_module *the_module, bool need_to_attach)
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
                goto out;
        }

        the_module->under_analysis = false;
        likely(good == 1) ? pr_info(KBUILD_MODNAME ": no threat detected") : remove_malicious_lkm(the_module);

out:
        atomic_set(&sync_leave, 0);
        preempt_enable();
}

/**
 * __sync_master - function that allows you to request the execution of sync_worker
 * function to the other CPU cores online
 */
static void __always_inline sync_master(void)
{
        atomic_set(&sync_enter, num_online_cpus() - 1);
        atomic_set(&sync_leave, 1);

        preempt_disable();
        smp_call_function_many(cpu_online_mask, sync_worker, NULL, false);

        while (atomic_read(&sync_enter) > 0);
        pr_debug(KBUILD_MODNAME ": all cores are syncronized");
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

        the_module = (struct module *)regs->di;

        list_for_each_entry_safe(mm, tmp_mm, &monitored_modules_list, links) {
                if (likely(strncmp(mm->module->name, the_module->name, MODULE_NAME_LEN) != 0))
                        continue;

                remove_module_from_list(mm);
        }

        return 0;
}


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

        the_monitored_module = (struct monitored_module *)kzalloc(sizeof(struct monitored_module), GFP_KERNEL);
        if (unlikely(the_monitored_module == NULL))
                return -ENOMEM;

        the_monitored_module->module = (struct module *)regs->di;
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
static int attach_kretprobe_on_each_symbol(void)
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
 * remove_probes_from - function responsible for removing the kretprobes registered
 * on the functions defined in the module received as a parameter and freeing the
 * memory areas allocated for management
 *
 * @param mm: module from which to remove the kretprobes
 */
static void remove_probes_from(struct monitored_module *mm)
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
 * remove_module_from_list - function that internally invokes the remove_probes_from
 * and subsequently also removes the module from the list
 *
 * @param mm: module to be removed
 */
static void remove_module_from_list(struct monitored_module *mm)
{
        remove_probes_from(mm);
        pr_debug(KBUILD_MODNAME ": removed \"%s\" from monitored modules", mm->module->name);
        list_del(&(mm->links));
        kfree(mm);
}


/**
 * do_init_module_kretprobe - kretprobe to hook to do_init_module
 */
static struct kretprobe do_init_module_kretprobe = {
        .entry_handler       = start_monitoring_module,
        .handler             = verify_safe_areas_mount,
        .data_size           = sizeof(struct kretprobe_private_data),
};

/**
 * free_module_kretprobe - kretprobe to hook to do_init_module
 */
static struct kprobe free_module_kprobe = {
        .symbol_name = "free_module",
        .pre_handler = stop_monitoring_module
};


/**
 * mlkm_shield_init - initialization function
 */
static int __init mlkm_shield_init(void)
{
        int ret;

        cr0 = read_cr0();

        ret = cache_safe_areas();
        if (unlikely(ret != 0))
                return ret;

        free_module = get_free_module();
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

        pr_info(KBUILD_MODNAME ": successfully removed");
}

/* Module stuffs */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Protection against malicious LKM (Loadable Kernel Module)");

module_init(mlkm_shield_init);
module_exit(mlkm_shield_cleanup);
