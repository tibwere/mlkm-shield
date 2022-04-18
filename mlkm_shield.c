#include <linux/module.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/kprobes.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP (1)
#endif


/**
 * safe_area - structure representing a good-state cache of memory
 * @field addr: address of a critical location
 * @field value: value of the critical memory location
 */
struct safe_area {
        unsigned long *addr;
        unsigned long value;
} *areas;

/**
 * barrier - cache-aligned variable (64B) used to synchronize the various
 * CPUs through the IPI mechanism
 */
static atomic_t barrier __attribute__((aligned(64)));

/**
 * currently_loading_module - Address associated with the
 * struct module being mounted
 */
static struct module *currently_loading_module;


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
        struct kprobe kp = {
                .symbol_name = "kallsyms_lookup_name"
        };
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;

        if (likely(!register_kprobe(&kp))) {
	        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	        unregister_kprobe(&kp);
        } else {
                return NULL;
        }
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
 * cache_safe_areas - It stores the address and current reference value pairs
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

        areas = kzalloc(NR_syscalls * sizeof(struct safe_area), GFP_KERNEL);
        if (unlikely(areas == NULL))
                return -ENOMEM;

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
 * let_verify - function used to make the other CPU cores wait actively
 * (via a spin on the barrier variable) as long as the module is being assembled
 *
 * @param info: not used (according to smp_call_function_t)
 */
static void let_verify(void *info) {
        unsigned int cpuid;

        cpuid = smp_processor_id();
        pr_debug(KBUILD_MODNAME ": core %d wait until verification is completed", cpuid);
        // while(atomic_read(&barrier));
        pr_debug(KBUILD_MODNAME ": core %d resumes work left earlier", cpuid);
}


/**
 * verify_safe_areas - post handler of the do_init_module function in which
 * the comparison is made between the cached values of the critical locations
 * and the current ones.
 *
 * @param ki:   not used (according to kretprobe_handler_t)
 * @param regs: not used (according to kretprobe_handler_t)
 * @return:     always 0 (not used)
 */
static int verify_safe_areas(struct kretprobe_instance *ki, struct pt_regs *regs)
{
        int i, good;

        /* Assume initially that module is not malicious */
        good = 1;

        pr_info(KBUILD_MODNAME ": start analysis");
        for (i = 0; i < NR_syscalls; ++i) {
                if (*(areas[i].addr) != areas[i].value) {
                        pr_alert(KBUILD_MODNAME ": rootkit detected [memory at 0x%lx has changed]", (unsigned long)areas[i].addr);
                        good = 0;

                        /*TODO: revert changes (by unprotect/protect memory) and unload malicious module */
                }
        }

        if (good)
                pr_info(KBUILD_MODNAME ": no threat detected");

        atomic_set(&barrier, 0);

        currently_loading_module = NULL;
        return 0;
}


/**
 * atom_insmod - pre handler of the do_init_module function in which the execution of the synchronization
 * function is requested from the other CPU cores and the address of the struct module associated with
 * the module being assembled is stored
 *
 * @param ki:   not used (according to kretprobe_handler_t)
 * @param regs: not used (according to kretprobe_handler_t)
 * @return:     always 0 (not used)
 */
static int atom_insmod(struct kretprobe_instance *ki, struct pt_regs *regs)
{
        /*
         * static noinline int do_init_module(struct module *mod)
         * in the x86 convention, the first parameter is stored in the RDI register
         */
        currently_loading_module = (struct module *)regs->di;
        pr_debug(KBUILD_MODNAME ": module installation at address 0x%lx is taking place on CPU core %d",
                 (unsigned long)currently_loading_module,
                 smp_processor_id());

        atomic_set(&barrier, 1);
        smp_call_function(let_verify, NULL, 0);
        return 0;
}


/**
 * mount_kretprobe - kretprobe to hook to do_init_module
 */
static struct kretprobe mount_kretprobe = {
        .entry_handler       = atom_insmod,
        .handler = verify_safe_areas,
};


/**
 * mlkm_shield_init - initialization function
 */
static int __init mlkm_shield_init(void)
{
        int ret;

        ret = cache_safe_areas();
        if (unlikely(ret != 0))
                return ret;

        mount_kretprobe.kp.symbol_name = "do_init_module";
        if (unlikely(register_kretprobe(&mount_kretprobe))) {
                pr_info(KBUILD_MODNAME ": impossibile to hook do_init_module function");
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
        unregister_kretprobe(&mount_kretprobe);
        pr_info(KBUILD_MODNAME ": successfully removed");
}

/* Module stuffs */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Protection against malicious LKM (Loadable Kernel Module)");

module_init(mlkm_shield_init);
module_exit(mlkm_shield_cleanup);
