/**
 * @file mlkm_shield.c
 * @brief This is the source file for the MLKM_SHIELD (Malicious Loadable Kernel Module).
 *
 * Taking advantage of the kretprobing mechanism offered by the Linux kernel, several internal kernel
 * functions are hooked (e.g. do_init_module, __tasklet_schedule_common) in order to verify the
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
} areas[NR_syscalls];


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
 * curr_module - address associated with the struct module being mounted
 */
static struct module *curr_module;

/**
 * cr0 - cached value of CR0 register
 * (used to unprotect/protect memory mechanism)
 */
static unsigned long cr0;

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
 * __get_kallsysm_lookup_name - helper function for retrieving the address where the
 * kallsyms_lookup_name function is present in memory
 *
 * @return function pointer (kallsyms_lookup_name_t type)
 */
static kallsyms_lookup_name_t __get_kallsysm_lookup_name(void)
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
        kallsyms_lookup_name_t kallsyms_lookup_name = __get_kallsysm_lookup_name();
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
	kallsyms_lookup_name_t kallsyms_lookup_name = __get_kallsysm_lookup_name();
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
static void __always_inline __write_to_cr0(unsigned long new) {
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
 * revert_to_good_state - Function that allows you to revert the changes
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
        free_module_t free_module;

        free_module = get_free_module();
        if (unlikely(free_module == NULL))
                pr_warn(KBUILD_MODNAME ": free_module symbol not found so it will be impossibile to remove module if necessary");

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

        atomic_set(&sync_leave, 0);
        preempt_enable();
        if (likely(good == 1)) {
                pr_info(KBUILD_MODNAME ": no threat detected");
        } else {
                if (free_module != NULL)
                        free_module(curr_module);
        }

        curr_module = NULL;
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
        curr_module = (struct module *)regs->di;
        pr_debug(KBUILD_MODNAME ": module \"%s\" (@ 0x%lx) installation is taking place on CPU core %d",
                curr_module->name, (unsigned long)curr_module, smp_processor_id());

        atomic_set(&sync_enter, num_online_cpus() - 1);
        atomic_set(&sync_leave, 1);

        preempt_disable();
        smp_call_function_many(cpu_online_mask, let_verify, NULL, false);

        while (atomic_read(&sync_enter) > 0);
        pr_debug(KBUILD_MODNAME ": all cores are syncronized");
        return 0;
}


/**
 * mount_kretprobe - kretprobe to hook to do_init_module
 */
static struct kretprobe mount_kretprobe = {
        .entry_handler       = atom_insmod,
        .handler             = verify_safe_areas,
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
