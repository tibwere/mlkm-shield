#include <linux/module.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/kprobes.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP (1)
#endif

struct safe_area {
        unsigned long *addr;
        unsigned long value;
} *areas;

static struct kretprobe mount_module_krp;

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

static int cache_safe_areas(void)
{
        int i;
        unsigned long *system_call_table = get_system_call_table_address();
        if (unlikely(system_call_table == NULL))
                return -ENOMEM;

        pr_debug(KBUILD_MODNAME ": system call table address is 0x%p", system_call_table);

        areas = kzalloc(NR_syscalls * sizeof(struct safe_area), GFP_KERNEL);
        if (unlikely(areas == NULL))
                return -ENOMEM;

        for (i = 0; i < NR_syscalls; ++i) {
                areas[i].addr = &(system_call_table[i]);
                areas[i].value = system_call_table[i];
                pr_debug(KBUILD_MODNAME ": address 0x%p -> value %lu",
                        &(system_call_table[i]), system_call_table[i]);
        }

        return 0;
}

static int verify_safe_areas(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        int i;

        pr_info(KBUILD_MODNAME ": start analysis");
        for (i = 0; i < NR_syscalls; ++i) {
                if (*(areas[i].addr) != areas[i].value) {
                        pr_alert(KBUILD_MODNAME ": rootkit detected [memory at 0x%p has changed]", areas[i].addr);
                        return -EFAULT;
                }
        }

        pr_info(KBUILD_MODNAME ": no threat detected");

        return 0;
}

static int __init mlkm_shield_init(void)
{
        int ret;
        ret = cache_safe_areas();
        if (unlikely(ret != 0))
                return ret;

        mount_module_krp.kp.symbol_name = "load_module";
        mount_module_krp.handler = verify_safe_areas;
        ret = register_kretprobe(&mount_module_krp);

        if (unlikely(ret != 0)) {
                pr_info(KBUILD_MODNAME ": impossible to hook init_module function");
                return -EINVAL;
        }

        pr_info(KBUILD_MODNAME ": successfully initialized");

        return 0;
}

static void __exit mlkm_shield_cleanup(void)
{
        unregister_kretprobe(&mount_module_krp);
        pr_info(KBUILD_MODNAME ": successfully removed");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Protection against malicious LKM (Loadable Kernel Module)");

module_init(mlkm_shield_init);
module_exit(mlkm_shield_cleanup);
