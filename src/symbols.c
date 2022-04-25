#include <linux/kprobes.h>
#include <linux/version.h>
#include <asm/desc.h>

#include "symbols.h"


#if LINUX_VERSION_CODE > KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP (1)
#endif


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
 * symbol_lookup - as the name implies, it looks for the address associated
 * with a certain symbol in a differentiated way according to the
 * kernel version
 *
 * @param name: name of the symbol
 * @return      address of the symbol
 */
inline unsigned long symbol_lookup(const char *name)
{
#ifdef KPROBE_LOOKUP
	kallsyms_lookup_name_t kallsyms_lookup_name = __get_kallsyms_lookup_name();
        if (unlikely(kallsyms_lookup_name == NULL))
                return 0;
#endif
        return kallsyms_lookup_name(name);
}


/**
 * get_system_call_table_addres - function that allows to obtain the logical
 * address of the system call table in a differentiated way according to
 * the current version of the kernel
 *
 * @return sys_call_table address
 */
unsigned long *get_system_call_table_address(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
        return (unsigned long *)symbol_lookup("sys_call_table");
#else
        unsigned long *addr;
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

unsigned long *get_idt_address(void)
{
        struct desc_ptr idtr;
        memset(&idtr, 0x0, sizeof(struct desc_ptr));
        store_idt(&idtr);

        return (unsigned long *)idtr.address;
}
