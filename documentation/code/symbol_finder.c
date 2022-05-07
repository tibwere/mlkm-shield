#include <linux/module.h>
#include <linux/kprobes.h>

#define SYMBOL_NAME "__tasklet_schedule"

static int symbol_finder_init(void)
{
        int retval;
        struct kprobe kp = {
                .symbol_name = SYMBOL_NAME
        };

        if ((retval = register_kprobe(&kp)) == 0) {
                pr_info(KBUILD_MODNAME ": %s symbol fount at address: 0x%p", SYMBOL_NAME, kp.addr);
                unregister_kprobe(&kp);
                return 0;
        }

        pr_info(KBUILD_MODNAME ": %s symbol not found! (retval: %d)", SYMBOL_NAME, retval);

        return 0;
}

static void symbol_finder_clean(void) {pr_debug(KBUILD_MODNAME ": removing ...");}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Symbol finder utiliy");

module_init(symbol_finder_init);
module_exit(symbol_finder_clean);
