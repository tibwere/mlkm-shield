#include <linux/module.h>
#include <linux/printk.h>

int dummy_init(void)
{
        pr_info(KBUILD_MODNAME ": dummy module init");
        return 0;
}

void dummy_exit(void)
{
        pr_info(KBUILD_MODNAME ": dummy module cleanup");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Dummy module to evaluate performances of MLKM shield module");
module_init(dummy_init);
module_exit(dummy_exit);

