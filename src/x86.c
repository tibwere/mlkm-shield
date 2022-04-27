/**
 * @file x86.c
 * @brief architecture specific task management file (x86_64 only)
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


/**
 * cr0 - cached value of CR0 register
 * (used to unprotect/protect memory mechanism)
 */
unsigned long cr0;


/**
 * force_write_cr0 - function that uses inline ASM to overwrite the CR0 register
 * (see https://elixir.bootlin.com/linux/v5.17.3/source/arch/x86/include/asm/special_insns.h#L54)
 *
 * @param val: new value to store in CR0 register
 */
inline void force_write_cr0(unsigned long val)
{
        asm volatile("mov %0,%%cr0": : "r" (val) : "memory");
}
