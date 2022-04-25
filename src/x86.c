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
