#ifndef __H_MLKM_SHIELD_X86__
#define __H_MLKM_SHIELD_X86__


/**
 * cr0 - cached value of CR0 register
 * (used to unprotect/protect memory mechanism)
 */
static unsigned long cr0;


/**
 * force_write_cr0 - function that uses inline ASM to overwrite the CR0 register
 * (see https://elixir.bootlin.com/linux/v5.17.3/source/arch/x86/include/asm/special_insns.h#L54)
 *
 * @param val: new value to store in CR0 register
 */
static inline void force_write_cr0(unsigned long val)
{
        asm volatile("mov %0,%%cr0": : "r" (val) : "memory");
}

/**
 * These macros allow you to delimit a portion of code that can be accessed
 * in an arbitrary way both on registers and in memory (thanks to the overwriting of cr0)
 */
#define START_UNPROTECTED_EDITING force_write_cr0(cr0 & ~0x00010000)
#define END_UNPROTECTED_EDITING   force_write_cr0(cr0)


#endif // !__H_MLKM_SHIELD_X86__
