/**
 * @file asm/x86.h
 * @brief header file for x86 stuffs (@see ${basedir}/src/x86.c)
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
#ifndef _MLKM_SHIELD_X86_H
#define _MLKM_SHIELD_X86_H


/* Variables declaration */
extern unsigned long cr0;


/* Prototypes */
void force_write_cr0(unsigned long val);

/**
 * These macros allow you to delimit a portion of code that can be accessed
 * in an arbitrary way both on registers and in memory (thanks to the overwriting of cr0)
 */
#define START_UNPROTECTED_EDITING force_write_cr0(cr0 & ~X86_CR0_WP)
#define END_UNPROTECTED_EDITING   force_write_cr0(cr0)

#endif // !_MLKM_SHIELD_X86_H
