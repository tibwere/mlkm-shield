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
#define START_UNPROTECTED_EDITING force_write_cr0(cr0 & ~0x00010000)
#define END_UNPROTECTED_EDITING   force_write_cr0(cr0)

#endif // !_MLKM_SHIELD_X86_H
