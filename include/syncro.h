/**
 * @file syncro.h
 * @brief header file for the IPI synchronization lookup stuffs (@see ${basedir}/src/syncro.c)
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
#ifndef _MLKM_SHIELD_SYNCRO_H
#define _MLKM_SHIELD_SYNCRO_H

#include <linux/types.h>


/* Variables declaration */
extern atomic_t sync_leave;


/* Prototypes */
void sync_worker(void *info);
inline void sync_master(void);

#endif // !_MLKM_SHIELD_SYNCRO_H
