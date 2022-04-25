#ifndef _MLKM_SHIELD_SYNCRO_H
#define _MLKM_SHIELD_SYNCRO_H

#include <linux/types.h>

/* Variables declaration */
extern atomic_t sync_leave;


/* Prototypes */
inline void sync_worker(void *info);
inline void sync_master(void);

#endif // !_MLKM_SHIELD_SYNCRO_H
