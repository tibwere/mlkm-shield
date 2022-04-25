#ifndef _MLKM_SHIELD_SAFEMEM_H
#define _MLKM_SHIELD_SAFEMEM_H

#include <linux/types.h>

#include "shield.h"

/**
 * safe_area - structure representing a good-state cache of memory
 *
 * @member addr:  address of a critical location
 * @member value: value of the critical memory location
 */
struct safe_area {
        unsigned long *addr;
        unsigned long value;
};

/* Variables declaration */
extern struct safe_area *areas;
extern size_t num_areas;

/* Prototypes */
int         cache_safe_areas(void);
void        verify_safe_areas(struct monitored_module *the_module, bool need_to_attach);
inline void revert_to_good_state(struct safe_area *a);
size_t      safe_areas_length(void);


#endif // !_MLKM_SHIELD_SAFEMEM_H
