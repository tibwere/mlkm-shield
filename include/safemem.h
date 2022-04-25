#ifndef _MLKM_SHIELD_SAFEMEM_H
#define _MLKM_SHIELD_SAFEMEM_H

#include <linux/types.h>
#include "shield.h"

#define SA_SYS_CALL_TABLE_IDX (0)
#define SA_IDT_IDX (1)
#define SA_ADDITIONAL_SYMBOLS_IDX (2)
#define NUM_AREAS (3)

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
extern struct safe_area *areas[NUM_AREAS];
extern size_t num_additional_symbols;

/* Prototypes */
void          cache_additional_symbols_mem_area(void);
int           cache_mem_area(const char *audit, unsigned long *start_address, int length, int index);
void          verify_safe_areas(struct monitored_module *the_module, bool need_to_attach);
inline void   revert_to_good_state(struct safe_area *a);
inline size_t count_additional_symbols(void);

#define cache_sys_call_table_mem_area() cache_mem_area("sys_call_table", get_system_call_table_address(), NR_syscalls, SA_SYS_CALL_TABLE_IDX)
#define cache_idt_mem_area() cache_mem_area("IDT", get_idt_address(), IDT_ULONG_COUNT, SA_IDT_IDX)

#endif // !_MLKM_SHIELD_SAFEMEM_H
