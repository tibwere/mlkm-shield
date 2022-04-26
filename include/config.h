#ifndef _MLKM_SHIELD_CONFIG_H
#define _MLKM_SHIELD_CONFIG_H

#include <linux/types.h>


extern const bool PROTECT_SYS_CALL_TABLE;
extern const bool PROTECT_IDT;
extern const char *SAFE_SYMBOLS[];
extern const char *MODULE_WHITE_LIST[];
extern const char *MODULE_BLACK_LIST[];

#endif // !_MLKM_SHIELD_CONFIG_H
