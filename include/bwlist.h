#ifndef _MLKM_SHIELD_BWLIST_H
#define _MLKM_SHIELD_BWLIST_H

#include <linux/types.h>
#include "config.h"

inline bool is_in_list(const char **list, const char *name);

#define is_in_white_list(name) is_in_list(MODULE_WHITE_LIST, name)
#define is_in_black_list(name) is_in_list(MODULE_BLACK_LIST, name)

#endif // !_MLKM_SHIELD_BWLIST_H
