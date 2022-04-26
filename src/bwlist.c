#include <linux/types.h>
#include <linux/module.h>
#include <linux/string.h>
#include "config.h"

inline bool is_in_list(const char **list, const char *name)
{
        int i;
        for (i = 0; list[i] != NULL; ++i) {
                if (unlikely(strncmp(list[i], name, MODULE_NAME_LEN) == 0))
                        return true;
        }

        return false;
}
