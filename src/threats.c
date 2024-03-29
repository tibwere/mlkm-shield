/**
 * @file symbols.c
 * @brief file for managing the audit on /sys file system of information relating to identified threats
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
#include <linux/list.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include "threats.h"


/**
 * threat_list - list of identified threats
 */
static LIST_HEAD(threat_list);


/**
 * queue - queue in which to place requests to add threats
 */
struct workqueue_struct *queue;


/**
 * mu - mutex to regulate access to the threat list
 */
static struct mutex mu;


/**
 * draw_line - draws a dashed line useful for dividing the rows of the table
 *
 * @param buf: the buffer to write the dashes
 * @param ret: final length of buffer
 */
#define draw_line(buf, ret)                                             \
({                                                                      \
        for (i = 0; i < ROW_LEN; ++i)                                   \
                ret += snprintf(buf + ret, PAGE_SIZE - ret, "-");       \
        ret += snprintf(buf + ret, PAGE_SIZE - ret, "\n");              \
})


/**
 * threat_show - function responsible for showing the threats
 * detected in /sys
 *
 * @param kobj: kernel object (/sys/kernel/mlkm_shield)
 * @param attr: kernel attribute (/sys/kernel/mlkm_shield/threats)
 * @param buf:  buffer in which to store the requested data
 * @return      size of written data
 */
static ssize_t threats_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
        int ret, i;
        struct threat *t;

        ret = 0;
        draw_line(buf, ret);
        ret += snprintf(buf + ret, PAGE_SIZE - ret, HDR_FMT, "MODULE NAME (max 24 chr)", "ADDRESS", "GOOD VALUE", "HACKED VALUE");
        draw_line(buf, ret);

        mutex_lock(&mu);
        list_for_each_entry(t, &threat_list, links) {
                ret += snprintf(buf + ret, PAGE_SIZE - ret, ROW_FMT, t->short_name, t->address, t->saved, t->hacked);
                draw_line(buf, ret);
        }
        mutex_unlock(&mu);

        return ret;
}


/**
 * forbidden_store - makes it impossible to write threats info from /sys
 *
 * @param kobj:  not used
 * @param attr:  not used
 * @param buf:   not used
 * @param count: not used
 * @return       always -EACCESS
 */
static ssize_t forbidden_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
        return -EACCES;
}


/**
 * mlkm_shield_sys_kobj - object in /sys for audit threats
 */
struct kobject *mlkm_shield_sys_kobj;


/**
 * threats_attr - attribute for threat info in /sys
 */
static struct kobj_attribute threats_attr = __ATTR(threats, S_IRUSR | S_IRGRP, threats_show, forbidden_store);


/* Other minor stuff related to /sys audit */
static struct attribute *attrs[] = {
	&threats_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};
static struct attribute_group attr_group = {
	.attrs = attrs,
};


/**
 * init_threats_for_sys_audit - initialization function of the elements necessary
 * for the management of the audit on sys (e.g. mutex, workqueue)
 *
 * @return 0 if ok, -E otherwise
 */
int init_threats_for_sys_audit(void)
{
        mutex_init(&mu);
        queue = create_singlethread_workqueue("threats-sys-audit");
        if (unlikely(queue == NULL))
                return -ENOMEM;

        mlkm_shield_sys_kobj = kobject_create_and_add("mlkm_shield", kernel_kobj);
        if (unlikely(!mlkm_shield_sys_kobj))
                return -ENOMEM;


	if(unlikely(sysfs_create_group(mlkm_shield_sys_kobj, &attr_group)))
		kobject_put(mlkm_shield_sys_kobj);

        return 0;
}


/**
 * destroy_threats_for_sys_audit - cleanup function of the elements necessary
 * for the management of the audit on sys (e.g. mutex, workqueue)
 */
void destroy_threats_for_sys_audit(void)
{
        struct threat *t, *tmp;
        mutex_lock(&mu);
        list_for_each_entry_safe(t, tmp, &threat_list, links) {
                list_del(&(t->links));
                kfree(t);
        }
        mutex_unlock(&mu);
        destroy_workqueue(queue);
        kobject_put(mlkm_shield_sys_kobj);
}


/**
 * do_the_linkage - function performed by the kworker responsible for
 * inserting the new threat into the linked list
 *
 * @param work: work_struct as expected by the
 *              prototype contained in the struct
 */
static void do_the_linkage(struct work_struct *work)
{
        struct work_metadata *the_task = (struct work_metadata *)container_of((void *)work, struct work_metadata, the_work);
        mutex_lock(&mu);
        list_add(&(the_task->t->links), &threat_list);
        mutex_unlock(&mu);

        kfree(the_task);
        module_put(THIS_MODULE);
}


/**
 * insert_new_threat - function used to allocate memory for the addition
 * of the new threat and to schedule the insertion through deferred work
 *
 * @param malicious_lkm: malicious module that is the subject of the threat
 * @param sa:            attack target safe_area struct
 * @param hacked         new value specified by the attacker for the attacked area
 * @return               0 if ok, -E otherwise
 */
int insert_new_threat(struct module *malicious_lkm, struct safe_area *sa, unsigned long hacked)
{
        struct work_metadata *the_task;
        struct threat *t;

        if (!try_module_get(THIS_MODULE))
                return -ENODEV;

        the_task = (struct work_metadata *)kzalloc(sizeof(struct work_metadata), GFP_KERNEL);
        if(unlikely(the_task == NULL))
                return -ENOMEM;

        t = (struct threat *)kzalloc(sizeof(struct threat), GFP_KERNEL);
        if (unlikely(t == NULL)) {
                kfree(the_task);
                return -ENOMEM;
        }

        if (strlen(malicious_lkm->name) > SHORT_NAME_LEN) {
                strncpy(t->short_name, malicious_lkm->name, SHORT_NAME_LEN-1);
                t->short_name[SHORT_NAME_LEN-1] = '.';
        } else {
                strncpy(t->short_name, malicious_lkm->name, SHORT_NAME_LEN);
        }

        t->address = (unsigned long)sa->addr;
        t->saved = sa->value;
        t->hacked = hacked;

        the_task->t = t;

        INIT_WORK(&(the_task->the_work),do_the_linkage);
        queue_work(queue, &the_task->the_work);

        return 0;
}
