#include <linux/types.h>
#include <linux/smp.h>


/**
 * sync_enter - synchronization barrier on which the master spins
 * until all workers have started executing the function
 */
static atomic_t sync_enter __attribute__((aligned(64)));

/**
 * sync_leave - synchronization barrier on which the worker spins
 * until the master has completed verification
 */
atomic_t sync_leave __attribute__((aligned(64)));


/**
 * sync_worker - function used to make the other CPU cores wait actively
 * (via a spin on the barrier variable) as long as the module is being assembled
 *
 * @param info: not used
 */
inline void sync_worker(void *info)
{
        unsigned int cpuid;
        cpuid = smp_processor_id();

        pr_debug(KBUILD_MODNAME ": core %d wait until verification is completed", cpuid);

        atomic_dec(&sync_enter);
        // preempt_disable();
        // while(atomic_read(&sync_leave) > 0);
        // preempt_enable();

        pr_debug(KBUILD_MODNAME ": core %d resumes work left earlier", cpuid);
}


/**
 * __sync_master - function that allows you to request the execution of sync_worker
 * function to the other CPU cores online
 */
inline void sync_master(void)
{
        atomic_set(&sync_enter, num_online_cpus() - 1);
        atomic_set(&sync_leave, 1);

        preempt_disable();
        smp_call_function_many(cpu_online_mask, sync_worker, NULL, false);

        while (atomic_read(&sync_enter) > 0);
        pr_debug(KBUILD_MODNAME ": all cores are syncronized");
}


