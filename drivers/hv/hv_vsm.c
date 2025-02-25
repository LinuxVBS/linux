// SPDX-License-Identifier: GPL-2.0-only
/*
 * VSM framework that enables VTL1, loads secure kernel and boots VTL1.
 *
 * Copyright © 2024 Microsoft Corporation
 */

#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/heki.h>
#include <asm/mshyperv.h>
#include "hv_vsm.h"

static int hv_vsm_lock_crs(void)
{
	cpumask_var_t orig_mask;
	struct hv_vtlcall_param args = {0};
	int cpu, ret = 0;

	args.a0 = VSM_VTL_CALL_FUNC_ID_LOCK_REGS;

	if (!alloc_cpumask_var(&orig_mask, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto out;
	}
	cpumask_copy(orig_mask, &current->cpus_mask);
	/*
	 * ToDo: Spin off separate threads on each cpu to do this.
	 * Should be better from a performance point of view.
	 * Irrespective this thread should wait until all cpus have locked
	 * the registers
	 */
	for_each_online_cpu(cpu) {
		set_cpus_allowed_ptr(current, cpumask_of(cpu));
		ret = hv_vsm_vtlcall(&args);
		if (ret) {
			pr_err("%s: Unable to lock registers for cpu%d..Aborting\n",
			       __func__, cpu);
			break;
		}
	}
	set_cpus_allowed_ptr(current, orig_mask);
	free_cpumask_var(orig_mask);

out:
	return ret;
}

static struct heki_hypervisor hyperv_heki_hypervisor = {
	.lock_crs = hv_vsm_lock_crs,
};

int __init hv_vsm_init_heki(void)
{
	heki_register_hypervisor(&hyperv_heki_hypervisor);

	return 0;
}
