/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common header
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef _HEKI_COMMON_H

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "heki-guest: " fmt

/*
 * If the active hypervisor supports Heki, it will plug its heki_hypervisor
 * pointer into this heki structure.
 */
struct heki {
	struct heki_hypervisor *hypervisor;
};

/* Callback function called by the table walker. */
typedef void (*heki_func_t)(phys_addr_t pa, unsigned long addr, unsigned long size,
			    unsigned long flags);

void heki_walk(unsigned long va, unsigned long va_end, heki_func_t func);

#endif /* _HEKI_COMMON_H */
