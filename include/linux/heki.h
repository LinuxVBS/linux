/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Definitions
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __HEKI_H__
#define __HEKI_H__

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>

#define HEKI_MEM_ATTR_READ		BIT(0)
#define HEKI_MEM_ATTR_WRITE		BIT(1)
#define HEKI_MEM_ATTR_EXECUTE		BIT(2)

struct heki_protect_memory {
	unsigned long start_pfn;
	unsigned long end_pfn;
	unsigned long perm;
};

/*
 * A hypervisor that supports Heki will instantiate this structure to
 * provide hypervisor specific functions for Heki.
 */
struct heki_hypervisor {
	/* Lock control registers. */
	int (*lock_crs)(void);

	/* Signal end of kernel boot */
	int (*finish_boot)(void);

	/* Set memory permissions for entries in the page.
	 * Entries are in the form of struct heki_protect_memory
	 */
	int (*protect_memory)(unsigned long page_pfn, int entries);
};

#ifdef CONFIG_HEKI

void heki_late_init(void);
void heki_register_hypervisor(struct heki_hypervisor *hypervisor);
int heki_arch_get_kernel_va_range(unsigned long *start, unsigned long *end);
int heki_arch_flags_to_perm(unsigned long pfn, unsigned long addr, unsigned long flags,
			    unsigned long *perm);
bool heki_arch_protect_pfn(unsigned long pfn, unsigned long perm);

#else /* !CONFIG_HEKI */

static inline void heki_late_init(void) { }
static inline void heki_register_hypervisor(struct heki_hypervisor *hypervisor) { }

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
