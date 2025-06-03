/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common definition for enabling VTL1 and VSM.
 *
 * Copyright (c) 2025, Microsoft Corporation.
 *
 * Author:
 *
 */

#ifndef _VSM_H
#define _VSM_H

#include <linux/types.h>
#include <linux/align.h>

/* Define PAGE size and related variables for initial secure kernel pages */
#define VSM_PAGE_SHIFT			12
#define VSM_PAGE_SIZE			(((uint32_t)1) << VSM_PAGE_SHIFT)
#define PAGE_AT(addr, idx)		((addr) + (idx) * VSM_PAGE_SIZE)
#define VSM_VA_FROM_PA(pa)		(pa) // Assumes identity mapping in secure kernel

/* Number of entries in a page table (all levels) */
#define VSM_ENTRIES_PER_PT		512
#define VSM_PMD_SIZE			(VSM_PAGE_SIZE * VSM_ENTRIES_PER_PT)

/*
 * Initial memory that will be mapped for secure kernel.
 * Secure Kernel memory can be larger than this.
 */
#define VSM_SK_INITIAL_MAP_SIZE		(16 * 1024 * 1024)
#define VSM_SK_PTE_PAGES_COUNT	(ALIGN(VSM_SK_INITIAL_MAP_SIZE, VSM_PMD_SIZE) / VSM_PMD_SIZE)

/* VSM pages */
enum {
	VSM_GDT_PAGE,
	VSM_TSS_PAGE,
	VSM_PML4E_PAGE,
	VSM_PDPE_PAGE,
	VSM_PDE_PAGE,
	VSM_PTE_PAGES,
	/* PTE tables consume several pages */
	VSM_KERNEL_STACK_PAGE = VSM_PTE_PAGES + VSM_SK_PTE_PAGES_COUNT,
	/* Kernel boot pages */
	VSM_BOOT_PARAMS_PAGE,
	VSM_CMDLINE_PAGE,
	VSM_PAGES_COUNT
};

#define VSM_PAGES_SIZE          (VSM_PAGES_COUNT << VSM_PAGE_SHIFT)

struct hv_vtlcall_param {
	u64	a0;
	u64	a1;
	u64	a2;
	u64	a3;
} __packed;

#endif /* _VSM_H */
