// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Kernel page table walker.
 *
 * Copyright © 2023 Microsoft Corporation
 *
 */

#include <linux/heki.h>
#include <linux/pagewalk.h>
#include "common.h"

static int heki_pte_entry(pte_t *pte, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	phys_addr_t pa;
	heki_func_t func = walk->private;

	if (!pte_present(*pte))
		return 0; /* Skip empty PTE entries */
	pa = pte_pfn(*pte) << PAGE_SHIFT;
	pa += addr & (PAGE_SIZE - 1);
	if (func)
		func(pa, addr, next - addr, pte_flags(*pte));
	return 0;
}

static int heki_pmd_entry(pmd_t *pmd, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	phys_addr_t pa;
	heki_func_t func = walk->private;

	if (!pmd_present(*pmd))
		return 0; /* Skip empty PMD entries */
	if (pmd_leaf(*pmd)) {
		pa = pmd_pfn(*pmd) << PAGE_SHIFT;
		pa += addr & (PMD_SIZE - 1);
		if (func)
			func(pa, addr, next - addr, pmd_flags(*pmd));
		walk->action = ACTION_CONTINUE;
	}
	return 0;
}

static int heki_pud_entry(pud_t *pud, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	phys_addr_t pa;
	heki_func_t func = walk->private;

	if (!pud_present(*pud))
		return 0; /* Skip empty PUD entries */
	if (pud_leaf(*pud)) {
		pa = pud_pfn(*pud) << PAGE_SHIFT;
		pa += addr & (PUD_SIZE - 1);
		if (func)
			func(pa, addr, next - addr, pud_flags(*pud));
		walk->action = ACTION_CONTINUE;
	}
	return 0;
}

static int heki_p4d_entry(p4d_t *p4d, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	phys_addr_t pa;
	heki_func_t func = walk->private;

	if (!p4d_present(*p4d))
		return 0; /* Skip empty P4D entries */
	if (p4d_leaf(*p4d)) {
		pa = p4d_pfn(*p4d) << PAGE_SHIFT;
		pa += addr & (P4D_SIZE - 1);
		if (func)
			func(pa, addr, next - addr, p4d_flags(*p4d));
		walk->action = ACTION_CONTINUE;
	}
	return 0;
}

static int heki_pgd_entry(pgd_t *pgd, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	phys_addr_t pa;
	heki_func_t func = walk->private;

	if (!pgd_present(*pgd))
		return 0; /* Skip empty PGD entries */
	if (pgd_leaf(*pgd)) {
		pa = pgd_pfn(*pgd) << PAGE_SHIFT;
		pa += addr & (PGDIR_SIZE - 1);
		if (func)
			func(pa, addr, next - addr, pgd_flags(*pgd));
		walk->action = ACTION_CONTINUE;
	}
	return 0;
}

static const struct mm_walk_ops heki_walk_ops = {
	.pgd_entry	= heki_pgd_entry,
	.p4d_entry	= heki_p4d_entry,
	.pud_entry	= heki_pud_entry,
	.pmd_entry	= heki_pmd_entry,
	.pte_entry	= heki_pte_entry,
};

void heki_walk(unsigned long va, unsigned long va_end, heki_func_t func)
{
	mmap_read_lock(&init_mm);
	walk_kernel_page_table_range(va, va_end, &heki_walk_ops, init_mm.pgd, func);
	mmap_read_unlock(&init_mm);
}
