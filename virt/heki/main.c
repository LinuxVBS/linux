// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Common code
 *
 * Copyright © 2023 Microsoft Corporation
 */

#include <linux/heki.h>
#include <linux/mm.h>
#include <linux/xarray.h>
#include <asm-generic/sections.h>

#include "common.h"

bool heki_enabled __ro_after_init = true;
struct heki heki;
struct xarray init_permissions;

/*
 * This function should be implemented by the architecture-specific code
 * to provide the kernel's virtual address range that Heki has to walk to
 * gather permissions for sending them across to the hypervisor.
 */
int __weak heki_arch_get_kernel_va_range(unsigned long *start, unsigned long *end)
{
	return -EOPNOTSUPP;
}

/*
 * This function should be implemented by the architecture-specific code
 * to procees the mm flags for a pfn and return the heki permissions.
 */
int __weak heki_arch_flags_to_perm(unsigned long pfn, unsigned long addr, unsigned long flags,
				   unsigned long *perm)
{
	return -EOPNOTSUPP;
}

bool __weak heki_arch_protect_pfn(unsigned long pfn, unsigned long perm)
{
		return false;
}

static void heki_collect_initial_permissions(phys_addr_t pa, unsigned long addr,
					     unsigned long size, unsigned long flags)
{
	unsigned long pfn, perm, cur_perm;
	phys_addr_t pa_cur, pa_end;
	unsigned long va_cur = addr;
	int ret;

	pa_end = pa + size;
	for (pa_cur = pa; pa_cur < pa_end; pa_cur += PAGE_SIZE, va_cur += PAGE_SIZE) {
		pfn = pa_cur >> PAGE_SHIFT;
		perm = 0;
		ret = heki_arch_flags_to_perm(pfn, va_cur, flags, &perm);
		if (ret)
			break;
		cur_perm = (unsigned long)xa_load(&init_permissions, pfn);
		if (cur_perm)
			perm |= cur_perm;
		/* Store the permissions in the xarray */
		xa_store(&init_permissions, pfn, (void *)perm, GFP_KERNEL);
	}
}

static void heki_build_memory_page(void *buf, int *count)
{
	struct heki_protect_memory mem;
	struct heki_protect_memory *buf_ptr = (struct heki_protect_memory *)buf;
	unsigned long perm, prev_perm = 0;
	unsigned long pfn, start_pfn, prev_pfn = 0;
	void *entry;
	bool start_gather = false;

	*count = 0;
	/* Group contigous memory with same permissions so that number of entries in the
	 * page is limited.
	 */
	xa_for_each(&init_permissions, pfn, entry) {
		perm = (unsigned long)entry;
		if (!heki_arch_protect_pfn(pfn, perm))
			continue;
		if (perm != prev_perm || pfn != prev_pfn + 1) {
			if (start_gather) {
				mem.start_pfn = start_pfn;
				mem.end_pfn = prev_pfn + 1;
				mem.perm = prev_perm;
				memcpy(buf_ptr, &mem, sizeof(mem));
				buf_ptr++;
				(*count)++;
			}
			start_pfn = pfn;
			start_gather = true;
		}
		prev_pfn = pfn;
		prev_perm = perm;
	}

	/* Handle the last entry */
	if (start_gather) {
		mem.start_pfn = start_pfn;
		mem.end_pfn = prev_pfn + 1;
		mem.perm = prev_perm;
		memcpy(buf_ptr, &mem, sizeof(mem));
		(*count)++;
	}
}

static void heki_establish_initial_memory_protection(void)
{
	unsigned long va_start, va_end;
	struct page *page;
	int ret, mem_page_entries, i;
	struct heki_protect_memory *mem;
	struct heki_hypervisor *hypervisor = heki.hypervisor;

	if (!hypervisor->protect_memory)
		return;

	ret = heki_arch_get_kernel_va_range(&va_start, &va_end);
	if (ret) {
		pr_err("Failed to get kernel VA range for walk to establish initial memory protection\n");
		return;
	}

	/*
	 * Allocate a page to send to the hypervisor pfns and the permissions to be placed on them.
	 * Requests are built in the form of start_pfn, end_pfn, permissions each field being
	 * unsigned long. In the current format a page can hold 170 entries assuming unsigned
	 * long is 64 bits.
	 */

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("Failed to allocate memory page for initial memory protection\n");
		return;
	}

	heki_walk(va_start, va_end, heki_collect_initial_permissions);
	memset(page_address(page), 0, PAGE_SIZE);
	heki_build_memory_page(page_address(page), &mem_page_entries);
	if (hypervisor->protect_memory(page_to_pfn(page), mem_page_entries))
		pr_err("Failed to establish initial kernel memory protection with hypervisor\n");
	else
		pr_info("Established initial kernel memory protection with hypervisor\n");
	for (i = 0; i < mem_page_entries; i++) {
		mem = (struct heki_protect_memory *)(page_address(page) + i * sizeof(struct heki_protect_memory));
		pr_err("%s: Start PA: %lx, End PA: %lx, Permissions: %lx, Size: %d\n",
		       __func__, mem->start_pfn, mem->end_pfn, mem->perm, (mem->end_pfn - mem->start_pfn) << PAGE_SHIFT);
	}
	__free_page(page);
}

/*
 * Must be called after mark_readonly().
 */
void heki_late_init(void)
{
	struct heki_hypervisor *hypervisor = heki.hypervisor;
	int ret;

	if (!heki_enabled || !heki.hypervisor)
		return;

	/* Locks control registers so a compromised guest cannot change them. */
	if (hypervisor->lock_crs)
		ret = hypervisor->lock_crs();

	if (ret)
		pr_warn("Unable to lock down control registers\n");
	else
		pr_warn("Control registers locked\n");

	xa_init(&init_permissions);
	heki_establish_initial_memory_protection();
	/*
	 * Signal end of kernel boot.
	 * This means all boot time lvbs protections are in place and protections on
	 * many of the resources cannot be altered now.
	 */
	if (hypervisor->finish_boot)
		hypervisor->finish_boot();
}

void heki_register_hypervisor(struct heki_hypervisor *hypervisor)
{
	heki.hypervisor = hypervisor;
}

static int __init heki_parse_config(char *str)
{
	if (kstrtobool(str, &heki_enabled))
		pr_warn("Invalid option string for heki: '%s'\n", str);
	return 1;
}
__setup("heki=", heki_parse_config);
