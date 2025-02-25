// SPDX-License-Identifier: GPL-2.0
/*
 * VSM boot framework that enables VTL1, loads secure kernel
 * and boots VTL1.
 *
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */

#define pr_fmt(fmt) "vsm: " fmt

#include <linux/hyperv.h>
#include <linux/cpumask.h>
#include <linux/namei.h>
#include <linux/acpi.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <hyperv/vsm.h>
#include <asm/e820/types.h>
#include <asm/mshyperv.h>
#include "mshv.h"
#include "hv_vsm.h"

#define HV_VTL1_ENABLE_BIT	BIT(1)
#define SK_PATH			"/usr/lib/firmware/vmlinux"
#define VSM_PAGES_SIZE		(VSM_PAGES_COUNT << VSM_PAGE_SHIFT)
#define VSM_BOOT_SIGNAL		0xDC
#define VSM_MAX_BOOT_CPUS       96

static phys_addr_t vsm_skm_pa;
static void *vsm_skm_va;
static struct task_struct **ap_thread;
static u8 *boot_signal;

/*
 * By default, when a processor boots in VTL1, we assume that MBEC (Mode-Based Execution Control)
 * support is also enabled. MBEC distinguishes between user and kernel memory execution permissions.
 * After the processor boots in VTL1, we verify whether MBEC is actually enabled. If it is not,
 * we set a global flag to false. This flag is shared across all processors—if any processor fails
 * to enable MBEC, the system treats MBEC as disabled.
 */
bool hv_vsm_mbec_enabled = true;

static int hv_vsm_get_register(u32 reg_name, u64 *result)
{
	struct hv_register_assoc reg = {
		.name = reg_name,
	};
	union hv_input_vtl input_vtl = {
		.as_uint8 = 0,
	};
	int ret;

	ret = hv_call_get_vp_registers(HV_VP_INDEX_SELF,
				       HV_PARTITION_ID_SELF,
				       1, input_vtl, &reg);
	if (ret)
		return ret;

	*result = reg.value.reg64;
	return 0;
}

static __init struct page *hv_vsm_alloc_shared_page(void)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("Unable to establish VTL0-VTL1 shared page\n");
		return ERR_PTR(-ENOMEM);
	}

	memset(page_address(page), 0, PAGE_SIZE);
	return page;
}

static Elf64_Addr __init hv_vsm_elf_min_load_paddr(void *image)
{
	Elf64_Ehdr *ehdr = image;
	Elf64_Phdr *phdr = image + ehdr->e_phoff;
	Elf64_Addr paddr = ULLONG_MAX;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_paddr < paddr)
			paddr = phdr->p_paddr;
	}

	return paddr;
}

static size_t __init hv_vsm_elf_binary_size(void *image)
{
	Elf64_Ehdr *ehdr = image;
	Elf64_Phdr *phdr = image + ehdr->e_phoff;
	Elf64_Addr min_paddr, max_paddr = 0;
	int i;

	min_paddr = hv_vsm_elf_min_load_paddr(image);
	if (min_paddr == ULLONG_MAX)
		return 0;

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type != PT_LOAD)
			continue;

		max_paddr = max(max_paddr, phdr->p_paddr + phdr->p_filesz);
	}

	return max_paddr - min_paddr;
}

static int __init hv_vsm_load_elf(void *image, Elf64_Addr *sk_entry_pa)
{
	Elf64_Ehdr *ehdr = image;
	Elf64_Phdr *phdr = image + ehdr->e_phoff;
	Elf64_Addr min_paddr;
	size_t size;
	void *base_addr;
	int i;

	/* Align the base load address up to the first segment alignment */
	base_addr = PTR_ALIGN(vsm_skm_va + phdr->p_align, phdr->p_align);
	if (base_addr < vsm_skm_va + VSM_PAGES_SIZE) {
		pr_err("VSM pages overlap with secure kernel load address\n");
		return -ENOSPC;
	}

	size = hv_vsm_elf_binary_size(image);
	if (vsm_skm_va + VSM_SK_INITIAL_MAP_SIZE - base_addr < size) {
		pr_err("secure kernel does not fit: %lu > %lu\n", size,
		       vsm_skm_va + VSM_SK_INITIAL_MAP_SIZE - base_addr);
		return -EFBIG;
	}

	pr_debug("secure kernel binary size: %#lx\n", size);

	min_paddr = hv_vsm_elf_min_load_paddr(image);
	if (min_paddr == ULLONG_MAX) {
		pr_err("Secure kernel does not have loadable segments\n");
		return -EINVAL;
	}

	pr_debug("secure kernel minimal paddr: %#llx\n", min_paddr);

	pr_debug("loading secure kernel ELF segments:\n");

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		void *load_addr;

		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_align % SZ_2M) {
			pr_err("LOAD segment is not aligned by 2MB\n");
			return -EINVAL;
		}

		/*
		 * Adjust the load address by min_paddr to compensate the
		 * offset.
		 */
		load_addr = base_addr + (phdr->p_paddr - min_paddr);

		pr_debug("  p_offset: %#016llx, p_filesz: %#016llx, p_memsz: %#016llx to pa %#016llx\n",
			 phdr->p_offset, phdr->p_filesz, phdr->p_memsz,
			 virt_to_phys(load_addr));
		memcpy(load_addr, image + phdr->p_offset, phdr->p_filesz);

		if (phdr->p_memsz == phdr->p_filesz)
			continue;

		pr_debug("    zeroing %#016llx bytes at pa %#016llx\n",
			 phdr->p_memsz - phdr->p_filesz,
			 virt_to_phys(load_addr + phdr->p_filesz));
		memset(load_addr + phdr->p_filesz, 0,
		       phdr->p_memsz - phdr->p_filesz);
	}

	*sk_entry_pa = virt_to_phys(base_addr + (ehdr->e_entry - min_paddr));
	pr_debug("secure kernel entry pa: %#llx\n", *sk_entry_pa);

	return 0;
}

static void __init add_e820_entry(struct boot_params *bootparams,
				  u64 start_addr, u64 end_addr, u32 type)
{
	struct boot_e820_entry *entry = &bootparams->e820_table[bootparams->e820_entries++];

	entry->addr = start_addr;
	entry->size = end_addr - start_addr;
	entry->type = type;
}

static void __init hv_vsm_add_acpi_e820(struct boot_params *bp)
{
	int i;
	struct boot_e820_entry *entry;

	for (i = 0; i < boot_params.e820_entries; i++) {
		entry = &boot_params.e820_table[i];

		if (entry->type != E820_TYPE_ACPI)
			continue;

		add_e820_entry(bp, entry->addr, entry->addr + entry->size,
			       E820_TYPE_ACPI);
	}
}

static void __init hv_vsm_build_boot_params(void)
{
	struct boot_params *bootparams = PAGE_AT(vsm_skm_va, VSM_BOOT_PARAMS_PAGE);
	char *cmdline = PAGE_AT(vsm_skm_va, VSM_CMDLINE_PAGE);
	u64 cmd_line_ptr = (u64)VSM_VA_FROM_PA(PAGE_AT(vsm_skm_pa, VSM_CMDLINE_PAGE));
	u64 start_phys_mem = sk_res.start;
	u64 end_phys_mem = sk_res.end + 1;
	u64 total_mem = max_pfn << PAGE_SHIFT;

	snprintf(cmdline, VSM_PAGE_SIZE,
		 "debug rootwait console=ttyS1,115200 earlyprintk=ttyS1,115200 cpuidle.off=1 cpufreq.off=1 idle=halt initcall_blacklist=do_init_real_mode,sbf_init maxcpus=1 noxsave possible_cpus=%u",
		 num_possible_cpus());

	bootparams->hdr.type_of_loader = 0xFF;
	bootparams->hdr.hardware_subarch = X86_SUBARCH_LGUEST;
	bootparams->hdr.cmd_line_ptr = cmd_line_ptr & 0xFFFFFFFF;
	bootparams->ext_cmd_line_ptr = (cmd_line_ptr >> 32) & 0xFFFFFFFF;
	bootparams->acpi_rsdp_addr = acpi_os_get_root_pointer();
	bootparams->e820_entries = 0;

	add_e820_entry(bootparams, 0, start_phys_mem, E820_TYPE_RESERVED);
	add_e820_entry(bootparams, start_phys_mem, end_phys_mem, E820_TYPE_RAM);
	add_e820_entry(bootparams, end_phys_mem, total_mem, E820_TYPE_RESERVED);

	hv_vsm_add_acpi_e820(bootparams);
}

static void * __init hv_vsm_read_file(const char *path, size_t *size)
{
	struct file *filp;
	char *buffer;
	int ret = 0;

	filp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(filp))
		return ERR_CAST(filp);

	*size = i_size_read(file_inode(filp));

	buffer = kvmalloc(*size, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto close_filp;
	}

	if (kernel_read(filp, buffer, *size, &filp->f_pos) != *size) {
		ret = -EIO;
		goto free_buf;
	}

close_filp:
	filp_close(filp, NULL);
	return ret ? ERR_PTR(ret) : buffer;

free_buf:
	kvfree(buffer);
	goto close_filp;
}

static void __init *hv_vsm_read_elf(const char *path, size_t *size)
{
	void *image;
	Elf64_Ehdr *ehdr;
	int ret;

	if (!path)
		return ERR_PTR(-EINVAL);

	image = hv_vsm_read_file(path, size);
	if (IS_ERR(image)) {
		pr_err("Failed to read %s file: %ld\n", path,
		       PTR_ERR(image));
		return image;
	}

	ehdr = image;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) ||
	    (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
	    !elf_check_arch(ehdr)) {
		pr_err("Not a valid ELF file: %s\n", path);
		ret = -ENOEXEC;
		goto out_free;
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		pr_err("Not a 64-bit compatible ELF file: %s\n", path);
		ret = -ENOEXEC;
		goto out_free;
	}

	return image;

out_free:
	kvfree(image);
	return ERR_PTR(ret);
}

static int __init hv_vsm_load_secure_kernel(Elf64_Addr *sk_entry_pa)
{
	struct path p;
	size_t size;
	void *image;
	int ret;

	compiletime_assert(VSM_SK_PTE_PAGES_COUNT <= VSM_ENTRIES_PER_PT,
			   "VSM page table can't accommodate secure kernel.");
	compiletime_assert(sizeof(struct boot_params) <= VSM_PAGE_SIZE,
			   "VSM page can't accommodate boot params.");

	if (kern_path(SK_PATH, LOOKUP_FOLLOW, &p)) {
		pr_err("File %s not found\n", SK_PATH);
		return -ENOENT;
	}

	path_put(&p);

	image = hv_vsm_read_elf(SK_PATH, &size);
	if (IS_ERR(image))
		return PTR_ERR(image);

	hv_vsm_build_boot_params();

	ret = hv_vsm_load_elf(image, sk_entry_pa);
	kvfree(image);

	return ret;
}

static int __init hv_vsm_enable_vp_vtl(Elf64_Addr sk_entry_pa)
{
	u64 status = 0;
	unsigned long flags;
	struct hv_enable_vp_vtl *hvin = NULL;

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(hvin, 0, sizeof(*hvin));

	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->vp_index = HV_VP_INDEX_SELF;
	hvin->target_vtl.target_vtl = HV_VTL_SECURE;

	hv_vsm_arch_init_vp(&hvin->vp_context, sk_entry_pa, vsm_skm_pa);

	local_irq_save(flags);
	status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, hvin, NULL);
	local_irq_restore(flags);

	return (int)(status & HV_HYPERCALL_RESULT_MASK);
}

static int hv_vsm_get_vp_status(u16 *enabled_vtl_set, u8 *active_mbec_enabled)
{
	u64 result;
	int ret;
	union hv_register_vsm_vp_status vsm_vp_status = { 0 };

	ret = hv_vsm_get_register(HV_REGISTER_VSM_VP_STATUS, &result);
	if (ret)
		return ret;

	vsm_vp_status = (union hv_register_vsm_vp_status)result;
	*enabled_vtl_set = vsm_vp_status.enabled_vtl_set;
	*active_mbec_enabled = vsm_vp_status.active_mbec_enabled;

	return 0;
}

static int __init hv_vsm_enable_partition_vtl(void)
{
	u64 status = 0;
	unsigned long flags;
	struct hv_input_enable_partition_vtl *hvin = NULL;

	local_irq_save(flags);

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(hvin, 0, sizeof(*hvin));

	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->target_vtl.as_uint8 = 1;
	hvin->flags.enable_mbec = 1;

	status = hv_do_hypercall(HVCALL_ENABLE_PARTITION_VTL, hvin, NULL);
	if (hv_result(status))
		pr_err("Enable Partition VTL failed. status=0x%x\n",
		       hv_result(status));

	local_irq_restore(flags);

	return hv_result(status);
}

static int hv_vsm_get_partition_status(u16 *enabled_vtl_set, u8 *max_vtl, u16 *mbec_enabled_vtl_set)
{
	u64 result;
	int ret;
	union hv_register_vsm_partition_status vsm_partition_status = { 0 };

	ret = hv_vsm_get_register(HV_REGISTER_VSM_PARTITION_STATUS, &result);
	if (ret)
		return ret;

	vsm_partition_status = (union hv_register_vsm_partition_status)result;
	*enabled_vtl_set = vsm_partition_status.enabled_vtl_set;
	*max_vtl = vsm_partition_status.max_vtl;
	*mbec_enabled_vtl_set = vsm_partition_status.mbec_enabled_vtl_set;
	return 0;
}

static __init int hv_vsm_boot_sec_vp_thread_fn(void *unused)
{
	struct hv_vtlcall_param args = {0};
	unsigned long flags = 0;
	int cpu = smp_processor_id(), next_cpu;
	u16 vp_enabled_vtl_set = 0;
	u8 active_mbec_enabled = 0;
	int ret;

	if (cpu > (VSM_MAX_BOOT_CPUS - 1)) {
		pr_err("CPU%d: Secure Kernel currently supports CPUID <= %d.",
		       smp_processor_id(), (VSM_MAX_BOOT_CPUS - 1));
		return -EINVAL;
	}

	pr_info("cpu%d entering vtl1 boot thread\n", cpu);
	local_irq_save(flags);
	while (READ_ONCE(boot_signal[cpu]) != VSM_BOOT_SIGNAL) {
		if (kthread_should_stop()) {
			local_irq_restore(flags);
			goto out;
		}
	}

	local_irq_restore(flags);
	hv_vsm_init_vtlcall(&args);
out:
	next_cpu = cpumask_next(cpu, cpu_online_mask);
	if (next_cpu > 0 && next_cpu < nr_cpu_ids) {
		wake_up_process(ap_thread[next_cpu]);
		pr_info("cpu%d exiting vtl1 boot thread. Waking up cpu%d\n",
			cpu, next_cpu);
	}

	ret = hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
	if (ret)
		return ret;

	if (!active_mbec_enabled) {
		pr_err("Failed to enable MBEC for VP%d\n", cpu);
		hv_vsm_mbec_enabled = false;
	}
	return 0;
}

static __init int hv_vsm_boot_ap_vtl(void)
{
	struct hv_vtlcall_param args = {0};
	struct page *boot_signal_page, *cpu_online_page;
	unsigned int cpu, cur_cpu = smp_processor_id(), vsm_cpus = num_possible_cpus(), next_cpu;
	int ret = 0;

	/* Allocate & Initialize Boot Signal Page */
	boot_signal_page = hv_vsm_alloc_shared_page();
	if (IS_ERR(boot_signal_page))
		return -ENOMEM;

	boot_signal = (u8 *)page_address(boot_signal_page);
	boot_signal[0] = VSM_BOOT_SIGNAL;

	/* Allocate Online Cpumask Page & Copy cpu_online_mask */
	cpu_online_page = hv_vsm_alloc_shared_page();
	if (IS_ERR(cpu_online_page)) {
		ret = -ENOMEM;
		goto free_bootsignal;
	}

	cpumask_copy(page_address(cpu_online_page), cpu_online_mask);

	/* Create per-CPU threads to do vtlcall and complete per-CPU hotplug boot in VTL1 */
	ap_thread = kmalloc_array(vsm_cpus, sizeof(*ap_thread), GFP_KERNEL);

	if (!ap_thread) {
		ret = -ENOMEM;
		goto free_sharedpages;
	}

	memset(ap_thread, 0, sizeof(*ap_thread) * vsm_cpus);

	for_each_online_cpu(cpu) {
		if (cpu == cur_cpu)
			continue;
		ap_thread[cpu] = kthread_create(hv_vsm_boot_sec_vp_thread_fn, NULL, "ap_thread");

		if (IS_ERR(ap_thread[cpu])) {
			ret = PTR_ERR(ap_thread[cpu]);
			goto out;
		}

		kthread_bind(ap_thread[cpu], cpu);
		sched_set_fifo(ap_thread[cpu]);
	}

	next_cpu = cpumask_next(cur_cpu, cpu_online_mask);
	if (next_cpu >= nr_cpu_ids)
		goto out;

	wake_up_process(ap_thread[next_cpu]);
	args.a0 = VSM_VTL_CALL_FUNC_ID_BOOT_APS;
	args.a1 = page_to_pfn(cpu_online_page);
	args.a2 = page_to_pfn(boot_signal_page);

	ret = hv_vsm_vtlcall(&args);

out:
	for_each_online_cpu(cpu) {
		if (ap_thread[cpu])
			kthread_stop(ap_thread[cpu]);
	}
	kfree(ap_thread);
free_sharedpages:
	__free_page(cpu_online_page);
free_bootsignal:
	__free_page(boot_signal_page);
	if (ret)
		panic("Failed to boot APs for VTL1. Error %d", ret);
	return ret;
}

static __init int hv_vsm_boot_vtl1(void)
{
	struct hv_vtlcall_param args = {0};
	u16 vp_enabled_vtl_set = 0;
	u8 active_mbec_enabled = 0;
	int ret;

	args.a0 = 0;
	args.a1 = (u64)VSM_VA_FROM_PA(PAGE_AT(vsm_skm_pa, VSM_BOOT_PARAMS_PAGE));

	/*
	 * Kick start vtl1 boot on primary cpu. There is currently no way to exit
	 * gracefully if this boot is not successful. In case of a failure, primary cpu
	 * will not return from vtl1 and system will hang.
	 */
	hv_vsm_init_vtlcall(&args);

	ret = hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
	if (ret)
		return ret;

	if (!active_mbec_enabled) {
		pr_err("Failed to enable MBEC for VP0\n");
		hv_vsm_mbec_enabled = false;
	}
	return 0;
}

static int __init hv_vsm_bootstrap_vtl(void)
{
	u16 partition_enabled_vtl_set = 0, partition_mbec_enabled_vtl_set = 0;
	u16 vp_enabled_vtl_set = 0;
	u8 partition_max_vtl, active_mbec_enabled = 0;
	Elf64_Addr sk_entry_pa;
	int ret;

	/* Check and enable VTL1 at the partition level */
	ret = hv_vsm_get_partition_status(&partition_enabled_vtl_set, &partition_max_vtl,
					  &partition_mbec_enabled_vtl_set);
	if (ret)
		return ret;

	if (partition_max_vtl < HV_VTL_SECURE) {
		pr_err("VTL1 is not supported by the partition\n");
		return -EINVAL;
	}

	if (partition_enabled_vtl_set & HV_VTL1_ENABLE_BIT) {
		pr_info("Partition VTL1 is already enabled\n");
	} else {
		ret = hv_vsm_enable_partition_vtl();
		if (ret) {
			pr_err("Enabling Partition VTL1 failed with status 0x%x\n",
			       ret);
			return -EINVAL;
		}
		ret = hv_vsm_get_partition_status(&partition_enabled_vtl_set, &partition_max_vtl,
						  &partition_mbec_enabled_vtl_set);
		if (ret)
			return ret;
		if (!(partition_enabled_vtl_set & HV_VTL1_ENABLE_BIT)) {
			pr_err("Tried Enabling Partition VTL 1 and still failed");
			return -EINVAL;
		}
		if (!partition_mbec_enabled_vtl_set) {
			pr_err("Tried Enabling Partition MBEC and failed");
			return -EINVAL;
		}
	}

	ret = hv_vsm_load_secure_kernel(&sk_entry_pa);
	if (ret)
		return ret;

	/* Check and enable VTL1 for the primary virtual processor */
	ret = hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
	if (ret)
		return ret;

	if (vp_enabled_vtl_set & HV_VTL1_ENABLE_BIT) {
		pr_info("VP VTL1 is already enabled\n");
	} else {
		ret = hv_vsm_enable_vp_vtl(sk_entry_pa);
		if (ret) {
			pr_err("Enabling VP VTL1 failed with status 0x%x\n", ret);
			/* ToDo: Should we disable VTL1 at partition level in this case */
			return -EINVAL;
		}
		ret = hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
		if (ret)
			return ret;

		if (!(vp_enabled_vtl_set & HV_VTL1_ENABLE_BIT)) {
			pr_err("Tried Enabling VP VTL 1 and still failed");
			return -EINVAL;
		}
	}

	/* Boot Primary Virtual Processor in VTL1 */
	ret = hv_vsm_boot_vtl1();
	if (ret)
		return ret;

	if (num_present_cpus() == 1)
		return 0;

	return hv_vsm_boot_ap_vtl();
}

static void __init hv_vsm_get_sk_mem(void)
{
	if (!sk_res.start)
		panic("No memory reserved in cmdline for secure kernel");

	vsm_skm_pa = sk_res.start;
	vsm_skm_va = phys_to_virt(vsm_skm_pa);

	pr_info("secure kernel region: %#llx-%#llx (%lld MB)\n",
		sk_res.start, sk_res.end, resource_size(&sk_res) >> 20);
}

static int __init vsm_arch_has_vsm_access(void)
{
	if (!(ms_hyperv.features & HV_MSR_SYNIC_AVAILABLE))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VSM))
		return false;
	if (!(ms_hyperv.priv_high & HV_ACCESS_VP_REGS))
		return false;
	return true;
}

static int __init hv_vsm_boot_init(void)
{
	cpumask_var_t mask;
	unsigned int boot_cpu;
	int ret;

	if (!vsm_arch_has_vsm_access())
		return 0;

	hv_vsm_get_sk_mem();

	/*
	 * Copy the current cpu mask and pin rest of the running code to boot cpu.
	 * Important since we want boot cpu of VTL0 to be the boot cpu for VTL1.
	 * ToDo: Check if copying and restoring current->cpus_mask is enough
	 * ToDo: Verify the assumption that cpumask_first(cpu_online_mask) is
	 * the boot cpu
	 */
	if (!alloc_cpumask_var(&mask, GFP_KERNEL))
		panic("Could not allocate cpumask");

	cpumask_copy(mask, &current->cpus_mask);
	boot_cpu = cpumask_first(cpu_online_mask);
	set_cpus_allowed_ptr(current, cpumask_of(boot_cpu));

	ret = hv_vsm_bootstrap_vtl();
	if (ret)
		panic("VTL1 boot failure caused kernel panic; consult log for more details.\n");

	hv_vsm_init_heki();

	set_cpus_allowed_ptr(current, mask);
	free_cpumask_var(mask);
	return ret;
}
device_initcall(hv_vsm_boot_init);
