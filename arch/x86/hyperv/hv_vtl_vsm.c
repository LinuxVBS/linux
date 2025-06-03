// SPDX-License-Identifier: GPL-2.0
#include <hyperv/vsm.h>
#include <hyperv/hvgdk_mini.h>
#include <asm/mshyperv.h>

#define VSM_PAGE_MASK			(_PAGE_PRESENT | _PAGE_RW)
#define VSM_PAGE_PTE_MASK		(VSM_PAGE_MASK | _PAGE_ACCESSED | _PAGE_DIRTY)

/* Shifts to compute page table mapping */
#define VSM_PD_TABLE_SHIFT		21
#define VSM_PDP_TABLE_SHIFT		30
#define VSM_PML4_TABLE_SHIFT		39

/* Given VA, get index into the page table at a given level */
#define VSM_GET_PML4_INDEX(addr)	(((addr) >> VSM_PML4_TABLE_SHIFT) & 0x1FF)
#define VSM_GET_PDP_INDEX(addr)		(((addr) >> VSM_PDP_TABLE_SHIFT) & 0x1FF)
#define VSM_GET_PD_INDEX(addr)		(((addr) >> VSM_PD_TABLE_SHIFT) & 0x1FF)

static union hv_register_vsm_code_page_offsets vsm_code_page_offsets;
bool is_code_page_offset_retrieved;

static void __init hv_vsm_fill_pte_tables(phys_addr_t sk_pa, u64 *pde,
					  int pd_index, int num_pte_tables)
{
	u16 i, j;
	phys_addr_t pte_pa;
	u64 *pte;

	/* Fill page tables with entries */
	for (i = 0; i < num_pte_tables; i++) {
		pte_pa = PAGE_AT(sk_pa, VSM_PTE_PAGES + i);
		pte = phys_to_virt(pte_pa);
		*(pde + pd_index + i) = pte_pa | VSM_PAGE_PTE_MASK;
		for (j = 0; j < VSM_ENTRIES_PER_PT; j++) {
			*(pte + j) =
				(sk_pa + ((j + (i * VSM_ENTRIES_PER_PT)) * VSM_PAGE_SIZE)) |
					VSM_PAGE_PTE_MASK;
		}
	}
}

static void __init hv_vsm_init_page_tables(struct hv_init_vp_context *vp_ctx, phys_addr_t sk_pa)
{
	u64 pml4_index;
	u64 pdp_index;
	u64 pd_index;
	phys_addr_t pml4e_pa;
	phys_addr_t pdpe_pa;
	phys_addr_t pde_pa;
	u64 *pml4e;
	u64 *pdpe;
	u64 *pde;
	int num_pte_tables;

	/* Get offset to know where to start mapping. Note sk_pa is the VA for OP-TEE */
	pml4_index = VSM_GET_PML4_INDEX(sk_pa);
	pdp_index = VSM_GET_PDP_INDEX(sk_pa);
	pd_index = VSM_GET_PD_INDEX(sk_pa);

	pml4e_pa = PAGE_AT(sk_pa, VSM_PML4E_PAGE);
	pdpe_pa = PAGE_AT(sk_pa, VSM_PDPE_PAGE);
	pde_pa = PAGE_AT(sk_pa, VSM_PDE_PAGE);

	pml4e = phys_to_virt(pml4e_pa);
	pdpe = phys_to_virt(pdpe_pa);
	pde = phys_to_virt(pde_pa);

	/* N.B.: Adding '+ 1' to a pointer moves the underlying value forward by 8 bytes! */
	*(pml4e + pml4_index) = pdpe_pa | VSM_PAGE_MASK;
	*(pdpe + pdp_index) = pde_pa | VSM_PAGE_MASK;

	/* Initial page tables map only the first VSM_SK_INITIAL_MAP_SIZE size of memory.
	 * This memory will be used for the Secure Loader and initial Secure Kernel
	 */
	num_pte_tables = (VSM_SK_INITIAL_MAP_SIZE / VSM_PAGE_SIZE) / VSM_ENTRIES_PER_PT;
	hv_vsm_fill_pte_tables(sk_pa, pde, pd_index, num_pte_tables);

	vp_ctx->cr3 = pml4e_pa;
}

static void __init hv_vsm_init_gdt(struct hv_init_vp_context *vp_ctx, phys_addr_t sk_pa)
{
	phys_addr_t gdt_pa, tss_pa, kstack_pa;
	void *gdt_va;
	u64 tss_sk_va, gdt;
	struct x86_hw_tss *tss;
	size_t gdt_size = sizeof(gdt), tss_size = sizeof(*tss), gdt_offset = 0;

	/* Get a page for the GDT */
	gdt_pa = PAGE_AT(sk_pa, VSM_GDT_PAGE);
	gdt_va = phys_to_virt(gdt_pa);
	/* Get a page for the TSS */
	tss_pa = PAGE_AT(sk_pa, VSM_TSS_PAGE);
	tss = phys_to_virt(tss_pa);
	/* Compute the VA that secure kernele will see for the TSS */
	tss_sk_va = VSM_VA_FROM_PA(tss_pa);
	/* Get a page for the secure kernel initial stack */
	kstack_pa = PAGE_AT(sk_pa, VSM_KERNEL_STACK_PAGE);
	/* Set the initial stack pointer for the kernel to point to bottom of kernel stack */
	tss->sp0 = VSM_VA_FROM_PA(kstack_pa) + VSM_PAGE_SIZE - 1;
	vp_ctx->rsp = tss->sp0;

	/* Make and add the NULL descriptor to the GDT */
	gdt = GDT_ENTRY(0x2018, 0, 0);
	memcpy(gdt_va + gdt_offset, &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Make and add a code segment descriptor to the GDT */
	gdt = GDT_ENTRY(0x2098, 0, 0);
	memcpy(gdt_va + gdt_offset, &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Make and add a data segment descriptor to the GDT */
	gdt = GDT_ENTRY(0x90, 0, 0);
	memcpy(gdt_va + gdt_offset, &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Make and add a system segment descriptor for the TSS in the GDT */
	gdt = GDT_ENTRY(0x89, tss_sk_va, tss_size);
	memcpy(gdt_va + gdt_offset, &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Set up the GDT register */
	vp_ctx->gdtr.base = VSM_VA_FROM_PA(gdt_pa);
	vp_ctx->gdtr.limit = gdt_offset - 1;

	/* Set the code segment (CS) selector */
	vp_ctx->cs.base = 0;
	vp_ctx->cs.limit = 0;
	vp_ctx->cs.selector = 1 << 3;
	vp_ctx->cs.attributes = 0x209b;

	/* Set the data segment (DS) selector */
	vp_ctx->ds.base = 0;
	vp_ctx->ds.limit = 0;
	vp_ctx->ds.selector = 2 << 3;
	vp_ctx->ds.attributes = 0x4093;

	/* Set the ES, FS and GS to be the same as DS, for now */
	vp_ctx->es = vp_ctx->ds;
	vp_ctx->fs = vp_ctx->ds;
	vp_ctx->gs = vp_ctx->ds;

	/* Set the stack selector to 0 (unused in long mode) */
	vp_ctx->ss.selector = 0;

	/* Set the task register selector  */
	vp_ctx->tr.base = tss_sk_va;
	vp_ctx->tr.limit = tss_size - 1;
	vp_ctx->tr.selector = 3 << 3;
	vp_ctx->tr.attributes = 0x8b;
}

static void __init hv_vsm_init_cpu(struct hv_init_vp_context *vp_ctx, Elf64_Addr sk_entry_pa)
{
	/* Offset rip by any secure kernel header length */
	vp_ctx->rip = VSM_VA_FROM_PA(sk_entry_pa);

	/* ToDo: Check if can be replaced with CR0_STATE */
	vp_ctx->cr0 =
		X86_CR0_PG |	// Paging
		X86_CR0_WP |	// Write Protect
		X86_CR0_NE |	// Numeric Error
		X86_CR0_ET |	// Extension Type
		X86_CR0_MP |	// Math Present
		X86_CR0_PE;	// Protection Enable

	vp_ctx->cr4 =
		X86_CR4_PSE |	// Page Size Extensions
		X86_CR4_PGE |	// Page Global Enable
		X86_CR4_PAE;	// Physical Address Extensions

	vp_ctx->efer =
		EFER_LMA |	// Long Mode Active
		EFER_LME |	// Long Mode Enable
		EFER_NX  |	// No Execute Enable
		EFER_SCE;	// System Call Enable

	/*
	 * Intel CPUs fail if the architectural read-as-one bit 1 of RFLAGS is not
	 * set. See Intel SDM Vol 3C, 26.3.1.4 (RFLAGS).
	 *
	 * TODO: Has Hyper-V implemented setting this automatically?
	 */
	vp_ctx->rflags = 0b10;

	vp_ctx->msr_cr_pat = 0x7040600070406;
}

static void __init hv_vsm_init_code_page_offsets(void)
{
	u64 control = HV_HYPERCALL_REP_COMP_1 | HVCALL_GET_VP_REGISTERS;
	struct hv_input_get_vp_registers *input;
	struct hv_output_get_vp_registers *output;
	unsigned long flags;
	u64 ret;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, struct_size(input, names, 1));
	input->partition_id = HV_PARTITION_ID_SELF;
	input->vp_index = HV_VP_INDEX_SELF;
	input->input_vtl.as_uint8 = 0;
	input->names[0] = HV_REGISTER_VSM_CODE_PAGE_OFFSETS;

	ret = hv_do_hypercall(control, input, output);
	local_irq_restore(flags);
	if (hv_result_success(ret))
		vsm_code_page_offsets.as_uint64 = output->values[0].reg64;
}

/*
 * This function expects the upper VTL to preserve all registers except
 * those used by the VTL calling convention ABI (%rdi, %rsi, %rdx, %r8).
 *
 * VTL1 reliance means the Linux x86_64 ABI (%rbx, %r12, %r13, %r14, %r15)
 * must be restored by the caller during bootstrapping when VTL1 is not
 * operational.
 *
 * The %rcx register must be explicitly preserved as it is clobbered,
 * causing issues if this function is inlined. %rax is not restored by the
 * upper VTL (passed via the assist page) but is unused and can be ignored.
 *
 * This function preserves the args variable on the stack as it is passed
 * via a scratch register and clobbered.
 *
 * Microsoft Hypervisor preserves %rsp during VTL switches.
 */
static void __hv_vsm_vtlcall(struct hv_vtlcall_param *args)
{
	register u64 r8 asm("r8");
	u64 hcall_addr;

	hcall_addr = (u64)((u8 *)hv_hypercall_pg + vsm_code_page_offsets.vtl_call_offset);
	r8 = args->a3;

	asm volatile
	(/* Push args to stack as %rcx is not preserved across a VTL call */
		"pushq %[args]\n"
	/* Make rcx 0 */
		"xorl	%%ecx, %%ecx\n"
	/* VTL call */
		CALL_NOSPEC
	/* Restore args from stack */
		"popq %[args]\n"
		: "+D"(args->a0), "+S"(args->a1),
		  "+d"(args->a2), "+r"(r8)
		: [thunk_target]"a"(hcall_addr), [args]"r"(args)
	/* See the comment above the function why %rcx if here */
		: "cc", "memory", "rcx");

	args->a3 = r8;
}

static void __init __hv_vsm_init_vtlcall(struct hv_vtlcall_param *args)
{
	asm volatile("pushq %%rbp\n"
		     CALL_NOSPEC
		     "popq %%rbp\n"
			:
			: "D" (args), THUNK_TARGET(__hv_vsm_vtlcall)
			: "cc", "memory", "rbx", "r12", "r13", "r14", "r15");
}

void __init hv_vsm_arch_init_vp(struct hv_init_vp_context *vp_ctx, Elf64_Addr sk_entry_pa,
				 phys_addr_t sk_pa)
{
	hv_vsm_init_cpu(vp_ctx, sk_entry_pa);
	hv_vsm_init_gdt(vp_ctx, sk_pa);
	hv_vsm_init_page_tables(vp_ctx, sk_pa);
}

int __init hv_vsm_init_vtlcall(struct hv_vtlcall_param *args)
{
	unsigned long flags = 0;
	u64 cr2;

	// Retrieve hypercall page offset for vtlcall just once
	if (!is_code_page_offset_retrieved) {
		hv_vsm_init_code_page_offsets();
		is_code_page_offset_retrieved = true;
	}

	local_irq_save(flags);
	kernel_fpu_begin_mask(0);
	cr2 = native_read_cr2();
	__hv_vsm_init_vtlcall(args);
	native_write_cr2(cr2);
	kernel_fpu_end();
	local_irq_restore(flags);

	return (int)args->a3;
}
