/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *
 */

#ifndef _HV_VSM_H
#define _HV_VSM_H

#include <linux/types.h>

#define VSM_VTL_CALL_FUNC_ID_BOOT_APS		0x1FFE1
#define VSM_VTL_CALL_FUNC_ID_LOCK_REGS		0x1FFE2
#define VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT	0x1FFE3
#define VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY	0x1FFE4

extern struct resource sk_res;
extern struct boot_params boot_params;

int __init hv_vsm_init_heki(void);

#endif /* _HV_VSM_H */
