# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_HYPERV)		+= hv_vmbus.o
obj-$(CONFIG_HYPERV_UTILS)	+= hv_utils.o
obj-$(CONFIG_HYPERV_BALLOON)	+= hv_balloon.o
obj-$(CONFIG_MSHV_ROOT)		+= mshv_root.o

CFLAGS_hv_trace.o = -I$(src)
CFLAGS_hv_balloon.o = -I$(src)

hv_vmbus-y := vmbus_drv.o \
		 hv.o connection.o channel.o \
		 channel_mgmt.o ring_buffer.o hv_trace.o
hv_vmbus-$(CONFIG_HYPERV_TESTING)	+= hv_debugfs.o
hv_utils-y := hv_util.o hv_kvp.o hv_snapshot.o hv_utils_transport.o
mshv_root-y := mshv_root_main.o mshv_synic.o mshv_eventfd.o mshv_irq.o \
	       mshv_root_hv_call.o mshv_portid_table.o

# Code that must be built-in
obj-$(subst m,y,$(CONFIG_HYPERV)) += hv_common.o
obj-$(subst m,y,$(CONFIG_MSHV_ROOT)) += hv_proc.o
ifneq ($(CONFIG_MSHV_ROOT)$(CONFIG_HYPERV_VSM)$(CONFIG_HV_SECURE_VTL),)
	obj-y += mshv_common.o
endif
obj-$(subst m,y,$(CONFIG_HYPERV_VSM)) += hv_vsm_securekernel.o hv_vsm_boot.o hv_vsm.o
obj-$(subst m,y,$(CONFIG_HV_SECURE_VTL)) += mshv_vsm_vtl1.o
