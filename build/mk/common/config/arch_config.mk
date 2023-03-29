# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
#
CFLAGS :=
CPPFLAGS :=
ASFLAGS :=
CXXFLAGS :=

CCFLAGS :=

NK_CFLAGS =
NK_CXXFLAGS =
NK_LDFLAGS =
NK_ASFLAGS =

NK_CCFLAGS =

comma := ,

ifeq ($(CONFIG_ARCH_ARM),y)
	export ARCH := arm
	DEFS += ARCH_ARM
	export ARCH_ARM
endif

ifeq ($(CONFIG_ARCH_AARCH32),y)
	DEFS += AARCH32
	DEFS += __KERNEL_32__
	export __ARM_32__ = y
	export KERNEL_32 = y
	export TEE_ARCH = arm
	export HM_ARCH = aarch32
	export TYPE_SUFFIX = 32
endif

ifeq ($(CONFIG_ARCH_AARCH64),y)
	DEFS += AARCH64
	DEFS += __KERNEL_64__
	export TEE_ARCH = aarch64
	export __ARM_64__ = y
	export KERNEL_64 = y
	export HM_ARCH = aarch64
	export TYPE_SUFFIX = 64
endif

ifeq ($(CONFIG_ARM_CORTEX_A15),y)
	DEFS += ARMV7_A
	DEFS += ARM_CORTEX_A15
	export ARMV=armv7ve
	export CPU=cortex-a15
endif

ifeq ($(CONFIG_ARM_CORTEX_A53),y)
	C_FLAGS += -mtune=cortex-a53
ifeq ($(CONFIG_ARCH_AARCH64),y)
	C_FLAGS  += -march=armv8-a+nofp
	AS_FLAGS += -march=armv8-a
	AS_FLAGS += -mcpu=cortex-a53
endif
	DEFS += ARMV8_A
	DEFS += ARM_CORTEX_A53
	export ARMV=armv8-a
	export CPU=cortex-a53
endif
