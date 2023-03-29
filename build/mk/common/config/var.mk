# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# basic dirs, these variables will be used by whole project
override BUILD_DIR     := $(OUTPUTDIR)/$(ARCH)/obj/$(ARCH)/$(MODULE_FOLDER)
override LIB_DIR       := $(OUTPUTDIR)/$(ARCH)/libs
ifeq ($(CONFIG_ARCH_AARCH32),y)
override LIB_DIR_A32   := $(OUTPUTDIR)/arm/libs
endif
override APP_DIR       := $(OUTPUTDIR)/$(ARCH)/apps
override DRV_DIR       := $(OUTPUTDIR)/$(ARCH)/drivers
override HDR_L_DIR     := $(OUTPUTDIR)/headers
override KERNEL_OUTDIR := $(OUTPUTDIR)/kernel

ifneq ($V,)
VER :=
else
VER := @
endif

# kernel header do not relative with arch
KERNEL_HDR_DIR := $(OUTPUTDIR)/kernel/headers

ifeq ($(PREBUILD_ROOT),)
override PREBUILD_ROOT := $(TOPDIR)/prebuild
endif

### prebuild directory:
PREBUILD_DIR    := $(PREBUILD_ROOT)/$(SDK_VER)
PREBUILD_HEADER := $(PREBUILD_DIR)/headers
PREBUILD_LIBS   := $(PREBUILD_DIR)/libs

PREBUILD_LIBC_INC   := $(PREBUILD_HEADER)/libc

PREBUILD_ARCH_PLAT_LIBS := $(PREBUILD_LIBS)/$(ARCH)

## package directory:
STAGE_DIR := $(OUTPUTDIR)/stage

-include $(PREBUILD_HEADER)/.config

# selection of platform

ifeq ($(TARGET_BUILD_VARIANT),eng)
	WITH_ENG_VERSION = true
else
	WITH_ENG_VERSION = false
endif


ifeq ($(WITH_ENG_VERSION), true)
	TRUSTEDCORE_PLATFORM_FLAGS += -DSECMEM_UT
endif

ifeq ($(RELEASE_SIGN), true)
	TRUSTEDCORE_PLATFORM_FLAGS += -DRELEASE_SIGN_BUILD_TEE
endif

SECUREC_LIB := $(TEE_SECUREC_DIR)/include
