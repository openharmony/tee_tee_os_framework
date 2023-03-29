# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

include $(BUILD_CONFIG)/var.mk
PREBUILD_DDK  := $(PREBUILD_DIR)/headers/ddk
PREBUILD_SYS  := $(PREBUILD_DIR)/headers/sys
PREBUILD_KERNEL := $(PREBUILD_DIR)/headers/kernel

KERNEL_INCLUDE_PATH_COMMON = $(PREBUILD_KERNEL)/ \
                             $(PREBUILD_KERNEL)/uapi

DDK_INCLUDE_PATH_COMMON += $(PREBUILD_DDK)

SYS_INCLUDE_PATH = $(PREBUILD_SYS)

ifeq ($(TARGET_IS_SYS),y)
INCLUDE_PATH += $(SYS_INCLUDE_PATH)
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
endif

ifeq ($(TARGET_IS_DRV),y)
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
endif

ifeq ($(TARGET_IS_TA),y)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
endif
