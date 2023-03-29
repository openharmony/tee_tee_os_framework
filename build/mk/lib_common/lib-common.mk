# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# setup toolchain
TARGET_IS_SYS := y
include $(BUILD_CONFIG)/var.mk
include $(BUILD_CONFIG)/cfg.mk
include $(BUILD_CONFIG)/toolchain.mk
include $(BUILD_OPERATION)/common.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

flags += -fdata-sections -ffunction-sections

ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
endif

# cpp flags:
cxx-flags += -nostdinc++ -static-libstdc++
cxx-flags += -I$(LLVM_INC)
flags += $(INCLUDES)

include $(BUILD_CFI)/llvm-apps-cfi.mk
