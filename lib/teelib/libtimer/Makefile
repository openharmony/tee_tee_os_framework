# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# Targets
MODULE := libtimer${TARG}.a

flags += -fno-builtin

inc-flags += -I$(TEELIB)/libtimer/include
inc-flags += -I$(TEELIB)/libagent/include
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libssa/include
inc-flags += -I$(PREBUILD_HEADER)/sys
ifeq (${TARG}, _a32)
inc-flags += -I$(TEELIB)/libtimer/include/arm
else
inc-flags += -I$(TEELIB)/libtimer/include/aarch64
endif

# Source files required to build the target
ifeq ($(CONFIG_OFF_DRV_TIMER), y)
libtimer_c_files := $(wildcard src/*.c)
endif

include $(BUILD_LIB)/lib-common.mk
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
flags += -DCONFIG_TEE_TIME_STUB
