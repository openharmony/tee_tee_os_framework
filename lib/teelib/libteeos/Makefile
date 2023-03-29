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
MODULE := libteeos${TARG}.a

# This library only provides 32-bit headers of libbteeos.
# If we want 64-bit headers of libteeos, we should depend on libac temporarily.

CPPFLAGS += -I$(TEELIB)/libdrv/include
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libagent_base/include # tee_secfile_load_agent.h
CPPFLAGS += -I$(TEELIB)/libteeconfig/include # root_status_ops.h
CPPFLAGS += -I$(TEELIB)/libteeconfig/include/kernel/
CPPFLAGS += -I$(TEELIB)/libteeconfig/include/TEE_ext/
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(TEELIB)/libtee_shared/include # oemkey.h
CPPFLAGS += -I$(DRIVERS_PATH)/include
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(PREBUILD_HEADER)/sys
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libssa/src
CPPFLAGS += -I$(TEELIB)/libssa/include
CPPFLAGS += -I$(TEELIB)/libhuk/include
CPPFLAGS += -I$(TEELIB)/libipc_hal/include

# Source files required to build the target
ASMFILES := $(wildcard src/*.S)
ifeq (${TARG}, _a32)
ASMFILES += $(wildcard src/*/*.S)
ASMFILES += $(wildcard src/*/arm/*.S)
endif

CFILES   := $(wildcard src/*.c)
CFILES   += $(wildcard src/*/*.c)

ifneq ($(CONFIG_PRIVATE_OEMKEY_SUPPORT),y)
CFILES := $(filter-out src/tee_private_api.c, $(CFILES))
endif

# fixup for TEE, check "trustedcore/trustedcore_plats.mk"
CFLAGS +=	-DARM_PAE=1 \
		-D__ARM_ARCH__=7
CFLAGS +=	-DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

include $(BUILD_LIB)/lib-common.mk
