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
# Targets

MODULE := libteeconfig$(TARG).a

flags += -fno-builtin

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_SUPPORT_GET_DIEID), true)
flags += -DCONFIG_SUPPORT_GET_DIEID
endif

ifeq ($(CONFIG_DYN_CONF), true)
flags += -DTEE_SUPPORT_DYN_CONF
endif

ifneq (, $(filter $(TARGET_BOARD_PLATFORM), baltimore))
flags += -DCONFIG_GENERIC_ROT
flags += -DCONFIG_GENERIC_ART
endif
inc-flags += -I$(TEELIB)/libteeconfig/include/TEE_ext
inc-flags += -I$(TEELIB)/libteeconfig/include/kernel/
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libagent_base/include
inc-flags += -I$(TEELIB)/libdrv/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(DRIVERS_PATH)/tee_misc_driver/src
inc-flags += -I$(TEELIB)/libteemem/include

ifneq ($(findstring $(CONFIG_CRYPTO_SOFT_ENGINE), openssl openssl3),)
inc-flags += -I$(TEELIB)/libopenssl/openssl/include
inc-flags += -I$(TEELIB)/libopenssl/openssl/crypto
endif


# Source files required to build the target
libteeconfig_c_files += $(wildcard src/drv_hal/*.c)
libteeconfig_c_files += $(wildcard src/tee_config/*.c)

include $(BUILD_LIB)/lib-common.mk
include $(BUILD_CONFIG)/feature-macro.mk
flags += -DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
