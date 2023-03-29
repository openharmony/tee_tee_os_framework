# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# TARGET is a lib
MODULE := libelf_verify_key${TARG}.a

include $(BUILD_CONFIG)/var.mk
include $(BUILD_CONFIG)/feature-macro.mk

ifneq ($(chip_type),cs2)
flags += -DWITH_CHIP_CS
else
flags += -DWITH_CHIP_CS2
endif

ifeq ($(CONFIG_SIGN_KEY_RELEASE_DEBUG_ISOLATION),true)
flags += -DSUPPORT_SIGN_KEY_RELEASE_DEBUG_ISOLATION
endif

ifeq ($(CONFIG_DYN_TA_FORMAT),1)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
flags += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

libelf_verify_key_c_files := $(wildcard src/*.c)
libelf_verify_key_c_files += $(wildcard src/common/*.c)
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/gtask/include
inc-flags += -I$(SYSLIB)/libelf_verify_key/src/
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libswcrypto_engine/include
inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(DRIVERS_PATH)/tee_misc_driver/src/

ifeq ($(CONFIG_PUBKEY_SHAREMEM),true)
libelf_sharemem_key_c_files := $(wildcard src/*.c)
libelf_sharemem_key_c_files += $(wildcard src/sharemem/*.c)
inc-flags += -I$(SYSLIB)/libelf_verify_key/src/
endif

ifeq ($(CONFIG_OH_LOAD_KEY),y)
libelf_verify_key_c_files += $(wildcard src/common/openharmony/*.c)
endif

ifeq ($(CONFIG_PUBKEY_SHAREMEM),true)
libelf_verify_key_c_files := $(filter-out $(FILTEROUT_CFILES), $(libelf_sharemem_key_c_files))
else
libelf_verify_key_c_files := $(filter-out $(FILTEROUT_CFILES), $(libelf_verify_key_c_files))
endif

include $(BUILD_LIB)/lib-common.mk
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
