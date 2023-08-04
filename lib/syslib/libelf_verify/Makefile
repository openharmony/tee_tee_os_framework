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
MODULE := libelf_verify${TARG}.a

SOURCE_DIR := $(SYSLIB)/libelf_verify

# Source files required to build the target
CFILES := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_load_ext_mf.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_elf_verify.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_load_key_ops.c))

ifeq ($(CONFIG_ELF_DECRYPT_ENABLE),y)
CFLAGS += -DELF_DECRYPT_ENABLE
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_load_dec_key_ops.c))
ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), mbedtls)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_elf_verify_mbedtls.c))
else
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_elf_verify_openssl.c))
endif
else
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_elf_verify_stub.c))
endif

ifneq ($(findstring y, $(CONFIG_APP_TEE_PERM) $(CONFIG_APP_TEE_PERM_A32)),)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_perm_img.c))
else
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_perm_img_stub.c))
endif

ifeq ($(CONFIG_DYN_TA_FORMAT),1)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_comm_elf_verify.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_v3_elf_verify.c))
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_comm_elf_verify.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_v3_elf_verify.c))
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_v3_elf_verify.c))
endif

LDFLAGS += -z noexecstack

CPPFLAGS += -I$(SYSLIB)/libelf_verify/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libpermission_service/src
CPPFLAGS += -I$(SERVICES_PATH)/permission_service/src
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee # ta_framework.h
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(SYSLIB)/libelf_verify_key/include/
CPPFLAGS += -I$(SYSLIB)/libelf_verify_key/src/
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(SYSLIB)/libdynconfmgr/include
CPPFLAGS += -I$(SYSLIB)/libdynconfbuilder/include
CPPFLAGS += -I$(FRAMEWORK_PATH)/drvmgr/src
CPPFLAGS += -I$(DRIVERS_PATH)/include
CPPFLAGS += -I$(TEELIB)/libtimer/include/
CPPFLAGS += -I$(SYSLIB)/libspawn_common/include/
CPPFLAGS += -I$(TEELIB)/libdrv/include

ifneq ($(findstring $(CONFIG_CRYPTO_SOFT_ENGINE), openssl openssl3),)
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/include
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto
endif

# Source files required to build the target
CPPFLAGS += -I$(SOURCE_DIR)/include/
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl3)
CFLAGS += -DOPENSSL3_ENABLE
else 
CFLAGS += -DOPENSSL_ENABLE
endif

ifeq ($(CONFIG_DYN_TA_FORMAT),1)
CFLAGS += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
CFLAGS += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
CFLAGS += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

include $(BUILD_LIB)/lib-common.mk
include $(BUILD_CONFIG)/feature-macro.mk
