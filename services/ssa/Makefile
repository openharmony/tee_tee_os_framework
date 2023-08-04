# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
DRIVER := ssa${TARG}.elf

CFILES := $(wildcard src/*/*.c)

include $(BUILD_CONFIG)/var.mk

CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include/TEE_ext/
CPPFLAGS += -I$(TEELIB)/libteeos/src/TEE/permission_service
CPPFLAGS += -I$(TEELIB)/libteemem/include # mem_ops_ext.h
CPPFLAGS += -I$(TEELIB)/libteeconfig/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libtee_shared/include
CPPFLAGS += -I$(TEELIB)/libssa/src
CPPFLAGS += -I$(TEELIB)/libssa/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libpermission_service/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libhuk/include
CPPFLAGS += -I$(SERVICES_PATH)/huk_service/src
CPPFLAGS += -I$(SERVICES_PATH)/huk_service/include
CPPFLAGS += -I$(SERVICES_PATH)/ssa/src/secure_storage_agent
CPPFLAGS += -I$(SERVICES_PATH)/ssa/src
CPPFLAGS += -I$(TOPDIR)/libs/libcrypto_common
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(TEELIB)/libipc_hal/include

ifneq ($(findstring $(CONFIG_CRYPTO_SOFT_ENGINE), openssl openssl3),)
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/include
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto
endif

CFLAGS += -fvisibility=hidden

LDFLAGS += -z noexecstack

ifeq (${CONFIG_TEE_TEST_UT},y)
    CFLAGS += -DTEE_TEST_UT
endif

ifeq ($(TARGET_IS_ARM32),y)
CFLAGS += -mno-thumb
endif

LDFLAGS += -e tee_task_entry

SVC_PARTITIAL_LINK = y

include $(BUILD_SERVICE)/svc-common.mk
