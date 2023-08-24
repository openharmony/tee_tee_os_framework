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
MODULE := libcrypto${TARG}.a

CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/src
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libssa/include
CPPFLAGS += -I$(SYSLIB)/libelf_verify/include

CFILES   := $(wildcard src/*.c)

ifeq ($(GP_SUPPORT), y)
CFILES := $(filter-out src/tee_crypto_api_hash.c, $(CFILES))
CFILES := $(filter-out src/tee_crypto_api_hmac.c, $(CFILES))
else
CFILES := $(filter-out src/tee_crypto_gp_hash.c, $(CFILES))
CFILES := $(filter-out src/tee_crypto_gp_hmac.c, $(CFILES))
endif

#32M when ascend, others 500K
CFLAGS += -DMAX_SRC_SIZE=512000
A32_CFLAGS += -DMAX_SRC_SIZE=512000

ifneq ($(findstring $(CONFIG_CRYPTO_SOFT_ENGINE), openssl openssl3),)
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/include
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
CFLAGS += -DOPENSSL_ENABLE
A32_CFLAGS += -DOPENSSL_ENABLE
else ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl3)
CFLAGS += -DOPENSSL3_ENABLE
A32_CFLAGS += -DOPENSSL3_ENABLE
endif

ifeq (${TARG}, _a32)
ASMFILES += $(wildcard src/arm/*.S)
endif

ifeq (${TARG}, )
ASMFILES += $(wildcard src/aarch64/*.S)
endif

include $(BUILD_LIB)/lib-common.mk
