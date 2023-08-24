# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
MODULE := libcrypto_hal${TARG}.a
include $(BUILD_CONFIG)/feature-macro.mk

ifeq ($(CONFIG_CRYPTO_SUPPORT_EC25519),true)
c-flags += -DCRYPTO_SSL_SUPPORT_EC25519
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),openssl3)
    c-flags += -DOPENSSL3_ENABLE
else
    c-flags += -DOPENSSL_ENABLE
endif

ifneq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), )
c-flags += -DCRYPTO_MGR_SERVER_ENABLE
endif

inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(DRIVERS_PATH)/crypto_mgr/src/crypto_ioctl
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libdrv/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libswcrypto_engine/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(TEELIB)/libssa/include
inc-flags += -I$(PREBUILD_HEADER)/sys

ifneq ($(findstring $(CONFIG_CRYPTO_SOFT_ENGINE), openssl openssl3),)
inc-flags += -I$(TEELIB)/libopenssl/openssl/include
inc-flags += -I$(TEELIB)/libopenssl/openssl/crypto
endif

# Source files required to build the target
libcrypto_hal_c_files += $(wildcard src/*.c) \
                         $(wildcard src/stub/*.c) \
                         $(wildcard src/boringssl/*.c)

ifeq ($(CONFIG_CRYPTO_SUPPORT_SOFT_ECC),true)
c-flags += -DCRYPTO_SUPPORT_SOFT_ECC
libcrypto_hal_c_files := $(filter-out src/stub/soft_ec_api.c, $(libcrypto_hal_c_files))
else
libcrypto_hal_c_files := $(filter-out src/boringssl/soft_ec_api.c, $(libcrypto_hal_c_files))
endif

ifeq ($(CONFIG_CRYPTO_SUPPORT_SOFT_SM2),true)
c-flags += -DCRYPTO_SUPPORT_SOFT_SM2
libcrypto_hal_c_files := $(filter-out src/stub/soft_gmssl_asym.c, $(libcrypto_hal_c_files))
else
libcrypto_hal_c_files := $(filter-out src/boringssl/soft_gmssl_asym.c, $(libcrypto_hal_c_files))
endif
include $(BUILD_LIB)/lib-common.mk
