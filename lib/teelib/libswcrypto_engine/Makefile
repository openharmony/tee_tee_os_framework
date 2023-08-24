# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

MODULE := libswcrypto_engine${TARG}.a

c-flags += -DARM_PAE=1 -D__ARM_ARCH_=7 -DTARGET_PRODUCT_VAL=\"$(TARGET_BOARD_PLATFORM)\"

inc-flags += -I$(TEELIB)/libswcrypto_engine/include
inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libssa/include
inc-flags += -I$(TEELIB)/libhuk/include
inc-flags += -I$(TEELIB)/libtee_shared/include
inc-flags += -I$(PREBUILD_HEADER)/sys

ifneq ($(findstring $(CONFIG_CRYPTO_SOFT_ENGINE), openssl openssl3),)
inc-flags += -I$(TEELIB)/libopenssl/openssl/include
inc-flags += -I$(TEELIB)/libopenssl/openssl/crypto
endif

libswcrypto_engine_c_files += $(wildcard src/*.c)
libswcrypto_engine_c_files += $(wildcard src/stub/*.c)

ifeq ($(CONFIG_CRYPTO_SUPPORT_X509),true)
c-flags += -DCRYPTO_SSL_SUPPORT_X509
libswcrypto_engine_c_files := $(filter-out src/stub/create_cert_wrapper_stub.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/stub/tee_ext_cert_api_stub.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/stub/x509_wrapper_stub.c, $(libswcrypto_engine_c_files))
else
libswcrypto_engine_c_files := $(filter-out src/create_cert_wrapper.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/tee_ext_cert_api.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/x509_wrapper.c, $(libswcrypto_engine_c_files))
endif

ifeq ($(CONFIG_CRYPTO_ECC_WRAPPER),true)
libswcrypto_engine_c_files := $(filter-out src/stub/ec_wrapper_stub.c, $(libswcrypto_engine_c_files))
ifeq ($(CONFIG_CRYPTO_SUPPORT_X509),true)
libswcrypto_engine_c_files := $(filter-out src/stub/ec_wrapper_x509_stub.c, $(libswcrypto_engine_c_files))
else
libswcrypto_engine_c_files := $(filter-out src/ec_wrapper_x509.c, $(libswcrypto_engine_c_files))
endif
else
libswcrypto_engine_c_files := $(filter-out src/ec_wrapper.c, $(libswcrypto_engine_c_files))
libswcrypto_engine_c_files := $(filter-out src/ec_wrapper_x509.c, $(libswcrypto_engine_c_files))
endif

ifeq ($(CONFIG_CRYPTO_AES_WRAPPER),true)
libswcrypto_engine_c_files := $(filter-out src/stub/aes_wrapper_stub.c, $(libswcrypto_engine_c_files))
else
libswcrypto_engine_c_files := $(filter-out src/aes_wrapper.c, $(libswcrypto_engine_c_files))
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),openssl3)
    c-flags += -DOPENSSL3_ENABLE
else
    c-flags += -DOPENSSL_ENABLE
endif
libswcrypto_engine_c_files := $(filter-out src/stub/rsa_wrapper_stub.c, $(libswcrypto_engine_c_files))

include $(BUILD_LIB)/lib-common.mk
