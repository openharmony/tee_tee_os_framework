# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

OPENSSL_CRYPTO_PATH := $(TEELIB)/libopenssl/openssl/crypto

LOCAL_SRC_FILES := \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/aes/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/asn1/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/bn/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/cmac/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/ec/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/evp/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/hmac/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/md5/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/modes/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/objects/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/pem/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/rsa/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/sha/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/x509/x509_set.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/x509/t_x509.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/x509/x_attrib.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/x509/x_pubkey.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/pkcs7/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/pkcs12/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/bio/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/stack/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/buffer/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/lhash/lhash.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/conf/*.c)  \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/kdf/*.c) \
	$(wildcard $(TEELIB)/libopenssl/src/openssl_stub.c)

LOCAL_SRC_FILES += \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/des/*.c)

LOCAL_SRC_FILES += \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/x509/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/x509v3/*.c)
LOCAL_SRC_FILES += \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/siphash/*.c)

LOCAL_SRC_FILES += \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/sm2/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/sm3/*.c) \
	$(wildcard $(OPENSSL_CRYPTO_PATH)/sm4/*.c)

LOCAL_SRC_FILES += \
	$(OPENSSL_CRYPTO_PATH)/cryptlib.c \
	$(OPENSSL_CRYPTO_PATH)/mem.c \
	$(OPENSSL_CRYPTO_PATH)/mem_sec.c \
	$(OPENSSL_CRYPTO_PATH)/mem_dbg.c \
	$(OPENSSL_CRYPTO_PATH)/ex_data.c \

LOCAL_SRC_FILES := $(filter-out $(OPENSSL_CRYPTO_PATH)/ec/ecp_nistz256_table.c \
	$(OPENSSL_CRYPTO_PATH)/aes/aes_ige.c \
	$(OPENSSL_CRYPTO_PATH)/aes/aes_x86core.c \
	$(OPENSSL_CRYPTO_PATH)/x509/x509_def.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_camellia.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_bf.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_cast.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_chacha20_poly1305.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_idea.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_rc2.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_rc4.c \
	$(OPENSSL_CRYPTO_PATH)/evp/e_rc4_hmac_md5.c \
	$(OPENSSL_CRYPTO_PATH)/evp/m_md4.c \
	$(OPENSSL_CRYPTO_PATH)/evp/m_mdc2.c \
	$(OPENSSL_CRYPTO_PATH)/evp/m_ripemd.c \
	$(OPENSSL_CRYPTO_PATH)/conf/conf_sap.c \
	$(OPENSSL_CRYPTO_PATH)/evp/m_wp.c, $(LOCAL_SRC_FILES))

CFILES :=  $(patsubst $(TEELIB)/libopenssl/%,%,$(LOCAL_SRC_FILES))

ifeq ($(CONFIG_OPENSSL_NO_ASM),true)
A32_CFLAGS += -DCONFIG_OPENSSL_NO_ASM
CFLAGS += -DCONFIG_OPENSSL_NO_ASM
endif

ifneq ($(CONFIG_OPENSSL_NO_ASM),true)
A32_CFLAGS += -DOPENSSL_BN_ASM_MONT -DOPENSSL_CPUID_OBJ -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DBSAES_ASM -DOPENSSL_BN_ASM_GF2m
CFLAGS += -DOPENSSL_BN_ASM_MONT -DOPENSSL_CPUID_OBJ -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DECP_NISTZ256_ASM
endif

ifeq ($(CONFIG_CRYPTO_GET_ENTROPY),true)
CFLAGS += -DOPENSSL_THREADS -DPTHREAD_RWLOCK_INITIALIZER
endif
CFLAGS += -DOPENSSL_NO_UI_CONSOLE -DOPENSSL_NO_EC448 -DOPENSSL_NO_KECCAK1600
CFLAGS += -DCC_DRIVER -O3
CFLAGS += -DOPENSSL_RAND_SEED_ENTROPY_CUSTOMER=crypto_driver_get_entropy
