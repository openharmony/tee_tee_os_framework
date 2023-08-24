# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#Targets
MODULE := libopenssl${TARG}.a

CFLAGS += -w -Wno-unused-parameter -Wno-int-conversion
A32_CFLAGS += -w -Wno-unused-parameter -Wno-int-conversion

CPPFLAGS += -I$(TEELIB)/libopenssl/include
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/include
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/include/crypto
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/include/openssl
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/sm2
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/sm3
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/sm4
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/ec
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/ec/curve448
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/ec/curve448/arch_32
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/evp
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/modes
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/crypto/siphash
CPPFLAGS += -I$(PREBUILD_DIR)/headers/libc

CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/providers/common/include
CPPFLAGS += -I$(TEELIB)/libopenssl/openssl/providers/implementations/include

ifeq (${CONFIG_CRYPTO_SOFT_ENGINE},openssl3)
include $(TEELIB)/libopenssl/openssl3.mk
else
include $(TEELIB)/libopenssl/openssl.mk
endif

ifeq ($(CONFIG_OPENSSL_NO_ASM),true)
	LOCAL_SRC_FILES += $(OPENSSL_CRYPTO_PATH)/mem_clr.c
endif


ASFLAGS := $(filter-out -march=armv8-a+nofp, $(ASFLAGS)) -march=armv8-a
CFLAGS := $(filter-out -fno-builtin-memcpy, $(CFLAGS))
CFLAGS := $(filter-out -march=armv8-a+nofp, $(CFLAGS)) -march=armv8-a
A32_CFLAGS := $(filter-out -fno-builtin-memcpy, $(CFLAGS))
A32_CFLAGS := $(filter-out -march=armv8-a+nofp, $(A32_CFLAGS)) -march=armv8-a

ifeq (${CONFIG_UNALIGNED_ACCESS},y)
ifeq (${TARG},_a32)
# Now if enable "-fmax-type-align=1" with "-DOPENSSL_THREADS", compile will be generated a "__atomic_fetch_add_4" undefined ;
# Then using "DSRTICT_ALIGMENT" to avoid this problem after solve the undefined symbol;
CFLAGS := $(filter-out -fmax-type-align=1, $(CFLAGS)) -fmax-type-align=4
CFLAGS := $(filter-out -munaligned-access, $(CFLAGS))
CFLAGS += -DSRTICT_ALIGMENT
A32_CFLAGS := $(filter-out -fmax-type-align=1, $(A32_CFLAGS)) -fmax-type-align=4
A32_CFLAGS := $(filter-out -munaligned-access, $(A32_CFLAGS))
A32_CFLAGS += -DSRTICT_ALIGMENT
endif
endif

include $(BUILD_LIB)/lib-common.mk
