# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# TARGET is an app
TARGET := huk_service${TARG}.elf

include $(BUILD_CONFIG)/var.mk

CFILES := $(wildcard src/*.c)

inc-flags += -I$(SERVICES_PATH)/huk_service/include
inc-flags += -I$(SERVICES_PATH)/huk_service/src
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libswcrypto_engine/include/
inc-flags += -I$(TEELIB)/libcrypto_hal/include/
inc-flags += -I$(TEELIB)/libteeconfig/include/
inc-flags += -I$(TEELIB)/libteeconfig/include/TEE_ext/
inc-flags += -I$(TEELIB)/libtee_shared/include/
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libhuk/include
inc-flags += -I$(TEELIB)/libssa/include
inc-flags += -I$(TEELIB)/libssa/src
inc-flags += -I$(TEELIB)/libipc_hal/include
inc-flags += -I$(PREBUILD_HEADER)/sys

LDFLAGS += -z noexecstack

include $(BUILD_FRAMEWORK)/ta-common.mk
include $(BUILD_CONFIG)/feature-macro.mk
