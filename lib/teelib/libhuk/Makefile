# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
MODULE := libhuk${TARG}.a

CFILES += $(wildcard src/tee_huk_derive_key.c)
CFILES += $(wildcard src/tee_huk_get_device_id.c)
CFILES += $(wildcard src/huk_service_msg_call.c)

CPPFLAGS += -I$(TEELIB)/libhuk/include
CPPFLAGS += -I$(TEELIB)/libhuk/src/huk_service
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include/TEE_ext
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libssa/include
CPPFLAGS += -I$(PREBUILD_HEADER)/sys

include $(BUILD_LIB)/lib-common.mk
