# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
MODULE := libssa${TARG}.a

CFILES   := $(wildcard src/*.c)
CPPFLAGS += -I$(TEELIB)/libssa/include
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee # tee_inner_uuid.h
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(TEELIB)/libhuk/include
CPPFLAGS += -I$(TEELIB)/libipc_hal/include

CFLAGS += -DOPENSSL_ENABLE
A32_CFLAGS += -DOPENSSL_ENABLE

include $(BUILD_LIB)/lib-common.mk
