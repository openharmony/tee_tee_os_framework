# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

MODULE := libtaentry${TARG}.a

CFILES := $(wildcard src/*.c)

CPPFLAGS += -I$(TEELIB)/libteeconfig/include/TEE_ext
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libipc_hal/include
CPPFLAGS += -I$(FRAMEWORK_PATH)/tarunner/src

ifeq ($(CONFIG_TEST_CA_CHECK),y)
    CPPFLAGS += -I$(TEELIB)/libteeconfig/src/tee_test_config
endif

include $(BUILD_LIB)/lib-common.mk
