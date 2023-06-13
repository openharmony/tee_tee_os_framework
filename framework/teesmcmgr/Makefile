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
TARGET := teesmcmgr.elf

TA_NAME := teesmcmgr

include $(BUILD_CONFIG)/var.mk

PWD := $(shell pwd)

flags += -I$(PWD)/include
flags += -I$(PREBUILD_HEADER)/sys
flags += -I$(TEELIB)/libteeos/include/tee

LDFLAGS += -z noexecstack -u main -e main

# Source files required to build the target
teesmcmgr_c_files :=  $(wildcard src/*.c)

$(BUILD_DIR)/$(TA_NAME): $(BUILD_DIR)/$(TARGETS)
	cp $< $@

# Libraries
LIBS := c_shared$(TARG)
LDFLAGS += --dynamic-linker=libc_shared$(TARG).so

include $(BUILD_SERVICE)/svc-common.mk

flags += -fvisibility=default
