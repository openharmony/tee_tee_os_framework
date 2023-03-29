# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# MODULE
MODULE := libdynconfmgr${TARG}.a

ifeq ($(CONFIG_DYN_CONF), true)
flags += -DTEE_SUPPORT_DYN_CONF
endif

inc-flags += -I$(SYSLIB)/libdynconfmgr/include
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteemem/include

# Source files required to build the target
libdynconfmgr_c_files += $(wildcard src/*.c)

include $(BUILD_LIB)/lib-common.mk
