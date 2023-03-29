# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
MODULE := libdrv_frame${TARG}.a

include $(BUILD_CONFIG)/var.mk

flags += -fno-builtin
flags += -I$(DRVLIB)/common/libdrv_frame/include/
flags += -I$(TEELIB)/libtimer/include/
flags += -I$(TEELIB)/libdrv/include
flags += -I$(TEELIB)/libteeos/include/legacy
flags += -I$(TEELIB)/libteeos/include/tee
flags += -I$(TEELIB)/libteeos/src/log/
flags += -I$(TEELIB)/libteemem/include
flags += -I$(TEELIB)/libipc_hal/include

flags += -I$(DRIVERS_PATH)/include
flags += -I$(TEELIB)/libteeconfig/include/
flags += -I$(PREBUILD_HEADER)/sys

# Source files required to build the target
libdrv_frame_c_files := $(wildcard src/*.c)

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(DRVLIB)/common/libdrv_frame/include/*)

include $(BUILD_DRIVER)/drv-common.mk
