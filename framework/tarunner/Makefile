# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# DRIVER is a driver

DRIVER := tarunner${TARG}.elf

include $(BUILD_CONFIG)/var.mk

tarunner_c_files := $(wildcard src/*.c)

# Libraries
LIBS := c_shared${TARG}

inc-flags += -I$(SYSLIB)/libspawn_common/include/
inc-flags += -I$(DRVLIB)/libdrv_shared/src/
inc-flags += -I$(TEELIB)/libteeconfig/include/
inc-flags += -I$(TEELIB)/libagent_base/include/
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libipc_hal/include
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(PREBUILD_HEADER)/sys
inc-flags += -I$(FRAMEWORK_PATH)/gtask/src/framework

LIBS += ipc_hal${TARG}

# drv makefile will fully link a binary.
include $(BUILD_SERVICE)/svc-common.mk
tarunner_LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so -e main
