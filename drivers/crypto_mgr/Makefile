# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

DRIVER := crypto_mgr.elf

include $(BUILD_CONFIG)/var.mk

crypto_mgr_c_files += $(wildcard src/*.c) \
                      $(wildcard src/crypto_ioctl/*.c)

inc-flags += -I$(FRAMEWORK_PATH)/drvmgr/src
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(DRVLIB)/common/libdrv_frame/include
inc-flags += -I$(DRVLIB)/libdrv_shared/src
inc-flags += -I$(DRIVERS_PATH)/crypto_mgr/src/crypto_ioctl/
inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libtimer/include
inc-flags += -I$(TEELIB)/libteemem/include

# Libraries

SVC_PARTITIAL_LINK = y
include $(BUILD_SERVICE)/svc-common.mk
