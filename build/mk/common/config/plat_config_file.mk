# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

export PLAT_AUTOCONF_FILE := $(PREBUILD_DIR)/headers/platautoconf.h

DEBUG_RELEASE_MACRO := release
ifeq ($(PLAT_CONFIG_DEBUG), true)
DEBUG_RELEASE_MACRO := debug
endif

export CONFIG_FILE := $(TOPDIR)/config/$(DEBUG_RELEASE_MACRO)_config/$(TARGET_BOARD_PLATFORM)_$(DEBUG_RELEASE_MACRO)_config
