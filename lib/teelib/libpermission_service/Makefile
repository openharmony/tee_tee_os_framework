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
MODULE := libpermission_service${TARG}.a

# This library only provides 32-bit headers of libbteeos.
# If we want 64-bit headers of libteeos, we should depend on libac temporarily.

CPPFLAGS += -I$(TEELIB)/libpermission_service/include
CPPFLAGS += -I$(TEELIB)/libpermission_service/src
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libswcrypto_engine/include
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(SYSLIB)/libelf_verify/include

CFILES := $(wildcard src/permsrv_api_imp.c)
CFILES += $(wildcard src/permsrv_api.c)

include $(BUILD_LIB)/lib-common.mk
