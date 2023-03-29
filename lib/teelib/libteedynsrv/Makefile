# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

MODULE := libteedynsrv${TARG}.a

libteedynsrv_c_files += $(wildcard src/*.c)
inc-flags += -I$(TEELIB)/libteedynsrv/include
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libtimer/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(TEELIB)/libipc_hal/include
inc-flags += -I$(PREBUILD_HEADER)/sys
# Libraries
include $(BUILD_CONFIG)/feature-macro.mk
include $(BUILD_LIB)/lib-common.mk


