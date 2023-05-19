# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

TEED_DIR  := services/spd/teed

SPD_INCLUDES        := -Iservices/spd/teed/include      \
                       -Iinclude/bl31                   \
                       -Iinclude/lib                    \
                       -Iinclude/lib/el3_runtime        \
                       -Iinclude/lib/psci               \
                       -Iinclude/common                 \
                       -Iinclude/plat/common            \
                       -Iinclude/lib/el3_runtime/aarch64

SPD_SOURCES := services/spd/teed/src/teed_common.c \
               services/spd/teed/src/teed_helpers.S \
               services/spd/teed/src/teed_main.c \
               services/spd/teed/src/teed_pm.c \
               services/spd/teed/src/teed_global.c

CTX_INCLUDE_FPREGS := 1
NEED_BL32       :=  yes

#CFLAGS += -DBOOT_BL32_FROM_OTHER_EXCEPTION

ifeq ($(EL3_EXCEPTION_HANDLING),1)
ifeq ($(TEE_NS_INTR_ASYNC_PREEMPT),0)
$(error When EL3_EXCEPTION_HANDLING=1, TEE_NS_INTR_ASYNC_PREEMPT must also be 1)
endif
endif
