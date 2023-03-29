# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

TARGET_IS_TA := y
# setup toolchain
include $(BUILD_CONFIG)/cfg.mk
include $(BUILD_CONFIG)/toolchain.mk
include $(BUILD_OPERATION)/common.mk

inc-flags += $(INCLUDE_PATH:%=-I%)

# for ld flags
ifeq ($(ARCH),aarch64)
LDFLAGS += -x -z text -z now -z relro -z max-page-size=4096 -shared -z noexecstack --strip-debug
flags += -fvisibility=hidden
else
LDFLAGS += -x -z text -z now -z relro -shared -z noexecstack
flags += -fvisibility=hidden
endif

LINK_LIBS=$(LIBS:%=-l%)
LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) $(LINK_LIBS)
flags += $(INCLUDES)

include $(BUILD_CFI)/llvm-apps-cfi.mk

### HM_NOTE: where added this flags  while compiling tee kernel
### 	     do it later.
LDFLAGS:=$(filter-out -pie,$(LDFLAGS))
LDFLAGS:=$(filter-out --gc-sections,$(LDFLAGS))
