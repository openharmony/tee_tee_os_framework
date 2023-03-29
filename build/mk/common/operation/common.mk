# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

MODULE_FOLDER := $(shell basename $(CURDIR))

ifeq ($(ARCH),)
$(error ARCH must be set, now we support both arm and aarch64)
endif

# default target
default: all

inc-flags += -I$(TEE_SECUREC_DIR)/include
INCLUDE_PATH += $(PREBUILD_DIR)/headers/
INCLUDE_PATH += $(TOPDIR)/tools/

ifeq ($(TARGET_IS_HOST),)
# use musl lib c headers.
inc-flags += -I$(PREBUILD_LIBC_INC) -I$(PREBUILD_LIBC_INC)/arch/generic -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)
## for some header file include "alltypes.h" directly.
inc-flags += -I$(PREBUILD_LIBC_INC)/arch/$(ARCH)/bits
flags += -nodefaultlibs -nostdinc -std=gnu11
endif

# all target flags for both c & c++ compiler
ifneq ($(TARGET_IS_HOST),y)
flags += -Oz
else
#gcc optimization flags
flags += -Os
endif

ifeq ($(TARGET_IS_HOST),)
ifeq ($(CONFIG_LLVM_LTO),y)
flags += -flto -fsplit-lto-unit
endif
endif

# other options
flags += -fPIC -fstack-protector-strong
flags += -fno-omit-frame-pointer -fno-short-enums
flags += -include$(PREBUILD_DIR)/headers/platautoconf.h
flags += -DARM_PAE=1
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DDEBUG -DHM_DEBUG_KERNEL -DNDEBUG
flags += -DHAVE_AUTOCONF
flags += -DVFMW_EXTRA_TYPE_DEFINE -DENV_SOS_KERNEL
ifeq ($(CONFIG_UBSAN),y)
flags += -fsanitize=bounds-strict -fsanitize-address-use-after-scope -fsanitize-undefined-trap-on-error
endif

## argument pointer will be aligned with 1 Byte
ifneq ($(TARGET_IS_HOST),y)
ifeq ($(ARCH),arm)
ifeq (${CONFIG_UNALIGNED_ACCESS},y)
flags += -munaligned-access -fmax-type-align=1
endif
endif
endif
flags += -fno-builtin
flags += -D__FILE__=0 -Wno-builtin-macro-redefined

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
flags += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

ifeq ($(CONFIG_DEBUG_BUILD), y)
CFLAGS += -g
ASFLAGS += -g
endif

LDFLAGS += -s -z separate-loadable-segments

# all target for c++ compiler
cxx-flags += -funwind-tables -fexceptions -std=gnu++11 -frtti -fno-builtin

#include the sub makefile as needed
include $(BUILD_CONFIG)/var.mk
include $(BUILD_OPERATION)/rule.mk

flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
CFLAGS   += ${TRUSTEDCORE_PLATFORM_FLAGS}
CPPFLAGS += ${TRUSTEDCORE_PLATFORM_FLAGS}
CXXFLAGS += ${TRUSTEDCORE_PLATFORM_FLAGS}
ASFLAGS  += ${TRUSTEDCORE_PLATFORM_FLAGS}
# always generate compiling object file rule
$(eval $(call eval_objs,$(MODULE_FOLDER)))

# compile libs
ifneq ($(MODULE),)
INSTALL_FILE := $(LIB_DIR)/$(MODULE)
MODULE_FILE  := $(BUILD_DIR)/$(MODULE)
target: $(MODULE_FILE)
$(eval $(call eval_libs,$(MODULE_FOLDER),$(MODULE_FILE)))
## install libs
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL MODULE ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(INSTALL_FILE)
	touch $(INSTALL_FILE)
endif

ifneq ($(TARGET)$(DRIVER),)
ifneq ($(TARGET),)
INSTALL_FILE := $(APP_DIR)/$(TARGET)
TARGET_FILE  := $(BUILD_DIR)/$(TARGET)
else
INSTALL_FILE := $(DRV_DIR)/$(DRIVER)
TARGET_FILE  := $(BUILD_DIR)/$(DRIVER)
endif
target: $(TARGET_FILE)
$(eval $(call eval_dep_libs,$(MODULE_FOLDER),$(LIB_DIR),$(LIBS:%=lib%.a)))
$(eval $(call eval_elf,$(MODULE_FOLDER),$(TARGET_FILE)))
$(INSTALL_FILE): $(TARGET_FILE)
	@test -d $(APP_DIR) || mkdir -p $(APP_DIR)
	@test -d $(DRV_DIR) || mkdir -p $(DRV_DIR)
	$(VER)cp -rafp $(TARGET_FILE) $(INSTALL_FILE)
	touch $(INSTALL_FILE)
endif

# all the target
all: target install

## this is ugly..
ifneq ($(EXPORT_HDRS),)
install_headers:
	@echo "cp export_hdrs=${EXPORT_HDRS} installdir=${HDR_INSTALL_DIR}"
	@ cp -raf $(EXPORT_HDRS) $(HDR_INSTALL_DIR)/
else
install_headers:

endif
install: $(INSTALL_FILE)
