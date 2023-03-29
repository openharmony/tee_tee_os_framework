# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
#
#toolchain.mk
#
export TOOLCHAIN_ROOT=$(TEE_CLANG_DIR)

export CLANG_TOOLCHAIN   := $(TOOLCHAIN_ROOT)
export PATH := $(CLANG_TOOLCHAIN):$(PATH)
CROSS_COMPILE := $(CLANG_TOOLCHAIN)

override CC      := $(SOURCEANALYZER) $(CCACHE) $(CROSS_COMPILE)/clang
override CXX     := $(SOURCEANALYZER) $(CCACHE) $(CROSS_COMPILE)/clang++
override AS      := $(CROSS_COMPILE)/llvm-as
override LD      := $(CROSS_COMPILE)/ld.lld
override CPP     := $(srctree)/kernel/clang-cpp
# disable ar creating debug
override AR      := $(CROSS_COMPILE)/llvm-ar 2>/dev/null
override NM      := $(CROSS_COMPILE)/llvm-nm
override OBJCOPY := $(CROSS_COMPILE)/llvm-objcopy
override READELF := $(CROSS_COMPILE)/llvm-readelf
override STRIP   := $(CROSS_COMPILE)/llvm-strip
override RANLIB  := $(CROSS_COMPILE)/llvm-ranlib

export CC CXX AS LD CPP AR NM OBJCOPY READELF STRIP

# clang need `--target=$(TARGET_ARCH)` option
export TARGET_ARCH_32 := arm-linux-gnueabi
export TARGET_ARCH_64 := aarch64-linux-gnu

ifeq ($(ARCH), arm)
	TARGET_ARCH := $(TARGET_ARCH_32)
	LIBCOMPILER_RT_BUILTINS := $(TEE_COMPILER_DIR)/lib/arm-linux-ohosmusl/libclang_rt.builtins.a
ifeq (${CONFIG_THUMB_SUPPORT},y)
    flags += -mthumb
endif
ifeq ($(CONFIG_ARM_CORTEX_A15),y)
    flags += -march=armv7ve
endif
ifeq ($(CONFIG_ARM_CORTEX_A53),y)
    flags += -march=armv8-a
endif
else
	TARGET_ARCH := $(TARGET_ARCH_64)
	LIBCOMPILER_RT_BUILTINS := $(TEE_COMPILER_DIR)/lib/aarch64-linux-ohosmusl/libclang_rt.builtins.a
    flags += -march=armv8-a
ifeq ($(CONFIG_ARM_CORTEX_A53),y)
    ASFLAGS += -march=armv8-a
    ASFLAGS += -mcpu=cortex-a53
endif
endif

flags     += --target=$(TARGET_ARCH)
cxx-flags += --target=$(TARGET_ARCH)
asflags   += --target=$(TARGET_ARCH)
