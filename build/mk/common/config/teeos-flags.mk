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
#teeos-flags.mk
#

ifeq ($(CONFIG_DEBUG_BUILD), y)
CFLAGS += -g
ASFLAGS += -g
A32_CFLAGS += -g
A32_ASFLAGS += -g
endif

C_OPTIM_FLAGS :=
ifeq (${CONFIG_USER_CFLAGS},)
    CFLAGS += $(WARNINGS:%=-W%) -nostdinc -std=gnu11
    CXXFLAGS += $(WARNINGS:%=-W%) -nostdinc -std=gnu++14

    ifeq (${CONFIG_USER_OPTIMIZATION_Os},y)
        C_OPTIM_FLAGS += -Oz
    endif
    ifeq (${CONFIG_USER_OPTIMIZATION_O0},y)
        C_OPTIM_FLAGS += -O0
    endif
    ifeq (${CONFIG_USER_OPTIMIZATION_O1},y)
        C_OPTIM_FLAGS += -O1
    endif
    ifeq (${CONFIG_USER_OPTIMIZATION_O3},y)
        C_OPTIM_FLAGS += -O3
    endif
    ifeq (${CONFIG_USER_OPTIMIZATION_O2},y)
        C_OPTIM_FLAGS += -O2
    endif

    ifeq (${CONFIG_LINK_TIME_OPTIMIZATIONS},y)
        C_OPTIM_FLAGS += -flto
        STARTGROUP :=
        ENDGROUP :=
    endif

    CFLAGS += $(C_OPTIM_FLAGS)
    CXXFLAGS += $(C_OPTIM_FLAGS)

    CFLAGS += $(NK_CFLAGS)
    CXXFLAGS += $(NK_CXXFLAGS)
else
	CFLAGS += ${CONFIG_USER_CFLAGS}
endif

CFLAGS += -fno-omit-frame-pointer
CFLAGS += -fno-builtin-aligned_alloc    \
	-fno-builtin-alloca \
	-fno-builtin-calloc \
	-fno-builtin-fwrite	\
	-fno-builtin-fread	\
	-fno-builtin-fseek	\
	-fno-builtin-fclose	\
	-fno-builtin-malloc \
	-fno-builtin-memcpy	\
	-fno-builtin-memcmp	\
	-fno-builtin-memset	\
	-fno-builtin-memmove	\
	-fno-builtin-realloc    \
	-fno-builtin-strncmp	\
	-fno-builtin-strlen	\
	-fno-builtin-strncpy	\
	-fno-builtin-strncat	\
	-fno-builtin-posix_memalign \
	-fno-builtin-printf	\
	-fno-builtin-snprintf \
	-fno-builtin-vsnprintf \
	-fno-builtin-fwrite_unlocked \
	-fno-builtin-memchr \
	-fno-builtin-strcspn\
	-fno-builtin-strspn \
	-fno-builtin-bcmp \
	-fno-builtin-bcopy \
	-fno-builtin-bzero \
	-fno-builtin-strncasecmp \
	-fno-builtin-stpncpy \
	-fno-builtin-strndup \

ifeq (${CONFIG_WHOLE_PROGRAM_OPTIMIZATIONS_USER},y)
    LDFLAGS += -fwhole-program
endif

ifeq ($(USE_LIBC), y)
	CFLAGS := $(filter-out -march=armv8-a+nofp, $(CFLAGS)) -march=armv8-a
endif

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
	CPPFLAGS += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

#start add to A32_CFLAGS

ifeq ($(CONFIG_UBSAN),y)
A32_CFLAGS += -fsanitize=bounds-strict -fsanitize-address-use-after-scope -fsanitize-undefined-trap-on-error
endif

ifeq ($(USE_NDK_32), y)
  A32_CFLAGS += -nodefaultlibs -nostartfiles
  LDFLAGS += --eh-frame-hdr --allow-shlib-undefined
endif

ifeq ($(USE_NDK_64), y)
  CFLAGS += -nodefaultlibs -nostartfiles
  LDFLAGS += --eh-frame-hdr --allow-shlib-undefined
  CFLAGS := $(filter-out -march=armv8-a+nofp -nostdinc -march=armv8-a, $(CFLAGS)) -march=armv8-a
endif

ASFLAGS += $(NK_ASFLAGS)

A32_CFLAGS +=	-march=$(ARMV)		\
		-nostdinc \
		-nodefaultlibs \
		-fno-short-enums	\
		-fno-builtin-aligned_alloc  \
		-fno-builtin-alloca \
		-fno-builtin-calloc \
		-fno-builtin-fwrite	\
		-fno-builtin-fread	\
		-fno-builtin-fseek	\
		-fno-builtin-fclose	\
		-fno-builtin-malloc \
		-fno-builtin-memcpy	\
		-fno-builtin-memcmp	\
		-fno-builtin-memset	\
		-fno-builtin-memmove	\
		-fno-builtin-realloc    \
		-fno-builtin-strncmp	\
		-fno-builtin-strlen	\
		-fno-builtin-strncpy	\
		-fno-builtin-strncat	\
		-fno-builtin-posix_memalign \
		-fno-builtin-printf	\
		-fno-builtin-snprintf \
		-fno-builtin-vsnprintf \
		-fno-builtin-fwrite_unlocked \
		-fno-builtin-memchr \
		-fno-builtin-strcspn\
		-fno-builtin-strspn \
		-fno-builtin-bcmp \
		-fno-builtin-bcopy \
		-fno-builtin-bzero \
		-fno-builtin-strncasecmp \
		-fno-builtin-stpncpy \
		-fno-builtin-strndup \
		-fno-omit-frame-pointer


ifeq (${CONFIG_USER_LINKER_GC_SECTIONS},y)
    A32_CFLAGS += -ffunction-sections
    A32_CFLAGS += -fdata-sections
    A32_LDFLAGS += --gc-sections
endif

A32_CFLAGS += -fPIC

ifeq (${CONFIG_UNALIGNED_ACCESS},y)
	A32_CFLAGS += -munaligned-access -fmax-type-align=1
endif

ifeq ($(CONFIG_CC_STACKPROTECTOR_STRONG),y)
	A32_CFLAGS += -fstack-protector-strong
endif


ifeq (${CONFIG_USER_FULL_RELRO},y)
	NK_LDFLAGS += -z relro -z now
ifeq ($(TARGET_IS_ARM32),y)
ifneq ($(USE_NDK_32),y)
ifneq ($(TARGET_CUSTOM_LINK_SCRIPT),y)
	NK_LDFLAGS += -T $(COMMON_PATH)/app-arm-eabi.lds
endif
endif
endif
endif

ifeq (${TARGET_IS_ARM32},y)
	CFLAGS += ${A32_CFLAGS}
	CXXFLAGS += ${A32_CXXFLAGS}
ifeq ($(USE_NDK_64), y)
	CFLAGS := $(filter-out -nostdinc,$(CFLAGS))
endif

ifeq ($(USE_NDK_32), y)
	CFLAGS := $(filter-out -nostdinc,$(CFLAGS))
endif
endif

CFLAGS += -DARM_PAE=1

ifeq ($(TARGET_IS_HOST),)
ifeq ($(CONFIG_LLVM_LTO),y)
CFLAGS += -flto -fsplit-lto-unit
endif
endif
