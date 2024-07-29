# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

ifeq ($(CONFIG_LLVM_CFI),y)

ifeq ($(CONFIG_LLVM_LTO),y)
tee-sanitize-cfi := -fsanitize=cfi -fno-sanitize-cfi-cross-dso
else
$(info use cfi $(tee-sanitize-cfi) please set CONFIG_LLVM_LTO)
endif

## can't support -fno-sanitize-trap=cfi -fsanitize-recover=cfi
ifeq ($(findstring fvisibility=hidden,$(flags)),)
apps-sanitize-cfi += -fvisibility=default
endif

ifeq ($(ARCH),aarch64)
cfi-no-icall := libswcrypto_engine.a tarunner.elf libtimer.a libcrypto_hal.a libteeos.a libpermission_service.a libtaentry.a \
	libcrypto.a libssa.a

ifneq ($(filter $(cfi-no-icall),$(MODULE)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(cfi-no-icall),$(DRIVER)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

else #32bit

cfi-no-icall := libswcrypto_engine_a32.a tarunner_a32.elf libtimer_a32.a libcrypto_hal_a32.a libteeos_a32.a \
	libpermission_service_a32.a libtaentry_a32.a libcrypto_a32.a libssa_a32.a libdrv_frame_a32.a

no-cfi:= libopenssl${TARG}.a

ifneq ($(filter $(cfi-no-icall),$(MODULE)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(cfi-no-icall),$(DRIVER)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(cfi-no-icall),$(TARGET)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(no-cfi),$(MODULE)), )
apps-sanitize-cfi :=
endif

ifneq ($(filter $(no-cfi),$(DRIVER)), )
apps-sanitize-cfi :=
endif

ifneq ($(filter $(no-cfi),$(TARGET)), )
apps-sanitize-cfi :=
endif

endif#aarch64

flags += $(apps-sanitize-cfi)
$(info inapps $(DRIVER)$(MODULE)$(TARGET) use $(apps-sanitize-cfi))
endif #CONFIG_LLVM_CFI
