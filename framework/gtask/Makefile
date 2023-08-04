# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# TARGET is an app

DRIVER := gtask${TARG}.elf

include $(BUILD_CONFIG)/var.mk
ifeq ($(CONFIG_DYN_TA_FORMAT),1)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),2)
flags += -DDYN_TA_SUPPORT_V3
else ifeq ($(CONFIG_DYN_TA_FORMAT),3)
flags += -DDYN_TA_SUPPORT_V3
else
$(error "dynamic TA format not supported, please check CONFIG_DYN_TA_FORMAT")
endif

PWD := $(shell pwd)

gtask_c_files := $(wildcard src/*.c)
gtask_c_files   += $(wildcard src/*/*.c)
gtask_c_files   += $(wildcard src/*/*/*.c)

inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/gtask/include
inc-flags += -I$(TEELIB)/libteeconfig/src/tee_config
inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include

inc-flags += -I$(TEELIB)/libopenssl/openssl/include
inc-flags += -I$(TEELIB)/libopenssl/openssl/crypto
inc-flags += -I$(PREBUILD_HEADER)/sys
inc-flags += -I$(SYSLIB)/libelf_verify/include
inc-flags += -I$(PWD)/../teesmcmgr/src
inc-flags += -I$(PWD)/src/init
inc-flags += -I$(PWD)/src/include
inc-flags += -I$(PWD)/src/app_load
inc-flags += -I$(PWD)/src/framework
inc-flags += -I$(PWD)/src/task_adaptor
inc-flags += -I$(PWD)/src/manager
inc-flags += -I$(PWD)/src
inc-flags += -I$(SYSLIB)/libdynconfmgr/include
inc-flags += -I$(SYSLIB)/libdynconfbuilder/include
inc-flags += -I$(PWD)/../drvmgr/src
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(SYSLIB)/libspawn_common/include/
inc-flags += -I$(TEELIB)/libagent_base/include/
inc-flags += -I$(TEELIB)/libdrv/include/
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libpermission_service/include
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libtimer/include
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libteeconfig/include/kernel
inc-flags += -I$(TEELIB)/libteeconfig/include/TEE_ext
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(TEELIB)/libssa/src
inc-flags += -I$(TEELIB)/libssa/include
inc-flags += -I$(TEELIB)/libhuk/include
inc-flags += -I$(TEELIB)/libse/include
inc-flags += -I$(TEELIB)/libse/src/se_service
inc-flags += -I$(TEELIB)/libipc_hal/include

ifeq ($(product_type), cdc)
$(info product type is cdc)
flags += -DCONFIG_TA_SIGN_CDC
else ifeq ($(product_type), cdc_ace)
$(info product type is cdc_ace)
flags += -DCONFIG_TA_SIGN_CDC
else ifeq ($(product_name), mdc)
$(info product type is mdc)
flags += -DCONFIG_TA_SIGN_MDC
else ifeq ($(product_name), mini)
$(info product type is mini)
flags += -DCONFIG_TA_SIGN_MINI
else ifeq ($(CONFIG_TA_SIGN_KEY_CBG),true)
flags += -DCONFIG_TA_SIGN_CBG
else ifeq ($(CONFIG_HUANGLONG_LOAD_KEY_3072),y)
flags += -DCONFIG_TA_SIGN_HUANGLONG
endif

gtask_c_files := $(filter-out $(FILTEROUT_CFILES), $(gtask_c_files))

LIBS := c_shared${TARG}        \
    tee_shared${TARG}      \
    permission_service${TARG} \
    teemem${TARG}          \
    drv${TARG}           \
    teeconfig${TARG}       \
    dynconfmgr${TARG}      \
    dynconfbuilder${TARG}  \
    spawn_common${TARG}

ifeq ($(findstring y, $(CONFIG_APP_TEE_PERM) $(CONFIG_APP_TEE_PERM_A32)),)
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG}
endif

ifeq ($(CONFIG_TERMINAL_DRV_SUPPORT),y)
LIBS += devchip_api${TARG}
endif

LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so

ENTRY_POINT := main

# drv makefile will fully link a binary.
include $(BUILD_SERVICE)/svc-common.mk
include $(BUILD_CONFIG)/feature-macro.mk

ifeq ($(DRIVER),gtask_a32.elf)
flags := $(filter-out -flto -fsplit-lto-unit,$(flags))
endif

flags += -fstack-protector-all
## gtask will only link here, so so object folder, need to create it.
$(shell mkdir -p $(BUILD_DIR))

#gtask need to print tlogi info log
flags += -DTA_LOG_LEVEL=2

# Suppress Wimplicit-fall-through warning: gtask heavily uses it

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),openssl)
flags += -DOPENSSL_ENABLE
else ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),openssl3)
flags += -DOPENSSL3_ENABLE
endif
