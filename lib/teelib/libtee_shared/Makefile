# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

SONAME := libtee_shared$(TARG).so

libtee_shared_c_files := $(wildcard src/*.c)

inc-flags += -I$(DRIVERS_PATH)/include # dynion.h
inc-flags += -I$(TEELIB)/libtee_shared/include
inc-flags += -I$(TEELIB)/libdrv/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libstub/include
inc-flags += -I$(PREBUILD_HEADER)/sys

include $(BUILD_LIB)/lib-common.mk
include $(BUILD_CONFIG)/feature-macro.mk

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
flags += -DCONFIG_TEE_MISC_DRIVER
endif

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

target: $(INSTALL_FILE)
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "[ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

libtee_shared_c_files :=  $(filter-out src/gk_auth_token.c, $(libtee_shared_c_files))

ifeq ($(strip $(TARGET_BUILD_VARIANT)), user)
flags += -DDEF_BUILDUSERMODE
endif

ifeq ($(CONFIG_EXPORT_OPENSSL_SYMBOL), true)
flags += -DSUPPORT_EXPORT_OPENSSL_SYMBOL
endif

ifeq (${CONFIG_DYN_IMPORT_CERT},y)
flags += -DDYN_IMPORT_CERT=1
endif

EXTERN_FILE := oh_extern.txt
EXPORT_FILE := oh_export.txt

${BUILD_DIR}/$(EXTERN_FILE): $(EXTERN_FILE) ${BUILD_DIR}/$(EXPORT_FILE)
	@echo "preprocess ${BUILD_DIR}/$(EXTERN_FILE)"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<
${BUILD_DIR}/$(EXPORT_FILE): $(EXPORT_FILE)
	@echo "preprocess ${BUILD_DIR}/$(EXPORT_FILE)"
	@mkdir -p $(@D)
	@${CC} ${flags} -P -E -o $@ -x c $<
ld-flags := -lcrypto_hal$(TARG) -ltimer$(TARG) -lagent$(TARG) -lagent_base$(TARG) -ldrv$(TARG) \
    -lteeos$(TARG) -lpermission_service$(TARG) -lswcrypto_engine$(TARG) -ltaentry$(TARG) -lteeagentcommon_client$(TARG) -lcrypto$(TARG) \
    -lteeconfig$(TARG) -lteemem$(TARG) -lssa$(TARG) -lhuk${TARG} -lteedynsrv$(TARG) -lipc_hal$(TARG)


ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),mbedtls)
ld-flags += -lmbedtls${TARG}
else ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),openssl3)
ld-flags += -lopenssl${TARG}
flag += -DOPENSSL3_ENABLE
else
ld-flags += -lopenssl${TARG}
flag += -DOPENSSL_ENABLE
endif

ifeq ($(findstring true, $(CONFIG_SE_SERVICE_32BIT) $(CONFIG_SE_SERVICE_64BIT)), true)
ld-flags += -lse$(TARG)
endif

ld-flags += -z separate-loadable-segments

$(MODULE_FILE): $(BUILD_DIR)/$(EXTERN_FILE) $(libtee_shared_objs)
	@echo "LibTEE [LD] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/$(EXPORT_FILE) -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096
	$(VER)$(OBJCOPY) $@
