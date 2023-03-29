# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

SONAME := libdrv_shared$(TARG).so

libdrv_shared_c_files :=

libdrv_shared_c_files += src/io_operations.c
libdrv_shared_c_files += src/drv_share.c
libdrv_shared_c_files += $(DRVLIB)/common/libdrv_frame/src/drv_thread.c
libdrv_shared_c_files += $(DRVLIB)/common/libdrv_frame/src/drv_param_ops.c

ifneq ($(CONFIG_DRVMGR_64BIT), )
libdrv_shared_c_files += src/tee_drv_entry.c
libdrv_shared_c_files += src/drv_dispatch.c
libdrv_shared_c_files += src/drv_operations.c

ifneq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), )
flags += -DCRYPTO_MGR_SERVER_ENABLE
libdrv_shared_c_files += src/drv_random.c
endif

ifeq ($(WITH_ENG_VERSION), true)
flags += -DTEE_SUPPORT_CMD_DUMP
flags += -DTEE_SUPPORT_DRV_FD_DUMP
endif
endif

include $(BUILD_LIB)/lib-common.mk
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(PREBUILD_HEADER)/libc/arch/$(ARCH)/bits
inc-flags += -I$(DRVLIB)/common/libdrv_frame/include
inc-flags += -I$(DRVLIB)/libdrv_shared/include
inc-flags += -I$(TEELIB)/libdrv/include
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(TEELIB)/libipc_hal/include

ifneq ($(CONFIG_DRVMGR_64BIT), )
inc-flags += -I$(SYSLIB)/libspawn_common/include
inc-flags += -I$(TEELIB)/libteeconfig/include
endif

include $(BUILD_CONFIG)/feature-macro.mk

MODULE_FILE = $(BUILD_DIR)/$(SONAME)
INSTALL_FILE = $(LIB_DIR)/$(SONAME)

target: $(INSTALL_FILE)
$(INSTALL_FILE): $(MODULE_FILE)
	@test -d $(LIB_DIR) || mkdir -p $(LIB_DIR)
	@echo "libdrv_shared [ INSTALL ] $(MODULE_FILE)"
	$(VER)cp -rafp $(MODULE_FILE) $(LIB_DIR)

$(BUILD_DIR)/extern.txt: extern.txt $(BUILD_DIR)/export.txt
	@echo "libdrv_shared preprocess ${BUILD_DIR}/extern.txt"
	@mkdir -p $(@D)
	@echo "libdrv_shared extern ${flags}"
	@${CC} ${flags} -P -E -o $@ -x c $<
$(BUILD_DIR)/export.txt: export.txt
	@echo "libdrv_shared preprocess ${BUILD_DIR}/export.txt"
	@mkdir -p $(@D)
	@echo "libdrv_shared export ${flags}"
	@${CC} ${flags} -P -E -o $@ -x c $<

ld-flags :=
ld-flags += -lhwi$(TARG) -lc_shared$(TARG) -lteemem$(TARG) -lteeconfig$(TARG) -lio$(TARG)

ld-flags += -z separate-loadable-segments

$(MODULE_FILE): $(BUILD_DIR)/extern.txt $(libdrv_shared_objs)
	@echo "libdrv_shared xom32_disable ld-flags is $(ld-flags) [ LD ] $@ LIB_DIR=$(LIB_DIR)"
	$(VER)$(LD) --shared -X -EL -z text -z now -z relro -z noexecstack --gc-sections --version-script=$(BUILD_DIR)/export.txt -o $@ \
		$^ -L$(LIB_DIR) -L$(PREBUILD_LIBS)/$(ARCH) --start-group \
		$(LIBCOMPILER_RT_BUILTINS) --end-group $(ld-flags) -nostdlib -z max-page-size=4096
	$(VER)$(OBJCOPY) $@
