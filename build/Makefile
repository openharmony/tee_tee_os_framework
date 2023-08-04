# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
ifneq ($V,)
VER :=
else
VER := @
endif

ifneq ($(TOPDIR),)
export TOPDIR := $(TOPDIR)
else
export TOPDIR := $(CURDIR)/../
endif

ifneq (${TARGET_BOARD_PLATFORM},)
export TARGET_BOARD_PLATFORM := ${TARGET_BOARD_PLATFORM}
else
export TARGET_BOARD_PLATFORM := oh_64
endif

ifneq (${FRAMEWORK_ELF_PATH},)
export FRAMEWORK_ELF_PATH := ${FRAMEWORK_ELF_PATH}
else
export FRAMEWORK_ELF_PATH := $(TOPDIR)/elf_out
endif

ifneq (${TEE_COMPILER_DIR},)
export TEE_COMPILER_DIR := ${TEE_COMPILER_DIR}
else
export TEE_COMPILER_DIR := $(TOPDIR)/../../../../tools/llvm
endif

ifneq (${LLVM_BASEVER},)
export LLVM_BASEVER := ${LLVM_BASEVER}
else
export LLVM_BASEVER := 15.0.4
endif

ifneq ($(THIRDPARTY),)
	export THIRDPARTY := $(THIRDPARTY)
else
	# Try to find third_party directory in default places
	IS_THIRDPARTY_EMPTY := $(wildcard $(TOPDIR)/../third_party/*)
	ifneq ($(IS_THIRDPARTY_EMPTY),)
		export THIRDPARTY := $(TOPDIR)/../third_party/
	endif

	IS_THIRDPARTY_EMPTY := $(wildcard $(TOPDIR)/../../../third_party/*)
	ifneq ($(IS_THIRDPARTY_EMPTY),)
		export THIRDPARTY := $(TOPDIR)/../../../third_party/
	endif
endif

export TEE_CLANG_DIR := ${TEE_COMPILER_DIR}/bin
export TEE_SECUREC_DIR := $(THIRDPARTY)/bounds_checking_function

export OLD_TOPDIR := $(TOPDIR)/config
export TOOLS      := $(TOPDIR)/build/tools
export VER
export PLATFORM_DIR := $(OLD_TOPDIR)/platform
export TEELIB := $(TOPDIR)/lib/teelib
export DRVLIB := $(TOPDIR)/lib/drvlib
export FRAMEWORK_PATH := $(TOPDIR)/framework
export SYSLIB := $(TOPDIR)/lib/syslib
export SERVICES_PATH := $(TOPDIR)/services
export DRIVERS_PATH := $(TOPDIR)/drivers
export THIRDPARTY_LIBS := $(TOPDIR)/lib/thirdparty
export CONFIG_PATH := $(TOPDIR)/config

export BUILD_TOOLS := $(TOPDIR)/build/tools
export BUILD_PACK := $(TOPDIR)/build/mk/pack
export BUILD_LIB := $(TOPDIR)/build/mk/lib_common
export BUILD_SERVICE := $(TOPDIR)/build/mk/service_common
export BUILD_DRIVER := $(TOPDIR)/build/mk/driver_common
export BUILD_FRAMEWORK := $(TOPDIR)/build/mk/framework_common
export BUILD_CFI := $(TOPDIR)/build/mk/common/cfi
export BUILD_CONFIG := $(TOPDIR)/build/mk/common/config
export BUILD_OPERATION := $(TOPDIR)/build/mk/common/operation

export PREBUILD_ROOT := $(TOPDIR)/prebuild
export OUTPUTDIR := $(TOPDIR)/output

export SDK_VER := tee-kernel-local-release

PHONY += default
default: all

# top directory use aarch64
ARCH = aarch64
include $(BUILD_CONFIG)/var.mk
include $(BUILD_CONFIG)/plat_config_file.mk

PHONY += GEN_CONF_FILE PATCH_OPENSSL

GEN_CONF_FILE:
	echo "generated platautoconf.h "
	rm -rf $(PLAT_AUTOCONF_FILE)
	test -d $(PREBUILD_DIR)/headers || mkdir -p $(PREBUILD_DIR)/headers
	touch $(PLAT_AUTOCONF_FILE)
	grep '.*=.*' < $(CONFIG_FILE) > $(PLAT_AUTOCONF_FILE)
	sed -i '1i\#define PLAT_AUTO_CONFIG_H' $(PLAT_AUTOCONF_FILE)
	sed -i '1i\#ifndef PLAT_AUTO_CONFIG_H' $(PLAT_AUTOCONF_FILE)
	sed -i -r 's/(.*)=y/#define \1\t1/g' $(PLAT_AUTOCONF_FILE)
	sed -i -r '/(.*)=n/d' $(PLAT_AUTOCONF_FILE)
	sed -i -r 's/(.*)=(.*)/#define \1\t\2/g' $(PLAT_AUTOCONF_FILE)
	sed -i '$$a\#endif /* AUTO_CONFIG_H */'  $(PLAT_AUTOCONF_FILE)
	rm -rf $(PREBUILD_DIR)/headers/.config
	cat $(CONFIG_FILE) | tee $(PREBUILD_DIR)/headers/.config

PATCH_OPENSSL:
	@bash $(TOPDIR)/lib/teelib/libopenssl/build_openssl.sh $(THIRDPARTY) $(TOPDIR)

export CONFIG_CRYPTO_SOFT_ENGINE := $(CONFIG_CRYPTO_SOFT_ENGINE)

export PLAT_CFG_DIR := $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/plat_cfg
export PLAT_COMMON_DIR := $(PLATFORM_DIR)/common
ifneq ($(strip $(TARGET_BOARD_PLATFORM)), )
ifeq ($(LIBS_INSTALL_DIR),)
include $(BUILD_PACK)/plat_config.mk
endif
endif
include $(BUILD_CONFIG)/toolchain.mk
include $(BUILD_OPERATION)/project.mk

# for install header
ifeq ($(HDR_INSTALL_DIR),)
HDR_INSTALL_DIR:=$(HDR_L_DIR)
$(shell test -d $(HDR_INSTALL_DIR) || mkdir -p $(HDR_INSTALL_DIR))
endif

# default target
PHONY += libs $(drivers) $(frameworks) $(service) package
all: install_headers setup_links libs $(drivers) $(frameworks) $(service) package
tees: setup_links libs $(drivers) $(frameworks) $(service)
$(drivers): setup_links libs link_libs
$(frameworks): setup_links libs link_libs
$(service): setup_links libs link_libs
package: check_sym
	@mkdir -p $(FRAMEWORK_ELF_PATH)
	@mkdir -p $(FRAMEWORK_ELF_PATH)/apps
	cp -a $(product_apps) $(FRAMEWORK_ELF_PATH)/apps

ifeq ($(CONFIG_SUPPORT_64BIT),)
PHONY += link_libs link_arm_libs link_aarch64_libs $(product_apps)
link_libs: link_arm_libs link_aarch64_libs
endif

ifeq ($(CONFIG_SUPPORT_64BIT), false)
PHONY += link_libs link_arm_libs $(product_apps)
link_libs: link_arm_libs
endif

ifeq ($(CONFIG_SUPPORT_64BIT), true)
PHONY += link_libs link_aarch64_libs $(product_apps)
link_libs: link_aarch64_libs
endif

link_arm_libs: libs
	@echo "[link] libs=$(libs)"
	$(VER) PBD=$(PREBUILD_LIBS)/arm/ ; \
	for lib in `ls $$PBD`; do \
		link=$(OUTPUTDIR)/arm/libs/$$lib ; \
		f=$$PBD/$$lib ; \
		if [ ! -L $$link ] && [ ! -e $$link ] ; then \
			ln -s $$f $$link && \
			echo "link prebuild library: $$link" ; \
		fi \
	done

link_aarch64_libs: libs
	@echo "[link] aarch libs=$(libs)"
	$(VER) PBD=$(PREBUILD_LIBS)/aarch64/ ; \
	for lib in `ls $$PBD`; do \
		link=$(OUTPUTDIR)/aarch64/libs/$$lib ; \
		f=$$PBD/$$lib ; \
		if [ ! -L $$link ] && [ ! -e $$link ] ; then \
			ln -s $$f $$link && \
			echo "link prebuild library: $$link" ; \
		fi \
	done

check_sym: $(product_apps)
	@if [ "xy" = "xy" ] ; then \
	set -e ;\
	for i in $(check-syms-y) ; do \
		echo " [ CHECK SYMS ]: $$i" ;\
		$(BUILD_TOOLS)/generate_img/check-syms.sh $$i \
			$(PREBUILD_LIBS)/arm/libc_shared_a32.so \
			$(OUTPUTDIR)/arm/obj/arm/libtee_shared/libtee_shared_a32.so; \
	done ;\
	for i in $(check-a64-syms-y) ; do \
		echo " [ CHECK a64 SYMS ]: $$i" ;\
		$(BUILD_TOOLS)/generate_img/check-syms.sh $$i \
			$(PREBUILD_LIBS)/aarch64/libc_shared.so \
			$(OUTPUTDIR)/aarch64/obj/aarch64/libtee_shared/libtee_shared.so; \
	done ; fi
	$(BUILD_TOOLS)/generate_img/smart-strip.sh $(product_apps)

## setup & clean directory symbol-links, to compatible with CI circle-complexity
setup_links:

clean_links:

## install headers:
install_headers: setup_links $(HDR_INSTALL_DIR)/.timestamp
$(HDR_INSTALL_DIR)/.timestamp:
	@echo "before tools ${EXPORT_HDRS}"
	$(VER) if [ -f "$(PLATFORM_DIR)/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg/plat_cfg.h" ] ; then \
	cp $(PLATFORM_DIR)/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg/plat_cfg.h $(HDR_INSTALL_DIR)/; fi;
	touch $(HDR_INSTALL_DIR)/.timestamp

## install libs:
install_libs:
	@for l in $(OUTPUTDIR)/arm/libs/* $(OUTPUTDIR)/aarch64/libs/*; do \
		if [ -e $$l ] && [ ! -L $$l ]; then cp -rf $$l $(LIBS_INSTALL_DIR); fi; \
	done

PHONY += release
release:
	@echo "!!compile release"
	@rm -rf tools/elf_extract

PHONY += clean
clean: clean_links
	bash $(TOPDIR)/lib/teelib/libopenssl/clean_openssl.sh $(TOPDIR)
	@rm -rf $(OUTPUTDIR)
	@rm -rf sec_trustedcore.img
	@rm -rf tools/linker.lds_pp
	@rm -rf $(TOPDIR)/prebuild

.PHONY: $(PHONY)
