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
# FILE: project.mk
#

# ramdisk tools, run on host
# compile libs rules

include $(BUILD_CONFIG)/arch_config.mk
libtee_shared_a32: libteeconfig libtimer libteeagentcommon_client libcrypto_hal libswcrypto_engine $(crypto_lib) libteedynsrv libtee_stub
libtee_shared: libteeconfig libtimer libteeagentcommon_client libcrypto_hal libswcrypto_engine $(crypto_lib) libteedynsrv libtee_stub

libdrv_shared_a32: #libteeconfig_a32
libdrv_shared: #libteeconfig

teelib := libcrypto_hal libtimer libagent libagent_base libdrv libteeos libpermission_service \
	libswcrypto_engine libtaentry libteeagentcommon_client libcrypto libteeconfig libteemem \
	libssa libhuk libteedynsrv libopenssl libipc_hal libtee_stub
syslib := libelf_verify libspawn_common libelf_verify_key libdynconfmgr libdynconfbuilder
drvlib := #libdrv_frame

libs: libtee_shared $(syslib) #libdrv_shared
	@echo "libsok"

$(teelib):
	@echo "building teelibs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

$(drvlib):
	@echo "building drvlibs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/common/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/common/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

$(syslib):
	@echo "bulding syslibs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(SYSLIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(SYSLIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

libtee_shared: $(teelib)
	@echo "building libtee_shared target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

libdrv_shared: $(drvlib)
	@echo "building libdrv_shared target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

# compile drivers rules

frameworks := gtask teesmcmgr tarunner #drvmgr
service := huk_service

ifdef CONFIG_SSA_64BIT
service += ssa
endif

ifdef CONFIG_PERMSRV_64BIT
service += permission_service
endif

#drivers := crypto_mgr

ifdef CONFIG_TEE_MISC_DRIVER_64BIT
#drivers += tee_misc_driver
endif

$(drivers):
	@echo "building ARCH=arm driver=$@ target"
	$(VER) LDFLAGS= $(MAKE) -C $(DRIVERS_PATH)/$@ ARCH=arm TARG=_a32 -f $(PREBUILD_HEADER)/.config -f Makefile all
	$(VER) LDFLAGS= $(MAKE) -C $(DRIVERS_PATH)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all

$(frameworks):
	@echo "tee_os_framework framework compile $@"
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(FRAMEWORK_PATH)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(FRAMEWORK_PATH)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)

$(service):
	@echo "tee_os_framework service compile $@"
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(SERVICES_PATH)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(SERVICES_PATH)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)

ifneq ($(VERSION_DDK),y)
	$(VER) rm -rf $(BUILD_TOOLS)/generate_img/cpio-strip/cpio-strip
endif

include $(BUILD_SERVICE)/svc-flags.mk

# export for tools/gen_boot_image.sh
ifeq (${HM_ARCH}, aarch32)
	HM_TARGET_ARCH := $(TARGET_ARCH_32)
else
	HM_TARGET_ARCH := $(TARGET_ARCH_64)
endif
GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -fsigned-char -fno-strict-aliasing \
                   -pipe -fno-common
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))
