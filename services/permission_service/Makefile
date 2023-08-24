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
TARGET := permission_service${TARG}.elf

include $(BUILD_CONFIG)/var.mk
CFILES := $(wildcard src/*.c)

CFILES += $(wildcard src/perm_srv_ta_crl/perm_srv_ta_crl.c)
CFILES += $(wildcard src/perm_srv_ta_crl/perm_srv_ta_crl_cmd.c)
CFILES += $(wildcard src/perm_srv_ta_ctrl/perm_srv_ta_ctrl_stub.c)
CFILES += $(wildcard src/perm_srv_ta_config/perm_srv_ta_config.c)
CFILES += $(wildcard src/perm_srv_elf_verify/perm_srv_elf_verify_cmd.c)
CFILES += $(wildcard src/perm_srv_cms_crl/perm_srv_cms_crl_storage_stub.c)
CFILES += $(wildcard src/perm_srv_ta_cert/perm_srv_ta_cert_nodyn_import.c)
CFILES += $(wildcard src/perm_srv_ta_cert/perm_srv_ta_cert.c)
ifeq ($(CONFIG_OH_LOAD_KEY),y)
CFILES += $(wildcard src/perm_srv_ta_cert/perm_srv_ta_cert_nodate_check.c)
else
CFILES += $(wildcard src/perm_srv_ta_cert/perm_srv_ta_cert_date_check.c)
endif
CFILES += $(wildcard src/permission_config/permission_config.c)
CFILES += $(wildcard src/pub_key/pub_key_nonsharemem.c)
CFILES += $(wildcard src/pub_key/pub_key_stub.c)

ifneq ($(CONFIG_DISABLE_PERM_STORAGE),y)
CFILES += $(wildcard src/file_op/perm_srv_file_op.c)
CFILES += $(wildcard src/file_op/handle_file_op.c)
CFILES += $(wildcard src/file_op/handle_rpmb_sfs_file_op.c)
else
CFILES += $(wildcard src/file_op/perm_srv_no_file_op.c)
endif

CFILES += $(wildcard src/anti_rollback/handle_anti_rollback_stub.c)

# these libs are for elf verify
LIBS += elf_verify${TARG} \
    elf_verify_key${TARG} \
    dynconfmgr${TARG}     \
    dynconfbuilder${TARG}

inc-flags += -I$(DRIVERS_PATH)/tee_misc_driver/src
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libpermission_service/include
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteemem/include # mem_ops_ext.h
inc-flags += -I$(TEELIB)/libteeconfig/include
inc-flags += -I$(TEELIB)/libteeconfig/include/TEE_ext/
inc-flags += -I$(TEELIB)/libteeconfig/include/kernel/
inc-flags += -I$(TEELIB)/libtimer/include/
inc-flags += -I$(SYSLIB)/libspawn_common/include/
inc-flags += -I$(TEELIB)/libssa/include/
inc-flags += -I$(TEELIB)/libcrypto/include
inc-flags += -I$(TEELIB)/libswcrypto_engine/include
inc-flags += -I$(TEELIB)/libcrypto_hal/include
inc-flags += -I$(TEELIB)/libipc_hal/include
inc-flags += -I$(SYSLIB)/libelf_verify/include
inc-flags += -I$(SYSLIB)/libelf_verify/src
inc-flags += -I$(TEELIB)/libpermission_service/src
inc-flags += -I$(SYSLIB)/libelf_verify_key/src/
inc-flags += -I$(TEELIB)/libteeagentcommon_client/include
inc-flags += -I$(SYSLIB)/libdynconfmgr/include/
inc-flags += -I$(SYSLIB)/libdynconfbuilder/include/
inc-flags += -I$(SERVICES_PATH)/permission_service/src
inc-flags += -I$(SERVICES_PATH)/permission_service/src/permission_config/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/perm_srv_ta_ctrl/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/perm_srv_ta_crl/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/perm_srv_ta_config/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/perm_srv_ta_cert/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/perm_srv_elf_verify/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/perm_srv_cms_crl/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/file_op/
inc-flags += -I$(SERVICES_PATH)/permission_service/src/anti_rollback
inc-flags += -I$(SERVICES_PATH)/permission_service/src/auth/tee_auth_sign_rsa.h
inc-flags += -I$(PREBUILD_HEADER)/sys

ifneq ($(findstring $(CONFIG_CRYPTO_SOFT_ENGINE), openssl openssl3),)
inc-flags += -I$(TEELIB)/libopenssl/openssl/include
inc-flags += -I$(TEELIB)/libopenssl/openssl/crypto
inc-flags += -I$(TEELIB)/libopenssl/openssl/crypto/include
endif

LDFLAGS += -e tee_task_entry

ifeq ($(CONFIG_DYN_IMPORT_CERT),y)
CPPFLAGS += -DDYN_IMPORT_CERT=1
CFILES := $(filter-out , $(CFILES))
endif

CFLAGS += -fvisibility=hidden -Wno-pointer-to-int-cast
ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl3)
CFLAGS += -DOPENSSL3_ENABLE
else
CFLAGS += -DOPENSSL_ENABLE
endif

include $(BUILD_FRAMEWORK)/ta-common.mk
include $(BUILD_CONFIG)/feature-macro.mk
