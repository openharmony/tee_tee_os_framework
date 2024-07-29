# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# extra-flags is for export.txt and extern.txt of libteec_share
ifeq ($(CONFIG_SSA_64BIT), true)
flags += -DTEE_SUPPORT_SSA_64BIT
endif
ifeq ($(CONFIG_SSA_64BIT), false)
flags += -DTEE_SUPPORT_SSA_32BIT
endif

ifdef CONFIG_PERMSRV_64BIT
ifeq ($(CONFIG_PERMSRV_64BIT), true)
flags += -DTEE_SUPPORT_PERM_64BIT
else
flags += -DTEE_SUPPORT_PERM_32BIT
endif
endif

ifeq ($(CONFIG_PUBKEY_SHAREMEM), true)
flags += -DCONFIG_PUBKEY_SHAREMEM
endif

ifeq ($(CONFIG_TA_LOCAL_SIGN), true)
flags += -DTA_LOCAL_SIGN
endif

# keywest branch
#flags += -DKEYWEST_SIGN_PUB_KEY
#flags += -DTA_LOCAL_SIGN
#keywest branch end

ifeq ($(CONFIG_SE_SERVICE_64BIT), true)
flags += -DTEE_SUPPORT_SE_SERVICE_64BIT
endif
ifeq ($(CONFIG_SE_SERVICE_32BIT), true)
flags += -DTEE_SUPPORT_SE_SERVICE_32BIT
endif

ifeq ($(CONFIG_HUK_SERVICE_64BIT), true)
flags += -DTEE_SUPPORT_HUK_SERVICE_64BIT
endif

ifeq ($(CONFIG_HUK_SERVICE_32BIT), true)
flags += -DTEE_SUPPORT_HUK_SERVICE_32BIT
endif

ifeq ($(CONFIG_DRVMGR_64BIT), true)
flags += -DTEE_SUPPORT_DRV_SERVER_64BIT
endif

ifeq ($(CONFIG_DRVMGR_64BIT), false)
flags += -DTEE_SUPPORT_DRV_SERVER_32BIT
endif
