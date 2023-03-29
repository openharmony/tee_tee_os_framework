/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef GTASK_TEE_LOAD_EXT_MF_H
#define GTASK_TEE_LOAD_EXT_MF_H

#include <dyn_conf_common.h>
#include <dyn_conf_dispatch_inf.h>
#include "tee_defines.h"
#include "tee_elf_verify.h"
enum {
    UNSUPPORTED,
    TA_DISTRIBUTION,
    TA_API_LEVEL,
    SDK_VERSION,
    IS_LIB,
    SSA_ENUM_ENABLE,
    IS_DYN_CONF,
    TARGET_TYPE,
    TARGET_VERSION,
    SYS_VERIFY_TA,
    MEM_PAGE_ALIGN,
    HARD_WARE_TYPE,
    SRV_RELEASE_TA_RES,
    SRV_CRASH_CALLBACK,
    SRV_NEED_CREATE_MSG,
    SRV_NEED_RELEASE_MSG,
};

TEE_Result tee_secure_img_parse_manifest_extension(const char *extension, uint32_t extension_size,
                                                   manifest_extension_t *mani_ext, struct dyn_conf_t *dyn_conf);
#endif
