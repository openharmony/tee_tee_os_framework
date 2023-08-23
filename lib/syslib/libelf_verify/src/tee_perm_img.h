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
#ifndef TEE_PERM_IMG_H
#define TEE_PERM_IMG_H

#include "tee_defines.h"
#include "permission_service.h"

struct sign_config_t {
    uint32_t key_len;
    size_t hash_size;
    int32_t hash_nid;
    int32_t padding;
    uint32_t key_style;
    uint32_t sign_ta_alg;
    bool is_oh;
};

TEE_Result get_config_cert_param(cert_param_t *cert_param, struct sign_config_t *config);

#endif

