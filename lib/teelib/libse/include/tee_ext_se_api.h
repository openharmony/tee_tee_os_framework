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
#ifndef TEE_EXT_SE_API_H
#define TEE_EXT_SE_API_H

#include "tee_internal_se_api.h"

#define SEAID_LIST_LEN_MAX 64

struct seaid_switch_info {
    uint8_t aid[AID_LEN_MAX];
    uint32_t aid_len;
    bool closed;
};

void tee_se_set_aid(const struct seaid_switch_info *seaid_list, uint32_t seaid_list_len);
void tee_se_set_deactive(bool deactive);
#endif
