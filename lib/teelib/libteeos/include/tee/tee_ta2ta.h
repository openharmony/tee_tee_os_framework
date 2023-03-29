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

#ifndef __TEE_TA2TA_H_
#define __TEE_TA2TA_H_

#include <dlist.h>
#include "ta_framework.h"
#include "tee_init.h"

/* change according to ta_framework.h */
typedef union {
    struct {
        unsigned int buffer;
        unsigned int size;
    } memref;
    struct {
        unsigned int a;
        unsigned int b;
    } value;
} tee_param_comp;

struct smc_operation {
    uint32_t types;
    tee_param_comp params[TEE_PARAM_NUM];
    uint32_t p_h_addr[TEE_PARAM_NUM]; /* add for aarch64 TA, store buffer high addr bit[32:63] */
};

struct tls_info {
    struct dlist_node list;
    struct running_info *info;
};

void add_tls_info(struct running_info *info);
void delete_tls_info(uint32_t session_id);

void delete_all_ta2ta_session(uint32_t tid);
#endif
