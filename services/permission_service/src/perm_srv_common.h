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
#ifndef PERM_SRV_COMMON_H
#define PERM_SRV_COMMON_H

#include <tee_defines.h>
#include "permission_service.h"
#include "tee_crypto_api.h"
#include "tee_crypto_hal.h"

typedef TEE_Result (*perm_srv_cmd_func)(const perm_srv_req_msg_t *req_msg, uint32_t sndr_taskid,
                                        const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp);

typedef struct {
    uint32_t cmd;
    perm_srv_cmd_func func;
} perm_srv_cmd_t;

int32_t perm_srv_map_from_task(uint32_t taskid, uint64_t src_vaddr, uint32_t size, uint64_t *dst_vaddr);

void perm_srv_unmap_from_task(uint64_t vaddr, uint32_t size);

TEE_Result perm_srv_get_buffer(uint64_t src_buffer, uint32_t src_len, uint32_t sndr_taskid,
                               uint8_t *dst_buffer, uint32_t dst_len);

TEE_Result perm_srv_calc_hash(const uint8_t *hash_body, size_t hash_body_size, uint8_t *hash_result,
                              size_t hash_result_size, uint32_t alg);
#endif
