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

#ifndef __PERSRV_API_H__
#define __PERSRV_API_H__

#include "tee_defines.h"

enum TaManager {
    TA_MANAGER_UNKNOWN,
    TA_MANAGER_TRUSTONIC
};

void tee_ext_register_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id);
void tee_ext_unregister_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id);
void tee_ext_notify_unload_ta(const TEE_UUID *uuid);
void tee_ext_load_file(void);

TEE_Result tee_ext_crl_cert_process(const char *crl_cert, uint32_t crl_cert_size);
TEE_Result tee_ext_elf_verify_req(const void *req, uint32_t len);
#endif
