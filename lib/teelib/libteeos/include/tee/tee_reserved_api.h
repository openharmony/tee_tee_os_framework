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
#ifndef __TEE_RESERVE_API_H
#define __TEE_RESERVE_API_H

#include "tee_defines.h"
#include "ta_framework.h"

void init_property(uint32_t login_method, TEE_UUID *client_uuid, const struct ta_property *prop);
void tee_log_init(const TEE_UUID *uuid);
void tee_log_exit(void);
void init_tee_internal_api(void);
void add_session_cancel_state(uint32_t session_id);
void del_session_cancel_state(uint32_t session_id);

#endif // __TEE_RESERVE_API_H
