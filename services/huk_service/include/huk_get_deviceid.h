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
#ifndef HUK_GET_DEVICEID_H
#define HUK_GET_DEVICEID_H

#include <tee_defines.h>
#include "huk_service_msg.h"

TEE_Result huk_task_get_deviceid(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t sndr_pid, const TEE_UUID *uuid);

#endif
