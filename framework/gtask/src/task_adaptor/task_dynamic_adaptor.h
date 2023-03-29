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

#ifndef GTASK_TASK_DYNAMIC_ADAPTOR_H
#define GTASK_TASK_DYNAMIC_ADAPTOR_H

#include "task_adaptor.h"
#include "gtask_inner.h"

#define TASK_PRIO_ART_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_BIO_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_CRYPTO_AGENT_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_HSM_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_HUK_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_ROT_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_VLTMM_SRV (DEFAULT_TASK_PRIO - 1)

void register_dynamic_task(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *srv_config);

#endif
