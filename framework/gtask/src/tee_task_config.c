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

#include "tee_task_config.h"

#include <tee_log.h>
#include <securec.h>

bool is_ssa_enable(void)
{
#if (defined TEE_SUPPORT_SSA_64BIT || defined TEE_SUPPORT_SSA_32BIT)
    return true;
#else
    return false;
#endif
}

bool is_se_service_enable(void)
{
#if (defined TEE_SUPPORT_SE_SERVICE_32BIT || defined TEE_SUPPORT_SE_SERVICE_64BIT)
    return true;
#else
    return false;
#endif
}