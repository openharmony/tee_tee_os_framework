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
#include "permission_config.h"
#include "tee_mem_mgmt_api.h"
#include "ta_permission.h"

static bool ta_perm_check(const TEE_UUID *uuid_array, uint32_t array_size, const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid_array == NULL || uuid == NULL)
        return false;

    for (i = 0; i < array_size; i++) {
        if (TEE_MemCompare(uuid, &(uuid_array[i]), sizeof(*uuid)) == 0)
            return true;
    }

    return false;
}

bool check_sem_permission(const TEE_UUID *uuid)
{
    return ta_perm_check(g_sem_reserved_permsrv,
                         sizeof(g_sem_reserved_permsrv) / sizeof(g_sem_reserved_permsrv[0]), uuid);
}
