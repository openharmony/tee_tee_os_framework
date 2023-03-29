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

#include "drv_dyn_policy_mgr.h"

int32_t add_dynamic_policy_to_drv(const struct task_tlv *tlv)
{
    (void)tlv;
    return 0;
}

void del_dynamic_policy_to_drv(const struct tee_uuid *uuid)
{
    (void)uuid;
}

int32_t register_drv_policy(struct task_node *node)
{
    (void)node;
    return 0;
}
