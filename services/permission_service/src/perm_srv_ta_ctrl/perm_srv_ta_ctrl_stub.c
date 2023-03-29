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
#include "perm_srv_ta_ctrl.h"

TEE_Result perm_srv_global_ta_ctrl_list_loading(bool check_empty)
{
    (void)check_empty;
    return TEE_SUCCESS;
}

TEE_Result perm_srv_ta_ctrl_buff_process(const uint8_t *ctrl_buff, uint32_t ctrl_buff_size)
{
    (void)ctrl_buff;
    (void)ctrl_buff_size;
    return TEE_SUCCESS;
}

TEE_Result perm_srv_check_ta_deactivated(const TEE_UUID *uuid, uint16_t version)
{
    (void)uuid;
    (void)version;
    return TEE_SUCCESS;
}
