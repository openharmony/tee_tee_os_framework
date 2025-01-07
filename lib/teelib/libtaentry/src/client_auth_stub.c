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
#include "client_auth.h"
#include <tee_ext_api.h>

TEE_Result check_client_perm(uint32_t param_types, const TEE_Param params[TEE_PARAMS_NUM])
{
    (void)param_types;
    (void)params;

    return TEE_SUCCESS;
}

TEE_Result AddCaller_CA_exec(const char *ca_name, uint32_t ca_uid)
{
    (void)ca_name;
    (void)ca_uid;
    return TEE_SUCCESS;
}

TEE_Result AddCaller_TA_all(void)
{
    return TEE_SUCCESS;
}

TEE_Result tee_ext_get_caller_info(caller_info *caller_info_data, uint32_t length)
{
    (void)caller_info_data;
    (void)length;
    return TEE_ERROR_NOT_SUPPORTED;;
}

TEE_Result tee_ext_get_caller_userid(uint32_t *user_id)
{
    (void)user_id;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result AddCaller_CA(const uint8_t *cainfo_hash, uint32_t length)
{
    (void)cainfo_hash;
    (void)length;
    return TEE_SUCCESS;
}

uint32_t tee_get_session_type(void)
{
    return 0;
}
TEE_Result TEE_EXT_CheckClientPerm(uint32_t param_types, const TEE_Param params[TEE_PARAMS_NUM])
{
    (void)param_types;
    (void)params;
    return TEE_SUCCESS;
}