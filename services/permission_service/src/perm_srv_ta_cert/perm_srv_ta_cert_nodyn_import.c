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
#include "perm_srv_ta_cert.h"
#include <tee_log.h>

TEE_Result perm_srv_export_cert_from_storage(uint8_t *dst, uint32_t *dst_len, uint32_t limit)
{
    (void)dst;
    (void)dst_len;
    (void)limit;
    return TEE_SUCCESS;
}

TEE_Result perm_srv_import_cert_to_storage(const uint8_t *src, size_t len)
{
    (void)src;
    (void)len;
    return TEE_SUCCESS;
}

TEE_Result perm_srv_remove_cert_from_storage(void)
{
    return TEE_SUCCESS;
}

void perm_srv_cert_expiration_alarm(const TEE_Date_Time *time1, const TEE_Date_Time *time2)
{
    (void)time1;
    (void)time2;
    return;
}

TEE_Result perm_srv_get_imported_cert_pubkey(uint8_t *dst, uint32_t *len)
{
    (void)dst;
    *len = 0;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result perm_srv_check_cert_import_enable(const struct config_info *config, uint32_t cmd,
                                             bool *is_cert_import_enable)
{
    if (config == NULL || is_cert_import_enable == NULL) {
        tloge("invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    (void)cmd;
    *is_cert_import_enable = false;
    
    return TEE_SUCCESS;
}
