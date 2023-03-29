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
#include "tee_ext_api.h"
#include "tee_log.h"
#include "permsrv_api.h"
#include "permsrv_api_imp.h"
/* follow function for global task */

void tee_ext_register_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id)
{
    if (uuid == NULL) {
        tloge("register TA with NULL uuid\n");
        return;
    }

    permsrv_registerta(uuid, task_id, user_id, REGISTER_TA);
}

void tee_ext_unregister_ta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id)
{
    if (uuid == NULL) {
        tloge("unregister TA with NULL uuid\n");
        return;
    }

    permsrv_registerta(uuid, task_id, user_id, UNREGISTER_TA);
}

void tee_ext_notify_unload_ta(const TEE_UUID *uuid)
{
    if (uuid == NULL) {
        tloge("uuid is NULL.\n");
        return;
    }
    permsrv_notify_unload_ta(uuid);
}

void tee_ext_load_file(void)
{
    permsrv_load_file();
}

TEE_Result tee_ext_crl_cert_process(const char *crl_cert, uint32_t crl_cert_size)
{
    TEE_Result ret;

    if (crl_cert == NULL) {
        tloge("crl cert process bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crl_cert_size == 0) {
        tloge("crl cert process bad parameter, size error!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = tee_crl_cert_process(crl_cert, crl_cert_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to do crl cert process\n");
        return ret;
    }

    return ret;
}

TEE_Result tee_ext_elf_verify_req(const void *req, uint32_t len)
{
    return permsrv_elf_verify(req, len);
}
