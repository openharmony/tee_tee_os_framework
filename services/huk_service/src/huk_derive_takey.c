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
#include "huk_derive_takey.h"
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <mem_ops.h>
#include <crypto_driver_adaptor.h>
#include <crypto_hal_derive_key.h>

static TEE_Result huk_task_takey_param_check(const struct huk_srv_msg *msg, const TEE_UUID *uuid)
{
    if (uuid == NULL) {
        tloge("huk derive takey check uuid failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((msg == NULL) || (msg->data.takey_msg.salt_buf == 0) ||
        (msg->data.takey_msg.salt_size == 0) ||
        (msg->data.takey_msg.salt_size > CMAC_DERV_MAX_DATA_IN_SIZE)) {
        tloge("huk derive takey check salt messages failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((msg->data.takey_msg.key_buf == 0) ||
        (msg->data.takey_msg.key_size == 0) ||
        (msg->data.takey_msg.key_size > CMAC_DERV_MAX_DATA_IN_SIZE)) {
        tloge("huk derive takey check key messages failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static int32_t huk_srv_map_from_task(uint32_t in_task_id, uint64_t va_addr, uint32_t size, uint64_t *virt_addr)
{
    uint64_t vaddr;
    int32_t ret;

    ret = map_sharemem(in_task_id, va_addr, size, &vaddr);
    if (ret == 0)
        *virt_addr = (uintptr_t)vaddr;
    else
        tloge("huk map from %u failed\n", in_task_id);

    return ret;
}

static void huk_srv_task_unmap(uint64_t virt_addr, uint32_t size)
{
    if (virt_addr == 0)
        return;
    if (unmap_sharemem((void *)(uintptr_t)virt_addr, size) != 0)
        tloge("huk srv unmap error\n");
}

static TEE_Result do_derive_takey(const uint8_t *salt_tmp, uint32_t salt_size, uint8_t *key_tmp, uint32_t key_size,
    uint32_t inner_iter_num)
{
    uint32_t derive_type = CRYPTO_KEYTYPE_HUK;

    struct memref_t salt = {0};
    salt.buffer = (uintptr_t)salt_tmp;
    salt.size = salt_size;

    struct memref_t cmac = {0};
    cmac.buffer = (uintptr_t)key_tmp;
    cmac.size = key_size;

    return tee_crypto_derive_root_key(derive_type, &salt, &cmac, inner_iter_num);
}

static TEE_Result huk_derive_takey(uint64_t vmaddr_salt_shared, uint32_t salt_size,
    uint64_t vmaddr_key_shared, uint32_t key_size, const struct huk_access_table *huk_access)
{
    if (salt_size > CMAC_DERV_MAX_DATA_IN_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result ret = TEE_ERROR_GENERIC;
    uint32_t salt_tmp_size = salt_size + (uint32_t)sizeof(TEE_UUID);
    uint8_t *salt_tmp = TEE_Malloc(salt_tmp_size, 0);
    if (salt_tmp == NULL) {
        tloge("huk derive takey malloc salt memory failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    uint8_t *key_tmp = TEE_Malloc(key_size, 0);
    if (key_tmp == NULL) {
        tloge("huk derive takey malloc key memory failed\n");
        TEE_Free(salt_tmp);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    errno_t rc = memcpy_s(salt_tmp, salt_tmp_size, (uint8_t *)(uintptr_t)vmaddr_salt_shared, salt_size);
    if (rc != EOK)
        goto end_clean;

    if (memcpy_s(salt_tmp + salt_size, sizeof(TEE_UUID), &(huk_access->uuid), sizeof(TEE_UUID)) != EOK) {
            tloge("huk copy uuid failed\n");
            goto end_clean;
    }

    ret = do_derive_takey(salt_tmp, salt_tmp_size, key_tmp, key_size, 1);
    if (ret == TEE_SUCCESS) {
        if (memcpy_s((uint8_t *)(uintptr_t)vmaddr_key_shared, key_size, key_tmp, key_size) != EOK) {
            tloge("huk copy takey failed\n");
            ret = TEE_ERROR_GENERIC;
        }
    } else {
        tloge("huk cmac derive takey failed\n");
    }
end_clean:
    (void)memset_s(salt_tmp, salt_tmp_size, 0, salt_tmp_size);
    TEE_Free(salt_tmp);
    (void)memset_s(key_tmp, key_size, 0, key_size);
    TEE_Free(key_tmp);
    return ret;
}

TEE_Result huk_task_derive_takey(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t sndr_pid, const TEE_UUID *uuid)
{
    uint64_t vmaddr_salt_shared = 0;
    uint64_t vmaddr_takey_shared = 0;

    if (rsp == NULL) {
        tloge("huk derive takey check rsp failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = huk_task_takey_param_check(msg, uuid);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = ret;
        return ret;
    }

    uint32_t salt_size = msg->data.takey_msg.salt_size;
    uint32_t key_size = msg->data.takey_msg.key_size;
    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.key_buf, key_size, &vmaddr_takey_shared) != 0) {
        tloge("huk service map takey buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.salt_buf, salt_size, &vmaddr_salt_shared) != 0) {
        tloge("huk service map salt buffer from 0x%x failed\n", sndr_pid);
        huk_srv_task_unmap(vmaddr_takey_shared, key_size);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }
    struct huk_access_table huk_access = { msg->header.send.msg_id, *uuid };
    ret = huk_derive_takey(vmaddr_salt_shared, salt_size, vmaddr_takey_shared, key_size, &huk_access);
    huk_srv_task_unmap(vmaddr_salt_shared, salt_size);
    huk_srv_task_unmap(vmaddr_takey_shared, key_size);
    rsp->data.ret = ret;
    return ret;
}
