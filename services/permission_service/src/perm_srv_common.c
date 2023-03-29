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
#include "perm_srv_common.h"
#include <sys/mman.h>
#include <mem_ops.h>
#include <securec.h>
#include <tee_log.h>

#define SHA256_LEN         32
#define HASH_UPDATA_LEN    1024

int32_t perm_srv_map_from_task(uint32_t taskid, uint64_t src_vaddr, uint32_t size, uint64_t *dst_vaddr)
{
    uint64_t vaddr = 0;

    if (dst_vaddr == NULL)
        return -1;

    int32_t ret = map_sharemem(taskid, src_vaddr, size, &vaddr);
    if (ret == 0)
        *dst_vaddr = vaddr;

    return ret;
}

void perm_srv_unmap_from_task(uint64_t vaddr, uint32_t size)
{
    if (vaddr == 0)
        return;

    if (munmap((void *)(uintptr_t)vaddr, size) != 0)
        tloge("perm unmap error\n");
}

TEE_Result perm_srv_get_buffer(uint64_t src_buffer, uint32_t src_len, uint32_t sndr_taskid,
                               uint8_t *dst_buffer, uint32_t dst_len)
{
    uint64_t temp_shared = 0;
    errno_t rc;

    if (dst_buffer == NULL || dst_len < src_len)
        return TEE_ERROR_BAD_PARAMETERS;

    /* must to be map the shared memory */
    if (perm_srv_map_from_task(sndr_taskid, src_buffer, src_len, &temp_shared) != 0) {
        tloge("map writeBuffer from 0x%x fail\n", sndr_taskid);
        return TEE_ERROR_GENERIC;
    }

    rc = memcpy_s(dst_buffer, dst_len, (uint8_t *)(uintptr_t)temp_shared, src_len);
    if (rc != EOK) {
        tloge("Failed to copy config to config buffer\n");
        perm_srv_unmap_from_task(temp_shared, src_len);
        return TEE_ERROR_SECURITY;
    }

    perm_srv_unmap_from_task(temp_shared, src_len);
    return TEE_SUCCESS;
}

TEE_Result perm_srv_calc_hash(const uint8_t *hash_body, size_t hash_body_size, uint8_t *hash_result,
                                    size_t hash_result_size, uint32_t alg)
{
    TEE_Result tee_ret;
    TEE_OperationHandle crypto_ops = NULL;
    size_t per_op_len; /* TEE_ALG_SHA256 */

    bool is_invalid =
        (hash_body == NULL || hash_result == NULL || hash_body_size == 0 || hash_result_size < SHA256_LEN);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    /*
     * Calculate the hash value of configure package
     * sha1 with DX driver
     */
    tee_ret = TEE_AllocateOperation(&crypto_ops, alg, TEE_MODE_DIGEST, 0);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;

    tee_ret = TEE_SetCryptoFlag(crypto_ops, SOFT_CRYPTO);
    if (tee_ret != TEE_SUCCESS) {
        tloge("set soft engine failed ret = 0x%x\n", tee_ret);
        TEE_FreeOperation(crypto_ops);
        return tee_ret;
    }

    while (hash_body_size > 0) {
        per_op_len = (hash_body_size > HASH_UPDATA_LEN ? HASH_UPDATA_LEN : hash_body_size);
        if (TEE_DigestUpdate(crypto_ops, hash_body, per_op_len) != TEE_SUCCESS) {
            TEE_FreeOperation(crypto_ops);
            crypto_ops = NULL;
            tloge("Failed to call\n");
            return TEE_ERROR_GENERIC;
        }

        hash_body_size -= per_op_len;
        hash_body += per_op_len;
    }

    tee_ret = TEE_DigestDoFinal(crypto_ops, NULL, 0, hash_result, &hash_result_size);
    TEE_FreeOperation(crypto_ops);

    return tee_ret;
}
