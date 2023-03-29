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
#include "tee_defines.h"
#include "sfs.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "tee_ext_api.h"
#include "sfs_internal.h"
#include "securec.h"
#include "string.h"
#include "tee_crypto_hal.h"
#include "ssa_fs.h"


static TEE_Result aes_xts_crypto_check(const struct sfd_t *sfd, const struct memref_t *tweak,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    if (sfd == NULL || tweak == NULL || data_in == NULL || data_out == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (sfd->meta_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if ((void *)(uintptr_t)tweak->buffer == NULL || (void *)(uintptr_t)data_in->buffer == NULL
        || (void *)(uintptr_t)data_out->buffer == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (data_in->size % AES_XTS_SINGLE_UNIT != 0) {
        tloge("data size not supported, size=%u\n", data_in->size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result aes_xts_crypto_init(TEE_ObjectHandleVar *key_obj1, TEE_ObjectHandleVar *key_obj2,
    const struct sfd_t *sfd)
{
    /* set key */
    (void)memset_s((void *)key_obj1, sizeof(*key_obj1), 0, sizeof(*key_obj1));
    (void)memset_s((void *)key_obj2, sizeof(*key_obj2), 0, sizeof(*key_obj2));

    key_obj1->Attribute = (TEE_Attribute *)TEE_Malloc(sizeof(TEE_Attribute), 0);
    key_obj2->Attribute = (TEE_Attribute *)TEE_Malloc(sizeof(TEE_Attribute), 0);
    if (key_obj1->Attribute == NULL || key_obj2->Attribute == NULL) {
        tloge("cipher alloc key attr failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    key_obj1->Attribute->content.ref.length = sizeof(sfd->meta_data->xts_key1);
    key_obj1->Attribute->content.ref.buffer = sfd->meta_data->xts_key1;
    key_obj2->Attribute->content.ref.length = sizeof(sfd->meta_data->xts_key2);
    key_obj2->Attribute->content.ref.buffer = sfd->meta_data->xts_key2;

    return TEE_SUCCESS;
}

static void aes_xts_crypto_clean(TEE_OperationHandle handle,
    TEE_ObjectHandleVar *key_obj1, TEE_ObjectHandleVar *key_obj2)
{
    if (handle != NULL) {
        TEE_FreeOperation(handle);
        handle = NULL;
    }

    if (key_obj1->Attribute != NULL) {
        TEE_Free(key_obj1->Attribute);
        key_obj1->Attribute = NULL;
    }
    if (key_obj2->Attribute != NULL) {
        TEE_Free(key_obj2->Attribute);
        key_obj2->Attribute = NULL;
    }
}

TEE_Result aes_xts_crypto(uint32_t mode, const struct sfd_t *sfd, const struct memref_t *tweak,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    TEE_Result ret;
    TEE_OperationHandle handle = NULL;
    TEE_ObjectHandleVar key_obj1, key_obj2;
    uint32_t i;
    uint32_t data_offset;

    ret = aes_xts_crypto_check(sfd, tweak, data_in, data_out);
    if (ret != TEE_SUCCESS) {
        tloge("aes xts crypto check failed, ret 0x%x\n", ret);
        return ret;
    }

    ret = aes_xts_crypto_init(&key_obj1, &key_obj2, sfd);
    if (ret != TEE_SUCCESS) {
        tloge("aes xts crypto init failed, ret 0x%x\n", ret);
        goto clean;
    }

    uint32_t cipher_times = data_in->size / AES_XTS_SINGLE_UNIT;
    for (i = 0; i < cipher_times; i++) {
        ret = TEE_AllocateOperation(&handle, TEE_ALG_AES_XTS, mode, TEE_MAX_KEY_SIZE_IN_BITS);
        if (ret != TEE_SUCCESS) {
            tloge("alloc crypto operation failed, ret=0x%x\n", ret);
            goto clean;
        }

        ret = TEE_SetCryptoFlag(handle, SOFT_CRYPTO);
        if (ret != TEE_SUCCESS)
            goto clean;

        ret = TEE_SetOperationKey2(handle, &key_obj1, &key_obj2);
        if (ret != TEE_SUCCESS) {
            tloge("cipher setkey2 failed, ret=0x%x\n", ret);
            goto clean;
        }

        /* cipher init */
        TEE_CipherInit(handle, (void *)(uintptr_t)tweak->buffer, tweak->size);

        data_out->size = AES_XTS_SINGLE_UNIT;
        data_offset   = i * AES_XTS_SINGLE_UNIT;
        ret = TEE_CipherDoFinal(handle, (void *)(uintptr_t)(data_in->buffer + data_offset), AES_XTS_SINGLE_UNIT,
                                (void *)(uintptr_t)(data_out->buffer + data_offset), (size_t *)&data_out->size);
        if (ret != TEE_SUCCESS) {
            tloge("cipher dofinal failed, ret=0x%x\n", ret);
            goto clean;
        }

        TEE_FreeOperation(handle);
        handle = NULL;
    }

clean:
    aes_xts_crypto_clean(handle, &key_obj1, &key_obj2);
    return ret;
}

TEE_Result calc_hmac256(struct key_info_t *key_info, const uint8_t *src, int32_t length,
    uint8_t *dest, uint32_t *dest_len)
{
    TEE_OperationHandle mac_ops = NULL;
    TEE_Result ret;
    size_t out_len;

    if (key_info == NULL || src == NULL || dest == NULL || dest_len == NULL || length < 0)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = TEE_AllocateOperation(&mac_ops, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, key_info->key_len);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = TEE_SetCryptoFlag(mac_ops, SOFT_CRYPTO);
    if (ret != TEE_SUCCESS)
        goto clean;

    TEE_ObjectHandleVar key_obj;
    (void)memset_s((void *)&key_obj, sizeof(key_obj), 0, sizeof(key_obj));
    key_obj.Attribute = TEE_Malloc(sizeof(TEE_Attribute), 0);
    if (key_obj.Attribute == NULL) {
        tloge("alloc key attr failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto clean;
    }

    key_obj.Attribute->content.ref.length = key_info->key_len;
    key_obj.Attribute->content.ref.buffer = key_info->key;
    ret = TEE_SetOperationKey(mac_ops, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("set operation key fail, ret:0x%x", ret);
        goto clean;
    }

    TEE_MACInit(mac_ops, NULL, 0);
    out_len = *dest_len;
    ret = TEE_MACComputeFinal(mac_ops, src, (size_t)length, dest, &out_len);
    if (ret != 0) {
        tloge("TEE MAC error! %x\n", ret);
        goto clean;
    }
    *dest_len = out_len;
    ret = TEE_SUCCESS;

clean:
    TEE_FreeOperation(mac_ops);
    TEE_Free(key_obj.Attribute);
    return ret;
}

#define BLOCK_SIZE_MAX 0x7D000 /* 500K */

TEE_Result cmd_hash(const uint8_t *src_data, uint32_t src_len, uint8_t *dest_data, size_t dest_len)
{
    TEE_OperationHandle crypto_ops = NULL;
    uint32_t i, block_count;
    TEE_Result ret;

    if ((src_data == NULL) || (dest_data == NULL)) {
        tloge("src data or dest data is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_AllocateOperation(&crypto_ops, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_AllocateOperation, fail %x\n", ret);
        return ret;
    }

    block_count = src_len / BLOCK_SIZE_MAX;
    for (i = 0; i < block_count; i++) {
        ret = TEE_DigestUpdate(crypto_ops, (void *)(src_data + (uint32_t)(i * BLOCK_SIZE_MAX)), BLOCK_SIZE_MAX);
        if (ret != TEE_SUCCESS) {
            tloge("TEE_DigestUpdate, fail ret=%x\n", ret);
            TEE_FreeOperation(crypto_ops);
            return ret;
        }
    }

    ret = TEE_DigestDoFinal(crypto_ops, (void *)(src_data + (uint32_t)(block_count * BLOCK_SIZE_MAX)),
                            (src_len % BLOCK_SIZE_MAX), dest_data, &dest_len);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_DigestDoFinal, fail ret=%x, srclen=%x, dst_len=%x\n", ret, (src_len % BLOCK_SIZE_MAX), dest_len);
        TEE_FreeOperation(crypto_ops);
        return ret;
    }

    TEE_FreeOperation(crypto_ops);

    return TEE_SUCCESS;
}

#define AES_IV_LEN 16
TEE_Result aes_cbc_crypto(uint32_t mode, uint8_t *key_value, uint32_t key_size, const uint8_t *iv,
    uint32_t iv_size, const uint8_t *data_in, uint32_t data_in_size, uint8_t *data_out)
{
    (void)iv_size;
    if (key_value == NULL || iv == NULL || data_in == NULL || data_out == NULL)
        return -1;

    TEE_ObjectHandleVar object = { 0 };
    TEE_OperationHandle operation = NULL;

    object.Attribute = TEE_Malloc(sizeof(TEE_Attribute), 0);
    if (object.Attribute == NULL) {
        tloge("allocate key failed!");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    object.Attribute->content.ref.length = key_size;
    object.Attribute->content.ref.buffer = key_value;

    TEE_Result ret = TEE_AllocateOperation(&operation, TEE_ALG_AES_CBC_NOPAD, mode, key_size);
    if (ret != TEE_SUCCESS) {
        tloge("allocate operation failed, ret = 0x%x", ret);
        TEE_Free(object.Attribute);
        return ret;
    }

    ret = TEE_SetOperationKey(operation, &object);
    if (ret != TEE_SUCCESS) {
        tloge("set operation key failed, ret = 0x%x", ret);
        TEE_Free(object.Attribute);
        TEE_FreeOperation(operation);
        return ret;
    }

    TEE_CipherInit(operation, iv, AES_IV_LEN);

    size_t data_out_size = data_in_size;
    ret = TEE_CipherDoFinal(operation, data_in, data_in_size, data_out, &data_out_size);
    TEE_Free(object.Attribute);
    object.Attribute = NULL;
    TEE_FreeOperation(operation);
    if (ret != TEE_SUCCESS)
        tloge("aes do final failed, ret = 0x%x", ret);
    return ret;
}
