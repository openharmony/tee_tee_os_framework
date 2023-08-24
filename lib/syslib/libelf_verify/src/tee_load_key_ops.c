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
#include "tee_load_key_ops.h"
#include <tee_crypto_api.h>
#include "tee_elf_verify.h"
#include "ta_load_key.h"
#include "ta_verify_key.h"
#include "ta_framework.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "securec.h"
#include "crypto_inner_interface.h"
#include "tee_crypto_hal.h"
#include "ta_load_config.h"
#include "tee_elf_verify_openssl.h"
#include <tee_crypto_signature_verify.h>

RSA *get_ta_verify_key(void)
{
    struct ta_verify_key verify_key = { PUB_KEY_2048_BITS, PUB_KEY_RELEASE, NULL};

    TEE_Result ret = get_ta_verify_pubkey(&verify_key);
    if (ret != TEE_SUCCESS || verify_key.key == NULL)
        return NULL;

    return rsa_build_public_key(verify_key.key);
}

/* Process steps:
 * 1, Get public key,
 * 2, Verify the signature using the public key,
 */
TEE_Result tee_secure_ta_release_verify(const uint8_t *hash, uint32_t hash_size, const uint8_t *signature,
                                         uint32_t signature_size)
{
    /* This is for 3rd party to developing TA with signature check off */
    if (get_ta_signature_ctrl()) {
        tloge("DEBUG_VERSION: signature VerifyDigest is OFF\n");
        return TEE_SUCCESS;
    }

    return tee_secure_img_release_verify(hash, hash_size, signature, signature_size, get_ta_verify_key());
}

TEE_Result tee_secure_img_hash_ops(const uint8_t *data, size_t data_size, uint8_t *hash, size_t hash_size)
{
    uint32_t alg_type;
    TEE_OperationHandle hash_op = NULL;
    int32_t per_op_len;

    bool check = (data == NULL || hash == NULL || data_size == 0);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    if (hash_size == SHA256_LEN) {
        alg_type = TEE_ALG_SHA256;
    } else {
        alg_type = TEE_ALG_SHA512;
    }

    TEE_Result ret = TEE_AllocateOperation(&hash_op, alg_type, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("Allocate Operation, fail 0x%x\n", ret);
        return ret;
    }
    ret = TEE_SetCryptoFlag(hash_op, SOFT_CRYPTO);
    if (ret != TEE_SUCCESS) {
        TEE_FreeOperation(hash_op);
        tloge("set soft engine failed ret = 0x%x\n", ret);
        return ret;
    }

    while (data_size > 0) {
        per_op_len = (int32_t)(data_size > HASH_UPDATA_LEN ? HASH_UPDATA_LEN : data_size);
        ret = TEE_DigestUpdate(hash_op, data, per_op_len);
        if (ret != TEE_SUCCESS) {
            TEE_FreeOperation(hash_op);
            tloge("Failed to call digest update\n");
            return TEE_ERROR_GENERIC;
        }
        data_size -= (size_t)per_op_len;
        data += per_op_len;
    }

    ret = TEE_DigestDoFinal(hash_op, NULL, 0, hash, &hash_size);
    if (ret != TEE_SUCCESS) {
        tloge("Digest Do Final, fail ret=0x%x, srclen=0x%x, dst_len=0x%x\n",
            ret, (data_size % HASH_UPDATA_LEN), hash_size);
        TEE_FreeOperation(hash_op);
        return ret;
    }

    TEE_FreeOperation(hash_op);

    return TEE_SUCCESS;
}
