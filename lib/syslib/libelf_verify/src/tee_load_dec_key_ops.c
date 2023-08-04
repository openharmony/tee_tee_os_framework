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
#include "tee_elf_verify.h"
#include "ta_load_key.h"
#include "ta_framework.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "crypto_inner_interface.h"
#include "tee_crypto_hal.h"
#include "ta_load_config.h"
#include <tee_crypto_signature_verify.h>
#include "securec.h"
#include "tee_elf_verify_openssl.h"

TEE_Result get_key_data(int32_t img_version, struct key_data *key_data)
{
    TEE_Result ret;

    switch (img_version) {
    case TA_RSA2048_VERSION:
        ret = get_ta_load_key(key_data);
        break;
    case CIPHER_LAYER_VERSION:
        ret = get_ta_load_key(key_data);
        break;
    default:
        tloge("Unsupported secure image version: %d\n", img_version);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ret != TEE_SUCCESS)
        tloge("get key failed for version:%d\n", img_version);

    return ret;
}

const struct ecies_key_struct *get_ecies_key_data(int32_t img_version, enum ta_type type)
{
    TEE_Result ret;
    struct key_data key_data = {
        .pro_type = ECIES_KEY,
        .ta_type = type,
        .key = NULL,
        .key_len = 0,
    };

    ret = get_key_data(img_version, &key_data);
    if (ret != TEE_SUCCESS) {
        tloge("get ecies key failed for version:%d\n", img_version);
        return NULL;
    }

    if (key_data.key_len != sizeof(struct ecies_key_struct)) {
        tloge("ecies key len error\n");
        return NULL;
    }

    return (struct ecies_key_struct *)key_data.key;
}

TEE_Result get_rsa_priv_aes_key(const struct ecies_key_struct *ecies_key_data, uint8_t *key_buff,
    uint32_t buff_size)
{
    if (ecies_key_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    uint8_t oem_ecc_priv[ECIES_PRIV_LEN];
    struct ecc_derive_data_st ecc_data = {0};

    int ret = get_class_ecc_key(oem_ecc_priv, ECIES_PRIV_LEN);
    if (ret != 0) {
        tloge("OEM KEY get failed");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    ecc_data.ec1_priv = oem_ecc_priv;
    ecc_data.ec1_len = sizeof(oem_ecc_priv);
    ecc_data.ec2_pub = ecies_key_data->ecc_pub;
    ecc_data.ec2_len = sizeof(ecies_key_data->ecc_pub);
    ret = ecies_kem_decrypt(&ecc_data, key_buff, buff_size);
    (void)memset_s(oem_ecc_priv, sizeof(oem_ecc_priv), 0, sizeof(oem_ecc_priv));
    if (ret < 0) {
        tloge("ECIES decryption failed");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

TEE_Result aes_decrypt_rsa_private(const struct ecies_key_struct *ecies_data, const uint8_t *aes_key,
    uint32_t key_size, struct rsa_priv_key *priv)
{
    (void)key_size;
    if (ecies_data == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t ret = aes_cbc_256_decrypt(aes_key, ecies_data->iv, ecies_data->wrapped_rsa_priv_p,
        ecies_data->wrapped_rsa_priv_p_len, priv->p);
    bool con = (ret == -1 || ret > (int32_t)ecies_data->wrapped_rsa_priv_p_len);
    if (con)
        return TEE_ERROR_GENERIC;
    priv->p_size = (uint32_t)ret;
    ret = aes_cbc_256_decrypt(aes_key, ecies_data->iv, ecies_data->wrapped_rsa_priv_q,
        ecies_data->wrapped_rsa_priv_q_len, priv->q);
    con = (ret == -1 || ret > (int32_t)ecies_data->wrapped_rsa_priv_q_len);
    if (con)
        return TEE_ERROR_GENERIC;
    priv->q_size = (uint32_t)ret;
    ret = aes_cbc_256_decrypt(aes_key, ecies_data->iv, ecies_data->wrapped_rsa_priv_dq,
        ecies_data->wrapped_rsa_priv_dq_len, priv->dq);
    con = (ret == -1 || ret > (int32_t)ecies_data->wrapped_rsa_priv_dq_len);
    if (con)
        return TEE_ERROR_GENERIC;
    priv->dq_size = (uint32_t)ret;
    ret = aes_cbc_256_decrypt(aes_key, ecies_data->iv, ecies_data->wrapped_rsa_priv_dp,
        ecies_data->wrapped_rsa_priv_dp_len, priv->dp);
    con = (ret == -1 || ret > (int32_t)ecies_data->wrapped_rsa_priv_dp_len);
    if (con)
        return TEE_ERROR_GENERIC;
    priv->dp_size = (uint32_t)ret;
    ret = aes_cbc_256_decrypt(aes_key, ecies_data->iv, ecies_data->wrapped_rsa_priv_qinv,
        ecies_data->wrapped_rsa_priv_qinv_len, priv->qinv);
    con = (ret == -1 || ret > (int32_t)ecies_data->wrapped_rsa_priv_qinv_len);
    if (con)
        return TEE_ERROR_GENERIC;
    priv->qinv_size = (uint32_t)ret;
    ret = aes_cbc_256_decrypt(aes_key, ecies_data->iv, ecies_data->wrapped_rsa_pub_d,
        ecies_data->wrapped_rsa_pub_d_len, priv->d);
    con = (ret == -1 || ret > (int32_t)ecies_data->wrapped_rsa_pub_d_len);
    if (con)
        return TEE_ERROR_GENERIC;
    priv->d_size = (uint32_t)ret;
    ret = aes_cbc_256_decrypt(aes_key, ecies_data->iv, ecies_data->wrapped_rsa_pub_e,
        sizeof(ecies_data->wrapped_rsa_pub_e), priv->e);
    con = (ret == -1 || ret > (int32_t)sizeof(ecies_data->wrapped_rsa_pub_e));
    if (con)
        return TEE_ERROR_GENERIC;
    priv->e_size = (uint32_t)ret;

    return TEE_SUCCESS;
}

