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

#include "soft_cipher.h"
#include "soft_gmssl.h"
#include <openssl/err.h>
#include <openssl/cmac.h>
#include <securec.h>
#include <tee_log.h>
#include "soft_common_api.h"
#include "ae_common.h"
#include "soft_err.h"

#define AES_NO_PADDING   0

static const uint32_t g_algorithm_cipher[] = {
    CRYPTO_TYPE_AES_ECB_NOPAD,
    CRYPTO_TYPE_AES_ECB_PKCS5,
    CRYPTO_TYPE_AES_CBC_PKCS5,
    CRYPTO_TYPE_AES_CBC_NOPAD,
    CRYPTO_TYPE_AES_XTS,
    CRYPTO_TYPE_AES_CTR,
    CRYPTO_TYPE_AES_CBC_MAC_NOPAD,
    CRYPTO_TYPE_AES_CMAC,
    CRYPTO_TYPE_DES_ECB_NOPAD,
    CRYPTO_TYPE_DES_CBC_NOPAD,
    CRYPTO_TYPE_DES3_ECB_NOPAD,
    CRYPTO_TYPE_DES3_CBC_NOPAD,
    CRYPTO_TYPE_SM4_ECB,
    CRYPTO_TYPE_SM4_CBC,
    CRYPTO_TYPE_SM4_CBC_PKCS7,
    CRYPTO_TYPE_SM4_CTR,
    CRYPTO_TYPE_SM4_CFB128,
};

static bool check_is_aes_algorithm(uint32_t alg)
{
    bool is_aes_alg = (alg == CRYPTO_TYPE_AES_ECB_NOPAD || alg == CRYPTO_TYPE_AES_CBC_NOPAD ||
        alg == CRYPTO_TYPE_AES_CTR || alg == CRYPTO_TYPE_AES_CTS || alg == CRYPTO_TYPE_AES_XTS ||
        alg == CRYPTO_TYPE_AES_CBC_MAC_NOPAD || alg == CRYPTO_TYPE_AES_CBC_MAC_PKCS5 ||
        alg == CRYPTO_TYPE_AES_CMAC || alg == CRYPTO_TYPE_AES_CCM || alg == CRYPTO_TYPE_AES_GCM ||
        alg == CRYPTO_TYPE_AES_ECB_PKCS5 || alg == CRYPTO_TYPE_AES_CBC_PKCS5);
    return is_aes_alg;
}

static bool check_is_des_algorithm(uint32_t alg)
{
    bool is_des_alg = (alg == CRYPTO_TYPE_DES_ECB_NOPAD || alg == CRYPTO_TYPE_DES_CBC_NOPAD ||
        alg == CRYPTO_TYPE_DES_CBC_MAC_NOPAD);

    return is_des_alg;
}

static bool check_is_des3_algorithm(uint32_t alg)
{
    bool is_des3_alg = (alg == CRYPTO_TYPE_DES3_ECB_NOPAD || alg == CRYPTO_TYPE_DES3_CBC_NOPAD ||
        alg == CRYPTO_TYPE_DES3_CBC_MAC_NOPAD);

    return is_des3_alg;
}

static bool check_cipher_key_des_size_valid(uint32_t alg, uint32_t key_size)
{
    if (check_is_des_algorithm(alg)) {
        if (key_size == DES_KEY_SIZE)
            return true;
    } else if (check_is_des3_algorithm(alg)) {
        if (key_size == DES3_KEY_SIZE)
            return true;
    }
    return false;
}

static bool check_cipher_aes_key_size_valid(uint32_t alg, uint32_t key_size)
{
    uint32_t i = 0;
    if (check_is_aes_algorithm(alg)) {
        uint32_t key_size_set[] = { AES_TEN_ROUNDS_KEY_SIZE, AES_TWELVE_ROUNDS_KEY_SIZE, AES_FOURTEEN_ROUNDS_KEY_SIZE,
            AES_MAX_KEY_SIZE };
        for (; i < ARRAY_NUM(key_size_set); i++) {
            if (key_size_set[i] == key_size)
                return true;
        }
    }
    return false;
}

static void free_amac_context(uint64_t *ctx)
{
    if (*ctx == 0)
        return;
    CMAC_CTX_free((void *)(uintptr_t)*ctx);
    *ctx = 0;
}


/* The boringssl default padding is pkcs7 */
static void set_aes_cipher_no_padding(uint32_t algorithm, EVP_CIPHER_CTX *ctx)
{
    if (algorithm == CRYPTO_TYPE_AES_ECB_PKCS5 || algorithm == CRYPTO_TYPE_AES_CBC_PKCS5)
        return;
    (void)EVP_CIPHER_CTX_set_padding(ctx, AES_NO_PADDING);

    return;
}

static int32_t get_aes_des_cipher_key(uint32_t alg_type, uint8_t *key_buff, uint32_t key_size,
    const struct symmerit_key_t *key)
{
    bool is_abnormal = ((key->key_size > key_size) ||
        (alg_type == CRYPTO_TYPE_AES_XTS && key->key_size != AES_MAX_KEY_SIZE));
    if (is_abnormal) {
        tloge("Invalid aes key size, key_size=0x%x\n", key->key_size);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;
    errno_t rc = memcpy_s(key_buff, key_size, key_buffer, key->key_size);
    if (rc != EOK) {
        tloge("Copy aes key failed");
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

static int32_t get_and_check_cipher_key(uint32_t alg_type, uint8_t *key_buff, uint32_t key_size,
    const struct symmerit_key_t *key)
{
    int32_t ret = get_aes_des_cipher_key(alg_type, key_buff, key_size, key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get aes key failed");
        return ret;
    }
    if (!check_cipher_aes_key_size_valid(alg_type, key->key_size) &&
        !check_cipher_key_des_size_valid(alg_type, key->key_size)) {
        tloge("The key size is not support, algorithm type = 0x%x size = 0x%x", alg_type, key->key_size);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t get_cipher_iv(uint8_t *iv_buff, uint32_t iv_size, const struct memref_t *iv)
{
    if (iv == NULL) {
        tlogd("No iv info");
        return CRYPTO_SUCCESS;
    }
    if (iv->size > iv_size) {
        tloge("Invalid iv len, len=0x%x\n", iv->size);
        return CRYPTO_BAD_PARAMETERS;
    }
    errno_t rc = memcpy_s(iv_buff, iv_size, (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
    if (rc != EOK) {
        tloge("Copy iv info failed, rc %x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    return CRYPTO_SUCCESS;
}

static int32_t proc_aes_cbc_mac_cipher_update(struct ctx_handle_t *cbc_mac_ctx, const struct memref_t *data_in)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(uintptr_t)(cbc_mac_ctx->ctx_buffer);
    if (ctx == NULL) {
        tloge("The evp cipher ctx or data out is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((data_in->size == 0) || (data_in->size > INT32_MAX) || (data_in->size % AES_BLOCK_SIZE != 0)) {
        tloge("The cbc no pad mac src len is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *tmp_dest_data = TEE_Malloc(data_in->size, 0);
    if (tmp_dest_data == NULL) {
        tloge("Malloc memory failed \n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t tmp_dest_len = (int32_t)data_in->size;
    int32_t ret = EVP_CipherUpdate(ctx, tmp_dest_data, &tmp_dest_len,
        in_buffer, data_in->size);
    if ((ret != BORINGSSL_OK) || (tmp_dest_len < AES_BLOCK_SIZE)) {
        tloge("Evp aes cipher update failed\n");
        TEE_Free(tmp_dest_data);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    errno_t rc = memcpy_s(cbc_mac_ctx->cbc_mac_buffer, sizeof(cbc_mac_ctx->cbc_mac_buffer),
        tmp_dest_data + tmp_dest_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    TEE_Free(tmp_dest_data);
    if (rc != EOK) {
        tloge("Copy aes cmac key failed");
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

static void *proc_soft_aes_des_cipher_init(uint32_t alg_type, uint32_t direction, const uint8_t *aes_key,
    uint32_t key_size, const uint8_t *iv)
{
    uint32_t i                 = 0;
    evp_cipher_func aes_cipher = NULL;
    for (; i < ARRAY_NUM(g_aes_des_init_oeration); i++) {
        if (g_aes_des_init_oeration[i].algorithm == alg_type &&
            g_aes_des_init_oeration[i].key_size == key_size) {
            aes_cipher = g_aes_des_init_oeration[i].aes_cipher;
            break;
        }
    }
    if (aes_cipher == NULL) {
        tloge("Get aes cipher func failed");
        return NULL;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        tloge("New aes ctx failed");
        return NULL;
    }
    uint32_t enc_mode = (direction == DEC_MODE) ? AES_MODE_DECRYPT : AES_MODE_ENCRYPT;
    int32_t rc = EVP_CipherInit_ex(ctx, aes_cipher(), NULL, aes_key, iv, (int32_t)enc_mode);
    if (rc != BORINGSSL_OK) {
        tloge("Evp aes cipher init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    set_aes_cipher_no_padding(alg_type, ctx);
    return ctx;
}

static bool check_is_sm4_algorithm(uint32_t alg)
{
    bool is_sm4_alg = (alg == CRYPTO_TYPE_SM4_ECB || alg == CRYPTO_TYPE_SM4_CBC || alg == CRYPTO_TYPE_SM4_CBC_PKCS7 ||
        alg == CRYPTO_TYPE_SM4_CTR || alg == CRYPTO_TYPE_SM4_CFB128);
    return is_sm4_alg;
}

static int32_t proc_aes_cmac_cipher_update(struct ctx_handle_t *cmac_ctx, const struct memref_t *data_in)
{
    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;

    CMAC_CTX *ctx = (CMAC_CTX *)(uintptr_t)(cmac_ctx->ctx_buffer);
    if (ctx == NULL) {
        tloge("The aes cmac ctx is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t rc = CMAC_Update(ctx, in_buffer, data_in->size);
    if (rc != BORINGSSL_OK) {
        tloge("Aes cmac update failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t soft_des_src_len_check(uint32_t alg, uint32_t src_len)
{
    if (check_is_des_algorithm(alg) || check_is_des3_algorithm(alg)) {
        if (src_len % DES_BLOCK_SIZE != 0) {
            tloge("des src len error:0x%x", src_len);
            return CRYPTO_BAD_PARAMETERS;
        }
    }
    return CRYPTO_SUCCESS;
}

static int32_t proc_aes_des_cipher_update(struct ctx_handle_t *cipher_ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(uintptr_t)(cipher_ctx->ctx_buffer);
    if (ctx == NULL) {
        tloge("The evp cipher ctx is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (data_out == NULL || data_out->size > INT32_MAX) {
        tloge("data out is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    int32_t ret = soft_des_src_len_check(cipher_ctx->alg_type, data_in->size);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    int32_t dest_len_temp = (int32_t)data_out->size;
    int32_t rc = EVP_CipherUpdate(ctx, out_buffer, &dest_len_temp, in_buffer, data_in->size);
    if (rc != BORINGSSL_OK || dest_len_temp < 0) {
        tloge("Evp aes cipher update failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = (uint32_t)dest_len_temp;
    return CRYPTO_SUCCESS;
}

static int32_t proc_aes_cmac_cipher_final(struct ctx_handle_t *cipher_ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    CMAC_CTX *ctx = (CMAC_CTX *)(uintptr_t)(cipher_ctx->ctx_buffer);
    if (ctx == NULL) {
        tloge("The aes cmac ctx is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t rc;
    if (data_in != NULL && data_in->buffer != 0) {
        uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
        rc = CMAC_Update(ctx, in_buffer, data_in->size);
        if (rc != BORINGSSL_OK) {
            tloge("Aes cmac update failed\n");
            CMAC_CTX_free(ctx);
            cipher_ctx->ctx_buffer = 0;
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    size_t temp_out_size = data_out->size;
    rc = CMAC_Final(ctx, out_buffer, &temp_out_size);
    CMAC_CTX_free(ctx);
    cipher_ctx->ctx_buffer = 0;
    if (rc != BORINGSSL_OK) {
        tloge("Aes cmac final failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = AES_MAC_LEN;

    return TEE_SUCCESS;
}

static int32_t proc_aes_cbc_mac_cipher_final(struct ctx_handle_t *cipher_ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    if (data_out->buffer == 0 || data_out->size == 0 || data_out->size > INT32_MAX)
        return CRYPTO_BAD_PARAMETERS;

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(uintptr_t)(cipher_ctx->ctx_buffer);
    if (ctx == NULL) {
        tloge("The aes cmac ctx is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (data_in != NULL && data_in->buffer != 0) {
        int32_t ret = proc_aes_cbc_mac_cipher_update(cipher_ctx, data_in);
        if (ret != CRYPTO_SUCCESS) {
            tloge("Proc aes cbc mac update in final failed");
            EVP_CIPHER_CTX_free(ctx);
            cipher_ctx->ctx_buffer = 0;
            return ret;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    cipher_ctx->ctx_buffer = 0;

    errno_t rc = memcpy_s((void *)(uintptr_t)data_out->buffer, data_out->size,
                          cipher_ctx->cbc_mac_buffer, sizeof(cipher_ctx->cbc_mac_buffer));
    if (rc != EOK) {
        tloge("Copy cbc mac failed");
        return CRYPTO_ERROR_SECURITY;
    }
    data_out->size = AES_MAC_LEN;

    return CRYPTO_SUCCESS;
}

static int32_t proc_aes_des_cipher_final(struct ctx_handle_t *cipher_ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(uintptr_t)(cipher_ctx->ctx_buffer);
    if (ctx == NULL || data_out->buffer == 0 || data_out->size == 0 || data_out->size < data_in->size ||
        data_out->size > INT32_MAX) {
        tloge("ctx is null or data out size is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t update_len = 0;
    int32_t rc;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    if (data_in != NULL && data_in->buffer != 0) {
        uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
        update_len = (int32_t)(data_out->size);
        rc = EVP_CipherUpdate(ctx, out_buffer, &update_len, in_buffer, data_in->size);
        if (rc != BORINGSSL_OK || update_len < 0) {
            tloge("Evp aes cipher update failed\n");
            EVP_CIPHER_CTX_free(ctx);
            cipher_ctx->ctx_buffer = 0;
            return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        }
    }

    int32_t final_len = data_out->size - update_len;
    rc = EVP_CipherFinal_ex(ctx, out_buffer + update_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    cipher_ctx->ctx_buffer = 0;

    if (rc != BORINGSSL_OK || update_len + final_len < 0) {
        if (ERR_GET_REASON(ERR_peek_last_error()) == EVP_R_BAD_DECRYPT)
            return CRYPTO_BAD_FORMAT;
        tloge("Evp aes cipher final failed\n");
        return get_soft_crypto_error(TEE_ERROR_GENERIC);
    }
    data_out->size = (uint32_t)(update_len + final_len);
    return CRYPTO_SUCCESS;
}

static void *soft_aes_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    uint8_t aes_key[AES_MAX_KEY_SIZE] = { 0 };
    uint8_t aes_iv[AES_MAX_IV_SIZE] = { 0 };

    int32_t rc = get_and_check_cipher_key(alg_type, aes_key, sizeof(aes_key), key);
    if (rc != CRYPTO_SUCCESS) {
        tloge("Get aes key and iv failed, ret=%d", rc);
        (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
        return NULL;
    }

    rc = get_cipher_iv(aes_iv, sizeof(aes_iv), iv);
    if (rc != CRYPTO_SUCCESS) {
        tloge("Get aes key and iv failed, ret=%d", rc);
        (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
        return NULL;
    }

    void *cipher_ctx = proc_soft_aes_des_cipher_init(alg_type, direction, aes_key, key->key_size, aes_iv);
    (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    return cipher_ctx;
}

static void *soft_aes_cmac_cipher_init(const struct symmerit_key_t *key)
{
    uint8_t cmac_key[AES_FOURTEEN_ROUNDS_KEY_SIZE] = { 0 };

    if ((key->key_size != AES_TEN_ROUNDS_KEY_SIZE) && (key->key_size != AES_FOURTEEN_ROUNDS_KEY_SIZE)) {
        tloge("Invalid aes cmac key size\n");
        return NULL;
    }
    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;
    errno_t rc = memcpy_s(cmac_key, AES_FOURTEEN_ROUNDS_KEY_SIZE, key_buffer, key->key_size);
    if (rc != EOK) {
        tloge("Copy aes cmac key failed");
        return NULL;
    }
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (ctx == NULL) {
        tloge("New aes cmac ctx failed\n");
        (void)memset_s(cmac_key, sizeof(cmac_key), 0x0, sizeof(cmac_key));
        return NULL;
    }

    const EVP_CIPHER *cipher = (key->key_size == AES_TEN_ROUNDS_KEY_SIZE) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    int32_t ret = CMAC_Init(ctx, cmac_key, key->key_size, cipher, NULL);
    (void)memset_s(cmac_key, AES_FOURTEEN_ROUNDS_KEY_SIZE, 0, AES_FOURTEEN_ROUNDS_KEY_SIZE);
    if (ret != BORINGSSL_OK) {
        tloge("Evp aes cipher init failed\n");
        (void)CMAC_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

int32_t soft_crypto_cipher_init(struct ctx_handle_t *ctx,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    if (ctx == NULL || key == NULL || key->key_buffer == 0) {
        tloge("param is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (check_is_sm4_algorithm(ctx->alg_type))
        return sm4_cipher_init(ctx, key, iv);

    int32_t rc = check_valid_algorithm(ctx->alg_type, g_algorithm_cipher, ARRAY_NUM(g_algorithm_cipher));
    if (rc != CRYPTO_SUCCESS) {
        tloge("algorithm 0x%x is incorrect or not supported", ctx->alg_type);
        return rc;
    }
    void *cipher_ctx = NULL;
    if (ctx->alg_type == CRYPTO_TYPE_AES_CMAC)
        cipher_ctx = soft_aes_cmac_cipher_init(key);
    else
        cipher_ctx = soft_aes_cipher_init(ctx->alg_type, ctx->direction, key, iv);

    if (cipher_ctx == NULL) {
        tloge("cipher init failed");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    ctx->ctx_buffer = (uint64_t)(uintptr_t)cipher_ctx;
    if (ctx->alg_type == CRYPTO_TYPE_AES_CMAC)
        ctx->free_context = free_amac_context;
    else
        ctx->free_context = free_cipher_context;

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (ctx == NULL || data_in == NULL || data_in->buffer == 0) {
        tloge("invalid input params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (check_is_sm4_algorithm(ctx->alg_type))
        return sm4_cipher_update(ctx, data_in, data_out);

    if (ctx->alg_type == CRYPTO_TYPE_AES_CMAC)
        return proc_aes_cmac_cipher_update(ctx, data_in);
    else if (ctx->alg_type == CRYPTO_TYPE_AES_CBC_MAC_NOPAD)
        return proc_aes_cbc_mac_cipher_update(ctx, data_in);
    else
        return proc_aes_des_cipher_update(ctx, data_in, data_out);
}

int32_t soft_crypto_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (ctx == NULL || data_out == NULL) {
        tloge("invalid input params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (check_is_sm4_algorithm(ctx->alg_type))
        return sm4_cipher_do_final(ctx, data_in, data_out);

    if (ctx->alg_type == CRYPTO_TYPE_AES_CMAC)
        return proc_aes_cmac_cipher_final(ctx, data_in, data_out);
    else if (ctx->alg_type == CRYPTO_TYPE_AES_CBC_MAC_NOPAD)
        return proc_aes_cbc_mac_cipher_final(ctx, data_in, data_out);
    else
        return proc_aes_des_cipher_final(ctx, data_in, data_out);
}

int32_t soft_crypto_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct ctx_handle_t *ctx = TEE_Malloc(sizeof(*ctx), 0);
    if (ctx == NULL) {
        tloge("Malloc failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    ctx->alg_type = alg_type;
    ctx->direction = direction;

    int32_t rc = soft_crypto_cipher_init(ctx, key, iv);
    if (rc != CRYPTO_SUCCESS) {
        tloge("cipher init failed");
        TEE_Free(ctx);
        return rc;
    }
    rc = soft_crypto_cipher_dofinal(ctx, data_in, data_out);
    TEE_Free(ctx);
    ctx = NULL;
    if (rc != CRYPTO_SUCCESS)
        tloge("cipher failed");
    return rc;
}

