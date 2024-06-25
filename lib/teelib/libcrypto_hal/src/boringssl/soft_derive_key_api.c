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

#include "soft_derive_key_api.h"
#include <crypto/evp.h>
#ifdef CRYPTO_SUPPORT_SOFT_ECC
#include <crypto/ec/ec_local.h>
#include <openssl/ecdh.h>
#endif
#include <openssl/evp.h>
#include <securec.h>
#include <tee_log.h>
#include "crypto_inner_interface.h"
#include "soft_common_api.h"
#include "soft_err.h"

static EVP_MD *get_pbkdf_digest_type(uint32_t digest_type)
{
    switch (digest_type) {
    case CRYPTO_TYPE_DIGEST_SHA1:
        return (EVP_MD *)EVP_sha1();
    case CRYPTO_TYPE_DIGEST_SHA224:
        return (EVP_MD *)EVP_sha224();
    case CRYPTO_TYPE_DIGEST_SHA256:
        return (EVP_MD *)EVP_sha256();
    case CRYPTO_TYPE_DIGEST_SHA384:
        return (EVP_MD *)EVP_sha384();
    case CRYPTO_TYPE_DIGEST_SHA512:
        return (EVP_MD *)EVP_sha512();
    default:
        return 0;
    }
}

#ifdef CRYPTO_SUPPORT_SOFT_ECC
static int32_t x25519_derive_key(const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
    uint8_t *out_shared_key, uint32_t *out_share_key_len)
{
#ifdef CRYPTO_SSL_SUPPORT_EC25519
    if (server_key->r_len < X25519_SHARE_KEY_LEN || client_key->x_len < X25519_SHARE_KEY_LEN) {
        tloge("invalid length for x25519");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t res = X25519(out_shared_key, server_key->r, client_key->x);
    if (res != BORINGSSL_OK) {
        tloge("x25519 share key make error");
        return CRYPTO_BAD_PARAMETERS;
    }
    *out_share_key_len = X25519_SHARE_KEY_LEN;
    return CRYPTO_SUCCESS;
#else
    (void)client_key;
    (void)server_key;
    (void)out_shared_key;
    (void)out_share_key_len;
    return CRYPTO_NOT_SUPPORTED;
#endif
}

static int32_t derive_key_get_boringkey(const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
    EC_KEY **ec_pub_key, EC_KEY **ec_pri_key)
{
    struct ecc_pub_key_t *public = (struct ecc_pub_key_t *)client_key;
    uint32_t tee_domain = public->domain_id;
    int32_t ret = get_boring_nid_by_tee_curve(public->domain_id, &public->domain_id);
    if (ret != CRYPTO_SUCCESS) {
        tloge("change nid fail");
        return ret;
    }

    ret = (int32_t)ecc_pubkey_tee_to_boring(public, ec_pub_key);
    public->domain_id = tee_domain;
    if (ret != CRYPTO_SUCCESS) {
        tloge("PubKeyToBoringKey key error");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    struct ecc_priv_key_t *private = (struct ecc_priv_key_t *)server_key;
    tee_domain = private->domain_id;
    ret = get_boring_nid_by_tee_curve(private->domain_id, &private->domain_id);
    if (ret != CRYPTO_SUCCESS) {
        tloge("change nid fail");
        EC_KEY_free(*ec_pub_key);
        *ec_pub_key = NULL;
        return ret;
    }
    ret = (int32_t)ecc_privkey_tee_to_boring(private, (void **)ec_pri_key);
    private->domain_id = tee_domain;
    if (ret != CRYPTO_SUCCESS) {
        tloge("Tee Private Key To Boring Key error");
        EC_KEY_free(*ec_pub_key);
        *ec_pub_key = NULL;
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    return CRYPTO_SUCCESS;
}

static int32_t ecdh_derive_key(const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
    uint8_t *out_shared_key, uint32_t *out_share_key_len)
{
    EC_KEY *ec_pub_key = NULL;
    EC_KEY *ec_pri_key = NULL;
    int32_t ret = derive_key_get_boringkey(client_key, server_key, &ec_pub_key, &ec_pri_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("get boring key error");
        return ret;
    }
    *out_share_key_len = (uint32_t)ECDH_compute_key(out_shared_key, SHARE_KEY_MAX_LEN,
        EC_KEY_get0_public_key(ec_pub_key), ec_pri_key, NULL);
    EC_KEY_free(ec_pub_key);
    EC_KEY_free(ec_pri_key);
    if (*out_share_key_len == 0) {
        tloge("boring compute key fail");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_ecdh_derive_key(uint32_t alg_type, const struct ecc_pub_key_t *client_key,
    const struct ecc_priv_key_t *server_key, const struct asymmetric_params_t *ec_params,
    struct memref_t *secret)
{
    (void)ec_params;
    bool check = (client_key == NULL || server_key == NULL || secret == NULL);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }
    uint8_t out_shared_key[SHARE_KEY_MAX_LEN] = { 0 };
    uint32_t out_share_key_len = 0;
    int32_t ret;
    if (alg_type == CRYPTO_TYPE_X25519)
        ret = x25519_derive_key(client_key, server_key, out_shared_key, &out_share_key_len);
    else
        ret = ecdh_derive_key(client_key, server_key, out_shared_key, &out_share_key_len);

    if (ret != TEE_SUCCESS) {
        tloge("derive key failed");
        return ret;
    }

    if (secret->size < out_share_key_len) {
        tloge("key size %u is not enough %u", secret->size, out_share_key_len);
        (void)memset_s(out_shared_key, sizeof(out_shared_key), 0, sizeof(out_shared_key));
        return CRYPTO_SHORT_BUFFER;
    }
    errno_t rc = memcpy_s((void *)(uintptr_t)(secret->buffer), secret->size, out_shared_key, out_share_key_len);
    (void)memset_s(out_shared_key, sizeof(out_shared_key), 0, sizeof(out_shared_key));
    if (rc != EOK) {
        tloge("copy secret key failed");
        return CRYPTO_ERROR_SECURITY;
    }
    return CRYPTO_SUCCESS;
}
#else
int32_t soft_crypto_ecdh_derive_key(uint32_t alg_type, const struct ecc_pub_key_t *client_key,
    const struct ecc_priv_key_t *server_key, const struct asymmetric_params_t *ec_params,
    struct memref_t *secret)
{
    (void)alg_type;
    (void)client_key;
    (void)server_key;
    (void)ec_params;
    (void)secret;
    return CRYPTO_NOT_SUPPORTED;
}
#endif

int32_t soft_crypto_pbkdf2(const struct memref_t *password, const struct memref_t *salt,
    uint32_t iterations, uint32_t digest_type, struct memref_t *data_out)
{
    bool check = (password == NULL || salt == NULL || data_out == NULL);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    EVP_MD *digest = get_pbkdf_digest_type(digest_type);
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)(data_out->buffer);

    int ret = PKCS5_PBKDF2_HMAC((const char *)(uintptr_t)(password->buffer), password->size,
        (uint8_t *)(uintptr_t)salt->buffer, salt->size, iterations, digest, data_out->size, out_buffer);
    if (ret != BORINGSSL_OK) {
        tloge("pbkdf failed");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}
